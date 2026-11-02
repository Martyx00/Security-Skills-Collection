"""Build analysis, include resolution and API-identifier attribution (contract sections 6.9, 6.10).

* ``Build``            targets, directory reachability, link graph, compiled files and per-configuration values of
                       build-level conditions;
* ``IncludeResolver``  the six-step include resolution of section 6.10;
* ``Scanner``          creates the ``INCLUDE`` and ``API_HIT`` verification records and keeps, for each, the per-configuration
                       status the rule engine needs (``Site``).

Only first-party files (and, for the transitive rule of Appendix D, files of in-tree candidates) are ever read, with the
guarded reader of ``inputs`` (``"rb"``, ``lstat`` first, 2 MiB cap). Nothing here writes.
"""
from __future__ import annotations

import hashlib
import posixpath
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from sbomlib import ids, model, norm
from sbomlib.context import RunContext
from sbomlib.verify import configs
from sbomlib.verify.configs import DISABLED, ENABLED, UNKNOWN, any_of, combine, is_enabled
from sbomlib.verify.inputs import (FETCHED_OR_DECLARED, IN_TREE, TEXT_SCAN_CAP, RepoData, candidate_dir, compile_source,
                                   decode_text, is_c_family, is_header_file, is_source_file, path_scope,
                                   read_target_bytes, within)

MAX_CLOSURE_DEPTH = 10
MAX_INCLUDE_RECORDS_PER_CANDIDATE = 200
MAX_HIT_RECORDS_PER_CANDIDATE = 300
MAX_DERIVE_HEADERS = 30
WEAK_DISTINCT_NEEDED = 3

_BUILD_FILE_RE = re.compile(r"(?:^|/)(?:CMakeLists\.txt|[^/]*\.cmake|meson\.build|Makefile(?:\.am|\.in)?|makefile|GNUmakefile|[^/]*\.mk|[^/]*\.txt)$")
_SOURCE_DIR_VARS = ("${CMAKE_CURRENT_SOURCE_DIR}", "${CMAKE_CURRENT_LIST_DIR}")
_ROOT_DIR_VARS = ("${CMAKE_SOURCE_DIR}", "${PROJECT_SOURCE_DIR}", "${CMAKE_PROJECT_SOURCE_DIR}")


def parent_dir(directory: str) -> str:
    return directory.rsplit("/", 1)[0] if "/" in directory else ""


def norm_dir(value: Any) -> str:
    text = norm.normalize_path(str(value or ""))
    return "" if text == "." else text


def expand_dir(path: Any, base_dir: str) -> Optional[str]:
    """Repo-relative form of a build-file directory string; ``None`` when a variable stays unexpanded."""
    text = str(path or "")
    for var in _SOURCE_DIR_VARS:
        text = text.replace(var, base_dir or ".")
    for var in _ROOT_DIR_VARS:
        text = text.replace(var, ".")
    if "$" in text:
        return None
    text = norm.normalize_path(text)
    return "" if text == "." else posixpath.normpath(text) if text else ""


# ------------------------------------------------------------------------------------------------------ build model

class Build:
    """Targets, directory reachability, link graph and compiled files of one repository (buildmodel + inventory)."""

    def __init__(self, data: RepoData, shipping: Dict[str, Any]) -> None:
        self.data = data
        bm = data.buildmodel
        self.shipping = shipping
        self.ship: List[str] = list(shipping["configs"])
        self.configs: List[str] = list(shipping["all"])
        self.vars: Dict[str, Dict[str, Optional[str]]] = {
            c: configs.variables_for(bm, c, data.inventory) for c in self.configs}
        self.targets: List[Dict[str, Any]] = [t for t in bm.get("targets") or [] if isinstance(t, dict)]
        self.by_name: Dict[str, List[int]] = {}
        for index, target in enumerate(self.targets):
            self.by_name.setdefault(str(target.get("name")), []).append(index)
        self.tdir: List[str] = [self._target_dir(t) for t in self.targets]
        # subdirs: child directory -> [(condition, parent directory)]; the parent comes from ``from`` when discovery gave it
        self.entries: Dict[str, List[Tuple[Optional[Dict[str, Any]], Optional[str]]]] = {}
        for entry in bm.get("subdirs") or []:
            if isinstance(entry, dict):
                key = norm_dir(entry.get("dir") if entry.get("dir") is not None else entry.get("path"))
                origin = entry.get("from")
                parent: Optional[str] = None
                if isinstance(origin, str):
                    parent = norm_dir(parent_dir(origin) if _BUILD_FILE_RE.search(origin) else origin)
                self.entries.setdefault(key, []).append((entry.get("condition"), parent))
        self.tree_dirs: List[str] = sorted({d for cid, d in data.dir_of.items() if data.in_tree(data.cand_by_id[cid])},
                                           key=lambda d: (-len(d), d))
        self._dir_cache: Dict[Tuple[str, str], str] = {}
        self._tgt_cache: Dict[Tuple[int, str], str] = {}
        self._carried: Dict[Tuple[str, str], Set[int]] = {}
        self._active: Dict[Tuple[int, str], str] = {}
        self.has_subdirs = bool(self.entries)
        self._by_source: Optional[Dict[str, List[Tuple[int, Dict[str, Any]]]]] = None
        self._reach_by_config: Dict[str, Dict[int, List[int]]] = {}
        self._governing: Dict[str, List[int]] = {}
        self._scope_cache: Dict[int, str] = {}
        self._link_refs: Optional[List[Tuple[int, List[Tuple[int, Optional[Dict[str, Any]]]]]]] = None

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _target_dir(target: Dict[str, Any]) -> str:
        if target.get("dir") is not None:
            return norm_dir(target.get("dir"))
        return norm_dir(parent_dir(str(target.get("path") or "")))

    def cond(self, condition: Optional[Dict[str, Any]], config: str) -> str:
        return configs.evaluate(condition, self.vars.get(config) or {})

    def inner_tree_dir(self, directory: str) -> Optional[str]:
        for tree in self.tree_dirs:
            if directory == tree or directory.startswith(tree + "/"):
                return tree
        return None

    def is_first_party_target(self, index: int) -> bool:
        return self.inner_tree_dir(self.tdir[index]) is None

    def target_scope(self, index: int) -> str:
        """``test`` for a target flagged ``test`` or whose sources and directory lie in test paths, ``dev`` for examples and
        tools, else ``product`` (section 6.9)."""
        if index in self._scope_cache:
            return self._scope_cache[index]
        target = self.targets[index]
        scope = "product"
        if target.get("test"):
            scope = "test"
        else:
            base = ""
            owner = self.data.owner_of(self.tdir[index] + "/x") if self.tdir[index] else None
            if owner is not None:
                base = self.data.dir_of.get(owner) or ""
            sources = [norm.normalize_path(str(s.get("path", ""))) for s in target.get("sources") or []
                       if isinstance(s, dict) and s.get("path")]
            scopes = {path_scope(p, self.data.test_dirs, base=base) for p in sources}
            if scopes and "product" not in scopes:
                scope = "test" if "test" in scopes else "dev"
            elif not scopes and self.tdir[index]:
                scope = path_scope(self.tdir[index] + "/x", self.data.test_dirs, base=base)
        self._scope_cache[index] = scope
        return scope

    def is_test_target(self, index: int) -> bool:
        """True for a target that is not part of the product (``test`` or ``dev`` scope)."""
        return self.target_scope(index) != "product"

    # ------------------------------------------------------------------ directories
    def dir_status(self, directory: str, config: str) -> str:
        """Value of "the build reaches this directory" in one configuration (``subdirs`` chain, section 6.10 + D20)."""
        key = (directory, config)
        if key in self._dir_cache:
            return self._dir_cache[key]
        self._dir_cache[key] = ENABLED                   # cycle guard
        value = self._dir_status(directory, config)
        self._dir_cache[key] = value
        return value

    def _entry_value(self, directory: str, config: str) -> str:
        """Value of "this directory is entered" over its ``add_subdirectory`` entries (each: its condition and its parent)."""
        values = []
        for condition, parent in self.entries.get(directory, []):
            where = parent if parent is not None else parent_dir(directory)
            if directory == "" or where == directory:
                values.append(self.cond(condition, config))
            else:
                values.append(combine([self.cond(condition, config), self.dir_status(where, config)]))
        return any_of(values)

    def _dir_status(self, directory: str, config: str) -> str:
        inner = self.inner_tree_dir(directory)
        probe = directory
        if inner is None:
            while True:                                  # nearest entered ancestor-or-self; none -> a build root
                if probe in self.entries:
                    break
                if not probe:
                    return ENABLED
                probe = parent_dir(probe)
        else:
            while probe not in self.entries:             # must be entered from inside the candidate, else not built
                if probe == inner or not probe:
                    return DISABLED
                probe = parent_dir(probe)
        return self._entry_value(probe, config)

    # ------------------------------------------------------------------ targets
    def target_status(self, index: int, config: str) -> str:
        key = (index, config)
        if key not in self._tgt_cache:
            target = self.targets[index]
            self._tgt_cache[key] = combine([self.cond(target.get("condition"), config),
                                            self.dir_status(self.tdir[index], config)])
        return self._tgt_cache[key]

    def _edges(self, config: str, accept: Callable[[str], bool]) -> Dict[int, Set[int]]:
        edges: Dict[int, Set[int]] = {}
        globals_link = [g for g in (self.data.buildmodel.get("globals") or {}).get("link") or [] if isinstance(g, dict)]
        for index, target in enumerate(self.targets):
            if not accept(self.target_status(index, config)):
                continue
            items = list(target.get("link") or [])
            for glob in globals_link:
                gdir = norm_dir(parent_dir(str(glob.get("path") or "")))
                if within(self.tdir[index], gdir) or not gdir:
                    items.append(glob)
            for item in items:
                if not isinstance(item, dict) or not accept(self.cond(item.get("condition"), config)):
                    continue
                name = str(item.get("item") or "")
                matches = self.by_name.get(name)
                if not matches and "::" in name:
                    matches = self.by_name.get(name.rsplit("::", 1)[-1])
                for other in matches or []:
                    if other != index and accept(self.target_status(other, config)):
                        edges.setdefault(index, set()).add(other)
        # An alias (``add_library(ZLIB::ZLIB ALIAS zlibstatic)``) is not in the build model: discovery resolved the link item to
        # the candidate, so the linking target carries every library target defined inside that candidate's directory.
        for source, others in self._link_ref_edges():
            if not accept(self.target_status(source, config)):
                continue
            for other, condition in others:
                if other != source and accept(combine([self.cond(condition, config), self.target_status(other, config)])):
                    edges.setdefault(source, set()).add(other)
        return edges

    def _link_ref_edges(self) -> List[Tuple[int, List[Tuple[int, Optional[Dict[str, Any]]]]]]:
        """``[(linking target, [(library target inside the linked candidate's directory, record condition)])]`` from LINK_REF."""
        if self._link_refs is None:
            libraries: Dict[str, List[int]] = {}
            for cid, directory in self.data.dir_of.items():
                if not self.data.in_tree(self.data.cand_by_id[cid]):
                    continue
                found = [i for i, t in enumerate(self.targets)
                         if str(t.get("kind") or "").endswith("_library") and within(self.tdir[i], directory)]
                if found:
                    libraries[cid] = found
            table: Dict[int, List[Tuple[int, Optional[Dict[str, Any]]]]] = {}
            for rec in self.data.evidence:
                if rec.get("type") != "LINK_REF" or not rec.get("target") or rec.get("candidate") not in libraries:
                    continue
                source = self.resolve_target(rec.get("target"), None)
                if source is None:
                    continue
                table.setdefault(source, []).extend((i, rec.get("condition")) for i in libraries[rec["candidate"]])
            self._link_refs = sorted(table.items())
        return self._link_refs

    def carried(self, config: str, strict: bool) -> Set[int]:
        """Targets reachable by enabled link edges from the first-party, non-test targets (``strict``: certain only)."""
        key = (config, "s" if strict else "l")
        if key in self._carried:
            return self._carried[key]
        accept = is_enabled if strict else (lambda v: v != DISABLED)
        edges = self._edges(config, accept)
        roots = [i for i in range(len(self.targets))
                 if self.is_first_party_target(i) and not self.is_test_target(i) and accept(self.target_status(i, config))]
        seen: Set[int] = set(roots)
        stack = list(roots)
        while stack:
            for nxt in sorted(edges.get(stack.pop(), ())):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        if not roots:                                    # a build of vendored libraries only: they are the product
            for i in range(len(self.targets)):
                if not self.is_test_target(i) and accept(self.target_status(i, config)):
                    seen.add(i)
        self._carried[key] = seen
        return seen

    def active_status(self, index: int, config: str) -> str:
        """Target status that also demands the target is part of the product (carried by a first-party target)."""
        key = (index, config)
        if key in self._active:
            return self._active[key]
        value = self.target_status(index, config)
        if value != DISABLED and not self.is_test_target(index) and not self.is_first_party_target(index):
            if index in self.carried(config, True):
                pass
            elif index in self.carried(config, False):
                value = combine([value, UNKNOWN])
            else:
                value = DISABLED
        self._active[key] = value
        return value

    def root_reach(self, config: str) -> Dict[int, List[int]]:
        """For each target the first-party, non-test targets that (transitively) link it, by enabled edges only."""
        if config in self._reach_by_config:
            return self._reach_by_config[config]
        edges = self._edges(config, is_enabled)
        reach: Dict[int, List[int]] = {}
        for root in range(len(self.targets)):
            if (not self.is_first_party_target(root) or self.is_test_target(root)
                    or not is_enabled(self.target_status(root, config))):
                continue
            seen = {root}
            stack = [root]
            while stack:
                node = stack.pop()
                reach.setdefault(node, []).append(root)
                for nxt in sorted(edges.get(node, ())):
                    if nxt not in seen:
                        seen.add(nxt)
                        stack.append(nxt)
        self._reach_by_config[config] = reach
        return reach

    def resolve_target(self, name: Optional[str], path: Optional[str] = None) -> Optional[int]:
        """Index of the target called ``name`` (the one that lists ``path`` as a source when several share the name)."""
        if not name:
            return None
        matches = self.by_name.get(str(name)) or []
        if not matches:
            return None
        if len(matches) > 1 and path:
            for index in matches:
                if any(norm.normalize_path(str(s.get("path"))) == path for s in self.targets[index].get("sources") or []):
                    return index
        return matches[0]

    # ------------------------------------------------------------------ sources
    def by_source(self) -> Dict[str, List[Tuple[int, Dict[str, Any]]]]:
        """Source path -> ``[(target index, source entry)]`` from ``targets[].sources`` and from ``COMPILE_LIST`` records
        whose target resolves (a glob-expanded list may be missing from the model but present as evidence)."""
        if self._by_source is None:
            table: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {}
            for index, target in enumerate(self.targets):
                for source in target.get("sources") or []:
                    if isinstance(source, dict) and source.get("path"):
                        table.setdefault(norm.normalize_path(str(source["path"])), []).append((index, source))
            for rec in self.data.evidence:
                path = compile_source(rec) if rec.get("type") == "COMPILE_LIST" else None
                if not path or not rec.get("target"):
                    continue
                index = self.resolve_target(rec.get("target"), path)
                if index is None or any(i == index for i, _ in table.get(path, [])):
                    continue
                table.setdefault(path, []).append((index, {"path": path, "line": rec.get("line"),
                                                           "condition": rec.get("condition")}))
            self._by_source = table
        return self._by_source

    def source_values(self, path: str, config: str) -> Tuple[str, str]:
        """``(product value, test value)`` of a source file named by targets in one configuration (disabled when unnamed)."""
        prod: List[str] = []
        test: List[str] = []
        for index, source in self.by_source().get(path, []):
            value = combine([self.active_status(index, config), self.cond(source.get("condition"), config)])
            (test if self.is_test_target(index) else prod).append(value)
        return any_of(prod), any_of(test)

    def source_scopes(self, path: str) -> Set[str]:
        """Scopes of the targets that name ``path`` as a source."""
        return {self.target_scope(i) for i, _ in self.by_source().get(path, [])}

    def names_any_source(self) -> bool:
        """A covered build system names sources for at least one target enabled in a shipping configuration."""
        for entries in self.by_source().values():
            for index, _source in entries:
                if any(self.target_status(index, c) != DISABLED for c in self.ship):
                    return True
        return False

    def governing(self, directory: str) -> List[int]:
        """Targets defined in ``directory`` or an ancestor of it, closest first (the build files that govern it)."""
        if directory not in self._governing:
            found = [i for i in range(len(self.targets)) if within(directory, self.tdir[i]) or not self.tdir[i]]
            found.sort(key=lambda i: (-len(self.tdir[i]), i))
            self._governing[directory] = found
        return self._governing[directory]

    def include_dirs_for(self, path: str) -> List[str]:
        """Include directories (repo-relative) of the targets that compile ``path`` (else that govern its directory)."""
        found: List[Tuple[str, str]] = []
        named = self.by_source().get(path, [])
        indices = [i for i, _ in named]
        if not indices:
            indices = self.governing(parent_dir(path))
        for index in indices:
            base = self.tdir[index]
            for entry in self.targets[index].get("include_dirs") or []:
                found.extend(self._dir_variants(entry, base))
        gl = (self.data.buildmodel.get("globals") or {}).get("include_dirs") or []
        for entry in gl:
            base = norm_dir(parent_dir(str(entry.get("file") or ""))) if isinstance(entry, dict) else ""
            found.extend(self._dir_variants(entry, base))
        seen: Set[str] = set()
        out: List[str] = []
        for _, directory in found:
            if directory not in seen:
                seen.add(directory)
                out.append(directory)
        return out

    @staticmethod
    def _dir_variants(entry: Any, base: str) -> List[Tuple[str, str]]:
        if not isinstance(entry, dict):
            return []
        raw = None
        for key in ("dir", "directory", "value", "include"):
            if isinstance(entry.get(key), str) and entry.get(key):
                raw = entry[key]
                break
        if raw is None:
            path = entry.get("path")
            if not isinstance(path, str) or _BUILD_FILE_RE.search(path):
                return []
            raw = path
        out: List[Tuple[str, str]] = []
        expanded = expand_dir(raw, base)
        if expanded is None:
            return out
        out.append(("repo", expanded))
        if base and not str(raw).startswith(("${", "/")):
            rel = norm.normalize_path(posixpath.join(base, str(raw)))
            if rel != expanded:
                out.append(("rel", rel))
        return out


# ------------------------------------------------------------------------------------------------ include resolution

class Resolution:
    """Outcome of resolving one include line (section 6.10)."""

    __slots__ = ("kind", "path", "cands", "library", "ambiguous")

    def __init__(self, kind: str, path: Optional[str] = None, cands: Sequence[str] = (), library: Optional[str] = None,
                 ambiguous: Sequence[str] = ()) -> None:
        self.kind = kind              # file | library | system | unresolved | generated
        self.path = path
        self.cands = list(cands)      # candidate ids the include lands in (several only when ambiguous)
        self.library = library
        self.ambiguous = list(ambiguous)


class IncludeResolver:
    def __init__(self, ctx: RunContext, data: RepoData, build: Build) -> None:
        self.data = data
        self.build = build
        inc_map = ctx.asset("include_map.json") if _asset_exists(ctx, "include_map.json") else {}
        self.exact: Dict[str, str] = {}
        self.prefixes: List[Tuple[str, str]] = []
        for header, library in (inc_map.get("headers") or {}).items():
            if header.endswith("/*"):
                self.prefixes.append((header[:-1], library))
            else:
                self.exact[header] = library
        self.prefixes.sort(key=lambda x: (-len(x[0]), x[0]))
        self.system = set(inc_map.get("system_headers") or [])
        self.link_names: Dict[str, str] = dict(inc_map.get("link_names") or {})
        templates = (data.inventory.get("generated_macros") or {}).get("templates") or []
        self.generated_headers: Set[str] = set()
        for template in templates:
            name = posixpath.basename(str(template.get("path", "")))
            for suffix in (".in", ".cmake"):
                if name.endswith(suffix):
                    self.generated_headers.add(name[:-len(suffix)])
        self.generated_headers.update(("config.h", "autoconf.h"))
        self._extra_dirs = self._include_dir_evidence()
        self._cache: Dict[Tuple[str, str, bool], Resolution] = {}
        self._dirs_cache: Dict[str, List[str]] = {}

    def _include_dir_evidence(self) -> List[str]:
        out: List[str] = []
        for rec in self.data.evidence:
            if rec.get("type") == "INCLUDE_DIR" and isinstance(rec.get("value"), str):
                base = norm_dir(parent_dir(str(rec.get("path") or "")))
                expanded = expand_dir(rec["value"], base)
                if expanded is not None and expanded not in out:
                    out.append(expanded)
        return out

    # ------------------------------------------------------------------ library lookup
    def library_for(self, header: str) -> Optional[str]:
        if header in self.exact:
            return self.exact[header]
        for prefix, library in self.prefixes:
            if header.startswith(prefix):
                return library
        return None

    def candidates_for_library(self, library: str, from_path: str) -> List[str]:
        """Ids of the candidates of that identity, best first: in-tree (nearest), declared/fetched, other."""
        key = norm.norm_library(library)
        matches = []
        for cand in self.data.candidates:
            keys = {cand.get("norm_name"), norm.norm_library(str(cand.get("name", ""))),
                    norm.norm_library(str(cand.get("map_entry") or ""))}
            if key and key in keys and cand.get("detected_as") != "declared_unresolved":
                matches.append(cand)
        if not matches:
            return []

        def rank(cand: Dict[str, Any]) -> Tuple[int, int, str]:
            kind = cand.get("detected_as")
            tier = 0 if kind in IN_TREE else (1 if kind in FETCHED_OR_DECLARED else 2)
            directory = candidate_dir(cand) or self.data.file_of.get(cand["id"]) or ""
            common = len(posixpath.commonprefix([directory + "/", from_path])) if directory else 0
            return (tier, -common, cand["id"])

        matches.sort(key=rank)
        return [c["id"] for c in matches]

    # ------------------------------------------------------------------ resolution
    def resolve(self, path: str, header: str, angle: bool) -> Resolution:
        key = (path, header, angle)
        if key in self._cache:
            return self._cache[key]
        result = self._resolve(path, header, angle)
        self._cache[key] = result
        return result

    def _file_resolution(self, found: str, kind_hint: str = "file") -> Resolution:
        owner = self.data.owner_of(found)
        return Resolution("file", path=found, cands=[owner] if owner else [])

    def _resolve(self, path: str, header: str, angle: bool) -> Resolution:
        data = self.data
        clean = header.replace("\\", "/").strip()
        bare = _strip_dots(clean)
        # (1) quoted includes relative to the including file
        if not angle:
            rel = posixpath.normpath(posixpath.join(parent_dir(path), clean))
            if not rel.startswith("..") and rel in data.tracked:
                return self._file_resolution(rel)
        # (2) include directories of the targets that compile the file, then every INCLUDE_DIR
        if path not in self._dirs_cache:
            self._dirs_cache[path] = self.build.include_dirs_for(path) + list(self._extra_dirs)
        for directory in self._dirs_cache[path]:
            probe = posixpath.normpath(posixpath.join(directory, clean)) if directory else posixpath.normpath(clean)
            if not probe.startswith("..") and probe in data.tracked:
                return self._file_resolution(probe)
        # a header the configure step generates (config.h ...) is never searched for among vendored copies
        base = posixpath.basename(bare)
        if base in self.generated_headers and bare == base:
            return Resolution("generated")
        # (3) shortest tracked path ending in /<header> inside a candidate directory (ties: lexicographic, ambiguity noted)
        suffix = "/" + bare
        matches = [p for p in data.by_basename.get(base, []) if p.endswith(suffix) or p == bare]
        inside = [p for p in matches if data.owner_of(p) is not None]
        if inside:
            shortest = min(len(p) for p in inside)
            tied = sorted(p for p in inside if len(p) == shortest)
            first_owner = data.owner_of(tied[0])
            owners = sorted({data.owner_of(p) for p in tied if data.owner_of(p) != first_owner})
            return Resolution("file", path=tied[0], cands=[first_owner], ambiguous=owners)
        # (3b) quoted include of a first-party header elsewhere in the repository
        if not angle:
            outside = sorted((p for p in matches if data.owner_of(p) is None), key=lambda p: (len(p), p))
            if outside:
                return Resolution("file", path=outside[0])
        # (4) include_map.json (exact header, then dir/*)
        library = self.library_for(bare)
        if library:
            cands = self.candidates_for_library(library, path)
            return Resolution("library", cands=cands[:1], library=library)
        # (5) system headers are ignored
        if bare in self.system or (angle and "." not in bare) or bare.startswith(("bits/", "sys/", "linux/")):
            return Resolution("system")
        if posixpath.basename(bare) in self.generated_headers:
            return Resolution("generated")
        return Resolution("unresolved")


def _strip_dots(header: str) -> str:
    """``./a/b.h`` and ``../a/b.h`` -> ``a/b.h`` (the part that can be matched against a path suffix)."""
    parts = [p for p in header.split("/") if p not in ("", ".", "..")]
    return "/".join(parts)


def _asset_exists(ctx: RunContext, name: str) -> bool:
    import os
    return os.path.isfile(os.path.join(str(ctx.layout.assets), name))


# ------------------------------------------------------------------------------------------------ API identifiers

class IdentSet:
    """Strong and weak identifier patterns of one candidate (a trailing ``*`` is a prefix)."""

    def __init__(self, strong: Iterable[str] = (), weak: Iterable[str] = ()) -> None:
        self.strong_names: Set[str] = set()
        self.strong_prefixes: List[str] = []
        self.weak_names: Set[str] = set()
        self.weak_prefixes: List[str] = []
        for pattern in strong:
            self._add(pattern, self.strong_names, self.strong_prefixes)
        for pattern in weak:
            self._add(pattern, self.weak_names, self.weak_prefixes)

    @staticmethod
    def _add(pattern: str, names: Set[str], prefixes: List[str]) -> None:
        pattern = pattern.strip()
        if not pattern:
            return
        if pattern.endswith("*"):
            if pattern[:-1] not in prefixes:
                prefixes.append(pattern[:-1])
        else:
            names.add(pattern)

    @property
    def names(self) -> Set[str]:
        return self.strong_names | self.weak_names

    @property
    def prefixes(self) -> List[str]:
        return self.strong_prefixes + self.weak_prefixes

    def empty(self) -> bool:
        return not (self.names or self.prefixes)

    @staticmethod
    def _match(token: str, names: Set[str], prefixes: Sequence[str]) -> bool:
        """Exact name or prefix; patterns without ``::`` also match the last ``::`` component of a qualified token."""
        last = token.rsplit("::", 1)[-1] if "::" in token else None
        for name in names:
            if name == token or ("::" not in name and last is not None and name == last):
                return True
        for prefix in prefixes:
            if token.startswith(prefix) or ("::" not in prefix and last is not None and last.startswith(prefix)):
                return True
        return False

    def classify(self, token: str) -> Optional[str]:
        if self._match(token, self.strong_names, self.strong_prefixes):
            return "strong"
        if self._match(token, self.weak_names, self.weak_prefixes):
            return "weak"
        return None


def load_api_idents(ctx: RunContext) -> Dict[str, Dict[str, List[str]]]:
    try:
        doc = ctx.asset("api_idents.json")
    except Exception:                                            # a missing asset only disables the curated idents
        return {}
    libraries = doc.get("libraries") if isinstance(doc, dict) else None
    return dict(libraries or {})


_KEYWORDS = frozenset(("if", "else", "while", "for", "switch", "return", "sizeof", "typeof", "defined", "case", "do",
                       "goto", "new", "delete", "throw", "catch", "static_assert", "alignof", "decltype", "operator",
                       "__attribute__", "__declspec", "_Static_assert", "assert", "va_arg", "va_start", "va_end"))
_FUNC_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")
_DEFINE_FN_RE = re.compile(r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)\(")
_TRAILING_WORD_RE = re.compile(r"([A-Za-z_]\w*)$")


def derive_idents(header_texts: Iterable[str]) -> IdentSet:
    """Identifiers from in-tree headers: function-like declarations and macros; the most common ``prefix_`` carried by at
    least three names becomes strong (as a prefix), every other name weak (section 6.10)."""
    from sbomlib import csource
    names: Set[str] = set()
    for text in header_texts:
        stripped = csource.strip_comments_and_strings(text)
        for match in _DEFINE_FN_RE.finditer(stripped):
            names.add(match.group(1))
        for match in _FUNC_RE.finditer(stripped):
            name = match.group(1)
            if name in _KEYWORDS:
                continue
            end = match.start() - 1
            while end >= 0 and stripped[end].isspace():
                end -= 1
            if end < 0:
                continue
            last = stripped[end]
            if not (last.isalnum() or last in "_*&>"):
                continue
            word = _TRAILING_WORD_RE.search(stripped[max(0, end - 64):end + 1])
            if word and word.group(1) in _KEYWORDS:
                continue
            names.add(name)
    counts: Dict[str, int] = {}
    for name in names:
        cut = name.find("_", 1)
        if cut > 0:
            counts[name[:cut + 1]] = counts.get(name[:cut + 1], 0) + 1
    strong: List[str] = []
    best = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if best and best[0][1] >= 3:
        strong.append(best[0][0] + "*")
    prefix = best[0][0] if (best and best[0][1] >= 3) else None
    weak = sorted(n for n in names if not (prefix and n.startswith(prefix)))[:60]
    return IdentSet(strong, weak)

# ------------------------------------------------------------------------------------------------------- sites

class Site:
    """A verification record (``INCLUDE`` or ``API_HIT``) with the context the rule engine needs."""

    __slots__ = ("rec", "cand", "file", "origin", "compiled", "scope", "status", "terms", "ambiguous", "header_only_code")

    def __init__(self, rec: Dict[str, Any], cand: str, file: str, origin: Optional[str], compiled: str, scope: str,
                 status: Dict[str, str], terms: List[str], ambiguous: Sequence[str] = (),
                 header_only_code: bool = False) -> None:
        self.rec = rec
        self.cand = cand
        self.file = file
        self.origin = origin              # id of the candidate whose file this is; None for a first-party file
        self.compiled = compiled          # yes | assumed | no | unknown
        self.scope = scope
        self.status = status              # configuration -> condition value
        self.terms = terms
        self.ambiguous = list(ambiguous)  # other candidates the include landed in (a tie of section 6.10 step 3)
        self.header_only_code = header_only_code

    @property
    def positive(self) -> bool:
        """The file is (assumed to be) compiled, so the record counts as use evidence."""
        return self.compiled in ("yes", "assumed")


class Scan:
    """Everything ``Scanner.run`` found (kept in memory for the rule engine, persisted as ``verify_evidence.jsonl``)."""

    def __init__(self) -> None:
        self.includes: List[Site] = []
        self.hits: List[Site] = []
        self.unresolved: List[Tuple[str, int, str]] = []
        self.unreadable: List[str] = []
        self.assumed = False
        self.sources_named = False
        self.coverage_sources = "complete"
        self.compiled_files: Dict[str, str] = {}
        self.header_only_code: Dict[str, bool] = {}
        self.idents: Dict[str, IdentSet] = {}
        self.guard_cache: Dict[Tuple[str, str], Tuple[str, List[str]]] = {}

    @property
    def records(self) -> List[Dict[str, Any]]:
        return [s.rec for s in self.includes] + [s.rec for s in self.hits]


def _quote_hash(raw_lines: Sequence[bytes], line: int) -> Optional[str]:
    if 1 <= line <= len(raw_lines):
        return hashlib.sha256(raw_lines[line - 1].rstrip(b"\r")).hexdigest()
    return None


def _line_text(raw_lines: Sequence[bytes], line: int) -> str:
    if 1 <= line <= len(raw_lines):
        return decode_text(raw_lines[line - 1].rstrip(b"\r")).strip()[:model.DETAIL_MAX]
    return ""


_RANK_STATE = {"yes": 3, "assumed": 2, "unknown": 1, "no": 0}


class Scanner:
    """Include resolution, include closure, compiled status and API-identifier attribution for one repository."""

    def __init__(self, ctx: RunContext, data: RepoData, build: Build) -> None:
        self.ctx = ctx
        self.data = data
        self.build = build
        self.resolver = IncludeResolver(ctx, data, build)
        self.scan = Scan()
        self.api = load_api_idents(ctx)
        self._api_by_norm = {norm.norm_library(name): entry for name, entry in self.api.items()}
        self.includes_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for path, entries in (data.inventory.get("includes") or {}).items():
            self.includes_by_file[norm.normalize_path(str(path))] = [e for e in entries or [] if isinstance(e, dict)]
        self._resolved: Dict[str, List[Tuple[Dict[str, Any], Resolution]]] = {}
        self._closure: Dict[str, Tuple[List[str], Dict[str, List[Tuple[str, Dict[str, Any], Resolution]]]]] = {}
        self._compiled_cfg: Dict[str, Dict[str, Tuple[str, str]]] = {}
        self._defs_cache: Dict[str, List[Dict[str, Any]]] = {}
        self._nonproduct_scopes: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------------ resolution graph
    def resolved(self, path: str) -> List[Tuple[Dict[str, Any], Resolution]]:
        if path not in self._resolved:
            self._resolved[path] = [(inc, self.resolver.resolve(path, str(inc.get("header", "")), bool(inc.get("angle"))))
                                    for inc in self.includes_by_file.get(path, []) if inc.get("header")]
        return self._resolved[path]

    def owner(self, path: str) -> Optional[str]:
        return self.data.owner_of(path)

    @staticmethod
    def landing(res: Resolution) -> List[str]:
        """Candidates an include lands in: the chosen one first, then the tied ones (ambiguity)."""
        out: List[str] = []
        for cid in res.cands + res.ambiguous:
            if cid not in out:
                out.append(cid)
        return out

    def closure(self, path: str) -> Tuple[List[str], Dict[str, List[Tuple[str, Dict[str, Any], Resolution]]]]:
        """Files reachable from ``path`` through resolved includes that stay in the same owner scope (depth <= 10) and,
        for each candidate included by any of them, the include sites ``(file, include, resolution)``."""
        if path in self._closure:
            return self._closure[path]
        scope_owner = self.owner(path)
        order: List[str] = []
        seen: Set[str] = set()
        sites: Dict[str, List[Tuple[str, Dict[str, Any], Resolution]]] = {}
        frontier = [path]
        depth = 0
        while frontier and depth <= MAX_CLOSURE_DEPTH:
            nxt: List[str] = []
            for current in frontier:
                if current in seen:
                    continue
                seen.add(current)
                order.append(current)
                for inc, res in self.resolved(current):
                    for cid in self.landing(res):
                        if cid != scope_owner:
                            sites.setdefault(cid, []).append((current, inc, res))
                    if res.kind == "file" and res.path and self.owner(res.path) == scope_owner and res.path not in seen:
                        nxt.append(res.path)
            frontier = nxt
            depth += 1
        self._closure[path] = (order, sites)
        return self._closure[path]

    # ------------------------------------------------------------------ compiled status
    def _first_party_c_sources(self) -> List[str]:
        return [p for p in sorted(self.data.tracked) if is_source_file(p) and self.owner(p) is None]

    def _extra_named(self) -> Dict[str, str]:
        """Sources named by by-product ``COMPILE_LIST`` records that no target explains (path -> scope)."""
        out: Dict[str, str] = {}
        for rec in self.data.evidence:
            if rec.get("type") != "COMPILE_LIST" or rec.get("strength") != "strong":
                continue
            path = compile_source(rec)
            if not path or self.build.resolve_target(rec.get("target"), path) is not None:
                continue
            out[path] = rec.get("scope") or "product"
        return out

    def _decide_assumed(self) -> None:
        """``coverage.sources`` input: does any covered build name sources? If none, product sources count as compiled."""
        scan = self.scan
        scan.sources_named = self.build.names_any_source() or bool(self._extra_named())
        has_product_source = any(path_scope(p, self.data.test_dirs) == "product" for p in self._first_party_c_sources())
        covered = self.data.buildmodel.get("coverage") != "none"
        scan.assumed = bool(not scan.sources_named and covered and has_product_source)

    def _build_compiled_tables(self, files: Sequence[str]) -> None:
        """Per-configuration compile values of every source in ``files`` and, through the closure, of the headers they pull in."""
        build = self.build
        extra = self._extra_named()
        assumed = self.scan.assumed
        by_source = build.by_source()
        sources = [p for p in files if is_source_file(p)]
        table: Dict[str, Dict[str, Tuple[str, str]]] = {}
        state: Dict[str, str] = {}
        for src in sources:
            self.ctx.check_deadline()
            per_cfg: Dict[str, Tuple[str, str]] = {}
            for config in build.configs:
                prod, test = build.source_values(src, config)
                if src in extra:
                    if extra[src] == "test":
                        test = any_of([test, ENABLED])
                    else:
                        prod = any_of([prod, ENABLED])
                elif assumed and src not in by_source and self.owner(src) is None:
                    if path_scope(src, self.data.test_dirs) == "product":
                        prod = ENABLED
                    else:
                        test = ENABLED
                per_cfg[config] = (prod, test)
            table[src] = per_cfg
            if src in by_source or src in extra:
                state[src] = "yes"
            elif assumed and self.owner(src) is None:
                state[src] = "assumed"
            else:
                state[src] = "no" if self.scan.sources_named else "unknown"
        headers: Dict[str, Dict[str, Tuple[str, str]]] = {}
        header_state: Dict[str, str] = {}
        for src in sources:
            order, _ = self.closure(src)
            src_scopes = build.source_scopes(src) - {"product"}
            if src_scopes:
                self._nonproduct_scopes.setdefault(src, set()).update(src_scopes)
            for member in order:
                if src_scopes:
                    self._nonproduct_scopes.setdefault(member, set()).update(src_scopes)
                if member == src:
                    continue
                cur = headers.setdefault(member, {c: (DISABLED, DISABLED) for c in build.configs})
                for config in build.configs:
                    p0, t0 = cur[config]
                    p1, t1 = table[src][config]
                    cur[config] = (any_of([p0, p1]), any_of([t0, t1]))
                if _RANK_STATE[state[src]] > _RANK_STATE.get(header_state.get(member, "no"), 0):
                    header_state[member] = state[src]
        for path, per_cfg in table.items():
            self._compiled_cfg[path] = per_cfg
            self.scan.compiled_files[path] = state[path]
        for path, per_cfg in headers.items():
            if path not in self._compiled_cfg:
                self._compiled_cfg[path] = per_cfg
                self.scan.compiled_files[path] = header_state.get(path, "no")

    def compiled_state(self, path: str) -> str:
        found = self.scan.compiled_files.get(path)
        if found is not None:
            return found
        return "no" if self.scan.sources_named else "unknown"

    # ------------------------------------------------------------------ macro context and guards
    def _definitions_for(self, path: str) -> List[Dict[str, Any]]:
        if path in self._defs_cache:
            return self._defs_cache[path]
        build = self.build
        defs: List[Dict[str, Any]] = []
        indices = [i for i, _ in build.by_source().get(path, [])]
        if not indices:
            indices = build.governing(parent_dir(path))
        for index in indices:
            target = build.targets[index]
            for definition in target.get("definitions") or []:
                if isinstance(definition, dict) and definition.get("name"):
                    defs.append({"name": definition["name"],
                                 "condition": configs.conjoin(target.get("condition"), definition.get("condition"))})
        for definition in (self.data.buildmodel.get("globals") or {}).get("definitions") or []:
            if isinstance(definition, dict) and definition.get("name"):
                defs.append({"name": definition["name"], "condition": definition.get("condition")})
        self._defs_cache[path] = defs
        return defs

    def guard_status(self, path: str, guards: Sequence[str], config: str) -> Tuple[str, List[str]]:
        if not guards:
            return ENABLED, []
        key = (path, "|".join(guards) + "#" + config)
        cached = self.scan.guard_cache.get(key)
        if cached is not None:
            return cached
        order, _ = self.closure(path)
        ctx_macros = configs.macro_context(self.data.buildmodel, self.data.inventory, self.build.vars.get(config) or {},
                                           definitions=self._definitions_for(path), closure_files=order)
        result = configs.guard_value(list(guards), config, ctx_macros)
        self.scan.guard_cache[key] = result
        return result

    # ------------------------------------------------------------------ file facts
    def file_scope(self, path: str) -> str:
        owner = self.owner(path)
        if owner is not None:
            return path_scope(path, (), base=self.data.dir_of.get(owner) or "")
        klass = self.data.file_class.get(path)
        if klass in ("test", "dev"):
            return klass
        return path_scope(path, self.data.test_dirs)

    def file_values(self, path: str) -> Tuple[Dict[str, str], str, str]:
        """``(per-configuration compile value, scope, compiled state)`` of a file; a product file that only test targets
        compile has scope ``test``."""
        per_cfg = self._compiled_cfg.get(path, {})
        state = self.compiled_state(path)
        scope = self.file_scope(path)
        prod_any = any(p != DISABLED for p, _ in per_cfg.values())
        test_any = any(t != DISABLED for _, t in per_cfg.values())
        if scope == "product" and state in ("yes", "assumed") and not prod_any and test_any:
            scope = "test" if "test" in self._nonproduct_scopes.get(path, {"test"}) else "dev"
        values: Dict[str, str] = {}
        for config in self.build.configs:
            prod, test = per_cfg.get(config, (DISABLED, DISABLED))
            values[config] = prod if scope == "product" else any_of([prod, test])
        return values, scope, state

    def code_status(self, path: str, guards: Sequence[str]) -> Tuple[Dict[str, str], List[str], str, str]:
        """``(status per configuration, platform terms, scope, compiled state)`` of code at ``path`` under ``guards``."""
        values, scope, state = self.file_values(path)
        status: Dict[str, str] = {}
        terms: List[str] = []
        for config in self.build.configs:
            gval, gterms = self.guard_status(path, guards, config)
            status[config] = combine([values.get(config, DISABLED), gval])
            for term in gterms:
                if term not in terms:
                    terms.append(term)
        return status, sorted(terms), scope, state

    # ------------------------------------------------------------------ candidate facts
    def candidate_idents(self, cand: Dict[str, Any]) -> IdentSet:
        cid = cand["id"]
        if cid in self.scan.idents:
            return self.scan.idents[cid]
        entry = None
        for key in (cand.get("map_entry"), cand.get("name"), cand.get("norm_name")):
            if key and norm.norm_library(str(key)) in self._api_by_norm:
                entry = self._api_by_norm[norm.norm_library(str(key))]
                break
        if entry is not None:
            idents = IdentSet(entry.get("strong") or [], entry.get("weak") or [])
        elif self.data.in_tree(cand):
            texts = []
            for rel in self._candidate_headers(cand)[:MAX_DERIVE_HEADERS]:
                raw = read_target_bytes(self.data.repo_dir, rel)
                if raw is not None:
                    texts.append(decode_text(raw))
            idents = derive_idents(texts)
        else:
            idents = IdentSet()
        self.scan.idents[cid] = idents
        return idents

    def _candidate_headers(self, cand: Dict[str, Any]) -> List[str]:
        cid = cand["id"]
        directory = self.data.dir_of.get(cid)
        single = self.data.file_of.get(cid)
        if single:
            return [single] if is_header_file(single) else []
        if not directory:
            return []
        files = [p for p in self.data.tracked if p.startswith(directory + "/") and is_header_file(p)
                 and self.data.owner_of(p) == cid and path_scope(p, (), base=directory) == "product"]
        return sorted(files, key=lambda p: (len(p), p))

    def is_header_only_with_code(self, cand: Dict[str, Any]) -> bool:
        """In-tree, no product source files of its own, and a header with a function body, inline definition, template
        or function-like macro (section 6.10: the header-only ``USED`` kind requires code in the header)."""
        cid = cand["id"]
        if cid in self.scan.header_only_code:
            return self.scan.header_only_code[cid]
        result = False
        if self.data.in_tree(cand):
            from sbomlib import csource
            directory = self.data.dir_of.get(cid)
            single = self.data.file_of.get(cid)
            headers = self._candidate_headers(cand)
            if single:
                result = bool(headers)
            elif directory:
                has_sources = any(is_source_file(p) and p.startswith(directory + "/") and self.data.owner_of(p) == cid
                                  and path_scope(p, (), base=directory) == "product" for p in self.data.tracked)
                result = bool(headers) and not has_sources
            if result:
                result = False
                for rel in headers[:MAX_DERIVE_HEADERS]:
                    raw = read_target_bytes(self.data.repo_dir, rel)
                    if raw is not None and csource.has_code_in_header(decode_text(raw)):
                        result = True
                        break
        self.scan.header_only_code[cid] = result
        return result

    def has_sources(self, cand: Dict[str, Any]) -> bool:
        """The candidate owns at least one product C/C++ source file."""
        cid = cand["id"]
        return any(is_source_file(p) and self.data.owner_of(p) == cid for p in self.data.tracked)

    # ------------------------------------------------------------------ the scan
    def run(self) -> Scan:
        scan = self.scan
        self._decide_assumed()
        files = sorted(self.includes_by_file)
        tables = sorted(set([p for p in files if is_source_file(p)] + [p for p in self.build.by_source() if is_source_file(p)]
                            + list(self._extra_named())))
        self._build_compiled_tables(tables)
        for path in files:
            if self.owner(path) is None:
                for inc, res in self.resolved(path):
                    if res.kind == "unresolved":
                        scan.unresolved.append((path, int(inc.get("line") or 0), str(inc.get("header"))))
        include_sites: List[Site] = []
        hit_sites: List[Site] = []
        for path in files:
            self.ctx.check_deadline()
            self._scan_file(path, include_sites, hit_sites)
        self._flag_unscannable()
        scan.includes = self._cap(include_sites, MAX_INCLUDE_RECORDS_PER_CANDIDATE)
        scan.hits = self._cap(hit_sites, MAX_HIT_RECORDS_PER_CANDIDATE)
        self._dedupe_ids(scan.includes + scan.hits)
        self._coverage()
        return scan

    def _flag_unscannable(self) -> None:
        """First-party C/C++ files that discovery and this phase cannot read (symlinks, over the 2 MiB scan cap) are named
        so the coverage is not reported as complete."""
        sizes = {norm.normalize_path(str(f.get("path", ""))): f for f in self.data.inventory.get("files") or []
                 if isinstance(f, dict)}
        for path in sorted(sizes):
            entry = sizes[path]
            if not is_c_family(path) or self.owner(path) is not None:
                continue
            size = entry.get("size")
            if entry.get("mode") == "120000" or (isinstance(size, int) and size > TEXT_SCAN_CAP):
                if path not in self.scan.unreadable:
                    self.scan.unreadable.append(path)

    @staticmethod
    def _cap(sites: List[Site], limit: int) -> List[Site]:
        by_cand: Dict[str, List[Site]] = {}
        for site in sites:
            by_cand.setdefault(site.cand, []).append(site)
        out: List[Site] = []
        for cid in sorted(by_cand):
            group = by_cand[cid]

            def key(s: Site) -> Tuple[int, int, int, str, int]:
                useful = 0 if s.positive else 1
                enabled = 0 if any(is_enabled(v) for v in s.status.values()) else 1
                weak = 0 if s.rec.get("weight") != "weak" else 1
                return (useful, enabled, weak * 2 + (0 if s.origin is None else 1), s.file, s.rec.get("line") or 0)

            group.sort(key=key)
            out.extend(group[:limit])
        out.sort(key=lambda s: (s.file, s.rec.get("line") or 0, s.rec["type"], s.cand, s.rec.get("symbol") or ""))
        return out

    @staticmethod
    def _dedupe_ids(sites: List[Site]) -> None:
        """Section 6.3: a colliding id gets the suffix -2, -3, ... in (path, line, type, symbol) order."""
        seen: Dict[str, int] = {}
        for site in sorted(sites, key=lambda s: (s.file, s.rec.get("line") or 0, s.rec["type"], s.rec.get("symbol") or "",
                                                 s.cand)):
            rid = site.rec["id"]
            count = seen.get(rid, 0) + 1
            seen[rid] = count
            if count > 1:
                site.rec["id"] = "%s-%d" % (rid, count)

    def _coverage(self) -> None:
        """``coverage.sources``: complete (the build names the compiled sources and every file was scanned), assumed (the
        covered build names no sources, so product sources count as compiled), partial otherwise."""
        scan = self.scan
        build_cov = self.data.buildmodel.get("coverage")
        if scan.unreadable or build_cov == "none":
            scan.coverage_sources = "partial"
        elif scan.assumed:
            scan.coverage_sources = "assumed"
        elif not scan.sources_named:
            scan.coverage_sources = "complete"            # nothing product-scope to compile
        elif build_cov == "partial":
            scan.coverage_sources = "partial"
        else:
            scan.coverage_sources = "complete"

    # ------------------------------------------------------------------ per-file scanning
    def _value(self, state: str, owner: Optional[str], status: Dict[str, str], terms: Sequence[str],
               **extra: Any) -> Dict[str, Any]:
        configs_all = self.build.configs
        out: Dict[str, Any] = {
            "compiled": state, "origin": owner,
            "enabled_in": [c for c in configs_all if is_enabled(status.get(c, DISABLED))],
            "disabled_in": [c for c in configs_all if status.get(c, DISABLED) == DISABLED],
            "unknown_in": [c for c in configs_all if status.get(c, DISABLED) == UNKNOWN]}
        if terms:
            out["terms"] = list(terms)
        for key, val in extra.items():
            if val not in (None, [], False):
                out[key] = val
        return out

    def _scan_file(self, path: str, include_sites: List[Site], hit_sites: List[Site]) -> None:
        _order, cand_sites = self.closure(path)
        if not cand_sites:
            return
        owner = self.owner(path)
        raw = read_target_bytes(self.data.repo_dir, path)
        if raw is None:
            if owner is None:
                self.scan.unreadable.append(path)
            return
        raw_lines = raw.split(b"\n")
        repo = self.data.repo
        for inc, res in self.resolved(path):
            landing = [cid for cid in self.landing(res) if cid != owner]
            if not landing:
                continue
            line = int(inc.get("line") or 0)
            header = str(inc.get("header"))
            guards = list(inc.get("guards") or [])
            status, terms, scope, state = self.code_status(path, guards)
            tied = len(landing) > 1
            for cid in landing:
                header_only = self.is_header_only_with_code(self.data.cand_by_id[cid])
                others = [x for x in landing if x != cid] if tied else []
                quote = '<%s>' % header if inc.get("angle") else '"%s"' % header
                rec = model.new_evidence(
                    id=ids.evidence_id("u", repo, "INCLUDE", path, line, header, cid), repo=repo, type="INCLUDE",
                    candidate=cid, path=path, line=line, symbol=header,
                    detail=_line_text(raw_lines, line) or "#include " + quote,
                    quote_sha256=_quote_hash(raw_lines, line), guards=guards, scope=scope)
                rec["value"] = self._value(state, owner, status, terms, header=header, resolved=res.path,
                                           ambiguous=others, header_only_code=header_only)
                include_sites.append(Site(rec, cid, path, owner, state, scope, status, terms, others, header_only))
        self._scan_identifiers(path, raw, raw_lines, cand_sites, owner, hit_sites)

    def _scan_identifiers(self, path: str, raw: bytes, raw_lines: Sequence[bytes],
                          cand_sites: Dict[str, List[Tuple[str, Dict[str, Any], Resolution]]], owner: Optional[str],
                          hit_sites: List[Site]) -> None:
        """API hits of the candidates reachable through this file's include closure (section 6.10: an identifier counts
        for a candidate only when the file's include closure holds a header resolved to it)."""
        from sbomlib import csource
        idents: Dict[str, IdentSet] = {}
        for cid in sorted(cand_sites):
            if cid == owner:
                continue
            ident = self.candidate_idents(self.data.cand_by_id[cid])
            if not ident.empty():
                idents[cid] = ident
        if not idents:
            return
        names: Set[str] = set()
        prefixes: List[str] = []
        for ident in idents.values():
            names |= ident.names
            for prefix in ident.prefixes:
                if prefix not in prefixes:
                    prefixes.append(prefix)
        stripped = csource.strip_comments_and_strings(decode_text(raw))
        include_lines = {int(inc.get("line") or 0) for inc in self.includes_by_file.get(path, [])}
        repo = self.data.repo
        made: Dict[Tuple[str, str, Tuple[str, ...]], Site] = {}
        counts: Dict[Tuple[str, str], int] = {}
        for line, token, guards in csource.scan_identifiers(stripped, names, prefixes):
            if line in include_lines:
                continue
            for cid in sorted(idents):
                weight = idents[cid].classify(token)
                if weight is None:
                    continue
                counts[(cid, token)] = counts.get((cid, token), 0) + 1
                key = (cid, token, tuple(guards))
                if key in made:
                    continue
                status, terms, scope, state = self.code_status(path, guards)
                rec = model.new_evidence(
                    id=ids.evidence_id("u", repo, "API_HIT", path, line, token, cid), repo=repo, type="API_HIT",
                    candidate=cid, path=path, line=line, symbol=token, detail=_line_text(raw_lines, line),
                    quote_sha256=_quote_hash(raw_lines, line), guards=list(guards), scope=scope, weight=weight)
                rec["value"] = self._value(state, owner, status, terms)
                site = Site(rec, cid, path, owner, state, scope, status, terms)
                made[key] = site
                hit_sites.append(site)
        for (cid, token, _), site in made.items():
            total = counts.get((cid, token), 0)
            if total > 1:
                site.rec["value"]["count"] = total
