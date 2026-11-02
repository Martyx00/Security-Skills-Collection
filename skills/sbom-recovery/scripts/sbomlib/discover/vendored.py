"""Vendored directories and single-file libraries: identity and version from the tree (contract section 3.9).

A *candidate directory* is a child of a vendored parent directory (``third_party``, ``vendor`` ...), a directory in which
``version_rules.json`` finds a library (``zlib.h`` with ``ZLIB_VERSION`` ...), the directory of a ``README.chromium`` or a
submodule path. Identity comes from, in this order: a version rule (macro, parts, banner, ``project()`` name, template),
``include_map.json`` header ownership, the ``project()`` / ``AC_INIT`` / Meson name inside the directory, the directory
name. Versions come from the rules, ``*.in`` templates with a companion ``VERSION.dat`` / ``VERSION``, and the
directory's own ``project(VERSION)`` / ``AC_INIT`` / Meson ``version:``. The miniz trap: miniz defines ``ZLIB_VERSION`` and
``MZ_VERSION`` with a private scheme, so its rule ignores those macros and reads the version from the banner.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from sbomlib import csource, versions
from sbomlib.discover import cmake
from sbomlib.discover import session as sess
from sbomlib.discover.session import Session
from sbomlib.norm import norm_library

INCLUDE_LIKE = frozenset(("include", "inc", "includes", "headers", "public", "src", "source", "sources", "lib"))
GENERIC_DIRS = INCLUDE_LIKE | frozenset(("app", "main", "core", "common", "util", "utils", "code", "platform", "port",
                                         "libs", "third_party", "thirdparty", "vendor", "external", "deps", "dep",
                                         "contrib", "extern"))
_PARTS_TMPL = r'#\s*define\s+%s\b[ \t]+\(?\s*"?(\d+)"?\s*\)?'
_AC_INIT_RE = re.compile(r"AC_INIT\s*\(\s*\[?([^\],()\n]*)\]?\s*,\s*\[?([^\],()\n]*)\]?", re.S)
_MESON_PROJECT_RE = re.compile(r"project\s*\(\s*'([^']+)'(?P<rest>.*?)\)", re.S)
_MESON_VERSION_RE = re.compile(r"version\s*:\s*'([^']+)'")
_VERSION_FILE_RE = re.compile(r"^\s*v?(\d+(?:\.\d+){1,3}[a-z]?(?:[-.]?(?:rc|alpha|beta)\.?\d*)?)\s*$", re.I)
_KEY_VALUE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_REGEX_CACHE: Dict[Tuple[str, int], "re.Pattern[str]"] = {}


def _rx(pattern: str, flags: int = re.M) -> "re.Pattern[str]":
    key = (pattern, flags)
    compiled = _REGEX_CACHE.get(key)
    if compiled is None:
        compiled = re.compile(pattern, flags)
        _REGEX_CACHE[key] = compiled
    return compiled


class RuleHit:
    """One finding of a version rule in one file."""

    def __init__(self, rule: Dict[str, Any], path: str, kind: str) -> None:
        self.rule = rule
        self.lib: str = rule["library"]
        self.path = path
        self.kind = kind                      # version | parts | identity | banner_version | project | template | placeholder | banner
        self.version: Optional[str] = None    # raw version text (joined parts)
        self.anchor = path                     # the file that decides which directory the hit belongs to
        self.lines: List[Tuple[int, str, str]] = []   # (line, symbol, value) records to quote
        self.detail: Optional[str] = None
        self.macros: List[str] = []

    @property
    def line(self) -> int:
        return self.lines[0][0] if self.lines else 1


class Plan:
    def __init__(self) -> None:
        self.hits: List[RuleHit] = []
        self.dirs: Dict[str, str] = {}                    # directory -> origin (parent | rule | readme | gitlink)
        self.single: Dict[Tuple[str, str], List[RuleHit]] = {}
        self.dir_hits: Dict[str, List[RuleHit]] = {}
        self.files_of: Dict[str, List[str]] = {}

    def owner_dir(self, path: str) -> Optional[str]:
        probe = posixpath.dirname(path)
        while probe:
            if probe in self.dirs:
                return probe
            probe = posixpath.dirname(probe)
        return None


# --------------------------------------------------------------------------------------------------- rule scanning

def _rule_index(S: Session) -> Dict[str, List[Dict[str, Any]]]:
    index: Dict[str, List[Dict[str, Any]]] = {}
    for rule in S.rules.get("rules", []):
        names = set(rule.get("files") or [])
        for template in rule.get("templates") or []:
            names.add(template["file"])
        for name in names:
            index.setdefault(name, []).append(rule)
    return index


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_rules(S: Session) -> List[RuleHit]:
    """Apply every version rule to the tracked files it names."""
    index = _rule_index(S)
    hits: List[RuleHit] = []
    if not index:
        return hits
    for base in sorted(index):
        for path in S.by_base.get(base, []):
            S.check_budget()
            text = S.fs.text(path)
            if text is None:
                continue
            stripped = csource.strip_comments(text) if base.endswith((".h", ".hpp", ".c", ".cc", ".in", ".hh", ".hxx")) else text
            for rule in index[base]:
                hits.extend(_apply_rule(S, rule, path, base, text, stripped))
    return hits


def _apply_rule(S: Session, rule: Dict[str, Any], path: str, base: str, raw: str, stripped: str) -> List[RuleHit]:
    out: List[RuleHit] = []
    excluded = any(token in stripped for token in rule.get("exclude_if") or [])
    placeholders = rule.get("placeholders") or []
    if base in (rule.get("files") or []):
        if rule.get("project_version") and base == "CMakeLists.txt":
            info = cmake.project_info(raw)
            if info is not None and info["name"] == rule["project_version"]:
                hit = RuleHit(rule, path, "project")
                hit.version = info["version"]
                hit.lines = [(info["version_line"] or info["line"], info["name"], info["version"] or "")]
                out.append(hit)
        if not excluded:
            patterns = list(rule.get("patterns") or ([rule["pattern"]] if rule.get("pattern") else []))
            for pattern in patterns:
                try:
                    match = _rx(pattern).search(stripped)
                except re.error:
                    continue
                if match is None or not match.groups():
                    continue
                raw_version = match.group(1)
                line = _line_of(stripped, match.start(1))
                macro = rule.get("macro") or (re.search(r"[A-Za-z_]\w+", match.group(0)) or match).group(0)
                if any(token in raw_version for token in placeholders):
                    hit = RuleHit(rule, path, "placeholder")
                    hit.detail = match.group(0)[:100]
                    hit.lines = [(line, macro, raw_version)]
                else:
                    hit = RuleHit(rule, path, "version")
                    hit.version = raw_version
                    hit.lines = [(line, macro, raw_version)]
                hit.macros = [macro]
                out.append(hit)
                break
            parts = rule.get("parts") or []
            if parts:
                found: List[Tuple[int, str, str]] = []
                for macro in parts:
                    match = _rx(_PARTS_TMPL % re.escape(macro)).search(stripped)
                    if match is not None:
                        found.append((_line_of(stripped, match.start(1)), macro, match.group(1)))
                if len(found) == len(parts):
                    hit = RuleHit(rule, path, "parts")
                    hit.version = ".".join(value for _l, _m, value in found)
                    hit.lines = found
                    hit.macros = list(parts)
                    out.append(hit)
                elif found:
                    hit = RuleHit(rule, path, "identity")
                    hit.lines = [found[0]]
                    hit.detail = "#define %s" % found[0][1]
                    out.append(hit)
        for banner in rule.get("banners") or []:
            match = re.search(re.escape(banner), raw, re.I)
            if match is not None:
                hit = RuleHit(rule, path, "banner")
                hit.lines = [(_line_of(raw, match.start()), "banner", rule["library"])]
                hit.detail = match.group(0)[:100]
                out.append(hit)
                break
        for pattern in rule.get("identity") or []:
            match = _rx(pattern).search(stripped)
            if match is not None:
                hit = RuleHit(rule, path, "identity")
                hit.lines = [(_line_of(stripped, match.start()), match.group(0).split()[-1], rule["library"])]
                hit.detail = match.group(0)[:100]
                out.append(hit)
                break
        if rule.get("banner_version"):
            match = _rx(rule["banner_version"]).search(raw)
            if match is not None and match.groups():
                hit = RuleHit(rule, path, "banner_version")
                hit.version = match.group(1)
                hit.lines = [(_line_of(raw, match.start(1)), "banner", match.group(1))]
                hit.detail = match.group(0)[:100]
                out.append(hit)
    for template in rule.get("templates") or []:
        if template["file"] != base:
            continue
        companion = _find_companion(S, path, template["companion"])
        if companion is None:
            hit = RuleHit(rule, path, "identity")
            hit.lines = [(1, "template", rule["library"])]
            hit.detail = "version template %s without companion %s" % (base, template["companion"])
            out.append(hit)
            continue
        hit = _template_hit(S, rule, template, path, companion)
        if hit is not None:
            out.append(hit)
    return out


def _find_companion(S: Session, template_path: str, name: str) -> Optional[str]:
    best: Optional[str] = None
    best_key: Optional[Tuple[int, int, str]] = None
    base_parts = posixpath.dirname(template_path).split("/")
    for candidate in S.by_base.get(name, []):
        cand_parts = posixpath.dirname(candidate).split("/") if posixpath.dirname(candidate) else []
        shared = 0
        for a, b in zip(base_parts, cand_parts):
            if a != b:
                break
            shared += 1
        if shared < len(cand_parts):
            continue                                    # the companion must be in the template's directory or above it
        key = (-shared, candidate.count("/"), candidate)
        if best_key is None or key < best_key:
            best, best_key = candidate, key
    return best


def _template_hit(S: Session, rule: Dict[str, Any], template: Dict[str, Any], path: str, companion: str) -> Optional[RuleHit]:
    text = S.fs.text(companion)
    if text is None:
        return None
    values: Dict[str, Tuple[int, str]] = {}
    for number, line in enumerate(text.split("\n"), start=1):
        match = _KEY_VALUE_RE.match(line)
        if match is not None:
            values[match.group(1)] = (number, match.group(2).strip().strip("\"'"))
    keys = template.get("keys") or []
    if not keys or any(k not in values or not values[k][1].isdigit() for k in keys):
        return None
    hit = RuleHit(rule, companion, "template")
    hit.anchor = path
    pieces = [values[k][1] for k in keys]
    lines = [(values[k][0], k, values[k][1]) for k in keys]
    pre = template.get("pre")
    version = ".".join(pieces)
    if pre and pre in values and values[pre][1]:
        version = "%s-%s" % (version, values[pre][1])
        lines.append((values[pre][0], pre, values[pre][1]))
    hit.version = version
    hit.lines = lines
    hit.detail = "from %s for template %s" % (companion, posixpath.basename(path))
    return hit


# --------------------------------------------------------------------------------------------------- directories

def _header_dirs(S: Session, lib: str) -> Set[str]:
    cached = getattr(S, "_header_dir_cache", None)
    if cached is None:
        cached = {}
        for key, owner in S.imap_data.get("headers", {}).items():
            if key.endswith("/*"):
                cached.setdefault(owner, set()).add(key[:-2].split("/")[0])
        setattr(S, "_header_dir_cache", cached)
    return cached.get(lib, set())


def climb(S: Session, directory: str, lib: str, stop_at: Optional[str]) -> str:
    """The project directory that holds a header found in ``directory`` (``include/curl`` -> the directory above)."""
    current = directory
    header_dirs = _header_dirs(S, lib)
    while current and current != stop_at:
        base = posixpath.basename(current)
        parent = posixpath.dirname(current)
        if base.lower() in INCLUDE_LIKE:
            current = parent
            continue
        if base in header_dirs and posixpath.basename(parent).lower() in INCLUDE_LIKE:
            current = posixpath.dirname(parent)
            continue
        break
    if stop_at and current and not (current == stop_at or current.startswith(stop_at + "/")):
        return stop_at
    return current


def _readme_chromium_dirs(S: Session) -> List[str]:
    return sorted({posixpath.dirname(p) for p in S.by_base.get("README.chromium", []) if posixpath.dirname(p)})


def plan(S: Session, vendored_children: List[str]) -> Plan:
    """Candidate directories and the rule hits that belong to each (or become single-file candidates)."""
    result = Plan()
    result.hits = scan_rules(S)
    for directory in vendored_children:
        result.dirs[directory] = "parent"
    for directory in _readme_chromium_dirs(S):
        if directory not in S.gitlink_paths:
            result.dirs.setdefault(directory, "readme")
    for gitlink in S.gitlink_paths:
        result.dirs[gitlink] = "gitlink"
    # rule hits that create directories or single files
    for hit in sorted(result.hits, key=lambda h: (h.anchor, h.rule["library"], h.kind)):
        enclosing = result.owner_dir(hit.anchor)
        target = climb(S, posixpath.dirname(hit.anchor), hit.lib, enclosing)
        if enclosing is not None and target == enclosing:
            continue                                              # belongs to the enclosing candidate directory
        generic = (not target) or posixpath.basename(target).lower() in GENERIC_DIRS
        if generic:
            if enclosing is None and hit.kind != "project":
                result.single.setdefault((hit.anchor, hit.lib), []).append(hit)
            continue
        if target not in result.dirs:
            result.dirs[target] = "rule"
    for hit in result.hits:
        owner = result.owner_dir(hit.anchor)
        if owner is not None:
            result.dir_hits.setdefault(owner, []).append(hit)
    # single-file hits inside a directory are not single files
    for key in list(result.single):
        if result.owner_dir(key[0]) is not None:
            del result.single[key]
    for path in S.paths:
        owner = result.owner_dir(path)
        if owner is not None:
            result.files_of.setdefault(owner, []).append(path)
    return result


def same_lib(S: Session, a: str, b: str) -> bool:
    return norm_library(S.identity.canonical(a)) == norm_library(S.identity.canonical(b))


# --------------------------------------------------------------------------------------------------- identity of a directory

def _project_names(S: Session, directory: str) -> List[Tuple[str, Optional[str], str, int, Optional[int]]]:
    """``(name, version, source, line, version_line)`` for the directory's own ``project()`` / ``AC_INIT`` / Meson project."""
    found: List[Tuple[str, Optional[str], str, int, Optional[int]]] = []
    prefix = directory + "/" if directory else ""
    text = S.fs.text(prefix + "CMakeLists.txt")
    if text is not None:
        info = cmake.project_info(text)
        if info is not None:
            found.append((info["name"], info["version"], prefix + "CMakeLists.txt", info["line"], info["version_line"]))
    for name in ("configure.ac", "configure.in"):
        text = S.fs.text(prefix + name)
        if text is None:
            continue
        stripped = re.sub(r"(?m)^\s*(?:dnl|#).*$", "", text)
        match = _AC_INIT_RE.search(stripped)
        if match is not None:
            pname = match.group(1).strip()
            pver = match.group(2).strip()
            line = _line_of(text, text.find("AC_INIT")) if "AC_INIT" in text else 1
            if pname and not pname.startswith(("m4_", "$", "AC_")):
                version = pver if re.match(r"^\d", pver) else None
                found.append((pname, version, prefix + name, line, line))
            break
    text = S.fs.text(prefix + "meson.build")
    if text is not None:
        match = _MESON_PROJECT_RE.search(text)
        if match is not None:
            version_match = _MESON_VERSION_RE.search(match.group("rest"))
            line = _line_of(text, match.start())
            version = version_match.group(1) if version_match and re.match(r"^\d", version_match.group(1)) else None
            found.append((match.group(1), version, prefix + "meson.build", line, line))
    return found


def _version_file(S: Session, directory: str) -> Optional[Tuple[str, int, str]]:
    prefix = directory + "/" if directory else ""
    for name in ("VERSION", "VERSION.txt", "version.txt"):
        path = prefix + name
        if not S.tracked(path):
            continue
        text = S.fs.text(path)
        if text is None or len(text) > 200:
            continue
        for number, line in enumerate(text.split("\n"), start=1):
            if not line.strip():
                continue
            match = _VERSION_FILE_RE.match(line)
            return (path, number, match.group(1)) if match else None
    return None


def _ownership(S: Session, files: List[str]) -> Dict[str, List[str]]:
    """``lib -> [header paths]`` for the headers of ``files`` that ``include_map`` assigns to a library."""
    owned: Dict[str, List[str]] = {}
    for path in files:
        if not sess.is_c_header(path):
            continue
        for lib in S.imap.path_libs(path):
            owned.setdefault(lib, []).append(path)
    return owned


def emit_hit(S: Session, cand: Dict[str, Any], hit: RuleHit, use_version: bool,
             ignored_macros: Set[str]) -> List[str]:
    """Evidence for one rule hit; returns the evidence ids that support a version (empty for identity-only records)."""
    version_ids: List[str] = []
    path = hit.path
    if hit.kind in ("version", "parts"):
        for line, macro, value in hit.lines:
            if macro in ignored_macros:
                continue
            evid = S.ev("VERSION_MACRO", path=path, line=line, symbol=macro, value=value, candidate=cand["id"])
            if use_version:
                version_ids.append(evid)
            else:
                S.reg.claim_identity(cand, hit.lib, [evid])
    elif hit.kind == "project":
        line, symbol, value = hit.lines[0]
        evid = S.ev("PROJECT_VERSION", path=path, line=line, symbol=symbol, value=value or None, candidate=cand["id"])
        S.reg.claim_identity(cand, hit.lib, [evid])
        if use_version and hit.version:
            version_ids.append(evid)
    elif hit.kind == "template":
        for line, key, value in hit.lines:
            evid = S.ev("VERSION_FILE", path=path, line=line, symbol=key, value=value, candidate=cand["id"],
                        detail=hit.detail)
            if use_version:
                version_ids.append(evid)
    elif hit.kind == "banner_version":
        line, symbol, value = hit.lines[0]
        evid = S.ev("BANNER", path=path, line=line, symbol=symbol, value=value, candidate=cand["id"], detail=hit.detail)
        if use_version:
            version_ids.append(evid)
    else:                                                         # identity | banner | placeholder
        line, symbol, value = hit.lines[0]
        evid = S.ev("BANNER", path=path, line=line, symbol=symbol, value=hit.lib, candidate=cand["id"], detail=hit.detail)
        S.reg.claim_identity(cand, hit.lib, [evid])
    return version_ids


def _version_channel(hit: RuleHit) -> Tuple[str, str]:
    if hit.kind == "banner_version":
        return "banner", "banner"
    if hit.kind == "template":
        return "version_file", "version_file"
    if hit.kind == "project":
        return "project_version", "project_version"
    return "header_macro", "header_macro"


def add_version_claims(S: Session, cand: Dict[str, Any], hits: List[RuleHit], lib: str, ignored: Set[str]) -> None:
    """Emit the evidence of ``hits`` and the version claims of those that name ``lib``."""
    for hit in sorted(hits, key=lambda h: (h.path, h.line, h.kind)):
        use = same_lib(S, hit.lib, lib)
        ids = emit_hit(S, cand, hit, use, ignored)
        if use and ids and hit.version:
            channel, source = _version_channel(hit)
            canon = versions.canonicalize(hit.version, library=lib, channel=channel, rules=S.rules)
            S.reg.claim_version(cand, canon, source, "tree", ids)
        elif use and hit.kind == "placeholder":
            canon = versions.canonicalize(hit.lines[0][2], library=lib, channel="header_macro", rules=S.rules)
            S.reg.claim_version(cand, canon, "header_macro", "tree", [])


def _generic_claims(S: Session, cand: Dict[str, Any], directory: str, lib: str, skip_project: bool) -> None:
    """``project(VERSION)`` / ``AC_INIT`` / Meson version and a ``VERSION`` file of the directory itself."""
    for name, version, path, line, version_line in _project_names(S, directory):
        if not version:
            continue
        if skip_project:
            continue
        evid = S.ev("PROJECT_VERSION", path=path, line=version_line or line, symbol=name, value=version, candidate=cand["id"])
        canon = versions.canonicalize(version, library=lib, channel="project_version", rules=S.rules)
        S.reg.claim_version(cand, canon, "project_version", "tree", [evid])
        break
    found = _version_file(S, directory)
    if found is not None:
        path, number, text = found
        evid = S.ev("VERSION_FILE", path=path, line=number, symbol=posixpath.basename(path), value=text, candidate=cand["id"])
        canon = versions.canonicalize(text, library=lib, channel="version_file", rules=S.rules)
        S.reg.claim_version(cand, canon, "version_file", "tree", [evid])


def resolve_identity(S: Session, directory: str, hits: List[RuleHit], owned: Dict[str, List[str]],
                     projects: List[Tuple[str, Optional[str], str, int, Optional[int]]]) -> Tuple[str, str, str, List[Tuple[str, str]]]:
    """``(name, source, confidence, claims)``: the chosen library name, where it came from, and every claim."""
    claims: List[Tuple[int, str, str]] = []                      # (rank, name, source)
    counts: Dict[str, int] = {}
    for hit in hits:
        counts[hit.lib] = counts.get(hit.lib, 0) + 1
    for lib, _count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        claims.append((0, lib, "rule"))
    for lib, _paths in sorted(owned.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        claims.append((1, lib, "header"))
    for name, _ver, _path, _line, _vline in projects:
        known = S.identity.canonical_or_none(name)
        claims.append((2 if known else 4, known or name, "project"))
    base = posixpath.basename(directory)
    cleaned = S.identity.clean_dir_name(base)
    known_dir = S.identity.resolve_name(cleaned, base)
    claims.append((3 if known_dir else 5, known_dir or cleaned, "dir"))
    claims.sort(key=lambda c: c[0])
    best_rank, best_name, best_source = claims[0]
    if best_rank == 0:
        strong = any(h.lib == best_name and h.kind in ("version", "parts", "template", "project") for h in hits)
        confidence = "high" if strong else "medium"
    elif best_rank <= 3:
        confidence = "medium"
    else:
        confidence = "low"
    return best_name, best_source, confidence, [(name, source) for _r, name, source in claims]


def _ignored_macros(S: Session, lib: str) -> Set[str]:
    for rule in S.rules.get("rules", []):
        if rule.get("library") == lib:
            return set(rule.get("ignore_macros") or [])
    return set()


def create_dir_candidates(S: Session, pl: Plan) -> None:
    """Candidates and evidence for the vendored and rule-found directories (submodule paths are handled by ``submodules``)."""
    for directory in sorted(pl.dirs):
        if pl.dirs[directory] == "gitlink":
            continue
        S.check_budget()
        files = pl.files_of.get(directory, [])
        hits = pl.dir_hits.get(directory, [])
        owned = _ownership(S, files)
        projects = _project_names(S, directory)
        name, source, confidence, claims = resolve_identity(S, directory, hits, owned, projects)
        canon = S.identity.canonical(name)
        entry = S.identity.map_entry_name(canon)
        base = posixpath.basename(directory)
        notes: List[str] = []
        fork_of: Optional[str] = None
        dir_known = S.identity.canonical_or_none(S.identity.clean_dir_name(base))
        if source in ("rule", "header") and norm_library(canon) not in (
                norm_library(S.identity.clean_dir_name(base)), norm_library(dir_known or "")) \
                and norm_library(S.identity.clean_dir_name(base)) not in ("src", "lib", "source", "sources"):
            fork_of = canon
            notes.append("vendored fork of %s" % canon)
        cand = S.reg.create(canon, "vendored", "dir", directory, None, map_entry=entry,
                            aliases=[base, S.identity.clean_dir_name(base)] + [p[0] for p in projects],
                            notes=notes, fork_of=fork_of, first_party=S.is_first_party_name(norm_library(canon)),
                            identity_confidence=confidence)
        upstream = S.identity.upstream_url(canon)
        if upstream and not cand["upstream"]["url"]:
            cand["upstream"]["url"] = upstream
        presence = S.ev("FILE_PRESENT", path=directory, symbol=source, value=directory, candidate=cand["id"],
                        detail="vendored directory (identity from %s)" % source, quote=False)
        S.reg.claim_identity(cand, canon, [presence])
        for alt, _alt_source in claims:
            if norm_library(alt) != norm_library(canon):
                S.reg.claim_identity(cand, S.identity.canonical(alt), [])
        ignored = _ignored_macros(S, canon)
        add_version_claims(S, cand, hits, canon, ignored)
        _generic_claims(S, cand, directory, canon, skip_project=False)
        _manifest_notes(S, cand, directory, files)


_OTHER_ECOSYSTEM = ("Cargo.lock", "package-lock.json", "yarn.lock", "go.sum", "Gemfile.lock", "poetry.lock", "composer.lock",
                    "pnpm-lock.yaml", "Pipfile.lock", "pubspec.lock")
_OWN_TOOLING = ("conanfile.txt", "conanfile.py", "conan.lock", "vcpkg.json", "west.yml", "idf_component.yml",
                "dependencies.lock", "MODULE.bazel", "platformio.ini", "spack.lock", "xmake-requires.lock")


def _manifest_notes(S: Session, cand: Dict[str, Any], directory: str, files: List[str]) -> None:
    """Manifests and lockfiles inside a vendored directory are the vendored project's own tooling: a note, no candidates."""
    for path in files:
        base = posixpath.basename(path)
        if base in _OTHER_ECOSYSTEM or base in _OWN_TOOLING or (base.endswith(".wrap") and "/subprojects/" in "/" + path):
            S.reg.add_note(cand, "vendored project's own tooling: %s" % path)


def create_single_files(S: Session, pl: Plan) -> None:
    """``single_file`` candidates: rule hits on a file that lies outside every candidate directory."""
    by_file: Dict[str, List[RuleHit]] = {}
    for (path, _lib), hits in pl.single.items():
        by_file.setdefault(path, []).extend(hits)
    for path in sorted(by_file):
        S.check_budget()
        hits = by_file[path]
        libs: Dict[str, int] = {}
        for hit in hits:
            libs[hit.lib] = libs.get(hit.lib, 0) + 1
        lib = sorted(libs.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        canon = S.identity.canonical(lib)
        cand = S.reg.create(canon, "single_file", "file", path, None, map_entry=S.identity.map_entry_name(canon),
                            aliases=[posixpath.splitext(posixpath.basename(path))[0]],
                            first_party=S.is_first_party_name(norm_library(canon)),
                            identity_confidence="high" if any(h.kind in ("version", "parts") for h in hits) else "medium")
        upstream = S.identity.upstream_url(canon)
        if upstream and not cand["upstream"]["url"]:
            cand["upstream"]["url"] = upstream
        presence = S.ev("FILE_PRESENT", path=path, symbol="rule", value=path, candidate=cand["id"],
                        detail="single-file library (identity from a version rule)", quote=False)
        S.reg.claim_identity(cand, canon, [presence])
        add_version_claims(S, cand, [h for h in hits], canon, _ignored_macros(S, canon))
