"""Loading of the phase-2 outputs a verification run reads, plus path and scope helpers (contract sections 6.8, 6.9).

``RepoData`` bundles ``inventory.json``, ``buildmodel.json``, ``candidates.json`` and ``evidence.jsonl`` of one
repository with the indexes the other verify modules need (tracked paths, candidate directories, owners of a path).
Target files are read only with ``read_target_bytes``: ``"rb"``, ``lstat`` first, regular files only, size capped.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from sbomlib import errors, fsio, norm, paths, state
from sbomlib.context import RunContext

SCHEMA = 1
TEXT_SCAN_CAP = 2 * 1024 * 1024               # G13: text scan cap per file

C_SOURCE_EXT = (".c", ".cc", ".cpp", ".cxx", ".c++")
HEADER_EXT = (".h", ".hh", ".hpp", ".hxx", ".h++", ".inl", ".ipp", ".tcc")

TEST_DIR_WORDS = frozenset(("test", "tests", "testing", "unittest", "unittests", "unit_tests", "unit-tests", "gtest",
                            "ctest", "fuzz", "fuzzing", "fuzzer", "fuzzers"))
DEV_DIR_WORDS = frozenset(("example", "examples", "sample", "samples", "demo", "demos", "bench", "benchmark",
                           "benchmarks", "tools", "scripts", "doc", "docs"))
_TEST_FILE_RE = re.compile(r"^(?:test_.*|.*_tests?\..*|.*_unittest\..*|.*Test\..*)$")

IN_TREE = ("vendored", "single_file", "submodule", "prebuilt")
#: evidence files verification reads besides its own; ``cpp_evidence.jsonl`` is the M2 slot for compiler evidence (absent in M1)
DISCOVER_EVIDENCE_FILES = ("evidence.jsonl", "cpp_evidence.jsonl")
FETCHED_OR_DECLARED = ("fetchcontent", "cpm", "external_project", "lockfile", "package_manager")


def is_source_file(path: str) -> bool:
    return path.lower().endswith(C_SOURCE_EXT)


def is_header_file(path: str) -> bool:
    return path.lower().endswith(HEADER_EXT)


def is_c_family(path: str) -> bool:
    return is_source_file(path) or is_header_file(path)


def path_scope(path: str, test_dirs: Sequence[str] = (), *, base: str = "") -> str:
    """``test`` / ``dev`` / ``product`` by the path rules of section 6.9 (``base`` is stripped first, so the scope of a
    file inside a vendored library is judged by its path inside that library)."""
    rel = path
    if base and (path == base or path.startswith(base + "/")):
        rel = path[len(base):].lstrip("/")
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return "product"
    dirs, name = parts[:-1], parts[-1]
    for directory in test_dirs:
        if directory and (path == directory or path.startswith(directory.rstrip("/") + "/")):
            if not base or not directory.startswith(base):
                return "test"
    if any(d.lower() in TEST_DIR_WORDS for d in dirs) or _TEST_FILE_RE.match(name) or name.lower() in TEST_DIR_WORDS:
        return "test"
    if any(d.lower() in DEV_DIR_WORDS for d in dirs):
        return "dev"
    return "product"


def read_target_bytes(repo_dir: Path, rel: str, cap: int = TEXT_SCAN_CAP) -> Optional[bytes]:
    """Bytes of a regular file inside a target repository, else ``None`` (missing, symlink, too large, unreadable).

    Never follows a symlink (``assert_under`` refuses a symlinked final component or an escaping parent), opens ``"rb"``.
    """
    if not norm.is_safe_relative_path(rel):
        return None
    try:
        full = paths.assert_under(Path(repo_dir) / rel, repo_dir)
        info = os.lstat(str(full))
    except (OSError, errors.SbomError):
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
        return None
    try:
        with open(str(full), "rb") as handle:
            return handle.read(cap + 1)[:cap]
    except OSError:
        return None


def decode_text(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _read_json_optional(path: Path) -> Optional[Any]:
    if not os.path.lexists(str(path)):
        return None
    return fsio.read_json(path)


def _check_schema(doc: Any, name: str) -> Dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise errors.StateError("%s has an unsupported schema" % name)
    return doc


def compile_source(rec: Dict[str, Any]) -> Optional[str]:
    """The source file a ``COMPILE_LIST`` record names. Target-derived records carry it in ``value``/``symbol`` and the build
    file that lists it in ``path``; by-product records (``compile_commands.json``, ``*.d``) carry it in ``path``."""
    for key in ("value", "symbol", "path"):
        value = rec.get(key)
        if isinstance(value, str) and value and is_c_family(value):
            return norm.normalize_path(value)
    path = rec.get("path")
    return norm.normalize_path(str(path)) if isinstance(path, str) and path else None


def candidate_dir(candidate: Dict[str, Any]) -> Optional[str]:
    """Directory a candidate owns (kind ``dir``/``gitlink``), else ``None``."""
    loc = candidate.get("location") or {}
    if loc.get("kind") in ("dir", "gitlink") and loc.get("path"):
        return norm.normalize_path(str(loc["path"]))
    return None


def candidate_file(candidate: Dict[str, Any]) -> Optional[str]:
    loc = candidate.get("location") or {}
    if loc.get("kind") == "file" and loc.get("path"):
        return norm.normalize_path(str(loc["path"]))
    return None


def within(path: str, directory: Optional[str]) -> bool:
    return bool(directory) and (path == directory or path.startswith(directory + "/"))


class RepoData:
    """Phase-2 outputs of one repository plus lookup indexes (read-only after construction)."""

    def __init__(self, ctx: RunContext, repo: str) -> None:
        self.ctx = ctx
        self.repo = repo
        self.out_dir = ctx.layout.repo_out(repo)
        self.repo_dir = ctx.layout.parent / repo
        inventory = _check_schema(_read_required(self.out_dir / "inventory.json"), "inventory.json")
        buildmodel = _check_schema(_read_required(self.out_dir / "buildmodel.json"), "buildmodel.json")
        candidates_doc = _check_schema(_read_required(self.out_dir / "candidates.json"), "candidates.json")
        self.inventory: Dict[str, Any] = inventory
        self.buildmodel: Dict[str, Any] = buildmodel
        self.candidates: List[Dict[str, Any]] = list(candidates_doc.get("candidates") or [])
        self.discover_blindspots: List[Dict[str, Any]] = list(candidates_doc.get("blindspots") or [])
        evidence: List[Dict[str, Any]] = []
        for name in DISCOVER_EVIDENCE_FILES:
            evidence.extend(r for r in _read_jsonl_optional(self.out_dir / name) if r.get("id") and r.get("type"))
        self.evidence: List[Dict[str, Any]] = evidence
        self.cand_by_id: Dict[str, Dict[str, Any]] = {c["id"]: c for c in self.candidates}
        self.siblings = self._siblings()
        self._index_files()
        self._index_candidates()

    # ------------------------------------------------------------------ queue
    def _siblings(self) -> List[str]:
        queue = state.load_queue(self.ctx)
        names = [str(entry.get("name")) for entry in queue.get("repos") or [] if entry.get("name")]
        return sorted(n for n in names if n != self.repo)

    # ------------------------------------------------------------------ files
    def _index_files(self) -> None:
        self.file_class: Dict[str, str] = {}
        self.tracked: Set[str] = set()
        for entry in self.inventory.get("files") or []:
            path = norm.normalize_path(str(entry.get("path", "")))
            if path:
                self.tracked.add(path)
                self.file_class[path] = str(entry.get("class") or "other")
        for sub, names in (self.inventory.get("submodule_files") or {}).items():
            base = norm.normalize_path(str(sub))
            for rel in names or []:
                path = base + "/" + norm.normalize_path(str(rel))
                self.tracked.add(path)
                self.file_class.setdefault(path, "submodule")
        self.by_basename: Dict[str, List[str]] = {}
        for path in sorted(self.tracked):
            self.by_basename.setdefault(path.rsplit("/", 1)[-1], []).append(path)
        self.test_dirs: List[str] = [norm.normalize_path(str(d)) for d in self.inventory.get("test_dirs") or []]

    # ------------------------------------------------------------------ candidates
    def _index_candidates(self) -> None:
        self.dir_of: Dict[str, str] = {}
        self.file_of: Dict[str, str] = {}
        for cand in self.candidates:
            directory = candidate_dir(cand)
            if directory:
                self.dir_of[cand["id"]] = directory
            single = candidate_file(cand)
            if single:
                self.file_of[cand["id"]] = single
        self._dirs_longest_first = sorted(((d, cid) for cid, d in self.dir_of.items()), key=lambda x: (-len(x[0]), x[0], x[1]))
        self._file_owner = {f: cid for cid, f in self.file_of.items()}
        self._owner_cache: Dict[str, Optional[str]] = {}
        located = set(self.dir_of) | set(self.file_of)
        self.in_tree_ids: Set[str] = {c["id"] for c in self.candidates if c.get("detected_as") in IN_TREE and c["id"] in located}

    def owner_of(self, path: str) -> Optional[str]:
        """Id of the candidate whose directory (deepest first) or single file contains ``path``."""
        if path in self._owner_cache:
            return self._owner_cache[path]
        found: Optional[str] = self._file_owner.get(path)
        if found is None:
            for directory, cid in self._dirs_longest_first:
                if path == directory or path.startswith(directory + "/"):
                    found = cid
                    break
        self._owner_cache[path] = found
        return found

    def in_tree(self, cand: Dict[str, Any]) -> bool:
        """A vendored, single-file, submodule or prebuilt candidate that owns a directory or a file of the repository."""
        return cand["id"] in self.in_tree_ids

    def evidence_for(self, candidate_id: str) -> List[Dict[str, Any]]:
        return [e for e in self.evidence if e.get("candidate") == candidate_id]

    def read(self, rel: str, cap: int = TEXT_SCAN_CAP) -> Optional[bytes]:
        return read_target_bytes(self.repo_dir, rel, cap)


def _read_required(path: Path) -> Any:
    """A discovery output verification cannot do without: missing means discovery did not finish for this repository."""
    if not os.path.lexists(str(path)):
        raise errors.RepoFailure("%s is missing; discovery has not produced it" % path.name, path=path.name)
    return fsio.read_json(path)


def _read_jsonl_optional(path: Path) -> List[Dict[str, Any]]:
    if not os.path.lexists(str(path)):
        return []
    return [r for r in fsio.read_jsonl(path) if isinstance(r, dict)]


def repo_file(ctx: RunContext, repo: str, name: str) -> Path:
    return ctx.layout.repo_out(repo) / name


def load_json_if_exists(path: Path) -> Optional[Any]:
    return _read_json_optional(path)
