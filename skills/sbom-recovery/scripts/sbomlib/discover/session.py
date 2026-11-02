"""State shared by the discovery channels of one repository (private module of WP-discover)."""
from __future__ import annotations

import bisect
import fnmatch
import posixpath
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

from sbomlib import model
from sbomlib.context import RunContext
from sbomlib.discover import identity as identity_mod
from sbomlib.discover.bm import BuildModel
from sbomlib.discover.fsread import RepoFS
from sbomlib.discover.imap import IncludeMap
from sbomlib.discover.registry import Registry
from sbomlib.norm import norm_library
from sbomlib.state import RunState

TEST_COMPONENTS = frozenset(("test", "tests", "testing", "unittest", "unittests", "unit_tests", "unit-tests", "gtest",
                             "ctest", "fuzz", "fuzzing", "fuzzer", "fuzzers"))
DEV_COMPONENTS = frozenset(("example", "examples", "sample", "samples", "demo", "demos", "bench", "benchmark",
                            "benchmarks", "tools", "scripts", "doc", "docs"))
_TEST_NAME_PATTERNS = ("test_*", "*_test.*", "*_tests.*", "*_unittest.*", "*Test.*")
#: Meson's directory for vendored subprojects; added to the contract's list of vendored parent directories
EXTRA_VENDORED_PARENTS = ("subprojects",)

C_SOURCE_EXT = (".c", ".cc", ".cpp", ".cxx", ".c++")
C_HEADER_EXT = (".h", ".hh", ".hpp", ".hxx", ".h++", ".inl", ".ipp", ".tcc")


def is_c_source(path: str) -> bool:
    return path.lower().endswith(C_SOURCE_EXT)


def is_c_header(path: str) -> bool:
    return path.lower().endswith(C_HEADER_EXT)


def is_c_file(path: str) -> bool:
    return is_c_source(path) or is_c_header(path)


def scope_of_path(path: str) -> str:
    """``"test"``, ``"dev"`` or ``"product"`` for a repository-relative path (contract section 6.9)."""
    parts = path.split("/")
    for part in parts[:-1]:
        if part.lower() in TEST_COMPONENTS:
            return "test"
    base = parts[-1]
    if any(fnmatch.fnmatchcase(base, pattern) for pattern in _TEST_NAME_PATTERNS):
        return "test"
    if base.lower() in TEST_COMPONENTS:
        return "test"
    for part in parts[:-1]:
        if part.lower() in DEV_COMPONENTS:
            return "dev"
    return "product"


def is_test_dir(path: str) -> bool:
    return any(part.lower() in TEST_COMPONENTS for part in path.split("/") if part)


class Session:
    def __init__(self, ctx: RunContext, run: RunState, repo: str, entry: Dict[str, Any]) -> None:
        self.ctx = ctx
        self.run = run
        self.repo = repo
        self.entry = entry
        self.layout = ctx.layout
        self.repo_dir: Path = ctx.layout.parent / repo
        self.fs = RepoFS(str(self.repo_dir))
        self.rules: Dict[str, Any] = ctx.asset("version_rules.json")
        self.imap_data: Dict[str, Any] = ctx.asset("include_map.json")
        self.imap = IncludeMap(self.imap_data)
        self.identity = identity_mod.Identity(ctx, self.rules, self.imap_data)
        self.reg = Registry(repo)
        self.bm = BuildModel()
        self.incomplete: List[str] = []
        self.warnings: List[Dict[str, Any]] = []
        self.inv: Dict[str, Any] = {}
        self.queue_ignored: List[Dict[str, str]] = []                  # IGNORED items phase 1 recorded for this repository
        self.dropped_dirs: Dict[str, str] = {}                         # agent tooling folders left out of the inventory (folder -> reason)
        # tracked files: every path (superproject files and files of initialized submodules), sorted
        self.paths: List[str] = []
        self.path_set: Set[str] = set()
        self.by_base: Dict[str, List[str]] = {}
        self.dirs: Set[str] = set()
        self.gitlink_paths: Set[str] = set()
        self.submodules: List[Dict[str, Any]] = list(entry.get("submodules") or [])
        self.generated_macros: Dict[str, Any] = {"templates": [], "checks": []}
        self.release_scripts: List[Dict[str, Any]] = []
        self.siblings: Set[str] = set()
        for name in run.all_repos():
            self.siblings.add(norm_library(name))
        self.siblings.add(norm_library(repo))
        self.vendored_parents = set(model.VENDORED_PARENT_DIRS) | set(EXTRA_VENDORED_PARENTS)

    # ------------------------------------------------------------------ files
    def set_paths(self, paths: List[str]) -> None:
        self.paths = sorted(set(paths))
        self.path_set = set(self.paths)
        self.by_base = {}
        self.dirs = set()
        for path in self.paths:
            self.by_base.setdefault(posixpath.basename(path), []).append(path)
            parent = posixpath.dirname(path)
            while parent and parent not in self.dirs:
                self.dirs.add(parent)
                parent = posixpath.dirname(parent)

    def files_under(self, directory: str) -> Iterator[str]:
        """Tracked paths below ``directory`` ('' = the whole repository), in path order."""
        if not directory:
            for path in self.paths:
                yield path
            return
        prefix = directory.rstrip("/") + "/"
        index = bisect.bisect_left(self.paths, prefix)
        while index < len(self.paths) and self.paths[index].startswith(prefix):
            yield self.paths[index]
            index += 1

    def has_dir(self, directory: str) -> bool:
        return directory in self.dirs

    def tracked(self, path: str) -> bool:
        return path in self.path_set

    # ------------------------------------------------------------------ evidence
    def ev(self, etype: str, *, path: Optional[str] = None, line: Optional[int] = None, quote: bool = True,
           detail: Optional[str] = None, **fields: Any) -> str:
        """Record evidence; for ``path:line`` records the exact line bytes are hashed (``quote_sha256``) and, unless
        ``detail`` is given, the trimmed line becomes the detail (at most 200 characters)."""
        if quote and path and line:
            raw = self.fs.line_bytes(path, line)
            if raw is not None:
                fields["quote"] = raw
                if detail is None:
                    detail = raw.decode("utf-8", "replace").strip()[:200]
        if "scope" not in fields:
            fields["scope"] = "product"
        return self.reg.ev(etype, path=path, line=line, detail=detail, **fields)

    def check_budget(self) -> None:
        self.ctx.check_deadline()

    def add_incomplete(self, reason: str) -> None:
        if reason not in self.incomplete:
            self.incomplete.append(reason)

    def log(self, event: str, **fields: Any) -> None:
        try:
            self.ctx.log.warning(event, repo=self.repo, **fields)
        except Exception:
            pass

    def is_first_party_name(self, norm_name: str) -> bool:
        return norm_name in self.siblings
