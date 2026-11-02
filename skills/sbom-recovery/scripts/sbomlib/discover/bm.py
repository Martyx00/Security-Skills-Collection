"""The build model under construction (contract section 4.7) shared by the build-system parsers.

``BuildModel`` collects what ``cmake.py``, ``meson.py`` and ``make.py`` find (options, targets, packages, subdirectories,
configurations) in the shapes of ``buildmodel.json`` and offers the lookups the evidence passes need. Conditions are
``None`` (unconditional) or ``{"all": [clause, ...]}``; a clause is ``{"var", "op": "truthy"|"falsy"}``,
``{"var", "op": "eq"|"ne", "value"}`` or ``{"op": "unknown", "raw"}``.
"""
from __future__ import annotations

import copy
import posixpath
import re
from typing import Any, Dict, List, Optional, Set, Tuple

Condition = Optional[Dict[str, Any]]

#: option names that, when switched on, build tests (``include(CTest)`` adds BUILD_TESTING)
TEST_OPTION_RE = re.compile(
    r"^(?:\w+_)?(?:BUILD|ENABLE|WITH|USE|RUN)_(?:\w+_)?(?:TEST|TESTS|TESTING|TESTSUITE|UNITTEST|UNITTESTS|UNIT_TESTS?|"
    r"CTEST|GTEST|FUZZERS?|FUZZING|FUZZ|COVERAGE|CHECKS?)$", re.I)


def cond_and(a: Condition, b: Condition) -> Condition:
    if a is None:
        return copy.deepcopy(b) if b and b["all"] else None
    if b is None:
        return copy.deepcopy(a) if a["all"] else None
    merged = copy.deepcopy(a["all"])
    for clause in b["all"]:
        if clause not in merged:
            merged.append(copy.deepcopy(clause))
    return {"all": merged} if merged else None


def cond_from_clauses(clauses: List[Dict[str, Any]]) -> Condition:
    return {"all": clauses} if clauses else None


def clause_negate(clause: Dict[str, Any]) -> Dict[str, Any]:
    op = clause.get("op")
    flips = {"truthy": "falsy", "falsy": "truthy", "eq": "ne", "ne": "eq"}
    if op in flips:
        out = dict(clause)
        out["op"] = flips[op]
        return out
    return {"op": "unknown", "raw": "not (%s)" % clause.get("raw", "")}


def cond_negate(cond: Condition) -> Condition:
    """Negation of one branch condition: exact for a single clause, ``unknown`` for anything else."""
    if cond is None:
        return {"all": [{"op": "unknown", "raw": "else of an unconditional branch"}]}
    clauses = cond["all"]
    if len(clauses) == 1:
        return {"all": [clause_negate(clauses[0])]}
    return {"all": [{"op": "unknown", "raw": "not (%s)" % " AND ".join(_clause_text(c) for c in clauses)}]}


def _clause_text(clause: Dict[str, Any]) -> str:
    op = clause.get("op")
    if op == "truthy":
        return clause["var"]
    if op == "falsy":
        return "NOT " + clause["var"]
    if op in ("eq", "ne"):
        return "%s %s %s" % (clause["var"], "STREQUAL" if op == "eq" else "NOT STREQUAL", clause.get("value"))
    return clause.get("raw", "?")


def cond_vars(cond: Condition) -> List[str]:
    return [c["var"] for c in (cond or {}).get("all", []) if "var" in c]


def dir_of(path: str) -> str:
    return posixpath.dirname(path)


class BuildModel:
    def __init__(self) -> None:
        self.systems: Set[str] = set()
        self.options: List[Dict[str, Any]] = []
        self.cache_defaults: Dict[str, str] = {}
        self.configurations: List[Dict[str, Any]] = []
        self.targets: List[Dict[str, Any]] = []
        self.subdirs: List[Dict[str, Any]] = []
        self.packages: List[Dict[str, Any]] = []
        self.globals: Dict[str, Any] = {"link": [], "include_dirs": [], "definitions": [], "variables": {}}
        self.tests_enabled_by: List[str] = []
        self.uncovered: List[str] = []
        self.unresolved_targets: List[Tuple[str, str, int]] = []        # (target, build file, line)
        self.fetch_decls: List[Dict[str, Any]] = []
        self.parsed_files: List[str] = []
        self.sensitive_calls: List[Tuple[str, str, int]] = []           # user-defined commands that define targets
        self.dir_edges: List[Tuple[str, str, Condition]] = []           # (from dir, to dir, condition)
        self.roots: List[str] = []                                      # directories parsed without a parent
        self._test_only_dirs: Optional[Set[str]] = None
        self.test_scope_names: Set[str] = set()
        self.aliases: Dict[str, str] = {}
        self.imported: Dict[str, Optional[str]] = {}

    # ------------------------------------------------------------------ helpers
    def target(self, name: str, near_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
        found = [t for t in self.targets if t["name"] == name]
        if not found:
            return None
        if near_dir is not None:
            found.sort(key=lambda t: (-_shared(t["dir"], near_dir), t["path"]))
        return found[0]

    def add_test_option(self, name: str) -> None:
        if name not in self.tests_enabled_by:
            self.tests_enabled_by.append(name)

    def is_test_condition(self, cond: Condition) -> bool:
        """True when the condition contains a truthy clause on a variable that gates tests (section 4.7)."""
        for clause in (cond or {}).get("all", []):
            if clause.get("op") == "truthy" and clause.get("var") in self.tests_enabled_by:
                return True
        return False

    def compute_test_dirs(self, is_test_dir: Any) -> None:
        """Directories reached only through test-gated ``add_subdirectory`` edges (or that are test directories)."""
        reached_free: Set[str] = set()
        reached_any: Set[str] = set()
        edges: Dict[str, List[Tuple[str, bool]]] = {}
        for src, dst, cond in self.dir_edges:
            gated = self.is_test_condition(cond) or bool(is_test_dir(dst))
            edges.setdefault(src, []).append((dst, gated))
            reached_any.add(dst)
        roots = set(self.roots) | {d for d in {s for s, _d, _c in self.dir_edges} if d not in reached_any}
        stack = list(roots)
        reached_free.update(roots)
        while stack:
            cur = stack.pop()
            for dst, gated in edges.get(cur, []):
                if not gated and dst not in reached_free:
                    reached_free.add(dst)
                    stack.append(dst)
        self._test_only_dirs = {d for d in reached_any if d not in reached_free}

    def dir_is_test_only(self, directory: str) -> bool:
        if self._test_only_dirs is None:
            return False
        probe = directory
        while True:
            if probe in self._test_only_dirs:
                return True
            if not probe or probe == ".":
                return False
            parent = posixpath.dirname(probe)
            if parent == probe:
                return False
            probe = parent

    def finish_targets(self, is_test_dir: Any) -> None:
        for target in self.targets:
            if self.dir_is_test_only(target["dir"]) or self.is_test_condition(target.get("condition")):
                target["test"] = True

    def to_json(self, repo: str, coverage: str) -> Dict[str, Any]:
        targets = []
        for t in sorted(self.targets, key=lambda t: (t["path"], t["line"], t["name"])):
            item = dict(t)
            targets.append(item)
        data = {
            "schema": 1, "repo": repo, "systems": sorted(self.systems), "coverage": coverage,
            "uncovered": sorted(set(self.uncovered)),
            "options": sorted(self.options, key=lambda o: (o["name"], o["path"], o["line"])),
            "cache_defaults": dict(sorted(self.cache_defaults.items())),
            "configurations": list(self.configurations),
            "targets": targets,
            "subdirs": sorted(self.subdirs, key=lambda s: (s["path"] or "", s["line"], s.get("from") or "")),
            "globals": {"link": self.globals["link"], "include_dirs": self.globals["include_dirs"],
                        "definitions": self.globals["definitions"],
                        "variables": dict(sorted(self.globals["variables"].items()))},
            "packages": sorted(self.packages, key=lambda p: (p["path"], p["line"], p["name"], p["kind"])),
            "tests_enabled_by": sorted(self.tests_enabled_by),
        }
        return data


def _shared(a: str, b: str) -> int:
    pa = a.split("/") if a and a != "." else []
    pb = b.split("/") if b and b != "." else []
    n = 0
    for x, y in zip(pa, pb):
        if x != y:
            break
        n += 1
    return n
