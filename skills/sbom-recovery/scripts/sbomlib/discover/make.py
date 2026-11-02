"""Autotools and plain Makefiles (contract sections 3.9, 4.7).

``configure.ac`` is read for ``PKG_CHECK_MODULES``, ``AC_CHECK_LIB``, ``AC_SEARCH_LIBS`` and the macros configure-time checks
define; ``Makefile.am`` for ``*_SOURCES``, ``*_LDADD`` / ``*_LIBADD``, ``SUBDIRS``, ``check_PROGRAMS`` and ``if`` blocks;
plain ``Makefile`` for variables, rules that compile or link (``-o``, ``-l<name>``, ``-I``, ``-D``), ``include`` and
``$(MAKE) -C``. Nothing is executed (not even ``make -n``): variables are expanded textually and what cannot be resolved
(``$(wildcard ...)``, ``$(shell ...)``) leaves a target with an unresolved source list.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from sbomlib.discover import bm as bmod
from sbomlib.discover.bm import Condition
from sbomlib.discover.session import Session

MAX_DEPTH = 24
_VAR_RE = re.compile(r"\$\(([^()]*)\)|\$\{([^{}]*)\}|@([A-Za-z_][A-Za-z0-9_]*)@")
_ASSIGN_RE = re.compile(r"^\s*(?:export\s+|override\s+)*([A-Za-z_][A-Za-z0-9_.\-]*)\s*([:+?!]?=|::=)\s*(.*)$")
_RULE_RE = re.compile(r"^([^\s:=#][^:=#]*?)\s*:(?!=)\s*([^=]*?)\s*(?:\|[^=]*)?$")
_C_EXT = (".c", ".cc", ".cpp", ".cxx", ".c++")
_OBJ_EXT = (".o", ".obj", ".lo")
_COMPILER_RE = re.compile(r"(?:\$\((?:CC|CXX|LD|CPP|CROSS_COMPILE)\)|\$\{(?:CC|CXX|LD)\}|"
                          r"(?<![\w.-])(?:[\w.+-]*-)?(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+|icc|armcc|armclang)(?![\w.-]))")
_ARCHIVE_RE = re.compile(r"(?:\$\(AR\)|(?<![\w.-])(?:[\w.+-]*-)?ar(?![\w.-]))\s+-?[rcsT]+")


# --------------------------------------------------------------------------------------------------- m4 / autoconf

def macro_calls(text: str, name: str) -> List[Tuple[int, List[str]]]:
    """``(line, [argument text, ...])`` for each call ``NAME(...)`` in an autoconf script (brackets and parentheses balance)."""
    out: List[Tuple[int, List[str]]] = []
    for match in re.finditer(r"(?<![A-Za-z0-9_])%s\s*\(" % re.escape(name), text):
        pos = match.end()
        depth = 1
        quote = 0
        start = pos
        args: List[str] = []
        while pos < len(text) and depth:
            ch = text[pos]
            if ch == "[":
                quote += 1
            elif ch == "]":
                quote = max(0, quote - 1)
            elif quote == 0 and ch == "(":
                depth += 1
            elif quote == 0 and ch == ")":
                depth -= 1
                if depth == 0:
                    break
            elif quote == 0 and ch == "," and depth == 1:
                args.append(text[start:pos])
                start = pos + 1
            pos += 1
        args.append(text[start:pos])
        cleaned = [re.sub(r"^\s*\[|\]\s*$", "", a.strip()).strip() for a in args]
        out.append((text.count("\n", 0, match.start()) + 1, cleaned))
    return out


def parse_configure(S: Session, path: str, pkg_vars: Dict[str, List[str]]) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    stripped = re.sub(r"(?m)^\s*dnl.*$", "", text)
    stripped = re.sub(r"(?m)(?<![\\$])#.*$", "", stripped)
    for macro in ("PKG_CHECK_MODULES", "PKG_CHECK_MODULES_STATIC", "PKG_CHECK_EXISTS"):
        for line, args in macro_calls(stripped, macro):
            if macro == "PKG_CHECK_EXISTS":
                modules = args[0] if args else ""
                var = None
            else:
                if len(args) < 2:
                    continue
                var, modules = args[0], args[1]
            tokens = modules.split()
            names: List[str] = []
            index = 0
            while index < len(tokens):
                token = tokens[index]
                if token in (">=", "<=", "=", "==", "<", ">") and names and index + 1 < len(tokens):
                    names[-1] = names[-1] + token + tokens[index + 1]
                    index += 2
                    continue
                if re.match(r"^[A-Za-z0-9_.+\-]+(?:[<>=]+\S+)?$", token) and not token.startswith("$"):
                    names.append(token)
                index += 1
            if var:
                pkg_vars[var] = [re.split(r"[<>=]", n, maxsplit=1)[0] for n in names]
            for spec in names:
                name = re.split(r"[<>=]", spec, maxsplit=1)[0]
                constraint = spec[len(name):] or None
                if constraint and constraint.startswith("=") and not constraint.startswith("=="):
                    constraint = "=" + constraint
                S.bm.packages.append({"name": name, "kind": "pkg_check_ac", "version_constraint": constraint,
                                      "required": True, "condition": None, "path": path, "line": line, "evidence_id": None})
    for macro in ("AC_CHECK_LIB", "AC_SEARCH_LIBS"):
        for line, args in macro_calls(stripped, macro):
            libs: List[str] = []
            if macro == "AC_CHECK_LIB" and args:
                libs = [args[0]]
            elif macro == "AC_SEARCH_LIBS" and len(args) > 1:
                libs = args[1].split()
            for lib in libs:
                if re.match(r"^[A-Za-z0-9_.+\-]+$", lib):
                    S.bm.packages.append({"name": lib, "kind": "ac_check_lib", "version_constraint": None, "required": False,
                                          "condition": None, "path": path, "line": line, "evidence_id": None})
    checks = S.generated_macros["checks"]
    for macro in ("AC_DEFINE", "AC_DEFINE_UNQUOTED"):
        for line, args in macro_calls(stripped, macro):
            if args and re.match(r"^[A-Za-z_]\w*$", args[0]):
                checks.append({"path": path, "line": line, "macro": args[0]})
    for macro in ("AC_CHECK_HEADERS", "AC_CHECK_FUNCS", "AC_CHECK_LIB", "AC_CONFIG_HEADERS", "AC_CONFIG_HEADER",
                  "AC_CHECK_TYPES", "AC_CHECK_MEMBERS", "AC_CHECK_DECLS"):
        calls = macro_calls(stripped, macro)
        if calls:
            checks.append({"path": path, "line": calls[0][0], "macro": "HAVE_*"})
            break
    for macro in ("AC_CONFIG_HEADERS", "AC_CHECK_HEADERS", "AC_CHECK_FUNCS", "AC_CHECK_LIB"):
        if macro_calls(stripped, macro):
            line = macro_calls(stripped, macro)[0][0]
            if {"path": path, "line": line, "macro": "HAVE_*"} not in checks:
                checks.append({"path": path, "line": line, "macro": "HAVE_*"})
    S.bm.systems.add("autotools")


# --------------------------------------------------------------------------------------------------- Makefile parser

class MakeParser:
    def __init__(self, S: Session, pkg_vars: Dict[str, List[str]]) -> None:
        self.S = S
        self.bm = S.bm
        self.pkg_vars = pkg_vars
        self.vars: Dict[str, Optional[str]] = {}
        # every assignment of a variable as (line, right-hand side, condition): conditional assignments add up (the union
        # of the branches), an unconditional ``=`` starts again
        self.assigns: Dict[str, List[Tuple[int, str, Condition]]] = {}
        self.dir = ""
        self.file = ""
        self.top = ""
        self.frames: List[Condition] = []
        self.visited: set = set()
        self.depth = 0
        self.rules: List[Dict[str, Any]] = []
        self.automake = False

    # ------------------------------------------------------------------ expansion
    def expand(self, text: str, depth: int = 0) -> Tuple[str, bool]:
        ok = True

        def sub(match: "re.Match[str]") -> str:
            nonlocal ok
            name = match.group(1) or match.group(2) or match.group(3) or ""
            if " " in name and not name.startswith(("wildcard", "shell")):
                ok = False
                return ""
            if name.split(" ", 1)[0] in ("wildcard", "shell", "foreach", "call", "eval", "if", "or", "and", "filter",
                                           "filter-out", "sort", "word", "words", "dir", "notdir", "basename", "abspath",
                                           "realpath", "subst", "strip", "findstring", "firstword", "lastword",
                                           "patsubst", "addprefix", "addsuffix", "join", "suffix", "origin", "flavor",
                                           "value", "error", "warning", "info"):
                ok = False
                return ""
            if name in ("top_srcdir", "top_builddir", "abs_top_srcdir", "abs_top_builddir"):
                return "/@TOP/" + self.top if self.top else "/@TOP"
            if name in ("srcdir", "abs_srcdir", "builddir", "abs_builddir", "CURDIR", "PWD"):
                return "/@TOP/" + self.dir if self.dir else "/@TOP"
            if name in ("MAKE", "CC", "CXX", "LD", "AR", "CROSS_COMPILE", "RM", "CP", "MKDIR", "SHELL", "MAKEFLAGS",
                        "MAKECMDGOALS", "@", "<", "^", "?", "*", "(MAKE)"):
                return "$(%s)" % name
            subst = re.match(r"^([A-Za-z_][\w.\-]*):([^=]*)=(.*)$", name)
            if subst:
                base, old, new = subst.groups()
                value, good = self.lookup(base, depth)
                if not good:
                    ok = False
                    return ""
                return " ".join((w[:-len(old)] + new) if old and w.endswith(old) else w for w in value.split())
            value, good = self.lookup(name, depth)
            if not good:
                ok = False
                return ""
            return value

        for _ in range(6):
            new = _VAR_RE.sub(sub, text)
            if new == text:
                break
            text = new
        return text, ok

    def lookup(self, name: str, depth: int) -> Tuple[str, bool]:
        if name not in self.vars:
            if name.endswith(("_LIBS", "_CFLAGS")) and name.rsplit("_", 1)[0] in self.pkg_vars:
                return "", True
            return "", name in ("CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "LDLIBS", "LIBS", "DEFS", "CC", "CXX")
        raw = self.vars[name]
        if raw is None:
            return "", False
        if depth > 6:
            return "", False
        value, ok = self.expand(raw, depth + 1)
        return value, ok

    def path(self, text: str) -> Optional[str]:
        value = text.strip().strip("\"'")
        if not value or value.startswith(("-", "$")):
            return None
        if value.startswith("/@TOP"):
            joined = posixpath.normpath(value[len("/@TOP"):].lstrip("/") or ".")
        elif value.startswith("/"):
            return None
        else:
            joined = posixpath.normpath(posixpath.join(self.dir or ".", value))
        if joined.startswith(".."):
            return None
        return "" if joined == "." else joined

    @property
    def cond(self) -> Condition:
        return self.frames[-1] if self.frames else None

    def cond_copy(self) -> Condition:
        return None if not self.cond or not self.cond["all"] else {"all": [dict(c) for c in self.cond["all"]]}

    def word_conditions(self) -> Dict[str, Condition]:
        """Condition under which each word of a conditionally assigned variable appears (None for a word that some
        unconditional assignment also provides); used to give ``-l``/``-I``/``-D`` words of a recipe their condition."""
        found: Dict[str, Condition] = {}
        for name in sorted(self.assigns):
            for _line, text, cond in self.assigns[name]:
                value, _ok = self.expand(text)
                for word in value.split():
                    if word in found and found[word] is None:
                        continue
                    if cond is None:
                        found[word] = None
                    elif word not in found:
                        found[word] = cond
        return found

    def items(self, name: str, raw: bool = False) -> Tuple[List[Tuple[str, int, Condition]], bool]:
        """Words of a variable as ``(word, line, condition)`` per assignment (``raw``: before expansion); second value
        False when an expansion failed."""
        out: List[Tuple[str, int, Condition]] = []
        ok = True
        for line, text, cond in self.assigns.get(name, []):
            value, good = (text, True) if raw else self.expand(text)
            ok = ok and good
            for word in value.split():
                out.append((word, line, cond))
        return out, ok

    # ------------------------------------------------------------------ driver
    def logical_lines(self, text: str) -> List[Tuple[int, str, bool]]:
        out: List[Tuple[int, str, bool]] = []
        raw_lines = text.split("\n")
        index = 0
        while index < len(raw_lines):
            start = index + 1
            line = raw_lines[index].rstrip("\r")
            index += 1
            while line.endswith("\\") and index < len(raw_lines):
                line = line[:-1] + " " + raw_lines[index].strip().rstrip("\r")
                index += 1
            is_recipe = line.startswith("\t")
            if not is_recipe:
                line = re.sub(r"(?<!\\)#.*$", "", line)
            if line.strip():
                out.append((start, line, is_recipe))
        return out

    def parse_file(self, path: str, directory: str, include: bool = False, base: Condition = None) -> None:
        if self.depth >= MAX_DEPTH or (path in self.visited and not include):
            return
        text = self.S.fs.text(path)
        if text is None:
            return
        self.visited.add(path)
        self.bm.parsed_files.append(path)
        saved = (self.dir, self.file, self.frames)
        if not include:
            self.dir = directory
            self.frames = [base] if base is not None else []
        self.file = path
        self.depth += 1
        base_depth = len(self.frames)
        branches: List[List[Condition]] = []
        current: Optional[Dict[str, Any]] = None
        try:
            for number, line, is_recipe in self.logical_lines(text):
                if is_recipe:
                    if current is not None:
                        current["recipe"].append((number, line.strip()))
                    continue
                stripped = line.strip()
                word = stripped.split(None, 1)[0] if stripped else ""
                if word == "if" and self.automake:
                    name = stripped[2:].strip()
                    cond = {"all": [{"var": name.lstrip("!"), "op": "falsy" if name.startswith("!") else "truthy"}]}
                    self.frames.append(bmod.cond_and(self.cond, cond) or {"all": []})
                    branches.append([cond])
                    current = None
                    continue
                if word in ("ifdef", "ifndef", "ifeq", "ifneq"):
                    cond = self._condition(word, stripped[len(word):].strip())
                    self.frames.append(bmod.cond_and(self.cond, cond) or {"all": []})
                    branches.append([cond])
                    current = None
                    continue
                if word == "else" and len(self.frames) > base_depth:
                    self.frames.pop()
                    rest = stripped[4:].strip()
                    prior = branches[-1]
                    if rest.split(None, 1)[:1] and rest.split(None, 1)[0] in ("ifdef", "ifndef", "ifeq", "ifneq"):
                        inner = self._condition(rest.split(None, 1)[0], rest.split(None, 1)[1] if len(rest.split(None, 1)) > 1 else "")
                        negated = bmod.cond_negate(prior[-1])
                        self.frames.append(bmod.cond_and(bmod.cond_and(self.cond, negated), inner) or {"all": []})
                        prior.append(inner)
                    else:
                        negated: Condition = None
                        for earlier in prior:
                            negated = bmod.cond_and(negated, bmod.cond_negate(earlier))
                        self.frames.append(bmod.cond_and(self.cond, negated) or {"all": []})
                    continue
                if word == "endif" and len(self.frames) > base_depth:
                    self.frames.pop()
                    if branches:
                        branches.pop()
                    continue
                if word in ("include", "-include", "sinclude"):
                    current = None
                    self._include(stripped[len(word):].strip())
                    continue
                if word in ("define", "endef", "export", "unexport", "vpath", ".PHONY") and not _ASSIGN_RE.match(stripped):
                    current = None
                    continue
                assign = _ASSIGN_RE.match(stripped)
                if assign:
                    current = None
                    self._assign(assign.group(1), assign.group(2), assign.group(3), number)
                    continue
                rule = _RULE_RE.match(stripped)
                if rule and not stripped.startswith("."):
                    current = {"targets": rule.group(1).split(), "prereqs": rule.group(2), "recipe": [], "line": number,
                               "file": path, "dir": self.dir, "cond": self.cond_copy()}
                    self.rules.append(current)
                    continue
                current = None
        finally:
            self.depth -= 1
            del self.frames[base_depth:]
            if not include:
                self.dir, self.file, self.frames = saved
            else:
                self.file = saved[1]

    def _condition(self, word: str, rest: str) -> Condition:
        if word in ("ifdef", "ifndef"):
            name = rest.strip()
            clause = {"var": name, "op": "truthy"}
            return {"all": [bmod.clause_negate(clause) if word == "ifndef" else clause]}
        match = re.match(r"^\(\s*\$[({]([A-Za-z_][\w.\-]*)[)}]\s*,\s*([^)]*?)\s*\)$", rest)
        if match:
            op = "eq" if word == "ifeq" else "ne"
            value = match.group(2).strip("\"'")
            return {"all": [{"var": match.group(1), "op": op, "value": value}]}
        return {"all": [{"op": "unknown", "raw": ("%s %s" % (word, rest))[:120]}]}

    def _assign(self, name: str, op: str, value: str, line: int) -> None:
        cond = self.cond_copy()
        known = name in self.vars
        old = self.vars.get(name, "")
        if op in (":=", "::="):
            expanded, ok = self.expand(value)
            new_value: Optional[str] = expanded if ok else None
            if cond is not None and known and old is not None and new_value is not None:
                new_value = (old + " " + new_value).strip()
            self.vars[name] = new_value
        elif op == "+=":
            self.vars[name] = None if old is None else (old + " " + value).strip()
        elif op == "?=":
            if not known:
                self.vars[name] = value
        elif op == "!=":
            self.vars[name] = None
        else:
            self.vars[name] = (old + " " + value).strip() if (cond is not None and known and old is not None) else value
        entries = self.assigns.setdefault(name, [])
        if op == "?=":
            if not known:
                entries.append((line, value, cond))
        elif op == "!=":
            self.assigns[name] = [(line, "$(shell)", cond)]
        elif op == "+=" or (cond is not None and entries):
            entries.append((line, value, cond))
        else:
            self.assigns[name] = [(line, value, cond)]

    def _include(self, rest: str) -> None:
        for item in rest.split():
            value, ok = self.expand(item)
            if not ok:
                continue
            path = self.path(value)
            if path and self.S.tracked(path):
                self.parse_file(path, posixpath.dirname(path), include=True)


# --------------------------------------------------------------------------------------------------- targets from rules

def _tokens(text: str) -> List[str]:
    return [t.strip("\"'") for t in text.split()]


def _source_for_object(S: Session, directory: str, obj: str) -> Optional[str]:
    stem = posixpath.splitext(obj)[0]
    base = posixpath.normpath(posixpath.join(directory or ".", stem))
    if base.startswith(".."):
        return None
    base = "" if base == "." else base
    for ext in _C_EXT:
        candidate = base + ext
        if S.tracked(candidate):
            return candidate
    name = posixpath.basename(stem)
    matches = [p for ext in _C_EXT for p in S.by_base.get(name + ext, []) if posixpath.dirname(p).startswith(directory or "")]
    return matches[0] if len(matches) == 1 else None


_SOURCE_HINT_RE = re.compile(r"\.(?:c|cc|cpp|cxx|c\+\+|o|obj)(?![\w])|\*\.|(?:SRCS?|SOURCES|OBJS?|OBJECTS)\b", re.I)


def _failure_hits_sources(parser: MakeParser, raw: str) -> bool:
    """True when a make expansion that failed in ``raw`` could have supplied source files: ``$(wildcard *.c)``, a variable
    holding such a list, as opposed to ``$(shell pkg-config --libs ...)`` in a flag position."""
    for match in _VAR_RE.finditer(raw):
        text = match.group(0)
        name = match.group(1) or match.group(2) or match.group(3) or ""
        _value, good = parser.expand(text)
        if good:
            continue
        pieces = [text]
        if re.match(r"^[A-Za-z_][\w.\-]*$", name):
            pieces.extend(rhs for _line, rhs, _cond in parser.assigns.get(name, []))
            if _SOURCE_HINT_RE.search(name):
                return True
        if any(_SOURCE_HINT_RE.search(piece) for piece in pieces):
            return True
    return False


def _rule_targets(parser: MakeParser) -> None:
    S = parser.S
    bm = parser.bm
    parser.dir = parser.dir
    word_conds = parser.word_conditions()
    for rule in parser.rules:
        parser.dir = rule["dir"]
        directory = rule["dir"]
        names = [n for n in rule["targets"] if "%" not in n and not n.startswith(".")]
        recipe = rule["recipe"]
        if not names:
            continue
        prereq_text, prereq_ok = parser.expand(rule["prereqs"])
        prereqs = _tokens(prereq_text) if prereq_ok else []
        for number, line in recipe:
            sub_dir = None
            match = re.search(r"\$\(MAKE\)\s+(?:-\S+\s+)*-C\s+(\S+)", line) or re.search(r"cd\s+(\S+)\s*&&\s*\$\(MAKE\)", line)
            if match:
                value, ok = parser.expand(match.group(1))
                path = parser.path(value) if ok else None
                if path is not None:
                    sub_dir = path
            if sub_dir is not None:
                cond = rule["cond"]
                bm.subdirs.append({"path": sub_dir or ".", "line": number, "condition": cond, "evidence_id": None,
                                   "from": directory or ".", "file": rule["file"]})
                bm.dir_edges.append((directory, sub_dir, cond))
        for number, line in recipe:
            archive = bool(_ARCHIVE_RE.search(line))
            expanded, ok = parser.expand(line.replace("$@", names[0]).replace("$<", prereqs[0] if prereqs else "")
                                         .replace("$^", " ".join(prereqs)).replace("$+", " ".join(prereqs)))
            if not (_COMPILER_RE.search(line) or archive):
                continue
            words = _tokens(expanded)
            out_name: Optional[str] = None
            if archive:
                for index, word in enumerate(words):
                    if re.fullmatch(r"-?[rcsT]+", word) and index + 1 < len(words):
                        out_name = words[index + 1]
                        break
            for index, word in enumerate(words):
                if word == "-o" and index + 1 < len(words):
                    out_name = words[index + 1]
                elif word.startswith("-o") and len(word) > 2 and not archive and not word.startswith("-opt"):
                    out_name = word[2:]
            if out_name is None or out_name.endswith(_OBJ_EXT) and not archive:
                continue
            kind = "static_library" if archive else "executable"
            target_name = posixpath.basename(out_name)
            sources: List[Dict[str, Any]] = []
            unresolved = (not ok or not prereq_ok) and _failure_hits_sources(parser, line + " " + rule["prereqs"])
            candidates_src = [w for w in words if w.lower().endswith(_C_EXT)] + [p for p in prereqs if p.lower().endswith(_C_EXT)]
            objs = [w for w in words if w.endswith(_OBJ_EXT)] + [p for p in prereqs if p.endswith(_OBJ_EXT)]
            for src in candidates_src:
                path = parser.path(src)
                if path is not None:
                    sources.append({"path": path, "line": number, "condition": rule["cond"], "file": rule["file"]})
            for obj in objs:
                path = _source_for_object(S, directory, obj)
                if path is not None:
                    sources.append({"path": path, "line": number, "condition": rule["cond"], "file": rule["file"]})
                else:
                    unresolved = True
            def word_cond(word: str) -> Condition:
                return bmod.cond_and(rule["cond"], word_conds.get(word))

            link = [{"item": w, "line": number, "condition": word_cond(w), "file": rule["file"]}
                    for w in words if w.startswith("-l") and len(w) > 2]
            for w in words:
                if w.endswith((".a", ".la", ".so")) and "/" in w and not w.startswith("-") and w != out_name:
                    lib_path = parser.path(w)
                    if lib_path:
                        link.append({"item": posixpath.relpath(lib_path, directory or "."), "line": number,
                                     "condition": word_cond(w), "file": rule["file"]})
            incs = []
            for w in words:
                if w.startswith("-I") and len(w) > 2:
                    path = parser.path(w[2:])
                    if path is not None:
                        incs.append({"path": path or ".", "line": number, "condition": word_cond(w), "file": rule["file"]})
            defs = []
            for w in words:
                if w.startswith("-D") and len(w) > 2:
                    dname, sep, dval = w[2:].partition("=")
                    defs.append({"name": dname, "value": dval if sep else None, "line": number, "condition": word_cond(w),
                                 "file": rule["file"]})
            unique: Dict[Tuple[str, int], Dict[str, Any]] = {}
            for item in sources:
                unique[(item["path"], item["line"])] = item
            is_test = target_name.lower().startswith(("test", "check")) or any(n in ("test", "check", "tests") for n in names)
            bm.targets.append({"name": target_name, "kind": kind, "dir": directory or ".", "path": rule["file"],
                               "line": number, "test": bool(is_test), "sources": list(unique.values()), "link": link,
                               "include_dirs": incs, "definitions": defs, "condition": rule["cond"], "evidence_id": None,
                               "_unresolved": bool(unresolved)})
            break


def _globals_from_vars(parser: MakeParser, file: str) -> None:
    bm = parser.bm
    for name in sorted(parser.assigns):
        if name in ("LDLIBS", "LIBS", "LDFLAGS"):
            words, ok = parser.items(name)
            for word, line, cond in words:
                if word.startswith("-l") and len(word) > 2:
                    bm.globals["link"].append({"item": word, "line": line, "condition": cond, "path": file})
        elif name in ("CPPFLAGS", "CFLAGS", "CXXFLAGS", "DEFS", "AM_CPPFLAGS", "AM_CFLAGS"):
            words, ok = parser.items(name)
            for word, line, cond in words:
                if word.startswith("-I") and len(word) > 2:
                    path = parser.path(word[2:])
                    if path is not None:
                        bm.globals["include_dirs"].append({"path": path or ".", "line": line, "condition": cond, "file": file})
                elif word.startswith("-D") and len(word) > 2:
                    dname, sep, dval = word[2:].partition("=")
                    bm.globals["definitions"].append({"name": dname, "value": dval if sep else None, "line": line,
                                                      "condition": cond, "path": file})


# --------------------------------------------------------------------------------------------------- Makefile.am

def parse_automake(S: Session, pkg_vars: Dict[str, List[str]], path: str, visited: set) -> None:
    if path in visited:
        return
    visited.add(path)
    parser = MakeParser(S, pkg_vars)
    parser.automake = True
    directory = posixpath.dirname(path)
    parser.parse_file(path, directory)
    parser.dir, parser.file = directory, path
    S.bm.systems.add("autotools")
    am_targets(S, parser, path, directory)
    for sub, line, cond in _subdirs(parser):
        child = posixpath.normpath(posixpath.join(directory or ".", sub))
        if child.startswith(".."):
            continue
        child = "" if child == "." else child
        S.bm.subdirs.append({"path": child or ".", "line": line, "condition": cond, "evidence_id": None,
                             "from": directory or ".", "file": path})
        S.bm.dir_edges.append((directory, child, cond))
        sub_file = (child + "/Makefile.am") if child else "Makefile.am"
        if S.tracked(sub_file):
            parse_automake(S, pkg_vars, sub_file, visited)


def _subdirs(parser: MakeParser) -> List[Tuple[str, int, Condition]]:
    out: List[Tuple[str, int, Condition]] = []
    seen = set()
    for name in ("SUBDIRS", "DIST_SUBDIRS"):
        words, _ok = parser.items(name)
        for word, line, cond in words:
            if word.startswith("$") or word in (".", "") or (word, line) in seen:
                continue
            seen.add((word, line))
            out.append((word, line, cond))
    return out


def _am_ident(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9@_]", "_", name)


def am_targets(S: Session, parser: MakeParser, path: str, directory: str) -> None:
    bm = S.bm
    tests = {word for word, _line, _cond in parser.items("TESTS")[0]}
    kinds = [(k, "executable") for k in parser.assigns if k.endswith("_PROGRAMS")]
    kinds += [(k, "static_library") for k in parser.assigns if k.endswith("_LTLIBRARIES") or k.endswith("_LIBRARIES")]
    for var, kind in sorted(kinds):
        names, _names_ok = parser.items(var)
        is_check = var.startswith("check_")
        for name, name_line, name_cond in names:
            if name.startswith("$"):
                continue
            ident = _am_ident(name)
            unresolved = (ident + "_SOURCES") not in parser.assigns
            sources: List[Dict[str, Any]] = []
            src_items, src_ok = parser.items(ident + "_SOURCES")
            unresolved = unresolved or not src_ok
            for src, line, cond in src_items:
                spath = parser.path(src)
                if spath is not None and src.lower().endswith(_C_EXT):
                    sources.append({"path": spath, "line": line, "condition": bmod.cond_and(name_cond, cond), "file": path})
                elif spath is None and src.startswith("$"):
                    unresolved = True
            link: List[Dict[str, Any]] = []
            for add in (ident + "_LDADD", ident + "_LIBADD", "LDADD", "LIBS", ident + "_LDFLAGS", "AM_LDFLAGS"):
                words, _ok = parser.items(add, raw=True)
                for word, line, cond in words:
                    link.extend(_am_link_items(parser, word, path, directory, line, bmod.cond_and(name_cond, cond)))
            incs: List[Dict[str, Any]] = []
            defs: List[Dict[str, Any]] = []
            for flag_var in (ident + "_CPPFLAGS", ident + "_CFLAGS", "AM_CPPFLAGS", "AM_CFLAGS"):
                words, _ok = parser.items(flag_var)
                for word, line, cond in words:
                    both = bmod.cond_and(name_cond, cond)
                    if word.startswith("-I") and len(word) > 2:
                        ipath = parser.path(word[2:])
                        if ipath is not None:
                            incs.append({"path": ipath or ".", "line": line, "condition": both, "file": path})
                    elif word.startswith("-D") and len(word) > 2:
                        dname, sep, dval = word[2:].partition("=")
                        defs.append({"name": dname, "value": dval if sep else None, "line": line, "condition": both,
                                     "file": path})
            bm.targets.append({"name": name, "kind": kind, "dir": directory or ".", "path": path, "line": name_line,
                               "test": bool(is_check or name in tests), "sources": sources, "link": link,
                               "include_dirs": incs, "definitions": defs, "condition": name_cond, "evidence_id": None,
                               "_unresolved": bool(unresolved)})


def _am_link_items(parser: MakeParser, word: str, path: str, directory: str, line: int,
                   cond: Condition) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    match = re.fullmatch(r"(?:\$\(([A-Za-z_]\w*)_LIBS\)|\$\{([A-Za-z_]\w*)_LIBS\}|@([A-Za-z_]\w*)_LIBS@)", word)
    if match:
        var = match.group(1) or match.group(2) or match.group(3)
        for module in parser.pkg_vars.get(var, []):
            items.append({"item": module, "line": line, "condition": cond, "file": path})
        return items
    expanded, _ok = parser.expand(word)
    for piece in expanded.split():
        if piece.startswith("-l") and len(piece) > 2:
            items.append({"item": piece, "line": line, "condition": cond, "file": path})
        elif piece.endswith((".la", ".a")):
            repo_path = parser.path(piece)
            if repo_path and "/" in piece:
                items.append({"item": posixpath.relpath(repo_path, directory or "."), "line": line, "condition": cond,
                              "file": path})
            else:
                items.append({"item": posixpath.basename(piece), "line": line, "condition": cond, "file": path})
    return items


# --------------------------------------------------------------------------------------------------- entry point

def parse_all(S: Session, files: List[str]) -> None:
    """Interpret ``configure.ac`` / ``Makefile.am`` and plain Makefiles; shared by the autotools and make systems."""
    pkg_vars: Dict[str, List[str]] = {}
    for path in sorted(files):
        if posixpath.basename(path) in ("configure.ac", "configure.in"):
            parse_configure(S, path, pkg_vars)
    visited: set = set()
    ams = sorted((p for p in files if posixpath.basename(p) == "Makefile.am"), key=lambda p: (p.count("/"), p))
    for path in ams:
        S.check_budget()
        if path not in visited:
            S.bm.roots.append(posixpath.dirname(path))
            parse_automake(S, pkg_vars, path, visited)
    makefiles = sorted((p for p in files if posixpath.basename(p) in ("Makefile", "makefile", "GNUmakefile")
                        and not _generated_by_automake(S, p)), key=lambda p: (p.count("/"), p))
    parser = MakeParser(S, pkg_vars)
    for path in makefiles:
        S.check_budget()
        if path in parser.visited:
            continue
        directory = posixpath.dirname(path)
        S.bm.roots.append(directory)
        parser.vars = {}
        parser.assigns = {}
        parser.rules = []
        parser.parse_file(path, directory)
        _globals_from_vars(parser, path)
        _rule_targets(parser)
        S.bm.systems.add("make")


def _generated_by_automake(S: Session, path: str) -> bool:
    directory = posixpath.dirname(path)
    sibling = (directory + "/Makefile.in") if directory else "Makefile.in"
    am = (directory + "/Makefile.am") if directory else "Makefile.am"
    return sibling in S.path_set or am in S.path_set
