"""CMake: tokenizer, static interpreter and ``CMakePresets.json`` reader (contract sections 3.9, 4.7).

Nothing is executed and nothing is configured. The interpreter walks ``CMakeLists.txt`` and ``*.cmake`` files in the
order CMake would read them (``add_subdirectory`` and ``include`` of tracked files are followed), keeps a condition
stack (``if`` / ``elseif`` / ``else``), expands variables whose value is a literal and fills the shared ``BuildModel``.
Values it cannot know (globs, generator expressions, unknown variables) stay unresolved; a target with an unresolved
source list is reported as naming no sources (the verifier then assumes every product source is compiled).
"""
from __future__ import annotations

import json
import posixpath
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from sbomlib.discover import bm as bmod
from sbomlib.discover.bm import BuildModel, Condition
from sbomlib.discover.session import Session

MAX_FOLLOW_DEPTH = 40
_SRC = "/@SRC"          # marks a value that is already relative to the repository root (CMAKE_CURRENT_SOURCE_DIR ...)
MAX_FOREACH = 64
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BRACKET_OPEN_RE = re.compile(r"\[(=*)\[")
_BRACKET_COMMENT_RE = re.compile(r"#\[(=*)\[")
_WHOLE_VAR_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_.+\-]*)\}$")
_VAR_RE = re.compile(r"\$\{([^${}]*)\}")
_VAR_ONLY_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_.+\-]*)\}$")
_BARE_VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:+\-]*$")
_TRUE_CONSTS = frozenset(("1", "ON", "YES", "TRUE", "Y"))
_FALSE_CONSTS = frozenset(("0", "OFF", "NO", "FALSE", "N", "IGNORE", "NOTFOUND", ""))
_TARGET_KEYWORDS = frozenset(("PRIVATE", "PUBLIC", "INTERFACE", "SYSTEM", "BEFORE", "AFTER", "STATIC", "SHARED", "MODULE",
                              "OBJECT", "IMPORTED", "GLOBAL", "EXCLUDE_FROM_ALL", "WIN32", "MACOSX_BUNDLE", "UNKNOWN",
                              "ALIAS", "FILE_SET", "BASE_DIRS", "HEADERS", "CXX_MODULES", "FRAMEWORK"))
_LINK_KEYWORDS = frozenset(("PRIVATE", "PUBLIC", "INTERFACE", "debug", "optimized", "general", "LINK_PUBLIC",
                            "LINK_PRIVATE", "LINK_INTERFACE_LIBRARIES"))
_CHECK_COMMANDS = {
    "check_include_file": 1, "check_include_files": 1, "check_include_file_cxx": 1, "check_symbol_exists": 2,
    "check_cxx_symbol_exists": 2, "check_function_exists": 1, "check_library_exists": 3, "check_c_source_compiles": 1,
    "check_cxx_source_compiles": 1, "check_c_source_runs": 1, "check_cxx_source_runs": 1, "check_struct_has_member": 3,
    "check_type_size": 1, "check_c_compiler_flag": 1, "check_cxx_compiler_flag": 1, "check_variable_exists": 1,
    "check_prototype_definition": 3, "check_ipo_supported": -1, "check_cxx_source_compiles_ex": 1}
_PKG_KEYWORDS = frozenset(("REQUIRED", "QUIET", "NO_CMAKE_PATH", "NO_CMAKE_ENVIRONMENT_PATH", "IMPORTED_TARGET", "GLOBAL",
                           "NO_CMAKE_SYSTEM_PATH", "EXACT", "MODULE", "CONFIG", "NO_MODULE", "EXCLUDE", "ALL", "BYPASS_PROVIDER"))
_STRING_OUT_INDEX = {"CONCAT": 1, "APPEND": 1, "PREPEND": 1, "JOIN": 2, "TOLOWER": 2, "TOUPPER": 2, "STRIP": 2, "LENGTH": 2,
                     "MAKE_C_IDENTIFIER": 2, "HEX": 2, "REPLACE": 3, "SUBSTRING": 4, "FIND": 3, "TIMESTAMP": 1, "UUID": 1,
                     "CONFIGURE": 2, "MD5": 1, "SHA1": 1, "SHA224": 1, "SHA256": 1, "SHA384": 1, "SHA512": 1}


# --------------------------------------------------------------------------------------------------- tokenizer

class Arg:
    __slots__ = ("text", "quoted", "line", "bracket")

    def __init__(self, text: str, quoted: bool, line: int, bracket: bool = False) -> None:
        self.text = text
        self.quoted = quoted
        self.line = line
        self.bracket = bracket

    def __repr__(self) -> str:                                  # pragma: no cover - debugging aid
        return "Arg(%r%s)" % (self.text, ", quoted" if self.quoted else "")


class Command:
    __slots__ = ("name", "raw", "args", "line", "end_line")

    def __init__(self, name: str, raw: str, args: List[Arg], line: int, end_line: int) -> None:
        self.name = name
        self.raw = raw
        self.args = args
        self.line = line
        self.end_line = end_line

    def __repr__(self) -> str:                                  # pragma: no cover - debugging aid
        return "Command(%s %r @%d)" % (self.name, self.args, self.line)


def _skip_comment(text: str, pos: int, line: int) -> Tuple[int, int]:
    """``pos`` is at '#': skip a bracket or line comment; returns the new position and line."""
    match = _BRACKET_COMMENT_RE.match(text, pos)
    if match is not None:
        close = "]" + match.group(1) + "]"
        end = text.find(close, match.end())
        end = len(text) if end == -1 else end + len(close)
        return end, line + text.count("\n", pos, end)
    end = text.find("\n", pos)
    return (len(text) if end == -1 else end), line


def _read_quoted(text: str, pos: int, line: int) -> Tuple[str, int, int]:
    """``pos`` is just after the opening quote."""
    out: List[str] = []
    n = len(text)
    while pos < n:
        ch = text[pos]
        if ch == "\\" and pos + 1 < n:
            nxt = text[pos + 1]
            if nxt == "\n":
                line += 1
                pos += 2
                continue
            if nxt in '"\\$@;':
                out.append(nxt if nxt != ";" else "\\;")
            elif nxt == "n":
                out.append("\n")
            elif nxt == "t":
                out.append("\t")
            else:
                out.append("\\" + nxt)
            pos += 2
            continue
        if ch == '"':
            return "".join(out), pos + 1, line
        if ch == "\n":
            line += 1
        out.append(ch)
        pos += 1
    return "".join(out), pos, line


def _parse_args(text: str, pos: int, line: int) -> Tuple[List[Arg], int, int]:
    args: List[Arg] = []
    n = len(text)
    depth = 1
    while pos < n:
        ch = text[pos]
        if ch == "\n":
            line += 1
            pos += 1
        elif ch in " \t\r":
            pos += 1
        elif ch == "#":
            pos, line = _skip_comment(text, pos, line)
        elif ch == ")":
            depth -= 1
            pos += 1
            if depth == 0:
                return args, pos, line
            args.append(Arg(")", False, line))
        elif ch == "(":
            depth += 1
            args.append(Arg("(", False, line))
            pos += 1
        elif ch == '"':
            start_line = line
            value, pos, line = _read_quoted(text, pos + 1, line)
            args.append(Arg(value, True, start_line))
        elif ch == "[" and _BRACKET_OPEN_RE.match(text, pos):
            match = _BRACKET_OPEN_RE.match(text, pos)
            assert match is not None
            close = "]" + match.group(1) + "]"
            end = text.find(close, match.end())
            stop = n if end == -1 else end
            args.append(Arg(text[match.end():stop], True, line, True))
            line += text.count("\n", pos, stop + len(close))
            pos = n if end == -1 else end + len(close)
        else:
            start = pos
            start_line = line
            parts: List[str] = []
            while pos < n:
                c = text[pos]
                if c in " \t\r\n()":
                    break
                if c == "#" and pos == start:
                    break
                if c == '"':
                    value, pos2, line2 = _read_quoted(text, pos + 1, line)
                    parts.append(value)
                    pos, line = pos2, line2
                    continue
                if c == "\\" and pos + 1 < n and text[pos + 1] != "\n":
                    parts.append(text[pos + 1] if text[pos + 1] in '"\\$@;()#' else "\\" + text[pos + 1])
                    pos += 2
                    continue
                if c == "$" and text.startswith("$<", pos):
                    # generator expression: copy up to the matching '>' (it may contain spaces only when quoted)
                    level = 0
                    scan = pos
                    while scan < n:
                        if text.startswith("$<", scan):
                            level += 1
                            scan += 2
                            continue
                        if text[scan] == ">":
                            level -= 1
                            scan += 1
                            if level == 0:
                                break
                            continue
                        if text[scan] in " \t\r\n":
                            break
                        scan += 1
                    parts.append(text[pos:scan])
                    pos = scan
                    continue
                parts.append(c)
                pos += 1
            if pos == start:
                pos += 1                                     # stray character
                continue
            args.append(Arg("".join(parts), False, start_line))
    return args, pos, line


def tokenize(text: str) -> List[Command]:
    """Commands of a CMake script, in order, with 1-based lines; comments are dropped."""
    commands: List[Command] = []
    pos = 0
    n = len(text)
    line = 1
    while pos < n:
        ch = text[pos]
        if ch == "\n":
            line += 1
            pos += 1
        elif ch in " \t\r":
            pos += 1
        elif ch == "#":
            pos, line = _skip_comment(text, pos, line)
        else:
            match = _NAME_RE.match(text, pos)
            if match is None:
                pos += 1
                continue
            start_line = line
            pos = match.end()
            scan = pos
            scan_line = line
            while scan < n and text[scan] in " \t\r\n":
                if text[scan] == "\n":
                    scan_line += 1
                scan += 1
            if scan >= n or text[scan] != "(":
                continue
            args, pos, line = _parse_args(text, scan + 1, scan_line)
            commands.append(Command(match.group(0).lower(), match.group(0), args, start_line, line))
    return commands


def project_info(text: str) -> Optional[Dict[str, Any]]:
    """The first ``project()`` call of a script: ``{"name", "version", "line", "version_line"}`` (version None when absent
    or not a literal)."""
    set_vars: Dict[str, str] = {}
    for command in tokenize(text):
        if command.name == "set" and len(command.args) >= 2 and not any(a.text == "CACHE" for a in command.args):
            value = " ".join(a.text for a in command.args[1:] if not _VAR_RE.search(a.text))
            if len(command.args) == 2 and not _VAR_RE.search(command.args[1].text):
                set_vars[command.args[0].text] = value
        if command.name != "project" or not command.args:
            continue
        name = command.args[0].text
        version = None
        version_line = None
        for index, arg in enumerate(command.args):
            if arg.text == "VERSION" and index + 1 < len(command.args):
                raw = command.args[index + 1].text
                match = _VAR_ONLY_RE.match(raw)
                if match is not None:
                    raw = set_vars.get(match.group(1), "")
                if raw and not _VAR_RE.search(raw) and re.match(r"^\d", raw):
                    version = raw
                    version_line = command.args[index + 1].line
        return {"name": name, "version": version, "line": command.line, "version_line": version_line}
    return None


# --------------------------------------------------------------------------------------------------- interpreter

class _Scope:
    def __init__(self, parent: Optional["_Scope"] = None) -> None:
        self.vars: Dict[str, Optional[str]] = {}
        # list variables assigned or extended under a condition: name -> [(item, condition of the assignment)] (the union of
        # every branch, so that ``add_executable(app ${SRCS})`` can give each source its own condition)
        self.alts: Dict[str, List[Tuple[str, Condition]]] = {}
        self.parent = parent

    def alternatives(self, name: str) -> Optional[List[Tuple[str, Condition]]]:
        scope: Optional[_Scope] = self
        while scope is not None:
            if name in scope.vars:
                return scope.alts.get(name)
            scope = scope.parent
        return None

    def lookup(self, name: str) -> Tuple[bool, Optional[str]]:
        scope: Optional[_Scope] = self
        while scope is not None:
            if name in scope.vars:
                return True, scope.vars[name]
            scope = scope.parent
        return False, None


class _Frame:
    __slots__ = ("kind", "prev", "cur", "eff", "parent_eff")

    def __init__(self, kind: str, parent_eff: Condition, cur: Condition) -> None:
        self.kind = kind
        self.prev: List[Condition] = []
        self.cur = cur
        self.parent_eff = parent_eff
        self.eff = bmod.cond_and(parent_eff, cur)
        if self.eff is not None and not self.eff["all"]:
            self.eff = None


def _is_true_const(text: str) -> bool:
    return text.upper() in _TRUE_CONSTS or bool(re.fullmatch(r"[1-9]\d*", text))


def _is_false_const(text: str) -> bool:
    return text.upper() in _FALSE_CONSTS or text.upper().endswith("-NOTFOUND")


class CMakeParser:
    def __init__(self, S: Session) -> None:
        self.S = S
        self.bm: BuildModel = S.bm
        self.cache: Dict[str, str] = {}
        self.var_assign: Dict[str, Optional[str]] = self.bm.globals["variables"]
        self.visited: Set[str] = set()
        self.frames: List[_Frame] = []
        self.scope = _Scope()
        self.dir = ""
        self.list_dir = ""
        self.file = ""
        self.project_root = ""
        self.project_names: Dict[str, str] = {}
        self.functions: Dict[str, bool] = {}
        self.aliases: Dict[str, str] = {}
        self.imported: Dict[str, Optional[str]] = {}
        self.ops: List[Dict[str, Any]] = []
        self.declared: Dict[str, Dict[str, Any]] = {}
        self.available: Set[str] = set()
        self.depth = 0
        self.module_path: List[str] = []
        self.in_function = 0
        self.base_depth = 0

    # ------------------------------------------------------------------ conditions
    @property
    def cond(self) -> Condition:
        return self.frames[-1].eff if self.frames else None

    def _clause_for(self, arg: Arg) -> List[Dict[str, Any]]:
        text = arg.text
        if _is_true_const(text) and not arg.quoted:
            return []
        if _is_false_const(text) and not arg.quoted:
            return [{"var": "FALSE", "op": "truthy"}]
        name = self._var_name(arg)
        if name is None:
            return [{"op": "unknown", "raw": text[:120]}]
        return [{"var": name, "op": "truthy"}]

    @staticmethod
    def _var_name(arg: Arg) -> Optional[str]:
        match = _VAR_ONLY_RE.match(arg.text)
        if match is not None:
            return match.group(1)
        if not arg.quoted and _BARE_VAR_RE.match(arg.text) and "::" not in arg.text:
            return arg.text
        if arg.quoted and _BARE_VAR_RE.match(arg.text) and "::" not in arg.text:
            return arg.text
        return None

    def parse_condition(self, args: Sequence[Arg]) -> Condition:
        tokens = list(args)
        depth = 0
        for tok in tokens:
            if tok.text == "(" and not tok.quoted:
                depth += 1
            elif tok.text == ")" and not tok.quoted:
                depth -= 1
            elif tok.text == "OR" and depth == 0 and not tok.quoted:
                return {"all": [{"op": "unknown", "raw": " ".join(t.text for t in tokens)[:120]}]}
        groups: List[List[Arg]] = [[]]
        depth = 0
        for tok in tokens:
            if tok.text == "(" and not tok.quoted:
                depth += 1
            elif tok.text == ")" and not tok.quoted:
                depth -= 1
            if tok.text == "AND" and depth == 0 and not tok.quoted:
                groups.append([])
            else:
                groups[-1].append(tok)
        clauses: List[Dict[str, Any]] = []
        for group in groups:
            clauses.extend(self._unary(group))
        return bmod.cond_from_clauses(clauses)

    def _unary(self, group: List[Arg]) -> List[Dict[str, Any]]:
        if not group:
            return []
        raw = " ".join(a.text for a in group)[:120]
        if group[0].text == "(" and group[-1].text == ")" and not group[0].quoted:
            depth = 0
            wraps = True
            for index, tok in enumerate(group):
                if tok.text == "(" and not tok.quoted:
                    depth += 1
                elif tok.text == ")" and not tok.quoted:
                    depth -= 1
                    if depth == 0 and index < len(group) - 1:
                        wraps = False
                        break
            if wraps:
                inner = self.parse_condition(group[1:-1])
                return list(inner["all"]) if inner else []
        words = [a.text for a in group]
        if len(group) == 1:
            return self._clause_for(group[0])
        if words[0] == "NOT" and not group[0].quoted:
            rest = group[1:]
            if len(rest) == 1:
                clauses = self._clause_for(rest[0])
                if not clauses:
                    return [{"var": "FALSE", "op": "truthy"}]
                if clauses[0].get("op") == "truthy" and clauses[0].get("var") == "FALSE":
                    return []
                return [bmod.clause_negate(c) for c in clauses]
            inner = self._unary(rest)
            if len(inner) == 1:
                return [bmod.clause_negate(inner[0])]
            return [{"op": "unknown", "raw": raw}]
        if len(group) == 3 and words[1] in ("STREQUAL", "EQUAL") and not group[1].quoted:
            name = self._var_name(group[0])
            value = group[2].text
            if name is not None and "${" not in value and "$<" not in value:
                return [{"var": name, "op": "eq", "value": value}]
        return [{"op": "unknown", "raw": raw}]

    # ------------------------------------------------------------------ variables and expansion
    def builtin(self, name: str) -> Tuple[bool, Optional[str]]:
        if name in ("CMAKE_CURRENT_SOURCE_DIR",):
            return True, _SRC + (("/" + self.dir) if self.dir else "")
        if name in ("CMAKE_CURRENT_LIST_DIR",):
            return True, _SRC + (("/" + self.list_dir) if self.list_dir else "")
        if name in ("CMAKE_SOURCE_DIR", "PROJECT_SOURCE_DIR", "CMAKE_HOME_DIRECTORY"):
            return True, _SRC + (("/" + self.project_root) if self.project_root else "")
        if name.endswith("_SOURCE_DIR") and name[:-len("_SOURCE_DIR")] in self.project_names:
            root = self.project_names[name[:-len("_SOURCE_DIR")]]
            return True, _SRC + (("/" + root) if root else "")
        if name in ("CMAKE_CURRENT_LIST_FILE", "CMAKE_PARENT_LIST_FILE"):
            return True, self.file
        if name in ("CMAKE_CURRENT_BINARY_DIR", "CMAKE_BINARY_DIR", "PROJECT_BINARY_DIR", "CMAKE_CURRENT_LIST_LINE"):
            return True, None
        return False, None

    def lookup(self, name: str) -> Optional[str]:
        known, value = self.builtin(name)
        if known:
            return value
        known, value = self.scope.lookup(name)
        if known:
            return value
        if name in self.cache:
            return self.cache[name]
        return None

    def expand(self, text: str) -> Tuple[str, bool]:
        ok = True
        for _ in range(8):
            if "${" not in text:
                break

            def sub(match: "re.Match[str]") -> str:
                nonlocal ok
                value = self.lookup(match.group(1))
                if value is None:
                    ok = False
                    return ""
                return value

            new = _VAR_RE.sub(sub, text)
            if new == text:
                break
            text = new
        if "${" in text or "$<" in text or "$ENV{" in text or "$CACHE{" in text:
            ok = False
        return text, ok

    def args(self, command: Command, start: int = 0) -> List[Tuple[str, Arg, bool]]:
        return [(value, arg, ok) for value, arg, ok, _extra in self.args_c(command, start)]

    def args_c(self, command: Command, start: int = 0) -> List[Tuple[str, Arg, bool, Condition]]:
        """Like ``args`` with a fourth element: the condition under which an element of a conditionally built list variable
        (``set``/``list(APPEND)`` inside ``if``) was added, for an argument that is exactly ``${NAME}``."""
        out: List[Tuple[str, Arg, bool, Condition]] = []
        for arg in command.args[start:]:
            alts = None
            whole = _WHOLE_VAR_RE.match(arg.text) if not arg.quoted else None
            if whole is not None:
                alts = self.scope.alternatives(whole.group(1))
            if alts:
                for item, cond in alts:
                    out.append((item, arg, True, bmod.cond_and(None, cond)))
                continue
            value, ok = self.expand(arg.text)
            if not arg.quoted and ok and ";" in value and "\\;" not in value:
                for part in value.split(";"):
                    if part:
                        out.append((part, arg, True, None))
                continue
            if not arg.quoted and ok and value == "" and "${" in arg.text:
                continue
            out.append((value.replace("\\;", ";"), arg, ok, None))
        return out

    def alt_snapshot(self, name: str, parent: bool = False) -> Optional[List[Tuple[str, Condition]]]:
        """The elements (with their conditions) a list variable holds before an assignment, or None when its value is
        unknown (then no per-element conditions can be derived)."""
        scope = self.scope.parent if parent and self.scope.parent is not None else self.scope
        alts = scope.alternatives(name)
        if alts is not None:
            return list(alts)
        known, value = scope.lookup(name)
        if known and value is None:
            return None
        return [(i, None) for i in (value or "").split(";") if i]

    def alt_commit(self, name: str, before: Optional[List[Tuple[str, Condition]]], items: List[str], *, append: bool,
                   parent: bool = False) -> None:
        """Record the conditions of ``items`` just assigned to (or appended to) list variable ``name``."""
        if before is None:
            return
        had_alts = any(c is not None for _i, c in before)
        if self.cond is None and not had_alts:
            return
        scope = self.scope.parent if parent and self.scope.parent is not None else self.scope
        merged = list(before) if (append or self.cond is not None) else []
        for text in items:
            for item in text.split(";"):
                entry = (item, self.cond_copy())
                if item and entry not in merged:
                    merged.append(entry)
        scope.alts[name] = merged

    def set_var(self, name: str, value: Optional[str], *, parent: bool = False) -> None:
        scope = self.scope.parent if parent and self.scope.parent is not None else self.scope
        scope.vars[name] = value
        scope.alts.pop(name, None)

    def record_assign(self, name: str, value: Optional[str]) -> None:
        if value is not None:
            value = value.replace(_SRC + "/", "").replace(_SRC, ".")
        if self.cond is not None or self.in_function or value is None:
            self.var_assign[name] = None
        elif name in self.var_assign and self.var_assign[name] is None:
            return
        else:
            self.var_assign[name] = value

    def path_of(self, value: str) -> Optional[str]:
        """Repository-relative form of a path argument evaluated in the current directory, or None."""
        return _path_in(self.dir, value)

    # ------------------------------------------------------------------ driver
    def parse_file(self, path: str, scope: Optional[_Scope] = None, *, new_dir: Optional[str] = None,
                   include: bool = False, base: Condition = None) -> None:
        """Interpret one script. ``new_dir`` is the source directory (add_subdirectory); ``include`` keeps the caller's
        directory (``include()``)."""
        if self.depth >= MAX_FOLLOW_DEPTH or path in self.visited and not include:
            return
        text = self.S.fs.text(path)
        if text is None:
            return
        self.visited.add(path)
        self.bm.parsed_files.append(path)
        saved = (self.scope, self.dir, self.list_dir, self.file, self.frames, self.project_root, self.module_path[:],
                 self.base_depth)
        if scope is not None:
            self.scope = scope
        if new_dir is not None:
            self.dir = new_dir
        self.list_dir = posixpath.dirname(path)
        self.file = path
        if not include:
            self.frames = [_Frame("base", None, base)] if base is not None else []
        self.base_depth = 1 if (base is not None and not include) else (0 if not include else self.base_depth)
        self.depth += 1
        try:
            self.run(tokenize(text))
        finally:
            self.depth -= 1
            (self.scope, self.dir, self.list_dir, self.file, self.frames, self.project_root, self.module_path,
             self.base_depth) = saved

    def run(self, commands: List[Command]) -> None:
        index = 0
        total = len(commands)
        while index < total:
            command = commands[index]
            name = command.name
            if name in ("function", "macro"):
                end = self._find_end(commands, index, name, "end" + name)
                self._define_function(commands, index, end)
                index = end + 1
                continue
            if name == "foreach":
                end = self._find_end(commands, index, "foreach", "endforeach")
                self._foreach(commands, index, end)
                index = end + 1
                continue
            if name == "while":
                index = self._find_end(commands, index, "while", "endwhile") + 1
                continue
            if name == "block":
                index += 1
                continue
            handler = _HANDLERS.get(name)
            if handler is not None:
                try:
                    handler(self, command)
                except (IndexError, ValueError, KeyError, AttributeError) as exc:       # malformed command: skip it
                    self.S.log("discover.cmake_command_error", file=self.file, line=command.line, command=name,
                               error="%s: %s" % (type(exc).__name__, str(exc)[:100]))
            elif name in self.functions:
                if self.functions[name]:
                    self.bm.sensitive_calls.append((command.raw, self.file, command.line))
            index += 1

    @staticmethod
    def _find_end(commands: List[Command], start: int, opener: str, closer: str) -> int:
        depth = 0
        for index in range(start, len(commands)):
            name = commands[index].name
            if name == opener:
                depth += 1
            elif name == closer:
                depth -= 1
                if depth == 0:
                    return index
        return len(commands) - 1

    def _define_function(self, commands: List[Command], start: int, end: int) -> None:
        header = commands[start]
        if not header.args:
            return
        sensitive = any(c.name in _SENSITIVE for c in commands[start + 1:end])
        self.functions[header.args[0].text.lower()] = sensitive

    def _foreach(self, commands: List[Command], start: int, end: int) -> None:
        header = commands[start]
        body = commands[start + 1:end]
        if not header.args:
            return
        var = header.args[0].text
        items: Optional[List[str]] = None
        rest = self.args(header, 1)
        if rest and rest[0][0] == "RANGE":
            items = None
        elif rest and rest[0][0] in ("IN", "ZIP_LISTS"):
            if rest[0][0] == "IN":
                items = []
                mode = None
                for value, _arg, ok in rest[1:]:
                    if value in ("ITEMS", "LISTS"):
                        mode = value
                        continue
                    if mode == "LISTS":
                        known = self.lookup(value)
                        if known is None:
                            items = None
                            break
                        items.extend(p for p in known.split(";") if p)
                    elif ok:
                        items.append(value)
                    else:
                        items = None
                        break
        else:
            if all(ok for _v, _a, ok in rest):
                items = [value for value, _arg, _ok in rest]
        if items is not None and 0 < len(items) <= MAX_FOREACH:
            for item in items:
                self.set_var(var, item)
                self.run(body)
            return
        self.set_var(var, None)
        self.run(body)

    # ------------------------------------------------------------------ helpers for records
    def cond_copy(self) -> Condition:
        return None if self.cond is None else {"all": [dict(c) for c in self.cond["all"]]}

    def dir_str(self) -> str:
        return self.dir or "."


_SENSITIVE = frozenset(("add_executable", "add_library", "add_subdirectory", "target_sources", "target_link_libraries",
                        "find_package", "fetchcontent_declare", "cpmaddpackage", "externalproject_add", "pkg_check_modules"))


# --------------------------------------------------------------------------------------------------- handlers

def _h_if(p: CMakeParser, c: Command) -> None:
    cond = p.parse_condition(c.args)
    p.frames.append(_Frame("if", p.cond, cond))


def _h_elseif(p: CMakeParser, c: Command) -> None:
    if len(p.frames) <= p.base_depth:
        return
    frame = p.frames[-1]
    frame.prev.append(frame.cur)
    negated: Condition = None
    for earlier in frame.prev:
        negated = bmod.cond_and(negated, bmod.cond_negate(earlier))
    frame.cur = bmod.cond_and(negated, p.parse_condition(c.args))
    frame.eff = bmod.cond_and(frame.parent_eff, frame.cur)


def _h_else(p: CMakeParser, c: Command) -> None:
    if len(p.frames) <= p.base_depth:
        return
    frame = p.frames[-1]
    frame.prev.append(frame.cur)
    negated: Condition = None
    for earlier in frame.prev:
        negated = bmod.cond_and(negated, bmod.cond_negate(earlier))
    frame.cur = negated
    frame.eff = bmod.cond_and(frame.parent_eff, frame.cur)


def _h_endif(p: CMakeParser, c: Command) -> None:
    if len(p.frames) > p.base_depth:
        p.frames.pop()


def _h_project(p: CMakeParser, c: Command) -> None:
    if not c.args:
        return
    name = c.args[0].text
    p.project_names[name] = p.dir
    if not p.project_root or p.dir == "":
        p.project_root = p.dir
    p.set_var("PROJECT_NAME", name)
    if p.scope.parent is None:
        p.set_var("CMAKE_PROJECT_NAME", name)
    values = p.args(c, 1)
    for index, (value, _arg, ok) in enumerate(values):
        if value == "VERSION" and index + 1 < len(values) and values[index + 1][2]:
            version = values[index + 1][0]
            p.set_var("PROJECT_VERSION", version)
            p.set_var(name + "_VERSION", version)
            pieces = version.split(".")
            for suffix, piece in zip(("MAJOR", "MINOR", "PATCH", "TWEAK"), pieces):
                p.set_var("PROJECT_VERSION_" + suffix, piece)
                p.set_var("%s_VERSION_%s" % (name, suffix), piece)


def _h_option(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    name = values[0][0]
    default = values[2][0] if len(values) > 2 and values[2][2] else ("OFF" if len(values) <= 2 else None)
    p.bm.options.append({"name": name, "default": default, "path": p.file, "line": c.line, "evidence_id": None})
    if default is not None and name not in p.cache:
        p.cache[name] = default
    elif default is None:
        p.cache.pop(name, None)
    if bmod.TEST_OPTION_RE.match(name):
        p.bm.add_test_option(name)


def _h_dependent_option(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if len(values) < 3:
        return
    name = values[0][0]
    default = values[2][0] if values[2][2] else None
    option = {"name": name, "default": default, "path": p.file, "line": c.line, "evidence_id": None,
              "dependent": True, "depends": values[3][0] if len(values) > 3 else None,
              "force": values[4][0] if len(values) > 4 else None}
    p.bm.options.append(option)
    if default is not None and name not in p.cache:
        p.cache[name] = default
    if bmod.TEST_OPTION_RE.match(name):
        p.bm.add_test_option(name)


def _h_set(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    name = values[0][0]
    if name.startswith("ENV{"):
        return
    words = [v[0] for v in values]
    if "CACHE" in words:
        at = words.index("CACHE")
        data = [v for v in values[1:at]]
        value = ";".join(v[0] for v in data) if all(v[2] for v in data) else None
        if value is not None and (name not in p.cache or "FORCE" in words):
            p.cache[name] = value
            p.bm.cache_defaults.setdefault(name, value)
        elif value is None:
            p.cache.pop(name, None)
        return
    parent = "PARENT_SCOPE" in words
    data = [v for v in values[1:] if v[0] != "PARENT_SCOPE"]
    value = ";".join(v[0] for v in data) if all(v[2] for v in data) else None
    before = p.alt_snapshot(name, parent)
    if not data:
        p.scope.vars.pop(name, None)
        p.set_var(name, "", parent=parent)
        p.record_assign(name, "")
        return
    p.set_var(name, value, parent=parent)
    p.record_assign(name, value)
    if value is not None:
        p.alt_commit(name, before, [v[0] for v in data], append=False, parent=parent)


def _h_unset(p: CMakeParser, c: Command) -> None:
    if c.args:
        p.set_var(c.args[0].text, None)
        p.var_assign[c.args[0].text] = None


def _h_list(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if len(values) < 2:
        return
    mode, name = values[0][0], values[1][0]
    if mode in ("APPEND", "PREPEND"):
        items = values[2:]
        known = p.lookup(name)
        defined = p.scope.lookup(name)[0] or name in p.cache
        if all(i[2] for i in items) and (known is not None or not defined):
            current = [x for x in (known or "").split(";") if x]
            addition = [i[0] for i in items]
            new = current + addition if mode == "APPEND" else addition + current
            before = p.alt_snapshot(name)
            p.set_var(name, ";".join(new))
            p.record_assign(name, ";".join(new))
            p.alt_commit(name, before, addition, append=True)
            return
        p.set_var(name, None)
        p.var_assign[name] = None
        return
    if mode in ("LENGTH", "GET", "JOIN", "FIND", "SUBLIST") and len(values) > 2:
        p.set_var(values[-1][0], None)
        return
    p.set_var(name, None)
    p.var_assign[name] = None


def _h_unknown_out(index: int):
    def handler(p: CMakeParser, c: Command) -> None:
        values = p.args(c)
        if len(values) > index >= 0:
            p.set_var(values[index][0], None)
            p.var_assign[values[index][0]] = None
    return handler


def _h_string(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    mode = values[0][0]
    index = _STRING_OUT_INDEX.get(mode)
    if mode == "REGEX" and len(values) > 1:
        index = 4 if values[1][0] == "REPLACE" else 3
    if index is not None and len(values) > index:
        p.set_var(values[index][0], None)
        p.var_assign[values[index][0]] = None


def _h_file(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if len(values) < 2:
        return
    mode = values[0][0]
    out: Optional[str] = None
    if mode in ("GLOB", "GLOB_RECURSE"):
        out = values[1][0]
    elif mode in ("READ", "STRINGS", "TO_CMAKE_PATH", "TO_NATIVE_PATH", "REAL_PATH", "SIZE", "TIMESTAMP", "SHA256",
                  "MD5", "SHA1", "RELATIVE_PATH") and len(values) > 2:
        out = values[2][0]
    if out:
        p.set_var(out, None)
        p.var_assign[out] = None


def _h_execute_process(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    for index, (value, _arg, _ok) in enumerate(values):
        if value.endswith("_VARIABLE") and index + 1 < len(values):
            p.set_var(values[index + 1][0], None)
            p.var_assign[values[index + 1][0]] = None


def _h_check(p: CMakeParser, c: Command) -> None:
    index = _CHECK_COMMANDS.get(c.name, -1)
    values = p.args(c)
    if 0 <= index < len(values):
        var = values[index][0]
        p.set_var(var, None)
        p.var_assign[var] = None
        p.S.generated_macros["checks"].append({"path": p.file, "line": c.line, "macro": var})


def _h_try(p: CMakeParser, c: Command) -> None:
    for arg in c.args[:2 if c.name == "try_run" else 1]:
        if _BARE_VAR_RE.match(arg.text):
            p.S.generated_macros["checks"].append({"path": p.file, "line": c.line, "macro": arg.text})
            p.set_var(arg.text, None)
            p.var_assign[arg.text] = None


def _h_include(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    target, _arg, ok = values[0]
    if target in ("CTest", "CTest.cmake"):
        if not any(o["name"] == "BUILD_TESTING" for o in p.bm.options):
            p.bm.options.append({"name": "BUILD_TESTING", "default": "ON", "path": p.file, "line": c.line,
                                 "evidence_id": None})
        p.cache.setdefault("BUILD_TESTING", "ON")
        p.bm.add_test_option("BUILD_TESTING")
        return
    if not ok:
        return
    local = p.path_of(target)
    if local is None:
        return
    candidates: List[str] = [local]
    if not target.endswith(".cmake"):
        candidates.append(local + ".cmake")
        if "/" not in target:
            for module_dir in list(p.module_path) + ["cmake", "CMake", ""]:
                candidates.append(posixpath.normpath(posixpath.join(module_dir, target + ".cmake")) if module_dir
                                  else target + ".cmake")
    for path in candidates:
        if path and p.S.tracked(path) and p.S.fs.exists(path):
            p.parse_file(path, include=True)
            return


def _h_add_subdirectory(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    value, _arg, ok = values[0]
    if not ok:
        p.bm.sensitive_calls.append(("add_subdirectory(%s)" % c.args[0].text, p.file, c.line))
        return
    path = p.path_of(value)
    if path is None:
        return
    entry = {"path": path or ".", "line": c.line, "condition": p.cond_copy(), "evidence_id": None,
             "from": p.dir_str(), "file": p.file}
    if "EXCLUDE_FROM_ALL" in [v[0] for v in values]:
        entry["exclude_from_all"] = True
    p.bm.subdirs.append(entry)
    p.bm.dir_edges.append((p.dir, path, p.cond_copy()))
    build_file = (path + "/CMakeLists.txt") if path else "CMakeLists.txt"
    if build_file not in p.visited and p.S.tracked(build_file):
        child = _Scope(p.scope)
        p.parse_file(build_file, child, new_dir=path, base=p.cond_copy() or {"all": []})


def _h_add_target(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    name = values[0][0]
    is_library = c.name == "add_library"
    words = [v[0] for v in values[1:]]
    if "ALIAS" in words:
        index = words.index("ALIAS")
        if index + 1 < len(words):
            p.aliases[name] = words[index + 1]
        return
    kind = "executable"
    if is_library:
        kind = "static_library"
        for word, mapped in (("STATIC", "static_library"), ("SHARED", "shared_library"), ("MODULE", "module_library"),
                             ("OBJECT", "object_library"), ("INTERFACE", "interface_library")):
            if word in words:
                kind = mapped
                break
    if "IMPORTED" in words:
        p.imported.setdefault(name, None)
        return
    target = {"name": name, "kind": kind, "dir": p.dir_str(), "path": p.file, "line": c.line, "test": False,
              "sources": [], "link": [], "include_dirs": [], "definitions": [], "condition": p.cond_copy(),
              "evidence_id": None, "_unresolved": False, "_objects": []}
    for value, arg, ok, extra in p.args_c(c, 1):
        if value in _TARGET_KEYWORDS and not arg.quoted:
            continue
        _add_source(p, target, value, arg, ok, c.line, extra)
    p.bm.targets.append(target)


def _add_source(p: CMakeParser, target: Dict[str, Any], value: str, arg: Arg, ok: bool, line: int,
                extra: Condition = None) -> None:
    objects = re.match(r"^\$<TARGET_OBJECTS:([^>]+)>$", arg.text)
    if objects is not None:
        target["_objects"].append(objects.group(1))
        return
    if not ok:
        target["_unresolved"] = True
        return
    path = p.path_of(value)
    if path is None:
        target["_unresolved"] = True if value.startswith("$") else target["_unresolved"]
        return
    target["sources"].append({"path": path, "line": arg.line or line, "condition": bmod.cond_and(p.cond_copy(), extra),
                              "file": p.file})


def _h_add_custom_target(p: CMakeParser, c: Command) -> None:
    if c.args:
        p.bm.targets.append({"name": c.args[0].text, "kind": "custom", "dir": p.dir_str(), "path": p.file, "line": c.line,
                             "test": False, "sources": [], "link": [], "include_dirs": [], "definitions": [],
                             "condition": p.cond_copy(), "evidence_id": None, "_unresolved": False, "_objects": []})


def _target_op(kind: str):
    def handler(p: CMakeParser, c: Command) -> None:
        if not c.args:
            return
        name = c.args[0].text
        p.ops.append({"kind": kind, "target": name, "command": c, "dir": p.dir, "file": p.file, "cond": p.cond_copy(),
                      "values": p.args_c(c, 1)})
    return handler


def _h_global_link(p: CMakeParser, c: Command) -> None:
    for value, arg, ok in p.args(c):
        if value in _LINK_KEYWORDS or not ok:
            continue
        p.bm.globals["link"].append({"item": value, "line": arg.line, "condition": p.cond_copy(), "path": p.file})


def _h_global_include(p: CMakeParser, c: Command) -> None:
    for value, arg, ok in p.args(c):
        if value in ("SYSTEM", "BEFORE", "AFTER") or not ok:
            continue
        path = p.path_of(_strip_genex(value))
        if path is not None:
            p.bm.globals["include_dirs"].append({"path": path or ".", "line": arg.line, "condition": p.cond_copy(),
                                                 "file": p.file})


def _definition(value: str) -> Tuple[str, Optional[str]]:
    text = value[2:] if value.startswith("-D") else value
    name, sep, val = text.partition("=")
    return name, (val if sep else None)


def _h_global_definitions(p: CMakeParser, c: Command) -> None:
    for value, arg, ok in p.args(c):
        if not ok:
            continue
        if c.name == "add_definitions" and not value.startswith("-D"):
            continue
        name, val = _definition(value)
        if name and re.match(r"^[A-Za-z_]\w*$", name):
            p.bm.globals["definitions"].append({"name": name, "value": val, "line": arg.line,
                                                "condition": p.cond_copy(), "path": p.file})


def _strip_genex(value: str) -> str:
    match = re.match(r"^\$<BUILD_INTERFACE:(.*)>$", value)
    if match:
        return match.group(1)
    return value


def _package_record(p: CMakeParser, name: str, kind: str, c: Command, required: bool,
                    constraint: Optional[str]) -> None:
    p.bm.packages.append({"name": name, "kind": kind, "version_constraint": constraint, "required": required,
                          "condition": p.cond_copy(), "path": p.file, "line": c.line, "evidence_id": None})


def _h_find_package(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    name = values[0][0]
    if not values[0][2] or not name:
        return
    words = [v[0] for v in values]
    constraint = None
    if len(values) > 1 and re.match(r"^\d+(?:\.\d+)*$", values[1][0]):
        constraint = values[1][0]
    required = "REQUIRED" in words
    p.set_var(name + "_FOUND", None)
    _package_record(p, name, "find_package", c, required, constraint)


def _split_module(spec: str) -> Tuple[str, Optional[str]]:
    match = re.match(r"^([^<>=!\s]+)\s*(>=|<=|=|==|<|>)\s*(\S+)$", spec)
    if match:
        op = "==" if match.group(2) == "=" else match.group(2)
        return match.group(1), op + match.group(3)
    return spec, None


def _h_pkg_check_modules(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if len(values) < 2:
        return
    prefix = values[0][0]
    p.set_var(prefix + "_FOUND", None)
    words = [v[0] for v in values]
    required = "REQUIRED" in words
    index = 1
    pending: List[str] = []
    while index < len(values):
        value = values[index][0]
        index += 1
        if value in _PKG_KEYWORDS:
            continue
        if value in (">=", "<=", "=", "==", "<", ">") and pending and index < len(values):
            pending[-1] = pending[-1] + value + values[index][0]
            index += 1
            continue
        pending.append(value)
    for spec in pending:
        name, constraint = _split_module(spec)
        if name:
            _package_record(p, name, "pkg_check_modules", c, required, constraint)


def _h_find_program(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    p.set_var(values[0][0], None)
    names: List[str] = []
    for value, _arg, ok in values[1:]:
        if value in ("NAMES", "PATHS", "HINTS", "DOC", "REQUIRED", "NO_DEFAULT_PATH", "PATH_SUFFIXES", "NAMES_PER_DIR"):
            if value in ("PATHS", "HINTS", "DOC", "PATH_SUFFIXES"):
                break
            continue
        if ok:
            names.append(value)
    if names:
        _package_record(p, names[0], "find_program", c, "REQUIRED" in [v[0] for v in values], None)


def _h_find_out(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if values:
        p.set_var(values[0][0], None)
        p.var_assign[values[0][0]] = None


def _kw_value(values: List[Tuple[str, Arg, bool]], key: str) -> Tuple[Optional[str], Optional[int]]:
    for index, (value, arg, ok) in enumerate(values):
        if value == key and index + 1 < len(values):
            nxt = values[index + 1]
            return (nxt[0] if nxt[2] else None), nxt[1].line
    return None, None


_FETCH_KEYS = ("GIT_REPOSITORY", "GIT_TAG", "URL", "URL_HASH", "SOURCE_DIR", "SVN_REPOSITORY", "SVN_REVISION",
               "DOWNLOAD_COMMAND", "GIT_SHALLOW", "GIT_PROGRESS", "SOURCE_SUBDIR", "OVERRIDE_FIND_PACKAGE", "FIND_PACKAGE_ARGS",
               "BINARY_DIR", "PATCH_COMMAND", "UPDATE_COMMAND", "CONFIGURE_COMMAND", "BUILD_COMMAND", "INSTALL_COMMAND",
               "TEST_COMMAND", "GIT_SUBMODULES", "DOWNLOAD_NO_EXTRACT", "DOWNLOAD_DIR", "LOG_DOWNLOAD", "EXCLUDE_FROM_ALL",
               "SYSTEM", "CMAKE_ARGS", "CMAKE_CACHE_ARGS", "DEPENDS", "BUILD_IN_SOURCE", "STEP_TARGETS", "PREFIX", "GIT_REMOTE_NAME")


def _fetch_record(p: CMakeParser, kind: str, name: str, c: Command, values: List[Tuple[str, Arg, bool]],
                  *, repo: Optional[str] = None, tag: Optional[str] = None, tag_line: Optional[int] = None,
                  url: Optional[str] = None, version: Optional[str] = None) -> Dict[str, Any]:
    record = {"kind": kind, "name": name, "repo": repo, "tag": tag, "url": url, "version": version,
              "path": p.file, "line": c.line, "tag_line": tag_line or c.line, "condition": p.cond_copy(),
              "available": kind in ("cpm", "external_project"), "dir": p.dir}
    local = _kw_value(values, "SOURCE_DIR")[0]
    if local:
        record["local_source"] = local
    return record


def _h_fetch_declare(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    name = values[0][0]
    repo, _ = _kw_value(values, "GIT_REPOSITORY")
    tag, tag_line = _kw_value(values, "GIT_TAG")
    url, url_line = _kw_value(values, "URL")
    record = _fetch_record(p, "fetchcontent", name, c, values, repo=repo, tag=tag, tag_line=tag_line or url_line, url=url)
    p.declared[name.lower()] = record
    p.bm.fetch_decls.append(record)


def _h_fetch_available(p: CMakeParser, c: Command) -> None:
    for value, _arg, _ok in p.args(c):
        record = p.declared.get(value.lower())
        if record is not None:
            record["available"] = True
        p.available.add(value.lower())


def _h_cpm(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    keys = [v[0] for v in values]
    name = _kw_value(values, "NAME")[0]
    repo: Optional[str] = None
    tag: Optional[str] = None
    tag_line = c.line
    version = _kw_value(values, "VERSION")[0]
    url = _kw_value(values, "URL")[0]
    github = _kw_value(values, "GITHUB_REPOSITORY")[0]
    gitlab = _kw_value(values, "GITLAB_REPOSITORY")[0]
    bitbucket = _kw_value(values, "BITBUCKET_REPOSITORY")[0]
    git_repo = _kw_value(values, "GIT_REPOSITORY")[0]
    tag, tag_line_found = _kw_value(values, "GIT_TAG")
    if tag_line_found:
        tag_line = tag_line_found
    if github:
        repo = "https://github.com/" + github
    elif gitlab:
        repo = "https://gitlab.com/" + gitlab
    elif bitbucket:
        repo = "https://bitbucket.org/" + bitbucket
    elif git_repo:
        repo = git_repo
    shorthand = None
    if not any(k in keys for k in ("NAME", "GITHUB_REPOSITORY", "GIT_REPOSITORY", "URL")) or (
            values and values[0][0] == "URI" and len(values) > 1):
        shorthand = values[1][0] if values[0][0] == "URI" and len(values) > 1 else values[0][0]
    elif len(values) == 1 and re.match(r"^(?:gh|gl|bb):", values[0][0]):
        shorthand = values[0][0]
    if shorthand:
        match = re.match(r"^(gh|gl|bb):([^@#\s]+)(?:[@#](.+))?$", shorthand)
        if match:
            host = {"gh": "https://github.com/", "gl": "https://gitlab.com/", "bb": "https://bitbucket.org/"}[match.group(1)]
            repo = host + match.group(2)
            tag = match.group(3) or tag
            name = name or match.group(2).rsplit("/", 1)[-1]
        else:
            return
    if not name:
        name = (repo or url or "").rstrip("/").rsplit("/", 1)[-1].replace(".git", "") or None
    if not name:
        return
    if tag is None and version and not url:
        tag = version if re.match(r"^v", version) else "v" + version if repo and "github" in repo else version
    record = _fetch_record(p, "cpm", name, c, values, repo=repo, tag=tag, tag_line=tag_line, url=url, version=version)
    p.bm.fetch_decls.append(record)


def _h_external_project(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    name = values[0][0]
    repo, _ = _kw_value(values, "GIT_REPOSITORY")
    tag, tag_line = _kw_value(values, "GIT_TAG")
    url, url_line = _kw_value(values, "URL")
    record = _fetch_record(p, "external_project", name, c, values, repo=repo, tag=tag, tag_line=tag_line or url_line, url=url)
    p.bm.fetch_decls.append(record)


def _h_add_test(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if not values:
        return
    command: Optional[str] = None
    if values[0][0] == "NAME":
        command, _ = _kw_value(values, "COMMAND")
    elif len(values) > 1:
        command = values[1][0]
    if command:
        p.ops.append({"kind": "add_test", "target": command, "command": c, "dir": p.dir, "file": p.file,
                      "cond": p.cond_copy(), "values": values})


def _h_discover_tests(p: CMakeParser, c: Command) -> None:
    if c.args:
        p.ops.append({"kind": "discover_tests", "target": c.args[0].text, "command": c, "dir": p.dir, "file": p.file,
                      "cond": p.cond_copy(), "values": []})


def _h_set_target_properties(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    words = [v[0] for v in values]
    if "PROPERTIES" not in words:
        return
    at = words.index("PROPERTIES")
    targets = words[:at]
    props = values[at + 1:]
    for index, (value, _arg, ok) in enumerate(props):
        if value in ("IMPORTED_LOCATION", "IMPORTED_LOCATION_RELEASE", "IMPORTED_LOCATION_DEBUG") and index + 1 < len(props):
            loc = props[index + 1]
            path = p.path_of(loc[0]) if loc[2] else None
            for target in targets:
                p.imported[target] = path


def _h_list_dir_var(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if len(values) >= 2:
        p.set_var(values[0][0], None)


def _h_cmake_path(p: CMakeParser, c: Command) -> None:
    values = p.args(c)
    if len(values) >= 2 and values[0][0] == "SET":
        p.set_var(values[1][0], None)


def _h_find_package_dep(p: CMakeParser, c: Command) -> None:
    _h_find_package(p, c)


_HANDLERS: Dict[str, Any] = {
    "if": _h_if, "elseif": _h_elseif, "else": _h_else, "endif": _h_endif, "project": _h_project, "option": _h_option,
    "cmake_dependent_option": _h_dependent_option, "set": _h_set, "unset": _h_unset, "list": _h_list,
    "string": _h_string, "file": _h_file, "execute_process": _h_execute_process, "include": _h_include,
    "add_subdirectory": _h_add_subdirectory, "add_executable": _h_add_target, "add_library": _h_add_target,
    "add_custom_target": _h_add_custom_target, "target_sources": _target_op("sources"),
    "target_link_libraries": _target_op("link"), "target_include_directories": _target_op("include"),
    "target_compile_definitions": _target_op("definitions"), "link_libraries": _h_global_link,
    "include_directories": _h_global_include, "add_compile_definitions": _h_global_definitions,
    "add_definitions": _h_global_definitions, "find_package": _h_find_package, "find_dependency": _h_find_package_dep,
    "pkg_check_modules": _h_pkg_check_modules, "pkg_search_module": _h_pkg_check_modules, "find_program": _h_find_program,
    "find_library": _h_find_out, "find_path": _h_find_out, "find_file": _h_find_out,
    "fetchcontent_declare": _h_fetch_declare, "fetchcontent_makeavailable": _h_fetch_available,
    "fetchcontent_populate": _h_fetch_available, "cpmaddpackage": _h_cpm, "cpmfindpackage": _h_cpm,
    "externalproject_add": _h_external_project, "add_test": _h_add_test, "gtest_discover_tests": _h_discover_tests,
    "gtest_add_tests": _h_discover_tests, "catch_discover_tests": _h_discover_tests,
    "doctest_discover_tests": _h_discover_tests, "set_target_properties": _h_set_target_properties,
    "get_filename_component": _h_list_dir_var, "cmake_path": _h_cmake_path, "try_compile": _h_try, "try_run": _h_try,
    "configure_file": lambda p, c: None, "math": _h_unknown_out(1),
}
for _name in _CHECK_COMMANDS:
    _HANDLERS[_name] = _h_check


# --------------------------------------------------------------------------------------------------- finishing

def _resolve_alias(parser: CMakeParser, name: str) -> str:
    seen = 0
    while name in parser.aliases and seen < 8:
        name = parser.aliases[name]
        seen += 1
    return name


def _apply_ops(parser: CMakeParser) -> None:
    bm = parser.bm
    for op in parser.ops:
        name = _resolve_alias(parser, op["target"])
        target = bm.target(name, op["dir"] or ".")
        kind = op["kind"]
        if kind in ("add_test", "discover_tests"):
            if target is not None and (kind == "discover_tests" or _looks_like_test(target)):
                target["test"] = True
            continue
        if target is None:
            continue
        values: List[Tuple[str, Arg, bool, Condition]] = op["values"]
        file, base_cond, directory = op["file"], op["cond"], op["dir"]
        for value, arg, ok, extra in values:
            cond = bmod.cond_and(base_cond, extra)
            if value in _TARGET_KEYWORDS or value in _LINK_KEYWORDS:
                continue
            if kind == "link":
                if ok and value:
                    target["link"].append({"item": value, "line": arg.line, "condition": cond, "file": file})
            elif kind == "sources":
                tmp_path = _path_in(directory, value) if ok else None
                if tmp_path is not None:
                    target["sources"].append({"path": tmp_path, "line": arg.line, "condition": cond, "file": file})
                else:
                    objects = re.match(r"^\$<TARGET_OBJECTS:([^>]+)>$", arg.text)
                    if objects is not None:
                        target["_objects"].append(objects.group(1))
                    else:
                        target["_unresolved"] = True
            elif kind == "include":
                if not ok:
                    continue
                path = _path_in(directory, _strip_genex(value))
                if path is not None:
                    target["include_dirs"].append({"path": path or ".", "line": arg.line, "condition": cond, "file": file})
            elif kind == "definitions":
                if not ok:
                    continue
                dname, dval = _definition(value)
                if dname and re.match(r"^[A-Za-z_]\w*$", dname):
                    target["definitions"].append({"name": dname, "value": dval, "line": arg.line, "condition": cond,
                                                  "file": file})


def _path_in(directory: str, value: str) -> Optional[str]:
    """Repository-relative form of a path argument evaluated in ``directory`` ('' = the root), or None."""
    text = value.strip().replace("\\", "/")
    if not text or text.startswith(("$", "-")):
        return None
    if text.startswith(_SRC):
        joined = posixpath.normpath(text[len(_SRC):].lstrip("/") or ".")
    elif text.startswith("/"):
        return None
    else:
        joined = posixpath.normpath(posixpath.join(directory or ".", text))
    if joined.startswith("..") or joined.startswith("/"):
        return None
    return "" if joined == "." else joined


def _looks_like_test(target: Dict[str, Any]) -> bool:
    from sbomlib.discover import session as sess
    name = target["name"].lower()
    if re.search(r"(?:^|[_\-.])(?:test|tests|unittest|unittests|check|spec|specs)(?:$|[_\-.])|test", name):
        return True
    return sess.scope_of_path(target["path"]) == "test"


def _expand_objects(parser: CMakeParser) -> None:
    bm = parser.bm
    for target in bm.targets:
        for obj in target.get("_objects", []):
            source = bm.target(_resolve_alias(parser, obj), target["dir"])
            if source is None:
                target["_unresolved"] = True
                continue
            for item in source["sources"]:
                target["sources"].append(dict(item))


def finish(S: Session, parser: CMakeParser) -> None:
    """Apply the deferred target operations and expand object libraries (targets are settled by ``buildrefs``)."""
    bm = S.bm
    _apply_ops(parser)
    _expand_objects(parser)
    bm.aliases.update(parser.aliases)
    bm.imported.update(parser.imported)


# --------------------------------------------------------------------------------------------------- entry points

def parse_all(S: Session, cmake_files: List[str]) -> Optional[CMakeParser]:
    """Interpret every tracked CMake script reachable from a root ``CMakeLists.txt``; unreachable ones (a vendored
    project's own build) are interpreted as roots of their own so their targets are known."""
    lists = sorted((p for p in cmake_files if posixpath.basename(p) == "CMakeLists.txt"),
                   key=lambda p: (p.count("/"), p))
    if not lists:
        return None
    parser = CMakeParser(S)
    for path in lists:
        S.check_budget()
        if path in parser.visited:
            continue
        directory = posixpath.dirname(path)
        parser.project_root = directory
        S.bm.roots.append(directory)
        parser.parse_file(path, _Scope(), new_dir=directory)
    S.bm.systems.add("cmake")
    finish(S, parser)
    return parser


# --------------------------------------------------------------------------------------------------- presets

def _preset_lines(text: str) -> Dict[str, int]:
    lines: Dict[str, int] = {}
    for number, line in enumerate(text.split("\n"), start=1):
        for match in re.finditer(r'"name"\s*:\s*"([^"]+)"', line):
            lines.setdefault(match.group(1), number)
    return lines


def _cache_value(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if isinstance(value, dict):
        return _cache_value(value.get("value"))
    if value is None:
        return None
    return str(value)


def parse_presets(S: Session, files: List[str]) -> None:
    """``CMakePresets.json`` configure presets with ``inherits`` and ``include`` (``CMakeUserPresets.json`` is ignored)."""
    presets: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    def load(path: str, depth: int) -> None:
        if depth > 8:
            return
        text = S.fs.text(path)
        if text is None:
            return
        try:
            data = json.loads(text)
        except ValueError:
            S.log("discover.presets_invalid", file=path)
            return
        if not isinstance(data, dict):
            return
        lines = _preset_lines(text)
        base = posixpath.dirname(path)
        for include in data.get("include") or []:
            if isinstance(include, str):
                target = posixpath.normpath(posixpath.join(base or ".", include))
                if S.tracked(target) and posixpath.basename(target) != "CMakeUserPresets.json":
                    load(target, depth + 1)
        for preset in data.get("configurePresets") or []:
            if not isinstance(preset, dict) or not isinstance(preset.get("name"), str):
                continue
            name = preset["name"]
            if name not in presets:
                order.append(name)
            inherits = preset.get("inherits") or []
            if isinstance(inherits, str):
                inherits = [inherits]
            variables = preset.get("cacheVariables")
            cache = {k: _cache_value(v) for k, v in variables.items()} if isinstance(variables, dict) else {}
            presets[name] = {"name": name, "source": path, "line": lines.get(name, 1), "hidden": bool(preset.get("hidden")),
                             "inherits": [i for i in inherits if isinstance(i, str)], "own": cache}

    for path in files:
        if posixpath.basename(path) == "CMakePresets.json":
            load(path, 0)

    def resolve(name: str, stack: Tuple[str, ...]) -> Dict[str, Optional[str]]:
        preset = presets.get(name)
        if preset is None or name in stack:
            return {}
        merged: Dict[str, Optional[str]] = {}
        for parent in reversed(preset["inherits"]):          # earlier parents take precedence
            merged.update(resolve(parent, stack + (name,)))
        merged.update(preset["own"])
        return merged

    named: Dict[str, List[str]] = {}
    for script in S.release_scripts:
        for preset in script["presets"]:
            named.setdefault(preset, []).append(script["path"])
    for name in order:
        preset = presets[name]
        S.bm.configurations.append({
            "name": name, "source": preset["source"], "line": preset["line"], "hidden": preset["hidden"],
            "inherits": list(preset["inherits"]),
            "cache": {k: v for k, v in sorted(resolve(name, ()).items()) if v is not None},
            "named_by": sorted(named.get(name, []))})
