"""Meson: ``meson.build`` interpreter, option files and ``subprojects/*.wrap`` (contract sections 3.9, 4.7).

A small tokenizer and expression parser (strings, names, lists, calls with keyword arguments, method chains,
``if`` / ``elif`` / ``else`` / ``foreach``) walks the build files; nothing is executed and Meson is never run. Wrap files
are read with ``configparser``. ``dependency()`` becomes a package, ``subproject()`` and ``subdir()`` become
subdirectories that are followed, ``executable()`` / ``library()`` become targets, ``test()`` marks its executable as a
test target, and ``get_option()`` conditions refer to the options of ``meson_options.txt`` / ``meson.options``.
"""
from __future__ import annotations

import configparser
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import versions
from sbomlib.discover import bm as bmod
from sbomlib.discover.bm import Condition
from sbomlib.discover.manifests import declare
from sbomlib.discover.session import Session

MAX_DEPTH = 30
_TOKEN_RE = re.compile(r"""
    (?P<ws>[ \t\r]+) | (?P<comment>\#[^\n]*) | (?P<nl>\n)
  | (?P<mstr>'''.*?''') | (?P<str>'(?:\\.|[^'\\\n])*') | (?P<num>0[xX][0-9a-fA-F]+|\d+)
  | (?P<name>[A-Za-z_][A-Za-z0-9_]*) | (?P<op>==|!=|<=|>=|\+=|[()\[\]{},:.=<>+\-*/%?])
""", re.X | re.S)
_TARGET_FUNCS = {"executable": "executable", "library": "static_library", "static_library": "static_library",
                 "shared_library": "shared_library", "both_libraries": "static_library", "shared_module": "module_library",
                 "build_target": "static_library", "jar": "custom"}
_TEST_OPTION_NAMES = ("tests", "test", "build_tests", "enable_tests", "with_tests", "unit_tests", "testing")
_SYSTEM_NAMES = {"linux": "Linux", "windows": "Windows", "darwin": "Darwin", "freebsd": "FreeBSD", "netbsd": "NetBSD",
                 "openbsd": "OpenBSD", "android": "Android", "cygwin": "CYGWIN", "sunos": "SunOS", "haiku": "Haiku",
                 "emscripten": "Emscripten", "dragonfly": "DragonFly"}      # Meson's lowercase names in CMake's spelling
_PLATFORM_CALLS = {"host_machine.system": "CMAKE_SYSTEM_NAME", "host_machine.cpu_family": "CMAKE_SYSTEM_PROCESSOR",
                   "host_machine.cpu": "CMAKE_SYSTEM_PROCESSOR", "build_machine.system": "CMAKE_HOST_SYSTEM_NAME",
                   "cc.get_id": "CMAKE_C_COMPILER_ID", "cpp.get_id": "CMAKE_CXX_COMPILER_ID"}


class Tok:
    __slots__ = ("kind", "text", "line")

    def __init__(self, kind: str, text: str, line: int) -> None:
        self.kind = kind
        self.text = text
        self.line = line

    def __repr__(self) -> str:                                  # pragma: no cover - debugging aid
        return "Tok(%s %r @%d)" % (self.kind, self.text, self.line)


def tokenize(text: str) -> List[Tok]:
    """Tokens with 1-based lines; newlines inside brackets are dropped, a ``nl`` token ends a statement."""
    tokens: List[Tok] = []
    pos = 0
    line = 1
    depth = 0
    n = len(text)
    while pos < n:
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            pos += 1
            continue
        kind = match.lastgroup or ""
        chunk = match.group(0)
        if kind == "nl":
            if depth == 0:
                tokens.append(Tok("nl", "\n", line))
            line += 1
        elif kind in ("ws", "comment"):
            pass
        elif kind in ("str", "mstr"):
            body = chunk[3:-3] if kind == "mstr" else chunk[1:-1]
            tokens.append(Tok("str", re.sub(r"\\(.)", r"\1", body) if kind == "str" else body, line))
            line += chunk.count("\n")
        else:
            if chunk in "([{":
                depth += 1
            elif chunk in ")]}":
                depth = max(0, depth - 1)
            tokens.append(Tok(kind, chunk, line))
        pos = match.end()
    tokens.append(Tok("nl", "\n", line))
    return tokens


# --------------------------------------------------------------------------------------------------- expressions

class Node:
    """Expression node: ``kind`` is str, name, list, call, method, binop or other."""
    __slots__ = ("kind", "value", "args", "kwargs", "obj", "line", "text")

    def __init__(self, kind: str, value: Any = None, line: int = 0, text: str = "") -> None:
        self.kind = kind
        self.value = value
        self.args: List["Node"] = []
        self.kwargs: Dict[str, "Node"] = {}
        self.obj: Optional["Node"] = None
        self.line = line
        self.text = text


class ExprParser:
    def __init__(self, tokens: List[Tok], pos: int = 0) -> None:
        self.t = tokens
        self.i = pos

    def peek(self) -> Optional[Tok]:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> Tok:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def accept(self, text: str) -> bool:
        tok = self.peek()
        if tok is not None and tok.text == text and tok.kind in ("op", "name"):
            self.i += 1
            return True
        return False

    def expr(self) -> Node:
        node = self.primary()
        while True:
            tok = self.peek()
            if tok is None or tok.kind == "nl":
                return node
            if tok.kind == "op" and tok.text in ("+", "-", "*", "/", "%", "==", "!=", "<", ">", "<=", ">=", "?", ":") \
                    or (tok.kind == "name" and tok.text in ("and", "or", "in", "not")):
                op = self.take()
                if op.text == "?":
                    self.expr()
                    self.accept(":")
                    self.expr()
                    node = Node("other", line=node.line, text="?")
                    continue
                right = self.primary()
                if op.text == "+" and node.kind == "list" and right.kind == "list":
                    merged = Node("list", line=node.line)
                    merged.args = node.args + right.args
                    node = merged
                elif op.text == "+" and node.kind == "str" and right.kind == "str":
                    node = Node("str", node.value + right.value, node.line)
                elif op.text == "/" and node.kind == "str" and right.kind == "str":
                    node = Node("str", node.value + "/" + right.value, node.line)
                else:
                    node = Node("other", line=node.line, text=op.text)
                continue
            return node

    def primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            return Node("other")
        if tok.kind == "nl":
            return Node("other", line=tok.line)
        self.i += 1
        if tok.kind == "str":
            node = Node("str", tok.text, tok.line)
        elif tok.kind == "num":
            node = Node("other", line=tok.line, text=tok.text)
        elif tok.kind == "op" and tok.text == "[":
            node = Node("list", line=tok.line)
            while self.peek() is not None and not (self.peek().kind == "op" and self.peek().text == "]"):   # type: ignore[union-attr]
                if self.peek().kind == "nl":                                                                   # type: ignore[union-attr]
                    self.i += 1
                    continue
                node.args.append(self.expr())
                self.accept(",")
            self.accept("]")
        elif tok.kind == "op" and tok.text == "{":
            depth = 1
            while self.peek() is not None and depth:
                cur = self.take()
                if cur.text == "{":
                    depth += 1
                elif cur.text == "}":
                    depth -= 1
            node = Node("other", line=tok.line, text="dict")
        elif tok.kind == "op" and tok.text == "(":
            node = self.expr()
            self.accept(")")
        elif tok.kind == "name" and tok.text == "not":
            self.primary()
            node = Node("other", line=tok.line, text="not")
        elif tok.kind == "name":
            nxt = self.peek()
            if nxt is not None and nxt.kind == "op" and nxt.text == "(":
                self.i += 1
                node = Node("call", tok.text, tok.line)
                self._arguments(node)
            else:
                node = Node("name", tok.text, tok.line)
        else:
            node = Node("other", line=tok.line, text=tok.text)
        while True:
            nxt = self.peek()
            if nxt is not None and nxt.kind == "op" and nxt.text == ".":
                self.i += 1
                name = self.take()
                method = Node("method", name.text, name.line)
                method.obj = node
                after = self.peek()
                if after is not None and after.kind == "op" and after.text == "(":
                    self.i += 1
                    self._arguments(method)
                node = method
            elif nxt is not None and nxt.kind == "op" and nxt.text == "[":
                self.i += 1
                self.expr()
                self.accept("]")
                node = Node("other", line=node.line, text="index")
            else:
                return node

    def _arguments(self, node: Node) -> None:
        while True:
            tok = self.peek()
            if tok is None:
                return
            if tok.kind == "nl":
                self.i += 1
                continue
            if tok.kind == "op" and tok.text == ")":
                self.i += 1
                return
            if tok.kind == "op" and tok.text == ",":
                self.i += 1
                continue
            if tok.kind == "name" and self.i + 1 < len(self.t) and self.t[self.i + 1].kind == "op" \
                    and self.t[self.i + 1].text == ":":
                self.i += 2
                node.kwargs[tok.text] = self.expr()
                continue
            node.args.append(self.expr())


# --------------------------------------------------------------------------------------------------- interpreter

class MesonParser:
    def __init__(self, S: Session) -> None:
        self.S = S
        self.bm = S.bm
        self.vars: Dict[str, Node] = {}
        self.lists: Dict[str, List[Tuple[str, int, Condition]]] = {}     # string-list variables with per-element conditions
        self.dep_vars: Dict[str, Dict[str, Any]] = {}
        self.target_vars: Dict[str, str] = {}
        self.frames: List[Condition] = []
        self.visited: set = set()
        self.dir = ""
        self.file = ""
        self.depth = 0
        self.options: Dict[str, str] = {}

    @property
    def cond(self) -> Condition:
        return self.frames[-1] if self.frames else None

    def cond_copy(self) -> Condition:
        return None if not self.cond or not self.cond["all"] else {"all": [dict(c) for c in self.cond["all"]]}

    # ------------------------------------------------------------------ helpers
    def path(self, rel: str) -> Optional[str]:
        text = rel.strip().replace("\\", "/")
        if not text or text.startswith(("/", "$")):
            return None
        joined = posixpath.normpath(posixpath.join(self.dir or ".", text))
        if joined.startswith(".."):
            return None
        return "" if joined == "." else joined

    def strings(self, node: Optional[Node], depth: int = 0) -> Tuple[List[Tuple[str, int, Condition]], bool]:
        """Strings of a string / list / ``files()`` / known variable as ``(text, line, condition)`` (the condition under
        which a conditionally extended list variable received the element); second value False when something was unknown."""
        if node is None or depth > 6:
            return [], False
        if node.kind == "str":
            return [(node.value, node.line, None)], True
        if node.kind in ("list", "call") and (node.kind == "list" or node.value == "files"):
            out: List[Tuple[str, int, Condition]] = []
            ok = True
            for child in node.args:
                items, good = self.strings(child, depth + 1)
                out.extend(items)
                ok = ok and good
            return out, ok
        if node.kind == "name" and node.value in self.lists:
            return list(self.lists[node.value]), True
        if node.kind == "name" and node.value in self.vars:
            return self.strings(self.vars[node.value], depth + 1)
        return [], False

    def parse_cond(self, tokens: List[Tok]) -> Condition:
        text = " ".join(("'%s'" % t.text) if t.kind == "str" else t.text for t in tokens if t.kind != "nl")
        text = re.sub(r"\s*\.\s*", ".", text)
        text = re.sub(r"\(\s+", "(", text)
        text = re.sub(r"\s+\)", ")", text)
        text = re.sub(r"\s+\(\)", "()", text)
        text = re.sub(r"\(\)", "()", text)
        return self._cond_text(text.strip())

    def _cond_text(self, text: str) -> Condition:
        if re.search(r"\bor\b", text):
            return {"all": [{"op": "unknown", "raw": text[:120]}]}
        clauses: List[Dict[str, Any]] = []
        for part in re.split(r"\s+and\s+", text):
            part = part.strip()
            if part.startswith("(") and part.endswith(")"):
                part = part[1:-1].strip()
            clauses.append(self._clause(part))
        return bmod.cond_from_clauses(clauses)

    def _clause(self, part: str) -> Dict[str, Any]:
        negate = False
        text = part
        if text.startswith("not "):
            negate, text = True, text[4:].strip()
        match = re.fullmatch(r"get_option\('([^']+)'\)(?:\.(enabled|disabled|auto)\(\))?", text)
        if match:
            clause: Dict[str, Any] = {"var": match.group(1), "op": "falsy" if match.group(2) == "disabled" else "truthy"}
            return bmod.clause_negate(clause) if negate else clause
        match = re.fullmatch(r"get_option\('([^']+)'\)\s*(==|!=)\s*'([^']*)'", text)
        if match:
            equal = (match.group(2) == "==") != negate
            return {"var": match.group(1), "op": "eq" if equal else "ne", "value": match.group(3)}
        match = re.fullmatch(r"([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)?)\(\)\s*(==|!=)\s*'([^']*)'", text)
        if match and match.group(1) in _PLATFORM_CALLS:
            equal = (match.group(2) == "==") != negate
            var = _PLATFORM_CALLS[match.group(1)]
            value = _SYSTEM_NAMES.get(match.group(3), match.group(3)) if var in ("CMAKE_SYSTEM_NAME", "CMAKE_HOST_SYSTEM_NAME") \
                else match.group(3)
            return {"var": var, "op": "eq" if equal else "ne", "value": value}
        if re.fullmatch(r"true", text):
            return {"var": "FALSE", "op": "truthy"} if negate else {"op": "unknown", "raw": "true"}
        return {"op": "unknown", "raw": part[:120]}

    # ------------------------------------------------------------------ driver
    def parse_file(self, path: str, directory: str, base: Condition = None) -> None:
        if self.depth >= MAX_DEPTH or path in self.visited:
            return
        text = self.S.fs.text(path)
        if text is None:
            return
        self.visited.add(path)
        self.bm.parsed_files.append(path)
        saved = (self.dir, self.file, self.frames)
        self.dir, self.file = directory, path
        self.frames = [base] if base is not None else []
        self.depth += 1
        try:
            self.run(tokenize(text))
        finally:
            self.depth -= 1
            self.dir, self.file, self.frames = saved

    def run(self, tokens: List[Tok]) -> None:
        index = 0
        n = len(tokens)
        base_depth = len(self.frames)
        branches: List[List[Condition]] = []
        while index < n:
            tok = tokens[index]
            if tok.kind == "nl":
                index += 1
                continue
            end = index
            while end < n and tokens[end].kind != "nl":
                end += 1
            line_tokens = tokens[index:end]
            index = end + 1
            first = line_tokens[0]
            if first.kind == "name" and first.text == "if":
                cond = self.parse_cond(line_tokens[1:])
                parent = self.cond
                self.frames.append(bmod.cond_and(parent, cond) or {"all": []})
                branches.append([cond])
                continue
            if first.kind == "name" and first.text == "elif" and len(self.frames) > base_depth:
                self.frames.pop()
                parent = self.cond
                prior = branches[-1]
                negated: Condition = None
                for earlier in prior:
                    negated = bmod.cond_and(negated, bmod.cond_negate(earlier))
                cond = bmod.cond_and(negated, self.parse_cond(line_tokens[1:]))
                prior.append(self.parse_cond(line_tokens[1:]))
                self.frames.append(bmod.cond_and(parent, cond) or {"all": []})
                continue
            if first.kind == "name" and first.text == "else" and len(self.frames) > base_depth:
                self.frames.pop()
                parent = self.cond
                negated = None
                for earlier in branches[-1]:
                    negated = bmod.cond_and(negated, bmod.cond_negate(earlier))
                self.frames.append(bmod.cond_and(parent, negated) or {"all": []})
                continue
            if first.kind == "name" and first.text == "endif" and len(self.frames) > base_depth:
                self.frames.pop()
                if branches:
                    branches.pop()
                continue
            if first.kind == "name" and first.text in ("foreach", "endforeach", "break", "continue"):
                continue
            self._statement(line_tokens)
        del self.frames[base_depth:]

    def _statement(self, tokens: List[Tok]) -> None:
        if len(tokens) >= 2 and tokens[0].kind == "name" and tokens[1].kind == "op" and tokens[1].text in ("=", "+="):
            parser = ExprParser(tokens, 2)
            node = parser.expr()
            name = tokens[0].text
            append = tokens[1].text == "+="
            items, ok = self.strings(node)
            previous = self.lists.get(name)
            if previous is None and name in self.vars:
                previous_items, previous_ok = self.strings(self.vars[name])
                previous = previous_items if previous_ok else None
            if append and previous is None and name in self.vars:
                self.lists.pop(name, None)                       # extends something unknown: stays unknown
                self.vars[name] = Node("other", line=node.line, text="unknown")
            elif ok and (node.kind in ("str", "list") or node.kind == "call" and node.value == "files" or node.kind == "name"):
                here = self.cond_copy()
                added = [(text, line, bmod.cond_and(here, cond)) for text, line, cond in items]
                if append or (here is not None and previous):
                    merged = list(previous or [])
                    for entry in added:
                        if entry not in merged:
                            merged.append(entry)
                else:
                    merged = added
                self.lists[name] = merged
                self.vars[name] = node
            else:
                self.lists.pop(name, None)
                self.vars[name] = node
            self._evaluate(node, name)
            return
        parser = ExprParser(tokens, 0)
        node = parser.expr()
        self._evaluate(node, None)

    # ------------------------------------------------------------------ evaluation of calls
    def _evaluate(self, node: Node, assigned: Optional[str]) -> None:
        if node.kind == "method":
            self._method(node)
            return
        if node.kind != "call":
            return
        name = node.value
        handler = getattr(self, "_f_" + name, None)
        if handler is not None:
            handler(node, assigned)
        elif name in _TARGET_FUNCS:
            self._target(node, assigned, _TARGET_FUNCS[name])

    def _method(self, node: Node) -> None:
        obj = node.obj
        if obj is not None and node.value in ("set", "set10", "set_quoted") and node.args and node.args[0].kind == "str":
            self.S.generated_macros["checks"].append({"path": self.file, "line": node.line, "macro": node.args[0].value})
        if obj is not None and obj.kind == "name" and obj.value in ("cc", "cpp", "compiler") and node.value in (
                "has_header", "has_function", "has_member", "has_type", "check_header", "compiles", "links"):
            return

    def _f_project(self, node: Node, assigned: Optional[str]) -> None:
        return

    def _f_dependency(self, node: Node, assigned: Optional[str]) -> None:
        names = [a for a in node.args if a.kind == "str"]
        if not names:
            return
        name = names[0].value
        constraint = None
        version = node.kwargs.get("version")
        if version is not None:
            items, _ok = self.strings(version)
            if items:
                constraint = items[0][0]
        required = True
        req = node.kwargs.get("required")
        if req is not None and req.kind == "name" and req.value == "false":
            required = False
        package = {"name": name, "kind": "meson_dependency", "version_constraint": constraint, "required": required,
                   "condition": self.cond_copy(), "path": self.file, "line": node.line, "evidence_id": None}
        self.bm.packages.append(package)
        if assigned:
            self.dep_vars[assigned] = {"kind": "package", "name": name}

    def _f_declare_dependency(self, node: Node, assigned: Optional[str]) -> None:
        if not assigned:
            return
        info: Dict[str, Any] = {"kind": "declared", "link": [], "deps": [], "includes": []}
        for key in ("link_with",):
            items = self._link_items(node.kwargs.get(key))
            info["link"].extend(items)
        info["deps"].extend(self._dep_items(node.kwargs.get("dependencies")))
        self.dep_vars[assigned] = info

    def _f_subproject(self, node: Node, assigned: Optional[str]) -> None:
        if not node.args or node.args[0].kind != "str":
            return
        name = node.args[0].value
        directory = "subprojects/" + name
        wrap = "subprojects/%s.wrap" % name
        if self.S.tracked(wrap):
            text = self.S.fs.text(wrap) or ""
            match = re.search(r"^\s*directory\s*=\s*(\S+)", text, re.M)
            if match:
                directory = "subprojects/" + match.group(1)
        self._subdir_edge(directory, node.line)
        self.bm.packages.append({"name": name, "kind": "meson_subproject", "version_constraint": None, "required": True,
                                 "condition": self.cond_copy(), "path": self.file, "line": node.line, "evidence_id": None})
        if assigned:
            self.dep_vars[assigned] = {"kind": "package", "name": name}

    def _f_subdir(self, node: Node, assigned: Optional[str]) -> None:
        if not node.args or node.args[0].kind != "str":
            return
        directory = self.path(node.args[0].value)
        if directory is None:
            return
        self._subdir_edge(directory, node.line)

    def _subdir_edge(self, directory: str, line: int) -> None:
        cond = self.cond_copy()
        self.bm.subdirs.append({"path": directory or ".", "line": line, "condition": cond, "evidence_id": None,
                                "from": self.dir or ".", "file": self.file})
        self.bm.dir_edges.append((self.dir, directory, cond))
        build = (directory + "/meson.build") if directory else "meson.build"
        if self.S.tracked(build):
            self.parse_file(build, directory, base=cond or {"all": []})

    def _f_files(self, node: Node, assigned: Optional[str]) -> None:
        return

    def _f_include_directories(self, node: Node, assigned: Optional[str]) -> None:
        return

    def _f_test(self, node: Node, assigned: Optional[str]) -> None:
        if len(node.args) >= 2 and node.args[1].kind == "name":
            target_name = self.target_vars.get(node.args[1].value)
            if target_name:
                for target in self.bm.targets:
                    if target["name"] == target_name:
                        target["test"] = True

    _f_benchmark = _f_test

    def _f_configure_file(self, node: Node, assigned: Optional[str]) -> None:
        return

    def _link_items(self, node: Optional[Node]) -> List[str]:
        items: List[str] = []
        if node is None:
            return items
        children = node.args if node.kind == "list" else [node]
        for child in children:
            if child.kind == "name" and child.value in self.target_vars:
                items.append(self.target_vars[child.value])
            elif child.kind == "str":
                items.append(child.value)
        return items

    def _dep_items(self, node: Optional[Node]) -> List[str]:
        items: List[str] = []
        if node is None:
            return items
        children = node.args if node.kind == "list" else [node]
        for child in children:
            while child.kind == "method" and child.obj is not None:
                child = child.obj
            if child.kind == "name" and child.value in self.dep_vars:
                info = self.dep_vars[child.value]
                if info["kind"] == "package":
                    items.append(info["name"])
                else:
                    items.extend(info["link"])
                    items.extend(info["deps"])
            elif child.kind == "call" and child.value == "dependency" and child.args and child.args[0].kind == "str":
                items.append(child.args[0].value)
                self._f_dependency(child, None)
        return items

    def _include_args(self, node: Node, depth: int = 0) -> Node:
        """The string arguments of ``include_directories(...)`` (directly, in a list or through a variable)."""
        if depth > 4:
            return node
        if node.kind == "call" and node.value == "include_directories":
            merged = Node("list", line=node.line)
            merged.args = list(node.args)
            return merged
        if node.kind == "list":
            merged = Node("list", line=node.line)
            merged.args = [self._include_args(child, depth + 1) for child in node.args]
            return merged
        if node.kind == "name" and node.value in self.vars and node.value not in self.lists:
            return self._include_args(self.vars[node.value], depth + 1)
        return node

    def _target(self, node: Node, assigned: Optional[str], kind: str) -> None:
        if not node.args or node.args[0].kind != "str":
            return
        name = node.args[0].value
        target = {"name": name, "kind": kind, "dir": self.dir or ".", "path": self.file, "line": node.line, "test": False,
                  "sources": [], "link": [], "include_dirs": [], "definitions": [], "condition": self.cond_copy(),
                  "evidence_id": None, "_unresolved": False}
        unresolved = False
        sources: List[Node] = list(node.args[1:])
        if "sources" in node.kwargs:
            sources.append(node.kwargs["sources"])
        for source in sources:
            items, ok = self.strings(source)
            if not ok:
                unresolved = True
            for text, line, extra in items:
                path = self.path(text)
                if path is not None:
                    target["sources"].append({"path": path, "line": line or node.line,
                                              "condition": bmod.cond_and(self.cond_copy(), extra), "file": self.file})
        for item in self._link_items(node.kwargs.get("link_with")) + self._dep_items(node.kwargs.get("dependencies")):
            target["link"].append({"item": item, "line": node.line, "condition": self.cond_copy(), "file": self.file})
        incs = node.kwargs.get("include_directories")
        if incs is not None:
            items, _ok = self.strings(self._include_args(incs))
            for text, line, extra in items:
                path = self.path(text)
                if path is not None:
                    target["include_dirs"].append({"path": path or ".", "line": line or node.line,
                                                   "condition": bmod.cond_and(self.cond_copy(), extra), "file": self.file})
        for key in ("c_args", "cpp_args"):
            items, _ok = self.strings(node.kwargs.get(key))
            for text, line, _extra in items:
                if text.startswith("-D"):
                    dname, _sep, dval = text[2:].partition("=")
                    target["definitions"].append({"name": dname, "value": dval if _sep else None, "line": line or node.line,
                                                  "condition": self.cond_copy(), "file": self.file})
        target["_unresolved"] = unresolved
        self.bm.targets.append(target)
        if assigned:
            self.target_vars[assigned] = name


# --------------------------------------------------------------------------------------------------- options

def parse_options(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    tokens = tokenize(text)
    index = 0
    n = len(tokens)
    while index < n:
        if tokens[index].kind == "name" and tokens[index].text == "option":
            parser = ExprParser(tokens, index)
            node = parser.expr()
            index = max(parser.i, index + 1)
            if node.kind != "call" or not node.args or node.args[0].kind != "str":
                continue
            name = node.args[0].value
            kind = node.kwargs["type"].value if "type" in node.kwargs and node.kwargs["type"].kind == "str" else "string"
            value_node = node.kwargs.get("value")
            default: Optional[str] = None
            if value_node is not None:
                if value_node.kind == "name" and value_node.value in ("true", "false"):
                    default = "ON" if value_node.value == "true" else "OFF"
                elif value_node.kind == "str":
                    default = value_node.value
                elif value_node.kind == "list":
                    default = ";".join(a.value for a in value_node.args if a.kind == "str")
            elif kind == "boolean":
                default = "ON"
            elif kind == "feature":
                default = "auto"
            if kind == "feature":
                default = {"enabled": "ON", "disabled": "OFF", "auto": "ON"}.get(default or "auto", default)
            S.bm.options.append({"name": name, "default": default, "path": path, "line": node.line, "evidence_id": None})
            if name in _TEST_OPTION_NAMES or bmod.TEST_OPTION_RE.match(name):
                S.bm.add_test_option(name)
        else:
            index += 1


# --------------------------------------------------------------------------------------------------- wraps

def _wrap_line(text: str, key: str, section: Optional[str] = None) -> int:
    current = None
    for number, line in enumerate(text.split("\n"), start=1):
        header = re.match(r"^\s*\[([^\]]+)\]", line)
        if header:
            current = header.group(1)
            continue
        if re.match(r"^\s*%s\s*=" % re.escape(key), line) and (section is None or current == section):
            return number
    return 1


def parse_wrap(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    parser = configparser.RawConfigParser(strict=False, interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return
    name = posixpath.splitext(posixpath.basename(path))[0]
    for section in parser.sections():
        values = dict(parser.items(section))
        if section == "wrap-file":
            wrapdb = values.get("wrapdb_version")
            raw: Optional[str] = wrapdb
            channel = "wrapdb"
            line = _wrap_line(text, "wrapdb_version", section) if wrapdb else _wrap_line(text, "directory", section)
            if raw is None:
                directory = values.get("directory") or ""
                url = values.get("source_url") or values.get("source_filename") or ""
                match = re.search(r"[-_]v?(\d+(?:\.\d+){1,3}[a-z]?)(?:\.tar|\.zip|\.tgz|$)", url.rsplit("/", 1)[-1]) or \
                    re.search(r"[-_]v?(\d+(?:\.\d+){1,3}[a-z]?)$", directory)
                raw = match.group(1) if match else None
                channel = "generic"
                if raw is None and values.get("source_url"):
                    line = _wrap_line(text, "source_url", section)
            url_value = values.get("source_url")
            declare(S, "LOCK_PIN", name, path, line, raw_version=raw, channel=channel,
                    ref_kind="version" if raw else "url", url=url_value, detected="lockfile")
        elif section == "wrap-git":
            revision = (values.get("revision") or "head").strip()
            url_value = values.get("url")
            line = _wrap_line(text, "revision", section)
            if versions.looks_like_sha(revision):
                declare(S, "FETCH_PIN", name, path, line, ref_kind="commit", commit=revision, url=url_value, detected="lockfile")
            elif revision.lower() == "head" or versions.is_branch_like(revision):
                declare(S, "FETCH_PIN", name, path, line, raw_version=revision if revision.lower() != "head" else "HEAD",
                        ref_kind="branch", url=url_value, detected="lockfile")
            else:
                declare(S, "FETCH_PIN", name, path, line, raw_version=revision, channel="git_tag", ref_kind="tag",
                        url=url_value, detected="lockfile")
        elif section in ("wrap-svn", "wrap-hg"):
            declare(S, "FETCH_PIN", name, path, _wrap_line(text, "url", section), ref_kind="branch",
                    raw_version=values.get("revision") or "HEAD", url=values.get("url"), detected="lockfile")


# --------------------------------------------------------------------------------------------------- entry points

def parse_all(S: Session, files: List[str]) -> Optional[MesonParser]:
    builds = sorted((p for p in files if posixpath.basename(p) == "meson.build"), key=lambda p: (p.count("/"), p))
    for option_file in sorted(p for p in files if posixpath.basename(p) in ("meson_options.txt", "meson.options")):
        parse_options(S, option_file)
    if not builds:
        return None
    parser = MesonParser(S)
    for path in builds:
        S.check_budget()
        if path in parser.visited:
            continue
        directory = posixpath.dirname(path)
        S.bm.roots.append(directory)
        parser.parse_file(path, directory)
    S.bm.systems.add("meson")
    return parser


def run_wraps(S: Session, files: List[str]) -> None:
    for path in sorted(files):
        if path.endswith(".wrap") and S.reg.owner_of(path) is None:
            S.check_budget()
            try:
                parse_wrap(S, path)
            except (configparser.Error, ValueError, KeyError, AttributeError) as exc:
                S.log("discover.wrap_error", file=path, error="%s: %s" % (type(exc).__name__, str(exc)[:100]))
