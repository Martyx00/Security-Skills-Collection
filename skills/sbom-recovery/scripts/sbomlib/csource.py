"""C/C++ text helpers shared by discovery and verification (contract section 3.9).

Comment and string stripping that keeps every character position and every newline (so line numbers and columns stay
valid), ``#include`` and ``#define`` scanning, identifier scanning and preprocessor-guard tracking.

Guards are normalized strings for the enclosing ``#if`` stack, a conjunction: ``"defined(X)"``, ``"!defined(X)"`` and
``"expr:<raw text>"``. ``#else`` / ``#elif`` negate the earlier branches of the same ``#if`` (a single-term branch flips
``defined(X)`` <-> ``!defined(X)`` and ``expr:R`` -> ``expr:!(R)``). A condition ``a && b`` at the top level yields one
guard per conjunct. The include-guard idiom (a file's first directive ``#ifndef X`` immediately followed by ``#define X``
and closed by the file's last ``#endif``) and ``#pragma once`` produce no guard. Code under a literal ``#if 0`` (and the
``#else`` branch of ``#if 1``) can never be compiled: includes, defines and identifiers in it are not reported.
"""
from __future__ import annotations

import bisect
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

_STRIP_RE = re.compile(
    r"""
    (?P<lc>//(?:\\\r?\n|[^\n])*)
  | (?P<bc>/\*.*?\*/)
  | (?P<bcu>/\*.*\Z)
  | (?P<raw>(?<![A-Za-z0-9_])(?:u8|u|U|L)?R"(?P<rd>[^()\\\s"]{0,16})\(.*?\)(?P=rd)")
  | (?P<str>"(?:\\(?:\r\n|[^\n])|[^"\\\n])*")
  | (?P<chr>'(?:\\(?:x[0-9A-Fa-f]{1,8}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}|[^\n])|[^'\\\n]){1,4}')
    """, re.X | re.S)
_NON_NEWLINE_RE = re.compile(r"[^\n\r]")
_DIRECTIVE_RE = re.compile(r"^[ \t]*#[ \t]*(\w*)([^\n]*)", re.M)
_INCLUDE_ARG_RE = re.compile(r'^\s*(?:<([^>\n]+)>|"([^"\n]+)")')
_TOKEN_RE = re.compile(r"[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*")
_DEFINED_RE = re.compile(r"^defined\s*\(\s*([A-Za-z_]\w*)\s*\)$|^defined\s+([A-Za-z_]\w*)$")
_NOT_DEFINED_RE = re.compile(r"^!\s*defined\s*\(\s*([A-Za-z_]\w*)\s*\)$|^!\s*defined\s+([A-Za-z_]\w*)$")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_SKIP_IDENT_DIRECTIVES = frozenset(("include", "include_next", "import", "pragma", "error", "warning", "line", "if",
                                    "ifdef", "ifndef", "elif", "else", "endif", "undef", "elifdef", "elifndef"))
_FUNC_BODY_RE = re.compile(r"\)\s*(?:(?:const|noexcept|override|final|volatile|mutable|throw\s*\([^)]*\)|"
                           r"->\s*[\w:<>*&,\s]+?)\s*)*\{")
_TEMPLATE_RE = re.compile(r"\btemplate\s*<")
_LOGIC_RE = re.compile(r"[{};?]|&&|\|\||[=!<>]=|<<|>>|[+/%^]|-(?!>)|\b(?:if|for|while|return|switch)\b")

#: the state of a line: (guards, dead)
_State = Tuple[Tuple[str, ...], bool]


# --------------------------------------------------------------------------------------------------- stripping

def _blank(chunk: str) -> str:
    return _NON_NEWLINE_RE.sub(" ", chunk)


def _strip_comments_repl(match: "re.Match[str]") -> str:
    if match.group("lc") is not None or match.group("bc") is not None or match.group("bcu") is not None:
        return _blank(match.group(0))
    return match.group(0)


def _strip_all_repl(match: "re.Match[str]") -> str:
    text = match.group(0)
    if match.group("lc") is not None or match.group("bc") is not None or match.group("bcu") is not None:
        return _blank(text)
    if match.group("raw") is not None:
        return _blank(text)
    return text[0] + _blank(text[1:-1]) + text[-1]


def strip_comments(text: str) -> str:
    """Comments replaced by spaces; string and character literals kept as they are. Newlines and positions kept."""
    if "/" not in text:
        return text
    return _STRIP_RE.sub(_strip_comments_repl, text)


def strip_comments_and_strings(text: str) -> str:
    """Comment and string/character literal *contents* replaced by spaces (the quotes stay); every newline and every
    character position is kept, so line numbers and columns stay valid."""
    if "/" not in text and '"' not in text and "'" not in text:
        return text
    return _STRIP_RE.sub(_strip_all_repl, text)


# --------------------------------------------------------------------------------------------------- guards

def _strip_parens(cond: str) -> str:
    cond = cond.strip()
    while cond.startswith("(") and cond.endswith(")"):
        depth = 0
        for index, ch in enumerate(cond):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and index < len(cond) - 1:
                    return cond
        cond = cond[1:-1].strip()
    return cond


def _split_and(cond: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    index = 0
    while index < len(cond):
        ch = cond[index]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "&" and depth == 0 and cond.startswith("&&", index):
            parts.append(cond[start:index])
            index += 2
            start = index
            continue
        index += 1
    parts.append(cond[start:])
    return parts


def _terms(cond: str) -> List[str]:
    """Guard strings (a conjunction) of one ``#if`` / ``#elif`` condition."""
    cond = _strip_parens(re.sub(r"\s+", " ", cond.strip()))
    if not cond:
        return []
    out: List[str] = []
    for part in _split_and(cond):
        part = _strip_parens(part)
        if not part:
            continue
        match = _DEFINED_RE.match(part)
        if match:
            out.append("defined(%s)" % (match.group(1) or match.group(2)))
            continue
        match = _NOT_DEFINED_RE.match(part)
        if match:
            out.append("!defined(%s)" % (match.group(1) or match.group(2)))
            continue
        out.append("expr:" + part)
    return out


def _raw(term: str) -> str:
    return term[5:] if term.startswith("expr:") else term


def _flip_terms(terms: Sequence[str]) -> List[str]:
    """Negation of a conjunction (the guards of the branches that precede an ``#else`` / ``#elif``)."""
    if not terms:
        return []
    if len(terms) == 1:
        term = terms[0]
        if term.startswith("!defined("):
            return ["defined(" + term[len("!defined("):]]
        if term.startswith("defined("):
            return ["!" + term]
        raw = term[5:]
        if raw.startswith("!(") and raw.endswith(")") and _strip_parens(raw[1:]) == raw[2:-1].strip():
            return ["expr:" + raw[2:-1]]
        return ["expr:!(%s)" % raw]
    return ["expr:!(%s)" % " && ".join(_raw(t) for t in terms)]


def _const_value(cond: str) -> Optional[bool]:
    value = _strip_parens(cond.strip())
    if value == "0":
        return False
    if re.fullmatch(r"[1-9]\d*", value):
        return True
    return None


class _Entry:
    __slots__ = ("neg", "cur", "dead", "taken", "transparent")

    def __init__(self) -> None:
        self.neg: List[str] = []
        self.cur: List[str] = []
        self.dead = False
        self.taken = False
        self.transparent = False


def _apply_condition(entry: _Entry, cond: str) -> None:
    const = _const_value(cond)
    if const is False:
        entry.cur, entry.dead = [], True
    elif const is True:
        entry.cur, entry.dead, entry.taken = [], False, True
    else:
        entry.cur, entry.dead = _terms(cond), False


def _guard_idiom_index(directives: Sequence[Tuple[int, int, str, str]]) -> Optional[int]:
    """Index of the opening directive of the include-guard idiom, or None."""
    first = None
    for index, (_start, _end, name, _rest) in enumerate(directives):
        if name == "pragma":
            continue
        first = index
        break
    if first is None or first + 1 >= len(directives):
        return None
    name, rest = directives[first][2], directives[first][3]
    macro: Optional[str] = None
    if name == "ifndef":
        match = _IDENT_RE.match(rest.strip())
        macro = match.group(0) if match else None
    elif name == "if":
        match = _NOT_DEFINED_RE.match(rest.strip())
        macro = (match.group(1) or match.group(2)) if match else None
    if macro is None:
        return None
    nxt = directives[first + 1]
    if nxt[2] != "define":
        return None
    match = _IDENT_RE.match(nxt[3].strip())
    if match is None or match.group(0) != macro:
        return None
    depth = 0
    for index in range(first, len(directives)):
        dname = directives[index][2]
        if dname in ("if", "ifdef", "ifndef"):
            depth += 1
        elif dname == "endif":
            depth -= 1
            if depth == 0:
                return first if index == len(directives) - 1 else None
        elif dname in ("else", "elif", "elifdef", "elifndef") and depth == 1:
            return None
    return None


class _Walk:
    """Directives of a (comment-stripped) text with the guard state in effect at every line."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.directives: List[Tuple[int, int, str, str]] = []     # (first line, last line, name, rest)
        self._lines = text.count("\n") + 1
        self._collect()
        self._points: List[int] = [0]
        self._states: List[_State] = [((), False)]
        self._run()

    def _collect(self) -> None:
        text = self.text
        if "#" not in text:
            return
        line = 1
        pos = 0
        skip_until = -1
        for match in _DIRECTIVE_RE.finditer(text):
            if match.start() < skip_until:
                continue
            line += text.count("\n", pos, match.start())
            pos = match.start()
            name, rest = match.group(1), match.group(2)
            end = match.end()
            last = line
            while rest.rstrip(" \t\r").endswith("\\") and end < len(text):
                nxt_end = text.find("\n", end + 1)
                nxt_end = len(text) if nxt_end == -1 else nxt_end
                rest = rest.rstrip(" \t\r")[:-1] + " " + text[end + 1:nxt_end]
                end = nxt_end
                last += 1
            skip_until = end
            self.directives.append((line, last, name, rest))

    def _run(self) -> None:
        idiom = _guard_idiom_index(self.directives)
        stack: List[_Entry] = []

        def state() -> _State:
            guards: List[str] = []
            dead = False
            for entry in stack:
                if entry.dead:
                    dead = True
                if not entry.transparent:
                    guards.extend(entry.neg)
                    guards.extend(entry.cur)
            return tuple(guards), dead

        for index, (_first, last, name, rest) in enumerate(self.directives):
            changed = True
            if name in ("if", "ifdef", "ifndef"):
                entry = _Entry()
                if name == "ifdef":
                    entry.cur = _terms("defined(%s)" % rest.strip().split()[0]) if rest.strip() else []
                elif name == "ifndef":
                    entry.cur = ["!defined(%s)" % rest.strip().split()[0]] if rest.strip() else []
                else:
                    _apply_condition(entry, rest)
                entry.transparent = index == idiom
                stack.append(entry)
            elif name in ("elif", "elifdef", "elifndef") and stack:
                entry = stack[-1]
                if not entry.dead:
                    entry.neg.extend(_flip_terms(entry.cur))
                if entry.taken:
                    entry.dead = True
                    entry.cur = []
                elif name == "elif":
                    _apply_condition(entry, rest)
                else:
                    word = rest.strip().split()[0] if rest.strip() else ""
                    entry.cur = ["defined(%s)" % word] if name == "elifdef" else ["!defined(%s)" % word]
                    entry.dead = False
            elif name == "else" and stack:
                entry = stack[-1]
                if not entry.dead:
                    entry.neg.extend(_flip_terms(entry.cur))
                if entry.taken:
                    entry.dead, entry.cur = True, []
                else:
                    entry.dead, entry.cur = False, []
            elif name == "endif" and stack:
                stack.pop()
            else:
                changed = False
            if changed:
                self._points.append(last + 1)
                self._states.append(state())

    def state_at(self, line: int) -> _State:
        return self._states[bisect.bisect_right(self._points, line) - 1]

    def guards_at(self, line: int) -> List[str]:
        return list(self.state_at(line)[0])

    def dead_at(self, line: int) -> bool:
        return self.state_at(line)[1]


# --------------------------------------------------------------------------------------------------- scanners

def scan_includes(text: str) -> List[Dict[str, Any]]:
    """``[{"line", "header", "angle", "guards"}]`` for every live ``#include`` / ``#include_next`` / ``#import`` whose
    argument is a quoted or angle-bracket header (computed includes are skipped)."""
    if "include" not in text and "import" not in text:
        return []
    stripped = strip_comments(text)
    walk = _Walk(stripped)
    out: List[Dict[str, Any]] = []
    for first, _last, name, rest in walk.directives:
        if name not in ("include", "include_next", "import"):
            continue
        match = _INCLUDE_ARG_RE.match(rest)
        if match is None or walk.dead_at(first):
            continue
        angle = match.group(1) is not None
        out.append({"line": first, "header": (match.group(1) if angle else match.group(2)).strip(),
                    "angle": angle, "guards": walk.guards_at(first)})
    return out


def defined_macros(text: str) -> List[Tuple[int, str, List[str]]]:
    """``(line, macro, guards)`` of each live ``#define`` (object-like and function-like)."""
    if "define" not in text:
        return []
    walk = _Walk(strip_comments(text))
    out: List[Tuple[int, str, List[str]]] = []
    for first, _last, name, rest in walk.directives:
        if name != "define" or walk.dead_at(first):
            continue
        match = _IDENT_RE.match(rest.strip())
        if match is not None:
            out.append((first, match.group(0), walk.guards_at(first)))
    return out


def scan_identifiers(text: str, names: Set[str], prefixes: Sequence[str]) -> List[Tuple[int, str, List[str]]]:
    """Identifier hits on *stripped* text (``strip_comments_and_strings``).

    Tokens are qualified names ``[A-Za-z_]\\w*(::[A-Za-z_]\\w*)*`` (``nlohmann::json::parse`` is one token). A token
    matches when it equals a name or starts with a prefix; names and prefixes without ``::`` also match the last
    ``::`` component of a qualified token (``foo::compress2``). Directive lines other than ``#define`` bodies are not
    scanned, dead code (``#if 0``) is skipped. Returns ``(line, token, guards)``.
    """
    names = set(names)
    prefix_tuple = tuple(p for p in prefixes if p)
    if not names and not prefix_tuple:
        return []
    needles = sorted(set(list(names) + list(prefix_tuple)), key=len, reverse=True)
    quick = re.compile("|".join(re.escape(n) for n in needles))
    if quick.search(text) is None:
        return []
    plain_names = {n for n in names if "::" not in n}
    plain_prefixes = tuple(p for p in prefix_tuple if "::" not in p)
    walk = _Walk(text)
    skip_lines: Set[int] = set()
    define_lines: Set[int] = set()
    for first, last, name, _rest in walk.directives:
        if name == "define":
            define_lines.add(first)             # only the body of the first physical line is scanned (below)
        elif name in _SKIP_IDENT_DIRECTIVES or name == "":
            skip_lines.update(range(first, last + 1))
    out: List[Tuple[int, str, List[str]]] = []
    lines = text.split("\n")
    for number, line in enumerate(lines, start=1):
        if number in define_lines:
            line = re.sub(r"^\s*#\s*define\s+[A-Za-z_]\w*(?:\([^)]*\))?", "", line, count=1)
        elif number in skip_lines:
            continue
        if not line.strip() or quick.search(line) is None:
            continue
        if walk.dead_at(number):
            continue
        for match in _TOKEN_RE.finditer(line):
            token = match.group(0)
            hit = token in names or (bool(prefix_tuple) and token.startswith(prefix_tuple))
            if not hit and "::" in token:
                last_part = token.rsplit("::", 1)[1]
                hit = last_part in plain_names or (bool(plain_prefixes) and last_part.startswith(plain_prefixes))
            if hit:
                out.append((number, token, walk.guards_at(number)))
    return out


def has_code_in_header(text: str) -> bool:
    """True when a header holds code, not only declarations: a function body, an ``inline`` definition, a template,
    or a function-like macro whose body has logic (operators, statements, ``?:``) rather than a bare call."""
    stripped = strip_comments_and_strings(text)
    walk = _Walk(stripped)
    for first, _last, name, rest in walk.directives:
        if name != "define" or walk.dead_at(first):
            continue
        match = re.match(r"\s*[A-Za-z_]\w*\(([^)]*)\)(.*)$", rest, re.S)
        if match is not None and _LOGIC_RE.search(match.group(2)):
            return True
    lines = stripped.split("\n")
    for first, last, _name, _rest in walk.directives:
        for number in range(first, last + 1):
            if number <= len(lines):
                lines[number - 1] = ""
    for number in range(1, len(lines) + 1):
        if walk.dead_at(number):
            lines[number - 1] = ""
    blanked = "\n".join(lines)
    return bool(_TEMPLATE_RE.search(blanked) or _FUNC_BODY_RE.search(blanked))
