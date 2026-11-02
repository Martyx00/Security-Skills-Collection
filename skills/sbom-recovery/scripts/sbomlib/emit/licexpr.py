"""SPDX licence expression validation against the vendored licence list (contract section 3.12).

Grammar (SPDX 2.3, annex D), validated, not evaluated::

    expression  = compound
    compound    = simple | compound " AND " compound | compound " OR " compound | "(" compound ")"
    simple      = license-id | license-id "+" | license-id " WITH " exception-id | license-ref
    license-ref = ["DocumentRef-" idstring ":"] "LicenseRef-" idstring

``AND``, ``OR`` and ``WITH`` are case-sensitive. Licence and exception identifiers must be spelled exactly as in the
licence list (the list holds the current identifiers in ``licenses`` and the deprecated ones in ``deprecated``; both are
valid). The whole value ``NOASSERTION`` or ``NONE`` is accepted as an expression (it is a legal value of the SPDX
licence fields), but not inside a compound expression. ``WITH`` takes a listed exception or an ``AdditionRef-``
reference.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set

_IDSTRING = r"[A-Za-z0-9.\-]+"
_LICENSE_REF_RE = re.compile(r"(?:DocumentRef-%s:)?LicenseRef-%s" % (_IDSTRING, _IDSTRING))
_ADDITION_REF_RE = re.compile(r"(?:DocumentRef-%s:)?AdditionRef-%s" % (_IDSTRING, _IDSTRING))
_TOKEN_RE = re.compile(r"\s*(\(|\)|[^\s()]+)")
SPECIAL_VALUES = ("NOASSERTION", "NONE")

_MEMO: Dict[int, Any] = {}


def _id_sets(licenses: Any) -> Any:
    """``(licence ids, exception ids)``, memoised per asset object (the loaded asset is shared by every caller)."""
    cached = _MEMO.get(id(licenses))
    if cached is not None and cached[0] is licenses:
        return cached[1], cached[2]
    lic, exc = _ids(licenses, "licenses"), _ids(licenses, "exceptions")
    if isinstance(licenses, dict):
        _MEMO.clear()
        _MEMO[id(licenses)] = (licenses, lic, exc)
    return lic, exc


def _ids(licenses: Any, key: str) -> Set[str]:
    """The set of identifiers under ``key`` (and ``deprecated`` for licences) of the asset dict."""
    if not isinstance(licenses, dict):
        return set(licenses) if isinstance(licenses, (list, tuple, set, frozenset)) and key == "licenses" else set()
    found: Set[str] = set()
    for name in ((key, "deprecated") if key == "licenses" else (key,)):
        value = licenses.get(name)
        if isinstance(value, (list, tuple, set, frozenset)):
            found.update(str(v) for v in value)
    return found


def _tokens(expr: str) -> Optional[List[str]]:
    """Tokens of the expression, ``None`` when it holds a character outside the grammar."""
    out: List[str] = []
    pos = 0
    text = expr
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if match is None:
            if text[pos:].strip() == "":
                break
            return None
        out.append(match.group(1))
        pos = match.end()
    return out


class _Parser:
    def __init__(self, tokens: List[str], licenses: Set[str], exceptions: Set[str]) -> None:
        self.tokens = tokens
        self.licenses = licenses
        self.exceptions = exceptions
        self.pos = 0

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> Optional[str]:
        token = self.peek()
        self.pos += 1
        return token

    def compound(self) -> bool:
        if not self.simple_or_group():
            return False
        while self.peek() in ("AND", "OR"):
            self.take()
            if not self.simple_or_group():
                return False
        return True

    def simple_or_group(self) -> bool:
        token = self.peek()
        if token is None:
            return False
        if token == "(":
            self.take()
            if not self.compound():
                return False
            return self.take() == ")"
        return self.simple()

    def simple(self) -> bool:
        token = self.take()
        if token is None or token in ("(", ")", "AND", "OR", "WITH"):
            return False
        if _LICENSE_REF_RE.fullmatch(token):
            ok = True
        else:
            base = token[:-1] if token.endswith("+") else token
            ok = base in self.licenses
        if not ok:
            return False
        if self.peek() == "WITH":
            self.take()
            exception = self.take()
            if exception is None:
                return False
            return exception in self.exceptions or _ADDITION_REF_RE.fullmatch(exception) is not None
        return True


def is_valid_expression(expr: str, licenses: Dict[str, Any]) -> bool:
    """True when ``expr`` is a valid SPDX licence expression over the identifiers of ``licenses`` (the asset
    ``spdx-licenses.json``: keys ``licenses``, ``deprecated``, ``exceptions``)."""
    if not isinstance(expr, str) or expr != expr.strip() or expr == "":
        return False
    if expr in SPECIAL_VALUES:
        return True
    tokens = _tokens(expr)
    if not tokens:
        return False
    lic, exc = _id_sets(licenses)
    parser = _Parser(tokens, lic, exc)
    return parser.compound() and parser.pos == len(tokens)


def license_refs(expr: str) -> List[str]:
    """The ``LicenseRef-`` identifiers (without a ``DocumentRef-`` prefix) used by an expression, sorted, unique."""
    return sorted({t for t in (_tokens(expr) or []) if t.startswith("LicenseRef-")})


def normalize_for_comparison(expr: str) -> str:
    """Key under which two licence expressions count as the same: case-folded, white space and parentheses spacing
    collapsed (``mit`` and ``MIT`` agree; ``MIT OR Apache-2.0`` and ``MIT  OR  Apache-2.0`` agree)."""
    tokens = _tokens(expr or "") or []
    return " ".join(tokens).casefold()
