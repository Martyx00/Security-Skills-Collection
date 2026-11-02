"""CPE 2.3 formatted strings: building, escaping, splitting, validating (contract sections 3.11, 6.11 and Appendix C).

Pure functions, no I/O. Vendor and product values travel in their CPE-escaped attribute form everywhere in the pack
(for example ``stm32cube_mcu_\\&_mpu_packages``); ``escape_attr`` is applied once, where a raw value (a version) is put
into a string.
"""
from __future__ import annotations

import re
from typing import List, Tuple

# Appendix C: the CVE-schema regex for the 13-field formatted string, and the building blocks derived from it.
_CPE23_SRC = (r"cpe:2\.3:[aho\*\-]"
              r"(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#\$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+(\?*|\*?))|[\*\-])){5}"
              r"(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))"
              r"(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#\$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+(\?*|\*?))|[\*\-])){4}")
ATTRVAL = r"(?:[A-Za-z0-9\-._]|\\[\\*?!\"#$%&'()+,/:;<=>@\[\]^`{|}~])+"
_ATTR_SRC = r"\*|-|(?:\?*|\*?)" + ATTRVAL + r"(?:\?*|\*?)"          # cpe_version_override / cpe_update_override
_PAIR_SRC = r"(?:([aoh]):)?(" + ATTRVAL + r"):(" + ATTRVAL + r")"     # extra_vendor_products items, map pairs
_HINT_SRC = r"[a-z0-9][a-z0-9._\-]{0,99}"                              # model hints (vendor, product)
_HINT_CELL_SRC = r"[A-Za-z0-9._\-]{1,100}"                              # human vendor_hint / product_hint

CPE23_RE = re.compile(_CPE23_SRC)
ATTR_RE = re.compile(_ATTR_SRC)
PAIR_RE = re.compile(_PAIR_SRC)
HINT_RE = re.compile(_HINT_SRC)
HINT_CELL_RE = re.compile(_HINT_CELL_SRC)

PARTS = ("a", "o", "h")
# The characters a CPE 2.3 formatted string may quote with a backslash (the set of the regex above).
QUOTABLE = "\\*?!\"#$%&'()+,/:;<=>@[]^`{|}~"
_PLAIN = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")
FIELD_COUNT = 13


def escape_attr(value: str) -> str:
    """Backslash-escape every character outside ``[A-Za-z0-9._-]``.

    ``ValueError`` for a character a formatted string cannot carry at all (whitespace, control characters, characters
    beyond ASCII): such a value can only come from a bug or hostile input, and the result would not validate.
    """
    out: List[str] = []
    for ch in value:
        if ch in _PLAIN:
            out.append(ch)
        elif ch in QUOTABLE:
            out.append("\\" + ch)
        else:
            raise ValueError("character %r cannot be part of a CPE attribute value" % (ch,))
    return "".join(out)


def unescape_attr(value: str) -> str:
    """Remove the backslash of every escaped character (a trailing lone backslash is kept)."""
    out: List[str] = []
    i = 0
    size = len(value)
    while i < size:
        ch = value[i]
        if ch == "\\" and i + 1 < size:
            out.append(value[i + 1])
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def make_cpe23(part: str, vendor: str, product: str, version: str = "*", update: str = "*") -> str:
    """``cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:*:*:*:*:*:*`` (vendor, product, version, update already escaped).

    ``ValueError`` when ``part`` is not ``a``, ``o`` or ``h`` or a value is empty.
    """
    if part not in PARTS:
        raise ValueError("CPE part must be one of a, o, h: %r" % (part,))
    for label, value in (("vendor", vendor), ("product", product), ("version", version), ("update", update)):
        if not value:
            raise ValueError("CPE %s must not be empty" % label)
    return "cpe:2.3:%s:%s:%s:%s:%s:*:*:*:*:*:*" % (part, vendor, product, version, update)


def split_cpe23(s: str) -> List[str]:
    """The 13 fields of a formatted string (``cpe``, ``2.3``, part, ..., other) with their escapes kept.

    The scanner honours backslash escapes (``\\:`` does not separate fields). ``ValueError`` unless there are exactly
    13 fields and the string starts with ``cpe:2.3``.
    """
    fields: List[str] = []
    current: List[str] = []
    i = 0
    size = len(s)
    while i < size:
        ch = s[i]
        if ch == "\\":
            if i + 1 >= size:
                raise ValueError("a trailing backslash escapes nothing: %r" % (s,))
            current.append(ch)
            current.append(s[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    fields.append("".join(current))
    if len(fields) != FIELD_COUNT:
        raise ValueError("a CPE 2.3 formatted string has %d fields, found %d: %r" % (FIELD_COUNT, len(fields), s))
    if fields[0] != "cpe" or fields[1] != "2.3":
        raise ValueError("not a CPE 2.3 formatted string: %r" % (s,))
    return fields


def is_valid_cpe23(s: str) -> bool:
    """``CPE23_RE.fullmatch`` on the unstripped value."""
    return isinstance(s, str) and CPE23_RE.fullmatch(s) is not None


def parse_pair(s: str) -> Tuple[str, str, str]:
    """``[part:]vendor:product`` -> ``(part, vendor, product)``; the part defaults to ``a``; ``ValueError`` otherwise.

    Vendor and product keep their escapes.
    """
    match = PAIR_RE.fullmatch(s) if isinstance(s, str) else None
    if match is None:
        raise ValueError("not a vendor:product pair: %r" % (s,))
    return (match.group(1) or "a", match.group(2), match.group(3))


def pair_str(part: str, vendor: str, product: str) -> str:
    """``part:vendor:product``."""
    return "%s:%s:%s" % (part, vendor, product)


def pair_of_cpe23(s: str) -> Tuple[str, str, str]:
    """``(part, vendor, product)`` of a formatted string; ``ValueError`` when the string is not 13-field or the part/vendor/product
    is a wildcard or NA (``*``, ``-``) rather than a name."""
    fields = split_cpe23(s)
    part, vendor, product = fields[2], fields[3], fields[4]
    if part not in PARTS or vendor in ("*", "-", "") or product in ("*", "-", ""):
        raise ValueError("the CPE does not name a vendor and product: %r" % (s,))
    return (part, vendor, product)
