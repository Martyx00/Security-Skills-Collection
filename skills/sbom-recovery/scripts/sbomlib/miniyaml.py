"""A small YAML subset parser for manifests (``west.yml``, ``idf_component.yml``, ``dependencies.lock``, ``module.yml``).

Supported: block mappings and sequences, plain / single-quoted / double-quoted scalars, comments, ``---`` at the top,
flat flow sequences and mappings on one line. Everything else fails closed with ``YamlUnsupported`` so callers can fall
back to line regexes: anchors, aliases, tags, block scalars (``|``, ``>``), multi-line scalars, complex keys, merge
keys, multi-line flow collections, tabs in indentation, several documents.

Scalars: ``null`` / ``~`` / empty -> None, ``true`` / ``false`` -> bool, everything else stays the exact **string**
(numbers are not converted, so ``1.10`` is never turned into ``1.1``). Mappings and sequences are ``dict`` / ``list``
subclasses (``LDict`` / ``LList``) that also remember the 1-based line of each key / item in ``.lines``.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


class YamlUnsupported(ValueError):
    """The text uses YAML this subset parser does not handle (or is not valid YAML)."""


class LDict(dict):
    """dict that remembers the line of each key (``lines[key]``)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: Dict[str, int] = {}


class LList(list):
    """list that remembers the line of each item (``lines[index]``)."""

    def __init__(self) -> None:
        super().__init__()
        self.lines: List[int] = []


class _Line:
    __slots__ = ("indent", "text", "no")

    def __init__(self, indent: int, text: str, no: int) -> None:
        self.indent = indent
        self.text = text
        self.no = no


_MAX_DEPTH = 40
_BAD_START = "&*!|>%@`"
_INT_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "/": "/", " ": " ", "a": "\a",
                "b": "\b", "e": "\x1b", "f": "\f", "v": "\v"}


def _strip_comment(text: str) -> str:
    quote = ""
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                if quote == "'" and i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                quote = ""
        elif ch in "\"'" and (i == 0 or text[i - 1] in " \t[{,:-"):
            quote = ch
        elif ch == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip()
        i += 1
    return text.rstrip()


def _tokenize(text: str) -> List[_Line]:
    lines: List[_Line] = []
    seen_start = False
    for number, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), start=1):
        if number == 1 and raw.startswith("﻿"):
            raw = raw[1:]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "---" or stripped.startswith("--- "):
            if seen_start or lines:
                raise YamlUnsupported("several YAML documents (line %d)" % number)
            seen_start = True
            rest = stripped[3:].strip()
            if rest and not rest.startswith("#"):
                raise YamlUnsupported("content after --- (line %d)" % number)
            continue
        if stripped == "..." or stripped.startswith("%"):
            raise YamlUnsupported("YAML directive or document end (line %d)" % number)
        indent_text = raw[:len(raw) - len(raw.lstrip(" \t"))]
        if "\t" in indent_text:
            raise YamlUnsupported("tab in indentation (line %d)" % number)
        content = _strip_comment(raw.strip())
        if content:
            lines.append(_Line(len(indent_text), content, number))
    return lines


def _unquote_double(body: str, line: int) -> str:
    out: List[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(body):
            raise YamlUnsupported("dangling escape (line %d)" % line)
        esc = body[i]
        if esc in _INT_ESCAPES:
            out.append(_INT_ESCAPES[esc])
            i += 1
        elif esc in "xuU":
            width = {"x": 2, "u": 4, "U": 8}[esc]
            digits = body[i + 1:i + 1 + width]
            if len(digits) != width or not re.fullmatch(r"[0-9a-fA-F]+", digits):
                raise YamlUnsupported("bad escape (line %d)" % line)
            out.append(chr(int(digits, 16)))
            i += 1 + width
        else:
            raise YamlUnsupported("unsupported escape \\%s (line %d)" % (esc, line))
    return "".join(out)


def _quoted_end(text: str, start: int) -> int:
    """Index just past the closing quote of the quoted scalar starting at ``start``; -1 when it does not close."""
    quote = text[start]
    i = start + 1
    n = len(text)
    while i < n:
        ch = text[i]
        if quote == '"' and ch == "\\":
            i += 2
            continue
        if ch == quote:
            if quote == "'" and i + 1 < n and text[i + 1] == "'":
                i += 2
                continue
            return i + 1
        i += 1
    return -1


def _scalar(text: str, line: int) -> Any:
    value = text.strip()
    if not value:
        return None
    if value[0] in "\"'":
        end = _quoted_end(value, 0)
        if end != len(value):
            raise YamlUnsupported("multi-line or malformed quoted scalar (line %d)" % line)
        body = value[1:-1]
        return _unquote_double(body, line) if value[0] == '"' else body.replace("''", "'")
    if value[0] in _BAD_START:
        raise YamlUnsupported("anchors, aliases, tags and block scalars are not supported (line %d)" % line)
    if value[0] in "[{":
        return _flow(value, line)
    if value in ("~", "null", "Null", "NULL"):
        return None
    if value in ("true", "True", "TRUE"):
        return True
    if value in ("false", "False", "FALSE"):
        return False
    if value.startswith("? ") or value == "?":
        raise YamlUnsupported("complex keys are not supported (line %d)" % line)
    return value


def _split_flow(body: str, line: int) -> List[str]:
    items: List[str] = []
    depth = 0
    quote = ""
    start = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if quote:
            if quote == '"' and ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
            if depth < 0:
                raise YamlUnsupported("unbalanced flow collection (line %d)" % line)
        elif ch == "," and depth == 0:
            items.append(body[start:i])
            start = i + 1
        i += 1
    if depth != 0 or quote:
        raise YamlUnsupported("multi-line or unbalanced flow collection (line %d)" % line)
    tail = body[start:]
    if tail.strip() or items:
        items.append(tail)
    return items


def _flow(text: str, line: int) -> Any:
    value = text.strip()
    if value[0] == "[":
        if not value.endswith("]"):
            raise YamlUnsupported("multi-line flow sequence (line %d)" % line)
        result = LList()
        for item in _split_flow(value[1:-1], line):
            if item.strip():
                result.append(_scalar(item, line))
                result.lines.append(line)
        return result
    if not value.endswith("}"):
        raise YamlUnsupported("multi-line flow mapping (line %d)" % line)
    mapping = LDict()
    for item in _split_flow(value[1:-1], line):
        if not item.strip():
            continue
        key, rest = _split_key(item.strip(), line)
        if key is None:
            raise YamlUnsupported("flow mapping item without a key (line %d)" % line)
        mapping[key] = _scalar(rest, line)
        mapping.lines[key] = line
    return mapping


def _split_key(text: str, line: int) -> Tuple[Optional[str], str]:
    """``(key, rest)`` when ``text`` is ``key: rest`` / ``key:``; ``(None, text)`` when it is not a mapping entry."""
    if text[0] in "\"'":
        end = _quoted_end(text, 0)
        if end == -1:
            raise YamlUnsupported("malformed quoted key (line %d)" % line)
        after = text[end:].lstrip(" ")
        if not after.startswith(":") or (len(after) > 1 and after[1] not in " "):
            return None, text
        key = _scalar(text[:end], line)
        return str(key), after[1:].strip()
    if text[0] in _BAD_START:
        raise YamlUnsupported("anchors, aliases, tags and block scalars are not supported (line %d)" % line)
    if text.startswith("? ") or text == "?":
        raise YamlUnsupported("complex keys are not supported (line %d)" % line)
    depth = 0
    for i, ch in enumerate(text):
        if ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        elif ch == ":" and depth <= 0 and (i + 1 == len(text) or text[i + 1] == " "):
            key = text[:i].strip()
            if not key:
                raise YamlUnsupported("empty key (line %d)" % line)
            if key == "<<":
                raise YamlUnsupported("merge keys are not supported (line %d)" % line)
            return key, text[i + 1:].strip()
    return None, text


def _is_seq_item(text: str) -> bool:
    return text == "-" or text.startswith("- ")


def _parse_block(lines: List[_Line], index: int, indent: int, depth: int) -> Tuple[Any, int]:
    if depth > _MAX_DEPTH:
        raise YamlUnsupported("nesting too deep")
    first = lines[index]
    if first.indent != indent:
        raise YamlUnsupported("unexpected indentation (line %d)" % first.no)
    if _is_seq_item(first.text):
        return _parse_sequence(lines, index, indent, depth)
    key, _rest = _split_key(first.text, first.no)
    if key is None:
        return _scalar(first.text, first.no), index + 1
    return _parse_mapping(lines, index, indent, depth)


def _parse_mapping(lines: List[_Line], index: int, indent: int, depth: int) -> Tuple[Any, int]:
    result = LDict()
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise YamlUnsupported("unexpected indentation (line %d)" % line.no)
        if _is_seq_item(line.text):
            break
        key, rest = _split_key(line.text, line.no)
        if key is None:
            raise YamlUnsupported("line is not a mapping entry (line %d)" % line.no)
        result.lines[key] = line.no
        index += 1
        if rest:
            if index < len(lines) and lines[index].indent > indent:
                raise YamlUnsupported("multi-line scalar or unexpected nesting (line %d)" % lines[index].no)
            result[key] = _scalar(rest, line.no)
            continue
        if index < len(lines) and lines[index].indent > indent:
            value, index = _parse_block(lines, index, lines[index].indent, depth + 1)
            result[key] = value
        elif index < len(lines) and lines[index].indent == indent and _is_seq_item(lines[index].text):
            value, index = _parse_sequence(lines, index, indent, depth + 1)
            result[key] = value
        else:
            result[key] = None
    return result, index


def _parse_sequence(lines: List[_Line], index: int, indent: int, depth: int) -> Tuple[Any, int]:
    result = LList()
    while index < len(lines):
        line = lines[index]
        if line.indent != indent or not _is_seq_item(line.text):
            if line.indent > indent:
                raise YamlUnsupported("unexpected indentation (line %d)" % line.no)
            break
        rest = line.text[1:].lstrip(" ")
        column = indent + (len(line.text) - len(rest))
        result.lines.append(line.no)
        if not rest:
            index += 1
            if index < len(lines) and lines[index].indent > indent:
                value, index = _parse_block(lines, index, lines[index].indent, depth + 1)
                result.append(value)
            else:
                result.append(None)
            continue
        key, _tail = _split_key(rest, line.no) if rest[0] not in "[{" else (None, rest)
        if _is_seq_item(rest) or key is not None:
            lines[index] = _Line(column, rest, line.no)          # the item continues as a block at its own column
            value, index = _parse_block(lines, index, column, depth + 1)
            result.append(value)
            continue
        index += 1
        if index < len(lines) and lines[index].indent > indent:
            raise YamlUnsupported("multi-line scalar (line %d)" % lines[index].no)
        result.append(_scalar(rest, line.no))
    return result, index


def load(text: str) -> Any:
    """Parse ``text``; raises ``YamlUnsupported`` for anything outside the subset (callers fall back to regexes)."""
    if not isinstance(text, str):
        raise YamlUnsupported("not text")
    lines = _tokenize(text)
    if not lines:
        return None
    value, index = _parse_block(lines, 0, lines[0].indent, 0)
    if index < len(lines):
        raise YamlUnsupported("unexpected content (line %d)" % lines[index].no)
    return value


def line_of(container: Any, key: Any, default: Optional[int] = None) -> Optional[int]:
    """1-based line of ``key`` (mapping) or index ``key`` (sequence) in a value returned by ``load``."""
    lines = getattr(container, "lines", None)
    try:
        if isinstance(lines, dict):
            return lines.get(key, default)
        if isinstance(lines, list):
            return lines[key]
    except (IndexError, TypeError):
        return default
    return default
