#!/usr/bin/env python3
"""One tolerant reader for the JSON a role hands back (decision D3 of the cross-skill review).

Every path that takes a role's reply goes through here (`sweep-record`, `verify-record`, `validate_report.py --stdin-json`
and the reply-file check of `validate_report.py --schema`), so that no spelling of a code fence can turn a delivered answer
into a refusal. The sweep has one generation: a refused reply ends the run, so a reply that was delivered must be read.

* A fence is a line of three or more backticks or tildes (any indent), whatever follows it on that line (`json`, `JSON`,
  `Json`, `jsonc`, `json title="x"`, nothing). CRLF and CR line ends are read. A closing fence written at the end of the last
  line of the object (`}` followed by three backticks) is read.
* A leading UTF-8 byte order mark is dropped (PowerShell 5.1 and some editors write one).
* Text before or after a single fenced block is ignored, but a second JSON object in it, a second fenced object, or a second
  fence left open after the first block is refused: nothing here may choose between two answers.
* A fence that is opened and never closed is read as far as it goes and NOTED: the reply may have been cut off, and a reader
  that took it quietly would hide that. The note is returned to the caller, which records it in the run manifest and prints it
  in `summary`. An unclosed fence whose content does not parse is refused with a message that names the fence.

Nothing is dropped silently: what the reader tolerated comes back as a note, and what it could not read comes back as a
problem that says why (and never echoes the content).
"""
from __future__ import annotations

import json
import re

BOM = "﻿"
FENCE_OPEN = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
FENCE_CLOSE = re.compile(r"^[ \t]*(`{3,}|~{3,})[ \t]*$")

KIND_UNCLOSED = "fence_unclosed"
NOTE_UNCLOSED = ("the reply opened a code fence and never closed it, so it may have been cut off; it was read as far as it "
                 "goes")
ONE_OBJECT = "give exactly one JSON object, bare or in one fenced block"


def decode(raw: bytes) -> str:
    """The text of a reply file: UTF-8 with or without a byte order mark; a stray byte becomes U+FFFD, never an exception."""
    return raw.decode("utf-8-sig", errors="replace")


def fences(text: str) -> list:
    """Every code fence of `text` as (info, body, first line, last line, closed), the lines counted from 0.

    Line based. A backtick fence whose info string holds a backtick is an inline code span, not a fence. A fence ends at a line
    of the same character, at least as long, with nothing else on it, or at the end of a line whose last characters are such a
    run. A fence still open at the end of the text is returned with `closed` False; it is always the last one."""
    found: list = []
    mark = None
    info, body, first = "", [], 0
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    for number, line in enumerate(lines):
        seen = line.lstrip(BOM)
        if mark is None:
            match = FENCE_OPEN.match(seen)
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                mark, info, body, first = match.group(1), match.group(2).strip(), [], number
            continue
        match = FENCE_CLOSE.match(seen)
        if match and match.group(1)[0] == mark[0] and len(match.group(1)) >= len(mark):
            found.append((info, "\n".join(body), first, number, True))
            mark = None
            continue
        tail = line.rstrip()
        run = len(tail) - len(tail.rstrip(mark[0]))
        if run >= len(mark):                       # `}` and the closing fence on one line
            found.append((info, "\n".join(body + [tail[:len(tail) - run]]), first, number, True))
            mark = None
            continue
        body.append(line)
    if mark is not None:
        found.append((info, "\n".join(body), first, len(lines) - 1, False))
    return found


def _outside(text: str, found: list) -> str:
    """The lines of `text` that sit in no fence."""
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    inside = set()
    for _info, _body, first, last, _closed in found:
        inside.update(range(first, last + 1))
    return "\n".join(line for number, line in enumerate(lines) if number not in inside)


def _balanced_objects(text: str) -> list:
    """Every top-level {...} of `text`, brace-balanced and string-aware."""
    out, depth, start, in_string, escaped = [], 0, None, False, False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                out.append(text[start:index + 1])
                start = None
    return out


def _loads(text: str):
    """(True, value) or (False, a short message). A reply nested so deeply that the decoder gives up is not valid JSON for
    this purpose: it is refused with a sentence, not allowed to end the command in a traceback."""
    try:
        return True, json.loads(text)
    except ValueError as exc:
        return False, str(exc)[:80]
    except RecursionError:
        return False, "nested too deeply to read"


def _label(info: str) -> str:
    return f"the fenced block (marked {info[:20]})" if info else "the fenced block"


def _holds_object(body: str) -> bool:
    return body.lstrip().startswith("{")


def parse_text(text: str):
    """(value, json text, problem, notes) for a reply given as text.

    `json text` is what is stored: the whole reply, or the content of its one fenced block, stripped. `problem` is one sentence
    saying why nothing could be read, or None; `notes` is a list of (kind, sentence) for what was tolerated. Exactly one of
    `json text` and `problem` is not None (the value may be any JSON value; the caller checks that it is an object)."""
    body = (text or "").lstrip(BOM).strip()
    if not body:
        return None, None, "nothing was given", []
    ok, value = _loads(body)
    if ok:
        return value, body, None, []
    whole_problem = value
    found = fences(body)
    closed = [f for f in found if f[4]]
    unclosed = [f for f in found if not f[4]]
    notes = [(KIND_UNCLOSED, NOTE_UNCLOSED)] if unclosed else []
    objects = [f for f in closed if _holds_object(f[1])]
    if len(objects) > 1:
        return None, None, f"more than one fenced JSON object; {ONE_OBJECT}", notes
    if len(objects) == 1:
        if unclosed and _holds_object(unclosed[0][1]):
            return None, None, ("a fenced JSON object and then a second code fence that is opened and never closed (cut off?); "
                                + ONE_OBJECT), notes
        if any(ok and isinstance(parsed, dict) for ok, parsed in map(_loads, _balanced_objects(_outside(body, found)))):
            return None, None, f"a fenced JSON object and a second JSON object outside the fence; {ONE_OBJECT}", notes
        block = objects[0]
        ok, value = _loads(block[1])
        if not ok:
            return None, None, f"{_label(block[0])} is not valid JSON: {value}", notes
        return value, block[1].strip(), None, notes
    if len(closed) == 1 and not unclosed:
        ok, value = _loads(closed[0][1])
        if not ok:
            return None, None, f"{_label(closed[0][0])} is not valid JSON: {value}", notes
        return value, closed[0][1].strip(), None, notes
    if len(closed) > 1:
        return None, None, f"more than one fenced block and none holds a JSON object; {ONE_OBJECT}", notes
    if unclosed:
        piece = unclosed[0][1].strip()
        ok, value = _loads(piece)
        if not ok:
            return None, None, ("the reply opened a code fence and never closed it, and what is inside is not complete JSON "
                                f"({value}); the reply was probably cut off"), notes
        return value, piece, None, notes
    return None, None, f"not valid JSON: {whole_problem}; {ONE_OBJECT}", notes


def parse_bytes(raw: bytes):
    """`parse_text` for the bytes of a file."""
    return parse_text(decode(raw))
