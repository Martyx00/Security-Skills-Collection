"""One tolerant reader for the JSON a role hands back (decision D3 of the cross-skill review).

Three paths bring a model's JSON into the script: the reply file of the worker (``llm/worker.json``), the decisions files of
the ``usage``, ``trace_build`` and ``hint`` blocks, and the standard input of ``reply``. All three go through here, so that no
spelling of a code fence can turn a delivered answer into a refusal:

* a fence is a line of three or more backticks or tildes (up to any indent), whatever follows it on that line (``json``,
  ``JSON``, ``Json``, ``jsonc``, `` json``, nothing); CRLF and CR line ends are read; a closing fence written at the end of
  the last line of the object (``}```` ``) is read;
* a leading UTF-8 byte order mark is dropped (an editor or a Windows shell puts one there);
* prose before or after a single fenced block is not read, and **said**: the reply comes back with a note that counts the lines
  of text outside the block. A second JSON object outside the block (a draft before it, an afterthought behind it) is refused:
  nothing here may choose between two answers. Two fenced objects are refused for the same reason;
* a fence that is opened and never closed is read as far as it goes **and noted**: the reply may have been cut off, and a
  reader that accepted it quietly would hide that. The note is returned to the caller, which records it on the unit and in
  ``summary``. An unclosed fence whose content does not parse is refused with a message that names the fence.

Nothing is dropped silently: what the reader tolerated comes back as a note, what it could not read comes back as a problem
that says why (and never echoes the content). Nothing a model writes makes the reader raise: JSON nested thousands of levels deep
(``json`` answers with a ``RecursionError``, which is not a ``ValueError``) is refused like any other unreadable reply.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

FENCE_OPEN = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
FENCE_CLOSE = re.compile(r"^[ \t]*(`{3,}|~{3,})[ \t]*$")

KIND_UNCLOSED = "fence_unclosed"
NOTE_UNCLOSED = ("the reply opened a code fence and never closed it, so it may have been cut off; it was read as far as it "
                 "goes")
KIND_OUTSIDE = "text_outside_block"
NOTE_OUTSIDE = "the reply held %d line(s) of text outside the code block; they were not read"


def decode(raw: bytes) -> Tuple[Optional[str], Optional[str]]:
    """``(text, None)`` or ``(None, problem)``: UTF-8, with or without a byte order mark."""
    try:
        return raw.decode("utf-8-sig"), None
    except UnicodeDecodeError as exc:
        return None, "the bytes are not UTF-8 (%s)" % str(exc)[:60]


def _scan(lines: List[str]) -> List[Tuple[int, int, str, str, bool]]:
    """``[(first line, last line, info, body, closed)]`` of every fenced block, in order, by line index (both ends included).

    Line based. A backtick fence whose info string holds a backtick is an inline code span, not a fence. A block ends at a line
    of the same character, at least as long, with nothing else on it, or at the end of a line whose last characters are such a
    run (``}```` ``). A block that is never closed runs to the last line."""
    found: List[Tuple[int, int, str, str, bool]] = []
    mark: Optional[str] = None
    info, first = "", 0
    body: List[str] = []
    for number, line in enumerate(lines):
        if mark is None:
            m = FENCE_OPEN.match(line)
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                mark, info, first, body = m.group(1), m.group(2).strip(), number, []
            continue
        m = FENCE_CLOSE.match(line)
        if m and m.group(1)[0] == mark[0] and len(m.group(1)) >= len(mark):
            found.append((first, number, info, "\n".join(body), True))
            mark = None
            continue
        tail = line.rstrip()
        run = len(tail) - len(tail.rstrip(mark[0]))
        if run >= len(mark):
            found.append((first, number, info, "\n".join(body + [tail[:len(tail) - run]]), True))
            mark = None
            continue
        body.append(line)
    if mark is not None:
        found.append((first, len(lines) - 1, info, "\n".join(body), False))
    return found


def _lines(text: str) -> List[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def fenced_blocks(text: str) -> Tuple[List[Tuple[str, str]], Optional[Tuple[str, str]]]:
    """``([(info, body) of the closed fences], (info, body) of the one left open or None)``."""
    blocks = _scan(_lines(text))
    closed = [(i, b) for _f, _l, i, b, done in blocks if done]
    left = [(i, b) for _f, _l, i, b, done in blocks if not done]
    return closed, (left[0] if left else None)


def _label(info: str) -> str:
    return "the fenced block (marked %s)" % info[:20] if info else "the fenced block"


def _loads(text: str) -> Tuple[Any, Optional[str]]:
    try:
        return json.loads(text), None
    except ValueError as exc:
        return None, str(exc)[:80]
    except RecursionError:                          # `[[[[...` a few thousand deep: a reply to refuse, not a crash of `next`
        return None, "the JSON is nested too deeply to read"


MAX_PROBES = 2000                  # `{` positions tried in the text around the block before the check gives up (and refuses)


def _object_outside(text: str) -> Optional[bool]:
    """Does ``text`` hold a JSON object (a non-empty one)? None when it holds too many ``{`` to look at all of them, or one
    nested too deeply to read: the caller refuses, it cannot say the text is clear."""
    decoder = json.JSONDecoder()
    position = text.find("{")
    tries = 0
    while position != -1:
        tries += 1
        if tries > MAX_PROBES:
            return None
        try:
            value, end = decoder.raw_decode(text, position)
        except ValueError:
            position = text.find("{", position + 1)
            continue
        except RecursionError:
            return None
        if isinstance(value, dict) and value:
            return True
        position = text.find("{", end)
    return False


def _outside(lines: List[str], first: int, last: int) -> List[str]:
    """The lines of the reply that are not in the block ``first..last``."""
    return lines[:first] + lines[last + 1:]


def _read_block(lines: List[str], block: Tuple[int, int, str, str, bool], notes: List[Tuple[str, str]]
                ) -> Tuple[Any, Optional[str]]:
    """The value of one fenced block, or a problem, after the text around it was looked at: a second JSON object there is
    refused (two answers), other text is not read and is noted with its line count."""
    first, last, info, body, _closed = block
    around = _outside(lines, first, last)
    text = "\n".join(around)
    found = _object_outside(text)
    if found is None:
        return None, ("there is too much text around the fenced block to check it (or text nested too deeply); give exactly one "
                      "JSON object and nothing else")
    if found:
        return None, "a JSON object inside the fenced block and another one outside it; give exactly one JSON object"
    unread = sum(1 for line in around if line.strip())
    if unread:
        notes.append((KIND_OUTSIDE, NOTE_OUTSIDE % unread))
    value, problem = _loads(body if block[4] else body.strip())
    if problem is not None:
        if not block[4]:
            return None, ("the reply opened a code fence and never closed it, and what is inside is not complete JSON (%s); "
                          "the reply was probably cut off" % problem)
        return None, "%s is not valid JSON: %s" % (_label(info), problem)
    return value, None


def parse_text(text: str) -> Tuple[Any, Optional[str], List[Tuple[str, str]]]:
    """``(value, problem, notes)`` for a reply as text: the whole text, or one fenced block in it.

    ``notes`` is a list of ``(kind, sentence)`` for what was tolerated; ``problem`` is a sentence saying why nothing could be
    read. Exactly one of ``value`` and ``problem`` is meaningful (``value`` may be any JSON value; the caller checks that it
    is an object)."""
    body = text.lstrip("\ufeff").strip()
    if not body:
        return None, "nothing was given", []
    whole, whole_problem = _loads(body)
    if whole_problem is None:
        return whole, None, []
    lines = _lines(body)
    blocks = _scan(lines)
    closed = [b for b in blocks if b[4]]
    unclosed = [b for b in blocks if not b[4]]
    notes: List[Tuple[str, str]] = [(KIND_UNCLOSED, NOTE_UNCLOSED)] if unclosed else []
    objects = [b for b in closed if b[3].lstrip().startswith("{")]
    if len(objects) > 1:
        return None, "more than one fenced block; give exactly one JSON object", notes
    if len(objects) == 1:
        if unclosed and unclosed[0][3].lstrip().startswith("{"):
            return None, ("a fenced JSON object and then a second code fence that is opened and never closed (cut off?); "
                          "give exactly one JSON object"), notes
        value, problem = _read_block(lines, objects[0], notes)
        return (None, problem, notes) if problem is not None else (value, None, notes)
    if len(closed) == 1 and not unclosed:
        value, problem = _read_block(lines, closed[0], notes)
        return (None, problem, notes) if problem is not None else (value, None, notes)
    if len(closed) > 1:
        return None, "more than one fenced block; give exactly one JSON object", notes
    if unclosed:
        value, problem = _read_block(lines, unclosed[0], notes)
        return (None, problem, notes) if problem is not None else (value, None, notes)
    return None, "not valid JSON: %s" % whole_problem, notes


def parse_bytes(raw: bytes) -> Tuple[Any, Optional[str], List[Tuple[str, str]]]:
    """``parse_text`` for the bytes of a file."""
    text, problem = decode(raw)
    if text is None:
        return None, problem, []
    return parse_text(text)


def note_records(notes: List[Tuple[str, str]], *, attempt: Optional[int] = None) -> List[Dict[str, Any]]:
    """The notes as the records stored on a unit: ``{"kind", "text"}`` and the attempt they were found in."""
    out: List[Dict[str, Any]] = []
    for kind, text in notes:
        item: Dict[str, Any] = {"kind": kind, "text": text}
        if attempt is not None:
            item["attempt"] = attempt
        out.append(item)
    return out


def record(run: Any, entry: Dict[str, Any], unit: str, notes: List[Dict[str, Any]], repo: Optional[str] = None) -> None:
    """Keep what the reader tolerated on the unit's record (``entry["notes"]`` in ``run.json``) and as an INFORMATIONAL
    ``REPLY_NOTE`` warning, which ``report.md`` and ``summary`` print. Called once per reading; a repeat is not added twice."""
    if not notes:
        return
    from sbomlib import model
    known = entry.setdefault("notes", [])
    for note in notes:
        if any(k.get("attempt") == note.get("attempt") and k.get("kind") == note.get("kind") for k in known):
            continue
        known.append(dict(note))
        where = " (attempt %s)" % note["attempt"] if note.get("attempt") else ""
        run.add_warnings([model.warning("INFORMATIONAL", "REPLY_NOTE", "%s: %s%s" % (unit, note.get("text"), where), repo)])
