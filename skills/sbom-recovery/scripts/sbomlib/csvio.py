"""The CSV contract of the report: formula-injection guard, UTF-8 BOM, CRLF, strict reading (contract section 3.3)."""
from __future__ import annotations

import csv
import io
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from sbomlib import errors, fsio

GUARD_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n", "＝", "＋", "－", "＠", "'")
BOM = b"\xef\xbb\xbf"


def guard_cell(value: Any) -> str:
    """Prefix an apostrophe when a spreadsheet could read the cell as a formula; ``None`` -> empty cell."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if text[:1] in GUARD_TRIGGERS and text != "":
        return "'" + text
    return text


def unguard_cell(value: str) -> str:
    """Strip exactly one leading apostrophe."""
    if value[:1] == "'":
        return value[1:]
    return value


def render_csv(header: Sequence[str], rows: Iterable[Sequence[Any]], *, preamble: Sequence[str] = ()) -> bytes:
    """UTF-8 BOM + CRLF + QUOTE_MINIMAL. Preamble lines are single-cell comment rows starting with ``#``."""
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    for line in preamble:
        if not line.startswith("#") or "\n" in line or "\r" in line:
            raise ValueError("preamble lines must start with '#' and contain no newline: %r" % (line,))
        writer.writerow([line])
    writer.writerow(list(header))
    for row in rows:
        writer.writerow([guard_cell(cell) for cell in row])
    return BOM + buffer.getvalue().encode("utf-8")


def write_csv(path: Path, header: Sequence[str], rows: Iterable[Sequence[Any]], *, root: Path,
              preamble: Sequence[str] = ()) -> str:
    """Atomic write of ``render_csv`` output; returns the sha256."""
    return fsio.atomic_write_bytes(path, render_csv(header, rows, preamble=preamble), root=root)


@dataclass
class CsvTable:
    header: List[str]
    rows: List[Dict[str, str]]       # cells already unguarded
    line_numbers: List[int]          # 1-based physical line of each row
    delimiter: str                   # "," or ";"


def _line_end(text: str, start: int) -> int:
    """Index of the first line terminator at or after ``start`` (or len(text))."""
    pos = start
    size = len(text)
    while pos < size and text[pos] not in "\r\n":
        pos += 1
    return pos


def _skip_comment_lines(text: str) -> "tuple[str, int]":
    """Drop leading blank lines and lines starting (after an optional opening quote) with '#'."""
    pos = 0
    skipped = 0
    size = len(text)
    while pos < size:
        end = _line_end(text, pos)
        line = text[pos:end]
        probe = line[1:] if line.startswith('"') else line
        if line.strip() == "" or probe.startswith("#"):
            skipped += 1
            if end < size and text[end] == "\r" and end + 1 < size and text[end + 1] == "\n":
                pos = end + 2
            else:
                pos = end + 1
            continue
        break
    return text[pos:], skipped


def parse_csv_strict(data: bytes, expected_header: Sequence[str], *, allow_semicolon: bool = True,
                     skip_comment_rows: bool = True) -> CsvTable:
    """Strict reader: UTF-8 only, comment lines skipped by raw text, exact header, ``,`` then ``;``, cells unguarded."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        line = data[:exc.start].count(b"\n") + 1
        raise errors.CsvReadError("the file is not valid UTF-8 (first bad byte on line %d)" % line,
                                  reason="NON_UTF8", line=line) from exc
    skipped = 0
    if skip_comment_rows:
        text, skipped = _skip_comment_lines(text)
    if text == "":
        raise errors.CsvReadError("the file has no header line", reason="EMPTY", line=skipped + 1)
    expected = list(expected_header)
    first_line = text[:_line_end(text, 0)]
    delimiter = None
    found: List[str] = []
    for candidate in (",", ";") if allow_semicolon else (",",):
        try:
            found = next(csv.reader([first_line], delimiter=candidate), [])
        except csv.Error:
            found = []
        if found == expected:
            delimiter = candidate
            break
    if delimiter is None:
        raise errors.CsvReadError("the header line does not match the expected header", reason="BAD_HEADER",
                                  line=skipped + 1, expected=expected, found=found)
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter)
    rows: List[Dict[str, str]] = []
    numbers: List[int] = []
    try:
        next(reader)                                   # the header
        previous_end = reader.line_num
        for cells in reader:
            start_line = skipped + previous_end + 1
            previous_end = reader.line_num
            if not cells or all(cell == "" for cell in cells):
                continue
            if len(cells) != len(expected):
                raise errors.CsvReadError("row has %d cells, expected %d" % (len(cells), len(expected)),
                                          reason="BAD_ROW_LENGTH", line=start_line)
            rows.append({name: unguard_cell(cell) for name, cell in zip(expected, cells)})
            numbers.append(start_line)
    except csv.Error as exc:
        raise errors.CsvReadError("malformed CSV: %s" % exc, reason="BAD_ROW_LENGTH",
                                  line=skipped + reader.line_num) from exc
    return CsvTable(header=expected, rows=rows, line_numbers=numbers, delimiter=delimiter)


def read_csv_strict(path: Path, expected_header: Sequence[str], **kw: Any) -> CsvTable:
    with open(os.fspath(path), "rb") as handle:
        data = handle.read()
    return parse_csv_strict(data, expected_header, **kw)
