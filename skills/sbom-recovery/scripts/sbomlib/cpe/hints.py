"""Model hints: the hint request, validation and application of ``review/hints.json`` (contract section 4.12, 5.7).

The model sees at most 50 review rows that have no High or Medium proposal and answers with up to three
``vendor:product`` guesses per row. Accepted hints become ``alternatives`` with ``basis=model`` and ``tier=low``;
they are never emitted unless the human copies one into an editable cell.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import errors, fsio, model, replyread
from sbomlib.context import RunContext
from sbomlib.cpe import cpestr, review, store

MAX_FILE_BYTES = 40 * 1024
MAX_MESSAGES = 20
RATIONALE_MAX = 300
SUMMARY_IN_REQUEST = 200
PARTS = ("a", "o", "h")


def build_request(ctx: RunContext, run: Any, rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Write ``review/hint-request.json`` and return the ``adjudicate`` block of kind ``hint`` (without ``attempt`` and
    ``messages``, with ``input_sha256``); None (and no request file) when no row needs hints."""
    wanted = review.hint_rows(rows)
    request_path = store.hint_request_path(ctx)
    if not wanted:
        fsio.remove_file(request_path, root=ctx.layout.out)
        return None
    output = ctx.layout.rel(store.hints_path(ctx))
    rubric = store.RUBRIC_REL           # relative to the skill folder; the block carries the absolute path
    doc = {"schema": store.SCHEMA, "run_id": run.run_id, "kind": "hint", "rubric": rubric, "output": output,
           "max_hints_per_row": store.MAX_HINTS_PER_ROW,
           "rows": [{"row_id": r["id"], "name": r["name"], "version": r["version"], "upstream_url": r["upstream_url"],
                     "purl": r["purl"], "evidence_summary": store.clean_text(r["evidence_summary"], SUMMARY_IN_REQUEST)}
                    for r in wanted]}
    sha = fsio.atomic_write_json(request_path, doc, root=ctx.layout.out)
    return {"kind": "hint", "repo": None, "input": ctx.layout.rel(request_path), "output": output,
            "rubric": ctx.layout.skill_path(rubric), "input_sha256": sha, "items": len(wanted)}


def _read_limited(path: Any, limit: int) -> Optional[bytes]:
    try:
        with open(os.fspath(path), "rb") as handle:
            return handle.read(limit + 1)
    except FileNotFoundError:
        return None


def validate(request_bytes: bytes, request: Dict[str, Any], answer: Optional[bytes]
             ) -> Tuple[List[Dict[str, Any]], List[str], List[Tuple[str, str]]]:
    """``(valid hints, problems, notes)`` of the agent's answer. A file-level problem (missing, too large, not JSON, wrong
    request hash) leaves no valid hint. The reader is ``replyread`` (a code fence of any spelling, a byte order mark, CRLF);
    ``notes`` is what it tolerated (an unclosed fence), for the caller to record."""
    if answer is None:
        return ([], ["review/hints.json does not exist; write the hints file named in the request"], [])
    if len(answer) > MAX_FILE_BYTES:
        return ([], ["review/hints.json is larger than %d KB" % (MAX_FILE_BYTES // 1024)], [])
    doc, problem, notes = replyread.parse_bytes(answer)
    if problem is not None:
        return ([], ["review/hints.json is not valid UTF-8 JSON: %s" % problem], notes)
    if not isinstance(doc, dict):
        return ([], ["review/hints.json must be a JSON object"], notes)
    problems: List[str] = []
    if doc.get("schema") != store.SCHEMA:
        problems.append("schema must be 1")
    if doc.get("request_sha256") != fsio.sha256_bytes(request_bytes):
        problems.append("request_sha256 does not match the current review/hint-request.json")
    hints = doc.get("hints")
    if not isinstance(hints, list):
        problems.append("hints must be a list")
        return ([], problems, notes)
    if problems:
        return ([], problems, notes)
    requested = {r["row_id"] for r in request.get("rows") or []}
    max_per_row = int(request.get("max_hints_per_row") or store.MAX_HINTS_PER_ROW)
    valid: List[Dict[str, Any]] = []
    per_row: Dict[str, int] = {}
    for index, hint in enumerate(hints, 1):
        label = "hint %d" % index
        if not isinstance(hint, dict):
            problems.append("%s must be an object" % label)
            continue
        row_id, part = hint.get("row_id"), hint.get("part")
        vendor, product, rationale = hint.get("vendor"), hint.get("product"), hint.get("rationale")
        if row_id not in requested:
            problems.append("%s: row_id %r is not one of the requested rows" % (label, str(row_id)[:40]))
            continue
        if part not in PARTS:
            problems.append("%s: part must be a, o or h" % label)
            continue
        if not isinstance(vendor, str) or not cpestr.HINT_RE.fullmatch(vendor):
            problems.append("%s: vendor must match [a-z0-9][a-z0-9._-]{0,99} (no colon, no escape, not a CPE string)" % label)
            continue
        if not isinstance(product, str) or not cpestr.HINT_RE.fullmatch(product):
            problems.append("%s: product must match [a-z0-9][a-z0-9._-]{0,99} (no colon, no escape, not a CPE string)" % label)
            continue
        if not isinstance(rationale, str) or len(rationale) > RATIONALE_MAX:
            problems.append("%s: rationale must be text of at most %d characters" % (label, RATIONALE_MAX))
            continue
        if per_row.get(row_id, 0) >= max_per_row:
            problems.append("%s: row %s already has %d hints, at most %d are allowed" % (label, row_id, max_per_row, max_per_row))
            continue
        per_row[row_id] = per_row.get(row_id, 0) + 1
        valid.append({"row_id": row_id, "part": part, "vendor": vendor, "product": product,
                      "rationale": store.clean_text(rationale, RATIONALE_MAX)})
    return (valid, problems, notes)


def apply_hints(ctx: RunContext, run: Any, attempt: int) -> model.ApplyResult:
    """Validate ``review/hints.json`` and add the accepted hints to ``names_rows.json``.

    Attempt 1 is all-or-nothing (any problem gives ``ok=False`` and applies nothing); attempt 2 applies the valid hints,
    drops the invalid ones (their messages are returned and kept in ``names_rows.json`` ``hints_dropped``) and always
    gives ``ok=True``.
    """
    request_bytes = _read_limited(store.hint_request_path(ctx), 1024 * 1024)
    if request_bytes is None:
        return model.ApplyResult(True, [], 0, [])
    try:
        request = json.loads(request_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise errors.StateError("review/hint-request.json is not valid JSON") from exc
    valid, problems, notes = validate(request_bytes, request, _read_limited(store.hints_path(ctx), MAX_FILE_BYTES))
    found = replyread.note_records(notes, attempt=attempt)
    if problems and attempt < 2:
        return model.ApplyResult(False, problems[:MAX_MESSAGES], 0, [], found)
    doc = store.load_names_doc(ctx)
    by_id = {r["id"]: r for r in doc["rows"]}
    applied = 0
    for hint in valid:
        row = by_id.get(hint["row_id"])
        if row is None:
            continue
        pair = cpestr.pair_str(hint["part"], hint["vendor"], hint["product"])
        known = {p["pair"] for p in list(row.get("proposals") or []) + list(row.get("alternatives") or [])}
        if pair in known:
            continue
        row.setdefault("alternatives", []).append({"pair": pair, "role": "also_emit", "tier": "low", "basis": "model",
                                                   "note": hint["rationale"]})
        if not row.get("proposals"):
            row["tier"] = "low"
        applied += 1
    doc["hints_dropped"] = problems[:MAX_MESSAGES] if problems else []
    store.save_names_doc(ctx, doc)
    return model.ApplyResult(True, problems[:MAX_MESSAGES], applied, [], found)
