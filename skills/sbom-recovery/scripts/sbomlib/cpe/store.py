"""File locations and small shared helpers of the CPE package (private to ``sbomlib/cpe``)."""
from __future__ import annotations

import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional

from sbomlib import errors, fsio
from sbomlib.context import RunContext

SCHEMA = 1
NAMES_ROWS = "names_rows.json"
REVIEW_NAME = "cpe-lookup-names.csv"
HINT_REQUEST_NAME = "hint-request.json"
HINTS_NAME = "hints.json"
RESOLUTION_NAME = "cpe_resolution.csv"
LOCAL_DECISIONS_NAME = "local-cpe-decisions.csv"
RUBRIC_REL = "references/cpe-rules.md"       # relative to the skill folder
MAX_HINT_ROWS = 50
MAX_HINTS_PER_ROW = 3
ROLE_ORDER = ("primary", "also_emit", "cve_only", "override", "extra")
CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
TIER_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def names_rows_path(ctx: RunContext) -> Path:
    return ctx.layout.state / NAMES_ROWS


def review_path(ctx: RunContext) -> Path:
    return ctx.layout.review / REVIEW_NAME


def hint_request_path(ctx: RunContext) -> Path:
    return ctx.layout.review / HINT_REQUEST_NAME


def hints_path(ctx: RunContext) -> Path:
    return ctx.layout.review / HINTS_NAME


def approved_copy_path(ctx: RunContext, n: int) -> Path:
    return ctx.layout.state / ("approved-names-%d.csv" % n)


def progress_path(ctx: RunContext) -> Path:
    return ctx.layout.state / "cpe_progress.json"


def staged_resolution_path(ctx: RunContext, run_id: str) -> Path:
    return ctx.layout.staging(run_id) / RESOLUTION_NAME


def promoted_resolution_path(ctx: RunContext) -> Path:
    return ctx.layout.out / RESOLUTION_NAME


def local_decisions_path(ctx: RunContext) -> Path:
    return ctx.layout.out / LOCAL_DECISIONS_NAME


def load_names_doc(ctx: RunContext) -> Dict[str, Any]:
    """``.state/names_rows.json`` (``StateError`` when it is missing or not a names document)."""
    path = names_rows_path(ctx)
    try:
        doc = fsio.read_json(path)
    except FileNotFoundError as exc:
        raise errors.StateError(".state/names_rows.json does not exist; the names phase has not run", path=str(path)) from exc
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("rows"), list):
        raise errors.StateError(".state/names_rows.json is not a names document", path=str(path))
    return doc


def save_names_doc(ctx: RunContext, doc: Dict[str, Any]) -> str:
    doc["schema"] = SCHEMA
    return fsio.atomic_write_json(names_rows_path(ctx), doc, root=ctx.layout.out)


def included_repos(row: Dict[str, Any]) -> List[str]:
    """D19: ``include=no`` excludes the row everywhere (``include_in`` is ignored); ``include=yes`` with an empty
    ``include_in`` includes it in every repository of ``repositories``; otherwise in exactly the listed repositories."""
    if row.get("include") != "yes":
        return []
    repositories = list(row.get("repositories") or [])
    chosen = [r for r in (row.get("include_in") or []) if r in repositories]
    if chosen:
        return sorted(set(chosen))
    return sorted(set(repositories))


def clean_text(text: Any, limit: Optional[int] = None) -> str:
    """Text for a read-only CSV cell: control characters become spaces, runs of white space collapse."""
    if text is None:
        return ""
    plain = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in str(text))
    plain = " ".join(plain.split())
    if limit is not None and len(plain) > limit:
        plain = plain[:limit - 1] + "…"
    return plain


def pair_role_rank(role: Optional[str]) -> int:
    try:
        return ROLE_ORDER.index(role)      # type: ignore[arg-type]
    except ValueError:
        return len(ROLE_ORDER)
