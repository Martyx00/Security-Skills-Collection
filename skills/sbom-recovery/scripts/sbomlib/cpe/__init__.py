"""CPE names, the review file and CPE resolution (contract section 3.11).

Phase 5 (names): ``build_review``, ``apply_hints``, ``write_review``; the strict read-back ``read_back`` and the helpers of
the approved copy; phase 7: ``resolve`` and ``load_resolution``; ``write_local_decisions`` / ``load_local_decisions``.

Private modules: ``store`` (file locations, shared helpers), ``review`` (rows, CSV, read-back), ``hints``, ``decisions``,
``nvd`` (Products API client) and ``resolve``. ``resolve`` is both this package's phase-7 entry point and a submodule:
the submodule is a callable module (see the end of ``resolve.py``), so ``cpe.resolve(ctx, run)`` and
``from sbomlib.cpe import resolve; resolve.resolve_row(...)`` both work.

Nothing in this package imports another work package at import time (``sbomlib.verify`` is imported by the function that
needs it), so discovery can import ``sbomlib.cpe.cpemap`` while the other packages are absent.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from sbomlib.context import RunContext
from sbomlib.cpe import cpemap, cpestr, decisions, hints, nvd, resolve, review, store      # noqa: F401
from sbomlib.cpe.decisions import load_local_decisions, write_local_decisions                  # noqa: F401
from sbomlib.cpe.hints import apply_hints                                                      # noqa: F401
from sbomlib.cpe.resolve import load_resolution                                                # noqa: F401
from sbomlib.cpe.review import (approved_rows, load_written_rows, read_back, row_for_candidate,   # noqa: F401
                                write_review)
from sbomlib.cpe.store import included_repos                                                   # noqa: F401


def build_review(ctx: RunContext, run: Any) -> Tuple[int, Optional[Dict[str, Any]]]:
    """Unit ``names:build``: the review rows of every DONE/INCOMPLETE repository (``.state/names_rows.json``) and, when
    some rows need model hints, ``review/hint-request.json``.

    Returns ``(row_count, adjudicate block of kind "hint" without attempt/messages but with input_sha256, or None)``.
    """
    rows = review.build_rows(ctx, run)
    store.save_names_doc(ctx, {"schema": store.SCHEMA, "run_id": run.run_id, "rows": rows, "hints_dropped": []})
    block = hints.build_request(ctx, run, rows)
    return (len(rows), block)
