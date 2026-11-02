"""Approval binding, the numbered approval snapshots and stale detection (contract sections 5.3 and 5.8).

``approve`` is the only code that opens the gate. It reads the review file once, runs the strict read-back, records who
approved (see the evidence levels below), stores the exact approved bytes as ``.state/approved-names-<n>.csv`` and takes
``integrity-approve-<n>.json``. ``check_current`` detects an edit after approval. Both write ``run.json`` and must be called
with the op mutex held. ``sbomlib.cpe`` (WP-cpe) is imported inside the functions that need it.

Evidence levels. A plain skill install has no hook that records what a person typed, so a bound human reply (the
hardened variant's ``hook`` evidence) cannot exist and is not accepted here. Two levels remain, and every output records
the one that was used:

* ``tty``: the approval came through ``human_approve.py``, which needs a terminal on standard input and output and the typed
  word APPROVE. It is the strong form, and still only a speed bump: an agent can allocate a pseudo-terminal.
* ``agent-relayed``: the agent ran ``sbom.py approve`` after a person said "approved" in the conversation. The script cannot
  tell that a person said it, and says so (an ACTION_REQUIRED warning, ``report.md``, the summary, the SPDX comment).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import errors, fsio, integrity, model, state
from sbomlib.context import RunContext, iso_z

SCHEMA = 1
REVIEW_NAME = "cpe-lookup-names.csv"
APPROVAL_NAME = "approval.json"
DIFF_LIMIT = 50
RUN_COMPLETED_MESSAGE = ("This run is complete and its audit is final. To change the review, run start for a new run; "
                         "approved rows are pre-filled.")
NOT_AT_GATE_MESSAGE = "The run has not reached the approval gate yet. Run next until it stops for approval."
RELAYED_MESSAGE = ("The approval was relayed by the agent: this skill has no hook that records what a person typed, so "
                   "it cannot be attributed to a person. The strong form is human_approve.py run in a terminal.")


# --------------------------------------------------------------------------------------------------- locations

def review_path(ctx: RunContext) -> Path:
    return ctx.layout.review / REVIEW_NAME


def approval_path(ctx: RunContext) -> Path:
    return ctx.layout.state / APPROVAL_NAME


def approved_copy_path(ctx: RunContext, n: int) -> Path:
    return ctx.layout.state / ("approved-names-%d.csv" % n)


def load_approval(ctx: RunContext) -> Optional[Dict[str, Any]]:
    """``.state/approval.json`` (contract section 4.15); None when absent, ``StateError`` when malformed."""
    path = approval_path(ctx)
    if not os.path.lexists(str(path)):
        return None
    data = fsio.read_json(path)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or "sha256" not in data:
        raise errors.StateError(".state/approval.json is not an approval record", path=str(path))
    return data


# --------------------------------------------------------------------------------------------------- evidence

def verify_approval(ctx: RunContext, run: Any, *, mode: str) -> Dict[str, Any]:
    """Who approved? ``mode`` ``tty`` (a person at a terminal, through ``human_approve.py``) or ``agent`` (the chat).

    Returns ``{"ok", "evidence": "tty"|"agent-relayed", "human_record": None, "strict", "code", "message"}``. ``strict`` is
    true only for ``tty``. An agent approval is always accepted as ``agent-relayed``: there is no recorded human reply to
    bind it to, and the output says so.
    """
    if mode == "tty":
        return {"ok": True, "evidence": "tty", "human_record": None, "strict": True, "code": None,
                "message": "Approved by a person at a terminal."}
    if mode != "agent":
        raise ValueError("mode must be agent or tty")
    return {"ok": True, "evidence": "agent-relayed", "human_record": None, "strict": False, "code": None,
            "message": RELAYED_MESSAGE}


# --------------------------------------------------------------------------------------------------- result helpers

def _error(run: Any, code: str, message: str) -> Dict[str, Any]:
    return {"ok": False, "cmd": "approve", "run_id": run.run_id, "phase": run.phase, "next_action": "error",
            "error": {"code": code, "message": message, "retryable": False}, "message": message}


def _approval_block(status: str, n: Optional[int], evidence: Optional[str], sha256: Optional[str], code: Optional[str],
                    **extra: Any) -> Dict[str, Any]:
    block: Dict[str, Any] = {"status": status, "n": n, "evidence": evidence, "sha256": sha256, "diff": [],
                             "diff_truncated": False, "readonly_changes": [], "code": code}
    block.update(extra)
    return block


def _gate(ctx: RunContext, run: Any, envelope: Dict[str, Any]) -> Dict[str, Any]:
    """Add the ``gate`` block a ``stop_for_approval`` result carries (best effort)."""
    try:
        from sbomlib import cli_core
        envelope["gate"] = cli_core.gate_block(ctx, run)
    except Exception:
        ctx.log.exception("approval.gate_block_failed")
    return envelope


def _refuse(ctx: RunContext, run: Any, *, code: str, message: str, digest: Optional[str], reason: Optional[str] = None,
            line: Optional[int] = None, row_id: Optional[str] = None, column: Optional[str] = None,
            remember: bool = True) -> Dict[str, Any]:
    if remember:
        review = run.data.setdefault("review", {})
        review["last_refusal"] = {"code": code, "message": message, "line": line, "at": ctx.now_iso()}
        run.save(ctx)
    state.audit_event(ctx, {"event": "approval_refused", "code": code, "message": message[:300]})
    block = _approval_block("refused", None, None, digest, code, reason=reason or code, line=line,
                            row_id=row_id, column=column)
    envelope = {"ok": True, "cmd": "approve", "run_id": run.run_id, "phase": run.phase, "next_action": "stop_for_approval",
                "approval": block, "message": message}
    return _gate(ctx, run, envelope)


def _read_review(ctx: RunContext) -> Tuple[bytes, int]:
    """The review file's bytes and the modification time of that very descriptor (one read)."""
    with open(str(review_path(ctx)), "rb") as handle:
        data = handle.read()
        mtime = os.fstat(handle.fileno()).st_mtime_ns
    return data, mtime


# --------------------------------------------------------------------------------------------------- snapshots / files

def _take_snapshot(ctx: RunContext, label: str, extra: Dict[str, Any]) -> None:
    """``integrity.snapshot`` that survives a crash between the snapshot and the ``run.json`` update: an existing file
    with the same ``extra`` is kept, an orphan with different content is replaced (``run.json`` never recorded it)."""
    try:
        integrity.snapshot(ctx, label, extra=extra)
        return
    except FileExistsError:
        pass
    wanted = json.loads(json.dumps(extra))
    existing = integrity.load_snapshot(ctx, label)
    if existing is not None and existing.get("extra") == wanted:
        return
    fsio.remove_file(integrity.snapshot_path(ctx, label), root=ctx.layout.out)
    integrity.snapshot(ctx, label, extra=extra)


def _write_approved_copy(ctx: RunContext, n: int, data: bytes) -> None:
    path = approved_copy_path(ctx, n)
    try:
        fsio.write_once_bytes(path, data, root=ctx.layout.out)
        return
    except FileExistsError:
        pass
    try:
        with open(str(path), "rb") as handle:
            existing = handle.read()
    except OSError:
        existing = b""
    if existing == data:
        return
    fsio.remove_file(path, root=ctx.layout.out)                  # an orphan: approval n was never recorded
    fsio.write_once_bytes(path, data, root=ctx.layout.out)


def _reset_after_approval(ctx: RunContext, run: Any) -> None:
    """A new approval restarts lookup, emit, merge and audit (contract section 5.3)."""
    run.set_stage("lookup", "pending")
    run.set_stage("emit", "pending")
    for repo in run.active_repos():
        run.set_repo_phase(repo, "emit", "pending")
    run.clear_units(["cpe:", "emit:", "merge", "audit"])
    for name in ("cpe_progress.json", "validation.json", "audit_checks.json", "integrity-final.json"):
        fsio.remove_file(ctx.layout.state / name, root=ctx.layout.out)
    fsio.remove_tree(ctx.layout.state / "integrity-final.parts", root=ctx.layout.out)


# --------------------------------------------------------------------------------------------------- approve

def approve(ctx: RunContext, run: Any, *, mode: str, expected_sha256: Optional[str] = None) -> Dict[str, Any]:
    """Open the approval gate for the review file as it is now (contract section 5.3 "approve").

    Returns the ``approve`` result object: ``approval.status`` ``approved`` / ``already_approved`` (``next_action``
    ``run_again``), ``refused`` (``stop_for_approval``; ``code`` ``READBACK_REFUSED`` with the read-back ``reason``,
    ``REVIEW_MISSING`` or ``FILE_CHANGED``) or an ``error`` envelope (``RUN_COMPLETED``,
    ``NOT_AT_GATE``). The caller holds the op mutex. ``expected_sha256`` refuses when the bytes are not the ones the
    caller showed to the person.
    """
    if mode not in ("agent", "tty"):
        raise ValueError("mode must be agent or tty")
    ctx.run_id = ctx.run_id or run.run_id
    if run.completed:
        return _error(run, "RUN_COMPLETED", RUN_COMPLETED_MESSAGE)
    if run.gate == "none" or not (run.data.get("review") or {}).get("path"):
        return _error(run, "NOT_AT_GATE", NOT_AT_GATE_MESSAGE)
    try:
        data, review_mtime_ns = _read_review(ctx)
    except OSError:
        message = ("The review file %s cannot be read. Restore it, or abandon the run "
                   "with start --abandon from a terminal and start again." % ctx.layout.shown("review/cpe-lookup-names.csv"))
        return _refuse(ctx, run, code="REVIEW_MISSING", message=message, digest=None)
    digest = fsio.sha256_bytes(data)
    if expected_sha256 is not None and digest != expected_sha256:
        message = ("The review file changed after it was shown to you. Review it again, then run human_approve.py again.")
        return _refuse(ctx, run, code="FILE_CHANGED", message=message, digest=digest, remember=False)

    approvals: List[Dict[str, Any]] = run.data.setdefault("approvals", [])
    last = approvals[-1] if approvals else None
    if run.gate == "approved" and last is not None and not last.get("stale"):
        if digest == last.get("sha256"):
            return _already_approved(run, last)
        check_current(ctx, run)                                  # edit before `next`: stale-<n> first, then n + 1
        approvals = run.data["approvals"]
        if run.gate == "approved" and not approvals[-1].get("stale"):
            return _already_approved(run, approvals[-1])

    from sbomlib import cpe                                      # WP-cpe; imported here, never at module level
    try:
        read_back = cpe.read_back(ctx, data, cpe.load_written_rows(ctx))
    except errors.ReviewRefused as exc:
        return _refuse(ctx, run, code="READBACK_REFUSED", message=exc.message, digest=digest,
                       reason=str(exc.detail.get("reason") or "READBACK_REFUSED"), line=exc.detail.get("line"),
                       row_id=exc.detail.get("row_id"), column=exc.detail.get("column"))
    verdict = verify_approval(ctx, run, mode=mode)
    if not verdict["ok"]:
        return _refuse(ctx, run, code=str(verdict["code"]), message=verdict["message"], digest=digest)

    n = len(approvals) + 1
    now_ns = ctx.clock.wall_ns()
    now_text = iso_z(now_ns)
    review = run.data.setdefault("review", {})
    human = verdict["human_record"]
    _write_approved_copy(ctx, n, data)
    document = {"schema": SCHEMA, "status": "approved", "n": n, "run_id": run.run_id, "sha256": digest,
                "approved_at": now_text, "approved_at_ns": now_ns, "approval_evidence": verdict["evidence"],
                "strict": bool(verdict["strict"]), "names_written_at": review.get("names_written_at"),
                "names_written_at_ns": review.get("names_written_at_ns"), "review_mtime_ns": review_mtime_ns,
                "human_record": human, "approved_copy": ".state/approved-names-%d.csv" % n,
                "diff_count": len(read_back["diff"])}
    fsio.atomic_write_json(approval_path(ctx), document, root=ctx.layout.out)
    _take_snapshot(ctx, "approve-%d" % n, {"human_record": human, "approval_sha256": digest})
    approvals.append({"n": n, "sha256": digest, "evidence": verdict["evidence"], "approved_at": now_text,
                      "approved_at_ns": now_ns, "human_record": human, "stale": False})
    run.data["gate"] = "approved"
    run.data["phase"] = "cpe"
    review["last_refusal"] = None
    warnings: List[Dict[str, Any]] = []
    if verdict["evidence"] == "agent-relayed":
        warnings.append(model.warning("ACTION_REQUIRED", "APPROVAL_AGENT_RELAYED", RELAYED_MESSAGE))
        run.add_warnings(warnings)
    _reset_after_approval(ctx, run)
    run.save(ctx)
    state.audit_event(ctx, {"event": "approval", "n": n, "evidence": verdict["evidence"], "sha256": digest,
                            "human_record": human["id"] if human else None})
    diff = read_back["diff"]
    edits = len(diff)
    block = _approval_block("approved", n, verdict["evidence"], digest, None)
    block["diff"] = diff[:DIFF_LIMIT]
    block["diff_truncated"] = edits > DIFF_LIMIT
    block["readonly_changes"] = list(read_back["readonly_changes"])[:DIFF_LIMIT]
    summary = "no edits" if edits == 0 else ("1 edited cell" if edits == 1 else "%d edited cells" % edits)
    envelope: Dict[str, Any] = {"ok": True, "cmd": "approve", "run_id": run.run_id, "phase": run.phase,
                                "next_action": "run_again", "approval": block,
                                "message": "Approved review file (%s). Run next." % summary}
    folder = [w for w in run.data.get("warnings") or []
              if isinstance(w, dict) and w.get("code") in ("RUN_FOLDER_CHANGED", "RUN_FOLDER_EXTRA_FILE")]
    if folder:                      # found by this very command (runfiles.enter): say it before the lookups begin
        warnings = warnings + folder[:12]
        if any(w.get("code") == "RUN_FOLDER_CHANGED" for w in folder):
            envelope["message"] += (" The run folder was changed by something other than the script: the audit will fail "
                                    "and nothing will be promoted (see warnings).")
    if warnings:
        envelope["warnings"] = warnings
    return envelope


def _already_approved(run: Any, last: Dict[str, Any]) -> Dict[str, Any]:
    block = _approval_block("already_approved", last.get("n"), last.get("evidence"), last.get("sha256"), None)
    return {"ok": True, "cmd": "approve", "run_id": run.run_id, "phase": run.phase, "next_action": "run_again",
            "approval": block,
            "message": "The review file is already approved (approval %s). Run next." % last.get("n")}


# --------------------------------------------------------------------------------------------------- stale detection

def check_current(ctx: RunContext, run: Any) -> Dict[str, Any]:
    """Compare the live review file with the latest approval (before every unit of phases 7-10).

    ``{"ok": bool, "stale_now": bool, "n": int|None}``. A changed (or missing) file marks the approval stale, takes
    ``integrity-stale-<n>.json``, sets the gate back to ``awaiting_approval`` and the phase to ``approve``.
    """
    approvals = run.data.get("approvals") or []
    if not approvals:
        return {"ok": False, "stale_now": False, "n": None}
    last = approvals[-1]
    n = int(last["n"])
    if last.get("stale"):
        return {"ok": False, "stale_now": False, "n": n}
    try:
        live: Optional[str] = fsio.sha256_file(review_path(ctx))
    except OSError:
        live = None
    old = last.get("sha256")
    if live is not None and live == old:
        return {"ok": True, "stale_now": False, "n": n}
    document = load_approval(ctx)
    if document is None or document.get("n") != n:
        document = {"schema": SCHEMA, "n": n, "run_id": run.run_id, "sha256": old,
                    "approval_evidence": last.get("evidence"), "approved_at": last.get("approved_at"),
                    "approved_at_ns": last.get("approved_at_ns"), "human_record": last.get("human_record")}
    document["status"] = "stale"
    document["stale_sha256"] = live
    fsio.atomic_write_json(approval_path(ctx), document, root=ctx.layout.out)
    _take_snapshot(ctx, "stale-%d" % n, {"old_sha256": old, "new_sha256": live})
    last["stale"] = True
    run.data["gate"] = "awaiting_approval"
    run.data["phase"] = "approve"
    run.save(ctx)
    state.audit_event(ctx, {"event": "stale", "n": n, "old_sha256": old, "new_sha256": live})
    return {"ok": False, "stale_now": True, "n": n}
