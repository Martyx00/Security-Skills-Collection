"""Phase 10: the audit (contract sections 3.14 and 5.4, units ``audit:snapshot``, ``audit:validate``, ``audit:finalize``).

The audit proves what the run can prove: the final integrity snapshot is taken, every staged repository is validated
(``audit_checks.json`` is the checkpoint), and ``finalize`` combines the checks with the integrity comparison and the
unchanged-pack check. Only a PASS promotes the staged files; a FAIL leaves them staged. ``report.md`` and
``validation-report.txt`` are written on both outcomes, ``validation.json`` last.

``reaudit`` is the read-only re-check of a completed run (the ``audit`` subcommand on a finished run): the repositories, the
promoted outputs and the run folder against the ledger sealed when the run finished.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from sbomlib import fsio, integrity, model, runfiles, state, validate
from sbomlib.context import RunContext
from sbomlib.emit import merge, stage
from sbomlib.model import PhaseResult
from sbomlib.state import RunState

CHECKS_NAME = "audit_checks.json"


def _checks_path(ctx: RunContext) -> Any:
    return ctx.layout.state / CHECKS_NAME


def load_checks(ctx: RunContext, run: RunState) -> Dict[str, Dict[str, List[str]]]:
    """``audit_checks.json`` (repo -> check -> errors) of this run; empty when absent or from another run."""
    path = _checks_path(ctx)
    if not os.path.lexists(str(path)):
        return {}
    doc = fsio.read_json(path)
    if not isinstance(doc, dict) or doc.get("run_id") != run.run_id or not isinstance(doc.get("repos"), dict):
        return {}
    return doc["repos"]


# --------------------------------------------------------------------------------------------------- the units

def snapshot_unit(ctx: RunContext, run: RunState) -> PhaseResult:
    """Unit ``audit:snapshot``: the resumable ``final`` integrity snapshot."""
    try:
        sha = integrity.snapshot(ctx, "final", resumable=True)
    except FileExistsError:
        return PhaseResult()
    if sha is None:
        return PhaseResult(done=False)
    return PhaseResult(outputs={".state/integrity-final.json": sha})


def validate_unit(ctx: RunContext, run: RunState) -> PhaseResult:
    """Unit ``audit:validate``: the per-repository checks on the staged files, one repository at a time."""
    repos = merge.contributing_repos(run)
    done = load_checks(ctx, run)
    pending = [r for r in repos if r not in done]
    for index, repo in enumerate(pending):
        done[repo] = validate.check_repo(ctx, run, repo)
        fsio.atomic_write_json(_checks_path(ctx), {"schema": 1, "run_id": run.run_id, "repos": done}, root=ctx.layout.out)
        if index + 1 < len(pending) and ctx.should_yield():
            return PhaseResult(done=False)
    if not os.path.lexists(str(_checks_path(ctx))):
        fsio.atomic_write_json(_checks_path(ctx), {"schema": 1, "run_id": run.run_id, "repos": done}, root=ctx.layout.out)
    return PhaseResult(outputs={".state/%s" % CHECKS_NAME: fsio.sha256_file(_checks_path(ctx))})


def finalize(ctx: RunContext, run: RunState) -> PhaseResult:
    """Unit ``audit:finalize``: verdict, promotion (PASS only), the reports, ``validation.json``, completion of the run."""
    from sbomlib import cpe, report
    integrity_result = integrity.compare_run(ctx, run)
    pack_result = integrity.pack_check(ctx, run)
    folder_result = runfiles.check(ctx, run)
    per_repo = load_checks(ctx, run)
    validation = validate.check_run(ctx, run, per_repo=per_repo, integrity=integrity_result, pack=pack_result,
                                    run_folder=folder_result)
    verdict = validation["verdict"]
    result = PhaseResult()
    result.warnings.extend(pack_result.get("warnings") or [])
    if verdict == "PASS":
        # a FAIL adds every integrity warning below; on PASS only the one about a HEAD that moved while the run waited
        result.warnings.extend(w for w in integrity_result.get("warnings") or [] if w.get("code") == "HEAD_MOVED_WHILE_PAUSED")
        promoted = stage.promote(ctx, run)
        stage.cleanup_staging(ctx, run)
        run.data["outputs"] = dict(promoted)
        state.audit_event(ctx, {"event": "promote", "files": dict(promoted)})
        cpe.write_local_decisions(ctx, run)
        validation["outputs"] = dict(promoted)
    else:
        validation["outputs"] = {ctx.layout.out_rel(p): fsio.sha256_file(p) for p in stage.staged_files(ctx, run)}
        run.add_warnings(list(integrity_result.get("warnings") or []))
        run.add_warnings([model.warning(
            "ACTION_REQUIRED", "VALIDATION_FAIL",
            "The audit failed (%s); the staged outputs were not promoted. See report.md and validation-report.txt."
            % ", ".join(name for name, check in validation["checks"].items() if check["status"] == "fail"))])
    outcome = {"integrity": integrity_result, "pack": pack_result, "run_folder": folder_result, "validation": validation}
    report.write_report(ctx, run, outcome)
    report.write_validation_report(ctx, run, validation)
    fsio.atomic_write_json(ctx.layout.state / "validation.json", validation, root=ctx.layout.out)
    state.audit_event(ctx, {"event": "audit_result", "verdict": verdict,
                            "failed_checks": [n for n, c in validation["checks"].items() if c["status"] == "fail"]})
    run.data["completed"] = True
    run.data["audit"] = "pass" if verdict == "PASS" else "fail"
    run.data["closed_at"] = ctx.now_iso()
    run.data["closed_at_ns"] = ctx.clock.wall_ns()
    run.data["phase"] = "done"
    for stage_name in model.STAGES:
        run.set_stage(stage_name, "done")
    if verdict != "PASS":
        run.set_stage("emit", "failed")
    state.release_lock(ctx)
    result.info["audit"] = {"verdict": verdict, "validation": validation, "report": ctx.layout.shown("report.md")}
    return result


# --------------------------------------------------------------------------------------------------- the re-audit

def outputs_ok(ctx: RunContext, run: RunState) -> Dict[str, Any]:
    """Whether every promoted file still has the SHA-256 recorded at promotion (a completed run)."""
    recorded = run.data.get("outputs") or {}
    differences: List[str] = []
    for rel, sha in sorted(recorded.items()):
        path = ctx.layout.out / rel
        try:
            actual = fsio.sha256_file(path)
        except OSError:
            differences.append("%s: missing" % rel)
            continue
        if actual != sha:
            differences.append("%s: content changed" % rel)
    return {"ok": not differences, "differences": differences[:50], "checked": len(recorded)}


def reaudit(ctx: RunContext, run: RunState) -> Dict[str, Any]:
    """Read-only re-check of a completed run: a fresh ``integrity.take`` against ``integrity-final.json`` and the hashes of
    the promoted outputs. Writes nothing."""
    final = integrity.load_snapshot(ctx, "final")
    differences: List[Dict[str, Any]] = []
    verdict = "PASS"
    if final is None:
        verdict = "FAIL"
        differences.append({"repo": None, "path": "integrity-final.json", "change": "missing", "fields": [], "class": "violation"})
    else:
        current = integrity.take(ctx, "final")
        compared = integrity.compare(final, current, window="final->now", kind="attributed")
        differences = [d for d in compared.get("differences") or [] if d.get("class") == "violation"][:50]
        if compared.get("violations") or compared.get("head_changes"):
            verdict = "FAIL"
        differences.extend({"repo": h.get("repo"), "path": "HEAD", "change": "modified", "fields": ["head"],
                            "class": "violation"} for h in compared.get("head_changes") or [])
    outputs = outputs_ok(ctx, run)
    folder = runfiles.recheck(ctx, run)
    parts = ["Integrity %s" % verdict, "promoted outputs %s" % ("unchanged" if outputs["ok"] else "CHANGED"),
             "run folder %s" % ("not checked (%s)" % folder["unchecked"] if folder.get("unchecked") else
                                ("unchanged since the run finished" if folder["ok"] else "CHANGED"))]
    return {"ok": True, "cmd": "audit", "run_id": run.run_id, "phase": run.phase, "mode": "reaudit", "integrity": verdict,
            "outputs_ok": outputs["ok"], "run_folder_ok": folder["ok"], "differences": differences + [
                {"repo": None, "path": d.split(":")[0], "change": d.split(": ", 1)[-1], "fields": [], "class": "output"}
                for d in outputs["differences"]] + [
                {"repo": None, "path": d["path"], "change": d["change"], "fields": [], "class": "run_folder"}
                for d in folder["differences"]],
            "next_action": "done", "message": "Re-audit of the completed run: %s." % ", ".join(parts)}
