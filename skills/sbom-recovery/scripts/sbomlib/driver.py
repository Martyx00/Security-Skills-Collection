"""The unit table, the budget loop, repository isolation and stage bookkeeping (contract sections 3.14, 5.4-5.9).

``plan`` lists the units of a run in canonical order (phase-major, then queue order); ``run_units`` runs them one after
another until the time budget of one ``next`` call is used up, the run needs the agent (``adjudicate``), the human
(``stop_for_approval``), or is finished. Every unit writes its outputs atomically and only then is recorded as ``done`` in
``run.json``, so a crash re-runs the unit and rewrites identical outputs.

This module is the integration layer of the pack: it only orders and records. What a unit does lives in the phase modules
(``enumerate``, ``discover``, ``verify``, ``cpe``, ``emit``, ``audit``); this module never judges a component.
"""
from __future__ import annotations

import os
import traceback
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import approval, errors, fsio, model, replyread, state
from sbomlib.context import RunContext
from sbomlib.state import RunState

SOFT_BUDGET_S = 40.0
HARD_BUDGET_S = 80.0
MAX_BUDGET_ATTEMPTS = 2           # full-budget attempts of one unit before a per-repo unit fails its repo
MAX_MESSAGES = 20

PHASE_OF_PREFIX = {"enumerate": "enumerate", "discover": "discover", "verify": "verify", "adjudicate": "adjudicate",
                   "worker": "worker", "names": "names", "cpe": "cpe", "emit": "emit", "merge": "merge", "audit": "audit"}
STAGE_OF_PHASE = {"enumerate": "analyze", "discover": "analyze", "verify": "analyze", "adjudicate": "judge",
                  "worker": "judge", "names": "propose", "cpe": "lookup", "emit": "emit", "merge": "emit", "audit": "emit"}
REPO_PHASE_OF_PREFIX = {"enumerate": "enumerate", "discover": "discover", "verify": "verify", "adjudicate": "adjudicate",
                        "worker": "worker", "emit": "emit"}
CHECKED_PHASES = ("cpe", "emit", "merge", "audit")       # the approval is re-checked before every unit of these phases
POST_GATE_PHASES = CHECKED_PHASES
KIND_UNITS = ("usage", "trace_build")


NoRepositories = errors.NoRepositories


DONE_AGAIN = "Run complete. Run summary and put its whole output, unchanged, in a fenced block as the first thing in your reply."


class Outcome:
    """What one unit reports back to the loop."""

    def __init__(self, done: bool = True, *, adjudicate: Optional[Dict[str, Any]] = None, gate: bool = False,
                 outputs: Optional[Dict[str, str]] = None, message: Optional[str] = None) -> None:
        self.done = done
        self.adjudicate = adjudicate
        self.gate = gate
        self.outputs = outputs or {}
        self.message = message


# --------------------------------------------------------------------------------------------------- unit ids

SCAN_UNIT = "enumerate::scan"           # a double colon: a repository name can never contain ":" (D15), so the two
PREPARE_UNIT = "emit::prepare"          # global units cannot collide with the unit of a repository called "scan"


def split_unit(unit: str) -> Tuple[str, Optional[str], Optional[str]]:
    """``(prefix, repo, extra)`` of a unit id: ``adjudicate:app:usage`` -> ``("adjudicate", "app", "usage")``,
    ``discover:app`` -> ``("discover", "app", None)``, ``worker:app`` -> ``("worker", "app", None)``,
    ``names:build`` -> ``("names", None, "build")``,
    ``enumerate::scan`` -> ``("enumerate", None, "scan")``, ``merge`` -> ``("merge", None, None)``."""
    parts = unit.split(":")
    prefix = parts[0]
    if len(parts) == 3 and parts[1] == "":
        return (prefix, None, parts[2])
    if prefix in ("enumerate", "discover", "verify", "emit", "worker") and len(parts) == 2:
        return (prefix, parts[1], None)
    if prefix == "adjudicate" and len(parts) >= 3:
        return (prefix, ":".join(parts[1:-1]), parts[-1])
    return (prefix, None, ":".join(parts[1:]) or None)


def phase_of(unit: str) -> str:
    return PHASE_OF_PREFIX[split_unit(unit)[0]]


def stage_of(unit: str) -> str:
    return STAGE_OF_PHASE[phase_of(unit)]


def repo_of(unit: str) -> Optional[str]:
    return split_unit(unit)[1]


# --------------------------------------------------------------------------------------------------- the plan

def analysed_repos(run: RunState) -> List[str]:
    """The repositories that still take part in the run: not FAILED, not NOT ANALYZED."""
    return run.active_repos()


def plan(ctx: RunContext, run: RunState) -> List[str]:
    """The ordered unit ids of the run as it stands (contract section 5.4); reads ``run.json`` only."""
    repos = run.all_repos()
    live = analysed_repos(run)
    units = [SCAN_UNIT]
    for repo in repos:                      # a repository that failed while being described has no unit left to run
        unit = "enumerate:%s" % repo
        if run.repo(repo).get("status") != "FAILED" or run.unit_state(unit) == "done":
            units.append(unit)
    units.extend("discover:%s" % r for r in live)
    units.extend("verify:%s" % r for r in live)
    for repo in live:
        units.extend("adjudicate:%s:%s" % (repo, kind) for kind in KIND_UNITS)
    units.extend("worker:%s" % r for r in live)
    units.append("names:build")
    if "hint" in (run.data.get("adjudication") or {}):
        units.append("names:hints")
    units.append("names:write")
    units.append("cpe:resolve")
    units.append(PREPARE_UNIT)
    units.extend("emit:%s" % r for r in live)
    units.extend(["merge", "audit:snapshot", "audit:validate", "audit:finalize"])
    return units


def next_unit(ctx: RunContext, run: RunState) -> Optional[str]:
    """The first unit that is not done; None when every unit is."""
    for unit in plan(ctx, run):
        if run.unit_state(unit) != "done":
            return unit
    return None


# --------------------------------------------------------------------------------------------------- bookkeeping

def refresh_phase_and_stages(ctx: RunContext, run: RunState) -> None:
    """``run.json`` phase and stage values from the unit states (``phase`` is the phase of the next pending unit)."""
    units = plan(ctx, run)
    by_stage: Dict[str, List[str]] = {stage: [] for stage in model.STAGES}
    for unit in units:
        by_stage[stage_of(unit)].append(unit)
    pending = next_unit(ctx, run)
    for stage in model.STAGES:
        names = by_stage[stage]
        states = [run.unit_state(u) for u in names]
        current = run.data.get("stages", {}).get(stage, "pending")
        if current == "failed":
            continue
        if names and all(s == "done" for s in states):
            value = "done"
        elif any(s in ("done", "partial", "failed") for s in states):
            value = "running"
        else:
            value = "pending"
        run.set_stage(stage, value)
    if run.completed:
        run.data["phase"] = "done"
    elif run.gate == "awaiting_approval":
        run.data["phase"] = "approve"
    elif pending is not None:
        run.data["phase"] = phase_of(pending)


def _warn(run: RunState, tier: str, code: str, message: str, repo: Optional[str] = None) -> None:
    run.add_warnings([model.warning(tier, code, message, repo)])


def _clean(text: str, limit: int = 200) -> str:
    return " ".join(str(text).split())[:limit]


def fail_repo(ctx: RunContext, run: RunState, repo: str, unit: str, reason: str, *, count_attempt: bool = True) -> None:
    """Mark one repository FAILED (contract section 5.9) and take its staged output out of the way."""
    text = _clean("%s: %s" % (unit, reason))
    entry = run.repo(repo)
    phase = REPO_PHASE_OF_PREFIX.get(split_unit(unit)[0])
    run.set_repo_status(repo, "FAILED", text)
    prior = int(run.unit(unit).get("attempts") or 0)
    run.mark_unit(unit, "failed", attempts=prior + 1 if count_attempt else prior, error=text)
    for name in model.REPO_PHASES:
        if name == phase:
            run.set_repo_phase(repo, name, "failed")
        elif entry.get("phases", {}).get(name, "pending") == "pending":
            run.set_repo_phase(repo, name, "skipped")
    _warn(run, "ACTION_REQUIRED", "REPO_FAILED", "repository %s failed: %s" % (repo, text), repo)
    state.audit_event(ctx, {"event": "repo_failed", "repo": repo, "unit": unit, "reason": text})
    from sbomlib.emit import stage
    try:
        fsio.remove_tree(stage.staged_repo_dir(ctx, run, repo), root=ctx.layout.out)
        fsio.remove_file(ctx.layout.repo_out(repo) / "components.json", root=ctx.layout.out)
    except (errors.SbomError, OSError):
        ctx.log.warning("driver.failed_repo_cleanup", repo=repo)


def _record_done(ctx: RunContext, run: RunState, unit: str, outcome: Outcome, seconds: float) -> None:
    run.mark_unit(unit, "done", outputs=dict(outcome.outputs), finished_at=ctx.now_iso(), error=None)
    state.audit_event(ctx, {"event": "unit", "unit": unit, "state": "done", "outputs": dict(outcome.outputs),
                            "seconds": round(seconds, 2)})


def _merge_result(run: RunState, repo: str, result: model.PhaseResult) -> None:
    entry = run.repo(repo)
    if result.outputs:
        entry.setdefault("outputs", {}).update(result.outputs)
    if result.incomplete:
        known = list(entry.get("incomplete") or [])
        for reason in result.incomplete:
            if reason not in known:
                known.append(reason)
        entry["incomplete"] = known
    if result.warnings:
        run.add_warnings(result.warnings)


# --------------------------------------------------------------------------------------------------- the units

def _unit_scan(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib import enumerate as enum
    result = enum.scan(ctx, run)
    repos = list(result.info.get("repos") or [])
    for name in repos:
        run.ensure_repo(name)
    if not repos:
        raise NoRepositories(errors.no_repositories_message(ctx.layout.parent))
    run.add_warnings(result.warnings)
    return Outcome(outputs=result.outputs)


def _unit_describe(ctx: RunContext, run: RunState, unit: str, repo: str) -> Outcome:
    from sbomlib import enumerate as enum
    result = enum.describe_repo(ctx, run, repo)
    run.add_warnings(result.warnings)
    if result.repo_status == "NOT ANALYZED":
        run.set_repo_status(repo, "NOT ANALYZED", result.repo_reason)
        for name in model.REPO_PHASES:
            run.set_repo_phase(repo, name, "done" if name == "enumerate" else "skipped")
    else:
        head = result.info.get("head")
        if head:
            run.repo(repo)["head"] = head
        run.set_repo_phase(repo, "enumerate", "done")
    return Outcome(outputs=result.outputs)


def _unit_discover(ctx: RunContext, run: RunState, unit: str, repo: str) -> Outcome:
    from sbomlib import discover
    result = discover.run_repo(ctx, run, repo)
    _merge_result(run, repo, result)
    run.set_repo_phase(repo, "discover", "done")
    return Outcome(outputs=result.outputs)


def _unit_verify(ctx: RunContext, run: RunState, unit: str, repo: str) -> Outcome:
    from sbomlib import verify
    result = verify.run_repo(ctx, run, repo)
    _merge_result(run, repo, result)
    run.set_repo_phase(repo, "verify", "done")
    return Outcome(outputs=result.outputs)


def record_dispatch(run: RunState, unit: str, mode: str, model_name: Optional[str], ctx: RunContext,
                    *, automatic: bool = False, brief_first: Optional[bool] = None) -> Dict[str, Any]:
    """Store how an adjudication unit was run (``subagent`` or ``inline``) in ``run.json.dispatch``. ``brief_first`` is set for
    a worker unit that ran inline: whether ``inline-unit`` wrote the unit's brief before the reply file was written."""
    if mode not in ("subagent", "inline", "carried"):
        raise ValueError("mode must be subagent, inline or carried")
    table = run.data.setdefault("dispatch", {})
    previous = table.get(unit) or {}
    history = [h for h in previous.get("history") or [] if isinstance(h, dict)]
    entry = {"mode": mode, "model": _clean(model_name, 100) if model_name else "unknown", "recorded": ctx.now_iso(),
             "automatic": bool(automatic)}
    history.append(entry)
    table[unit] = {"unit": unit, "mode": mode, "model": entry["model"], "recorded": entry["recorded"],
                   "automatic": bool(automatic), "attempts": len(history), "history": history[-10:]}
    if brief_first is not None:
        table[unit]["brief_first"] = bool(brief_first)
    return table[unit]


def _rebuild_block(ctx: RunContext, repo: Optional[str], kind: str, attempt: int, messages: List[str]) -> Dict[str, Any]:
    """The ``adjudicate`` block of a corrective retry, rebuilt from the input file the first block named."""
    if kind == "worker":
        from sbomlib import worker
        request = fsio.read_json(worker.request_path(ctx, str(repo)))
        block = worker.block_for(ctx, request)
    elif kind == "hint":
        from sbomlib.cpe import store
        path = store.hint_request_path(ctx)
        request = fsio.read_json(path)
        block = {"kind": "hint", "repo": None, "input": ctx.layout.rel(path), "output": request["output"],
                 "rubric": ctx.layout.skill_path(request["rubric"]), "input_sha256": fsio.sha256_file(path),
                 "items": len(request.get("rows") or [])}
    else:
        from sbomlib.verify import adjudicate
        in_name = adjudicate.FILES[kind][0]
        summary = fsio.read_json(ctx.layout.repo_out(str(repo)) / in_name)
        block = adjudicate.summary_block(ctx, summary, kind)
    block["attempt"] = attempt
    block["messages"] = list(messages)[:MAX_MESSAGES]
    return block


def _adjudication_step(ctx: RunContext, run: RunState, unit: str, key: str, kind: str, repo: Optional[str],
                       first_block: Any, apply: Any) -> Outcome:
    """The shared sequence of section 5.7 for ``usage``, ``trace_build`` and ``hint``.

    ``first_block()`` builds the input file and returns the block (or None when nothing needs the agent); ``apply(attempt)``
    validates the agent's file and returns an ``ApplyResult``.
    """
    entries = run.data.setdefault("adjudication", {})
    entry = entries.get(key)
    if entry is None:
        block = first_block()
        if block is None:
            return Outcome()
        entries[key] = {"attempt": 1, "input_sha256": block["input_sha256"], "done": False}
        return Outcome(done=False, adjudicate=dict(block, unit=unit, attempt=1, messages=[]))
    if entry.get("done"):
        return Outcome()
    attempt = int(entry.get("attempt") or 1)
    result = apply(attempt)
    replyread.record(run, entry, unit, list(getattr(result, "notes", None) or []), repo)
    if result.ok:
        entry["done"] = True
        if entry.get("inline_open") or not (run.data.get("dispatch") or {}).get(unit):
            # the agent that was handed the block wrote the decisions file itself, in its own context (a worker unit that
            # was begun with inline-unit counts even when an earlier attempt was recorded as a subagent run)
            record_dispatch(run, unit, "inline", None, ctx, automatic=True)
        return Outcome()
    entry["attempt"] = 2
    entry["messages"] = list(result.messages)[:MAX_MESSAGES]
    return Outcome(done=False, adjudicate=dict(_rebuild_block(ctx, repo, kind, 2, result.messages), unit=unit))


def _unit_adjudicate(ctx: RunContext, run: RunState, unit: str, repo: str, kind: str) -> Outcome:
    from sbomlib import verify
    outcome = _adjudication_step(
        ctx, run, unit, "%s:%s" % (repo, kind), kind, repo,
        lambda: verify.evidence_summary(ctx, run, repo, kind),
        lambda attempt: verify.apply_decisions(ctx, run, repo, kind, attempt))
    if outcome.done and kind == "trace_build" and run.repo(repo).get("status") == "QUEUED":
        incomplete = run.repo(repo).get("incomplete") or []
        run.set_repo_status(repo, "INCOMPLETE" if incomplete else "DONE")
        run.set_repo_phase(repo, "adjudicate", "done")
    return outcome


# A worker reply is read only when the script knows how the unit ran, and not before the unit has had its turn. The skill cannot
# see a subagent, but it can see what the agent ran: ``dispatch-record <unit> subagent`` for a delegated unit (one per attempt),
# ``inline-unit <unit>`` (which writes the unit's brief) for a unit the agent runs itself. A reply that arrives with neither is
# held, not judged and not counted as an attempt. "Had its turn" means two different things. For a subagent it is the record
# that the subagent of this attempt finished (``dispatch.<unit>.attempts`` has reached the attempt number): one that is still
# working has not failed, and whatever file lies on disk from attempt 1 is not its answer. For an inline unit it is only that a
# reply file exists: the script does not remember which attempt wrote it, and compares no file times (that would be a proof of
# reading by another name). So the file attempt 1 left, a failed subagent's included, is judged as attempt 2 when the unit is
# moved to ``inline-unit`` and ``next`` runs before the file is written again; the unit then ends INCOMPLETE with an ACTION
# REQUIRED ``WORKER_FAILED``, in plain sight. The brief and the ``inline-unit`` text say to write the whole file again. These holds
# are bookkeeping. They do not check that a role or a brief was read; nothing in a plain skill install can
# (references/limitations.md).
HOLD_SLACK_NS = 2 * 1000 * 1000 * 1000          # file timestamps can be coarse: a reply up to 2 s older than the brief still counts as after it

HOLD_TEXT = {
    "DISPATCH_RECORD_MISSING": (
        "The reply file is there and nothing is wrong with it, but the script has no record of how %(unit)s ran, so it has not "
        "read it yet. If a subagent wrote it, run dispatch-record %(unit)s subagent (add --model NAME when the host says which "
        "model ran it). If you run the unit yourself because the host has no subagent tool or the first spawn failed, run "
        "inline-unit %(unit)s now, read the brief it names in full, follow it and write the whole reply file again. "
        "Do not dispatch another subagent for this. Then run next."),
    "REPLY_NOT_YET_WRITTEN": (
        "No reply for %(unit)s has been written yet, and the script has no record of how the unit runs. Nothing was counted "
        "against it. If you gave it to a subagent, wait until the subagent has finished, then run dispatch-record %(unit)s "
        "subagent and next. If you run it yourself because the host has no subagent tool or the first spawn failed, run "
        "inline-unit %(unit)s, read the brief it names in full and write the reply. Do not run next to poll."),
}
WAIT_TEXT = {
    "subagent": (
        "Attempt %(attempt)s of %(unit)s has not been recorded as finished, and nothing was counted against it: a subagent "
        "that is still working has not failed. Wait for it. When it has finished (it answered DELIVERED, NOT WRITTEN or "
        "REFUSED), run dispatch-record %(unit)s subagent and then next; a finished subagent that delivered nothing counts as "
        "its attempt. Do not run next to poll."),
    "inline": (
        "No reply for %(unit)s has been written yet, and nothing was counted against it. Do the unit as its brief says and "
        "write the whole reply file with your file-writing tool, then run next. If you cannot do the analysis, write the "
        "reply with status FAILED and a reason (or give it to reply %(unit)s on standard input). Do not run next to poll."),
}


def _reply_written_ns(ctx: RunContext, repo: str) -> Optional[int]:
    from sbomlib import worker
    try:
        return os.lstat(str(worker.reply_path(ctx, repo))).st_mtime_ns         # a link counts by its own time, never followed
    except OSError:
        return None


def _brief_ns(entry: Dict[str, Any]) -> Optional[int]:
    brief = entry.get("brief")
    ns = brief.get("ns") if isinstance(brief, dict) else None
    return ns if isinstance(ns, int) and not isinstance(ns, bool) else None


def _brief_first(ctx: RunContext, entry: Dict[str, Any], repo: str) -> bool:
    """The brief was written by ``inline-unit`` before the reply file was last written. The order of two files, nothing more:
    it does not show that the brief was read."""
    shown, written = _brief_ns(entry), _reply_written_ns(ctx, repo)
    return shown is not None and written is not None and written + HOLD_SLACK_NS >= shown


def _worker_hold(ctx: RunContext, run: RunState, unit: str, repo: str) -> Optional[Outcome]:
    """The unit handed back unchanged, with a ``hold`` that says what is missing, or None when the reply may be read."""
    entry = (run.data.get("adjudication") or {}).get("%s:worker" % repo)
    if not isinstance(entry, dict) or entry.get("done"):
        return None
    attempt = int(entry.get("attempt") or 1)
    record = (run.data.get("dispatch") or {}).get(unit) or {}
    subagent = record.get("mode") == "subagent"
    written = _reply_written_ns(ctx, repo) is not None
    code: Optional[str] = None
    text: Optional[str] = None
    if entry.get("inline_open"):
        if not written:
            code, text = "REPLY_NOT_YET_WRITTEN", WAIT_TEXT["inline"]
    elif not subagent:
        code = "DISPATCH_RECORD_MISSING" if written else "REPLY_NOT_YET_WRITTEN"
        text = HOLD_TEXT[code]
    elif int(record.get("attempts") or 0) < attempt:
        code, text = "REPLY_NOT_YET_WRITTEN", WAIT_TEXT["subagent"]          # recorded for an earlier attempt only
    if code is None or text is None:
        return None
    messages = list(entry.get("messages") or []) if attempt >= 2 else []
    block = dict(_rebuild_block(ctx, repo, "worker", attempt, messages), unit=unit)
    block["hold"] = {"code": code, "text": text % {"unit": unit, "attempt": attempt}}
    state.audit_event(ctx, {"event": "worker_hold", "unit": unit, "code": code, "attempt": attempt})
    return Outcome(done=False, adjudicate=block)


def _unit_worker(ctx: RunContext, run: RunState, unit: str, repo: str) -> Outcome:
    from sbomlib import worker
    held = _worker_hold(ctx, run, unit, repo)
    if held is not None:
        return held
    outcome = _adjudication_step(
        ctx, run, unit, "%s:worker" % repo, "worker", repo,
        lambda: worker.request_block(ctx, run, repo),
        lambda attempt: worker.apply_reply(ctx, run, repo, attempt))
    if outcome.done and outcome.adjudicate is None:
        summary = run.repo(repo).get("worker") or {}
        if summary.get("source") == "carried" and not (run.data.get("dispatch") or {}).get(unit):
            record_dispatch(run, unit, "carried", None, ctx, automatic=True)        # no worker ran: the baseline's claims hold
        record = (run.data.get("dispatch") or {}).get(unit)
        entry = (run.data.get("adjudication") or {}).get("%s:worker" % repo)
        if isinstance(record, dict) and record.get("mode") == "inline" and isinstance(entry, dict):
            record["brief_first"] = _brief_first(ctx, entry, repo)
    return outcome


def _unit_names_build(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib import cpe
    count, block = cpe.build_review(ctx, run)
    if block is None:
        return Outcome()
    run.data.setdefault("adjudication", {})["hint"] = {"attempt": 1, "input_sha256": block["input_sha256"], "done": False}
    # names:build is done; names:hints is pending and is the unit the next call starts with
    return Outcome(done=True, adjudicate=dict(block, attempt=1, messages=[]))


def _unit_names_hints(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib import cpe
    return _adjudication_step(ctx, run, unit, "hint", "hint", None, lambda: None,
                              lambda attempt: cpe.apply_hints(ctx, run, attempt))


def _unit_names_write(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib import cpe, integrity
    from sbomlib.cpe import store
    kept = (run.unit(unit) or {}).get("review")
    review_file = store.review_path(ctx)
    info: Optional[Dict[str, Any]] = None
    if isinstance(kept, dict) and os.path.isfile(str(review_file)):
        try:
            if fsio.sha256_file(review_file) == kept.get("sha256"):
                info = kept                        # written by an earlier call: the file is still the one recorded
        except OSError:
            info = None
    if info is None:
        info = cpe.write_review(ctx, run)
        run.mark_unit(unit, "partial", attempts=int((run.unit(unit) or {}).get("attempts", 0)), review=info)
        run.save(ctx)
    try:
        sha = integrity.snapshot(ctx, "gate", resumable=True)
    except FileExistsError:
        sha = "present"
    if sha is None:
        return Outcome(done=False)
    run.data["review"] = dict(info, last_refusal=None)
    run.data["gate"] = "awaiting_approval"
    run.data["phase"] = "approve"
    return Outcome(gate=True, outputs={ctx.layout.out_rel(ctx.layout.parent / info["path"]): info["sha256"]})


def _unit_cpe_resolve(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib import cpe
    result = cpe.resolve(ctx, run)
    if not result.done:
        return Outcome(done=False)
    run.data["nvd"] = dict(result.info.get("nvd") or {})
    run.add_warnings(result.warnings)
    nvd = run.data["nvd"]
    if nvd.get("source") == "offline" or nvd.get("status") == "offline":
        _warn(run, "ACTION_REQUIRED", "NVD_OFFLINE",
              "NVD unreachable: CPE names were constructed from the curated map and not checked against the NVD dictionary")
    return Outcome(outputs=result.outputs)


def _unit_emit_prepare(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib import emit
    emit.prepare(ctx, run)
    for repo in analysed_repos(run):
        run.set_repo_phase(repo, "emit", "pending")
    return Outcome()


def _unit_emit_repo(ctx: RunContext, run: RunState, unit: str, repo: str) -> Outcome:
    from sbomlib import emit
    built = emit.build_components(ctx, run, repo)
    written = emit.write_repo(ctx, run, repo)
    entry = run.repo(repo)
    entry["emit_errors"] = list(written.info.get("errors") or [])
    outputs = dict(built.outputs)
    outputs.update(written.outputs)
    entry.setdefault("outputs", {}).update(outputs)
    run.add_warnings(list(built.warnings) + list(written.warnings))
    run.set_repo_phase(repo, "emit", "done")
    return Outcome(outputs=outputs)


def _unit_merge(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib.emit import merge
    result = merge.write(ctx, run)
    return Outcome(outputs=result.outputs)


def _unit_audit(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    from sbomlib import audit
    function = {"audit:snapshot": audit.snapshot_unit, "audit:validate": audit.validate_unit,
                "audit:finalize": audit.finalize}[unit]
    result = function(ctx, run)
    if not result.done:
        return Outcome(done=False)
    run.add_warnings(result.warnings)
    return Outcome(outputs=result.outputs)


def execute(ctx: RunContext, run: RunState, unit: str) -> Outcome:
    """Run one unit. Raises whatever the unit raises; the loop decides what that means."""
    prefix, repo, extra = split_unit(unit)
    if unit == SCAN_UNIT:
        return _unit_scan(ctx, run, unit)
    if prefix == "enumerate" and repo:
        return _unit_describe(ctx, run, unit, repo)
    if prefix == "discover" and repo:
        return _unit_discover(ctx, run, unit, repo)
    if prefix == "verify" and repo:
        return _unit_verify(ctx, run, unit, repo)
    if prefix == "adjudicate" and repo and extra in KIND_UNITS:
        return _unit_adjudicate(ctx, run, unit, repo, extra)
    if prefix == "worker" and repo:
        return _unit_worker(ctx, run, unit, repo)
    if unit == "names:build":
        return _unit_names_build(ctx, run, unit)
    if unit == "names:hints":
        return _unit_names_hints(ctx, run, unit)
    if unit == "names:write":
        return _unit_names_write(ctx, run, unit)
    if unit == "cpe:resolve":
        return _unit_cpe_resolve(ctx, run, unit)
    if unit == PREPARE_UNIT:
        return _unit_emit_prepare(ctx, run, unit)
    if prefix == "emit" and repo:
        return _unit_emit_repo(ctx, run, unit, repo)
    if unit == "merge":
        return _unit_merge(ctx, run, unit)
    if prefix == "audit":
        return _unit_audit(ctx, run, unit)
    raise errors.StateError("unknown unit %r" % (unit,))


# --------------------------------------------------------------------------------------------------- the loop

def _envelope(ctx: RunContext, run: RunState, cmd: str, next_action: str, message: str, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ok": next_action != "error", "cmd": cmd, "run_id": run.run_id, "phase": run.phase,
                              "next_action": next_action, "message": message}
    result.update(extra)
    return result


def _progress(ctx: RunContext, run: RunState) -> Dict[str, Any]:
    from sbomlib import cli_core
    return cli_core.progress_block(ctx, run) or {}


def _error(ctx: RunContext, run: RunState, cmd: str, code: str, message: str, retryable: bool) -> Dict[str, Any]:
    result = _envelope(ctx, run, cmd, "error", message)
    result["error"] = {"code": code, "message": message, "retryable": retryable}
    result["progress"] = _progress(ctx, run)
    return result


def _gate_result(ctx: RunContext, run: RunState, cmd: str, stale: bool = False) -> Dict[str, Any]:
    from sbomlib import cli_core, report
    result = _envelope(ctx, run, cmd, "stop_for_approval", report.gate_message(ctx, run))
    result["gate"] = cli_core.gate_block(ctx, run)
    result["progress"] = _progress(ctx, run)
    return result


def _adjudicate_result(ctx: RunContext, run: RunState, cmd: str, block: Dict[str, Any]) -> Dict[str, Any]:
    from sbomlib import report
    result = _envelope(ctx, run, cmd, "adjudicate", report.adjudicate_message(ctx, block))
    result["adjudicate"] = block
    result["progress"] = _progress(ctx, run)
    return result


def _progress_message(ctx: RunContext, run: RunState) -> str:
    from sbomlib import report
    return report.progress_message(ctx, run)


def run_units(ctx: RunContext, run: RunState, *, driver: str = "chat", stop_at_stage_end: bool = False,
              cmd: str = "next") -> Dict[str, Any]:
    """The budget loop of section 5.5. The caller holds the op mutex and has claimed the driver."""
    ran: List[str] = []
    ctx.command_info["driver"] = driver
    ctx.command_info["units"] = ran

    def finish(result: Dict[str, Any]) -> Dict[str, Any]:
        refresh_phase_and_stages(ctx, run)
        result["phase"] = run.phase
        run.data["last_result"] = {"cmd": cmd, "next_action": result.get("next_action"),
                                   "message": str(result.get("message") or "")[:2000], "at": ctx.now_iso()}
        run.save(ctx)
        return result

    while True:
        unit = next_unit(ctx, run)
        if unit is None:
            return finish(_envelope(ctx, run, cmd, "done", DONE_AGAIN, progress=_progress(ctx, run)))
        phase = phase_of(unit)
        if run.gate == "awaiting_approval":
            return finish(_gate_result(ctx, run, cmd))
        if phase in POST_GATE_PHASES:
            if run.gate != "approved":
                return finish(_gate_result(ctx, run, cmd))
            checked = approval.check_current(ctx, run)
            if not checked["ok"]:
                run.data["gate"] = "awaiting_approval"
                return finish(_gate_result(ctx, run, cmd, stale=True))
        if ran and ctx.soft_expired():
            return finish(_envelope(ctx, run, cmd, "run_again", _progress_message(ctx, run), progress=_progress(ctx, run)))
        first = not ran
        ctx.unit_first = first
        ctx.unit_t0 = ctx.clock.monotonic()
        started = ctx.clock.monotonic()
        repo = repo_of(unit)
        try:
            outcome = execute(ctx, run, unit)
        except errors.BudgetExceeded as exc:
            if not first:
                return finish(_envelope(ctx, run, cmd, "run_again", _progress_message(ctx, run),
                                        progress=_progress(ctx, run)))        # the next call runs it first, full budget
            run.mark_unit(unit, "partial", error=exc.message)
            attempts = int(run.unit(unit).get("attempts") or 0)
            if attempts < MAX_BUDGET_ATTEMPTS:
                return finish(_envelope(ctx, run, cmd, "run_again", _progress_message(ctx, run),
                                        progress=_progress(ctx, run)))
            if repo is not None and split_unit(unit)[0] in REPO_PHASE_OF_PREFIX:
                fail_repo(ctx, run, repo, unit, "budget exceeded in %s" % unit, count_attempt=False)
                ran.append(unit)
                continue
            state.audit_event(ctx, {"event": "unit_failed", "unit": unit, "error_code": "BUDGET_EXCEEDED",
                                    "message": exc.message[:300], "attempt": attempts})
            return finish(_error(ctx, run, cmd, "BUDGET_EXCEEDED",
                                 "%s used the whole time budget twice; its progress is kept. Reply \"continue\" to try "
                                 "again (a very large workspace may need to be split)." % unit, True))
        except errors.SbomError as exc:
            if repo is not None and split_unit(unit)[0] in REPO_PHASE_OF_PREFIX and not isinstance(exc, (errors.Busy,)):
                ctx.log.exception("driver.repo_unit_failed", unit=unit)
                fail_repo(ctx, run, repo, unit, "%s: %s" % (type(exc).__name__, exc.message))
                ran.append(unit)
                continue
            ctx.log.exception("driver.unit_failed", unit=unit)
            run.mark_unit(unit, "failed", error=exc.message[:300])
            state.audit_event(ctx, {"event": "unit_failed", "unit": unit, "error_code": exc.code,
                                    "message": exc.message[:300], "attempt": run.unit(unit).get("attempts")})
            code = exc.code if exc.code in ("STATE_CORRUPT", "NO_REPOSITORIES", "BUSY", "BUDGET_EXCEEDED") else "UNIT_FAILED"
            text = exc.message if code in ("STATE_CORRUPT", "NO_REPOSITORIES") else "%s failed: %s" % (unit, exc.message)
            return finish(_error(ctx, run, cmd, code, text, exc.retryable or code == "UNIT_FAILED"))
        except Exception as exc:                                   # noqa: BLE001 - any other failure is isolated or reported
            ctx.log.exception("driver.unit_crashed", unit=unit, trace=traceback.format_exc()[-1500:])
            text = "%s: %s" % (type(exc).__name__, str(exc)[:200])
            if repo is not None and split_unit(unit)[0] in REPO_PHASE_OF_PREFIX:
                fail_repo(ctx, run, repo, unit, text)
                ran.append(unit)
                continue
            run.mark_unit(unit, "failed", error=text)
            state.audit_event(ctx, {"event": "unit_failed", "unit": unit, "error_code": "UNIT_FAILED", "message": text,
                                    "attempt": run.unit(unit).get("attempts")})
            return finish(_error(ctx, run, cmd, "UNIT_FAILED", "%s failed: %s" % (unit, text), True))

        ran.append(unit)
        seconds = ctx.clock.monotonic() - started
        if outcome.done:
            _record_done(ctx, run, unit, outcome, seconds)
        else:
            prior = int((run.unit(unit) or {}).get("attempts", 0))
            run.mark_unit(unit, "partial", attempts=prior)
        if outcome.adjudicate is not None:
            run.save(ctx)
            return finish(_adjudicate_result(ctx, run, cmd, outcome.adjudicate))
        if outcome.gate:
            return finish(_gate_result(ctx, run, cmd))
        if not outcome.done:
            return finish(_envelope(ctx, run, cmd, "run_again", _progress_message(ctx, run), progress=_progress(ctx, run)))
        refresh_phase_and_stages(ctx, run)
        run.save(ctx)
        if run.completed:
            return finish(_envelope(ctx, run, cmd, "done", _done_message(run), progress=_progress(ctx, run)))
        if stop_at_stage_end and (next_unit(ctx, run) is None or stage_of(next_unit(ctx, run) or unit) != stage_of(unit)):
            return finish(_envelope(ctx, run, cmd, "stage_done", _progress_message(ctx, run), progress=_progress(ctx, run)))


def _done_message(run: RunState) -> str:
    verdict = "PASS" if run.audit == "pass" else "FAIL"
    return ("Run complete: validation %s. Run summary and put its whole output, unchanged, in a fenced block as the first "
            "thing in your reply." % verdict)
