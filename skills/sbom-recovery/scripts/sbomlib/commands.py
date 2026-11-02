"""The subcommands behind ``sbom.py`` (contract sections 3.8, 5.1-5.3): ``status``, ``next``, ``approve``, ``audit``,
``explain``, ``summary``, ``dispatch-record``, ``dispatch-prompt``, ``inline-unit``, ``check-unit`` and ``reply`` (the worker
role, TASKLIST 3.8), plus the three M2 stubs.

``cli_core`` handles ``selfcheck`` and ``start`` itself and dispatches every other subcommand here. A handler returns the
result object (a dict) or, for ``explain`` and ``summary``, plain text. Handlers that write take the operation mutex; the
mutex is what makes two overlapping commands safe, because nothing else in a plain skill install serializes them.

A finished run is read-only. ``status``, ``next``, ``explain``, ``summary`` and ``audit`` compare its folder with the ledger
sealed when it finished (``runfiles.closed_check``) and say so first when it differs; ``approve``, ``dispatch-record`` and
``inline-unit`` refuse before they write anything, because a write to ``run.json`` there would look like the change it detects.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List, Optional

import sys

from sbomlib import approval, audit, driver, errors, fsio, lifecycle, model, report, runfiles, state
from sbomlib.cli_core import error_result
from sbomlib.context import RunContext
from sbomlib.state import RunState


def _no_run(cmd: str) -> Dict[str, Any]:
    return error_result(cmd, "NO_RUN", "No run. Run start.")


def _remember(ctx: RunContext, run: RunState, cmd: str, result: Dict[str, Any]) -> None:
    run.data["last_result"] = {"cmd": cmd, "next_action": result.get("next_action"),
                               "message": str(result.get("message") or "")[:2000], "at": ctx.now_iso()}
    run.save(ctx)


def _warnings_envelope(run: RunState) -> List[Dict[str, Any]]:
    items = [w for w in run.data.get("warnings") or [] if isinstance(w, dict)]
    items.sort(key=lambda w: 0 if w.get("tier") == "ACTION_REQUIRED" else 1)
    return items[:10]


# --------------------------------------------------------------------------------------------------- status

def _run_state(ctx: RunContext, run: Optional[RunState], lock: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if run is None:
        return {"run_state": "none", "next_step": "start"}
    if run.completed:
        return {"run_state": "completed_pass" if run.audit == "pass" else "completed_fail", "next_step": "start"}
    if lifecycle.heads_changed_before_gate(ctx, run):
        return {"run_state": "heads_changed", "next_step": "start"}
    if run.gate == "awaiting_approval":
        return {"run_state": "at_gate", "next_step": "approve"}
    if lock is not None and lock.get("driver") == "workflow" and state.heartbeat_age_s(ctx, lock) < state.TAKEOVER_AGE_S:
        return {"run_state": "workflow_driving", "next_step": "wait"}
    return {"run_state": "in_flight", "next_step": "next"}


def _env_facts(ctx: RunContext) -> Dict[str, Any]:
    try:
        env = fsio.read_json(ctx.layout.state / "env.json") if os.path.isfile(str(ctx.layout.state / "env.json")) else {}
    except (errors.StateError, OSError):
        env = {}
    python = env.get("python") if isinstance(env, dict) else None
    python = python if isinstance(python, dict) else {}
    return {"python_prefix": python.get("prefix") or ctx.python_prefix, "python3_IB_works": python.get("python3_IB_works")}


def cmd_status(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    """Where the run stands. Never creates a run and never writes: with no hook there is no guard state to refresh."""
    run = state.load_run(ctx)
    lock = state.read_lock(ctx) if run is not None else None
    steps = _run_state(ctx, run, lock)
    result: Dict[str, Any] = {"ok": True, "cmd": "status"}
    if run is None:
        result.update(run_state=steps["run_state"], start_needed=True, next_step="start",
                      message="No run. Run start.", warnings=[])
        result.update(_env_facts(ctx))
        result["enforcement"] = report.enforcement_note(ctx)
        result["mode"] = None
        result["output_folder"] = ctx.layout.out_name
        return result
    ctx.run_id = run.run_id
    review = run.data.get("review") or {}
    approvals = run.data.get("approvals") or []
    latest = approvals[-1] if approvals else None
    changed: Optional[bool] = None
    if review.get("path"):
        try:
            changed = fsio.sha256_file(ctx.layout.review / "cpe-lookup-names.csv") != review.get("sha256")
        except OSError:
            changed = True
    messages = {
        "none": "No run. Run start.",
        "completed_pass": "The last run is complete and passed its audit. A request to recover SBOMs means start: it begins "
                          "the next run, with this one as the baseline. A question about this run is answered with summary, posted "
                          "unchanged in a fenced block.",
        "completed_fail": "The last run is complete but failed its audit. A request to recover SBOMs means start: it begins "
                          "a new run. A question about why it failed is answered with summary, posted unchanged in a fenced block.",
        "heads_changed": "A repository HEAD changed before the gate; start moves this run to abandoned/ and begins a new one.",
        "at_gate": "Waiting at the approval gate. After the human replies, run approve.",
        "workflow_driving": "Another driver is running this run; wait.",
        "in_flight": "The run is in progress. Run next.",
    }
    folder = runfiles.closed_check(ctx, run) if run.completed else None
    verdict, disagreement = report.closed_verdict(ctx, run) if run.completed else (None, None)
    result.update({
        "run_id": run.run_id, "phase": run.phase, "run_state": steps["run_state"],
        "start_needed": steps["next_step"] == "start", "next_step": steps["next_step"], "gate": run.gate,
        "stages": dict(run.data.get("stages") or {}), "completed": run.completed, "audit": run.audit,
        "driver": (lock or {}).get("driver"),
        "heartbeat_age_s": round(state.heartbeat_age_s(ctx, lock), 1) if lock else None,
        "heads_changed_before_gate": steps["run_state"] == "heads_changed",
        "review": {"path": review.get("path"), "rows": review.get("rows", 0), "rows_included": review.get("rows_included", 0),
                   "changed_since_written": changed, "last_refusal": review.get("last_refusal")},
        "approval": {"status": ("stale" if latest and latest.get("stale") else ("approved" if latest else "none")),
                     "evidence": latest.get("evidence") if latest else None, "n": len(approvals)},
        "enforcement": report.enforcement_note(ctx),
        "repos": {name: run.repo(name).get("status") for name in run.all_repos()},
        "mode": run.data.get("mode", "full"), "output_folder": ctx.layout.out_name,
        "pilot_repos": list(run.data.get("pilot_repos") or []),
        "baseline": {k: (run.data.get("baseline") or {}).get(k) for k in ("present", "run_id", "closed_at", "mode")},
        "commits": {name: run.repo(name).get("head") for name in run.all_repos()},
        "worker": {name: run.repo(name).get("worker") for name in run.all_repos() if run.repo(name).get("worker")},
        "outputs_ok": audit.outputs_ok(ctx, run)["ok"] if run.completed else None,
        "message": messages.get(steps["run_state"], ""), "warnings": _warnings_envelope(run),
    })
    if run.completed:
        _closed_facts(ctx, result, folder, verdict, disagreement)
    result.update(_env_facts(ctx))
    return result


def _closed_facts(ctx: RunContext, result: Dict[str, Any], folder: Optional[Dict[str, Any]], verdict: Optional[str],
                  disagreement: Optional[str]) -> None:
    """What ``status`` and ``next`` add about a finished run: whether its folder is what the script sealed, and the verdict
    taken from both ``run.json`` and ``validation.json``. The first sentence of ``message`` and the first warning say so when
    it is not; ``next_action`` and ``run_state`` stay as they are (the summary is how the person is told)."""
    notes: List[Dict[str, Any]] = []
    prefix: List[str] = []
    if folder is not None:
        result["run_folder_ok"] = folder["ok"]
        if folder.get("unchecked"):
            result["run_folder_unchecked"] = folder["unchecked"]
        if not folder["ok"]:
            result["run_folder_changes"] = folder["changed"]
            notes.append(runfiles.closed_warning(ctx, folder))
            prefix.append(runfiles.closed_line(ctx, folder))
        if folder["added_count"]:
            result["run_folder_extra"] = folder["added"]
    if verdict is not None:
        result["verdict"] = verdict
    if disagreement:
        notes.append(model.warning("ACTION_REQUIRED", "VALIDATION_FAIL", disagreement))
        prefix.append(disagreement)
    if notes:
        result["warnings"] = notes + [w for w in result.get("warnings") or [] if isinstance(w, dict)]
        result["message"] = " ".join(prefix + [str(result.get("message") or "")]).strip()


# --------------------------------------------------------------------------------------------------- next / audit

def _done_again(ctx: RunContext, run: RunState, cmd: str) -> Dict[str, Any]:
    """``next`` on a finished run: ``done`` again, with the folder compared against the ledger sealed at the end (nothing is
    written). ``done`` stays ``done`` when the folder changed: the summary that the agent posts next opens with the change."""
    result: Dict[str, Any] = {"ok": True, "cmd": cmd, "run_id": run.run_id, "phase": run.phase, "next_action": "done",
                              "message": driver.DONE_AGAIN}
    _closed_facts(ctx, result, runfiles.closed_check(ctx, run), *report.closed_verdict(ctx, run))
    return result


def _drive(ctx: RunContext, cmd: str) -> Dict[str, Any]:
    """The body of ``next`` (and of ``audit`` while the run is at phase ``audit``)."""
    run = state.load_run(ctx)
    if run is None:
        return _no_run(cmd)
    ctx.run_id = run.run_id
    if run.completed:
        return _done_again(ctx, run, cmd)
    with state.op_mutex(ctx, cmd):
        run = state.load_run(ctx)
        if run is None:
            return _no_run(cmd)
        if run.completed:
            return _done_again(ctx, run, cmd)
        claimed, active, age = state.claim_driver(ctx, run.run_id, "chat")
        if not claimed:
            raise errors.DriverBusy("another driver (%s) was active %.0f s ago; wait for it or reply \"continue\" "
                                    "later" % (active, age))
        try:
            if run.gate == "awaiting_approval":
                result = driver._gate_result(ctx, run, cmd)
                _remember(ctx, run, cmd, result)
                return result
            result = driver.run_units(ctx, run, driver="chat", cmd=cmd)
        finally:
            state.heartbeat(ctx, "chat")
        return result


def cmd_next(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    return _drive(ctx, "next")


def cmd_audit(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    run = state.load_run(ctx)
    if run is None:
        return _no_run("audit")
    ctx.run_id = run.run_id
    if run.completed:
        with state.op_mutex(ctx, "audit"):
            run = state.load_run(ctx) or run
            ctx.command_info["driver"] = "none"
            result = audit.reaudit(ctx, run)
            if result.get("run_folder_ok") is False:
                folder = runfiles.closed_check(ctx, run)
                if not folder["ok"]:
                    result["warnings"] = [runfiles.closed_warning(ctx, folder)]
                    result["message"] = "%s %s" % (runfiles.closed_line(ctx, folder), result["message"])
            return result
    if run.phase == "audit":
        return _drive(ctx, "audit")
    return {"ok": True, "cmd": "audit", "run_id": run.run_id, "phase": run.phase, "next_action": "run_again",
            "message": "The audit runs as phase 10; run next."}


# --------------------------------------------------------------------------------------------------- approve

def cmd_approve(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    run = state.load_run(ctx)
    if run is None:
        return _no_run("approve")
    ctx.run_id = run.run_id
    with state.op_mutex(ctx, "approve"):
        run = state.load_run(ctx)
        if run is None:
            return _no_run("approve")
        ctx.command_info["driver"] = "none"
        result = approval.approve(ctx, run, mode="agent")
        if not run.completed:           # a finished run is not written to: that would be the change the ledger reports
            _remember(ctx, run, "approve", result)
        return result


# --------------------------------------------------------------------------------------------------- text commands

def cmd_explain(ctx: RunContext, args: argparse.Namespace) -> str:
    return report.explain_text(ctx, state.load_run(ctx))


def cmd_summary(ctx: RunContext, args: argparse.Namespace) -> str:
    return report.summary_text(ctx, state.load_run(ctx))


# --------------------------------------------------------------------------------------------------- dispatch record

def cmd_dispatch_record(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    """``dispatch-record <unit id> <subagent|inline> [--model NAME]``: how an adjudication unit was run.

    The script records ``inline`` by itself when the decisions file of a unit validates, because the agent that was handed
    the block wrote it in its own context. This command exists for a host run that delegated the unit to a subagent (a
    ``worker:<repo>`` unit above all); it overwrites the automatic record and keeps the history.
    """
    run = state.load_run(ctx)
    if run is None:
        return _no_run("dispatch-record")
    ctx.run_id = run.run_id
    if run.completed:
        raise errors.UsageError("the run is complete; there is nothing to record (a finished run is not written to)")
    unit = args.unit
    known = [u for u in driver.plan(ctx, run) if u.startswith(("adjudicate:", "worker:")) or u == "names:hints"]
    if unit not in known:
        raise errors.UsageError("%r is not an adjudication unit of this run; known: %s" % (unit, ", ".join(known) or "none"))
    with state.op_mutex(ctx, "dispatch-record"):
        run = state.load_run(ctx)
        if run is None:
            return _no_run("dispatch-record")
        if run.completed:
            raise errors.UsageError("the run is complete; there is nothing to record (a finished run is not written to)")
        if args.dispatch_mode == "inline" and unit.startswith("worker:"):
            began = (run.data.get("adjudication") or {}).get("%s:worker" % unit[len("worker:"):])
            if not (isinstance(began, dict) and began.get("inline_open")):
                raise errors.UsageError(
                    "%s was not begun with inline-unit, which writes the unit's brief, so it cannot be recorded as inline. "
                    "Run inline-unit %s, read the brief it names in full, follow it, and the script records the unit itself "
                    "when its reply validates. If a subagent wrote the reply, record it as subagent." % (unit, unit))
        entry = driver.record_dispatch(run, unit, args.dispatch_mode, args.model, ctx)
        if args.dispatch_mode == "subagent" and unit.startswith("worker:"):
            # a subagent now holds the unit: an earlier inline-unit call no longer decides how it is recorded
            opened = (run.data.get("adjudication") or {}).get("%s:worker" % unit[len("worker:"):])
            if isinstance(opened, dict):
                opened.pop("inline_open", None)
        run.save(ctx)
    note = ("the mode is what you report; this tool cannot verify it. `inline` means the unit ran in the orchestrator's own "
            "context, which is weaker independence (%s)." % report.limitations_path(ctx))
    return {"ok": True, "cmd": "dispatch-record", "run_id": run.run_id, "unit": unit, "dispatch_mode": entry["mode"],
            "model": entry["model"], "attempts": entry["attempts"], "message": note}


# --------------------------------------------------------------------------------------------------- the worker role

def _worker_unit(run: RunState, ctx: RunContext, unit: Optional[str]) -> str:
    from sbomlib import worker
    if not unit:
        raise errors.UsageError("name a worker unit, for example worker:<repo>")
    repo = worker.repo_of_unit(unit)
    plan = driver.plan(ctx, run)
    if repo is None or unit not in plan:
        known = [u for u in plan if u.startswith(worker.DISPATCH_PREFIX)]
        if unit.startswith(("adjudicate:", "names:")):
            raise errors.UsageError("%s is answered by the orchestrator itself, with the rubric of its adjudicate block; only "
                                    "worker units are dispatched to a role (worker units: %s). dispatch-record records how "
                                    "an adjudication unit ran." % (unit, ", ".join(known) or "none yet"))
        raise errors.UsageError("%r is not a worker unit of this run; worker units: %s" % (unit, ", ".join(known) or "none"))
    return str(repo)


def _ensure_request(ctx: RunContext, run: RunState, repo: str) -> Optional[Dict[str, Any]]:
    """The recorded request entry of ``worker:<repo>``, created (with the files the worker reads) when it is not there yet.
    None when the repository's claims were carried over from the baseline instead."""
    from sbomlib import worker
    unit = worker.unit_of(repo)
    for prerequisite in ("adjudicate:%s:usage" % repo, "adjudicate:%s:trace_build" % repo):
        if run.unit_state(prerequisite) != "done":
            raise errors.UsageError("%s is not ready: %s is not done yet. Run next first." % (unit, prerequisite))
    entries = run.data.setdefault("adjudication", {})
    key = "%s:worker" % repo
    if key not in entries:
        block = worker.request_block(ctx, run, repo)
        if block is None:
            return None
        entries[key] = {"attempt": 1, "input_sha256": block["input_sha256"], "done": False}
    return entries[key]


def cmd_dispatch_prompt(ctx: RunContext, args: argparse.Namespace) -> Any:
    """``dispatch-prompt <unit id>`` or ``dispatch-prompt --stage worker``: the fixed prompt of SKILL_MIGRATION section 6 with
    every placeholder filled by the script (skill folder, run folder and unit id are resolved here, never typed by hand), as
    plain text, one block per unit. The first call for a unit also writes the request the role reads. A unit that failed its
    first reply gets the problems the script found appended on a ``RETRY:`` line."""
    from sbomlib import worker
    run = state.load_run(ctx)
    if run is None:
        return _no_run("dispatch-prompt")
    ctx.run_id = run.run_id
    if run.completed:
        raise errors.UsageError("the run is complete; there is nothing to dispatch")
    if bool(args.unit) == bool(args.stage):
        raise errors.UsageError("give one worker unit (worker:<repo>) or --stage worker, not both and not neither")
    with state.op_mutex(ctx, "dispatch-prompt"):
        run = state.load_run(ctx)
        if run is None:
            return _no_run("dispatch-prompt")
        if args.stage:
            units = [u for u in driver.plan(ctx, run) if u.startswith(worker.DISPATCH_PREFIX) and run.unit_state(u) != "done"]
            if not units:
                raise errors.UsageError("no worker unit is waiting. Run next.")
        else:
            _worker_unit(run, ctx, args.unit)
            units = [args.unit]
        blocks: List[str] = []
        carried: List[str] = []
        for unit in units:
            repo = str(worker.repo_of_unit(unit))
            entry = _ensure_request(ctx, run, repo)
            if entry is None:
                carried.append(unit)
                continue
            if entry.get("done"):
                continue
            retry = entry.get("messages") if int(entry.get("attempt") or 1) >= 2 else None
            blocks.append("===== %s =====\n%s\n===== end of %s =====" % (unit, worker.prompt_for(ctx, unit, retry), unit))
        mode_block = report.mode_said_block(run, "subagent")        # the mode line to say, once, last in the output
        run.save(ctx)
    if not blocks:
        raise errors.UsageError("nothing to dispatch: %s" % (
            "the claims of %s are carried over from the baseline; run next" % ", ".join(carried) if carried else
            "the worker units are done"))
    head = ["%d prompt(s) for the `worker` role. Give each block between the ===== lines, whole and unchanged, to one subagent "
            "(at most four at a time), and wait for all of them. Then run dispatch-record <unit> subagent for each unit "
            "(add --model NAME when the host says which model ran it), then next. A worker does not write anything but its "
            "reply file." % len(blocks)]
    if carried:
        head.append("Carried over from the baseline, no worker needed: %s." % ", ".join(carried))
    return "\n".join(head + [""] + blocks) + mode_block


def cmd_inline_unit(ctx: RunContext, args: argparse.Namespace) -> Any:
    """``inline-unit <unit id>``: start one worker unit in the orchestrator's own context (a host without a subagent tool,
    or a first spawn that failed). Writes the unit's brief (the paths of the unit and the role file, verbatim) to
    ``repos/<repo>/worker.brief.md`` and prints only its path and one instruction to read it in full with the file-reading
    tool. Nothing is proved by that: whether the brief was read, and whether a unit was done on its own, are conventions
    (references/limitations.md). The unit is recorded as ``inline`` when its reply validates (``driver._adjudication_step``),
    not here. The script refuses to begin a second unit while one is open."""
    from sbomlib import worker
    run = state.load_run(ctx)
    if run is None:
        return _no_run("inline-unit")
    ctx.run_id = run.run_id
    if run.completed:
        raise errors.UsageError("the run is complete; there is nothing to do for %s" % (args.unit or "a unit"))
    with state.op_mutex(ctx, "inline-unit"):
        run = state.load_run(ctx)
        if run is None:
            return _no_run("inline-unit")
        if run.completed:
            raise errors.UsageError("the run is complete; there is nothing to do for %s" % (args.unit or "a unit"))
        repo = _worker_unit(run, ctx, args.unit)
        entry = _ensure_request(ctx, run, repo)
        if entry is None:
            raise errors.UsageError("%s was carried over from the baseline; no worker is needed. Run next." % args.unit)
        entries = run.data.get("adjudication") or {}
        for key, other in entries.items():
            if key.endswith(":worker") and key != "%s:worker" % repo and other.get("inline_open") and not other.get("done"):
                raise errors.UsageError("%s is still open; finish it (write its reply and run next) before you begin %s." % (
                    worker.unit_of(key[:-len(":worker")]), args.unit))
        info = worker.check_unit(ctx, run, args.unit, entry)
        text = worker.brief_text(ctx, args.unit, info, entry)
        path = worker.brief_path(ctx, repo)
        sha = fsio.atomic_write_text(path, text, root=ctx.layout.out)
        shown = entry.get("brief")
        entry["inline_open"] = True
        # when the brief was written and which one: `summary` counts the units whose brief came before the reply file
        # (driver._brief_first); the order of two files, not a proof of reading
        entry["brief"] = {"at": ctx.now_iso(), "ns": ctx.clock.wall_ns(), "sha256": sha, "path": ctx.layout.rel(path),
                          "count": int(shown.get("count") or 0) + 1 if isinstance(shown, dict) else 1}
        mode_block = report.mode_said_block(run, "inline")          # computed before this unit is recorded: said once
        run.save(ctx)
    attempt = entry.get("attempt", 1)
    # the file of the earlier attempt is still on disk, and `next` judges whatever file is there (driver._worker_hold): say so
    again = (" The reply file of the earlier attempt is still there and next judges whatever file is there, so write the whole "
             "reply file again before you run next." if info.get("reply_exists") and int(attempt or 1) >= 2 else "")
    return ("Unit %s, inline (attempt %s). Your brief is this file:\n%s\n"
            "Read it in full with your file-reading tool (not a shell command), then follow it for this one repository. "
            "When its reply file is written, run next.%s\n%s" % (args.unit, attempt, path.as_posix(), again, mode_block))


def cmd_check_unit(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    """``check-unit <unit id>``: step 0 of the worker role. Tells the role whether the unit belongs to this run and gives it the
    exact paths to read and write; once the reply file exists it validates it (read-only) with the rules ``next`` applies."""
    from sbomlib import worker
    run = state.load_run(ctx)
    if run is None:
        return {"ok": False, "cmd": "check-unit", "unit": args.unit, "reason": "no run in this working directory",
                "message": "REFUSED step 0: no run in this working directory. Stay in the workspace the orchestrator named."}
    ctx.run_id = run.run_id
    entry = (run.data.get("adjudication") or {}).get("%s:worker" % (worker.repo_of_unit(args.unit) or ""))
    answer = worker.check_unit(ctx, run, args.unit, entry)
    answer["cmd"] = "check-unit"
    if not answer.get("ok"):
        answer["message"] = "REFUSED step 0: %s" % answer.get("reason")
    else:
        answer["message"] = ("The unit is yours. Write only the reply file" +
                             ("; its checks found problems, fix them." if answer.get("problems") else ".") +
                             (" The reader noted: %s; write the file again as one plain JSON object." % "; ".join(answer["notes"])
                              if answer.get("notes") else ""))
    # the verdict first: a worker that checks its reply reads the top of the answer and has nothing to filter out of it
    first = ("ok", "unit", "reply_exists", "reply_valid", "problems", "notes", "message", "reason")
    return dict([(k, answer[k]) for k in first if k in answer] + [(k, v) for k, v in answer.items() if k not in first])


def cmd_reply(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    """``reply <unit id>``: the reply of a role that had no tool to write a file, on standard input (one JSON object, bare or in
    one code fence of any spelling). The script writes the reply file itself, then validates it like ``check-unit`` does. An
    unclosed fence is read as far as it goes and noted on the unit's record and in ``summary``; an unreadable one is refused
    with a message that names the fence."""
    from sbomlib import replyread, worker
    run = state.load_run(ctx)
    if run is None:
        return _no_run("reply")
    ctx.run_id = run.run_id
    stdin = sys.stdin
    try:
        interactive = stdin is None or bool(stdin.isatty())
    except (AttributeError, ValueError):
        interactive = False
    if interactive:
        raise errors.UsageError("reply reads the JSON object from standard input; give it on standard input, not a terminal")
    text = stdin.read(worker.MAX_REPLY_BYTES + 1)
    document, problem, notes = replyread.parse_text(text)
    if problem is not None or not isinstance(document, dict):
        raise errors.UsageError("the reply on standard input is unusable: %s" % (problem or "it must be one JSON object"))
    with state.op_mutex(ctx, "reply"):
        run = state.load_run(ctx)
        if run is None:
            return _no_run("reply")
        repo = _worker_unit(run, ctx, args.unit)
        entry = (run.data.get("adjudication") or {}).get("%s:worker" % repo)
        info = worker.check_unit(ctx, run, args.unit, entry)
        if not info.get("ok"):
            raise errors.UsageError("cannot take a reply for %s: %s" % (args.unit, info.get("reason")))
        fsio.ensure_dir(ctx.layout.llm_dir(repo), root=ctx.layout.out)
        sha = fsio.atomic_write_json(worker.reply_path(ctx, repo), document, root=ctx.layout.out)
        if notes and isinstance(entry, dict):
            replyread.record(run, entry, args.unit, replyread.note_records(notes, attempt=int(entry.get("attempt") or 1)), repo)
            run.save(ctx)
        info = worker.check_unit(ctx, run, args.unit, entry)
    result = {"ok": True, "cmd": "reply", "unit": args.unit, "written": ctx.layout.rel(worker.reply_path(ctx, repo)),
              "sha256": sha, "problems": info.get("problems", []),
              "message": "Reply written by the script. Run dispatch-record if a subagent produced it, then next."}
    if notes:
        result["notes"] = [t for _k, t in notes]
    return result


# --------------------------------------------------------------------------------------------------- M2 stubs

def _stub(cmd: str) -> Dict[str, Any]:
    result = error_result(cmd, "NOT_IMPLEMENTED_M2", "The %s subcommand belongs to a later milestone and is not available." % cmd)
    return result


def cmd_stage(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    return _stub("stage")


def cmd_gate_status(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    return _stub("gate-status")


def cmd_validate(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    return _stub("validate")
