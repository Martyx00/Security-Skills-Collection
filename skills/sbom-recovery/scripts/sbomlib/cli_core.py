"""Command-line front end: argument parsing, layout validation, dispatch and output (contract sections 3.7, 5).

``main`` prints exactly one result to stdout (JSON for most subcommands, plain text for ``explain`` and ``summary``) and
nothing to stderr. Diagnostics go to ``sbom-out/.state/sbom.log``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from sbomlib import errors, fsio, lifecycle, model, paths, selfcheck, state
from sbomlib.context import FULL_OUT, PILOT_OUT, RunContext, make_context, optional_module
from sbomlib.log import Logger

SUBCOMMANDS = ("selfcheck", "start", "pilot", "status", "next", "approve", "audit", "explain", "summary", "stage", "gate-status",
               "validate", "dispatch-record", "dispatch-prompt", "inline-unit", "check-unit", "reply")
DISPATCH_MODES = ("subagent", "inline")
STAGES_WITH_ROLE = ("worker",)                    # the stages whose units are dispatched to a role (dispatch-prompt --stage)
MAX_PILOT_REPOS = 20
COMMAND_AUDITED = ("start", "pilot", "status", "next", "approve", "audit")      # commands that write a `command` audit event
RESERVED_SWITCHES = ("--carry-stale", "--no-upstream-match", "--sandbox-configure", "--determineversion")
MAX_RESULT_BYTES = 10 * 1024


# --------------------------------------------------------------------------------------------------- arguments

class _Parser(argparse.ArgumentParser):
    """ArgumentParser whose ``error`` raises ``UsageError`` (it never prints and never exits)."""

    def error(self, message: str) -> Any:        # type: ignore[override]
        raise errors.UsageError(message)

    def exit(self, status: int = 0, message: Optional[str] = None) -> Any:     # type: ignore[override]
        raise errors.UsageError(message or "argument parsing stopped")


class _Once(argparse.Action):
    """A switch that may be given only once (a repeat is a usage error); flags take no value."""

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values: Any,
                 option_string: Optional[str] = None) -> None:
        given = getattr(namespace, "_given", None)
        if given is None:
            given = []
            setattr(namespace, "_given", given)
        if self.dest in [name for name, _ in given]:
            parser.error("the switch %s was given more than once" % option_string)
        given.append((self.dest, option_string))
        setattr(namespace, self.dest, True if self.nargs == 0 else values)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="sbom.py", add_help=False, allow_abbrev=False)
    sub = parser.add_subparsers(dest="cmd", parser_class=_Parser)
    sub.required = True
    for name in SUBCOMMANDS:
        sp = sub.add_parser(name, add_help=False, allow_abbrev=False)
        if name == "start":
            sp.add_argument("--abandon", action=_Once, nargs=0, default=False, dest="abandon")
            sp.add_argument("--scope", action=_Once, choices=model.SCOPE_VALUES, default="product", dest="scope")
            for switch in RESERVED_SWITCHES:
                sp.add_argument(switch, action=_Once, nargs=0, default=False, dest=switch.lstrip("-").replace("-", "_"))
        elif name == "pilot":
            sp.add_argument("pilot_repos", nargs="+", metavar="repo")
        elif name == "dispatch-record":
            sp.add_argument("unit")
            sp.add_argument("dispatch_mode", choices=DISPATCH_MODES)
            sp.add_argument("--model", action=_Once, default=None, dest="model")
        elif name == "dispatch-prompt":
            sp.add_argument("unit", nargs="?", default=None)
            sp.add_argument("--stage", action=_Once, choices=STAGES_WITH_ROLE, default=None, dest="stage")
        elif name in ("inline-unit", "check-unit", "reply"):
            sp.add_argument("unit")
    return parser


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse ``argv`` (without the program name). ``UsageError`` for anything unexpected."""
    if any(token == "--" for token in argv):
        # Python 3.13 argparse accepts a leading "--" where 3.9 rejects it; section 5.1 says any extra token is an error
        raise errors.UsageError("the token -- is not accepted")
    args = build_parser().parse_args(list(argv))
    for switch in RESERVED_SWITCHES:
        if getattr(args, switch.lstrip("-").replace("-", "_"), False):
            raise errors.UsageError("the switch %s is not available in this version" % switch)
    args.switches = [option for _, option in getattr(args, "_given", [])]
    return args


# --------------------------------------------------------------------------------------------------- help

#: ``name -> (arguments, what it does)``; the text of ``sbom.py --help`` and ``sbom.py <subcommand> --help``
HELP = {
    "status": ("", "Where the run stands. Never creates a run and never writes."),
    "start": ("[--scope all] [--abandon]", "Create a run, or resume an unfinished one. --scope all also lists test, dev and "
              "build-only dependencies; --abandon drops a pending run."),
    "pilot": ("<repo>...", "A run on the named repositories only (1 to 20 folder names), in sbom-out-pilot/."),
    "next": ("", "One bounded step of work (a minute at most). Prints one JSON object whose next_action says what to do."),
    "approve": ("", "Bind the person's approval of the review file (recorded as agent-relayed)."),
    "summary": ("", "The final text of a finished run, plain text, to be posted unchanged in a fenced block."),
    "explain": ("", "Plain-language state of the run, for a person who asks what is going on."),
    "audit": ("", "Re-check a finished run (read-only)."),
    "selfcheck": ("", "Check the install: Python, git, bundled files."),
    "dispatch-prompt": ("<unit> | --stage worker", "The prompt of one worker unit, or of every waiting worker unit, with every "
                        "placeholder filled."),
    "dispatch-record": ("<unit> <subagent|inline> [--model NAME]", "Record how a unit ran."),
    "inline-unit": ("<unit>", "Inline mode only: write the unit's brief (its paths and the role file) and print its path."),
    "check-unit": ("<unit>", "Step 0 of the worker role: the paths of the unit, and a read-only check of its reply file."),
    "reply": ("<unit>", "The reply of a role without a file tool, on standard input (one JSON object, bare or fenced)."),
    "stage": ("", "Not available in this version."),
    "gate-status": ("", "Not available in this version."),
    "validate": ("", "Not available in this version."),
}


def help_text(topic: Optional[str] = None) -> str:
    """The help for the whole tool, or for one subcommand. Plain text; nothing is read from disk."""
    if topic in HELP:
        arguments, what = HELP[topic]
        return "usage: sbom.py %s%s\n%s\n" % (topic, (" " + arguments) if arguments else "", what)
    lines = ["usage: sbom.py <subcommand> [arguments]", "",
             "Run it from the workspace (the folder whose subfolders are the repositories), as "
             "python3 -I -B <skill folder>/scripts/sbom.py <subcommand>. Every subcommand prints one JSON object, except "
             "summary, explain, dispatch-prompt and inline-unit (plain text). start, pilot, next and approve may end with a "
             "SAY THIS block after the object (the start sentences, the gate text); dispatch-prompt and inline-unit end with one "
             "(the mode line) until the first worker unit is recorded. `sbom.py <subcommand> --help` prints one entry.",
             "", "subcommands:"]
    for name in SUBCOMMANDS:
        if name not in ("stage", "gate-status", "validate"):
            arguments, what = HELP[name]
            lines.append("  %s%s" % (name, (" " + arguments) if arguments else ""))
            lines.append("      %s" % what)
    return "\n".join(lines) + "\n"


def _help_request(argv: Sequence[str]) -> Optional[str]:
    """The help text asked for by ``argv`` (``--help``, ``-h``, ``help [subcommand]``), or None when it is no help request."""
    tokens = list(argv)
    if not tokens:
        return None
    if tokens[0] in ("-h", "--help"):
        return help_text()
    if tokens[0] == "help":
        return help_text(tokens[1] if len(tokens) > 1 else None)
    if tokens[0] in SUBCOMMANDS and any(t in ("-h", "--help") for t in tokens[1:]):
        return help_text(tokens[0])
    return None


# --------------------------------------------------------------------------------------------------- output

def error_result(cmd: Optional[str], code: str, message: str, retryable: bool = False, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ok": False, "cmd": cmd, "next_action": "error",
                              "error": {"code": code, "message": message, "retryable": retryable}, "message": message}
    result.update(extra)
    return result


def _list_paths(node: Any, trail: tuple = ()) -> List[tuple]:
    """Every list inside ``node`` as (size, container, key) for the clipping pass."""
    found: List[tuple] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, list) and value:
                found.append((len(json.dumps(value, ensure_ascii=True)), node, key))
            found.extend(_list_paths(value, trail + (key,)))
    elif isinstance(node, list):
        for item in node:
            found.extend(_list_paths(item, trail))
    return found


def clip_result(result: Dict[str, Any], limit: int = MAX_RESULT_BYTES) -> Dict[str, Any]:
    """Keep the serialized result under ``limit`` bytes: the largest lists are shortened and get a ``truncated``
    sibling holding the number of dropped items."""
    def size() -> int:
        return len(json.dumps(result, ensure_ascii=True).encode("ascii"))

    guard = 0
    while size() > limit and guard < 2000:
        guard += 1
        candidates = _list_paths(result)
        if not candidates:
            break
        _, container, key = max(candidates, key=lambda c: c[0])
        container[key].pop()
        container["truncated"] = int(container.get("truncated", 0)) + 1
    if size() > limit and isinstance(result.get("message"), str):
        result["message"] = result["message"][:max(200, limit // 4)]
        result["truncated_message"] = True
    return result


def _emit(payload: Any) -> None:
    """Print the one result. A closed stdout (the reader went away) is not an error of ours."""
    if isinstance(payload, str):
        text = payload if payload.endswith("\n") else payload + "\n"
    else:
        text = json.dumps(payload, ensure_ascii=True) + "\n"
    try:
        buffer = getattr(sys.stdout, "buffer", None)
        if buffer is not None:
            buffer.write(text.encode("utf-8", "replace"))
            buffer.flush()
        else:
            sys.stdout.write(text)
            sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        pass


# --------------------------------------------------------------------------------------------------- progress / gate

def progress_block(ctx: RunContext, run: state.RunState) -> Optional[Dict[str, Any]]:
    """``{"units_done", "units_total", "repos": {...}}`` from ``driver.plan``; None while ``driver`` is absent."""
    driver = optional_module("driver")
    if driver is None:
        return None
    plan = driver.plan(ctx, run)
    done = sum(1 for unit_id in plan if run.unit_state(unit_id) == "done")
    counts = {status: 0 for status in model.REPO_STATUS}
    for name in run.all_repos():
        status = run.repo(name).get("status", "QUEUED")
        counts[status] = counts.get(status, 0) + 1
    return {"units_done": done, "units_total": len(plan), "repos": counts}


def gate_block(ctx: RunContext, run: state.RunState) -> Dict[str, Any]:
    """The ``gate`` object of a ``stop_for_approval`` result (contract section 5.3)."""
    review = run.data.get("review") or {}
    queue = state.load_queue(ctx)
    approvals = run.data.get("approvals") or []
    return {
        "review_file": review.get("path"),
        "rows": review.get("rows", 0),
        "rows_included": review.get("rows_included", 0),
        "editable_columns": list(model.EDITABLE_COLUMNS),
        "checkout_warnings": list(queue.get("checkout_warnings", []))[:20],
        "repo_status": {name: run.repo(name).get("status") for name in run.all_repos()},
        "ignored_count": len(queue.get("ignored", [])),
        "stale": bool(approvals and approvals[-1].get("stale")),
        "last_refusal": review.get("last_refusal"),
    }


def _gate_message(ctx: RunContext, run: state.RunState, warnings: List[Dict[str, Any]]) -> str:
    report = optional_module("report")
    if report is None:
        warnings.append(model.warning("INFORMATIONAL", "MODULE_MISSING", "module report is not available"))
        return "Waiting at the approval gate."
    return report.gate_message(ctx, run)


# --------------------------------------------------------------------------------------------------- handlers

def cmd_selfcheck(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    """Phase 0 probes; prints the env.json body and writes nothing."""
    env = selfcheck.probe(ctx)
    warnings = list(env.get("warnings", []))
    git = env["git"]
    py = env["python"]
    result: Dict[str, Any] = {"ok": bool(git.get("ok")), "cmd": "selfcheck", "env": env}
    if git.get("ok"):
        interpreter = ("%s (Python %s)" % (py["prefix"], py["version"])) if py.get("version") else \
            "no working Python 3.9+ interpreter found for the prefix %s" % py["prefix"]
        result["message"] = "Environment check passed: git %s, %s." % (git["version"], interpreter)
    else:
        code = "GIT_MISSING" if git.get("version") is None else "GIT_TOO_OLD"
        message = git.get("error") or "git is not usable"
        result["error"] = {"code": code, "message": message, "retryable": False}
        result["message"] = message
    if warnings:
        result["warnings"] = warnings[:10]
    return result


def _warnings_envelope(warnings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ordered = sorted(warnings, key=lambda w: 0 if w.get("tier") == "ACTION_REQUIRED" else 1)
    return ordered[:10]


def _pilot_names(ctx: RunContext, args: argparse.Namespace) -> List[str]:
    """The repositories of a ``pilot`` command: each must be a repository directly inside the workspace."""
    from sbomlib import enumerate as enum
    wanted: List[str] = []
    for name in args.pilot_repos:
        if name not in wanted:
            wanted.append(name)
    if len(wanted) > MAX_PILOT_REPOS:
        raise errors.UsageError("a pilot run takes at most %d repositories" % MAX_PILOT_REPOS)
    available = [e.name for e in enum.scan_parent(ctx.layout) if e.kind == "repo"]
    missing = [name for name in wanted if name not in available]
    if missing:
        listing = ", ".join(available[:20]) + (", ..." if len(available) > 20 else "") if available else "none"
        raise errors.NoSuchRepository(
            "Not a git repository directly inside %s: %s. Repositories there: %s. Nothing was started." % (
                ctx.layout.parent, ", ".join(missing), listing))
    return wanted


def cmd_pilot(ctx: RunContext, args: argparse.Namespace) -> Dict[str, Any]:
    """``pilot <repo>...``: a run limited to the named repositories, in its own output folder (``sbom-out-pilot``) with its
    own baseline, so that a trial never touches the results of a full run."""
    return cmd_start(ctx, args, pilot=_pilot_names(ctx, args))


def _require_repositories(ctx: RunContext) -> None:
    """Refuse (writing nothing) when no git repository sits directly inside the workspace. Read-only: ``scan_parent`` only
    lists the folder and classifies each entry."""
    from sbomlib import enumerate as enum
    if not any(entry.kind == "repo" for entry in enum.scan_parent(ctx.layout)):
        raise errors.NoRepositories(errors.no_repositories_message(ctx.layout.parent))


def cmd_start(ctx: RunContext, args: argparse.Namespace, pilot: Optional[List[str]] = None) -> Dict[str, Any]:
    """Validate layout (done by ``main``) -> ensure_out_tree -> op mutex -> ``lifecycle.start``. A run that begins carries a
    ``say`` list: ``main`` prints it after the JSON as the block the model repeats to the person."""
    from sbomlib import report
    abandon = bool(getattr(args, "abandon", False))
    other = None if abandon else paths.unfinished_elsewhere(ctx.layout.parent, ctx.layout.out_name)
    if other is not None:
        kind = "pilot" if other == PILOT_OUT else "full"
        raise errors.OtherRunInFlight(
            "A %s run is unfinished (%s/). Finish it first: reply \"continue\" and run next. To drop it, run start "
            "--abandon." % (kind, other))
    if not abandon and pilot is None and not paths.has_unfinished_run(ctx.layout.parent, ctx.layout.out_name):
        _require_repositories(ctx)                       # a wrong folder must not leave an output folder and a run behind
    paths.ensure_out_tree(ctx.layout)
    ctx.log = Logger(ctx.layout.state / "sbom.log", ctx.run_id)
    with state.op_mutex(ctx, "start"):
        outcome = lifecycle.start(ctx, scope=getattr(args, "scope", "product"), abandon=abandon, pilot=pilot)
        if outcome.started == "abandoned_only":
            if outcome.moved is not None:
                message = ("Run %s abandoned. Run start again to begin a new run." % (ctx.run_id or "(unknown)"))
            else:
                message = "No unfinished run to abandon."
            result: Dict[str, Any] = {"ok": True, "cmd": "start", "started": "abandoned_only", "next_action": "done",
                                      "message": message}
            if outcome.moved is not None:
                result["moved"] = outcome.moved
            return result
        run = outcome.run
        assert run is not None
        ctx.run_id = run.run_id
        ctx.log.run_id = run.run_id
        warnings = list(outcome.warnings)
        cmd = "pilot" if pilot else "start"
        result = {"ok": True, "cmd": cmd, "run_id": run.run_id, "phase": run.phase, "started": outcome.started,
                  "mode": run.data.get("mode", "full")}
        if run.data.get("mode") == "pilot":
            result["pilot_repos"] = list(run.data.get("pilot_repos") or [])
        baseline = run.data.get("baseline") or {}
        result["baseline"] = {"present": bool(baseline.get("present")), "run_id": baseline.get("run_id")}
        if outcome.moved is not None:
            result["moved"] = outcome.moved
        if outcome.started == "resumed" and run.gate == "awaiting_approval":
            result["next_action"] = "stop_for_approval"
            result["gate"] = gate_block(ctx, run)
            result["message"] = _gate_message(ctx, run, warnings)
        elif outcome.started == "resumed":
            result["next_action"] = "run_again"
            result["message"] = "Run %s resumed. Run next." % run.run_id
        else:
            result["next_action"] = "run_again"
            result["message"] = ("Pilot run %s started. Run next." if run.data.get("mode") == "pilot"
                                 else "Run %s started. Run next.") % run.run_id
            say = list(report.START_SAY)
            if run.data.get("mode") == "pilot":
                say.insert(0, "This is a pilot run on the named repositories only; its results are kept apart from any full run.")
            result["say"] = say
        try:
            result["progress"] = progress_block(ctx, run)
        except Exception:                      # the run exists already; a planning problem must not hide that
            ctx.log.exception("cli.progress_failed")
            result["progress"] = None
        if warnings:
            result["warnings"] = _warnings_envelope(warnings)
        run.data["last_result"] = {"cmd": cmd, "next_action": result["next_action"], "message": result["message"],
                                   "at": ctx.now_iso()}
        run.save(ctx)
        ctx.command_info["driver"] = "none"
        return result


def _not_implemented(cmd: str, what: str) -> Dict[str, Any]:
    return error_result(cmd, "NOT_IMPLEMENTED", "The %s subcommand is not implemented in this build (%s)." % (cmd, what))


def dispatch(ctx: RunContext, args: argparse.Namespace) -> Any:
    cmd = args.cmd
    if cmd == "selfcheck":
        return cmd_selfcheck(ctx, args)
    if cmd == "start":
        return cmd_start(ctx, args)
    if cmd == "pilot":
        return cmd_pilot(ctx, args)
    commands = optional_module("commands")     # WP-integration; imported here, never at module level
    if commands is None:
        return _not_implemented(cmd, "module sbomlib.commands is missing")
    handler = getattr(commands, "cmd_" + cmd.replace("-", "_"), None)
    if handler is None:
        return _not_implemented(cmd, "no handler cmd_%s" % cmd.replace("-", "_"))
    return handler(ctx, args)


# --------------------------------------------------------------------------------------------------- main

def choose_out_name(cwd: Path, args: argparse.Namespace) -> Optional[str]:
    """The output folder a command works in: ``sbom-out-pilot`` for ``pilot``, ``sbom-out`` for ``start`` and ``selfcheck``,
    and for every other command (and for ``start --abandon``) the folder of the active run (``paths.pick_out_name``)."""
    if args.cmd == "pilot":
        return PILOT_OUT
    if args.cmd == "selfcheck" or (args.cmd == "start" and not args.abandon):
        return FULL_OUT
    try:
        return paths.pick_out_name(Path(cwd).resolve())
    except (OSError, RuntimeError):
        return None


def _bind_run(ctx: RunContext) -> None:
    """Copy run id, scope and the recorded interpreter prefix into the context when a run exists."""
    run_path = ctx.layout.state / "run.json"
    if not os.path.isfile(str(run_path)):
        return
    try:
        data = fsio.read_json(run_path)
    except (errors.StateError, OSError):
        return
    if isinstance(data, dict):
        ctx.run_id = data.get("run_id")
        ctx.scope = data.get("scope", "product")
        ctx.log.run_id = ctx.run_id
    try:
        env = fsio.read_json(ctx.layout.state / "env.json") if os.path.isfile(str(ctx.layout.state / "env.json")) else {}
        prefix = (env.get("python") or {}).get("prefix")
        if prefix:
            ctx.python_prefix = prefix
    except (errors.StateError, OSError, AttributeError):
        pass


def _write_command_event(ctx: RunContext, args: argparse.Namespace, result: Any, exit_code: int) -> None:
    """The ``command`` audit event (contract section 4.3) for the commands that write one, once a run exists."""
    if args.cmd not in COMMAND_AUDITED or ctx.command_info.get("audited"):
        return
    if not os.path.isfile(str(ctx.layout.state / "run.json")):
        return
    try:
        run = state.load_run(ctx)
    except errors.StateError:
        return
    if run is None:
        return
    ctx.run_id = run.run_id
    event = {"event": "command", "cmd": args.cmd, "switches": list(getattr(args, "switches", [])), "tty": ctx.tty,
             "exit": exit_code, "next_action": result.get("next_action") if isinstance(result, dict) else None,
             "units": list(ctx.command_info.get("units", [])), "driver": ctx.command_info.get("driver")}
    state.audit_event(ctx, event)


def main(argv: Sequence[str], *, script_file: Path, overrides: Optional[Dict[str, Any]] = None) -> int:
    """Entry point. Returns the exit code of contract section 5.10 (0 whenever a result object was printed)."""
    try:
        return _main(argv, script_file=script_file, overrides=overrides)
    except Exception as exc:                                        # nothing may escape without a JSON answer
        message = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        _emit(error_result(None, "INTERNAL", message))
        return 1


def _main(argv: Sequence[str], *, script_file: Path, overrides: Optional[Dict[str, Any]]) -> int:
    overrides = dict(overrides or {})
    asked = _help_request(argv)
    if asked is not None:
        _emit(asked)
        return 0
    try:
        args = parse_args(argv)
    except errors.UsageError as exc:
        first = next((t for t in argv if not t.startswith("-")), None)
        _emit(error_result(first if first in SUBCOMMANDS else None, "USAGE", exc.message))
        return 2
    try:
        cwd = Path(os.getcwd())
    except OSError as exc:
        _emit(error_result(args.cmd, "UNSAFE_LAYOUT", "cannot determine the working directory: %s" % exc))
        return 3
    try:
        layout = paths.resolve_layout(Path(script_file), cwd, choose_out_name(cwd, args))
    except errors.LayoutError as exc:
        _emit(error_result(args.cmd, exc.code, exc.message))
        return 3
    ctx = make_context(layout, overrides=overrides)
    _bind_run(ctx)
    exit_code = 0
    result: Any = None
    try:
        result = dispatch(ctx, args)
    except errors.UsageError as exc:
        result, exit_code = error_result(args.cmd, exc.code, exc.message), 2
    except errors.LayoutError as exc:
        result, exit_code = error_result(args.cmd, exc.code, exc.message), 3
    except errors.SbomError as exc:
        ctx.log.error("cli.command_failed", cmd=args.cmd, code=exc.code, message=exc.message[:300])
        result = error_result(args.cmd, exc.code, exc.message, exc.retryable)
        if ctx.run_id:
            result["run_id"] = ctx.run_id
    except Exception as exc:                                        # unexpected: print a JSON INTERNAL error, exit 1
        ctx.log.exception("cli.unexpected", cmd=args.cmd)
        message = "%s: %s" % (type(exc).__name__, str(exc)[:200])
        result, exit_code = error_result(args.cmd, "INTERNAL", message), 1
    said: Optional[str] = None
    if isinstance(result, dict):
        lines = result.pop("say", None)
        if lines:
            from sbomlib import report
            said = report.say_block("NOW, once, in your first message of this run", lines)
        elif result.get("next_action") == "stop_for_approval" and result.get("message"):
            # the gate: the text to post is the last thing printed, between two lines that say so, as the other skills print it;
            # the JSON keeps the same text in `message`
            from sbomlib import report
            said = report.say_text("in your reply now, in a fenced block, first; then end your turn and run nothing else",
                                   str(result["message"]))
        try:
            _write_command_event(ctx, args, result, exit_code)
        except Exception:                                           # the audit trail must never hide the result
            ctx.log.exception("cli.audit_failed", cmd=args.cmd)
        result = clip_result(result)
    _emit(result)
    if said:
        _emit(said)                                                 # the last thing printed: where the model's next message starts
    return exit_code
