"""Run lifecycle: ``start``, resume, history/abandoned moves (contract sections 3.4 and 5.3).

Nothing is ever deleted except the scratch directory ``.tmp``; old runs are moved to ``history/<UTC>/`` or
``abandoned/<UTC>/``. ``start`` is called with the op mutex held and the output tree created (``cli_core.cmd_start``).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from sbomlib import errors, fsio, gitro, model, pack, paths, selfcheck, state
from sbomlib.context import RunContext, iso_z, optional_module
from sbomlib.state import RunState

RUN_FILES_STATE = ("run.json", "lock", "env.json", "pack.json", "queue.json", "audit.jsonl", "sbom.log", "names_rows.json",
                   "approval.json", "cpe_progress.json", "validation.json",
                   "runfiles.json")                                            # plus approved-names-*.csv, integrity-*.json
RUN_FILES_OUT = ("repos", "review", "merged-sbom.csv", "cpe_resolution.csv", "report.md", "validation-report.txt")
# Never moved: .state/human-input.jsonl, .state/guard-calls.jsonl, .state/hook-errors.log (written only by a hook, which a
# plain skill install does not have; a workspace shared with the hardened variant may still hold them),
# local-cpe-decisions.csv, .cache/, history/, abandoned/; .tmp/ is emptied. .staging/<run_id>/ moves with the run.
PERSISTENT_STATE = ("human-input.jsonl", "guard-calls.jsonl", "hook-errors.log")
MUTEX_FILE = "op.lock"
ARCHIVE_INFO = "archive.json"

REASON_HISTORY = "completed run with audit=pass"
REASON_AUDIT_FAIL = "completed run with audit=fail"
REASON_HEADS = "unfinished run whose repository HEADs changed before the gate"
REASON_ABANDON = "abandoned with start --abandon"
REASON_LEFTOVER = "leftover files of an interrupted run"


@dataclass
class StartOutcome:
    started: str                         # "new" | "resumed" | "abandoned_only"
    run: Optional[RunState]
    moved: Optional[Dict[str, str]]      # {"to": rel path, "reason": "..."}
    warnings: List[Dict[str, Any]]


def heads_changed_before_gate(ctx: RunContext, run: RunState) -> bool:
    """True when ``integrity-gate.json`` does not exist yet and a recorded HEAD differs from the current one.

    A repository that can no longer be read counts as changed (the old run is only moved, never deleted).
    """
    if os.path.lexists(str(ctx.layout.state / "integrity-gate.json")):
        return False
    try:
        queue = state.load_queue(ctx)
    except errors.StateError:
        return False
    queue_heads = {entry.get("name"): entry.get("head") for entry in queue.get("repos", [])}
    for name, entry in run.data.get("repos", {}).items():
        recorded = entry.get("head") or queue_heads.get(name)
        if not recorded:
            continue
        if entry.get("status") == "NOT ANALYZED":
            continue
        try:
            current = gitro.rev_parse_head(ctx.layout.parent / name, layout=ctx.layout, env=ctx.env,
                                           timeout=gitro.budget_timeout(ctx))
        except (errors.SbomError, OSError):
            return True
        if current != recorded:
            return True
    return False


def decide_existing(ctx: RunContext, run: Optional[RunState]) -> str:
    """``none`` | ``resume`` | ``history`` (completed, audit=pass) | ``abandon_fail`` (completed, audit=fail) |
    ``abandon_heads`` (unfinished, HEADs changed before the gate) | ``abandon_closed`` (unfinished although the close
    time is stamped: an abandon died after ``_close_run`` and before ``run.json`` moved, so the move is repeated)."""
    if run is None:
        return "none"
    if run.completed:
        return "history" if run.audit == "pass" else "abandon_fail"
    if heads_changed_before_gate(ctx, run):
        return "abandon_heads"
    if run.data.get("closed_at_ns") is not None:
        return "abandon_closed"
    return "resume"


def _utc_dirname(ctx: RunContext) -> str:
    return iso_z(ctx.clock.now_utc()).replace("-", "").replace(":", "")


def _unique_dir(base: Path, name: str) -> Path:
    candidate = base / name
    number = 1
    while os.path.lexists(str(candidate)):
        number += 1
        candidate = base / ("%s-%d" % (name, number))
    return candidate


def _state_entries_to_move(ctx: RunContext) -> List[str]:
    """Names in ``.state`` that belong to a run (everything but the persistent files, the mutex and stray temp files);
    ``run.json`` comes last."""
    try:
        listing = sorted(os.listdir(str(ctx.layout.state)))
    except OSError:
        return []
    names = [n for n in listing
             if n not in PERSISTENT_STATE and n != MUTEX_FILE and not (n.startswith(".") and n.endswith(".tmp"))
             and not (n.startswith("." + MUTEX_FILE + ".") and n.endswith(".stale"))]
    if "run.json" in names:
        names.remove("run.json")
        names.append("run.json")
    return names


def _present(path: Path) -> bool:
    """True for a file, a symlink or a non-empty directory (the empty directories of the output tree are not run files)."""
    if not os.path.lexists(str(path)):
        return False
    if os.path.isdir(str(path)) and not os.path.islink(str(path)):
        try:
            return bool(os.listdir(str(path)))
        except OSError:
            return True
    return True


def _out_entries_to_move(ctx: RunContext, run_id: Optional[str]) -> List[Path]:
    moves: List[Path] = []
    for name in RUN_FILES_OUT:
        path = ctx.layout.out / name
        if _present(path):
            moves.append(path)
    if run_id:
        staged = ctx.layout.staging(run_id)
        if _present(staged):
            moves.append(staged)
    return moves


def has_leftovers(ctx: RunContext) -> bool:
    """Run files that exist although there is no usable ``run.json`` (an interrupted ``start`` or archive move)."""
    significant = [n for n in _state_entries_to_move(ctx) if n != "sbom.log"]
    return bool(significant) or bool(_out_entries_to_move(ctx, None))


def _empty_tmp(ctx: RunContext) -> None:
    tmp = ctx.layout.tmp
    if not os.path.isdir(str(tmp)) or os.path.islink(str(tmp)):
        return
    for name in os.listdir(str(tmp)):
        try:
            if os.path.islink(str(tmp / name)):
                os.unlink(str(tmp / name))                    # a link is removed itself, never followed
            else:
                fsio.remove_tree(tmp / name, root=ctx.layout.out)
        except (OSError, errors.SbomError):
            ctx.log.warning("lifecycle.tmp_clean_failed", name=name)


def archive_run(ctx: RunContext, run: Optional[RunState], kind: str, reason: str, *, event: Optional[str] = None) -> Path:
    """Move the run's files to ``out/<kind>/<UTC>[-n]/`` (``kind`` is ``history`` or ``abandoned``).

    The directory mirrors the layout of ``sbom-out`` (``.state/`` for the state files). ``run.json`` moves last so an
    interrupted move is repeated by the next ``start``. The persistent files, ``.cache``, ``history``, ``abandoned``
    and ``local-cpe-decisions.csv`` stay where they are; ``.tmp`` is emptied. ``event`` names an audit event (for example
    ``abandon``) that is written, with the destination in ``to``, to the audit log that moves with the run.
    """
    if kind not in ("history", "abandoned", "previous"):
        raise ValueError("kind must be history, abandoned or previous")
    base = ctx.layout.history if kind == "history" else ctx.layout.abandoned
    run_id = run.run_id if run is not None else None
    state_moves = [ctx.layout.state / name for name in _state_entries_to_move(ctx)]
    out_moves = _out_entries_to_move(ctx, run_id)
    for source in state_moves + out_moves:           # refuse symlinks and escapes before anything is moved
        paths.assert_under(source, ctx.layout.out)
    if kind == "previous":
        dest = ctx.layout.previous
        assert dest is not None
        paths.assert_under(dest, ctx.layout.out)
        if os.path.lexists(str(dest)):
            raise errors.StateError("previous/ is not empty; rotate_previous must move it away first")
    else:
        fsio.ensure_dir(base, root=ctx.layout.out)
        dest = _unique_dir(base, _utc_dirname(ctx))
    fsio.ensure_dir(dest, root=ctx.layout.out)
    info = {"schema": 1, "kind": kind, "reason": reason, "run_id": run_id,
            "moved_at": ctx.now_iso(), "moved_at_ns": ctx.clock.wall_ns(),
            "completed": bool(run and run.completed), "audit": run.audit if run else None,
            "closed_at": run.data.get("closed_at") if run else None,
            "closed_at_ns": run.data.get("closed_at_ns") if run else None,
            "mode": run.data.get("mode", "full") if run else None,
            "commits": {name: run.repo(name).get("head") for name in run.all_repos()} if run else {}}
    fsio.atomic_write_json(dest / ARCHIVE_INFO, info, root=ctx.layout.out)
    state_dest = dest / ".state"
    fsio.ensure_dir(state_dest, root=ctx.layout.out)
    if event is not None:
        state.audit_event(ctx, {"event": event, "to": ctx.layout.rel(dest), "reason": reason})
        if (ctx.layout.state / "audit.jsonl") not in state_moves and os.path.lexists(str(ctx.layout.state / "audit.jsonl")):
            state_moves.insert(0, ctx.layout.state / "audit.jsonl")
    for source in state_moves:
        fsio.move_into(source, state_dest, root=ctx.layout.out)
    for path in out_moves:
        target_dir = dest / ".staging" if path.parent == ctx.layout.staging_root else dest
        fsio.move_into(path, target_dir, root=ctx.layout.out)
    _empty_tmp(ctx)
    for name in ("repos", "review"):
        fsio.ensure_dir(ctx.layout.out / name, root=ctx.layout.out)
    return dest


def newest_closed_at_ns(ctx: RunContext) -> int:
    """Largest ``closed_at_ns`` recorded in ``previous/``, ``history/`` and ``abandoned/`` (0 when there is none)."""
    best = 0
    for base in (ctx.layout.history, ctx.layout.abandoned):
        if not os.path.isdir(str(base)):
            continue
        for name in os.listdir(str(base)):
            best = max(best, _closed_at_ns(base / name / ARCHIVE_INFO))
    if ctx.layout.previous is not None:
        best = max(best, _closed_at_ns(ctx.layout.previous / ARCHIVE_INFO))
    return best


def _closed_at_ns(info_path: Path) -> int:
    try:
        info = fsio.read_json(info_path)
    except (errors.StateError, OSError):
        return 0
    value = info.get("closed_at_ns") if isinstance(info, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def rotate_previous(ctx: RunContext) -> Optional[str]:
    """Move an existing baseline ``previous/`` to ``history/<UTC>/`` so that the run that has just finished can take its
    place. Nothing is overwritten or deleted. Returns the ``history`` entry (sbom-out relative) or None when there was no
    baseline. The folder keeps the UTC stamp of the moment it became the baseline."""
    previous = ctx.layout.previous
    if previous is None or not os.path.lexists(str(previous)):
        return None
    paths.assert_under(previous, ctx.layout.out)
    stamp = None
    try:
        info = fsio.read_json(previous / ARCHIVE_INFO)
        moved = info.get("moved_at") if isinstance(info, dict) else None
        if isinstance(moved, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", moved):
            stamp = moved.replace("-", "").replace(":", "")
    except (errors.StateError, OSError):
        stamp = None
    fsio.ensure_dir(ctx.layout.history, root=ctx.layout.out)
    dest = _unique_dir(ctx.layout.history, stamp or _utc_dirname(ctx))
    fsio.rename_file(previous, dest, root=ctx.layout.out)
    return ctx.layout.out_rel(dest)


def _close_run(ctx: RunContext, run: RunState) -> None:
    """Stamp ``closed_at``/``closed_at_ns`` on an unfinished run before it is moved (the run is abandoned)."""
    if run.data.get("closed_at_ns") is None:
        run.data["closed_at"] = ctx.now_iso()
        run.data["closed_at_ns"] = ctx.clock.wall_ns()
        run.save(ctx)


def _guard_block(ctx: RunContext, since_ns: int, warnings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """``run.json.guard``: what the hooks of the hardened variant would have recorded. A plain skill install has no hook,
    so ``guardlib`` answers ``guard_active = "false"`` and no hook fired without reading any log (``HOOKS_SHIPPED``)."""
    block = {"guard_active": "false", "hooks_fired": {"prompt": False, "pretooluse": False},
             "agent_profile": "unknown", "checked_at": ctx.now_iso()}
    guardlib = optional_module("guardlib")
    if guardlib is None:
        warnings.append(model.warning("INFORMATIONAL", "MODULE_MISSING",
                                      "module guardlib is not available; guard status is unknown"))
        block["guard_active"] = "unknown"
    else:
        try:
            block["guard_active"] = guardlib.guard_active(ctx, "start", since_ns)
            fired = guardlib.hooks_fired(ctx, since_ns)
            block["hooks_fired"] = {"prompt": bool(fired.get("prompt")), "pretooluse": bool(fired.get("pretooluse"))}
        except Exception as exc:     # a broken guard module must not stop `start`
            ctx.log.error("lifecycle.guard_probe_failed", error="%s: %s" % (type(exc).__name__, str(exc)[:200]))
        if getattr(guardlib, "HOOKS_SHIPPED", False):
            humaninput = optional_module("humaninput")
            if humaninput is not None:
                try:
                    block["agent_profile"] = humaninput.latest_agent_profile(ctx, since_ns)
                except Exception as exc:
                    ctx.log.error("lifecycle.agent_profile_failed", error="%s: %s" % (type(exc).__name__, str(exc)[:200]))
    return block


def refresh_guard(ctx: RunContext, run: RunState, warnings: List[Dict[str, Any]]) -> None:
    """Recompute ``run.json.guard`` (contract section 4.1: written by ``start``, ``next`` and ``status``).

    A terminal command is never logged by the hooks, so when ``ctx.tty`` makes the answer ``unknown`` a previously
    recorded ``true``/``false`` is kept.
    """
    previous = run.data.get("guard") or {}
    block = _guard_block(ctx, int(run.data.get("strict_since_ns") or 0), warnings)
    if ctx.tty and block["guard_active"] == "unknown" and previous.get("guard_active") in ("true", "false"):
        block["guard_active"] = previous["guard_active"]
    run.data["guard"] = block


def _fail_fast(env: Dict[str, Any]) -> None:
    git = env.get("git", {})
    if git.get("ok"):
        return
    if git.get("version") is None:
        raise errors.GitMissing(git.get("error") or "git was not found on PATH")
    raise errors.GitTooOld(git.get("error") or "git is older than 2.25")


def start(ctx: RunContext, *, scope: str, abandon: bool, pilot: Optional[List[str]] = None) -> StartOutcome:
    """The ``start`` subcommand (contract section 5.3). The op mutex is held and ``ensure_out_tree`` has run.

    ``pilot`` (the ``pilot`` subcommand) names the repositories of a pilot run; the run then lives in ``sbom-out-pilot`` and
    looks at those repositories only."""
    if scope not in model.SCOPE_VALUES:
        raise ValueError("unknown scope: %r" % (scope,))
    try:
        run = state.load_run(ctx)
    except errors.StateError:
        if not abandon:
            raise
        run = None                       # a corrupt run.json must not block the terminal escape hatch
    warnings: List[Dict[str, Any]] = []

    if abandon:
        if run is None and not has_leftovers(ctx):
            return StartOutcome("abandoned_only", None, None, warnings)
        if run is not None and run.completed:
            return StartOutcome("abandoned_only", None, None, warnings)      # nothing unfinished to abandon
        ctx.run_id = run.run_id if run else None
        if run is not None:
            _close_run(ctx, run)
        reason = REASON_ABANDON if run is not None else REASON_LEFTOVER
        dest = archive_run(ctx, run, "abandoned", reason, event="abandon")
        return StartOutcome("abandoned_only", None, {"to": ctx.layout.rel(dest), "reason": reason}, warnings)

    decision = decide_existing(ctx, run)
    if decision == "resume":
        assert run is not None
        ctx.run_id = run.run_id
        ctx.scope = run.data.get("scope", "product")
        if state.read_lock(ctx) is None:
            state.create_lock(ctx, run.run_id)
        refresh_guard(ctx, run, warnings)
        run.save(ctx)
        return StartOutcome("resumed", run, None, warnings)

    env = selfcheck.probe(ctx)
    _fail_fast(env)                                  # nothing has been moved yet
    moved: Optional[Dict[str, str]] = None
    previous_closed_ns = 0
    old_id: Optional[str] = None
    if run is not None:
        old_id = run.run_id
        kind, reason = {"history": ("previous", REASON_HISTORY), "abandon_fail": ("abandoned", REASON_AUDIT_FAIL),
                        "abandon_heads": ("abandoned", REASON_HEADS),
                        "abandon_closed": ("abandoned", REASON_ABANDON)}[decision]
        if decision == "abandon_heads":
            _close_run(ctx, run)
        previous_closed_ns = int(run.data.get("closed_at_ns") or 0)
        rotated = rotate_previous(ctx) if kind == "previous" else None     # the older baseline goes to history/
        dest = archive_run(ctx, run, kind, reason)
        moved = {"to": ctx.layout.rel(dest), "reason": reason}
        if rotated:
            moved["older_baseline_to"] = ctx.layout.rel(ctx.layout.out / rotated)
    elif has_leftovers(ctx):
        dest = archive_run(ctx, None, "abandoned", REASON_LEFTOVER)
        moved = {"to": ctx.layout.rel(dest), "reason": REASON_LEFTOVER}

    strict_since_ns = max(previous_closed_ns, newest_closed_at_ns(ctx))
    run_id = state.new_run_id(ctx.clock)
    ctx.run_id = run_id
    ctx.scope = scope
    ctx.log.run_id = run_id
    py = env.get("python", {})
    if py.get("prefix"):
        ctx.python_prefix = py["prefix"]
    fsio.remove_file(ctx.layout.state / "validation.json", root=ctx.layout.out)
    fsio.atomic_write_json(ctx.layout.state / "env.json", env, root=ctx.layout.out)
    state.create_lock(ctx, run_id)
    integrity = optional_module("integrity")
    if integrity is None:
        warnings.append(model.warning("INFORMATIONAL", "MODULE_MISSING",
                                      "module integrity is not available; the init snapshot was skipped"))
    else:
        try:
            integrity.snapshot(ctx, "init")
        except FileExistsError:
            pass
        except BaseException:
            state.release_lock(ctx)
            raise
    new = state.new_run(ctx, run_id=run_id, scope=scope, strict_since_ns=strict_since_ns, env=env)
    new.data["mode"] = "pilot" if pilot else "full"
    new.data["pilot_repos"] = list(pilot or [])
    from sbomlib import baseline
    new.data["baseline"] = baseline.describe(ctx)
    new.data["guard"] = _guard_block(ctx, strict_since_ns, warnings)
    # the baseline of the unchanged-pack check (the audit compares the skill folder with this manifest)
    manifest = pack.manifest(ctx.layout.skill)
    try:
        fsio.write_once_json(ctx.layout.state / "pack.json", manifest, root=ctx.layout.out)
    except FileExistsError:
        pass
    new.data["pack"] = {"version": ctx.version(), "digest": manifest["digest"], "files": manifest["count"]}
    env_warnings = list(env.get("warnings", []))
    new.add_warnings(env_warnings + warnings)
    new.save(ctx)
    if moved is not None:
        state.audit_event(ctx, {"event": "moved_run", "from_run": old_id, "to": moved["to"], "reason": moved["reason"]})
    return StartOutcome("new", new, moved, env_warnings + warnings)
