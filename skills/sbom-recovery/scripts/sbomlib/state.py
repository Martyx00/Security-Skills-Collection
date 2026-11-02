"""Run state: run.json, queue.json, the run lock with driver and heartbeat, the op mutex, the audit log
(contract sections 3.4, 4.1-4.3, 5.11).

``run.json`` is written only by the driver/commands (WP-integration), ``lifecycle.start`` (WP-core) and the approval
module (WP-security), always under the op mutex.
"""
from __future__ import annotations

import errno
import json
import os
import platform
import re
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from sbomlib import errors, fsio, model, norm
from sbomlib.context import Clock, RunContext, iso_z

SCHEMA = 1
TAKEOVER_AGE_S = 270             # 3 x 90 s (driver takeover, contract section 5.11)
OP_MUTEX_STALE_S = 600

_RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")


def _host() -> str:
    return platform.node() or "unknown"


def run_json_path(ctx: RunContext) -> Path:
    return ctx.layout.state / "run.json"


# --------------------------------------------------------------------------------------------------- run state

def new_repo_entry() -> Dict[str, Any]:
    """The run.json entry of a freshly enumerated repository (status QUEUED, every phase pending)."""
    return {"status": "QUEUED", "reason": None, "head": None,
            "phases": {phase: "pending" for phase in model.REPO_PHASES},
            "incomplete": [], "outputs": {}, "emit_errors": []}


class RunState:
    """Wrapper over the exact content of ``.state/run.json`` (contract section 4.1)."""

    def __init__(self, path: Path, data: Dict[str, Any]) -> None:
        self.path = Path(path)
        self.data = data

    # read-only properties over data
    @property
    def run_id(self) -> str:
        return self.data["run_id"]

    @property
    def phase(self) -> str:
        return self.data["phase"]

    @property
    def gate(self) -> str:
        return self.data["gate"]

    @property
    def completed(self) -> bool:
        return bool(self.data.get("completed"))

    @property
    def audit(self) -> Optional[str]:
        return self.data.get("audit")

    # repositories
    def _repos(self) -> Dict[str, Any]:
        repos = self.data.setdefault("repos", {})
        return repos

    def all_repos(self) -> List[str]:
        """Every enumerated git repository in queue order (NFC name, then exact spelling)."""
        return sorted(self._repos(), key=norm.repo_sort_key)

    def active_repos(self) -> List[str]:
        """``all_repos`` without FAILED and NOT ANALYZED repositories."""
        return [name for name in self.all_repos() if self._repos()[name].get("status") not in ("FAILED", "NOT ANALYZED")]

    def ensure_repo(self, name: str) -> Dict[str, Any]:
        """Create the entry of a newly enumerated repository when missing; returns it."""
        repos = self._repos()
        if name not in repos:
            repos[name] = new_repo_entry()
        return repos[name]

    def repo(self, name: str) -> Dict[str, Any]:
        try:
            return self._repos()[name]
        except KeyError:
            raise errors.StateError("run.json has no repository %r" % (name,), repo=name) from None

    def set_repo_status(self, name: str, status: str, reason: Optional[str] = None) -> None:
        if status not in model.REPO_STATUS:
            raise ValueError("unknown repository status: %r" % (status,))
        entry = self.repo(name)
        entry["status"] = status
        entry["reason"] = reason

    def repo_phase(self, name: str, phase: str) -> str:
        return self.repo(name).get("phases", {}).get(phase, "pending")

    def set_repo_phase(self, name: str, phase: str, value: str) -> None:
        if phase not in model.REPO_PHASES:
            raise ValueError("unknown repository phase: %r" % (phase,))
        if value not in model.REPO_PHASE_VALUES:
            raise ValueError("unknown repository phase value: %r" % (value,))
        self.repo(name).setdefault("phases", {})[phase] = value

    # units
    def unit(self, unit_id: str) -> Dict[str, Any]:
        """The unit record, ``{}`` when absent."""
        return self.data.get("units", {}).get(unit_id, {})

    def unit_state(self, unit_id: str) -> str:
        return self.unit(unit_id).get("state", "pending")

    def mark_unit(self, unit_id: str, state: str, **fields: Any) -> None:
        """Record a unit. ``attempts`` grows by one unless ``state`` is ``pending`` (or ``attempts=`` is passed)."""
        if state not in model.UNIT_STATES:
            raise ValueError("unknown unit state: %r" % (state,))
        units = self.data.setdefault("units", {})
        entry = units.setdefault(unit_id, {})
        entry.setdefault("attempts", 0)
        entry.setdefault("finished_at", None)
        entry.setdefault("outputs", {})
        entry.setdefault("error", None)
        entry["state"] = state
        if state != "pending" and "attempts" not in fields:
            entry["attempts"] = entry["attempts"] + 1
        for key, value in fields.items():
            entry[key] = value

    def clear_units(self, prefixes: Sequence[str]) -> None:
        units = self.data.setdefault("units", {})
        for unit_id in [u for u in units if any(u.startswith(p) for p in prefixes)]:
            del units[unit_id]

    def set_stage(self, stage: str, value: str) -> None:
        if stage not in model.STAGES:
            raise ValueError("unknown stage: %r" % (stage,))
        if value not in model.STAGE_VALUES:
            raise ValueError("unknown stage value: %r" % (value,))
        self.data.setdefault("stages", {})[stage] = value

    def add_warnings(self, warnings: Sequence[Dict[str, Any]]) -> None:
        """Append warnings, deduplicated by (code, repo, message)."""
        known = self.data.setdefault("warnings", [])
        seen = {(w.get("code"), w.get("repo"), w.get("message")) for w in known}
        for warning in warnings:
            key = (warning.get("code"), warning.get("repo"), warning.get("message"))
            if key not in seen:
                seen.add(key)
                known.append(warning)

    def save(self, ctx: RunContext) -> None:
        fsio.atomic_write_json(ctx.layout.state / "run.json", self.data, root=ctx.layout.out)
        self.path = ctx.layout.state / "run.json"


def new_run_id(clock: Clock, rand_hex: Optional[str] = None) -> str:
    """``YYYYMMDDThhmmssZ-<6 hex>``."""
    if rand_hex is None:
        rand_hex = secrets.token_hex(3)
    elif not re.fullmatch(r"[0-9a-f]{6}", rand_hex):
        raise ValueError("rand_hex must be six lowercase hex characters")
    stamp = iso_z(clock.now_utc()).replace("-", "").replace(":", "")
    return "%s-%s" % (stamp, rand_hex)


def new_run(ctx: RunContext, *, run_id: str, scope: str, strict_since_ns: int, env: Dict[str, Any]) -> RunState:
    """A fresh run (contract section 4.1) at phase ``enumerate``; not saved."""
    if scope not in model.SCOPE_VALUES:
        raise ValueError("unknown scope: %r" % (scope,))
    now = ctx.now_iso()
    data: Dict[str, Any] = {
        "schema": SCHEMA,
        "run_id": run_id,
        "created_at": now,
        "pack": {"version": ctx.version(), "digest": None, "files": 0},
        "runfiles": {"schema": 1},
        "scope": scope,
        "phase": "enumerate",
        "gate": "none",
        "stages": {stage: "pending" for stage in model.STAGES},
        "completed": False,
        "audit": None,
        "closed_at": None,
        "closed_at_ns": None,
        "strict_since_ns": int(strict_since_ns),
        "repos": {},
        "units": {},
        "adjudication": {},
        "dispatch": {},
        "review": {"path": None, "sha256": None, "rows": 0, "rows_included": 0, "names_written_at": None,
                   "names_written_at_ns": None, "last_refusal": None},
        "approvals": [],
        "nvd": {"source": None, "status": None},
        "guard": {"guard_active": "unknown", "hooks_fired": {"prompt": False, "pretooluse": False},
                  "agent_profile": "unknown", "checked_at": None},
        "analysis_mode": env.get("analysis_mode", "static") if isinstance(env, dict) else "static",
        "analysis_mode_reason": (env.get("analysis_mode_reason", model.ANALYSIS_MODE_REASON)
                                 if isinstance(env, dict) else model.ANALYSIS_MODE_REASON),
        "outputs": {},
        "last_result": None,
        "warnings": [],
    }
    return RunState(ctx.layout.state / "run.json", data)


def load_run(ctx: RunContext) -> Optional[RunState]:
    """The current run, None when ``run.json`` is absent, ``StateError`` when it is corrupt."""
    path = ctx.layout.state / "run.json"
    if not os.path.lexists(str(path)):
        return None
    data = fsio.read_json(path)
    if not isinstance(data, dict) or "run_id" not in data:
        raise errors.StateError(".state/run.json is not a run record", path=str(path))
    if data.get("schema") != SCHEMA:
        raise errors.StateError(".state/run.json has unsupported schema %r" % (data.get("schema"),), path=str(path))
    for key in ("phase", "gate", "repos", "units"):
        if key not in data:
            raise errors.StateError(".state/run.json lacks %r" % key, path=str(path))
    return RunState(path, data)


def empty_queue(run_id: Optional[str] = None) -> Dict[str, Any]:
    return {"schema": SCHEMA, "run_id": run_id, "repos": [], "skipped": [], "checkout_warnings": [], "ignored": []}


def load_queue(ctx: RunContext) -> Dict[str, Any]:
    """``.state/queue.json``; before ``enumerate:scan`` has run an empty skeleton is returned."""
    path = ctx.layout.state / "queue.json"
    if not os.path.lexists(str(path)):
        return empty_queue(ctx.run_id)
    data = fsio.read_json(path)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("repos"), list):
        raise errors.StateError(".state/queue.json is not a valid queue", path=str(path))
    return data


def save_queue(ctx: RunContext, queue: Dict[str, Any]) -> str:
    """Atomic write; returns the sha256."""
    queue["schema"] = SCHEMA
    return fsio.atomic_write_json(ctx.layout.state / "queue.json", queue, root=ctx.layout.out)


# --------------------------------------------------------------------------------------------------- lock

def _lock_path(ctx: RunContext) -> Path:
    return ctx.layout.state / "lock"


def read_lock(ctx: RunContext) -> Optional[Dict[str, Any]]:
    """The run lock, None when absent, ``StateError`` when malformed."""
    path = _lock_path(ctx)
    if not os.path.lexists(str(path)):
        return None
    data = fsio.read_json(path)
    if not isinstance(data, dict) or "run_id" not in data or "driver" not in data:
        raise errors.StateError(".state/lock is not a lock record", path=str(path))
    if data.get("schema") != SCHEMA:
        raise errors.StateError(".state/lock has unsupported schema %r" % (data.get("schema"),), path=str(path))
    heartbeat_ns = data.get("heartbeat_ns")
    if (not isinstance(data["run_id"], str) or data["driver"] not in model.DRIVERS
            or isinstance(heartbeat_ns, bool) or not isinstance(heartbeat_ns, int)):
        raise errors.StateError(".state/lock holds malformed values (run_id, driver or heartbeat_ns)", path=str(path))
    return data


def _write_lock(ctx: RunContext, data: Dict[str, Any]) -> None:
    fsio.atomic_write_json(_lock_path(ctx), data, root=ctx.layout.out)


def create_lock(ctx: RunContext, run_id: str) -> None:
    """Create (or recreate) the run lock with driver ``none`` and a first heartbeat."""
    wall = ctx.clock.wall_ns()
    now = ctx.now_iso()
    _write_lock(ctx, {"schema": SCHEMA, "run_id": run_id, "pid": os.getpid(), "host": _host(), "driver": "none",
                      "created_at": now, "heartbeat_at": now, "heartbeat_ns": wall})


def heartbeat_age_s(ctx: RunContext, lock: Dict[str, Any]) -> float:
    return max(0.0, (ctx.clock.wall_ns() - int(lock.get("heartbeat_ns") or 0)) / 1e9)


def claim_driver(ctx: RunContext, run_id: str, driver: str) -> Tuple[bool, str, float]:
    """``(ok, active_driver, heartbeat_age_s)``. Driver ``none`` or the same driver: ok. Another driver whose heartbeat is
    at least ``TAKEOVER_AGE_S`` old: takeover (logged). Otherwise not ok (the caller raises ``DriverBusy``).
    A missing lock is created; a lock of a different run is a ``StateError``."""
    if driver not in ("chat", "workflow"):
        raise ValueError("unknown driver: %r" % (driver,))
    lock = read_lock(ctx)
    if lock is None:
        create_lock(ctx, run_id)
        lock = read_lock(ctx) or {}
    if lock.get("run_id") != run_id:
        raise errors.StateError(".state/lock belongs to run %s, not %s" % (lock.get("run_id"), run_id))
    active = lock.get("driver", "none")
    age = heartbeat_age_s(ctx, lock)
    if active in ("none", driver):
        takeover = False
    elif age >= TAKEOVER_AGE_S:
        takeover = True
    else:
        return (False, active, age)
    if takeover:
        ctx.log.info("state.driver_takeover", previous=active, new=driver, heartbeat_age_s=round(age, 1))
    lock["driver"] = driver
    lock["pid"] = os.getpid()
    lock["host"] = _host()
    lock["heartbeat_at"] = ctx.now_iso()
    lock["heartbeat_ns"] = ctx.clock.wall_ns()
    _write_lock(ctx, lock)
    return (True, driver, age)


def heartbeat(ctx: RunContext, driver: str) -> None:
    """Refresh the heartbeat (and driver) of an existing lock; a missing lock is not recreated."""
    lock = read_lock(ctx)
    if lock is None:
        return
    lock["driver"] = driver
    lock["heartbeat_at"] = ctx.now_iso()
    lock["heartbeat_ns"] = ctx.clock.wall_ns()
    _write_lock(ctx, lock)


def set_driver(ctx: RunContext, driver: str) -> None:
    if driver not in model.DRIVERS:
        raise ValueError("unknown driver: %r" % (driver,))
    lock = read_lock(ctx)
    if lock is None:
        return
    lock["driver"] = driver
    _write_lock(ctx, lock)


def release_lock(ctx: RunContext) -> None:
    fsio.remove_file(_lock_path(ctx), root=ctx.layout.out)


# --------------------------------------------------------------------------------------------------- op mutex

def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        return True           # os.kill(pid, 0) would terminate the process on Windows; rely on the age instead
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        return exc.errno != errno.ESRCH
    return True


def _mutex_is_stale(ctx: RunContext, path: Path) -> Tuple[bool, Dict[str, Any]]:
    holder: Dict[str, Any] = {}
    try:
        holder = fsio.read_json(path)
        if not isinstance(holder, dict):
            holder = {}
    except (errors.StateError, OSError):
        holder = {}
    now = ctx.clock.wall_ns()
    at_ns = holder.get("at_ns")
    if not isinstance(at_ns, int):
        try:
            at_ns = os.stat(str(path)).st_mtime_ns          # unreadable holder record: fall back to the file's age
        except OSError:
            return (True, holder)
    if (now - at_ns) / 1e9 > OP_MUTEX_STALE_S:
        return (True, holder)
    pid = holder.get("pid")
    if holder.get("host") == _host() and isinstance(pid, int) and not _pid_alive(pid):
        return (True, holder)
    return (False, holder)


_HOLDER_KEYS = ("pid", "host", "cmd", "at_ns")


def _same_holder(first: Dict[str, Any], second: Dict[str, Any]) -> bool:
    return all(first.get(key) == second.get(key) for key in _HOLDER_KEYS)


def _read_holder_bytes(path: Path) -> Tuple[bytes, Dict[str, Any]]:
    """Raw bytes and parsed record of a mutex file; ``(b"", {})`` when unreadable, ``(raw, {})`` when not a JSON object."""
    try:
        with open(str(path), "rb") as handle:
            raw = handle.read(65536)
    except OSError:
        return (b"", {})
    try:
        record = json.loads(raw.decode("utf-8"))
    except ValueError:
        return (raw, {})
    return (raw, record if isinstance(record, dict) else {})


def _break_stale_mutex(ctx: RunContext, path: Path, judged: Dict[str, Any]) -> bool:
    """Remove the mutex that was judged stale, but only if it is still that very mutex.

    Two processes can judge the same ``op.lock`` stale at once. A plain ``remove_file`` would let the second one delete
    the fresh mutex the first one has just created. The file is therefore renamed to a private name first (an atomic
    step that moves whatever is there now) and compared with the holder that was judged stale: when it is the same
    record it is discarded; when it is somebody else's fresh mutex it is put back (``write_once``: if a third process
    created a mutex in the meantime that one stays) and ``False`` is returned, so the caller reports ``Busy``.
    """
    aside = path.parent / (".op.lock.%d.%s.stale" % (os.getpid(), secrets.token_hex(4)))
    try:
        fsio.rename_file(path, aside, root=ctx.layout.out)
    except FileNotFoundError:
        return True                                           # somebody else removed it already: just retry the create
    raw, moved = _read_holder_bytes(aside)
    if _same_holder(moved, judged):
        fsio.remove_file(aside, root=ctx.layout.out)
        return True
    try:
        fsio.write_once_bytes(path, raw, root=ctx.layout.out)
    except FileExistsError:
        pass                                                  # a newer mutex exists; the displaced holder sees it at release
    finally:
        fsio.remove_file(aside, root=ctx.layout.out)
    return False


def _release_mutex(ctx: RunContext, path: Path, record: Dict[str, Any]) -> None:
    """Remove ``op.lock`` only when it still is the mutex this process created (a command that outlived
    ``OP_MUTEX_STALE_S`` may find that a successor replaced it)."""
    _, current = _read_holder_bytes(path)
    if _same_holder(current, record):
        fsio.remove_file(path, root=ctx.layout.out)
    else:
        ctx.log.warning("state.op_mutex_not_ours", holder=current)


@contextmanager
def op_mutex(ctx: RunContext, cmd: str) -> Iterator[None]:
    """Serialize mutating commands: ``O_EXCL`` creation of ``.state/op.lock`` with ``{pid, host, cmd, at_ns}``.

    A mutex is stale when its host is ours and its pid is dead, or when it is older than ``OP_MUTEX_STALE_S``; a stale
    mutex is replaced (and logged) through ``_break_stale_mutex``, which never removes a mutex other than the one that
    was judged stale. Otherwise ``Busy`` is raised. Release removes only this process's own mutex.
    """
    path = ctx.layout.state / "op.lock"
    record = {"pid": os.getpid(), "host": _host(), "cmd": cmd, "at_ns": ctx.clock.wall_ns()}
    acquired = False
    for attempt in range(3):
        try:
            fsio.write_once_json(path, record, root=ctx.layout.out)
            acquired = True
            break
        except FileExistsError:
            stale, holder = _mutex_is_stale(ctx, path)
            if not stale:
                raise errors.Busy(
                    "another sbom.py command (%s, pid %s) is still running; wait for it to finish and retry"
                    % (holder.get("cmd", "unknown"), holder.get("pid", "?")), holder=holder)
            ctx.log.warning("state.op_mutex_stale", holder=holder)
            if not _break_stale_mutex(ctx, path, holder):
                raise errors.Busy("another sbom.py command took over the operation mutex; wait for it to finish and retry",
                                  holder=holder)
    if not acquired:
        raise errors.Busy("could not acquire the operation mutex; retry")
    from sbomlib import runfiles
    tracking = None
    try:
        # the run folder is verified against the ledger the previous command sealed, and sealed again when this one is done
        # (runfiles.py: the detect-only replacement for the guard hook's write confinement)
        tracking = runfiles.enter(ctx, cmd)
        yield
    finally:
        try:
            if tracking is not None:
                runfiles.leave(ctx, tracking)
        except Exception:                                    # noqa: BLE001 - a failed seal is found by the next command
            ctx.log.exception("state.run_folder_seal_failed", cmd=cmd)
        try:
            _release_mutex(ctx, path, record)
        except (OSError, errors.SbomError):
            pass


# --------------------------------------------------------------------------------------------------- audit log

def audit_event(ctx: RunContext, event: Dict[str, Any]) -> None:
    """Append one event to ``.state/audit.jsonl`` (adds ``ts`` and ``run_id``). A no-op while ``.state`` does not exist."""
    state_dir = ctx.layout.state
    if not os.path.isdir(str(state_dir)):
        return
    record = dict(event)
    record.setdefault("ts", ctx.now_iso())
    record.setdefault("run_id", ctx.run_id)
    fsio.append_jsonl(state_dir / "audit.jsonl", record, root=ctx.layout.out)
