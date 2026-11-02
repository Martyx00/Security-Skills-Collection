"""Layout, clocks, HTTP interface and the run context (contract section 3.1).

This module never imports another work package's module at import time: ``net`` is imported inside
``make_context`` (``net.UrllibHttp`` subclasses ``Http`` defined here).
"""
from __future__ import annotations

import calendar
import importlib
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from sbomlib import errors
from sbomlib.log import Logger

OUT_NAMES = ("sbom-out", "sbom-out-pilot")       # the two output folders of a workspace: a full run and a pilot run
FULL_OUT, PILOT_OUT = OUT_NAMES

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_ISO_Z_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$")


def default_skill_root() -> Path:
    """The folder that holds this skill (the folder with ``scripts/``, ``assets/`` and ``references/``), found from the
    location of this module. Read-only: nothing is ever written there. The workspace is never derived from it."""
    return Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Layout:
    """The two roots of the skill. ``skill`` is where the code, the assets and the rubrics live (from ``__file__``, wherever
    the skill is installed, read-only). ``parent`` is the workspace folder (the working directory), the folder whose
    subfolders are the repositories; every output goes below ``parent/sbom-out`` (``sbom-out-pilot`` for a pilot run).
    Neither is derived from the other."""
    parent: Path         # PARENT = the workspace folder (the working directory), resolved
    skill: Path          # the skill folder (read-only)
    scripts: Path        # skill/scripts
    assets: Path         # skill/assets
    out: Path            # PARENT/sbom-out (or PARENT/sbom-out-pilot)
    state: Path          # out/.state
    repos_out: Path      # out/repos
    review: Path         # out/review
    staging_root: Path   # out/.staging
    cache: Path          # out/.cache
    tmp: Path            # out/.tmp
    history: Path        # out/history
    abandoned: Path      # out/abandoned
    previous: Optional[Path] = None   # out/previous: the newest finished run, kept under a fixed name as the baseline
    out_name: str = "sbom-out"        # the output folder name: "sbom-out" (a full run) or "sbom-out-pilot" (a pilot run)

    @classmethod
    def for_parent(cls, parent: Path, skill: Optional[Path] = None, out_name: str = "sbom-out") -> "Layout":
        """The layout of the workspace ``parent`` for the skill folder ``skill`` (default: the folder this module is
        installed in); no validation, no mkdir. ``out_name`` is one of ``OUT_NAMES`` (a closed set: no value from the
        environment or the command line ever chooses another folder)."""
        if out_name not in OUT_NAMES:
            raise ValueError("unknown output folder name: %r" % (out_name,))
        parent = Path(parent)
        skill = Path(skill) if skill is not None else default_skill_root()
        out = parent / out_name
        return cls(parent=parent, skill=skill, scripts=skill / "scripts", assets=skill / "assets",
                   out=out, state=out / ".state", repos_out=out / "repos", review=out / "review",
                   staging_root=out / ".staging", cache=out / ".cache", tmp=out / ".tmp", history=out / "history",
                   abandoned=out / "abandoned", previous=out / "previous", out_name=out_name)

    def shown(self, relative: str = "") -> str:
        """``sbom-out/<relative>`` (or ``sbom-out-pilot/<relative>``): how a path below the output folder is written in a
        message."""
        return self.out_name + "/" + relative if relative else self.out_name + "/"

    def repo_out(self, repo: str) -> Path:
        return self.repos_out / repo

    def skill_path(self, relative: str) -> str:
        """Absolute POSIX path of a file inside the skill folder (read-only). The adjudication blocks use it to point the
        model at a rubric that lives outside the workspace; files keep the skill-relative text so that their hashes do not
        depend on where the skill is installed."""
        return (self.skill / relative).as_posix()

    def llm_dir(self, repo: str) -> Path:
        return self.repos_out / repo / "llm"

    def staging(self, run_id: str) -> Path:
        return self.staging_root / run_id

    def _relative(self, p: Path, base: Path) -> str:
        p = Path(p)
        try:
            return p.relative_to(base).as_posix()
        except ValueError:
            pass
        real_p = Path(os.path.realpath(str(p)))
        real_base = Path(os.path.realpath(str(base)))
        try:
            return real_p.relative_to(real_base).as_posix()
        except ValueError:
            raise ValueError("%s is not below %s" % (p, base))

    def rel(self, p: Path) -> str:
        """PARENT-relative POSIX string, e.g. ``sbom-out/review/cpe-lookup-names.csv``."""
        return self._relative(p, self.parent)

    def out_rel(self, p: Path) -> str:
        """sbom-out-relative POSIX string, e.g. ``repos/app_zlib/candidates.json``."""
        return self._relative(p, self.out)


class Clock:
    """Base clock; SystemClock and the tests' FakeClock subclass it."""

    def wall_ns(self) -> int:
        """ALWAYS the real ``time.time_ns()`` (same clock as ``st_mtime_ns`` and hook records)."""
        return time.time_ns()

    def time_ns(self) -> int:
        """Fakeable: human-readable timestamps, cache TTL, run ids."""
        return time.time_ns()

    def now_utc(self) -> datetime:
        return _EPOCH + timedelta(microseconds=self.time_ns() // 1000)

    def monotonic(self) -> float:
        """Fakeable: budgets and rate limits."""
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


class SystemClock(Clock):
    pass


def iso_z(value: Union[int, datetime]) -> str:
    """Nanoseconds since the epoch (int) or a datetime -> ``YYYY-MM-DDThh:mm:ssZ`` (UTC, no fraction)."""
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    else:
        dt = _EPOCH + timedelta(seconds=int(value) // 10 ** 9)
    return "%04d-%02d-%02dT%02d:%02d:%02dZ" % (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def parse_iso_z(text: str) -> int:
    """``YYYY-MM-DDThh:mm:ssZ`` -> nanoseconds since the epoch (UTC). ValueError for anything else."""
    match = _ISO_Z_RE.fullmatch(text if isinstance(text, str) else "")
    if not match:
        raise ValueError("not a YYYY-MM-DDThh:mm:ssZ timestamp: %r" % (text,))
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    return calendar.timegm(dt.utctimetuple()) * 10 ** 9


@dataclass
class HttpResponse:
    status: int
    body: Optional[Any]                                      # parsed JSON or None
    headers: Dict[str, str]


class Http:
    """Base class; ``net.UrllibHttp`` and the tests' FakeHttp subclass it."""

    def get_json(self, url: str, headers: Dict[str, str], timeout: float) -> HttpResponse:
        """Raises ``errors.NetworkUnavailable`` on DNS, connect, TLS or proxy CONNECT failure; HTTP errors return a response."""
        raise NotImplementedError


@dataclass
class RunContext:
    layout: Layout
    clock: Clock
    http: Optional[Http]                 # None => offline (phase 7 degrades)
    env: Dict[str, str]                  # snapshot of os.environ taken once in main()
    log: Logger
    tty: bool                            # sys.stdin.isatty() and sys.stdout.isatty()
    budget_soft_s: float = 40.0
    budget_hard_s: float = 80.0
    t0: float = 0.0                      # clock.monotonic() at command start
    unit_t0: float = 0.0                 # clock.monotonic() at the start of the current unit (set by the driver)
    unit_first: bool = True              # True when the current unit is the first unit of this invocation
    run_id: Optional[str] = None
    scope: str = "product"               # "product" | "all", copied from run.json
    python_prefix: str = "python3 -I -B"  # from env.json once a run exists
    # Per-command scratch information that cli_core.main turns into the ``command`` audit event
    # (keys: units, driver, audited). A handler that writes its own ``command`` event sets ``audited``.
    command_info: Dict[str, Any] = field(default_factory=dict)

    def elapsed(self) -> float:
        """Seconds since the command started."""
        return self.clock.monotonic() - self.t0

    def unit_elapsed(self) -> float:
        """Seconds since the current unit started."""
        return self.clock.monotonic() - self.unit_t0

    def remaining(self) -> float:
        return self.budget_hard_s - self.elapsed()

    def soft_expired(self) -> bool:
        return self.elapsed() >= self.budget_soft_s

    def should_yield(self, margin_s: float = 10.0) -> bool:
        """Checkpointing units return ``done=False`` when this is true."""
        return self.remaining() < margin_s

    def check_deadline(self) -> None:
        if self.elapsed() >= self.budget_hard_s:
            raise errors.BudgetExceeded("the hard time budget of %.0f s is used up" % self.budget_hard_s)

    def created(self) -> str:
        """SPDX ``created``: SOURCE_DATE_EPOCH from env if a valid int >= 0, else the clock."""
        raw = self.env.get("SOURCE_DATE_EPOCH")
        if isinstance(raw, str) and re.fullmatch(r"[0-9]+", raw.strip() or "x"):
            try:
                return iso_z(int(raw.strip()) * 10 ** 9)
            except (OverflowError, ValueError):
                pass
        return iso_z(self.clock.now_utc())

    def now_iso(self) -> str:
        """The command clock as ``iso_z`` text (never SOURCE_DATE_EPOCH)."""
        return iso_z(self.clock.now_utc())

    def asset(self, name: str) -> Any:
        from sbomlib import assets
        return assets.load(self.layout, name)

    def version(self) -> str:
        """``VERSION`` of the skill folder stripped; ``0.0.0`` if missing."""
        try:
            with open(str(self.layout.skill / "VERSION"), encoding="utf-8") as handle:
                text = handle.read().strip()
        except (OSError, UnicodeDecodeError):
            return "0.0.0"
        return text or "0.0.0"


def optional_module(name: str) -> Any:
    """Import ``sbomlib.<name>`` inside the function that needs it; None when that module itself is absent.

    An ImportError raised *inside* an existing module (a missing dependency of its own) is re-raised.
    """
    full = "sbomlib." + name
    try:
        return importlib.import_module(full)
    except ImportError as exc:
        if getattr(exc, "name", None) == full:
            return None
        raise


def _detect_tty() -> bool:
    try:
        return bool(sys.stdin is not None and sys.stdin.isatty() and sys.stdout is not None and sys.stdout.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def make_context(layout: Layout, *, overrides: Optional[Dict[str, Any]] = None) -> RunContext:
    """Build the run context.

    overrides keys (tests only): clock, http, env, tty, budget_soft_s, budget_hard_s. The default http is
    ``net.UrllibHttp()`` (imported here, never at module level); None when ``sbomlib.net`` is absent. It is only ever
    called by cpe/nvd.py.
    """
    overrides = dict(overrides or {})
    clock = overrides.get("clock") or SystemClock()
    if "http" in overrides:
        http = overrides["http"]
    else:
        net = optional_module("net")
        http = net.UrllibHttp() if net is not None else None
    env = dict(overrides["env"]) if overrides.get("env") is not None else dict(os.environ)
    tty = bool(overrides["tty"]) if "tty" in overrides else _detect_tty()
    state_dir = str(layout.state)
    log = Logger(layout.state / "sbom.log") if os.path.isdir(state_dir) and not os.path.islink(state_dir) else Logger(None)
    now = clock.monotonic()
    return RunContext(
        layout=layout, clock=clock, http=http, env=env, log=log, tty=tty,
        budget_soft_s=float(overrides.get("budget_soft_s", 40.0)),
        budget_hard_s=float(overrides.get("budget_hard_s", 80.0)),
        t0=now, unit_t0=now)
