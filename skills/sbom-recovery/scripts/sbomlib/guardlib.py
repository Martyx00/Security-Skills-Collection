"""What is left of the hook guard's library (contract sections 3.13, 4.14, 5.12) in a skill that ships no hook.

The hardened Kiro variant ran ``guard.py`` as a hook: it refused shell commands and writes while a run was active and
recorded each human message. This skill has no hook entry point, so the decision functions, the prompt recorder and the
guard-call log were retired with it (references/provenance.md lists them). What stays are the two readers that
``lifecycle`` asks for ``run.json.guard``:

* ``guard_active``: "false" here. A guard that was not installed cannot be active.
* ``hooks_fired``: no hook fired.

Both answer without reading a log while ``HOOKS_SHIPPED`` is false, because a log that happens to sit in the workspace
(left by the hardened variant, or planted) says nothing about this run. A host adapter that really feeds
``.state/guard-calls.jsonl`` and ``.state/human-input.jsonl`` sets ``HOOKS_SHIPPED`` to true and gets the original
behaviour back.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

from sbomlib import humaninput
from sbomlib.context import RunContext

HOOKS_SHIPPED = False       # True only where a hook entry point really feeds the logs this module reads
SUBCOMMANDS = ("selfcheck", "start", "status", "next", "approve", "audit", "explain", "summary", "stage", "gate-status",
               "validate")
GUARD_ACTIVE_WINDOW_NS = 30 * 10 ** 9
TAIL_BYTES = 256 * 1024
GUARD_CALLS_NAME = "guard-calls.jsonl"


def _tail_records(path: Path, max_bytes: int = TAIL_BYTES) -> List[Dict[str, Any]]:
    """The last records of a JSON-lines file (at most ``max_bytes`` read from its end); malformed lines are skipped."""
    try:
        with open(os.fspath(path), "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            start = max(0, size - max_bytes)
            handle.seek(start)
            raw = handle.read()
    except OSError:
        return []
    lines = raw.split(b"\n")
    if start > 0:
        lines = lines[1:]                                  # the first line is probably cut
    records: List[Dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(record, dict) and isinstance(record.get("ts_ns"), int):
            records.append(record)
    return records


def guard_active(ctx: RunContext, subcommand: str, since_ns: int) -> str:
    """``false`` without a hook. With ``HOOKS_SHIPPED``: ``true`` when the guard hook logged an ``allow`` of a pack
    subcommand within the last 30 s (and not before ``since_ns``); else ``unknown`` for a terminal command (a terminal is
    never logged); else ``false`` (the hooks did not run).

    The record for ``subcommand`` itself is the proof that this very invocation went through the hook. A record for
    another pack subcommand proves the same thing about the workspace (the hook fires for agent commands), and
    ``lifecycle.refresh_guard`` asks about ``start`` whichever command it runs for, so any ``allow`` of a pack
    subcommand counts.
    """
    if not HOOKS_SHIPPED:
        return "false"
    now = ctx.clock.wall_ns()
    for record in _tail_records(ctx.layout.state / GUARD_CALLS_NAME):
        if (record.get("mode") == "shell" and record.get("decision") == "allow"
                and record.get("subcommand") in SUBCOMMANDS
                and record["ts_ns"] >= now - GUARD_ACTIVE_WINDOW_NS and record["ts_ns"] >= since_ns):
            return "true"
    return "unknown" if ctx.tty else "false"


def hooks_fired(ctx: RunContext, since_ns: int) -> Dict[str, bool]:
    """``{"prompt", "pretooluse"}``: whether the prompt hook and a PreToolUse guard hook logged anything since ``since_ns``
    (the files are append-only, so the last record decides). Nothing fired without a hook."""
    result = {"prompt": False, "pretooluse": False}
    if not HOOKS_SHIPPED:
        return result
    for key, name in (("prompt", humaninput.HUMAN_INPUT_NAME), ("pretooluse", GUARD_CALLS_NAME)):
        records = _tail_records(ctx.layout.state / name)
        result[key] = bool(records) and records[-1]["ts_ns"] >= since_ns
    return result
