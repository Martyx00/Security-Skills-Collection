"""Human-input records: reading ``.state/human-input.jsonl`` and the agent profile (contract sections 3.13 and 4.14).

The prompt hook of the hardened variant appended one record per user turn (a hash and whether the turn looked like an
approval, never the text). This skill has no hook, so nothing writes the file and no approval is ever bound to a record
(``approval.verify_approval``). The recorder rules (approval phrases, host-made turns) were retired with the hook; the
readers stay for ``guardlib`` and ``lifecycle``, which only consult them where ``guardlib.HOOKS_SHIPPED`` says a hook exists.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from sbomlib.context import RunContext

HUMAN_INPUT_NAME = "human-input.jsonl"
EMPTY_PROMPT_REASON = "empty_prompt"         # drop_reason of a presence-only record (the hook gave no text)


def human_input_path(ctx: RunContext) -> Path:
    return ctx.layout.state / HUMAN_INPUT_NAME


def read_records(ctx: RunContext, since_ns: int = 0) -> List[Dict[str, Any]]:
    """Every record of ``.state/human-input.jsonl`` in file order (``ts_ns >= since_ns`` when given).

    Malformed lines are skipped and logged; a missing file is an empty list.
    """
    path = human_input_path(ctx)
    try:
        with open(os.fspath(path), "rb") as handle:
            raw = handle.read()
    except OSError:
        return []
    records: List[Dict[str, Any]] = []
    for number, line in enumerate(raw.split(b"\n"), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            ctx.log.warning("humaninput.bad_line", line=number)
            continue
        if not isinstance(record, dict) or not isinstance(record.get("ts_ns"), int) or isinstance(record.get("ts_ns"), bool):
            ctx.log.warning("humaninput.bad_record", line=number)
            continue
        if record["ts_ns"] >= since_ns:
            records.append(record)
    return records


def latest_agent_profile(ctx: RunContext, since_ns: int) -> str:
    """``sbom`` | ``default`` | ``unknown`` from the agent name of the latest human record at or after ``since_ns``.

    ``unknown`` when there is no such record or its payload did not name the agent; any agent other than ``sbom``
    counts as ``default`` (the strict agent is not in use). A presence-only record (empty prompt) still names the agent;
    host-made turns do not count.
    """
    latest: Optional[Dict[str, Any]] = None
    for record in read_records(ctx, since_ns):
        own_turn = record.get("human") is True or record.get("drop_reason") == EMPTY_PROMPT_REASON
        if own_turn and (latest is None or record["ts_ns"] >= latest["ts_ns"]):
            latest = record
    if latest is None:
        return "unknown"
    name = latest.get("agent")
    if not isinstance(name, str) or not name.strip():
        return "unknown"
    return "sbom" if name.strip().casefold() == "sbom" else "default"
