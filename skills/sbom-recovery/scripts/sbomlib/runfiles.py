"""The run-folder ledger: detect-only confinement of what is written below ``sbom-out/`` (SKILL_MIGRATION 7.2).

The hardened variant of this tool had a guard hook that stopped the agent from writing anywhere but one file. A plain skill
install has no hook, so the script now notices after the fact what the hook would have refused. ``.state/runfiles.json``
holds the SHA-256 of every file the script has written below the output folder (``sbom-out/`` or ``sbom-out-pilot/``):

* every command that takes the operation mutex first **verifies** the folder against the ledger the previous command left
  (``enter``) and last **seals** it again with the files as the command left them (``leave``). The agent acts between two
  commands, never inside one, so whatever differs at ``enter`` is not the script's doing;
* a script file that was **changed or deleted** is a failure: derived files may already rest on it, so the check
  ``run_folder_unchanged`` of the audit fails, nothing is promoted, and the finding stays even when the file is put back;
* a **file the script did not write** is an ACTION REQUIRED warning in ``report.md`` and the summary. It is not part of the
  SBOM and nothing is deleted. Once reported it is no longer tracked (the person may remove it; that is not a failure);
* the files the agent or the person legitimately write are not covered: the ``output`` files of ``adjudicate`` blocks
  (``repos/<repo>/llm/``, ``review/hints.json``), whose content is validated when the script reads them, and the review
  file, whose content the approval digests. ``previous/``, ``history/``, ``abandoned/``, ``.cache/``, ``.tmp/`` and the logs
  are not covered either (``references/limitations.md``).

A command that died before it sealed leaves ``open`` set; the next command then cannot tell the script's writes from anyone
else's, re-baselines, and says so (INFORMATIONAL). This is a speed bump against an agent that edits a state file by
mistake or because a hostile text told it to; an agent that rewrites the ledger as well is not detected.

**After the run finished** nothing is verified-and-resealed any more (resealing would bless an edit), but nothing is taken
on trust either: the ledger sealed when the run finished stays as it is, and every command an agent runs on a finished run
(``next``, ``status``, ``summary``, ``explain``, ``audit``) compares the folder with it, read-only (``closed_check``). A
script file that was changed or deleted since then is reported in the first line of each answer, because the verdict and the
outputs those answers quote may rest on it. Because of that, **no command writes to a finished run**: ``approve``,
``dispatch-record`` and ``inline-unit`` refuse before they touch ``run.json`` (a script write there would be a false alarm).
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from typing import Any, Dict, List, Optional, Set, Tuple

from sbomlib import errors, fsio, model, state
from sbomlib.context import RunContext
from sbomlib.state import RunState

SCHEMA = 1
LEDGER_NAME = "runfiles.json"
LEDGER_REL = ".state/" + LEDGER_NAME
MAX_FINDINGS = 200                 # kept in the ledger; the rest is counted in ``dropped``
MAX_WARNINGS = 10                  # warnings per kind and per command; the rest is one more warning
MAX_ERRORS = 50

SKIP_TOP = ("previous", "history", "abandoned", ".cache", ".tmp")         # folders below the output folder that are not covered
STATE_SKIP = frozenset(("op.lock", "lock", "sbom.log", "audit.jsonl", LEDGER_NAME, "human-input.jsonl", "guard-calls.jsonl",
                        "hook-errors.log"))                                # logs and per-command files, rewritten by every command
REVIEW_WRITTEN = frozenset(("cpe-lookup-names.csv", "hints.json"))        # the review file (the person) and the hints (the agent)
NOISE_NAMES = frozenset((".DS_Store", "Thumbs.db", "desktop.ini"))         # a file manager browsing the folder
_TEMP_RE = re.compile(r"^\..+\.\d+\.[0-9a-f]{8}\.tmp$")                    # fsio's temp file of an atomic write that was cut off
_STALE_RE = re.compile(r"^\.op\.lock\.\d+\.[0-9a-f]{8}\.stale$")
_EDITOR_RE = re.compile(r"^([~][$].*|\.[~]lock\..*#|.*[~]|\..*\.sw[a-p])$")    # lock and backup files of a spreadsheet or text editor

CHANGED = "RUN_FOLDER_CHANGED"
EXTRA = "RUN_FOLDER_EXTRA_FILE"
REBASELINED = "RUN_FOLDER_REBASELINED"
FAILING = ("modified", "removed", "ledger")
LEDGER_SINCE = (0, 2, 2)           # the first version of the skill that seals a ledger


class Tracking:
    """What ``enter`` saw, for ``leave``: the run the command found and whether it was already closed."""

    def __init__(self, run_id: Optional[str], completed: bool, cmd: str) -> None:
        self.run_id = run_id
        self.completed = completed
        self.cmd = cmd


# --------------------------------------------------------------------------------------------------- what is covered

def is_exempt(rel: str) -> bool:
    """True for a file below the output folder that the ledger does not cover (``rel`` is POSIX, relative to the folder)."""
    parts = rel.split("/")
    name = parts[-1]
    if name in NOISE_NAMES or _TEMP_RE.match(name) or _STALE_RE.match(name):
        return True
    if len(parts) == 1:
        return False
    top = parts[0]
    if top in SKIP_TOP:
        return True
    if top == ".state":
        return len(parts) == 2 and name in STATE_SKIP
    if top == "review":
        return len(parts) == 2 and (name in REVIEW_WRITTEN or bool(_EDITOR_RE.match(name)))
    if top == "repos":
        return len(parts) >= 4 and parts[2] == "llm"
    return False


def _skip_dir(rel: str) -> bool:
    parts = rel.split("/")
    if len(parts) == 1:
        return parts[0] in SKIP_TOP
    return len(parts) == 3 and parts[0] == "repos" and parts[2] == "llm"


def _canonical(rel: str) -> str:
    """The spelling a path has after a round trip through the ledger (a lone surrogate is written as literal text)."""
    return rel.encode("utf-8", "backslashreplace").decode("utf-8")


def _digest(path: str) -> str:
    try:
        info = os.lstat(path)
    except OSError as exc:
        return "error:%s" % (exc.errno,)
    if stat.S_ISLNK(info.st_mode):
        try:
            return "link:" + fsio.sha256_bytes(os.fsencode(os.readlink(path)))
        except OSError as exc:
            return "error:%s" % (exc.errno,)
    if not stat.S_ISREG(info.st_mode):
        return "special:%o" % stat.S_IFMT(info.st_mode)
    try:
        return fsio.sha256_file(path)
    except OSError as exc:
        return "error:%s" % (exc.errno,)


def scan(ctx: RunContext) -> Dict[str, str]:
    """``{relative path: digest}`` of every covered file below the output folder. Links are recorded, never followed;
    directories are not recorded (an empty one is part of the layout)."""
    found: Dict[str, str] = {}
    stack: List[Tuple[str, str]] = [("", os.fspath(ctx.layout.out))]
    while stack:
        rel_dir, abs_dir = stack.pop()
        try:
            with os.scandir(abs_dir) as listing:
                entries = sorted(listing, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            rel = rel_dir + "/" + entry.name if rel_dir else entry.name
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                is_dir = False
            if is_dir:
                if not _skip_dir(rel):
                    stack.append((rel, entry.path))
                continue
            if is_exempt(rel):
                continue
            found[_canonical(rel)] = _digest(entry.path)
    return found


# --------------------------------------------------------------------------------------------------- the ledger file

def _path(ctx: RunContext) -> Any:
    return ctx.layout.state / LEDGER_NAME


def load(ctx: RunContext) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """``(ledger, problem)``: the ledger, or None and the reason it cannot be used."""
    path = _path(ctx)
    if not os.path.lexists(str(path)):
        return (None, "missing")
    try:
        doc = fsio.read_json(path)
    except (errors.SbomError, OSError):
        return (None, "unreadable")
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA or not isinstance(doc.get("files"), dict) \
            or not isinstance(doc.get("findings"), list):
        return (None, "not a ledger of this version")
    return (doc, None)


def _write(ctx: RunContext, run_id: str, files: Dict[str, str], findings: List[Dict[str, Any]], dropped: int,
           open_by: Optional[Dict[str, Any]]) -> None:
    doc = {"schema": SCHEMA, "run_id": run_id, "sealed_at": ctx.now_iso(), "open": open_by, "files": files,
           "findings": findings, "dropped": dropped}
    fsio.atomic_write_json(_path(ctx), doc, root=ctx.layout.out)


def _finding(rel: str, change: str, cmd: str, ctx: RunContext, detail: str = "") -> Dict[str, Any]:
    return {"path": rel, "change": change, "found_by": cmd, "at": ctx.now_iso(), "detail": detail}


def _strays(findings: List[Dict[str, Any]]) -> Set[str]:
    """The paths already reported as files the script did not write. They are kept out of ``files``, so that removing one
    (what the warning asks the person to do) is not a deletion of a script file."""
    return {str(f.get("path")) for f in findings if isinstance(f, dict) and f.get("change") == "added"}


def _merge(old: List[Dict[str, Any]], new: List[Dict[str, Any]], dropped: int) -> Tuple[List[Dict[str, Any]], int]:
    seen = {(f.get("path"), f.get("change")) for f in old if isinstance(f, dict)}
    merged = [f for f in old if isinstance(f, dict)]
    for item in new:
        key = (item["path"], item["change"])
        if key not in seen:
            seen.add(key)
            merged.append(item)
    if len(merged) > MAX_FINDINGS:
        dropped += len(merged) - MAX_FINDINGS
        merged = merged[:MAX_FINDINGS]
    return (merged, dropped)


# --------------------------------------------------------------------------------------------------- warnings

def describe(ctx: RunContext, item: Dict[str, Any]) -> str:
    shown = ctx.layout.shown(str(item.get("path")))
    change = item.get("change")
    by = item.get("found_by") or "a command"
    if change == "modified":
        return ("%s was changed after the script wrote it (found by %s). The files of a run are written by the script only: "
                "the audit fails and nothing is promoted." % (shown, by))
    if change == "removed":
        return ("%s was deleted after the script wrote it (found by %s). The files of a run are written by the script only: "
                "the audit fails and nothing is promoted." % (shown, by))
    if change == "ledger":
        return ("The ledger of the run folder (%s) is %s (found by %s), so the files of the run cannot be checked: the audit "
                "fails and nothing is promoted." % (ctx.layout.shown(LEDGER_REL), item.get("detail") or "unusable", by))
    return ("%s was found in the run folder, but the script did not write it (found by %s). It is not part of the SBOM and "
            "the script changed nothing; remove it if it is not yours." % (shown, by))


def _warnings(ctx: RunContext, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for code, kinds, label in ((CHANGED, FAILING, "changed or deleted file(s)"), (EXTRA, ("added",), "file(s) the script did not write")):
        chosen = [f for f in findings if f["change"] in kinds]
        for item in chosen[:MAX_WARNINGS]:
            result.append(model.warning("ACTION_REQUIRED", code, describe(ctx, item)))
        if len(chosen) > MAX_WARNINGS:
            result.append(model.warning("ACTION_REQUIRED", code, "... and %d more %s in the run folder; see %s." % (
                len(chosen) - MAX_WARNINGS, label, ctx.layout.shown(LEDGER_REL))))
    return result


# --------------------------------------------------------------------------------------------------- enter / leave

def enter(ctx: RunContext, cmd: str) -> Tracking:
    """Called by ``state.op_mutex`` once the mutex is held. Verifies the run folder against the ledger and records what it
    finds; never raises (a check that cannot run is itself a finding)."""
    try:
        run = state.load_run(ctx)
    except (errors.SbomError, OSError):
        return Tracking(None, False, cmd)
    if run is None:
        return Tracking(None, False, cmd)
    if run.completed:
        return Tracking(run.run_id, True, cmd)
    try:
        _verify(ctx, run, cmd)
    except Exception as exc:                                  # noqa: BLE001 - see the docstring
        try:
            ctx.log.exception("runfiles.verify_failed", cmd=cmd)
            _record(ctx, run, [_finding(LEDGER_REL, "ledger", cmd, ctx, "not checkable (%s)" % type(exc).__name__)], [])
        except Exception:                                     # noqa: BLE001
            ctx.log.exception("runfiles.record_failed", cmd=cmd)
    return Tracking(run.run_id, False, cmd)


def _record(ctx: RunContext, run: RunState, findings: List[Dict[str, Any]], notes: List[Dict[str, Any]]) -> None:
    """Keep ``findings`` in the ledger and raise the warnings in ``run.json`` (the caller holds the mutex)."""
    doc, _ = load(ctx)
    old = doc["findings"] if doc is not None and doc.get("run_id") == run.run_id else []
    files = doc["files"] if doc is not None and doc.get("run_id") == run.run_id else {}
    merged, dropped = _merge(old, findings, int((doc or {}).get("dropped") or 0))
    _write(ctx, run.run_id, files, merged, dropped, (doc or {}).get("open"))
    run.add_warnings(_warnings(ctx, findings) + notes)
    run.save(ctx)


def _predates_ledger(run: RunState) -> bool:
    """True for a run that an older version of the skill began (``pack.version`` below ``LEDGER_SINCE``). Only such a run may
    lack the ledger and the ``runfiles`` mark; for any other, a missing ledger is a finding."""
    numbers = re.findall(r"\d+", str((run.data.get("pack") or {}).get("version") or ""))[:3]
    return len(numbers) == 3 and tuple(int(n) for n in numbers) < LEDGER_SINCE


def _verify(ctx: RunContext, run: RunState, cmd: str) -> None:
    current = scan(ctx)
    ledger, problem = load(ctx)
    tracked = (run.data.get("runfiles") or {}).get("schema") == SCHEMA or not _predates_ledger(run)
    findings: List[Dict[str, Any]] = []
    notes: List[Dict[str, Any]] = []
    previous: List[Dict[str, Any]] = []
    dropped = 0
    if ledger is None or ledger.get("run_id") != run.run_id:
        if tracked:
            findings.append(_finding(LEDGER_REL, "ledger", cmd, ctx,
                                     (problem or "from another run") if ledger is None else "from another run"))
    else:
        previous = ledger["findings"]
        dropped = int(ledger.get("dropped") or 0)
        if ledger.get("open"):
            opened = ledger["open"]
            notes.append(model.warning(
                "INFORMATIONAL", REBASELINED,
                "The command %s did not finish (it did not seal the run folder), so changes made to %s after it cannot be told "
                "apart from its own writes; the folder was taken as it is now." % (opened.get("cmd") or "before this one",
                                                                                  ctx.layout.shown())))
        else:
            old = ledger["files"]
            for rel in sorted(old):
                if rel not in current:
                    findings.append(_finding(rel, "removed", cmd, ctx))
                elif current[rel] != old[rel]:
                    findings.append(_finding(rel, "modified", cmd, ctx))
            known = _strays(previous)
            findings.extend(_finding(rel, "added", cmd, ctx) for rel in sorted(current) if rel not in old and rel not in known)
    merged, dropped = _merge(previous, findings, dropped)
    strays = _strays(merged)
    _write(ctx, run.run_id, {rel: d for rel, d in current.items() if rel not in strays}, merged, dropped,
           {"cmd": cmd, "at": ctx.now_iso()})
    changed = bool(findings or notes)
    if not (run.data.get("runfiles") or {}).get("schema") == SCHEMA and not findings:
        run.data["runfiles"] = {"schema": SCHEMA}            # a run begun before the ledger existed is adopted as it stands
        changed = True
    if findings or notes:
        run.add_warnings(_warnings(ctx, findings) + notes)
        state.audit_event(ctx, {"event": "run_folder", "cmd": cmd,
                                "changed": [f["path"] for f in findings if f["change"] in FAILING][:MAX_ERRORS],
                                "extra": [f["path"] for f in findings if f["change"] == "added"][:MAX_ERRORS],
                                "rebaselined": bool(notes)})
    if changed:
        run.save(ctx)


def leave(ctx: RunContext, tracking: Tracking) -> None:
    """Called by ``state.op_mutex`` before the mutex is released: seals the folder as the command left it. A command that
    found the run already closed seals nothing: a later change to a finished run is reported by ``closed_check`` (and
    by the ``audit`` subcommand), never absorbed."""
    try:
        run = state.load_run(ctx)
    except (errors.SbomError, OSError):
        return
    if run is None:
        return
    if tracking.completed and run.run_id == tracking.run_id:
        return
    seal(ctx, run)


def seal(ctx: RunContext, run: RunState) -> None:
    ledger, _ = load(ctx)
    same = ledger is not None and ledger.get("run_id") == run.run_id
    findings = list(ledger["findings"]) if same else []
    strays = _strays(findings)
    _write(ctx, run.run_id, {rel: d for rel, d in scan(ctx).items() if rel not in strays}, findings,
           int(ledger.get("dropped") or 0) if same else 0, None)


# --------------------------------------------------------------------------------------------------- the audit

def check(ctx: RunContext, run: RunState) -> Dict[str, Any]:
    """The input of the validation check ``run_folder_unchanged``: ``status`` (``fail`` for a changed or deleted script file or
    an unusable ledger), ``errors``, and the files the script did not write (``added``) that are still there."""
    ledger, problem = load(ctx)
    if ledger is None or ledger.get("run_id") != run.run_id:
        reason = "from another run" if ledger is not None else (problem or "unusable")
        return {"status": "fail", "checked": 0, "added": [], "added_count": 0, "dropped": 0,
                "errors": ["the run folder ledger %s is %s, so the files of the run were not checked" % (LEDGER_REL, reason)]}
    problems: List[str] = []
    added: List[str] = []
    for item in ledger["findings"]:
        if not isinstance(item, dict):
            continue
        if item.get("change") in FAILING:
            problems.append(describe(ctx, item))
        elif item.get("change") == "added" and os.path.lexists(os.path.join(os.fspath(ctx.layout.out), str(item.get("path")))):
            added.append(str(item.get("path")))
    dropped = int(ledger.get("dropped") or 0)
    if dropped:
        problems.append("%d more finding(s) were not kept in the ledger (more than %d)" % (dropped, MAX_FINDINGS))
    return {"status": "fail" if problems else "pass", "checked": len(ledger["files"]), "errors": problems[:MAX_ERRORS],
            "added": added[:MAX_ERRORS], "added_count": len(added), "dropped": dropped}


def recheck(ctx: RunContext, run: RunState) -> Dict[str, Any]:
    """Read-only comparison of a finished run's folder with the ledger sealed when it finished (the ``audit`` subcommand and
    ``closed_check``). Writes nothing. The lists are cut at ``MAX_ERRORS``; ``changed_total`` and ``added_total`` count every
    difference (a changed or deleted file, an unusable or unsealed ledger; a file the script did not write)."""
    ledger, problem = load(ctx)
    if ledger is None and problem == "missing" and _predates_ledger(run) and (run.data.get("runfiles") or {}).get("schema") != SCHEMA:
        return {"ok": True, "modified": [], "removed": [], "added": [], "changed_total": 0, "added_total": 0, "differences": [],
                "unchecked": "the run was made by a version of the skill that sealed no ledger"}
    if ledger is None or ledger.get("run_id") != run.run_id:
        return {"ok": False, "modified": [], "removed": [], "added": [], "changed_total": 1, "added_total": 0,
                "differences": [{"path": LEDGER_REL, "change": "ledger %s" % (problem or "from another run")}]}
    current = scan(ctx)
    old = ledger["files"]
    known = _strays(ledger["findings"])
    modified = sorted(rel for rel in old if rel in current and current[rel] != old[rel])
    removed = sorted(rel for rel in old if rel not in current)
    added = sorted(rel for rel in current if rel not in old and rel not in known)
    changed = [{"path": rel, "change": "modified"} for rel in modified] + [{"path": rel, "change": "removed"} for rel in removed]
    opened = ledger.get("open")
    if opened:                  # the command that finished the run did not seal: the digests may predate its last writes
        changed.insert(0, {"path": LEDGER_REL, "change": "ledger not sealed (the command %s did not finish)" % (
            (opened.get("cmd") if isinstance(opened, dict) else None) or "that finished the run")})
    differences = changed + [{"path": rel, "change": "added"} for rel in added]
    return {"ok": not differences, "modified": modified[:MAX_ERRORS], "removed": removed[:MAX_ERRORS], "added": added[:MAX_ERRORS],
            "changed_total": len(changed), "added_total": len(added), "differences": differences[:MAX_ERRORS]}


MAX_SHOWN = 5                      # paths named in the first line of an answer


def closed_check(ctx: RunContext, run: RunState) -> Dict[str, Any]:
    """What ``next``, ``status``, ``summary``, ``explain`` and ``audit`` ask about a finished run: does its folder still hold
    what the script sealed? Read-only, never raises (a check that cannot run is itself a difference).

    ``ok`` is False when a file the script wrote was changed or deleted, or the ledger is missing, unusable, of another run
    or was left open; ``changed`` lists those (``[{path, change}]``, at most ``MAX_ERRORS``) and ``changed_count`` counts them
    all. A file the script did not write does not make ``ok`` False; it is in ``added`` (``added_count``)."""
    try:
        found = recheck(ctx, run)
    except Exception:                                         # noqa: BLE001 - see the docstring
        try:
            ctx.log.exception("runfiles.closed_check_failed")
        except Exception:                                     # noqa: BLE001
            pass
        found = {"changed_total": 1, "added_total": 0, "added": [],
                 "differences": [{"path": LEDGER_REL, "change": "ledger not checkable"}]}
    differences = [d for d in found.get("differences") or [] if isinstance(d, dict)]
    changed = [d for d in differences if d.get("change") != "added"]
    changed_count = int(found.get("changed_total") or 0)
    return {"ok": changed_count == 0, "changed": changed, "changed_count": changed_count,
            "added": list(found.get("added") or []), "added_count": int(found.get("added_total") or 0),
            "unchecked": found.get("unchecked")}


def closed_line(ctx: RunContext, check: Dict[str, Any]) -> str:
    """The first line of an answer about a finished run whose folder changed: what changed and what that means."""
    shown = ["%s (%s)" % (ctx.layout.shown(str(d.get("path"))), d.get("change")) for d in check.get("changed") or []]
    more = int(check.get("changed_count") or 0) - min(len(shown), MAX_SHOWN)
    names = ", ".join(shown[:MAX_SHOWN]) + (" and %d more" % more if more > 0 else "")
    return ("RUN FOLDER CHANGED since the run finished: %s. The script did not make these changes, so the verdict and the "
            "outputs of this run cannot be trusted; run audit for the full list." % names)


def closed_warning(ctx: RunContext, check: Dict[str, Any]) -> Dict[str, Any]:
    """The ACTION REQUIRED warning that carries ``closed_line`` in an answer's ``warnings``."""
    return model.warning("ACTION_REQUIRED", CHANGED, closed_line(ctx, check))
