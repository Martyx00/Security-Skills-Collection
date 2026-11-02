"""The baseline of an incremental run: the newest finished run, kept in ``previous/`` (TASKLIST 3.7, INTEGRATION_NOTES).

``start`` moves the run that has just passed its audit to ``previous/`` and the older baseline to ``history/<UTC>/``, so a
new run always finds the last good run in one fixed place. Everything here only reads that folder (and the repositories,
through ``gitro``); nothing is written except ``repos/<repo>/baseline.json`` of the current run.

An incremental run is not a shortcut: every phase runs again over the whole tree. What the baseline adds is (1) the commit
of every repository at the last good run, (2) the paths that changed since then, (3) the components of the last run, which
the worker role gets as a lead list and which the delta (``delta.py``) is computed against, and (4) the validated worker
claims of an unchanged repository, which are re-checked and carried over instead of asking for them again.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from sbomlib import errors, fsio, gitro
from sbomlib.context import RunContext
from sbomlib.state import RunState

MAX_CHANGED_FILES = 5000
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
STATUSES = ("no-baseline", "unchanged", "listed", "commit-not-local", "unknown")


def previous_dir(ctx: RunContext) -> Optional[Path]:
    """``previous/`` when it holds a finished, audited run, else None."""
    folder = ctx.layout.previous
    if folder is None or os.path.islink(str(folder)) or not os.path.isdir(str(folder)):
        return None
    try:
        info = fsio.read_json(folder / "archive.json")
    except (errors.StateError, OSError):
        return None
    if not isinstance(info, dict) or info.get("kind") != "previous" or not info.get("completed") or info.get("audit") != "pass":
        return None
    return folder


def _read(path: Path) -> Optional[Any]:
    try:
        return fsio.read_json(path)
    except (errors.StateError, OSError):
        return None


def describe(ctx: RunContext) -> Dict[str, Any]:
    """What the baseline is, for ``run.json``: ``{"present": False, "reason": ...}`` or the run id, close time, mode and the
    commit analysed per repository."""
    folder = previous_dir(ctx)
    if folder is None:
        return {"present": False, "reason": "no finished run has been moved to previous/ yet"}
    info = _read(folder / "archive.json") or {}
    run_doc = _read(folder / ".state" / "run.json") or {}
    repos = run_doc.get("repos") if isinstance(run_doc, dict) else None
    commits: Dict[str, Optional[str]] = {}
    statuses: Dict[str, str] = {}
    if isinstance(repos, dict):
        for name, entry in repos.items():
            if isinstance(entry, dict):
                head = entry.get("head")
                commits[str(name)] = head if isinstance(head, str) and COMMIT_RE.match(head) else None
                statuses[str(name)] = str(entry.get("status"))
    return {"present": True, "run_id": info.get("run_id"), "closed_at": info.get("closed_at"),
            "mode": info.get("mode") or "full", "commits": commits, "statuses": statuses}


def _entry(ctx: RunContext, run: RunState, repo: str) -> Dict[str, Any]:
    baseline = run.data.get("baseline")
    if not isinstance(baseline, dict) or not baseline.get("present"):
        return {}
    return {"commit": (baseline.get("commits") or {}).get(repo), "status": (baseline.get("statuses") or {}).get(repo)}


def commit_of(ctx: RunContext, run: RunState, repo: str) -> Optional[str]:
    """The commit the baseline analysed in ``repo``, or None (no baseline, repository not in it, or it was not analysed)."""
    entry = _entry(ctx, run, repo)
    if entry.get("status") in ("FAILED", "NOT ANALYZED", None):
        return None
    return entry.get("commit")


def components_of(ctx: RunContext, repo: str) -> Optional[List[Dict[str, Any]]]:
    """The components of ``repo`` in the baseline (``name``, ``version``, ``norm_name``, ``locations``, ``verification``),
    or None when the baseline has no components document for it."""
    folder = previous_dir(ctx)
    if folder is None:
        return None
    doc = _read(folder / "repos" / repo / "components.json")
    if not isinstance(doc, dict) or not isinstance(doc.get("components"), list):
        return None
    out = []
    for comp in doc["components"]:
        if isinstance(comp, dict) and comp.get("name"):
            out.append({"name": comp.get("name"), "version": comp.get("version") or "NOASSERTION",
                        "norm_name": comp.get("norm_name") or str(comp.get("name")).lower(),
                        "locations": list(comp.get("locations") or []), "verification": comp.get("verification")})
    return out


def worker_result_of(ctx: RunContext, repo: str) -> Optional[Dict[str, Any]]:
    """The validated worker document of ``repo`` in the baseline (``worker_validated.json``), or None."""
    folder = previous_dir(ctx)
    if folder is None:
        return None
    doc = _read(folder / "repos" / repo / "worker_validated.json")
    return doc if isinstance(doc, dict) and doc.get("schema") == 1 else None


def _baseline_json_path(ctx: RunContext, repo: str) -> Path:
    return ctx.layout.repo_out(repo) / "baseline.json"


def changes(ctx: RunContext, run: RunState, repo: str) -> Dict[str, Any]:
    """What changed in ``repo`` since the baseline: ``{"status", "baseline_commit", "head", "count", "files", "truncated"}``.

    ``status`` is ``no-baseline``, ``unchanged`` (the baseline analysed this very commit), ``listed`` (``files`` holds the
    paths that differ between the two commits), ``commit-not-local`` (the baseline commit is no longer in the repository's
    history, so nothing can be said about the change) or ``unknown`` (git could not tell). The answer is computed once per
    run and kept in ``repos/<repo>/baseline.json``. Only git plumbing is used and nothing in the repository is touched."""
    path = _baseline_json_path(ctx, repo)
    kept = _read(path) if os.path.lexists(str(path)) else None
    head = run.repo(repo).get("head")
    if isinstance(kept, dict) and kept.get("schema") == 1 and kept.get("head") == head and kept.get("run_id") == run.run_id:
        return kept
    base = commit_of(ctx, run, repo)
    result: Dict[str, Any] = {"schema": 1, "run_id": run.run_id, "repo": repo, "status": "no-baseline", "baseline_commit": base,
                              "head": head, "count": 0, "files": [], "truncated": False}
    if base and head:
        if base == head:
            result["status"] = "unchanged"
        else:
            repo_dir = ctx.layout.parent / repo
            try:
                if not gitro.cat_file_exists(repo_dir, base, layout=ctx.layout, env=ctx.env,
                                             timeout=gitro.budget_timeout(ctx)):
                    result["status"] = "commit-not-local"
                else:
                    names = gitro.diff_tree_names(repo_dir, base, head, layout=ctx.layout, env=ctx.env,
                                                  timeout=gitro.budget_timeout(ctx))
                    result.update(status="listed", count=len(names), files=sorted(names)[:MAX_CHANGED_FILES],
                                  truncated=len(names) > MAX_CHANGED_FILES)
            except errors.GitError as exc:
                result["status"] = "unknown"
                result["error"] = exc.message[:200]
    fsio.ensure_dir(ctx.layout.repo_out(repo), root=ctx.layout.out)
    fsio.atomic_write_json(path, result, root=ctx.layout.out)
    return result


def was_clean(ctx: RunContext, repo: str) -> bool:
    """True when the baseline analysed ``repo`` with no modified, deleted or unreadable tracked file (so its commit alone
    says what the tree was)."""
    folder = previous_dir(ctx)
    if folder is None:
        return False
    queue = _read(folder / ".state" / "queue.json")
    for entry in (queue.get("repos") if isinstance(queue, dict) else None) or []:
        if isinstance(entry, dict) and entry.get("name") == repo:
            dirty = entry.get("dirty") or {}
            return not (dirty.get("modified") or dirty.get("deleted") or dirty.get("unknown") or dirty.get("truncated"))
    return False
