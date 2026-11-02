"""Staging directory layout and promotion of the validated outputs (contract sections 3.12 and 5.4).

Phase 8 and 9 write below ``sbom-out/.staging/<run_id>/``; the audit validates the *staged* files and only on PASS does
``promote`` move them to their final place with ``os.replace``. On FAIL they stay staged. The staged tree mirrors the final
one::

    .staging/<run_id>/repos/<repo>/{<repo>.sbom.csv, <repo>.spdx.json, <repo>.cdx.json, <repo>.evidence.csv,
                                    candidates_audit.csv[, <repo>.delta.csv]}
    .staging/<run_id>/merged-sbom.csv                 ->  sbom-out/merged-sbom.csv
    .staging/<run_id>/cpe_resolution.csv              ->  sbom-out/cpe_resolution.csv
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

from sbomlib import fsio, paths
from sbomlib.context import RunContext
from sbomlib.state import RunState

MERGED_NAME = "merged-sbom.csv"
RESOLUTION_NAME = "cpe_resolution.csv"
AUDIT_NAME = "candidates_audit.csv"


def repo_file_names(repo: str) -> List[str]:
    """The files phase 8 writes per repository (``<repo>.delta.csv`` only when a baseline exists)."""
    return ["%s.sbom.csv" % repo, "%s.spdx.json" % repo, "%s.cdx.json" % repo, "%s.evidence.csv" % repo, AUDIT_NAME,
            "%s.delta.csv" % repo]


def staged_repo_dir(ctx: RunContext, run: RunState, repo: str) -> Path:
    return ctx.layout.staging(run.run_id) / "repos" / repo


def staged_csv(ctx: RunContext, run: RunState, repo: str) -> Path:
    return staged_repo_dir(ctx, run, repo) / ("%s.sbom.csv" % repo)


def staged_spdx(ctx: RunContext, run: RunState, repo: str) -> Path:
    return staged_repo_dir(ctx, run, repo) / ("%s.spdx.json" % repo)


def staged_cdx(ctx: RunContext, run: RunState, repo: str) -> Path:
    return staged_repo_dir(ctx, run, repo) / ("%s.cdx.json" % repo)


def staged_delta(ctx: RunContext, run: RunState, repo: str) -> Path:
    return staged_repo_dir(ctx, run, repo) / ("%s.delta.csv" % repo)


def staged_merged(ctx: RunContext, run: RunState) -> Path:
    return ctx.layout.staging(run.run_id) / MERGED_NAME


def staged_resolution(ctx: RunContext, run: RunState) -> Path:
    return ctx.layout.staging(run.run_id) / RESOLUTION_NAME


def _is_file(path: Path) -> bool:
    return os.path.isfile(str(path)) and not os.path.islink(str(path))


def staged_files(ctx: RunContext, run: RunState) -> List[Path]:
    """Every staged output that ``promote`` moves, sorted by path: the files of each repository directory, the merged
    CSV and the CPE resolution."""
    root = ctx.layout.staging(run.run_id)
    found: List[Path] = []
    repos_dir = root / "repos"
    if os.path.isdir(str(repos_dir)) and not os.path.islink(str(repos_dir)):
        for repo in sorted(os.listdir(str(repos_dir))):
            directory = repos_dir / repo
            if not os.path.isdir(str(directory)) or os.path.islink(str(directory)):
                continue
            for name in repo_file_names(repo):
                if _is_file(directory / name):
                    found.append(directory / name)
    for path in (root / MERGED_NAME, root / RESOLUTION_NAME):
        if _is_file(path):
            found.append(path)
    return sorted(found, key=lambda p: p.as_posix())


def final_path(ctx: RunContext, run: RunState, staged: Path) -> Path:
    """Where a staged file belongs below ``sbom-out``."""
    relative = Path(staged).relative_to(ctx.layout.staging(run.run_id))
    return ctx.layout.out / relative


def promote(ctx: RunContext, run: RunState) -> Dict[str, str]:
    """Move every staged file to its final place (``os.replace``, so each file appears complete or not at all).

    Returns ``sbom-out``-relative final path -> sha256 of the promoted file. Both ends are checked to lie below
    ``sbom-out`` (``fsio.rename_file``); a final path that is a symlink is refused.
    """
    plan = [(staged, final_path(ctx, run, staged)) for staged in staged_files(ctx, run)]
    for staged, final in plan:                             # refuse before moving anything: no half-promoted tree
        paths.assert_under(staged, ctx.layout.out)
        paths.assert_under(final, ctx.layout.out)
    promoted: Dict[str, str] = {}
    for staged, final in plan:
        fsio.ensure_dir(final.parent, root=ctx.layout.out)
        fsio.rename_file(staged, final, root=ctx.layout.out)
        promoted[ctx.layout.out_rel(final)] = fsio.sha256_file(final)
    return promoted


def cleanup_staging(ctx: RunContext, run: RunState) -> int:
    """After a promotion, remove the run's now empty staging folders (``repos/<repo>/`` and the run folder itself).

    Only empty directories are removed (``os.rmdir``): a file that is still there, for example one the promotion did not
    take, keeps its folder. Symlinks are never followed. Returns the number of directories removed."""
    root = str(ctx.layout.staging(run.run_id))
    removed = 0
    if os.path.islink(root) or not os.path.isdir(root):
        return 0
    for current, dirnames, filenames in os.walk(root, topdown=False):
        if os.path.islink(current):
            continue
        try:
            os.rmdir(current)
            removed += 1
        except OSError:
            pass
    return removed

