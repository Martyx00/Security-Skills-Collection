"""Layout derivation and path safety (contract sections 3.3 and 6.8).

``resolve_layout`` is the only place PARENT (the working directory) and the skill root (from the script's location) are
computed. The only other use of a module's own ``__file__`` is ``context.default_skill_root``, which tests and library
callers use when no script path is at hand.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional, Tuple, Union

from sbomlib import errors, norm
from sbomlib.context import FULL_OUT, OUT_NAMES, Layout

PathLike = Union[str, "os.PathLike[str]"]

OUT_SUBDIRS = (".state", "repos", "review", ".staging", ".cache", ".tmp", "history", "abandoned")


def _real(path: PathLike) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(path)))


def _is_under(path_real: str, root_real: str) -> bool:
    """True when ``path_real`` equals ``root_real`` or lies below it (both already real and normcased)."""
    if path_real == root_real:
        return True
    prefix = root_real if root_real.endswith(os.sep) else root_real + os.sep
    return path_real.startswith(prefix)


def _run_stamp(parent: str, name: str) -> Optional[Tuple[bool, int]]:
    """``(unfinished, stamp)`` of the run recorded in ``parent/<name>/.state/run.json``; None when there is none.

    A folder that is a symlink counts as absent (it is never read). An unreadable ``run.json`` counts as an unfinished run
    so that the real error is reported by the command that reads it. ``stamp`` orders runs: the close time of a finished
    run, the modification time of ``run.json`` for an unfinished one."""
    folder = os.path.join(parent, name)
    run_json = os.path.join(folder, ".state", "run.json")
    try:
        if os.path.islink(folder) or not os.path.isfile(run_json):
            return None
        mtime = os.stat(run_json).st_mtime_ns
    except OSError:
        return None
    try:
        with open(run_json, "rb") as handle:
            data = json.loads(handle.read(4 * 1024 * 1024).decode("utf-8"))
    except (OSError, ValueError):
        return (True, 0)
    if not isinstance(data, dict):
        return (True, 0)
    if not data.get("completed"):
        return (True, mtime)
    closed = data.get("closed_at_ns")
    return (False, closed if isinstance(closed, int) and not isinstance(closed, bool) else mtime)


def pick_out_name(parent: PathLike) -> str:
    """The output folder the commands that carry no mode of their own work on.

    A workspace has two output folders (``sbom-out`` for a full run, ``sbom-out-pilot`` for a pilot run) and at most one
    unfinished run across both (``start`` and ``pilot`` refuse otherwise). The unfinished run wins; with none, the run that
    finished last; with no run at all, ``sbom-out``."""
    best: Optional[Tuple[Tuple[bool, int], str]] = None
    for name in OUT_NAMES:
        stamp = _run_stamp(os.fspath(parent), name)
        if stamp is not None and (best is None or stamp > best[0]):
            best = (stamp, name)
    return best[1] if best is not None else FULL_OUT


def has_unfinished_run(parent: PathLike, out_name: str) -> bool:
    """True when ``parent/<out_name>`` holds a run that is not finished (``start`` resumes it instead of scanning again)."""
    stamp = _run_stamp(os.fspath(parent), out_name)
    return stamp is not None and stamp[0]


def unfinished_elsewhere(parent: PathLike, out_name: str) -> Optional[str]:
    """The name of the other output folder when it holds an unfinished run, else None."""
    for name in OUT_NAMES:
        if name != out_name:
            stamp = _run_stamp(os.fspath(parent), name)
            if stamp is not None and stamp[0]:
                return name
    return None


def resolve_layout(script_file: Path, cwd: Path, out_name: Optional[str] = None) -> Layout:
    """Derive the layout from the location of the script and the working directory, and validate it (no mkdir).

    Two roots (SKILL_MIGRATION 7.1), neither derived from the other:

    1. the skill root is two levels above the script (``<skill>/scripts/<file>``), wherever the skill is installed
       (a project folder, a global folder, a plain copy). It is read-only;
    2. the workspace PARENT is the working directory, resolved. All state and every output goes below
       ``PARENT/sbom-out`` (``PARENT/sbom-out-pilot`` for a pilot run: ``out_name`` names it, ``None`` picks the folder of
       the active run with ``pick_out_name``);
    3. the workspace may not be the skill folder or lie inside it;
    4. neither PARENT nor any ancestor may contain ".git" (file or directory);
    5. an existing PARENT/sbom-out (or sbom-out-pilot) must be a real directory (no symlink).
    """
    try:
        resolved = Path(script_file).resolve()
    except (OSError, RuntimeError) as exc:
        raise errors.LayoutError("cannot resolve the script path: %s" % exc, reason="SCRIPT_PATH")
    parents = resolved.parents
    if len(parents) < 3 or parents[0].name != "scripts":
        raise errors.LayoutError(
            "BAD_SCRIPT_LOCATION: sbom.py must sit in the scripts folder of the skill (<skill>/scripts/sbom.py)",
            reason="BAD_SCRIPT_LOCATION")
    skill = parents[1]
    try:
        parent = Path(cwd).resolve()
    except (OSError, RuntimeError) as exc:
        raise errors.LayoutError("cannot resolve the working directory: %s" % exc, reason="CWD_UNUSABLE")
    if _is_under(_real(parent), _real(skill)):
        raise errors.LayoutError(
            "WORKSPACE_IN_SKILL: the working directory %s is the skill folder or lies inside it; run the command "
            "from the workspace folder, the folder whose subfolders are the repositories" % parent,
            reason="WORKSPACE_IN_SKILL", parent=str(parent))
    for candidate in (parent,) + tuple(parent.parents):
        if os.path.lexists(os.path.join(str(candidate), ".git")):
            raise errors.LayoutError(
                "PARENT_IN_GIT_WORKTREE: the workspace folder %s is inside a git work tree (%s contains .git); "
                "it must be a plain folder whose subfolders are the repositories" % (parent, candidate),
                reason="PARENT_IN_GIT_WORKTREE", parent=str(parent))
    chosen = out_name if out_name is not None else pick_out_name(parent)
    if chosen not in OUT_NAMES:
        raise errors.LayoutError("unknown output folder %r" % (chosen,), reason="UNSAFE_OUTPUT_DIR")
    layout = Layout.for_parent(parent, skill, chosen)
    out = str(layout.out)
    if os.path.lexists(out):
        if os.path.islink(out) or not os.path.isdir(out) or _real(out) != os.path.normcase(out):
            raise errors.LayoutError(
                "UNSAFE_OUTPUT_DIR: %s exists but is not a real directory (symlinks are refused)" % out,
                reason="UNSAFE_OUTPUT_DIR", path=out)
    return layout


def ensure_out_tree(layout: Layout) -> None:
    """Create the output folder and its fixed subdirectories (call only after ``resolve_layout``)."""
    out = str(layout.out)
    if os.path.lexists(out) and (os.path.islink(out) or not os.path.isdir(out)):
        raise errors.LayoutError("UNSAFE_OUTPUT_DIR: %s is not a real directory" % out, reason="UNSAFE_OUTPUT_DIR")
    os.makedirs(out, exist_ok=True)
    if _real(out) != os.path.normcase(out):
        raise errors.LayoutError("UNSAFE_OUTPUT_DIR: %s resolves elsewhere" % out, reason="UNSAFE_OUTPUT_DIR")
    for name in OUT_SUBDIRS:
        sub = os.path.join(out, name)
        if os.path.islink(sub) or (os.path.lexists(sub) and not os.path.isdir(sub)):
            raise errors.LayoutError("UNSAFE_OUTPUT_DIR: %s is not a real directory (symlinks are refused)" % sub,
                                     reason="UNSAFE_OUTPUT_DIR", path=sub)
        os.makedirs(sub, exist_ok=True)


def assert_under(path: PathLike, root: PathLike) -> Path:
    """Return the resolved ``path``; refuse anything that is not strictly a path below (or equal to) ``root``.

    PathEscape when: a component is "..", the real path of the parent directory is not inside the real path of the
    root, or the final component is an existing symlink. ``root`` itself is accepted (for ensure_dir).
    """
    raw = os.fspath(path)
    if "\x00" in raw:
        raise errors.PathEscape("path contains a NUL byte", path=raw)
    candidate = Path(raw)
    if ".." in candidate.parts:
        raise errors.PathEscape("path contains '..': %s" % raw, path=raw)
    if not candidate.is_absolute():
        candidate = Path(os.getcwd()) / candidate
    root_real = _real(root)
    if _real(candidate) == root_real and not os.path.islink(str(candidate)):
        return Path(os.path.realpath(str(candidate)))
    parent_real = os.path.realpath(str(candidate.parent))
    if not _is_under(os.path.normcase(parent_real), root_real):
        raise errors.PathEscape("path escapes the output root: %s" % raw, path=raw, root=str(root))
    final = os.path.join(parent_real, candidate.name)
    if os.path.islink(final):
        raise errors.PathEscape("final path component is a symlink: %s" % raw, path=raw)
    return Path(final)


def safe_join(root: PathLike, *parts: str) -> Path:
    """Join relative ``parts`` below ``root`` and check the result with ``assert_under``."""
    for part in parts:
        if not norm.is_safe_relative_path(part):
            raise errors.PathEscape("unsafe relative path: %r" % (part,), path=part)
    return assert_under(Path(os.fspath(root)).joinpath(*parts), root)
