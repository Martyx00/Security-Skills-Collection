"""Identity of the installed skill folder (the "pack"): a manifest and one digest over the files that run or instruct.

The audit proves that the tool itself did not change while a run was in progress (contract section 3.13, ``pack_check``).
The Kiro original compared the tracked files of the git repository that held the skill with their blob ids; a skill can be installed
anywhere and need not be a git work tree, so the baseline is a manifest taken by ``start`` instead (``.state/pack.json``,
write-once, moved with the run). Nothing here writes: callers decide where the manifest goes.

The manifest covers ``scripts/``, ``assets/``, ``references/``, ``SKILL.md`` and ``VERSION``: code that runs, data it
reads and text the model is told to follow. ``tests/`` and bytecode caches are left out; they are never needed at run time.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Dict, List

SCHEMA = 1
TOP_DIRS = ("scripts", "assets", "references")
TOP_FILES = ("SKILL.md", "VERSION")
SKIP_DIRS = ("__pycache__",)
MAX_LISTED = 50


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entries(skill_root: Path) -> Dict[str, str]:
    """Relative POSIX path -> sha256 of the bytes (a symlink: ``link:<target>``, never followed)."""
    root = str(skill_root)
    found: Dict[str, str] = {}

    def add(full: str, rel: str) -> None:
        try:
            info = os.lstat(full)
        except OSError:
            found[rel] = "unreadable"
            return
        if stat.S_ISLNK(info.st_mode):
            try:
                found[rel] = "link:" + os.readlink(full)
            except OSError:
                found[rel] = "unreadable"
        elif stat.S_ISREG(info.st_mode):
            try:
                found[rel] = _sha256_file(full)
            except OSError:
                found[rel] = "unreadable"

    for name in TOP_FILES:
        full = os.path.join(root, name)
        if os.path.lexists(full):
            add(full, name)
    for top in TOP_DIRS:
        base = os.path.join(root, top)
        if not os.path.isdir(base):
            continue
        for current, dirs, files in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                if name.endswith((".pyc", ".pyo")):
                    continue
                full = os.path.join(current, name)
                add(full, os.path.relpath(full, root).replace(os.sep, "/"))
    return found


def manifest(skill_root: Path) -> Dict[str, Any]:
    """``{"schema", "digest", "count", "files": {rel: sha256}}`` of the skill folder."""
    files = _entries(Path(skill_root))
    digest = hashlib.sha256()
    for rel in sorted(files):
        digest.update(("%s\0%s\n" % (rel, files[rel])).encode("utf-8", "surrogateescape"))
    return {"schema": SCHEMA, "digest": digest.hexdigest(), "count": len(files), "files": files}


def differences(before: Dict[str, Any], after: Dict[str, Any]) -> List[str]:
    """Human-readable differences between two manifests (at most ``MAX_LISTED`` lines)."""
    old = before.get("files") if isinstance(before.get("files"), dict) else {}
    new = after.get("files") if isinstance(after.get("files"), dict) else {}
    out: List[str] = []
    for rel in sorted(set(old) | set(new)):
        if rel not in new:
            out.append("%s: removed" % rel)
        elif rel not in old:
            out.append("%s: added" % rel)
        elif old[rel] != new[rel]:
            out.append("%s: content changed" % rel)
    if len(out) > MAX_LISTED:
        out = out[:MAX_LISTED] + ["... and %d more" % (len(out) - MAX_LISTED)]
    return out
