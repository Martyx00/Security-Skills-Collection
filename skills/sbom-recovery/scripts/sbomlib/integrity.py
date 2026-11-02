"""Filesystem-only integrity snapshots of the target repositories and their comparison (contract sections 3.13, 4.26).

A snapshot records, per top-level repository, an ``lstat`` walk (directories, ``.git`` and checked-out submodules, never
following a symlink), the SHA-256 of the git metadata files (``index``, ``HEAD``, ``config``, ``packed-refs``,
``info/*`` and ``hooks/*`` of ``.git`` and of every ``.git/modules/**`` git directory), a digest over each index's
entries without their cached stat data, and the current HEAD (reporting only). Object stores (``objects`` and
``lfs/objects``) are recorded at directory level only (contract S19). No ``status`` or ``diff-files`` is ever run: both
execute filters and rewrite the index. The only git calls are ``rev-parse HEAD`` and ``config`` reads through ``gitro``.

Snapshots are written once (temp file plus ``os.link`` through ``fsio.write_once_json``). ``compare`` classifies the
differences between two snapshots as ``violation``, ``host_source_control`` (what the IDE's own Source Control view is
known to cause) or ``paused`` (anything that changed while the run was waiting for the human).
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import enumerate as enumerate_mod
from sbomlib import errors, fsio, gitindex, gitro, model
from sbomlib.context import OUT_NAMES, RunContext

SCHEMA = 1
LABEL_RE = re.compile(r"^(?:init|gate|final|approve-[1-9][0-9]*|stale-[1-9][0-9]*)$")
GIT_META_FILES = ("index", "HEAD", "config", "packed-refs")
GIT_META_DIRS = ("info", "hooks")
LFS_HOOK_NAMES = ("pre-push", "post-checkout", "post-commit", "post-merge")
DIFFERENCE_CAP = 500
MAX_HOOK_READ = 1024 * 1024
EXTERNAL_PREFIX = ".git@external"
CLASS_ORDER = {"violation": 0, "host_source_control": 1, "paused": 2}
CLASS_NOTES = {"host_source_control": "possibly host Source Control (not attributed)",
               "paused": "changed while the run was paused (not attributed)"}
ENTRY_FIELDS = ("type", "size", "mtime_ns", "ctime_ns", "mode", "ino", "link_target")    # entry positions 1..7
TIME_FIELDS = frozenset(("mtime_ns", "ctime_ns", "size"))
INDEX_STAT_FIELDS = frozenset(("size", "mtime_ns", "ctime_ns", "ino", "sha256"))
_LFS_GUARD_RE = re.compile(r'command -v git-lfs >/dev/null 2>&1 \|\| \{ echo >&2 "(?:[^"`$\\\n]|\\n)*"; exit 2; \}')

# kinds of directories during the walk
NORMAL, GITDIR, GITSUB, STORE, LFS, MODULES = range(6)


# --------------------------------------------------------------------------------------------------- small helpers

def _clean(text: str) -> str:
    """Make a path string identical to what a JSON round trip through ``fsio`` gives (undecodable bytes -> ``\\udcXX``)."""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _type_of(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "d"
    if stat.S_ISREG(mode):
        return "f"
    if stat.S_ISLNK(mode):
        return "l"
    return "o"


def _join(rel: str, name: str) -> str:
    return rel + "/" + name if rel else name


def _entry(rel: str, st: os.stat_result, link: Optional[str]) -> List[Any]:
    return [_clean(rel), _type_of(st.st_mode), st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_ino,
            _clean(link) if link is not None else None]


def _check_label(label: str) -> None:
    if not isinstance(label, str) or not LABEL_RE.match(label):
        raise ValueError("unknown snapshot label: %r" % (label,))


def snapshot_path(ctx: RunContext, label: str) -> Path:
    return ctx.layout.state / ("integrity-%s.json" % label)


def parts_path(ctx: RunContext, label: str) -> Path:
    return ctx.layout.state / ("integrity-%s.parts" % label)


def _git_options(ctx: RunContext) -> Dict[str, Any]:
    return {"env": ctx.env, "timeout": gitro.budget_timeout(ctx)}


def is_lfs_stock_hook(name: str, data: bytes) -> bool:
    """True when ``data`` is git-lfs's stock text for the hook ``name``: the shebang, the optional "git-lfs not found"
    guard line (an echo of plain text, no substitutions) and the single ``git lfs <name> "$@"`` line - nothing else."""
    if name not in LFS_HOOK_NAMES:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    lines = [line.strip() for line in text.replace("\r\n", "\n").split("\n") if line.strip()]
    if len(lines) not in (2, 3) or lines[0] != "#!/bin/sh" or lines[-1] != 'git lfs %s "$@"' % name:
        return False
    if len(lines) == 3 and _LFS_GUARD_RE.fullmatch(lines[1]) is None:
        return False
    return True


# --------------------------------------------------------------------------------------------------- snapshot of a repository

def _child_kind(kind: int, name: str, path: str) -> int:
    if kind == NORMAL:
        return GITDIR if name == ".git" else NORMAL
    if kind == GITDIR:
        if name == "objects":
            return STORE
        if name == "lfs":
            return LFS
        if name == "modules":
            return MODULES
        return GITSUB
    if kind == LFS:
        return STORE if name == "objects" else GITSUB
    if kind == MODULES:
        return GITDIR if os.path.lexists(os.path.join(path, "HEAD")) else MODULES
    return kind


def _walk(root: str, prefix: str, root_kind: int, errs: List[str]) -> Tuple[List[List[Any]], List[str]]:
    """``lstat`` walk of ``root``; returns the entries and the relative paths of the git directories to hash.

    ``prefix`` is the relative path of ``root`` itself ("" for a work tree, ``.git@external`` for an external git
    directory). The first git directory of a work tree (``.git`` at depth 0) and every module git directory below
    ``.git/modules`` are returned; a ``.git`` directory nested deeper in the work tree is walked (with its object store
    compressed) but not hashed.
    """
    entries: List[List[Any]] = []
    gitdirs: List[str] = []
    try:
        root_stat = os.lstat(root)
    except OSError as exc:
        errs.append("cannot read %s: %s" % (prefix or ".", type(exc).__name__))
        return entries, gitdirs
    root_entry = _entry(prefix, root_stat, None)
    entries.append(root_entry)
    if root_kind == GITDIR:
        gitdirs.append(_clean(prefix))
    stack: List[Tuple[str, str, int, List[Any]]] = [(root, prefix, root_kind, root_entry)]
    while stack:
        dpath, rel, kind, own = stack.pop()
        try:
            with os.scandir(dpath) as handle:
                children = list(handle)
        except OSError as exc:
            errs.append("cannot read directory %s: %s" % (_clean(rel) or ".", type(exc).__name__))
            continue
        if kind == STORE:
            count = 0
            for child in children:
                try:
                    is_dir = child.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                if not is_dir:
                    count += 1
                    continue
                try:
                    st = child.stat(follow_symlinks=False)
                except OSError as exc:
                    errs.append("cannot stat %s: %s" % (_clean(_join(rel, child.name)), type(exc).__name__))
                    continue
                sub = _entry(_join(rel, child.name), st, None)
                entries.append(sub)
                stack.append((child.path, _join(rel, child.name), STORE, sub))
            own[2] = count
            continue
        for child in children:
            crel = _join(rel, child.name)
            try:
                st = child.stat(follow_symlinks=False)
            except OSError as exc:
                errs.append("cannot stat %s: %s" % (_clean(crel), type(exc).__name__))
                continue
            link = None
            if stat.S_ISLNK(st.st_mode):
                try:
                    link = os.readlink(child.path)
                except OSError:
                    link = None
            entry = _entry(crel, st, link)
            entries.append(entry)
            if stat.S_ISDIR(st.st_mode):
                ckind = _child_kind(kind, child.name, child.path)
                if kind == NORMAL and child.name == ".git" and rel == prefix and root_kind == NORMAL:
                    gitdirs.append(_clean(crel))
                elif kind == MODULES and ckind == GITDIR:
                    gitdirs.append(_clean(crel))
                stack.append((child.path, crel, ckind, entry))
    entries.sort(key=lambda e: e[0])
    return entries, gitdirs


def _open_regular(path: str) -> Optional[int]:
    """A read-only descriptor for a regular file, never following a symlink and never blocking on a FIFO that was
    swapped in after the ``lstat``; None for anything else."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    return fd


def _read_regular(path: str, limit: Optional[int] = None) -> Optional[bytes]:
    """The bytes of a regular file (at most ``limit`` when given); None when it is not one or cannot be read."""
    fd = _open_regular(path)
    if fd is None:
        return None
    try:
        chunks: List[bytes] = []
        remaining = limit
        while remaining is None or remaining > 0:
            chunk = os.read(fd, 1024 * 1024 if remaining is None else min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            if remaining is not None:
                remaining -= len(chunk)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def _sha256_regular(path: str) -> Optional[str]:
    fd = _open_regular(path)
    if fd is None:
        return None
    digest = hashlib.sha256()
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    return digest.hexdigest()


def _hash_path(path: str) -> Optional[str]:
    """SHA-256 of a regular file; of ``symlink:<target>`` for a symlink; of ``type:<x>`` for anything else; None if absent."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISREG(st.st_mode):
        return _sha256_regular(path)
    if stat.S_ISLNK(st.st_mode):
        try:
            return fsio.sha256_bytes(("symlink:" + os.readlink(path)).encode("utf-8", "surrogateescape"))
        except OSError:
            return None
    return fsio.sha256_bytes(("type:" + _type_of(st.st_mode)).encode("ascii"))


def _hash_git_metadata(root: str, gitdir_rel: str, git_meta: Dict[str, Optional[str]],
                       index_entries: Dict[str, Optional[str]], lfs_hooks: List[str], errs: List[str]) -> None:
    """Hash the metadata files of one git directory (``gitdir_rel`` is relative to ``root``)."""
    base = os.path.join(root, *[part for part in gitdir_rel.split("/") if part]) if gitdir_rel else root
    for name in GIT_META_FILES:
        key = _clean(_join(gitdir_rel, name))
        path = os.path.join(base, name)
        if name == "index":
            try:
                st = os.lstat(path)
            except OSError:
                git_meta[key] = None
                continue
            if not stat.S_ISREG(st.st_mode):
                git_meta[key] = _hash_path(path)
                index_entries[key] = None
                continue
            data = _read_regular(path)
            if data is None:
                errs.append("cannot read %s" % key)
                git_meta[key] = None
                continue
            git_meta[key] = fsio.sha256_bytes(data)
            index_entries[key] = gitindex.entries_digest(data)
        else:
            git_meta[key] = _hash_path(path)
    for sub in GIT_META_DIRS:
        directory = os.path.join(base, sub)
        try:
            with os.scandir(directory) as handle:
                names = sorted(child.name for child in handle)
        except OSError:
            continue
        for name in names:
            key = _clean(_join(_join(gitdir_rel, sub), name))
            path = os.path.join(directory, name)
            git_meta[key] = _hash_path(path)
            if sub == "hooks" and name in LFS_HOOK_NAMES:
                try:
                    small = os.lstat(path).st_size <= MAX_HOOK_READ
                except OSError:
                    continue
                data = _read_regular(path, MAX_HOOK_READ) if small else None
                if data is not None and is_lfs_stock_hook(name, data):
                    lfs_hooks.append(key)


def _external_gitdir(root: str) -> Optional[str]:
    """The directory a ``.git`` file (``gitdir: <path>``) points to, when it exists."""
    raw = _read_regular(os.path.join(root, ".git"), 4096)
    if raw is None:
        return None
    head = raw.decode("utf-8", "surrogateescape")
    first = head.splitlines()[0] if head.splitlines() else ""
    if not first.startswith("gitdir:"):
        return None
    target = first[len("gitdir:"):].strip()
    if not target:
        return None
    full = os.path.normpath(os.path.join(root, target))
    return full if os.path.isdir(full) else None


def _fsmonitor(ctx: RunContext, repo: Path, errs: List[str]) -> bool:
    """Whether ``core.fsmonitor`` is configured, read per scope WITHOUT gitro's command-scope override."""
    for scope in ("local", "global", "system"):
        try:
            value = gitro.config_get(repo, "core.fsmonitor", layout=ctx.layout, scope=scope, **_git_options(ctx))
        except errors.SbomError as exc:
            errs.append("core.fsmonitor (%s) could not be read: %s" % (scope, exc.code))
            continue
        if value is not None:
            return value.strip().lower() not in ("", "false", "no", "off", "0")
    return False


def _snapshot_repo(ctx: RunContext, name: str) -> Dict[str, Any]:
    root = str(ctx.layout.parent / name)
    errs: List[str] = []
    entries, gitdirs = _walk(root, "", NORMAL, errs)
    git_meta: Dict[str, Optional[str]] = {}
    index_entries: Dict[str, Optional[str]] = {}
    lfs_hooks: List[str] = []
    for gitdir in gitdirs:
        _hash_git_metadata(root, gitdir, git_meta, index_entries, lfs_hooks, errs)
    if not gitdirs:                                           # `.git` is a file: hash it and follow it
        git_meta[".git"] = _hash_path(os.path.join(root, ".git"))
        external = _external_gitdir(root)
        if external is not None:
            ext_entries, ext_gitdirs = _walk(external, EXTERNAL_PREFIX, GITDIR, errs)
            entries.extend(ext_entries)
            entries.sort(key=lambda e: e[0])
            for gitdir in ext_gitdirs:
                relative = gitdir[len(EXTERNAL_PREFIX):].lstrip("/")
                _hash_external(external, EXTERNAL_PREFIX, relative, git_meta, index_entries, lfs_hooks, errs)
    head: Optional[str] = None
    try:
        head = gitro.rev_parse_head(ctx.layout.parent / name, layout=ctx.layout, **_git_options(ctx))
    except errors.SbomError as exc:
        errs.append("HEAD could not be read: %s" % exc.code)
    fsmonitor = _fsmonitor(ctx, ctx.layout.parent / name, errs)
    return {"head": head, "entries": entries, "git_meta": git_meta, "index_entries": index_entries,
            "lfs_hooks": sorted(lfs_hooks), "fsmonitor": fsmonitor, "errors": sorted(errs)[:50]}


def _hash_external(external_root: str, prefix: str, relative: str, git_meta: Dict[str, Optional[str]],
                   index_entries: Dict[str, Optional[str]], lfs_hooks: List[str], errs: List[str]) -> None:
    """Hash the metadata of an external git directory; keys are prefixed with ``.git@external/``."""
    scratch_meta: Dict[str, Optional[str]] = {}
    scratch_index: Dict[str, Optional[str]] = {}
    scratch_hooks: List[str] = []
    _hash_git_metadata(external_root, relative, scratch_meta, scratch_index, scratch_hooks, errs)
    for key, value in scratch_meta.items():
        git_meta[prefix + "/" + key] = value
    for key, value in scratch_index.items():
        index_entries[prefix + "/" + key] = value
    lfs_hooks.extend(prefix + "/" + key for key in scratch_hooks)


def _parent_entries(ctx: RunContext) -> List[Dict[str, Any]]:
    """The top-level entries of the workspace folder other than the output folders and the dot-entries.

    A dot-entry is never a repository (``enumerate`` skips it) and is where an agent host keeps its own files: the folder a
    skill is installed in (a project's hidden host folder), settings, caches. A host can create or remove one in
    the middle of a run, which says nothing about the repositories, so none is recorded or compared.
    """
    items: List[Dict[str, Any]] = []
    try:
        with os.scandir(str(ctx.layout.parent)) as handle:
            children = list(handle)
    except OSError:
        return items
    for child in children:
        if child.name in OUT_NAMES or child.name.startswith("."):
            continue
        try:
            st = child.stat(follow_symlinks=False)
        except OSError:
            continue
        items.append({"name": _clean(child.name), "type": _type_of(st.st_mode), "size": st.st_size,
                      "mtime_ns": st.st_mtime_ns})
    items.sort(key=lambda item: item["name"])
    return items


def _repo_names(ctx: RunContext) -> List[str]:
    return [entry.name for entry in enumerate_mod.scan_parent(ctx.layout) if entry.kind == "repo"]


def _header(ctx: RunContext, label: str) -> Dict[str, Any]:
    return {"schema": SCHEMA, "label": label, "run_id": ctx.run_id, "taken_at": ctx.now_iso(),
            "ctime_reliable": os.name != "nt"}


def take(ctx: RunContext, label: str) -> Dict[str, Any]:
    """An in-memory snapshot (contract section 4.26); writes nothing."""
    snap = _header(ctx, label)
    snap["parent_entries"] = _parent_entries(ctx)
    snap["repos"] = {_clean(name): _snapshot_repo(ctx, name) for name in _repo_names(ctx)}
    return snap


def snapshot(ctx: RunContext, label: str, *, extra: Optional[Dict[str, Any]] = None,
             resumable: bool = False) -> Optional[str]:
    """Write ``.state/integrity-<label>.json`` once; returns its sha256 (None when a resumable walk yielded).

    ``FileExistsError`` when the file exists (callers treat that as "already taken"). With ``resumable=True`` the walk
    goes repository by repository into ``.state/integrity-<label>.parts/<repo>.json`` and returns None as soon as
    ``ctx.should_yield()`` says the call is out of time (after at least one repository per call); the next call
    skips repositories whose part exists and, when all exist, assembles the write-once file and removes the parts.
    """
    _check_label(label)
    target = snapshot_path(ctx, label)
    parts = parts_path(ctx, label)
    if os.path.lexists(str(target)):
        if os.path.lexists(str(parts)):
            fsio.remove_tree(parts, root=ctx.layout.out)
        raise FileExistsError("%s already exists" % target.name)
    if not resumable:
        snap = take(ctx, label)
        if extra is not None:
            snap["extra"] = extra
        return fsio.write_once_json(target, snap, root=ctx.layout.out)
    return _snapshot_resumable(ctx, label, extra, target, parts)


def _snapshot_resumable(ctx: RunContext, label: str, extra: Optional[Dict[str, Any]], target: Path,
                        parts: Path) -> Optional[str]:
    fsio.ensure_dir(parts, root=ctx.layout.out)
    header_file = parts / ".header.json"
    if os.path.lexists(str(header_file)):
        header = fsio.read_json(header_file)
        if not isinstance(header, dict) or header.get("label") != label or not isinstance(header.get("repos"), list):
            raise errors.StateError("%s is not a snapshot header" % header_file.name, path=str(header_file))
    else:
        header = _header(ctx, label)
        header["repos"] = [_clean(name) for name in _repo_names(ctx)]
        fsio.atomic_write_json(header_file, header, root=ctx.layout.out)
    current = {_clean(name): name for name in _repo_names(ctx)}
    wanted = [name for name in header["repos"]]
    pending = [name for name in wanted if name in current and not os.path.lexists(str(parts / (name + ".json")))]
    for index, name in enumerate(pending):
        data = _snapshot_repo(ctx, current[name])
        fsio.atomic_write_json(parts / (name + ".json"), data, root=ctx.layout.out)
        if index + 1 < len(pending) and ctx.should_yield():
            return None
    repos: Dict[str, Any] = {}
    for name in wanted:
        part = parts / (name + ".json")
        if name in current and os.path.lexists(str(part)):
            repos[name] = fsio.read_json(part)
    snap = {key: header[key] for key in ("schema", "label", "run_id", "taken_at", "ctime_reliable")}
    snap["parent_entries"] = _parent_entries(ctx)
    snap["repos"] = repos
    if extra is not None:
        snap["extra"] = extra
    sha = fsio.write_once_json(target, snap, root=ctx.layout.out)
    fsio.remove_tree(parts, root=ctx.layout.out)
    return sha


def load_snapshot(ctx: RunContext, label: str) -> Optional[Dict[str, Any]]:
    """The written snapshot ``label``; None when absent; ``StateError`` when it does not parse or has another schema."""
    path = snapshot_path(ctx, label)
    if not os.path.lexists(str(path)):
        return None
    data = fsio.read_json(path)
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("repos"), dict):
        raise errors.StateError("%s is not an integrity snapshot" % path.name, path=str(path))
    return data


# --------------------------------------------------------------------------------------------------- comparison

def _parent_of(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def _diff_repo(a: Dict[str, Any], b: Dict[str, Any], use_ctime: bool) -> Dict[str, Dict[str, Any]]:
    """Raw differences of one repository: path -> {"change", "fields", "type"}."""
    found: Dict[str, Dict[str, Any]] = {}
    ea = {e[0]: e for e in a.get("entries", [])}
    eb = {e[0]: e for e in b.get("entries", [])}
    for path in set(ea) | set(eb):
        old, new = ea.get(path), eb.get(path)
        if old is None:
            found[path] = {"change": "added", "fields": [], "type": new[1]}
        elif new is None:
            found[path] = {"change": "removed", "fields": [], "type": old[1]}
        else:
            fields = [name for position, name in enumerate(ENTRY_FIELDS, 1)
                      if old[position] != new[position] and (use_ctime or name != "ctime_ns")]
            if fields:
                found[path] = {"change": "modified", "fields": fields, "type": new[1]}
    for key, field_name in (("git_meta", "sha256"), ("index_entries", "entries_sha256")):
        ma, mb = a.get(key) or {}, b.get(key) or {}
        for path in set(ma) | set(mb):
            if ma.get(path) != mb.get(path):
                item = found.get(path)
                if item is None:
                    item = found[path] = {"change": "modified", "fields": [], "type": (eb.get(path) or ea.get(path) or [0, "f"])[1]}
                if field_name not in item["fields"]:
                    item["fields"].append(field_name)
    return found


def _classify_repo(found: Dict[str, Dict[str, Any]], a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, str]:
    """``violation`` or ``host_source_control`` per path of one repository (attributed window)."""
    fsmonitor = bool(a.get("fsmonitor")) and bool(b.get("fsmonitor"))
    stock_hooks = set(b.get("lfs_hooks") or [])
    index_a, index_b = a.get("index_entries") or {}, b.get("index_entries") or {}
    classes: Dict[str, str] = {}

    def own(path: str, item: Dict[str, Any]) -> bool:
        if path == ".git/lfs" or path.startswith(".git/lfs/"):
            return True
        if path == ".git/index.lock":
            return True
        if path == ".git/index":
            digest = index_a.get(path)
            return (item["change"] == "modified" and digest is not None and digest == index_b.get(path)
                    and set(item["fields"]) <= INDEX_STAT_FIELDS)
        if item["change"] == "added" and path in stock_hooks and path.startswith(".git/hooks/") \
                and path.rsplit("/", 1)[1] in LFS_HOOK_NAMES:
            return True
        if fsmonitor and (path == ".git/fsmonitor--daemon" or path.startswith(".git/fsmonitor--daemon/")
                          or path == ".git/fsmonitor--daemon.ipc"):
            return True
        return False

    kids_by_parent: Dict[str, List[str]] = {}
    for path in found:
        if path:
            kids_by_parent.setdefault(_parent_of(path), []).append(path)

    for path in sorted(found, key=lambda p: (-p.count("/"), p)):
        item = found[path]
        if own(path, item):
            classes[path] = "host_source_control"
            continue
        if item["type"] == "d" and item["change"] == "modified" and set(item["fields"]) <= TIME_FIELDS \
                and (path == ".git" or (path.startswith(".git/") and not path.startswith(".git/modules"))):
            kids = kids_by_parent.get(path, [])
            if all(classes.get(kid) == "host_source_control" for kid in kids) and (kids or path == ".git"):
                classes[path] = "host_source_control"
                continue
        classes[path] = "violation"
    return classes


def _compare_parent(a: Dict[str, Any], b: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Gained, lost or retyped top-level entries of the workspace folder."""
    ea = {e["name"]: e for e in a.get("parent_entries", [])}
    eb = {e["name"]: e for e in b.get("parent_entries", [])}
    out: List[Dict[str, Any]] = []
    for name in sorted(set(ea) | set(eb)):
        if name not in ea:
            out.append({"repo": None, "path": name, "change": "added", "fields": []})
        elif name not in eb:
            out.append({"repo": None, "path": name, "change": "removed", "fields": []})
        elif ea[name]["type"] != eb[name]["type"]:
            out.append({"repo": None, "path": name, "change": "modified", "fields": ["type"]})
    return out


def compare(a: Dict[str, Any], b: Dict[str, Any], *, window: str, kind: str) -> Dict[str, Any]:
    """Compare snapshot ``a`` (earlier) with ``b`` (later) for one window.

    ``kind`` ``attributed``: every difference is a ``violation`` or ``host_source_control``. ``pause``: every difference
    is ``paused`` ("changed while the run was paused (not attributed)"). The result has the exact counts and at most
    ``DIFFERENCE_CAP`` differences (violations first, then ``differences_truncated``), plus ``head_changes``.
    """
    if kind not in ("attributed", "pause"):
        raise ValueError("kind must be attributed or pause")
    use_ctime = bool(a.get("ctime_reliable", True)) and bool(b.get("ctime_reliable", True))
    diffs: List[Dict[str, Any]] = []
    head_changes: List[Dict[str, Any]] = []
    ra_all, rb_all = a.get("repos") or {}, b.get("repos") or {}
    for item in _compare_parent(a, b):
        item["class"] = "violation" if kind == "attributed" else "paused"
        diffs.append(item)
    for name in sorted(set(ra_all) | set(rb_all)):
        old, new = ra_all.get(name), rb_all.get(name)
        if old is None or new is None:
            diffs.append({"repo": name, "path": "", "change": "added" if old is None else "removed", "fields": ["repository"],
                          "class": "violation" if kind == "attributed" else "paused"})
            continue
        found = _diff_repo(old, new, use_ctime)
        classes = _classify_repo(found, old, new) if kind == "attributed" else {}
        for path in sorted(found):
            item = {"repo": name, "path": path, "change": found[path]["change"], "fields": list(found[path]["fields"]),
                    "class": classes.get(path, "paused")}
            if kind == "pause":
                item["head"] = old.get("head")
            diffs.append(item)
        if old.get("head") != new.get("head"):
            head_changes.append({"window": window, "kind": kind, "repo": name, "before": old.get("head"),
                                 "after": new.get("head")})
    counts = {"violation": 0, "host_source_control": 0, "paused": 0}
    for item in diffs:
        counts[item["class"]] += 1
        if item["class"] in CLASS_NOTES:
            item["note"] = CLASS_NOTES[item["class"]]
    diffs.sort(key=lambda d: (CLASS_ORDER[d["class"]], d["repo"] or "", d["path"]))
    result: Dict[str, Any] = {"window": window, "kind": kind, "violations": counts["violation"],
                              "host_source_control": counts["host_source_control"], "paused": counts["paused"],
                              "differences": diffs[:DIFFERENCE_CAP], "head_changes": head_changes}
    if len(diffs) > DIFFERENCE_CAP:
        result["differences_truncated"] = len(diffs) - DIFFERENCE_CAP
    return result


def _expected_labels(run: Any) -> List[str]:
    labels = ["init"]
    approvals = run.data.get("approvals") or []
    if run.gate != "none" or approvals or (run.data.get("review") or {}).get("path"):
        labels.append("gate")
    for approval in approvals:
        n = int(approval.get("n") or 0)
        labels.append("approve-%d" % n)
        if approval.get("stale"):
            labels.append("stale-%d" % n)
    if run.completed or run.phase in ("audit", "done"):
        labels.append("final")
    return labels


def _window_kind(first: str, second: str) -> str:
    if first == "gate" and second.startswith("approve-"):
        return "pause"
    if first.startswith("stale-") and second.startswith("approve-"):
        return "pause"
    return "attributed"


def compare_run(ctx: RunContext, run: Any) -> Dict[str, Any]:
    """The IntegrityResult over the run's snapshot chain (contract section 4.26).

    Windows: init->gate attributed; gate->approve-1 pause; approve-n->stale-n attributed; stale-n->approve-(n+1) pause;
    approve-last->final attributed. A snapshot the run should have but does not is an error and the verdict is FAIL.
    ``verdict`` is PASS iff there is no violation, no HEAD change and no gained or lost top-level entry in an attributed
    window and no snapshot is missing.
    """
    labels = _expected_labels(run)
    problems: List[str] = []
    windows: List[Dict[str, Any]] = []
    head_changes: List[Dict[str, Any]] = []
    reliable = True
    loaded_any = False
    previous: Optional[Dict[str, Any]] = None
    previous_label = ""
    for label in labels:                                # at most two snapshots are in memory at a time
        current = load_snapshot(ctx, label)
        if current is None:
            problems.append("integrity-%s.json is missing" % label)
            continue
        loaded_any = True
        reliable = reliable and bool(current.get("ctime_reliable", True))
        if previous is not None:
            result = compare(previous, current, window="%s->%s" % (previous_label, label),
                             kind=_window_kind(previous_label, label))
            head_changes.extend(result.get("head_changes") or [])
            windows.append(result)
        previous, previous_label = current, label
    failed = bool(problems) or any(w["kind"] == "attributed" and w["violations"] for w in windows) \
        or any(h["kind"] == "attributed" for h in head_changes)
    if not loaded_any:
        reliable = os.name != "nt"
    result_dict: Dict[str, Any] = {"verdict": "FAIL" if failed else "PASS", "ctime_reliable": reliable, "windows": windows,
                                   "head_changes": head_changes}
    if problems:
        result_dict["errors"] = problems
    warnings: List[Dict[str, Any]] = []
    if failed:
        attributed = sum(w["violations"] for w in windows if w["kind"] == "attributed")
        moved = sum(1 for h in head_changes if h["kind"] == "attributed")
        warnings.append(model.warning(
            "ACTION_REQUIRED", "INTEGRITY_VIOLATION",
            "The unchanged-targets check failed: %d changed path(s) and %d HEAD change(s) in windows the run is "
            "responsible for, %d missing snapshot(s)." % (attributed, moved, len(problems))))
    seen_moves = set()
    for change in head_changes:
        if change.get("kind") != "pause" or change.get("repo") in seen_moves:
            continue
        seen_moves.add(change.get("repo"))
        warnings.append(model.warning(
            "ACTION_REQUIRED", "HEAD_MOVED_WHILE_PAUSED",
            "HEAD of %s moved from %s to %s while the run waited for approval; the outputs describe %s, the commit that was "
            "analysed, and not the new HEAD. Run again to cover it." % (
                change.get("repo"), str(change.get("before") or "no commit")[:12], str(change.get("after") or "no commit")[:12],
                str(change.get("before") or "no commit")[:12]), change.get("repo")))
    if warnings:
        result_dict["warnings"] = warnings
    return result_dict


# --------------------------------------------------------------------------------------------------- the pack itself

def pack_check(ctx: RunContext, run: Any = None) -> Dict[str, Any]:
    """``{"status": "pass"|"fail"|"skipped", "errors": [...], "pack_commit": None, "pack_digest": hex|None}``.

    The skill folder (scripts, assets, references, SKILL.md, VERSION) is hashed again and compared with the manifest that
    ``start`` took (``.state/pack.json``, see ``sbomlib.pack``). ``skipped`` (with an INFORMATIONAL ``PACK_NOT_RECORDED``
    warning) when the run has no manifest, for example a run started by an older build. Nothing is written.
    """
    from sbomlib import pack as pack_mod
    result: Dict[str, Any] = {"status": "skipped", "errors": [], "pack_commit": None, "pack_digest": None, "warnings": []}
    path = ctx.layout.state / "pack.json"
    try:
        recorded = fsio.read_json(path) if os.path.lexists(str(path)) else None
    except errors.StateError as exc:
        result["status"] = "fail"
        result["errors"] = ["the recorded pack manifest cannot be read: %s" % exc.message[:200]]
        return result
    if not isinstance(recorded, dict) or not isinstance(recorded.get("files"), dict):
        result["warnings"].append(model.warning("INFORMATIONAL", "PACK_NOT_RECORDED",
                                                "the run has no pack manifest, so the unchanged-pack check was skipped"))
        return result
    current = pack_mod.manifest(ctx.layout.skill)
    result["pack_digest"] = current["digest"]
    if current["digest"] == recorded.get("digest"):
        result["status"] = "pass"
        return result
    result["status"] = "fail"
    result["errors"] = pack_mod.differences(recorded, current) or ["the skill folder differs from the manifest taken at start"]
    return result
