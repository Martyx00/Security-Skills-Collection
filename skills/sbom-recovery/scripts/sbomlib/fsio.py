"""Atomic and write-once file output, JSON helpers (contract section 3.3).

Every writing function takes ``root=`` and calls ``paths.assert_under`` first, so nothing outside the root is ever
touched. Writers create missing parent directories below the root. Files are written to a temp file in the target
directory, fsynced and moved into place with ``os.replace`` so a reader never sees a partial file.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import shutil
import stat
from pathlib import Path
from typing import Any, List, Union

from sbomlib import errors, paths

PathLike = Union[str, "os.PathLike[str]"]
_BINARY = getattr(os, "O_BINARY", 0)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: PathLike) -> str:
    digest = hashlib.sha256()
    with open(os.fspath(path), "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def dumps_pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def dumps_compact(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _encode(text: str) -> bytes:
    # lone surrogates (undecodable on-disk names) become literal \udcXX text instead of invalid UTF-8
    return text.encode("utf-8", "backslashreplace")


def _temp_name(final: Path) -> Path:
    return final.parent / (".%s.%d.%s.tmp" % (final.name, os.getpid(), secrets.token_hex(4)))


def _fsync_dir(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_temp(final: Path, data: bytes) -> Path:
    os.makedirs(str(final.parent), exist_ok=True)
    temp = _temp_name(final)
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        _unlink_quiet(temp)
        raise
    os.close(fd)
    return temp


def _unlink_quiet(path: Path) -> None:
    try:
        os.unlink(str(path))
    except OSError:
        pass


def atomic_write_bytes(path: PathLike, data: bytes, *, root: PathLike) -> str:
    """Temp file in the same directory, fsync, ``os.replace``; returns the sha256 of ``data``."""
    final = paths.assert_under(path, root)
    temp = _write_temp(final, data)
    try:
        os.replace(str(temp), str(final))
    except BaseException:
        _unlink_quiet(temp)
        raise
    _fsync_dir(final.parent)
    return sha256_bytes(data)


def atomic_write_text(path: PathLike, text: str, *, root: PathLike, newline: str = "\n") -> str:
    if newline != "\n":
        # normalise first: text that already holds CRLF (or a lone CR) must not become CR CR LF
        text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", newline)
    return atomic_write_bytes(path, _encode(text), root=root)


def atomic_write_json(path: PathLike, obj: Any, *, root: PathLike) -> str:
    return atomic_write_text(path, dumps_pretty(obj), root=root)


def write_once_bytes(path: PathLike, data: bytes, *, root: PathLike) -> str:
    """Create ``path`` with ``data`` unless it exists (``FileExistsError``).

    The content is written to a temp file and hard-linked into place, so the file appears complete or not at all.
    On a filesystem without hard links the fallback is ``O_CREAT|O_EXCL`` plus write (the file is removed again if
    the write fails). Readers of write-once files verify them and raise StateError when they do not parse.
    """
    final = paths.assert_under(path, root)
    if os.path.lexists(str(final)):
        raise FileExistsError(errno.EEXIST, "file exists", str(final))
    temp = _write_temp(final, data)
    try:
        try:
            os.link(str(temp), str(final))
        except FileExistsError:
            raise
        except OSError:
            _exclusive_create(final, data)
    finally:
        _unlink_quiet(temp)
    _fsync_dir(final.parent)
    return sha256_bytes(data)


def _exclusive_create(final: Path, data: bytes) -> None:
    fd = os.open(str(final), os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, 0o644)
    try:
        try:
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        _unlink_quiet(final)
        raise


def write_once_json(path: PathLike, obj: Any, *, root: PathLike) -> str:
    return write_once_bytes(path, _encode(dumps_pretty(obj)), root=root)


def open_append(path: PathLike) -> int:
    """Open ``path`` for appending (creating it) and return the descriptor; ``PathEscape`` when the file is not ours.

    The symlink check of ``paths.assert_under`` is not enough for an append: the existing inode is written in place, so
    a hard link planted at ``path`` (``ln target-file sbom-out/.state/audit.jsonl``) would append into the other file.
    The descriptor is therefore opened with ``O_NOFOLLOW`` and then checked with ``fstat``: only a regular file with
    a single link is accepted. Atomic writers are not affected because ``os.replace`` creates a new inode.
    """
    # O_NONBLOCK: opening a planted FIFO for writing must fail at once (ENXIO) instead of blocking for a reader
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | _BINARY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(os.fspath(path), flags, 0o644)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.ENXIO):
            raise errors.PathEscape("%s is a symbolic link or not a regular file" % os.fspath(path),
                                    path=os.fspath(path)) from exc
        raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
            raise errors.PathEscape("%s is not a regular file with a single link; refusing to append to it"
                                    % os.fspath(path), path=os.fspath(path))
    except BaseException:
        os.close(fd)
        raise
    return fd


def append_jsonl(path: PathLike, obj: Any, *, root: PathLike) -> None:
    """One ``dumps_compact`` line, appended with a single ``os.write`` on an ``O_APPEND`` descriptor
    (``open_append``: a symlink, a non-regular file or a file with several hard links raises ``PathEscape``)."""
    final = paths.assert_under(path, root)
    data = _encode(dumps_compact(obj) + "\n")
    os.makedirs(str(final.parent), exist_ok=True)
    fd = open_append(final)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    finally:
        os.close(fd)


def remove_file(path: PathLike, *, root: PathLike) -> bool:
    final = paths.assert_under(path, root)
    try:
        os.unlink(str(final))
    except FileNotFoundError:
        return False
    return True


def remove_tree(path: PathLike, *, root: PathLike) -> bool:
    """Remove a directory tree below ``root`` (symlinks inside are unlinked, never followed)."""
    final = paths.assert_under(path, root)
    if not os.path.lexists(str(final)):
        return False
    if os.path.isdir(str(final)) and not os.path.islink(str(final)):
        shutil.rmtree(str(final))
    else:
        os.unlink(str(final))
    return True


def ensure_dir(path: PathLike, *, root: PathLike) -> None:
    final = paths.assert_under(path, root)
    os.makedirs(str(final), exist_ok=True)


def move_into(src: PathLike, dest_dir: PathLike, *, root: PathLike) -> Path:
    """``os.replace(src, dest_dir/src.name)``; both under ``root``. Returns the new path."""
    source = paths.assert_under(src, root)
    target_dir = paths.assert_under(dest_dir, root)
    os.makedirs(str(target_dir), exist_ok=True)
    target = paths.assert_under(target_dir / source.name, root)
    os.replace(str(source), str(target))
    return target


def rename_file(src: PathLike, dest: PathLike, *, root: PathLike) -> None:
    """``os.replace(src, dest)`` for two paths below ``root`` (``FileNotFoundError`` when ``src`` is gone)."""
    source = paths.assert_under(src, root)
    target = paths.assert_under(dest, root)
    os.replace(str(source), str(target))


def read_json(path: PathLike) -> Any:
    """UTF-8 strict JSON; ``StateError`` (with path and line) when the file does not parse."""
    try:
        with open(os.fspath(path), encoding="utf-8") as handle:
            text = handle.read()
    except UnicodeDecodeError as exc:
        raise errors.StateError("%s is not valid UTF-8" % os.fspath(path), path=os.fspath(path), line=None) from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        line = getattr(exc, "lineno", None)
        raise errors.StateError("%s is not valid JSON (line %s)" % (os.fspath(path), line), path=os.fspath(path),
                                line=line) from exc


def read_jsonl(path: PathLike) -> List[Any]:
    """One JSON value per non-blank line; ``StateError`` with the line number on a malformed line."""
    items: List[Any] = []
    try:
        with open(os.fspath(path), encoding="utf-8") as handle:
            lines = handle.read().split("\n")
    except UnicodeDecodeError as exc:
        raise errors.StateError("%s is not valid UTF-8" % os.fspath(path), path=os.fspath(path), line=None) from exc
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except ValueError as exc:
            raise errors.StateError("%s line %d is not valid JSON" % (os.fspath(path), number),
                                    path=os.fspath(path), line=number) from exc
    return items
