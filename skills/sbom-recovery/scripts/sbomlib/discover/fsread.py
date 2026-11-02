"""Read-only access to the files of one target repository (contract G13, section 6.8).

Target files are opened only with ``O_RDONLY | O_NOFOLLOW`` after an ``lstat``; only regular files are read, a symbolic
link is never followed (neither as the file itself nor as one of its leading directories); text reads stop at 2 MiB,
binary hashes at 256 MiB. Nothing here writes.
"""
from __future__ import annotations

import hashlib
import os
import stat
from typing import Dict, List, Optional

MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_HASH_BYTES = 256 * 1024 * 1024
_CACHE_FILE_LIMIT = 256 * 1024
_CACHE_TOTAL_LIMIT = 48 * 1024 * 1024
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)


def safe_tracked_path(path: str) -> bool:
    """A tracked path that may be joined below the repository directory (no absolute path, no ``..``, no ``.git``)."""
    if not path or path.startswith("/") or path.startswith("\\") or "\x00" in path:
        return False
    for segment in path.split("/"):
        if segment in ("", ".", "..") or segment.lower() == ".git":
            return False
    return True


class RepoFS:
    """Cached, bounded, symlink-safe reader rooted at one repository directory."""

    def __init__(self, root: str) -> None:
        self.root = str(root)
        self._dirs: Dict[str, bool] = {}
        self._bytes: Dict[str, Optional[bytes]] = {}
        self._text: Dict[str, Optional[str]] = {}
        self._cached_total = 0
        self.oversize: List[str] = []
        self.unreadable: List[str] = []

    # ------------------------------------------------------------------ metadata
    def _leading_dirs_real(self, rel: str) -> bool:
        prefix = ""
        for part in rel.split("/")[:-1]:
            prefix = prefix + "/" + part if prefix else part
            known = self._dirs.get(prefix)
            if known is None:
                try:
                    known = stat.S_ISDIR(os.lstat(os.path.join(self.root, prefix)).st_mode)
                except OSError:
                    known = False
                self._dirs[prefix] = known
            if not known:
                return False
        return True

    def lstat(self, rel: str) -> Optional[os.stat_result]:
        """``lstat`` of a regular file below the root, else None (missing, symlink, directory, unsafe path)."""
        if not safe_tracked_path(rel) or not self._leading_dirs_real(rel):
            return None
        try:
            info = os.lstat(os.path.join(self.root, rel))
        except OSError:
            return None
        return info if stat.S_ISREG(info.st_mode) else None

    def is_symlink(self, rel: str) -> bool:
        if not safe_tracked_path(rel) or not self._leading_dirs_real(rel):
            return False
        try:
            return stat.S_ISLNK(os.lstat(os.path.join(self.root, rel)).st_mode)
        except OSError:
            return False

    def exists(self, rel: str) -> bool:
        return self.lstat(rel) is not None

    # ------------------------------------------------------------------ reading
    def read_bytes(self, rel: str, limit: int = MAX_TEXT_BYTES) -> Optional[bytes]:
        """The bytes of a regular file of at most ``limit`` bytes, else None (oversize files are recorded)."""
        if rel in self._bytes and limit <= MAX_TEXT_BYTES:
            return self._bytes[rel]
        info = self.lstat(rel)
        if info is None:
            return None
        if info.st_size > limit:
            self.oversize.append(rel)
            return None
        try:
            fd = os.open(os.path.join(self.root, rel), os.O_RDONLY | _NOFOLLOW | _BINARY)
        except OSError:
            self.unreadable.append(rel)
            return None
        try:
            fstat = os.fstat(fd)
            if not stat.S_ISREG(fstat.st_mode) or fstat.st_size > limit:
                return None
            chunks: List[bytes] = []
            remaining = fstat.st_size + 1
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        except OSError:
            self.unreadable.append(rel)
            return None
        finally:
            os.close(fd)
        if len(data) > limit:
            self.oversize.append(rel)
            return None
        if len(data) <= _CACHE_FILE_LIMIT and self._cached_total + len(data) <= _CACHE_TOTAL_LIMIT:
            self._bytes[rel] = data
            self._cached_total += len(data)
        return data

    def text(self, rel: str) -> Optional[str]:
        """The file decoded as UTF-8 (undecodable bytes replaced), a leading BOM removed; None when unreadable."""
        if rel in self._text:
            return self._text[rel]
        data = self.read_bytes(rel)
        value: Optional[str] = None
        if data is not None:
            value = data.decode("utf-8", "replace")
            if value.startswith("﻿"):
                value = value[1:]
            if len(data) <= _CACHE_FILE_LIMIT:
                self._text[rel] = value
        return value

    def sha256(self, rel: str, cap: int = MAX_HASH_BYTES) -> Optional[str]:
        """SHA-256 of a regular file of at most ``cap`` bytes (symlinks are skipped), else None."""
        info = self.lstat(rel)
        if info is None or info.st_size > cap:
            return None
        try:
            fd = os.open(os.path.join(self.root, rel), os.O_RDONLY | _NOFOLLOW | _BINARY)
        except OSError:
            return None
        digest = hashlib.sha256()
        try:
            fstat = os.fstat(fd)
            if not stat.S_ISREG(fstat.st_mode) or fstat.st_size > cap:
                return None
            total = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > cap:
                    return None
                digest.update(chunk)
        except OSError:
            return None
        finally:
            os.close(fd)
        return digest.hexdigest()

    def line_bytes(self, rel: str, line: int) -> Optional[bytes]:
        """The exact bytes of 1-based ``line`` without its terminator (``\\n`` or ``\\r\\n``); None when out of range."""
        data = self.read_bytes(rel)
        if data is None or line < 1:
            return None
        lines = data.split(b"\n")
        if line > len(lines):
            return None
        return lines[line - 1].rstrip(b"\r")

    def line_text(self, rel: str, line: int, limit: int = 200) -> Optional[str]:
        raw = self.line_bytes(rel, line)
        if raw is None:
            return None
        return raw.decode("utf-8", "replace").strip()[:limit]
