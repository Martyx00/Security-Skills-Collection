"""Reader for ``.git/index`` versions 2, 3 and 4 (contract section 3.13).

Only the entries are read (path, mode, blob id, stage); the cached stat data and the extensions are skipped. The index
checksum is verified, so a truncated or damaged file raises ``ValueError`` instead of producing a partial answer. The
digest over the entries is what the integrity audit compares: it does not change when git only refreshes the cached
stat data of the entries (for example after a ``git status`` run by the IDE's Source Control view).

Only SHA-1 repositories are supported (``extensions.objectformat=sha256`` indexes carry 32-byte object ids and raise
``ValueError``; the digest is then ``None`` and the audit falls back to the stricter comparison).
"""
from __future__ import annotations

import hashlib
import struct
from typing import List, Optional, Tuple

SIGNATURE = b"DIRC"
SUPPORTED_VERSIONS = (2, 3, 4)
FIXED_ENTRY_SIZE = 62            # ctime(8) mtime(8) dev ino mode uid gid size (24) sha1(20) flags(2)
CHECKSUM_SIZE = 20
EXTENDED_FLAG = 0x4000
NAME_LENGTH_MASK = 0x0FFF
STAGE_SHIFT = 12
MAX_ENTRIES = 50_000_000


def _read_offset_varint(data: bytes, pos: int, end: int) -> Tuple[int, int]:
    """Git's offset-encoded variable length integer (used for the path prefix lengths of version 4)."""
    if pos >= end:
        raise ValueError("index entry is truncated (path prefix length)")
    byte = data[pos]
    pos += 1
    value = byte & 0x7F
    while byte & 0x80:
        if pos >= end:
            raise ValueError("index entry is truncated (path prefix length)")
        byte = data[pos]
        pos += 1
        value = ((value + 1) << 7) + (byte & 0x7F)
        if value > 1 << 40:
            raise ValueError("index path prefix length is out of range")
    return value, pos


def read_index_entries(data: bytes) -> List[Tuple[str, int, str, int]]:
    """``(path, mode, sha1 hex, stage)`` of every entry, in index order. ``ValueError`` when the data cannot be parsed."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("index data must be bytes")
    if len(data) < 12 + CHECKSUM_SIZE:
        raise ValueError("index is too short")
    if bytes(data[:4]) != SIGNATURE:
        raise ValueError("not a git index (bad signature)")
    version, count = struct.unpack(">II", bytes(data[4:12]))
    if version not in SUPPORTED_VERSIONS:
        raise ValueError("unsupported index version %d" % version)
    if count > MAX_ENTRIES:
        raise ValueError("index entry count is out of range")
    end = len(data) - CHECKSUM_SIZE
    if hashlib.sha1(bytes(data[:end])).digest() != bytes(data[end:]):
        raise ValueError("index checksum mismatch")
    entries: List[Tuple[str, int, str, int]] = []
    pos = 12
    previous = b""
    for _ in range(count):
        if pos + FIXED_ENTRY_SIZE > end:
            raise ValueError("index entry is truncated")
        fixed = bytes(data[pos:pos + FIXED_ENTRY_SIZE])
        mode = struct.unpack(">I", fixed[24:28])[0]
        sha = fixed[40:60]
        flags = struct.unpack(">H", fixed[60:62])[0]
        stage = (flags >> STAGE_SHIFT) & 3
        cursor = pos + FIXED_ENTRY_SIZE
        if flags & EXTENDED_FLAG:
            if version < 3:
                raise ValueError("extended flags in a version 2 index")
            if cursor + 2 > end:
                raise ValueError("index entry is truncated (extended flags)")
            cursor += 2
        if version == 4:
            strip, cursor = _read_offset_varint(data, cursor, end)
            terminator = data.find(b"\0", cursor, end)
            if terminator < 0:
                raise ValueError("index entry has no path terminator")
            if strip > len(previous):
                raise ValueError("index path prefix length exceeds the previous path")
            path = previous[:len(previous) - strip] + bytes(data[cursor:terminator])
            pos = terminator + 1
        else:
            terminator = data.find(b"\0", cursor, end)
            if terminator < 0:
                raise ValueError("index entry has no path terminator")
            path = bytes(data[cursor:terminator])
            name_length = flags & NAME_LENGTH_MASK
            if name_length < NAME_LENGTH_MASK and name_length != len(path):
                raise ValueError("index entry path length does not match its flags")
            size = (cursor - pos) + len(path) + 8
            pos += size & ~7
            if pos > end:
                raise ValueError("index entry is truncated (padding)")
        previous = path
        entries.append((path.decode("utf-8", "surrogateescape"), mode, sha.hex(), stage))
    return entries


def entries_digest(data: bytes) -> Optional[str]:
    """SHA-256 over the sorted entries, each as ``path NUL mode(octal) NUL sha1 NUL stage LF``; None if unparseable."""
    try:
        entries = read_index_entries(data)
    except (ValueError, struct.error):
        return None
    digest = hashlib.sha256()
    for path, mode, sha, stage in sorted(entries, key=lambda e: (e[0], e[3], e[1], e[2])):
        digest.update(path.encode("utf-8", "surrogateescape"))
        digest.update(b"\0")
        digest.update(("%o" % mode).encode("ascii"))
        digest.update(b"\0")
        digest.update(sha.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(stage).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()
