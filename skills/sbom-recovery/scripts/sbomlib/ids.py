"""Stable identifiers (contract sections 3.6 and 6.3). Every id in the pack is derived here and nowhere else."""
from __future__ import annotations

import hashlib
import re
from typing import Optional, Sequence, Tuple

from sbomlib.norm import norm_library

_NON_SLUG_RE = re.compile(r"[^A-Za-z0-9.-]+")
_DASHES_RE = re.compile(r"-{2,}")


def slug(text: str, maxlen: int = 60) -> str:
    """[^A-Za-z0-9.-]+ -> '-', runs of '-' collapsed, trimmed, truncated; 'x' when nothing is left."""
    out = _NON_SLUG_RE.sub("-", text or "")
    out = _DASHES_RE.sub("-", out).strip("-")
    out = out[:maxlen].strip("-")
    return out or "x"


def _encode(text: str) -> bytes:
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        # on-disk names decoded with surrogateescape: encode them back to the original bytes
        return text.encode("utf-8", "surrogateescape")


def short_hash(*parts: str, n: int = 8) -> str:
    """First ``n`` hex characters of sha256 over the parts joined with U+001F."""
    return hashlib.sha256(_encode("\x1f".join(parts))).hexdigest()[:n]


def spdx_id(kind: str, name: str, version: str, extra: str = "") -> str:
    """SPDXID of a root ('root') or package ('package') element."""
    if kind == "root":
        return "SPDXRef-Root-" + slug(name) + "-" + short_hash("root", norm_library(name))
    if kind == "package":
        return ("SPDXRef-Package-" + slug(name) + "-" + slug(version) + "-"
                + short_hash("package", norm_library(name), version, extra))
    raise ValueError("unknown SPDXID kind: %r" % (kind,))


def candidate_id(repo: str, norm_name: str, location_kind: str, location_path: str) -> str:
    return "c-" + short_hash(repo, norm_name, location_kind, location_path, n=10)


def evidence_id(prefix: str, repo: str, etype: str, path: Optional[str], line: Optional[int], symbol: Optional[str],
                candidate: Optional[str]) -> str:
    """prefix 'e' (discover) or 'u' (verify)."""
    return "%s-%s" % (prefix, short_hash(repo, etype, path or "", str(line or ""), symbol or "", candidate or "", n=12))


def row_id(key: Sequence[str]) -> str:
    return "n-" + short_hash(*key, n=10)


def fold_key(norm_name: str, version: str, upstream_commit: Optional[str]) -> Tuple[str, ...]:
    """D12: (norm_name, version) for a release; (norm_name, 'NOASSERTION', upstream_commit or '') otherwise."""
    if version != "NOASSERTION":
        return (norm_name, version)
    return (norm_name, "NOASSERTION", upstream_commit or "")


def review_key(fold: Tuple[str, ...], repo: str) -> Tuple[str, ...]:
    """Section 6.11: the fold key, except (n, 'NOASSERTION', '') -> (n, 'NOASSERTION', 'repo:' + repo)."""
    if len(fold) == 3 and fold[1] == "NOASSERTION" and fold[2] == "":
        return (fold[0], "NOASSERTION", "repo:" + repo)
    return tuple(fold)


def merge_key(fold: Tuple[str, ...], repo: str) -> Tuple[str, ...]:
    """Section 4.24: (n, version) for a release; every NOASSERTION fold -> (n, 'NOASSERTION', repo)."""
    if len(fold) == 3 and fold[1] == "NOASSERTION":
        return (fold[0], "NOASSERTION", repo)
    return (fold[0], fold[1])


def human_record_id(ts_ns: int, prompt_sha256: str, pid: int) -> str:
    return "h-" + short_hash(str(ts_ns), prompt_sha256, str(pid), n=16)
