"""Name, path and list-cell normalization helpers (contract sections 3.6 and 6.4)."""
from __future__ import annotations

import re
import unicodedata
from typing import Iterable, List, Mapping, Tuple

# D15: a top-level directory name is unsupported when this matches (re.search), when it is longer than 100 characters
# or when it contains a character of Unicode category "Cc".
REPO_NAME_BAD_RE = re.compile(r"[;:/\\\x00-\x1f\x7f]|^[.\- ]|[ ]$|^\*$")
REPO_NAME_MAX = 100

_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_SEGMENT_SPLIT_RE = re.compile(r"[\\/]")


def norm_library(name: str) -> str:
    """Key used to compare library names: NFKC, casefold, '+' -> 'plus', micro/mu -> 'u', alphanumerics only."""
    text = unicodedata.normalize("NFKC", name or "")
    text = text.replace("+", "plus").replace("µ", "u").replace("μ", "u")
    text = text.casefold()
    return "".join(ch for ch in text if ch.isalnum())


def normalize_path(path: str) -> str:
    """POSIX form of a repository-relative path: '/' separators, no empty or '.' segments, no trailing '/'.

    '..' segments are kept as they are (``is_safe_relative_path`` refuses them); the text is not Unicode-normalized
    because on-disk spelling must be preserved.
    """
    text = (path or "").replace("\\", "/")
    parts = [p for p in text.split("/") if p not in ("", ".")]
    return "/".join(parts)


def is_safe_relative_path(path: str) -> bool:
    """True for a relative path that is safe to join below a root.

    Rejects: empty, absolute (leading '/' or '\\'), drive letters, a leading '~', '$' anywhere, '://', NUL and other
    control characters, and empty, '.' or '..' segments (either separator).
    """
    if not isinstance(path, str) or not path:
        return False
    if path[0] in ("/", "\\") or path[0] == "~":
        return False
    if _DRIVE_RE.match(path) or "$" in path or "://" in path:
        return False
    if any(unicodedata.category(ch) == "Cc" for ch in path):
        return False
    for segment in _SEGMENT_SPLIT_RE.split(path):
        if segment in ("", ".", ".."):
            return False
    return True


def split_list(cell: str, sep: str = ";") -> List[str]:
    """Split a multi-valued cell: items stripped, empties dropped, order kept."""
    if not cell:
        return []
    return [item.strip() for item in cell.split(sep) if item.strip()]


def join_list(items: Iterable[str], sep: str = ";", *, sort: bool = True) -> str:
    """Join items without duplicates; sorted unless ``sort=False`` (then first-occurrence order)."""
    seen = []
    known = set()
    for item in items:
        if item is None or item == "":
            continue
        if item not in known:
            known.add(item)
            seen.append(item)
    if sort:
        seen.sort()
    return sep.join(seen)


def repo_kv(values: Mapping[str, str]) -> str:
    """'app_a:proven;app_b:declared', sorted by repository name."""
    return ";".join("%s:%s" % (repo, values[repo]) for repo in sorted(values))


def is_valid_repo_name(name: str) -> bool:
    """D15: True when the directory name is analysed under its exact on-disk spelling.

    The NFC duplicate check is done by ``enumerate.scan_parent``.
    """
    if not isinstance(name, str) or not name or len(name) > REPO_NAME_MAX:
        return False
    if REPO_NAME_BAD_RE.search(name):
        return False
    return not any(unicodedata.category(ch) == "Cc" for ch in name)


def nfc(name: str) -> str:
    return unicodedata.normalize("NFC", name)


def repo_sort_key(name: str) -> Tuple[str, str]:
    """Queue order of top-level names: NFC form first, then the exact spelling."""
    return (nfc(name), name)
