"""Cached loader for the JSON assets shipped with the skill (contract section 3.6).

The returned object is shared between callers of the same process: treat it as read-only.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Tuple

from sbomlib import errors
from sbomlib.context import Layout

ASSET_NAMES = ("cpe_map.json", "aliases.json", "version_rules.json", "include_map.json", "api_idents.json",
               "spdx-schema-2.3.json", "spdx-schema-2.3.1.json", "spdx-licenses.json", "cyclonedx-license-ids.json")

_CACHE: Dict[str, Tuple[int, int, Any]] = {}


def clear_cache() -> None:
    _CACHE.clear()


def load(layout: Layout, name: str) -> Any:
    """Parse ``assets/<name>`` of the skill folder (UTF-8 JSON), cached per (path, mtime_ns).

    ``StateError`` when the file is missing or malformed.
    """
    if not isinstance(name, str) or os.path.basename(name) != name or name in ("", ".", "..") or "\\" in name:
        raise errors.StateError("invalid asset name: %r" % (name,))
    path = os.path.join(str(layout.assets), name)
    try:
        st = os.stat(path)
    except OSError as exc:
        raise errors.StateError("asset %s is missing" % name, path=path) from exc
    cached = _CACHE.get(path)
    if cached is not None and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise errors.StateError("asset %s is not valid UTF-8 JSON: %s" % (name, exc), path=path) from exc
    _CACHE[path] = (st.st_mtime_ns, st.st_size, data)
    return data
