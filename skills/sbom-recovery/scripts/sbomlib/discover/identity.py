"""Canonical library names for discovery (contract sections 3.9 and 6.4).

Names come from WP-cpe's curated map (``cpe/cpemap.py``: ``CpeMap.canonical``, ``entry``, ``entry_for_url``). That
module is imported inside functions only, so discovery works (with a small built-in fallback built from the shipped
``version_rules.json`` and ``include_map.json``) while the CPE package is absent or its assets cannot be loaded.
Tests may install a loader with ``set_cpemap_loader``.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Optional

from sbomlib import urls
from sbomlib.norm import norm_library

_LOADER: Optional[Callable[[Any], Any]] = None

_VERSION_TAIL_RE = re.compile(r"[-_.]v?\d+(?:[._]\d+)*[a-z]?$", re.I)
_LIB_PREFIX_RE = re.compile(r"^lib(?=[a-z])", re.I)


def set_cpemap_loader(loader: Optional[Callable[[Any], Any]]) -> None:
    """Install ``loader(ctx) -> object with canonical/entry/entry_for_url`` (tests); None restores the default."""
    global _LOADER
    _LOADER = loader


def _default_loader(ctx: Any) -> Any:
    from sbomlib.cpe import cpemap          # function-local import: WP-cpe's module may be absent
    return cpemap.load(ctx)


class Identity:
    """Name resolution against the curated map, with a fallback built from the shipped asset tables."""

    def __init__(self, ctx: Any, rules: Optional[Dict[str, Any]] = None, imap: Optional[Dict[str, Any]] = None) -> None:
        self.ctx = ctx
        self.map: Any = None
        self.map_error: Optional[str] = None
        self._canon_cache: Dict[str, Optional[str]] = {}
        self._fallback: Dict[str, str] = {}
        self._build_fallback(rules or {}, imap or {})
        loader = _LOADER or _default_loader
        try:
            self.map = loader(ctx)
        except Exception as exc:                              # missing module or asset: degrade, never fail discovery
            self.map = None
            self.map_error = "%s: %s" % (type(exc).__name__, str(exc)[:120])
            try:
                ctx.log.warning("discover.cpemap_unavailable", error=self.map_error)
            except Exception:
                pass

    def _build_fallback(self, rules: Dict[str, Any], imap: Dict[str, Any]) -> None:
        names: List[str] = [r.get("library", "") for r in rules.get("rules", [])]
        for table in ("headers", "packages", "link_names", "link_namespaces", "distro_packages"):
            names.extend(v for v in (imap.get(table) or {}).values() if isinstance(v, str))
        for name in names:
            if name:
                self._fallback.setdefault(norm_library(name), name)

    # ------------------------------------------------------------------ lookups
    def _map_canonical(self, name: str) -> Optional[str]:
        if self.map is None:
            return None
        try:
            return self.map.canonical(name)
        except Exception:
            return None

    def canonical_or_none(self, name: str) -> Optional[str]:
        """The canonical display name when the name is known (map or fallback), else None."""
        key = (name or "").strip()
        if not key:
            return None
        if key in self._canon_cache:
            return self._canon_cache[key]
        found = self._map_canonical(key)
        if found is None:
            found = self._fallback.get(norm_library(key))
        self._canon_cache[key] = found
        return found

    def canonical(self, name: str) -> str:
        """Canonical display name, else the name as discovered."""
        known = self.canonical_or_none(name)
        return known if known is not None else (name or "").strip()

    def entry(self, name: str) -> Optional[Dict[str, Any]]:
        if self.map is None:
            return None
        try:
            found = self.map.entry(name)
        except Exception:
            return None
        return found if isinstance(found, dict) else None

    def map_entry_name(self, name: str) -> Optional[str]:
        found = self.entry(name)
        if found is not None and isinstance(found.get("name"), str):
            return found["name"]
        return None

    def entry_for_url(self, url: Optional[str]) -> Optional[Dict[str, Any]]:
        if not url or self.map is None:
            return None
        try:
            found = self.map.entry_for_url(url)
        except Exception:
            return None
        return found if isinstance(found, dict) else None

    def upstream_url(self, name: str) -> Optional[str]:
        found = self.entry(name)
        if found is None:
            return None
        upstream = found.get("upstream")
        if isinstance(upstream, dict) and isinstance(upstream.get("url"), str):
            return upstream["url"]
        return None

    # ------------------------------------------------------------------ naming helpers
    def from_url(self, url: Optional[str]) -> Optional[str]:
        """Canonical name of a repository URL: the map entry that owns it; without one, the forge path ``owner/repo`` or the
        repository name when either is itself a known library name; else None."""
        found = self.entry_for_url(url)
        if found is not None and isinstance(found.get("name"), str):
            return found["name"]
        scrubbed = urls.https_form(url) if url else None
        if scrubbed:
            segments = scrubbed.split("/")[3:]
            if len(segments) >= 2:
                for probe in ("/".join(segments[:2]), segments[1]):
                    known = self.canonical_or_none(probe)
                    if known is not None:
                        return known
        return None

    @staticmethod
    def url_last_component(url: Optional[str]) -> Optional[str]:
        scrubbed = urls.scrub_url(url) if url else None
        if not scrubbed:
            return None
        tail = scrubbed.rstrip("/").rsplit("/", 1)[-1]
        if tail.endswith(".git"):
            tail = tail[:-4]
        return tail or None

    def clean_dir_name(self, name: str) -> str:
        """A directory name as a library name: a trailing version (``zlib-1.2.11``) is removed."""
        stripped = _VERSION_TAIL_RE.sub("", name)
        return stripped if stripped and not stripped.isdigit() else name

    def resolve_name(self, *names: Optional[str]) -> Optional[str]:
        """The first of ``names`` that is a known library, canonicalized (also with ``lib`` stripped)."""
        for name in names:
            if not name:
                continue
            for variant in (name, _LIB_PREFIX_RE.sub("", name)):
                found = self.canonical_or_none(variant)
                if found is not None:
                    return found
        return None

    def norm_set(self, names: Iterable[Optional[str]]) -> List[str]:
        return sorted({norm_library(n) for n in names if n})
