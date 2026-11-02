"""The curated CPE map: canonical names, upstream URLs and pair proposals (contract sections 3.11, 4.28, 6.11, Appendix B).

Imports nothing outside WP-core so discovery can use it for canonical names and upstream URLs. The map is data
(``assets/cpe_map.json`` and ``assets/aliases.json``); this module only indexes it.

Name resolution (``canonical`` and ``entry``), all comparisons by ``norm.norm_library``:

1. an entry name;
2. an alias (``aliases.json`` ``alias``): renames and merges, the canonical name is the entry's name;
3. a ``covers`` pattern (case-insensitive ``fnmatch``): shares the entry's CPE status but keeps its own row name, so
   ``canonical`` returns the name as given while ``entry`` returns the covered entry.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sbomlib import errors, model, urls
from sbomlib.context import RunContext
from sbomlib.cpe import cpestr
from sbomlib.norm import norm_library

STATUSES = ("mapped", "no-nvd-cpe")
ROLE_ORDER = {"primary": 0, "also_emit": 1, "cve_only": 2, "never_emit": 3}
M1_OFFLINE_SOURCES = ["local", "map", "declared", "model"]
WITHHELD_REASONS = ("umbrella", "toolchain_runtime", "closest_modified", "version_scope")

_VERSION_PART_RE = re.compile(r"^(\d+)")
_NUM_PREFIX_RE = re.compile(r"^\d+(?:\.\d+)*")


# ---------------------------------------------------------------------------------------------------- versions

def version_tuple(text: Optional[str]) -> Optional[Tuple[int, ...]]:
    """The numeric dotted prefix of a version (``10.0.1`` -> ``(10, 0, 1)``, ``1.1.1w`` -> ``(1, 1, 1)``); None when the
    version does not start with a number (``NOASSERTION``, ``master``)."""
    if not text:
        return None
    match = _NUM_PREFIX_RE.match(text.strip())
    if not match:
        return None
    return tuple(int(p) for p in match.group(0).split("."))


def _padded(first: Tuple[int, ...], second: Tuple[int, ...]) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    size = max(len(first), len(second))
    return (first + (0,) * (size - len(first)), second + (0,) * (size - len(second)))


def in_version_scope(version: Optional[str], scope: Optional[Dict[str, Any]]) -> bool:
    """True when ``version`` lies inside ``scope`` (``{"min_inclusive"?, "max_inclusive"?}``, numeric dotted comparison).

    A pair without a scope is always in scope; a scoped pair never matches a version that is not numeric.
    """
    if not scope:
        return True
    current = version_tuple(version)
    if current is None:
        return False
    low = scope.get("min_inclusive")
    high = scope.get("max_inclusive")
    if low is not None:
        bound = version_tuple(str(low))
        if bound is None:
            return False
        a, b = _padded(current, bound)
        if a < b:
            return False
    if high is not None:
        bound = version_tuple(str(high))
        if bound is None:
            return False
        a, b = _padded(current, bound)
        if a > b:
            return False
    return True


# ---------------------------------------------------------------------------------------------------- the map

def _bad(message: str) -> errors.StateError:
    return errors.StateError("cpe_map.json: " + message)


def _normalize_entry(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not raw["name"].strip():
        raise _bad("every entry needs a name")
    name = raw["name"]
    status = raw.get("status", "mapped")
    if status not in STATUSES:
        raise _bad("%s: status must be one of %s" % (name, ", ".join(STATUSES)))
    pairs: List[Dict[str, Any]] = []
    for item in raw.get("pairs") or []:
        if not isinstance(item, dict):
            raise _bad("%s: a pair must be an object" % name)
        part, vendor, product = item.get("part", "a"), item.get("vendor"), item.get("product")
        role = item.get("role", "primary")
        if part not in cpestr.PARTS or not isinstance(vendor, str) or not isinstance(product, str):
            raise _bad("%s: malformed pair %r" % (name, item))
        if cpestr.PAIR_RE.fullmatch(cpestr.pair_str(part, vendor, product)) is None:
            raise _bad("%s: pair %s:%s:%s is not a valid vendor:product pair" % (name, part, vendor, product))
        if role not in model.ROLES:
            raise _bad("%s: unknown pair role %r" % (name, role))
        scope = item.get("version_scope")
        if scope is not None and (not isinstance(scope, dict)
                                  or set(scope) - {"min_inclusive", "max_inclusive"}):
            raise _bad("%s: version_scope must be null or an object with min_inclusive/max_inclusive" % name)
        pairs.append({"part": part, "vendor": vendor, "product": product, "role": role,
                      "version_scope": dict(scope) if scope else None})
    if status == "no-nvd-cpe" and pairs:
        raise _bad("%s: a no-nvd-cpe entry has no pairs" % name)
    upstream = raw.get("upstream")
    if upstream is not None:
        if not isinstance(upstream, dict) or not isinstance(upstream.get("url"), str):
            raise _bad("%s: upstream must be null or an object with a url" % name)
        upstream = {"url": upstream["url"], "purl_type": upstream.get("purl_type"),
                    "tag_format": upstream.get("tag_format")}
    provenance = raw.get("provenance") or {}
    return {"name": name, "status": status, "umbrella": bool(raw.get("umbrella", False)),
            "toolchain_runtime": bool(raw.get("toolchain_runtime", False)),
            "header_only": bool(raw.get("header_only", False)), "pairs": pairs, "upstream": upstream,
            "provenance": {"nvd_cpe_count": provenance.get("nvd_cpe_count"), "nvd_cve_count": provenance.get("nvd_cve_count"),
                           "verified_on": provenance.get("verified_on"), "source": provenance.get("source")},
            "notes": raw.get("notes") or ""}


def url_key(url: Optional[str]) -> Optional[str]:
    """Comparison key of a repository URL: the forge form ``host/owner/repo`` lowercased, without ``.git``."""
    if not url:
        return None
    form = urls.https_form(url)
    if form is None:
        scrubbed = urls.scrub_url(url)
        if scrubbed is None:
            return None
        form = scrubbed
        if form.endswith(".git"):
            form = form[:-4]
    form = form.rstrip("/").lower()
    for prefix in ("https://", "http://", "ssh://", "git://"):
        if form.startswith(prefix):
            form = form[len(prefix):]
            break
    return form


class CpeMap:
    """Indexes over the two assets. Entries are shared with the loaded assets: treat them as read-only."""

    def __init__(self, map_doc: Dict[str, Any], aliases_doc: Optional[Dict[str, Any]] = None) -> None:
        if not isinstance(map_doc, dict) or not isinstance(map_doc.get("entries"), list):
            raise _bad("the file needs an entries list")
        aliases_doc = aliases_doc or {}
        self.entries: List[Dict[str, Any]] = []
        self._by_norm: Dict[str, Dict[str, Any]] = {}
        for raw in map_doc["entries"]:
            entry = _normalize_entry(raw)
            key = norm_library(entry["name"])
            if not key:
                raise _bad("entry name %r has no alphanumeric character" % entry["name"])
            if key in self._by_norm:
                raise _bad("entries %r and %r have the same normalized name" % (self._by_norm[key]["name"], entry["name"]))
            self._by_norm[key] = entry
            self.entries.append(entry)
        self._alias: Dict[str, Dict[str, Any]] = {}
        alias_table = aliases_doc.get("alias") or {}
        if not isinstance(alias_table, dict):
            raise _bad("aliases.json: alias must be an object")
        for alias, target in alias_table.items():
            target_entry = self._by_norm.get(norm_library(str(target)))
            if target_entry is None:
                raise errors.StateError("aliases.json: alias %r points to %r, which is not a map entry" % (alias, target))
            key = norm_library(alias)
            if not key:
                raise errors.StateError("aliases.json: alias %r has no alphanumeric character" % (alias,))
            known = self._alias.get(key)
            if known is not None and known is not target_entry:
                raise errors.StateError("aliases.json: alias %r resolves to two entries (%s, %s)"
                                        % (alias, known["name"], target_entry["name"]))
            self._alias[key] = target_entry
        self._covers: List[Tuple[str, Dict[str, Any]]] = []
        for item in aliases_doc.get("covers") or []:
            if not isinstance(item, dict) or not isinstance(item.get("pattern"), str):
                raise errors.StateError("aliases.json: a covers item needs a pattern")
            target_entry = self._by_norm.get(norm_library(str(item.get("entry", ""))))
            if target_entry is None:
                raise errors.StateError("aliases.json: covers pattern %r points to %r, which is not a map entry"
                                        % (item["pattern"], item.get("entry")))
            self._covers.append((item["pattern"].lower(), target_entry))
        self.known_unmapped: List[str] = [str(n) for n in aliases_doc.get("known_unmapped") or []]
        self._by_url: Dict[str, Dict[str, Any]] = {}
        for entry in self.entries:
            key = url_key(entry["upstream"]["url"]) if entry["upstream"] else None
            if key and key not in self._by_url:
                self._by_url[key] = entry

    # ------------------------------------------------------------------ lookups
    def _resolve(self, name: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """(entry, how) with how in "entry", "alias", "covers", or (None, "")."""
        text = (name or "").strip()
        key = norm_library(text)
        if not key:
            return (None, "")
        found = self._by_norm.get(key)
        if found is not None:
            return (found, "entry")
        found = self._alias.get(key)
        if found is not None:
            return (found, "alias")
        lowered = text.lower()
        for pattern, target in self._covers:
            if fnmatch.fnmatchcase(lowered, pattern):
                return (target, "covers")
        return (None, "")

    def canonical(self, name: str) -> Optional[str]:
        """The display name of a known library: the entry name for an entry name or alias; the name as given for a
        ``covers`` match (it keeps its own row name); None when the map does not know the name."""
        found, how = self._resolve(name)
        if found is None:
            return None
        if how == "covers":
            return (name or "").strip()
        return found["name"]

    def entry(self, name: str) -> Optional[Dict[str, Any]]:
        """The map entry for an entry name, alias or ``covers`` match; None when unknown."""
        return self._resolve(name)[0]

    def entry_for_url(self, url: str) -> Optional[Dict[str, Any]]:
        """The entry whose upstream repository is ``url`` (scheme, ``.git``, case and userinfo do not matter)."""
        key = url_key(url)
        return self._by_url.get(key) if key else None

    # ------------------------------------------------------------------ pairs
    @staticmethod
    def pairs_of(entry: Dict[str, Any], *, include_never_emit: bool = False) -> List[Dict[str, Any]]:
        """The entry's pairs in role order (primary, also_emit, cve_only; map order inside a role)."""
        ordered = sorted(enumerate(entry["pairs"]), key=lambda it: (ROLE_ORDER[it[1]["role"]], it[0]))
        return [p for _, p in ordered if include_never_emit or p["role"] != "never_emit"]

    @staticmethod
    def pair_text(pair: Dict[str, Any]) -> str:
        return cpestr.pair_str(pair["part"], pair["vendor"], pair["product"])

    def never_emit_pairs(self, entry: Dict[str, Any]) -> List[str]:
        return [self.pair_text(p) for p in entry["pairs"] if p["role"] == "never_emit"]

    def proposals(self, entry: Dict[str, Any], version: str, version_kind: str,
                  detected_as: Sequence[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """``(proposed, alternatives)`` for a row (contract section 6.11).

        Each item is ``{"pair": "a:zlib:zlib", "role": ..., "tier": ..., "basis": "alias"}``. ``proposed`` holds High
        proposals in role order. ``alternatives`` holds the pairs the rules withhold (tier ``low``, an extra
        ``"withheld"`` key naming the reason: ``umbrella``, ``toolchain_runtime``, ``closest_modified`` or
        ``version_scope``). ``never_emit`` pairs appear in neither list.
        """
        proposed: List[Dict[str, Any]] = []
        alternatives: List[Dict[str, Any]] = []
        if entry["status"] != "mapped":
            return (proposed, alternatives)
        no_version = (version or "NOASSERTION") == "NOASSERTION"
        reason: Optional[str] = None
        if entry["umbrella"]:
            reason = "umbrella"
        elif entry["toolchain_runtime"] or ("toolchain_runtime" in list(detected_as) and no_version):
            reason = "toolchain_runtime"
        elif version_kind == "closest_modified":
            reason = "closest_modified"
        for pair in self.pairs_of(entry):
            item = {"pair": self.pair_text(pair), "role": pair["role"], "tier": "high", "basis": "alias"}
            why = reason
            if why is None and pair["version_scope"]:
                if no_version or not in_version_scope(version, pair["version_scope"]):
                    why = "version_scope"
            if why is not None:
                item["tier"] = "low"
                item["withheld"] = why
                alternatives.append(item)
            else:
                proposed.append(item)
        return (proposed, alternatives)

    # ------------------------------------------------------------------ upstream
    @staticmethod
    def upstream_tag(entry: Dict[str, Any], version: Optional[str]) -> Optional[str]:
        """The tag the map's ``tag_format`` gives for a release version (``v{version}`` -> ``v1.3.1``); None without a
        format or version. Placeholders: ``{version}``, ``{major}``, ``{minor}``, ``{patch}``, ``{version_underscored}``;
        a missing minor or patch component is ``0``."""
        upstream = entry.get("upstream")
        if not upstream or not upstream.get("tag_format") or not version or version == "NOASSERTION":
            return None
        parts = version.split(".")
        major = parts[0]
        minor = parts[1] if len(parts) > 1 else "0"
        patch = parts[2] if len(parts) > 2 else "0"
        try:
            return upstream["tag_format"].format(version=version, major=major, minor=minor, patch=patch,
                                                 version_underscored=version.replace(".", "_"))
        except (KeyError, IndexError, ValueError):
            return None

    def size(self) -> int:
        return len(self.entries)


# ---------------------------------------------------------------------------------------------------- loading

_CACHE: Dict[str, Any] = {"docs": None, "map": None}


def from_docs(map_doc: Dict[str, Any], aliases_doc: Optional[Dict[str, Any]] = None) -> CpeMap:
    """Build a map from already parsed documents (tests)."""
    return CpeMap(map_doc, aliases_doc)


def load(ctx: RunContext) -> CpeMap:
    """The map of the shipped assets, indexed once per loaded asset objects (``assets.load`` caches per file stamp)."""
    map_doc = ctx.asset("cpe_map.json")
    aliases_doc = ctx.asset("aliases.json")
    docs = _CACHE.get("docs")
    if docs is not None and docs[0] is map_doc and docs[1] is aliases_doc:
        return _CACHE["map"]
    built = CpeMap(map_doc, aliases_doc)
    _CACHE["docs"] = (map_doc, aliases_doc)
    _CACHE["map"] = built
    return built


def offline_sources(ctx: RunContext) -> List[str]:
    """Pre-gate candidate sources in precedence order. M1: local decisions, the curated map, declared identifiers, model
    hints; the M2 index sources would be added here."""
    return list(M1_OFFLINE_SOURCES)
