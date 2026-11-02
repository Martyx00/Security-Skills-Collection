"""NVD Products API 2.0 client (contract section 3.11, "NVD client rules"). The only caller of ``ctx.http``.

* every URL comes from ``build_url``, so the request, the cache key, the audit event and test routes agree byte for byte;
* ``apiKey`` header from ``ctx.env["NVD_API_KEY"]`` when set (never logged, never written);
* sliding window of 5 requests per 30 s without a key, 50 with one, measured with ``ctx.clock`` (the window is persisted
  between invocations by the caller);
* HTTP 403, 429 and 503 back off 6 s, 12 s, 30 s, then the query is recorded as an API error;
* responses (status 200 only) are cached under ``.cache/nvd/api/<sha256(url)>.json`` for 7 days;
* no request is made when ``ctx.remaining() < 10`` (``NvdYield`` is raised and the caller returns ``done=False``);
* the first ``NetworkUnavailable`` switches the client to offline for the rest of the phase;
* every request, cached or not, is an ``nvd_query`` audit event.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from sbomlib import errors, fsio, state
from sbomlib.context import RunContext, iso_z, parse_iso_z
from sbomlib.cpe import cpestr

BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CACHE_TTL_S = 7 * 24 * 3600
WINDOW_S = 30.0
LIMIT_WITHOUT_KEY = 5
LIMIT_WITH_KEY = 50
BACKOFF_S = (6.0, 12.0, 30.0)
RETRY_STATUS = (403, 429, 503)
TIMEOUT_S = 30.0
MIN_REMAINING_S = 10.0
KEYWORD_CANDIDATE_MAX = 10
SUCCESSOR_DEPTH = 3


def build_url(kind: str, *, part: str = "a", vendor: str = "", product: str = "", version: Optional[str] = None,
              keyword: Optional[str] = None) -> str:
    """The one place that makes an NVD URL (contract section 3.11).

    ``kind`` ``exact``: ``cpeMatchString=cpe:2.3:<part>:<vendor>:<product>:<version>``; ``exists``:
    ``cpeMatchString=cpe:2.3:<part>:<vendor>:<product>`` and ``resultsPerPage=1``; ``keyword``: ``keywordSearch`` and
    ``resultsPerPage=20``. Vendor, product and version are CPE-escaped attribute values.
    """
    if kind == "exact":
        if version is None:
            raise ValueError("an exact query needs a version")
        params = [("cpeMatchString", "cpe:2.3:%s:%s:%s:%s" % (part, vendor, product, version))]
    elif kind == "exists":
        params = [("cpeMatchString", "cpe:2.3:%s:%s:%s" % (part, vendor, product)), ("resultsPerPage", "1")]
    elif kind == "keyword":
        if keyword is None:
            raise ValueError("a keyword query needs a keyword")
        params = [("keywordSearch", keyword), ("resultsPerPage", "20")]
    else:
        raise ValueError("unknown query kind: %r" % (kind,))
    return BASE + "?" + "&".join(name + "=" + quote(value, safe=":*") for name, value in params)


class NvdYield(Exception):
    """Raised when the time budget does not allow the next request; the phase returns ``done=False``."""


class QueryResult:
    """The outcome of one query (cached or not)."""

    def __init__(self, status: int, body: Optional[Dict[str, Any]], cached: bool, error: Optional[str] = None,
                 fetched_at: Optional[str] = None) -> None:
        self.status = status
        self.body = body
        self.cached = cached
        self.error = error                      # None, "offline" or a short text for an API error
        self.fetched_at = fetched_at            # iso_z text of the response (live: now; cached: the cache entry)

    @property
    def ok(self) -> bool:
        return self.error is None and self.body is not None

    @property
    def offline(self) -> bool:
        return self.error == "offline"


# ------------------------------------------------------------------------------------------------ response parsing

def products_of(body: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The CPE records of a response: ``{"cpe_name", "cpe_name_id", "deprecated", "deprecated_by": [{"cpe_name", "cpe_name_id"}]}``."""
    out: List[Dict[str, Any]] = []
    if not isinstance(body, dict):
        return out
    for item in body.get("products") or []:
        cpe = item.get("cpe") if isinstance(item, dict) else None
        if not isinstance(cpe, dict) or not isinstance(cpe.get("cpeName"), str):
            continue
        successors = []
        for succ in cpe.get("deprecatedBy") or []:
            if isinstance(succ, dict) and isinstance(succ.get("cpeName"), str):
                successors.append({"cpe_name": succ["cpeName"], "cpe_name_id": str(succ.get("cpeNameId") or "")})
        out.append({"cpe_name": cpe["cpeName"], "cpe_name_id": str(cpe.get("cpeNameId") or ""),
                    "deprecated": bool(cpe.get("deprecated")), "deprecated_by": successors})
    return out


def total_results(body: Optional[Dict[str, Any]]) -> int:
    if not isinstance(body, dict):
        return 0
    total = body.get("totalResults")
    if isinstance(total, int):
        return total
    return len(products_of(body))


def _fields(name: str) -> Optional[List[str]]:
    try:
        return cpestr.split_cpe23(name)
    except ValueError:
        return None


def products_of_pair(products: List[Dict[str, Any]], part: str, vendor: str, product: str) -> List[Dict[str, Any]]:
    """The records whose part, vendor and product are the queried ones (a response never widens an approved pair)."""
    wanted = (part, cpestr.unescape_attr(vendor).lower(), cpestr.unescape_attr(product).lower())
    out = []
    for item in products:
        fields = _fields(item["cpe_name"])
        if fields is not None and (fields[2], cpestr.unescape_attr(fields[3]).lower(), cpestr.unescape_attr(fields[4]).lower()) == wanted:
            out.append(item)
    return out


def select_name(products: List[Dict[str, Any]], version_field: str, update_field: str) -> Optional[Dict[str, Any]]:
    """The dictionary name for exactly this version (and update), or None.

    ``version_field`` and ``update_field`` are CPE-escaped attribute values. A name qualifies when its version equals the
    wanted one (case-insensitively, escapes removed), every trailing field is ``*`` and its update matches: the wanted
    update when one is given, else ``*`` (preferred) or ``-``.
    """
    wanted_version = cpestr.unescape_attr(version_field).lower()
    wanted_update = cpestr.unescape_attr(update_field).lower()
    best: Optional[Tuple[Tuple[int, str], Dict[str, Any]]] = None
    for product in products:
        fields = _fields(product["cpe_name"])
        if fields is None or cpestr.unescape_attr(fields[5]).lower() != wanted_version:
            continue
        if any(f != "*" for f in fields[7:]):
            continue
        update = cpestr.unescape_attr(fields[6]).lower()
        if wanted_update != "*":
            if update != wanted_update:
                continue
            score = 0
        elif update == "*":
            score = 0
        elif update == "-":
            score = 1
        else:
            continue
        candidate = (score, product["cpe_name"])
        if best is None or candidate < best[0]:
            best = (candidate, product)
    return best[1] if best else None


def version_in_products(products: List[Dict[str, Any]], version_field: str) -> bool:
    wanted = cpestr.unescape_attr(version_field).lower()
    for product in products:
        fields = _fields(product["cpe_name"])
        if fields is not None and cpestr.unescape_attr(fields[5]).lower() == wanted:
            return True
    return False


def pairs_of_products(products: List[Dict[str, Any]], *, vendor_hint: str = "", part_hint: str = "",
                      limit: int = KEYWORD_CANDIDATE_MAX) -> List[str]:
    """Unique ``part:vendor:product`` pairs of keyword results, hinted vendor first, at most ``limit``."""
    seen: List[str] = []
    for product in products:
        fields = _fields(product["cpe_name"])
        if fields is None or fields[3] in ("*", "-") or fields[4] in ("*", "-"):
            continue
        pair = cpestr.pair_str(fields[2], fields[3], fields[4])
        if part_hint and fields[2] != part_hint:
            continue
        if pair not in seen:
            seen.append(pair)
    if vendor_hint:
        wanted = vendor_hint.lower()
        seen.sort(key=lambda p: 0 if cpestr.unescape_attr(p.split(":")[1]).lower() == wanted else 1)
    return seen[:limit]


# ------------------------------------------------------------------------------------------------ the client

class NvdClient:
    def __init__(self, ctx: RunContext, window_ns: Optional[List[int]] = None) -> None:
        self.ctx = ctx
        key = (ctx.env.get("NVD_API_KEY") or "").strip()
        self._key = key or None
        self.limit = LIMIT_WITH_KEY if self._key else LIMIT_WITHOUT_KEY
        self.offline = ctx.http is None
        self.queries_made = 0
        self.api_errors = 0
        self._stamps: List[Tuple[float, int]] = []
        now_ns = ctx.clock.time_ns()
        mono = ctx.clock.monotonic()
        for ns in window_ns or []:
            age = (now_ns - int(ns)) / 1e9
            if 0 <= age < WINDOW_S:
                self._stamps.append((mono - age, int(ns)))

    # -------------------------------------------------------------- state kept by the caller
    @property
    def api_key_set(self) -> bool:
        return self._key is not None

    def window_ns(self) -> List[int]:
        """Wall-clock stamps (``clock.time_ns``) of the requests inside the current window, for ``cpe_progress.json``."""
        self._prune()
        return [ns for _, ns in self._stamps]

    # -------------------------------------------------------------- cache
    def _cache_path(self, url: str) -> Any:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
        return self.ctx.layout.cache / "nvd" / "api" / (digest + ".json")

    def _read_cache(self, url: str) -> Optional[Dict[str, Any]]:
        path = self._cache_path(url)
        try:
            doc = fsio.read_json(path)
        except (OSError, errors.StateError):
            return None
        if not isinstance(doc, dict) or doc.get("schema") != 1 or doc.get("url") != url or doc.get("status") != 200:
            return None
        if not isinstance(doc.get("body"), dict):
            return None
        try:
            fetched_ns = parse_iso_z(str(doc.get("fetched_at")))
        except ValueError:
            return None
        age_s = (self.ctx.clock.time_ns() - fetched_ns) / 1e9
        if age_s > CACHE_TTL_S or age_s < -86400:
            return None
        return doc

    def _write_cache(self, url: str, body: Dict[str, Any], fetched_at: str) -> None:
        doc = {"schema": 1, "url": url, "fetched_at": fetched_at, "status": 200, "body": body}
        try:
            fsio.atomic_write_json(self._cache_path(url), doc, root=self.ctx.layout.out)
        except (OSError, errors.SbomError) as exc:
            try:
                self.ctx.log.warning("cpe.nvd_cache_write_failed", error=type(exc).__name__)
            except Exception:
                pass

    # -------------------------------------------------------------- rate limit
    def _prune(self) -> None:
        now = self.ctx.clock.monotonic()
        self._stamps = [(m, ns) for m, ns in self._stamps if now - m < WINDOW_S]

    def _wait_needed(self) -> float:
        self._prune()
        if len(self._stamps) < self.limit:
            return 0.0
        oldest_relevant = self._stamps[len(self._stamps) - self.limit][0]
        return max(0.0, oldest_relevant + WINDOW_S - self.ctx.clock.monotonic())

    def _sleep_or_yield(self, seconds: float) -> None:
        if seconds <= 0:
            return
        if self.ctx.remaining() - seconds < MIN_REMAINING_S:
            raise NvdYield()
        self.ctx.clock.sleep(seconds)

    def _audit(self, url: str, status: int, cached: bool, row_id: Optional[str]) -> None:
        state.audit_event(self.ctx, {"event": "nvd_query", "url": url, "status": status, "cached": cached,
                                     "api_key": self.api_key_set, "row_id": row_id})

    # -------------------------------------------------------------- queries
    def fetch(self, url: str, row_id: Optional[str] = None) -> QueryResult:
        """One query. Cache first; then the network with rate limiting and back-off.

        Raises ``NvdYield`` when the budget does not allow the request. Returns a result with ``error == "offline"`` once
        the network is unavailable, and ``error`` set for an API error; never raises for HTTP errors.
        """
        cached = self._read_cache(url)
        if cached is not None:
            self._audit(url, 200, True, row_id)
            return QueryResult(200, cached["body"], True, None, str(cached["fetched_at"]))
        if self.offline:
            return QueryResult(0, None, False, "offline")
        headers = {"apiKey": self._key} if self._key else {}
        attempt = 0
        while True:
            if self.ctx.remaining() < MIN_REMAINING_S:
                raise NvdYield()
            self._sleep_or_yield(self._wait_needed())
            if self.ctx.remaining() < MIN_REMAINING_S:
                raise NvdYield()
            self._stamps.append((self.ctx.clock.monotonic(), self.ctx.clock.time_ns()))
            self.queries_made += 1
            try:
                response = self.ctx.http.get_json(url, headers, TIMEOUT_S)          # type: ignore[union-attr]
            except errors.NetworkUnavailable:
                self.offline = True
                self._audit(url, 0, False, row_id)
                return QueryResult(0, None, False, "offline")
            self._audit(url, int(response.status), False, row_id)
            if response.status == 200:
                if isinstance(response.body, dict):
                    fetched_at = iso_z(self.ctx.clock.time_ns())
                    self._write_cache(url, response.body, fetched_at)
                    return QueryResult(200, response.body, False, None, fetched_at)
                self.api_errors += 1
                return QueryResult(200, None, False, "malformed response", iso_z(self.ctx.clock.time_ns()))
            if response.status in RETRY_STATUS and attempt < len(BACKOFF_S):
                self._sleep_or_yield(BACKOFF_S[attempt])
                attempt += 1
                continue
            self.api_errors += 1
            return QueryResult(int(response.status), None, False, "HTTP %d" % int(response.status),
                               iso_z(self.ctx.clock.time_ns()))

    def follow_deprecation(self, product: Dict[str, Any], row_id: Optional[str]) -> Tuple[List[Dict[str, Any]], bool]:
        """Successors of a deprecated dictionary name, up to ``SUCCESSOR_DEPTH`` hops (names are added, never dropped).

        Returns ``(names, complete)``: each name is ``{"cpe_name", "cpe_name_id", "deprecated": bool|None}`` (``None`` =
        not checked); ``complete`` is False when a lookup failed (the chain may be longer).
        """
        found: List[Dict[str, Any]] = []
        known = {product["cpe_name"].lower()}
        frontier = [dict(s, depth=1) for s in product.get("deprecated_by") or []]
        complete = True
        while frontier:
            succ = frontier.pop(0)
            name = succ["cpe_name"]
            if name.lower() in known:
                continue
            known.add(name.lower())
            entry = {"cpe_name": name, "cpe_name_id": succ.get("cpe_name_id", ""), "deprecated": None}
            if succ["depth"] < SUCCESSOR_DEPTH:
                fields = _fields(name)
                if fields is not None:
                    url = build_url("exact", part=fields[2], vendor=fields[3], product=fields[4], version=fields[5])
                    result = self.fetch(url, row_id)
                    if result.ok:
                        match = next((p for p in products_of(result.body) if p["cpe_name"].lower() == name.lower()), None)
                        if match is not None:
                            entry["deprecated"] = match["deprecated"]
                            entry["cpe_name_id"] = match["cpe_name_id"] or entry["cpe_name_id"]
                            if match["deprecated"]:
                                frontier.extend(dict(s, depth=succ["depth"] + 1) for s in match["deprecated_by"])
                    else:
                        complete = False
            found.append(entry)
        return (found, complete)


__all__ = ["BASE", "build_url", "NvdClient", "NvdYield", "QueryResult", "products_of", "products_of_pair", "select_name",
           "total_results", "version_in_products", "pairs_of_products"]
