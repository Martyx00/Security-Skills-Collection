"""Phase 7: approved-only CPE resolution (contract sections 3.11, 4.17, 6.11).

Only the pairs of the approved copy of the review file are resolved. Per row:

* ``action=skip`` -> nothing; a row included in no repository (D19) -> nothing and no query;
* ``action=lookup`` -> ``cpe_override`` (verbatim) or the proposals, plus the human-typed pairs; each pair is checked
  against the NVD dictionary (exact version, then pair existence) and ``deprecatedBy`` successors are added;
* ``action=manual`` -> only the human-typed pairs, no query;
* a lookup row with no pair but a ``search_name`` -> a keyword query whose pairs are listed, never emitted.

The phase is resumable: ``.state/cpe_progress.json`` keeps the finished rows, the NVD cache keeps the responses.
"""
from __future__ import annotations

import os
import re
import sys
import types
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import csvio, errors, fsio, model
from sbomlib.context import RunContext
from sbomlib.cpe import cpestr, nvd, review, store
from sbomlib.norm import join_list, split_list

HEADER = ("row_id", "name", "version", "action", "pair", "role", "pair_source", "tier", "cpe23", "cpe_name_source",
          "cpe_name_id", "deprecated", "deprecated_by", "version_in_dictionary", "cpe_version_wildcard", "emitted",
          "keyword_candidates", "data_source", "note")
NO_QUERY_ROLES = ("cve_only",)
OFFLINE_MESSAGE = ("NVD unreachable: CPE names were constructed from the curated map and not checked against the NVD "
                   "dictionary")


class Spec:
    """One approved pair of a row."""

    def __init__(self, part: str, vendor: str, product: str, role: str, pair_source: str, tier: str,
                 override: Optional[str] = None) -> None:
        self.part = part
        self.vendor = vendor
        self.product = product
        self.role = role
        self.pair_source = pair_source
        self.tier = tier
        self.override = override

    @property
    def pair(self) -> str:
        return cpestr.pair_str(self.part, self.vendor, self.product)


def _source_of_basis(basis: str) -> str:
    if basis == "local":
        return "local"
    if basis.startswith("declared"):
        return "declared"
    return "alias"


def approved_specs(row: Dict[str, Any]) -> List[Spec]:
    """The approved pairs of a row, in emission order: override or proposals (primary, also_emit, cve_only), then the
    pairs the human typed (``extra_vendor_products`` items, then ``vendor_hint`` with ``product_hint``)."""
    action = row.get("action")
    if action == "skip":
        return []
    specs: List[Spec] = []
    seen = set()

    def add(spec: Spec) -> None:
        key = (spec.part, spec.vendor.lower(), spec.product.lower())
        if key not in seen:
            seen.add(key)
            specs.append(spec)

    override = str(row.get("cpe_override") or "")
    if override:
        fields = cpestr.split_cpe23(override)
        add(Spec(fields[2], fields[3], fields[4], "override", "override", "high", override))
    elif action == "lookup":
        for proposal in row.get("proposals") or []:
            part, vendor, product = cpestr.parse_pair(proposal["pair"])
            add(Spec(part, vendor, product, proposal["role"], _source_of_basis(str(proposal.get("basis") or "")),
                     str(proposal.get("tier") or "high")))
    for item in split_list(str(row.get("extra_vendor_products") or ""), ";"):
        part, vendor, product = cpestr.parse_pair(item)
        add(Spec(part, vendor, product, "extra", "manual", "high"))
    if row.get("vendor_hint") and row.get("product_hint"):
        add(Spec(str(row.get("part_hint") or "a"), str(row["vendor_hint"]), str(row["product_hint"]), "extra", "manual", "high"))
    return specs


def version_fields(row: Dict[str, Any]) -> Tuple[str, str]:
    """``(version, update)`` attribute values of the CPEs of a row (section 6.11, D6): the override, else the escaped
    ``cpe_version`` of a release, else ``*``; the update is the override, else the pre-release, else ``*``."""
    version = str(row.get("cpe_version_override") or "")
    if not version:
        raw = row.get("cpe_version") or (row.get("version") if row.get("version") != "NOASSERTION" else None)
        version = _escaped(raw)
    update = str(row.get("cpe_update_override") or "")
    if not update:
        update = _escaped(row.get("cpe_update"))
    return (version, update)


def _escaped(raw: Any) -> str:
    """The escaped attribute value, or ``*`` when there is none or it cannot be written in a CPE."""
    if not raw:
        return "*"
    try:
        return cpestr.escape_attr(str(raw))
    except ValueError:
        return "*"


def _needs_query(row: Dict[str, Any], specs: List[Spec]) -> bool:
    if row.get("action") != "lookup" or not store.included_repos(row):
        return False
    if any(s.role not in NO_QUERY_ROLES for s in specs):
        return True
    return not specs and bool(str(row.get("search_name") or "").strip())


def _pair_entry(spec: Spec, cpe23: str, version_field: str) -> Dict[str, Any]:
    return {"pair": spec.pair, "role": spec.role, "pair_source": spec.pair_source, "tier": spec.tier, "cpe23": cpe23,
            "cpe_name_source": "constructed", "cpe_name_id": "", "deprecated": "", "deprecated_by": [],
            "version_in_dictionary": "unknown", "wildcard": version_field == "*", "emitted": True, "note": ""}


def _successor_entry(spec: Spec, succ: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        fields = cpestr.split_cpe23(succ["cpe_name"])
    except ValueError:
        return None
    flag = {True: "yes", False: "no", None: ""}[succ.get("deprecated")]
    return {"pair": cpestr.pair_str(fields[2], fields[3], fields[4]), "role": spec.role, "pair_source": "api",
            "tier": spec.tier, "cpe23": succ["cpe_name"], "cpe_name_source": "dictionary",
            "cpe_name_id": succ.get("cpe_name_id", ""), "deprecated": flag, "deprecated_by": [],
            "version_in_dictionary": "yes", "wildcard": fields[5] == "*", "emitted": True,
            "note": "successor of %s (deprecatedBy)" % spec.pair}


class _Tally:
    def __init__(self) -> None:
        self.dates: List[str] = []
        self.offline = False
        self.api_errors = 0


_UNESCAPED_WILDCARD_RE = re.compile(r"(?<!\\)[*?]")


def _is_offline(client: Optional[nvd.NvdClient]) -> bool:
    return client is None or client.offline


def _read(result: nvd.QueryResult, tally: _Tally) -> Tuple[str, Optional[Dict[str, Any]]]:
    """``("ok", body)``, ``("offline", None)`` or ``("error", None)``. An HTTP 404 on a ``cpeMatchString`` or keyword query is
    read as "no match" (an unknown route also answers 404 in the test double); every other failure is an API error."""
    if result.offline:
        tally.offline = True
        return ("offline", None)
    if result.ok:
        tally.dates.append(str(result.fetched_at or ""))
        return ("ok", result.body)
    if result.status == 404:
        tally.dates.append(str(result.fetched_at or ""))
        return ("ok", {"products": [], "totalResults": 0})
    tally.api_errors += 1
    return ("error", None)


def _resolve_spec(client: Optional[nvd.NvdClient], row: Dict[str, Any], spec: Spec, version_field: str, update_field: str,
                  tally: _Tally) -> List[Dict[str, Any]]:
    row_id = row["id"]
    if spec.override:
        fields = cpestr.split_cpe23(spec.override)
        query_version, query_update = fields[5], fields[6]
        entry = _pair_entry(spec, spec.override, query_version)
    else:
        query_version, query_update = version_field, update_field
        entry = _pair_entry(spec, cpestr.make_cpe23(spec.part, spec.vendor, spec.product, version_field, update_field),
                            version_field)
    out = [entry]
    if row.get("action") != "lookup" or spec.role in NO_QUERY_ROLES:
        return out
    if client is None or client.offline:
        tally.offline = True
        entry["note"] = "NVD offline: name constructed"
        return out
    notes: List[str] = []
    selected: Optional[Dict[str, Any]] = None
    products: List[Dict[str, Any]] = []
    exact_ok = False
    pair_exists = "unknown"
    version_known = "unknown"
    wildcard_version = query_version in ("*", "-") or _UNESCAPED_WILDCARD_RE.search(query_version) is not None
    if not wildcard_version:
        result = client.fetch(nvd.build_url("exact", part=spec.part, vendor=spec.vendor, product=spec.product,
                                            version=query_version), row_id)
        kind, body = _read(result, tally)
        if kind == "offline":
            entry["note"] = "NVD offline: name constructed"
            return out
        if kind == "ok":
            exact_ok = True
            products = nvd.products_of_pair(nvd.products_of(body), spec.part, spec.vendor, spec.product)
            if products:
                pair_exists = "yes"
                version_known = "yes" if nvd.version_in_products(products, query_version) else "no"
                selected = nvd.select_name(products, query_version, query_update)
            else:
                version_known = "no"
        else:
            notes.append("NVD query failed (%s): name constructed" % result.error)
    if not products and (wildcard_version or exact_ok):
        result = client.fetch(nvd.build_url("exists", part=spec.part, vendor=spec.vendor, product=spec.product), row_id)
        kind, body = _read(result, tally)
        if kind == "offline":
            entry["note"] = "NVD offline: name constructed"
            return out
        if kind == "ok":
            listed = nvd.products_of(body)
            if listed:
                pair_exists = "yes" if nvd.products_of_pair(listed, spec.part, spec.vendor, spec.product) else "no"
            else:
                pair_exists = "yes" if nvd.total_results(body) > 0 else "no"
        else:
            notes.append("NVD query failed (%s): pair not checked" % result.error)
    entry["version_in_dictionary"] = version_known
    if pair_exists == "no":
        notes.append("pair not found in the NVD dictionary: name constructed")
    elif version_known == "no" and exact_ok:
        notes.append("version not in the NVD dictionary: name constructed")
    if selected is not None and (not spec.override or selected["cpe_name"].lower() == spec.override.lower()):
        entry["cpe23"] = selected["cpe_name"] if not spec.override else spec.override
        entry["cpe_name_source"] = "dictionary"
        entry["cpe_name_id"] = selected["cpe_name_id"]
        entry["deprecated"] = "yes" if selected["deprecated"] else "no"
        entry["deprecated_by"] = [s["cpe_name"] for s in selected["deprecated_by"]]
        if selected["deprecated"]:
            names: List[Dict[str, Any]] = []
            if selected["deprecated_by"]:
                names, complete = client.follow_deprecation(selected, row_id)       # type: ignore[union-attr]
                if not complete:
                    notes.append("deprecation chain not fully followed")
            for succ in names:
                made = _successor_entry(spec, succ)
                if made is not None:
                    out.append(made)
            notes.append("deprecated in the NVD dictionary" + ("; successors added" if names else ""))
    entry["note"] = "; ".join(notes)
    return out


def _search_only(client: Optional[nvd.NvdClient], row: Dict[str, Any], tally: _Tally) -> Tuple[List[str], str]:
    keyword = str(row.get("search_name") or "").strip()
    if row.get("product_hint"):
        keyword = "%s %s" % (keyword, row["product_hint"])
    if client is None or client.offline:
        tally.offline = True
        return ([], "NVD offline: keyword search not made")
    result = client.fetch(nvd.build_url("keyword", keyword=keyword), row["id"])
    kind, body = _read(result, tally)
    if kind == "offline":
        return ([], "NVD offline: keyword search not made")
    if kind == "error":
        return ([], "NVD query failed (%s): no candidates listed" % result.error)
    pairs = nvd.pairs_of_products(nvd.products_of(body), vendor_hint=str(row.get("vendor_hint") or ""),
                                  part_hint=str(row.get("part_hint") or ""))
    note = "search name only: candidates listed not emitted" if pairs else "search name only: no candidates found"
    return (pairs, note)


def _date_of(stamp: str) -> str:
    return stamp[:10] if stamp else ""


def resolve_row(client: Optional[nvd.NvdClient], row: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve one approved row (may raise ``nvd.NvdYield``); returns the JSON-compatible result kept in the progress file."""
    specs = approved_specs(row)
    result: Dict[str, Any] = {"row_id": row["id"], "kind": "pairs", "pairs": [], "keyword_candidates": [], "note": "",
                              "data_source": "not-needed", "api_errors": 0, "offline": False}
    if row.get("action") == "skip":
        result.update(kind="skip", note="skipped by approval")
        return result
    if not store.included_repos(row):
        result.update(kind="excluded", note="not included by approval")
        return result
    tally = _Tally()
    version_field, update_field = version_fields(row)
    if specs:
        seen_cpes = set()
        for spec in specs:
            for item in _resolve_spec(client, row, spec, version_field, update_field, tally):
                key = item["cpe23"].lower()
                if key in seen_cpes:
                    continue
                seen_cpes.add(key)
                result["pairs"].append(item)
    elif row.get("action") == "lookup" and str(row.get("search_name") or "").strip():
        pairs, note = _search_only(client, row, tally)
        result.update(kind="search", keyword_candidates=pairs, note=note)
    elif row.get("action") == "manual":
        result.update(kind="empty", note="manual: no pair typed")
    else:
        result.update(kind="empty", note="no approved pair and no search name")
    needs = _needs_query(row, specs)
    if tally.offline and needs:
        result["data_source"] = "offline"
        result["offline"] = True
    elif any(tally.dates):
        result["data_source"] = "live-api:%s" % min(_date_of(d) for d in tally.dates if d)
    result["api_errors"] = tally.api_errors
    return result


# ---------------------------------------------------------------------------------------------------- progress

def _load_progress(ctx: RunContext, run_id: str, approval_n: int) -> Dict[str, Any]:
    path = store.progress_path(ctx)
    try:
        doc = fsio.read_json(path)
    except (FileNotFoundError, errors.StateError):
        doc = None
    if (isinstance(doc, dict) and doc.get("schema") == store.SCHEMA and doc.get("run_id") == run_id
            and doc.get("approval_n") == approval_n and isinstance(doc.get("rows"), dict)):
        return doc
    return {"schema": store.SCHEMA, "run_id": run_id, "approval_n": approval_n, "status": "running", "nvd": "online",
            "data_source": "not-needed", "queries_done": 0, "queries_total": 0, "window_ns": [], "rows": {}}


def _save_progress(ctx: RunContext, progress: Dict[str, Any]) -> None:
    fsio.atomic_write_json(store.progress_path(ctx), progress, root=ctx.layout.out)


def _short_pairs(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"pair": p["pair"], "dictionary": p["cpe_name_source"] == "dictionary", "cpe_name_id": p["cpe_name_id"],
             "deprecated": p["deprecated"] == "yes", "deprecated_by": list(p["deprecated_by"])} for p in result["pairs"]]


# ---------------------------------------------------------------------------------------------------- the CSV

def _csv_rows(rows: Dict[str, Dict[str, Any]], results: Dict[str, Dict[str, Any]]) -> List[List[str]]:
    items: List[Tuple[Tuple[Any, ...], List[str]]] = []
    for row_id, row in rows.items():
        result = results[row_id]
        base = [row_id, row["name"], row["version"], row["action"]]
        if result["kind"] == "pairs":
            for p in result["pairs"]:
                cells = base + [p["pair"], p["role"], p["pair_source"], p["tier"], p["cpe23"], p["cpe_name_source"],
                                p["cpe_name_id"], p["deprecated"], join_list(p["deprecated_by"], sort=False),
                                p["version_in_dictionary"], "yes" if p["wildcard"] else "no", "yes" if p["emitted"] else "no",
                                "", result["data_source"], p["note"]]
                items.append(((row["name"], row["version"], store.pair_role_rank(p["role"]), p["pair"], row_id), cells))
        else:
            tier = "none"
            cells = base + ["", "", "", tier, "", "", "", "", "", "", "", "no",
                            join_list(result["keyword_candidates"], sort=False), result["data_source"], result["note"]]
            items.append(((row["name"], row["version"], 99, "", row_id), cells))
    items.sort(key=lambda it: it[0])
    return [cells for _, cells in items]


def _write_csv(ctx: RunContext, run: Any, rows: Dict[str, Dict[str, Any]], results: Dict[str, Dict[str, Any]]) -> str:
    fsio.ensure_dir(ctx.layout.staging(run.run_id), root=ctx.layout.out)
    path = store.staged_resolution_path(ctx, run.run_id)
    csvio.write_csv(path, HEADER, _csv_rows(rows, results), root=ctx.layout.out)
    return ctx.layout.out_rel(path)


# ---------------------------------------------------------------------------------------------------- the phase

def _planned_queries(rows: List[Dict[str, Any]]) -> int:
    total = 0
    for row in rows:
        specs = approved_specs(row)
        if not _needs_query(row, specs):
            continue
        total += sum(1 for s in specs if s.role not in NO_QUERY_ROLES) or 1
    return total


def resolve(ctx: RunContext, run: Any) -> model.PhaseResult:
    """Unit ``cpe:resolve``. ``done=False`` means: call again (the time budget ran out, progress is saved)."""
    rows = review.approved_rows(ctx, run)
    approval_n = int(run.data["approvals"][-1]["n"])
    progress = _load_progress(ctx, run.run_id, approval_n)
    ordered = sorted(rows.values(), key=lambda r: (r["norm_name"], r["version"], r["id"]))
    specs_of = {r["id"]: approved_specs(r) for r in ordered}
    needs = {r["id"]: _needs_query(r, specs_of[r["id"]]) for r in ordered}
    progress["queries_total"] = _planned_queries(ordered)
    client: Optional[nvd.NvdClient] = None
    if any(needs.values()):
        client = nvd.NvdClient(ctx, progress.get("window_ns") or [])
        if progress.get("nvd") == "offline":
            client.offline = True
    yielded = False
    for row in ordered:
        entry = progress["rows"].get(row["id"])
        if entry is not None and entry.get("state") == "done":
            continue
        if needs[row["id"]] and ctx.should_yield():
            yielded = True
            break
        made_before = client.queries_made if client is not None else 0
        try:
            result = resolve_row(client, row)
        except nvd.NvdYield:
            yielded = True
            progress["queries_done"] = int(progress.get("queries_done", 0)) + (client.queries_made - made_before if client else 0)
            break
        progress["rows"][row["id"]] = {"state": "done", "pairs": _short_pairs(result), "result": result}
        if client is not None:
            progress["queries_done"] = int(progress.get("queries_done", 0)) + client.queries_made - made_before
            progress["window_ns"] = client.window_ns()
            if client.offline:
                progress["nvd"] = "offline"
        _save_progress(ctx, progress)
    results = {rid: e["result"] for rid, e in progress["rows"].items() if e.get("state") == "done"}
    all_done = all(row["id"] in results for row in ordered)
    offline_rows = [r for r in results.values() if r.get("offline")]
    errors_total = sum(int(r.get("api_errors", 0)) for r in results.values())
    dates = sorted(r["data_source"][len("live-api:"):] for r in results.values() if r["data_source"].startswith("live-api:"))
    if not any(needs.values()):
        status, source = "not_needed", "not-needed"
    elif offline_rows or (client is not None and client.offline):
        status, source = "offline", "offline"
    elif dates:
        status, source = "online", "live-api:%s" % dates[-1]
    elif all_done:
        status, source = "online", "live-api:%s" % self_date(ctx)
    else:
        status, source = "online", ""
    progress["nvd"] = status
    progress["data_source"] = source or "not-needed"
    progress["status"] = "done" if all_done else "running"
    _save_progress(ctx, progress)
    phase = model.PhaseResult(done=all_done and not yielded)
    phase.info["nvd"] = {"source": source or None, "status": status}
    if status == "offline":
        phase.warnings.append(model.warning("ACTION_REQUIRED", "NVD_OFFLINE", OFFLINE_MESSAGE))
    if errors_total:
        phase.warnings.append(model.warning(
            "INFORMATIONAL", "NVD_API_ERRORS",
            "%d NVD queries failed after retries; the affected CPE names were constructed without dictionary checking"
            % errors_total))
    if phase.done:
        rel = _write_csv(ctx, run, {r["id"]: r for r in ordered}, results)
        phase.outputs[rel] = fsio.sha256_file(store.staged_resolution_path(ctx, run.run_id))
    return phase


def self_date(ctx: RunContext) -> str:
    """``YYYY-MM-DD`` of the command clock."""
    return ctx.now_iso()[:10]


# ---------------------------------------------------------------------------------------------------- reading it back

def load_resolution(ctx: RunContext, run: Any) -> Dict[str, Dict[str, Any]]:
    """``row_id -> {"emitted": [...], "alternates": [...], "flags": [...]}`` from the staged (else promoted) CSV.

    ``emitted`` items: ``cpe23``, ``role``, ``pair_source``, ``cpe_name_source``, ``cpe_name_id``, ``wildcard``.
    ``alternates``: the row's alternative pairs and keyword candidates that were not emitted. ``flags``: any of
    ``cpe_version_wildcard``, ``nvd_offline``, ``deprecated_name``, ``version_not_in_dictionary``.
    """
    staged = store.staged_resolution_path(ctx, run.run_id)
    path = staged if os.path.lexists(str(staged)) else store.promoted_resolution_path(ctx)
    try:
        table = csvio.read_csv_strict(path, HEADER)
    except FileNotFoundError as exc:
        raise errors.StateError("cpe_resolution.csv does not exist; phase 7 has not run", path=str(path)) from exc
    written = {r["id"]: r for r in review.load_written_rows(ctx)}
    out: Dict[str, Dict[str, Any]] = {}
    for rec in table.rows:
        item = out.setdefault(rec["row_id"], {"emitted": [], "alternates": [], "flags": []})
        flags: List[str] = item["flags"]
        if rec["emitted"] == "yes":
            item["emitted"].append({"cpe23": rec["cpe23"], "role": rec["role"], "pair_source": rec["pair_source"],
                                    "cpe_name_source": rec["cpe_name_source"], "cpe_name_id": rec["cpe_name_id"],
                                    "wildcard": rec["cpe_version_wildcard"] == "yes"})
            if rec["cpe_version_wildcard"] == "yes" and "cpe_version_wildcard" not in flags:
                flags.append("cpe_version_wildcard")
            if rec["data_source"] == "offline" and "nvd_offline" not in flags:
                flags.append("nvd_offline")
            if rec["deprecated"] == "yes" and "deprecated_name" not in flags:
                flags.append("deprecated_name")
            if rec["version_in_dictionary"] == "no" and "version_not_in_dictionary" not in flags:
                flags.append("version_not_in_dictionary")
        for pair in split_list(rec["keyword_candidates"], ";"):
            if pair not in item["alternates"]:
                item["alternates"].append(pair)
    for row_id, item in out.items():
        row = written.get(row_id)
        emitted_pairs = set()
        for e in item["emitted"]:
            try:
                emitted_pairs.add(cpestr.pair_str(*cpestr.pair_of_cpe23(e["cpe23"])))
            except ValueError:
                pass
        if row is not None:
            for alt in row.get("alternatives") or []:
                if alt["pair"] not in item["alternates"]:
                    item["alternates"].append(alt["pair"])
        item["alternates"] = sorted(p for p in item["alternates"] if p not in emitted_pairs)
        item["flags"] = sorted(item["flags"])
    return out


class _CallableModule(types.ModuleType):
    """``sbomlib.cpe.resolve`` is the phase-7 entry point of the package and also a module: calling the module runs it."""

    def __call__(self, ctx: RunContext, run: Any) -> model.PhaseResult:
        return resolve(ctx, run)


sys.modules[__name__].__class__ = _CallableModule
