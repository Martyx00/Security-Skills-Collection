"""``sbom-out/local-cpe-decisions.csv``: approved decisions carried into the next run (contract section 4.18).

Written by the audit on PASS only, from the latest approval, so every row comes from an audited run. The file survives
``start`` and accumulates: rows whose key is absent from the new run are kept unchanged. Only the CPE columns and
``emitted_pairs`` are carried into the next review file; ``include`` and ``include_in`` are recorded for information.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sbomlib import csvio, errors
from sbomlib.context import RunContext
from sbomlib.cpe import cpestr, store
from sbomlib.norm import join_list, split_list

HEADER = ("key", "name", "version", "upstream_commit", "include", "include_in", "action", "search_name", "vendor_hint",
          "product_hint", "part_hint", "cpe_override", "cpe_version_override", "cpe_update_override",
          "extra_vendor_products", "emitted_pairs", "run_id", "approved_at")
# The columns that are copied into the next review file (the report's precedence 2).
CARRIED_COLUMNS = ("action", "search_name", "vendor_hint", "product_hint", "part_hint", "cpe_override",
                   "cpe_version_override", "cpe_update_override", "extra_vendor_products")
SEPARATOR = ";"


def key_text(key: Tuple[str, ...]) -> str:
    return SEPARATOR.join(key)


def key_tuple(text: str) -> Tuple[str, ...]:
    return tuple(text.split(SEPARATOR))


def _read_records(ctx: RunContext) -> List[Dict[str, str]]:
    path = store.local_decisions_path(ctx)
    try:
        table = csvio.read_csv_strict(path, HEADER)
    except FileNotFoundError:
        return []
    except errors.CsvReadError as exc:
        try:
            ctx.log.warning("cpe.local_decisions_unreadable", reason=exc.detail.get("reason"), line=exc.detail.get("line"))
        except Exception:
            pass
        return []
    return list(table.rows)


def load_local_decisions(ctx: RunContext) -> Dict[Tuple[str, ...], Dict[str, Any]]:
    """Review key tuple -> the recorded row (all cells as text). An absent or unreadable file gives ``{}``."""
    out: Dict[Tuple[str, ...], Dict[str, Any]] = {}
    for record in _read_records(ctx):
        if record["key"]:
            out[key_tuple(record["key"])] = dict(record)
    return out


def emitted_pairs_text(emitted: List[Dict[str, Any]]) -> str:
    """The pairs behind the emitted CPEs of a row, without the ones typed by the human (they travel in their own cells)."""
    pairs: List[str] = []
    for item in emitted:
        if item.get("role") in ("override", "extra"):
            continue
        try:
            part, vendor, product = cpestr.pair_of_cpe23(item["cpe23"])
        except (ValueError, KeyError):
            continue
        text = cpestr.pair_str(part, vendor, product)
        if text not in pairs:
            pairs.append(text)
    return SEPARATOR.join(pairs)


def write_local_decisions(ctx: RunContext, run: Any) -> str:
    """Write ``sbom-out/local-cpe-decisions.csv`` from the latest approval; returns its PARENT-relative path."""
    from sbomlib.cpe import resolve, review            # function-local: both import this module
    rows = review.approved_rows(ctx, run)
    resolution = resolve.load_resolution(ctx, run)
    approvals = run.data.get("approvals") or []
    approved_at = str(approvals[-1].get("approved_at") or "") if approvals else ""
    merged: Dict[str, Dict[str, str]] = {}
    for record in _read_records(ctx):
        if record["key"]:
            merged[record["key"]] = dict(record)
    for row in rows.values():
        emitted = (resolution.get(row["id"]) or {}).get("emitted") or []
        record = {
            "key": key_text(tuple(row["key"])), "name": str(row.get("name") or ""), "version": str(row.get("version") or ""),
            "upstream_commit": str(row.get("upstream_commit") or ""), "include": str(row.get("include") or ""),
            "include_in": join_list(row.get("include_in") or []),
            "emitted_pairs": emitted_pairs_text(emitted), "run_id": str(run.run_id), "approved_at": approved_at,
        }
        for column in CARRIED_COLUMNS:
            record[column] = str(row.get(column) or "")
        merged[record["key"]] = record
    ordered = [merged[k] for k in sorted(merged)]
    csvio.write_csv(store.local_decisions_path(ctx), HEADER, [[rec.get(c, "") for c in HEADER] for rec in ordered],
                    root=ctx.layout.out)
    return ctx.layout.rel(store.local_decisions_path(ctx))


def split_emitted(text: str) -> List[str]:
    return [item for item in split_list(text or "", SEPARATOR) if item]


def recorded_inclusion(decision: Dict[str, Any]) -> Tuple[str, List[str]]:
    """``(include, include_in)`` recorded by the previous run."""
    return (str(decision.get("include") or "").lower(), split_list(str(decision.get("include_in") or ""), SEPARATOR))


def previous_run_note(decision: Optional[Dict[str, Any]], include: str, include_in: List[str]) -> str:
    """``previous run: include=no; `` when the recorded inclusion differs from this run's pre-fill, else an empty string."""
    if not decision:
        return ""
    old_include, old_in = recorded_inclusion(decision)
    if old_include not in ("yes", "no"):
        return ""
    differs = old_include != include
    if not differs and include == "yes" and old_in and set(old_in) != set(include_in):
        differs = True
    if not differs:
        return ""
    text = "previous run: include=%s" % old_include
    if old_include == "yes" and old_in:
        text += " in %s" % SEPARATOR.join(sorted(old_in))
    return text + "; "


__all__ = ["HEADER", "CARRIED_COLUMNS", "load_local_decisions", "write_local_decisions", "emitted_pairs_text",
           "previous_run_note", "key_text", "key_tuple"]
