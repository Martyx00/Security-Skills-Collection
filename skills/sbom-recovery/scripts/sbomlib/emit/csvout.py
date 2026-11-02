"""The three per-repository CSV tables derived from ``components.json`` (contract sections 4.20, 4.22 and 4.23).

Pure functions, no I/O: they return ``(header, rows)`` and ``csvio.render_csv`` / ``csvio.write_csv`` (formula guard,
``utf-8-sig``, CRLF) turn them into files. Multi-valued cells are ``;``-joined (``notes``: `` | ``); unknown names and
versions are ``NOASSERTION``; booleans are ``yes`` / ``no``.
"""
from __future__ import annotations

import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sbomlib.norm import join_list

NOASSERTION = "NOASSERTION"

REPO_HEADER = ("name", "version", "cpe23", "locations", "spdx_id", "verification", "cpe_alternates", "purl", "upstream_url",
               "upstream_commit", "usage", "usage_level", "scope", "identity_confidence", "version_confidence",
               "version_source", "version_kind", "analysis_mode", "evidence_types", "detection_method", "detected_as",
               "sha256", "supplier", "license_declared", "cpe_version_wildcard", "cpe_name_source", "pair_source",
               "cpe_name_id", "notes")
EVIDENCE_HEADER = ("spdx_id", "candidate_id", "evidence_id", "type", "strength", "path", "line", "symbol", "detail", "scope",
                   "condition", "technique")
AUDIT_HEADER = ("candidate_id", "name", "version", "class", "usage_level", "scope", "reason_code", "condition",
                "verification", "in_sbom", "spdx_id", "detected_as", "locations", "evidence_ids", "notes")


def yes_no(flag: bool) -> str:
    return "yes" if flag else "no"


def semi(items: Iterable[Any]) -> str:
    """``;``-joined, unique, sorted."""
    return join_list([str(i) for i in items if i not in (None, "")])


def render_condition(condition: Optional[Dict[str, Any]]) -> str:
    """Compact rendering of a build condition (section 4.22): ``WITH_LZ4`` / ``NOT WITH_LZ4`` /
    ``CMAKE_BUILD_TYPE==Release`` / ``platform:WIN32``, ``&&``-joined, ``?`` for an unknown clause."""
    if not condition:
        return ""
    from sbomlib.verify.configs import render_condition as render
    return render(condition)


def plain(text: Any, limit: Optional[int] = None) -> str:
    """Single-line text for a cell: control characters become spaces, runs of white space collapse."""
    if text is None:
        return ""
    value = "".join(" " if unicodedata.category(ch) == "Cc" else ch for ch in str(text))
    value = " ".join(value.split())
    if limit is not None and len(value) > limit:
        value = value[:limit - 1] + "…"
    return value


def cpe_cells(component: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """``(cpe23, cpe_name_source, pair_source, cpe_name_id)`` cells: ``;``-joined, aligned with each other."""
    cpes = component.get("cpes") or []
    if not cpes:
        return ("", "", "", "")
    return (";".join(str(c.get("cpe23") or "") for c in cpes),
            ";".join(str(c.get("cpe_name_source") or "none") for c in cpes),
            ";".join(str(c.get("pair_source") or "none") for c in cpes),
            ";".join(str(c.get("cpe_name_id") or "none") for c in cpes))


def component_row(component: Dict[str, Any], analysis_mode: str) -> List[str]:
    """One row of the per-repository CSV, in the order of ``REPO_HEADER``."""
    cpe23, name_source, pair_source, name_id = cpe_cells(component)
    wildcard = any(bool(c.get("wildcard")) for c in component.get("cpes") or [])
    values = {
        "name": plain(component.get("name")) or NOASSERTION,
        "version": str(component.get("version") or NOASSERTION),
        "cpe23": cpe23,
        "locations": semi(component.get("locations") or []),
        "spdx_id": component["spdx_id"],
        "verification": str(component.get("verification") or ""),
        "cpe_alternates": semi(component.get("cpe_alternates") or []),
        "purl": semi(component.get("purls") or []),
        "upstream_url": component.get("upstream_url") or "",
        "upstream_commit": component.get("upstream_commit") or "",
        "usage": semi(component.get("usage") or []),
        "usage_level": str(component.get("usage_level") or "none"),
        "scope": str(component.get("scope") or "product"),
        "identity_confidence": str(component.get("identity_confidence") or "none"),
        "version_confidence": str(component.get("version_confidence") or "none"),
        "version_source": str(component.get("version_source") or "none"),
        "version_kind": str(component.get("version_kind") or "none"),
        "analysis_mode": analysis_mode,
        "evidence_types": semi(component.get("evidence_types") or []),
        "detection_method": str(component.get("detection_method") or "other"),
        "detected_as": semi(component.get("detected_as") or []),
        "sha256": component.get("sha256") or "",
        "supplier": str(component.get("supplier") or NOASSERTION),
        "license_declared": str(component.get("license_declared") or NOASSERTION),
        "cpe_version_wildcard": yes_no(wildcard),
        "cpe_name_source": name_source,
        "pair_source": pair_source,
        "cpe_name_id": name_id,
        "notes": " | ".join(plain(n) for n in component.get("notes") or [] if n),
    }
    return [values[column] for column in REPO_HEADER]


def repo_table(components: Dict[str, Any]) -> Tuple[List[str], List[List[str]]]:
    """Header and rows of ``<repo>.sbom.csv``: one row per component, sorted by ``(norm_name, version, spdx_id)``."""
    mode = str(components.get("analysis_mode") or "static")
    items = sorted(components.get("components") or [],
                   key=lambda c: (str(c.get("norm_name") or ""), str(c.get("version") or ""), str(c["spdx_id"])))
    return (list(REPO_HEADER), [component_row(c, mode) for c in items])


def evidence_table(components: Dict[str, Any], evidence: Dict[str, Dict[str, Any]]) -> Tuple[List[str], List[List[str]]]:
    """Header and rows of ``<repo>.evidence.csv``: one row per evidence record of the repository, sorted by
    ``(path, line, evidence_id)``. ``spdx_id`` is empty for records of candidates that are not in the SBOM (and for records
    without a candidate)."""
    spdx_of: Dict[str, str] = {}
    for comp in components.get("components") or []:
        for cid in comp.get("candidate_ids") or []:
            spdx_of[str(cid)] = comp["spdx_id"]
    records = sorted(evidence.values() if isinstance(evidence, dict) else evidence, key=lambda r: (str(r.get("path") or ""),
                                                      r.get("line") if isinstance(r.get("line"), int) else -1,
                                                      str(r.get("id"))))
    rows: List[List[str]] = []
    for rec in records:
        cid = str(rec.get("candidate") or "")
        line = rec.get("line")
        rows.append([spdx_of.get(cid, ""), cid, str(rec.get("id")), str(rec.get("type") or ""),
                     str(rec.get("strength") or ""), str(rec.get("path") or ""),
                     str(line) if isinstance(line, int) and not isinstance(line, bool) else "",
                     plain(rec.get("symbol")), plain(rec.get("detail"), 200), str(rec.get("scope") or ""),
                     render_condition(rec.get("condition")), str(rec.get("technique") or "")])
    return (list(EVIDENCE_HEADER), rows)


def audit_table(components: Dict[str, Any]) -> Tuple[List[str], List[List[str]]]:
    """Header and rows of ``candidates_audit.csv``: every candidate, in the SBOM or not, sorted by
    ``(name, version, candidate_id)``."""
    rows: List[Tuple[Tuple[str, str, str], List[str]]] = []
    for comp in components.get("components") or []:
        info = comp.get("candidate_info") or {}
        for cid in comp.get("candidate_ids") or []:
            item = info.get(cid) or {}
            rows.append(((str(comp["name"]), str(comp["version"]), str(cid)), [
                str(cid), plain(comp["name"]), str(comp["version"]), str(item.get("class") or comp.get("class") or ""),
                str(item.get("usage_level") or comp.get("usage_level") or "none"),
                str(item.get("scope") or comp.get("scope") or "product"), str(item.get("reason_code") or ""),
                str(item.get("condition") or comp.get("condition") or ""),
                str(item.get("verification") or comp.get("verification") or ""), "yes", comp["spdx_id"],
                semi(comp.get("detected_as") or []), semi(item.get("locations") or comp.get("locations") or []),
                semi(item.get("evidence_ids") or comp.get("evidence_ids") or []),
                " | ".join(plain(n) for n in (item.get("notes") if item.get("notes") is not None else comp.get("notes")) or [])]))
    for entry in components.get("excluded") or []:
        rows.append(((str(entry["name"]), str(entry["version"]), str(entry["candidate_id"])), [
            str(entry["candidate_id"]), plain(entry["name"]), str(entry["version"]), str(entry.get("class") or ""),
            str(entry.get("usage_level") or "none"), str(entry.get("scope") or "product"),
            str(entry.get("reason_code") or ""), str(entry.get("condition") or ""), str(entry.get("verification") or ""),
            "no", "", semi(entry.get("detected_as") or []), semi(entry.get("locations") or []),
            semi(entry.get("evidence_ids") or []), " | ".join(plain(n) for n in entry.get("notes") or [])]))
    rows.sort(key=lambda item: item[0])
    return (list(AUDIT_HEADER), [r for _k, r in rows])


def creation_comment(ctx: Any, run: Any, repo: str) -> str:
    """``creationInfo.comment`` of the repository's SPDX document (implemented in ``emit.spdx``)."""
    from sbomlib.emit import spdx
    return spdx.creation_comment(ctx, run, repo)
