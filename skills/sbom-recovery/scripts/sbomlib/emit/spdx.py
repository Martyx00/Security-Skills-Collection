"""The SPDX 2.3 JSON document of one repository (contract section 4.21).

``build_document`` is a pure function of ``components.json``: stable SPDXIDs, ``DESCRIBES`` from the document to the root
package, ``cpe23Type`` and ``purl`` external references, one location annotation per location plus one provenance
annotation per package, relationships per usage class, and a content-derived document namespace.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Sequence

from sbomlib import fsio, ids, model, urls
from sbomlib.context import RunContext
from sbomlib.emit.components import REVERSED_RELATIONSHIPS, scrub
from sbomlib.emit.csvout import plain
from sbomlib.state import RunState

NOASSERTION = "NOASSERTION"
SPDX_VERSION = "SPDX-2.3"
DOCUMENT_ID = "SPDXRef-DOCUMENT"
NAMESPACE_PREFIX = "https://spdx.org/spdxdocs/kiro-sbomber/"
LOCATION_PREFIX = "kiro-sbomber:location "
PROVENANCE_PREFIX = "kiro-sbomber:provenance "
MAX_BLINDSPOT_COMMENT = 2000
MAX_SOURCE_INFO_LOCATIONS = 10


def tool_name(version: str) -> str:
    """``kiro-sbomber-<version>``."""
    return "kiro-sbomber-%s" % version


def creator_of(tool: str) -> str:
    """``Tool: kiro-sbomber-0.1.0`` from ``kiro-sbomber-0.1.0`` or ``Tool: kiro-sbomber-0.1.0``."""
    return tool if tool.startswith("Tool: ") else "Tool: " + tool


# ------------------------------------------------------------------------------------------------ creation comment

def creation_comment(ctx: RunContext, run: RunState, repo: str) -> str:
    """``creationInfo.comment``: the generation context, what is described, the repository status, approval evidence, the
    enforcement statement, the NVD data source, a pointer to the blind spots, the repositories that have no SBOM in this run,
    and the NVD notice (contract section 4.21)."""
    entry = run.repo(repo)
    head = entry.get("head") or _queue_head(ctx, repo) or "unknown"
    status = str(entry.get("status") or "DONE")
    incomplete = [plain(r, 160) for r in (entry.get("incomplete") or [])][:3]
    status_text = "%s (%s)" % (status, "; ".join(incomplete)) if incomplete and status == "INCOMPLETE" else status
    approvals = run.data.get("approvals") or []
    evidence = (approvals[-1].get("evidence") if approvals else None) or "none"
    nvd = (run.data.get("nvd") or {}).get("source") or _progress_source(ctx) or "unknown"
    missing = []
    for other in run.all_repos():
        if other == repo:
            continue
        other_status = run.repo(other).get("status")
        if other_status in ("FAILED", "NOT ANALYZED"):
            missing.append("%s (%s)" % (plain(other, 100), other_status))
    parts = [
        "%s." % model.SPDX_CONTEXT,
        "Describes HEAD %s of %s plus checked-out submodules." % (head, plain(repo, 120)),
        "Repository status: %s." % status_text,
        "Approval evidence: %s; %s." % (evidence, model.ENFORCEMENT_NOTE),
        "NVD data source: %s." % nvd,
        "Blind spots: see the DEPENDS_ON NOASSERTION relationship.",
    ]
    if missing:
        parts.append("Repositories without an SBOM in this run: %s." % ", ".join(sorted(missing)))
    parts.append(model.NVD_NOTICE)
    return " ".join(parts)


def _queue_head(ctx: RunContext, repo: str) -> Optional[str]:
    try:
        from sbomlib import state
        for item in state.load_queue(ctx).get("repos") or []:
            if item.get("name") == repo and item.get("head"):
                return str(item["head"])
    except Exception:                                 # noqa: BLE001 - the HEAD is a detail of a comment
        return None
    return None


def _progress_source(ctx: RunContext) -> Optional[str]:
    try:
        doc = fsio.read_json(ctx.layout.state / "cpe_progress.json")
    except Exception:                                 # noqa: BLE001 - a missing or damaged progress file only loses a detail
        return None
    value = doc.get("data_source") if isinstance(doc, dict) else None
    return str(value) if value else None


# ----------------------------------------------------------------------------------------------------- the document

def _annotation(creator: str, created: str, comment: str) -> Dict[str, Any]:
    return {"annotationType": "OTHER", "annotator": creator, "annotationDate": created, "comment": comment}


def _blindspot_comment(blindspots: Sequence[Dict[str, Any]]) -> str:
    head = "Source-recovered list may be incomplete."
    if not blindspots:
        return head + " Blind spots: none recorded."
    items = []
    for spot in blindspots:
        where = " at %s" % spot["loc"] if spot.get("loc") else ""
        items.append("%s%s: %s" % (spot.get("code"), where, plain(spot.get("message"), 200)))
    text = head + " Blind spots: " + "; ".join(items)
    if len(text) > MAX_BLINDSPOT_COMMENT:
        text = text[:MAX_BLINDSPOT_COMMENT - 1] + "…"
    return text


def provenance_payload(component: Dict[str, Any], analysis_mode: str) -> Dict[str, Any]:
    cpes = component.get("cpes") or []
    payload: Dict[str, Any] = {
        "analysis_mode": analysis_mode,
        "cpe_name_sources": sorted({str(c.get("cpe_name_source")) for c in cpes if c.get("cpe_name_source")}),
        "cpe_version_wildcard": any(bool(c.get("wildcard")) for c in cpes),
        "detected_as": sorted(component.get("detected_as") or []),
        "identity_confidence": component.get("identity_confidence"),
        "pair_sources": sorted({str(c.get("pair_source")) for c in cpes if c.get("pair_source")}),
        "scope": component.get("scope"),
        "usage": sorted(component.get("usage") or []),
        "usage_level": component.get("usage_level"),
        "verification": component.get("verification"),
        "version_confidence": component.get("version_confidence"),
        "version_kind": component.get("version_kind"),
        "version_source": component.get("version_source"),
    }
    if component.get("condition"):
        payload["condition"] = component["condition"]
    return payload


def _package(component: Dict[str, Any], creator: str, created: str, analysis_mode: str) -> Dict[str, Any]:
    locations = list(component.get("locations") or [])
    shown = locations[:MAX_SOURCE_INFO_LOCATIONS]
    info = "package found in: " + ", ".join(shown) if shown else "package found by script evidence"
    if len(locations) > len(shown):
        info += " and %d more" % (len(locations) - len(shown))
    pkg: Dict[str, Any] = {
        "SPDXID": component["spdx_id"], "name": component["name"],
        "versionInfo": component.get("version") or NOASSERTION,
        "downloadLocation": urls.spdx_download_location(component.get("upstream_url"), component.get("upstream_commit")),
        "filesAnalyzed": False, "primaryPackagePurpose": "LIBRARY",
        "supplier": component.get("supplier") or NOASSERTION,
        "licenseConcluded": NOASSERTION, "licenseDeclared": component.get("license_declared") or NOASSERTION,
        "copyrightText": NOASSERTION, "sourceInfo": info,
    }
    if component.get("sha256"):
        pkg["checksums"] = [{"algorithm": "SHA256", "checksumValue": component["sha256"]}]
    notes = [plain(n) for n in component.get("notes") or [] if n]
    if notes:
        pkg["comment"] = " | ".join(notes)
    refs: List[Dict[str, str]] = []
    for cpe in component.get("cpes") or []:
        refs.append({"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": cpe["cpe23"]})
    for purl in component.get("purls") or []:
        refs.append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl})
    if refs:
        pkg["externalRefs"] = refs
    occurrences = list(component.get("occurrences") or [])
    if len(occurrences) == len(locations):
        occurrence_of = dict(zip(locations, occurrences))          # one occurrence per location, in the same order
    else:
        occurrence_of = {}
        for occ in occurrences:
            occurrence_of.setdefault(_occurrence_location(occ), occ)
    annotations = []
    for loc in locations:
        occ = occurrence_of.get(loc) or {}
        payload = {"evidence_id": occ.get("evidence_id"), "loc": loc, "type": occ.get("evidence_type")}
        annotations.append(_annotation(creator, created, LOCATION_PREFIX + fsio.dumps_compact(payload)))
    annotations.append(_annotation(creator, created, PROVENANCE_PREFIX + fsio.dumps_compact(
        provenance_payload(component, analysis_mode))))
    annotations.sort(key=lambda a: a["comment"])
    pkg["annotations"] = annotations
    return pkg


def _occurrence_location(occ: Dict[str, Any]) -> str:
    path = occ.get("path") or ""
    line = occ.get("line")
    if occ.get("evidence_type") == "FILE_PRESENT" and path:
        return path.rstrip("/") + "/"
    return "%s:%d" % (path, line) if isinstance(line, int) and line > 0 else path


def _relationships(components: Dict[str, Any]) -> List[Dict[str, Any]]:
    root_id = components["root"]["spdx_id"]
    rels: List[Dict[str, Any]] = [{"spdxElementId": DOCUMENT_ID, "relationshipType": "DESCRIBES",
                                   "relatedSpdxElement": root_id}]
    for comp in components.get("components") or []:
        for token in comp.get("relationships") or []:
            if token in REVERSED_RELATIONSHIPS:
                rels.append({"spdxElementId": comp["spdx_id"], "relationshipType": token, "relatedSpdxElement": root_id})
            else:
                rels.append({"spdxElementId": root_id, "relationshipType": token, "relatedSpdxElement": comp["spdx_id"]})
        if comp.get("class") == "UNANALYZED":
            rels.append({"spdxElementId": comp["spdx_id"], "relationshipType": "CONTAINS", "relatedSpdxElement": NOASSERTION})
    rels.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": NOASSERTION,
                 "comment": _blindspot_comment(components.get("blindspots") or [])})
    seen = set()
    unique = []
    for rel in rels:
        key = (rel["spdxElementId"], rel["relationshipType"], rel["relatedSpdxElement"])
        if key not in seen:
            seen.add(key)
            unique.append(rel)
    unique.sort(key=lambda r: (r["spdxElementId"], r["relationshipType"], r["relatedSpdxElement"]))
    return unique


def namespace_for(repo: str, document: Dict[str, Any]) -> str:
    """``documentNamespace``: the repository slug plus a UUIDv5 of the canonical content, so that it is stable across
    runs and changes with the content (the namespace itself, ``creationInfo`` and every ``annotationDate`` are left out)."""
    body = json.loads(json.dumps(document))
    body.pop("documentNamespace", None)
    body.pop("creationInfo", None)
    for pkg in body.get("packages") or []:
        for annotation in pkg.get("annotations") or []:
            annotation.pop("annotationDate", None)
    for annotation in body.get("annotations") or []:
        annotation.pop("annotationDate", None)
    digest = hashlib.sha256(fsio.dumps_compact(body).encode("utf-8", "backslashreplace")).hexdigest()
    return NAMESPACE_PREFIX + ids.slug(repo) + "-" + str(uuid.uuid5(uuid.NAMESPACE_URL, digest))


def build_document(components: Dict[str, Any], *, created: str, tool: str, creation_comment: str) -> Dict[str, Any]:
    """The SPDX 2.3 document for ``components`` (the content of ``components.json``)."""
    creator = creator_of(tool)
    mode = str(components.get("analysis_mode") or "static")
    root = components["root"]
    root_pkg: Dict[str, Any] = {"SPDXID": root["spdx_id"], "name": root["name"]}
    version = root.get("describe") or (str(root["head"])[:12] if root.get("head") else None)
    if version:
        root_pkg["versionInfo"] = version
    root_pkg.update({
        "downloadLocation": root.get("download_location") or NOASSERTION, "filesAnalyzed": False,
        "primaryPackagePurpose": "SOURCE", "sourceInfo": root.get("source_info") or "",
        "licenseConcluded": NOASSERTION, "licenseDeclared": NOASSERTION, "copyrightText": NOASSERTION,
        "supplier": NOASSERTION})
    packages = [root_pkg]
    for comp in sorted(components.get("components") or [], key=lambda c: c["spdx_id"]):
        packages.append(_package(comp, creator, created, mode))
    document: Dict[str, Any] = {
        "spdxVersion": SPDX_VERSION, "dataLicense": "CC0-1.0", "SPDXID": DOCUMENT_ID,
        "name": "%s-sbom" % components["repo"],
        "documentNamespace": "",
        "creationInfo": {"created": created, "creators": [creator], "comment": creation_comment},
        "packages": packages, "relationships": _relationships(components),
    }
    refs = sorted({ref for comp in components.get("components") or [] for ref in _license_refs(comp)})
    if refs:
        document["hasExtractedLicensingInfos"] = [
            {"licenseId": ref, "extractedText": NOASSERTION, "name": ref,
             "comment": "Referenced by a recovered licence expression; the licence text was not extracted."} for ref in refs]
    document["documentNamespace"] = namespace_for(components["repo"], document)
    return scrub(document)


def _license_refs(component: Dict[str, Any]) -> List[str]:
    from sbomlib.emit import licexpr
    return licexpr.license_refs(str(component.get("license_declared") or ""))


def dumps_document(document: Dict[str, Any]) -> str:
    """The file text: not key-sorted, two-space indent, trailing newline (contract section 4.21)."""
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def parse_location_annotation(comment: str) -> Optional[Dict[str, Any]]:
    """The payload of a ``kiro-sbomber:location`` annotation comment, or ``None``."""
    return _parse_payload(comment, LOCATION_PREFIX)


def parse_provenance_annotation(comment: str) -> Optional[Dict[str, Any]]:
    return _parse_payload(comment, PROVENANCE_PREFIX)


def _parse_payload(comment: Any, prefix: str) -> Optional[Dict[str, Any]]:
    if not isinstance(comment, str) or not comment.startswith(prefix):
        return None
    try:
        payload = json.loads(comment[len(prefix):])
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None
