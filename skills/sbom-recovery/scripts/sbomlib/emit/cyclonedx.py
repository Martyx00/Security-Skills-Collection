"""The CycloneDX 1.6 JSON document of one repository, next to the SPDX 2.3 document (TASKLIST 3.7).

``build_document`` is a pure function of ``components.json``: the same components, the same identifiers and the same
facts as ``spdx.build_document``, written in the other format. It is deterministic: the ``bom-ref`` of a component is its
SPDX id without the prefix (stable between runs, unlike an ordinal), and ``serialNumber`` is a UUIDv5 of the content (the
timestamp and the serial number themselves are left out), so the same inputs give the same file. ``cdxcheck`` checks the
shape of the result with the standard library only; ``validate`` runs that check and compares the document with the CSV.

What the document claims, and what it does not:

* ``version`` of the root component is the commit that was analysed; ``kiro-sbomber:describe`` and ``:branch`` are properties;
* a component without a normalized release has no ``version`` (the raw text and the kind are properties and notes);
* the aggregate of ``compositions`` is never ``complete``: a list recovered from source may be incomplete;
* a licence is a ``license.id`` only when the id is in the CycloneDX 1.6 list (``assets/cyclonedx-license-ids.json``),
  otherwise an ``expression``; nothing is looked up;
* ``cpe`` carries the primary emitted CPE, further emitted CPEs are ``kiro-sbomber:cpe-additional`` properties.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Sequence

from sbomlib import fsio, urls
from sbomlib.emit.components import scrub
from sbomlib.emit.csvout import plain

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.6"
PROP = "kiro-sbomber:"
SERIAL_NAMESPACE = uuid.UUID("5d0b2d3c-7a51-5f0e-9a3e-6a52c1f0b9a1")
MAX_KNOWN_UNKNOWNS = 100
MAX_PROPERTY = 2000
NOASSERTION = "NOASSERTION"
#: SPDX relationship types that say "this component is only a test, development or build dependency of the root"
NOT_SHIPPED_TOKENS = ("TEST_DEPENDENCY_OF", "TEST_TOOL_OF", "DEV_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "BUILD_TOOL_OF")


def tool_name() -> str:
    return "kiro-sbomber"


def _strip_prefix(spdx_id: str) -> str:
    return spdx_id[len("SPDXRef-"):] if spdx_id.startswith("SPDXRef-") else spdx_id


def root_ref(components: Dict[str, Any]) -> str:
    return _strip_prefix(components["root"]["spdx_id"])


def component_ref(component: Dict[str, Any]) -> str:
    return _strip_prefix(component["spdx_id"])


def _prop(name: str, value: Any) -> Dict[str, str]:
    return {"name": PROP + name, "value": plain(value, MAX_PROPERTY)}


def _props(pairs: Sequence[Any]) -> List[Dict[str, str]]:
    return [_prop(name, value) for name, value in pairs if value not in (None, "", [])]


def _supplier_name(text: Any) -> Optional[str]:
    value = " ".join(str(text or "").split())
    if not value or value == NOASSERTION:
        return None
    for prefix in ("Organization: ", "Person: ", "Tool: "):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value or None


def license_entries(value: Any, listed_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """``licenses`` of a component: ``[]`` for NOASSERTION, ``{"license": {"id": ...}}`` for one id of the CycloneDX list,
    otherwise ``{"expression": ...}`` (a compound expression, a ``LicenseRef`` or an id the list does not have)."""
    text = " ".join(str(value or "").split())
    if not text or text == NOASSERTION:
        return []
    if text in listed_ids:
        return [{"license": {"id": text}}]
    return [{"expression": text}]


def _scope_of(component: Dict[str, Any]) -> str:
    tokens = component.get("relationships") or []
    if any(t in NOT_SHIPPED_TOKENS for t in tokens):
        return "excluded"
    return "optional" if component.get("class") == "OPTIONAL" else "required"


def _component(comp: Dict[str, Any], listed_ids: Sequence[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"type": "firmware" if "co_flashed_image" in (comp.get("detected_as") or []) else "library",
                           "bom-ref": component_ref(comp), "name": plain(comp.get("name")) or NOASSERTION}
    supplier = _supplier_name(comp.get("supplier"))
    if supplier:
        out["supplier"] = {"name": plain(supplier)}
    version = comp.get("version")
    if version and version != NOASSERTION:
        out["version"] = str(version)
    out["scope"] = _scope_of(comp)
    if comp.get("sha256"):
        out["hashes"] = [{"alg": "SHA-256", "content": str(comp["sha256"]).lower()}]
    licenses = license_entries(comp.get("license_declared"), listed_ids)
    if licenses:
        out["licenses"] = licenses
    cpes = [c for c in comp.get("cpes") or [] if c.get("cpe23")]
    if cpes:
        out["cpe"] = str(cpes[0]["cpe23"])
    purls = [p for p in comp.get("purls") or [] if p]
    if purls:
        out["purl"] = str(purls[0])
    props: List[Dict[str, str]] = []
    props.extend(_props([("verification", comp.get("verification")), ("class", comp.get("class")),
                         ("usage-level", comp.get("usage_level")), ("scope", comp.get("scope")),
                         ("version-kind", comp.get("version_kind")), ("version-source", comp.get("version_source")),
                         ("version-raw", comp.get("version_raw")),
                         ("identity-confidence", comp.get("identity_confidence")),
                         ("version-confidence", comp.get("version_confidence")),
                         ("condition", comp.get("condition")), ("upstream-commit", comp.get("upstream_commit"))]))
    for kind in sorted(comp.get("detected_as") or []):
        props.append(_prop("detected-as", kind))
    for usage in sorted(comp.get("usage") or []):
        props.append(_prop("usage", usage))
    for extra in cpes[1:]:
        props.append(_prop("cpe-additional", extra["cpe23"]))
    for alternate in comp.get("cpe_alternates") or []:
        props.append(_prop("cpe-alternate", alternate))
    if any(bool(c.get("wildcard")) for c in cpes):
        props.append(_prop("cpe-version-wildcard", "yes"))
    for source in sorted({str(c.get("cpe_name_source")) for c in cpes if c.get("cpe_name_source")}):
        props.append(_prop("cpe-name-source", source))
    for source in sorted({str(c.get("pair_source")) for c in cpes if c.get("pair_source")}):
        props.append(_prop("pair-source", source))
    notes = [plain(n) for n in comp.get("notes") or [] if n]
    if notes:
        props.append(_prop("notes", " | ".join(notes)))
    out["properties"] = props
    occurrences = []
    for occ in comp.get("occurrences") or []:
        path = occ.get("path")
        if not path:
            continue
        item: Dict[str, Any] = {"location": str(path)}
        line = occ.get("line")
        if isinstance(line, int) and not isinstance(line, bool) and line >= 0:
            item["line"] = line
        if occ.get("symbol"):
            item["symbol"] = plain(occ["symbol"], 200)
        occurrences.append(item)
    if occurrences:
        out["evidence"] = {"occurrences": occurrences}
    ref = urls.https_form(comp.get("upstream_url")) if comp.get("upstream_url") else None
    if ref:
        out["externalReferences"] = [{"type": "vcs", "url": ref}]
    return out


def _root(components: Dict[str, Any], tool_version: str) -> Dict[str, Any]:
    root = components["root"]
    out: Dict[str, Any] = {"type": "application", "bom-ref": root_ref(components), "name": components["repo"]}
    if root.get("head"):
        out["version"] = str(root["head"])
    out["properties"] = _props([("commit", root.get("head")), ("describe", root.get("describe")),
                                ("branch", root.get("branch")), ("repository-status", components.get("status"))])
    origin = urls.https_form(root.get("origin")) if root.get("origin") else None
    if origin:
        out["externalReferences"] = [{"type": "vcs", "url": origin}]
    return out


def _compositions(components: Dict[str, Any]) -> List[Dict[str, Any]]:
    unanalyzed = sorted(component_ref(c) for c in components.get("components") or [] if c.get("class") == "UNANALYZED")
    open_items = [e for e in components.get("excluded") or [] if e.get("class") in ("INCONCLUSIVE", "UNANALYZED")]
    incomplete = (components.get("status") == "INCOMPLETE" or bool(components.get("blindspots")) or bool(open_items)
                  or bool(unanalyzed))
    result = [{"aggregate": "incomplete" if incomplete else "unknown", "assemblies": [root_ref(components)]}]
    if unanalyzed:
        result.append({"aggregate": "unknown", "assemblies": unanalyzed})
    return result


def build_document(components: Dict[str, Any], *, created: str, tool_version: str, creation_comment: str,
                   license_ids: Sequence[str] = ()) -> Dict[str, Any]:
    """The CycloneDX 1.6 document for ``components`` (the content of ``components.json``)."""
    comps = sorted(components.get("components") or [], key=lambda c: c["spdx_id"])
    ref_of_root = root_ref(components)
    listed = set(license_ids)
    metadata: Dict[str, Any] = {
        "timestamp": created,
        "lifecycles": [{"phase": "pre-build"}],
        "tools": {"components": [{"type": "application", "name": tool_name(), "version": tool_version}]},
        "component": _root(components, tool_version),
    }
    meta_props = _props([("generation-context", "Source"), ("creation-comment", creation_comment),
                         ("analysis-mode", components.get("analysis_mode"))])
    for spot in (components.get("blindspots") or [])[:MAX_KNOWN_UNKNOWNS]:
        where = " at %s" % spot["loc"] if spot.get("loc") else ""
        meta_props.append(_prop("known-unknown", "%s%s: %s" % (spot.get("code"), where, plain(spot.get("message"), 200))))
    metadata["properties"] = meta_props
    body_components = [_component(c, listed) for c in comps]
    depends = sorted(component_ref(c) for c in comps
                     if "DEPENDS_ON" in (c.get("relationships") or []))
    document: Dict[str, Any] = {"bomFormat": BOM_FORMAT, "specVersion": SPEC_VERSION, "serialNumber": "", "version": 1,
                                "metadata": metadata, "components": body_components}
    if depends:
        document["dependencies"] = [{"ref": ref_of_root, "dependsOn": depends}]
    document["compositions"] = _compositions(components)
    document["serialNumber"] = serial_for(document)
    return scrub(document)


def serial_for(document: Dict[str, Any]) -> str:
    """``urn:uuid:`` + the UUIDv5 of the canonical content (without ``serialNumber`` and ``metadata.timestamp``), so the same
    inputs always give the same serial number and any change of content gives another one."""
    body = json.loads(json.dumps(document))
    body.pop("serialNumber", None)
    (body.get("metadata") or {}).pop("timestamp", None)
    digest = hashlib.sha256(fsio.dumps_compact(body).encode("utf-8", "backslashreplace")).hexdigest()
    return "urn:uuid:" + str(uuid.uuid5(SERIAL_NAMESPACE, digest))


def dumps_document(document: Dict[str, Any]) -> str:
    """The file text: not key-sorted, two-space indent, trailing newline (the same form as the SPDX file)."""
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"
