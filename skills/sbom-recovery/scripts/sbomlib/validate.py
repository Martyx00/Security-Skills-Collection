"""Validation of the emitted outputs (contract sections 3.12, 4.25 and 6.12).

Per repository (``check_repo``, run by ``audit:validate`` one repository at a time on the *staged* files):

* ``spdx_schema``       the document validates against the vendored SPDX 2.3 and 2.3.1 schemas (``jsonschema_lite``);
* ``spdx_semantic``     the seven rule groups of section 6.12 (a stricter profile than the schemas);
* ``csv_spdx_parity``   the per-repository CSV and the SPDX document say the same thing, and the evidence and candidate
                        audit files are present and list the candidates of ``components.json``;
* ``gitlinks_accounted``  every gitlink of the repository is accounted for by a component or an excluded candidate;
* ``version_evidence``  every released version still has re-checkable evidence and matches the release scheme.

Run-wide (``check_run``): merged CSV parity, CPE provenance, the integrity result and the pack check. ``check_run`` returns
the body of ``.state/validation.json`` (without ``outputs``) and writes nothing.

``spdx_semantic_errors`` has no context argument in the contract; it reads the vendored 2.3.1 schema and the licence list
from the assets directory that ships next to this module unless ``ctx=`` is given (then ``ctx.asset`` is used).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from sbomlib import cdxcheck, csvio, delta, errors, fsio, jsonschema_lite, model, paths, urls
from sbomlib.context import RunContext, parse_iso_z
from sbomlib.emit import csvout, cyclonedx, licexpr, merge, spdx, stage
from sbomlib.state import RunState

SCHEMA_NAMES = ("spdx-schema-2.3.json", "spdx-schema-2.3.1.json")
MAX_ERRORS = 50
MAX_FILE_BYTES = 2 * 1024 * 1024

# Appendix C
SPDXID_RE = re.compile(r"SPDXRef-[A-Za-z0-9.-]+")
ACTOR_RE = re.compile(r"(Tool|Organization|Person): \S.*")
CREATED_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
TOOL_RE = re.compile(r"Tool: kiro-sbomber-\S+")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
EXTERNAL_CATEGORIES = ("SECURITY", "PACKAGE-MANAGER", "PERSISTENT-ID", "OTHER")
RESOLUTION_HEADER = ("row_id", "name", "version", "action", "pair", "role", "pair_source", "tier", "cpe23",
                     "cpe_name_source", "cpe_name_id", "deprecated", "deprecated_by", "version_in_dictionary",
                     "cpe_version_wildcard", "emitted", "keyword_candidates", "data_source", "note")
REPO_CHECKS = ("spdx_schema", "spdx_semantic", "csv_spdx_parity", "cyclonedx", "gitlinks_accounted", "version_evidence")
RUN_CHECKS = ("merged_parity", "cpe_provenance", "targets_unchanged", "pack_unchanged", "run_folder_unchanged")
CHECK_ORDER = ("spdx_schema", "spdx_semantic", "csv_spdx_parity", "cyclonedx", "merged_parity", "gitlinks_accounted",
               "cpe_provenance", "version_evidence", "targets_unchanged", "pack_unchanged", "run_folder_unchanged")


# ----------------------------------------------------------------------------------------------------------- assets

_FILE_ASSETS: Dict[str, Tuple[int, int, Any]] = {}


def _asset(name: str, ctx: Optional[RunContext] = None) -> Any:
    """A shipped asset: through ``ctx.asset`` when a context is given, else from the assets directory next to this module."""
    if ctx is not None:
        return ctx.asset(name)
    path = Path(__file__).resolve().parents[2] / "assets" / name
    try:
        st = os.stat(str(path))
    except OSError as exc:
        raise errors.StateError("asset %s is missing" % name, path=str(path)) from exc
    cached = _FILE_ASSETS.get(str(path))
    if cached is not None and cached[0] == st.st_mtime_ns and cached[1] == st.st_size:
        return cached[2]
    with open(str(path), encoding="utf-8") as handle:
        data = json.load(handle)
    _FILE_ASSETS[str(path)] = (st.st_mtime_ns, st.st_size, data)
    return data


def _cap(items: Sequence[str]) -> List[str]:
    return list(items)[:MAX_ERRORS]


# ------------------------------------------------------------------------------------------------------ schema check

def schema_errors(doc: Dict[str, Any], schema_name: str, ctx: RunContext) -> List[str]:
    """Problems of ``doc`` against the vendored schema ``spdx-schema-2.3.json`` or ``spdx-schema-2.3.1.json``."""
    if schema_name not in SCHEMA_NAMES:
        raise ValueError("unknown schema: %r" % (schema_name,))
    schema = ctx.asset(schema_name)
    label = "schema " + schema_name[len("spdx-schema-"):-len(".json")]
    return ["%s: %s" % (label, message) for message in jsonschema_lite.validate(doc, schema)]


# --------------------------------------------------------------------------------------------------- semantic check

def _list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _props(schema: Dict[str, Any], *path: str) -> Tuple[str, ...]:
    node: Any = schema
    for step in path:
        node = (node.get("properties") or {}).get(step) if step != "[]" else node.get("items")
        if node is None:
            return ()
    return tuple((node.get("properties") or {}).keys()) if isinstance(node, dict) else ()


def _is_license_value(value: Any, licenses: Dict[str, Any]) -> bool:
    return isinstance(value, str) and licexpr.is_valid_expression(value, licenses)


def _check_annotations(annotations: Any, where: str, allowed: Sequence[str], out: List[str]) -> None:
    for index, item in enumerate(_list(annotations)):
        pointer = "%s/%d" % (where, index)
        if not isinstance(item, dict):
            out.append("rule 4: %s: an annotation must be an object" % pointer)
            continue
        if item.get("annotationType") not in ("OTHER", "REVIEW"):
            out.append("rule 4: %s/annotationType: %r is not OTHER or REVIEW" % (pointer, item.get("annotationType")))
        annotator = item.get("annotator")
        if not (isinstance(annotator, str) and ACTOR_RE.fullmatch(annotator)):
            out.append("rule 4: %s/annotator: %r is not 'Tool|Organization|Person: name'" % (pointer, annotator))
        if not _created_ok(item.get("annotationDate")):
            out.append("rule 4: %s/annotationDate: %r is not YYYY-MM-DDThh:mm:ssZ" % (pointer, item.get("annotationDate")))
        if not isinstance(item.get("comment"), str):
            out.append("rule 4: %s/comment: must be a string" % pointer)
        for key in item:
            if allowed and key not in allowed:
                out.append("rule 7: %s: %r is not a property of an SPDX annotation" % (pointer, key))


def _created_ok(value: Any) -> bool:
    if not (isinstance(value, str) and CREATED_RE.fullmatch(value)):
        return False
    try:
        parse_iso_z(value)
    except ValueError:
        return False
    return True


def spdx_semantic_errors(doc: Dict[str, Any], *, ctx: Optional[RunContext] = None) -> List[str]:
    """The semantic profile of section 6.12; every message starts with ``rule <n>:``. ``[]`` when the document passes."""
    out: List[str] = []
    if not isinstance(doc, dict):
        return ["rule 1: the document is not a JSON object"]
    schema = _asset("spdx-schema-2.3.1.json", ctx)
    licenses = _asset("spdx-licenses.json", ctx)
    version = ctx.version() if ctx is not None else None

    # ---- rule 1: the document header
    if doc.get("spdxVersion") != spdx.SPDX_VERSION:
        out.append("rule 1: /spdxVersion: expected 'SPDX-2.3', found %r" % (doc.get("spdxVersion"),))
    if doc.get("dataLicense") != "CC0-1.0":
        out.append("rule 1: /dataLicense: expected 'CC0-1.0', found %r" % (doc.get("dataLicense"),))
    if doc.get("SPDXID") != spdx.DOCUMENT_ID:
        out.append("rule 1: /SPDXID: expected 'SPDXRef-DOCUMENT', found %r" % (doc.get("SPDXID"),))
    namespace = doc.get("documentNamespace")
    if not isinstance(namespace, str) or not namespace:
        out.append("rule 1: /documentNamespace: missing")
    else:
        parts = urlsplit(namespace)
        if parts.scheme != "https" or not parts.netloc or "#" in namespace or any(ch.isspace() for ch in namespace):
            out.append("rule 1: /documentNamespace: %r is not an absolute https URI without a fragment" % namespace)

    # ---- rule 2: creation information
    info = doc.get("creationInfo")
    if not isinstance(info, dict):
        out.append("rule 2: /creationInfo: missing")
        info = {}
    if not _created_ok(info.get("created")):
        out.append("rule 2: /creationInfo/created: %r is not YYYY-MM-DDThh:mm:ssZ" % (info.get("created"),))
    creators = info.get("creators")
    if not isinstance(creators, list) or not creators:
        out.append("rule 2: /creationInfo/creators: must be a non-empty list")
    else:
        for index, creator in enumerate(creators):
            if not (isinstance(creator, str) and ACTOR_RE.fullmatch(creator)):
                out.append("rule 2: /creationInfo/creators/%d: %r is not 'Tool|Organization|Person: name'" % (index, creator))
        expected = ("Tool: " + spdx.tool_name(version)) if version else None
        if expected is not None:
            if expected not in creators:
                out.append("rule 2: /creationInfo/creators: %r is missing" % expected)
        elif not any(isinstance(c, str) and TOOL_RE.fullmatch(c) for c in creators):
            out.append("rule 2: /creationInfo/creators: no 'Tool: kiro-sbomber-<version>' creator")
    comment = info.get("comment")
    if not (isinstance(comment, str) and comment.startswith(model.SPDX_CONTEXT)):
        out.append("rule 2: /creationInfo/comment: must start with %r" % model.SPDX_CONTEXT)

    # ---- rule 3 and 5: packages and external references
    packages = _list(doc.get("packages"))
    if not isinstance(doc.get("packages"), list):
        out.append("rule 3: /packages: missing")
    seen: Dict[str, int] = {}
    package_ids = set()
    for index, pkg in enumerate(packages):
        pointer = "/packages/%d" % index
        if not isinstance(pkg, dict):
            out.append("rule 3: %s: a package must be an object" % pointer)
            continue
        spdx_id = pkg.get("SPDXID")
        if not (isinstance(spdx_id, str) and SPDXID_RE.fullmatch(spdx_id)):
            out.append("rule 3: %s/SPDXID: %r does not match SPDXRef-[A-Za-z0-9.-]+" % (pointer, spdx_id))
        elif spdx_id in seen:
            out.append("rule 3: %s/SPDXID: %r is also used by /packages/%d" % (pointer, spdx_id, seen[spdx_id]))
        else:
            seen[spdx_id] = index
        if isinstance(spdx_id, str):
            package_ids.add(spdx_id)
        if pkg.get("filesAnalyzed") is not False:
            out.append("rule 3: %s/filesAnalyzed: must be present and false (no files are analysed), found %r"
                       % (pointer, pkg.get("filesAnalyzed")))
        download = pkg.get("downloadLocation")
        if not (isinstance(download, str) and (download in ("NOASSERTION", "NONE") or urls.DOWNLOAD_LOCATION_RE.fullmatch(download))):
            out.append("rule 3: %s/downloadLocation: %r is not NOASSERTION, NONE or a git+https URL without credentials"
                       % (pointer, download))
        supplier = pkg.get("supplier")
        if not (isinstance(supplier, str) and (supplier == "NOASSERTION" or ACTOR_RE.fullmatch(supplier))):
            out.append("rule 3: %s/supplier: %r is not NOASSERTION or an actor" % (pointer, supplier))
        for key in ("licenseDeclared", "licenseConcluded"):
            value = pkg.get(key)
            if value in ("NOASSERTION", "NONE"):
                continue
            if not _is_license_value(value, licenses):
                out.append("rule 3: %s/%s: %r is not NOASSERTION, NONE or a valid SPDX licence expression" % (pointer, key, value))
        if not isinstance(pkg.get("copyrightText"), str):
            out.append("rule 3: %s/copyrightText: missing" % pointer)
        for sub, checksum in enumerate(_list(pkg.get("checksums"))):
            where = "%s/checksums/%d" % (pointer, sub)
            if not isinstance(checksum, dict):
                out.append("rule 3: %s: a checksum must be an object" % where)
                continue
            if checksum.get("algorithm") != "SHA256":
                out.append("rule 3: %s/algorithm: only SHA256 is produced, found %r" % (where, checksum.get("algorithm")))
            value = checksum.get("checksumValue")
            if not (isinstance(value, str) and SHA256_RE.fullmatch(value)):
                out.append("rule 3: %s/checksumValue: %r is not 64 lowercase hex digits" % (where, value))
        _check_annotations(pkg.get("annotations"), pointer + "/annotations",
                           _props(schema, "packages", "[]", "annotations", "[]"), out)
        for sub, ref in enumerate(_list(pkg.get("externalRefs"))):
            where = "%s/externalRefs/%d" % (pointer, sub)
            _check_external_ref(ref, where, out)

    # ---- rule 4 at document level
    _check_annotations(doc.get("annotations"), "/annotations", _props(schema, "annotations", "[]"), out)

    # ---- rule 6: relationships
    all_ids = package_ids | {spdx.DOCUMENT_ID}
    describes = []
    for index, rel in enumerate(_list(doc.get("relationships"))):
        pointer = "/relationships/%d" % index
        if not isinstance(rel, dict):
            out.append("rule 6: %s: a relationship must be an object" % pointer)
            continue
        source, target, kind = rel.get("spdxElementId"), rel.get("relatedSpdxElement"), rel.get("relationshipType")
        if source not in all_ids:
            out.append("rule 6: %s/spdxElementId: %r is neither the document nor a package" % (pointer, source))
        if target not in all_ids and target not in ("NOASSERTION", "NONE"):
            out.append("rule 6: %s/relatedSpdxElement: %r is neither the document nor a package" % (pointer, target))
        if not isinstance(kind, str) or not kind:
            out.append("rule 6: %s/relationshipType: missing" % pointer)
        if kind == "DESCRIBES" and source == spdx.DOCUMENT_ID:
            describes.append(target)
    if len(describes) != 1:
        out.append("rule 6: /relationships: exactly one DESCRIBES from SPDXRef-DOCUMENT is required, found %d" % len(describes))
    elif describes[0] not in package_ids:
        out.append("rule 6: /relationships: DESCRIBES points to %r, which is not a package" % (describes[0],))

    # ---- rule 7: every key is declared by the 2.3.1 schema for that object
    _check_keys(doc, _props(schema), "", "document", out)
    _check_keys(info, _props(schema, "creationInfo"), "/creationInfo", "creationInfo", out)
    pkg_allowed = _props(schema, "packages", "[]")
    ref_allowed = _props(schema, "packages", "[]", "externalRefs", "[]")
    checksum_allowed = _props(schema, "packages", "[]", "checksums", "[]")
    rel_allowed = _props(schema, "relationships", "[]")
    for index, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            continue
        _check_keys(pkg, pkg_allowed, "/packages/%d" % index, "package", out)
        for sub, ref in enumerate(_list(pkg.get("externalRefs"))):
            if isinstance(ref, dict):
                _check_keys(ref, ref_allowed, "/packages/%d/externalRefs/%d" % (index, sub), "externalRefs item", out)
        for sub, checksum in enumerate(_list(pkg.get("checksums"))):
            if isinstance(checksum, dict):
                _check_keys(checksum, checksum_allowed, "/packages/%d/checksums/%d" % (index, sub), "checksum", out)
    for index, rel in enumerate(_list(doc.get("relationships"))):
        if isinstance(rel, dict):
            _check_keys(rel, rel_allowed, "/relationships/%d" % index, "relationship", out)
    return out


def _check_keys(obj: Any, allowed: Sequence[str], pointer: str, what: str, out: List[str]) -> None:
    if not isinstance(obj, dict) or not allowed:
        return
    for key in obj:
        if key not in allowed:
            out.append("rule 7: %s/%s: %r is not a property of an SPDX %s" % (pointer, key, key, what))


def _check_external_ref(ref: Any, where: str, out: List[str]) -> None:
    from sbomlib import purl as purl_module
    from sbomlib.cpe import cpestr
    if not isinstance(ref, dict):
        out.append("rule 5: %s: an external reference must be an object" % where)
        return
    category, rtype, locator = ref.get("referenceCategory"), ref.get("referenceType"), ref.get("referenceLocator")
    if category not in EXTERNAL_CATEGORIES:
        out.append("rule 5: %s/referenceCategory: %r is not one of %s" % (where, category, ", ".join(EXTERNAL_CATEGORIES)))
    if not isinstance(rtype, str) or not rtype:
        out.append("rule 5: %s/referenceType: missing" % where)
    if not isinstance(locator, str) or not locator or any(ch.isspace() for ch in locator):
        out.append("rule 5: %s/referenceLocator: %r is empty or contains white space" % (where, locator))
        return
    if rtype == "cpe23Type":
        if category != "SECURITY":
            out.append("rule 5: %s/referenceCategory: a cpe23Type reference belongs to SECURITY, found %r" % (where, category))
        if not cpestr.CPE23_RE.fullmatch(locator):
            out.append("rule 5: %s/referenceLocator: %r is not a CPE 2.3 formatted string" % (where, locator))
    elif rtype == "purl":
        if category != "PACKAGE-MANAGER":
            out.append("rule 5: %s/referenceCategory: a purl reference belongs to PACKAGE-MANAGER, found %r" % (where, category))
        if not purl_module.is_valid_purl(locator):
            out.append("rule 5: %s/referenceLocator: %r is not a valid package URL" % (where, locator))


# ----------------------------------------------------------------------------------------------------- parity checks

def _root_id(doc: Dict[str, Any]) -> Optional[str]:
    for rel in _list(doc.get("relationships")):
        if isinstance(rel, dict) and rel.get("relationshipType") == "DESCRIBES" and rel.get("spdxElementId") == spdx.DOCUMENT_ID:
            return rel.get("relatedSpdxElement")
    return None


def _diff_text(left: Iterable[str], right: Iterable[str], left_name: str, right_name: str) -> str:
    a, b = set(left), set(right)
    parts = []
    if a - b:
        parts.append("only in %s: %s" % (left_name, ", ".join(sorted(a - b))[:300]))
    if b - a:
        parts.append("only in %s: %s" % (right_name, ", ".join(sorted(b - a))[:300]))
    return "; ".join(parts)


def csv_spdx_parity_errors(csv_bytes: bytes, doc: Dict[str, Any]) -> List[str]:
    """Differences between a per-repository CSV and its SPDX document (cells compared unguarded)."""
    try:
        table = csvio.parse_csv_strict(csv_bytes, csvout.REPO_HEADER)
    except errors.CsvReadError as exc:
        return ["csv: %s" % exc.message]
    out: List[str] = []
    packages: Dict[str, Dict[str, Any]] = {}
    for pkg in _list(doc.get("packages")) if isinstance(doc, dict) else []:
        if isinstance(pkg, dict) and isinstance(pkg.get("SPDXID"), str):
            packages[pkg["SPDXID"]] = pkg
    root = _root_id(doc) if isinstance(doc, dict) else None
    spdx_ids = set(packages) - ({root} if root else set())
    csv_ids = [row["spdx_id"] for row in table.rows]
    if len(csv_ids) != len(set(csv_ids)):
        out.append("the CSV lists a spdx_id more than once")
    diff = _diff_text(csv_ids, spdx_ids, "the CSV", "the SPDX document")
    if diff:
        out.append("the set of spdx_id values differs: %s" % diff)
    for row in table.rows:
        spdx_id = row["spdx_id"]
        pkg = packages.get(spdx_id)
        if pkg is None:
            continue
        label = "%s (%s)" % (spdx_id, row["name"])
        if row["name"] != pkg.get("name"):
            out.append("%s: name %r differs from the SPDX name %r" % (label, row["name"], pkg.get("name")))
        if row["version"] != pkg.get("versionInfo", "NOASSERTION"):
            out.append("%s: version %r differs from versionInfo %r" % (label, row["version"], pkg.get("versionInfo")))
        refs = [r for r in _list(pkg.get("externalRefs")) if isinstance(r, dict)]
        cpes = [r.get("referenceLocator") for r in refs if r.get("referenceType") == "cpe23Type"]
        purls = [r.get("referenceLocator") for r in refs if r.get("referenceType") == "purl"]
        csv_cpes = merge.split_cell(row["cpe23"])
        if set(csv_cpes) != set(cpes) or len(csv_cpes) != len(cpes):
            out.append("%s: cpe23 differs: %s" % (label, _diff_text(csv_cpes, cpes, "the CSV", "SPDX") or "duplicates differ"))
        csv_purls = merge.split_cell(row["purl"])
        if set(csv_purls) != set(purls) or len(csv_purls) != len(purls):
            out.append("%s: purl differs: %s" % (label, _diff_text(csv_purls, purls, "the CSV", "SPDX") or "duplicates differ"))
        locations: List[str] = []
        provenance: Optional[Dict[str, Any]] = None
        for annotation in _list(pkg.get("annotations")):
            if not isinstance(annotation, dict):
                continue
            payload = spdx.parse_location_annotation(annotation.get("comment"))
            if payload is not None and isinstance(payload.get("loc"), str):
                locations.append(payload["loc"])
            found = spdx.parse_provenance_annotation(annotation.get("comment"))
            if found is not None:
                provenance = found
        if row["locations"] != ";".join(sorted(set(locations))):
            out.append("%s: locations differ: %s" % (label, _diff_text(merge.split_cell(row["locations"]), locations,
                                                                         "the CSV", "SPDX annotations") or "order differs"))
        if provenance is None:
            out.append("%s: the package has no kiro-sbomber:provenance annotation" % label)
        elif row["verification"] != provenance.get("verification"):
            out.append("%s: verification %r differs from the provenance annotation %r"
                       % (label, row["verification"], provenance.get("verification")))
        if row["license_declared"] != pkg.get("licenseDeclared", "NOASSERTION"):
            out.append("%s: license_declared %r differs from licenseDeclared %r"
                       % (label, row["license_declared"], pkg.get("licenseDeclared")))
        if row["supplier"] != pkg.get("supplier", "NOASSERTION"):
            out.append("%s: supplier %r differs from the SPDX supplier %r" % (label, row["supplier"], pkg.get("supplier")))
        checksums = [c.get("checksumValue") for c in _list(pkg.get("checksums")) if isinstance(c, dict)]
        if (row["sha256"] or "") != (checksums[0] if checksums else ""):
            out.append("%s: sha256 %r differs from the SPDX checksum" % (label, row["sha256"]))
    return out


def _cdx_license_text(component: Dict[str, Any]) -> str:
    entries = [e for e in _list(component.get("licenses")) if isinstance(e, dict)]
    if not entries:
        return "NOASSERTION"
    first = entries[0]
    if "expression" in first:
        return str(first["expression"])
    lic = first.get("license") if isinstance(first.get("license"), dict) else {}
    return str(lic.get("id") or lic.get("name") or "")


def _cdx_property(component: Dict[str, Any], name: str) -> Optional[str]:
    for item in _list(component.get("properties")):
        if isinstance(item, dict) and item.get("name") == cyclonedx.PROP + name:
            return str(item.get("value"))
    return None


def cyclonedx_errors(ctx: Optional[RunContext], csv_bytes: Optional[bytes], doc: Dict[str, Any]) -> List[str]:
    """The shape of the CycloneDX document (``cdxcheck``) and its agreement with the per-repository CSV: the same components
    (by SPDX id, which is the ``bom-ref`` plus its prefix), names, versions, CPE, purl, licence, SHA-256, verification and
    root commit."""
    ids: List[str] = []
    try:
        ids = list((_asset("cyclonedx-license-ids.json", ctx) or {}).get("ids") or [])
    except errors.SbomError as exc:
        return ["the CycloneDX licence id list cannot be read: %s" % exc.message]
    out = cdxcheck.shape_errors(doc, ids)
    if out or csv_bytes is None:
        return out
    try:
        table = csvio.parse_csv_strict(csv_bytes, csvout.REPO_HEADER)
    except errors.CsvReadError as exc:
        return ["csv: %s" % exc.message]
    comps = {c["bom-ref"]: c for c in _list(doc.get("components")) if isinstance(c, dict) and "bom-ref" in c}
    csv_refs = {row["spdx_id"][len("SPDXRef-"):] if row["spdx_id"].startswith("SPDXRef-") else row["spdx_id"]: row
                for row in table.rows}
    diff = _diff_text(csv_refs, comps, "the CSV", "the CycloneDX document")
    if diff:
        out.append("the set of components differs: %s" % diff)
    for ref, row in sorted(csv_refs.items()):
        comp = comps.get(ref)
        if comp is None:
            continue
        label = "%s (%s)" % (ref, row["name"])
        if row["name"] != comp.get("name"):
            out.append("%s: name %r differs from the CycloneDX name %r" % (label, row["name"], comp.get("name")))
        if row["version"] != comp.get("version", "NOASSERTION"):
            out.append("%s: version %r differs from the CycloneDX version %r" % (label, row["version"], comp.get("version")))
        csv_cpes = merge.split_cell(row["cpe23"])
        cdx_cpes = ([comp["cpe"]] if comp.get("cpe") else []) + [
            str(p.get("value")) for p in _list(comp.get("properties")) if isinstance(p, dict)
            and p.get("name") == cyclonedx.PROP + "cpe-additional"]
        if csv_cpes != cdx_cpes:
            out.append("%s: cpe23 differs: %s" % (label, _diff_text(csv_cpes, cdx_cpes, "the CSV", "CycloneDX") or "order differs"))
        csv_purls = merge.split_cell(row["purl"])
        if csv_purls[:1] != ([comp["purl"]] if comp.get("purl") else []):
            out.append("%s: purl %r differs from the CycloneDX purl %r" % (label, row["purl"], comp.get("purl")))
        hashes = [h.get("content") for h in _list(comp.get("hashes")) if isinstance(h, dict)]
        if (row["sha256"] or "") != (hashes[0] if hashes else ""):
            out.append("%s: sha256 %r differs from the CycloneDX hash" % (label, row["sha256"]))
        if row["verification"] != (_cdx_property(comp, "verification") or ""):
            out.append("%s: verification %r differs from the CycloneDX property %r"
                       % (label, row["verification"], _cdx_property(comp, "verification")))
        if row["license_declared"] != _cdx_license_text(comp):
            out.append("%s: license_declared %r differs from the CycloneDX licence %r"
                       % (label, row["license_declared"], _cdx_license_text(comp)))
    root = (doc.get("metadata") or {}).get("component") if isinstance(doc.get("metadata"), dict) else None
    if not isinstance(root, dict) or not root.get("name"):
        out.append("the CycloneDX document has no root component")
    return out


def auxiliary_csv_errors(ctx: RunContext, run: RunState, repo: str, components: Dict[str, Any]) -> List[str]:
    """The staged ``evidence.csv`` and ``candidates_audit.csv`` exist, parse with their exact headers, and the audit file
    lists exactly the candidates of ``components.json`` (in the SBOM or excluded) with the right ``in_sbom`` flags."""
    out: List[str] = []
    tables: Dict[str, csvio.CsvTable] = {}
    directory = stage.staged_repo_dir(ctx, run, repo)
    for name, header in (("%s.evidence.csv" % repo, csvout.EVIDENCE_HEADER), (stage.AUDIT_NAME, csvout.AUDIT_HEADER)):
        try:
            tables[name] = csvio.read_csv_strict(directory / name, header)
        except FileNotFoundError:
            out.append("the staged %s is missing" % name)
        except errors.CsvReadError as exc:
            out.append("the staged %s is unreadable: %s" % (name, exc.message))
    expected_delta = delta.read(ctx, repo)
    delta_path = stage.staged_delta(ctx, run, repo)
    if expected_delta is not None:
        try:
            table = csvio.read_csv_strict(delta_path, delta.HEADER)
            if len(table.rows) != len(expected_delta["entries"]):
                out.append("%s lists %d change(s) but delta.json has %d" % (delta_path.name, len(table.rows),
                                                                            len(expected_delta["entries"])))
            for row in table.rows:
                if row["change"] not in delta.CHANGES or row["cause"] not in delta.CAUSES:
                    out.append("%s: %s has an unknown change or cause" % (delta_path.name, row["name"]))
        except FileNotFoundError:
            out.append("the staged %s is missing" % delta_path.name)
        except errors.CsvReadError as exc:
            out.append("the staged %s is unreadable: %s" % (delta_path.name, exc.message))
    elif os.path.lexists(str(delta_path)):
        out.append("%s exists although this run has no baseline for %s" % (delta_path.name, repo))
    audit = tables.get(stage.AUDIT_NAME)
    if audit is not None:
        in_sbom: Dict[str, str] = {}
        for comp in components.get("components") or []:
            for cid in comp.get("candidate_ids") or []:
                in_sbom[str(cid)] = str(comp.get("spdx_id"))
        expected = set(in_sbom) | {str(e.get("candidate_id")) for e in components.get("excluded") or []}
        found = [row["candidate_id"] for row in audit.rows]
        if len(found) != len(set(found)):
            out.append("candidates_audit.csv lists a candidate more than once")
        diff = _diff_text(found, expected, "candidates_audit.csv", "components.json")
        if diff:
            out.append("candidates_audit.csv and components.json list different candidates: %s" % diff)
        for row in audit.rows:
            cid = row["candidate_id"]
            wanted = ("yes", in_sbom[cid]) if cid in in_sbom else ("no", "")
            if cid in expected and (row["in_sbom"], row["spdx_id"]) != wanted:
                out.append("candidates_audit.csv: %s has in_sbom=%r spdx_id=%r, expected %r" % (
                    cid, row["in_sbom"], row["spdx_id"], wanted))
    return out


def merged_parity_errors(ctx: RunContext, run: RunState) -> List[str]:
    """The staged ``merged-sbom.csv`` against a recomputation from the staged per-repository CSV files."""
    out: List[str] = []
    entries: List[Dict[str, Any]] = []
    for repo in merge.contributing_repos(run):
        path = stage.staged_csv(ctx, run, repo)
        try:
            table = csvio.read_csv_strict(path, csvout.REPO_HEADER)
        except FileNotFoundError:
            out.append("%s: the staged CSV %s is missing" % (repo, path.name))
            continue
        except errors.CsvReadError as exc:
            out.append("%s: the staged CSV is unreadable: %s" % (repo, exc.message))
            continue
        entries.extend(merge.entry_from_csv_row(repo, row) for row in table.rows)
    header, expected = merge.merged_table(entries)
    merged_path = stage.staged_merged(ctx, run)
    try:
        actual = csvio.read_csv_strict(merged_path, merge.MERGED_HEADER)
    except FileNotFoundError:
        out.append("the staged merged-sbom.csv is missing")
        return out
    except errors.CsvReadError as exc:
        out.append("the staged merged-sbom.csv is unreadable: %s" % exc.message)
        return out
    found = [[row[c] for c in header] for row in actual.rows]
    if len(found) != len(expected):
        out.append("merged-sbom.csv has %d row(s), the per-repository CSV files give %d" % (len(found), len(expected)))
    for index, (want, have) in enumerate(zip(expected, found)):
        for column, a, b in zip(header, want, have):
            if a != b:
                out.append("merged-sbom.csv row %d (%s %s) column %s: expected %r, found %r"
                           % (index + 1, want[0], want[1], column, a, b))
    return out


# ------------------------------------------------------------------------------------------------ run-level checks

def gitlink_errors(components: Dict[str, Any]) -> List[str]:
    """Every gitlink must name a component's SPDXID or an excluded candidate that exists."""
    out: List[str] = []
    spdx_ids = {c.get("spdx_id") for c in components.get("components") or []}
    excluded = {e.get("candidate_id") for e in components.get("excluded") or []}
    for link in components.get("gitlinks") or []:
        accounted = link.get("accounted_by")
        if not accounted:
            out.append("gitlink %s is not accounted for by any component or excluded candidate" % link.get("path"))
        elif isinstance(accounted, str) and accounted.startswith("excluded:"):
            if accounted[len("excluded:"):] not in excluded:
                out.append("gitlink %s names the excluded candidate %s, which is not listed" % (link.get("path"), accounted))
        elif accounted not in spdx_ids:
            out.append("gitlink %s names %s, which is not a component" % (link.get("path"), accounted))
    return out


def _resolution_table(ctx: RunContext, run: RunState) -> Optional[csvio.CsvTable]:
    for path in (stage.staged_resolution(ctx, run), ctx.layout.out / stage.RESOLUTION_NAME):
        if os.path.isfile(str(path)):
            return csvio.read_csv_strict(path, RESOLUTION_HEADER)
    return None


def cpe_provenance_errors(ctx: RunContext, run: RunState) -> List[str]:
    """Every emitted CPE of every staged SPDX document and CSV has an ``emitted=yes`` row in ``cpe_resolution.csv`` whose
    pair is an approved pair of the latest approved copy (or an API successor of one), with a ``pair_source``."""
    from sbomlib import cpe
    out: List[str] = []
    try:
        table = _resolution_table(ctx, run)
    except errors.CsvReadError as exc:
        return ["cpe_resolution.csv is unreadable: %s" % exc.message]
    if table is None:
        return ["cpe_resolution.csv does not exist"]
    approved_pairs: Dict[str, set] = {}
    try:
        for row_id, row in cpe.approved_rows(ctx, run).items():
            approved_pairs[row_id] = {spec.pair.lower() for spec in cpe.resolve.approved_specs(row)}
    except errors.SbomError as exc:
        return ["the approved review copy cannot be read: %s" % exc.message]
    emitted: Dict[str, List[Dict[str, str]]] = {}
    for rec in table.rows:
        if rec["emitted"] == "yes":
            emitted.setdefault(rec["cpe23"].lower(), []).append(rec)
    for rec in table.rows:
        if rec["emitted"] != "yes":
            continue
        if rec["pair_source"] not in model.PAIR_SOURCES:
            out.append("cpe_resolution.csv: %s has pair_source %r" % (rec["cpe23"], rec["pair_source"]))
        pairs = approved_pairs.get(rec["row_id"])
        if pairs is None:
            out.append("cpe_resolution.csv: %s belongs to the unknown review row %s" % (rec["cpe23"], rec["row_id"]))
        elif rec["pair_source"] == "api":
            match = re.match(r"successor of (\S+)", rec["note"])
            if not match or match.group(1).lower() not in pairs:
                out.append("cpe_resolution.csv: %s is an API successor of a pair that is not approved (%s)"
                           % (rec["cpe23"], rec["note"] or "no note"))
        elif rec["pair"].lower() not in pairs:
            out.append("cpe_resolution.csv: %s uses the pair %s, which is not an approved pair of row %s"
                       % (rec["cpe23"], rec["pair"], rec["row_id"]))
    for repo in merge.contributing_repos(run):
        seen: List[Tuple[str, str]] = []                 # (cpe23, pair_source) as the CSV cells say
        csv_path = stage.staged_csv(ctx, run, repo)
        spdx_path = stage.staged_spdx(ctx, run, repo)
        if os.path.isfile(str(csv_path)):
            try:
                rows = csvio.read_csv_strict(csv_path, csvout.REPO_HEADER).rows
            except errors.CsvReadError:
                rows = []
            for row in rows:
                cpes = merge.split_cell(row["cpe23"])
                sources = row["pair_source"].split(";") if row["pair_source"] else []
                for index, value in enumerate(cpes):
                    seen.append((value, sources[index] if index < len(sources) else ""))
        spdx_cpes: List[str] = []
        if os.path.isfile(str(spdx_path)):
            try:
                doc = fsio.read_json(spdx_path)
            except errors.StateError:
                doc = {}
            for pkg in _list(doc.get("packages")) if isinstance(doc, dict) else []:
                for ref in _list(pkg.get("externalRefs")) if isinstance(pkg, dict) else []:
                    if isinstance(ref, dict) and ref.get("referenceType") == "cpe23Type":
                        spdx_cpes.append(str(ref.get("referenceLocator")))
        for value, source in seen:
            recs = emitted.get(value.lower())
            if not recs:
                out.append("%s: the CSV emits %s but cpe_resolution.csv has no emitted=yes row for it" % (repo, value))
            elif source and source not in {r["pair_source"] for r in recs}:
                out.append("%s: %s has pair_source %s in the CSV but %s in cpe_resolution.csv"
                           % (repo, value, source, "/".join(sorted({r["pair_source"] for r in recs}))))
        for value in spdx_cpes:
            if value.lower() not in emitted:
                out.append("%s: the SPDX document emits %s but cpe_resolution.csv has no emitted=yes row for it" % (repo, value))
    return out


def _read_target_line(ctx: RunContext, repo: str, rel: str, line: int) -> Optional[bytes]:
    from sbomlib import norm
    if not norm.is_safe_relative_path(rel):
        return None
    root = ctx.layout.parent / repo
    try:
        path = paths.safe_join(root, rel)
        info = os.lstat(str(path))
    except (errors.SbomError, OSError):
        return None
    if not os.path.isfile(str(path)) or os.path.islink(str(path)) or info.st_size > MAX_FILE_BYTES:
        return None
    try:
        with open(str(path), "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return None
    lines = data.split(b"\n")
    if line < 1 or line > len(lines):
        return None
    return lines[line - 1].rstrip(b"\r")


def _record_rechecks(ctx: RunContext, repo: str, rec: Dict[str, Any]) -> Optional[str]:
    """``None`` when the evidence record still re-checks, else the reason it does not."""
    from sbomlib import gitro
    if rec.get("object") and rec.get("object_store"):
        store = str(rec["object_store"])
        try:
            git_dir = paths.safe_join(ctx.layout.parent, store)
            found = gitro.cat_file_exists(ctx.layout.parent / repo, str(rec["object"]), layout=ctx.layout,
                                          git_dir=git_dir, env=ctx.env)
        except (errors.SbomError, OSError) as exc:
            return "object %s cannot be looked up in %s: %s" % (str(rec["object"])[:12], store, getattr(exc, "message", exc))
        return None if found else "object %s is not in %s" % (str(rec["object"])[:12], store)
    if rec.get("quote_sha256") and rec.get("path") and isinstance(rec.get("line"), int):
        raw = _read_target_line(ctx, repo, str(rec["path"]), int(rec["line"]))
        if raw is None:
            return "%s:%s cannot be re-read" % (rec["path"], rec["line"])
        import hashlib
        if hashlib.sha256(raw).hexdigest() != rec["quote_sha256"]:
            return "%s:%s no longer matches its recorded hash" % (rec["path"], rec["line"])
        return None
    return "%s %s has no re-checkable anchor (no quote hash and no git object)" % (rec.get("type"), rec.get("id"))


def version_evidence_errors(ctx: RunContext, run: RunState, repo: str) -> List[str]:
    """Every component with a version other than NOASSERTION needs at least one version evidence record that still
    re-checks (the line re-read with ``quote_sha256``, or the git object in the named object store) and a version that
    matches the release scheme (or the scheme of its version rule)."""
    from sbomlib import versions
    from sbomlib.emit.components import load_evidence
    out: List[str] = []
    try:
        doc = fsio.read_json(ctx.layout.repo_out(repo) / "components.json")
    except FileNotFoundError:
        return ["components.json is missing"]
    rules = ctx.asset("version_rules.json")
    own_schemes = {}
    for rule in rules.get("rules") or []:
        if rule.get("scheme"):
            own_schemes[str(rule.get("library", "")).casefold()] = str(rule["scheme"])
    universe = load_evidence(ctx, repo)
    for comp in doc.get("components") or []:
        version = comp.get("version")
        if not version or version == "NOASSERTION":
            continue
        label = "%s %s" % (comp.get("name"), version)
        scheme = own_schemes.get(str(comp.get("name", "")).casefold())
        scheme_ok = versions.release_scheme_ok(version, rules)
        if not scheme_ok and scheme:
            try:
                scheme_ok = re.search(scheme, version) is not None
            except re.error:
                scheme_ok = False
        if not scheme_ok:
            out.append("%s: the version does not match the release scheme" % label)
        evidence_ids = [e for e in comp.get("version_evidence_ids") or []]
        if not evidence_ids:
            out.append("%s: no version evidence record is recorded" % label)
            continue
        problems = []
        passed = False
        for eid in evidence_ids:
            rec = universe.get(eid)
            if rec is None:
                problems.append("record %s does not exist" % eid)
                continue
            problem = _record_rechecks(ctx, repo, rec)
            if problem is None:
                passed = True
                break
            problems.append(problem)
        if not passed:
            out.append("%s: no version evidence re-checks (%s)" % (label, "; ".join(problems)[:300]))
    return out


# --------------------------------------------------------------------------------------------------- per-repo check

def _read_text_json(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        with open(str(path), "rb") as handle:
            data = handle.read()
    except OSError as exc:
        return (None, "%s cannot be read: %s" % (path.name, exc.strerror or exc))
    try:
        doc = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        return (None, "%s is not valid JSON: %s" % (path.name, exc))
    if not isinstance(doc, dict):
        return (None, "%s is not a JSON object" % path.name)
    return (doc, None)


def check_repo(ctx: RunContext, run: RunState, repo: str) -> Dict[str, List[str]]:
    """The per-repository checks on the staged files: check name -> errors (at most 50 each)."""
    result: Dict[str, List[str]] = {name: [] for name in REPO_CHECKS}
    spdx_path = stage.staged_spdx(ctx, run, repo)
    csv_path = stage.staged_csv(ctx, run, repo)
    doc, problem = _read_text_json(spdx_path)
    if doc is None:
        result["spdx_schema"].append(problem or "the staged SPDX document is missing")
        result["spdx_semantic"].append(problem or "the staged SPDX document is missing")
        result["csv_spdx_parity"].append(problem or "the staged SPDX document is missing")
    else:
        for name in SCHEMA_NAMES:
            result["spdx_schema"].extend(schema_errors(doc, name, ctx))
        result["spdx_semantic"].extend(spdx_semantic_errors(doc, ctx=ctx))
        try:
            with open(str(csv_path), "rb") as handle:
                csv_bytes = handle.read()
        except OSError as exc:
            result["csv_spdx_parity"].append("the staged CSV %s cannot be read: %s" % (csv_path.name, exc.strerror or exc))
        else:
            result["csv_spdx_parity"].extend(csv_spdx_parity_errors(csv_bytes, doc))
    cdx_doc, problem = _read_text_json(stage.staged_cdx(ctx, run, repo))
    if cdx_doc is None:
        result["cyclonedx"].append(problem or "the staged CycloneDX document is missing")
    else:
        try:
            with open(str(csv_path), "rb") as handle:
                cdx_csv: Optional[bytes] = handle.read()
        except OSError:
            cdx_csv = None
        result["cyclonedx"].extend(cyclonedx_errors(ctx, cdx_csv, cdx_doc))
    components, problem = _read_text_json(ctx.layout.repo_out(repo) / "components.json")
    if components is None:
        result["gitlinks_accounted"].append(problem or "components.json is missing")
    else:
        result["gitlinks_accounted"].extend(gitlink_errors(components))
        result["gitlinks_accounted"].extend(_inventory_gitlink_errors(ctx, repo, components))
        result["csv_spdx_parity"].extend(auxiliary_csv_errors(ctx, run, repo, components))
    try:
        result["version_evidence"].extend(version_evidence_errors(ctx, run, repo))
    except errors.SbomError as exc:
        result["version_evidence"].append("version evidence cannot be checked: %s" % exc.message)
    return {name: _cap(items) for name, items in result.items()}


def _inventory_gitlink_errors(ctx: RunContext, repo: str, components: Dict[str, Any]) -> List[str]:
    """Every gitlink of the repository's inventory must appear in ``components.json`` ``gitlinks``."""
    try:
        inventory = fsio.read_json(ctx.layout.repo_out(repo) / "inventory.json")
    except (FileNotFoundError, errors.StateError):
        return []
    listed = {g.get("path") for g in components.get("gitlinks") or []}
    return ["gitlink %s of the inventory is missing from components.json" % g.get("path")
            for g in (inventory.get("gitlinks") or []) if g.get("path") not in listed]


# ------------------------------------------------------------------------------------------------------- check_run

def _normalize_repo_result(value: Any) -> Tuple[str, List[str]]:
    """A per-repo check result is a list of errors, or a dict ``{"status", "errors"}``."""
    if isinstance(value, dict):
        status = str(value.get("status") or ("fail" if value.get("errors") else "pass")).lower()
        problems = [str(e) for e in value.get("errors") or []]
        if status == "pass" and problems:
            status = "fail"
        if status not in ("pass", "fail"):
            return ("fail", ["the check did not run (%s)" % status] + problems)
        return (status, problems)
    if isinstance(value, (list, tuple)):
        problems = [str(e) for e in value]
        return ("fail" if problems else "pass", problems)
    return ("fail", ["the check did not run"])


def _combine(per_repo: Dict[str, Dict[str, Any]], repos: Sequence[str], check: str) -> Dict[str, Any]:
    problems: List[str] = []
    failed = False
    for repo in repos:
        results = per_repo.get(repo)
        if results is None or check not in results:
            failed = True
            problems.append("%s: the check %s did not run" % (repo, check))
            continue
        status, messages = _normalize_repo_result(results[check])
        if status != "pass":
            failed = True
        problems.extend("%s: %s" % (repo, message) for message in messages)
    return {"status": "fail" if failed or problems else "pass", "errors": _cap(problems)}


def _integrity_check(integrity: Any) -> Dict[str, Any]:
    verdict = str(integrity.get("verdict") or "").upper() if isinstance(integrity, dict) else ""
    problems: List[str] = []
    boundary = {"host_source_control": 0, "paused": 0}
    moved: List[Dict[str, Any]] = []
    if isinstance(integrity, dict):
        for window in integrity.get("windows") or []:
            boundary["host_source_control"] += int(window.get("host_source_control") or 0)
            boundary["paused"] += int(window.get("paused") or 0)
            for diff in window.get("differences") or []:
                if diff.get("class") == "violation":
                    problems.append("%s: %s %s in %s (%s)" % (window.get("window"), diff.get("repo"), diff.get("path"),
                                                             diff.get("change"), ", ".join(diff.get("fields") or [])))
        for change in integrity.get("head_changes") or []:
            problems.append("HEAD changed: %s" % (change if isinstance(change, str) else fsio.dumps_compact(change)))
            if isinstance(change, dict) and change.get("kind") == "pause":
                moved.append({"repo": change.get("repo"), "before": change.get("before"), "after": change.get("after")})
    if verdict != "PASS":
        if not problems:
            problems.append("the integrity comparison did not pass (verdict %r)" % (verdict or "missing"))
        status = "fail"
    else:
        status = "pass"
    return {"status": status, "errors": _cap(problems), "host_source_control": boundary["host_source_control"],
            "paused": boundary["paused"], "head_moved_while_paused": moved[:20]}


def _pack_check(pack: Any) -> Dict[str, Any]:
    status = str(pack.get("status") or "").lower() if isinstance(pack, dict) else ""
    errors_list = [str(e) for e in (pack.get("errors") or [])] if isinstance(pack, dict) else []
    if status not in ("pass", "fail", "skipped"):
        return {"status": "fail", "errors": _cap(errors_list or ["the pack check did not run"])}
    if status == "pass" and errors_list:
        status = "fail"
    return {"status": status, "errors": _cap(errors_list)}


def _run_folder_check(info: Any) -> Dict[str, Any]:
    """``run_folder_unchanged``: no file the script wrote was changed or deleted, and the ledger of the run folder is usable
    (``runfiles.check``). Files the script did not write do not fail it; they are listed in ``added`` and raise a warning."""
    if not isinstance(info, dict) or info.get("status") not in ("pass", "fail"):
        return {"status": "fail", "errors": ["the run folder check did not run"]}
    problems = [str(e) for e in info.get("errors") or []]
    result: Dict[str, Any] = {"status": "fail" if (problems or info.get("status") == "fail") else "pass", "errors": _cap(problems),
                              "checked": int(info.get("checked") or 0), "added": [str(p) for p in info.get("added") or []][:50],
                              "added_count": int(info.get("added_count") or 0)}
    if result["status"] == "fail" and not problems:
        result["errors"] = ["the run folder check failed"]
    return result


def check_run(ctx: RunContext, run: RunState, *, per_repo: Dict[str, Dict[str, Any]], integrity: Dict[str, Any],
              pack: Dict[str, Any], run_folder: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The body of ``.state/validation.json`` without ``outputs`` (contract section 4.25); writes nothing.

    Only ``pack_unchanged`` may be ``skipped``; any other check that could not run is ``fail`` (``run_folder`` left out
    counts as a check that did not run). The verdict is ``PASS`` iff every check passes (or ``pack_unchanged`` is skipped).
    """
    repos = merge.contributing_repos(run)
    checks: Dict[str, Dict[str, Any]] = {}
    checks["spdx_schema"] = _combine(per_repo, repos, "spdx_schema")
    checks["spdx_semantic"] = _combine(per_repo, repos, "spdx_semantic")
    checks["csv_spdx_parity"] = _combine(per_repo, repos, "csv_spdx_parity")
    checks["cyclonedx"] = _combine(per_repo, repos, "cyclonedx")
    checks["merged_parity"] = _run_wide(lambda: merged_parity_errors(ctx, run))
    checks["gitlinks_accounted"] = _combine(per_repo, repos, "gitlinks_accounted")
    checks["cpe_provenance"] = _run_wide(lambda: cpe_provenance_errors(ctx, run))
    checks["version_evidence"] = _combine(per_repo, repos, "version_evidence")
    checks["targets_unchanged"] = _integrity_check(integrity)
    checks["pack_unchanged"] = _pack_check(pack)
    checks["run_folder_unchanged"] = _run_folder_check(run_folder)
    ordered = {name: checks[name] for name in CHECK_ORDER}
    passed = all(c["status"] == "pass" or (name == "pack_unchanged" and c["status"] == "skipped")
                 for name, c in ordered.items())
    approvals = run.data.get("approvals") or []
    last = approvals[-1] if approvals else None
    pack_commit = (pack.get("pack_commit") if isinstance(pack, dict) else None) or (run.data.get("pack") or {}).get("commit")
    return {
        "schema": 1, "verdict": "PASS" if passed else "FAIL", "run_id": run.run_id, "pack_commit": pack_commit,
        "written_at": ctx.now_iso(),
        "approval": ({"n": last.get("n"), "sha256": last.get("sha256"), "evidence": last.get("evidence")} if last else None),
        "checks": ordered,
        "repos": {repo: run.repo(repo).get("status") for repo in run.all_repos()},
    }


def _run_wide(compute: Any) -> Dict[str, Any]:
    try:
        problems = compute()
    except errors.SbomError as exc:
        problems = ["the check could not run: %s" % exc.message]
    return {"status": "fail" if problems else "pass", "errors": _cap(problems)}
