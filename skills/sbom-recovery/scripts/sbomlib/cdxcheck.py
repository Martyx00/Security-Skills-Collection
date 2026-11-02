"""A standard-library check of the shape of the CycloneDX 1.6 documents this skill writes (TASKLIST 3.7).

There is no JSON Schema interpreter in the standard library that could read the official ``bom-1.6.schema.json``
(``$ref``, ``oneOf``, ``format`` and more), and the skill ships no third-party code. So the checker is written out by hand for
the part of the format the skill emits. It is stricter than the official schema in one way, on purpose: an object may carry
only the keys ``emit.cyclonedx`` writes, so a typo or a drift of the writer is an error here. It is not looser anywhere: every
rule is a rule of the official schema (required fields, enumerations, patterns, types, unique items) or a rule of the format
that a schema cannot express (a ``bom-ref`` is unique, a reference points at an existing component). The test suite checks
the writer's output against the official schema when the ``jsonschema`` package is installed and ``SBOM_CDX_SCHEMA_DIR``
names a folder with the three schema files (they are not shipped with the skill; ``INTEGRATION_NOTES.md`` says where they come from).

``shape_errors(document, license_ids)`` returns the problems as ``/pointer: message`` lines (at most ``MAX_ERRORS``).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Sequence

from sbomlib import purl as purl_mod
from sbomlib.cpe import cpestr

MAX_ERRORS = 50
SERIAL_RE = re.compile(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
HASH_LENGTHS = {"MD5": 32, "SHA-1": 40, "SHA-256": 64, "SHA-384": 96, "SHA-512": 128, "SHA3-256": 64, "SHA3-384": 96,
                "SHA3-512": 128, "BLAKE2b-256": 64, "BLAKE2b-384": 96, "BLAKE2b-512": 128, "BLAKE3": 64}
COMPONENT_TYPES = ("application", "framework", "library", "container", "platform", "operating-system", "device",
                   "device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset")
SCOPES = ("required", "optional", "excluded")
PHASES = ("design", "pre-build", "build", "post-build", "operations", "discovery", "decommission")
AGGREGATES = ("complete", "incomplete", "incomplete_first_party_only", "incomplete_first_party_proprietary_only",
              "incomplete_first_party_opensource_only", "incomplete_third_party_only",
              "incomplete_third_party_proprietary_only", "incomplete_third_party_opensource_only", "unknown",
              "not_specified")
EXTERNAL_REFERENCE_TYPES = ("vcs", "issue-tracker", "website", "advisories", "bom", "mailing-list", "social", "chat",
                            "documentation", "support", "source-distribution", "distribution", "distribution-intake",
                            "license", "build-meta", "build-system", "release-notes", "security-contact", "model-card",
                            "log", "configuration", "evidence", "formulation", "attestation", "threat-model",
                            "adversary-model", "risk-assessment", "vulnerability-assertion", "exploitability-statement",
                            "pentest-report", "static-analysis-report", "dynamic-analysis-report", "runtime-analysis-report",
                            "component-analysis-report", "maturity-report", "certification-report", "quality-metrics",
                            "codified-infrastructure", "poam", "electronic-signature", "digital-signature",
                            "rfc-9116", "other")
TOP_KEYS = ("bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "dependencies", "compositions")
METADATA_KEYS = ("timestamp", "lifecycles", "tools", "component", "properties")
COMPONENT_KEYS = ("type", "bom-ref", "supplier", "name", "version", "scope", "hashes", "licenses", "cpe", "purl",
                  "externalReferences", "properties", "evidence")


class _Errors:
    def __init__(self) -> None:
        self.items: List[str] = []

    def add(self, where: str, message: str) -> None:
        if len(self.items) < MAX_ERRORS:
            self.items.append("%s: %s" % (where or "/", message))


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _object(value: Any, where: str, allowed: Sequence[str], required: Sequence[str], errs: _Errors) -> bool:
    if not isinstance(value, dict):
        errs.add(where, "must be an object")
        return False
    for key in required:
        if key not in value:
            errs.add(where, "the property %r is required" % key)
    for key in value:
        if key not in allowed:
            errs.add(where, "the property %r is not one this tool writes" % key)
    return True


def _array(value: Any, where: str, errs: _Errors, *, unique: bool = False) -> List[Any]:
    if not isinstance(value, list):
        errs.add(where, "must be an array")
        return []
    if unique:
        seen = set()
        for item in value:
            marker = repr(item)
            if marker in seen:
                errs.add(where, "items must be unique")
                break
            seen.add(marker)
    return value


def _string(value: Any, where: str, errs: _Errors, *, nonempty: bool = True) -> bool:
    if not isinstance(value, str):
        errs.add(where, "must be a string")
        return False
    if nonempty and not value:
        errs.add(where, "must not be empty")
        return False
    return True


def _properties(value: Any, where: str, errs: _Errors) -> None:
    for index, item in enumerate(_array(value, where, errs)):
        here = "%s/%d" % (where, index)
        if _object(item, here, ("name", "value"), ("name",), errs):
            _string(item.get("name"), here + "/name", errs)
            if "value" in item:
                _string(item["value"], here + "/value", errs, nonempty=False)


def _external_references(value: Any, where: str, errs: _Errors) -> None:
    for index, item in enumerate(_array(value, where, errs)):
        here = "%s/%d" % (where, index)
        if _object(item, here, ("type", "url"), ("url", "type"), errs):
            if item.get("type") not in EXTERNAL_REFERENCE_TYPES:
                errs.add(here + "/type", "is not a CycloneDX 1.6 external reference type")
            if _string(item.get("url"), here + "/url", errs) and not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", item["url"]):
                errs.add(here + "/url", "must be an absolute URL")


def _licenses(value: Any, where: str, license_ids: Iterable[str], errs: _Errors) -> None:
    known = set(license_ids)
    for index, item in enumerate(_array(value, where, errs)):
        here = "%s/%d" % (where, index)
        if not isinstance(item, dict):
            errs.add(here, "must be an object")
        elif "expression" in item:
            if _object(item, here, ("expression",), ("expression",), errs):
                _string(item["expression"], here + "/expression", errs)
        elif _object(item, here, ("license",), ("license",), errs):
            lic = item["license"]
            if _object(lic, here + "/license", ("id", "name"), (), errs):
                if ("id" in lic) == ("name" in lic):
                    errs.add(here + "/license", "must have exactly one of id and name")
                if "id" in lic and known and lic["id"] not in known:
                    errs.add(here + "/license/id", "%r is not in the CycloneDX 1.6 licence id list" % (lic["id"],))
                if "name" in lic:
                    _string(lic["name"], here + "/license/name", errs)


def _hashes(value: Any, where: str, errs: _Errors) -> None:
    for index, item in enumerate(_array(value, where, errs, unique=True)):
        here = "%s/%d" % (where, index)
        if _object(item, here, ("alg", "content"), ("alg", "content"), errs):
            alg, content = item.get("alg"), item.get("content")
            if alg not in HASH_LENGTHS:
                errs.add(here + "/alg", "%r is not a CycloneDX 1.6 hash algorithm" % (alg,))
            elif not isinstance(content, str) or not re.fullmatch(r"[a-fA-F0-9]{%d}" % HASH_LENGTHS[alg], content):
                errs.add(here + "/content", "must be %d hexadecimal characters for %s" % (HASH_LENGTHS[alg], alg))


def _evidence(value: Any, where: str, errs: _Errors) -> None:
    if not _object(value, where, ("occurrences",), (), errs):
        return
    for index, item in enumerate(_array(value.get("occurrences", []), where + "/occurrences", errs)):
        here = "%s/occurrences/%d" % (where, index)
        if _object(item, here, ("location", "line", "symbol"), ("location",), errs):
            _string(item.get("location"), here + "/location", errs)
            if "line" in item and (not _is_int(item["line"]) or item["line"] < 0):
                errs.add(here + "/line", "must be an integer of at least 0")
            if "symbol" in item:
                _string(item["symbol"], here + "/symbol", errs, nonempty=False)


def _component(value: Any, where: str, license_ids: Iterable[str], refs: Dict[str, str], errs: _Errors) -> None:
    if not _object(value, where, COMPONENT_KEYS, ("type", "name"), errs):
        return
    if value.get("type") not in COMPONENT_TYPES:
        errs.add(where + "/type", "%r is not a CycloneDX 1.6 component type" % (value.get("type"),))
    _string(value.get("name"), where + "/name", errs)
    if "bom-ref" in value:
        if _string(value["bom-ref"], where + "/bom-ref", errs):
            if value["bom-ref"] in refs:
                errs.add(where + "/bom-ref", "%r is already used at %s" % (value["bom-ref"], refs[value["bom-ref"]]))
            else:
                refs[value["bom-ref"]] = where
    if "version" in value:
        _string(value["version"], where + "/version", errs)
    if "scope" in value and value["scope"] not in SCOPES:
        errs.add(where + "/scope", "must be one of %s" % ", ".join(SCOPES))
    if "supplier" in value and _object(value["supplier"], where + "/supplier", ("name",), (), errs):
        if "name" in value["supplier"]:
            _string(value["supplier"]["name"], where + "/supplier/name", errs)
    if "hashes" in value:
        _hashes(value["hashes"], where + "/hashes", errs)
    if "licenses" in value:
        _licenses(value["licenses"], where + "/licenses", license_ids, errs)
    if "cpe" in value and _string(value["cpe"], where + "/cpe", errs) and not cpestr.is_valid_cpe23(value["cpe"]):
        errs.add(where + "/cpe", "is not a valid CPE 2.3 formatted string")
    if "purl" in value and _string(value["purl"], where + "/purl", errs) and not purl_mod.is_valid_purl(value["purl"]):
        errs.add(where + "/purl", "is not a valid package URL")
    if "externalReferences" in value:
        _external_references(value["externalReferences"], where + "/externalReferences", errs)
    if "properties" in value:
        _properties(value["properties"], where + "/properties", errs)
    if "evidence" in value:
        _evidence(value["evidence"], where + "/evidence", errs)


def _metadata(value: Any, license_ids: Iterable[str], refs: Dict[str, str], errs: _Errors) -> None:
    where = "/metadata"
    if not _object(value, where, METADATA_KEYS, (), errs):
        return
    if "timestamp" in value and (not isinstance(value["timestamp"], str) or not TIMESTAMP_RE.match(value["timestamp"])):
        errs.add(where + "/timestamp", "must be an RFC 3339 date-time")
    for index, item in enumerate(_array(value.get("lifecycles", []), where + "/lifecycles", errs)):
        here = "%s/lifecycles/%d" % (where, index)
        if _object(item, here, ("phase",), ("phase",), errs) and item.get("phase") not in PHASES:
            errs.add(here + "/phase", "must be one of %s" % ", ".join(PHASES))
    if "tools" in value and _object(value["tools"], where + "/tools", ("components",), (), errs):
        for index, item in enumerate(_array(value["tools"].get("components", []), where + "/tools/components", errs)):
            _component(item, "%s/tools/components/%d" % (where, index), license_ids, {}, errs)
    if "component" in value:
        _component(value["component"], where + "/component", license_ids, refs, errs)
        if isinstance(value["component"], dict) and "bom-ref" not in value["component"]:
            errs.add(where + "/component", "the root component needs a bom-ref (the dependencies point at it)")
    if "properties" in value:
        _properties(value["properties"], where + "/properties", errs)


def shape_errors(document: Any, license_ids: Iterable[str] = ()) -> List[str]:
    """The problems of a CycloneDX 1.6 document as the skill writes it; an empty list means the shape is right."""
    errs = _Errors()
    if not _object(document, "/", TOP_KEYS, ("bomFormat", "specVersion"), errs):
        return errs.items
    if document.get("bomFormat") != "CycloneDX":
        errs.add("/bomFormat", 'must be "CycloneDX"')
    if document.get("specVersion") != "1.6":
        errs.add("/specVersion", 'must be "1.6"')
    if "serialNumber" in document and (not isinstance(document["serialNumber"], str)
                                       or not SERIAL_RE.match(document["serialNumber"])):
        errs.add("/serialNumber", "must be urn:uuid: followed by a lowercase UUID")
    if "version" in document and (not _is_int(document["version"]) or document["version"] < 1):
        errs.add("/version", "must be an integer of at least 1")
    refs: Dict[str, str] = {}
    if "metadata" in document:
        _metadata(document["metadata"], license_ids, refs, errs)
    for index, item in enumerate(_array(document.get("components", []), "/components", errs)):
        _component(item, "/components/%d" % index, license_ids, refs, errs)
        if isinstance(item, dict) and "bom-ref" not in item:
            errs.add("/components/%d" % index, "a component needs a bom-ref (the SBOM identifies it by that)")
    for index, item in enumerate(_array(document.get("dependencies", []), "/dependencies", errs)):
        here = "/dependencies/%d" % index
        if _object(item, here, ("ref", "dependsOn"), ("ref",), errs):
            if item.get("ref") not in refs:
                errs.add(here + "/ref", "%r is not the bom-ref of a component" % (item.get("ref"),))
            targets = _array(item.get("dependsOn", []), here + "/dependsOn", errs, unique=True)
            for target in targets:
                if target not in refs:
                    errs.add(here + "/dependsOn", "%r is not the bom-ref of a component" % (target,))
    for index, item in enumerate(_array(document.get("compositions", []), "/compositions", errs)):
        here = "/compositions/%d" % index
        if _object(item, here, ("aggregate", "assemblies"), ("aggregate",), errs):
            if item.get("aggregate") not in AGGREGATES:
                errs.add(here + "/aggregate", "is not a CycloneDX 1.6 aggregate")
            for target in _array(item.get("assemblies", []), here + "/assemblies", errs, unique=True):
                if target not in refs:
                    errs.add(here + "/assemblies", "%r is not the bom-ref of a component" % (target,))
    return errs.items
