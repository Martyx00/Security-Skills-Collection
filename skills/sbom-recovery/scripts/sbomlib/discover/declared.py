"""Identifiers that repositories declare about themselves (contract section 3.9, report "Declared identifiers").

``.gitmodules`` ``sbom-version`` / ``sbom-cpe`` / ``sbom-hash``, ``README.chromium`` ``CPEPrefix`` (CPE 2.2 converted to
2.3), Buildroot ``*_CPE_ID_*`` variables, Zephyr ``zephyr/module.yml`` external references, ESP-IDF ``sbom*.yml`` and the
``sbom:`` block of ``idf_component.yml``, and SPDX / CycloneDX documents vendored under a candidate directory (anywhere
else they are IGNORED by phase 1). Every declaration is a ``DECLARED_ID`` record whose ``value`` is
``{"cpe23", "purl", "name", "version", "hash", "supplier", "source"}``; ``candidate.declared_ids`` lists the evidence ids.
"""
from __future__ import annotations

import json
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import miniyaml
from sbomlib.discover.session import Session
from sbomlib.norm import norm_library

MAX_BUILDROOT_PACKAGES = 500
_CPE23_RE = re.compile(r"^cpe:2\.3:[aho*-](?::[^:\s]*){10}$")
_BUILDROOT_VAR_RE = re.compile(r"^([A-Z0-9_]+?)_(CPE_ID_(?:VENDOR|PRODUCT|VERSION|UPDATE|PREFIX|VALID)|VERSION)\s*[:?+]?=\s*(.*?)\s*$",
                               re.M)


def _escape(value: str) -> str:
    return re.sub(r"([^A-Za-z0-9._\-*?])", lambda m: "\\" + m.group(1), value)


def cpe_to_23(text: str) -> Optional[str]:
    """A CPE 2.2 URI (``cpe:/a:vendor:product:1.0``) or a 2.3 formatted string as a 2.3 formatted string, else None."""
    value = (text or "").strip()
    if _CPE23_RE.match(value):
        return value
    if not value.startswith("cpe:/"):
        return None
    parts = value[len("cpe:/"):].split(":")
    if not parts or parts[0] not in ("a", "o", "h") or len(parts) < 3 or len(parts) > 7:
        return None
    fields: List[str] = []
    for part in parts[1:]:
        decoded = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), part)
        if decoded == "":
            fields.append("*")
        elif decoded == "-":
            fields.append("-")
        else:
            fields.append(_escape(decoded.lower()))
    while len(fields) < 10:
        fields.append("*")
    return "cpe:2.3:%s:%s" % (parts[0], ":".join(fields[:10]))


def _record(S: Session, cand: Dict[str, Any], path: str, line: int, symbol: str, source: str, *, cpe23: Optional[str] = None,
            purl: Optional[str] = None, name: Optional[str] = None, version: Optional[str] = None,
            hash_value: Optional[str] = None, supplier: Optional[str] = None) -> str:
    value = {"cpe23": cpe23, "purl": purl, "name": name, "version": version, "hash": hash_value, "supplier": supplier,
             "source": source}
    evid = S.ev("DECLARED_ID", path=path, line=line, symbol=symbol[:120], value=value, candidate=cand["id"])
    S.reg.meta[cand["id"]].declared_ids.add(evid)
    if supplier and not cand.get("supplier"):
        cand["supplier"] = supplier
    return evid


def _declared_candidate(S: Session, name: str, path: str, line: int) -> Dict[str, Any]:
    """The candidate a declaration without a candidate directory belongs to (attach by identity, else create)."""
    canon = S.identity.canonical(name)
    cand = S.reg.find(norm_library(canon), path)
    if cand is not None:
        return cand
    return S.reg.create(canon, "declared_unresolved", "manifest", path, line, map_entry=S.identity.map_entry_name(canon),
                        aliases=[name], first_party=S.is_first_party_name(norm_library(canon)),
                        identity_confidence="medium" if S.identity.canonical_or_none(name) else "low")


# --------------------------------------------------------------------------------------------------- .gitmodules

def gitmodules(S: Session) -> None:
    declared = [m for m in S.submodules if m.get("sbom")]
    if not declared or not S.tracked(".gitmodules"):
        return
    text = S.fs.text(".gitmodules") or ""
    lines = text.split("\n")
    first_line: Dict[str, int] = {}
    section: Optional[str] = None
    for number, line in enumerate(lines, start=1):
        match = re.match(r'^\s*\[submodule\s+"(.*)"\s*\]', line)
        if match:
            section = match.group(1)
            continue
        if section is not None and re.match(r"^\s*sbom-", line):
            first_line.setdefault(section, number)
    for meta in declared:
        cand = S.reg.owner_of(meta["path"])
        if cand is None or cand["detected_as"] != "submodule":
            continue
        sbom = meta["sbom"]
        cpe = cpe_to_23(sbom.get("cpe", "")) if sbom.get("cpe") else None
        line = first_line.get(meta.get("name") or meta["path"], 1)
        _record(S, cand, ".gitmodules", line, sbom.get("cpe") or "sbom", ".gitmodules", cpe23=cpe,
                version=sbom.get("version"), hash_value=sbom.get("hash"))


# --------------------------------------------------------------------------------------------------- README.chromium

def readme_chromium(S: Session) -> None:
    for path in sorted(S.by_base.get("README.chromium", [])):
        directory = posixpath.dirname(path)
        text = S.fs.text(path)
        if text is None or not directory:
            continue
        cand = S.reg.owner_of(directory)
        if cand is None:
            continue
        fields: Dict[str, Tuple[str, int]] = {}
        for number, line in enumerate(text.split("\n"), start=1):
            match = re.match(r"^\s*([A-Za-z][A-Za-z ]*?)\s*:\s*(.*?)\s*$", line)
            if match and match.group(1) not in fields:
                fields[match.group(1)] = (match.group(2), number)
        if "CPEPrefix" not in fields:
            continue
        raw, line = fields["CPEPrefix"]
        cpe = cpe_to_23(raw)
        if cpe is None:
            continue
        version = fields.get("Version", (None, 0))[0]
        _record(S, cand, path, line, raw, "README.chromium", cpe23=cpe, name=fields.get("Name", (None, 0))[0],
                version=version if version and version.lower() != "unknown" else None)


# --------------------------------------------------------------------------------------------------- Buildroot

def buildroot(S: Session) -> None:
    created = 0
    for path in S.paths:
        if not path.endswith(".mk") or S.reg.owner_of(path) is not None:
            continue
        text = S.fs.text(path)
        if text is None or "_CPE_ID_" not in text:
            continue
        packages: Dict[str, Dict[str, Tuple[str, int]]] = {}
        for match in _BUILDROOT_VAR_RE.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            packages.setdefault(match.group(1), {})[match.group(2)] = (match.group(3), line)
        stem = posixpath.splitext(posixpath.basename(path))[0]
        for prefix in sorted(packages):
            fields = packages[prefix]
            ids = [k for k in fields if k.startswith("CPE_ID_")]
            if not ids or created >= MAX_BUILDROOT_PACKAGES:
                continue
            pkg = stem if prefix == re.sub(r"[^A-Z0-9]", "_", stem.upper()) else prefix.lower().replace("_", "-")
            vendor = fields.get("CPE_ID_VENDOR", (None, 0))[0]
            product = fields.get("CPE_ID_PRODUCT", (None, 0))[0]
            valid = (fields.get("CPE_ID_VALID", ("", 0))[0] or "").upper() == "YES"
            if not vendor and not product and not valid:
                continue
            vendor = vendor or (pkg + "_project")
            product = product or pkg
            package_version = fields.get("VERSION", (None, 0))[0]
            version = fields.get("CPE_ID_VERSION", (None, 0))[0] or package_version
            if version and "$(" in version:
                version = package_version if package_version and "$(" not in package_version else None
            version = (version or "*").strip() or "*"
            update = fields.get("CPE_ID_UPDATE", ("*", 0))[0] or "*"
            cpe_prefix = fields.get("CPE_ID_PREFIX", ("cpe:2.3:a", 0))[0] or "cpe:2.3:a"
            cpe = "%s:%s:%s:%s:%s:*:*:*:*:*:*" % (cpe_prefix, _escape(vendor.lower()), _escape(product.lower()),
                                                  _escape(version) if version != "*" else "*", _escape(update) if update != "*" else "*")
            if not _CPE23_RE.match(cpe):
                continue
            first = min(line for _v, line in fields.values())
            cand = _declared_candidate(S, pkg, path, first)
            created += 1
            _record(S, cand, path, first, cpe, "buildroot", cpe23=cpe, name=pkg, version=None if version == "*" else version)


# --------------------------------------------------------------------------------------------------- Zephyr, ESP-IDF

def zephyr_modules(S: Session) -> None:
    for path in sorted(S.paths):
        if posixpath.basename(path) != "module.yml" or posixpath.basename(posixpath.dirname(path)) != "zephyr":
            continue
        text = S.fs.text(path)
        if text is None:
            continue
        root = posixpath.dirname(posixpath.dirname(path))
        if not root:
            continue                                            # the repository is itself the module
        try:
            data = miniyaml.load(text)
        except miniyaml.YamlUnsupported:
            continue
        if not isinstance(data, dict):
            continue
        security = data.get("security")
        refs = security.get("external-references") if isinstance(security, dict) else None
        if not isinstance(refs, list):
            continue
        name = data.get("name") if isinstance(data.get("name"), str) else posixpath.basename(root)
        cand = S.reg.owner_of(root) or _declared_candidate(S, name, path, 1)
        for index, ref in enumerate(refs):
            if not isinstance(ref, dict) or not isinstance(ref.get("value"), str):
                continue
            line = refs.lines[index] if hasattr(refs, "lines") else 1
            kind = str(ref.get("type", "")).lower()
            if kind == "cpe":
                cpe = cpe_to_23(ref["value"])
                if cpe:
                    _record(S, cand, path, line, ref["value"], "zephyr module.yml", cpe23=cpe, name=name)
            elif kind == "purl" and ref["value"].startswith("pkg:"):
                _record(S, cand, path, line, ref["value"], "zephyr module.yml", purl=ref["value"], name=name)


def _sbom_block(S: Session, path: str, block: Dict[str, Any], default_name: str, lines: Any) -> None:
    directory = posixpath.dirname(path)
    version = block.get("version") if isinstance(block.get("version"), str) else None
    cpe_raw = block.get("cpe") if isinstance(block.get("cpe"), str) else None
    purl_raw = block.get("purl") if isinstance(block.get("purl"), str) else None
    if cpe_raw:
        cpe_raw = cpe_raw.replace("{}", version or "*")
    if purl_raw:
        purl_raw = purl_raw.replace("{}", version or "") if version else purl_raw.replace("@{}", "")
    cpe = cpe_to_23(cpe_raw) if cpe_raw else None
    if not (cpe or purl_raw or version):
        return
    supplier = block.get("supplier") if isinstance(block.get("supplier"), str) else None
    if supplier and not supplier.startswith(("Organization:", "Person:", "NOASSERTION")):
        supplier = "Organization: " + supplier
    cand = S.reg.owner_of(directory) if directory else None
    if cand is None:
        cand = _declared_candidate(S, default_name, path, 1)
    line = 1
    if hasattr(lines, "lines"):
        line = min([v for k, v in lines.lines.items() if k in ("cpe", "purl", "version", "supplier", "hash")] or [1])
    _record(S, cand, path, line, cpe_raw or purl_raw or version or "sbom", "sbom.yml", cpe23=cpe, purl=purl_raw,
            name=default_name, version=version, hash_value=block.get("hash") if isinstance(block.get("hash"), str) else None,
            supplier=supplier)


def esp_idf_sbom(S: Session) -> None:
    for path in sorted(S.paths):
        base = posixpath.basename(path)
        is_sbom = bool(re.match(r"^sbom.*\.ya?ml$", base))
        if not (is_sbom or base == "idf_component.yml"):
            continue
        if S.reg.owner_of(path) is not None and base == "idf_component.yml":
            continue
        text = S.fs.text(path)
        if text is None:
            continue
        try:
            data = miniyaml.load(text)
        except miniyaml.YamlUnsupported:
            continue
        if not isinstance(data, dict):
            continue
        block = data if is_sbom else data.get("sbom")
        if not isinstance(block, dict):
            continue
        directory = posixpath.dirname(path)
        name = posixpath.basename(directory) if directory else S.repo
        _sbom_block(S, path, block, name, block)


# --------------------------------------------------------------------------------------------------- vendored SBOM documents

def _spdx_package(doc: Dict[str, Any], norm_name: str) -> Optional[Dict[str, Any]]:
    packages = [p for p in doc.get("packages") or [] if isinstance(p, dict)]
    matches = [p for p in packages if norm_library(str(p.get("name", ""))) == norm_name]
    if matches:
        return matches[0]
    if len(packages) == 1:
        return packages[0]
    return None


def _cdx_component(doc: Dict[str, Any], norm_name: str) -> Optional[Dict[str, Any]]:
    comps = [c for c in doc.get("components") or [] if isinstance(c, dict)]
    matches = [c for c in comps if norm_library(str(c.get("name", ""))) == norm_name]
    if matches:
        return matches[0]
    meta = (doc.get("metadata") or {}).get("component") if isinstance(doc.get("metadata"), dict) else None
    if isinstance(meta, dict) and norm_library(str(meta.get("name", ""))) == norm_name:
        return meta
    return comps[0] if len(comps) == 1 else None


def vendored_sbom_documents(S: Session) -> None:
    for path in sorted(S.paths):
        lowered = path.lower()
        if not (lowered.endswith(".spdx.json") or lowered.endswith(".cdx.json")):
            continue
        owner = S.reg.owner_of(path)
        if owner is None:
            continue
        data = S.fs.read_bytes(path)
        if data is None:
            continue
        try:
            doc = json.loads(data.decode("utf-8", "replace"))
        except ValueError:
            continue
        if not isinstance(doc, dict):
            continue
        text = data.decode("utf-8", "replace")
        if lowered.endswith(".spdx.json"):
            package = _spdx_package(doc, owner["norm_name"])
            if package is None:
                continue
            cpe = purl = None
            for ref in package.get("externalRefs") or []:
                if not isinstance(ref, dict):
                    continue
                locator = ref.get("referenceLocator")
                if ref.get("referenceType") == "cpe23Type" and cpe is None and isinstance(locator, str):
                    cpe = cpe_to_23(locator)
                elif ref.get("referenceType") == "purl" and purl is None and isinstance(locator, str):
                    purl = locator
            sha = next((c.get("checksumValue") for c in package.get("checksums") or []
                        if isinstance(c, dict) and str(c.get("algorithm", "")).upper() == "SHA256"), None)
            supplier = package.get("supplier") if isinstance(package.get("supplier"), str) else None
            name, version = package.get("name"), package.get("versionInfo")
        else:
            comp = _cdx_component(doc, owner["norm_name"])
            if comp is None:
                continue
            cpe = cpe_to_23(comp["cpe"]) if isinstance(comp.get("cpe"), str) else None
            purl = comp.get("purl") if isinstance(comp.get("purl"), str) else None
            sha = next((h.get("content") for h in comp.get("hashes") or []
                        if isinstance(h, dict) and h.get("alg") == "SHA-256"), None)
            supplier_obj = comp.get("supplier")
            supplier = ("Organization: " + str(supplier_obj["name"])) if isinstance(supplier_obj, dict) and supplier_obj.get("name") else None
            name, version = comp.get("name"), comp.get("version")
        if not (cpe or purl or supplier or version):
            continue
        needle = '"cpe23Type"' if cpe and lowered.endswith(".spdx.json") else ('"%s"' % name if name else "{")
        offset = text.find(needle)
        line = text.count("\n", 0, offset) + 1 if offset >= 0 else 1
        _record(S, owner, path, line, cpe or purl or str(name), "vendored SBOM document", cpe23=cpe, purl=purl,
                name=name if isinstance(name, str) else None, version=version if isinstance(version, str) else None,
                hash_value=sha if isinstance(sha, str) else None, supplier=supplier)


# --------------------------------------------------------------------------------------------------- entry points

def run_in_tree(S: Session) -> None:
    """Pass 1: declarations that enrich candidates which already exist (submodules, vendored directories)."""
    gitmodules(S)
    readme_chromium(S)
    vendored_sbom_documents(S)


def run_declared(S: Session) -> None:
    """Pass 2: declarations that may create a candidate of their own."""
    buildroot(S)
    zephyr_modules(S)
    esp_idf_sbom(S)
