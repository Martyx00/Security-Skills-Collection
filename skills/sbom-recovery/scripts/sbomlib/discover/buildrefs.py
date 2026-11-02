"""Evidence from the parsed build model (private module of WP-discover; contract section 3.9 tables).

``emit_fetch`` (pass 2) turns FetchContent / CPM / ExternalProject declarations into ``FETCH_PIN`` evidence and
candidates. ``emit_refs`` (pass 3) turns packages, targets, link items, include directories and subdirectories into
``FIND_PACKAGE``, ``COMPILE_LIST``, ``LINK_REF``, ``INCLUDE_DIR`` and ``SUBDIR_BUILD`` evidence attached by identity or
by directory. ``emit_unparsed`` records the build files no parser covers.
"""
from __future__ import annotations

import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import model, urls, versions
from sbomlib.discover import session as sess
from sbomlib.discover.bm import Condition
from sbomlib.discover.session import Session
from sbomlib.norm import norm_library

_ARCHIVE_VERSION_RE = re.compile(r"(?:^|[/_\-])v?(\d+(?:\.\d+){1,3}[a-z]?)(?=\.(?:tar|tgz|zip|tbz|txz)|/|$)", re.I)
_ARCHIVE_TAG_RE = re.compile(r"/(?:download|tags?|releases?)/([A-Za-z_\-]*\d[^/]*)/")
_ARCHIVE_NAME_RE = re.compile(r"/archive/(?:refs/tags/)?([^/]+?)\.(?:tar\.\w+|tgz|zip)$")


# --------------------------------------------------------------------------------------------------- scope helpers

def record_scope(S: Session, path: str, cond: Condition, *, target: Optional[Dict[str, Any]] = None,
                 tool: bool = False) -> str:
    """Scope of a build-file record: test when its condition gates tests, its directory is reached only through
    test-gated subdirectories, its target is a test target or its path is a test path; dev for dev paths."""
    directory = posixpath.dirname(path)
    if S.bm.is_test_condition(cond) or S.bm.dir_is_test_only(directory) or (target is not None and target.get("test")):
        return "test"
    scope = sess.scope_of_path(path)
    if scope != "product":
        return scope
    return "build" if tool else "product"


def display_name(S: Session, name: str) -> Tuple[str, Optional[str]]:
    """``(canonical display name, map entry name)`` for a library name."""
    canon = S.identity.canonical(name)
    return canon, S.identity.map_entry_name(canon)


def _is_first_party(S: Session, norm_name: str) -> bool:
    return S.is_first_party_name(norm_name)


def find_or_create_system(S: Session, name: str, near: Optional[str], *, detected_as: str = "system",
                          alias: Optional[str] = None) -> Dict[str, Any]:
    """Attach by identity (in-tree first), else create a ``system`` candidate."""
    canon, entry = display_name(S, name)
    found = S.reg.find(norm_library(canon), near)
    if found is not None:
        if alias:
            S.reg.add_alias(found, alias)
        return found
    cand = S.reg.create(canon, detected_as, "system", None, None, map_entry=entry, aliases=[a for a in (alias, name) if a],
                        first_party=_is_first_party(S, norm_library(canon)),
                        identity_confidence="medium" if S.identity.canonical_or_none(name) else "low")
    upstream = S.identity.upstream_url(canon)
    if upstream and not cand["upstream"]["url"]:
        cand["upstream"]["url"] = upstream
    return cand


def settle_targets(S: Session) -> None:
    """After every parser ran: test directories, test targets, unresolved source lists, duplicate sources."""
    bm = S.bm
    bm.compute_test_dirs(sess.is_test_dir)
    bm.finish_targets(sess.is_test_dir)
    for target in bm.targets:
        if sess.scope_of_path(target["path"]) == "test":
            target["test"] = True
        if target.get("_unresolved"):
            bm.unresolved_targets.append((target["name"], target["path"], target["line"]))
            target["sources"] = []
        seen = set()
        unique = []
        for source in target["sources"]:
            key = (source["path"], source["line"], source["file"])
            if key not in seen:
                seen.add(key)
                unique.append(source)
        target["sources"] = unique
        target.pop("_unresolved", None)
        target.pop("_objects", None)


# --------------------------------------------------------------------------------------------------- pass 2

def _archive_version(url: str) -> Optional[str]:
    match = _ARCHIVE_TAG_RE.search(url)
    if match:
        return match.group(1)
    match = _ARCHIVE_NAME_RE.search(url)
    if match:
        return match.group(1)
    base = url.rsplit("/", 1)[-1]
    match = _ARCHIVE_VERSION_RE.search(base)
    return match.group(1) if match else None


def emit_fetch(S: Session) -> None:
    """FETCH_PIN evidence and candidates for FetchContent, CPM and ExternalProject declarations."""
    for decl in sorted(S.bm.fetch_decls, key=lambda d: (d["path"], d["line"], d["name"])):
        S.check_budget()
        if decl.get("local_source"):
            continue
        name = decl["name"]
        repo_url = decl.get("repo")
        archive_url = decl.get("url")
        tag = decl.get("tag")
        raw_url = repo_url or archive_url
        scrubbed = urls.scrub_url(raw_url) if raw_url else None
        upstream_url = (urls.https_form(raw_url) or scrubbed) if raw_url else None
        canon_hint = S.identity.from_url(raw_url) if raw_url else None
        canon = canon_hint or S.identity.canonical_or_none(name) or name
        canon, entry = display_name(S, canon)
        ref_kind: Optional[str] = None
        value: Optional[str] = None
        strength = "weak"
        if tag:
            value = tag
            if versions.looks_like_sha(tag):
                ref_kind, strength = "commit", "strong"
            elif versions.is_branch_like(tag):
                ref_kind, strength = "branch", "weak"
            else:
                ref_kind, strength = "tag", "strong"
        elif archive_url:
            value = scrubbed or archive_url
            ref_kind, strength = "url", "strong"
        elif repo_url:
            value, ref_kind, strength = "HEAD", "branch", "weak"
        unresolved = ref_kind in ("branch",) or ref_kind is None
        detected = "declared_unresolved" if unresolved else decl["kind"]
        near = decl["path"]
        existing = S.reg.find(norm_library(canon), near)
        if existing is not None:
            cand = existing
            S.reg.add_alias(cand, name)
        else:
            cand = S.reg.create(canon, detected, "manifest", decl["path"], decl["line"], map_entry=entry, aliases=[name],
                                first_party=_is_first_party(S, norm_library(canon)),
                                identity_confidence="high" if canon_hint else ("medium" if S.identity.canonical_or_none(name)
                                                                              else "low"))
        if upstream_url and not cand["upstream"]["url"]:
            cand["upstream"]["url"] = upstream_url
        elif not cand["upstream"]["url"] and S.identity.upstream_url(canon):
            cand["upstream"]["url"] = S.identity.upstream_url(canon)
        scope = record_scope(S, decl["path"], decl["condition"])
        evid = S.ev("FETCH_PIN", path=decl["path"], line=decl["tag_line"], symbol=name, value=value, ref_kind=ref_kind,
                    strength=strength, candidate=cand["id"], condition=decl["condition"], scope=scope)
        S.reg.claim_identity(cand, canon, [evid])
        if ref_kind == "tag" and value:
            canon_v = versions.canonicalize(value, library=canon, channel="fetchcontent_tag", rules=S.rules)
            S.reg.claim_version(cand, canon_v, "fetchcontent_tag", "declared", [evid])
        elif ref_kind == "commit" and value:
            if existing is None or not cand["upstream"]["commit"]:
                cand["upstream"]["commit"] = value
            canon_v = versions.canonicalize("", rules=S.rules)
            S.reg.claim_version(cand, canon_v, "none", "declared", [evid], ["pinned to commit %s" % value[:12]])
        elif ref_kind == "url" and archive_url:
            raw_version = _archive_version(archive_url)
            if raw_version:
                canon_v = versions.canonicalize(raw_version, library=canon, channel="fetchcontent_tag", rules=S.rules)
                S.reg.claim_version(cand, canon_v, "fetchcontent_tag", "declared", [evid])
        elif ref_kind == "branch":
            canon_v = {"version": "NOASSERTION", "version_raw": value or "", "version_kind": "unpinned_ref",
                       "cpe_version": None, "cpe_update": None, "notes": ["follows branch %s" % (value or "HEAD")]}
            S.reg.claim_version(cand, canon_v, "none", "declared", [evid])
            S.reg.add_note(cand, "%s follows branch %s (%s:%d)" % (decl["kind"], value or "HEAD", decl["path"],
                                                                    decl["tag_line"]))
            S.reg.blind("UNPINNED_REF", "%s %s follows branch %s" % (decl["kind"], name, value or "HEAD"),
                        "%s:%d" % (decl["path"], decl["tag_line"]), cand["id"])
        elif ref_kind is None:
            S.reg.blind("UNPINNED_REF", "%s %s has no pinned reference" % (decl["kind"], name),
                        "%s:%d" % (decl["path"], decl["line"]), cand["id"])
        S.bm.packages.append({"name": name, "kind": decl["kind"], "version_constraint": None, "required": True,
                              "condition": decl["condition"], "path": decl["path"], "line": decl["line"],
                              "evidence_id": evid, "pin": {"ref": value, "ref_kind": ref_kind, "url": scrubbed}})


# --------------------------------------------------------------------------------------------------- pass 3

def _attach_package(S: Session, package: Dict[str, Any]) -> None:
    kind = package["kind"]
    name = package["name"]
    if not name:
        return
    if kind == "find_package" and name.lower() in {t.lower() for t in model.FIND_PACKAGE_TOOLS}:
        return
    known = S.imap.package_lib(name)
    if kind in ("ac_check_lib", "pkg_check_ac"):
        known = known or S.imap.link_lib(name)
    mapped = known or S.identity.canonical_or_none(name)
    tool = kind == "find_program"
    if kind in ("ac_check_lib", "find_program") and not mapped:
        return
    if tool and not (known or S.identity.canonical_or_none(name)):
        return
    target_name = known or name
    cand = find_or_create_system(S, target_name, package["path"], alias=name)
    scope = record_scope(S, package["path"], package.get("condition"), tool=tool)
    evid = S.ev("FIND_PACKAGE", path=package["path"], line=package["line"], symbol=name, value=name, candidate=cand["id"],
                condition=package.get("condition"), scope=scope)
    package["evidence_id"] = evid
    S.reg.claim_identity(cand, cand["name"], [evid])
    constraint = package.get("version_constraint")
    if constraint:
        raw = constraint if re.match(r"^(?:>=|<=|==|<|>|=|~|\^)", constraint) else ">=" + constraint
        canon = versions.canonicalize(raw, library=cand["name"], channel="constraint", rules=S.rules)
        S.reg.claim_version(cand, canon, "constraint", "declared", [evid])


def _owner_of_dir(S: Session, directory: str) -> Optional[Dict[str, Any]]:
    if not directory or directory == ".":
        return None
    return S.reg.owner_of(directory)


def resolve_link_item(S: Session, item: str, file: str, directory: str) -> Optional[Dict[str, Any]]:
    """The candidate a link item refers to (contract section 3.9, ``LINK_REF``), creating a ``system`` candidate only for
    an item that maps through ``include_map.link_names``."""
    text = (item or "").strip()
    if not text or "$<" in text or "${" in text:
        return None
    if text.startswith("-") and not text.startswith("-l"):
        return None
    if text.startswith("-l"):
        text = text[2:]
    if not text:
        return None
    bm = S.bm
    resolved = bm.aliases.get(text, text)
    target = bm.target(resolved, directory)
    if target is not None:
        owner = _owner_of_dir(S, target["dir"])
        if owner is not None:
            return owner
        # A target defined outside any candidate directory (the project's own CMakeLists naming a vendored library's sources):
        # it stands for the candidate that owns its sources, else for a candidate its name aliases. Never a system candidate.
        owners = {}
        for source in target.get("sources") or []:
            found = S.reg.owner_of(source["path"])
            if found is not None:
                owners[found["id"]] = found
        if len(owners) == 1:
            return list(owners.values())[0]
        for probe in (text, resolved):
            found = S.reg.find_alias(norm_library(probe), file)
            if found is not None and found["detected_as"] != "system":
                return found
        return None
    if resolved in bm.imported:
        location = bm.imported[resolved]
        if location:
            owner = S.reg.owner_of(location)
            if owner is not None:
                return owner
    if "/" in text and "::" not in text:
        path = posixpath.normpath(posixpath.join(directory or ".", text.replace("\\", "/")))
        if not path.startswith(".."):
            owner = S.reg.owner_of("" if path == "." else path)
            if owner is not None:
                return owner
    lib = S.imap.link_lib(text)
    if lib:
        return find_or_create_system(S, lib, file, alias=text)
    for probe in (text, text.split("::", 1)[0]):
        found = S.reg.find_alias(norm_library(probe), file)
        if found is not None and found["detected_as"] != "system":
            return found
    return None


def _emit_target(S: Session, target: Dict[str, Any]) -> None:
    scope = record_scope(S, target["path"], target.get("condition"), target=target)
    for source in target["sources"]:
        owner = S.reg.owner_of(source["path"])
        if owner is None or not S.reg.count_compile(owner["id"], target["name"]):
            continue
        S.ev("COMPILE_LIST", path=source["file"], line=source["line"], symbol=source["path"], value=source["path"],
             candidate=owner["id"], target=target["name"], condition=source.get("condition"),
             scope=record_scope(S, source["file"], source.get("condition"), target=target))
    for link in target["link"]:
        cand = resolve_link_item(S, link["item"], link["file"], target["dir"] if target["dir"] != "." else "")
        if cand is None:
            continue
        S.ev("LINK_REF", path=link["file"], line=link["line"], symbol=link["item"], value=link["item"],
             candidate=cand["id"], target=target["name"], condition=link.get("condition"),
             scope=record_scope(S, link["file"], link.get("condition"), target=target))
    for include in target["include_dirs"]:
        owner = S.reg.owner_of(include["path"]) if include["path"] not in ("", ".") else None
        if owner is None:
            continue
        S.ev("INCLUDE_DIR", path=include["file"], line=include["line"], symbol=include["path"], value=include["path"],
             candidate=owner["id"], target=target["name"], condition=include.get("condition"), scope=scope)


def emit_refs(S: Session) -> None:
    """FIND_PACKAGE, COMPILE_LIST, LINK_REF, INCLUDE_DIR and SUBDIR_BUILD evidence from the build model."""
    bm = S.bm
    for package in sorted(bm.packages, key=lambda p: (p["path"], p["line"], p["name"])):
        if package["kind"] in ("fetchcontent", "cpm", "external_project", "meson_subproject"):
            continue
        S.check_budget()
        _attach_package(S, package)
    for subdir in sorted(bm.subdirs, key=lambda s: (s.get("file") or "", s["line"], s["path"])):
        owner = S.reg.owner_of(subdir["path"]) if subdir["path"] not in ("", ".") else None
        if owner is None:
            continue
        file = subdir.get("file") or "CMakeLists.txt"
        scope = record_scope(S, file, subdir.get("condition"))
        if bm.dir_is_test_only(subdir["path"]):
            scope = "test"
        subdir["evidence_id"] = S.ev("SUBDIR_BUILD", path=file, line=subdir["line"], symbol=subdir["path"],
                                     value=subdir["path"], candidate=owner["id"], condition=subdir.get("condition"),
                                     scope=scope)
    for target in sorted(bm.targets, key=lambda t: (t["path"], t["line"], t["name"])):
        S.check_budget()
        _emit_target(S, target)
    for item in bm.globals["link"]:
        cand = resolve_link_item(S, item["item"], item["path"], posixpath.dirname(item["path"]))
        if cand is not None:
            S.ev("LINK_REF", path=item["path"], line=item["line"], symbol=item["item"], value=item["item"],
                 candidate=cand["id"], condition=item.get("condition"),
                 scope=record_scope(S, item["path"], item.get("condition")))
    for item in bm.globals["include_dirs"]:
        owner = S.reg.owner_of(item["path"]) if item["path"] not in ("", ".") else None
        if owner is not None:
            S.ev("INCLUDE_DIR", path=item["file"], line=item["line"], symbol=item["path"], value=item["path"],
                 candidate=owner["id"], condition=item.get("condition"),
                 scope=record_scope(S, item["file"], item.get("condition")))


# --------------------------------------------------------------------------------------------------- uncovered builds

def emit_unparsed(S: Session, files: List[str]) -> None:
    """``BUILD_FILE_UNPARSED`` for each build file of an uncovered system and ``BUILD_REF_UNPARSED`` for the lines that
    mention a candidate by name (word match, case-insensitive; at most 10 lines per file and candidate)."""
    names: List[Tuple[Dict[str, Any], "re.Pattern[str]"]] = []
    for cand in S.reg.cands.values():
        if cand["detected_as"] in ("toolchain_runtime",) or len(cand["norm_name"]) < 3:
            continue
        words = {cand["name"]}
        path = cand["location"]["path"]
        if path and cand["location"]["kind"] in ("dir", "gitlink", "file"):
            words.add(posixpath.basename(path.rstrip("/")))
        pattern = "|".join(re.escape(w) for w in sorted(words, key=len, reverse=True) if len(w) >= 3)
        if pattern:
            names.append((cand, re.compile(r"(?<![A-Za-z0-9_])(?:%s)(?![A-Za-z0-9_])" % pattern, re.I)))
    for path in sorted(files):
        S.check_budget()
        S.ev("BUILD_FILE_UNPARSED", path=path, symbol=posixpath.basename(path), value=posixpath.basename(path), quote=False)
        text = S.fs.text(path)
        if text is None:
            continue
        lines = text.split("\n")
        counts: Dict[str, int] = {}
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            for cand, regex in names:
                if counts.get(cand["id"], 0) >= 10:
                    continue
                if regex.search(line):
                    counts[cand["id"]] = counts.get(cand["id"], 0) + 1
                    S.ev("BUILD_REF_UNPARSED", path=path, line=number, symbol=cand["norm_name"], value=cand["name"],
                         candidate=cand["id"], scope=record_scope(S, path, None))
