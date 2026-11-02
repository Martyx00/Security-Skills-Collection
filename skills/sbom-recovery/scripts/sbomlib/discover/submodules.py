"""Gitlinks (submodules): candidates, ``GITLINK`` and ``GIT_DESCRIBE`` evidence (contract sections 1.3 S2 and 3.9).

Versions come only from the submodule's own object store (``<repo>/.git/modules/<name>``, offline, through ``gitro``):
an exact tag is a release, a commit between tags is ``between_releases`` (version ``NOASSERTION``, the nearest tag and the
commit count are kept). Nothing is ever fetched, and ``describe`` is never run inside an uninitialized submodule path.
"""
from __future__ import annotations

import posixpath
from typing import Any, Dict, List, Optional

from sbomlib import errors, gitro, urls, versions
from sbomlib.discover import vendored
from sbomlib.discover.session import Session
from sbomlib.norm import norm_library


def _describe(S: Session, meta: Dict[str, Any]) -> Optional[str]:
    pinned = meta.get("pinned")
    git_dir = meta.get("git_dir")
    if not pinned or not git_dir:
        return None
    try:
        return gitro.describe(S.repo_dir / meta["path"], pinned, layout=S.layout, git_dir=S.layout.parent / git_dir,
                              tags=True, always=False, env=S.ctx.env, timeout=gitro.budget_timeout(S.ctx))
    except errors.GitUnreadable:
        raise
    except errors.SbomError as exc:
        S.log("discover.submodule_describe_failed", path=meta.get("path"), error=exc.message[:160])
        return None


def run(S: Session, pl: vendored.Plan) -> None:
    uninitialized: List[str] = []
    for meta in sorted(S.submodules, key=lambda m: m.get("path") or ""):
        path = meta.get("path")
        if not path:
            continue
        S.check_budget()
        state = meta.get("state") or "uninitialized"
        pinned = meta.get("pinned")
        url = meta.get("url")
        hits = pl.dir_hits.get(path, [])
        files = pl.files_of.get(path, [])
        owned = vendored._ownership(S, files)
        projects = vendored._project_names(S, path) if state != "uninitialized" else []
        url_entry = S.identity.entry_for_url(url)
        url_name = url_entry.get("name") if url_entry else None
        last_url = S.identity.url_last_component(url)
        last_path = posixpath.basename(path)
        claims = []
        for hit_lib in sorted({h.lib for h in hits}):
            claims.append((0, hit_lib, "rule"))
        if url_name:
            claims.append((1, url_name, "url"))
        for lib in sorted(owned):
            claims.append((2, lib, "header"))
        for name, _v, _p, _l, _vl in projects:
            known = S.identity.canonical_or_none(name)
            if known:
                claims.append((3, known, "project"))
        if last_url:
            claims.append((4, S.identity.resolve_name(last_url) or last_url, "url name"))
        claims.append((5, S.identity.resolve_name(last_path) or last_path, "path"))
        claims.sort(key=lambda c: c[0])
        rank, chosen, source = claims[0]
        canon = S.identity.canonical(chosen)
        entry = S.identity.map_entry_name(canon)
        confidence = "high" if rank <= 1 else ("medium" if rank <= 4 else "low")
        upstream_url = (urls.https_form(url) or url) if url else None
        if not upstream_url:
            upstream_url = S.identity.upstream_url(canon)
        cand = S.reg.create(
            canon, "submodule", "gitlink", path, None, map_entry=entry,
            aliases=[last_path, meta.get("name") or "", last_url or ""],
            upstream={"url": upstream_url, "commit": pinned, "nearest_tag": None, "commits_since_tag": None},
            submodule={"path": path, "state": state, "pinned": pinned, "checked_out": meta.get("checked_out")},
            first_party=S.is_first_party_name(norm_library(canon)), identity_confidence=confidence)
        gitlink = S.ev("GITLINK", path=path, symbol=meta.get("name") or path, value=pinned, ref_kind="commit",
                       candidate=cand["id"], quote=False, detail="gitlink %s pinned at %s" % (path, (pinned or "")[:12]))
        S.reg.claim_identity(cand, canon, [gitlink])
        for _r, alt, _s in claims[1:]:
            if norm_library(alt) != norm_library(canon):
                S.reg.claim_identity(cand, S.identity.canonical(alt), [])
        if state == "different_commit":
            S.reg.add_note(cand, "checked out at %s but the repository pins %s" % (
                (meta.get("checked_out") or "")[:12], (pinned or "")[:12]))
        elif state == "conflict":
            S.reg.add_note(cand, "merge conflict in the index entry of this submodule")
        if state == "uninitialized":
            uninitialized.append(path)
            S.reg.add_note(cand, "submodule is not initialized: no content, version or describe available")
            S.reg.blind("UNINITIALIZED_SUBMODULE", 'submodule "%s" is not initialized' % path, path, cand["id"])
            continue
        if hits:
            vendored.add_version_claims(S, cand, hits, canon, vendored._ignored_macros(S, canon))
        vendored._generic_claims(S, cand, path, canon, skip_project=False)
        _describe_claim(S, cand, meta, canon)


def _describe_claim(S: Session, cand: Dict[str, Any], meta: Dict[str, Any], canon: str) -> None:
    describe = _describe(S, meta)
    if not describe:
        return
    parts = versions.describe_parts(describe)
    git_dir = meta.get("git_dir")
    pinned = meta.get("pinned")
    if parts is not None and parts[1] > 0:
        tag, count, _sha = parts
        evid = S.ev("GIT_DESCRIBE", symbol=tag, value=describe, candidate=cand["id"], strength="medium",
                    object_store=git_dir, object=pinned, quote=False, detail="git describe --tags %s" % describe)
        cand["upstream"]["nearest_tag"] = tag
        cand["upstream"]["commits_since_tag"] = count
        canon_v = versions.canonicalize(describe, library=canon, channel="describe", rules=S.rules)
        S.reg.claim_version(cand, canon_v, "describe", "tree", [evid])
        S.reg.add_note(cand, "git describe %s" % describe)
        return
    tag = describe
    evid = S.ev("GIT_DESCRIBE", symbol=tag, value=tag, candidate=cand["id"], strength="strong", ref_kind="tag",
                object_store=git_dir, object=pinned, quote=False, detail="git describe --tags %s (exact tag)" % tag)
    cand["upstream"]["nearest_tag"] = tag
    cand["upstream"]["commits_since_tag"] = 0
    canon_v = versions.canonicalize(tag, library=canon, channel="git_tag", rules=S.rules)
    S.reg.claim_version(cand, canon_v, "git_tag", "tree", [evid])
