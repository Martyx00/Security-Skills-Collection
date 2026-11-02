"""Phase 2: discovery of third-party components in one repository (contract section 3.9).

``run_repo`` reads the queue entry of phase 1, lists the tracked files through ``gitro`` and writes
``repos/<repo>/{inventory.json, buildmodel.json, candidates.json, evidence.jsonl}``. Channels run in three passes so that
the candidate an item attaches to does not depend on file order:

1. in-tree: vendored directories, single-file libraries, submodules, committed binaries, licences, in-tree declarations;
2. manifests, lockfiles, wrap files, fetch declarations (FetchContent, CPM, ExternalProject) and declared identifiers;
3. build references (find_package, link items, compile lists, subdirectories), by-products and linker maps, runtime
   loading, CI install lines and ``#include`` scanning.

Nothing is executed, nothing is written outside ``sbom-out``, and all git access goes through ``gitro``.
"""
from __future__ import annotations

import posixpath
from typing import Any, Dict, List, Optional

from sbomlib import errors, fsio, model, state
from sbomlib.context import RunContext
from sbomlib.discover import (buildrefs, byproducts, cmake, declared, includes, inventory, licenses, make, manifests,
                              meson, submodules, vendored)
from sbomlib.discover.session import Session
from sbomlib.model import PhaseResult
from sbomlib.state import RunState

SCHEMA = 1


def upstream_version(ctx: RunContext, candidate: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """M2 slot (nearest tag and upstream blob matching through ``gitnet``); returns None in M1."""
    return None


def _entry(ctx: RunContext, repo: str) -> Dict[str, Any]:
    queue = state.load_queue(ctx)
    for entry in queue.get("repos", []):
        if entry.get("name") == repo:
            return entry
    raise errors.StateError("queue.json has no repository %r" % repo, repo=repo)


def _queue_ignored(ctx: RunContext, repo: str) -> List[Dict[str, str]]:
    """The IGNORED items phase 1 recorded for ``repo`` (in-repo agent files, repository-level SBOM documents ...)."""
    items: List[Dict[str, str]] = []
    for item in state.load_queue(ctx).get("ignored", []):
        if item.get("repo") == repo and isinstance(item.get("path"), str):
            items.append({"path": item["path"], "reason": str(item.get("reason") or "")})
    return items


def _bazel_covered(S: Session) -> bool:
    """BUILD / WORKSPACE files count as covered only when ``MODULE.bazel`` declares dependencies."""
    for path in S.paths:
        if posixpath.basename(path) == "MODULE.bazel" and S.reg.owner_of(path) is None:
            text = S.fs.text(path) or ""
            if "bazel_dep(" in text:
                return True
    return False


def _coverage(S: Session, systems: Dict[str, List[str]]) -> Dict[str, Any]:
    bm = S.bm
    uncovered = [p for p in systems["uncovered"] if S.reg.owner_of(p) is None]
    bazel_files = [p for p in systems["bazel"] if S.reg.owner_of(p) is None]
    covered = set(bm.systems)
    if bazel_files:
        if _bazel_covered(S):
            covered.add("bazel")
        else:
            uncovered.extend(bazel_files)
    named = [t for t in bm.targets if t["sources"]]
    mixed = (bool(bm.unresolved_targets) and bool(named)) or bool(bm.sensitive_calls)
    uncovered = sorted(set(uncovered))
    if not covered:
        level = "none"
    elif uncovered or mixed:
        level = "partial"
    else:
        level = "complete"
    return {"level": level, "uncovered": uncovered, "mixed": mixed, "systems": sorted(covered)}


def run_repo(ctx: RunContext, run: RunState, repo: str) -> PhaseResult:
    entry = _entry(ctx, repo)
    if entry.get("status") == "NOT ANALYZED" or not entry.get("head"):
        raise errors.RepoFailure("repository %s was not analysed in phase 1: %s" % (repo, entry.get("reason")))
    S = Session(ctx, run, repo, entry)
    S.queue_ignored = _queue_ignored(ctx, repo)
    inventory.collect(S)
    systems = inventory.detect_build_systems(S)

    # ---- pass 1: in-tree
    plan = vendored.plan(S, inventory.vendored_parent_children(S))
    vendored.create_dir_candidates(S, plan)
    vendored.create_single_files(S, plan)
    submodules.run(S, plan)
    byproducts.prebuilt(S)
    licenses.run(S)
    declared.run_in_tree(S)
    S.release_scripts = inventory.find_release_scripts(S)

    # ---- build files are parsed once; their evidence is produced in passes 2 and 3
    cmake.parse_all(S, systems["cmake"])
    cmake.parse_presets(S, systems["cmake"])
    meson.parse_all(S, systems["meson"])
    make.parse_all(S, systems["autotools"] + systems["make"])
    buildrefs.settle_targets(S)

    # ---- pass 2: manifests, lockfiles, fetch declarations, declared identifiers
    manifests.run(S)
    meson.run_wraps(S, systems["meson"])
    buildrefs.emit_fetch(S)
    declared.run_declared(S)

    # ---- pass 3: build references, by-products, runtime loading, includes
    buildrefs.emit_refs(S)
    cover = _coverage(S, systems)
    buildrefs.emit_unparsed(S, cover["uncovered"])
    byproducts.byproduct_lists(S)
    byproducts.linker_maps(S)
    byproducts.toolchain_flags(S)
    byproducts.dlopen(S)
    manifests.run_ci(S)
    includes.run(S)
    _finish_notes(S, cover)

    inventory.finalize_inventory(S, systems)
    return _write(S, cover)


def _finish_notes(S: Session, cover: Dict[str, Any]) -> None:
    """Blind spots and INCOMPLETE reasons."""
    for rec in list(S.reg.evidence.values()):
        if rec["type"] == "BUILD_FILE_UNPARSED":
            S.reg.blind("BUILD_FILE_UNPARSED", "build file %s is not parsed by this version" % rec["path"], rec["path"])
    for path in cover["uncovered"]:
        S.add_incomplete("build system not covered: %s" % path)
    if S.bm.unresolved_targets and cover["mixed"]:
        names = sorted({name for name, _p, _l in S.bm.unresolved_targets})
        S.add_incomplete("sources of CMake/Meson/Make target(s) not resolvable statically: %s" % ", ".join(names[:5]))
        for name, path, line in S.bm.unresolved_targets[:20]:
            S.bm.uncovered.append("%s:%d (sources of target %s not statically resolvable)" % (path, line, name))
    if S.bm.sensitive_calls:
        seen = sorted({(path, line, raw) for raw, path, line in S.bm.sensitive_calls})
        S.add_incomplete("build script call(s) not followed statically (user-defined function or computed path): %s"
                         % ", ".join("%s:%d" % (path, line) for path, line, _raw in seen[:5]))
        for path, line, raw in seen[:20]:
            S.bm.uncovered.append("%s:%d (%s is not followed statically)" % (path, line, raw.strip()[:60]))
    if cover["level"] in ("partial", "none"):
        what = {"none": "no covered build system was found", "partial": "some build files are not covered"}[cover["level"]]
        S.reg.blind("COVERAGE_PARTIAL", "build coverage is %s: %s" % (cover["level"], what),
                    (cover["uncovered"] or [None])[0])
    uninit = [m for m in S.submodules if (m.get("state") or "uninitialized") == "uninitialized" and m.get("path")]
    if uninit:
        names = ", ".join(m["path"] for m in uninit[:5]) + (", ..." if len(uninit) > 5 else "")
        S.add_incomplete("%d uninitialized submodule%s (%s)" % (len(uninit), "" if len(uninit) == 1 else "s", names))
    dirty = S.entry.get("dirty") or {}
    if dirty.get("unknown"):
        S.reg.blind("DIRTY_UNKNOWN", "%d tracked file(s) could not be compared with HEAD (filters, line-ending conversion "
                    "or size); they are analysed as they are on disk" % dirty["unknown"])
    S.inv.setdefault("ignored", []).extend(S.queue_ignored)
    S.inv["ignored"].extend({"path": folder, "reason": reason} for folder, reason in sorted(S.dropped_dirs.items()))
    for name, bucket in (("oversize", S.fs.oversize), ("unreadable", S.fs.unreadable)):
        for path in sorted(set(bucket))[:50]:
            S.inv.setdefault("ignored", []).append({"path": path, "reason": "file is %s for the 2 MiB text scan: not analysed"
                                                    % ("larger" if name == "oversize" else "unreadable")})


def _jsonl(records: List[Dict[str, Any]]) -> str:
    return "".join(fsio.dumps_compact(r) + "\n" for r in records)


def _write(S: Session, cover: Dict[str, Any]) -> PhaseResult:
    ctx = S.ctx
    candidates, blindspots, evidence = S.reg.finalize()
    base = ctx.layout.repo_out(S.repo)
    root = ctx.layout.out
    result = PhaseResult()
    S.inv.setdefault("ignored", [])
    unique = {(i["path"], i["reason"]): i for i in S.inv["ignored"]}
    S.inv["ignored"] = [unique[key] for key in sorted(unique)]
    buildmodel = S.bm.to_json(S.repo, cover["level"])
    buildmodel["systems"] = cover["systems"]
    buildmodel["uncovered"] = sorted(set(buildmodel["uncovered"]) | set(cover["uncovered"]))
    candidates_doc = {"schema": SCHEMA, "repo": S.repo, "candidates": candidates, "blindspots": blindspots}
    outputs = {
        "inventory.json": S.inv,
        "buildmodel.json": buildmodel,
        "candidates.json": candidates_doc,
    }
    for name, document in outputs.items():
        sha = fsio.atomic_write_json(base / name, document, root=root)
        result.outputs[ctx.layout.out_rel(base / name)] = sha
    sha = fsio.atomic_write_text(base / "evidence.jsonl", _jsonl(evidence), root=root)
    result.outputs[ctx.layout.out_rel(base / "evidence.jsonl")] = sha
    result.incomplete = list(S.incomplete)
    if cover["level"] == "partial":
        result.warnings.append(model.warning("INFORMATIONAL", "COVERAGE_PARTIAL",
                                             "build coverage of %s is partial: %s" % (
                                                 S.repo, "; ".join(S.incomplete[:3]) or "see buildmodel.json"), S.repo))
    return result
