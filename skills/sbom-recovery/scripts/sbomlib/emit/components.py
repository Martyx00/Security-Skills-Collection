"""``repos/<repo>/components.json``: the format-neutral intermediate of phase 8 (contract sections 3.12 and 4.19).

The builder folds the review-eligible candidates of a repository into components (D12), decides which of them the
approved review file includes (D19), attaches CPEs and purls from the approved rows and the staged resolution, and records
everything that is not in the SBOM under ``excluded``. Both CSV files and the SPDX document derive from the result.

Beyond the keys of section 4.19, every component also carries ``evidence_ids`` (all evidence records of its candidates),
``version_evidence_ids`` (the records behind its version, re-checked by ``validate.version_evidence_errors``) and
``candidate_info`` (per candidate: the fields of ``candidates_audit.csv``). Consumers ignore keys they do not know.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from sbomlib import errors, fsio, ids, model, urls
from sbomlib.context import RunContext
from sbomlib.emit.csvout import plain
from sbomlib.model import PhaseResult
from sbomlib.norm import norm_library
from sbomlib.state import RunState

SCHEMA = 1
MAX_LOCATIONS = 50
MAX_INCLUDE_SITES = 5
NOASSERTION = "NOASSERTION"

# Evidence types whose location identifies, declares or builds a component (contract section 4.19), in the order that also
# breaks ties between two records at the same location and decides the detection method (section 4.9).
IDENTITY_TYPES = ("VERSION_MACRO", "BANNER", "PROJECT_VERSION", "VERSION_FILE", "GIT_DESCRIBE", "GITLINK", "LOCK_PIN",
                  "FETCH_PIN", "MANIFEST_DECL", "DECLARED_ID", "PREBUILT", "FIND_PACKAGE", "FILE_PRESENT",
                  "TOOLCHAIN_RUNTIME", "WORKER_CLAIM")
LOCATION_TYPES = ("FILE_PRESENT", "VERSION_MACRO", "BANNER", "PROJECT_VERSION", "VERSION_FILE", "GITLINK", "LOCK_PIN",
                  "FETCH_PIN", "MANIFEST_DECL", "FIND_PACKAGE", "LINK_REF", "SUBDIR_BUILD", "PREBUILT", "DECLARED_ID",
                  "DLOPEN", "TOOLCHAIN_RUNTIME", "WORKER_CLAIM")
IN_TREE = ("vendored", "single_file", "submodule", "prebuilt")
STRENGTH_RANK = {"strong": 3, "medium": 2, "weak": 1}
VERIFICATION_RANK = {"proven": 3, "declared": 2, "unresolved": 1}
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}
ROLE_ORDER = ("primary", "also_emit", "cve_only", "override", "extra")
REVERSED_RELATIONSHIPS = ("RUNTIME_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF",
                          "BUILD_TOOL_OF", "TEST_TOOL_OF")
FALLBACK_REASON = {"TEST_ONLY": "TEST_ONLY", "BUILD_ONLY": "BUILD_ONLY", "DEV_ONLY": "DEV_ONLY",
                   "OPTIONAL": "CONDITIONAL_DISABLED", "UNUSED_DEAD_COPY": "PRESENT_NOT_BUILT",
                   "FIRST_PARTY": "FIRST_PARTY", "UNANALYZED": "UNINITIALIZED_SUBMODULE"}
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_ACTOR_RE = re.compile(r"(Tool|Organization|Person): \S.*")


# ---------------------------------------------------------------------------------------------------- small helpers

def scrub(value: Any) -> Any:
    """Replace lone surrogates (undecodable on-disk names) by U+FFFD in every string of a JSON-like value."""
    if isinstance(value, str):
        return _SURROGATE_RE.sub("�", value) if _SURROGATE_RE.search(value) else value
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {scrub(k) if isinstance(k, str) else k: scrub(v) for k, v in value.items()}
    return value


def _verify() -> Any:
    from sbomlib import verify
    return verify


def _cpe() -> Any:
    from sbomlib import cpe
    return cpe


def _render_condition(condition: Optional[Dict[str, Any]]) -> str:
    from sbomlib.verify.configs import render_condition
    return render_condition(condition)


def load_evidence(ctx: RunContext, repo: str) -> Dict[str, Dict[str, Any]]:
    """The evidence universe of a repository: discover's ``evidence.jsonl``, verify's ``verify_evidence.jsonl`` and the worker
    role's ``worker_evidence.jsonl`` by id."""
    base = ctx.layout.repo_out(repo)
    records: Dict[str, Dict[str, Any]] = {}
    for name in ("evidence.jsonl", "verify_evidence.jsonl", "worker_evidence.jsonl"):
        path = base / name
        if os.path.lexists(str(path)):
            for rec in fsio.read_jsonl(path):
                if isinstance(rec, dict) and rec.get("id"):
                    records[str(rec["id"])] = rec
    return records


def _read_json(path: Any) -> Any:
    try:
        return fsio.read_json(path)
    except FileNotFoundError:
        return None


def location_string(rec: Dict[str, Any], cand: Optional[Dict[str, Any]]) -> Optional[str]:
    """``path:line``, ``path`` when there is no line, ``path/`` for the directory of a ``FILE_PRESENT`` record."""
    path = rec.get("path")
    if not path or not isinstance(path, str):
        return None
    if rec.get("type") == "FILE_PRESENT":
        kind = ((cand or {}).get("location") or {}).get("kind")
        return path.rstrip("/") + "/" if kind == "dir" else path
    line = rec.get("line")
    if isinstance(line, int) and not isinstance(line, bool) and line > 0:
        return "%s:%d" % (path, line)
    return path


def locations_of(records: Iterable[Dict[str, Any]], cands: Dict[str, Dict[str, Any]]
                 ) -> Tuple[List[str], List[Dict[str, Any]], int]:
    """``(locations, occurrences, omitted)`` of a set of evidence records (section 4.19).

    ``locations`` are the sorted unique location strings of the identity, declaration and build records plus at most five
    ``INCLUDE`` sites, capped at 50; ``occurrences`` has one entry per location (the best record at that location).
    """
    order = {t: i for i, t in enumerate(LOCATION_TYPES)}
    best: Dict[str, Tuple[Tuple[int, str], Dict[str, Any]]] = {}
    includes: Dict[str, Tuple[Tuple[int, str, int, str], Dict[str, Any]]] = {}
    for rec in records:
        etype = rec.get("type")
        loc = location_string(rec, cands.get(rec.get("candidate") or ""))
        if loc is None:
            continue
        if etype in order:
            key = (order[etype], str(rec.get("id")))
            if loc not in best or key < best[loc][0]:
                best[loc] = (key, rec)
        elif etype == "INCLUDE":
            line = rec.get("line") if isinstance(rec.get("line"), int) else 0
            key2 = (0 if rec.get("scope", "product") == "product" else 1, str(rec.get("path")), line, str(rec.get("id")))
            if loc not in includes or key2 < includes[loc][0]:
                includes[loc] = (key2, rec)
    chosen_includes = sorted(includes.items(), key=lambda it: it[1][0])[:MAX_INCLUDE_SITES]
    base = sorted(best)
    omitted = 0
    room = MAX_LOCATIONS - len(chosen_includes)
    if len(base) > room:
        omitted = len(base) - room
        base = base[:room]
    selected: Dict[str, Dict[str, Any]] = {loc: best[loc][1] for loc in base}
    for loc, (_key, rec) in chosen_includes:
        selected.setdefault(loc, rec)
    locations = sorted(selected)
    occurrences = []
    for loc in locations:
        rec = selected[loc]
        occurrences.append({"path": rec.get("path"), "line": rec.get("line"), "symbol": rec.get("symbol"),
                            "evidence_type": rec.get("type"), "technique": rec.get("technique"),
                            "evidence_id": rec.get("id")})
    return locations, occurrences, omitted


def detection_method(records: Iterable[Dict[str, Any]]) -> str:
    """The technique of the strongest identity record; ties broken by the order of ``IDENTITY_TYPES``."""
    order = {t: i for i, t in enumerate(IDENTITY_TYPES)}
    best: Optional[Tuple[Tuple[int, int, str], Dict[str, Any]]] = None
    for rec in records:
        if rec.get("type") not in order:
            continue
        key = (-STRENGTH_RANK.get(str(rec.get("strength")), 0), order[rec["type"]], str(rec.get("id")))
        if best is None or key < best[0]:
            best = (key, rec)
    return str(best[1].get("technique") or "other") if best else "other"


def relationship_tokens(cls: str, usage: Sequence[str], detected_as: Sequence[str], tool: bool) -> List[str]:
    """The relationships of a component to the root, as SPDX relationship types (section 4.21). Types in
    ``REVERSED_RELATIONSHIPS`` point from the component to the root; the others from the root to the component."""
    tokens: Set[str] = set()
    if cls == "TEST_ONLY":
        tokens.add("TEST_TOOL_OF" if tool else "TEST_DEPENDENCY_OF")
    elif cls == "DEV_ONLY":
        tokens.add("DEV_DEPENDENCY_OF")
    elif cls == "BUILD_ONLY":
        tokens.add("BUILD_TOOL_OF" if tool else "BUILD_DEPENDENCY_OF")
    else:
        tokens.add("DEPENDS_ON")
        if "static" in usage:
            tokens.add("STATIC_LINK")
        if "dynamic" in usage:
            tokens.add("DYNAMIC_LINK")
        if "runtime_loaded" in usage:
            tokens.add("RUNTIME_DEPENDENCY_OF")
    if any(d in IN_TREE for d in detected_as):
        tokens.add("CONTAINS")
    return sorted(tokens)


def _actor(text: Optional[str]) -> str:
    """``NOASSERTION`` or an SPDX actor (``Organization: name``)."""
    value = " ".join(str(text or "").split())
    if not value or value == NOASSERTION:
        return NOASSERTION
    if _ACTOR_RE.fullmatch(value):
        return value
    return "Organization: " + value


def _ordered_notes(*groups: Iterable[Any]) -> List[str]:
    """Notes of the groups in order, each group sorted, duplicates dropped; the verdict's ``model: ...`` rationale comes
    first because the groups are passed verdict first."""
    out: List[str] = []
    for group in groups:
        for text in sorted({" ".join(str(n).split()) for n in group if n}):
            if text not in out:
                out.append(text)
    return out


def _best(values: Iterable[str], rank: Dict[str, int]) -> str:
    items = list(values)
    return max(items, key=lambda v: rank.get(v, 0)) if items else "none"


def _most_common(names: Sequence[str]) -> str:
    counts: Dict[str, int] = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    return sorted(counts, key=lambda n: (-counts[n], n))[0]


def _source_info(entry: Dict[str, Any]) -> str:
    dirty = entry.get("dirty") or {}
    modified, deleted, unknown = (int(dirty.get(k) or 0) for k in ("modified", "deleted", "unknown"))
    if modified or deleted or unknown:
        tree = "working tree with %d modified, %d deleted and %d unverifiable tracked file(s)" % (modified, deleted, unknown)
    else:
        tree = "clean working tree"
    untracked = int((entry.get("untracked") or {}).get("count") or 0)
    return "%s; %d untracked file%s; describes HEAD plus checked-out submodules" % (
        tree, untracked, "" if untracked == 1 else "s")


# ---------------------------------------------------------------------------------------------------- the builder

class _Member:
    """One candidate of the repository with its verdict, identity and version."""

    def __init__(self, cand: Dict[str, Any], verdict: Dict[str, Any], identity: str, version: Dict[str, Any]) -> None:
        self.cand = cand
        self.cid = str(cand["id"])
        self.verdict = verdict
        self.identity = identity
        self.version = version
        commit = (cand.get("upstream") or {}).get("commit")
        self.commit = str(commit) if commit else None
        text = str(version.get("version") or NOASSERTION)
        self.fold = ids.fold_key(norm_library(identity), text, self.commit)


def _member_rank(member: _Member) -> Tuple[int, int, str]:
    verification = member.verdict.get("verification")
    return (-VERIFICATION_RANK.get(str(verification), 0), 0 if member.verdict.get("class") == "USED" else 1, member.cid)


def _exclusion_reason(verdict: Dict[str, Any], row: Optional[Dict[str, Any]], repo: str) -> str:
    """The ``reason_code`` of a candidate that is not in the SBOM (section 4.23)."""
    base = verdict.get("reason_code")
    cls = str(verdict.get("class") or "")
    if row is not None:
        if (row.get("verification") or {}).get(repo) == "proven":
            return "HUMAN_EXCLUDED"
        if not base or str(base).startswith("REVIEW_"):
            return "NOT_VERIFIED"
        return str(base)
    if base:
        return str(base)
    return FALLBACK_REASON.get(cls, "NOT_VERIFIED")


def _candidate_info(cand: Dict[str, Any], member: Optional[_Member], records: List[Dict[str, Any]],
                    cands: Dict[str, Dict[str, Any]], verification: Optional[str]) -> Dict[str, Any]:
    locs, _occ, _omitted = locations_of(records, cands)
    verdict = member.verdict if member else {}
    notes = _ordered_notes(verdict.get("notes") or [], cand.get("notes") or [])
    return {"evidence_ids": sorted({str(r["id"]) for r in records}), "locations": locs,
            "class": verdict.get("class") or "INCONCLUSIVE", "usage_level": verdict.get("usage_level") or "none",
            "scope": verdict.get("scope") or "product", "reason_code": verdict.get("reason_code"),
            "verification": verification, "condition": verdict.get("condition"), "notes": notes}


def _records_of(cids: Iterable[str], cands: Dict[str, Dict[str, Any]], verdicts: Dict[str, Dict[str, Any]],
                universe: Dict[str, Dict[str, Any]], by_candidate: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for cid in cids:
        for rec in by_candidate.get(cid, []):
            seen[str(rec["id"])] = rec
        for source in ((cands.get(cid) or {}).get("evidence_ids") or [], (verdicts.get(cid) or {}).get("evidence_ids") or []):
            for eid in source:
                if eid in universe:
                    seen[str(eid)] = universe[eid]
    return [seen[k] for k in sorted(seen)]


def _gitlink_accounting(inventory: Dict[str, Any], cands: Dict[str, Dict[str, Any]], component_of: Dict[str, str]
                        ) -> List[Dict[str, Any]]:
    out = []
    for link in sorted(inventory.get("gitlinks") or [], key=lambda g: str(g.get("path"))):
        path = link.get("path")
        owners = sorted(cid for cid, cand in cands.items()
                        if ((cand.get("location") or {}).get("kind") == "gitlink" and (cand.get("location") or {}).get("path") == path)
                        or (cand.get("submodule") or {}).get("path") == path)
        accounted: Optional[str] = None
        for cid in owners:
            if cid in component_of:
                accounted = component_of[cid]
                break
        if accounted is None and owners:
            accounted = "excluded:" + owners[0]
        out.append({"path": path, "state": link.get("state"), "accounted_by": accounted})
    return out


def build(ctx: RunContext, run: RunState, repo: str) -> Dict[str, Any]:
    """The ``components.json`` document of one repository (not written)."""
    verify, cpe = _verify(), _cpe()
    layout = ctx.layout
    base = layout.repo_out(repo)
    cand_doc = fsio.read_json(base / "candidates.json")
    cands: Dict[str, Dict[str, Any]] = {str(c["id"]): c for c in cand_doc.get("candidates") or []}
    verdicts: Dict[str, Dict[str, Any]] = {str(v["candidate"]): v for v in verify.final_verdicts(ctx, repo)}
    universe = load_evidence(ctx, repo)
    by_candidate: Dict[str, List[Dict[str, Any]]] = {}
    for rec in universe.values():
        if rec.get("candidate"):
            by_candidate.setdefault(str(rec["candidate"]), []).append(rec)
    rows = cpe.approved_rows(ctx, run)
    row_of = cpe.row_for_candidate(ctx)
    resolution = cpe.load_resolution(ctx, run)
    inventory = _read_json(base / "inventory.json") or {}
    queue_entry = _queue_entry(ctx, repo)

    members: Dict[str, _Member] = {}
    for cid in sorted(cands):
        cand = cands[cid]
        verdict = verdicts.get(cid) or {}
        members[cid] = _Member(cand, verdict, str(verify.chosen_identity(cand, verdict)), verify.chosen_version(cand, verdict))

    # ---- group the review-eligible candidates by fold key (D12); everything else is excluded
    groups: Dict[Tuple[str, ...], List[_Member]] = {}
    for cid, member in members.items():
        row_id = row_of.get((repo, cid))
        if row_id is not None and row_id in rows:
            groups.setdefault(member.fold, []).append(member)

    components: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    component_of: Dict[str, str] = {}
    included_cids: Set[str] = set()
    excluded_cids: Set[str] = set()
    for fold in sorted(groups):
        group = sorted(groups[fold], key=_member_rank)
        row_ids = {row_of[(repo, m.cid)] for m in group}
        if len(row_ids) != 1:
            raise errors.StateError("candidates %s of %s fold to one component but belong to review rows %s"
                                    % (", ".join(m.cid for m in group), repo, ", ".join(sorted(row_ids))), repo=repo)
        row = rows[next(iter(row_ids))]
        expected = ids.review_key(fold, repo)
        if tuple(row.get("key") or ()) != expected:
            raise errors.StateError("review row %s has key %r but the component of %s folds to %r"
                                    % (row["id"], tuple(row.get("key") or ()), repo, expected), repo=repo, row=row["id"])
        if repo not in cpe.included_repos(row):
            for m in group:
                excluded.append(_excluded_entry(m, _exclusion_reason(m.verdict, row, repo), universe, by_candidate, cands,
                                                verdicts))
                excluded_cids.add(m.cid)
            continue
        comp = _component(ctx, repo, group, row, resolution.get(row["id"]) or {}, universe, by_candidate, cands, verdicts)
        components.append(comp)
        for m in group:
            component_of[m.cid] = comp["spdx_id"]
            included_cids.add(m.cid)
    for cid, member in members.items():
        if cid in included_cids or cid in excluded_cids:
            continue
        row = rows.get(row_of.get((repo, cid), ""))
        excluded.append(_excluded_entry(member, _exclusion_reason(member.verdict, row, repo), universe, by_candidate, cands,
                                        verdicts))
    components.sort(key=lambda c: (c["norm_name"], c["version"], c["spdx_id"]))
    excluded.sort(key=lambda e: (e["name"], e["version"], e["candidate_id"]))

    ignored: Dict[Tuple[str, str], Dict[str, str]] = {}
    for item in list(inventory.get("ignored") or []) + state_ignored(ctx, repo):
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            ignored[(item["path"], str(item.get("reason") or ""))] = {"path": item["path"], "reason": str(item.get("reason") or "")}
    head = run.repo(repo).get("head") or queue_entry.get("head")
    origin = urls.scrub_url(queue_entry.get("origin")) if queue_entry.get("origin") else None
    repo_entry = run.repo(repo)
    doc: Dict[str, Any] = {
        "schema": SCHEMA, "repo": repo, "run_id": run.run_id, "status": repo_entry.get("status"),
        "root": {"name": repo, "spdx_id": ids.spdx_id("root", repo, ""), "head": head,
                 "describe": queue_entry.get("describe"), "branch": queue_entry.get("branch"), "origin": origin,
                 "download_location": urls.spdx_download_location(origin, head), "source_info": _source_info(queue_entry)},
        "analysis_mode": run.data.get("analysis_mode") or "static",
        "analysis_mode_reason": run.data.get("analysis_mode_reason") or model.ANALYSIS_MODE_REASON,
        "scope": run.data.get("scope") or ctx.scope or "product",
        "components": components, "excluded": excluded,
        "ignored": [ignored[k] for k in sorted(ignored)],
        "blindspots": verify.blindspots(ctx, repo),
        "gitlinks": _gitlink_accounting(inventory, cands, component_of),
    }
    return scrub(doc)


def state_ignored(ctx: RunContext, repo: str) -> List[Dict[str, str]]:
    """The IGNORED items phase 1 recorded for ``repo`` (a safety net: discovery copies them into the inventory)."""
    from sbomlib import state
    items = []
    for item in state.load_queue(ctx).get("ignored") or []:
        if item.get("repo") == repo and isinstance(item.get("path"), str):
            items.append({"path": item["path"], "reason": str(item.get("reason") or "")})
    return items


def _queue_entry(ctx: RunContext, repo: str) -> Dict[str, Any]:
    from sbomlib import state
    for entry in state.load_queue(ctx).get("repos") or []:
        if entry.get("name") == repo:
            return entry
    return {}


def _excluded_entry(member: _Member, reason: str, universe: Dict[str, Dict[str, Any]],
                    by_candidate: Dict[str, List[Dict[str, Any]]], cands: Dict[str, Dict[str, Any]],
                    verdicts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    records = _records_of([member.cid], cands, verdicts, universe, by_candidate)
    locs, _occ, _omitted = locations_of(records, cands)
    verdict = member.verdict
    version = member.version.get("version") if member.version.get("version_kind") == "release" else NOASSERTION
    notes = _ordered_notes(verdict.get("notes") or [], member.cand.get("notes") or [])
    return {"candidate_id": member.cid, "name": plain(member.identity) or NOASSERTION, "version": str(version or NOASSERTION),
            "class": verdict.get("class") or "INCONCLUSIVE", "usage_level": verdict.get("usage_level") or "none",
            "scope": verdict.get("scope") or "product", "reason_code": reason, "condition": verdict.get("condition"),
            "verification": verdict.get("verification"), "detected_as": [member.cand.get("detected_as")],
            "locations": locs, "evidence_ids": sorted({str(r["id"]) for r in records}), "in_sbom": False, "notes": notes}


def _component(ctx: RunContext, repo: str, group: List[_Member], row: Dict[str, Any], resolved: Dict[str, Any],
               universe: Dict[str, Dict[str, Any]], by_candidate: Dict[str, List[Dict[str, Any]]],
               cands: Dict[str, Dict[str, Any]], verdicts: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    primary = group[0]
    cids = sorted(m.cid for m in group)
    verdict = primary.verdict
    name = _most_common([m.identity for m in group]) if len({m.identity for m in group}) > 1 else primary.identity
    name = plain(name) or NOASSERTION                     # one line, so that the CSV cell and the SPDX name agree
    option = primary.version
    kind = str(option.get("version_kind") or "none")
    raw_version = str(option.get("version") or NOASSERTION)
    version = raw_version if kind == "release" and raw_version != NOASSERTION else NOASSERTION
    commit = next((m.commit for m in sorted(group, key=lambda m: m.cid) if m.commit), None)
    # D12: components of one fold have the same (norm_name, version[, commit]); the SBOM keys come from the fold
    norm_name = norm_library(name)
    spdx_id = ids.spdx_id("package", name, version, (commit or "") if version == NOASSERTION else "")
    records = _records_of(cids, cands, verdicts, universe, by_candidate)
    locations, occurrences, omitted = locations_of(records, cands)
    usage = sorted({u for m in group for u in (m.verdict.get("usage") or []) if u in model.USAGE_VALUES})
    detected = sorted({str(m.cand.get("detected_as")) for m in group})
    cls = str(verdict.get("class") or "USED")
    verification = (row.get("verification") or {}).get(repo) or verdict.get("verification") or "declared"
    tool = bool(verdict.get("tool"))
    emitted = sorted(resolved.get("emitted") or [],
                     key=lambda e: (ROLE_ORDER.index(e["role"]) if e.get("role") in ROLE_ORDER else len(ROLE_ORDER),
                                    str(e.get("cpe23"))))
    cpes = [{"cpe23": e["cpe23"], "role": e.get("role"), "pair_source": e.get("pair_source"),
             "cpe_name_source": e.get("cpe_name_source"), "cpe_name_id": e.get("cpe_name_id") or None,
             "wildcard": bool(e.get("wildcard"))} for e in emitted]
    flags = list(resolved.get("flags") or [])
    notes: List[str] = []

    def note(text: Any) -> None:
        text = " ".join(str(text).split())
        if text and text not in notes:
            notes.append(text)

    condition = verdict.get("condition")
    if condition:
        note("platform-conditional: %s" % condition)
    for text in option.get("notes") or []:
        note(text)
    if kind != "release" and option.get("version_raw"):
        note("version %s (%s) is not a normalized release" % (option.get("version_raw"), kind))
    elif kind == "release" and version == NOASSERTION:
        note("version %s was not written: no normalized release" % raw_version)
    for m in sorted(group, key=lambda m: m.cid):
        for text in sorted(m.cand.get("notes") or []):
            note(text)
        for text in m.verdict.get("notes") or []:
            note(text)
    if "deprecated_name" in flags:
        note("an emitted CPE name is deprecated in the NVD dictionary")
    if "version_not_in_dictionary" in flags:
        note("the NVD dictionary has no CPE name for this version")
    if "nvd_offline" in flags:
        note("CPE names were constructed offline and not checked against the NVD dictionary")
    if omitted:
        note("%d further location(s) omitted; see the evidence file" % omitted)
    licence_ids = sorted({str((m.cand.get("license") or {}).get("id") or NOASSERTION) for m in group} - {NOASSERTION})
    if len(licence_ids) > 1:
        note("candidates disagree on the licence (%s); NOASSERTION used" % ", ".join(licence_ids))
        licence = NOASSERTION
    else:
        licence = licence_ids[0] if licence_ids else NOASSERTION
    licence = _checked_licence(ctx, licence, note)
    licence_loc = None
    for m in sorted(group, key=lambda m: m.cid):
        loc = (m.cand.get("license") or {}).get("loc")
        if loc and str((m.cand.get("license") or {}).get("id") or NOASSERTION) == licence:
            licence_loc = loc
            break
    info: Dict[str, Any] = {}
    for m in group:
        member_records = _records_of([m.cid], cands, verdicts, universe, by_candidate)
        info[m.cid] = _candidate_info(m.cand, m, member_records, cands, m.verdict.get("verification") or verification)
    upstream_url = str(row.get("upstream_url") or "") or None
    comp: Dict[str, Any] = {
        "spdx_id": spdx_id, "name": name, "norm_name": norm_name, "version": version,
        "version_raw": option.get("version_raw"), "version_kind": kind,
        "version_source": option.get("version_source") or "none",
        "identity_confidence": _best((m.cand.get("identity_confidence") or "none" for m in group), CONFIDENCE_RANK),
        "version_confidence": _best((m.cand.get("version_confidence") or "none" for m in group), CONFIDENCE_RANK),
        "class": cls, "verification": verification, "usage": usage, "usage_level": verdict.get("usage_level") or "none",
        "scope": verdict.get("scope") or "product",
        "configs": sorted({c for m in group for c in (m.verdict.get("configs") or [])}),
        "artifacts": sorted({a for m in group for a in (m.verdict.get("artifacts") or [])}),
        "condition": condition or None,
        "detected_as": detected, "detection_method": detection_method(records),
        "evidence_types": sorted({str(r.get("type")) for r in records}),
        "locations": locations, "occurrences": occurrences,
        "cpes": cpes, "cpe_alternates": sorted(resolved.get("alternates") or []),
        "purls": [str(row["purl"])] if row.get("purl") else [], "upstream_url": upstream_url, "upstream_commit": commit,
        "sha256": next((m.cand.get("sha256") for m in sorted(group, key=lambda m: m.cid) if m.cand.get("sha256")), None),
        "supplier": _actor(next((m.cand.get("supplier") for m in sorted(group, key=lambda m: m.cid)
                                 if m.cand.get("supplier")), None)),
        "license_declared": licence, "license_loc": licence_loc,
        "relationships": relationship_tokens(cls, usage, detected, tool),
        "review_row_id": row["id"], "candidate_ids": cids, "files_analyzed": False, "notes": notes,
        "evidence_ids": sorted({str(r["id"]) for r in records}),
        "version_evidence_ids": sorted(str(e) for e in (option.get("evidence_ids") or [])),
        "candidate_info": info,
    }
    return comp


def _checked_licence(ctx: RunContext, licence: str, note: Any) -> str:
    """The licence expression when it is valid SPDX, else NOASSERTION with a note."""
    if licence == NOASSERTION:
        return licence
    from sbomlib.emit import licexpr
    try:
        valid = licexpr.is_valid_expression(licence, ctx.asset("spdx-licenses.json"))
    except errors.SbomError:
        valid = True                      # the list is unreadable: validation will report it; do not drop the value here
    if valid:
        return licence
    note("licence %r is not a valid SPDX expression; NOASSERTION used" % licence)
    return NOASSERTION


def build_components(ctx: RunContext, run: RunState, repo: str) -> PhaseResult:
    """Unit ``emit:<repo>``, first half: write ``repos/<repo>/components.json``."""
    document = build(ctx, run, repo)
    path = ctx.layout.repo_out(repo) / "components.json"
    sha = fsio.atomic_write_json(path, document, root=ctx.layout.out)
    result = PhaseResult()
    result.outputs[ctx.layout.out_rel(path)] = sha
    return result
