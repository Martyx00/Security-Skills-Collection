"""Phase 9: the merged CSV across repositories (contract section 4.24).

``merged_table`` is the one place that derives merged rows. ``write`` feeds it from every DONE/INCOMPLETE repository's
``components.json`` (it never re-scans a repository); ``validate.merged_parity_errors`` feeds the same function from the
staged per-repository CSV files and compares the result cell by cell.

Identity: ``ids.merge_key(ids.fold_key(norm_name, version, upstream_commit), repo)``, so ``(norm_name, version)`` for a
release and ``(norm_name, "NOASSERTION", repo)`` for everything else: an unversioned component is never merged across
repositories.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Tuple

from sbomlib import csvio, errors, fsio, ids
from sbomlib.context import RunContext
from sbomlib.emit import licexpr
from sbomlib.model import PhaseResult
from sbomlib.norm import norm_library
from sbomlib.state import RunState

NOASSERTION = "NOASSERTION"
MERGED_HEADER = ("name", "version", "repositories", "repo_count", "cpe23", "purl", "usages", "locations",
                 "versions_seen_all_repos", "detected_as", "conflicts")
MERGE_REPO_STATUSES = ("DONE", "INCOMPLETE")


def split_cell(cell: str) -> List[str]:
    """Items of a ``;``-joined cell. A ``;`` preceded by an odd number of backslashes belongs to the item (CPE escapes)."""
    if not cell:
        return []
    items: List[str] = []
    current: List[str] = []
    backslashes = 0
    for ch in cell:
        if ch == ";" and backslashes % 2 == 0:
            items.append("".join(current))
            current = []
            backslashes = 0
            continue
        backslashes = backslashes + 1 if ch == "\\" else 0
        current.append(ch)
    items.append("".join(current))
    return [i.strip() for i in items if i.strip()]


def entry_from_component(repo: str, comp: Dict[str, Any]) -> Dict[str, Any]:
    return {"repo": repo, "name": comp["name"], "norm_name": comp.get("norm_name") or norm_library(comp["name"]),
            "version": comp.get("version") or NOASSERTION, "upstream_commit": comp.get("upstream_commit") or "",
            "cpe23": [c["cpe23"] for c in comp.get("cpes") or []], "purl": list(comp.get("purls") or []),
            "usage": list(comp.get("usage") or []), "locations": sorted(comp.get("locations") or []),
            "detected_as": list(comp.get("detected_as") or []), "license": comp.get("license_declared") or NOASSERTION}


def entry_from_csv_row(repo: str, row: Dict[str, str]) -> Dict[str, Any]:
    """An entry from an (unguarded) row of ``<repo>.sbom.csv``."""
    return {"repo": repo, "name": row["name"], "norm_name": norm_library(row["name"]),
            "version": row["version"] or NOASSERTION, "upstream_commit": row["upstream_commit"],
            "cpe23": split_cell(row["cpe23"]), "purl": split_cell(row["purl"]), "usage": split_cell(row["usage"]),
            "locations": split_cell(row["locations"]), "detected_as": split_cell(row["detected_as"]),
            "license": row["license_declared"] or NOASSERTION}


def entry_key(entry: Dict[str, Any]) -> Tuple[str, ...]:
    fold = ids.fold_key(entry["norm_name"], entry["version"], entry.get("upstream_commit") or None)
    return ids.merge_key(fold, entry["repo"])


def _most_common(names: Sequence[str]) -> str:
    counts: Dict[str, int] = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    return sorted(counts, key=lambda n: (-counts[n], n))[0]


def _union_ordered(lists: Iterable[Sequence[str]]) -> List[str]:
    seen = set()
    out: List[str] = []
    for items in lists:
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
    return out


def merged_table(entries: Iterable[Dict[str, Any]]) -> Tuple[List[str], List[List[str]]]:
    """Header and rows of ``merged-sbom.csv`` for the entries of every contributing repository."""
    groups: Dict[Tuple[str, ...], List[Dict[str, Any]]] = {}
    versions_of: Dict[str, set] = {}
    for entry in entries:
        groups.setdefault(entry_key(entry), []).append(entry)
        versions_of.setdefault(entry["norm_name"], set()).add(entry["version"])
    rows: List[Tuple[Tuple[str, str, str], List[str]]] = []
    for key in groups:
        members = sorted(groups[key], key=lambda e: e["repo"])
        repos = sorted({e["repo"] for e in members})
        cpes = _union_ordered(e["cpe23"] for e in members)
        purls = sorted({p for e in members for p in e["purl"]})
        usages = sorted({u for e in members for u in e["usage"]})
        locations = [("%s:%s" % (e["repo"], loc)) for e in members for loc in e["locations"]]
        detected = sorted({d for e in members for d in e["detected_as"]})
        conflicts = []
        if len({frozenset(e["cpe23"]) for e in members}) > 1:
            conflicts.append("cpe23")
        if len({frozenset(e["purl"]) for e in members}) > 1:
            conflicts.append("purl")
        asserted = {licexpr.normalize_for_comparison(e["license"]) for e in members if e["license"] != NOASSERTION}
        if len(asserted) > 1:
            conflicts.append("license")
        norm_name = members[0]["norm_name"]
        version = members[0]["version"]
        repositories = ";".join(repos)
        rows.append(((norm_name, version, repositories), [
            _most_common([e["name"] for e in members]), version, repositories, str(len(repos)), ";".join(cpes),
            ";".join(purls), ";".join(usages), ";".join(locations), ";".join(sorted(versions_of[norm_name])),
            ";".join(detected), ";".join(conflicts)]))
    rows.sort(key=lambda item: item[0])
    return (list(MERGED_HEADER), [r for _k, r in rows])


def contributing_repos(run: RunState) -> List[str]:
    """DONE and INCOMPLETE repositories in queue order (FAILED and NOT ANALYZED ones contribute nothing)."""
    return [r for r in run.all_repos() if run.repo(r).get("status") in MERGE_REPO_STATUSES]


def staged_path(ctx: RunContext, run: RunState) -> Any:
    return ctx.layout.staging(run.run_id) / "merged-sbom.csv"


def write(ctx: RunContext, run: RunState) -> PhaseResult:
    """Unit ``merge``: the staged ``merged-sbom.csv`` from every contributing repository's ``components.json``."""
    entries: List[Dict[str, Any]] = []
    for repo in contributing_repos(run):
        path = ctx.layout.repo_out(repo) / "components.json"
        try:
            doc = fsio.read_json(path)
        except FileNotFoundError as exc:
            raise errors.StateError("repos/%s/components.json is missing; run the emit unit of %s first" % (repo, repo),
                                    repo=repo) from exc
        if not isinstance(doc, dict) or doc.get("schema") != 1:
            raise errors.StateError("repos/%s/components.json is not a components document" % repo, repo=repo)
        for comp in doc.get("components") or []:
            entries.append(entry_from_component(repo, comp))
    header, rows = merged_table(entries)
    path = staged_path(ctx, run)
    fsio.ensure_dir(path.parent, root=ctx.layout.out)
    sha = csvio.write_csv(path, header, rows, root=ctx.layout.out)
    result = PhaseResult()
    result.outputs[ctx.layout.out_rel(path)] = sha
    return result
