"""What changed since the baseline, per repository (TASKLIST 3.7, incremental runs).

The Vibe pipeline had its worker write a "changes file" by hand (CONFIRMED, UPDATED, CORRECTED, RENAMED, REMOVED, NEW, plus a
SUMMARY line the merge checked). Nothing here is hand-written: the delta is computed from two documents the script wrote,
``components.json`` of this run and of the baseline, and from the paths git reports as changed between the two commits
(``baseline.changes``).

* ``NEW``       the component is in this run and not in the baseline;
* ``REMOVED``   the component was in the baseline and is not in this run;
* ``UPDATED``   the name is in both with another version (one version replaced one version);
* nothing is listed for a component that is the same in both (``unchanged`` counts it).

The cause column replaces the CORRECTED and RENAMED classes of the old pipeline. ``code`` means a file the component's
locations lie in changed between the two commits; ``analysis`` means none did (or the commit is the same): the difference is
a result of the analysis, not of the code, for example a better version rule or a worker claim that is new; ``unverified``
means git could not say what changed (the baseline commit is not in the local history). Only ``code`` is a change of the
product.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from sbomlib import baseline, fsio
from sbomlib.context import RunContext
from sbomlib.state import RunState

SCHEMA = 1
HEADER = ("change", "name", "version", "baseline_version", "cause", "locations")
CHANGES = ("NEW", "REMOVED", "UPDATED")
CAUSES = ("code", "analysis", "unverified")
NOASSERTION = "NOASSERTION"
MAX_LISTED = 200


def _path_of(location: str) -> str:
    """``path`` of ``path``, ``path:line`` or ``path/``."""
    text = str(location)
    head, sep, tail = text.rpartition(":")
    if sep and tail.isdigit():
        text = head
    return text.rstrip("/")


def _touched(locations: Sequence[str], changed: Set[str]) -> bool:
    """A location is touched by a changed path that is the location, lies below it (a folder location), or contains it (a
    submodule whose pinned commit changed shows as the one path of the submodule)."""
    for location in locations:
        path = _path_of(location)
        if not path:
            continue
        if path in changed:
            return True
        prefix = path + "/"
        if any(item.startswith(prefix) or path.startswith(item.rstrip("/") + "/") for item in changed):
            return True
    return False


def _cause(status: str, changed: Set[str], locations: Sequence[str]) -> str:
    if status == "unchanged":
        return "analysis"
    if status == "listed":
        return "code" if _touched(locations, changed) else "analysis"
    return "unverified"


def _versions(items: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    by_name: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for item in items:
        by_name.setdefault(str(item.get("norm_name") or item["name"]).lower(), {})[str(item.get("version") or NOASSERTION)] = item
    return by_name


def compute(ctx: RunContext, run: RunState, repo: str, components: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The delta document of ``repo`` against the baseline, or None when there is no baseline for this repository (a first
    run, a repository the baseline did not analyse, a baseline without a components document)."""
    before = baseline.components_of(ctx, repo)
    if before is None or baseline.commit_of(ctx, run, repo) is None:
        return None
    changes = baseline.changes(ctx, run, repo)
    changed = set(changes.get("files") or [])
    status = str(changes.get("status"))
    now = [{"name": c["name"], "version": c.get("version") or NOASSERTION, "norm_name": c.get("norm_name") or str(c["name"]).lower(),
            "locations": list(c.get("locations") or [])} for c in components.get("components") or []]
    old_by, new_by = _versions(before), _versions(now)
    entries: List[Dict[str, Any]] = []
    unchanged = 0
    for key in sorted(set(old_by) | set(new_by)):
        old, new = old_by.get(key, {}), new_by.get(key, {})
        gone = sorted(set(old) - set(new))
        added = sorted(set(new) - set(old))
        unchanged += len(set(old) & set(new))
        if len(gone) == 1 and len(added) == 1:
            item, previous = new[added[0]], old[gone[0]]
            entries.append({"change": "UPDATED", "name": item["name"], "version": added[0], "baseline_version": gone[0],
                            "cause": _cause(status, changed, list(item["locations"]) + list(previous["locations"])),
                            "locations": list(item["locations"])})
            continue
        for version in gone:
            item = old[version]
            entries.append({"change": "REMOVED", "name": item["name"], "version": version, "baseline_version": version,
                            "cause": _cause(status, changed, item["locations"]), "locations": list(item["locations"])})
        for version in added:
            item = new[version]
            entries.append({"change": "NEW", "name": item["name"], "version": version, "baseline_version": "",
                            "cause": _cause(status, changed, item["locations"]), "locations": list(item["locations"])})
    order = {name: i for i, name in enumerate(CHANGES)}
    entries.sort(key=lambda e: (order[e["change"]], str(e["name"]).casefold(), e["version"]))
    counts = {"new": sum(1 for e in entries if e["change"] == "NEW"), "removed": sum(1 for e in entries if e["change"] == "REMOVED"),
              "updated": sum(1 for e in entries if e["change"] == "UPDATED"), "unchanged": unchanged,
              "code": sum(1 for e in entries if e["cause"] == "code"),
              "analysis": sum(1 for e in entries if e["cause"] == "analysis"),
              "unverified": sum(1 for e in entries if e["cause"] == "unverified")}
    return {"schema": SCHEMA, "repo": repo, "baseline_run": (run.data.get("baseline") or {}).get("run_id"),
            "baseline_commit": changes.get("baseline_commit"), "head": changes.get("head"), "changed_files_status": status,
            "changed_files": changes.get("count", 0), "counts": counts, "entries": entries}


def table(doc: Dict[str, Any]) -> Tuple[List[str], List[List[str]]]:
    """Header and rows of ``<repo>.delta.csv``."""
    rows = [[e["change"], e["name"], e["version"], e["baseline_version"], e["cause"],
             ";".join(str(loc) for loc in e["locations"][:10])] for e in doc["entries"]]
    return (list(HEADER), rows)


def read(ctx: RunContext, repo: str) -> Optional[Dict[str, Any]]:
    """``repos/<repo>/delta.json`` of this run, or None."""
    try:
        doc = fsio.read_json(ctx.layout.repo_out(repo) / "delta.json")
    except (OSError, ValueError):
        return None
    except Exception:                                   # noqa: BLE001 - a missing or damaged delta only loses a report section
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == SCHEMA else None


def summary_line(doc: Dict[str, Any]) -> str:
    counts = doc["counts"]
    return ("%d new, %d removed, %d updated, %d unchanged since run %s (%d change(s) caused by code, %d by the analysis, %d "
            "unverified)" % (counts["new"], counts["removed"], counts["updated"], counts["unchanged"],
                             doc.get("baseline_run") or "?", counts["code"], counts["analysis"], counts["unverified"]))
