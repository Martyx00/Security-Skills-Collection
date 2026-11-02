"""Phase 3 (usage verification) and the phase-4 helpers (contract section 3.10).

``run_repo``           reads the phase-2 outputs, writes ``verify_evidence.jsonl`` and ``verdicts.json``;
``evidence_summary``   writes the input file of an adjudication kind and returns the ``adjudicate`` block;
``apply_decisions``    validates the agent's answer (attempt 1 all-or-nothing, attempt 2 partial), writes
                       ``decisions_validated.json``;
``final_verdicts``     ``verdicts.json`` with the validated decisions applied (pure read);
``blindspots``         union of the blind spots of the three files (pure read);
``chosen_identity`` / ``chosen_version``   the name and version every later phase uses.
"""
from __future__ import annotations

from typing import Any, Dict

from sbomlib import fsio, model
from sbomlib.context import RunContext
from sbomlib.state import RunState
from sbomlib.verify import adjudicate, configs, rules, usage
from sbomlib.verify.adjudicate import apply_decisions, blindspots, evidence_summary, final_verdicts
from sbomlib.verify.inputs import RepoData

__all__ = ["run_repo", "evidence_summary", "apply_decisions", "final_verdicts", "blindspots", "chosen_identity",
           "chosen_version"]

_VERSION_KEYS = ("version", "version_raw", "version_kind", "version_source", "cpe_version", "cpe_update", "evidence_ids",
                 "notes")


def run_repo(ctx: RunContext, run: RunState, repo: str) -> model.PhaseResult:
    """Unit ``verify:<repo>``: shipping set, include/identifier scan, rule engine; writes the two output files."""
    data = RepoData(ctx, repo)
    shipping = configs.shipping_set(data.buildmodel)
    build = usage.Build(data, shipping)
    scanner = usage.Scanner(ctx, data, build)
    scan = scanner.run()
    engine = rules.Engine(ctx, data, shipping, build, scanner)
    result = engine.run()

    records = sorted(scan.records + result.records, key=lambda r: r["id"])
    out = ctx.layout.repo_out(repo)
    evidence_text = "".join(fsio.dumps_compact(r) + "\n" for r in records)
    outputs: Dict[str, str] = {}
    outputs[ctx.layout.out_rel(out / "verify_evidence.jsonl")] = fsio.atomic_write_text(
        out / "verify_evidence.jsonl", evidence_text, root=ctx.layout.out)

    pool = adjudicate.pool_from_memory(repo, result.verdicts, data.candidates, list(data.evidence) + records, shipping)
    hashes, capacity_spots = adjudicate.apply_capacity(pool)
    spots = sorted(result.blindspots + capacity_spots,
                   key=lambda b: (b["code"], b.get("loc") or "", b.get("candidate") or ""))
    doc = {"schema": 1, "repo": repo, "analysis_mode": (run.data.get("analysis_mode") if run is not None else None) or "static",
           "coverage": dict(result.coverage), "shipping": shipping, "verdicts": pool.verdicts, "blindspots": spots,
           "adjudication_inputs": hashes}
    outputs[ctx.layout.out_rel(out / "verdicts.json")] = fsio.atomic_write_json(out / "verdicts.json", doc,
                                                                                root=ctx.layout.out)
    phase = model.PhaseResult(done=True, outputs=outputs)
    if shipping.get("assumed"):
        phase.warnings.append(model.warning("INFORMATIONAL", "SHIPPING_CONFIG_ASSUMED",
                                            "every declared configuration looks like a debug, test or ci configuration; "
                                            "all of them decide usage (%s)" % repo, repo))
    if scan.unreadable:
        phase.incomplete.append("%d first-party source file(s) could not be scanned" % len(scan.unreadable))
        phase.warnings.append(model.warning("INFORMATIONAL", "COVERAGE_PARTIAL",
                                            "%d first-party source file(s) are symbolic links, larger than 2 MiB or unreadable, "
                                            "so include and identifier checks are partial (%s)"
                                            % (len(scan.unreadable), repo), repo))
    return phase


def chosen_identity(candidate: Dict[str, Any], verdict: Dict[str, Any]) -> str:
    """The adjudicated or rule-chosen canonical name, else the candidate's own."""
    return str(verdict.get("identity") or candidate["name"])


def chosen_version(candidate: Dict[str, Any], verdict: Dict[str, Any]) -> Dict[str, Any]:
    """The version option the verdict chose (keys ``version`` ... ``notes``); the candidate's preferred claim otherwise."""
    version = candidate.get("version") or {}
    wanted = verdict.get("version_option")
    for option in version.get("options") or []:
        if option.get("id") == wanted:
            return {key: option.get(key) for key in _VERSION_KEYS}
    return {k: v for k, v in version.items() if k != "options"}
