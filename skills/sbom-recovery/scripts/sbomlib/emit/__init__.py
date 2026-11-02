"""Phase 8 (emit) and phase 9 (merge) of the pipeline (contract section 3.12).

``prepare``           unit ``emit:prepare``: removes the previous emit outputs (``components.json`` and ``delta.json`` of every
                      repository too), keeps the staged CPE resolution;
``build_components``  first half of unit ``emit:<repo>``: ``repos/<repo>/components.json``;
``write_repo``        second half: the staged per-repository CSV, SPDX 2.3 JSON, CycloneDX 1.6 JSON, evidence and candidate
                      audit files (and the delta against the baseline when there is one), validated at once (a validation
                      problem is reported in ``PhaseResult.info["errors"]``, never raised).

Private modules: ``components`` (the builder), ``csvout``, ``spdx`` and ``cyclonedx`` (pure renderers), ``merge`` (phase 9), ``stage``
(staging layout and promotion), ``licexpr`` (SPDX licence expressions). Validation lives in ``sbomlib.validate``.
"""
from __future__ import annotations

import os
from typing import Any, List

from sbomlib import csvio, delta, errors, fsio
from sbomlib.context import RunContext
from sbomlib.emit import components as components_module
from sbomlib.emit import csvout, cyclonedx, merge, spdx, stage                         # noqa: F401
from sbomlib.emit.components import build_components                                    # noqa: F401
from sbomlib.emit.spdx import creation_comment                                          # noqa: F401
from sbomlib.model import PhaseResult
from sbomlib.state import RunState

__all__ = ["prepare", "build_components", "write_repo"]

MAX_REPORTED_ERRORS = 100


def prepare(ctx: RunContext, run: RunState) -> PhaseResult:
    """Unit ``emit:prepare``.

    Ensures ``.staging/<run_id>/`` exists and removes only the previous emit outputs: ``.staging/<run_id>/repos/``, the
    staged ``merged-sbom.csv``, every ``repos/<repo>/components.json``, ``.state/validation.json``,
    ``.state/audit_checks.json`` and ``.state/integrity-final.parts/``. It never touches
    ``.staging/<run_id>/cpe_resolution.csv``: only ``cpe:resolve`` rewrites that file.
    """
    layout = ctx.layout
    root = layout.out
    staging = layout.staging(run.run_id)
    fsio.ensure_dir(staging, root=root)
    fsio.remove_tree(staging / "repos", root=root)
    fsio.remove_file(stage.staged_merged(ctx, run), root=root)
    repos_dir = layout.repos_out
    if os.path.isdir(str(repos_dir)) and not os.path.islink(str(repos_dir)):
        for name in sorted(os.listdir(str(repos_dir))):
            for derived in ("components.json", "delta.json"):
                candidate = repos_dir / name / derived
                if os.path.lexists(str(candidate)):
                    fsio.remove_file(candidate, root=root)
    fsio.remove_file(layout.state / "validation.json", root=root)
    fsio.remove_file(layout.state / "audit_checks.json", root=root)
    fsio.remove_tree(layout.state / "integrity-final.parts", root=root)
    return PhaseResult()


def write_repo(ctx: RunContext, run: RunState, repo: str) -> PhaseResult:
    """Unit ``emit:<repo>``, second half: stage ``<repo>.sbom.csv``, ``<repo>.spdx.json``, ``<repo>.evidence.csv`` and
    ``candidates_audit.csv`` below ``.staging/<run_id>/repos/<repo>/`` and validate them.

    ``PhaseResult.info["errors"]`` lists the validation problems (``<check>: <message>``); the files are written either way.
    """
    layout = ctx.layout
    document = fsio.read_json(layout.repo_out(repo) / "components.json")
    if not isinstance(document, dict) or document.get("schema") != components_module.SCHEMA:
        raise errors.StateError("repos/%s/components.json is not a components document" % repo, repo=repo)
    evidence = components_module.load_evidence(ctx, repo)
    created = ctx.created()
    tool = spdx.tool_name(ctx.version())
    comment = spdx.creation_comment(ctx, run, repo)
    spdx_doc = spdx.build_document(document, created=created, tool=tool, creation_comment=comment)
    target = stage.staged_repo_dir(ctx, run, repo)
    fsio.ensure_dir(target, root=layout.out)
    result = PhaseResult()
    header, rows = csvout.repo_table(document)
    _write_csv(ctx, result, target / ("%s.sbom.csv" % repo), header, rows)
    sha = fsio.atomic_write_text(target / ("%s.spdx.json" % repo), spdx.dumps_document(spdx_doc), root=layout.out)
    result.outputs[layout.out_rel(target / ("%s.spdx.json" % repo))] = sha
    license_ids = (ctx.asset("cyclonedx-license-ids.json") or {}).get("ids") or []
    cdx_doc = cyclonedx.build_document(document, created=created, tool_version=ctx.version(), creation_comment=comment,
                                       license_ids=license_ids)
    sha = fsio.atomic_write_text(target / ("%s.cdx.json" % repo), cyclonedx.dumps_document(cdx_doc), root=layout.out)
    result.outputs[layout.out_rel(target / ("%s.cdx.json" % repo))] = sha
    header, rows = csvout.evidence_table(document, evidence)
    _write_csv(ctx, result, target / ("%s.evidence.csv" % repo), header, rows)
    header, rows = csvout.audit_table(document)
    _write_csv(ctx, result, target / stage.AUDIT_NAME, header, rows)
    changes = delta.compute(ctx, run, repo, document)
    if changes is not None:
        header, rows = delta.table(changes)
        _write_csv(ctx, result, target / ("%s.delta.csv" % repo), header, rows)
        fsio.atomic_write_json(layout.repo_out(repo) / "delta.json", changes, root=layout.out)
    else:
        fsio.remove_file(layout.repo_out(repo) / "delta.json", root=layout.out)
    from sbomlib import validate
    checked = validate.check_repo(ctx, run, repo)
    problems: List[str] = []
    for name in validate.REPO_CHECKS:
        problems.extend("%s: %s" % (name, message) for message in checked.get(name, []))
    result.info["errors"] = problems[:MAX_REPORTED_ERRORS]
    return result


def _write_csv(ctx: RunContext, result: PhaseResult, path: Any, header: Any, rows: Any) -> None:
    sha = csvio.write_csv(path, header, rows, root=ctx.layout.out)
    result.outputs[ctx.layout.out_rel(path)] = sha
