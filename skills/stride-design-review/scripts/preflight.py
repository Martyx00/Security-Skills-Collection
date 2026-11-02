#!/usr/bin/env python3
"""Corpus-hygiene preflight: refuse a review envelope whose corpus could instruct or mislead the reviewer.

    python3 -I -B <skill folder>/scripts/preflight.py <envelope.json> --workspace-root <workspace>

Checks, in order: the envelope has the shape `run-manifest-1.1` later requires of it; its paths
resolve inside the workspace, do not overlap in a way the validators refuse, and the run root is
not inside the (read-only) skill folder; the corpus holds no symlinks, does not contain the
installed skill, and holds no path that review roles must not read or that an agent host would
load as instructions or configuration (AGENTS.md, CLAUDE.md, GEMINI.md, .agents, .claude, .git,
.env, keys, and the folders of the other hosts, which includes an old copy of this tool). The
corpus folder's own path counts too, from the workspace down (`--docs-root .ssh` is refused),
while folders above the workspace may carry any name; the optional extraction map and baseline
report exist.

The corpus is untrusted data. A host that reads one file of a folder may load an instruction file
that sits next to it, and the only defence a skill has is to keep such files out of the corpus.

What this does NOT do: it does not attest how the host isolates a role from inherited context. The
envelope's `resourceIsolation*` and `inheritedResources` fields are checked for shape only (and
`resourceIsolationConfirmed` must be false); they are recorded claims, and `validate_run.py` checks
that they are consistent with the dispatch mode.
"""
from __future__ import annotations

import argparse, json, sys
from pathlib import Path

# `python3 -I` drops the script's own folder from sys.path; the sibling modules are imported by name.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from digest import ROOT, SCHEMAS, contains_skill_root, denied, inside_skill_root, judged, listing, top_level  # noqa: E402
from jsonschema_subset import validate  # noqa: E402

# The envelope fields every run must state. The three isolation fields are a recorded claim, not an attestation.
REQUIRED = ["docsRoot", "runRoot", "domainLens", "resourceIsolationConfirmed", "resourceIsolationMethod", "inheritedResources"]


def envelope_errors(envelope: object, workspace: Path) -> list[str]:
    """Shape, path and corpus errors the run validator would otherwise report only after the run started."""
    run_manifest = json.loads((SCHEMAS / "run-manifest-1.1.json").read_text(encoding="utf-8"))
    shape = {**run_manifest["properties"]["envelope"], "required": REQUIRED}
    errors = [f"envelope: {item}" for item in validate(envelope, shape)]
    if envelope["resourceIsolationConfirmed"]:
        errors.append("envelope: resourceIsolationConfirmed must be false; nothing in this skill can confirm how a host isolates a role (resourceIsolationMethod records the claim)")
    if errors:
        return errors
    docs = (workspace / envelope["docsRoot"]).resolve(); run = (workspace / envelope["runRoot"]).resolve()
    for label, path in (("docsRoot", docs), ("runRoot", run)):
        if not path.is_relative_to(workspace):
            errors.append(f"{label} escapes the workspace root: {path}")
    if inside_skill_root(run):
        errors.append(f"runRoot is inside the skill folder ({ROOT}), which is read-only at run time; use a directory in the workspace")
    if not docs.is_dir():
        errors.append(f"docsRoot is not an existing directory: {envelope['docsRoot']}")
    if docs == run:
        errors.append("docsRoot must not equal runRoot")
    elif run.is_relative_to(docs):
        errors.append("runRoot must not lie inside docsRoot")
    if docs.is_dir():
        if contains_skill_root(docs):
            errors.append("docsRoot contains the installed skill folder; point docsRoot at the design documents only")
        own = judged(docs, workspace)
        if denied(own):
            errors.append(f"docsRoot is itself a path that review roles must not read or that an agent host would load as "
                          f"instructions or configuration: {own.as_posix()}; point docsRoot at a folder of review sources")
        found = sorted(docs.rglob("*"), key=lambda path: path.relative_to(docs).as_posix())
        symlinks = [path.relative_to(docs).as_posix() for path in found if path.is_symlink()]
        if symlinks:
            errors.append("corpus contains symlinks: " + listing(symlinks))
        refused = top_level([path.relative_to(docs).as_posix() for path in found if denied(path, docs)])
        if refused:
            errors.append("corpus contains paths that review roles must not read or that an agent host would load as "
                          "instructions or configuration (an old copy of this tool, .claude, .agents, AGENTS.md, CLAUDE.md, "
                          ".git, .env, keys); remove them or point docsRoot at a directory holding only review sources: "
                          + listing(refused))
    for key in ("extractionMap", "baselineReport"):
        value = envelope.get(key)
        if value is not None and not (workspace / value).is_file():
            errors.append(f"{key} does not name an existing file: {value}")
    return errors


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("envelope", type=Path); p.add_argument("--workspace-root", type=Path, required=True); args = p.parse_args()
    envelope = json.loads(args.envelope.read_text(encoding="utf-8"))
    errors = envelope_errors(envelope, args.workspace_root.resolve())
    if errors:
        raise SystemExit("\n".join(errors))
    print("corpus-hygiene preflight passed (envelope shape, path rules, corpus instruction and secret scan)")
    return 0


if __name__ == "__main__": raise SystemExit(main())
