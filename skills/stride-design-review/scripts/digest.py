#!/usr/bin/env python3
"""Compute the SHA-256 values a coordinator must stamp into run artifacts.

The manifest, issue index, and ledger all require digests the model cannot compute by
inspection, and no role may write a script to compute them. This is the single place those
values are produced, and `validate_run.py` imports `sha`/`canonical` from here so the two
never drift. It also holds the one list of paths a review must never read or bind
(`denied`), shared by `corpus_manifest.py` and `preflight.py`.
"""
from __future__ import annotations

import argparse, hashlib, json, sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]  # the skill root: read-only
SCHEMAS = ROOT / "assets" / "schemas"
SCHEMA_NAMES = ["corpus-manifest-1.0.json", "run-manifest-1.1.json", "issue-index-1.0.json",
                "verification-ledger-1.0.json", "verifier-request-1.0.json",
                "verifier-result-1.0.json", "sweep-result-1.0.json"]


# Paths a review must never read or bind into a corpus: credentials and history, and the folders and
# files that agent hosts load as configuration, instructions or skills (a corpus is untrusted data, and a
# host that reads a file from a folder holding an instruction file may load that file as instructions).
# This is the union of what the two source packages refused (Kiro: .git .ssh .aws .kiro; Vibe: .git .ssh
# .aws .vibe .agents and AGENTS.md) plus the instruction files and configuration folders of the other hosts
# this skill is installed on (docs/agent-portability.md of the repository lists them): Claude Code, Codex,
# Copilot, Cursor, Gemini CLI, Windsurf and Devin, Cline, OpenCode, Qwen Code. The names are compared
# case-insensitively because macOS and Windows file systems are, and on path parts rather than globs,
# because PurePath.match does not treat "**" as recursive before Python 3.13 and would silently admit
# e.g. .git/objects/ab/cd.
DENIED_DIRECTORIES = {".git", ".ssh", ".aws"}
DENIED_DIRECTORIES |= {".kiro", ".vibe", ".agents", ".claude"}  # check-skills: allow-path
DENIED_DIRECTORIES |= {".codex", ".cursor", ".gemini", ".windsurf", ".devin", ".cline", ".clinerules", ".opencode", ".qwen",
                       ".copilot"}
DENIED_NAMES = {"agents.md", "claude.md", "gemini.md", "qwen.md", "copilot-instructions.md", ".cursorrules", ".windsurfrules",
                ".clinerules"}
DENIED_SUFFIXES = {".pem", ".key"}
# A folder that is ordinary elsewhere is refused only in the places a host reads skills or instructions from.
DENIED_PAIRS = {(".github", "skills"), (".github", "instructions")}


def denied(path: Path, root: Path | None = None) -> bool:
    """True when `path` must not be read or bound. With `root`, only the part below it is judged, so a
    corpus that sits under a folder with one of these names is not refused for its ancestors."""
    shown = path.relative_to(root) if root is not None else path
    folded = [part.casefold() for part in shown.parts]
    name = shown.name.casefold()
    return bool(set(folded) & DENIED_DIRECTORIES
                or name == ".env" or name.startswith(".env.")
                or name in DENIED_NAMES
                or shown.suffix.casefold() in DENIED_SUFFIXES
                or any(pair in DENIED_PAIRS for pair in zip(folded, folded[1:])))


def top_level(found: list[str]) -> list[str]:
    """Reduce relative POSIX paths to the topmost ones, so a refused folder is named once, not once per file."""
    names = set(found)
    return [name for name in found if not any(parent in names for parent in map(str, PurePosixPath(name).parents))]


def listing(names: list[str], limit: int = 20) -> str:
    shown = ", ".join(names[:limit])
    return shown + (f" (and {len(names) - limit} more)" if len(names) > limit else "")


def inside_skill_root(path: Path) -> bool:
    """True when `path` is the skill folder or below it. The skill folder is read-only at run time."""
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        return False
    return True


def contains_skill_root(path: Path) -> bool:
    """True when the skill folder sits inside `path`: a corpus must not swallow the installed skill."""
    try:
        ROOT.relative_to(path.resolve())
    except ValueError:
        return False
    return True


def judged(path: Path, workspace: Path | None = None) -> Path:
    """The part of a path that is judged against the refused names. A path below the workspace (default: the working
    directory) is judged by the part below it, so a workspace that sits under a folder with a refused name (a worktree below a
    host's folder, a global install) still works; the folders between the workspace and the path count, so a corpus folder
    named `.ssh` or `.claude` is refused. Any other path is judged whole, so a key under a home directory is refused
    wherever the tool is started."""
    resolved = path.resolve()
    try:
        return resolved.relative_to((workspace or Path.cwd()).resolve())
    except ValueError:
        return resolved


def readable(path: Path) -> Path:
    """The resolved path of a file this tool may hash (see `judged` for what is judged)."""
    resolved = path.resolve()
    if denied(judged(resolved)):
        raise SystemExit(f"refusing a path that review roles must not read: {path}")
    if not resolved.is_file():
        raise SystemExit(f"not a readable file: {path}")
    return resolved


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def select(document: object, pointer: str) -> object:
    node = document
    for part in [p for p in pointer.split(".") if p]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def candidate_issue_record(candidate: dict) -> dict:
    """The canonical projection of a sweep candidate into a blinded issue record."""
    evidence = candidate["evidence"]
    return {"claim": candidate["claim"],
            "scope": {"affectedScope": candidate["affectedScope"], "threatActors": candidate["threatActors"], "stride": candidate["stride"]},
            "sourceLocators": [f"{item['relativePath']}::{item['locator']}" for item in evidence],
            "sourceQuotes": [{"relativePath": item["relativePath"], "locator": item["locator"], "quote": item["quote"]} for item in evidence]}


def stage3_digests(run: Path) -> dict:
    """Recompute every Stage 3 digest and report it next to the recorded value."""
    index_path, ledger_path = run / "stage-3/issue-index.json", run / "stage-3/verification-ledger.json"
    sweep_path = run / "stage-3/sweep-result.json"
    for required in (index_path, sweep_path):
        if not required.is_file():
            raise SystemExit(f"missing Stage 3 artifact: {required}")
    index = json.loads(index_path.read_text(encoding="utf-8"))
    candidates = {c["candidateId"]: c for c in json.loads(sweep_path.read_text(encoding="utf-8"))["candidates"]}
    rows = []
    for item in index["items"]:
        rows.append({"queueKey": item["queueKey"], "field": "issueRecordDigest",
                     "recorded": item["issueRecordDigest"], "recomputed": canonical_digest(item["blindedRecord"])})
        if item["origin"] == "stage3":
            candidate = candidates.get(item["sourceCandidateId"])
            rows.append({"queueKey": item["queueKey"], "field": "sourceCandidateDigest",
                         "recorded": item["sourceCandidateDigest"],
                         "recomputed": canonical_digest(candidate) if candidate else None})
            rows.append({"queueKey": item["queueKey"], "field": "blindedRecord",
                         "recorded": canonical_digest(item["blindedRecord"]),
                         "recomputed": canonical_digest(candidate_issue_record(candidate)) if candidate else None})
    files = {"stage-3/issue-index.json": {"recordedIn": None, "recorded": None, "recomputed": sha(index_path)},
             "stage-3/sweep-result.json": {"recordedIn": "stage-3/issue-index.json", "recorded": index.get("sweepResultSha256"), "recomputed": sha(sweep_path)}}
    if ledger_path.is_file():
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        files["stage-3/issue-index.json"].update(recordedIn="stage-3/verification-ledger.json", recorded=ledger.get("issueIndexSha256"))
        manifest_path = run / "run-manifest.json"
        summary = (json.loads(manifest_path.read_text(encoding="utf-8")).get("stage3Ledger") or {}) if manifest_path.is_file() else {}
        files["stage-3/verification-ledger.json"] = {"recordedIn": "run-manifest.json" if summary else None,
                                                     "recorded": summary.get("sha256"), "recomputed": sha(ledger_path)}
    for row in rows:
        row["match"] = row["recorded"] == row["recomputed"]
    for record in files.values():
        # A row nobody records is "unrecorded", never a match: absence must not read as agreement.
        record["match"] = record["recorded"] == record["recomputed"] if record["recordedIn"] else None
    return {"items": rows, "files": files,
            "mismatches": [r for r in rows if not r["match"]] + [{"file": k, **v} for k, v in files.items() if v["match"] is False],
            "unrecorded": [k for k, v in files.items() if v["match"] is None]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    p_file = sub.add_parser("file", help="SHA-256 and byte count of raw file bytes")
    p_file.add_argument("paths", type=Path, nargs="+")
    p_canonical = sub.add_parser("canonical", help="SHA-256 over canonical JSON (sorted keys, compact separators)")
    p_canonical.add_argument("path", type=Path)
    p_canonical.add_argument("--select", help="dotted path into the document, e.g. items.0.blindedRecord")
    sub.add_parser("schemas", help="digests of the schema files shipped with the skill, shaped for environment.schemaDigests")
    p_stage3 = sub.add_parser("stage3", help="recompute every Stage 3 digest beside its recorded value")
    p_stage3.add_argument("run_root", type=Path)
    p_stage3.add_argument("--check", action="store_true", help="exit non-zero when a recomputed value differs from the recorded one")
    args = parser.parse_args()

    if args.mode == "file":
        checked = [readable(p) for p in args.paths]
        output = [{"path": str(given), "sha256": sha(path), "bytes": path.stat().st_size} for given, path in zip(args.paths, checked)]
    elif args.mode == "canonical":
        document = json.loads(readable(args.path).read_text(encoding="utf-8"))
        node = select(document, args.select) if args.select else document
        output = {"path": str(args.path), "select": args.select, "sha256": canonical_digest(node)}
    elif args.mode == "schemas":
        output = {name: sha(SCHEMAS / name) for name in SCHEMA_NAMES}
    else:
        output = stage3_digests(args.run_root.resolve())
    print(json.dumps(output, indent=2))
    if args.mode == "stage3" and args.check and output["mismatches"]:
        print(f"ERROR: {len(output['mismatches'])} recorded digest(s) do not match the recomputed value", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
