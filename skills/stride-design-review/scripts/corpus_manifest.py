#!/usr/bin/env python3
"""Create or verify a byte-bound corpus manifest with extraction metadata."""
from __future__ import annotations

import argparse, hashlib, json, mimetypes, sys
from datetime import datetime, timezone
from pathlib import Path

# `python3 -I` drops the script's own folder from sys.path; the sibling module is imported by name.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from digest import contains_skill_root, denied, inside_skill_root, judged, listing, top_level  # noqa: E402

TEXT_EXTENSIONS = {".md", ".txt", ".json", ".yaml", ".yml", ".csv", ".tsv", ".xml", ".html", ".rst"}


def digest(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def aggregate(sources: list[dict]) -> str:
    tuples = [[s["relativePath"], s["sha256"], s["bytes"]] for s in sources]
    encoded = json.dumps(tuples, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def build(root: Path, extraction: dict[str, dict], workspace: Path | None = None) -> dict:
    """The corpus manifest of `root`. `workspace` (default: the working directory) is what the corpus folder's own path is
    judged against: the folders from the workspace down to `root` must not be refused names either, or `--docs-root .ssh`
    would bind a credentials folder as a corpus. Folders above the workspace are not judged."""
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    own = judged(root, workspace)
    if denied(own):
        raise ValueError(f"the corpus folder itself is a path that review roles must not read or that an agent host would load as "
                         f"instructions or configuration: {own.as_posix()} (point docsRoot at a folder of review sources)")
    sources, unreadable_by_policy = [], []
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        if path.is_symlink():
            raise ValueError(f"symlinks are not allowed in a corpus: {path}")
        relative = path.relative_to(root).as_posix()
        if denied(path, root):
            # Review roles must not read these paths (credentials, history, host instruction and
            # configuration files), so a source here could never be reviewed; bind only what they may read.
            # Folders count too, so a refused folder is named once and not once per file.
            unreadable_by_policy.append(relative)
            continue
        if not path.is_file():
            continue
        sha, size = digest(path)
        supplied = extraction.get(relative)
        if supplied is None and path.suffix.lower() in TEXT_EXTENSIONS:
            supplied = {"extractionMethod": "native-text", "fidelity": "exact-text", "pageMapping": "not-applicable", "diagrams": "not-applicable", "limitations": []}
        if supplied is None:
            supplied = {"extractionMethod": "none", "fidelity": "unreadable", "pageMapping": "unknown", "diagrams": "unreadable", "limitations": ["No explicit extraction metadata supplied for non-text source"]}
        allowed = {"extractionMethod", "fidelity", "pageMapping", "diagrams", "limitations"}
        unexpected = sorted(set(supplied) - allowed)
        missing = sorted(allowed - set(supplied))
        if unexpected or missing:
            raise ValueError(f"invalid extraction metadata for {relative}: unexpected={unexpected}, missing={missing}")
        sources.append({**supplied, "relativePath": relative, "sha256": sha, "bytes": size, "mediaType": mimetypes.guess_type(relative)[0] or "application/octet-stream"})
    if unreadable_by_policy:
        raise ValueError("corpus contains paths review roles must not read, or that an agent host would load as instructions "
                         "or configuration (an old copy of this tool, .claude, .agents, AGENTS.md, .git, .env, keys; remove them or "
                         "point docsRoot at a directory holding only review sources): " + listing(top_level(unreadable_by_policy)))
    return {"schemaVersion": "1.0", "createdAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "root": str(root.resolve()), "aggregateDigest": aggregate(sources), "sourceCount": len(sources), "totalBytes": sum(s["bytes"] for s in sources), "sources": sources}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("docs_root", type=Path)
    parser.add_argument("--output", type=Path, help="where to write the manifest; not needed with --verify")
    parser.add_argument("--extraction-map", type=Path)
    parser.add_argument("--verify", type=Path, help="recompute and compare against this manifest instead of writing one")
    parser.add_argument("--allow-unreadable", action="store_true")
    parser.add_argument("--workspace-root", type=Path, help="the folder the corpus folder's own path is judged against "
                        "(default: the working directory); folders above it may carry any name")
    args = parser.parse_args()
    if not args.output and not args.verify:
        parser.error("provide --output to write a manifest or --verify to check an existing one")
    if args.output and inside_skill_root(args.output):
        raise SystemExit(f"refusing to write inside the skill folder (it is read-only at run time): {args.output}")
    if contains_skill_root(args.docs_root):
        raise SystemExit("docsRoot contains the installed skill folder; point docsRoot at the design documents only")
    extraction = json.loads(args.extraction_map.read_text(encoding="utf-8")) if args.extraction_map else {}
    try:
        result = build(args.docs_root.resolve(), extraction, args.workspace_root)
    except ValueError as exc:
        raise SystemExit(str(exc))
    unreadable = [s["relativePath"] for s in result["sources"] if s["fidelity"] == "unreadable"]
    if unreadable and not args.allow_unreadable:
        raise SystemExit("unreadable sources require extraction metadata: " + ", ".join(unreadable))
    if args.verify:
        expected = json.loads(args.verify.read_text(encoding="utf-8"))
        if expected.get("aggregateDigest") != result["aggregateDigest"]:
            raise SystemExit(f"corpus digest mismatch: expected {expected.get('aggregateDigest')}, got {result['aggregateDigest']}")
        print(result["aggregateDigest"])
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:  # Path.write_text has no newline= before 3.10
        handle.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(result["aggregateDigest"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
