#!/usr/bin/env python3
"""Compute the deterministic source delta between two corpus manifests."""
import argparse, json, sys
from pathlib import Path

# `python3 -I` drops the script's own folder from sys.path; the sibling module is imported by name.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from digest import inside_skill_root  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(); p.add_argument("baseline", type=Path); p.add_argument("current", type=Path); p.add_argument("--output", type=Path); args = p.parse_args()
    if args.output and inside_skill_root(args.output):
        raise SystemExit(f"refusing to write inside the skill folder (it is read-only at run time): {args.output}")
    old = json.loads(args.baseline.read_text(encoding="utf-8")); new = json.loads(args.current.read_text(encoding="utf-8"))
    left = {x["relativePath"]: x for x in old["sources"]}; right = {x["relativePath"]: x for x in new["sources"]}
    result = {"baselineDigest": old["aggregateDigest"], "currentDigest": new["aggregateDigest"], "added": sorted(right.keys() - left.keys()), "removed": sorted(left.keys() - right.keys()), "changed": sorted(k for k in left.keys() & right.keys() if (left[k]["sha256"], left[k]["bytes"]) != (right[k]["sha256"], right[k]["bytes"])), "unchanged": sorted(k for k in left.keys() & right.keys() if (left[k]["sha256"], left[k]["bytes"]) == (right[k]["sha256"], right[k]["bytes"]))}
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("w", encoding="utf-8", newline="\n") as handle:  # Path.write_text has no newline= before 3.10
            handle.write(text)
    else: print(text, end="")
    return 0


if __name__ == "__main__": raise SystemExit(main())
