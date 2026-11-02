#!/usr/bin/env python3
"""
smoke_test.py - run the deterministic stages end to end and check what fired.

Every other check in this skill tests one tool in isolation. That is where the
tools' own bugs live, and it is not where this pipeline's expensive failures
live: those are at the seams, where a field one tool writes is a field the next
one reads under a slightly different name, and where a rule table transcribed
from a C-centric source quietly does nothing on four of the languages it lists.

Both of those failures are silent in the worst way - the run completes, the
coverage account balances, and the report is about a smaller codebase than the
one on disk. `coverage.json` will say a rule found nothing, which is true, and
`zero_hit_cause: absent-from-tree` will say the tree does not use those
functions, which is also true if the pattern only knows `MD5` and the tree spells
it `hashlib.md5`.

So this runs the fixture at security-review/tests/fixture, which carries
vulnerable functions in every language the extractor assigns, with the rule each
line should trip written next to it, and fails when a rule that should have fired
did not. It was written after a probe found CRY-002 firing on Java's `"MD5"`
string and missing `hashlib.md5`, `md5.Sum` and `createHash('md5')` - three of the
five languages the fixture held then. The same gap later turned up in six more
rules - INJ-002 to INJ-005, CRY-004, LOG-005 - in languages the fixture held and
more so in the five it did not, which is why it now holds all of them and every
pattern rule has at least one expectation in it.

What it does NOT do is fail on a rule firing where the fixture did not predict
it. Recall bias is the design: stage 1 is supposed to over-emit and let the
validators throw candidates out, so an unexpected hit is the pipeline working.
Those are counted and sampled, never asserted on.

Stages 4 and 5 need a model and a person. What this covers is extract -> score
-> enrich, the candidate gate that verify_findings.py runs over the result, and
then run_status.py - the one exit code a CI job acts on - over what those real
stages wrote, before and after a stand-in stage 4 that answers every candidate
NEEDS_HUMAN_REVIEW. run_status.py's own selftest builds its inputs by hand from
the writers' field names, so without this nothing tested that it can read what
the writers actually write: rename a field on one side and every selftest still
passes while an incomplete run reports itself complete. Then it records one
`ledger.py suppress`, runs stage 3 again, and holds the gate to passing: a
suppressed function's MEM-WFS used to stay dispatched and fail I5.

It also holds the stages to one line model. Stage 1 counts a line as a
"\\n"-delimited segment of the decoded bytes; a later stage that splits
differently (str.splitlines() also breaks on form feeds and U+2028) quotes the
wrong line for every hit below the first such character, and on a tree nobody
edited mid-run that shows up as sink_text drift. So drift here is a failure.

Stdlib only. Python 3.8+.

Usage
  python3 smoke_test.py                     # run the shipped fixture
  python3 smoke_test.py --fixture DIR       # run another tree with EXPECT tags
  python3 smoke_test.py --keep              # leave the run directory for inspection
  python3 smoke_test.py --coverage          # per-language and per-rule summary only
  python3 smoke_test.py --fallback          # the same, with tree-sitter refused
  python3 smoke_test.py --snapshot          # extract from a frozen copy of the fixture
  python3 smoke_test.py --selftest

Exit codes
  0  every expectation met
  1  an expectation was missed, a stage failed, or a seam check failed (the
     candidate gate, the line model, run_status.py's reading of the run, the
     gate after a suppression, a reader that trusted a committed run directory,
     stage 1's MEM-WFS derivation: a record outside the rule's languages, a C,
     C++ or Rust function with a candidate and none, or, on the shipped
     fixture, no same-named pair for I5's function_key keying)
  2  the fixture or a tool is missing
"""

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(os.path.dirname(HERE), "tests", "fixture")

# `EXPECT: MEM-002` / `EXPECT: MEM-002, INJ-001` / `EXPECT-SKIP: MEM-002`
# / `EXPECT-FUNC: parse_tlv`. Anchored on the keyword rather than on a comment
# syntax, so one regex covers //, #, /* */ and //! without knowing the language.
EXPECT = re.compile(r"EXPECT(-SKIP|-FUNC)?:\s*([A-Za-z0-9_\-, ]+)")

STAGES = ("extract_functions.py", "score_functions.py", "enrich_candidates.py")

# Every tool a run of this test drives. Checked before anything runs: a missing
# stage used to be printed as SKIPPED and passed over, and a missing gate tool
# returned "passed" without a word, so a bundle that had lost stage 3 and
# verify_findings.py still reported "smoke test: ok". Every expectation is
# settled by stage 1, so nothing else would have noticed.
GATE_TOOLS = ("verify_findings.py", "run_status.py", "ledger.py")


class Missing(Exception):
    """A tool this test drives is not installed."""


def tool(name):
    path = os.path.join(HERE, name)
    if not os.path.isfile(path):
        raise Missing(path)
    return path


def missing_tools(snapshot=False, here=None):
    """Absolute paths of the tools this run needs and cannot find, sorted."""
    here = here or HERE
    names = STAGES + GATE_TOOLS + (("snapshot.py",) if snapshot else ())
    return sorted(os.path.join(here, name) for name in names
                  if not os.path.isfile(os.path.join(here, name)))


def run(argv, cwd):
    """Run a stage, returning (returncode, combined output)."""
    out = subprocess.run(                              # noqa: S603
        argv, cwd=cwd, capture_output=True, text=True, timeout=900,
    )
    return out.returncode, (out.stdout or "") + (out.stderr or "")


# --------------------------------------------------------------------------- #
# expectations
# --------------------------------------------------------------------------- #

def read_expectations(fixture):
    """{(relpath, line): {"rules": [...], "skips": [...], "func": name}}

    Lines are counted the way stage 1 counts them: the decoded bytes split on
    "\\n" and nothing else. A text-mode read treats a lone carriage return as a
    line break too, so a tag below one would be expected a line later than the
    extractor reports it, and the test would blame the rule for the reader.
    """
    want = {}
    for root, dirs, files in os.walk(fixture):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
        for name in sorted(files):
            if name == "README.md":
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, fixture)
            try:
                with open(path, "rb") as fh:
                    lines = fh.read().decode("utf-8", "replace").split("\n")
            except OSError:
                continue
            for n, text in enumerate(lines, 1):
                for kind, body in EXPECT.findall(text):
                    ids = [x.strip() for x in body.split(",") if x.strip()]
                    slot = want.setdefault(
                        (rel, n), {"rules": [], "skips": [], "func": None})
                    if kind == "-FUNC":
                        slot["func"] = ids[0]
                    elif kind == "-SKIP":
                        slot["skips"].extend(ids)
                    else:
                        slot["rules"].extend(ids)
    return want


def read_jsonl(path):
    if not os.path.isfile(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #

def stage_args(name, workdir, fallback=False, use_snapshot=False):
    if name == "extract_functions.py":
        # src/vendor holds first-party code a default exclusion catches, and a
        # path-scoped --include is how an operator recovers it. The exclusion
        # stays in manifest.json - it still excludes every other vendor/ - so
        # each later stage that walks the tree has to honour the include the
        # way stage 1 did, and the gate's recount is where one that did not
        # shows up.
        argv = [sys.executable, tool(name), "--root", ".", "--include", "src/vendor"]
        if use_snapshot:
            argv.append("--snapshot")
        if fallback:
            # The tier most installs actually run. tree-sitter is an optional
            # dependency and a bundle that only works with it installed is a
            # bundle whose default path nobody tested.
            argv.append("--no-tree-sitter")
        return argv
    if name == "score_functions.py":
        # Small fixture: take everything, so a missed expectation is a rule
        # problem and never the operating point declining to rank it.
        return [sys.executable, tool(name), "--root", ".",
                "--backend", "rules", "--strict-k", "1000",
                "--loose-percent", "100", "--budget", "1000"]
    return [sys.executable, tool(name), "--root", ".",
            "--budget", "1000", "--no-analyzers"]


def drive(fixture, workdir, verbose, fallback=False, use_snapshot=False):
    """Copy the fixture, run every deterministic stage, return the artifacts."""
    shutil.copytree(fixture, workdir, dirs_exist_ok=True)
    # A fixture is not a git checkout, and the extractor reads git for churn.
    # Initialising one keeps that path exercised rather than silently skipped.
    subprocess.run(["git", "init", "-q", "."], cwd=workdir,          # noqa: S603
                   capture_output=True, env=_git_env(workdir))

    if use_snapshot:
        # The seam this mode exists for: stage 1 reads frozen bytes while every
        # path it records stays relative to the working tree, so stages 2 and 3
        # - which never hear about the snapshot - must still join on those paths
        # and quote lines that resolve in the repository. A translation error
        # here would look exactly like a clean run with slightly wrong citations.
        code, out = run([sys.executable, tool("snapshot.py"), "--root", "."],
                        workdir)
        if verbose or code != 0:
            print("--- snapshot.py (exit %d)" % code)
            print(out.rstrip())
        if code != 0:
            return None, "snapshot.py exited %d" % code

    # A stage that is not installed raises Missing, which main() turns into exit
    # 2. It used to be printed as SKIPPED and passed over, on the argument that
    # the expectations are all settled by stage 1 - which is exactly why nothing
    # else noticed a bundle that had lost stage 3. main() checks every tool
    # before the run starts, so reaching this means one vanished mid-run.
    for name in STAGES:
        argv = stage_args(name, workdir, fallback, use_snapshot)
        code, out = run(argv, workdir)
        if verbose or code != 0:
            print("--- %s (exit %d)" % (name, code))
            print(out.rstrip())
        if code != 0:
            return None, "%s exited %d" % (name, code)

    base = os.path.join(workdir, ".security-review")
    return {
        "functions": read_jsonl(os.path.join(base, "extract", "functions.jsonl")),
        "rules": read_jsonl(os.path.join(base, "extract", "rules.jsonl")),
        "scores": read_jsonl(os.path.join(base, "scores", "scores.jsonl")),
        "base": base,
        "workdir": workdir,
        "snapshot": use_snapshot,
    }, ""


def wfs_shape(art, shipped_fixture=True):
    """Problems with stage 1's MEM-WFS derivation over the fixture; [] is right.

    MEM-WFS is derived for a function in one of its own languages and no other
    (extract_functions.derive_wfs), so a record on any other function is one
    stage 1 should not have written, and a function in one of them with an
    emitted candidate and no record is a pass that never ran. The shipped
    fixture also has to hold two functions with one name in one file that each
    get their own record: that is the shape the gate's I5 tells apart by
    function_key, and a fixture that stopped holding it would leave the keying
    untested with every check still green.
    """
    try:
        with open(os.path.join(art["base"], "extract", "coverage.json"),
                  encoding="utf-8") as fh:
            row = next(r for r in json.load(fh)["rules"] if r["rule_id"] == "MEM-WFS")
        languages = set(row["languages"])
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        return ["extract/coverage.json holds no MEM-WFS row with its languages: %s"
                % exc]
    record = {f["function_id"]: f for f in art["functions"]}

    def language(fid):
        return (record.get(fid) or {}).get("language")
    wfs = [h for h in art["rules"] if h["rule_id"] == "MEM-WFS"]
    problems = ["MEM-WFS on %s, a %s function: the rule runs on %s only"
                % (h.get("function_key"), language(h.get("function_id")),
                   ", ".join(sorted(languages)))
                for h in wfs if language(h.get("function_id")) not in languages]
    owed = {h["function_id"] for h in art["rules"]
            if h["rule_id"] != "MEM-WFS" and h.get("disposition") == "emitted"
            and h.get("function_id") and language(h["function_id"]) in languages}
    problems += ["%s produced a candidate and got no MEM-WFS" % fid
                 for fid in sorted(owed - {h.get("function_id") for h in wfs})]
    if shipped_fixture:
        keys = collections.defaultdict(set)
        for h in wfs:
            name = (record.get(h.get("function_id")) or {}).get("name")
            keys[(h["file"], name)].add(h.get("function_key"))
        if not any(len(k) > 1 for k in keys.values()):
            problems.append("no file holds two same-named functions with a MEM-WFS "
                            "each, so the gate's function_key pairing (I5) went "
                            "untested")
    return problems


def path_mapping(art):
    """Problems with the snapshot run's recorded paths. Empty means it mapped.

    Three ways the mapping goes wrong and one way it goes right. A recorded path
    that names the run directory means the extractor was pointed at the snapshot
    with --root; a path that does not exist in the working tree means whatever
    it names cannot be opened by a person; and a run.json whose repo_root is the
    snapshot means every downstream consumer resolves against a directory that
    is deleted between runs.
    """
    problems = []
    workdir = art["workdir"]
    for record in art["functions"] + art["rules"]:
        rel = record.get("file")
        if not rel:
            continue
        if ".security-review" in rel.split(os.sep):
            problems.append("%s names the run directory" % rel)
        elif not os.path.isfile(os.path.join(workdir, rel)):
            problems.append("%s does not resolve in the working tree" % rel)
    try:
        with open(os.path.join(art["base"], "run.json"), encoding="utf-8") as fh:
            run_json = json.load(fh)
    except (OSError, ValueError) as exc:
        return ["run.json: %s" % exc]
    if os.path.realpath(run_json.get("repo_root") or "") != os.path.realpath(workdir):
        problems.append("run.json repo_root is %r, not the repository"
                        % run_json.get("repo_root"))
    if not (run_json.get("snapshot") or {}).get("id"):
        problems.append("run.json records no snapshot id")
    if not run_json.get("rules_hash"):
        problems.append("run.json records no rules_hash")
    # Every problem, not the first ten. This used to return `[:10]` and the
    # caller printed `len(mapping)` as the total, so a run where all 4000 paths
    # named the snapshot directory announced "SNAPSHOT PATH MAPPING (10)" - a
    # count that disagrees with what produced it, reporting a catastrophe as a
    # handful. Truncation is the printer's job, and it says when it truncates.
    return sorted(set(problems))


def gate(workdir, verbose):
    """The candidate gate, which is the seam between stage 3 and stage 4."""
    path = os.path.join(HERE, "verify_findings.py")
    if not os.path.isfile(path):
        # This used to return True, and main() prints the gate's output only
        # when it fails, so a missing gate tool passed without a word.
        return False, "verify_findings.py is not installed, so nothing checked the gate"
    if not os.path.isdir(os.path.join(workdir, ".security-review", "candidates")):
        return True, ("no candidates/ directory, so stage 3 did not run and the "
                      "gate had nothing to check")
    code, out = run([sys.executable, path, "--root", ".",
                     "--candidates", ".security-review/candidates"], workdir)
    if code != 0 and verbose:
        print(out.rstrip())
    return code == 0, out


def line_agreement(art):
    """Where stage 3 quoted a different line than stage 1 matched. Empty means one line model.

    The fixture is copied once and never edited during the run, so every
    candidate's sink_text is the line stage 1's hit was on, byte for byte after
    stripping. Stage 2 once split lines its own way and broke text_sha256 on
    every real corpus; the fix there was to import stage 1's reader rather than
    to define a line once, so any other reader can still disagree - and a stage
    that splits on more than "\\n" disagrees only below the first form feed or
    U+2028, which a fixture without one never reaches. Stage 3 counts the
    disagreement itself (`sink_text_drift`) and a green run used to ship with it.
    """
    problems = []
    base = art["base"]
    try:
        with open(os.path.join(base, "enrich", "queue.json"), encoding="utf-8") as fh:
            counts = json.load(fh).get("counts") or {}
    except (OSError, ValueError, AttributeError) as exc:
        return ["enrich/queue.json: %s" % exc]
    for key in ("sink_text_drift", "sink_text_unreadable"):
        if counts.get(key):
            problems.append("queue.json counts.%s is %s on a tree nobody edited"
                            % (key, counts[key]))

    hits = {h.get("rule_hit_id"): h for h in art["rules"] if h.get("rule_hit_id")}
    cand_dir = os.path.join(base, "candidates")
    names = sorted(os.listdir(cand_dir)) if os.path.isdir(cand_dir) else []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(cand_dir, name), encoding="utf-8") as fh:
                records = json.load(fh)
        except (OSError, ValueError) as exc:
            problems.append("candidates/%s: %s" % (name, exc))
            continue
        if not isinstance(records, list):
            continue                       # coverage.json and its reconciliation
        for cand in records:
            if not isinstance(cand, dict):
                continue
            cid = cand.get("candidate_id")
            if cand.get("sink_matches_extract") is False:
                problems.append("%s: sink_matches_extract is false" % cid)
            hit = hits.get(cand.get("rule_hit_id"))
            if hit is None:
                continue
            said, quoted = (hit.get("sink_text") or "").strip(), \
                (cand.get("sink_text") or "").strip()
            # Containment rather than equality: a MEM-WFS record quotes the
            # signature, and either side may be the one truncated at 400.
            if said and not (quoted and (said in quoted or quoted in said)):
                problems.append("%s (%s) %s:%s quotes %r; stage 1 matched %r"
                                % (cid, cand.get("rule_id"), cand.get("file"),
                                   cand.get("line"), quoted[:60], said[:60]))
    return problems


# What a stand-in stage 4 writes: a verdict for every dispatched candidate that
# decides nothing, so it needs no evidence and no model, and is still a verdict
# the findings gate reads, queues and hands to run_status.
STAND_IN_VERDICT = {
    "schema_version": 1, "verdict": "NEEDS_HUMAN_REVIEW", "confidence": "low",
    "severity": "low", "title": "smoke test stand-in",
    "unresolved": ["smoke test: no model ran"], "primary_location": "",
    "evidence": [], "gates_evaluated": [],
}


def status_problems(code, doc, dispatched, after, reviewed=None):
    """How run_status.py's answer disagrees with the run it was asked about.

    `after` is "stage 3" or "stage 4". After stage 3 every dispatched candidate
    is a task with no verdict; after the stand-in stage 4 each has one, and each
    is queued for an arbiter that never ran. Neither run is complete, and a
    status that says otherwise is the failure CI cannot see: exit 0 is what a
    clean repository looks like too.
    """
    if not isinstance(doc, dict):
        return ["after %s: run-status.json is unreadable" % after]
    problems = []
    if dispatched:
        want_missing = (["adjudicate", "arbitrate"] if after == "stage 3"
                        else ["arbitrate"])
        want_code = 3
    else:
        want_missing, want_code = [], 0

    def expect(label, got, want):
        if got != want:
            problems.append("after %s: %s is %r, expected %r" % (after, label, got, want))

    expect("the exit code", code, want_code)
    expect("exit_code", doc.get("exit_code"), want_code)
    expect("stages_missing", doc.get("stages_missing"), want_missing)
    expect("incomplete_tasks", doc.get("incomplete_tasks"), dispatched)
    expect("gate_failures", doc.get("gate_failures"), [])
    if reviewed is not None:
        expect("review_candidates", doc.get("review_candidates"), reviewed)
    return problems


def _run_status(workdir, *extra):
    code, out = run([sys.executable, tool("run_status.py"), "--root", ".", "--quiet"]
                    + list(extra), workdir)
    try:
        with open(os.path.join(workdir, ".security-review", "run-status.json"),
                  encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        doc = None
    return code, out, doc


def status(workdir):
    """run_status.py over what the real stages wrote. (passed, problems)

    run_status.py is the only tool whose exit code a CI job acts on, and its own
    selftest builds every input by hand under the writers' field names. This is
    the one place it reads what extract, score, enrich and the findings gate
    actually wrote - so a field renamed on either side fails here instead of
    turning an incomplete run into exit 0.
    """
    base = os.path.join(workdir, ".security-review")
    try:
        with open(os.path.join(base, "enrich", "queue.json"), encoding="utf-8") as fh:
            queue = json.load(fh)
        entries = [e for e in queue["entries"] if not e.get("suppressed")]
        dispatched = queue["counts"]["dispatched"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, ["enrich/queue.json: %s" % exc]

    code, out, doc = _run_status(workdir)
    problems = status_problems(code, doc, dispatched, "stage 3")
    if not dispatched:
        return not problems, problems

    findings = os.path.join(base, "findings")
    os.makedirs(findings, exist_ok=True)
    for entry in entries:
        verdict = dict(STAND_IN_VERDICT, candidate_id=entry["candidate_id"],
                       rule_id=entry["rule_id"])
        with open(os.path.join(findings, entry["candidate_id"] + ".json"), "w",
                  encoding="utf-8") as fh:
            json.dump(verdict, fh)
    # The findings gate writes the arbitration queue run_status reads. Written
    # by hand here it would be the same copy of the field names the selftest
    # already has, which is the gap this closes.
    gcode, gout = run([sys.executable, tool("verify_findings.py"), "--root", ".",
                       "--findings", ".security-review/findings",
                       "--out", ".security-review/arbitration"], workdir)
    if gcode != 0:
        return False, problems + ["the findings gate refused the stand-in verdicts "
                                  "(exit %d): %s" % (gcode, gout.strip()[-600:])]
    code, out, doc = _run_status(workdir)
    problems += status_problems(code, doc, dispatched, "stage 4", reviewed=len(entries))
    ccode, cout = run([sys.executable, tool("run_status.py"), "--root", ".",
                       "--check", "--quiet"], workdir)
    if ccode != 0:
        problems.append("run_status.py --check disagrees with the file it just wrote "
                        "(exit %d): %s" % (ccode, cout.strip()[-300:]))
    return not problems, problems


# The documented suppression, on a function whose only other candidate is its
# MEM-WFS: the shape most suppressions have. It has to stay a C, C++ or Rust
# function - MEM-WFS is derived for no other, and `held` below expects one.
# Stage 3 used to leave that MEM-WFS dispatched over a pair no other candidate
# named, and the candidate gate then failed I5 and refused to dispatch the run.
SUPPRESS_KEY, SUPPRESS_RULE = "src/parse.c::shell::0", "INJ-002"


def suppression(workdir):
    """ledger.py suppress, stage 3 again, then the gate. (passed, problems)"""
    import datetime
    expires = (datetime.date.today() + datetime.timedelta(days=30)).isoformat()
    code, out = run([sys.executable, tool("ledger.py"), "suppress", "--root", ".",
                     "--function-key", SUPPRESS_KEY, "--rule", SUPPRESS_RULE,
                     "--author", "smoke-test", "--expires", expires,
                     "--reason", "smoke test: a suppressed candidate leaves the "
                                 "gate passing"], workdir)
    if code != 0:
        return False, ["ledger.py suppress exited %d: %s" % (code, out.strip()[-300:])]
    code, out = run(stage_args("enrich_candidates.py", workdir), workdir)
    if code != 0:
        return False, ["enrich_candidates.py over the suppression exited %d: %s"
                       % (code, out.strip()[-300:])]
    problems = []
    try:
        with open(os.path.join(workdir, ".security-review", "enrich", "queue.json"),
                  encoding="utf-8") as fh:
            held = sorted(e["rule_id"] for e in json.load(fh)["entries"]
                          if e.get("suppressed"))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, ["enrich/queue.json: %s" % exc]
    if held != sorted([SUPPRESS_RULE, "MEM-WFS"]):
        problems.append("%s %s suppressed %s; the rule and the MEM-WFS that follows it "
                        "were expected" % (SUPPRESS_KEY, SUPPRESS_RULE, held or "nothing"))
    passed, gout = gate(workdir, False)
    if not passed:
        problems.append("the candidate gate refused the run once %s was suppressed: %s"
                        % (SUPPRESS_KEY, gout.strip()[-600:]))
    return not problems, problems


# Every tool that reads the run directory, with the arguments this test already
# runs it with. Each must refuse a run directory the scanned repository ships
# into - exit 7, before reading or writing anything there - and each is driven
# here rather than in its own selftest because the question is where the check
# sits in main(): a gate placed after the first read passes every unit test.
SHIPPED_READERS = (
    ("extract_functions.py", ["--root", ".", "--include", "src/vendor"]),
    ("snapshot.py", ["--root", "."]),
    ("score_functions.py", ["--root", ".", "--backend", "rules", "--strict-k", "1000",
                            "--loose-percent", "100", "--budget", "1000"]),
    ("sweep_secrets.py", ["status", "--root", "."]),
    ("enrich_candidates.py", ["--root", ".", "--budget", "1000", "--no-analyzers"]),
    ("verify_findings.py", ["--root", ".", "--candidates",
                            ".security-review/candidates"]),
    ("ledger.py", ["status", "--root", "."]),
    ("run_status.py", ["--root", ".", "--quiet"]),
    ("export_sarif.py", ["--root", "."]),
    ("upstream_check.py", ["plan", "--root", "."]),
    ("review_run.py", ["next", "--root", "."]),
)
FORGED = ".security-review/scores/scores.jsonl"


def _git(workdir, *args):
    return subprocess.run(                                   # noqa: S603
        ["git", "-c", "user.name=smoke", "-c", "user.email=smoke@test.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull,
         "-c", "core.fsmonitor="]
        + list(args), cwd=workdir, capture_output=True, text=True,
        env=_git_env(workdir))


_FIXTURE_HOME = None


def _git_env(workdir):
    """The environment every fixture git call runs in. No inherited GIT_*: run
    from a git hook, GIT_DIR and GIT_INDEX_FILE would point these calls at the
    caller's repository and commit a forged score into it. And a HOME of the
    fixture's own - a private directory beside the work tree, never the shared
    temporary root - so nobody's .gitconfig or git/attributes takes part."""
    global _FIXTURE_HOME
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    if _FIXTURE_HOME is None:
        _FIXTURE_HOME = tempfile.mkdtemp(prefix="smoke-home-")     # 0700, ours
    env["HOME"] = env["XDG_CONFIG_HOME"] = _FIXTURE_HOME
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    return env


# The four readers that run the gate as a process of their own, and what each
# must do when that process cannot give a clean answer: refuse, exit 7, write
# nothing. (tool, arguments, rules_lib.py stand-in - None for missing.)
SHIM_READERS = (("snapshot.py", []), ("enrich_candidates.py", ["--no-analyzers"]),
                ("ledger.py", ["status"]), ("run_status.py", ["--quiet"]))
SHIM_STANDINS = (("missing", None), ("crashes", "import sys\nsys.exit(1)\n"),
                 ("not JSON", "print('ok')\n"), ("JSON but not an object", "print('[]')\n"))


def shim_fail_closed(workdir):
    """Each shim refuses when the gate cannot run. (passed, problems)"""
    base = os.path.join(workdir, ".security-review")
    before = _listing(base)
    problems = []
    for name, extra in SHIM_READERS:
        for label, standin in SHIM_STANDINS:
            alone = tempfile.mkdtemp(prefix="shim-")
            try:
                shutil.copy(tool(name), os.path.join(alone, name))
                if standin is not None:
                    with open(os.path.join(alone, "rules_lib.py"), "w",
                              encoding="utf-8") as fh:
                        fh.write(standin)
                argv = [sys.executable, os.path.join(alone, name)]
                if name == "ledger.py":
                    argv += extra + ["--root", workdir]
                else:
                    argv += ["--root", workdir] + extra
                code, out = run(argv, workdir)
                if code != 7:
                    problems.append("%s with rules_lib.py %s exited %d, not 7: %s"
                                    % (name, label, code, out.strip()[-200:]))
            finally:
                shutil.rmtree(alone, ignore_errors=True)
    if _listing(base) != before:
        problems.append("a shim that could not run the gate still changed the run "
                        "directory")
    return not problems, problems


def run_dir_record(workdir):
    """Stage 1 recorded that it could not vouch for the run directory, and
    run_status says so. The fixture is a `git init` with nothing committed -
    the unverified state. (passed, problems)"""
    base = os.path.join(workdir, ".security-review")
    problems = []
    try:
        with open(os.path.join(base, "run.json"), encoding="utf-8") as fh:
            record = json.load(fh).get("run_dir")
    except (OSError, ValueError) as exc:
        return False, ["run.json: %s" % exc]
    if record != {"check": "untracked-tree", "committed": [], "shipped": []}:
        problems.append("run.json run_dir is %r, not the untracked-tree record of a "
                        "tree with nothing committed" % (record,))
    _code, _out, doc = _run_status(workdir)
    if not any("run directory's provenance is unverified" in row
               for row in (doc or {}).get("coverage_limitations") or []):
        problems.append("run-status.json does not carry the unverified-provenance "
                        "coverage limitation")
    return not problems, problems


def _listing(base):
    seen = {}
    for top, _dirs, files in os.walk(base):
        for name in files:
            path = os.path.join(top, name)
            info = os.lstat(path)
            seen[os.path.relpath(path, base)] = (info.st_size, info.st_mtime_ns)
    return seen


def shipped(workdir):
    """A run directory the scanned repository commits into. (passed, problems)

    The run so far wrote everything untracked, as a run should. Now the
    repository commits a forged scores.jsonl, as a malicious one would: every
    reader must refuse with exit 7 and leave the run directory as it found it.
    Then the remedy the refusal prints - `git rm -r -f`, commit - must let the
    stages run again.
    """
    if shutil.which("git") is None:
        return True, ["skipped: git is not on PATH"]
    base = os.path.join(workdir, ".security-review")
    with open(os.path.join(workdir, FORGED), "w", encoding="utf-8") as fh:
        fh.write('{"function_id": "forged", "score": 0.0}\n')
    for argv in (["add", "-f", FORGED], ["commit", "-q", "-m", "ship a score"]):
        ran = _git(workdir, *argv)
        if ran.returncode != 0:
            return False, ["git %s failed: %s" % (" ".join(argv), ran.stderr.strip())]
    before = _listing(base)
    problems = []
    for name, extra in SHIPPED_READERS:
        code, out = run([sys.executable, tool(name)] + extra, workdir)
        if code != 7 or "REFUSED" not in out or FORGED not in out:
            problems.append("%s exited %d over a committed %s, not 7 with the refusal: "
                            "%s" % (name, code, FORGED, out.strip()[-300:]))
    if _listing(base) != before:
        changed = sorted(set(_listing(base).items()) ^ set(before.items()))
        problems.append("a refusing reader still changed the run directory: %s"
                        % ", ".join(sorted(set(p for p, _ in changed)))[:300])
    for argv in (["rm", "-r", "-f", "-q", ".security-review/scores"],
                 ["commit", "-q", "-m", "remove the run artifacts"]):
        ran = _git(workdir, *argv)
        if ran.returncode != 0:
            return False, problems + ["git %s failed: %s"
                                      % (" ".join(argv), ran.stderr.strip())]
    code, out = run(stage_args("score_functions.py", workdir), workdir)
    if code != 0:
        problems.append("after the remedy, score_functions.py exited %d: %s"
                        % (code, out.strip()[-300:]))
    return not problems, problems


# --------------------------------------------------------------------------- #
# checking
# --------------------------------------------------------------------------- #

def check(want, art):
    """Compare expectations against what the stages emitted."""
    fired = collections.defaultdict(set)      # (file, line) -> {rule_id}
    skipped = collections.defaultdict(set)
    for hit in art["rules"]:
        key = (hit["file"], hit["line"])
        if hit.get("disposition") == "skipped":
            skipped[key].add(hit["rule_id"])
        else:
            fired[key].add(hit["rule_id"])

    starts = {(f["file"], f["line_start"]): f["name"] for f in art["functions"]}

    missing, wrong_func, met = [], [], 0
    expected_pairs = set()

    for (rel, line), slot in sorted(want.items()):
        for rid in slot["rules"]:
            expected_pairs.add((rel, line, rid))
            if rid in fired[(rel, line)]:
                met += 1
            else:
                where = "skipped" if rid in skipped[(rel, line)] else "not emitted"
                missing.append((rel, line, rid, where))
        for rid in slot["skips"]:
            expected_pairs.add((rel, line, rid))
            if rid in skipped[(rel, line)]:
                met += 1
            elif rid in fired[(rel, line)]:
                missing.append((rel, line, rid,
                                "emitted, but the fixture says its skip_pattern "
                                "should have caught it"))
            else:
                missing.append((rel, line, rid, "the rule did not match at all, "
                                                "so its skip path was never reached"))
        if slot["func"]:
            got = starts.get((rel, line))
            # A definition line carrying the name is the common case; a language
            # whose body opens on the next line is not an error, so the search
            # widens by two lines before it is called a miss.
            if got != slot["func"]:
                for off in (1, 2):
                    if starts.get((rel, line + off)) == slot["func"]:
                        got = slot["func"]
                        break
            if got == slot["func"]:
                met += 1
            else:
                wrong_func.append((rel, line, slot["func"], got))

    unexpected = []
    for (rel, line), rids in fired.items():
        for rid in rids:
            if (rel, line, rid) not in expected_pairs:
                unexpected.append((rel, line, rid))

    return {
        "met": met, "missing": missing, "wrong_func": wrong_func,
        "unexpected": sorted(unexpected),
        "fired": fired, "skipped": skipped,
    }


def language_table(art):
    per = collections.defaultdict(lambda: {"functions": 0, "rules": set(),
                                           "exact": 0, "heuristic": 0, "window": 0})
    for f in art["functions"]:
        row = per[f["language"]]
        row["functions"] += 1
        row[f["extractor"]["confidence"]] += 1
    by_file_lang = {f["file"]: f["language"] for f in art["functions"]}
    for hit in art["rules"]:
        if hit.get("disposition") != "emitted" or hit["rule_id"] == "MEM-WFS":
            continue
        lang = by_file_lang.get(hit["file"]) or hit.get("language") or "?"
        per[lang]["rules"].add(hit["rule_id"])
    return per


def report(res, art, verbose):
    per = language_table(art)
    print()
    print("language    functions   exact/heur/window   distinct rules fired")
    for lang in sorted(per):
        r = per[lang]
        print("  %-9s %6d        %3d/%3d/%3d        %2d  %s"
              % (lang, r["functions"], r["exact"], r["heuristic"], r["window"],
                 len(r["rules"]), " ".join(sorted(r["rules"])) if verbose else ""))

    print()
    print("expectations met: %d" % res["met"])

    if res["wrong_func"]:
        print()
        print("FUNCTION BOUNDARIES (%d):" % len(res["wrong_func"]))
        for rel, line, want, got in res["wrong_func"]:
            print("  %s:%d  expected function %r, extractor resolved %r"
                  % (rel, line, want, got))

    if res["missing"]:
        print()
        print("MISSING (%d) - a rule the fixture says should fire, and did not:"
              % len(res["missing"]))
        by_rule = collections.defaultdict(list)
        for rel, line, rid, why in res["missing"]:
            by_rule[rid].append("%s:%d (%s)" % (rel, line, why))
        for rid in sorted(by_rule):
            print("  %-10s %s" % (rid, "; ".join(by_rule[rid])))

    if res["unexpected"]:
        sample = res["unexpected"][:6]
        print()
        print("unexpected hits: %d (not a failure - stage 1 is recall-biased). e.g. %s"
              % (len(res["unexpected"]),
                 ", ".join("%s %s:%d" % (r, f, l) for f, l, r in sample)))
    print()


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def selftest():
    failures = 0

    def ok(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "a.c")
        with open(src, "w", encoding="utf-8") as fh:
            fh.write("int f(void)        /* EXPECT-FUNC: f */\n"
                     "{\n"
                     "    strcpy(a, b);  /* EXPECT: MEM-001, INJ-001 */\n"
                     "    memcpy(a,b,sizeof(a)); /* EXPECT-SKIP: MEM-002 */\n"
                     "    return 0;      /* nothing here */\n"
                     "}\n")
        want = read_expectations(tmp)
        ok("a two-rule EXPECT parses as two ids",
           sorted(want[("a.c", 3)]["rules"]), ["INJ-001", "MEM-001"])
        ok("EXPECT-FUNC lands in its own slot", want[("a.c", 1)]["func"], "f")
        ok("EXPECT-SKIP is not counted as a rule expectation",
           (want[("a.c", 4)]["skips"], want[("a.c", 4)]["rules"]),
           (["MEM-002"], []))
        ok("a line with no tag has no slot", ("a.c", 5) in want, False)

        # Stage 1 splits the decoded bytes on "\n" and nothing else. A lone
        # carriage return is a line break to a text-mode read, which put the
        # tag below it one line later than the extractor reported the hit.
        with open(os.path.join(tmp, "b.c"), "wb") as fh:
            fh.write(b"/* a lone \r in a comment */\n"
                     b"strcpy(a, b);  /* EXPECT: MEM-001 */\n")
        want = read_expectations(tmp)
        ok("a lone carriage return does not move the tag below it",
           sorted(line for rel, line in want if rel == "b.c"), [2])

    # The comparison, against synthetic artifacts, so every branch is reachable
    # without running the stages.
    art = {
        "functions": [{"file": "a.c", "line_start": 1, "name": "f",
                       "language": "c",
                       "extractor": {"confidence": "exact"}}],
        "rules": [
            {"file": "a.c", "line": 3, "rule_id": "MEM-001",
             "disposition": "emitted", "language": "c"},
            {"file": "a.c", "line": 4, "rule_id": "MEM-002",
             "disposition": "skipped", "language": "c"},
            {"file": "a.c", "line": 9, "rule_id": "INJ-002",
             "disposition": "emitted", "language": "c"},
        ],
    }
    want = {
        ("a.c", 1): {"rules": [], "skips": [], "func": "f"},
        ("a.c", 3): {"rules": ["MEM-001", "INJ-001"], "skips": [], "func": None},
        ("a.c", 4): {"rules": [], "skips": ["MEM-002"], "func": None},
    }
    res = check(want, art)
    ok("a met rule, a met skip and a met function all count", res["met"], 3)
    ok("the unmet rule is reported once",
       [(r, w) for _, _, r, w in res["missing"]], [("INJ-001", "not emitted")])
    ok("a rule firing where nothing was expected is unexpected, not missing",
       res["unexpected"], [("a.c", 9, "INJ-002")])

    # A rule the fixture expects to be skipped, but which was emitted, is a
    # failure with its own wording - that is the skip path regressing, and it
    # reads nothing like a pattern that stopped matching.
    art2 = {"functions": art["functions"],
            "rules": [{"file": "a.c", "line": 4, "rule_id": "MEM-002",
                       "disposition": "emitted", "language": "c"}]}
    res2 = check({("a.c", 4): {"rules": [], "skips": ["MEM-002"], "func": None}}, art2)
    ok("a skip that stopped skipping says so",
       "skip_pattern should have caught it" in res2["missing"][0][3], True)

    res3 = check({("a.c", 4): {"rules": [], "skips": ["MEM-002"], "func": None}},
                 {"functions": art["functions"], "rules": []})
    ok("a skip whose rule stopped matching says THAT instead",
       "never reached" in res3["missing"][0][3], True)

    # The two-line widening for languages whose body opens below the signature.
    art4 = {"functions": [{"file": "b.go", "line_start": 3, "name": "F",
                           "language": "go",
                           "extractor": {"confidence": "exact"}}],
            "rules": []}
    res4 = check({("b.go", 1): {"rules": [], "skips": [], "func": "F"}}, art4)
    ok("a function resolved two lines below its tag still counts",
       (res4["met"], res4["wrong_func"]), (1, []))

    res5 = check({("b.go", 1): {"rules": [], "skips": [], "func": "G"}}, art4)
    ok("a genuinely wrong function name is reported",
       [(w, g) for _, _, w, g in res5["wrong_func"]], [("G", None)])

    # ---- the snapshot path mapping, both directions ---- #
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, ".security-review"))
        with open(os.path.join(tmp, "a.c"), "w", encoding="utf-8") as fh:
            fh.write("int f(void) { return 0; }\n")

        def run_json(doc):
            with open(os.path.join(tmp, ".security-review", "run.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(doc, fh)

        good = {"repo_root": tmp, "snapshot": {"id": "473367cc14267f10"},
                "rules_hash": "85e67df5f1ce7ed4"}
        base = {"base": os.path.join(tmp, ".security-review"), "workdir": tmp,
                "rules": []}
        run_json(good)
        ok("a correctly mapped snapshot run reports no problem",
           path_mapping(dict(base, functions=[{"file": "a.c"}])), [])

        # The failure this mode exists to catch: --root pointed at the snapshot.
        ok("a path naming the run directory is caught",
           path_mapping(dict(base, functions=[
               {"file": os.path.join(".security-review", "snapshot", "a.c")}])),
           [os.path.join(".security-review", "snapshot", "a.c")
            + " names the run directory"])
        ok("a path that no human could open is caught",
           path_mapping(dict(base, functions=[{"file": "gone.c"}])),
           ["gone.c does not resolve in the working tree"])

        run_json(dict(good, repo_root=os.path.join(tmp, ".security-review",
                                                   "snapshot")))
        ok("a repo_root pointing at the snapshot is caught",
           [p.split(" is ")[0] for p in
            path_mapping(dict(base, functions=[{"file": "a.c"}]))],
           ["run.json repo_root"])

        run_json({"repo_root": tmp})
        ok("missing provenance is caught",
           path_mapping(dict(base, functions=[{"file": "a.c"}])),
           ["run.json records no rules_hash", "run.json records no snapshot id"])

        # A wholesale mapping failure must be reported at its real size. The
        # count in the banner is len() of what this returns, so returning a
        # truncated list turned 25 broken paths into "(10)".
        run_json(good)
        ok("every broken path is returned, not the first ten",
           len(path_mapping(dict(base, functions=[
               {"file": "missing-%02d.c" % i} for i in range(25)]))), 25)

    # ---- MEM-WFS: C, C++ and Rust only, one per function, the keyed pair ---- #
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "extract"))

        def coverage(languages):
            with open(os.path.join(tmp, "extract", "coverage.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"rules": [{"rule_id": "MEM-WFS", "languages": languages}]},
                          fh)

        def fn(fid, path, name, language):
            return {"function_id": fid, "file": path, "name": name,
                    "language": language}

        def hit(rid, f):
            return {"rule_id": rid, "file": f["file"], "function_id": f["function_id"],
                    "function_key": "%s::%s::%s" % (f["file"], f["name"],
                                                    f["function_id"][-1]),
                    "disposition": "emitted"}
        fns = [fn("F0", "a.c", "shell", "c"), fn("F1", "r.cpp", "load", "cpp"),
               fn("F2", "r.cpp", "load", "cpp"), fn("F3", "a.py", "run", "python")]
        good_hits = ([hit("INJ-002", f) for f in fns]
                     + [hit("MEM-WFS", f) for f in fns[:3]])
        shape = {"base": tmp, "functions": fns, "rules": good_hits}
        coverage(["c", "cpp", "rust"])
        ok("one MEM-WFS per C, C++ and Rust function with a candidate, none on "
           "Python, and a same-named pair, is the shape", wfs_shape(shape), [])
        ok("a MEM-WFS on a Python function is one stage 1 should not have written",
           wfs_shape(dict(shape, rules=good_hits + [hit("MEM-WFS", fns[3])])),
           ["MEM-WFS on a.py::run::3, a python function: the rule runs on c, cpp, "
            "rust only"])
        ok("a C function with a candidate and no MEM-WFS is a pass that never ran",
           wfs_shape(dict(shape, rules=good_hits[:4] + good_hits[5:])),
           ["F0 produced a candidate and got no MEM-WFS"])
        unpaired = dict(shape, functions=fns[:2] + [fn("F2", "r.cpp", "save", "cpp")]
                        + fns[3:])
        ok("the shipped fixture has to keep a same-named pair, or I5's keying "
           "goes untested", [p.split(",")[0] for p in wfs_shape(unpaired)],
           ["no file holds two same-named functions with a MEM-WFS each"])
        ok("a fixture of someone else's need not", wfs_shape(unpaired, False), [])
        os.remove(os.path.join(tmp, "extract", "coverage.json"))
        ok("a run with no MEM-WFS row to read its languages from says so",
           [p.split(":")[0] for p in wfs_shape(shape)],
           ["extract/coverage.json holds no MEM-WFS row with its languages"])

    # ---- a missing tool is exit 2, not a skipped stage ---- #
    import contextlib as _contextlib
    import io as _io
    with tempfile.TemporaryDirectory() as tmp:
        ok("every tool a run drives is reported missing from an empty directory",
           [os.path.basename(p) for p in missing_tools(False, tmp)],
           ["enrich_candidates.py", "extract_functions.py", "ledger.py",
            "run_status.py", "score_functions.py", "verify_findings.py"])
        ok("--snapshot needs snapshot.py as well",
           "snapshot.py" in [os.path.basename(p) for p in missing_tools(True, tmp)], True)
        with open(os.path.join(tmp, "a.c"), "w", encoding="utf-8") as fh:
            fh.write("strcpy(a, b);  /* EXPECT: MEM-001 */\n")
        # The end-to-end form of the same claim. A bundle that had lost stage 3
        # and the gate tool used to print one SKIPPED line and "smoke test: ok".
        global HERE
        saved, HERE = HERE, tmp
        try:
            with _contextlib.redirect_stderr(_io.StringIO()) as err:
                code = main(["--fixture", tmp])
            ok("main() returns 2 when the tools it drives are not installed",
               code, 2)
            ok("...and names each one it could not find",
               err.getvalue().count("tool not installed:"), 6)
        finally:
            HERE = saved
    ok("the shipped bundle is missing none of them", missing_tools(True), [])

    # ---- run_status over what the stages wrote ---- #
    good3 = {"exit_code": 3, "stages_missing": ["adjudicate", "arbitrate"],
             "incomplete_tasks": 95, "gate_failures": []}
    ok("an unfinished run read as unfinished is no problem",
       status_problems(3, good3, 95, "stage 3"), [])
    # The failure this exists for: a field renamed on one side of the seam, so
    # the reader sees no tasks and calls a run nobody finished complete.
    complete = {"exit_code": 0, "stages_missing": [], "incomplete_tasks": 0,
                "gate_failures": []}
    ok("an unfinished run reported complete is caught, field by field",
       len(status_problems(0, complete, 95, "stage 3")), 4)
    good4 = dict(good3, stages_missing=["arbitrate"], review_candidates=95)
    ok("after the stand-in stage 4 only the arbiter is outstanding",
       status_problems(3, good4, 95, "stage 4", reviewed=95), [])
    ok("verdict files run_status did not count are caught",
       status_problems(3, dict(good4, review_candidates=0), 95, "stage 4",
                       reviewed=95),
       ["after stage 4: review_candidates is 0, expected 95"])
    ok("a status file that did not parse is a problem, not a pass",
       status_problems(3, None, 95, "stage 3"),
       ["after stage 3: run-status.json is unreadable"])

    # ---- one line model across the stages ---- #
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, ".security-review")
        os.makedirs(os.path.join(base, "enrich"))
        os.makedirs(os.path.join(base, "candidates"))

        def lay(drift, quoted, matches=True):
            with open(os.path.join(base, "enrich", "queue.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"counts": {"sink_text_drift": drift,
                                      "sink_text_unreadable": 0}}, fh)
            with open(os.path.join(base, "candidates", "memory-safety.json"), "w",
                      encoding="utf-8") as fh:
                json.dump([{"candidate_id": "CAND-0001", "rule_id": "MEM-001",
                            "file": "a.c", "line": 6, "rule_hit_id": "RH-000001",
                            "sink_text": quoted,
                            "sink_matches_extract": matches}], fh)
            with open(os.path.join(base, "candidates", "coverage.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"rules": []}, fh)
            return {"base": base, "rules": [{"rule_hit_id": "RH-000001",
                                             "sink_text": "strcpy(d, s);"}]}

        ok("the same line quoted by both stages is no problem",
           line_agreement(lay(0, "strcpy(d, s);")), [])
        # What a page break did to a GNU-style file: every hit below it quoted
        # the line before, and the run shipped green.
        ok("a drift count on an unedited tree is a problem",
           line_agreement(lay(2, "strcpy(d, s);")),
           ["queue.json counts.sink_text_drift is 2 on a tree nobody edited"])
        ok("stage 3's own mismatch flag is a problem",
           len(line_agreement(lay(0, "strcpy(d, s);", matches=False))), 1)
        ok("a different line quoted is caught even when nothing counted it",
           len(line_agreement(lay(0, "{"))), 1)
        ok("an empty quote is not 'contained' in the line stage 1 matched",
           len(line_agreement(lay(0, ""))), 1)

    # ---- every tool must read the same on a Python newer than the author's ---- #
    #
    # Two defects, one cause: the author always runs the older interpreter, so
    # the author is the one person who cannot see either.
    #
    #   INVALID escape (\s, \d, \w ...) - DeprecationWarning on 3.11, hidden by
    #   default; SyntaxWarning on 3.12; SyntaxError from 3.14. One shipped.
    #
    #   VALID but wrong escape - never warns on ANY version, because \b really
    #   is backspace and \udce9 really is a lone surrogate. A docstring quoting
    #   the regex `\bcalloc` stores U+0008 + "calloc", so the documented
    #   pattern is not the pattern; three shipped. One was worse than cosmetic:
    #   snapshot.py quoted "\udce9" while explaining a surrogate bug, which
    #   made the file uncompilable on 3.13 and 3.14 ("surrogates not allowed")
    #   while compiling fine on 3.12. No escape-sequence check in any Python
    #   would have found any of them, so this tests what the escape PRODUCES.
    #
    # Tokenizing rather than compiling, because compile() is measurably weaker:
    # it emits ONE warning per string literal however many escapes it holds, and
    # on 3.11 it reports the literal's opening line rather than the escape's -
    # which is why the same defect read as line 1530 here and 1538 to a user on
    # 3.12. compile() still runs below as a second opinion.
    import io as _io
    import glob as _glob
    import tokenize as _tokenize
    import warnings as _warnings
    import unicodedata as _unicodedata

    valid = set("\n\\'\"abfnrtv01234567xNuU")
    tools_dir = os.path.dirname(os.path.abspath(__file__))
    paths = sorted(_glob.glob(os.path.join(tools_dir, "**", "*.py"),
                              recursive=True))

    def _decoded(text, i):
        """The character `text[i:]`'s escape produces, or None if not one."""
        simple = {"a": "\a", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
        nxt = text[i + 1]
        if nxt in simple:
            return simple[nxt]
        width = {"x": 2, "u": 4, "U": 8}.get(nxt)
        if width is None:
            return None
        digits = text[i + 2:i + 2 + width]
        if len(digits) < width:
            return None
        try:
            return chr(int(digits, 16))
        except ValueError:
            return None

    invalid, corrupting = [], []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        where = os.path.basename(path)
        try:
            tokens = list(_tokenize.generate_tokens(_io.StringIO(source).readline))
        except (_tokenize.TokenError, SyntaxError) as exc:
            invalid.append("%s: will not tokenise: %s" % (where, exc))
            continue
        for tok in tokens:
            if tok.type != _tokenize.STRING:
                continue
            text = tok.string
            prefix = text[:len(text) - len(text.lstrip("rbfuRBFU"))].lower()
            if "r" in prefix:                  # raw: every backslash is literal
                continue
            body = text.lstrip("rbfuRBFU")
            docish = body.startswith('"""') or body.startswith("'''")
            i, line = 0, tok.start[0]
            while i < len(text) - 1:
                if text[i] != "\\":
                    line += text[i] == "\n"
                    i += 1
                    continue
                if text[i + 1] not in valid:
                    invalid.append("%s:%d \\%s" % (where, line, text[i + 1]))
                elif docish and "b" not in prefix:
                    produced = _decoded(text, i)
                    if produced and _unicodedata.category(produced).startswith("C"):
                        corrupting.append(
                            "%s:%d \\%s produces %r, a control or surrogate "
                            "character, not the token as written"
                            % (where, line, text[i + 1], produced))
                i += 2

    ok("no tool carries an invalid escape (SyntaxError from 3.14)", invalid, [])
    ok("no docstring silently stores a control or surrogate character",
       corrupting, [])

    compiled = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        with _warnings.catch_warnings(record=True) as caught:
            _warnings.simplefilter("always")
            try:
                compile(source, path, "exec")
            except SyntaxError as exc:
                compiled.append("%s: %s" % (os.path.basename(path), exc))
                continue
            for entry in caught:
                if "escape sequence" in str(entry.message):
                    compiled.append(os.path.basename(path))
    ok("and compile() agrees there is nothing left to find", compiled, [])

    print()
    print("selftest: %d failure(s)" % failures)
    return 1 if failures else 0


# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Run the deterministic stages over a tagged fixture and "
                    "check which rules fired.")
    p.add_argument("--fixture", default=FIXTURE,
                   help="tree carrying EXPECT tags (default: the shipped fixture)")
    p.add_argument("--keep", action="store_true",
                   help="leave the run directory in place and print its path")
    p.add_argument("--coverage", action="store_true",
                   help="print the per-language summary and exit 0 regardless")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="show each stage's output and the rules fired per language")
    p.add_argument("--fallback", action="store_true",
                   help="run stage 1 with --no-tree-sitter, exercising the stdlib "
                        "boundary walk that an install without a grammar gets")
    p.add_argument("--snapshot", action="store_true",
                   help="freeze the fixture with snapshot.py first and extract "
                        "from it, checking that every recorded path still "
                        "resolves in the working tree")
    p.add_argument("--selftest", action="store_true",
                   help="check this script's own comparison logic and exit")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()

    if not os.path.isdir(args.fixture):
        print("fixture not found: %s" % args.fixture, file=sys.stderr)
        return 2

    want = read_expectations(args.fixture)
    if not want:
        print("no EXPECT tags found under %s" % args.fixture, file=sys.stderr)
        return 2

    missing = missing_tools(args.snapshot)
    if missing:
        for path in missing:
            print("tool not installed: %s" % path, file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="smoke-")
    try:
        try:
            art, why = drive(args.fixture, workdir, args.verbose, args.fallback,
                             args.snapshot)
        except Missing as exc:
            print("tool not installed: %s" % exc, file=sys.stderr)
            return 2
        if art is None:
            print("stage failed: %s" % why, file=sys.stderr)
            return 1

        res = check(want, art)
        report(res, art, args.verbose)

        mapping = path_mapping(art) if args.snapshot else []
        if mapping:
            print()
            print("SNAPSHOT PATH MAPPING (%d) - stage 1 read the snapshot but "
                  "did not record paths relative to the repository:"
                  % len(mapping))
            for line in mapping[:10]:
                print("  %s" % line)
            if len(mapping) > 10:
                print("  ... and %d more" % (len(mapping) - 10))
        elif args.snapshot:
            print("snapshot: %d recorded path(s) all resolve in the working tree"
                  % len({r["file"] for r in art["functions"] if r.get("file")}))

        wfs_problems = wfs_shape(art, os.path.realpath(args.fixture)
                                 == os.path.realpath(FIXTURE))
        if wfs_problems:
            print()
            print("MEM-WFS (%d) - stage 1's whole-function derivation is not what "
                  "its rule says:" % len(wfs_problems))
            for line in wfs_problems[:10]:
                print("  %s" % line)

        drift = line_agreement(art)
        if drift:
            print()
            print("LINE MODEL (%d) - a later stage quoted a different line than "
                  "stage 1 matched, on a tree nobody edited:" % len(drift))
            for line in drift[:10]:
                print("  %s" % line)
            if len(drift) > 10:
                print("  ... and %d more" % (len(drift) - 10))

        passed, out = gate(workdir, args.verbose)
        if not passed:
            print("THE CANDIDATE GATE REFUSED THE RUN. That is the seam between "
                  "stage 3 and stage 4, and it failing here means the artifacts "
                  "disagree with each other rather than with the fixture.")
            if not args.verbose:
                print(out.rstrip()[:2000])

        # Only over a run the gate accepted: a refused gate is already the
        # failure, and run_status would only repeat it as exit 4.
        try:
            status_ok, status_out = status(workdir) if passed else (True, [])
        except Missing as exc:
            print("tool not installed: %s" % exc, file=sys.stderr)
            return 2
        if not status_ok:
            print()
            print("RUN STATUS (%d) - run_status.py, the exit code CI acts on, "
                  "misread what the stages wrote:" % len(status_out))
            for line in status_out:
                print("  %s" % line)
        elif passed:
            print("run status: run_status.py agreed with what the stages wrote, "
                  "before and after a stand-in stage 4")

        # Last, because it re-runs stage 3 over everything above.
        try:
            held_ok, held_out = suppression(workdir) if passed else (True, [])
        except Missing as exc:
            print("tool not installed: %s" % exc, file=sys.stderr)
            return 2
        if not held_ok:
            print()
            print("SUPPRESSION (%d) - a ledger suppression broke the run it was "
                  "recorded against:" % len(held_out))
            for line in held_out:
                print("  %s" % line)
        elif passed:
            print("suppression: %s %s suppressed with its MEM-WFS, and the gate "
                  "still passes" % (SUPPRESS_KEY, SUPPRESS_RULE))

        # Before anything is committed: the unverified record, and the shims
        # refusing when the gate cannot run.
        try:
            record_ok, record_out = run_dir_record(workdir) if passed else (True, [])
            shim_ok, shim_out = shim_fail_closed(workdir) if passed else (True, [])
        except Missing as exc:
            print("tool not installed: %s" % exc, file=sys.stderr)
            return 2
        for ok, out, what in ((record_ok, record_out, "RUN-DIRECTORY RECORD"),
                              (shim_ok, shim_out, "GATE SHIMS")):
            if not ok:
                print()
                print("%s (%d):" % (what, len(out)))
                for line in out:
                    print("  %s" % line)
        if passed and record_ok and shim_ok:
            print("run directory: stage 1 recorded it unverified, run_status said "
                  "so, and all %d gate shims refused when the gate could not run"
                  % len(SHIM_READERS))

        # Last of all: it commits into the fixture's repository.
        try:
            ship_ok, ship_out = shipped(workdir) if passed else (True, [])
        except Missing as exc:
            print("tool not installed: %s" % exc, file=sys.stderr)
            return 2
        if not ship_ok:
            print()
            print("SHIPPED RUN DIRECTORY (%d) - a reader trusted run-directory "
                  "content the scanned repository committed:" % len(ship_out))
            for line in ship_out:
                print("  %s" % line)
        elif passed:
            print("shipped: %s" % ("; ".join(ship_out) if ship_out else
                  "all %d readers refused a committed %s with exit 7 and wrote "
                  "nothing, and the printed remedy let the stages run again"
                  % (len(SHIPPED_READERS), FORGED)))

        if args.coverage:
            return 0
        bad = (res["missing"] or res["wrong_func"] or not passed or mapping or drift
               or wfs_problems
               or not status_ok or not held_ok or not ship_ok or not record_ok
               or not shim_ok)
        print("smoke test: %s" % ("FAILED" if bad else "ok"))
        return 1 if bad else 0
    finally:
        if args.keep:
            print("run directory kept at %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)
        if _FIXTURE_HOME is not None:
            shutil.rmtree(_FIXTURE_HOME, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
