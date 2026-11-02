#!/usr/bin/env python3
"""
run_status.py - the one answer to "how did the run go?", for whatever has to act
on it.

Every tool in this skill has exit codes of its own. `verify_findings.py`
returns 1 when it could not run and 2, 3, 4 and 5 for its four gates, the
highest one when several fail; `export_sarif.py` returns 2 when there is nothing
adjudicated; `snapshot.py` returns 5 when a re-hash disagrees; `smoke_test.py`
returns 2 when a tool is missing. A CI job wrapping the pipeline has to guess
which of those means "stop the build", and the guess everybody reaches for is
`exit 0 means fine`.

That guess fails in one direction, and it is the direction this whole bundle
exists to refuse. A run that stopped after stage 3 has its candidates dispatched,
no verdicts, and every artifact on disk parsing cleanly. Count the findings in it
and you get zero. Zero findings is also what a clean repository looks like. The
contract already has a name for that confusion and a field to stop it -
`not_selected_is_not_a_clean_bill`, §6 - but it stops it only INSIDE `REPORT.md`,
and the report gate only fires when somebody wrote a report. A run that never got
that far had nobody counting at all: an incomplete run and a clean run were the
same observation from outside.

So this writes one file, `.security-review/run-status.json`, computed from
artifacts and never from prose, and returns one exit code under a stated
precedence:

    setup failure > incomplete analysis > policy findings > no policy findings

The order is the entire point. A run that is BOTH incomplete AND has findings
exits 3, not 1. Getting that backwards is not a rounding error: "completed, with
findings" is a claim about the part nobody looked at as much as about the part
somebody did, and 1 is the code a CI job is most likely to have a "known issues"
exception for.

What it will not do is read prose. Every number here comes from an artifact -
`run.json`'s `stages_completed`, the verdict files under `findings/`, the ARB
records under `arbitration/`, `scores/operating-point.json`,
`enrich/dependencies.jsonl`, `secrets/inventory.json` (entries with
`is_finding: true`, contract §4a, and no others), `enrich/analyzer-runs.json` -
and an artifact that does not parse, or parses into a shape its writer never
emits (JSON `null`, an array where an object belongs, a queue with no
`entries`), is a setup failure rather than a zero, because a queue file read as
"no entries" is a run read as "no candidates" is a build read as green.

A verdict or ARB record counts only when it belongs to THIS run's candidate of
the same id: the same `rule_id` - or, for a finding this run's precheck flagged
`rule_id_mismatch`, either the stamped rule or the validator's - and not
locating its `sink`, or its reading list, only in another file. Candidate ids
restart at CAND-0001 on every stage-3 run, so a verdict a previous run left in
`findings/` has the name of a new candidate and says nothing about it. One that
does not match adjudicates nothing and is a gate failure naming it.

`coverage_limitations` is populated, not empty-by-default. An empty list is a
claim, and on almost every real run it is a false one.

`--check` recomputes the file and refuses to agree with itself: a
`run-status.json` that somebody edited, or that predates the artifacts beside it,
is exactly the drift this file was written to remove.

`--out` may name a path outside the scanned tree, or one under its
`.security-review/`, and nothing else (contract §9 rule 2). Under the run
directory a symlink is refused rather than written through (§1): the directory
lives in the tree under review, which is the one tree this tool cannot trust.

Stdlib only. Python 3.8+.

Exit codes
  The run's own status, per the policy above - these are what a wrapper reads:
    0  required analysis completed; nothing blocking under policy
    1  completed, with findings or candidates requiring action
    3  required analysis incomplete
    4  setup, configuration or gate failure
  This tool's own, deliberately outside that set so a wrapper cannot mistake one
  for a verdict about the run:
    2  --check: run-status.json disagrees with the artifacts, or there is none
    5  --selftest failed, or this tool could not run at all
    7  refused before reading anything: the scanned repository commits files
       under .security-review/ other than .gitignore and ledger/, git cannot
       say whether it does, or --root is this installed skill or an old copy of the scanner
       (rules_lib.run_dir_gate) - the run directory is not the run's own, so
       nothing in it is reported on

Usage
  python3 run_status.py --root .
  python3 run_status.py --root . --check
  python3 run_status.py --root . --out /tmp/run-status.json --quiet
  python3 run_status.py --selftest
"""

import argparse
import collections
import datetime
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile

SCHEMA_VERSION = 1
TOOL_VERSION = "1.0.0"
TOOL_NAME = "run_status.py"

RUN_DIR = ".security-review"
STATUS_NAME = "run-status.json"

# The run's status, as the research review defines it. 0/1/3/4 are the wrapper
# contract and must not be reused for anything this tool thinks about itself.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 3
EXIT_SETUP = 4
# This tool's own. 2 is unused by the policy above, which is why --check may have
# it: a drifted status file is a fact about the file, not a verdict on the run,
# and returning 1 for it would tell a wrapper the run had findings.
EXIT_DRIFT = 2
EXIT_TOOL = 5

# The stages a run must reach before "complete" means anything.
#
# Only the first three are ever written into `run.json.stages_completed` -
# extract, score and enrich append their own name, and stages 4 and 5 are a model
# and a person, so nothing appends theirs. Reading only that list would therefore
# call a run "complete" the moment stage 3 finished, which is the exact reading
# this tool exists to stop. The last two are established from artifacts instead:
# a candidate that was dispatched and has no verdict, or a finding the precheck
# queued and the arbiter never adjudicated, is a task that did not reach a
# terminal state (contract §7.2 of the research review; §1 here).
RECORDED_STAGES = ("extract", "score", "enrich")
DERIVED_STAGES = ("adjudicate", "arbitrate")
STAGES = RECORDED_STAGES + DERIVED_STAGES

# Verdicts, and which bucket each one lands in.
#
# ACCEPTED_RISK gets its own count and is NOT folded into `dismissed`. The whole
# reason that verdict exists is so "real, and knowingly accepted" is not filed as
# "not a bug" - folding it into dismissed would undo that in the one artifact a
# machine reads. It is also not folded into `confirmed_findings`, because exiting
# 1 on a risk somebody already accepted is how a gate gets switched off.
CONFIRMED_VERDICTS = ("VULNERABLE",)
REVIEW_VERDICTS = ("NEEDS_HUMAN_REVIEW",)
DISMISSED_VERDICTS = ("NOT_VULNERABLE",)
ACCEPTED_VERDICTS = ("ACCEPTED_RISK",)
KNOWN_VERDICTS = (CONFIRMED_VERDICTS + REVIEW_VERDICTS
                  + DISMISSED_VERDICTS + ACCEPTED_VERDICTS)

# `enrich/analyzer-runs.json` classifies every SARIF run it ingested. `failed`
# and `partial` both mean the analysis did not finish, and the research review's
# stage 2 gate is explicit that "missing or partial analysis cannot become a
# clean result" - so both count as a tool failure and both push the run to
# incomplete. `unknown` does NOT: most tools write no invocation block at all, so
# unknown is the common case, and rounding it up to a failure would fail every
# run that ever ran semgrep. It is a coverage limitation instead, which is what
# "we do not know whether it finished" actually is.
ANALYZER_INCOMPLETE = ("failed", "partial")

# The four gates `verify_findings.py` runs, and where each one leaves its record.
# A gate that recorded problems is a gate failure, and a gate failure outranks
# everything else in the precedence: the artifacts behind the counts are not
# trustworthy as an account of the run, so reporting the counts as if they were
# is worse than reporting nothing.
PRECHECK_PROBLEM_FILES = (
    ("candidates", os.path.join("arbitration", "coverage-precheck.json")),
    ("arbitration", os.path.join("arbitration", "arbitration-precheck.json")),
    ("report", os.path.join("arbitration", "report-precheck.json")),
)
# `precheck.json` has no top-level `problems` list - its problems hang off each
# finding, and only some codes fail the gate. These are the ones `run_findings()`
# turns into a non-zero exit; the rest are reported and survive, so counting them
# here would fail runs that tool passes.
FINDINGS_GATE_CODES = ("schema_invalid", "unparseable", "rule_id_unrecoverable",
                       "templated_dismissal")

# Source extensions this skill's extractor has no parser for.
#
# This is an ALLOWLIST and not "every extension rules_lib.LANGUAGE_BY_EXT does not
# know", which is what `extract-report.json.unsupported_extensions` actually
# holds. That file counts `.md`, `.json`, `.lock` and `.png` too, and a coverage
# section that reports a README as an unscanned language every single run teaches
# its reader to skip the section - which costs more than the occasional miss here
# does. Naming a language the extractor cannot read is a claim, and a claim comes
# from a list somebody wrote.
UNSUPPORTED_SOURCE = {
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".swift": "Swift",
    ".scala": "Scala", ".sc": "Scala",
    ".m": "Objective-C or MATLAB", ".mm": "Objective-C++",
    ".pl": "Perl", ".pm": "Perl",
    ".lua": "Lua",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ksh": "shell",
    ".ps1": "PowerShell", ".psm1": "PowerShell",
    ".dart": "Dart",
    ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".hrl": "Erlang",
    ".hs": "Haskell",
    ".zig": "Zig",
    ".sol": "Solidity",
    ".vb": "Visual Basic",
    ".jl": "Julia",
    ".groovy": "Groovy", ".gradle": "Groovy",
    ".clj": "Clojure", ".cljs": "Clojure",
    ".ml": "OCaml", ".mli": "OCaml",
    ".fs": "F#", ".fsx": "F#",
    ".nim": "Nim",
    ".cr": "Crystal",
    ".d": "D",
    ".adb": "Ada", ".ads": "Ada",
    ".pas": "Pascal",
    ".f90": "Fortran", ".f95": "Fortran", ".f03": "Fortran",
    ".asm": "assembly", ".s": "assembly",
    ".v": "Verilog", ".sv": "SystemVerilog",
    ".vhd": "VHDL", ".vhdl": "VHDL",
    ".sql": "SQL",
    ".tf": "Terraform",
}


class Refused(Exception):
    """The run cannot be read at all, and guessing at it would be worse."""


# --------------------------------------------------------------------------- #
# reading the run
# --------------------------------------------------------------------------- #
#
# Every read here has to distinguish three things that a naive `try: json.load`
# collapses into one: the artifact is absent (the stage did not run), the
# artifact is present and unparseable (something is broken), and the artifact is
# present and empty (the stage ran and found nothing). The second and third look
# identical to a caller that gets `{}` back, and reading a broken queue file as
# "no candidates" is how a broken run reports a clean repository.

def _load(path):
    """(object, error_sentence). Both are None only for an absent file.

    A file holding JSON `null` parses, and `json.load` hands back None - the
    same None an absent file gets. Returned as it came, a queue that is on disk
    and says `null` was read as a stage that never ran, and an inventory that
    says `null` produced "the sweep did not run" about a file somebody wrote. No
    writer in this skill emits a bare null, so it is an error with a sentence.
    """
    if not os.path.isfile(path):
        return None, None
    try:
        with open(path, encoding="utf-8") as fh:
            obj = json.load(fh)
    except ValueError as exc:
        return None, "%s does not parse as JSON (%s)" % (path, exc)
    except OSError as exc:
        return None, "%s could not be read (%s)" % (path, exc)
    if obj is None:
        return None, ("%s is on disk and holds JSON null, which no stage writes: "
                      "read as absent it would say the stage never ran, and read "
                      "as empty it would say the stage found nothing" % path)
    return obj, None


def _load_jsonl(path):
    """(rows, error_sentence). A malformed LINE is an error, not a skipped row:
    dropping it quietly is how a dependency finding stops being counted.

    Every row goes through `_schema_guard` for the same reason the object reads
    do. A `.jsonl` record carries `schema_version` exactly as a `.json` one does,
    and contract §0's refusal is about the record, not about the file extension:
    counting a row written by a newer stage is guessing at it.
    """
    if not os.path.isfile(path):
        return [], None
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for number, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    return [], ("%s line %d does not parse as JSON"
                                % (path, number))
                _schema_guard("%s line %d" % (path, number), row)
                rows.append(row)
    except OSError as exc:
        return [], "%s could not be read (%s)" % (path, exc)
    return rows, None


def _schema_guard(path, obj):
    """Contract §0: a tool reading a higher schema_version than it knows must
    refuse, not guess. Refusing here means the whole status is refused - a
    status file built by half-understanding its inputs is worse than none."""
    if not isinstance(obj, dict):
        return
    declared = obj.get("schema_version")
    if isinstance(declared, bool) or not isinstance(declared, int):
        return
    if declared > SCHEMA_VERSION:
        raise Refused(
            "%s declares schema_version %d; %s knows %d. Contract §0: a tool "
            "reading a higher schema_version than it knows must refuse, not "
            "guess." % (path, declared, TOOL_NAME, SCHEMA_VERSION))


def _dir_json(directory, keep):
    """{candidate_id: record} for every JSON file in a directory, plus errors."""
    out, errors = {}, []
    if not os.path.isdir(directory):
        return out, errors
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json") or not keep(name):
            continue
        path = os.path.join(directory, name)
        obj, err = _load(path)
        if err:
            errors.append(err)
            continue
        _schema_guard(path, obj)
        if isinstance(obj, dict) and obj.get("candidate_id"):
            out[obj["candidate_id"]] = obj
        else:
            errors.append("%s carries no candidate_id, so nothing can be joined "
                          "to it" % path)
    return out, errors


# The tables collect() reads, and the shape each one's writer always emits:
# (relpath, key in the returned dict, ((field, type, required), ...)). Every
# list field here holds objects in its writer, so a row that is not one is
# wrong too.
#
# These were read `or {}` and then swapped for {} when they were not an object,
# with nothing recorded. So `null`, `[]`, `{"schema_version": 1}` and an
# `entries` that is an object all became "stage 3 dispatched nothing", and a run
# with 95 candidates and no verdicts exited 0; `runs` keyed by analyzer name hid
# a failed semgrep the same way. The module docstring always said an artifact
# read as "no entries" is a build read as green - the check only ever ran for
# JSON that did not parse. `counts` is not required: enrich writes it, but a
# queue without it can still be read entry by entry, and `queue_problems` only
# reconciles it when it is there.
ARTIFACT_SHAPES = (
    (os.path.join("enrich", "queue.json"), "queue",
     (("entries", list, True), ("counts", dict, False),
      ("suppressions_stale", list, False),
      ("suppressions_expired", list, False),
      ("suppressions_unusable", list, False),
      ("suppressions_ignored", list, False),
      ("selected_without_candidate", list, False))),
    (os.path.join("enrich", "analyzer-runs.json"), "analyzer_runs",
     (("runs", list, True),)),
    (os.path.join("scores", "operating-point.json"), "operating_point", ()),
    (os.path.join("extract", "extract-report.json"), "extract_report", ()),
    (os.path.join("arbitration", "queue.json"), "arb_queue",
     (("queue", list, True),)),
)


def artifact_shape_problem(relpath, obj, fields):
    """One sentence saying how `obj` is not what its writer emits, or None."""
    path = "%s/%s" % (RUN_DIR, relpath.replace(os.sep, "/"))
    if not isinstance(obj, dict):
        return ("%s is on disk and is a JSON %s, not the object its writer "
                "emits: read as an empty one it would report a stage that ran "
                "as a stage that found nothing." % (path, _json_type(obj)))
    for field, kind, required in fields:
        if field not in obj:
            if required:
                return ("%s is on disk and has no `%s`, which its writer always "
                        "emits: read as empty it would report a stage that ran "
                        "as a stage that found nothing." % (path, field))
            continue
        value = obj[field]
        if not isinstance(value, kind):
            return ("%s is on disk and its `%s` is a JSON %s where %s belongs: "
                    "read as empty it would report a stage that ran as a stage "
                    "that found nothing."
                    % (path, field, _json_type(value),
                       "an array" if kind is list else "an object"))
        if kind is list:
            bad = [n for n, row in enumerate(value) if not isinstance(row, dict)]
            if bad:
                return ("%s is on disk and %d row(s) of its `%s` are not objects "
                        "(index %s): a row this tool cannot read is one it would "
                        "silently not count."
                        % (path, len(bad), field,
                           ", ".join(str(n) for n in bad[:5])))
    return None


def _json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def collect(root):
    """Everything run_status reads, with every read failure kept rather than
    swallowed. Raises Refused when there is nothing legible to report on."""
    base = os.path.join(root, RUN_DIR)
    if not os.path.isdir(base):
        raise Refused(
            "%s does not exist: there is no run here to report on. A missing "
            "run directory is a setup failure, not a clean result, so this "
            "returns %d - but it writes nothing, because a run-status.json in "
            "a tree that was never scanned is an artifact claiming a run "
            "happened." % (base, EXIT_SETUP))

    errors = []
    # Artifacts that are ON DISK and could not be used - unparseable, null, or
    # the wrong shape. Kept apart from "absent", because stage_account must not
    # read a queue it could not use as a queue with nothing in it.
    unusable = set()

    def read(relpath, label=None):
        path = os.path.join(base, relpath)
        obj, err = _load(path)
        if err:
            errors.append(err)
            if label:
                unusable.add(label)
        else:
            _schema_guard(path, obj)
        return obj

    run = read("run.json")
    if run is not None and not isinstance(run, dict):
        errors.append("%s is not a JSON object" % os.path.join(base, "run.json"))
        run = None

    tables = {}
    for relpath, label, fields in ARTIFACT_SHAPES:
        obj = read(relpath, label)
        if obj is not None:
            problem = artifact_shape_problem(relpath, obj, fields)
            if problem:
                errors.append(problem)
                unusable.add(label)
                obj = None
        tables[label] = obj if isinstance(obj, dict) else {}

    inventory_path = os.path.join(base, "secrets", "inventory.json")
    inventory = read(os.path.join("secrets", "inventory.json"))

    dependencies, err = _load_jsonl(
        os.path.join(base, "enrich", "dependencies.jsonl"))
    if err:
        errors.append(err)

    findings, ferrs = _dir_json(os.path.join(base, "findings"),
                                lambda n: True)
    errors.extend(ferrs)
    # `startswith("ARB")` and not `"ARB-"`, to match verify_findings.py's own
    # test exactly. Two tools disagreeing about which files in a directory are
    # ARB records is how a run passes the arbitration gate and then reports the
    # adjudication as missing.
    arbitrations, aerrs = _dir_json(os.path.join(base, "arbitration"),
                                    lambda n: n.startswith("ARB"))
    errors.extend(aerrs)

    # Deferred candidates live one file per category. Counting the records rather
    # than trusting queue.json's `deferred` count is deliberate: the number that
    # matters is how many records are on disk unexamined. The records are kept
    # too: they are candidates this run minted, and a verdict for one is this
    # run's verdict, not a leftover.
    deferred, deferred_rows = 0, []
    cand_dir = os.path.join(base, "candidates")
    if os.path.isdir(cand_dir):
        for name in sorted(os.listdir(cand_dir)):
            if not name.endswith("-deferred.json"):
                continue
            obj, err = _load(os.path.join(cand_dir, name))
            if err:
                errors.append(err)
                continue
            rows = obj if isinstance(obj, list) else (
                obj.get("candidates") if isinstance(obj, dict) else None)
            if not isinstance(rows, list):
                errors.append("%s/candidates/%s is on disk and holds no list of "
                              "candidate records, so the candidates the budget "
                              "cut cannot be counted." % (RUN_DIR, name))
                continue
            deferred += len(rows)
            deferred_rows.extend(r for r in rows if isinstance(r, dict))

    prechecks = {}
    for label, relpath in PRECHECK_PROBLEM_FILES:
        obj, err = _load(os.path.join(base, relpath))
        if err:
            errors.append(err)
        prechecks[label] = obj if isinstance(obj, dict) else None
    findings_precheck, err = _load(os.path.join(base, "arbitration",
                                                "precheck.json"))
    if err:
        errors.append(err)

    art = {
        "root": root,
        "base": base,
        "run": run,
        "queue": tables["queue"],
        "analyzer_runs": tables["analyzer_runs"],
        "operating_point": tables["operating_point"],
        "extract_report": tables["extract_report"],
        "inventory": inventory,
        # Presence, separately from content: a file that is on disk and could
        # not be read must never be described as a stage that did not run.
        "inventory_present": os.path.isfile(inventory_path),
        "arb_queue": tables["arb_queue"],
        "arb_queue_present": os.path.isfile(
            os.path.join(base, "arbitration", "queue.json")),
        "unusable": unusable,
        "dependencies": dependencies,
        "findings": findings,
        "arbitrations": arbitrations,
        "deferred": deferred,
        "prechecks": prechecks,
        "findings_precheck": (findings_precheck
                              if isinstance(findings_precheck, dict) else None),
        "read_errors": errors,
    }
    art["stale"] = bind_to_run(art, deferred_rows)
    return art


# --------------------------------------------------------------------------- #
# which run a verdict belongs to
# --------------------------------------------------------------------------- #
#
# Stage 3 mints candidate ids from a counter, `CAND-%04d`, and starts it again
# at 1 on every run. A verdict is keyed on that id and on nothing else, so the
# `findings/CAND-0002.json` a previous run left behind has exactly the name of
# this run's CAND-0002 - which is a different function, under a different rule.
# Counted by name, it was: a run that stopped after stage 3 reported
# "adjudicate, arbitrate: done, dismissed 2, exit 0", every dismissal written
# about code the new candidates are not in. That is the incomplete run read as a
# clean one, which is the one reading this tool exists to stop.
#
# So a record counts only when it matches this run's candidate of the same id.
# Its `rule_id` is the candidate's - or, for a candidate this run's precheck
# flagged `rule_id_mismatch`, the rule the validator filed it under instead
# (bind_to_run). And it is not positively about a function in another file.
# Either field may be missing from a record - validators omit `rule_id` and
# verify_findings recovers it - and a missing field cannot mismatch.
#
# The file half needs POSITIVE evidence, because a verdict about this
# candidate need not name this candidate's file at all. §7 tells a dismissal
# not to cite the sink back but "the guard that dominates every path, the
# declaration that fixes the size, the caller that passes the constant", §8's
# FP-NOT-COMPILED cites a build file, and `files_read` is optional - so a
# correct dismissal located wholly in a caller or a header, with no
# `files_read`, is an ordinary verdict, and calling it a previous run's made a
# complete run exit 4 with the gate's accepted verdicts uncounted. What does
# say "another function" is a `sink` that is somewhere else, or a reading list
# (`files_read`, the arbiter's `read_before_judging`) that never opened this
# candidate's file. Only those call a record stale, and only when nothing in
# it names this candidate's file. The price, stated: a previous run's
# dismissal under the same rule whose only citations are callers, guards or
# declarations in another file, with no reading list, is counted - as every
# record was before this check existed. The rule half still catches the
# measured case, a strcpy rewritten to a system() in the same function.

CANDIDATE_ID = re.compile(r"CAND-\d+\Z")
# Everything before the first `:<digit>`: `src/a.c:12`, `src/a.c:12-40` and
# `src/a.c:12 (memcpy)` all name `src/a.c`, and `C:\x\a.c:12` names `C:\x\a.c`.
# Used only to say which file a stale record cites.
_LOCATION = re.compile(r"(.+?):\d")

# The lists in a verdict (validator-contract §7) and an ARB record (the
# arbiter's `read_before_judging`) whose rows may name a file the record was
# written about. A row that names this candidate's file keeps the record.
CITING_LISTS = ("evidence", "guards_considered", "false_positive_reasons",
                "files_read", "read_before_judging")
# The lists that say which files the author OPENED. One that is there and
# names none of this candidate's is a record about somebody else's code.
READING_LISTS = ("files_read", "read_before_judging")

# What may stand either side of a path written into a citation: `src/a.c:12`,
# `src/a.c (lines 1-40)`, `src/a.c#L1-L40`, "`src/a.c`", `(see src/a.c)`. A
# letter, a digit, `_`, `-` or `.` may not, so `src/a.c` is not named by
# `src/ab.c`, `src/a.cc` or `xsrc/a.c`.
_PATH_BEFORE = frozenset(" \t\r\n\"'`([{<,;=")
_PATH_AFTER = frozenset(" \t\r\n\"'`)]}>:#(,;")


def _norm_path(path):
    path = path.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _names_file(text, wanted):
    """Does `text` name the file `wanted`, with a path boundary either side?

    Tolerates the root being spelled differently - an absolute path, a leading
    ./, backslashes - and a citation that dropped the directory (`a.c:12` for
    src/a.c). Reads prose, ranges and anchors around the path, and paths with
    a space in them: those used to be dropped as prose, so a candidate in
    `Source Files/parse.c` could only ever be matched by citations that could
    not match it, and one header citation beside them made the verdict stale.
    """
    text, wanted = _norm_path(text.strip()), _norm_path(wanted.strip())
    if not text or not wanted:
        return False
    parts = wanted.split("/")
    # The whole path, then each tail of it that starts at a directory boundary.
    # Only the whole path may follow a `/`: `lib/a.c` is not src/a.c.
    for n in range(len(parts)):
        tail = "/".join(parts[n:])
        if not tail:
            continue
        start = text.find(tail)
        while start >= 0:
            end = start + len(tail)
            before = text[start - 1] if start else ""
            after = text[end] if end < len(text) else ""
            # A `.` after it is a sentence's full stop, never `src/a.c.orig`.
            stop = after == "." and not text[end + 1:end + 2].strip()
            if ((not before or before in _PATH_BEFORE
                 or (n == 0 and before == "/"))
                    and (not after or after in _PATH_AFTER or stop)):
                return True
            start = text.find(tail, start + 1)
    return False


def _row_file(row):
    """The path-bearing text of one citing row: a string, or a dict's file."""
    if isinstance(row, dict):
        row = row.get("file") or row.get("path")
    return row if isinstance(row, str) and row.strip() else None


def _raw_citations(record):
    """Every string in a verdict or ARB record that may name a file, unparsed."""
    out = []
    loc = record.get("primary_location")
    if isinstance(loc, dict):
        loc = loc.get("file")
    if isinstance(loc, str):
        out.append(loc)
    relevance = record.get("relevance_test")
    if isinstance(relevance, dict) and isinstance(relevance.get("settled_by"),
                                                  str):
        out.append(relevance["settled_by"])
    for key in CITING_LISTS:
        rows = record.get(key)
        for row in (rows if isinstance(rows, list) else []):
            if isinstance(row, dict):
                out.extend(row[field] for field in ("file", "path")
                           if isinstance(row.get(field), str))
            elif isinstance(row, str):
                # A string reason too: "FP-CONST: ... src/a.c:9" names its
                # file in the prose, and _names_file reads prose.
                out.append(row)
    return out


def _elsewhere(record, path):
    """The citations that put `record` in a file other than `path`: a `sink`
    that is somewhere else, or a reading list that never opened `path`. []
    when there is no such positive evidence."""
    out = []
    evidence = record.get("evidence")
    for row in (evidence if isinstance(evidence, list) else []):
        if isinstance(row, dict) and row.get("role") == "sink":
            text = _row_file(row)
            if text and not _names_file(text, path):
                out.append(text)
    for key in READING_LISTS:
        rows = record.get(key)
        opened = [_row_file(row) for row in (rows if isinstance(rows, list)
                                             else [])]
        opened = [text for text in opened if text]
        if opened and not any(_names_file(text, path) for text in opened):
            out.extend(opened)
    return out


def _shown(text):
    """A citation as a file name, for a sentence: `src/zzz.c:1-40` is src/zzz.c."""
    match = _LOCATION.match(text.strip())
    return (match.group(1) if match else text).strip()


def _plain(text, limit=120):
    """A path the scanned repository chose, for a sentence an agent reads: control
    characters escaped and the length cut."""
    out = "".join(ch if ch.isprintable() else "\\x%02x" % ord(ch) if ord(ch) < 0x100
                  else "\\u%04x" % ord(ch) for ch in str(text))
    return out if len(out) <= limit else out[:limit] + "..."


def _rule(value):
    return value.strip().upper() if isinstance(value, str) and value.strip() \
        else None


def run_candidates(art, deferred_rows):
    """{candidate_id: (rule_id, file)} for every candidate this run minted.

    The dispatch queue - suppressed entries included, they were minted too -
    and the records the budget deferred. A queue entry names its file through
    `function_key` (`<file>::<name>::<ordinal>`, contract §2); a candidate
    record carries `file` directly.
    """
    out = {}
    for entry in (art["queue"].get("entries") or []):
        if not isinstance(entry, dict) or not entry.get("candidate_id"):
            continue
        path = entry.get("file")
        key = entry.get("function_key")
        if not isinstance(path, str) and isinstance(key, str) and "::" in key:
            path = key.split("::", 1)[0]
        out.setdefault(entry["candidate_id"],
                       (_rule(entry.get("rule_id")),
                        path if isinstance(path, str) and path else None))
    for row in deferred_rows:
        if row.get("candidate_id"):
            path = row.get("file")
            out.setdefault(row["candidate_id"],
                           (_rule(row.get("rule_id")),
                            path if isinstance(path, str) and path else None))
    return out


def _mismatch(record, rule_id, path, whose, also=()):
    """Why `record` is not about the candidate `whose` describes, or None.

    `also` is the rules this run itself filed the candidate under besides
    `rule_id` (bind_to_run's relabel); a record carrying one of them is not
    a stranger for it.
    """
    theirs = _rule(record.get("rule_id"))
    if theirs and rule_id and theirs != rule_id and theirs not in also:
        return "carries %s where %s is %s" % (theirs, whose, rule_id)
    if path and not any(_names_file(text, path)
                        for text in _raw_citations(record)):
        elsewhere = _elsewhere(record, path)
        if elsewhere:
            return ("cites %s where %s is in %s"
                    % (", ".join(sorted(set(_shown(t) for t in elsewhere))[:2]),
                       whose, path))
    return None


def relabelled_rules(art):
    """{candidate_id: rule} for every finding this run's precheck flagged
    `rule_id_mismatch`, with the rule the validator filed it under.

    A validator re-filing a candidate under another rule is a state of THIS
    run, and the pipeline carries it on: verify_findings keeps the finding's
    own rule and runs both rules' checks, queues it for the arbiter under its
    own rule, and roles/arbiter.md tells the arbiter to decide which rule it is
    really about. Read as staleness, it made the verdict fail against the rule
    stage 3 minted and the ARB record fail one of its two checks whichever rule
    the arbiter kept - a completed run exited 4 with a confirmed finding gone
    from its counts, while the SARIF and the ledger counted it. The precheck
    row is what shows this run's verify_findings compared the verdict against
    this run's candidate; a relabel seen before it runs is still stale here,
    in a run that is not complete yet anyway.
    """
    out = {}
    doc = art.get("findings_precheck") or {}
    rows = doc.get("findings")
    for row in (rows if isinstance(rows, list) else []):
        # A key, so a string: an id that is a list was a TypeError out of
        # collect() - a traceback where the run's account belonged.
        if not isinstance(row, dict) or not isinstance(
                row.get("candidate_id"), str) or not row["candidate_id"]:
            continue
        problems = row.get("problems")
        if any(isinstance(p, dict) and p.get("code") == "rule_id_mismatch"
               for p in (problems if isinstance(problems, list) else [])):
            rule = _rule(row.get("rule_id"))
            if rule:
                out[row["candidate_id"]] = rule
    return out


def bind_to_run(art, deferred_rows):
    """Remove every verdict and ARB record that is not this run's from `art`,
    and return a gate-failure sentence for each kind removed.

    Removed, not only reported, so that nothing downstream - stage_account,
    verdict_counts, the exit code - can count one: a previous run's dismissal
    adjudicates nothing, and the candidate it shadows is still owed a verdict.
    Ids that are not stage 3's (`MANUAL-1`, the one-off dispatch convention) are
    somebody's deliberate hand dispatch and are left alone. A queue that could
    not be read binds nothing: its own gate failure is the whole story, and
    calling every verdict a leftover on top of it would bury that sentence.

    A candidate this run's precheck flagged `rule_id_mismatch` may carry
    either rule, the minted one or the validator's, in its verdict and in both
    of its ARB record's checks (relabelled_rules). A third rule still
    mismatches, and so does a relabel with no precheck row to show it.
    """
    if "queue" in art["unusable"]:
        return []
    minted = run_candidates(art, deferred_rows)
    queued_rules = {}
    for entry in (art["arb_queue"].get("queue") or []):
        if isinstance(entry, dict) and entry.get("candidate_id"):
            queued_rules[entry["candidate_id"]] = _rule(entry.get("rule_id"))
    relabelled = relabelled_rules(art)

    out = []
    for label, prefix, kind, owed in (
            ("findings", "", "verdict file(s) in %s/findings/" % RUN_DIR,
             "a verdict"),
            ("arbitrations", "ARB-",
             "ARB record(s) in %s/arbitration/" % RUN_DIR, "an adjudication")):
        records = art[label]
        wrong, leftover = [], []
        for cid in sorted(records):
            if cid not in minted:
                if CANDIDATE_ID.match(cid):
                    leftover.append(cid)
                continue
            rule_id, path = minted[cid]
            # Both rules, in both checks: the arbiter may keep the validator's
            # rule or restore the minted one through `changes[]`, and the
            # queue carries the validator's.
            also = (tuple(r for r in (rule_id, relabelled[cid]) if r)
                    if cid in relabelled else ())
            why = _mismatch(records[cid], rule_id, path,
                            "this run's %s" % cid, also)
            if why is None and label == "arbitrations":
                why = _mismatch(records[cid], queued_rules.get(cid), None,
                                "arbitration/queue.json's %s" % cid, also)
            if why:
                wrong.append((cid, why))
        for cid in leftover + [cid for cid, _why in wrong]:
            del records[cid]
        if wrong:
            out.append(
                "%d %s were written about a different candidate than the one "
                "this run gave the same id (%s): candidate ids restart at "
                "CAND-0001 on every stage-3 run, so each is a previous run's "
                "record. None of them is counted, and each of those candidates "
                "is still owed %s."
                % (len(wrong), kind,
                   "; ".join("%s%s %s" % (prefix, cid, why)
                             for cid, why in wrong[:5]), owed))
        if leftover:
            out.append(
                "%d %s carry a candidate id this run's stage 3 never minted "
                "(%s): they are left over from a previous run, and none of them "
                "is counted as confirmed, dismissed or anything else."
                % (len(leftover), kind,
                   ", ".join(prefix + cid for cid in leftover[:5])))
    return out


# --------------------------------------------------------------------------- #
# stages and tasks
# --------------------------------------------------------------------------- #

def dispatched_candidates(art):
    """The candidate ids stage 3 actually sent to a validator, each one once.

    Suppressed entries are excluded because a suppression removes a candidate
    from the dispatch queue by design (contract §8 rule 4) - it is not a task
    that failed to complete. Everything else in `entries` was dispatched and owes
    a verdict.

    De-duplicated, because `incomplete_tasks` is a count of TASKS and a queue
    listing one candidate twice does not create a second task. Counting the rows
    made the number disagree with `queue.json`'s own `counts.dispatched` beside
    it, which is the shape of failure this whole bundle exists to catch. The
    duplicate itself is not swallowed - `queue_problems` reports it.
    """
    out, seen = [], set()
    for entry in (art["queue"].get("entries") or []):
        if not isinstance(entry, dict):
            continue
        if entry.get("suppressed"):
            continue
        cid = entry.get("candidate_id")
        if cid and cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def queue_problems(art):
    """The dispatch queue against its own accounting.

    `enrich/queue.json` carries `counts.dispatched` beside the `entries` it was
    computed from, so the two can be checked against each other for free - and a
    queue that cannot be reconciled with itself is not an account of what stage 3
    sent anywhere. Duplicated ids are reported here rather than counted above.
    """
    out = []
    queue = art["queue"]
    entries = [e for e in (queue.get("entries") or []) if isinstance(e, dict)]
    ids = [e.get("candidate_id") for e in entries if not e.get("suppressed")]
    dupes = sorted(cid for cid, n in collections.Counter(ids).items()
                   if cid and n > 1)
    if dupes:
        out.append("%s/enrich/queue.json lists %d candidate id(s) more than once "
                   "(%s): one candidate is one task, so a queue that names it "
                   "twice cannot be reconciled against the verdicts on disk."
                   % (RUN_DIR, len(dupes), ", ".join(dupes[:5])))
    counts = queue.get("counts")
    if isinstance(counts, dict):
        declared = counts.get("dispatched")
        actual = len(dispatched_candidates(art))
        if isinstance(declared, int) and not isinstance(declared, bool) \
                and declared != actual:
            out.append("%s/enrich/queue.json says `counts.dispatched` is %d and "
                       "carries %d unsuppressed entry(ies): the queue disagrees "
                       "with itself, so neither number is an account of what "
                       "stage 3 dispatched."
                       % (RUN_DIR, declared, actual))
    return out


def arbitration_queue_ids(art):
    """The candidate ids `verify_findings.py --findings` queued for the arbiter."""
    out = []
    for entry in (art["arb_queue"].get("queue") or []):
        if isinstance(entry, dict) and entry.get("candidate_id"):
            out.append(entry["candidate_id"])
    return out


def stage_account(art):
    """(completed, missing, incomplete_tasks, notes).

    `completed` is NOT a copy of `run.json.stages_completed`. It is that list
    plus the two stages nothing appends - adjudicate and arbitrate - established
    from the artifacts, because a run whose candidates have no verdicts has not
    adjudicated anything no matter what any list says.
    """
    run = art["run"] or {}
    recorded = [s for s in (run.get("stages_completed") or [])
                if isinstance(s, str)]
    done, notes = set(recorded), []

    dispatched = dispatched_candidates(art)
    unadjudicated = [c for c in dispatched if c not in art["findings"]]

    queued = arbitration_queue_ids(art)
    unarbitrated = [c for c in queued if c not in art["arbitrations"]]

    # Stage 4 counts as adjudicated when stage 3 finished and every dispatched
    # candidate has a verdict file. A run that dispatched nothing adjudicates
    # vacuously - there was nothing to send, and calling that a missing stage
    # would fail every repository the operating point selected nothing in. What
    # was never dispatched is a COVERAGE limitation, which is where it goes.
    # A queue that is on disk and could not be read dispatched nothing anybody
    # can name, which is not the same as dispatching nothing.
    if ("enrich" in done and not unadjudicated
            and "queue" not in art["unusable"]):
        done.add("adjudicate")

    # Stage 4's second half. `arbitration/queue.json` is written by
    # verify_findings.py's findings gate, so its absence alongside verdicts says
    # the gate never ran - the failure the README calls out ("the precheck is a
    # gate, not a note"), and not the same thing as an empty queue. With no
    # verdicts at all there is nothing for a gate to have skipped. A queue file
    # that IS there and could not be read is already a gate failure naming it;
    # "does not exist" would be a false sentence about it.
    if "adjudicate" in done:
        if not art["findings"]:
            done.add("arbitrate")
        elif not art["arb_queue_present"]:
            notes.append("%s/arbitration/queue.json does not exist while %d "
                         "verdict(s) are on disk: the findings gate never ran, "
                         "so nothing decided which of them an arbiter had to "
                         "review." % (RUN_DIR, len(art["findings"])))
        elif not unarbitrated and "arb_queue" not in art["unusable"]:
            done.add("arbitrate")

    completed = ([s for s in STAGES if s in done]
                 + [s for s in recorded if s not in STAGES])
    missing = [s for s in STAGES if s not in done]
    return completed, missing, unadjudicated, unarbitrated, notes


# --------------------------------------------------------------------------- #
# counts
# --------------------------------------------------------------------------- #

def effective_verdict(art, candidate_id):
    """The arbiter's word where there is one, the validator's otherwise.

    Same rule `export_sarif.py` uses. The arbiter overturns, and a status file
    reporting the overturned verdict would disagree with the SARIF and with
    REPORT.md about the same finding.
    """
    arb = art["arbitrations"].get(candidate_id) or {}
    finding = art["findings"].get(candidate_id) or {}
    return arb.get("final_verdict") or finding.get("verdict")


def verdict_counts(art):
    """(confirmed, review, dismissed, accepted, unrecognised)."""
    counts = collections.Counter()
    unrecognised = []
    for candidate_id in sorted(art["findings"]):
        verdict = effective_verdict(art, candidate_id)
        if verdict in CONFIRMED_VERDICTS:
            counts["confirmed"] += 1
        elif verdict in REVIEW_VERDICTS:
            counts["review"] += 1
        elif verdict in DISMISSED_VERDICTS:
            counts["dismissed"] += 1
        elif verdict in ACCEPTED_VERDICTS:
            counts["accepted"] += 1
        else:
            # Never silently dropped, and never counted as dismissed. A verdict
            # string nothing recognises is a finding nobody has classified, so it
            # goes where an unclassified finding belongs - in front of a person.
            counts["review"] += 1
            unrecognised.append("%s carries verdict %r, which is not one of the "
                                "contract's four; it is counted as a review "
                                "candidate so that it cannot vanish"
                                % (candidate_id, verdict))
    return (counts["confirmed"], counts["review"], counts["dismissed"],
            counts["accepted"], unrecognised)


def is_a_secret_finding(entry):
    """Contract §4a's rule, COMPUTED - never the entry's own claim.

    `is_finding` is `true` if and only if `kind == "secret"` and
    `origin == "literal"`, and it is the one field in that file an inventory can
    get wrong: the agent judges the candidates and writes it. `sweep_secrets.py`
    already learned this the expensive way - its `status` command used to split
    on `entry["is_finding"]`, and an `origin: "literal"` entry marked
    `is_finding: false` was filed under "INVENTORY - NOT findings" while the
    findings block said "none. No secret in this repository is written into the
    source." Its docstring for `is_a_finding` records both directions.

    Splitting on the claim here would be worse, because this file is the one a CI
    job reads: a hardcoded credential with `is_finding: false` would be counted
    as zero, nothing would block, and `sweep_secrets.py status` and
    `run-status.json` would print different numbers from the same file - a count
    that disagrees with what produced it, which is the failure the whole bundle
    is built around. So the rule is computed, and every disagreement between the
    rule and the claim is a gate failure (`secrets_problems`).
    """
    return (entry.get("kind") == "secret"
            and entry.get("origin") == "literal")


def secrets_entries(art):
    """(entries, problem_sentence).

    `entries` is None when there is nothing countable - either the sweep did not
    run (no file) or the file is there and is not an inventory. Those two are
    different facts and the caller must not collapse them, so the second one
    always arrives with a sentence.
    """
    doc = art["inventory"]
    if doc is None:
        return None, None                 # the sweep did not run - not "zero"
    path = "%s/secrets/inventory.json" % RUN_DIR
    shape = ("%s must be an object with an `entries` array, or a bare array of "
             "entries (contract §4a)" % path)
    if isinstance(doc, list):
        entries = doc
    elif isinstance(doc, dict):
        entries = doc.get("entries")
        if entries is None:
            return None, ("%s is on disk and has no `entries`: %s. Read as an "
                          "absent sweep it would report a repository nobody "
                          "swept; read as zero it would report a clean one."
                          % (path, shape))
    else:
        return None, "%s is on disk and is not an inventory: %s." % (path, shape)
    if not isinstance(entries, list):
        return None, ("%s is on disk and its `entries` is a %s, not an array: "
                      "%s." % (path, type(entries).__name__, shape))
    bad = [n for n, e in enumerate(entries) if not isinstance(e, dict)]
    if bad:
        return None, ("%s is on disk and %d of its entries are not objects "
                      "(index %s): an inventory this tool cannot read entry by "
                      "entry is not an inventory it can count."
                      % (path, len(bad),
                         ", ".join(str(n) for n in bad[:5])))
    return entries, None


def secrets_findings(art):
    """How many entries contract §4a's rule makes findings, and no others.

    A hardcoded secret is a finding, HOLDING a secret is not. An inventory of a
    crypto library lists every key, tag and nonce it handles; counting those as
    findings produces a status file with two hundred findings in it and no
    signal.
    """
    entries, _problem = secrets_entries(art)
    if entries is None:
        return None
    return sum(1 for e in entries if is_a_secret_finding(e))


def secrets_problems(art):
    """Gate-failure sentences about the inventory itself.

    An unreadable inventory, and an inventory whose `is_finding` contradicts
    contract §4a's rule. The second one does not change the count above - that is
    already computed - but it means the artifact and the rule disagree, and
    `sweep_secrets.py check` exists to refuse exactly this. A run whose inventory
    is wrong in that direction has a secrets track nobody can reconcile.
    """
    entries, problem = secrets_entries(art)
    if problem:
        return [problem]
    if entries is None:
        return []
    wrong = [e for e in entries
             if (e.get("is_finding") is True) != is_a_secret_finding(e)]
    if not wrong:
        return []
    ids = [str(e.get("entry_id") or "unnamed") for e in wrong]
    return ["%d inventory entry(ies) contradict contract §4a's rule that "
            "`is_finding` is true if and only if kind == \"secret\" and "
            "origin == \"literal\" (%s): the counts above are computed from the "
            "rule, not from the field, so the file and this status disagree "
            "about which values are findings. Run `sweep_secrets.py check`."
            % (len(wrong), ", ".join(ids[:5]))]


def analyzer_status_counts(art):
    """[(analyzer, sarif_file, run_index, status, basis)] for every ingested run."""
    rows = []
    for record in (art["analyzer_runs"].get("runs") or []):
        if not isinstance(record, dict):
            continue
        rows.append((record.get("analyzer") or record.get("analyzer_driver")
                     or "unnamed analyzer",
                     record.get("sarif_file") or "an unnamed SARIF file",
                     record.get("run_index"),
                     record.get("status") or "unknown",
                     record.get("basis") or "no basis recorded"))
    return rows


# --------------------------------------------------------------------------- #
# gate failures
# --------------------------------------------------------------------------- #

# The sub-objects of `extract/extract-report.json` this tool reads, and what each
# one has to be. They are read with `.get` and `.items`, so a stage that wrote a
# list where a table belongs used to end the run in an AttributeError - and an
# uncaught exception leaves through `sys.exit(main())` as exit 1, which in the
# policy above is "completed, with findings". A crashed status tool telling a
# wrapper the run completed is the single worst thing this file can do, so the
# shapes are checked, reported as gate failures, and then read defensively.
REPORT_SHAPES = (("counts", dict), ("confidence", dict),
                 ("by_language", dict), ("unsupported_extensions", dict),
                 ("extensionless_files", dict))


def _as(value, kind):
    """`value` if it is the shape the reader assumes, otherwise an empty one.
    Never a silent substitution: `shape_problems` names every one it makes."""
    return value if isinstance(value, kind) else kind()


def _count(value):
    """A positive integer count, or 0. `or 0` passed a string straight through
    to `%d` and ended the run in a TypeError; a bool is not a count either."""
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return 0


def _listed(names, total, limit=5):
    """ " (a, b, c)" naming up to `limit` of `total`, with `...` when there are
    more, or "" when there are no names to give."""
    names = [str(n) for n in names if n]
    if not names:
        return ""
    more = ", ..." if total > min(len(names), limit) else ""
    return " (%s%s)" % (", ".join(names[:limit]), more)


# One `unreadable_files` entry as stage 1 writes it: the file, then an optional
# line number, then the reason - "src/a.c: [Errno 13] ..." and
# "src/a.c:1: binary content, not scanned".
UNREADABLE_ENTRY = re.compile(r"(.+?):(?:\d+:)? ")


def _excludes_itself(directory, pattern):
    """Does `pattern` exclude `directory` itself, the way extract_functions.py's
    is_excluded() reads a pattern? Those are the patterns an `--include` of the
    directory waives; a pattern that only matches the files in it is not."""
    clean = pattern.rstrip("/")
    return (clean in directory.split(os.sep) or directory == clean
            or directory.startswith(clean + os.sep)
            or fnmatch.fnmatch(directory, pattern))


def shape_problems(art):
    """An artifact whose fields are the wrong TYPE, which a `.get` chain turns
    into a traceback and an absent field turns into a zero."""
    out = []
    report = art["extract_report"]
    for key, kind in REPORT_SHAPES:
        value = report.get(key)
        if value is None or isinstance(value, kind):
            continue
        out.append("%s/extract/extract-report.json `%s` is a %s where a %s "
                   "belongs; the coverage account read from it would be an "
                   "empty one, which reads as nothing to report rather than as "
                   "an artifact this tool could not use."
                   % (RUN_DIR, key, type(value).__name__, kind.__name__))
    return out


def gate_failures(art):
    """Every sentence that makes this run's artifacts untrustworthy as an
    account of it: a precheck gate that recorded problems, an artifact a
    completed stage says it wrote that is not there, an artifact that does not
    parse or is not the shape its writer emits, a verdict or ARB record left by
    a previous run, and an inventory that contradicts the rule it is held
    to."""
    out = list(art["read_errors"])
    out.extend(art["stale"])
    out.extend(secrets_problems(art))
    out.extend(shape_problems(art))
    out.extend(queue_problems(art))

    run = art["run"]
    if run is None:
        out.append("%s/run.json is missing or unreadable: the run has no "
                   "identity, no tool versions and no record of which stages "
                   "finished, so nothing downstream of it can be trusted as an "
                   "account of this repository." % RUN_DIR)
    else:
        done = set(run.get("stages_completed") or [])
        if not done:
            out.append("%s/run.json records no completed stage: stage 1 never "
                       "finished." % RUN_DIR)
        # A stage that appended its name and did not leave its artifact is a
        # half-deleted or half-written run directory. Read as zeros, it is a
        # clean result; named here, it is what it is.
        expected = (
            ("extract", os.path.join("extract", "extract-report.json")),
            ("score", os.path.join("scores", "operating-point.json")),
            ("enrich", os.path.join("enrich", "queue.json")),
            ("enrich", os.path.join("enrich", "analyzer-runs.json")),
        )
        for stage, relpath in expected:
            if stage in done and not os.path.isfile(
                    os.path.join(art["base"], relpath)):
                out.append("run.json records stage %r complete and %s/%s is not "
                           "there; the counts this tool would read from it would "
                           "be zeros standing in for an artifact, not for an "
                           "absence of findings." % (stage, RUN_DIR, relpath))

    for label, _relpath in PRECHECK_PROBLEM_FILES:
        doc = art["prechecks"].get(label)
        if not doc:
            continue
        problems = doc.get("problems")
        if not isinstance(problems, list) or not problems:
            continue
        by_code = collections.Counter(
            (p.get("code") or "uncoded") for p in problems
            if isinstance(p, dict))
        out.append("the %s gate recorded %d problem(s) (%s); verify_findings.py "
                   "stops the stage that follows it for these, so the run "
                   "continued past a gate or did not run one."
                   % (label, len(problems),
                      ", ".join("%s x%d" % (code, n)
                                for code, n in sorted(by_code.items()))))

    doc = art["findings_precheck"]
    if doc:
        by_code = collections.Counter()
        for record in (doc.get("findings") or []):
            if not isinstance(record, dict):
                continue
            for problem in (record.get("problems") or []):
                code = (problem or {}).get("code")
                if code in FINDINGS_GATE_CODES:
                    by_code[code] += 1
        if by_code:
            out.append("the findings gate recorded %d blocking problem(s) (%s); "
                       "verify_findings.py --findings returns non-zero for "
                       "these, so a run that carried on past them did so with "
                       "verdicts the rest of the pipeline cannot read as "
                       "written."
                       % (sum(by_code.values()),
                          ", ".join("%s x%d" % (c, n)
                                    for c, n in sorted(by_code.items()))))
        summary = doc.get("summary") or {}
        verdicts = (summary.get("counts") or {})
        if (summary.get("citations_verified") == 0
                and verdicts.get("VULNERABLE")):
            out.append("not one citation was verified across the whole run while "
                       "%d VULNERABLE verdict(s) are reported: the citation "
                       "check did not pass, it never ran."
                       % verdicts["VULNERABLE"])
    return out


# --------------------------------------------------------------------------- #
# coverage limitations
# --------------------------------------------------------------------------- #
#
# This list is the reason the file is worth writing. Every number above it is a
# count of things somebody looked at; this is the account of what nobody looked
# at, and an empty one is a claim that there is nothing - which on a real
# repository is false often enough that "empty by default" would be a lie with a
# schema around it.
#
# Each entry is one sentence a person can act on. Not a code, not a field name: a
# reader of a CI artifact has no way to look up `window_share: 0.14`.

# rules_lib.TRIAGE_REASONS in the short form a tally reads in, keyed by the same codes; this tool
# imports nothing from rules_lib, so tests/test_triage_derived.py holds the two key sets equal.
NOT_DERIVED_PHRASES = {
    "no-verdict": "the backend records no triage verdict",
    "verdict-medium": "rated medium", "verdict-low": "rated low", "verdict-none": "rated none",
    "has-rule-hit": "a rule matched",
    "not-a-function": "a module or window scope",
    "test-tree": "in the test tree", "generated": "in a generated file",
    "vendored": "in a vendored directory",
    "opted-out": "LOG-TRI was switched off (--no-triage-candidates)",
    "over-cap": "beyond --triage-candidates-max",
    "anchor-unreadable": "no readable line to anchor on",
    "scored-before-0.1.3": "scored before 0.1.3, so no verdict is recorded: re-run "
                           "score_functions.py --resume to derive LOG-TRI (every verdict is "
                           "cached); if the row chosen then holds LOG-TRI validator calls, "
                           "the cut is asked again",
    "unrecorded": "the queue records no reason, so it was written before 0.1.3",
}


def remainder_twins(queue, keys):
    """For each function in `keys` whose byte-identical copy was reviewed under some rule, one
    clause saying which copy and which candidate. A function with no candidate whose twin has
    one is not unexamined in the same sense as one with no twin, and the report should not list
    a reviewed body as unexamined without saying so."""
    entries = {e.get("function_key"): e for e in _as(queue.get("entries"), list)
               if isinstance(e, dict) and not e.get("suppressed")}
    groups = [g for g in _as(_as(queue.get("twins"), dict).get("listing"), list)
              if isinstance(g, dict)]
    out = []
    for key in keys:
        for group in groups:
            aliases = [a for a in _as(group.get("aliases"), list) if isinstance(a, str)]
            if key not in aliases:
                continue
            copies = [(a, entries[a]) for a in aliases if a != key and a in entries]
            if copies:
                alias, entry = copies[0]
                out.append("%s: its byte-identical copy %s was reviewed as %s under %s"
                           % (key, alias, entry.get("candidate_id"), entry.get("rule_id")))
            break
    return out


def coverage_limitations(art):
    out = []
    point = art["operating_point"]
    report = art["extract_report"]
    run = art["run"] or {}

    # 1. Functions below the operating point. The one §6 already has a field for,
    #    restated here because the field is in a file nobody outside the pipeline
    #    reads.
    not_selected = point.get("not_selected")
    if isinstance(not_selected, int) and not_selected > 0:
        kind = point.get("score_kind") or "ordinal"
        if kind == "probability":
            qualifier = ("a calibrated score below the selected threshold is a "
                         "ranking decision, not a verdict")
        else:
            qualifier = ("a rank under an uncalibrated ordinal score cleared "
                         "nothing")
        out.append("%d function(s) scored below the operating point and were "
                   "never adjudicated: %s, so those functions are unexamined, "
                   "not clean." % (not_selected, qualifier))

    # 2. Any analyzer run that is not `complete` - including `unknown`, which is
    #    most tools' normal silence and is still not a statement that the scan
    #    finished.
    for analyzer, sarif_file, index, status, basis in analyzer_status_counts(art):
        if status == "complete":
            continue
        out.append("analyzer %s (%s, run %s) finished as `%s`, not `complete`: "
                   "%s. A scan that stopped early is not a scan that found "
                   "nothing." % (analyzer, sarif_file,
                                 "?" if index is None else index, status, basis))
    if not art["analyzer_runs"].get("runs") and "enrich" in (
            run.get("stages_completed") or []):
        out.append("no analyzer SARIF was ingested, so no candidate carries "
                   "corroboration from semgrep, cppcheck or CodeQL: "
                   "`agreement.analyzer: false` on every candidate means nothing "
                   "was asked, not that something disagreed.")

    # 2a. A queue with nothing in it. This is why a zero-candidate run is
    #     "complete" rather than "missing stage 4": there was nothing to send,
    #     and the hole is in what stage 3 selected, not in what stage 4 did.
    if ("enrich" in (run.get("stages_completed") or [])
            and not dispatched_candidates(art)):
        out.append("stage 3 dispatched no candidate at all, so nothing in this "
                   "repository was adjudicated by anything: an empty queue is "
                   "not a clean queue.")

    # 2b. Functions the operating point SELECTED that produced no candidate.
    #     They are counted in neither `not_selected` (they were selected) nor
    #     the dispatch queue (there was no hit to anchor a candidate on), so
    #     without this sentence they vanish from the account entirely - ranked
    #     high enough to review, and read by nothing. enrich_candidates.py calls
    #     them the pipeline's own blind spot, visible only if it is counted.
    q_counts = _as(art["queue"].get("counts"), dict)
    no_candidate = _count(q_counts.get("selected_without_candidate"))
    if no_candidate:
        rows = [row for row in _as(art["queue"].get("selected_without_candidate"), list)
                if isinstance(row, dict)]
        keys = [row.get("function_key") for row in rows if row.get("function_key")]
        # Why no LOG-TRI was derived for them, in the words the queue's own codes
        # (rules_lib.TRIAGE_REASONS) stand for; a queue from before 0.1.3 records none.
        why = collections.Counter(row.get("not_derived_because") or "unrecorded"
                                  for row in rows)
        reasons = ", ".join("%d %s" % (n, NOT_DERIVED_PHRASES.get(code, code))
                            for code, n in sorted(why.items(), key=lambda kv: (-kv[1], kv[0])))
        twins = remainder_twins(art["queue"], keys[:5])
        out.append("%d function(s) were selected by the operating point and "
                   "produced no candidate: no rule matched them and no LOG-TRI was "
                   "derived for them (%s)%s%s; no validator read them, so they are "
                   "unexamined, not clean (listed in %s/enrich/queue.json "
                   "`selected_without_candidate`)."
                   % (no_candidate, reasons or "no reason recorded",
                      (": %s" % ", ".join(keys[:5])) if keys else "",
                      ("; " + "; ".join(twins)) if twins else "", RUN_DIR))

    # 2c. Functions reviewed ONLY because a triage model rated them high. No rule
    #     matched them; stage 3 gave each one LOG-TRI candidate on that rating, which
    #     is the model's unvalidated reading of the function's own text. The count is
    #     here so the basis of those reviews is not read as the basis of the rest.
    #
    #     "Reviewed" is the dispatched ones and only those. `counts.triage_derived` also
    #     holds the LOG-TRI a ledger suppression took out of dispatch and the ones the
    #     budget deferred, and no validator reads either: they are said apart, as not
    #     examined, so this list never claims a review that did not happen.
    derived = _count(q_counts.get("triage_derived"))
    if derived:
        split = isinstance(q_counts.get("triage_derived_dispatched"), int)
        reached = _count(q_counts.get("triage_derived_dispatched"))
        suppressed = _count(q_counts.get("triage_derived_suppressed"))
        deferred = _count(q_counts.get("triage_derived_deferred"))
        if reached:
            out.append("%d function(s) that no rule matched were reviewed only because the "
                       "triage model rated them high (LOG-TRI): that rating is a model's "
                       "unvalidated reading of the function, and selected functions it "
                       "rated lower that no rule matched were not reviewed." % reached)
        if not split:
            out.append("%d function(s) the triage model rated high were owed a LOG-TRI "
                       "candidate and queue.json does not record how many of them went to a "
                       "validator, so none is counted as reviewed: unexamined, not clean."
                       % derived)
        elif derived > reached:
            how = []
            if suppressed:
                how.append("%d suppressed by a ledger decision" % suppressed)
            if deferred:
                how.append("%d deferred by the budget, on disk in "
                           "%s/candidates/<category>-deferred.json" % (deferred, RUN_DIR))
            if derived - reached - suppressed - deferred > 0:
                how.append("%d not dispatched" % (derived - reached - suppressed - deferred))
            out.append("%d function(s) the triage model rated high (LOG-TRI) were not sent to "
                       "a validator in this run (%s): unexamined, not clean."
                       % (derived - reached, "; ".join(how)))

    # 3. The `window` tier. A window is a fixed range around a hit, so a verdict
    #    argued over one may have been argued over the wrong body entirely - the
    #    guards a validator reads belong to a neighbouring function.
    confidence = _as(report.get("confidence"), dict)
    window = confidence.get("window")
    if isinstance(window, int) and window > 0:
        total = sum(v for k, v in confidence.items()
                    if k in ("exact", "heuristic", "window")
                    and isinstance(v, int))
        share = confidence.get("window_share")
        if not isinstance(share, (int, float)):
            share = (window / total) if total else 0.0
        worst = sorted(
            ((name, (stats or {}).get("window") or 0)
             for name, stats in _as(report.get("by_language"), dict).items()
             if isinstance(stats, dict) and (stats.get("window") or 0) > 0),
            key=lambda row: (-row[1], row[0]))
        where = (" Worst: %s." % ", ".join("%s (%d)" % row for row in worst[:4])
                 if worst else "")
        out.append("%d of %d function record(s) (%.1f%%) have `window` "
                   "boundaries - a fixed range around a hit rather than a "
                   "measured function - so a verdict on one may have been "
                   "argued about the wrong body.%s Install "
                   "tree_sitter_language_pack and re-extract."
                   % (window, total or window, 100.0 * float(share), where))

    # 3a. No tree-sitter at all. The window line above only fires on window
    #     records, and a corpus can be 92% heuristic with 1.5% window - which is
    #     what a real field test produced, with every tree-sitter import failing
    #     and nothing in the run status saying so. A heuristic boundary is a
    #     guess at a function, and the walk that produces them also misses
    #     functions outright: on a measured C tree it found 752 where tree-sitter
    #     found 778. Those are not degraded records; they are absent, so no other
    #     line here can count them.
    parser = _as(report.get("parser"), dict)
    heuristic = confidence.get("heuristic")
    if (parser and parser.get("tree_sitter_parsed") is False
            and isinstance(heuristic, int) and heuristic > 0):
        total = sum(v for k, v in confidence.items()
                    if k in ("exact", "heuristic", "window") and isinstance(v, int))
        errs = [e for e in (parser.get("import_errors") or []) if isinstance(e, str)]
        out.append("no tree-sitter grammar parsed this corpus, so %d of %d function "
                   "record(s) (%.0f%%) have `heuristic` boundaries, and the walk that "
                   "made them misses some functions entirely - on one measured C "
                   "tree it found 752 where tree-sitter found 778, and a missed "
                   "function is not extracted, scored, adjudicated or ruled out. "
                   "Install tree_sitter_language_pack into the interpreter that "
                   "runs stage 1 and re-extract.%s"
                   % (heuristic, total or heuristic,
                      100.0 * heuristic / (total or heuristic),
                      (" First import error: %s" % errs[0]) if errs else ""))

    # 4. Deferred candidates: ranked, then cut by the budget. Nothing looked at
    #    them, and they are the population most likely to be assumed reviewed,
    #    because they got far enough to have an id.
    if art["deferred"]:
        out.append("%d candidate(s) were deferred by the budget and never "
                   "dispatched; they are on disk in "
                   "%s/candidates/<category>-deferred.json, ranked and then cut, "
                   "and nothing looked at them." % (art["deferred"], RUN_DIR))

    # 5. Stale and expired suppressions. A stale one does not suppress (contract
    #    §2), so the candidate came back - and the decision behind it has not
    #    been re-made against the code as it now stands.
    stale = art["queue"].get("suppressions_stale") or []
    if stale:
        ids = [s.get("suppression_id") for s in stale
               if isinstance(s, dict) and s.get("suppression_id")]
        out.append("%d suppression(s) did not apply because the function's "
                   "content_hash moved since they were written%s: the decision "
                   "behind each one has not been re-made against the code as it "
                   "now stands."
                   % (len(stale), (" (%s)" % ", ".join(ids[:5])) if ids else ""))
    expired = art["queue"].get("suppressions_expired") or []
    if expired:
        out.append("%d suppression(s) have passed their `expires_at` and no "
                   "longer suppress: there is no permanent suppression in this "
                   "bundle, and these are the ones that came due."
                   % len(expired))
    # Two more ways a ledger line suppresses nothing, which stage 3 lists and
    # this file did not: a record missing what a suppression needs, and a
    # MEM-WFS record the function's other candidates overrule. In both the
    # ledger says "suppressed" and the run did not, which is exactly the
    # disagreement a person reading the ledger will not notice by themselves.
    unusable = [s for s in _as(art["queue"].get("suppressions_unusable"), list)
                if isinstance(s, dict)]
    if unusable:
        ids = [str(s.get("suppression_id")) for s in unusable if s.get("suppression_id")]
        out.append("%d suppression(s) in the ledger suppress nothing because they "
                   "lack what a suppression needs - an expiry that parses, a "
                   "rule, a creation hash, a function key or an id%s: whatever "
                   "they were written to cover was dispatched as if they were not "
                   "there. `ledger.py check` names what each one is missing."
                   % (len(unusable), _listed(ids, len(unusable))))
    ignored = [s for s in _as(art["queue"].get("suppressions_ignored"), list)
               if isinstance(s, dict)]
    if ignored:
        ids = [str(s.get("suppression_id")) for s in ignored if s.get("suppression_id")]
        out.append("%d suppression(s) name MEM-WFS on a function whose other "
                   "candidates still dispatch, and were not applied%s: the "
                   "whole-function pass follows the function's other rules, so "
                   "it was dispatched anyway."
                   % (len(ignored), _listed(ids, len(ignored))))

    # 6. Languages in the tree the extractor has no parser for. Not "extensions
    #    it did not recognise" - see UNSUPPORTED_SOURCE for why.
    unsupported = _as(report.get("unsupported_extensions"), dict)
    by_language = collections.OrderedDict()
    for ext, count in sorted(unsupported.items()):
        language = UNSUPPORTED_SOURCE.get(str(ext).lower())
        if not language or not isinstance(count, int) or count <= 0:
            continue
        slot = by_language.setdefault(language, {"files": 0, "exts": []})
        slot["files"] += count
        slot["exts"].append(ext)
    for language, slot in sorted(by_language.items()):
        out.append("%d %s file(s) (%s) are in the tree and extract_functions.py "
                   "has no parser for them: nothing in them was extracted, "
                   "scored, adjudicated, or ruled out."
                   % (slot["files"], language, ", ".join(sorted(slot["exts"]))))

    # 6b. Scripts with no extension, which step 6 cannot see: stage 1 names
    #     them by their `#!` line. Only those - a Makefile or a LICENSE is not
    #     an unscanned language, for UNSUPPORTED_SOURCE's reason, so the bare
    #     `files` count never becomes a sentence. The labels stage 1 marked as
    #     languages this run reads come first and say so: that is source the
    #     run could have read, the same hole as an excluded directory. "This
    #     run", not "this skill": a `--language c` run reads no Python even
    #     with the extension, so the remedy would be false there.
    bare = _as(report.get("extensionless_files"), dict)
    readable = set(str(x) for x in _as(bare.get("readable_languages"), list))
    named = collections.defaultdict(list)
    for row in _as(bare.get("script_files"), list):
        if isinstance(row, dict) and isinstance(row.get("file"), str):
            named[str(row.get("language"))].append(row["file"])
    for language, count in sorted(_as(bare.get("scripts"), dict).items(),
                                  key=lambda kv: (kv[0] not in readable, kv[0])):
        count = _count(count)
        if not count:
            continue
        where = _listed(named.get(language, []), count)
        if language in readable:
            out.append("%d extensionless %s script(s)%s are in the tree, named "
                       "by their `#!` line: %s is a language this run reads, "
                       "but extract_functions.py selects files by extension, so "
                       "nothing in them was extracted, scored, adjudicated, or "
                       "ruled out. Giving a file its extension brings it into the corpus."
                       % (count, language, where, language))
        else:
            out.append("%d extensionless %s script(s)%s are in the tree, named "
                       "by their `#!` line, and %s is not a language this run "
                       "reads: nothing in them was extracted, scored, "
                       "adjudicated, or ruled out."
                       % (count, language, where, language))

    # 6a. Directories the exclude patterns removed that held source. Reported
    # beside the unparsed languages because it is the same kind of hole: files
    # that exist, are in a language this tool reads, and produced no record.
    # DEFAULT_EXCLUDES carries `vendor` and `third_party`, and vendored code is
    # in scope for a security review - a vulnerable dependency is your
    # vulnerability - so this must not be silent.
    #
    # The row names the patterns that removed its files, and the sentence names
    # them too: it used to call every one of them "the default exclude
    # patterns", including an operator's own --exclude and the manifest's
    # exclusions. And it offers `--include` only where `--include` works.
    # extract_functions.py waives, under an included directory, every pattern
    # that excluded that directory ITSELF - a default such as `vendor`, a
    # manifest exclusion or an --exclude naming the directory - and nothing
    # else: a pattern that removes files one by one (`src/legacy/*`,
    # `*.gen.c`) removes them under an include too, and a row for the root has
    # no directory to include. Advising `--include` there was a recovery that
    # recovered nothing.
    for row in _as(report.get("excluded_dirs"), list):
        if not isinstance(row, dict) or not _count(row.get("files")):
            continue
        directory = str(row.get("dir") or ".")
        patterns = [str(p) for p in _as(row.get("patterns"), list) if p]
        stuck = [p for p in patterns
                 if directory == "." or not _excludes_itself(directory, p)]
        if stuck:
            advice = ("`--include` does not bring them back, because %s %s "
                      "files rather than the directory: drop the matching "
                      "--exclude, or the manifest's exclusion, if that "
                      "directory holds code this review is meant to cover."
                      % (", ".join("`%s`" % p for p in stuck),
                         "removes" if len(stuck) == 1 else "remove"))
        else:
            advice = ("Pass `--include %s` to extract_functions.py if that "
                      "directory holds code this review is meant to cover."
                      % directory)
        out.append("%d source file(s) in `%s` (%s) were excluded by %s and never "
                   "extracted, scored, adjudicated or ruled out. %s"
                   % (row["files"], directory,
                      ", ".join(str(x) for x in _as(row.get("languages"), list)),
                      ", ".join("`%s`" % p for p in patterns) if patterns
                      else "the exclude patterns", advice))

    # 7. Files that were in the tree and never made it into the corpus. The
    #    walk COUNTS a file it could not stat (a dangling link, a permission, a
    #    race) for exactly this sentence - extract_functions.py calls it "a hole
    #    in the coverage claim §4 makes" - so it belongs beside its two siblings.
    #    Each part names up to five of the files, from the lists stage 1
    #    writes beside the counts: "4 could not be read" told a reader how big
    #    the hole was and not where.
    counts = _as(report.get("counts"), dict)
    unreadable = _count(counts.get("files_unreadable"))
    too_large = _count(counts.get("files_too_large"))
    unstattable = _count(counts.get("files_unstattable"))
    if unreadable or too_large or unstattable:
        parts = []
        if unreadable:
            # "src/a.c: [Errno 13] ..." or "src/a.c:1: binary content, ..."
            names = [UNREADABLE_ENTRY.match(entry).group(1)
                     if UNREADABLE_ENTRY.match(entry) else entry
                     for entry in _as(report.get("unreadable_files"), list)
                     if isinstance(entry, str) and entry]
            parts.append("%d file(s) could not be read%s"
                         % (unreadable, _listed(names, unreadable)))
        if too_large:
            names = [row.get("file") for row in
                     _as(report.get("too_large_files"), list)
                     if isinstance(row, dict) and row.get("file")]
            parts.append("%d file(s) exceeded the size limit%s"
                         % (too_large, _listed(names, too_large)))
        if unstattable:
            names = [row.get("file") for row in
                     _as(report.get("unstattable_files"), list)
                     if isinstance(row, dict) and row.get("file")]
            parts.append("%d file(s) could not be stat'ed - a dangling symlink, "
                         "a permission or a race%s"
                         % (unstattable, _listed(names, unstattable)))
        # Not .capitalize(): the sentence starts with a digit, and capitalize()
        # lower-cases everything after it - including the file names.
        out.append("%s: those files are in the repository and not in the "
                   "corpus, so no rule ran over them."
                   % (" and ".join(parts) if len(parts) < 3 else
                      "%s and %s" % (", ".join(parts[:-1]), parts[-1])))

    # 7a. Rule hits that joined to no record of any kind. `<module>` records
    #     catch hits outside functions, so this is 0 on every run stage 1's own
    #     selftest can build; it is read anyway, because stage 1 counts it as
    #     "the real coverage gap", and a gap nobody reads is one that can open
    #     without anybody seeing it.
    unjoined = _count(counts.get("hits_unjoined"))
    unjoined_files = _count(report.get("files_with_hits_no_functions"))
    if unjoined or unjoined_files:
        out.append("%s%s joined to no function record, so they were never "
                   "scored, ranked or dispatched: hits the rules found and "
                   "nothing downstream could see."
                   % ("%d rule hit(s)" % unjoined if unjoined else "rule hits",
                      " in %d file(s)" % unjoined_files if unjoined_files
                      else ""))

    # 7b. Functions still open when their file ended. The brace walk lost
    #     count of the braces, and a function it never closed is not in the
    #     corpus - stage 1 counts it as `functions_unclosed` and prints it as
    #     "lost", and until this was read, nothing past stage 1 said so.
    unclosed = _count(counts.get("functions_unclosed"))
    if unclosed:
        files = [row.get("file") for row in _as(report.get("unclosed_files"), list)
                 if isinstance(row, dict) and row.get("file")]
        out.append("%d function(s) were still open when their file ended%s: the "
                   "brace walk lost count of the braces, so they are not in the "
                   "corpus and no function record of theirs was scored, ranked "
                   "or dispatched (`unclosed_files` in extract-report.json)."
                   % (unclosed, _listed(files, len(files))))

    # 7c. Folders left out of the walk as the scanner's own tooling, or as the run folder
    #     of another skill. The skip rests on names and files a scanned tree can write (a
    #     SKILL.md in a dot folder's skills folder, a copy of this tool's signature line, a
    #     folder called `sbom-out`), so a hostile tree can use it to keep code out of the
    #     review; the folders are named here so the report cannot say "the repository was
    #     reviewed" over them.
    tooling = [row for row in _as(report.get("tooling_skipped"), list)
               if isinstance(row, dict) and row.get("path")]
    if tooling:
        named = ", ".join("`%s` (%s)" % (_plain(row["path"]), _plain(row.get("reason") or "tooling", 80))
                          for row in tooling[:8])
        if len(tooling) > 8:
            named += " and %d more" % (len(tooling) - 8)
        out.append("%d folder(s) were left out of the walk as this scanner's own "
                   "tooling or as the run folder of another skill, and were not read "
                   "by any stage: %s. That is correct for this skill, for skills "
                   "installed beside it and for their run folders; on a repository you "
                   "do not trust, a folder that only looks like one hides code from the "
                   "review, so open each one that is not yours." % (len(tooling), named))

    # 8. The snapshot, or its absence. Contract §3 keeps `cap_hit` and
    #    `changed_during_snapshot` on the run rather than only in the manifest
    #    precisely so that a summary like this one has to see them.
    snapshot = run.get("snapshot")
    if isinstance(snapshot, dict):
        if snapshot.get("cap_hit"):
            out.append("the snapshot stopped at its `%s` cap: every path after "
                       "that point was never copied and therefore never "
                       "scanned." % snapshot["cap_hit"])
        narrowed = [e for e in (snapshot.get("excludes") or []) if e]
        if narrowed:
            out.append("the snapshot this run read was narrowed by %d "
                       "--exclude pattern(s) (%s): those files were never "
                       "available to any stage, and a clean result over the "
                       "rest is not a clean result over the repository."
                       % (len(narrowed), ", ".join(sorted(narrowed))))
        if snapshot.get("copy_failed"):
            out.append("%d file(s) could not be written into the snapshot, so "
                       "they were not scanned. That is the scanning machine "
                       "rather than the tree - see snapshot-manifest.json's "
                       "`copy-failed` exclusions."
                       % snapshot["copy_failed"])
        changed = snapshot.get("changed_during_snapshot") or 0
        if isinstance(changed, int) and changed > 0:
            out.append("%d file(s) changed while the snapshot was being taken: "
                       "their recorded bytes and the file the citation names are "
                       "not the same thing." % changed)
    elif run:
        out.append("this run read the live working tree rather than a snapshot, "
                   "so every file:line in it points at a file somebody may have "
                   "edited since stage 1 read it.")

    # 8b. Whether git could vouch for the run directory. Stage 1 asked it
    #     (rules_lib.run_dir_gate) and recorded the answer; a tree git does not
    #     track - a tarball, a drop with its .git/ removed - cannot be asked,
    #     and files the scanned repository shipped there would have been read
    #     as this run's own.
    run_dir = run.get("run_dir")
    check = run_dir.get("check") if isinstance(run_dir, dict) else None
    if check in ("no-git", "untracked-tree"):
        out.append("the run directory's provenance is unverified: %s, so nothing "
                   "could say whether the files the stages read under "
                   ".security-review/ were written by this pipeline or shipped "
                   "with the tree."
                   % ("no git repository encloses the scanned tree"
                      if check == "no-git" else
                      "HEAD lists none of the scanned tree, so only the index "
                      "could be asked"))

    # 8a. The tree moving under the run, MEASURED rather than possible. Stage 3
    #     re-reads every sink line it quotes and counts the ones that no longer
    #     say what stage 1 read - contract §1's own example is "19 candidate(s)
    #     quote a line that changed since stage 1 read it". The sentence above
    #     says a live tree MAY have moved; this one says it did, and by how much.
    drift = _count(q_counts.get("sink_text_drift"))
    if drift:
        out.append("%d candidate(s) quote a line that changed since stage 1 read "
                   "it: the tree moved under the run, so those verdicts argue "
                   "about code that is not what stage 1 scored. Re-run from a "
                   "snapshot (snapshot.py, then extract_functions.py --snapshot)."
                   % drift)
    sink_unreadable = _count(q_counts.get("sink_text_unreadable"))
    if sink_unreadable:
        out.append("%d candidate(s) quote a line stage 3 could not re-read, so "
                   "nothing confirmed the quoted sink is still what the file "
                   "says." % sink_unreadable)

    # 9. The secret sweep. Its absence is not an absence of secrets, and four
    #    rules read its output (contract §4a).
    #
    #    Presence, not `art["inventory"] is None` and not
    #    `secrets_findings(art) is None`: both of those are also None for an
    #    inventory that is ON DISK and unreadable - JSON null included - and
    #    this sentence would then say a file that exists is absent. That belongs
    #    in gate_failures, where the read error and `secrets_problems` put it,
    #    and saying "the sweep did not run" about a sweep that ran and wrote
    #    something broken is a false sentence in the one artifact a CI job reads.
    if not art["inventory_present"]:
        out.append("%s/secrets/inventory.json is absent: stage 1's secret sweep "
                   "did not run, so no hardcoded credential was looked for and "
                   "LOG-007, LOG-008, HW-009 and CRY-005 had no evidence of "
                   "which values are actually secret." % RUN_DIR)
    return out


# --------------------------------------------------------------------------- #
# the policy
# --------------------------------------------------------------------------- #

def decide(setup, incomplete, policy_findings):
    """The precedence, in one place, written so it can only be read one way.

        setup failure > incomplete analysis > policy findings > no policy findings

    `incomplete and policy_findings` returns 3 and not 1. That is the case the
    rule exists for: an incomplete run WITH findings looks exactly like a
    successful run with findings, right down to the non-zero exit, and the
    difference between them is everything that was never examined.
    """
    if setup:
        return "setup_failed", EXIT_SETUP
    if incomplete:
        return "incomplete", EXIT_INCOMPLETE
    if policy_findings:
        return "complete", EXIT_FINDINGS
    return "complete", EXIT_CLEAN


def _stamp():
    # Aware, not `utcnow()`: the naive form is deprecated from 3.12 and every
    # other tool in this skill already stamps the same way.
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def build_status(art):
    """The run-status.json document, from artifacts and from nothing else."""
    completed, missing, unadjudicated, unarbitrated, notes = stage_account(art)
    confirmed, review, dismissed, accepted, odd = verdict_counts(art)

    analyzers = analyzer_status_counts(art)
    tool_failures = sum(1 for row in analyzers if row[3] in ANALYZER_INCOMPLETE)

    secrets = secrets_findings(art)
    dependency_findings = len(art["dependencies"])
    incomplete_tasks = len(unadjudicated) + len(unarbitrated)

    gates = gate_failures(art) + odd + notes
    limitations = coverage_limitations(art)

    run = art["run"] or {}
    snapshot = run.get("snapshot")
    cap_hit = bool(isinstance(snapshot, dict) and snapshot.get("cap_hit"))

    setup = bool(gates)
    is_incomplete = bool(missing or incomplete_tasks or tool_failures or cap_hit)
    blocking = confirmed + review + (secrets or 0) + dependency_findings
    state, exit_code = decide(setup, is_incomplete, blocking > 0)

    point = art["operating_point"]
    not_selected = point.get("not_selected")
    if not isinstance(not_selected, int) or isinstance(not_selected, bool):
        not_selected = 0

    return collections.OrderedDict((
        ("schema_version", SCHEMA_VERSION),
        ("generated_at", _stamp()),
        ("generated_by", collections.OrderedDict(
            (("tool", TOOL_NAME), ("version", TOOL_VERSION)))),
        ("run_id", run.get("run_id")),
        ("execution_state", state),
        ("stages_completed", completed),
        ("stages_missing", missing),
        ("confirmed_findings", confirmed),
        ("review_candidates", review),
        ("dismissed", dismissed),
        # Kept apart from `dismissed` on purpose - see ACCEPTED_VERDICTS.
        ("accepted_risk", accepted),
        ("incomplete_tasks", incomplete_tasks),
        ("tool_failures", tool_failures),
        ("gate_failures", gates),
        ("coverage_limitations", limitations),
        # `null` and `0` are different answers: null is "the sweep did not run",
        # 0 is "it ran and found no hardcoded secret". Collapsing them would make
        # a stage that never ran report a clean one.
        ("secrets_findings", secrets),
        ("dependency_findings", dependency_findings),
        ("not_selected", not_selected),
        # A literal, always true, for the same reason §6 makes it a literal: the
        # number above it must not be readable without the sentence that
        # qualifies it.
        ("not_selected_is_not_a_clean_bill", True),
        ("exit_code", exit_code),
        ("exit_reason", exit_reason(state, exit_code, gates, missing,
                                    incomplete_tasks, tool_failures, cap_hit,
                                    confirmed, review, secrets,
                                    dependency_findings, not_selected)),
    ))


def exit_reason(state, exit_code, gates, missing, incomplete_tasks,
                tool_failures, cap_hit, confirmed, review, secrets,
                dependency_findings, not_selected):
    """One sentence saying why this code and not another."""
    if state == "setup_failed":
        return ("%d setup or gate failure(s): %s Nothing in this run is "
                "reportable as a result until that is resolved."
                % (len(gates), gates[0] if gates else ""))
    if state == "incomplete":
        why = []
        if missing:
            why.append("stage(s) %s did not complete" % ", ".join(missing))
        if incomplete_tasks:
            why.append("%d dispatched task(s) never reached a terminal state"
                       % incomplete_tasks)
        if tool_failures:
            why.append("%d analyzer run(s) did not finish" % tool_failures)
        if cap_hit:
            why.append("the snapshot stopped at a cap, so the tree was only "
                       "partly admitted")
        return ("Required analysis is incomplete: %s. The counts above are a "
                "floor, not a result - an incomplete run and a clean run both "
                "report zero findings, and this one is the former."
                % "; ".join(why))
    if exit_code == EXIT_FINDINGS:
        parts = ["%d confirmed finding(s)" % confirmed,
                 "%d review candidate(s)" % review]
        if secrets:
            parts.append("%d hardcoded secret(s)" % secrets)
        if dependency_findings:
            parts.append("%d vulnerable dependency(ies)" % dependency_findings)
        return ("Required analysis completed. %s require action under policy."
                % ", ".join(parts))
    return ("Required analysis completed and nothing is blocking under policy. "
            "This is not a statement that the repository is secure: %d function(s) "
            "were never selected for adjudication, and what was not selected was "
            "not cleared." % not_selected)


# --------------------------------------------------------------------------- #
# --check
# --------------------------------------------------------------------------- #

# Everything except when the file was written. A status file produced by an older
# run_status.py IS drift - the derivation changed - and regenerating it is one
# command, so `generated_by` is compared like any other field.
IGNORED_ON_CHECK = ("generated_at",)


# `coverage_limitations` and `gate_failures` are lists of sentences, and their
# ORDER is a rendering decision - every source iterates a sorted listdir or a
# sorted dict today, but nothing asserts that, so a limitation built from an
# unsorted set would surface here as drift rather than as the bug it is. What
# --check is asking is whether the file says the same THINGS, so two lists of
# the same sentences in a different order are not drift. A repeated sentence
# still counts: sorted() compares multisets, not sets.
def _differs(left, right):
    if isinstance(left, list) and isinstance(right, list):
        try:
            return sorted(left, key=json.dumps) != sorted(right, key=json.dumps)
        except TypeError:
            return left != right
    return left != right


def differences(on_disk, computed):
    """Every way the file on disk disagrees with what the artifacts say."""
    out = []
    if not isinstance(on_disk, dict):
        return ["run-status.json is not a JSON object"]
    keys = [k for k in computed if k not in IGNORED_ON_CHECK]
    for key in keys:
        if key not in on_disk:
            out.append("field `%s` is missing from run-status.json; the "
                       "artifacts give %s" % (key, json.dumps(computed[key])))
        elif _differs(on_disk[key], computed[key]):
            out.append("field `%s`: run-status.json says %s, the artifacts say %s"
                       % (key, json.dumps(on_disk[key]),
                          json.dumps(computed[key])))
    for key in on_disk:
        if key not in computed and key not in IGNORED_ON_CHECK:
            out.append("field `%s` is in run-status.json and is not something "
                       "this tool computes" % key)
    return out


# --------------------------------------------------------------------------- #
# output
# --------------------------------------------------------------------------- #

def _under(path, directory):
    return path.startswith(directory + os.sep)


def check_run_dir_links(root, target):
    """Refuse a write into the run directory that a symlink would redirect.

    The run directory lives inside the scanned tree, which is the one tree
    this skill cannot trust, and a repository can legitimately commit
    `.security-review/ledger/` - so it can commit a link there too. Three ways a
    write under it would land somewhere else: `.security-review` or a directory
    beneath it on the way to the file is a link; the file itself is a link;
    the run directory does not resolve to `<real root>/.security-review`. The
    root itself and everything above it are never checked: `--root` may be a
    link on purpose, and on macOS /var is one.

    Every tool that writes under `.security-review/` enforces the same three
    cases: through rules_lib in the tools that already import it, and through a
    local copy like this one in the tools that import nothing from the skill
    (snapshot.py, score_functions.py, enrich_candidates.py, ledger.py), because
    the tools avoid new shared imports. Change them together.
    """
    run_dir = os.path.join(root, RUN_DIR)
    why = ("Contract §1 puts the run directory at <root>/%s and §9 rule 2 "
           "keeps every write inside it; following a link the scanned tree "
           "planted would write run-status.json wherever the tree chose. "
           "Remove the link and re-run." % RUN_DIR)
    path = run_dir
    parts = os.path.relpath(os.path.dirname(target), run_dir).split(os.sep)
    for part in [p for p in parts if p not in ("", os.curdir)] + [None]:
        if os.path.islink(path):
            raise Refused("%s is a symlink to %s. %s"
                          % (path, os.readlink(path), why))
        if part is None or not os.path.lexists(path):
            break
        path = os.path.join(path, part)
    if os.path.islink(target):
        raise Refused("%s is a symlink to %s. %s"
                      % (target, os.readlink(target), why))
    real = os.path.realpath(run_dir)
    want = os.path.join(os.path.realpath(root), RUN_DIR)
    if real != want:
        raise Refused("%s resolves to %s, not %s. %s" % (run_dir, real, want, why))


def _below_run_dir(root, target):
    """`target` relative to the run directory, when it is spelled under
    `<root>/.security-review` by ANY spelling of the root; otherwise None.

    A root has more than one spelling as soon as a link sits above it - on
    macOS `--root .` from /tmp/repo is /private/tmp/repo - and the --out an
    operator types need not use the one --root produced. Matched on --root's
    spelling alone, `/tmp/repo/.security-review/ci/x.json` was not "under the
    run directory", so the link walk never ran and a planted
    `.security-review/ci -> elsewhere` was written through.
    """
    root_real = os.path.realpath(root)
    head, below = os.path.dirname(target), [os.path.basename(target)]
    while True:
        if (os.path.basename(head) == RUN_DIR
                and os.path.realpath(os.path.dirname(head)) == root_real):
            return os.path.join(*below)
        parent = os.path.dirname(head)
        if parent == head:
            return None
        below.insert(0, os.path.basename(head))
        head = parent


def status_path(root, out):
    """Where run-status.json is written, refused where writing it would break
    contract §9 rule 2 (the tree under review is never written) or §1 (the
    run directory is not a door out of the tree).

    `--out` outside the scanned root is fine - the README's own example is
    `--out /tmp/run-status.json`, and a file there contaminates nothing. Inside
    the root, only the run directory: `--out src/rs.json` used to drop a status
    file into the code under review. Symlinks in the parent path are resolved
    before deciding, so `src/link/x.json` cannot reach the tree by a side door;
    a link AT the target outside the tree is harmless, because the write
    replaces the link rather than writing through it.
    """
    root = os.path.abspath(root)
    run_dir = os.path.join(root, RUN_DIR)
    target = (os.path.abspath(out) if out
              else os.path.join(run_dir, STATUS_NAME))
    below = _below_run_dir(root, target)
    if below is not None:
        # Walked from .security-review down under --root's own spelling, which
        # names the same directories: the links that matter are the ones in
        # the run directory, however the root above it was spelled.
        check_run_dir_links(root, os.path.join(run_dir, below))
        return target

    root_real = os.path.realpath(root)
    run_real = os.path.join(root_real, RUN_DIR)
    resolved = os.path.join(os.path.realpath(os.path.dirname(target)),
                            os.path.basename(target))
    if _under(resolved, run_real):
        # Spelled some other way, landing in the run directory: the same rules
        # apply to the path it lands on.
        check_run_dir_links(root, os.path.join(
            run_dir, os.path.relpath(resolved, run_real)))
        return target
    if resolved == root_real or _under(resolved, root_real):
        raise Refused(
            "--out %s resolves to %s, which is inside the scanned tree at %s "
            "and outside its %s/. Contract §9 rule 2: no tool in this skill "
            "writes to the tree under review, and a status file dropped into "
            "the code being reviewed is exactly that. Write it under %s, or "
            "anywhere outside the tree (--out /tmp/run-status.json)."
            % (out, resolved, root_real, RUN_DIR, run_dir))
    return target


def _umask():
    """The process umask. It can only be read by setting it, so it is set back
    at once; this tool runs no threads."""
    mask = os.umask(0o077)
    os.umask(mask)
    return mask


def write_status(path, status):
    """Atomically, and never through a link.

    `path + ".tmp"` was a name anybody could predict, in a directory the
    scanned tree can ship: a committed `.security-review/run-status.json.tmp`
    symlink made this write the status JSON into whatever it pointed at.
    mkstemp creates its file with O_EXCL, which never follows a link, and
    os.replace swaps a link at `path` rather than writing through it.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory,
                               prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(status, fh, indent=2)
            fh.write("\n")
        # mkstemp makes the file 0600. The mode open(path, "w") gave it before
        # is 0666 under the umask - not a fixed 0644, which would widen an
        # operator's `umask 077` to world-readable.
        os.chmod(tmp, 0o666 & ~_umask())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def summarise(status, stream=sys.stdout):
    print("execution_state: %s" % status["execution_state"], file=stream)
    print("  stages completed: %s"
          % (", ".join(status["stages_completed"]) or "none"), file=stream)
    print("  stages missing:   %s"
          % (", ".join(status["stages_missing"]) or "none"), file=stream)
    secrets = status["secrets_findings"]
    print("  confirmed %d   review %d   dismissed %d   accepted-risk %d"
          % (status["confirmed_findings"], status["review_candidates"],
             status["dismissed"], status["accepted_risk"]), file=stream)
    print("  secrets %s   dependencies %d   not selected %d"
          % ("not swept" if secrets is None else secrets,
             status["dependency_findings"], status["not_selected"]), file=stream)
    print("  incomplete tasks %d   tool failures %d"
          % (status["incomplete_tasks"], status["tool_failures"]), file=stream)
    for label, key in (("gate failure", "gate_failures"),
                       ("coverage limitation", "coverage_limitations")):
        rows = status[key]
        if rows:
            print("  %s(s) (%d):" % (label, len(rows)), file=stream)
            for row in rows:
                print("    - %s" % row, file=stream)
    print("exit %d: %s" % (status["exit_code"], status["exit_reason"]),
          file=stream)


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        if isinstance(obj, str):
            fh.write(obj)
        else:
            json.dump(obj, fh, indent=1)


def _fixture(tmp, stages=("extract", "score", "enrich"),
             dispatched=("CAND-0001",), verdicts=None, arb=None,
             arb_queue=None, analyzers=(), deps=0, inventory=None,
             not_selected=0, deferred=0, stale=0, expired=0,
             unsupported=None, window=0, unreadable=0, snapshot=None,
             gate_problems=0, run_json=True, run_schema=1,
             suppressed=(), inventory_raw=None, unstattable=0,
             hits_unjoined=0, no_candidate=0, sink_drift=0,
             sink_unreadable=0, too_large=0, unclosed=0, excluded_dirs=(),
             unusable=0, ignored=0, extensionless=None, not_derived=None,
             triage_derived=0, triage_suppressed=0, triage_deferred=0, triage_split=True,
             twins=None):
    """A run directory with exactly the artifacts a case needs.

    Real files in a real directory, because every failure this tool is written
    against is a file being absent, truncated or lying - none of which a mocked
    loader can reproduce.
    """
    base = os.path.join(tmp, RUN_DIR)
    os.makedirs(base, exist_ok=True)

    if run_json:
        run = {"schema_version": run_schema, "run_id": "2026-09-19T10-00-00Z",
               "started_at": "2026-09-19T10:00:00Z", "repo_root": tmp,
               "git": {"commit": "abc123", "branch": "main", "dirty": False},
               "bundle_version": "2.0.0", "rules_hash": "85e67df5f1ce7ed4",
               "snapshot": snapshot,
               "environment": {"python": "3.11.15", "tree_sitter": True},
               "stages_completed": list(stages)}
        _write(os.path.join(base, "run.json"), run)

    if "extract" in stages:
        total = 10
        _write(os.path.join(base, "extract", "extract-report.json"), {
            "schema_version": 1, "tool": "extract_functions.py",
            "counts": {"files_scanned": 6, "files_unreadable": unreadable,
                       "files_too_large": too_large,
                       "files_unstattable": unstattable,
                       "functions": total, "hits_unjoined": hits_unjoined,
                       "functions_unclosed": unclosed},
            "files_with_hits_no_functions": 1 if hits_unjoined else 0,
            # The shapes stage 1 writes: a string per unreadable file, an
            # object per oversize, unstattable and unclosed one.
            "unreadable_files": (["src/u%d.c:1: binary content, not scanned" % n
                                  for n in range(unreadable - 1)]
                                 + ["src/perm.c: [Errno 13] Permission denied"]
                                 if unreadable else []),
            "too_large_files": [{"file": "gen/big%d.c" % n, "bytes": 3000000}
                                for n in range(too_large)],
            "unstattable_files": [{"file": "src/Gone.c", "error": "ENOENT"}
                                  for _ in range(unstattable)],
            "unclosed_files": ([{"file": "src/brace.c", "functions": unclosed}]
                               if unclosed else []),
            "excluded_dirs": list(excluded_dirs),
            "confidence": {"exact": total - window, "heuristic": 0,
                           "window": window,
                           "window_share": round(window / float(total), 4)},
            "by_language": {"c": {"files": 1, "functions": total,
                                  "exact": total - window, "heuristic": 0,
                                  "window": window}},
            "unsupported_extensions": dict(unsupported or {}),
            "extensionless_files": dict(extensionless or {
                "files": 0, "scripts": {}, "readable_languages": [],
                "script_files": []}),
        })

    if "score" in stages:
        _write(os.path.join(base, "scores", "operating-point.json"), {
            "schema_version": 1, "calibration": "uncalibrated",
            "score_kind": "ordinal",
            "strict": {"mode": "top_k", "k": 200, "cutoff_rank": 200},
            "loose": {"mode": "top_percent", "percent": 2.0},
            "budget": {"max_adjudicated": 400},
            "selected": len(dispatched), "not_selected": not_selected,
            "fpr_claim": None, "recall_claim": None,
            "provenance": "rank-based", "not_selected_is_not_a_clean_bill": True,
        })

    if "enrich" in stages:
        # `function_key` as the real writer spells it, so the verdict-binding
        # check (bind_to_run) runs on every happy-path case rather than only in
        # the cases written to fail it.
        entries = [{"candidate_id": cid, "function_key": "src/a.c::f::0",
                    "rank": n + 1, "tier": "strict",
                    "category": "memory-safety", "rule_id": "MEM-002",
                    "suppressed": False, "suppression": None}
                   for n, cid in enumerate(dispatched)]
        entries += [{"candidate_id": cid, "function_key": "src/a.c::g::0",
                     "rank": 99, "tier": "strict",
                     "category": "memory-safety", "rule_id": "MEM-002",
                     "suppressed": True, "suppression": "SUP-0009"}
                    for cid in suppressed]
        _write(os.path.join(base, "enrich", "queue.json"), {
            "schema_version": 1, "operating_point": {}, "entries": entries,
            # `dispatched` is in the real writer's counts and is what
            # queue_problems reconciles the entries against, so the fixture
            # carries it: a check nothing exercises on the happy path is a check
            # that only ever runs when it fails.
            "counts": {"total": len(entries), "strict": len(entries),
                       "loose": 0, "suppressed": len(suppressed),
                       "deferred": deferred, "dispatched": len(dispatched),
                       "selected_without_candidate": no_candidate,
                       "triage_derived": triage_derived,
                       **({"triage_derived_dispatched": (triage_derived - triage_suppressed
                                                         - triage_deferred),
                           "triage_derived_suppressed": triage_suppressed,
                           "triage_derived_deferred": triage_deferred}
                          if triage_split else {}),
                       "sink_text_drift": sink_drift,
                       "sink_text_unreadable": sink_unreadable},
            "selected_without_candidate": [
                dict({"function_key": "src/a.c::quiet_%d::0" % n, "file": "src/a.c"},
                     **({"not_derived_because": not_derived[n % len(not_derived)]}
                        if not_derived else {}))
                for n in range(no_candidate)],
            "twins": twins or {},
            "suppressions_stale": [
                {"suppression_id": "SUP-%04d" % (n + 1),
                 "function_key": "src/a.c::f::0",
                 "reason": "content_hash differs from creation"}
                for n in range(stale)],
            "suppressions_expired": [
                {"suppression_id": "SUP-EXP-%04d" % (n + 1)}
                for n in range(expired)],
            "suppressions_unusable": [
                {"suppression_id": "SUP-UNU-%04d" % (n + 1),
                 "function_key": "src/a.c::f::0", "rule_id": None,
                 "reason": "no rule_id, so it cannot be matched to one rule on "
                           "one function as it is now, or revoked (contract §8)"}
                for n in range(unusable)],
            "suppressions_ignored": [
                {"suppression_id": "SUP-WFS-%04d" % (n + 1),
                 "function_key": "src/a.c::f::0", "rule_id": "MEM-WFS",
                 "reason": "MEM-WFS is derived from the function's other "
                           "candidates"}
                for n in range(ignored)],
        })
        runs = []
        for n, (analyzer, status) in enumerate(analyzers):
            runs.append({"sarif_file": "enrich/analyzers/%s.sarif" % analyzer,
                         "run_index": n, "analyzer": analyzer,
                         "analyzer_driver": analyzer, "analyzer_version": "1.0",
                         "execution_successful": status == "complete",
                         "exit_code": 0, "error_notifications": 0,
                         "results_truncated": False, "rules_declared": 1,
                         "results": 0, "status": status,
                         "basis": "fixture run recorded %s" % status})
        _write(os.path.join(base, "enrich", "analyzer-runs.json"), {
            "schema_version": 1, "generated_at": "2026-09-19T10:00:01Z",
            "generated_by": {"tool": "enrich_candidates.py", "version": "1.0.0"},
            "counts": {s: sum(1 for r in runs if r["status"] == s)
                       for s in ("complete", "partial", "failed", "unknown")},
            "runs": runs,
        })
        with open(os.path.join(base, "enrich", "dependencies.jsonl"), "w",
                  encoding="utf-8") as fh:
            for n in range(deps):
                fh.write(json.dumps({
                    "schema_version": 1, "finding_id": "DEP-%06d" % n,
                    "analyzer": "osv-scanner", "advisory": "GHSA-xxxx",
                    "package": {"ecosystem": "npm", "name": "lodash",
                                "version": "4.17.15"},
                    "adjudicated": False}) + "\n")
        if deferred:
            _write(os.path.join(base, "candidates", "memory-safety-deferred.json"),
                   [{"candidate_id": "CAND-%04d" % (900 + n),
                     "category": "memory-safety", "rule_id": "MEM-002",
                     "file": "src/a.c"}
                    for n in range(deferred)])

    for candidate_id, verdict in (verdicts or {}).items():
        _write(os.path.join(base, "findings", "%s.json" % candidate_id), {
            "schema_version": 1, "candidate_id": candidate_id,
            "rule_id": "MEM-002", "cwe": "CWE-787", "verdict": verdict,
            "confidence": "high", "severity": "high",
            "title": "fixture finding", "primary_location": "src/a.c:12",
            "evidence": [], "gates_evaluated": [],
        })

    if arb_queue is not None:
        _write(os.path.join(base, "arbitration", "queue.json"), {
            "summary": {"total_findings": len(verdicts or {}),
                        "queued_for_arbitration": len(arb_queue),
                        "citations_verified": 1,
                        "counts": {"VULNERABLE": sum(
                            1 for v in (verdicts or {}).values()
                            if v == "VULNERABLE")}},
            "queue": [{"candidate_id": cid, "rule_id": "MEM-002",
                       "verdict": (verdicts or {}).get(cid),
                       "reasons": ["fixture"], "priority": 1}
                      for cid in arb_queue],
        })

    for candidate_id, final in (arb or {}).items():
        _write(os.path.join(base, "arbitration", "ARB-%s.json" % candidate_id), {
            "candidate_id": candidate_id, "rule_id": "MEM-002",
            "arbitration": "UPHELD", "original_verdict": final,
            "final_verdict": final, "final_severity": "high",
            "final_confidence": "high", "crux": "fixture",
            "mechanical": {"citations_verified": 1, "citations_failed": 0,
                           "drift": 0, "problems": []},
        })

    if gate_problems:
        _write(os.path.join(base, "arbitration", "coverage-precheck.json"), {
            "summary": {"problems": gate_problems,
                        "problem_codes": {"coverage_count_mismatch":
                                          gate_problems}},
            "problems": [{"code": "coverage_count_mismatch",
                          "detail": "rule MEM-002 recorded 196 hits; "
                                    "re-running its pattern gives 190"}
                         for _ in range(gate_problems)],
        })

    if inventory is not None:
        _write(os.path.join(base, "secrets", "inventory.json"), {
            "schema_version": 1, "entries": inventory})
    # An inventory whose SHAPE is the thing under test, written verbatim.
    if inventory_raw is not None:
        _write(os.path.join(base, "secrets", "inventory.json"), inventory_raw)
    return base


def _status(tmp):
    return build_status(collect(tmp))


def selftest():
    import contextlib
    import io
    failures = 0

    def ok(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    def has(label, rows, needle):
        ok(label, any(needle in row for row in rows), True)

    def rewrite(path, drop=(), **fields):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc.update(fields)
        for key in drop:
            doc.pop(key, None)
        _write(path, doc)

    def link(target, name):
        """os.symlink, or False where this platform will not make one."""
        try:
            os.symlink(target, name)
            return True
        except (OSError, NotImplementedError, AttributeError):
            print("  skip symlink case: this platform cannot make one")
            return False

    def quiet_main(argv):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(argv)
        return code, err.getvalue()

    # ---- execution_state: complete ---------------------------------------- #
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                 arb_queue=[], analyzers=(("semgrep", "complete"),),
                 inventory=[])
        s = _status(tmp)
        ok("a run with every stage finished is complete",
           s["execution_state"], "complete")
        ok("and with nothing blocking it exits 0", s["exit_code"], EXIT_CLEAN)
        ok("the dismissal is counted as one", s["dismissed"], 1)
        ok("no stage is missing", s["stages_missing"], [])
        ok("the derived stages are in stages_completed, not only run.json's",
           s["stages_completed"],
           ["extract", "score", "enrich", "adjudicate", "arbitrate"])
        ok("the literal qualification is on the file",
           s["not_selected_is_not_a_clean_bill"], True)
        ok("and the 0 exit still says the repository is not certified secure",
           "not a statement that the repository is secure" in s["exit_reason"],
           True)

    # ---- execution_state: incomplete -------------------------------------- #
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, dispatched=("CAND-0001", "CAND-0002"),
                 verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("a dispatched candidate with no verdict makes the run incomplete",
           s["execution_state"], "incomplete")
        ok("it is counted as an incomplete task", s["incomplete_tasks"], 1)
        ok("adjudicate and arbitrate are the missing stages",
           s["stages_missing"], ["adjudicate", "arbitrate"])
        ok("and the run exits 3", s["exit_code"], EXIT_INCOMPLETE)
        ok("the reason says the counts are a floor",
           "floor, not a result" in s["exit_reason"], True)

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                 arb_queue=["CAND-0001"], analyzers=(("semgrep", "complete"),),
                 inventory=[])
        s = _status(tmp)
        ok("a queued finding with no ARB record is incomplete too",
           (s["execution_state"], s["incomplete_tasks"]), ("incomplete", 1))
        ok("and only arbitrate is missing", s["stages_missing"], ["arbitrate"])

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "failed"),), inventory=[])
        s = _status(tmp)
        ok("an analyzer that failed is a tool failure", s["tool_failures"], 1)
        ok("and an incomplete analysis, not a complete one",
           (s["execution_state"], s["exit_code"]), ("incomplete", EXIT_INCOMPLETE))

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "partial"),), inventory=[])
        s = _status(tmp)
        ok("a PARTIAL analyzer run is a failure too - 'missing or partial "
           "analysis cannot become a clean result'",
           (s["tool_failures"], s["exit_code"]), (1, EXIT_INCOMPLETE))

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "unknown"),), inventory=[])
        s = _status(tmp)
        ok("an UNKNOWN one is not: most tools write no invocation block",
           (s["tool_failures"], s["exit_code"]), (0, EXIT_CLEAN))
        has("but it is still a coverage limitation",
            s["coverage_limitations"], "finished as `unknown`")

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[],
                 snapshot={"id": "473367cc14267f10", "files": 2, "bytes": 91,
                           "cap_hit": "max_files", "changed_during_snapshot": 0})
        s = _status(tmp)
        ok("a snapshot that hit its cap is an incomplete run",
           (s["execution_state"], s["exit_code"]), ("incomplete", EXIT_INCOMPLETE))

    # ---- execution_state: setup_failed ------------------------------------ #
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, run_json=False, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                 arb_queue=[], analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("a run with no run.json is a setup failure",
           (s["execution_state"], s["exit_code"]), ("setup_failed", EXIT_SETUP))
        has("and says which file is missing", s["gate_failures"], "run.json")

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        os.remove(os.path.join(tmp, RUN_DIR, "enrich", "queue.json"))
        s = _status(tmp)
        ok("a stage that recorded itself complete without leaving its artifact "
           "is a setup failure, not a run with no candidates",
           (s["execution_state"], s["exit_code"]), ("setup_failed", EXIT_SETUP))

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        with open(os.path.join(tmp, RUN_DIR, "enrich", "queue.json"), "w",
                  encoding="utf-8") as fh:
            fh.write("{ this is not json")
        s = _status(tmp)
        ok("an artifact that does not parse is a setup failure and not a zero",
           (s["execution_state"], s["exit_code"]), ("setup_failed", EXIT_SETUP))

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[],
                 gate_problems=3)
        s = _status(tmp)
        ok("a precheck gate that recorded problems is a gate failure",
           (s["execution_state"], s["exit_code"]), ("setup_failed", EXIT_SETUP))
        has("naming the gate and the codes", s["gate_failures"],
            "coverage_count_mismatch x3")

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, run_schema=2)
        try:
            _status(tmp)
            ok("a run.json from a newer schema is refused, not guessed at",
               False, True)
        except Refused as exc:
            ok("a run.json from a newer schema is refused, not guessed at",
               "schema_version 2" in str(exc), True)

    with tempfile.TemporaryDirectory() as tmp:
        try:
            collect(tmp)
            ok("a tree with no .security-review/ is refused", False, True)
        except Refused as exc:
            ok("a tree with no .security-review/ is refused",
               "no run here to report on" in str(exc), True)

    # ---- the precedence, in every pairwise combination -------------------- #
    #
    # setup > incomplete > findings > clean. The third row is the one that
    # matters: an incomplete run WITH findings exits 3, because it looks exactly
    # like a successful run with findings and is not one.
    cases = (
        # (setup, incomplete, findings) -> (state, exit)
        ((False, False, False), ("complete", EXIT_CLEAN)),
        ((False, False, True), ("complete", EXIT_FINDINGS)),
        ((False, True, False), ("incomplete", EXIT_INCOMPLETE)),
        ((False, True, True), ("incomplete", EXIT_INCOMPLETE)),
        ((True, False, False), ("setup_failed", EXIT_SETUP)),
        ((True, False, True), ("setup_failed", EXIT_SETUP)),
        ((True, True, False), ("setup_failed", EXIT_SETUP)),
        ((True, True, True), ("setup_failed", EXIT_SETUP)),
    )
    for (setup, incomplete, findings), want in cases:
        ok("precedence setup=%s incomplete=%s findings=%s"
           % (setup, incomplete, findings),
           decide(setup, incomplete, findings), want)

    # And the same eight against real run directories, because a precedence rule
    # that only holds in the function that states it is not enforced.
    for setup, incomplete, findings in (c[0] for c in cases):
        with tempfile.TemporaryDirectory() as tmp:
            dispatched = ("CAND-0001", "CAND-0002") if incomplete else ("CAND-0001",)
            verdict = "VULNERABLE" if findings else "NOT_VULNERABLE"
            _fixture(tmp, dispatched=dispatched,
                     verdicts={"CAND-0001": verdict},
                     arb={"CAND-0001": verdict},
                     arb_queue=["CAND-0001"],
                     analyzers=(("semgrep", "complete"),), inventory=[],
                     gate_problems=2 if setup else 0)
            s = _status(tmp)
            want_state, want_code = dict(cases)[(setup, incomplete, findings)]
            ok("on disk: setup=%s incomplete=%s findings=%s"
               % (setup, incomplete, findings),
               (s["execution_state"], s["exit_code"]), (want_state, want_code))
            if incomplete and findings and not setup:
                ok("  ...and the findings are still counted, not hidden by the 3",
                   s["confirmed_findings"], 1)

    # ---- what counts as a policy finding ---------------------------------- #
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NEEDS_HUMAN_REVIEW"},
                 arb_queue=[], analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("a NEEDS_HUMAN_REVIEW verdict is a review candidate and blocks",
           (s["review_candidates"], s["exit_code"]), (1, EXIT_FINDINGS))

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "ACCEPTED_RISK"},
                 arb_queue=[], analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("ACCEPTED_RISK is counted apart from dismissed",
           (s["accepted_risk"], s["dismissed"]), (1, 0))
        ok("and does not block, because somebody already accepted it",
           s["exit_code"], EXIT_CLEAN)

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "SOMETHING_ELSE"},
                 arb_queue=[], analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("a verdict nothing recognises becomes a review candidate, never a "
           "dismissal", (s["review_candidates"], s["dismissed"]), (1, 0))
        ok("and it is a gate failure as well, so it cannot pass quietly",
           s["execution_state"], "setup_failed")

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                 arb={"CAND-0001": "VULNERABLE"}, arb_queue=["CAND-0001"],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("the arbiter's final_verdict wins over the validator's",
           (s["confirmed_findings"], s["dismissed"]), (1, 0))

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), deps=2,
                 inventory=[])
        s = _status(tmp)
        ok("a vulnerable dependency blocks on its own",
           (s["dependency_findings"], s["exit_code"]), (2, EXIT_FINDINGS))

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),),
                 inventory=[{"entry_id": "SEC-0001", "kind": "secret",
                             "origin": "literal", "is_finding": True},
                            {"entry_id": "SEC-0002", "kind": "secret",
                             "origin": "env", "is_finding": False},
                            {"entry_id": "SEC-0003", "kind": "public",
                             "origin": "wire", "is_finding": False}])
        s = _status(tmp)
        ok("only kind=secret origin=literal entries are secrets findings - "
           "holding a secret is not one", s["secrets_findings"], 1)
        ok("and one blocks", s["exit_code"], EXIT_FINDINGS)

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=None)
        s = _status(tmp)
        ok("an absent inventory is null, never 0", s["secrets_findings"], None)
        has("and says the sweep did not run", s["coverage_limitations"],
            "stage 1's secret sweep did not run")

    # Contract §4a's rule is COMPUTED here, never read off `is_finding`. That
    # field is written by the agent that judged the candidates, and
    # sweep_secrets.py already records both directions of it going wrong. A
    # hardcoded secret filed as `is_finding: false` must not become a zero in
    # the one artifact a CI job reads, and the two tools must not print
    # different numbers from the same file.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),),
                 inventory=[{"entry_id": "SEC-0001", "kind": "secret",
                             "origin": "literal", "is_finding": False}])
        s = _status(tmp)
        ok("a hardcoded secret marked is_finding:false is still counted - the "
           "rule is computed, not read off the field",
           s["secrets_findings"], 1)
        ok("and it blocks, rather than passing as a clean run",
           s["exit_code"], EXIT_SETUP)
        has("with the disagreement named as a gate failure", s["gate_failures"],
            "contradict contract §4a's rule")
        has("...naming the entry", s["gate_failures"], "SEC-0001")

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),),
                 inventory=[{"entry_id": "SEC-0002", "kind": "secret",
                             "origin": "env", "is_finding": True}])
        s = _status(tmp)
        ok("and HOLDING a secret is not a finding however the field is marked",
           s["secrets_findings"], 0)

    # An inventory that is on disk and is not one. Null for both is unavoidable
    # - there is nothing to count - but "the sweep did not run" is then a false
    # sentence about a file that exists, so it belongs in gate_failures instead.
    # JSON null is the case that used to get through: it parses, json.load
    # hands back the same None an absent file gets, and the sentence said the
    # sweep never ran about a file the sweeper wrote.
    for label, raw in (("with no `entries`", {"schema_version": 1}),
                       ("whose `entries` is an object",
                        {"schema_version": 1, "entries": {"a": 1}}),
                       ("that is a bare number", 7),
                       ("that is JSON null", "null"),
                       ("with a non-object entry",
                        {"schema_version": 1, "entries": ["SEC-0001"]})):
        with tempfile.TemporaryDirectory() as tmp:
            _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                     arb_queue=[], analyzers=(("semgrep", "complete"),),
                     inventory_raw=raw)
            s = _status(tmp)
            ok("an inventory %s is a gate failure, not a clean run" % label,
               s["exit_code"], EXIT_SETUP)
            ok("...and is never reported as an absent sweep",
               any("secret sweep did not run" in row
                   for row in s["coverage_limitations"]), False)
            has("...the sentence says the file is on disk", s["gate_failures"],
                "is on disk")

    # A sub-object of extract-report.json with the wrong TYPE. `.get` on a list
    # is an AttributeError, and an AttributeError leaves main() as exit 1 -
    # "completed, with findings" - unless something catches it.
    for key in ("counts", "confidence", "by_language", "unsupported_extensions",
                "extensionless_files"):
        with tempfile.TemporaryDirectory() as tmp:
            _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                     arb_queue=[], analyzers=(("semgrep", "complete"),),
                     inventory=[], window=3)
            path = os.path.join(tmp, RUN_DIR, "extract", "extract-report.json")
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            doc[key] = ["a list where a table belongs"]
            _write(path, doc)
            ok("extract-report.json `%s` of the wrong type does not crash the "
               "tool" % key, main(["--root", tmp, "--quiet"]), EXIT_SETUP)
            s = _status(tmp)
            has("...it is a named gate failure", s["gate_failures"],
                "`%s` is a list where a dict belongs" % key)

    # And whatever else goes wrong, the answer is 5 and never 1: 1 is
    # "completed, with findings" to every wrapper reading this tool.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        saved = globals()["build_status"]
        globals()["build_status"] = lambda art: (_ for _ in ()).throw(
            RuntimeError("fixture: something nobody predicted"))
        try:
            ok("an unexpected failure exits 5, never the 1 that means "
               "'completed, with findings'",
               main(["--root", tmp, "--quiet"]), EXIT_TOOL)
        finally:
            globals()["build_status"] = saved

    # Contract §0 applies to a .jsonl record exactly as it does to a .json one.
    with tempfile.TemporaryDirectory() as tmp:
        base = _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                        arb_queue=[], analyzers=(("semgrep", "complete"),),
                        inventory=[])
        with open(os.path.join(base, "enrich", "dependencies.jsonl"), "w",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({"schema_version": 2,
                                 "finding_id": "DEP-000001"}) + "\n")
        try:
            _status(tmp)
            ok("a dependencies.jsonl row from a newer schema is refused, not "
               "counted", False, True)
        except Refused as exc:
            ok("a dependencies.jsonl row from a newer schema is refused, not "
               "counted", "schema_version 2" in str(exc), True)

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, dispatched=("CAND-0001",), suppressed=("CAND-0009",),
                 verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("a suppressed candidate is not an incomplete task",
           (s["incomplete_tasks"], s["execution_state"]), (0, "complete"))

    # A queue that names one candidate twice. One candidate is one task, so the
    # duplicate must not become a second incomplete task - and it must not go
    # quiet either, because a queue that cannot be reconciled with itself is not
    # an account of what stage 3 dispatched.
    with tempfile.TemporaryDirectory() as tmp:
        base = _fixture(tmp, dispatched=("CAND-0001", "CAND-0002"),
                        verdicts={"CAND-0001": "NOT_VULNERABLE",
                                  "CAND-0002": "NOT_VULNERABLE"},
                        arb_queue=[], analyzers=(("semgrep", "complete"),),
                        inventory=[])
        path = os.path.join(base, "enrich", "queue.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["entries"].append(dict(doc["entries"][0]))
        _write(path, doc)
        s = _status(tmp)
        ok("a duplicated queue entry is not a second incomplete task",
           s["incomplete_tasks"], 0)
        has("but the duplicate is reported", s["gate_failures"],
            "lists 1 candidate id(s) more than once")

    # queue.json carries counts.dispatched beside the entries it was computed
    # from. Checking one against the other is free, and a disagreement there is
    # the exact failure §0 of the contract is written about.
    with tempfile.TemporaryDirectory() as tmp:
        base = _fixture(tmp, dispatched=("CAND-0001",),
                        verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                        analyzers=(("semgrep", "complete"),), inventory=[])
        path = os.path.join(base, "enrich", "queue.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["counts"]["dispatched"] = 9
        _write(path, doc)
        s = _status(tmp)
        ok("a queue whose own dispatched count disagrees with its entries is a "
           "gate failure", s["exit_code"], EXIT_SETUP)
        has("...and says both numbers", s["gate_failures"],
            "`counts.dispatched` is 9 and carries 1 unsuppressed entry(ies)")

    # A repository the operating point selected nothing in. There is no
    # findings/ directory and no arbitration queue, because there was nothing to
    # put in either - and calling that a missing stage would fail every clean
    # small repository this tool is ever pointed at.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, dispatched=(), analyzers=(("semgrep", "complete"),),
                 inventory=[], not_selected=412)
        s = _status(tmp)
        ok("a run that dispatched nothing is complete, not missing stage 4",
           (s["execution_state"], s["exit_code"]), ("complete", EXIT_CLEAN))
        has("and the empty queue is reported as the coverage hole it is",
            s["coverage_limitations"], "an empty queue is not a clean queue")
        has("beside the functions nothing ranked high enough to reach",
            s["coverage_limitations"], "412 function(s)")

    # ...but verdicts on disk with no arbitration queue beside them means the
    # findings gate never ran, which is a gate failure and not an empty queue.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=None,
                 analyzers=(("semgrep", "complete"),), inventory=[])
        s = _status(tmp)
        ok("verdicts with no arbitration queue means the gate never ran",
           (s["execution_state"], s["exit_code"]), ("setup_failed", EXIT_SETUP))
        has("and says so", s["gate_failures"], "the findings gate never ran")

    # ---- an artifact on disk in a shape its writer never emits ------------ #
    #
    # Each of these used to be read `or {}` and swapped for {} in silence: a
    # real smoke run with 95 dispatched candidates and no verdicts exited 0 with
    # its queue.json replaced by any of the first four.
    queue_rel = os.path.join("enrich", "queue.json")
    for rel, label, raw in (
            (queue_rel, "queue.json as JSON null", "null"),
            (queue_rel, "queue.json as an array", []),
            (queue_rel, "queue.json with no `entries`", {"schema_version": 1}),
            (queue_rel, "queue.json whose `entries` is an object",
             {"schema_version": 1, "entries": {"CAND-0001": {}}}),
            (queue_rel, "queue.json whose entries are not objects",
             {"schema_version": 1, "entries": ["CAND-0001"]}),
            (os.path.join("enrich", "analyzer-runs.json"),
             "analyzer-runs.json keyed by analyzer name",
             {"schema_version": 1,
              "runs": {"semgrep": {"status": "failed"}}}),
            (os.path.join("enrich", "analyzer-runs.json"),
             "analyzer-runs.json as JSON null", "null"),
            (os.path.join("scores", "operating-point.json"),
             "operating-point.json as JSON null", "null"),
            (os.path.join("scores", "operating-point.json"),
             "operating-point.json as an array", []),
            (os.path.join("extract", "extract-report.json"),
             "extract-report.json as an array", []),
            (os.path.join("arbitration", "queue.json"),
             "arbitration/queue.json whose `queue` is an object",
             {"summary": {}, "queue": {"CAND-0001": {}}}),
            (os.path.join("arbitration", "queue.json"),
             "arbitration/queue.json as JSON null", "null")):
        with tempfile.TemporaryDirectory() as tmp:
            base = _fixture(tmp, dispatched=("CAND-0001", "CAND-0002"),
                            verdicts={"CAND-0001": "NOT_VULNERABLE"},
                            arb_queue=["CAND-0001"],
                            arb={"CAND-0001": "NOT_VULNERABLE"},
                            analyzers=(("semgrep", "complete"),),
                            inventory=[])
            _write(os.path.join(base, rel), raw)
            s = _status(tmp)
            ok("%s is a gate failure, not a zero" % label,
               (s["execution_state"], s["exit_code"]),
               ("setup_failed", EXIT_SETUP))
            has("...naming the file", s["gate_failures"],
                os.path.basename(rel))
            ok("...and never as a file that does not exist",
               any("does not exist" in row for row in s["gate_failures"]),
               False)
    with tempfile.TemporaryDirectory() as tmp:
        base = _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                        arb_queue=[], analyzers=(("semgrep", "complete"),),
                        inventory=[])
        _write(os.path.join(base, queue_rel), "null")
        s = _status(tmp)
        ok("a queue that could not be read is not a queue that dispatched "
           "nothing: adjudicate is not done",
           "adjudicate" in s["stages_missing"], True)

    # ---- a previous run's verdicts are not this run's --------------------- #
    #
    # Stage 3 renumbers from CAND-0001 on every run, so the findings/CAND-0002
    # a previous run left behind has exactly the name of this run's CAND-0002.
    # Measured: a run that stopped after stage 3, over code rewritten from a
    # strcpy to a system() call, reported "adjudicate, arbitrate: done,
    # dismissed 2" and exited 0 - both dismissals written about a function and
    # a rule the new candidates are not.
    def stale_run(tmp, **extra):
        kw = dict(dispatched=("CAND-0001", "CAND-0002"),
                  verdicts={"CAND-0001": "NOT_VULNERABLE",
                            "CAND-0002": "NOT_VULNERABLE"},
                  arb_queue=[], analyzers=(("semgrep", "complete"),),
                  inventory=[])
        kw.update(extra)
        return _fixture(tmp, **kw)

    with tempfile.TemporaryDirectory() as tmp:
        base = stale_run(tmp)
        rewrite(os.path.join(base, "findings", "CAND-0002.json"),
                rule_id="MEM-001")
        s = _status(tmp)
        ok("a verdict carrying another rule adjudicates nothing",
           (s["dismissed"], s["incomplete_tasks"]), (1, 1))
        ok("...so stage 4 is not done", "adjudicate" in s["stages_missing"],
           True)
        ok("...and the run cannot exit 0", s["exit_code"], EXIT_SETUP)
        has("...the gate failure names the record and both rules",
            s["gate_failures"],
            "CAND-0002 carries MEM-001 where this run's CAND-0002 is MEM-002")

    with tempfile.TemporaryDirectory() as tmp:
        base = stale_run(tmp)
        rewrite(os.path.join(base, "findings", "CAND-0002.json"),
                primary_location="src/zzz.c:4",
                evidence=[{"role": "sink", "file": "src/zzz.c", "line": 4}])
        s = _status(tmp)
        ok("a verdict about a function in another file adjudicates nothing, "
           "even under the same rule",
           (s["dismissed"], s["incomplete_tasks"], s["exit_code"]),
           (1, 1, EXIT_SETUP))
        has("...and says which file it cites and which it should",
            s["gate_failures"],
            "cites src/zzz.c where this run's CAND-0002 is in src/a.c")

    with tempfile.TemporaryDirectory() as tmp:
        base = stale_run(tmp)
        rewrite(os.path.join(base, "findings", "CAND-0002.json"),
                primary_location="src/zzz.c:4",
                evidence=[{"role": "sink", "file": "src/zzz.c", "line": 4}],
                files_read=["src/zzz.c", "src/zzz.h"],
                guards_considered=[{"file": "src/zzz.c", "line": 3}])
        s = _status(tmp)
        ok("files_read and guards that name only another file bind nothing",
           (s["dismissed"], s["incomplete_tasks"], s["exit_code"]),
           (1, 1, EXIT_SETUP))

    # What the binding must NOT call stale. Each of these is a verdict a
    # validator writes about the right candidate.
    for label, fields, drop in (
            ("a dismissal located at a guard in a caller, quoting this "
             "candidate's file in its evidence",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "sink", "file": "src/a.c", "line": 12}]},
             ()),
            ("a location spelled ./src/a.c", {"primary_location": "./src/a.c:12"},
             ()),
            ("an absolute location",
             {"primary_location": "/work/repo/src/a.c:12"}, ()),
            ("a location with a line range",
             {"primary_location": "src/a.c:12-40"}, ()),
            ("a location with a note after the line",
             {"primary_location": "src/a.c:12 (the memcpy)"}, ()),
            ("a verdict with no rule_id (verify_findings recovers it)", {},
             ("rule_id",)),
            ("a verdict whose location is prose, not a path",
             {"primary_location": "the memcpy in parse_record"}, ()),
            ("a rule_id in lower case", {"rule_id": "mem-002"}, ()),
            # validator-contract §7: a dismissal cites "the declaration that
            # fixes the size, the caller that passes the constant" rather than
            # the sink, so all of its locations can be in another file.
            ("a dismissal citing only the header declaration that fixes the "
             "size, with the candidate's file in files_read",
             {"primary_location": "include/limits.h:31",
              "evidence": [{"role": "declaration", "file": "include/limits.h",
                            "line": 31}],
              "files_read": ["src/a.c:1-40", "include/limits.h"]}, ()),
            ("a dismissal at a caller naming the candidate's file only in "
             "guards_considered",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "caller", "file": "src/caller.c",
                            "line": 9}],
              "guards_considered": [{"file": "src/a.c", "line": 10}]}, ()),
            ("a dismissal naming the candidate's file only in an object-form "
             "false_positive_reasons entry",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "caller", "file": "src/caller.c",
                            "line": 9}],
              "false_positive_reasons": [{"code": "FP-GUARDED",
                                          "file": "src/a.c", "line": 10,
                                          "why": "fixture"}]}, ()),
            # files_read is optional (REQUIRED_IF_DISMISSAL does not list it),
            # so a correct dismissal can name no file of the candidate's at
            # all. The findings gate accepted each of these and the run exited
            # 4 with them uncounted.
            ("a dismissal located wholly at the caller that passes the "
             "constant, with no files_read",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "caller", "file": "src/caller.c",
                            "line": 9}],
              "false_positive_reasons": [
                  "FP-CONST: the only caller passes 16, src/caller.c:9"]}, ()),
            ("a dismissal located wholly at the header declaration that fixes "
             "the size, with no files_read",
             {"primary_location": "include/limits.h:31",
              "evidence": [{"role": "declaration", "file": "include/limits.h",
                            "line": 31}]}, ()),
            ("an FP-NOT-COMPILED dismissal citing only the build file",
             {"primary_location": "CMakeLists.txt:12",
              "evidence": [{"role": "config", "file": "CMakeLists.txt",
                            "line": 12}]}, ()),
            ("a files_read range written in prose",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "caller", "file": "src/caller.c",
                            "line": 9}],
              "files_read": ["src/a.c (lines 1-40)", "src/caller.c"]}, ()),
            ("a files_read range written as an anchor",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "caller", "file": "src/caller.c",
                            "line": 9}],
              "files_read": ["src/a.c#L1-L40"]}, ()),
            ("a files_read row written as an object with a path",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "caller", "file": "src/caller.c",
                            "line": 9}],
              "files_read": [{"path": "src/a.c", "lines": "1-40"}]}, ()),
            ("a files_read that dropped the directory",
             {"primary_location": "src/caller.c:9",
              "evidence": [{"role": "caller", "file": "src/caller.c",
                            "line": 9}],
              "files_read": ["a.c", "src/caller.c"]}, ())):
        with tempfile.TemporaryDirectory() as tmp:
            base = stale_run(tmp)
            rewrite(os.path.join(base, "findings", "CAND-0002.json"),
                    drop=drop, **fields)
            s = _status(tmp)
            ok("%s is this run's verdict" % label,
               (s["dismissed"], s["exit_code"], s["gate_failures"]),
               (2, EXIT_CLEAN, []))

    # And what it still must. The boundary is the point: a plain substring
    # test reads src/a.c into src/ab.c and src/a.cc and stops catching them.
    def respelled(base, path):
        """CAND-0002's file, as stage 3 wrote it into the dispatch queue."""
        queue_path = os.path.join(base, "enrich", "queue.json")
        with open(queue_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for entry in doc["entries"]:
            if entry["candidate_id"] == "CAND-0002":
                entry["function_key"] = "%s::f::0" % path
        _write(queue_path, doc)

    for label, fields, where in (
            ("a sink in src/ab.c", {
                "primary_location": "src/ab.c:4",
                "evidence": [{"role": "sink", "file": "src/ab.c", "line": 4}]},
             None),
            ("a sink in src/a.cc", {
                "primary_location": "src/a.cc:4",
                "evidence": [{"role": "sink", "file": "src/a.cc", "line": 4}]},
             None),
            ("a sink in src/a.c.orig", {
                "primary_location": "src/a.c.orig:4",
                "evidence": [{"role": "sink", "file": "src/a.c.orig",
                              "line": 4}]}, None),
            ("a guard in another file and a files_read range naming only it", {
                "primary_location": "src/zzz.c:4",
                "evidence": [{"role": "guard", "file": "src/zzz.c", "line": 4}],
                "files_read": ["src/zzz.c (lines 1-9)"]}, None),
            ("a sink in another directory with a space in it", {
                "primary_location": "Other Dir/x.c:4",
                "evidence": [{"role": "sink", "file": "Other Dir/x.c",
                              "line": 4}]}, "Source Files/a.c")):
        with tempfile.TemporaryDirectory() as tmp:
            base = stale_run(tmp)
            if where:
                respelled(base, where)
            rewrite(os.path.join(base, "findings", "CAND-0002.json"), **fields)
            s = _status(tmp)
            ok("%s is still another candidate's verdict" % label,
               (s["dismissed"], s["incomplete_tasks"], s["exit_code"]),
               (1, 1, EXIT_SETUP))

    # A path with a space in it. `Source Files/a.c` was dropped as prose, so
    # only the header beside it was left to compare, and a correct dismissal
    # citing both was called a previous run's.
    with tempfile.TemporaryDirectory() as tmp:
        base = stale_run(tmp)
        respelled(base, "Source Files/a.c")
        rewrite(os.path.join(base, "findings", "CAND-0002.json"),
                primary_location="Source Files/a.c:12",
                evidence=[{"role": "sink", "file": "Source Files/a.c",
                           "line": 12},
                          {"role": "declaration", "file": "include/limits.h",
                           "line": 31}],
                files_read=["Source Files/a.c", "include/limits.h"])
        s = _status(tmp)
        ok("a verdict about a candidate whose path has a space in it is this "
           "run's", (s["dismissed"], s["exit_code"], s["gate_failures"]),
           (2, EXIT_CLEAN, []))
        rewrite(os.path.join(base, "findings", "CAND-0002.json"),
                evidence=[{"role": "sink", "file": "Source Files/b.c",
                           "line": 12}],
                primary_location="Source Files/b.c:12",
                files_read=["Source Files/b.c"])
        s = _status(tmp)
        ok("...and one about its neighbour in the same directory is not",
           (s["dismissed"], s["exit_code"]), (1, EXIT_SETUP))
        has("...named with the space intact", s["gate_failures"],
            "cites Source Files/b.c where this run's CAND-0002 is in "
            "Source Files/a.c")

    with tempfile.TemporaryDirectory() as tmp:
        stale_run(tmp, dispatched=("CAND-0001",),
                  verdicts={"CAND-0001": "NOT_VULNERABLE",
                            "CAND-0007": "VULNERABLE"})
        s = _status(tmp)
        ok("a verdict for an id this run never minted is not counted",
           (s["confirmed_findings"], s["dismissed"]), (0, 1))
        has("...it is named as a leftover", s["gate_failures"],
            "carry a candidate id this run's stage 3 never minted (CAND-0007)")
        ok("...and the run does not pass on it", s["exit_code"], EXIT_SETUP)

    with tempfile.TemporaryDirectory() as tmp:
        stale_run(tmp, dispatched=("CAND-0001",),
                  verdicts={"CAND-0001": "NOT_VULNERABLE",
                            "MANUAL-1": "VULNERABLE"})
        s = _status(tmp)
        ok("a hand-dispatched MANUAL-1 verdict (the one-off dispatch convention) is "
           "counted and is not a leftover",
           (s["confirmed_findings"], s["gate_failures"]), (1, []))

    with tempfile.TemporaryDirectory() as tmp:
        stale_run(tmp, dispatched=("CAND-0001",), deferred=1,
                  verdicts={"CAND-0001": "NOT_VULNERABLE",
                            "CAND-0900": "NOT_VULNERABLE"})
        s = _status(tmp)
        ok("a verdict for a candidate this run deferred is this run's, not a "
           "leftover", (s["dismissed"], s["gate_failures"]), (2, []))

    with tempfile.TemporaryDirectory() as tmp:
        base = stale_run(tmp, dispatched=("CAND-0001",),
                         verdicts={"CAND-0001": "NOT_VULNERABLE"},
                         arb={"CAND-0001": "VULNERABLE"},
                         arb_queue=["CAND-0001"])
        rewrite(os.path.join(base, "arbitration", "ARB-CAND-0001.json"),
                rule_id="MEM-001")
        s = _status(tmp)
        ok("a previous run's ARB record does not overturn this run's verdict",
           (s["confirmed_findings"], s["dismissed"]), (0, 1))
        ok("...and does not arbitrate the queued finding",
           (s["incomplete_tasks"], "arbitrate" in s["stages_missing"]),
           (1, True))
        has("...it is named", s["gate_failures"],
            "ARB-CAND-0001 carries MEM-001 where this run's CAND-0001 is "
            "MEM-002")

    with tempfile.TemporaryDirectory() as tmp:
        base = stale_run(tmp, dispatched=("CAND-0001",),
                         verdicts={"CAND-0001": "NOT_VULNERABLE"},
                         arb={"CAND-0001": "NOT_VULNERABLE"},
                         arb_queue=["CAND-0001"])
        rewrite(os.path.join(base, "arbitration", "ARB-CAND-0001.json"),
                read_before_judging=["src/zzz.c:1-40"])
        s = _status(tmp)
        has("an ARB record that read only another candidate's file is not "
            "this candidate's", s["gate_failures"],
            "ARB-CAND-0001 cites src/zzz.c where this run's CAND-0001 is in "
            "src/a.c")

    with tempfile.TemporaryDirectory() as tmp:
        base = stale_run(tmp, dispatched=("CAND-0001",),
                         verdicts={"CAND-0001": "NOT_VULNERABLE"},
                         arb={"CAND-0001": "NOT_VULNERABLE"},
                         arb_queue=["CAND-0001"])
        path = os.path.join(base, "arbitration", "queue.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["queue"][0]["rule_id"] = "MEM-009"
        _write(path, doc)
        s = _status(tmp)
        has("an ARB record that disagrees with the arbitration queue about the "
            "rule is named too", s["gate_failures"],
            "ARB-CAND-0001 carries MEM-002 where arbitration/queue.json's "
            "CAND-0001 is MEM-009")

    # A validator re-filing a candidate under another rule is a state of THIS
    # run, not a previous one: verify_findings flags it `rule_id_mismatch`,
    # queues it under the validator's rule, and roles/arbiter.md has the arbiter
    # keep one rule or the other. Read as staleness, the verdict failed against
    # the minted rule and the ARB record failed one of its two checks whichever
    # rule it kept, so an upheld finding left the counts and the run exited 4.
    def relabelled(tmp, arb_rule, precheck=True):
        base = stale_run(tmp, dispatched=("CAND-0001",),
                         verdicts={"CAND-0001": "VULNERABLE"},
                         arb={"CAND-0001": "VULNERABLE"},
                         arb_queue=["CAND-0001"])
        rewrite(os.path.join(base, "findings", "CAND-0001.json"),
                rule_id="MEM-009")
        path = os.path.join(base, "arbitration", "queue.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["queue"][0]["rule_id"] = "MEM-009"
        _write(path, doc)
        rewrite(os.path.join(base, "arbitration", "ARB-CAND-0001.json"),
                rule_id=arb_rule)
        if precheck:
            _write(os.path.join(base, "arbitration", "precheck.json"), {
                "summary": {"counts": {"VULNERABLE": 1},
                            "citations_verified": 1},
                "findings": [{"candidate_id": "CAND-0001",
                              "rule_id": "MEM-009", "verdict": "VULNERABLE",
                              "problems": [{
                                  "code": "rule_id_mismatch",
                                  "detail": "the finding says MEM-009 but "
                                            "candidate record CAND-0001 was "
                                            "stamped MEM-002"}]}]})
        return _status(tmp)

    for arb_rule, kept in (("MEM-009", "the validator's"),
                           ("MEM-002", "the minted")):
        with tempfile.TemporaryDirectory() as tmp:
            s = relabelled(tmp, arb_rule)
            ok("a relabel this run's precheck flagged is this run's, and so "
               "is the ARB record that keeps %s rule" % kept,
               (s["confirmed_findings"], s["incomplete_tasks"],
                s["stages_missing"], s["exit_code"], s["gate_failures"]),
               (1, 0, [], EXIT_FINDINGS, []))
    with tempfile.TemporaryDirectory() as tmp:
        s = relabelled(tmp, "MEM-001")
        ok("...while an ARB record under a third rule is still another's",
           ("arbitrate" in s["stages_missing"], s["exit_code"]),
           (True, EXIT_SETUP))
    with tempfile.TemporaryDirectory() as tmp:
        s = relabelled(tmp, "MEM-009", precheck=False)
        ok("...and so is a relabel no precheck row accounts for",
           (s["confirmed_findings"], s["exit_code"]), (0, EXIT_SETUP))
    with tempfile.TemporaryDirectory() as tmp:
        relabelled(tmp, "MEM-009", precheck=False)
        _write(os.path.join(tmp, RUN_DIR, "arbitration", "precheck.json"), {
            "summary": {"counts": {"VULNERABLE": 1}, "citations_verified": 1},
            "findings": [{"candidate_id": ["CAND-0001"], "rule_id": "MEM-009",
                          "verdict": "VULNERABLE",
                          "problems": [{"code": "rule_id_mismatch"}]}]})
        s = _status(tmp)
        ok("...or by a precheck row whose id is not a string, and that is "
           "not a traceback", (s["confirmed_findings"], s["exit_code"]),
           (0, EXIT_SETUP))

    with tempfile.TemporaryDirectory() as tmp:
        stale_run(tmp, dispatched=("CAND-0001",),
                  verdicts={"CAND-0001": "NOT_VULNERABLE"},
                  arb={"CAND-0005": "VULNERABLE"})
        s = _status(tmp)
        ok("an ARB record for an id this run never minted is not counted",
           s["confirmed_findings"], 0)
        has("...and is named as a leftover", s["gate_failures"],
            "ARB-CAND-0005")

    # ---- --out, and the run directory as a door out of the tree ----------- #
    #
    # §9 rule 2: no tool writes to the tree under review. `--out src/rs.json`
    # did, and nothing about a status tool needs to.
    with tempfile.TemporaryDirectory() as tmp, \
            tempfile.TemporaryDirectory() as elsewhere:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        os.makedirs(os.path.join(tmp, "src"))
        inside = os.path.join(tmp, "src", "rs.json")
        code, err = quiet_main(["--root", tmp, "--out", inside, "--quiet"])
        ok("--out inside the scanned tree is refused",
           (code, os.path.exists(inside)), (EXIT_SETUP, False))
        ok("...citing §9 rule 2", "§9 rule 2" in err, True)
        outside = os.path.join(elsewhere, "run-status.json")
        ok("--out outside the scanned tree is written (the README's "
           "--out /tmp/run-status.json)",
           (main(["--root", tmp, "--out", outside, "--quiet"]),
            os.path.isfile(outside)), (EXIT_CLEAN, True))
        nested = os.path.join(tmp, RUN_DIR, "ci", "run-status.json")
        ok("--out under .security-review/ is written",
           (main(["--root", tmp, "--out", nested, "--quiet"]),
            os.path.isfile(nested)), (EXIT_CLEAN, True))
        if link(os.path.join(tmp, "src"), os.path.join(elsewhere, "side")):
            door = os.path.join(elsewhere, "side", "rs.json")
            ok("--out through a link that lands in the tree is refused too",
               (quiet_main(["--root", tmp, "--out", door, "--quiet"])[0],
                os.path.exists(inside)), (EXIT_SETUP, False))
        if link(tmp, os.path.join(elsewhere, "root-link")):
            ok("a --root that is itself a symlink is fine - only the run "
               "directory and below is checked",
               main(["--root", os.path.join(elsewhere, "root-link"),
                     "--quiet"]), EXIT_CLEAN)

    # A repository can commit .security-review/ - the ledger lives there - so
    # it can commit a link there too, and following it writes wherever the
    # scanned tree chose.
    with tempfile.TemporaryDirectory() as tmp, \
            tempfile.TemporaryDirectory() as elsewhere:
        _fixture(elsewhere, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                 arb_queue=[], analyzers=(("semgrep", "complete"),),
                 inventory=[])
        if link(os.path.join(elsewhere, RUN_DIR), os.path.join(tmp, RUN_DIR)):
            code, err = quiet_main(["--root", tmp, "--quiet"])
            ok("a .security-review that is a symlink out of the tree is "
               "refused", code, EXIT_SETUP)
            ok("...and nothing is written where it points",
               os.path.exists(os.path.join(elsewhere, RUN_DIR, STATUS_NAME)),
               False)
            ok("...the refusal names the link and cites §1",
               ("is a symlink to" in err and "§1" in err), True)

    with tempfile.TemporaryDirectory() as tmp, \
            tempfile.TemporaryDirectory() as elsewhere:
        base = _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                        arb_queue=[], analyzers=(("semgrep", "complete"),),
                        inventory=[])
        victim = os.path.join(elsewhere, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("keep\n")
        if link(victim, os.path.join(base, STATUS_NAME)):
            ok("a run-status.json that is a symlink is refused, not replaced "
               "or written through",
               (quiet_main(["--root", tmp, "--quiet"])[0],
                open(victim, encoding="utf-8").read()), (EXIT_SETUP, "keep\n"))
            os.remove(os.path.join(base, STATUS_NAME))
        if link(elsewhere, os.path.join(base, "ci")):
            ok("so is a directory link beneath .security-review/ on the way",
               (quiet_main(["--root", tmp, "--out",
                            os.path.join(base, "ci", "rs.json"),
                            "--quiet"])[0],
                os.path.exists(os.path.join(elsewhere, "rs.json"))),
               (EXIT_SETUP, False))
        # The planted temp name. `path + ".tmp"` was predictable, and
        # open(tmp, "w") followed a link there.
        if link(victim, os.path.join(base, STATUS_NAME + ".tmp")):
            ok("a planted run-status.json.tmp link is never written through",
               (main(["--root", tmp, "--quiet"]),
                open(victim, encoding="utf-8").read()), (EXIT_CLEAN, "keep\n"))
            ok("...the status file is a regular file",
               (os.path.islink(os.path.join(base, STATUS_NAME)),
                os.path.isfile(os.path.join(base, STATUS_NAME))),
               (False, True))
            ok("...and no temp file is left behind",
               sorted(n for n in os.listdir(base) if n.endswith(".tmp")),
               [STATUS_NAME + ".tmp"])

    # The same run directory spelled through another name for the root - on
    # macOS, `--root .` from /tmp/repo is /private/tmp/repo, and an --out typed
    # as /tmp/repo/... is the other spelling. The link walk used to run only
    # for --root's own spelling, so this one wrote through the planted link.
    with tempfile.TemporaryDirectory() as outer, \
            tempfile.TemporaryDirectory() as elsewhere:
        real = os.path.join(outer, "real")
        base = _fixture(os.path.join(real, "repo"),
                        verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                        analyzers=(("semgrep", "complete"),), inventory=[])
        alias = os.path.join(outer, "alias")
        if link(real, alias) and link(elsewhere, os.path.join(base, "ci")):
            spelled = os.path.join(alias, "repo", RUN_DIR)
            code, err = quiet_main(["--root", os.path.join(real, "repo"),
                                    "--out",
                                    os.path.join(spelled, "ci", "rs.json"),
                                    "--quiet"])
            ok("a planted link is refused however the root above it is spelled",
               (code, os.listdir(elsewhere)), (EXIT_SETUP, []))
            ok("...and that spelling, with no link on the way, is written",
               (main(["--root", os.path.join(real, "repo"), "--out",
                      os.path.join(spelled, "rs.json"), "--quiet"]),
                os.path.isfile(os.path.join(base, "rs.json"))),
               (EXIT_CLEAN, True))

    # mkstemp creates 0600, and a fixed 0644 after it made run-status.json
    # world-readable under an operator's `umask 077`. open() gave it 0666
    # under the umask, and so does the atomic write.
    if os.name == "posix":
        with tempfile.TemporaryDirectory() as tmp:
            base = _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"},
                            arb_queue=[], analyzers=(("semgrep", "complete"),),
                            inventory=[])
            modes = []
            for mask in (0o077, 0o022):
                held = os.umask(mask)
                try:
                    main(["--root", tmp, "--quiet"])
                finally:
                    os.umask(held)
                modes.append(oct(os.stat(os.path.join(base, STATUS_NAME))
                                 .st_mode & 0o777))
            ok("run-status.json gets the mode the umask gives, not a fixed 0644",
               modes, [oct(0o600), oct(0o644)])

    # ---- coverage_limitations, one source at a time ----------------------- #
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "partial"), ("cppcheck", "complete")),
                 inventory=[], not_selected=18012, deferred=7, stale=2,
                 expired=1, window=3, unreadable=4,
                 unsupported={".kt": 5, ".md": 9, ".png": 3},
                 extensionless={"files": 10,
                                "scripts": {"awk": 1, "python": 1, "shell": 2},
                                "readable_languages": ["python"],
                                "script_files": [
                                    {"file": "bin/count", "language": "awk",
                                     "extracted": False},
                                    {"file": "bin/deploy", "language": "shell",
                                     "extracted": False},
                                    {"file": "bin/tool", "language": "python",
                                     "extracted": False},
                                    {"file": "hooks/pre-commit",
                                     "language": "shell", "extracted": False}]},
                 snapshot={"id": "x", "files": 2, "bytes": 91, "cap_hit": None,
                           "changed_during_snapshot": 2})
        s = _status(tmp)
        rows = s["coverage_limitations"]
        ok("coverage_limitations is populated, not empty-by-default",
           len(rows) >= 8, True)
        has("functions below the operating point", rows, "18012 function(s)")
        has("...with the sentence that qualifies the number", rows,
            "unexamined, not clean")
        has("a scanner that is not complete", rows, "finished as `partial`")
        has("the window tier", rows, "`window` boundaries")
        has("...and where the windows are", rows, "Worst: c (3)")
        has("deferred candidates", rows, "deferred by the budget")
        has("stale suppressions", rows, "content_hash moved")
        has("expired suppressions", rows, "passed their `expires_at`")
        has("an unsupported language in the tree", rows, "5 Kotlin file(s)")
        ok("and a README is not reported as an unscanned language",
           any(".md" in row for row in rows), False)
        ok("nor is a PNG", any(".png" in row for row in rows), False)
        has("an extensionless script in a language the skill reads", rows,
            "1 extensionless python script(s) (bin/tool) are in the tree, named "
            "by their `#!` line: python is a language this run reads")
        has("and one in a language it does not, with every file named", rows,
            "2 extensionless shell script(s) (bin/deploy, hooks/pre-commit) are "
            "in the tree, named by their `#!` line, and shell is not a language "
            "this run reads")
        # awk sorts before python, so only the readable-first key puts python
        # at the top; alphabetical order alone would not.
        bare = [row.split(" script(s)")[0] for row in rows if "extensionless" in row]
        ok("the readable language comes first, and the six files with no `#!` "
           "- a Makefile, a LICENSE - are no row at all",
           bare, ["1 extensionless python", "1 extensionless awk",
                  "2 extensionless shell"])
        has("files that never entered the corpus", rows,
            "4 file(s) could not be read (src/u0.c, src/u1.c, src/u2.c, "
            "src/perm.c)")
        has("a tree that moved under the snapshot", rows,
            "2 file(s) changed while the snapshot was being taken")

    # The holes stages 1 and 3 COUNT and this file used to leave out: each has
    # a counter written for exactly this sentence, and none was read.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[],
                 unreadable=4, unstattable=1, hits_unjoined=2, no_candidate=3,
                 sink_drift=19, sink_unreadable=5)
        rows = _status(tmp)["coverage_limitations"]
        has("a file the walk could not stat", rows,
            "1 file(s) could not be stat'ed - a dangling symlink, a permission "
            "or a race (src/Gone.c)")
        has("...in the same sentence as its siblings, file names unmangled",
            rows, "src/perm.c) and 1 file(s) could not be stat'ed")
        has("hits that joined to no record", rows,
            "2 rule hit(s) in 1 file(s) joined to no function record")
        has("selected functions that produced no candidate", rows,
            "3 function(s) were selected by the operating point and produced "
            "no candidate")
        has("...naming them", rows, "src/a.c::quiet_0::0")
        has("sink lines that drifted since stage 1", rows,
            "19 candidate(s) quote a line that changed since stage 1 read it")
        has("sink lines that could not be re-read", rows,
            "5 candidate(s) quote a line stage 3 could not re-read")
    # LOG-TRI: why a selected function got no candidate, and the functions that got one
    # on a model's rating alone.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[], no_candidate=4,
                 not_derived=["verdict-medium", "verdict-medium", "verdict-medium",
                              "test-tree"], triage_derived=2)
        rows = _status(tmp)["coverage_limitations"]
        has("the remainder says no rule matched and no LOG-TRI was derived, and why", rows,
            "4 function(s) were selected by the operating point and produced no candidate: "
            "no rule matched them and no LOG-TRI was derived for them (3 rated medium, "
            "1 in the test tree)")
        has("it still says they are unexamined, not clean", rows, "unexamined, not clean")
        has("the functions reviewed on a rating alone are counted, with what the rating is",
            rows, "2 function(s) that no rule matched were reviewed only because the triage "
                  "model rated them high (LOG-TRI): that rating is a model's unvalidated "
                  "reading")
        has("and the lower-rated ones it does not call unreviewed are only those no rule matched",
            rows, "selected functions it rated lower that no rule matched were not reviewed")
        ok("all of them dispatched, so there is no not-sent sentence",
           [r for r in rows if "were not sent to a validator" in r], [])
    # A LOG-TRI a ledger suppression took out of dispatch, or the budget deferred, was read by
    # no validator: it is not "reviewed", and the list says so apart from the ones that were.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[],
                 triage_derived=4, triage_suppressed=1, triage_deferred=1)
        rows = _status(tmp)["coverage_limitations"]
        has("only the dispatched LOG-TRI are called reviewed", rows,
            "2 function(s) that no rule matched were reviewed only because the triage model "
            "rated them high (LOG-TRI)")
        ok("and 4 is not the number reviewed",
           [r for r in rows if "4 function(s) that no rule matched were reviewed" in r], [])
        has("the suppressed and the deferred are said apart as not sent to a validator", rows,
            "2 function(s) the triage model rated high (LOG-TRI) were not sent to a validator "
            "in this run (1 suppressed by a ledger decision; 1 deferred by the budget, on "
            "disk in .security-review/candidates/<category>-deferred.json): unexamined, "
            "not clean.")
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[],
                 triage_derived=4, triage_suppressed=1, triage_deferred=3)
        rows = _status(tmp)["coverage_limitations"]
        ok("with none dispatched no function is called reviewed on a rating",
           [r for r in rows if "reviewed only because" in r], [])
        has("and all four are said not to have been sent", rows,
            "4 function(s) the triage model rated high (LOG-TRI) were not sent to a validator "
            "in this run (1 suppressed by a ledger decision; 3 deferred by the budget")
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[],
                 triage_derived=3, triage_split=False)
        rows = _status(tmp)["coverage_limitations"]
        ok("a queue that records no split claims no review",
           [r for r in rows if "reviewed only because" in r], [])
        has("and says it cannot tell how many were read", rows,
            "queue.json does not record how many of them went to a validator")
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[], no_candidate=2,
                 not_derived=["no-verdict", "scored-before-0.1.3"])
        rows = _status(tmp)["coverage_limitations"]
        has("a rules-backend run says the backend records no verdict", rows,
            "1 the backend records no triage verdict")
        has("a run scored before 0.1.3 names the free remedy, not the backend", rows,
            "re-run score_functions.py --resume to derive LOG-TRI (every verdict is cached)")
        ok("and no 2c sentence appears when nothing was derived",
           [r for r in rows if "reviewed only because" in r], [])
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[], no_candidate=1,
                 not_derived=["verdict-medium"],
                 twins={"listing": [{"group": "TWIN-x", "aliases": [
                     "src/a.c::quiet_0::0", "src/b.c::quiet_0::0"],
                     "candidates": ["CAND-0001"]}]})
        _write(os.path.join(tmp, RUN_DIR, "enrich", "queue.json"), dict(
            json.load(open(os.path.join(tmp, RUN_DIR, "enrich", "queue.json"))),
            entries=[{"candidate_id": "CAND-0001", "function_key": "src/b.c::quiet_0::0",
                      "rank": 1, "tier": "strict", "category": "logic-flaws",
                      "rule_id": "LOG-002", "suppressed": False, "suppression": None}]))
        rows = _status(tmp)["coverage_limitations"]
        has("a remainder function says where its byte-identical copy was reviewed", rows,
            "src/a.c::quiet_0::0: its byte-identical copy src/b.c::quiet_0::0 was reviewed "
            "as CAND-0001 under LOG-002")
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        rows = _status(tmp)["coverage_limitations"]
        ok("and none of those sentences appears when the counts are zero",
           [r for r in rows if any(n in r for n in (
               "stat'ed", "joined to no function", "produced no candidate",
               "quote a line", "size limit", "still open", "were excluded by",
               "suppress nothing", "name MEM-WFS"))], [])

    # What stage 1 and stage 3 write beside the counts, which the sentences
    # used to leave out: the files, the patterns, and two more kinds of ledger
    # line that suppress nothing.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[],
                 unreadable=7, too_large=2, unclosed=3, unusable=1, ignored=1,
                 excluded_dirs=(
                     {"dir": "lib/vendor", "files": 2, "languages": ["c"],
                      "patterns": ["vendor"]},
                     {"dir": "src/legacy", "files": 1, "languages": ["c"],
                      "patterns": ["src/legacy/*"]},
                     {"dir": ".", "files": 1, "languages": ["c"],
                      "patterns": ["*.gen.c"]},
                     {"dir": "old", "files": 1, "languages": ["c"]}))
        rows = _status(tmp)["coverage_limitations"]
        has("files over the size limit are counted and named", rows,
            "2 file(s) exceeded the size limit (gen/big0.c, gen/big1.c)")
        has("...and more than five unreadable files say there are more", rows,
            "7 file(s) could not be read (src/u0.c, src/u1.c, src/u2.c, "
            "src/u3.c, src/u4.c, ...)")
        has("functions the brace walk lost are a hole, named by file", rows,
            "3 function(s) were still open when their file ended (src/brace.c)")
        has("an excluded directory names the pattern that excluded it", rows,
            "2 source file(s) in `lib/vendor` (c) were excluded by `vendor`")
        has("...and --include, where --include brings it back", rows,
            "Pass `--include lib/vendor` to extract_functions.py")
        ok("but not for a pattern that removes files one by one, nor for the "
           "root, which --include does not bring back",
           [r for r in rows if "`--include src/legacy`" in r
            or "`--include .`" in r], [])
        has("...where it says to drop the pattern instead", rows,
            "`--include` does not bring them back, because `src/legacy/*` "
            "removes files rather than the directory")
        has("the root's row says the same about its own pattern", rows,
            "1 source file(s) in `.` (c) were excluded by `*.gen.c`")
        has("a row from before the patterns were recorded still reads", rows,
            "1 source file(s) in `old` (c) were excluded by the exclude patterns")
        ok("and nothing calls an operator's pattern a default any more",
           [r for r in rows if "default exclude" in r], [])
        has("a ledger line that suppresses nothing for want of a field", rows,
            "1 suppression(s) in the ledger suppress nothing because they lack "
            "what a suppression needs")
        has("...named", rows, "(SUP-UNU-0001)")
        has("and a MEM-WFS suppression the function's other rules overruled",
            rows, "1 suppression(s) name MEM-WFS on a function whose other "
                  "candidates still dispatch, and were not applied (SUP-WFS-0001)")

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(), inventory=[])
        s = _status(tmp)
        has("no analyzer at all is itself a limitation",
            s["coverage_limitations"], "no analyzer SARIF was ingested")
        has("a run with no snapshot says so", s["coverage_limitations"],
            "read the live working tree rather than a snapshot")

    # Stage 1 records what git said about the run directory; an unverified one
    # is a limitation, a verified one and a run from before the record are not.
    for check_value, said in (("no-git", "no git repository encloses"),
                              ("untracked-tree", "HEAD lists none of the scanned tree"),
                              ("git", None), (None, None)):
        with tempfile.TemporaryDirectory() as tmp:
            _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                     analyzers=(("semgrep", "complete"),), inventory=[])
            run_path = os.path.join(tmp, RUN_DIR, "run.json")
            with open(run_path, encoding="utf-8") as fh:
                run_doc = json.load(fh)
            if check_value is not None:
                run_doc["run_dir"] = {"check": check_value, "committed": [],
                                      "shipped": []}
            _write(run_path, run_doc)
            rows = [row for row in _status(tmp)["coverage_limitations"]
                    if "provenance is unverified" in row]
            ok("run_dir %s: %s" % (check_value, "an unverified-provenance limitation"
                                   if said else "no provenance limitation"),
               (len(rows), bool(rows) and said in rows[0]), (1, True) if said
               else (0, False))

    # ---- --check ---------------------------------------------------------- #
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "VULNERABLE"},
                 arb={"CAND-0001": "VULNERABLE"}, arb_queue=["CAND-0001"],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        path = os.path.join(tmp, RUN_DIR, STATUS_NAME)
        ok("a run writes its status", main(["--root", tmp, "--quiet"]),
           EXIT_FINDINGS)
        ok("and --check agrees with what it just wrote",
           main(["--root", tmp, "--check", "--quiet"]), EXIT_CLEAN)

        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["confirmed_findings"] = 0
        doc["exit_code"] = 0
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        ok("a hand-edited status file is caught",
           main(["--root", tmp, "--check", "--quiet"]), EXIT_DRIFT)
        diffs = differences(doc, _status(tmp))
        has("and the field that was edited is named", diffs,
            "`confirmed_findings`")
        has("...as is the exit code it was edited to hide", diffs,
            "`exit_code`")

        os.remove(path)
        ok("--check with no status file to check is drift too",
           main(["--root", tmp, "--check", "--quiet"]), EXIT_DRIFT)

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, verdicts={"CAND-0001": "NOT_VULNERABLE"}, arb_queue=[],
                 analyzers=(("semgrep", "complete"),), inventory=[])
        main(["--root", tmp, "--quiet"])
        path = os.path.join(tmp, RUN_DIR, STATUS_NAME)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["coverage_limitations"] = []
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        ok("emptying coverage_limitations by hand is caught as well",
           main(["--root", tmp, "--check", "--quiet"]), EXIT_DRIFT)

        # Only generated_at is exempt: a file that is otherwise identical agrees.
        with open(path, "w", encoding="utf-8") as fh:
            fresh = _status(tmp)
            fresh["generated_at"] = "1999-01-01T00:00:00Z"
            json.dump(fresh, fh)
        ok("a different generated_at alone is not drift",
           main(["--root", tmp, "--check", "--quiet"]), EXIT_CLEAN)

    with tempfile.TemporaryDirectory() as tmp:
        ok("a tree with no run directory exits 4 in both modes",
           (main(["--root", tmp, "--quiet"]),
            main(["--root", tmp, "--check", "--quiet"])),
           (EXIT_SETUP, EXIT_SETUP))
        ok("and writes nothing into it", os.listdir(tmp), [])

    print()
    print("selftest: %d failure(s)" % failures)
    return EXIT_TOOL if failures else EXIT_CLEAN


# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Summarise a security-review run as one status file and "
                    "one exit code.")
    p.add_argument("--root", default=".",
                   help="scanned repository root, holding .security-review/")
    p.add_argument("--out", default=None,
                   help="output path (default: "
                        ".security-review/run-status.json); refused inside the "
                        "scanned tree unless it is under .security-review/")
    p.add_argument("--check", action="store_true",
                   help="recompute the status and exit non-zero if the "
                        "run-status.json on disk disagrees with the artifacts; "
                        "writes nothing")
    p.add_argument("--quiet", action="store_true",
                   help="write the file and say nothing; the exit code is the "
                        "answer")
    p.add_argument("--selftest", action="store_true")
    return p


# The run-directory gate, rules_lib.run_dir_gate: nothing under .security-review/
# is read while git says the scanned repository commits anything there but
# .gitignore and ledger/. This tool imports nothing from the skill, so it runs
# the gate as a process of its own - `-I`, which imports the standard library
# and nothing else, and `-B`, which leaves no bytecode in the scanned tree - and
# takes anything but a clean pass as a refusal: a gate that could not run has
# not said the directory is safe. tests/test_contract_parity.py holds every copy of this
# function to the same text.
EXIT_SHIPPED = 7


def _run_dir_gate(root):
    """(None, result) when the run directory may be read, else (refusal, result)."""
    gate = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules_lib.py")
    try:
        ran = subprocess.run([sys.executable, "-B", "-I", gate, "--check-run-dir",
                              "--root", os.path.abspath(root), "--json"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return ("REFUSED: the run-directory check could not run (%s: %s), so "
                "nothing under .security-review/ is read. (exit %d)"
                % (gate, exc, EXIT_SHIPPED)), None
    try:
        result = json.loads(ran.stdout.decode("utf-8"))
    except ValueError:
        result = None
    if ran.returncode == 0 and isinstance(result, dict):
        return None, result
    said = ran.stderr.decode("utf-8", "replace").strip()
    return (said or "REFUSED: the run-directory check exited %d without saying why, "
            "so nothing under .security-review/ is read. (exit %d)"
            % (ran.returncode, EXIT_SHIPPED)), result


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    try:
        return _run(args)
    except Refused as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        # Still 4. A wrapper asking "how did the run go?" about a directory with
        # no run in it has had a setup failure, whatever this tool thinks of the
        # question.
        return EXIT_SETUP
    except Exception as exc:                            # noqa: BLE001
        # 5, and never the 1 that an escaping exception would produce through
        # `sys.exit(main())`. 1 means "completed, with findings or candidates
        # requiring action" in the policy at the top of this file - so a
        # traceback out of here used to tell a CI job the run FINISHED. A
        # malformed `extract-report.json` was enough to do it: `.get` on a list
        # is an AttributeError, and the wrapper read the crash as a verdict.
        # Whatever went wrong, this tool could not answer the question, and that
        # is what 5 says.
        print("%s could not run: %s: %s"
              % (TOOL_NAME, type(exc).__name__, exc), file=sys.stderr)
        return EXIT_TOOL


def _run(args):
    # Before anything is read: a run directory the scanned repository supplied
    # is not this run's to report on (_run_dir_gate).
    refusal, _gate = _run_dir_gate(args.root)
    if refusal:
        print(refusal, file=sys.stderr)
        return EXIT_SHIPPED
    # And a destination this tool will refuse to write is a usage failure
    # whatever the run says. --check writes nothing, so it may compare against
    # a file anywhere.
    path = (status_path(args.root, args.out) if not args.check
            else args.out or os.path.join(args.root, RUN_DIR, STATUS_NAME))
    art = collect(args.root)
    status = build_status(art)

    if args.check:
        on_disk, err = _load(path)
        if on_disk is None:
            print("DRIFT: %s" % (err or "%s does not exist, so there is nothing "
                                        "to check against the artifacts beside "
                                        "it" % path), file=sys.stderr)
            return EXIT_DRIFT
        diffs = differences(on_disk, status)
        if diffs:
            print("DRIFT: %s disagrees with the artifacts it was computed from:"
                  % path, file=sys.stderr)
            for line in diffs:
                print("  %s" % line, file=sys.stderr)
            return EXIT_DRIFT
        if not args.quiet:
            print("run-status.json agrees with the artifacts (%d field(s) "
                  "checked)" % (len(status) - len(IGNORED_ON_CHECK)))
        return EXIT_CLEAN

    write_status(path, status)
    if not args.quiet:
        summarise(status)
        print("-> %s" % path)
    return status["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
