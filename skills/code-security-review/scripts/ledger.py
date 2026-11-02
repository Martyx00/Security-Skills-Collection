#!/usr/bin/env python3
"""
ledger.py - stage 5. The human's answers, kept, so the next run starts where the
last one finished.

Everything else under `.security-review/` is a run artefact: stage 1 rewrites it
the next time the pipeline runs. `.security-review/ledger/` is not. It is
committed, it outlives the run that produced it, and it is the only part of this
pipeline whose value compounds. Without it every run starts from zero and raises
in October exactly what a person closed in September - which is how a scanner
stops being read, and no amount of precision upstream survives that.

Three failures it is built against, each measured on an audited run.

The first: one dismissal sentence, identical, closed 41 findings, and all 41 were
upheld. A rejection that cannot name a disqualifier is a rejection nobody can
learn from and the training export will not take it, so `reject` refuses without
a `FP-*` code out of the Validator Contract's own §8 table - read from the
contract file by `check` rather than trusted to a constant somebody copied here
once and stopped looking at.

The second is quieter. A suppression with no expiry is a decision nobody
revisits, and a suppression that outlives an edit to the function it suppresses
is a decision about code that is no longer there - the `/* safe: bounded by
caller */` that stopped being true is exactly the edit it must not survive. So,
from contract §8, and enforced here rather than left to convention:

  1. a suppression with no `--expires` is refused; there is no permanent one;
  2. an expiry beyond `--max-expiry-days` (default 180) is refused unless
     `--force`, which records `forced: true` so `status` shows it and `check`
     can prove after the fact that the long expiry was deliberate. Raising that
     flag is the one way past the refusal that records nothing, so `status` and
     `check` compute the span against the DEFAULT and report a long expiry that
     was never forced - the escape leaves a mark either way;
  3. a suppression whose `content_hash_at_creation` differs from the function's
     current `content_hash` DOES NOT SUPPRESS. It is reported stale. There is no
     flag for this;
  4. a suppressed candidate is still extracted, still scored and still counted.
     Suppression removes a finding from the dispatch queue and from the report -
     never from the coverage account. `status` prints the suppressed set every
     time, because a scanner that forgets what it stopped looking at cannot tell
     you when it should start again.

The third was measured on the Mbed TLS run of 2026-09-29, and it is about the
labels. Twelve decisions went in, `check` said 0 problems, and the export held
psasim's process_response - one file vendored at framework/ and at
tf-psa-crypto/framework/, byte for byte - as vulnerable at one path and
not_vulnerable at the other, under one content hash and one CWE. So now:

  1. a person's FP-TEST and FP-GENERATED are held to the path facts a
     validator's are, on the file of the body the decision labels
     (verify_findings' TEST_PATH and GENERATED_*, and stage 1's in_test_tree
     where verify_findings.fp_test_basis takes it from a validator; for
     FP-GENERATED also stage 1's generated_file), and a mismatch is refused
     unless `--path-override` says why, which is recorded;
  2. "real, and outside what this project defends" is a decision of its own,
     `out-of-scope`, with a scope code and a FILE:LINE basis this tool quotes
     from the tree. It is not a rejection - every FP-* code says the finding
     was never real - and the export leaves it out unless asked;
  3. a label that disagrees with a standing decision on a byte-identical twin
     (the same content hash and rule at another path) or in the arbiter's
     MERGED cluster is refused unless `--acknowledge-conflict` says why, and
     `check` reports every disagreement nobody acknowledged;
  4. the CWE recorded is the one the verdict was given under - the arbiter's,
     the validator's, then the rule's - spelled as the twin gate compares it
     (`CWE-787`, whatever was written), with the rule's beside it;
  5. `export` leaves out a body labelled both ways and lists it, writes
     byte-identical copies of one answer once, and names what it folded;
  6. a decision in a later run on the same function body, rule and sink
     retires the earlier run's for every reader - `check`, `status`, the
     refusal in 3, `pending` and `export` - and so does one of the same run
     on the same measured sink under a candidate id stage 3 renumbered, so
     an old answer is corrected by deciding it again, not acknowledged in
     every session that follows. needs-info retires nothing: it is no
     answer. An earlier run's answer on a twin that a candidate of this run
     asks again is not refused over, since that copy is due to be decided
     too, and `check` reports the pair until it is;
  7. an answer no candidate of the current run asks again - its body was
     edited or is gone - cannot be decided again, so `withdraw` takes it
     out of the current answers by name, with a reason, and `check` says so
     where that is the only way to clear what it reports.

And one rule that is not §8's but §9's: every decision command refuses a
candidate that stage 4 never adjudicated - one with neither
`findings/<candidate>.json` (the validator's verdict) nor
`arbitration/ARB-<candidate>.json` (the arbiter's, on the subset `queue.json`
sent it), and one that `arbitration/queue.json` sent to the arbiter and that has
no ARB record yet, because for that candidate stage 4 has not finished (contract
§1 counts it as an incomplete task). No unadjudicated score is ever shown to a
person as a finding; a tool that accepted a human decision on one would be the
exception that makes the rule advisory. Otherwise either artefact settles it,
and the arbiter's `final_verdict` wins where there is one: demanding the ARB
file alone refused a decision on every finding the arbiter was never asked to
review, which is most of them. `export_sarif.py` is stricter on purpose - a
dashboard takes only ARB-backed findings - and counts the rest as withheld.

More rules that are the pipeline's rather than §8's. Contract §9 rule 2 confines
every write to `.security-review/`, so `export --out` refuses a path that
resolves outside the run directory - a tool that writes into the tree it is
reviewing is the one habit a scanner cannot be allowed. The run directory is
itself inside that tree, and the tree commits `ledger/`, so it can commit a
symlink there too: every write refuses a link anywhere from `.security-review`
down to the file, and opens nothing that follows one. Nothing in the ledger
carries key material either - it is committed and it is training data, so a
`--reason` that quotes a credential is refused, and `check` reports one already
there. And every file read here comes out of the scanned repository, two of them
committed, so reads are bounded: an oversize document or line is a recorded
problem, never a silent truncation.

The decisions file is append-only: a correction is a new line and the older one
stays in the trail. suppressions.jsonl is append-only with exactly one exception,
and it is the contract's own: `revoke` appends a revocation record naming the
suppression it ends, AND fills `revoked_at` on that suppression's own line.
Contract §8 puts that field on the suppression record - it is in the schema,
spelled `null` - so a line that still says `null` about a revoked suppression
contradicts its own trail. `enrich_candidates.py` and `export_sarif.py` once
read only that field, and appending alone left `status` printing REVOKED while
stage 3 went on suppressing the candidate until the expiry; they honour either
half now, as this tool does, and the field is still filled. A revoke that
stopped between its two writes is finished by running it again, which fills
the field from the revocation already recorded and appends nothing. Nothing
else on that line is touched and no line is ever removed, so a reader six
months out still sees what was decided, when, by whom and why - plus when it
ended. An audit trail you can edit is not one; an audit trail nobody
downstream reads is not one either. Every writer of either file holds the one
ledger lock, the revoke's two writes included, so a rewrite can never swallow an
append that landed while it was reading.

`pending` is the one command about the run rather than the ledger, and it
writes nothing: what this run leaves for a person to decide, by verdict, with
the NOT_VULNERABLE records stage 5 holds back until the reviewer asks for them
split into validator-only, upheld by the arbiter and overturned by it, and
each body at two paths listed with its copies already decided or dismissed.
The review agent opens a session on it, so that nobody counts hundreds of
records by hand.

Reads   .security-review/ledger/{decisions,suppressions}.jsonl
        .security-review/candidates/<category>.json      (stage 3)
        .security-review/findings/<candidate>.json        (stage 4, validator)
        .security-review/arbitration/ARB-<candidate>.json (stage 4, arbiter)
        .security-review/arbitration/queue.json           (what awaits the arbiter)
        .security-review/extract/functions.jsonl          (current content hashes)
        .security-review/scores/scores.jsonl              (context provenance)
        .security-review/run.json
        references/validator-contract.md       in the skill folder (the FP-* vocabulary)
        references/pipeline-contract-stage5.md in the skill folder (the OOS-* codes)
        assets/evalsets/*.json                 in the skill folder (frozen_at, for export)
        the scanned tree's own files                      (an out-of-scope basis
                                                          line; a file's head,
                                                          for FP-GENERATED)
Writes  .security-review/ledger/decisions.jsonl           (append-only)
        .security-review/ledger/suppressions.jsonl        (appended; revoke also
                                                          fills revoked_at)
        .security-review/ledger/training/samples.jsonl    (derived; regenerated)

Exit codes
  0  the command did what it says
  1  refused by a rule of contract §8 - a path code the path does not bear
     out, a label that disagrees with a twin's or its MERGED cluster's, a
     withdrawal of an answer a candidate of this run asks again - or `check`
     found problems, or `pending` could not read the candidates and so
     counted short, or --selftest failed
  2  something you named is not there or cannot be used: the run directory, a
     candidate, a function_key absent from this run's extract, a suppression
     or decision id, MEM-WFS as a suppression's rule, an unparseable date, a
     symlink on the path a write would take (contract §1, §9 rule 2)
  3  the candidate has no adjudication (contract §9 rule 3), or was queued for
     the arbiter and has no ARB record yet. Separate from 1 because it is the
     one refusal that is answered by running stage 4, not by changing the
     command.
  7  refused before reading or writing anything: the scanned repository commits
     files under .security-review/ other than .gitignore and regular files
     under ledger/, git cannot say whether it does, or --root is this installed
     skill or an old copy of the scanner rather than a repository
     (rules_lib.run_dir_gate). Checked first, so it outranks every other code

Usage
  python3 ledger.py confirm    --candidate CAND-0001 --author you@example.com \\
                              --reason "len is unbounded from the wire"
  python3 ledger.py reject     --candidate CAND-0002 --author you@example.com \\
                              --reason-code FP-GUARDED --reason "clamped at parse.c:198"
  python3 ledger.py out-of-scope --candidate CAND-0004 --author you@example.com \\
                              --scope-code OOS-TEST-INFRA \\
                              --basis tools/sim/README.md:5 --reason "simulator only"
  python3 ledger.py needs-info --candidate CAND-0003 --author you@example.com \\
                              --reason "need the build flags for HAVE_TPM"
  python3 ledger.py withdraw   --decision DEC-0009 --author you@example.com \\
                              --reason "psasim is not test code; that body is gone"
  python3 ledger.py suppress   --function-key "src/a.c::f::0" --rule MEM-002 \\
                              --author you@example.com --reason "ISSUE-441" \\
                              --expires 2026-12-18
  python3 ledger.py revoke     --suppression SUP-0001 --author you@example.com \\
                              --reason "the clamp was removed again"
  python3 ledger.py status
  python3 ledger.py pending [--json]
  python3 ledger.py export --out .security-review/ledger/training/samples.jsonl \\
                              [--include-out-of-scope] [--include-conflicts]
  python3 ledger.py check
  python3 ledger.py --selftest
"""

import argparse
import contextlib
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile

try:                                   # POSIX only, and only an advisory lock.
    import fcntl                       # Two people appending at once is rare and
except ImportError:                    # cheap to make impossible; Windows falls
    fcntl = None                       # back to a plain O_APPEND write.

# Not on every platform; 0 where absent, so the flags below still combine.
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

SCHEMA_VERSION = 1
TOOL_VERSION = "1.0.0"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_UNADJUDICATED = 3

_HERE = os.path.dirname(os.path.abspath(__file__))

# Contract §8: the decisions a person can record. out_of_scope was added after
# the Mbed TLS run (the module docstring), and withdrawn after the next run on
# its ledger (cmd_withdraw); a ledger written before either holds the others and
# reads exactly as it did.
DECISIONS = ("confirmed", "rejected", "needs_info", "out_of_scope", "withdrawn")
WITHDRAWN = "withdrawn"

# Contract §8: what a training sample may claim. The first two are the labels a
# model trains on. out_of_scope is written only when the export is asked for
# it: the defect is real, so it is no hard negative, and the project does not
# defend the code, so it is no positive either.
LABELS = ("vulnerable", "not_vulnerable")
OUT_OF_SCOPE = "out_of_scope"
SAMPLE_LABELS = LABELS + (OUT_OF_SCOPE,)
PROVENANCES = ("human-confirmed", "human-rejected", "verified-fix",
               "human-out-of-scope")

# The label each decision stands for. needs_info and withdrawn have none, so
# neither can become a sample, disagree with one, or retire one (retires()).
DECISION_LABEL = {"confirmed": "vulnerable", "rejected": "not_vulnerable",
                  "out_of_scope": OUT_OF_SCOPE}

# The Validator Contract's §8 disqualifiers, in the order the table lists them.
# This is a CACHE of references/validator-contract.md §8, not a second source of
# truth: `ledger.py check` re-reads the table and reports any disagreement, and
# tests/test_contract_parity.py holds VERDICTS against the contract the same way.
# A code that exists in the contract and not here cannot be used to reject; a
# code here that the contract dropped would let a rejection cite a disqualifier
# no validator can produce. Both are drift, and both are findable.
DISQUALIFIER_CODES = (
    "FP-CONST",
    "FP-GUARDED",
    "FP-SIZED-CORRECTLY",
    "FP-TEST",
    "FP-GENERATED",
    "FP-STALE",
    "FP-NO-CALLERS",
    "FP-UNREACHABLE",
    "FP-NOT-COMPILED",
    "FP-DEAD-CODE",
    "FP-NO-ATTACKER-INPUT",
    "FP-TRUSTED",
    "FP-NOT-SECURITY",
    "FP-WFS-CLEAN",
)

# FP-ACCEPTED is deliberately NOT in that tuple. Validator Contract §7: every §8
# code says the finding was never real, and ACCEPTED_RISK says the opposite - the
# defect is real and the codebase knowingly carries it. Recording that as a
# rejection would file a live bug as a false positive, so `reject` names it and
# refuses rather than failing with "unknown code".
ACCEPTED_RISK_CODE = "FP-ACCEPTED"

# The out-of-scope decision's codes, in the order contract §8's table lists them
# (pipeline-contract-stage5.md). They are not disqualifiers: every §8 code of
# the Validator Contract says the finding was never real (validator-reference
# §7), and every one of these says it is real and outside what the project
# defends. The Mbed TLS run had no way to say that, so a person closing real
# psasim overflows as "test code only" had to pick FP-TEST - false for
# framework/psasim/ under the pipeline's own path rule - and the export made
# six real defects hard negatives. Like DISQUALIFIER_CODES this is a cache of
# the contract's table, and `check` re-reads the table and reports drift.
SCOPE_CODES = (
    "OOS-TEST-INFRA",
    "OOS-THREAT-MODEL",
    "OOS-NOT-SHIPPED",
)

# FP-TEST and FP-GENERATED are the two disqualifiers Validator Contract §8
# defines by PATH, and verify_findings.py holds a validator to them: claimed on
# a path that does not show it, the finding is disqualifier_contradicted. A
# person's rejection was held to nothing. In the Mbed TLS run 6 of the 7 FP-TEST
# rejections sat under framework/psasim/ or tf-psa-crypto/framework/psasim/,
# which TEST_PATH does not match and stage 1 did not place in a test tree, and
# all six were recorded without a word. These are verify_findings' own
# patterns, copied because this tool imports nothing from the skill for its
# writes; tests/test_contract_parity.py holds the copies equal. What stage
# 1's in_test_tree bears out is not a pattern but a rule, and it is asked of
# verify_findings.fp_test_basis itself (test_tree_basis()): a copy here kept
# accepting every in_test_tree after the gate stopped taking stage 1's own
# test names, so a person's FP-TEST on OpenSSL's providers/fips/self_test.c
# was recorded where a validator's is disqualifier_contradicted.
TEST_PATH =re.compile(r"(^|/)(tests?|fuzz|bench|examples?)/|(^|/)third_party/[^/]+/test")
GENERATED_NAME = re.compile(r"(\.pb\.c|\.tab\.c|lex\.yy\.c|(^|/)moc_)")
GENERATED_MARK = re.compile(r"DO NOT EDIT|@generated|generated by", re.I)
# How much of a file verify_findings reads for GENERATED_MARK.
GENERATED_HEAD_LINES = 40
PATH_CODES = ("FP-TEST", "FP-GENERATED")

# The disqualifiers that are claims about the whole function rather than about
# one sink: it is test code, generated, never compiled, never called, never
# reached. A defect confirmed anywhere in the same body contradicts one of
# these whatever CWE each was filed under; FP-GUARDED on one sink does not.
WHOLE_FUNCTION_CODES = ("FP-TEST", "FP-GENERATED", "FP-NOT-COMPILED",
                        "FP-NO-CALLERS", "FP-UNREACHABLE")

# Mirrors rules_lib.RULE_ID. A suppression naming a rule id that cannot exist
# suppresses nothing and reads, in the ledger, exactly like one that works.
RULE_ID = re.compile(r"^(MEM|INJ|CRY|OTH|LOG|HW)-(\d{3}|WFS|TRI)$")

# The whole-function pass. A rule id, but not one a suppression can name: its
# candidates are derived from the function's other candidates, and stage 3
# (enrich_candidates.group_suppressions) makes it follow them - suppressed when
# every one of them is, and a record naming it ignored while any dispatches.
WFS_RULE = "MEM-WFS"

# The one §8 code that is true of one rule only: "the whole-function pass
# answered all seven questions and found nothing". On any other rule there was
# no such pass, so a rejection citing it labels a training sample with a reason
# nobody could have checked.
WFS_CLEAN_CODE = "FP-WFS-CLEAN"

# Contract §2: <rel_path>::<name>::<ordinal>.
FUNCTION_KEY = re.compile(r"^(?P<file>.+)::(?P<name>[^:]+)::(?P<ordinal>\d+)$")

# Contract §2: sha256(normalised_body)[:16].
CONTENT_HASH = re.compile(r"^[0-9a-f]{16}$")

DEFAULT_MAX_EXPIRY_DAYS = 180

# Everything this tool reads lives in the SCANNED repository, and two of those
# files - ledger/decisions.jsonl and ledger/suppressions.jsonl - are committed,
# which means a hostile tree ships them. `json.load` on a 4GB document and
# `for line in fh` on a file with no newline in it are both unbounded, so both
# are bounded here. An oversize document or line is a RECORDED problem, never a
# silent truncation: a ledger that quietly read half of itself and then counted
# what it found is the failure this whole file exists to avoid.
# 8MB is the sibling tools' ceiling for a source file (enrich_candidates.py,
# score_functions.py); a JSON document gets more because candidates/coverage.json
# is legitimately large on a big tree. The .jsonl files are streamed rather than
# capped as a whole - functions.jsonl is one record per function and runs to tens
# of megabytes on a real corpus - so the bound there is per line.
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 4 * 1024 * 1024
# The project's own files - a basis line, a file's head for FP-GENERATED - are
# read up to the sibling tools' ceiling for a source file.
MAX_TREE_BYTES = 8 * 1024 * 1024
# A basis is one line a reader can check, quoted whole or not at all.
MAX_BASIS_CHARS = 1000

# status groups active suppressions by how soon somebody has to look again.
HORIZONS = ((7, "within 7 days"), (30, "within 30 days"),
            (90, "within 90 days"), (None, "beyond 90 days"))


class LedgerError(Exception):
    """A refusal, or an input that is not there. Carries the exit code."""

    def __init__(self, message, code=EXIT_REFUSED):
        Exception.__init__(self, message)
        self.code = code


# --------------------------------------------------------------------------- #
# paths and small io
# --------------------------------------------------------------------------- #

def run_dir(root):
    return os.path.join(os.path.abspath(root), ".security-review")


def ledger_dir(root):
    return os.path.join(run_dir(root), "ledger")


def decisions_path(root):
    return os.path.join(ledger_dir(root), "decisions.jsonl")


def suppressions_path(root):
    return os.path.join(ledger_dir(root), "suppressions.jsonl")


def samples_path(root):
    return os.path.join(ledger_dir(root), "training", "samples.jsonl")


def confined_output(root, path, what):
    """An output path, refused unless it lands under `.security-review/`.

    Contract §9 rule 2: no tool in this skill writes to the scanned tree, and
    every write allowlist is confined to `.security-review/`. `--out` is the only
    place a caller names a path this tool will create, so it is the only place
    that rule can be broken here - and `ledger.py export --out src/samples.jsonl`
    broke it, writing a file into the repository under review. Symlinks are
    resolved first, so a link planted inside the run directory cannot point out
    of it.

    The base is `<realpath(root)>/.security-review`, NOT the realpath of the run
    directory: when `.security-review` is itself a committed link, its realpath
    is wherever the link points, and every path under the link's target passed.
    What passes is then held to guard_write(), which refuses a link anywhere
    from the run directory down, so an --out inside it cannot be a link to
    decisions.jsonl either.
    """
    base = os.path.join(os.path.realpath(root), ".security-review")
    target = os.path.realpath(os.path.abspath(path))
    if not (target == base or target.startswith(base + os.sep)):
        raise LedgerError(
            "%s resolves to %s, which is outside %s. Contract §9 rule 2 confines "
            "every write this skill makes to .security-review/; a tool that "
            "writes into the tree it is reviewing is the one habit a scanner "
            "cannot be allowed. Write it under %s and copy it out yourself."
            % (what, target, base, os.path.join(base, "ledger", "training")),
            EXIT_USAGE)
    return guard_write(root, path, what)


def run_dir_write_problem(root, path):
    """A sentence if a symlink could redirect a write of `path`, else None.

    The run directory lives inside the scanned tree, and contract §1 makes
    `ledger/` the one part of it that is committed - so a repository can ship
    `.security-review/ledger/decisions.jsonl` as a link to one of its own
    source files, or to anything the operator can write, and the next `confirm`
    appended a JSON line to it. So a write is refused when `.security-review` or
    any existing component beneath it on the way to `path` is a symlink, when
    `path` itself is one, or when the run directory does not resolve to
    `<realpath(root)>/.security-review`. `root` and its ancestors are never
    checked: --root may legitimately be a link, and on macOS /var is one.

    The sibling copy is export_sarif.run_dir_write_problem; this tool imports
    nothing from the skill for its writes, so a change to the walk under the
    run directory is a change to both. What lies outside the run directory
    differs on purpose: every path this tool writes is under it, and
    confined_output bounds `export --out` before this is asked, while the
    export may write its SARIF anywhere outside the scanned tree.
    """
    real_run = os.path.join(os.path.realpath(root), ".security-review")
    target = os.path.abspath(path)
    spelled = _run_dir_as_spelled(root, target)
    if spelled is None:
        return ("%s is not spelled under %s, so the path it is written through "
                "cannot be checked. Contract §9 rule 2 confines every write to the "
                "run directory; name it by a path under it." % (target, run_dir(root)))
    base, rel = spelled
    current = base
    for part in [""] + ([] if rel == os.curdir else rel.split(os.sep)):
        current = os.path.join(current, part) if part else current
        if os.path.islink(current):
            return ("%s is a symlink to %s. The run directory is inside the "
                    "scanned tree, which commits ledger/ and can commit a link "
                    "beside it, so writing through one lets the repository under "
                    "review choose what this tool appends to. Contract §1 puts the "
                    "run directory at the scanned root's .security-review/ and §9 "
                    "rule 2 confines every write to it. Remove the link - and look "
                    "at what it points at - then run this again."
                    % (current, os.readlink(current)))
    if os.path.lexists(base) and os.path.realpath(base) != real_run:
        return ("%s resolves to %s, not %s. Contract §1 puts the run directory at "
                "the scanned root's .security-review/ and §9 rule 2 confines every "
                "write to it." % (base, os.path.realpath(base), real_run))
    return None


def _run_dir_as_spelled(root, target):
    """(base, rel): the run directory as `target` spells it, and the rest of
    `target` below it - or None when `target` is under it by no spelling.

    Tried as run_dir(root), under realpath(root), and then under any other
    spelling of the root itself. The last is a link ABOVE .security-review,
    which is allowed: from /tmp/repo on macOS, `--root .` is /private/tmp/repo
    (getcwd resolves), and an --out written /tmp/repo/.security-review/... is
    the same directory. Refusing it as "not under the run directory" blocked a
    legitimate export; everything from .security-review down is still walked.
    """
    real_root = os.path.realpath(root)
    bases = [run_dir(root), os.path.join(real_root, ".security-review")]
    head = target
    while True:
        parent, name = os.path.split(head)
        if not name or parent == head:
            break
        if name == ".security-review" and os.path.realpath(parent) == real_root:
            bases.append(head)
        head = parent
    for base in bases:
        rel = os.path.relpath(target, base)
        if rel != os.pardir and not rel.startswith(os.pardir + os.sep):
            return base, rel
    return None


def guard_write(root, path, what):
    """`path`, absolute, or LedgerError if a write to it could be redirected.

    Called by every command before it writes anything, so a refused path
    refuses the command rather than its last step.
    """
    problem = run_dir_write_problem(root, path)
    if problem:
        raise LedgerError("refusing to write %s: %s" % (what, problem), EXIT_USAGE)
    return os.path.abspath(path)


@contextlib.contextmanager
def ledger_lock(directory):
    """The ledger's one lock: an exclusive flock on the directory itself.

    Every writer of decisions.jsonl and suppressions.jsonl holds it, and it is
    taken BEFORE the data file is opened. It used to be an flock on the data
    file's own descriptor, which `revoke` defeated: its second write rewrites
    suppressions.jsonl through os.replace, taking no lock, so a `suppress` that
    appended between the rewrite's read and its rename was erased - both
    commands exited 0 and `check` saw nothing wrong. A lock on the file cannot
    survive a rename of the file; a lock on the directory does, and it needs no
    lock file that stage 1's `!ledger/**` carve-out would then commit.

    Not reentrant: a second flock on a second descriptor for the same directory,
    in the same process, waits for the first. Nothing holding it takes it again.
    """
    if fcntl is None:
        yield
        return
    try:
        fd = os.open(directory, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    except OSError as exc:
        raise LedgerError("%s could not be opened to lock the ledger (%s)"
                          % (directory, exc), EXIT_USAGE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)                    # closing the descriptor releases it


def read_json(path):
    """(document, problem). Never raises for a missing, broken or huge file."""
    if not os.path.isfile(path):
        return None, "%s is not there" % path
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return None, "%s could not be read (%s)" % (path, exc)
    if size > MAX_JSON_BYTES:
        return None, ("%s is %d bytes, past the %d-byte limit this tool reads a "
                      "JSON document up to. It was not read: reading part of a "
                      "document and counting what was in it is worse than saying "
                      "the document was not read." % (path, size, MAX_JSON_BYTES))
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError) as exc:
        return None, "%s could not be read (%s)" % (path, exc)


def bounded_lines(fh, path, problems):
    """Yield (number, text) for every line, refusing one longer than the bound.

    `for line in fh` reads until a newline, so a single line with no newline in
    it is an unbounded read of a file this tool does not own. An oversize line is
    drained without being held, and reported with its number and its size, so it
    shows up in `check` rather than as a MemoryError or as a line nobody counted.
    """
    number = 0
    while True:
        chunk = fh.readline(MAX_LINE_BYTES + 1)
        if not chunk:
            return
        number += 1
        if len(chunk) <= MAX_LINE_BYTES:
            yield number, chunk
            continue
        dropped = len(chunk)
        while not chunk.endswith("\n"):
            chunk = fh.readline(MAX_LINE_BYTES + 1)
            if not chunk:
                break
            dropped += len(chunk)
        problems.append((path, number,
                         "is at least %d bytes, past the %d-byte line limit, and "
                         "was not read" % (dropped, MAX_LINE_BYTES)))


def read_jsonl(path):
    """(rows, problems). Each row carries `__line`, which is never written back.

    A malformed line is a problem, not an exception: `check` exists to list every
    one of them, and a ledger that cannot be read at all is the one state in
    which a reader most needs to be told which line is wrong.
    """
    rows, problems = [], []
    if not os.path.isfile(path):
        return rows, problems
    try:
        handle = open(path, encoding="utf-8")
    except OSError as exc:
        return rows, [(path, 0, "could not be read (%s)" % exc)]
    with handle as fh:
        for number, line in bounded_lines(fh, path, problems):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                problems.append((path, number, "is not JSON (%s)" % exc))
                continue
            if not isinstance(row, dict):
                problems.append((path, number, "is a %s, not a record object"
                                 % type(row).__name__))
                continue
            version = row.get("schema_version", SCHEMA_VERSION)
            if not isinstance(version, int) or version > SCHEMA_VERSION:
                # Contract preamble: a record from a newer schema is refused, not
                # guessed at. Skipping it here keeps every later count honest.
                problems.append((path, number,
                                 "carries schema_version %r and this tool knows %d; "
                                 "upgrade ledger.py rather than reading it as 1"
                                 % (version, SCHEMA_VERSION)))
                continue
            row["__line"] = number
            rows.append(row)
    return rows, problems


def append_jsonl(path, record, allocate=None):
    """Append one record, under the ledger lock. Returns what was written.

    Append is the only operation defined on the trail; the one exception is
    `revoke` filling `revoked_at`, which rewrites under the same lock.

    `allocate` is `(field, prefix)`, and when it is given the id is derived
    UNDER THE LOCK from the file as it stands at that moment. Allocating it
    outside - reading the file, then appending - is a read-modify-write with a
    window in it, and two people recording a decision at the same time both see
    DEC-0007 and both write it. `check` catches the collision afterwards, but an
    audit trail with two lines claiming one id has already lost the thing it is
    for, and the lock is right here.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with ledger_lock(directory or os.curdir):
        return _append_locked(path, record, allocate)


def _write_all(fd, data):
    while data:
        written = os.write(fd, data)
        data = data[written:]


def _append_locked(path, record, allocate=None):
    """append_jsonl's body, for a caller that already holds ledger_lock()."""
    payload = dict((k, v) for k, v in record.items() if not k.startswith("__"))
    # O_NOFOLLOW: a committed link AT the file is refused by the open itself,
    # whatever guard_write() saw a moment earlier.
    try:
        fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | _NOFOLLOW | _CLOEXEC,
                     0o644)
    except OSError as exc:
        raise LedgerError("%s could not be opened for append (%s). A symlink there "
                          "is refused, not followed: contract §9 rule 2."
                          % (path, exc), EXIT_USAGE)
    try:
        if allocate is not None:
            field, prefix = allocate
            existing = []
            with os.fdopen(os.dup(fd), "r", encoding="utf-8",
                           errors="replace") as reader:
                reader.seek(0)
                for _, line in bounded_lines(reader, path, []):
                    if not line.strip():
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, dict):
                        existing.append(row)
            payload[field] = next_id(prefix, existing, field)
        data = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        # A last line with no newline - an editor that strips it, a merge
        # resolved by hand, a torn write - used to have this record glued onto
        # it: `{...}{...}`, one line neither half of which read back, while the
        # command printed its DEC id and exited 0. Starting a line of our own
        # keeps this record whole and leaves a torn one where `check` names it.
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                data = b"\n" + data
        _write_all(fd, data)             # O_APPEND: always at the end
        os.fsync(fd)
    finally:
        os.close(fd)
    return payload


def _umask():
    """The process umask. It can only be read by setting it, so it is set back
    at once; this tool runs no threads. (Same helper as run_status._umask.)"""
    mask = os.umask(0o077)
    os.umask(mask)
    return mask


def _replace_atomic(path, data):
    """Replace `path` with `data` (bytes) without following a link on the way.

    Never through a predictable `path + ".tmp"`: a link planted at that name
    redirects the write wherever it points. mkstemp creates the temporary with
    O_EXCL in the target's own directory, and os.replace swaps a link at `path`
    out rather than writing through it.
    """
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        # mkstemp makes the file 0600. The mode open(path, "w") gave it before
        # is 0666 under the umask - not a fixed 0644, which would widen an
        # operator's `umask 077` to world-readable.
        os.chmod(temporary, 0o666 & ~_umask())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_jsonl_atomic(path, records):
    """Replace a DERIVED file. Used for samples.jsonl and nothing else.

    decisions.jsonl and suppressions.jsonl are never written through here: they
    are the audit trail, and the only operation defined on them is append.
    samples.jsonl is a projection of the decisions and is regenerated whole, so
    replacing it loses nothing that is not recoverable from the trail.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    _replace_atomic(path, "".join(json.dumps(record, sort_keys=True) + "\n"
                                  for record in records).encode("utf-8"))


def stamp_revocation(path, suppression_id, revocation):
    """Fill `revoked_at` on the suppression's own line. Returns how many it hit.

    The caller holds ledger_lock() for the whole read-rewrite-rename: an append
    landing inside that window was erased by the rename.

    An appended revocation record is the trail, and it was not enough. Contract
    §8 puts `revoked_at` ON the suppression record - it is in the schema,
    spelled `null` - and when this was written that field was all
    `enrich_candidates.py` and `export_sarif.py` read. A revoke that only
    appended left `status` printing REVOKED while stage 3 went on suppressing
    the finding until the expiry - measured on the fixture: a revoked CRY-002
    suppression still kept its candidate out of the queue until 2028. Both now
    honour a `record_type: "revocation"` line as well, so the trail alone ends
    the suppression; the field is still the contract's, and a record whose own
    line says `revoked_at: null` after a revoke says the opposite of its trail.

    Every other line is written back BYTE FOR BYTE - read and written as bytes,
    so not even a line that is not UTF-8 is re-encoded. The only thing that
    changes is a field the contract defines on that record and initialises to
    null, and the appended revocation record still carries who ended it, when
    and why.
    """
    with open(path, "rb") as fh:
        raw = fh.readlines()
    out, hit = [], 0
    for line in raw:
        if not line.strip():
            out.append(line)
            continue
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            out.append(line)                 # not ours to repair; `check` says so
            continue
        if (not isinstance(row, dict)
                or row.get("record_type", "suppression") != "suppression"
                or row.get("suppression_id") != suppression_id
                or row.get("revoked_at")):
            out.append(line)
            continue
        row["revoked_at"] = revocation["revoked_at"]
        row["revoked_by"] = revocation["author"]
        row["revoked_reason"] = revocation["reason"]
        out.append((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))
        hit += 1
    _replace_atomic(path, b"".join(out))
    return hit


# Stage 1 writes `.security-review/.gitignore` ignoring everything it produced,
# with `!ledger/` and `!ledger/**` carved back out, because contract §1 makes this
# one directory the exception. Nothing here writes that file - it belongs to
# stage 1 - but everything here checks it, because a ledger that is silently
# gitignored is not an audit trail, it is a scratch file that looks like one, and
# the failure shows up as "we have never had any of this" months later.
#
# Checked the way git reads the file, not by looking for a carve-out line. The
# check used to pass a file holding any one of `!ledger/`, `!ledger/**` and
# `!ledger`, and under `*` none of them is enough alone: `!ledger` and
# `!ledger/` give back the DIRECTORY, and `*` still matches
# ledger/decisions.jsonl by its own name; `!ledger/**` gives back nothing,
# because git never looks inside a directory it has excluded. `check` passed
# while every decision was lost on the next clone - the one failure it exists
# to catch. So each file the ledger writes, and each directory above it, is
# run through the file's patterns in order, the last match winning and an
# excluded directory taking everything below it. Only this file is read: a
# repository-level ignore that swallows .security-review/ whole is the
# operator's, and nothing here can see it.
GITIGNORE_CARVE_OUT = ("!ledger/", "!ledger/**")
LEDGER_FILES = ("ledger/decisions.jsonl", "ledger/suppressions.jsonl",
                "ledger/training/samples.jsonl")
# What git's bracket expressions name, in the spelling `re` understands.
_POSIX_CLASSES = {
    "alnum": "a-zA-Z0-9", "alpha": "a-zA-Z", "blank": " \\t",
    "cntrl": "\\x00-\\x1f\\x7f", "digit": "0-9", "graph": "!-~", "lower": "a-z",
    "print": " -~", "punct": "!-/:-@\\[-`{-~", "space": " \\t\\n\\r\\f\\v",
    "upper": "A-Z", "xdigit": "0-9a-fA-F"}


# A pattern git abandons outright - a bracket that never closes, a class it
# does not know - matches nothing, rather than reading `[` as itself.
_NEVER = "(?!)"


def _glob_bracket(pattern, i):
    """(regex, next index) for the bracket expression opening at pattern[i].

    As wildmatch's loop reads one: `!` or `^` negates, a `]` first is a
    member, a `\\` makes the next character a member, and nothing in it
    matches a `/`. A `-` after a single member and before anything but the
    closing `]` makes a range; after a range or a class it is itself. A range
    written backwards (`[z-a]`, `[a--]`) is empty and leaves its first member,
    as git has it - handed to `re` as written it raised re.error, and `check`,
    and every write that warns about this file after appending its record,
    died in a traceback over a file git reads without a murmur. `[:` opens a
    class only when the first `]` after it follows a `:`; otherwise the `[`
    is itself.
    """
    j, n = i + 1, len(pattern)
    negate = j < n and pattern[j] in "!^"
    if negate:
        j += 1
    out, first, prev = [], True, None
    while j < n:
        c = pattern[j]
        if c == "]" and not first:
            return "(?!/)[%s%s]" % ("^" if negate else "", "".join(out)), j + 1
        first = False
        if c == "\\":
            if j + 1 >= n:
                return _NEVER, n
            j += 1
            prev = pattern[j]
            out.append(re.escape(prev))
        elif (c == "-" and prev is not None and j + 1 < n
              and pattern[j + 1] != "]"):
            j += 1
            high = pattern[j]
            if high == "\\":
                if j + 1 >= n:
                    return _NEVER, n
                j += 1
                high = pattern[j]
            if prev <= high:
                out.append("%s-%s" % (re.escape(prev), re.escape(high)))
            prev = None
        elif c == "[" and pattern.startswith("[:", j):
            close = pattern.find("]", j + 2)
            if close < 0:
                return _NEVER, n
            if close == j + 2 or pattern[close - 1] != ":":
                prev = c                        # not a class: `[` is itself
                out.append(re.escape(c))
            else:
                name = pattern[j + 2:close - 1]
                if name not in _POSIX_CLASSES:
                    return _NEVER, n
                out.append(_POSIX_CLASSES[name])
                prev, j = None, close
        else:
            prev = c
            out.append(re.escape(c))
        j += 1
    return _NEVER, n


def _glob_regex(pattern):
    """git's wildmatch, as a regex over a path relative to the ignore file.

    `*` and `?` never cross a `/`; `**` does only as a whole segment - leading
    `**/`, trailing `/**`, or `/**/` for zero or more directories - and is a
    plain `*` anywhere else.
    """
    out, i, n = [], 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            j = i
            while j < n and pattern[j] == "*":
                j += 1
            whole = (j - i >= 2 and (i == 0 or pattern[i - 1] == "/")
                     and (j == n or pattern[j] == "/"))
            if whole and j < n:
                out.append("(?:.*/)?")          # `**/`: zero or more directories
                j += 1
            else:
                out.append(".*" if whole else "[^/]*")
            i = j
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            regex, i = _glob_bracket(pattern, i)
            out.append(regex)
        elif c == "\\":
            if i + 1 >= n:
                return re.compile(_NEVER)       # a trailing `\` matches nothing
            out.append(re.escape(pattern[i + 1]))
            i += 2
        else:
            out.append(re.escape(c))
            i += 1
    try:
        return re.compile("".join(out), re.S)
    except re.error:
        # Not reachable from anything git accepts, as far as the brackets
        # above go - but this file comes out of the scanned tree, and a line
        # read wrongly must cost that line, never the command.
        return re.compile(_NEVER)


def gitignore_patterns(text):
    """[(line number, line, negated, directories only, anchored, regex)], as
    git parses an ignore file."""
    out = []
    if text.startswith("\ufeff"):
        text = text[1:]                         # git skips a UTF-8 BOM
    for number, line in enumerate(text.split("\n"), 1):
        line = line[:-1] if line.endswith("\r") else line
        if not line or line.startswith("#"):
            continue
        # Trailing spaces go, from the first one no `\` escapes.
        pattern, last_space, k = line, None, 0
        while k < len(pattern):
            if pattern[k] == " ":
                last_space = k if last_space is None else last_space
            else:
                last_space = None
                k += pattern[k] == "\\"
            k += 1
        if last_space is not None:
            pattern = pattern[:last_space]
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
        dir_only = pattern.endswith("/")
        if dir_only:
            pattern = pattern[:-1]
        anchored = "/" in pattern
        if pattern.startswith("/"):
            pattern = pattern[1:]
        if pattern:
            out.append((number, line, negated, dir_only, anchored,
                        _glob_regex(pattern)))
    return out


def gitignore_verdict(patterns, path):
    """(what is lost, line number, line) when `patterns` keep `path` out of
    git - the file itself, or the first directory above it that is excluded,
    spelled with a trailing `/` - or None."""
    parts = path.split("/")
    for depth in range(1, len(parts) + 1):
        here, is_dir = "/".join(parts[:depth]), depth < len(parts)
        last = None
        for number, line, negated, dir_only, anchored, regex in patterns:
            if dir_only and not is_dir:
                continue
            if regex.fullmatch(here if anchored else parts[depth - 1]):
                last = None if negated else (number, line)
        if last:
            return (here + ("/" if is_dir else ""),) + last
    return None


def gitignore_problem(root):
    """A sentence if stage 1's ignore would swallow the ledger, else None."""
    path = os.path.join(run_dir(root), ".gitignore")
    if not os.path.isfile(path):
        return None                     # nothing is ignored, so nothing is lost
    try:
        with open(path, "rb") as fh:
            # Bounded: this file comes out of the scanned tree like everything
            # else here, and an ignore file is never megabytes long. Bytes,
            # as git reads it: a stray non-UTF-8 byte is not a traceback.
            text = fh.read(MAX_LINE_BYTES).decode("utf-8", "surrogateescape")
    except OSError as exc:
        return "%s could not be read (%s)" % (path, exc)
    patterns = gitignore_patterns(text)
    for tracked in LEDGER_FILES:
        verdict = gitignore_verdict(patterns, tracked)
        if verdict:
            lost, number, line = verdict
            return ("%s does not carve out ledger/: its line %d, `%s`, ignores "
                    "%s%s. Contract §1 makes the ledger the one directory that is "
                    "meant to be committed, so as written every decision recorded "
                    "here is lost on the next clone. Add %s after the last line "
                    "that ignores it."
                    % (path, number, line, lost,
                       ", and git never looks inside a directory it has excluded"
                       if lost.endswith("/") else "",
                       " and ".join("`%s`" % carve
                                    for carve in GITIGNORE_CARVE_OUT)))
    return None


def warn_gitignore(root):
    """Said on every write, not only on `check`: the record was just made, and
    this is the moment somebody can still fix where it landed."""
    problem = gitignore_problem(root)
    if problem:
        print("  WARNING: %s" % problem)


# --------------------------------------------------------------------------- #
# key material - the one thing the ledger must never carry
# --------------------------------------------------------------------------- #
#
# ledger/ is the directory stage 1's .gitignore carves back out, and
# training/samples.jsonl is what a model trains on. A reviewer confirming a
# LOG-005 finding naturally pastes the line - "confirmed: api_key = "sk_live_..."
# is live, rotate it" - and that went into decisions.jsonl, then into the
# sample's `explanation`, and `check` passed both. Contract §4a: copying a live
# credential into the run directory "turns the scanner into a second place the
# secret leaks from" - and this is the one copy that is committed, outlives a
# rotation and a history scrub alike, and ends up in training data.
#
# The detection is sweep_secrets', not a copy: sweep_secrets.export_spans, the
# one detector for text that leaves the machine, which the REPORT.md gate
# (verify_findings.secretish_spans) and the SARIF scrub read too - the known
# families, a quoted value under a secret-shaped name, because a reason quoting
# `password = "Winter2026Payroll"` carries no family and no entropy, a key byte
# array, and the high-entropy run. NOT the sweeper's 9-character leak test:
# that refuses a full commit SHA, and a reviewer cites a fix commit in a reason
# all the time. export_spans already skips a span that is redacted and excuses
# a fix-commit or blob URL, whose path `/` joins into one entropy run; what is
# this tool's own is the bare hex digest - a commit, a content_hash - which is
# not key material here wherever it stands, and the same digest where cgit,
# gitweb and Gerrit put it (QUERY_DIGEST, CHANGE_ID). And, as the report gate
# does, this leaves the kinds only a redacting reader acts on
# (REDACT_ONLY_KINDS, a value that reads as words): a hit here refuses a
# reason, and refuses `check` and `export` over a ledger already committed.

BENIGN_DIGEST = re.compile(r"(?:[0-9a-f]{16}|[0-9a-f]{40}|[0-9a-f]{64})\Z")

# The same digest named in a URL's QUERY rather than its path. cgit writes
# `commit/?id=<sha>` (git.kernel.org, savannah) and gitweb `;h=<sha>` or
# `;hb=<sha>` (sourceware, OpenSSL), and kernel, glibc and OpenSSL advisories
# cite their fixes in exactly that form - refused as key material, with
# `check` failing on a ledger that cited one and `export` refusing the whole
# training set. `?`, `&` and `;` end a secret-alphabet run and `=` does not,
# so the run starts at the parameter's name and BENIGN_DIGEST never saw the
# digest. Only these names, and only straight after `?`, `&` or `;` inside a
# URL: `?access_token=` with forty hex digits is a classic GitHub OAuth token
# and `?key=` with sixty-four an HMAC key, and both are still refused.
QUERY_DIGEST = re.compile(r"(?:id|h|hb|hp|hpb|commit|sha|rev)="
                          r"(?:[0-9a-f]{16}|[0-9a-f]{40}|[0-9a-f]{64})\Z")
# A Gerrit trailer, copied out of a fix commit's message: `Change-Id: I<40
# hex>`. Excused only straight after the trailer's own name.
CHANGE_ID = re.compile(r"I[0-9a-f]{40}\Z")
CHANGE_ID_NAME = re.compile(r"Change-Id:[ \t]*\Z")

_SIBLINGS = {}


def _sibling(name):
    """A sibling tool, imported on first use, or None if it will not load.

    Imported late and without bytecode: this tool is otherwise a standalone
    script, and a __pycache__ dropped beside it lands in the user's checkout.
    """
    if name not in _SIBLINGS:
        written = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            if _HERE not in sys.path:
                sys.path.insert(0, _HERE)
            _SIBLINGS[name] = __import__(name)
        except Exception:                              # noqa: BLE001
            _SIBLINGS[name] = None                     # not shipped
        finally:
            sys.dont_write_bytecode = written
    return _SIBLINGS[name]


def _sweeper():
    """sweep_secrets, imported on first use, or None if it will not load."""
    return _sibling("sweep_secrets")


def key_material(text):
    """Redacted samples of whatever in `text` reads as key material, or []."""
    sweep = _sweeper()
    if sweep is None or not isinstance(text, str) or not text:
        return []
    samples = []
    for start, end, kind in sorted(sweep.export_spans(text)):
        if kind in sweep.REDACT_ONLY_KINDS:
            continue                                   # words: see the block above
        span = text[start:end]
        if kind == "entropy" and BENIGN_DIGEST.match(span):
            continue                                   # a commit or a content hash
        if (kind == "entropy" and QUERY_DIGEST.match(span) and start
                and text[start - 1] in "?&;"
                and any(url.start() < start and end <= url.end()
                        for url in sweep.URL_IN_TEXT.finditer(text))):
            continue                                   # cgit's ?id=, gitweb's ;h=
        if (kind == "entropy" and CHANGE_ID.match(span)
                and CHANGE_ID_NAME.search(text[:start])):
            continue                                   # a Gerrit Change-Id
        sample = sweep.redact(span)
        if sample not in samples:
            samples.append(sample)
    return samples


def refuse_key_material(reason, what, flag="--reason"):
    """LedgerError if --reason quotes a credential. Only redactions are shown."""
    samples = key_material(reason)
    if samples:
        raise LedgerError(
            "%s carries what reads as key material (%s), and %s is not "
            "recorded with it. ledger/ is committed and a reason becomes a "
            "training sample's explanation, so a credential written here outlives "
            "any rotation and any scrub of the file it came from. Cite it by "
            "file:line, or quote it redacted - the first four and last four "
            "characters, the middle elided - and run this again. If it is live, "
            "rotate it: it is already in the tree."
            % (flag, ", ".join(samples), what))


# --------------------------------------------------------------------------- #
# time
# --------------------------------------------------------------------------- #

def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def stamp(moment):
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value):
    """An ISO-8601 stamp or a bare date as an aware UTC datetime, or None."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        moment = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone(datetime.timezone.utc)


def require_time(value, what):
    moment = parse_time(value)
    if moment is None:
        raise LedgerError("%s is not an ISO-8601 date or timestamp: %r. Write it "
                          "as 2026-12-18 or 2026-12-18T00:00:00Z." % (what, value),
                          EXIT_USAGE)
    return moment


# --------------------------------------------------------------------------- #
# the Validator Contract's FP-* vocabulary, read from the contract
# --------------------------------------------------------------------------- #

SECTION_8 = re.compile(r"^##\s*8\.\s", re.M)
TABLE_CODE = re.compile(r"^\|\s*`(FP-[A-Z0-9-]+)`\s*\|", re.M)


def contract_path(bundle_root):
    """references/validator-contract.md in the skill folder (`bundle_root`)."""
    return os.path.join(bundle_root, "references", "validator-contract.md")


def contract_disqualifiers(path):
    """(codes, problem) - the §8 table, read off the contract file.

    Only the rows of §8's own table count. FP-ACCEPTED is defined in §7 and is
    not a disqualifier, and the codes quoted in §8a's prose are discussion, not
    vocabulary, so the parser is anchored to the table rows between the §8
    heading and the next heading.
    """
    if not os.path.isfile(path):
        return None, "%s is not there, so the FP-* vocabulary could not be read" % path
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return None, "%s could not be read (%s)" % (path, exc)
    match = SECTION_8.search(text)
    if not match:
        return None, ("%s has no `## 8.` heading, so the disqualifier table could "
                      "not be located. Teach this parser the new shape rather than "
                      "leaving the check silently passing." % path)
    rest = text[match.end():]
    end = re.search(r"^##\s", rest, re.M)
    section = rest[:end.start()] if end else rest
    codes = TABLE_CODE.findall(section)
    if not codes:
        return None, ("%s §8 holds no `| `FP-…` |` table rows, so the disqualifier "
                      "vocabulary read as empty" % path)
    seen, ordered = set(), []
    for code in codes:
        if code not in seen:
            seen.add(code)
            ordered.append(code)
    return tuple(ordered), None


SCOPE_ROW = re.compile(r"^\|\s*`(OOS-[A-Z0-9-]+)`\s*\|", re.M)


def ledger_contract_path(bundle_root):
    """references/pipeline-contract-stage5.md in the skill folder."""
    return os.path.join(bundle_root, "references", "pipeline-contract-stage5.md")


def contract_scope_codes(path):
    """(codes, problem) - the out-of-scope codes, read off contract §8's table.

    The ledger's own section of pipeline-contract-stage5.md, between its
    `## 8.` heading and the next heading (§8b), the way contract_disqualifiers
    reads the Validator Contract's.
    """
    if not os.path.isfile(path):
        return None, ("%s is not there, so the out-of-scope codes could not be "
                      "read" % path)
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return None, "%s could not be read (%s)" % (path, exc)
    match = SECTION_8.search(text)
    if not match:
        return None, ("%s has no `## 8.` heading, so the out-of-scope table could "
                      "not be located" % path)
    rest = text[match.end():]
    end = re.search(r"^##\s", rest, re.M)
    codes = SCOPE_ROW.findall(rest[:end.start()] if end else rest)
    if not codes:
        return None, ("%s §8 holds no `| `OOS-…` |` table rows, so the out-of-scope "
                      "codes read as empty" % path)
    return tuple(dict.fromkeys(codes)), None


# --------------------------------------------------------------------------- #
# the run artefacts a decision is built from
# --------------------------------------------------------------------------- #

def load_run(root):
    document, _ = read_json(os.path.join(run_dir(root), "run.json"))
    return document if isinstance(document, dict) else None


def load_corpus(root):
    """What this run measured, and how completely.

    `hashes` is None when there is no extract at all. None is not an empty
    corpus: an empty corpus would say every suppression is stale; not knowing
    says nothing suppresses because nothing has been measured, which is the
    honest state and the one `status` reports separately.

    `complete` is the same distinction one level down, and it used to be missing.
    An extract that is THERE but unreadable - malformed lines, or records from a
    newer schema this tool refuses to guess at - produced an empty dict, and an
    empty dict made every suppression "stale: the function was renamed, moved or
    removed", which is a sentence about the repository that nobody measured. When
    the extract could not be read whole, absence proves nothing and says so.
    """
    path = os.path.join(run_dir(root), "extract", "functions.jsonl")
    if not os.path.isfile(path):
        return {"hashes": None, "problems": [], "path": path, "complete": False}
    hashes = {}
    rows, problems = read_jsonl(path)
    for row in rows:
        key = row.get("function_key")
        if key:
            hashes[key] = row.get("content_hash")
    return {"hashes": hashes, "problems": problems, "path": path,
            "complete": not problems}


def load_functions(root):
    path = os.path.join(run_dir(root), "extract", "functions.jsonl")
    rows, _ = read_jsonl(path)
    return dict((r.get("function_key"), r) for r in rows if r.get("function_key"))


def load_scores(root):
    path = os.path.join(run_dir(root), "scores", "scores.jsonl")
    rows, _ = read_jsonl(path)
    return dict((r.get("function_key"), r) for r in rows if r.get("function_key"))


# A derived MEM-WFS finding (rules_lib.derived_record has the full account): the memory-safety
# validator's whole-function pass found it while validating another candidate, so it has a
# finding file (findings/<candidate id>_WFS.json, `derived_from` naming that candidate) and no
# candidate record. It is read against its source's record, relabelled MEM-WFS. This is a copy
# of rules_lib's, because this tool imports nothing from it; tests/test_contract_parity.py
# pins the two equal.
DERIVED_RULE = "MEM-WFS"
DERIVED_FILE = re.compile(r"^.+_WFS\d*\.json$")
_DERIVED_LOCATION = re.compile(r"^(.*):(\d+)\s*$")


def derived_record(finding, source):
    if not isinstance(finding, dict) or not isinstance(source, dict):
        return None
    if finding.get("rule_id") != DERIVED_RULE or not finding.get("candidate_id"):
        return None
    if not source.get("candidate_id") or str(finding.get("derived_from")) != str(
            source["candidate_id"]):
        return None
    record = dict(source)
    for key in ("sink_text", "line", "sink_offset", "line_offset"):
        record.pop(key, None)
    record.update(candidate_id=finding["candidate_id"], rule_id=DERIVED_RULE,
                  derived_from=source["candidate_id"])
    where = finding.get("primary_location")
    hit = _DERIVED_LOCATION.match(where) if isinstance(where, str) else None
    if hit:
        record["file"] = hit.group(1)
        record["line"] = int(hit.group(2))
    for item in finding.get("evidence") or []:
        if isinstance(item, dict) and item.get("role") == "sink" and item.get("code"):
            record["sink_text"] = item["code"]
            break
    return record


def derived_findings(root):
    """[finding, ...] for every derived MEM-WFS finding file in this run, by name."""
    directory = os.path.join(run_dir(root), "findings")
    out = []
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if not DERIVED_FILE.match(name):
            continue
        document, _ = read_json(os.path.join(directory, name))
        if isinstance(document, dict) and document.get("derived_from"):
            out.append(document)
    return out


def load_candidate(root, candidate_id):
    """The stage 3 candidate record, or None. Searches every category file; a
    derived MEM-WFS finding's id answers with its source's record, relabelled."""
    found = _load_stage3_candidate(root, candidate_id)
    if found is not None or not DERIVED_FILE.match(candidate_id + ".json"):
        return found
    finding = load_finding(root, candidate_id)
    if isinstance(finding, dict) and finding.get("derived_from"):
        source = _load_stage3_candidate(root, str(finding["derived_from"]))
        return derived_record(finding, source)
    return None


def _load_stage3_candidate(root, candidate_id):
    directory = os.path.join(run_dir(root), "candidates")
    if not os.path.isdir(directory):
        return None
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json") or name == "coverage.json":
            continue
        document, _ = read_json(os.path.join(directory, name))
        if document is None:
            continue
        items = document if isinstance(document, list) else [document]
        for item in items:
            if isinstance(item, dict) and str(item.get("candidate_id")) == candidate_id:
                return item
    return None


def load_finding(root, candidate_id):
    """The stage 4 VALIDATOR verdict for this candidate, or None.

    Contract §1: `findings/CAND-####.json` is stage 4's verdict on every
    dispatched candidate, and `arbitration/ARB-CAND-####.json` is "one
    adjudication per QUEUED finding" - the subset `arbitration/queue.json` sent
    to the arbiter. Requiring the ARB file was therefore requiring the wrong
    artefact: it refused a decision on every finding the arbiter was never asked
    to review, which on any real run is most of them, and stage 5 could not be
    used at all. §9 rule 3 asks that the candidate be ADJUDICATED; a validator
    verdict is an adjudication - unless queue.json sent it on to the arbiter,
    which is arbitration_queued()'s half. `export_sarif.py` applies the same
    ARB-over-validator precedence but is stricter: a dashboard gets only
    ARB-backed findings, and the rest are counted as `withheld_unadjudicated`.
    """
    path = os.path.join(run_dir(root), "findings", "%s.json" % candidate_id)
    document, _ = read_json(path)
    if document is None:
        return None
    items = document if isinstance(document, list) else [document]
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("candidate_id") in (None, candidate_id):
            return item
    return None


def load_arbitration(root, candidate_id):
    """The stage 4 arbitration for this candidate, or None. Queued findings only."""
    path = os.path.join(run_dir(root), "arbitration", "ARB-%s.json" % candidate_id)
    document, _ = read_json(path)
    if document is None:
        return None
    items = document if isinstance(document, list) else [document]
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("candidate_id") in (None, candidate_id):
            return item
    return None


def arbitration_queued(root):
    """The candidate ids `arbitration/queue.json` sent to the arbiter.

    Empty when there is no queue or it cannot be read: a finding-only decision
    was accepted before this check existed, and a missing queue says nothing
    about which verdicts are still waiting. Read the way run_status.py reads it.
    """
    document, _ = read_json(os.path.join(run_dir(root), "arbitration", "queue.json"))
    queue = document.get("queue") if isinstance(document, dict) else None
    if not isinstance(queue, list):
        return frozenset()
    return frozenset(str(entry["candidate_id"]) for entry in queue
                     if isinstance(entry, dict) and entry.get("candidate_id"))


ARB_NAME = re.compile(r"^ARB-(?P<candidate>.+)\.json$")


def load_arbitrations(root):
    """{candidate_id: ARB record} for every ARB-*.json this run holds.

    Read for the MERGED relation, which is spread over the records: a merged
    finding names its survivor in `merged_into`, and nothing names the
    survivor's other members but their own records.
    """
    directory = os.path.join(run_dir(root), "arbitration")
    found = {}
    if not os.path.isdir(directory):
        return found
    for name in sorted(os.listdir(directory)):
        match = ARB_NAME.match(name)
        if match:
            record = load_arbitration(root, match.group("candidate"))
            if record is not None:
                found[match.group("candidate")] = record
    return found


def merged_cluster(candidate_id, arbitration, arbitrations):
    """(survivor, members): the arbiter's MERGED cluster this candidate is in.

    A MERGED record and its survivor assert one root cause (roles/arbiter.md,
    Step C), so a decision on one is a decision about all of them. The Mbed TLS
    session confirmed CAND-0026 and CAND-0020 while rejecting CAND-0010, the
    survivor they were merged into, and nothing noticed. A MERGED record with no
    `merged_into` names no survivor, and is its own cluster of one.
    """
    survivor = candidate_id
    if (arbitration or {}).get("arbitration") == "MERGED" and arbitration.get("merged_into"):
        survivor = str(arbitration["merged_into"])
    members = {survivor, candidate_id}
    for other, record in arbitrations.items():
        if (record.get("arbitration") == "MERGED" and record.get("merged_into")
                and str(record["merged_into"]) == survivor):
            members.add(other)
    return survivor, members


def split_function_id(function_id):
    """`<function_key>@<content_hash>` -> (key, hash). Contract §2."""
    if not function_id or "@" not in function_id:
        return None, None
    key, _, content_hash = function_id.rpartition("@")
    return key or None, content_hash or None


def identity_of(candidate, *others):
    """(function_key, content_hash) for a candidate, from whichever record has it."""
    for record in (candidate,) + others:
        if not isinstance(record, dict):
            continue
        key = record.get("function_key")
        content_hash = record.get("content_hash")
        if not (key and content_hash):
            from_id = split_function_id(record.get("function_id"))
            key = key or from_id[0]
            content_hash = content_hash or from_id[1]
        if key and content_hash:
            return key, content_hash
    return None, None


# --------------------------------------------------------------------------- #
# the ledger itself
# --------------------------------------------------------------------------- #

def load_ledger(root):
    """Every record, split by kind, with the problems found reading them."""
    decisions, problems_d = read_jsonl(decisions_path(root))
    for record in decisions:
        # recover_offsets() keeps a sink offset read back off this run here;
        # one a file carries was never measured by anything.
        record.pop("__line_offset", None)
    rows, problems_s = read_jsonl(suppressions_path(root))
    # A suppression file holds two record kinds. Older records predate
    # `record_type`, so a row without one is a suppression: the revocation is the
    # kind that was added, and it always carries the marker.
    suppressions = [r for r in rows
                    if r.get("record_type", "suppression") == "suppression"]
    revocations = [r for r in rows if r.get("record_type") == "revocation"]
    return {
        "decisions": decisions,
        "suppressions": suppressions,
        "revocations": revocations,
        "problems": problems_d + problems_s,
    }


def next_id(prefix, records, field):
    highest = 0
    pattern = re.compile(r"^%s-(\d+)$" % re.escape(prefix))
    for record in records:
        match = pattern.match(str(record.get(field) or ""))
        if match:
            highest = max(highest, int(match.group(1)))
    return "%s-%04d" % (prefix, highest + 1)


def decision_key(record):
    """What a later decision supersedes: the same candidate IN THE SAME RUN,
    about the same function body under the same rule.

    candidate_id alone was the key, and stage 3 numbers candidates from
    CAND-0001 on every run (enrich_candidates.py) while the ledger outlives the
    run (contract §1, §8). So run 2's decision on its CAND-0001 superseded run
    1's decision on a different function: `status` lost a confirmation, the
    export lost the sample, and the tool printed "supersedes DEC-0001" about
    code nobody had re-judged. run_id scopes the id; function_key, content_hash
    and rule_id stay in the key because re-running stage 3 alone under the same
    run_id renumbers the ids too. Not (function_key, content_hash, rule_id)
    alone: one function can carry two hits of one rule on different lines.
    A correction across runs is a later run's decision on the same question,
    and one across a renumbering is a decision of the same run on the same
    measured sink; either retires the earlier one (retires(),
    current_answers()) for `check`, `status`,
    the conflict refusal and the export alike; the export's (function_key,
    content_hash, cwe) dedup was that fold once, and stopped being it when
    `cwe` became the adjudicated CWE, which a model picks anew each run. A
    legacy line with no run_id gets "" in that slot.
    """
    return tuple(str(record.get(field) or "") for field in
                 ("run_id", "candidate_id", "function_key", "content_hash",
                  "rule_id"))


def latest_by_candidate(decisions):
    """The decision that stands, per decision_key(), and the ones it superseded.

    The file is append-only, so a correction is a new line rather than an edit.
    That only works if every reader agrees which line wins: the newest `at`, and
    on a tie the later line. Nothing else in this tool looks at a decision
    without going through here.
    """
    standing, superseded = {}, []
    ordered = sorted(decisions,
                     key=lambda r: (str(r.get("at") or ""), r.get("__line", 0)))
    for record in ordered:
        key = decision_key(record)
        if key in standing:
            superseded.append(standing[key])
        standing[key] = record
    return standing, superseded


def suppression_state(record, revocation, corpus, moment):
    """One suppression, resolved against the clock and the current corpus."""
    hashes = corpus["hashes"]
    key = record.get("function_key")
    expires = parse_time(record.get("expires_at"))
    current = None
    stale_reason = None
    unverified_reason = None
    if hashes is None:
        state = "unverified"
        unverified_reason = "this run has no extract, so nothing has been measured"
    elif key not in hashes and not corpus["complete"]:
        # Rule 3 turns on the function being shown UNCHANGED, and absence is the
        # one thing a half-read extract cannot show. Calling this stale would put
        # "the function was renamed, moved or removed" next to a file this tool
        # declined to read.
        state = "unverified"
        unverified_reason = ("%s has %d unreadable line(s), so this function's "
                             "absence from it proves nothing"
                             % (corpus.get("path"), len(corpus["problems"])))
    elif key not in hashes:
        # A function that is not in the corpus cannot be shown unchanged, and an
        # unverifiable suppression does not suppress. Renaming or deleting the
        # function is the commonest way a suppression outlives its subject.
        state = "stale"
        stale_reason = ("function_key is not in this run's extract; the function "
                        "was renamed, moved or removed")
    else:
        current = hashes.get(key)
        if current != record.get("content_hash_at_creation"):
            state = "stale"
            stale_reason = ("created against %s, function is now %s; the body "
                            "changed after the suppression was written"
                            % (record.get("content_hash_at_creation"), current))
        else:
            state = "active"
    # Either half says revoked: the appended revocation record, or `revoked_at`
    # on the record's own line. A record carrying one without the other is a
    # half-finished revoke, and `check` reports it rather than this quietly
    # papering over it.
    if revocation is not None or record.get("revoked_at"):
        state = "revoked"
    elif expires is not None and expires <= moment:
        state = "expired"
    days_left = None
    if expires is not None:
        days_left = (expires - moment).total_seconds() / 86400.0
    created = parse_time(record.get("created_at"))
    span = None
    if expires is not None and created is not None:
        span = (expires - created).total_seconds() / 86400.0
    # Rule 2 has exactly one legitimate escape - --force, which records itself.
    # Raising --max-expiry-days is the other way past 180 days and records only
    # the raised limit, so the folded view computes the span against the DEFAULT
    # and `status` and `check` both say when a long expiry never had to be forced.
    long_unforced = bool(span is not None and span > DEFAULT_MAX_EXPIRY_DAYS
                         and not record.get("forced"))
    return {
        "suppression_id": record.get("suppression_id"),
        "function_key": key,
        "rule_id": record.get("rule_id"),
        "author": record.get("author"),
        "reason": record.get("reason"),
        "created_at": record.get("created_at"),
        "expires_at": record.get("expires_at"),
        "content_hash_at_creation": record.get("content_hash_at_creation"),
        "current_content_hash": current,
        "forced": bool(record.get("forced")),
        "max_expiry_days": record.get("max_expiry_days"),
        "state": state,
        "stale_reason": stale_reason,
        "unverified_reason": unverified_reason,
        "days_total": None if span is None else round(span, 2),
        "long_unforced": long_unforced,
        "days_left": None if days_left is None else round(days_left, 2),
        "revoked_at": ((revocation or {}).get("revoked_at")
                       or record.get("revoked_at")),
        "revoked_by": ((revocation or {}).get("author")
                       or record.get("revoked_by")),
        "revoked_reason": ((revocation or {}).get("reason")
                           or record.get("revoked_reason")),
        "line": record.get("__line"),
    }


def resolve_suppressions(ledger, corpus, moment):
    revocation_by_id = {}
    for record in ledger["revocations"]:
        target = record.get("suppression_id")
        # First revocation wins. A second one is noise in the trail rather than a
        # second ending, and `check` reports it.
        revocation_by_id.setdefault(target, record)
    return [suppression_state(record, revocation_by_id.get(record.get("suppression_id")),
                              corpus, moment)
            for record in ledger["suppressions"]]


# --------------------------------------------------------------------------- #
# what a decision is held to: the path, the scope, and the decisions beside it
# --------------------------------------------------------------------------- #

def tree_file(root, relpath):
    """(absolute path, None) for a file of the scanned project, or (None, why).

    A basis line and the head FP-GENERATED is checked against come out of the
    scanned tree, which can commit a link to anywhere. So the path is relative,
    resolves inside the root, is a regular file, and is not under
    .security-review/: the run directory is this pipeline's state, never
    evidence about the project.
    """
    rel = relpath.strip() if isinstance(relpath, str) else ""
    if not rel:
        return None, "no path was given"
    if os.path.isabs(rel):
        return None, "%s is absolute; name it relative to the scanned root" % rel
    real_root = os.path.realpath(root)
    try:
        target = os.path.realpath(os.path.join(real_root, rel))
    except (ValueError, OSError) as exc:        # a NUL out of a candidate record
        return None, "%r cannot be a path (%s)" % (rel, exc)
    if not target.startswith(real_root + os.sep):
        return None, "%s resolves to %s, outside the scanned root %s" % (rel, target,
                                                                           real_root)
    state = os.path.join(real_root, ".security-review")
    if target == state or target.startswith(state + os.sep):
        return None, ("%s is under .security-review/, the pipeline's own state, not a "
                      "file of the project" % rel)
    if not os.path.isfile(target):
        return None, "%s is not a file under %s" % (rel, real_root)
    return target, None


def tree_lines(path, upto):
    """(lines, problem): the first `upto` lines of a project file, decoded.

    Bounded per line and in total, as every read here is: an oversize line is
    a problem, never a line quoted in half.
    """
    lines, total = [], 0
    try:
        with open(path, "rb") as fh:
            while len(lines) < upto:
                chunk = fh.readline(MAX_LINE_BYTES + 1)
                if not chunk:
                    break
                total += len(chunk)
                if len(chunk) > MAX_LINE_BYTES or total > MAX_TREE_BYTES:
                    return None, ("%s is past this tool's read limit by line %d, and "
                                  "was not read further" % (path, len(lines) + 1))
                lines.append(chunk.decode("utf-8", "replace").rstrip("\r\n"))
    except OSError as exc:
        return None, "%s could not be read (%s)" % (path, exc)
    return lines, None


def path_facts(candidate, function):
    """What the path and stage 1 say about test and generated code.

    The path is the file the decision labels - the candidate's, which is the
    snapshot's `file` and the body the export trains on - and nothing else.
    The finding's primary_location was a second path once: a validator
    pointing it at tests/fixtures/ made a person's FP-TEST on src/parse.c
    pass here, and `check`, which has only the snapshot's file, then reported
    the same decision as having no override. And a src/ body is not test code
    because a harness is where its bug was shown. Stage 1's own verdicts
    count too: `in_test_tree`, on the terms the findings gate takes it from a
    validator (test_tree_basis()), which turn on how stage 3 says the file got
    there (`path_class_basis`), and `generated_file` its generated-code markers.
    """
    path = candidate.get("file") or function.get("file")
    exposure = candidate.get("exposure") if isinstance(candidate.get("exposure"),
                                                       dict) else {}
    basis = exposure.get("path_class_basis")
    return {
        "paths": [path] if isinstance(path, str) and path else [],
        "in_test_tree": bool(candidate.get("in_test_tree")
                             or function.get("in_test_tree")),
        "path_class_basis": basis if isinstance(basis, str) else None,
        "generated_file": bool(candidate.get("generated_file")
                               or function.get("generated_file")),
    }


def stage1_test_file(path):
    """Stage 1's own verdict on a path, from its test-tree rules alone, or
    None when extract_functions will not load.

    For a decision written before the snapshot carried `in_test_tree`, whose
    function this run's extract no longer holds. Without it `check` read
    in_test_tree as false and told the reviewer that stage 1 had not placed
    pkg/server/conn_test.go in a test tree, which stage 1 does by its
    `_test.` rule. The operator's test_tree_globs cannot be read back for such
    a line, so none are applied, and path_problem() says so.
    """
    tool = _sibling("extract_functions")
    if tool is None or not isinstance(path, str) or not path:
        return None
    return bool(tool.in_test_tree(path.replace("/", os.sep), ()))


def recorded_basis(path, in_test_tree):
    """The path_class_basis that a snapshot written before it carried one
    stands for: stage 1's own names (`in-test-tree`) where its rules alone
    place the file in the test tree, the operator's globs where only they
    could have, None where neither can be said.

    The snapshot is all a ledger line keeps once its run directory is gone,
    and asked with no basis at all the findings gate reads a record from
    before path_class_basis as bearing nothing out - which would report every
    older FP-TEST the operator's globs had put under the test tree.
    """
    if not in_test_tree:
        return None
    own = stage1_test_file(path)
    if own is None:
        return None
    return "in-test-tree" if own else "test-tree-globs"


def test_tree_basis(path, facts):
    """(basis, None) when FP-TEST on `path` is borne out as the findings gate
    bears out a validator's, (None, None) when it is not, and (None, why) when
    the gate would not load, where the contract's own path list alone decides.

    The answer is verify_findings.fp_test_basis's, asked of a record built from
    the facts - never a copy of its rule, which is the gate's to move: a copy
    here went on taking every in_test_tree after the gate stopped taking stage
    1's own test names, so a person's FP-TEST on providers/fips/self_test.c,
    which the FIPS provider compiles and stage 1's `_test.` rule calls test
    code, was recorded where a validator's is disqualifier_contradicted. One
    file, one answer, for a person and a validator; where the two part is in
    what the gate does with the answer (queue_reasons), not in the answer.
    """
    gate = _sibling("verify_findings")
    if gate is None or not hasattr(gate, "fp_test_basis"):
        if isinstance(path, str) and TEST_PATH.search(path):
            return "test-path", None
        return None, ("verify_findings.py would not load, so stage 1's in_test_tree "
                      "could not be weighed as the findings gate weighs a validator's")
    record = {"file": path, "in_test_tree": bool(facts.get("in_test_tree")),
              "exposure": {"path_class_basis": facts.get("path_class_basis")}}
    return gate.fp_test_basis(path, record) or None, None


# How stage 3's path_class_basis says a file got into stage 1's test tree, in
# the words a refusal uses.
BASIS_WORDS = {
    "in-test-tree": "by stage 1's own test names alone (a test directory name or its "
                    "test file-name pattern)",
    "segment": "by a directory segment stage 3 classes as test or sample code",
    "test-tree-globs": "by the scope manifest's test_tree_globs",
}


def path_problem(code, root, facts):
    """None when the path facts bear out FP-TEST or FP-GENERATED, else why not."""
    paths = facts.get("paths") or []
    named = " or ".join(paths) or "no path the records name"
    if code == "FP-TEST":
        why_not = None
        for path in paths:
            basis, why_not = test_tree_basis(path, facts)
            if basis:
                return None
        unrecorded = facts.get("in_test_tree_unrecorded")
        in_tree = facts.get("in_test_tree")
        if why_not:
            placed = why_not
        elif unrecorded == "rules" and not in_tree:
            placed = ("stage 1's own test-tree rules do not place it in one either "
                      "(this decision predates the snapshot's in_test_tree and its "
                      "function is not in this run's extract, so a test_tree_globs "
                      "declaration of that run cannot be read back)")
        elif unrecorded and not in_tree:
            placed = ("whether stage 1 placed it in a test tree is not recorded: this "
                      "decision predates the snapshot's in_test_tree, its function is "
                      "not in this run's extract, and extract_functions.py would not "
                      "load to apply stage 1's rules")
        elif in_tree:
            placed = ("stage 1 placed it in its test tree %s, which verify_findings' "
                      "fp_test_basis does not take as bearing FP-TEST out for a "
                      "validator either (Validator Contract §8's FP-TEST row)"
                      % BASIS_WORDS.get(facts.get("path_class_basis"),
                                        "on a record that does not say how (no "
                                        "path_class_basis)"))
        else:
            placed = ("stage 1 did not place it in a test tree (in_test_tree false; "
                      "the scope manifest's test_tree_globs is where a harness "
                      "elsewhere is declared)")
        return ("FP-TEST says this is test code, but %s is under none of tests/, "
                "fuzz/, bench/, examples/ or third_party/*/test (Validator Contract "
                "§8, verify_findings' TEST_PATH), and %s" % (named, placed))
    if code == "FP-GENERATED":
        if facts.get("generated_file") or any(GENERATED_NAME.search(p) for p in paths):
            return None
        for path in paths:
            where, _ = tree_file(root, path)
            head, _ = tree_lines(where, GENERATED_HEAD_LINES) if where else (None, None)
            if head and any(GENERATED_MARK.search(line) for line in head):
                return None
        return ("FP-GENERATED says this is generated code, but %s matches no "
                "generated name (Validator Contract §8, verify_findings' "
                "GENERATED_NAME), stage 1 did not mark it generated_file, and its "
                "first %d lines carry no generated marker" % (named, GENERATED_HEAD_LINES))
    return None


def validate_scope_code(code):
    """The out-of-scope decision names what puts the defect out of scope."""
    code = (code or "").strip().upper()
    if not code:
        raise LedgerError("--scope-code is required for out-of-scope. One of: %s"
                          % ", ".join(SCOPE_CODES))
    if code.startswith("FP-"):
        raise LedgerError(
            "%s is a disqualifier, and every disqualifier says the finding was never "
            "real (validator-reference §7). out-of-scope says the defect is real and "
            "outside what the project defends. If it was never real, reject it; "
            "otherwise one of: %s" % (code, ", ".join(SCOPE_CODES)))
    if code not in SCOPE_CODES:
        raise LedgerError("%r is not one of contract §8's out-of-scope codes. One of: "
                          "%s" % (code, ", ".join(SCOPE_CODES)))
    return code


BASIS = re.compile(r"^(?P<file>.+):(?P<line>[1-9][0-9]*)$")


def read_basis(root, spec):
    """{file, line, text}: the line a person cites for out-of-scope, quoted.

    The text is READ from the tree, never typed: a scope call rests on a line
    of the project - a SECURITY.md threat model, a README saying what the
    directory is for, the build file that never ships it - and a reader six
    months out checks the call against that line. It is recorded as a quoted
    fact and nothing more. What the repository says decides nothing here; the
    person decided, and this is what they pointed at.
    """
    match = BASIS.match((spec or "").strip())
    if not match:
        raise LedgerError(
            "--basis is required for out-of-scope, as FILE:LINE - the line of the "
            "project the scope call rests on, e.g. SECURITY.md:12 or "
            "tools/sim/README.md:5. The tool quotes it into the record.", EXIT_USAGE)
    path, why = tree_file(root, match.group("file"))
    if path is None:
        raise LedgerError("--basis %s: %s." % (spec, why), EXIT_USAGE)
    number = int(match.group("line"))
    lines, why = tree_lines(path, number)
    if lines is None:
        raise LedgerError("--basis %s: %s." % (spec, why), EXIT_USAGE)
    if len(lines) < number:
        raise LedgerError("--basis %s: the file has %d line(s)." % (spec, len(lines)),
                          EXIT_USAGE)
    text = lines[number - 1]
    if not text.strip():
        raise LedgerError("--basis %s is a blank line, which says nothing a reader "
                          "can check." % spec, EXIT_USAGE)
    if len(text) > MAX_BASIS_CHARS:
        raise LedgerError("--basis %s is %d characters long; a basis is a line a reader "
                          "can check, and this tool quotes it whole or not at all "
                          "(limit %d)." % (spec, len(text), MAX_BASIS_CHARS), EXIT_USAGE)
    refuse_key_material(text, "the decision", flag="--basis %s" % spec)
    rel = os.path.normpath(match.group("file").strip()).replace(os.sep, "/")
    return {"file": rel, "line": number, "text": text}


def change_field(change):
    """A `changes[]` entry's field as verdict, severity or cwe, whatever prefix
    the arbiter spelled it with.

    verify_findings._change_field's reading, copied because this tool imports
    nothing from the skill for its writes; the selftest holds the two to the
    same answers. Compared exactly, a `final_cwe` entry the twin gate had
    accepted as aligning two copies never reached the ledger: one copy kept
    the validator's CWE-119 and the export wrote the twins as two samples.
    """
    field = " ".join(str(change.get("field") or "").split()).lower()
    for prefix in ("final_", "original_"):
        if field.startswith(prefix):
            field = field[len(prefix):]
    return field


def cwe_id(value):
    """`CWE-787` for any spelling of it, the first of a list, or None.

    verify_findings._cwe_number's reading, copied as change_field() is and
    held to the same answers by the selftest: the twin gate compares copies on
    it, so an arbiter's `to: "cwe-787"` aligned a copy with its twin's
    CWE-787 there, while this tool recorded the string as written and the
    export, grouping on it, wrote the two copies as two samples.
    """
    if not isinstance(value, str):
        value = json.dumps(value) if value is not None else ""
    found = re.search(r"(\d{1,5})", value)
    return "CWE-%s" % found.group(1) if found else None


def spelled_cwe(value):
    """A recorded CWE as the twin gate compares it (cwe_id()), or as written
    when it carries no CWE number at all, so nothing is recorded as null that
    somebody wrote."""
    return cwe_id(value) or (str(value) if value else None)


def adjudicated_cwe(candidate, finding, arbitration):
    """(cwe, source): the CWE the verdict was given under.

    The same precedence as the verdict: the arbiter's, then the validator's,
    then the rule's. record_decision took the candidate's first, which is the
    RULE's: MEM-WFS files every hit as the umbrella CWE-119 and the validator
    narrows it. So the Mbed TLS ledger held CWE-119 where the reviewer was
    shown CWE-787, folded a write overflow into a read overflow under one
    rule-level CWE, and kept a MEM-WFS survivor and its MEM-002 children apart.

    The arbiter's is the last `changes[]` entry on `cwe`, read as
    verify_findings.arb_final_state reads it, because the twin gate settles
    copies on that reading and the ARB schema has no CWE field of its own. A
    top-level `final_cwe` was read here and ignored there, so the gate failed
    copies the ledger had aligned; neither reads one now. Every source is
    spelled as the gate compares it (spelled_cwe()).
    """
    changed = [c.get("to") for c in (arbitration.get("changes") or [])
               if isinstance(c, dict) and change_field(c) == "cwe" and c.get("to")]
    if changed:
        return spelled_cwe(changed[-1]), "arbitration"
    if finding.get("cwe"):
        return spelled_cwe(finding["cwe"]), "finding"
    if candidate.get("cwe"):
        return spelled_cwe(candidate["cwe"]), "candidate"
    return None, None


def _offset(record):
    """The sink's line offset into the body: the one the decision recorded, or
    the one recover_offsets() read back off this run's candidate."""
    snapshot = record.get("snapshot")
    value = snapshot.get("line_offset") if isinstance(snapshot, dict) else None
    if value is None:
        value = record.get("__line_offset")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _same_sink(a, b):
    """True unless both decisions record a sink offset and the two differ.

    MEM-WFS asks about the whole function, so its offset never separates two
    decisions. A decision with no offset - written before line_offset was, and
    from a run whose candidates are gone - is paired with any sink of its rule:
    dropping it would hide a real same-sink contradiction in an old ledger, so
    the messages that rest on such a pairing say the offset was not recorded.
    """
    return (a.get("rule_id") == WFS_RULE or _offset(a) is None
            or _offset(b) is None or _offset(a) == _offset(b))


def unmeasured_sink(a, b):
    """The ids of a pair's decisions that record no sink offset, where that
    is what lets the pair count as one question; [] otherwise."""
    if a.get("rule_id") == WFS_RULE:
        return []
    return [str(r.get("decision_id")) for r in (a, b) if _offset(r) is None]


def recover_offsets(records, root):
    """Read back the sink offset of each decision of THIS run that has none.

    line_offset is newer than the ledger, and a decision without one is paired
    with any sink of its rule. So a legacy confirmation of one MEM-002 hit and
    a rejection of the other MEM-002 hit at a byte-identical copy - two
    questions - were reported as one answered two ways, and a new decision on
    either was refused. While the decision's run is the current one, its
    candidate and the extract still say where the sink is: the candidate's
    line less the function's line_start, which is what record_decision()
    stores. The value lives on the in-memory record only (load_ledger() drops
    a `__line_offset` a file carries) and is never written back.
    """
    run_id = str((load_run(root) or {}).get("run_id") or "")
    wanting = [r for r in records if run_id and _offset(r) is None
               and r.get("rule_id") != WFS_RULE
               and str(r.get("run_id") or "") == run_id]
    if not wanting:
        return
    candidates = dict((str(c["candidate_id"]), c) for c in run_candidates(root)[0])
    functions = load_functions(root)
    for record in wanting:
        candidate = candidates.get(str(record.get("candidate_id")))
        if candidate is None or identity_of(candidate) != (record.get("function_key"),
                                                           record.get("content_hash")):
            continue
        line = candidate.get("line")
        start = (functions.get(record.get("function_key")) or {}).get("line_start")
        if all(isinstance(v, int) and not isinstance(v, bool) for v in (line, start)):
            record["__line_offset"] = line - start


def same_question(a, b):
    """Two decisions on one sink of one body at one path under one rule."""
    return (bool(a.get("function_key") and a.get("content_hash"))
            and a.get("function_key") == b.get("function_key")
            and a.get("content_hash") == b.get("content_hash")
            and str(a.get("rule_id") or "") == str(b.get("rule_id") or "")
            and _same_sink(a, b))


def _candidate_line(record):
    """The candidate's line in the file, as the decision recorded it, or None."""
    snapshot = record.get("snapshot")
    value = snapshot.get("candidate_line") if isinstance(snapshot, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _measured_same_sink(a, b):
    """True when both decisions of one run measured their sink, and it is one.

    The offset into the body where both have one; otherwise the candidate's
    line, which in one run, one function_key and one content_hash is the same
    thing counted from the top of the file. Never "unmeasured, so any sink":
    that pairing is right for an old ledger's twins and wrong here, where it
    would fold two sinks of one rule in one function into one answer.
    """
    if _offset(a) is not None and _offset(b) is not None:
        return _offset(a) == _offset(b)
    return _candidate_line(a) is not None and _candidate_line(a) == _candidate_line(b)


def retires(later, earlier):
    """True when `later` answers `earlier`'s question in its place.

    Another run's decision on the same question (same_question()) does. So
    does one of the same run on another candidate id, where both measured the
    same sink: re-running stage 3 under one run_id renumbers the candidates
    (decision_key()), and a person who rejected CAND-0004 with FP-GUARDED and
    then confirmed the same sink as CAND-0009 had the export write both
    labels for one body at one path, under the two CWEs the validator picked.

    A decision with no label - needs_info, withdrawn - never retires one with
    a label. needs_info is the absence of an answer, and a later run's
    `needs-info` on the same question took the earlier run's confirmation out
    of the export and of `status`, and every twin and MERGED conflict it was
    part of out of `check`, with no answer given and nothing acknowledged.
    """
    if (DECISION_LABEL.get(later.get("decision")) is None
            and DECISION_LABEL.get(earlier.get("decision")) is not None):
        return False
    if decision_key(later) == decision_key(earlier) or not same_question(later, earlier):
        return False
    if str(later.get("run_id") or "") != str(earlier.get("run_id") or ""):
        return True
    return _measured_same_sink(later, earlier)


def current_answers(standing):
    """(current, retired): the standing decisions that answer their question
    now, oldest first, and [(earlier, later)] for each one a later decision
    retired (retires()).

    decision_key() scopes a supersede to one run, because stage 3 renumbers
    candidates every run. On its own that left an earlier run's decision
    standing forever beside the later run's answer to the same question:
    `check` went on reporting an FP-TEST on psasim the reviewer had since
    recorded out of scope, and nothing could clear it; every later decision on
    its twin was refused over it; and the export wrote both labels for one
    body whenever the two runs' adjudicated CWEs differed - a legacy line holds
    the rule's CWE-119, a new one the validator's CWE-787 - so its
    (function_key, content_hash, cwe) dedup no longer folded them. The
    question is same_question()'s, which no model's choice moves; the later
    decision (`at`, then line) is the answer, and the earlier stays in the
    trail. Within one run two candidates stay two answers unless both
    decisions measured the same sink (_measured_same_sink()): a legacy line
    records no offset, and reading that as any sink would fold two sinks of
    one run into one.
    """
    ordered = sorted(standing,
                     key=lambda r: (str(r.get("at") or ""), r.get("__line", 0)))
    groups, retired = {}, []
    for record in ordered:
        if not (record.get("function_key") and record.get("content_hash")):
            continue                     # no identity, so no question to share
        group = groups.setdefault((record.get("function_key"), record.get("content_hash"),
                                   str(record.get("rule_id") or "")), [])
        for earlier in [e for e in group if retires(record, e)]:
            group.remove(earlier)
            retired.append((earlier, record))
        group.append(record)
    gone = set(id(earlier) for earlier, _ in retired)
    return [r for r in ordered if id(r) not in gone], retired


def run_questions(root):
    """{(function_key, content_hash, rule_id): [decision]} - what a decision on
    each candidate of this run would record about its question, with the
    `confirmed` stand-in for a label, since every label retires alike.

    Whether a standing answer can be answered again decides what a person is
    told to do about it. A new decision on the candidate that asks its
    question replaces it; one on a body that changed or went away, which no
    candidate asks about any more, could only be withdrawn, and `check` told
    the reviewer to decide it again on a candidate that did not exist.
    Unreadable candidates count as none: nothing here is a count.
    """
    run_id = str((load_run(root) or {}).get("run_id") or "")
    functions = load_functions(root)
    questions = {}
    for candidate in run_candidates(root)[0]:
        key, content_hash = identity_of(candidate)
        if not (key and content_hash):
            continue
        line = candidate.get("line")
        line = line if isinstance(line, int) and not isinstance(line, bool) else None
        start = (functions.get(key) or {}).get("line_start")
        offset = (line - start if line is not None and isinstance(start, int)
                  and not isinstance(start, bool) else None)
        questions.setdefault((key, content_hash, str(candidate.get("rule_id") or "")),
                             []).append({
            "run_id": run_id, "candidate_id": str(candidate["candidate_id"]),
            "function_key": key, "content_hash": content_hash,
            "rule_id": candidate.get("rule_id"), "decision": "confirmed",
            "snapshot": {"line_offset": offset, "candidate_line": line}})
    return questions


def asked_by(record, questions):
    """The ids of this run's candidates a decision on which would supersede or
    retire `record` (run_questions()), sorted; [] when none would."""
    group = questions.get((record.get("function_key"), record.get("content_hash"),
                           str(record.get("rule_id") or "")), ())
    return sorted(pseudo["candidate_id"] for pseudo in group
                  if decision_key(pseudo) == decision_key(record)
                  or retires(pseudo, record))


def twins(a, b):
    """Two decisions asking one question of one body at two paths.

    The same content_hash (path-independent, contract §2) and rule, at another
    function_key. Where both record the sink's offset into the body, it has to
    match too - two MEM-002 hits in one function are two questions - except on
    MEM-WFS, whose question is the whole function (_same_sink()). The same
    function_key is not a twin: a later decision there is a correction, which
    supersedes in its own run and retires across runs (current_answers()).
    """
    return (bool(a.get("content_hash")) and a.get("content_hash") == b.get("content_hash")
            and a.get("function_key") != b.get("function_key")
            and str(a.get("rule_id") or "") == str(b.get("rule_id") or "")
            and _same_sink(a, b))


def disagreement(label, other):
    """What two different labels disagree about."""
    if "not_vulnerable" in (label, other):
        return "one says the defect is there, the other that it never was"
    return ("both say the defect is real, and one says it is outside the project's "
            "security scope")


def decision_conflicts(record, standing, members, run_id):
    """[(standing decision, kind)] whose label disagrees with `record`'s.

    `kind` is "merged" for a member of the arbiter's MERGED cluster in this run,
    "twin" for a byte-identical copy (twins()). A decision this one supersedes
    is a correction, not a disagreement, and so is an earlier decision on the
    same candidate in the same run; `standing` is the current answers less the
    earlier runs' decisions this one retires (current_answers(), retires()),
    which are corrections too.
    """
    label = DECISION_LABEL.get(record.get("decision"))
    if label is None:
        return []
    own, found = decision_key(record), []
    for other in standing:
        other_label = DECISION_LABEL.get(other.get("decision"))
        if other_label is None or other_label == label or decision_key(other) == own:
            continue
        same_run = str(other.get("run_id") or "") == str(run_id or "")
        other_id = str(other.get("candidate_id"))
        if same_run and other_id == str(record.get("candidate_id")):
            continue
        if same_run and other_id in members:
            found.append((other, "merged"))
        elif twins(record, other):
            found.append((other, "twin"))
    return found


def acknowledged(a, b):
    """True when either decision recorded an acknowledgement naming the other."""
    for one, other in ((a, b), (b, a)):
        ack = one.get("conflict_acknowledged")
        if isinstance(ack, dict) and other.get("decision_id") in (ack.get("decision_ids")
                                                                 or []):
            return True
    return False


def ledger_conflicts(standing, root):
    """[(a, b, kind)]: standing decisions whose labels disagree about one question.

    Worked out from the ledger itself, because it outlives the run: a decision
    records the survivor it was merged into (`snapshot.merged_into`), so the
    cluster is a group key. A decision written before that field existed is
    joined to this run's ARB records when it is this run's and its candidate
    still names the same function body - which is how `check` reads the Mbed
    TLS ledger that reported 0 problems.
    """
    current = str((load_run(root) or {}).get("run_id") or "")
    lookups = {}

    def survivor(record):
        snapshot = record.get("snapshot") if isinstance(record.get("snapshot"), dict) else {}
        own = str(record.get("candidate_id"))
        if "merged_into" in snapshot:
            return str(snapshot.get("merged_into") or own)
        if not current or str(record.get("run_id") or "") != current:
            return own
        if not lookups:
            lookups["arb"] = load_arbitrations(root)
            lookups["candidates"] = dict((str(c["candidate_id"]), c)
                                         for c in run_candidates(root)[0])
        arbitration = lookups["arb"].get(own) or {}
        candidate = lookups["candidates"].get(own)
        if (candidate is not None and arbitration.get("arbitration") == "MERGED"
                and arbitration.get("merged_into")
                and identity_of(candidate) == (record.get("function_key"),
                                               record.get("content_hash"))):
            return str(arbitration["merged_into"])
        return own

    labelled = [r for r in standing if DECISION_LABEL.get(r.get("decision"))]
    pairs = {}
    clusters, bodies = {}, {}
    for record in labelled:
        clusters.setdefault((str(record.get("run_id") or ""), survivor(record)),
                            []).append(record)
        bodies.setdefault((record.get("content_hash"), str(record.get("rule_id") or "")),
                          []).append(record)
    for kind, groups in (("merged", clusters), ("twin", bodies)):
        for group in groups.values():
            for i, a in enumerate(group):
                for b in group[i + 1:]:
                    if DECISION_LABEL[a["decision"]] == DECISION_LABEL[b["decision"]]:
                        continue
                    if kind == "twin" and not twins(a, b):
                        continue
                    if kind == "merged" and a.get("candidate_id") == b.get("candidate_id"):
                        continue
                    ids = tuple(sorted((str(a.get("decision_id")), str(b.get("decision_id")))))
                    pairs.setdefault(ids, (a, b, kind))
    return [pairs[ids] for ids in sorted(pairs)]


# --------------------------------------------------------------------------- #
# confirm / reject / needs-info / out-of-scope
# --------------------------------------------------------------------------- #

def record_decision(args, decision, bundle_root):
    root = args.root
    if not os.path.isdir(run_dir(root)):
        raise LedgerError("%s is not there. A decision is recorded against a run's "
                          "candidate and its adjudication, and there is no run here."
                          % run_dir(root), EXIT_USAGE)
    dpath = guard_write(root, decisions_path(root), "the decision trail")

    candidate_id = args.candidate
    candidate = load_candidate(root, candidate_id)
    if candidate is None:
        raise LedgerError("no candidate %s under %s. Stage 3 writes the candidate "
                          "records; nothing here invents one."
                          % (candidate_id, os.path.join(run_dir(root), "candidates")),
                          EXIT_USAGE)

    arbitration = load_arbitration(root, candidate_id)
    finding = load_finding(root, candidate_id)
    if arbitration is None and finding is None:
        # Contract §9 rule 3. A score is a ranking; only an adjudicated finding is
        # a finding. Taking a human decision on an unadjudicated candidate would
        # put this tool's output - the ledger, which outlives the run - behind a
        # judgement nobody made. Either stage 4 artefact settles it: the arbiter
        # only sees what queue.json sent it, so demanding the ARB file would
        # refuse most adjudicated findings.
        raise LedgerError(
            "%s has no adjudication: neither %s nor %s is there. Contract §9 rule "
            "3: no unadjudicated score is ever shown to a person as a finding, so "
            "no decision is recorded against one. Run stage 4 for this candidate "
            "first."
            % (candidate_id,
               os.path.join(run_dir(root), "findings", "%s.json" % candidate_id),
               os.path.join(run_dir(root), "arbitration", "ARB-%s.json" % candidate_id)),
            EXIT_UNADJUDICATED)
    if arbitration is None and candidate_id in arbitration_queued(root):
        # The finding-only case exists for the verdicts the queue never sent to
        # the arbiter. One it DID send and that has no ARB record is not that:
        # the precheck queues every VULNERABLE, NEEDS_HUMAN_REVIEW and
        # ACCEPTED_RISK, so this is a verdict still waiting for its second
        # opinion, and contract §1 counts it as an incomplete task. Taking a
        # decision on the validator's first answer here would put in the
        # ledger what export_sarif.py and the report both withhold.
        raise LedgerError(
            "%s was queued for the arbiter by %s and there is no %s: stage 4 has "
            "not finished for it (contract §1 counts it as an incomplete task). "
            "Contract §9 rule 3: nothing unadjudicated is shown to a person as a "
            "finding, so no decision is recorded against it. Run the arbiter for "
            "this candidate first."
            % (candidate_id,
               os.path.join(run_dir(root), "arbitration", "queue.json"),
               os.path.join(run_dir(root), "arbitration", "ARB-%s.json" % candidate_id)),
            EXIT_UNADJUDICATED)
    arbitration = arbitration or {}
    finding = finding or {}
    # The arbiter's verdict supersedes the validator's where there is one; this is
    # the same precedence export_sarif.py applies.
    final_verdict = arbitration.get("final_verdict") or finding.get("verdict")
    adjudicated_by = "arbitration" if arbitration else "finding"

    reason = (args.reason or "").strip()
    if decision in ("rejected", "needs_info", "out_of_scope") and not reason:
        raise LedgerError("--reason is required to %s: the ledger's whole value is "
                          "that a later run can tell why this was closed."
                          % {"rejected": "reject", "needs_info": "ask for info",
                             "out_of_scope": "record it out of scope"}[decision])
    refuse_key_material(reason, "the decision")

    # Every rule this adjudication was filed under. A MEM-WFS verdict derived
    # from the whole-function pass can sit under another rule's candidate id
    # (val-memory-safety, `derived_from`), and a finding the validator relabelled
    # answers to both rules, so the candidate's rule_id alone would refuse a
    # FP-WFS-CLEAN the verdict in front of the reviewer really is about.
    rule_ids = sorted({str(r) for r in (candidate.get("rule_id"), finding.get("rule_id"),
                                         arbitration.get("rule_id")) if r})

    reason_code = None
    if decision == "rejected":
        reason_code = validate_reason_code(getattr(args, "reason_code", None), rule_ids)
    scope_code, scope_basis = None, None
    if decision == "out_of_scope":
        scope_code = validate_scope_code(getattr(args, "scope_code", None))
        scope_basis = read_basis(root, getattr(args, "basis", None))

    key, content_hash = identity_of(candidate, arbitration, finding)
    if not (key and content_hash):
        raise LedgerError("candidate %s carries no function_key/content_hash and no "
                          "function_id to derive them from. The ledger joins on that "
                          "identity across runs and will not record a decision "
                          "without it." % candidate_id, EXIT_USAGE)

    run_json = load_run(root) or {}
    functions = load_functions(root)
    scores = load_scores(root)
    function = functions.get(key) or {}
    score = scores.get(key) or {}

    # A person's FP-TEST and FP-GENERATED are held to the path facts a
    # validator's are held to by verify_findings.py. A mismatch is refused, and
    # the refusal names the outcome that is usually meant: a real defect in code
    # the project does not defend is out of scope, not "never real".
    facts = path_facts(candidate, function)
    override = (getattr(args, "path_override", None) or "").strip()
    path_override = None
    mismatch = path_problem(reason_code, root, facts) if reason_code in PATH_CODES else None
    if mismatch and not override:
        raise LedgerError(
            "%s. verify_findings.py flags a validator's %s on this path "
            "disqualifier_contradicted, and a person's is held to the same facts. "
            "If the defect is real and the code is outside the project's security "
            "scope - test tooling, a simulator, a harness - that is not a rejection: "
            "every §8 code says the finding was never real (validator-reference §7). "
            "Record it with `ledger.py out-of-scope --candidate %s --scope-code "
            "OOS-TEST-INFRA --basis FILE:LINE --reason ...`, citing the line that "
            "puts it out of scope. If it is %s code that its path does not show, "
            "pass --path-override with why; that is recorded on the decision. "
            "Nothing was appended."
            % (mismatch, reason_code, candidate_id,
               "test" if reason_code == "FP-TEST" else "generated"))
    if mismatch:
        refuse_key_material(override, "the decision", flag="--path-override")
        path_override = dict(facts, code=reason_code, reason=override)

    cwe, cwe_source = adjudicated_cwe(candidate, finding, arbitration)
    line = candidate.get("line")
    start = function.get("line_start")
    offset = (line - start if all(isinstance(v, int) and not isinstance(v, bool)
                                  for v in (line, start)) else None)
    arbitrations = load_arbitrations(root)
    survivor, members = merged_cluster(candidate_id, arbitration, arbitrations)

    # The snapshot exists so `export` never has to describe the function as the
    # tree looks months later. The human decided about this body, under this
    # context profile, at this commit; a sample that carries a different one is a
    # label attached to code nobody judged.
    snapshot = {
        "repo": run_json.get("repo") or os.path.basename(
            os.path.abspath(run_json.get("repo_root") or root)),
        "commit": (run_json.get("git") or {}).get("commit"),
        "file": candidate.get("file") or function.get("file"),
        "language": candidate.get("language") or function.get("language"),
        "category": candidate.get("category"),
        "context_profile": score.get("context_profile")
                           or (function.get("context") or {}).get("profile"),
        "context_sha256": score.get("context_sha256")
                          or (function.get("context") or {}).get("text_sha256"),
        "localized_line": score.get("localized_line", candidate.get("line")),
        "arbitration": arbitration.get("arbitration"),
        "severity": (arbitration.get("final_severity") or arbitration.get("severity")
                     or finding.get("severity")),
        # Which stage 4 artefact carried the adjudication: `arbitration` when the
        # queue sent it to the arbiter, `finding` when the validator's verdict
        # stood. A reader six months out should not have to guess which.
        "adjudicated_by": adjudicated_by,
        # The rule ids the candidate, the finding and the ARB record carried.
        # `rule_id` above is the candidate's, and `check` reads this to accept an
        # FP-WFS-CLEAN recorded on a MEM-WFS verdict filed under another id.
        "rule_ids": rule_ids,
        # Added fields, all read with a default, so a ledger written before them
        # reads as it did. `merged_into` is the survivor the arbiter MERGED this
        # finding into, and it is what lets `check` find a cluster whose members
        # disagree after the run directory is gone. `line_offset` is the sink's
        # line into the body, which is what makes a twin's hit the same question.
        "merged_into": survivor if survivor != candidate_id else None,
        "candidate_line": line,
        "line_offset": offset,
        "in_test_tree": facts["in_test_tree"],
        # How stage 3 says the file got into the test tree, which the findings
        # gate's FP-TEST test turns on, so `check` asks it the same question
        # after the candidate record is gone.
        "path_class_basis": facts["path_class_basis"],
        "generated_file": facts["generated_file"],
        "cwe_source": cwe_source,
    }

    ledger = load_ledger(root)
    standing, _ = latest_by_candidate(ledger["decisions"])
    recover_offsets(standing.values(), root)
    current, _ = current_answers(standing.values())
    record = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": None,            # allocated under the lock by append_jsonl
        "at": stamp(now_utc()),
        "author": args.author,
        "run_id": run_json.get("run_id"),
        "candidate_id": candidate_id,
        "function_key": key,
        "content_hash": content_hash,
        "rule_id": (candidate.get("rule_id") or arbitration.get("rule_id")
                    or finding.get("rule_id")),
        # The adjudicated CWE (adjudicated_cwe), which the export deduplicates
        # and labels on; the rule's stays beside it.
        "cwe": cwe,
        "rule_cwe": candidate.get("cwe"),
        "final_verdict": final_verdict,
        "decision": decision,
        "reason_code": reason_code,
        "reason": reason or None,
        "fix_commit": getattr(args, "fix_commit", None),
        "scope_code": scope_code,
        "scope_basis": scope_basis,
        "path_override": path_override,
        "conflict_acknowledged": None,
        "tool_version": TOOL_VERSION,
        "snapshot": snapshot,
    }

    # One question, one answer. A decision whose label disagrees with a standing
    # one on a byte-identical twin or in the arbiter's MERGED cluster is refused
    # until the person says why the two differ; the Mbed TLS ledger took both
    # halves of five such contradictions without a word, and exported them.
    # An earlier run's decision on this very question is not a disagreement:
    # this one retires it, which is how a correction crosses runs.
    #
    # Nor is an earlier run's answer on a twin refused over while a candidate
    # of this run asks that twin's question: it is due to be answered again
    # here, and refusing both halves made re-deciding a pair impossible - in
    # the run after psasim's copies were recorded out of scope, confirming the
    # tf-psa-crypto copy was refused over the framework copy's old answer, and
    # confirming the framework copy over the tf-psa-crypto copy's, so the only
    # way through was an acknowledgement of a difference nobody claimed. Such
    # a decision is recorded, the twin named as still to decide, and `check`
    # reports the pair until it is.
    run_id = str(run_json.get("run_id") or "")
    retiring = [other for other in current if retires(record, other)]
    conflicts = decision_conflicts(
        record, [other for other in current if not retires(record, other)], members,
        run_json.get("run_id"))
    earlier = [other for other, kind in conflicts
               if kind == "twin" and str(other.get("run_id") or "") != run_id]
    questions = run_questions(root) if earlier else {}
    askers = dict((id(other), asked_by(other, questions)) for other in earlier)
    deferred = [(other, kind) for other, kind in conflicts if askers.get(id(other))]
    blocking = [(other, kind) for other, kind in conflicts if not askers.get(id(other))]
    acknowledgement = (getattr(args, "acknowledge_conflict", None) or "").strip()
    label = DECISION_LABEL.get(decision)
    listed = "\n".join(
        "  %s  %s%s  %s  %s\n      %s; %s%s%s"
        % (other.get("decision_id"), other.get("decision"),
           (" (%s)" % (other.get("reason_code") or other.get("scope_code"))
            if other.get("reason_code") or other.get("scope_code") else ""),
           other.get("candidate_id"), other.get("function_key"),
           ("the same body (%s) and rule %s at another path"
            % (content_hash, record["rule_id"])) if kind == "twin" else
           ("%s is the survivor the arbiter MERGED this one into" % survivor
            if other.get("candidate_id") == survivor else
            "the arbiter MERGED %s into this one" % other.get("candidate_id")
            if survivor == candidate_id else
            "the arbiter MERGED both into %s" % survivor),
           disagreement(label, DECISION_LABEL[other["decision"]]),
           ("\n      %s, so the two may be different sinks of the body"
            % ("%s records no sink offset (written before line_offset)"
               % other.get("decision_id") if _offset(other) is None else
               "this candidate's sink offset is unknown (no line, or no line_start "
               "in the extract)"))
           if kind == "twin" and unmeasured_sink(record, other) else "",
           ("\n      run %s's answer, and no candidate of this run asks its question, "
            "so no decision here replaces it: `ledger.py withdraw --decision %s` "
            "if it no longer stands" % (other.get("run_id") or "unrecorded",
                                         other.get("decision_id")))
           if str(other.get("run_id") or "") != run_id else "")
        for other, kind in blocking)
    if blocking and not acknowledgement:
        raise LedgerError(
            "%s as %s disagrees with %d standing decision(s) on the same question:\n"
            "%s\n"
            "A byte-identical copy asks the same rule's question of the same body, "
            "and a MERGED cluster is one root cause; the training export leaves out "
            "every body labelled both ways. Decide it the way the standing decision "
            "did, or first replace the standing one: a new decision on that "
            "function's candidate in this run supersedes this run's, and `ledger.py "
            "withdraw` takes out an earlier run's answer no candidate of this run "
            "asks again. If the two really differ - a copy under tests/ that is out "
            "of scope while the shipped one is not - pass --acknowledge-conflict "
            "with why; it is recorded with the ids it acknowledges. Nothing was "
            "appended."
            % (candidate_id, decision, len(blocking), listed))
    if conflicts and acknowledgement:
        refuse_key_material(acknowledgement, "the decision",
                            flag="--acknowledge-conflict")
        record["conflict_acknowledged"] = {
            "decision_ids": sorted(str(other.get("decision_id")) for other, _ in conflicts),
            "reason": acknowledgement}

    record = append_jsonl(dpath, record, allocate=("decision_id", "DEC"))
    warn_gitignore(root)

    previous = standing.get(decision_key(record))
    print("%s  %s  %s" % (record["decision_id"], decision, candidate_id))
    print("  %s  %s" % (key, content_hash))
    rule_cwe = record["rule_cwe"]
    print("  %s / %s%s, adjudicated %s (from the %s record)"
          % (record["rule_id"], record["cwe"],
             (" (the %s's; the rule's is %s)" % (cwe_source, rule_cwe)
              if rule_cwe and rule_cwe != record["cwe"] else ""),
             record["final_verdict"], adjudicated_by))
    if reason_code:
        print("  reason code: %s" % reason_code)
    if path_override:
        print("  --path-override recorded: %s held on %s, which no path fact shows - %s"
              % (reason_code, " or ".join(facts["paths"]), override))
    elif override:
        print("  --path-override was not recorded: the path facts bear %s out, or it "
              "is not a path code" % (reason_code or "no reason code"))
    if scope_code:
        print("  scope: %s, on %s:%d: %s" % (scope_code, scope_basis["file"],
                                            scope_basis["line"],
                                            _clip(scope_basis["text"], 70)))
    if survivor != candidate_id:
        print("  merged by the arbiter into %s" % survivor)
    if record["conflict_acknowledged"]:
        print("  disagrees with %s - acknowledged, and recorded with the reason given"
              % ", ".join(record["conflict_acknowledged"]["decision_ids"]))
    elif acknowledgement:
        print("  --acknowledge-conflict was not recorded: no standing decision "
              "disagrees with this one")
    else:
        for other, _ in deferred:
            print("  disagrees with %s (%s %s, run %s) on the copy at %s, which %s "
                  "asks again in this run: decide it there too, or `ledger.py check` "
                  "reports the pair"
                  % (other.get("decision_id"), other.get("decision"),
                     other.get("candidate_id"), other.get("run_id") or "unrecorded",
                     other.get("function_key"), " or ".join(askers[id(other)])))
    if previous is not None:
        print("  supersedes %s (%s, %s) - the earlier line stays in the trail"
              % (previous.get("decision_id"), previous.get("decision"),
                 previous.get("at")))
    for other in retiring:
        if str(other.get("run_id") or "") == run_id:
            print("  retires %s (%s %s) - this run's answer to the same sink, under "
                  "the id stage 3 gave the candidate before it renumbered; the earlier "
                  "line stays in the trail"
                  % (other.get("decision_id"), other.get("decision"),
                     other.get("candidate_id")))
        else:
            print("  retires %s (%s %s, run %s) - an earlier run's answer to the same "
                  "question; the earlier line stays in the trail"
                  % (other.get("decision_id"), other.get("decision"),
                     other.get("candidate_id"), other.get("run_id") or "unrecorded"))
    return EXIT_OK


def validate_reason_code(code, rule_ids=()):
    """Contract §8: a rejection names a disqualifier or it is not recorded.

    `rule_ids` is every rule the adjudication was filed under; it decides only
    FP-WFS-CLEAN, the one code §8 restricts to a single rule.
    """
    code = (code or "").strip().upper()
    if not code:
        raise LedgerError(
            "--reason-code is required to reject. A rejection that cannot name a "
            "disqualifier is one nobody can learn from and the training export "
            "will not take it. One of: %s" % ", ".join(DISQUALIFIER_CODES))
    if code == ACCEPTED_RISK_CODE:
        raise LedgerError(
            "%s is not a rejection. Validator Contract §7: every §8 code says the "
            "finding was never real, and ACCEPTED_RISK says the opposite - the "
            "defect is real and the codebase knowingly carries it. Confirm it and "
            "say so in --reason, or pick the disqualifier that is actually true."
            % ACCEPTED_RISK_CODE)
    if code in SCOPE_CODES:
        raise LedgerError(
            "%s is not a rejection: it says the defect is real and outside the "
            "project's security scope, and a rejection says it was never real. "
            "Record it with `ledger.py out-of-scope --scope-code %s --basis "
            "FILE:LINE`." % (code, code))
    if code not in DISQUALIFIER_CODES:
        raise LedgerError("%r is not one of the Validator Contract's §8 "
                          "disqualifiers. One of: %s"
                          % (code, ", ".join(DISQUALIFIER_CODES)))
    if code == WFS_CLEAN_CODE and WFS_RULE not in rule_ids:
        raise LedgerError(
            "%s closes a %s whole-function sweep and nothing else; this candidate's "
            "adjudication is filed under %s. Pick the disqualifier that is true of "
            "this rule." % (code, WFS_RULE, ", ".join(rule_ids) or "no rule id"))
    return code


# --------------------------------------------------------------------------- #
# suppress / revoke
# --------------------------------------------------------------------------- #

def cmd_withdraw(args, bundle_root):
    """Take a standing answer that nothing can answer again out of the current
    answers, by appending a `withdrawn` line on its own key.

    An answer is corrected by deciding its question again (retires()). A
    question no candidate of this run asks cannot be: the Mbed TLS ledger's
    FP-TEST on psasim's psa_wait, carried into a run where that body had been
    edited, was reported by `check` in every session after every psasim
    candidate was recorded out of scope, as the problem itself advised,
    because the new body is another question; and nothing else could reach
    it. The withdrawal carries the withdrawn decision's run, candidate and
    body (decision_key()), so it supersedes that line exactly as a correction
    in its run would, with no label: the export leaves it out, as it leaves
    out needs_info, and a later run that asks the question again retires it
    with an answer. Refused on an answer that a candidate of this run asks
    again - decide that, which gives the question an answer instead of none -
    and on one already superseded, retired or withdrawn.
    """
    root = args.root
    if not os.path.isdir(run_dir(root)):
        raise LedgerError("%s is not there. A withdrawal is refused while a candidate "
                          "of the current run could answer the question again, and "
                          "there is no run here to ask." % run_dir(root), EXIT_USAGE)
    dpath = guard_write(root, decisions_path(root), "the decision trail")
    reason = (args.reason or "").strip()
    if not reason:
        raise LedgerError("--reason is required to withdraw a decision: the ledger's "
                          "whole value is that a later run can tell why an answer "
                          "stopped standing.")
    refuse_key_material(reason, "the withdrawal")
    _, problems = run_candidates(root)
    if problems:
        raise LedgerError("%s. Without this run's candidates nothing says whether one "
                          "asks the question again, which is when a decision is "
                          "answered rather than withdrawn. Nothing was appended."
                          % "; ".join(problems), EXIT_USAGE)

    ledger = load_ledger(root)
    target = [r for r in ledger["decisions"] if r.get("decision_id") == args.decision]
    if not target:
        raise LedgerError("no decision %s in %s." % (args.decision, dpath), EXIT_USAGE)
    target = target[-1]
    standing, _ = latest_by_candidate(ledger["decisions"])
    recover_offsets(standing.values(), root)
    current, retired = current_answers(standing.values())
    if target.get("decision") == WITHDRAWN:
        raise LedgerError("%s is itself a withdrawal (of %s); there is no answer in it "
                          "to withdraw. Nothing was appended."
                          % (args.decision, target.get("withdraws")))
    if not any(r is target for r in current):
        later = standing.get(decision_key(target))
        later = later if later is not None and later is not target else next(
            (b for a, b in retired if a is target), None)
        raise LedgerError(
            "%s is not a current answer: %s replaced it. Nothing was appended."
            % (args.decision, "%s (%s)" % (later.get("decision_id"), later.get("decision"))
               if later is not None else "a later line"))
    askers = asked_by(target, run_questions(root))
    if askers:
        raise LedgerError(
            "%s asks %s's question again in this run (the same body, rule and sink), "
            "so decide it there - `ledger.py confirm / reject / out-of-scope / "
            "needs-info --candidate %s` - which supersedes or retires %s with an "
            "answer rather than none. Nothing was appended."
            % (" and ".join(askers), args.decision, askers[0], args.decision))

    run_json = load_run(root) or {}
    record = {
        "schema_version": SCHEMA_VERSION,
        "decision_id": None,            # allocated under the lock by append_jsonl
        "at": stamp(now_utc()),
        "author": args.author,
        # The withdrawn decision's own key (decision_key()), so this line
        # supersedes it in its run as a correction there would.
        "run_id": target.get("run_id"),
        "candidate_id": target.get("candidate_id"),
        "function_key": target.get("function_key"),
        "content_hash": target.get("content_hash"),
        "rule_id": target.get("rule_id"),
        "cwe": target.get("cwe"),
        "rule_cwe": target.get("rule_cwe"),
        "final_verdict": target.get("final_verdict"),
        "decision": WITHDRAWN,
        "reason_code": None,
        "reason": reason,
        "fix_commit": None,
        "scope_code": None,
        "scope_basis": None,
        "path_override": None,
        "conflict_acknowledged": None,
        "withdraws": target.get("decision_id"),
        "withdrawn_in_run": run_json.get("run_id"),
        "tool_version": TOOL_VERSION,
        "snapshot": target.get("snapshot") if isinstance(target.get("snapshot"),
                                                         dict) else {},
    }
    record = append_jsonl(dpath, record, allocate=("decision_id", "DEC"))
    warn_gitignore(root)
    print("%s  withdrawn  %s" % (record["decision_id"], target.get("decision_id")))
    print("  %s  %s  %s" % (target.get("function_key"), target.get("content_hash"),
                            target.get("rule_id")))
    print("  supersedes %s (%s %s, run %s): no candidate of run %s asks its question. "
          "It leaves the current answers and the export; the line stays in the trail, "
          "and a later decision on the question retires this one"
          % (target.get("decision_id"), target.get("decision"),
             target.get("candidate_id"), target.get("run_id") or "unrecorded",
             run_json.get("run_id") or "(no run_id)"))
    return EXIT_OK


def cmd_suppress(args, bundle_root):
    root = args.root
    spath = guard_write(root, suppressions_path(root), "the suppression ledger")
    key = args.function_key
    if not FUNCTION_KEY.match(key or ""):
        raise LedgerError("%r is not a function_key. Contract §2 shapes it "
                          "<rel_path>::<name>::<ordinal>, e.g. src/a.c::f::0."
                          % key, EXIT_USAGE)
    rule = (args.rule or "").strip().upper()
    if not RULE_ID.match(rule):
        raise LedgerError("%r is not a rule id. A suppression naming a rule that "
                          "cannot exist suppresses nothing and reads like one that "
                          "works." % args.rule, EXIT_USAGE)
    if rule == WFS_RULE:
        # The same trap one level up: a record stage 3 will not apply, written
        # with exit 0 and read in the ledger exactly like one that works.
        raise LedgerError(
            "%s is not suppressed on its own. It is the whole-function pass, and "
            "its candidates are derived from the function's other candidates: "
            "stage 3 suppresses it when every other candidate on the function is "
            "suppressed, and ignores a record naming it while any of them still "
            "dispatches (queue.json lists that record under "
            "`suppressions_ignored`). Suppress the function's other rules "
            "instead." % WFS_RULE, EXIT_USAGE)
    reason = (args.reason or "").strip()
    if not reason:
        raise LedgerError("--reason is required: a suppression with no reason is "
                          "the thing somebody has to reconstruct in six months.")
    refuse_key_material(reason, "the suppression")

    # Rule 1. Refused in code rather than by argparse so the message can say why
    # rather than printing a usage line.
    if not args.expires:
        raise LedgerError(
            "--expires is required. Contract §8 rule 1: there is no permanent "
            "suppression, because an indefinite one is a decision nobody "
            "revisits. Give it a date you are willing to be asked about.")

    moment = now_utc()
    expires = require_time(args.expires, "--expires")
    if expires <= moment:
        raise LedgerError("--expires %s is not in the future. A suppression born "
                          "expired suppresses nothing; it is a typo with a paper "
                          "trail." % args.expires, EXIT_USAGE)

    # Rule 2.
    days = (expires - moment).total_seconds() / 86400.0
    if days > args.max_expiry_days and not args.force:
        raise LedgerError(
            "--expires %s is %d days out and --max-expiry-days is %d. Contract §8 "
            "rule 2: pick a nearer date, or pass --force, which records "
            "forced: true on the record so `status` shows it and nobody has to "
            "reconstruct that the long expiry was deliberate."
            % (args.expires, int(round(days)), args.max_expiry_days))

    # Rule 3's half that happens at creation: the hash is MEASURED from this
    # run's extract, never asserted on the command line. There is no --content-hash
    # flag, because one would turn rule 3 into a convention.
    corpus = load_corpus(root)
    hashes = corpus["hashes"]
    if hashes is None:
        raise LedgerError(
            "%s is not there, so this run has not measured the function's content "
            "hash. A suppression records the hash it was created against - that "
            "record is what makes contract §8 rule 3 work - so run stage 1 first."
            % os.path.join(run_dir(root), "extract", "functions.jsonl"), EXIT_USAGE)
    if key not in hashes and not corpus["complete"]:
        raise LedgerError(
            "%s is not among the %d function(s) read from %s, but %d line(s) of "
            "that file could not be read, so this is not evidence the corpus does "
            "not hold it. Fix the extract and run this again.\n  %s"
            % (key, len(hashes), corpus["path"], len(corpus["problems"]),
               "\n  ".join("line %s: %s" % (n, d)
                           for _, n, d in corpus["problems"][:5])), EXIT_USAGE)
    if key not in hashes:
        raise LedgerError("%s is not in this run's extract. Suppressing a function "
                          "the corpus does not hold would be stale the moment it "
                          "was written." % key, EXIT_USAGE)
    content_hash = hashes[key]
    if not CONTENT_HASH.match(str(content_hash or "")):
        # Rule 3 compares this value on every later run. A null or malformed one
        # compares unequal to everything, so the suppression would be born stale
        # and read, in the trail, like one that simply stopped applying.
        raise LedgerError(
            "%s carries content_hash %r in %s, and contract §2 shapes it as "
            "sha256(normalised_body)[:16]. A suppression recorded against that "
            "cannot ever be shown unchanged, so it would suppress nothing while "
            "looking like it does. Re-run stage 1."
            % (key, content_hash, corpus["path"]), EXIT_USAGE)

    ledger = load_ledger(root)
    existing = [s for s in resolve_suppressions(ledger, corpus, moment)
                if s["function_key"] == key and s["rule_id"] == rule
                and s["state"] == "active"]

    record = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "suppression",
        "suppression_id": None,         # allocated under the lock by append_jsonl
        "created_at": stamp(moment),
        "author": args.author,
        "function_key": key,
        "rule_id": rule,
        "content_hash_at_creation": content_hash,
        "reason": reason,
        "expires_at": stamp(expires),
        "revoked_at": None,
        "forced": bool(args.force and days > args.max_expiry_days),
        # Recorded so `check` can prove after the fact that a long expiry was
        # forced deliberately. Without it, a hand-edited `forced: false` on a
        # five-year expiry reads exactly like a normal record.
        "max_expiry_days": args.max_expiry_days,
        "run_id": (load_run(root) or {}).get("run_id"),
        "tool_version": TOOL_VERSION,
    }
    record = append_jsonl(spath, record, allocate=("suppression_id", "SUP"))
    warn_gitignore(root)

    print("%s  %s  %s" % (record["suppression_id"], key, rule))
    print("  created against %s, expires %s (%d days)"
          % (content_hash, record["expires_at"], int(round(days))))
    if record["forced"]:
        print("  forced: %d days exceeds --max-expiry-days %d"
              % (int(round(days)), args.max_expiry_days))
    for previous in existing:
        print("  note: %s already suppresses this function for %s until %s"
              % (previous["suppression_id"], rule, previous["expires_at"]))
    print("  §8 rule 4: this function is still extracted, still scored and still "
          "counted. Suppression only removes it from the dispatch queue.")
    return EXIT_OK


def cmd_revoke(args, bundle_root):
    root = args.root
    spath = guard_write(root, suppressions_path(root), "the suppression ledger")
    ledger = load_ledger(root)
    target = args.suppression
    known = dict((r.get("suppression_id"), r) for r in ledger["suppressions"])
    if target not in known:
        raise LedgerError("no suppression %s in %s" % (target, suppressions_path(root)),
                          EXIT_USAGE)
    if known[target].get("revoked_at"):
        raise LedgerError(
            "%s already carries revoked_at %s on its own line (by %s). It is "
            "already out of the dispatch queue; a second revocation would put two "
            "endings in the trail for one decision."
            % (target, known[target].get("revoked_at"),
               known[target].get("revoked_by") or "an unrecorded author"))
    already = [r for r in ledger["revocations"] if r.get("suppression_id") == target]
    if already:
        # The line still says revoked_at: null (the test above), so this is a
        # revoke that stopped between its two writes - and `check` sends a
        # person here to finish it. Refusing it as a second revocation left
        # nothing that could.
        return finish_revoke(args, spath, known[target], already[0])
    reason = (args.reason or "").strip()
    if not reason:
        raise LedgerError("--reason is required to revoke: the revocation is the "
                          "half of the record that says what changed.")
    refuse_key_material(reason, "the revocation")

    # Two writes, in this order. The revocation record goes down first: it is the
    # trail, it says who ended this and why, and the suppression's own line keeps
    # saying what was decided on the day it was decided - and it is what stage 3
    # and the SARIF export need to stop honouring the suppression. Then
    # `revoked_at` is filled in on that line, because that is the field contract
    # §8 puts on the record. If the second write fails, `check` names the line
    # that still says null, and running this again finishes it
    # (finish_revoke).
    #
    # Both inside ONE hold of the ledger lock. The second write is a
    # read-rewrite-rename, and without the lock a `suppress` appending inside
    # that window was erased by the rename, both commands exiting 0.
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "revocation",
        "suppression_id": target,
        "revoked_at": stamp(now_utc()),
        "author": args.author,
        "reason": reason,
        "tool_version": TOOL_VERSION,
    }
    with ledger_lock(os.path.dirname(spath)):
        # The checks above read the file without the lock, so two revokes of one
        # suppression could both pass them. Under it, the second one cannot.
        rows, _ = read_jsonl(spath)
        for row in rows:
            if row.get("suppression_id") != target:
                continue
            if row.get("record_type") == "revocation" or row.get("revoked_at"):
                raise LedgerError(
                    "%s was revoked by another writer while this one waited for "
                    "the ledger lock. Revoking twice would put two endings in the "
                    "trail for one decision." % target)
        _append_locked(spath, record)
        stamped = stamp_revocation(spath, target, record)
    original = known[target]
    print("revoked %s (%s, %s) at %s"
          % (target, original.get("function_key"), original.get("rule_id"),
             record["revoked_at"]))
    print("  appended as a revocation record; line %s keeps every field it was "
          "written with" % original.get("__line"))
    print("  and revoked_at is now set on it, where contract §8 puts it; stage 3 "
          "and the SARIF export\n  honour either half, and the candidate comes back "
          "into the dispatch queue on the next run")
    if stamped != 1:
        print("  WARNING: %d line(s) carried suppression_id %s, so the revocation "
              "may not have landed where you meant it to. Run `ledger.py check`."
              % (stamped, target))
    warn_gitignore(root)
    return EXIT_OK


def finish_revoke(args, spath, original, revocation):
    """The second write of a revoke that stopped after its first.

    The revocation line is down and the suppression's own line still says
    `revoked_at: null`: `check` reports exactly that and says to run the
    revoke again, and the revoke used to refuse it as a second revocation, so
    the one command the message named could not do what it said. Nothing is
    appended - one decision gets one ending - and the field is filled from the
    revocation already recorded: its time, its author and its reason, never
    this invocation's. A revocation missing one of those has nothing to fill
    the field from, and is refused for a person to repair by hand.
    """
    target = original.get("suppression_id")
    missing = [field for field in ("revoked_at", "author", "reason")
               if not isinstance(revocation.get(field), str)
               or not revocation.get(field).strip()]
    if not missing and parse_time(revocation.get("revoked_at")) is None:
        missing = ["a revoked_at that parses"]
    if missing:
        raise LedgerError(
            "%s is revoked by line %s, and its own line %s still carries "
            "revoked_at: null - but that revocation has no %s, so there is "
            "nothing to fill the field from. Repair the revocation line by hand; "
            "`ledger.py check` names what it lacks."
            % (target, revocation.get("__line"), original.get("__line"),
               " or ".join(missing)))
    # The recorded reason is copied onto the suppression's line as
    # revoked_reason, and a copy is a second place a credential would sit.
    refuse_key_material(revocation["reason"], "the revocation")
    with ledger_lock(os.path.dirname(spath)):
        rows, _ = read_jsonl(spath)
        if any(row.get("record_type", "suppression") == "suppression"
               and row.get("suppression_id") == target and row.get("revoked_at")
               for row in rows):
            raise LedgerError(
                "%s had revoked_at filled in by another writer while this one "
                "waited for the ledger lock; there is nothing left to finish."
                % target)
        stamped = stamp_revocation(spath, target, revocation)
    print("finished revoking %s (%s, %s): revoked_at %s, by %s, filled in on line %s "
          "from the revocation at line %s"
          % (target, original.get("function_key"), original.get("rule_id"),
             revocation["revoked_at"], revocation["author"], original.get("__line"),
             revocation.get("__line")))
    print("  nothing was appended: one decision gets one ending")
    if (args.reason or "").strip():
        print("  --reason was not recorded; the revocation already says why: %s"
              % revocation["reason"])
    if stamped != 1:
        print("  WARNING: %d line(s) carried suppression_id %s, so the revocation "
              "may not have landed where you meant it to. Run `ledger.py check`."
              % (stamped, target))
    warn_gitignore(args.root)
    return EXIT_OK


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #

def horizon_of(days_left):
    for limit, label in HORIZONS:
        if limit is None or days_left <= limit:
            return label
    return HORIZONS[-1][1]


def cmd_status(args, bundle_root):
    root = args.root
    moment = now_utc()
    ledger = load_ledger(root)
    corpus = load_corpus(root)
    hashes = corpus["hashes"]
    run_json = load_run(root) or {}
    states = resolve_suppressions(ledger, corpus, moment)
    standing, superseded = latest_by_candidate(ledger["decisions"])
    recover_offsets(standing.values(), root)
    # What stands is each question's current answer: a decision a later run
    # re-decided is counted with the superseded, not beside its correction,
    # and so is one of this run re-decided on a renumbered candidate - counted
    # apart, since `retired_by_later_run` has said "another run" all along.
    current, retired = current_answers(standing.values())
    renumbered = [(a, b) for a, b in retired
                  if str(a.get("run_id") or "") == str(b.get("run_id") or "")]

    by_state = {}
    for state in states:
        by_state.setdefault(state["state"], []).append(state)

    counts = dict((name, 0) for name in DECISIONS)
    codes, scopes = {}, {}
    for record in current:
        decision = record.get("decision")
        counts[decision] = counts.get(decision, 0) + 1
        if decision == "rejected":
            code = record.get("reason_code") or "(none)"
            codes[code] = codes.get(code, 0) + 1
        if decision == "out_of_scope":
            code = record.get("scope_code") or "(none)"
            scopes[code] = scopes.get(code, 0) + 1
    # Standing decisions that answer one question two ways and that nobody
    # acknowledged. `check` names every pair; status counts them, so a session
    # opening on a contradicted ledger hears about it before the first finding.
    unacknowledged = [pair for pair in ledger_conflicts(current, root)
                      if not acknowledged(pair[0], pair[1])]
    # A hand-edited decision value is not one of the three, and the three lines
    # printed below would then sum to less than the standing total sitting right
    # above them. A count that disagrees with what produced it is the specific
    # failure this pipeline was built after, so it is named rather than dropped.
    unknown = dict((name, number) for name, number in counts.items()
                   if name not in DECISIONS)

    if args.json:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "tool": "ledger.py",
            "tool_version": TOOL_VERSION,
            "generated_at": stamp(moment),
            "ledger_dir": ledger_dir(root),
            "run_id": run_json.get("run_id"),
            "corpus_measured": hashes is not None,
            "corpus_complete": corpus["complete"],
            "corpus_functions": None if hashes is None else len(hashes),
            "corpus_problems": [{"file": p, "line": n, "detail": d}
                                for p, n, d in corpus["problems"]],
            "suppressions": {
                "total": len(states),
                "by_state": dict((k, len(v)) for k, v in sorted(by_state.items())),
                "forced": sum(1 for s in states if s["forced"]),
                "records": states,
            },
            "decisions": {
                "total": len(ledger["decisions"]),
                "standing": len(current),
                "superseded": len(superseded) + len(retired),
                "retired_by_later_run": len(retired) - len(renumbered),
                "retired_on_renumbered_candidate": len(renumbered),
                "by_decision": counts,
                "by_reason_code": codes,
                "by_scope_code": scopes,
                "unrecognised_decisions": unknown,
                "unacknowledged_conflicts": len(unacknowledged),
            },
            "problems": [{"file": p, "line": n, "detail": d}
                         for p, n, d in ledger["problems"]],
            "suppression_is_not_exclusion": True,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return EXIT_OK

    print("LEDGER  %s" % ledger_dir(root))
    if run_json.get("run_id"):
        measured = "not measured"
        if hashes is not None:
            measured = "%d functions" % len(hashes)
            if not corpus["complete"]:
                measured += (" read, %d line(s) unreadable - the corpus is "
                             "INCOMPLETE" % len(corpus["problems"]))
        print("run %s   corpus %s" % (run_json["run_id"], measured))
    if ledger["problems"]:
        print("\n%d unreadable record(s) - run `ledger.py check`"
              % len(ledger["problems"]))
    if corpus["problems"]:
        print("\n%d unreadable line(s) in %s. Staleness is measured against that "
              "file, so nothing below is\n  called stale on the strength of a "
              "function missing from it." % (len(corpus["problems"]), corpus["path"]))

    # Stale first, and loudly. These read as suppressions and are not ones; every
    # other group in this report is working as written.
    stale = by_state.get("stale", [])
    print("\nSTALE SUPPRESSIONS - %d   (these do NOT suppress; contract §8 rule 3)"
          % len(stale))
    for state in sorted(stale, key=lambda s: s["suppression_id"] or ""):
        print(("  %-9s %-46s %-8s %s"
               % (state["suppression_id"], state["function_key"], state["rule_id"],
                  state["author"])).rstrip())
        print("            %s" % state["stale_reason"])
        print("            re-read the function and re-suppress, or let the "
              "candidate come back")

    unverified = by_state.get("unverified", [])
    if unverified:
        print("\nUNVERIFIED - %d   (staleness could not be measured, so nothing is "
              "suppressed)" % len(unverified))
        for state in sorted(unverified, key=lambda s: s["suppression_id"] or ""):
            print("  %-9s %-46s %s"
                  % (state["suppression_id"], state["function_key"], state["rule_id"]))
            if state["unverified_reason"]:
                print("            %s" % state["unverified_reason"])

    active = by_state.get("active", [])
    print("\nACTIVE SUPPRESSIONS - %d" % len(active))
    grouped = {}
    for state in active:
        grouped.setdefault(horizon_of(state["days_left"] or 0.0), []).append(state)
    for _, label in HORIZONS:
        bucket = grouped.get(label)
        if not bucket:
            continue
        print("  %s - %d" % (label, len(bucket)))
        for state in sorted(bucket, key=lambda s: s["expires_at"] or ""):
            flag = "  [forced]" if state["forced"] else ""
            if state["long_unforced"]:
                flag = "  [%d days, past the default %d, never forced]" % (
                    int(round(state["days_total"] or 0)), DEFAULT_MAX_EXPIRY_DAYS)
            if state["rule_id"] == WFS_RULE:
                # One the pre-refusal ledger wrote. Stage 3 and the SARIF
                # export apply it only when the function's other rules are
                # suppressed too, so listed bare it read as one that works.
                flag += "  [only while every other rule on it is suppressed]"
            print(("    %-9s %-11s %-42s %-8s%s"
                   % (state["suppression_id"], (state["expires_at"] or "")[:10],
                      state["function_key"], state["rule_id"], flag)).rstrip())
            print("              %s - %s" % (state["author"], _clip(state["reason"], 60)))

    for name, title in (("expired", "EXPIRED"), ("revoked", "REVOKED")):
        bucket = by_state.get(name, [])
        if not bucket:
            continue
        print("\n%s - %d   (no longer suppressing)" % (title, len(bucket)))
        for state in sorted(bucket, key=lambda s: s["suppression_id"] or ""):
            when = state["revoked_at"] if name == "revoked" else state["expires_at"]
            print("  %-9s %-11s %-42s %s"
                  % (state["suppression_id"], (when or "")[:10], state["function_key"],
                     state["rule_id"]))

    print("\nDECISIONS - %d standing (%d superseded%s%s, %d lines in the trail)"
          % (len(current), len(superseded) + len(retired),
             ", %d of them retired by a later run's decision"
             % (len(retired) - len(renumbered)) if len(retired) > len(renumbered)
             else "",
             ", %d by a decision on the same sink under a renumbered candidate id"
             % len(renumbered) if renumbered else "", len(ledger["decisions"])))
    for name in DECISIONS:
        line = "  %-12s %d" % (name, counts.get(name, 0))
        if name == "rejected" and codes:
            line += "    " + ", ".join("%s %d" % (code, number)
                                       for code, number in sorted(codes.items()))
        if name == "out_of_scope" and scopes:
            line += "    " + ", ".join("%s %d" % (code, number)
                                       for code, number in sorted(scopes.items()))
        print(line)
    if unknown:
        print("  %-12s %d    %s   <- not one of %s; these were hand-edited and "
              "`check` fails on them"
              % ("unrecognised", sum(unknown.values()),
                 ", ".join("%r %d" % (name, number)
                           for name, number in sorted(unknown.items(),
                                                      key=lambda kv: str(kv[0]))),
                 ", ".join(DECISIONS)))
    if unacknowledged:
        print("  %d pair(s) of standing decisions answer one question two ways - a "
              "byte-identical twin or a\n  MERGED cluster - and nobody acknowledged "
              "it. `ledger.py check` names them." % len(unacknowledged))

    print("\n§8 rule 4: every suppressed function above is still extracted, still "
          "scored and still counted.\n  Suppression removes a finding from the "
          "dispatch queue and from the report, never from coverage.")
    return EXIT_OK


def _clip(text, width):
    text = " ".join(str(text or "").split())
    return text if len(text) <= width else text[:width - 1] + "…"


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #

def eval_freeze(bundle_root):
    """(id, frozen_at) of the LATEST registered evaluation set, or (None, None).

    The latest is the conservative choice: `postdates_eval_freeze` is only true
    when the sample postdates every freeze, so a training run can take the true
    ones without checking which set it is measuring against.
    """
    directory = os.path.join(bundle_root, "assets", "evalsets")
    if not os.path.isdir(directory):
        return None, None
    newest_id, newest = None, None
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        document, _ = read_json(os.path.join(directory, name))
        if not isinstance(document, dict):
            continue
        frozen = parse_time(document.get("frozen_at"))
        if frozen is None:
            continue
        if newest is None or frozen > newest:
            newest, newest_id = frozen, document.get("id") or name[:-5]
    return newest_id, newest


# --------------------------------------------------------------------------- #
# pending
# --------------------------------------------------------------------------- #

# The verdicts stage 5 presents without being asked. NOT_VULNERABLE is held back
# until the reviewer asks for it: the arbiter's calibration sample, not a person,
# is what measures wrong dismissals, and on the zlib field test the session opened
# on 170 of them that nobody had asked to see.
REVIEW_SET = ("VULNERABLE", "NEEDS_HUMAN_REVIEW", "ACCEPTED_RISK")
DISMISSED = "NOT_VULNERABLE"


def run_candidates(root):
    """(records, problems): every candidate stage 3 dispatched this run, by id.

    The deferred queues are left out - a deferred candidate was never dispatched,
    so no adjudication is coming for it - and so are the coverage files, which
    hold no candidates. A file that cannot be read is a problem, never a smaller
    count.
    """
    directory = os.path.join(run_dir(root), "candidates")
    records, problems, seen = [], [], set()
    if not os.path.isdir(directory):
        return records, ["%s is not there, so there are no candidates to count"
                         % directory]
    for name in sorted(os.listdir(directory)):
        if (not name.endswith(".json") or name.startswith("coverage")
                or name.endswith("-deferred.json")):
            continue
        document, why = read_json(os.path.join(directory, name))
        if document is None:
            problems.append(why)
            continue
        for item in document if isinstance(document, list) else [document]:
            if not isinstance(item, dict) or not item.get("candidate_id"):
                continue
            candidate_id = str(item["candidate_id"])
            # First wins, as load_candidate() resolves the same id.
            if candidate_id not in seen:
                seen.add(candidate_id)
                records.append(item)
    # The derived MEM-WFS findings of this run have no candidate record: they are read
    # against their source's, after the real ones.
    by_id = dict((str(r["candidate_id"]), r) for r in records)
    for finding in derived_findings(root):
        candidate_id = str(finding.get("candidate_id"))
        record = derived_record(finding, by_id.get(str(finding.get("derived_from"))))
        if record is not None and candidate_id not in seen:
            seen.add(candidate_id)
            records.append(record)
    return records, problems


def cmd_pending(args, bundle_root):
    """What is left for a person to decide in this run, counted off the records.

    Read-only. Each candidate's verdict is taken the way record_decision() takes
    it - the ARB record's final_verdict where there is one, the finding's verdict
    otherwise - and a candidate with a standing decision for this run is already
    settled and left out of the counts. The copies of a review-set body outside
    the review set are listed beside it, though: every one already decided, in
    this run or an earlier one, and every one dismissed. Stage 5 builds each
    finding's `Twins:` line from this, and while they were left out, a copy
    decided before a resumed session or dismissed at another path was never
    shown to the person best placed to see that the two answers disagree.
    Stage 5 opens with this rather than with an agent counting hundreds of
    records by hand: a count that disagrees with what produced it is the
    failure this pipeline was built after. A candidates directory or file that
    could not be read is listed as a problem and exits EXIT_REFUSED, since
    every count printed beside it is short by what it held.
    """
    root = args.root
    if not os.path.isdir(run_dir(root)):
        raise LedgerError("%s is not there. Pending review is counted off a run's "
                          "candidates and their adjudications, and there is no run "
                          "here." % run_dir(root), EXIT_USAGE)
    run_json = load_run(root) or {}
    run_id = str(run_json.get("run_id") or "")
    candidates, problems = run_candidates(root)
    standing, _ = latest_by_candidate(load_ledger(root)["decisions"])
    decided = {str(r.get("candidate_id")) for r in standing.values()
               if str(r.get("run_id") or "") == run_id}
    recover_offsets(standing.values(), root)
    current, _ = current_answers(standing.values())
    queued = arbitration_queued(root)

    by_verdict = {}
    awaiting, unadjudicated, settled = [], [], []
    held = {"validator_only": [], "upheld": [], "overturned": [], "other": []}
    reviewed = []            # (candidate, arbitration) for every review-set item
    held_back = []           # (candidate, verdict): adjudicated, undecided, not in it
    for candidate in candidates:
        candidate_id = str(candidate["candidate_id"])
        if candidate_id in decided:
            settled.append(candidate_id)
            continue
        arbitration = load_arbitration(root, candidate_id)
        finding = load_finding(root, candidate_id)
        if arbitration is None and finding is None:
            unadjudicated.append(candidate_id)
            continue
        if arbitration is None and candidate_id in queued:
            awaiting.append(candidate_id)
            continue
        arbitration, finding = arbitration or {}, finding or {}
        verdict = str(arbitration.get("final_verdict") or finding.get("verdict")
                      or "(no verdict)")
        by_verdict[verdict] = by_verdict.get(verdict, 0) + 1
        if verdict in REVIEW_SET:
            reviewed.append((candidate, arbitration))
        else:
            held_back.append((candidate, verdict))
        if verdict != DISMISSED:
            continue
        ruling = arbitration.get("arbitration")
        if not arbitration:
            held["validator_only"].append(candidate_id)
        elif ruling in ("UPHELD", "UPHELD_MODIFIED"):
            held["upheld"].append(candidate_id)
        elif ruling == "OVERTURNED":
            held["overturned"].append({"candidate_id": candidate_id,
                                       "from": finding.get("verdict")})
        else:
            held["other"].append({"candidate_id": candidate_id,
                                  "arbitration": ruling})

    review_set = sum(by_verdict.get(v, 0) for v in REVIEW_SET)
    shape = review_set_shape(reviewed, current, held_back)
    if args.json:
        payload = {
            "schema_version": SCHEMA_VERSION,
            "tool": "ledger.py",
            "tool_version": TOOL_VERSION,
            "run_id": run_json.get("run_id"),
            "candidates": len(candidates),
            "decided_this_run": len(settled),
            "by_verdict": by_verdict,
            "review_set": review_set,
            "review_set_shape": shape,
            "not_vulnerable": {
                "total": by_verdict.get(DISMISSED, 0),
                "validator_only": len(held["validator_only"]),
                "upheld": len(held["upheld"]),
                "overturned": held["overturned"],
                "other": held["other"],
            },
            "awaiting_arbiter": awaiting,
            "unadjudicated": unadjudicated,
            "problems": problems,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return EXIT_REFUSED if problems else EXIT_OK

    print("run %s: %d candidate(s), %d with a standing decision in this run"
          % (run_json.get("run_id") or "(no run_id)", len(candidates), len(settled)))
    print("  undecided, review set: %d = %d finding(s) + %d merged sink(s); %d distinct "
          "function bod%s at %d path(s)"
          % (review_set, shape["findings"], len(shape["merged"]), shape["bodies"],
             "y" if shape["bodies"] == 1 else "ies", shape["paths"]))
    for verdict in REVIEW_SET:
        print("    %-20s %d" % (verdict, by_verdict.get(verdict, 0)))
    for survivor, children in sorted(shape["merged_into"].items()):
        print("    merged into %s: %s" % (survivor, ", ".join(children)))
    for twin in shape["twins"]:
        print("    one body at %d paths: %s %s - %s"
              % (len(twin["all_function_keys"]), twin["content_hash"], twin["name"],
                 " | ".join(", ".join(ids) for ids in twin["candidate_ids"])))
        for copy in twin["decided"]:
            print("      decided%s: %s %s %s %s at %s"
                  % ("" if str(copy["run_id"] or "") == run_id
                     else " in run %s" % (copy["run_id"] or "unrecorded"),
                     copy["decision_id"], copy["decision"], copy["candidate_id"],
                     copy["rule_id"], copy["function_key"]))
        for copy in twin["held_back"]:
            print("      held back: %s %s %s at %s"
                  % (copy["candidate_id"], copy["verdict"], copy["rule_id"],
                     copy["function_key"]))
    dismissed = by_verdict.get(DISMISSED, 0)
    print("  undecided, %s: %d" % (DISMISSED, dismissed))
    print("    %-20s %d" % ("validator-only", len(held["validator_only"])))
    print("    %-20s %d" % ("arbiter UPHELD", len(held["upheld"])))
    print("    %-20s %d%s" % ("arbiter OVERTURNED", len(held["overturned"]),
                              ("  " + ", ".join("%s (from %s)" % (o["candidate_id"],
                                                                 o["from"] or "no finding")
                                                for o in held["overturned"]))
                              if held["overturned"] else ""))
    if held["other"]:
        print("    %-20s %d  %s" % ("other arbitration", len(held["other"]),
                                    ", ".join("%s (%s)" % (o["candidate_id"], o["arbitration"])
                                              for o in held["other"])))
    for verdict in sorted(v for v in by_verdict if v not in REVIEW_SET + (DISMISSED,)):
        print("  %s: %d (not a verdict stage 5 knows)" % (verdict, by_verdict[verdict]))
    if awaiting:
        print("  awaiting arbiter: %d  %s" % (len(awaiting), ", ".join(awaiting)))
    if unadjudicated:
        print("  not adjudicated: %d" % len(unadjudicated))
    for why in problems:
        print("  problem: %s" % why)
    # The counts above left out whatever could not be read, so they are lower
    # than the run's and must not reach the reviewer as its counts; a clean
    # exit beside a trailing problem line is how they would.
    return EXIT_REFUSED if problems else EXIT_OK


def review_set_shape(reviewed, decided=(), held_back=()):
    """What the review set's count is made of, for the line stage 5 opens with.

    The Mbed TLS session reported "12 candidates, all VULNERABLE" and a
    rejection rate over 12, when four were MERGED sinks whose survivor's record
    carries their rating (verify_findings counts 8 positives), and the 12 were
    five function bodies - process_response alone six times, at two paths that
    are one file twice. A rate weighted by how often the scanner raised one body
    is not a rate over the questions a person answered.

    `twins` names each review-set body that sits at more than one path, while
    the counts stay over the review set alone. Beside each body go its copies
    outside the review set: under `decided`, every current answer on it from
    any run (the `decided` argument, current_answers()'s first half), and under
    `held_back`, this run's adjudicated copies left out of the review set (the
    `held_back` argument, (candidate, verdict) pairs). A body whose other copy
    was decided or dismissed sits at two paths as surely as one whose copies
    are both undecided, and the copy already answered is the one the reviewer
    needs named.
    """
    merged_into, bodies, paths, by_body = {}, set(), set(), {}
    for candidate, arbitration in reviewed:
        candidate_id = str(candidate["candidate_id"])
        if arbitration.get("arbitration") == "MERGED":
            merged_into.setdefault(str(arbitration.get("merged_into") or "(unnamed)"),
                                   []).append(candidate_id)
        key, content_hash = identity_of(candidate)
        if not content_hash:
            continue
        bodies.add(content_hash)
        paths.add(key)
        by_body.setdefault(content_hash, {}).setdefault(key, []).append(candidate_id)
    elsewhere = {}
    for record in decided:
        if record.get("content_hash") in by_body:
            elsewhere.setdefault(record["content_hash"], ([], []))[0].append({
                "decision_id": record.get("decision_id"),
                "decision": record.get("decision"),
                "candidate_id": record.get("candidate_id"),
                "function_key": record.get("function_key"),
                "rule_id": record.get("rule_id"),
                "run_id": record.get("run_id")})
    for candidate, verdict in held_back:
        key, content_hash = identity_of(candidate)
        if content_hash in by_body:
            elsewhere.setdefault(content_hash, ([], []))[1].append({
                "candidate_id": str(candidate["candidate_id"]),
                "function_key": key,
                "rule_id": candidate.get("rule_id"),
                "verdict": verdict})
    copies = []
    for content_hash, at in sorted(by_body.items()):
        settled, dismissed = elsewhere.get(content_hash, ([], []))
        everywhere = sorted(set(at) | {c["function_key"] for c in settled + dismissed
                                       if c["function_key"]})
        if len(everywhere) < 2:
            continue
        keys = sorted(at)
        match = FUNCTION_KEY.match(keys[0])
        copies.append({"content_hash": content_hash,
                      "name": match.group("name") if match else keys[0],
                      "function_keys": keys,
                      "candidate_ids": [sorted(at[k]) for k in keys],
                      "all_function_keys": everywhere,
                      "decided": sorted(settled, key=lambda c: (
                          str(c["function_key"]), str(c["decision_id"]))),
                      "held_back": sorted(dismissed, key=lambda c: (
                          str(c["function_key"]), c["candidate_id"]))})
    merged = sorted(i for ids in merged_into.values() for i in ids)
    return {"findings": len(reviewed) - len(merged), "merged": merged,
            "merged_into": dict((k, sorted(v)) for k, v in merged_into.items()),
            "bodies": len(bodies), "paths": len(paths), "twins": copies}


# The words a decision's own verb and codes are spelled in. An explanation made
# of nothing else - "reject - FP-TEST", the reason the Mbed TLS session exported
# five times - says which box was ticked and nothing a model could learn why from.
RESTATING_WORDS = frozenset((
    "reject", "rejected", "confirm", "confirmed", "needs", "info", "out", "of",
    "scope", "fp", "oos", "code", "valid", "invalid", "issue", "yes", "no"))


def restates_code(text, codes):
    """True when `text` holds nothing but the decision's verb and its codes."""
    words = re.findall(r"[a-z0-9]+", str(text or "").lower())
    if not words:
        return False                    # empty is counted as unexplained instead
    spelled = set()
    for code in codes:
        for word in re.findall(r"[a-z0-9]+", str(code or "").lower()):
            spelled.update((word, word + "s"))
    return all(word in RESTATING_WORDS or word in spelled for word in words)


def label_conflicts(samples):
    """{id(sample): "same-cwe" | "cross-cwe"} for the samples that contradict
    another on the same body (cmd_export says which is which, and why)."""
    samples = list(samples)

    def present(sample):
        if "defect_present" in sample:
            return bool(sample["defect_present"])
        return sample.get("label") != "not_vulnerable"     # an older export's line

    cells, bodies, clashing = {}, {}, {}
    for sample in samples:
        cells.setdefault((sample.get("content_hash"), sample.get("cwe")), []).append(sample)
        bodies.setdefault(sample.get("content_hash"), []).append(sample)
    for group in cells.values():
        if len({present(s) for s in group}) > 1:
            for sample in group:
                clashing[id(sample)] = "same-cwe"
    for group in bodies.values():
        whole = [s for s in group if not present(s)
                 and s.get("reason_code") in WHOLE_FUNCTION_CODES]
        defects = [s for s in group if present(s)]
        if whole and defects:
            for sample in whole + defects:
                clashing.setdefault(id(sample), "cross-cwe")
    return clashing


def cmd_export(args, bundle_root):
    root = args.root
    # Checked before anything is read, so a refused path refuses the command
    # rather than the last step of it.
    out = (confined_output(root, args.out, "--out %s" % args.out) if args.out
           else guard_write(root, samples_path(root), "the training export"))
    ledger = load_ledger(root)
    standing, _ = latest_by_candidate(ledger["decisions"])
    freeze_id, freeze_at = eval_freeze(bundle_root)

    # out_of_scope is written only when it is asked for, by name or by the flag:
    # the defect is real, so it is no hard negative, and the project does not
    # defend the code, so it is no positive either.
    include_scope = bool(getattr(args, "include_out_of_scope", False)
                         or OUT_OF_SCOPE in (args.label_filter or ()))
    wanted = set(args.label_filter or (LABELS + ((OUT_OF_SCOPE,) if include_scope
                                                 else ())))
    # A later run's decision on the same question retires the earlier run's
    # before anything below reads it, on a key no model's choice moves. The
    # (function_key, content_hash, cwe) dedup was that fold, and stopped being
    # it when `cwe` became the adjudicated CWE: a legacy FP-GUARDED line under
    # the rule's CWE-119 and its correction under the validator's CWE-120 both
    # went out, as not_vulnerable and vulnerable, for one body at one path. The
    # same held inside one run whose stage 3 renumbered the candidate between
    # the two decisions, and retires() now takes that correction too.
    recover_offsets(standing.values(), root)
    ordered, retired = current_answers(standing.values())

    skipped_needs_info = skipped_withdrawn = 0
    unrecognised = {}
    by_key, winners, folds = {}, {}, []
    for record in ordered:
        decision = record.get("decision")
        if decision == "needs_info":
            # Not an approval. A sample needs a label and this decision is the
            # absence of one.
            skipped_needs_info += 1
            continue
        if decision == WITHDRAWN:
            # The absence of one too: the answer it replaces was taken back.
            skipped_withdrawn += 1
            continue
        if decision not in DECISION_LABEL:
            # needs_info and withdrawn are the sanctioned skips, each counted.
            # Anything else here is a hand-edited decision value, and dropping
            # it without a count would make the export quietly smaller than
            # the trail it was built from.
            unrecognised[str(decision)] = unrecognised.get(str(decision), 0) + 1
            continue

        # --label-filter is applied AFTER the dedup below, not here. Filtering
        # first let a vulnerable-only export emit a confirmation that a later
        # rejection of the same body had overturned: a filtered export must be
        # a subset of the unfiltered one, never a different answer.
        label = DECISION_LABEL[decision]
        if decision == "confirmed" and record.get("fix_commit"):
            provenance = "verified-fix"
        elif decision == "confirmed":
            provenance = "human-confirmed"
        elif decision == "rejected":
            provenance = "human-rejected"
        else:
            provenance = "human-out-of-scope"

        snapshot = record.get("snapshot") or {}
        approved_at = record.get("at")
        approved = parse_time(approved_at)
        if freeze_at is None:
            # Nothing is registered, so there is no freeze to postdate. null says
            # "not computed", which is what it is; writing false would assert the
            # sample predates a freeze that does not exist.
            postdates = None
        else:
            postdates = bool(approved is not None and approved > freeze_at)

        # Spelled as the twin gate compares CWEs (spelled_cwe()), as a decision
        # this version records already is: an older line's `cwe-787` beside a
        # newer CWE-787 is one CWE, and was two samples.
        cwe = spelled_cwe(record.get("cwe"))
        key = (record.get("function_key"), record.get("content_hash"), cwe)
        sample = {
            "schema_version": SCHEMA_VERSION,
            "sample_id": None,
            "label": label,
            "provenance": provenance,
            "repo": args.repo or snapshot.get("repo"),
            "commit": snapshot.get("commit"),
            "function_key": record.get("function_key"),
            "content_hash": record.get("content_hash"),
            "context_profile": snapshot.get("context_profile"),
            "context_sha256": snapshot.get("context_sha256"),
            "cwe": cwe,
            "localized_line": snapshot.get("localized_line"),
            "explanation": record.get("reason"),
            "approved_by": record.get("author"),
            "approved_at": approved_at,
            "postdates_eval_freeze": postdates,
            # Added fields: which freeze the flag was computed against, and the
            # decision it came from. A sample whose provenance cannot be walked
            # back to a line in the trail is a label with no argument behind it.
            "eval_freeze": (None if freeze_at is None
                            else {"id": freeze_id, "frozen_at": stamp(freeze_at)}),
            "decision_id": record.get("decision_id"),
            "reason_code": record.get("reason_code"),
            # Added after the Mbed TLS run. `defect_present` is what a label says
            # about the body, and what two labels are compared on: out_of_scope
            # and vulnerable both say the defect is there. The rest say where
            # else the same answer was given, and whether a person answered the
            # same body both ways.
            "defect_present": label != "not_vulnerable",
            "rule_cwe": record.get("rule_cwe"),
            "scope_code": record.get("scope_code"),
            "scope_basis": record.get("scope_basis"),
            "also_at": [],
            "also_decision_ids": [],
            "conflict": False,
        }
        # Dedup on (function_key, content_hash, cwe), contract §8. The same body
        # reached through two candidates is one training example, and the later
        # decision is the one that stands.
        if key in by_key:
            folds.append((by_key[key]["decision_id"], sample["decision_id"]))
        by_key[key] = sample
        winners[key] = record

    # Refused on the decisions that WIN the dedup, which are the ones that would
    # be written. A bad line that a later decision on the same body has already
    # superseded is history, and the fix for one is exactly that later line.
    for key, record in winners.items():
        if record.get("decision") == "rejected" and not record.get("reason_code"):
            # Contract §8: "the training export will not take it". Refusing the
            # whole export rather than dropping the line keeps the refusal
            # visible; the fix is to append a corrected rejection, which
            # latest-wins then exports instead.
            raise LedgerError(
                "%s (run %s) rejects %s with no reason_code, and contract §8 says "
                "the training export will not take a rejection that cannot name a "
                "disqualifier. Append a corrected decision on %s - `ledger.py "
                "reject --candidate %s --author %s --reason-code <FP-…> --reason …` "
                "while that run is current, or with the function's candidate id in "
                "a later one - and export again."
                % (record.get("decision_id"), record.get("run_id") or "unrecorded",
                   record.get("candidate_id"), record.get("function_key"),
                   record.get("candidate_id"), record.get("author")))
        basis = record.get("scope_basis") if isinstance(record.get("scope_basis"),
                                                        dict) else {}
        leaked = key_material(record.get("reason")) + key_material(basis.get("text"))
        if leaked:
            raise LedgerError(
                "%s carries key material in its reason (%s), and export would copy "
                "it into samples.jsonl as the explanation - a second committed "
                "copy, in the file a model trains on. Append a superseding decision "
                "on %s with a clean reason and export again; the trail keeps the "
                "old line, so rotate the credential too."
                % (record.get("decision_id"), ", ".join(leaked),
                   record.get("function_key")))

    # One body, labelled both ways. A sample is a function body under a CWE,
    # and the Mbed TLS export held psasim's process_response as vulnerable at
    # one path and not_vulnerable at its byte-identical copy, under one hash and
    # one CWE: the same input taught both answers, with nothing saying so.
    # "same-cwe" is that, whatever the paths. "cross-cwe" is the one only the
    # body shows: a label on one CWE does not contradict another's - a function
    # holds a real overflow and a guarded copy, or a MEM-002 defect beside a
    # clean whole-function sweep - unless the negative is a claim about the
    # whole function (WHOLE_FUNCTION_CODES), which no defect in it survives.
    # Under the adjudicated CWE, the Mbed TLS contradiction is that one: an
    # FP-TEST under MEM-WFS's CWE-119 beside the narrowed CWE-787 and CWE-125.
    # Either kind is left out and listed; --include-conflicts writes it marked.
    clashing = label_conflicts(by_key.values())
    bodies = {}
    for sample in by_key.values():
        bodies.setdefault(sample["content_hash"], []).append(sample)
    conflicts = []
    for content_hash, group in sorted(bodies.items(), key=lambda kv: str(kv[0])):
        members = [s for s in group if id(s) in clashing]
        if not members:
            continue
        conflicts.append((content_hash, "same-cwe" if "same-cwe" in
                          [clashing[id(s)] for s in members] else "cross-cwe", members))
        for sample in members:
            sample["conflict"] = True
            sample["conflict_kind"] = clashing[id(sample)]
            sample["conflict_with"] = sorted(
                str(o["decision_id"]) for o in members
                if o["defect_present"] != sample["defect_present"])
    emitted = [s for s in by_key.values()
               if getattr(args, "include_conflicts", False) or not s["conflict"]]

    # Twins: one answer, given at several byte-identical copies, is ONE sample
    # carrying the other paths in also_at. psasim's psa_wait and psa_call went
    # in twice each at two paths: weight doubled, and a split by path leaks one
    # copy into the other side.
    groups = {}
    for sample in sorted(emitted, key=lambda s: (str(s["approved_at"] or ""),
                                                 str(s["decision_id"] or ""))):
        groups.setdefault((sample["content_hash"], sample["cwe"], sample["label"]),
                          []).append(sample)
    collapsed, emitted = [], []
    for group in groups.values():
        keep = group[-1]                 # the latest answer, as everywhere else
        others = group[:-1]
        if others:
            keep["also_at"] = sorted(o["function_key"] for o in others)
            keep["also_decision_ids"] = [o["decision_id"] for o in others]
            collapsed.append(keep)
        emitted.append(keep)

    scope_left = [s for s in emitted if s["label"] == OUT_OF_SCOPE and not include_scope]
    kept = [s for s in emitted if s["label"] in wanted]
    filtered = len(emitted) - len(kept) - len(scope_left)
    samples = sorted(kept,
                     key=lambda s: (str(s["approved_at"] or ""), s["decision_id"] or ""))
    for index, sample in enumerate(samples, 1):
        sample["sample_id"] = "SMP-%04d" % index

    write_jsonl_atomic(out, samples)

    unexplained = sum(1 for s in samples if not s["explanation"])
    restating = [s for s in samples
                 if restates_code(s["explanation"], (s["reason_code"], s["scope_code"]))]
    print("wrote %d sample(s) to %s" % (len(samples), out))
    print("  vulnerable %d, not_vulnerable %d%s"
          % (sum(1 for s in samples if s["label"] == "vulnerable"),
             sum(1 for s in samples if s["label"] == "not_vulnerable"),
             (", out_of_scope %d" % sum(1 for s in samples if s["label"] == OUT_OF_SCOPE))
             if include_scope else ""))
    if retired:
        print("  %d decision(s) retired by a later decision on the same question "
              "(function_key, content_hash, rule_id and sink) - another run's, or this "
              "run's on a renumbered candidate: %s"
              % (len(retired), ", ".join("%s into %s" % (a.get("decision_id"),
                                                          b.get("decision_id"))
                                         for a, b in retired)))
    if folds:
        print("  %d duplicate(s) folded on (function_key, content_hash, cwe), the later "
              "decision standing: %s"
              % (len(folds), ", ".join("%s into %s" % pair for pair in folds)))
    if conflicts:
        print("  LABEL CONFLICTS - %d function bod%s labelled both ways; %s:"
              % (len(conflicts), "y" if len(conflicts) == 1 else "ies",
                 "written marked conflict: true (--include-conflicts)"
                 if getattr(args, "include_conflicts", False)
                 else "left out, --include-conflicts writes them marked"))
        for content_hash, kind, group in conflicts:
            sides = {}
            for sample in group:
                sides.setdefault(sample["label"], []).append(str(sample["decision_id"]))
            print("    %s %s: %s" % (content_hash, kind, "; ".join(
                "%s %s" % (label, ", ".join(sorted(ids)))
                for label, ids in sorted(sides.items()))))
    if collapsed:
        print("  %d sample(s) stand for byte-identical copies at other paths "
              "(also_at): %s"
              % (len(collapsed), ", ".join(
                  "%s with %s" % (s["decision_id"], ", ".join(s["also_decision_ids"]))
                  for s in collapsed)))
    if scope_left:
        scope_ids = sorted(str(i) for s in scope_left
                           for i in [s["decision_id"]] + s["also_decision_ids"])
        print("  %d out_of_scope decision(s) are not samples: the defect is real and "
              "outside the project's\n  security scope, so it is neither label "
              "(--include-out-of-scope writes them): %s"
              % (len(scope_ids), ", ".join(scope_ids)))
    if skipped_needs_info:
        print("  %d needs_info decision(s) are not samples: no label was given"
              % skipped_needs_info)
    if skipped_withdrawn:
        print("  %d withdrawn decision(s) are not samples: the answer each replaced "
              "was taken back" % skipped_withdrawn)
    if filtered:
        print("  %d sample(s) were left out by --label-filter %s"
              % (filtered, ", ".join(sorted(wanted))))
    if unrecognised:
        print("  %d standing decision(s) carry a decision value this tool does not "
              "know (%s) and are\n  not samples. `ledger.py check` names the lines; "
              "%s are the ones it knows."
              % (sum(unrecognised.values()),
                 ", ".join("%s x%d" % (name, number)
                           for name, number in sorted(unrecognised.items())),
                 ", ".join(DECISIONS)))
    if freeze_at is None:
        print("  postdates_eval_freeze is null on every sample: no evaluation set "
              "is registered in\n  %s, so there is no freeze to postdate. Freeze "
              "one before the flywheel makes the number meaningless."
              % os.path.join(bundle_root, "assets", "evalsets"))
    else:
        print("  postdates_eval_freeze computed against %s (frozen %s): %d true, "
              "%d false" % (freeze_id, stamp(freeze_at),
                            sum(1 for s in samples if s["postdates_eval_freeze"]),
                            sum(1 for s in samples
                                if s["postdates_eval_freeze"] is False)))
    if unexplained:
        print("  %d sample(s) carry no explanation; a label with no sentence behind "
              "it trains slowly" % unexplained)
    if restating:
        print("  %d sample(s) carry an explanation that only restates the decision "
              "and its code, which trains\n  no better than none: %s"
              % (len(restating), ", ".join("%s %r" % (s["decision_id"], s["explanation"])
                                           for s in restating)))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #

def cmd_check(args, bundle_root):
    root = args.root
    problems = []

    def problem(where, line, detail):
        problems.append((where, line, detail))

    def leak_problem(where, line, field, record):
        # Named by line and redacted sample only: the report must not become
        # the next place the credential is copied to.
        leaked = key_material(record.get(field))
        if leaked:
            problem(where, line,
                    "`%s` carries key material (%s). ledger/ is committed and is "
                    "training data; this line is in history now, so rotate the "
                    "credential, and supersede the record with one that cites "
                    "file:line instead." % (field, ", ".join(leaked)))

    # 1. The FP-* vocabulary, against the contract file it was copied from.
    path = contract_path(bundle_root)
    codes, why = contract_disqualifiers(path)
    if codes is None:
        problem(path, 0, why)
    else:
        missing = [c for c in codes if c not in DISQUALIFIER_CODES]
        extra = [c for c in DISQUALIFIER_CODES if c not in codes]
        if missing:
            problem(path, 0,
                    "§8 defines %s, which ledger.py will not accept on a rejection. "
                    "Add them to DISQUALIFIER_CODES." % ", ".join(missing))
        if extra:
            problem(os.path.join(_HERE, "ledger.py"), 0,
                    "DISQUALIFIER_CODES holds %s, which §8 no longer defines. A "
                    "rejection citing one names a disqualifier no validator can "
                    "produce." % ", ".join(extra))

    # 1, again: the out-of-scope codes, against the table in contract §8.
    spath_contract = ledger_contract_path(bundle_root)
    scope_codes, why = contract_scope_codes(spath_contract)
    if scope_codes is None:
        problem(spath_contract, 0, why)
    elif scope_codes != SCOPE_CODES:
        problem(spath_contract, 0,
                "§8 lists the out-of-scope codes %s and ledger.py's SCOPE_CODES holds "
                "%s. A code only one side knows is one `out-of-scope` refuses or one "
                "no contract defines." % (", ".join(scope_codes), ", ".join(SCOPE_CODES)))

    # 1a. The ledger has to actually survive a clone.
    swallowed = gitignore_problem(root)
    if swallowed:
        problem(os.path.join(run_dir(root), ".gitignore"), 0, swallowed)

    # 1b. And nothing it writes may be redirected. Every write refuses a link on
    # its path; this says so before anybody tries to record a decision, and
    # says it about the ledger a CI job is about to trust.
    for path in (decisions_path(root), suppressions_path(root), samples_path(root)):
        redirected = run_dir_write_problem(root, path)
        if redirected:
            problem(path, 0, redirected)

    ledger = load_ledger(root)
    for where, line, detail in ledger["problems"]:
        problem(where, line, detail)

    # 1c. Rule 3 is measured against extract/functions.jsonl. If that file cannot
    # be read whole, every staleness verdict below it is a guess, so it is a
    # problem of this ledger's - but only when there is a suppression whose fate
    # depends on it.
    corpus = load_corpus(root)
    if ledger["suppressions"] and corpus["problems"]:
        for where, line, detail in corpus["problems"]:
            problem(where, line,
                    "%s - and %d suppression(s) have their staleness measured "
                    "against this file (contract §8 rule 3)"
                    % (detail, len(ledger["suppressions"])))

    # 2. decisions.jsonl
    seen_ids = {}
    dpath = decisions_path(root)
    for record in ledger["decisions"]:
        line = record.get("__line")
        for field in ("decision_id", "at", "author", "candidate_id",
                      "function_key", "content_hash", "decision"):
            if not record.get(field):
                problem(dpath, line, "is missing %s" % field)
        decision = record.get("decision")
        if decision and decision not in DECISIONS:
            problem(dpath, line, "decision %r is not one of %s"
                    % (decision, ", ".join(DECISIONS)))
        code = record.get("reason_code")
        if decision == "rejected" and not code:
            problem(dpath, line, "rejects with no reason_code; contract §8 requires "
                                 "one and the training export refuses without it")
        if code and decision != "rejected":
            problem(dpath, line, "carries reason_code %r on a %s decision; the field "
                                 "means 'why this is not a bug' and nothing else"
                    % (code, decision))
        if code and code not in DISQUALIFIER_CODES:
            problem(dpath, line, "reason_code %r is not a §8 disqualifier" % code)
        scope = record.get("scope_code")
        if decision == "out_of_scope":
            basis = record.get("scope_basis")
            if scope not in SCOPE_CODES:
                problem(dpath, line, "records out_of_scope under scope_code %r, which is "
                                     "not one of %s" % (scope, ", ".join(SCOPE_CODES)))
            if not (isinstance(basis, dict) and basis.get("file")
                    and isinstance(basis.get("line"), int) and basis.get("text")):
                problem(dpath, line, "records out_of_scope with no scope_basis {file, "
                                     "line, text}: a scope call a reader cannot check "
                                     "against the line it rests on")
            elif key_material(basis.get("text")):
                problem(dpath, line, "`scope_basis.text` carries key material (%s)"
                        % ", ".join(key_material(basis.get("text"))))
        elif scope:
            problem(dpath, line, "carries scope_code %r on a %s decision; the field "
                                 "belongs to out_of_scope alone" % (scope, decision))
        # A withdrawal supersedes the line it names by carrying that line's key
        # (cmd_withdraw). One naming nothing, or another key, takes an answer
        # out of the export while no line in the trail says which.
        if decision == WITHDRAWN:
            target = next((r for r in ledger["decisions"]
                           if r.get("decision_id") == record.get("withdraws")
                           and r is not record), None)
            if target is None or decision_key(target) != decision_key(record):
                problem(dpath, line, "withdraws %r, which is %s" % (
                    record.get("withdraws"),
                    "no decision in this file" if target is None else
                    "a decision on another run, candidate, body or rule than the "
                    "one this line carries, so it supersedes nothing it names"))
            if not str(record.get("reason") or "").strip():
                problem(dpath, line, "withdraws a decision with no reason; a later run "
                                     "cannot tell why the answer stopped standing")
        for field in ("path_override", "conflict_acknowledged"):
            value = record.get(field)
            if isinstance(value, dict) and key_material(value.get("reason")):
                problem(dpath, line, "`%s.reason` carries key material (%s)"
                        % (field, ", ".join(key_material(value.get("reason")))))
        if code == WFS_CLEAN_CODE:
            snapshot = record.get("snapshot")
            filed = {str(record.get("rule_id") or "")}
            if isinstance(snapshot, dict) and isinstance(snapshot.get("rule_ids"), list):
                filed.update(str(r) for r in snapshot["rule_ids"])
            if WFS_RULE not in filed:
                problem(dpath, line, "rejects a %s decision with %s, which closes a %s "
                                     "whole-function sweep and nothing else"
                        % (record.get("rule_id") or "rule-less", code, WFS_RULE))
        identifier = record.get("decision_id")
        if identifier in seen_ids:
            problem(dpath, line, "reuses decision_id %s (first at line %d)"
                    % (identifier, seen_ids[identifier]))
        elif identifier:
            seen_ids[identifier] = line
        if record.get("at") and parse_time(record.get("at")) is None:
            problem(dpath, line, "`at` is not an ISO-8601 timestamp: %r"
                    % record.get("at"))
        if record.get("content_hash") and not CONTENT_HASH.match(
                str(record["content_hash"])):
            problem(dpath, line, "content_hash %r is not sha256(body)[:16]"
                    % record["content_hash"])
        leak_problem(dpath, line, "reason", record)

    # 2a. A standing FP-TEST or FP-GENERATED is held to the path facts it would
    # be refused on today. Ledgers written before that refusal hold them: six on
    # psasim in the Mbed TLS one, each a real defect exported as a hard
    # negative. The fix is a new decision on the candidate of this run that
    # asks the same question - out-of-scope, most often - which supersedes the
    # line in its own run and retires it from an earlier one
    # (current_answers()), and the problem names that candidate. Only current
    # answers are held to it: a line a later run re-decided is history, and
    # reporting it for ever was a problem nobody could clear. So is one whose
    # body changed or went away, which no candidate asks about any more: the
    # problem says so and names `withdraw`, the one way such a line leaves the
    # current answers.
    standing, _ = latest_by_candidate(ledger["decisions"])
    recover_offsets(standing.values(), root)
    current, _ = current_answers(standing.values())
    functions, questions = None, None

    def asked(record):
        nonlocal questions
        if questions is None:
            questions = run_questions(root)
        return asked_by(record, questions)

    for record in sorted(current, key=lambda r: r.get("__line", 0)):
        code = record.get("reason_code")
        if record.get("decision") != "rejected" or code not in PATH_CODES \
                or isinstance(record.get("path_override"), dict):
            continue
        if functions is None:
            functions = load_functions(root)
        snapshot = record.get("snapshot") if isinstance(record.get("snapshot"), dict) else {}
        function = functions.get(record.get("function_key")) or {}
        matched = FUNCTION_KEY.match(str(record.get("function_key") or ""))
        where = snapshot.get("file") or (matched.group("file") if matched else None)
        in_tree = snapshot.get("in_test_tree")
        # A line written before the snapshot carried in_test_tree, on a function
        # this extract no longer holds: stage 1's own rules decide, not "false".
        unrecorded = None
        if in_tree is None and not function:
            in_tree = stage1_test_file(where)
            unrecorded = "unknown" if in_tree is None else "rules"
        facts = path_facts({"file": where, "in_test_tree": in_tree,
                            "generated_file": snapshot.get("generated_file")}, function)
        # How stage 3 said the file got into the test tree, which the gate's
        # FP-TEST test turns on; read back from the path for a line written
        # before the snapshot kept it (recorded_basis()).
        facts["path_class_basis"] = (snapshot.get("path_class_basis")
                                     if "path_class_basis" in snapshot
                                     else recorded_basis(where, facts["in_test_tree"]))
        facts["in_test_tree_unrecorded"] = unrecorded
        mismatch = path_problem(code, root, facts)
        if mismatch:
            askers = asked(record)
            problem(dpath, record.get("__line"),
                    "%s rejects %s with %s: %s. Nothing recorded an override. %s; the "
                    "export trains on it as a hard negative meanwhile."
                    % (record.get("decision_id"), record.get("candidate_id"), code,
                       mismatch,
                       ("If the defect is real and out of the project's security "
                        "scope, record `ledger.py out-of-scope` on %s, the candidate of "
                        "this run that asks the same question, which supersedes or "
                        "retires this line" % " or ".join(askers)) if askers else
                       ("No candidate of this run asks its question - the body at %s "
                        "changed or is gone, or stage 3 did not raise it this run - "
                        "so no new decision retires this line. If the answer no "
                        "longer stands, `ledger.py withdraw --decision %s --author "
                        "<you> --reason ...` takes it out of the current answers, and "
                        "the line stays in the trail"
                        % (record.get("function_key"), record.get("decision_id")))))

    # 2b. One question answered two ways: byte-identical twins, and the members
    # of one MERGED cluster, whose labels disagree and which nobody
    # acknowledged when the second was recorded.
    for a, b, kind in ledger_conflicts(current, root):
        if acknowledged(a, b):
            continue
        later = max((a, b), key=lambda r: (str(r.get("at") or ""), r.get("__line", 0)))
        unmeasured = unmeasured_sink(a, b) if kind == "twin" else []
        askers = sorted(set(asked(a) + asked(b)))
        problem(dpath, later.get("__line"),
                "%s (%s %s, %s) and %s (%s %s, %s) answer one question two ways - %s - "
                "and nothing acknowledged it: %s.%s %s"
                % (a.get("decision_id"), a.get("decision"), a.get("candidate_id"),
                   a.get("function_key"), b.get("decision_id"), b.get("decision"),
                   b.get("candidate_id"), b.get("function_key"),
                   "byte-identical copies of one body under %s" % a.get("rule_id")
                   if kind == "twin" else "one MERGED cluster, one root cause",
                   disagreement(DECISION_LABEL[a["decision"]],
                                DECISION_LABEL[b["decision"]]),
                   (" %s record%s no sink offset (written before line_offset), so "
                    "the two may be different sinks of the body."
                    % (" and ".join(unmeasured), "s" if len(unmeasured) == 1 else ""))
                   if unmeasured else "",
                   ("Record a new decision on %s in this run - it supersedes a "
                    "decision of this run and retires one of an earlier run - "
                    "agreeing with the other, or with --acknowledge-conflict saying "
                    "why the two differ." % " or ".join(askers)) if askers else
                   ("No candidate of this run asks either question, so no new "
                    "decision replaces either: `ledger.py withdraw --decision` the "
                    "one that no longer stands, with --reason.")))

    # 3. suppressions.jsonl
    spath = suppressions_path(root)
    seen_sups = {}
    live_suppressions = dict((r.get("suppression_id"), r)
                             for r in ledger["suppressions"])
    for record in ledger["suppressions"]:
        line = record.get("__line")
        for field in ("suppression_id", "created_at", "author", "function_key",
                      "rule_id", "content_hash_at_creation", "reason", "expires_at"):
            if not record.get(field):
                problem(spath, line, "is missing %s" % field)
        identifier = record.get("suppression_id")
        if identifier in seen_sups:
            problem(spath, line, "reuses suppression_id %s (first at line %d)"
                    % (identifier, seen_sups[identifier]))
        elif identifier:
            seen_sups[identifier] = line
        if record.get("function_key") and not FUNCTION_KEY.match(
                str(record["function_key"])):
            problem(spath, line, "function_key %r is not <path>::<name>::<ordinal>"
                    % record["function_key"])
        if record.get("rule_id") and not RULE_ID.match(str(record["rule_id"])):
            problem(spath, line, "rule_id %r cannot exist" % record["rule_id"])
        if record.get("content_hash_at_creation") and not CONTENT_HASH.match(
                str(record["content_hash_at_creation"])):
            # Rule 3 compares this value every run. One of the wrong shape can
            # never compare equal, so the record suppresses nothing while reading
            # exactly like one that does.
            problem(spath, line,
                    "content_hash_at_creation %r is not sha256(body)[:16], so it "
                    "can never match the function's current hash and this "
                    "suppression suppresses nothing"
                    % record["content_hash_at_creation"])
        created = parse_time(record.get("created_at"))
        expires = parse_time(record.get("expires_at"))
        if record.get("expires_at") and expires is None:
            problem(spath, line, "expires_at is not a timestamp: %r"
                    % record.get("expires_at"))
        # Rule 2, re-checked after the fact. `max_expiry_days` is recorded at
        # creation precisely so a hand-edited `forced: false` on a five-year
        # expiry stops reading like an ordinary record.
        #
        # The comparison against the DEFAULT runs whatever that field holds.
        # Both tests used to sit under "max_expiry_days is a number", so a record
        # with the field missing - which is the exact shape of contract §8's own
        # example - or null or a string skipped rule 2 entirely: a ten-year
        # suppression passed `check` with 0 problems while `status` flagged it.
        # A missing field is not itself a problem; that example omits it.
        limit = record.get("max_expiry_days")
        numeric = isinstance(limit, (int, float)) and not isinstance(limit, bool)
        if limit is not None and not numeric:
            problem(spath, line, "max_expiry_days %r is not a number, so the "
                                 "ceiling this was created under cannot be read"
                    % (limit,))
        if created and expires:
            days = (expires - created).total_seconds() / 86400.0
            if numeric and days > limit and not record.get("forced"):
                problem(spath, line,
                        "expires %d days after creation, past its own recorded "
                        "max_expiry_days %s, without forced: true. Contract §8 rule "
                        "2 makes that combination unwritable, so this record was "
                        "edited by hand." % (int(round(days)), limit))
            elif days > DEFAULT_MAX_EXPIRY_DAYS and not record.get("forced"):
                # Written by this tool under a raised --max-expiry-days, or not
                # written by this tool at all. Rule 2's one supported escape is
                # --force, which records itself; anything else gets past the
                # refusal and leaves the record looking ordinary. It is
                # reported so it does not.
                how = ("it was created under --max-expiry-days %s" % limit
                       if numeric else
                       "it records no usable max_expiry_days, so `ledger.py "
                       "suppress` did not write it as it stands")
                problem(spath, line,
                        "expires %d days after creation, past the default limit of "
                        "%d, and was never forced: %s. The supported way past the "
                        "default is --force, which records forced: true. Revoke it "
                        "and re-suppress with --force, or bring the date in."
                        % (int(round(days)), DEFAULT_MAX_EXPIRY_DAYS, how))
        leak_problem(spath, line, "reason", record)
        leak_problem(spath, line, "revoked_reason", record)

    for record in ledger["revocations"]:
        line = record.get("__line")
        for field in ("suppression_id", "revoked_at", "author", "reason"):
            if not record.get(field):
                problem(spath, line, "revocation is missing %s" % field)
        leak_problem(spath, line, "reason", record)
        target = record.get("suppression_id")
        if target and target not in seen_sups:
            problem(spath, line, "revokes %s, which is not a suppression in this "
                                 "file" % target)
        elif target and not live_suppressions[target].get("revoked_at"):
            # A revoke does two writes; this is the state the second one failing
            # leaves behind. Stage 3 and the SARIF export honour the revocation
            # line on its own, so the candidate is back in the queue either way;
            # what is wrong is the record, whose own line now contradicts the
            # trail for anybody - or any tool - reading it alone.
            problem(spath, line,
                    "revokes %s, but line %d - the suppression itself - still "
                    "carries revoked_at: null. Contract §8 puts that field on the "
                    "suppression record, so as written the line says live what "
                    "the trail says revoked. Run `ledger.py revoke --suppression "
                    "%s --author <you>` again: it fills the field from this "
                    "revocation - its time, author and reason - and appends "
                    "nothing." % (target, seen_sups[target], target))
    revoked = {}
    for record in ledger["revocations"]:
        target = record.get("suppression_id")
        if target in revoked:
            problem(spath, record.get("__line"),
                    "is a second revocation of %s (first at line %d); one decision "
                    "gets one ending" % (target, revoked[target]))
        else:
            revoked[target] = record.get("__line")

    # 4. training/samples.jsonl, if an export has been run
    mpath = samples_path(root)
    samples, sample_problems = read_jsonl(mpath)
    for where, line, detail in sample_problems:
        problem(where, line, detail)
    seen_keys, sample_bodies = {}, {}
    for record in samples:
        line = record.get("__line")
        if record.get("label") not in SAMPLE_LABELS:
            problem(mpath, line, "label %r is not one of %s"
                    % (record.get("label"), ", ".join(SAMPLE_LABELS)))
        elif not record.get("conflict"):
            sample_bodies.setdefault(record.get("content_hash"), []).append(record)
        if record.get("provenance") not in PROVENANCES:
            problem(mpath, line, "provenance %r is not one of %s"
                    % (record.get("provenance"), ", ".join(PROVENANCES)))
        key = (record.get("function_key"), record.get("content_hash"),
               record.get("cwe"))
        if key in seen_keys:
            problem(mpath, line, "repeats (function_key, content_hash, cwe) from "
                                 "line %d; §8 deduplicates on it" % seen_keys[key])
        else:
            seen_keys[key] = line
        leak_problem(mpath, line, "explanation", record)
    # The export leaves out a body labelled both ways, or writes it marked. An
    # unmarked pair is an export this tool's current version did not write -
    # the Mbed TLS samples.jsonl is one - and regenerating it is the fix.
    clashing = label_conflicts(r for group in sample_bodies.values() for r in group)
    for content_hash, group in sorted(sample_bodies.items(), key=lambda kv: str(kv[0])):
        group = [r for r in group if id(r) in clashing]
        if group:
            problem(mpath, group[-1].get("__line"),
                    "holds %s both as a defect (%s) and as not_vulnerable (%s), and "
                    "neither is marked conflict: true. One body taught both answers "
                    "is noise whichever is right; run `ledger.py export` again, which "
                    "leaves such bodies out and lists them."
                    % (content_hash,
                       ", ".join(str(r.get("sample_id")) for r in group
                                 if r.get("label") != "not_vulnerable"),
                       ", ".join(str(r.get("sample_id")) for r in group
                                 if r.get("label") == "not_vulnerable")))

    for where, line, detail in problems:
        print("%s:%s: %s" % (where, line if line else "-", detail))
    print("\ncheck: %d problem(s)" % len(problems))
    return EXIT_REFUSED if problems else EXIT_OK


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    ap = argparse.ArgumentParser(
        description="Stage 5: the decision ledger - confirmations, rejections and "
                    "expiring suppressions that persist across runs.")
    ap.add_argument("--selftest", action="store_true",
                    help="run the fixtures and exit")
    subparsers = ap.add_subparsers(dest="command")

    def common(parser):
        parser.add_argument("--root", default=".",
                            help="scanned repository root, holding .security-review/ "
                                 "(default: .)")
        return parser

    for name, help_text in (("confirm", "record that a finding is real"),
                            ("reject", "record that a finding is a false positive"),
                            ("out-of-scope", "record that a finding is real and "
                                             "outside the project's security scope"),
                            ("needs-info", "record that the finding cannot be "
                                           "settled yet")):
        sub = common(subparsers.add_parser(name, help=help_text))
        sub.add_argument("--candidate", required=True, metavar="CAND-0001")
        sub.add_argument("--author", required=True)
        sub.add_argument("--reason", default=None,
                         help="why, in a sentence a later run can read")
        if name == "confirm":
            sub.add_argument("--fix-commit", default=None,
                             help="the commit that fixes it; exports the sample with "
                                  "provenance verified-fix")
        if name == "reject":
            sub.add_argument("--reason-code", default=None,
                             help="one of the Validator Contract §8 disqualifiers: "
                                  + ", ".join(DISQUALIFIER_CODES))
            sub.add_argument("--path-override", default=None, metavar="WHY",
                             help="record an FP-TEST or FP-GENERATED whose path facts "
                                  "do not show it, saying why; recorded on the decision")
        if name == "out-of-scope":
            sub.add_argument("--scope-code", default=None,
                             help="what puts it out of scope: " + ", ".join(SCOPE_CODES))
            sub.add_argument("--basis", default=None, metavar="FILE:LINE",
                             help="the line of the project the scope call rests on; "
                                  "the tool quotes it into the record")
        if name != "needs-info":
            sub.add_argument("--acknowledge-conflict", default=None, metavar="WHY",
                             help="record a label that disagrees with a standing "
                                  "decision on a byte-identical twin or in the "
                                  "arbiter's MERGED cluster, saying why the two differ")

    wdr = common(subparsers.add_parser(
        "withdraw", help="take a standing decision that no candidate of this run "
                         "asks again - its body changed or is gone - out of the "
                         "current answers"))
    wdr.add_argument("--decision", required=True, metavar="DEC-0001")
    wdr.add_argument("--author", required=True)
    wdr.add_argument("--reason", default=None,
                     help="required: why the answer no longer stands")

    sup = common(subparsers.add_parser(
        "suppress", help="stop a rule firing on a function, until a date"))
    sup.add_argument("--function-key", required=True, metavar="src/a.c::f::0")
    sup.add_argument("--rule", required=True, metavar="MEM-002")
    sup.add_argument("--author", required=True)
    sup.add_argument("--reason", default=None)
    sup.add_argument("--expires", default=None, metavar="YYYY-MM-DD",
                     help="required; there is no permanent suppression (§8 rule 1)")
    sup.add_argument("--max-expiry-days", type=int, default=DEFAULT_MAX_EXPIRY_DAYS,
                     help="longest expiry allowed without --force (default: %d). "
                          "Lowering it is free; raising it above %d gets past the "
                          "refusal without recording that anything was forced, so "
                          "`status` and `check` both report the result"
                          % (DEFAULT_MAX_EXPIRY_DAYS, DEFAULT_MAX_EXPIRY_DAYS))
    sup.add_argument("--force", action="store_true",
                     help="allow an expiry past --max-expiry-days; records "
                          "forced: true")

    rev = common(subparsers.add_parser(
        "revoke", help="end a suppression by appending a revocation"))
    rev.add_argument("--suppression", required=True, metavar="SUP-0001")
    rev.add_argument("--author", required=True)
    rev.add_argument("--reason", default=None)

    sta = common(subparsers.add_parser("status", help="what the ledger holds today"))
    sta.add_argument("--json", action="store_true",
                     help="machine-readable, for a dashboard or a CI job")

    pen = common(subparsers.add_parser(
        "pending", help="what this run leaves for a person to decide, by verdict, "
                        "with the NOT_VULNERABLE held back split by who settled it"))
    pen.add_argument("--json", action="store_true", help="machine-readable")

    exp = common(subparsers.add_parser(
        "export", help="write the human-approved decisions as training samples"))
    exp.add_argument("--out", default=None,
                     help="output path, which must be under .security-review/ "
                          "(contract §9 rule 2; default: "
                          ".security-review/ledger/training/samples.jsonl)")
    exp.add_argument("--label-filter", action="append", choices=list(SAMPLE_LABELS),
                     help="export only this label; repeatable. Naming out_of_scope "
                          "asks for it, as --include-out-of-scope does")
    exp.add_argument("--include-out-of-scope", action="store_true",
                     help="also write out_of_scope decisions, labelled out_of_scope "
                          "with defect_present true; left out by default")
    exp.add_argument("--include-conflicts", action="store_true",
                     help="also write the bodies labelled both ways, marked "
                          "conflict: true; left out and listed by default")
    exp.add_argument("--repo", default=None,
                     help="repository name for the samples (default: the run's)")

    common(subparsers.add_parser(
        "check", help="the ledger against its own rules, and the FP-* codes "
                      "against the Validator Contract"))
    return ap


def dispatch(args, bundle_root=None):
    bundle_root = bundle_root or os.path.dirname(_HERE)
    handlers = {
        "confirm": lambda: record_decision(args, "confirmed", bundle_root),
        "reject": lambda: record_decision(args, "rejected", bundle_root),
        "needs-info": lambda: record_decision(args, "needs_info", bundle_root),
        "out-of-scope": lambda: record_decision(args, "out_of_scope", bundle_root),
        "withdraw": lambda: cmd_withdraw(args, bundle_root),
        "suppress": lambda: cmd_suppress(args, bundle_root),
        "revoke": lambda: cmd_revoke(args, bundle_root),
        "status": lambda: cmd_status(args, bundle_root),
        "pending": lambda: cmd_pending(args, bundle_root),
        "export": lambda: cmd_export(args, bundle_root),
        "check": lambda: cmd_check(args, bundle_root),
    }
    return handlers[args.command]()


# The run-directory gate, rules_lib.run_dir_gate: nothing under .security-review/
# is read while git says the scanned repository commits anything there but
# .gitignore and ledger/. This tool imports nothing from rules_lib, so it runs
# the gate as a process of its own - `-I`, which imports the standard library
# and nothing else, and `-B`, which leaves no bytecode in the scanned tree - and
# takes anything but a clean pass as a refusal: a gate that could not run has
# not said the directory is safe. tests/test_contract_parity.py holds every copy
# of this function to the same text.
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


def main():
    args = build_parser().parse_args()
    if args.selftest:
        return selftest()
    if not args.command:
        build_parser().print_help()
        return EXIT_USAGE
    # Before anything under the run directory is read (_run_dir_gate).
    refusal, _gate = _run_dir_gate(getattr(args, "root", "."))
    if refusal:
        print(refusal, file=sys.stderr)
        return EXIT_SHIPPED
    try:
        return dispatch(args)
    except LedgerError as exc:
        prefix = "ERROR" if exc.code == EXIT_USAGE else "REFUSED"
        print("%s: %s" % (prefix, exc), file=sys.stderr)
        return exc.code


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

CONTRACT_FIXTURE = """\
## 7. Output format

`ACCEPTED_RISK` uses `FP-ACCEPTED`, and it is the one code that does not mean
"not a bug".

## 8. Standard false-positive disqualifiers

| Code | Disqualifier | Kind |
|---|---|---|
| `FP-CONST` | All inputs are literals | positive |
| `FP-GUARDED` | A correct check dominates | positive |
| `FP-TRUSTED` | The value is not attacker-influenced | **absence** |
| `FP-NEWTHING` | A disqualifier ledger.py has never heard of | positive |

## 8a. The relevance test

`FP-NOT-SECURITY` is available here too.
"""


def _fixture(tmp):
    """A run directory with two adjudicated candidates and one that is not."""
    root = os.path.join(tmp, "repo")
    review = os.path.join(root, ".security-review")
    for part in ("extract", "scores", "candidates", "arbitration"):
        os.makedirs(os.path.join(review, part), exist_ok=True)

    # Stage 1's own file, verbatim: it ignores the run artefacts and carves the
    # ledger back out.
    with open(os.path.join(review, ".gitignore"), "w", encoding="utf-8") as fh:
        fh.write("*\n!.gitignore\n!ledger/\n!ledger/**\n")

    with open(os.path.join(review, "run.json"), "w", encoding="utf-8") as fh:
        json.dump({"schema_version": 1, "run_id": "2026-09-19T04-31-46Z",
                   "started_at": "2026-09-19T04:31:46Z", "repo_root": root,
                   "git": {"commit": "c74df89a", "branch": "main", "dirty": False},
                   "stages_completed": ["extract", "score"]}, fh)

    functions = [
        {"schema_version": 1, "function_key": "src/parse.c::parse_tlv_record::0",
         "function_id": "src/parse.c::parse_tlv_record::0@fbb8544c6c43791a",
         "content_hash": "fbb8544c6c43791a", "file": "src/parse.c", "language": "c",
         "context": {"profile": "default-v1", "text_sha256": "8084e2b7"}},
        {"schema_version": 1, "function_key": "src/parse.c::handle_conn::0",
         "function_id": "src/parse.c::handle_conn::0@f81682d7bcfeac28",
         "content_hash": "f81682d7bcfeac28", "file": "src/parse.c", "language": "c",
         "context": {"profile": "default-v1", "text_sha256": "878086cc"}},
        {"schema_version": 1, "function_key": "src/app.py::run_cmd::0",
         "function_id": "src/app.py::run_cmd::0@fb7eb9b971430def",
         "content_hash": "fb7eb9b971430def", "file": "src/app.py",
         "language": "python",
         "context": {"profile": "default-v1", "text_sha256": "8b37de52"}},
    ]
    with open(os.path.join(review, "extract", "functions.jsonl"), "w",
              encoding="utf-8") as fh:
        for record in functions:
            fh.write(json.dumps(record) + "\n")

    scores = [
        {"schema_version": 1, "function_key": "src/parse.c::parse_tlv_record::0",
         "content_hash": "fbb8544c6c43791a", "context_profile": "default-v1",
         "context_sha256": "8084e2b7", "localized_line": 8, "score_kind": "ordinal"},
        {"schema_version": 1, "function_key": "src/app.py::run_cmd::0",
         "content_hash": "fb7eb9b971430def", "context_profile": "default-v1",
         "context_sha256": "8b37de52", "localized_line": 4, "score_kind": "ordinal"},
    ]
    with open(os.path.join(review, "scores", "scores.jsonl"), "w",
              encoding="utf-8") as fh:
        for record in scores:
            fh.write(json.dumps(record) + "\n")

    candidates = [
        {"candidate_id": "CAND-0001", "category": "memory-safety",
         "rule_id": "MEM-002", "cwe": "CWE-787", "language": "c",
         "file": "src/parse.c", "line": 8,
         "function_id": "src/parse.c::parse_tlv_record::0@fbb8544c6c43791a",
         "sink_text": "memcpy(rec->payload, cur, len);"},
        # Same function and body as CAND-0001, reached through a second rule, so
        # a confirmation on both must still export ONE sample.
        {"candidate_id": "CAND-0002", "category": "memory-safety",
         "rule_id": "MEM-001", "cwe": "CWE-787", "language": "c",
         "file": "src/parse.c", "line": 9,
         "function_id": "src/parse.c::parse_tlv_record::0@fbb8544c6c43791a",
         "sink_text": "memcpy(rec->payload + 1, cur, len);"},
        {"candidate_id": "CAND-0003", "category": "injection-input",
         "rule_id": "INJ-002", "cwe": "CWE-78", "language": "python",
         "file": "src/app.py", "line": 4,
         "function_id": "src/app.py::run_cmd::0@fb7eb9b971430def",
         "sink_text": "subprocess.run(user_input, shell=True)"},
        # Adjudicated, different function, different CWE - a second sample.
        {"candidate_id": "CAND-0004", "category": "memory-safety",
         "rule_id": "MEM-003", "cwe": "CWE-119", "language": "c",
         "file": "src/parse.c", "line": 17,
         "function_id": "src/parse.c::handle_conn::0@f81682d7bcfeac28",
         "sink_text": "read(fd, buf, n);"},
    ]
    with open(os.path.join(review, "candidates", "memory-safety.json"), "w",
              encoding="utf-8") as fh:
        json.dump([c for c in candidates if c["category"] == "memory-safety"], fh)
    with open(os.path.join(review, "candidates", "injection-input.json"), "w",
              encoding="utf-8") as fh:
        json.dump([c for c in candidates if c["category"] == "injection-input"], fh)
    with open(os.path.join(review, "candidates", "coverage.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"schema_version": 1, "rules": []}, fh)

    # Stage 4's validator verdicts. Every dispatched candidate gets one except
    # CAND-0003, which is deliberately left unadjudicated. CAND-0004 is the one
    # the arbiter never saw: the queue did not send it, so it has a finding and
    # NO ARB record, which is the ordinary case on a real run.
    os.makedirs(os.path.join(review, "findings"), exist_ok=True)
    for candidate_id, verdict, severity in (("CAND-0001", "VULNERABLE", "critical"),
                                            ("CAND-0002", "VULNERABLE", "high"),
                                            ("CAND-0004", "NOT_VULNERABLE", "medium")):
        with open(os.path.join(review, "findings", "%s.json" % candidate_id),
                  "w", encoding="utf-8") as fh:
            json.dump({"candidate_id": candidate_id, "rule_id": "MEM-002",
                       "cwe": "CWE-787", "verdict": verdict, "confidence": "high",
                       "severity": severity, "primary_location": "src/parse.c:8"}, fh)

    for candidate_id, verdict in (("CAND-0001", "VULNERABLE"),
                                  ("CAND-0002", "VULNERABLE")):
        with open(os.path.join(review, "arbitration", "ARB-%s.json" % candidate_id),
                  "w", encoding="utf-8") as fh:
            json.dump({"candidate_id": candidate_id, "arbitration": "UPHELD",
                       "final_verdict": verdict, "final_severity": "high"}, fh)
    return root


def _bundle(tmp, frozen_at="2026-01-14T00:00:00Z"):
    bundle = os.path.join(tmp, "bundle")
    os.makedirs(os.path.join(bundle, "references"), exist_ok=True)
    os.makedirs(os.path.join(bundle, "assets", "evalsets"), exist_ok=True)
    with open(contract_path(bundle), "w", encoding="utf-8") as fh:
        fh.write(CONTRACT_FIXTURE)
    if frozen_at:
        with open(os.path.join(bundle, "assets", "evalsets", "evalset-v1.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"id": "evalset-v1", "frozen_at": frozen_at,
                       "description": "fixture", "size": 8, "base_rate": 0.1,
                       "operating_points": []}, fh)
    return bundle


# The Mbed TLS run of 2026-09-29 (development @ c0748be), as its twelve
# decisions saw it. psasim is vendored twice - framework/ and
# tf-psa-crypto/framework/ are one submodule at two paths - so every body below
# but the ACVP harness's sits at both, under one content hash. Candidate CWEs
# are the rules' (MEM-WFS files CWE-119, MEM-002 CWE-787); the findings carry
# the narrowed CWE the session table printed.
MBEDTLS_RUN = "2026-09-29T12-03-47Z"
MBEDTLS_COMMIT = "c0748befd5beebad73e1797732290e6f7181a08f"
MBEDTLS_FW = "framework/psasim/src/"
MBEDTLS_TF = "tf-psa-crypto/framework/psasim/src/"
MBEDTLS_ACVP = "tf-psa-crypto/drivers/pqcp/mldsa-native/test/acvp/acvp_mldsa.c"
MBEDTLS_BODY = {"process_response": ("33bd5b6cc79c1924", 96),
                "send": ("148fe9cd157d709c", 206),
                "psa_call": ("49a083930d070f96", 345),
                "psa_wait": ("927d95cf0060f685", 96),
                "main": ("3f85716c62bb6e1c", 523)}
MBEDTLS_RULE_CWE = {"MEM-WFS": "CWE-119", "MEM-002": "CWE-787"}
# candidate, rule, narrowed cwe, file, function, line, arbitration, merged_into,
# final severity
MBEDTLS_ROWS = (
    ("CAND-0031", "MEM-WFS", "CWE-787", MBEDTLS_TF + "psa_ff_client.c",
     "process_response", 178, "UPHELD", None, "medium"),
    ("CAND-0047", "MEM-002", "CWE-787", MBEDTLS_TF + "psa_ff_client.c",
     "process_response", 178, "MERGED", "CAND-0031", None),
    ("CAND-0041", "MEM-002", "CWE-125", MBEDTLS_TF + "psa_ff_client.c",
     "process_response", 150, "MERGED", "CAND-0031", None),
    ("CAND-0010", "MEM-WFS", "CWE-119", MBEDTLS_FW + "psa_ff_client.c",
     "process_response", 178, "UPHELD_MODIFIED", None, "low"),
    ("CAND-0026", "MEM-002", "CWE-787", MBEDTLS_FW + "psa_ff_client.c",
     "process_response", 178, "MERGED", "CAND-0010", None),
    ("CAND-0020", "MEM-002", "CWE-125", MBEDTLS_FW + "psa_ff_client.c",
     "process_response", 150, "MERGED", "CAND-0010", None),
    ("CAND-0052", "MEM-WFS", "CWE-121", MBEDTLS_ACVP, "main", 648, "UPHELD", None, "low"),
    ("CAND-0123", "MEM-WFS", "CWE-119", MBEDTLS_FW + "psa_ff_client.c", "send", 242,
     "UPHELD", None, "low"),
    ("CAND-0132", "MEM-WFS", "CWE-908", MBEDTLS_FW + "psa_ff_server.c", "psa_wait", 222,
     "UPHELD", None, "low"),
    ("CAND-0146", "MEM-WFS", "CWE-908", MBEDTLS_TF + "psa_ff_server.c", "psa_wait", 222,
     "UPHELD", None, "low"),
    ("CAND-0162", "MEM-WFS", "CWE-119", MBEDTLS_FW + "psa_ff_client.c", "psa_call", 352,
     "UPHELD", None, "low"),
    ("CAND-0164", "MEM-WFS", "CWE-787", MBEDTLS_TF + "psa_ff_client.c", "psa_call", 354,
     "UPHELD", None, "low"),
)
# The session's twelve decisions, in order, with the reviewer's words verbatim
# (REVIEW-SESSION-2026-09-29.md; "FP-TESTS" was recorded as FP-TEST).
MBEDTLS_SESSION = (
    ("CAND-0031", "confirmed", None,
     "Valid issue, no guards are protecting from the arbitrary memcpy size being used."),
    ("CAND-0047", "confirmed", None, "confirm - no guards are protecting"),
    ("CAND-0041", "confirmed", None, "confirm - no read boundary enfroced"),
    ("CAND-0010", "rejected", "FP-TEST", "reject - test code only"),
    ("CAND-0026", "confirmed", None, "confirm - no bounds restriction"),
    ("CAND-0020", "confirmed", None, "confirm - no bounds"),
    ("CAND-0052", "rejected", "FP-TEST", "reject - FP-TEST"),
    ("CAND-0123", "rejected", "FP-TEST", "reject - FP-TEST"),
    ("CAND-0132", "rejected", "FP-TEST", "reject - FP-TESTS"),
    ("CAND-0146", "rejected", "FP-TEST", "reject - FP-TEST"),
    ("CAND-0162", "rejected", "FP-TEST", "reject - FP-TEST"),
    ("CAND-0164", "rejected", "FP-TEST", "reject - FP-TEST"),
)
# DEC-0004 exactly as the ledger.py of that run wrote it: no rule_cwe, no scope
# fields, no merged_into, and the rule's CWE in `cwe`.
MBEDTLS_LEGACY_LINE = (
    '{"at": "2026-09-29T15:28:56Z", "author": "MP", "candidate_id": "CAND-0010", '
    '"content_hash": "33bd5b6cc79c1924", "cwe": "CWE-119", "decision": "rejected", '
    '"decision_id": "DEC-0004", "final_verdict": "VULNERABLE", "fix_commit": null, '
    '"function_key": "framework/psasim/src/psa_ff_client.c::process_response::0", '
    '"reason": "reject - test code only", "reason_code": "FP-TEST", "rule_id": '
    '"MEM-WFS", "run_id": "2026-09-29T12-03-47Z", "schema_version": 1, "snapshot": '
    '{"adjudicated_by": "arbitration", "arbitration": "UPHELD_MODIFIED", "category": '
    '"memory-safety", "commit": "c0748befd5beebad73e1797732290e6f7181a08f", '
    '"context_profile": "default-v1", "context_sha256": "ctx-33bd5b6c", "file": '
    '"framework/psasim/src/psa_ff_client.c", "language": "c", "localized_line": 178, '
    '"repo": "mbedtls", "rule_ids": ["MEM-WFS"], "severity": "low"}, "tool_version": '
    '"1.0.0"}')
# The lines the psasim sources carry, where the real tree has them.
MBEDTLS_NOTES = {"psa_ff_client.c": (39, "/* Note that this implementation is "
                                         "functional and not secure */"),
                 "psa_ff_server.c": (35, "/* Note that this implementation is "
                                         "functional and not secure. */")}


def _mbedtls_key(row):
    return "%s::%s::0" % (row[3], row[4])


def _mbedtls_legacy(index, row, decision, code, reason):
    """One decision as the ledger.py of the Mbed TLS run wrote it."""
    candidate_id, rule, _cwe, path, name, line, ruling, _into, severity = row
    content_hash = MBEDTLS_BODY[name][0]
    at = (datetime.datetime(2026, 9, 29, 15, 28, 54, tzinfo=datetime.timezone.utc)
          + datetime.timedelta(seconds=(index + 1) // 2))
    return {"at": stamp(at), "author": "MP",
            "candidate_id": candidate_id, "content_hash": content_hash,
            "cwe": MBEDTLS_RULE_CWE[rule], "decision": decision,
            "decision_id": "DEC-%04d" % (index + 1), "final_verdict": "VULNERABLE",
            "fix_commit": None, "function_key": _mbedtls_key(row), "reason": reason,
            "reason_code": code, "rule_id": rule, "run_id": MBEDTLS_RUN,
            "schema_version": 1,
            "snapshot": {"adjudicated_by": "arbitration", "arbitration": ruling,
                         "category": "memory-safety", "commit": MBEDTLS_COMMIT,
                         "context_profile": "default-v1",
                         "context_sha256": "ctx-" + content_hash[:8], "file": path,
                         "language": "c", "localized_line": line, "repo": "mbedtls",
                         "rule_ids": [rule], "severity": severity or "low"},
            "tool_version": "1.0.0"}


def _mbedtls_fixture(tmp):
    """The run directory the twelve decisions were recorded against."""
    root = os.path.join(tmp, "mbedtls")
    review = os.path.join(root, ".security-review")
    for part in ("extract", "candidates", "findings", "arbitration"):
        os.makedirs(os.path.join(review, part), exist_ok=True)
    with open(os.path.join(review, ".gitignore"), "w", encoding="utf-8") as fh:
        fh.write("*\n!.gitignore\n!ledger/\n!ledger/**\n")
    with open(os.path.join(review, "run.json"), "w", encoding="utf-8") as fh:
        json.dump({"schema_version": 1, "run_id": MBEDTLS_RUN, "repo": "mbedtls",
                   "git": {"commit": MBEDTLS_COMMIT}}, fh)
    functions, candidates = {}, []
    for row in MBEDTLS_ROWS:
        candidate_id, rule, cwe, path, name, line, ruling, into, severity = row
        key = _mbedtls_key(row)
        content_hash, start = MBEDTLS_BODY[name]
        in_test = bool(TEST_PATH.search(path))
        functions[key] = {"schema_version": 1, "function_key": key,
                          "function_id": key + "@" + content_hash,
                          "content_hash": content_hash, "file": path, "language": "c",
                          "name": name, "line_start": start, "in_test_tree": in_test,
                          "context": {"profile": "default-v1",
                                      "text_sha256": "ctx-" + content_hash[:8]}}
        candidates.append({"candidate_id": candidate_id, "category": "memory-safety",
                           "rule_id": rule, "cwe": MBEDTLS_RULE_CWE[rule],
                           "language": "c", "file": path, "line": line,
                           "function_id": key + "@" + content_hash,
                           "function_key": key, "content_hash": content_hash,
                           "in_test_tree": in_test})
        with open(os.path.join(review, "findings", candidate_id + ".json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": candidate_id, "rule_id": rule, "cwe": cwe,
                       "verdict": "VULNERABLE", "confidence": "high",
                       "severity": severity or "low",
                       "primary_location": "%s:%d" % (path, line)}, fh)
        arb = {"candidate_id": candidate_id, "rule_id": rule, "arbitration": ruling,
               "original_verdict": "VULNERABLE", "final_verdict": "VULNERABLE",
               "final_confidence": "high", "merged_into": into}
        if severity:
            arb["final_severity"] = severity
        with open(os.path.join(review, "arbitration", "ARB-%s.json" % candidate_id),
                  "w", encoding="utf-8") as fh:
            json.dump(arb, fh)
    with open(os.path.join(review, "extract", "functions.jsonl"), "w",
              encoding="utf-8") as fh:
        for record in functions.values():
            fh.write(json.dumps(record) + "\n")
    with open(os.path.join(review, "candidates", "memory-safety.json"), "w",
              encoding="utf-8") as fh:
        json.dump(candidates, fh)
    with open(os.path.join(review, "arbitration", "queue.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"summary": {}, "queue": [{"candidate_id": row[0]}
                                            for row in MBEDTLS_ROWS]}, fh)
    for base in (MBEDTLS_FW, MBEDTLS_TF):
        os.makedirs(os.path.join(root, base), exist_ok=True)
        for name, (number, text) in MBEDTLS_NOTES.items():
            with open(os.path.join(root, base, name), "w", encoding="utf-8") as fh:
                fh.write("\n" * (number - 1) + text + "\n")
    return root


def _invoke(argv, bundle_root=None):
    """Run the CLI end to end. Returns (exit code, stdout, message)."""
    import contextlib
    import io
    buffer = io.StringIO()
    args = build_parser().parse_args(argv)
    try:
        with contextlib.redirect_stdout(buffer):
            code = dispatch(args, bundle_root=bundle_root)
        return code, buffer.getvalue(), ""
    except LedgerError as exc:
        return exc.code, buffer.getvalue(), str(exc)


def _rerun(root, run_id):
    """The same run directory under the next run's id: the tree unchanged,
    and stage 3's candidate ids meaning what they did."""
    path = os.path.join(run_dir(root), "run.json")
    with open(path, encoding="utf-8") as fh:
        run_json = json.load(fh)
    run_json["run_id"] = run_id
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(run_json, fh)


def _rewrite(root, part, name, **fields):
    """Rewrite one stage 4 record of the run directory, field by field."""
    path = os.path.join(run_dir(root), part, name)
    with open(path, encoding="utf-8") as fh:
        record = json.load(fh)
    record.update(fields)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh)


def _lines(path):
    with open(path, encoding="utf-8") as fh:
        return [line for line in fh if line.strip()]


def _raw(path):
    with open(path, "rb") as fh:
        return fh.read()


def selftest():
    import tempfile
    failures = 0

    def check(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    # ---- the FP-* vocabulary, against the real contract and a fixture ---- #
    real = contract_path(os.path.dirname(_HERE))
    if os.path.isfile(real):
        codes, why = contract_disqualifiers(real)
        check("the shipped validator contract parses", why, None)
        check("and its §8 table is exactly DISQUALIFIER_CODES",
              codes, DISQUALIFIER_CODES)
        check("FP-ACCEPTED is not among them - §7 says it is not a disqualifier",
              ACCEPTED_RISK_CODE in (codes or ()), False)
        check("and every code the path check and the conflict test name is one of them",
              [c for c in PATH_CODES + WHOLE_FUNCTION_CODES if c not in (codes or ())],
              [])
    else:
        # Not a skip: a check that silently tests nothing is the failure this
        # file's `check` command exists to refuse.
        failures += 1
        print("  FAIL the shipped validator contract is not there: %s" % real)

    with tempfile.TemporaryDirectory() as tmp:
        bundle = _bundle(tmp)
        codes, why = contract_disqualifiers(contract_path(bundle))
        check("only §8's own table rows are vocabulary",
              codes, ("FP-CONST", "FP-GUARDED", "FP-TRUSTED", "FP-NEWTHING"))
        check("§8a prose and §7's FP-ACCEPTED are not",
              [c for c in (codes or ()) if c in ("FP-ACCEPTED", "FP-NOT-SECURITY")],
              [])
        missing = os.path.join(tmp, "nope.md")
        codes, why = contract_disqualifiers(missing)
        check("a missing contract is a problem, not a silent pass",
              (codes, "not there" in (why or "")), (None, True))
        with open(contract_path(bundle), "w", encoding="utf-8") as fh:
            fh.write("## 9. Something else\n")
        codes, why = contract_disqualifiers(contract_path(bundle))
        check("a contract with no §8 heading reports why rather than reading empty",
              (codes, "no `## 8.` heading" in (why or "")), (None, True))

    # ---- decisions ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)

        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com", "--reason", "len is unbounded"], bundle)
        check("a confirmation on an adjudicated candidate is recorded", code, 0)
        rows, _ = read_jsonl(decisions_path(root))
        check("one decision line", len(rows), 1)
        record = rows[0]
        check("with an allocated id", record["decision_id"], "DEC-0001")
        check("the function_key comes off the candidate, not the keyboard",
              record["function_key"], "src/parse.c::parse_tlv_record::0")
        check("so does the content_hash", record["content_hash"], "fbb8544c6c43791a")
        check("the rule id and cwe too",
              (record["rule_id"], record["cwe"]), ("MEM-002", "CWE-787"))
        check("and the final verdict comes off the ARB record",
              record["final_verdict"], "VULNERABLE")
        check("the run is named", record["run_id"], "2026-09-19T04-31-46Z")
        check("a confirmation carries no reason code", record["reason_code"], None)
        check("the snapshot carries the context the sample will need",
              (record["snapshot"]["context_profile"],
               record["snapshot"]["context_sha256"],
               record["snapshot"]["localized_line"],
               record["snapshot"]["commit"]),
              ("default-v1", "8084e2b7", 8, "c74df89a"))
        check("stage 1's .gitignore carving out ledger/ draws no warning",
              "WARNING" in out, False)

        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0003",
             "--author", "a@example.com", "--reason", "looks real"], bundle)
        check("a decision on an unadjudicated candidate is refused",
              code, EXIT_UNADJUDICATED)
        check("and the refusal cites §9 rule 3", "§9 rule 3" in message, True)
        check("and names both stage 4 artefacts it looked for",
              ("findings/CAND-0003.json" in message
               and "ARB-CAND-0003.json" in message), True)
        check("nothing was appended", len(_lines(decisions_path(root))), 1)

        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-9999",
             "--author", "a@example.com"], bundle)
        check("a decision on a candidate that does not exist is a usage error",
              code, EXIT_USAGE)

        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason", "clamped upstream"], bundle)
        check("a rejection with no reason code is refused", code, EXIT_REFUSED)
        check("and the refusal lists the codes",
              "FP-GUARDED" in message and "FP-TRUSTED" in message, True)

        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason-code", "FP-MADE-UP",
             "--reason", "clamped upstream"], bundle)
        check("an invented reason code is refused", code, EXIT_REFUSED)

        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason-code", "FP-ACCEPTED",
             "--reason", "we live with it"], bundle)
        check("FP-ACCEPTED cannot reject: it says the defect is real", code, EXIT_REFUSED)
        check("and the refusal says so rather than 'unknown code'",
              "does not mean" in message or "says the opposite" in message, True)

        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason-code", "fp-guarded",
             "--reason", "bounds check at parse.c:14"], bundle)
        check("a lower-case code is normalised rather than refused", code, 0)
        rows, _ = read_jsonl(decisions_path(root))
        check("and stored upper-case", rows[-1]["reason_code"], "FP-GUARDED")

        code, out, message = _invoke(
            ["needs-info", "--root", root, "--candidate", "CAND-0002",
             "--author", "a@example.com"], bundle)
        check("needs-info with no reason is refused", code, EXIT_REFUSED)

        code, out, message = _invoke(
            ["needs-info", "--root", root, "--candidate", "CAND-0002",
             "--author", "a@example.com", "--reason", "need the caller"], bundle)
        check("needs-info with one is recorded", code, 0)

        # latest-wins, without the earlier line going anywhere
        before = len(_lines(decisions_path(root)))
        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0002",
             "--author", "b@example.com", "--reason", "caller passes wire length"],
            bundle)
        check("a later decision on the same candidate appends", code, 0)
        check("the trail grows rather than being rewritten",
              len(_lines(decisions_path(root))), before + 1)
        check("and the tool says what it superseded", "supersedes DEC-" in out, True)
        rows, _ = read_jsonl(decisions_path(root))
        standing, superseded = latest_by_candidate(rows)
        check("the newest decision stands",
              [r["decision"] for r in standing.values()
               if r["candidate_id"] == "CAND-0002"], ["confirmed"])
        check("the older one is superseded, not lost",
              [s["decision"] for s in superseded], ["needs_info"])

        # The arbiter only sees what queue.json sends it, so most adjudicated
        # findings carry a validator verdict and NO ARB record. CAND-0004 is one
        # of those, and every decision recorded on it above went through the
        # finding rather than an arbitration.
        by_candidate = dict((r["candidate_id"], r) for r in rows)
        check("a validator verdict with no arbitration is an adjudication",
              by_candidate["CAND-0004"]["decision"], "rejected")
        check("and the verdict comes off the finding",
              by_candidate["CAND-0004"]["final_verdict"], "NOT_VULNERABLE")
        check("with the record saying which artefact carried it",
              by_candidate["CAND-0004"]["snapshot"]["adjudicated_by"], "finding")
        check("and the severity the validator gave it",
              by_candidate["CAND-0004"]["snapshot"]["severity"], "medium")
        check("while an arbitrated candidate says so, and takes the arbiter's "
              "severity",
              (by_candidate["CAND-0001"]["snapshot"]["adjudicated_by"],
               by_candidate["CAND-0001"]["snapshot"]["severity"]),
              ("arbitration", "high"))

    # ---- FP-WFS-CLEAN: one rule's code ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason-code", "FP-WFS-CLEAN",
             "--reason", "read it all, nothing wrong"], bundle)
        check("FP-WFS-CLEAN is refused on a candidate no MEM-WFS verdict touches",
              (code, "MEM-WFS whole-function sweep and nothing else" in message),
              (EXIT_REFUSED, True))
        check("and nothing was appended", os.path.isfile(decisions_path(root)), False)
        append_jsonl(decisions_path(root), {
            "schema_version": 1, "decision_id": "DEC-0001", "at": "2026-09-19T00:00:00Z",
            "author": "a@example.com", "run_id": "2026-09-19T04-31-46Z",
            "candidate_id": "CAND-0004", "function_key": "src/parse.c::handle_conn::0",
            "content_hash": "f81682d7bcfeac28", "rule_id": "MEM-003",
            "decision": "rejected", "reason_code": "FP-WFS-CLEAN",
            "reason": "read it all", "snapshot": {"rule_ids": ["MEM-002", "MEM-003"]}})
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("check reports one stored on a record of another rule",
              (code, "rejects a MEM-003 decision with FP-WFS-CLEAN" in out),
              (EXIT_REFUSED, True))

    with tempfile.TemporaryDirectory() as tmp:
        # A MEM-WFS candidate, in a copy of the fixture rather than the fixture:
        # status and export counts elsewhere are pinned to its four candidates.
        root = _fixture(tmp)
        review = os.path.join(root, ".security-review")
        path = os.path.join(review, "candidates", "memory-safety.json")
        with open(path, encoding="utf-8") as fh:
            records = json.load(fh)
        records.append({"candidate_id": "CAND-0005", "category": "memory-safety",
                        "rule_id": "MEM-WFS", "cwe": "CWE-119", "language": "c",
                        "file": "src/parse.c", "line": 12,
                        "function_id": "src/parse.c::handle_conn::0@f81682d7bcfeac28",
                        "sink_text": "int handle_conn(int fd)"})
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh)
        with open(os.path.join(review, "findings", "CAND-0005.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": "CAND-0005", "rule_id": "MEM-WFS",
                       "verdict": "NOT_VULNERABLE", "confidence": "high"}, fh)
        real_bundle = os.path.dirname(_HERE)
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0005",
             "--author", "a@example.com", "--reason-code", "fp-wfs-clean",
             "--reason", "seven answers, each at its line"], real_bundle)
        check("FP-WFS-CLEAN is accepted on a MEM-WFS candidate", (code, message), (0, ""))
        rows, _ = read_jsonl(decisions_path(root))
        check("and recorded with the rules the adjudication was filed under",
              (rows[-1]["reason_code"], rows[-1]["snapshot"]["rule_ids"]),
              ("FP-WFS-CLEAN", ["MEM-WFS"]))
        # A MEM-WFS verdict derived under another rule's candidate id: the
        # finding is the whole-function pass even though the candidate is not.
        with open(os.path.join(review, "findings", "CAND-0004.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": "CAND-0004", "rule_id": "MEM-WFS",
                       "derived_from": "CAND-0004", "verdict": "NOT_VULNERABLE"}, fh)
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason-code", "FP-WFS-CLEAN",
             "--reason", "the derived sweep found nothing"], real_bundle)
        check("and on a MEM-WFS verdict filed under another rule's candidate",
              (code, message), (0, ""))
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("both pass check", "FP-WFS-CLEAN" in out, False)

    # ---- pending: what is left for a person, read off the records ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)

        def pending():
            code, out, message = _invoke(["pending", "--root", root, "--json"], bundle)
            return code, json.loads(out) if out else message

        code, got = pending()
        check("pending counts the fixture's adjudicated candidates by verdict",
              (code, got["by_verdict"], got["review_set"], got["unadjudicated"]),
              (0, {"VULNERABLE": 2, "NOT_VULNERABLE": 1}, 2, ["CAND-0003"]))
        check("and its one dismissal is validator-only",
              (got["not_vulnerable"]["total"], got["not_vulnerable"]["validator_only"],
               got["not_vulnerable"]["upheld"], got["not_vulnerable"]["overturned"]),
              (1, 1, 0, []))
        check("pending writes nothing", os.path.isdir(ledger_dir(root)), False)

        review = os.path.join(root, ".security-review")
        with open(os.path.join(review, "findings", "CAND-0004.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": "CAND-0004", "rule_id": "MEM-003",
                       "verdict": "VULNERABLE"}, fh)
        with open(os.path.join(review, "arbitration", "ARB-CAND-0004.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": "CAND-0004", "arbitration": "OVERTURNED",
                       "final_verdict": "NOT_VULNERABLE"}, fh)
        with open(os.path.join(review, "findings", "CAND-0003.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": "CAND-0003", "rule_id": "INJ-002",
                       "verdict": "VULNERABLE"}, fh)
        with open(os.path.join(review, "arbitration", "queue.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"queue": [{"candidate_id": "CAND-0003"}]}, fh)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "len is unbounded"], bundle)
        code, got = pending()
        check("an arbiter's overturn to NOT_VULNERABLE is named with what it overturned",
              got["not_vulnerable"]["overturned"],
              [{"candidate_id": "CAND-0004", "from": "VULNERABLE"}])
        check("a queued finding with no ARB record awaits the arbiter",
              got["awaiting_arbiter"], ["CAND-0003"])
        check("and a candidate decided in this run is no longer pending",
              (got["decided_this_run"], got["by_verdict"]),
              (1, {"VULNERABLE": 1, "NOT_VULNERABLE": 1}))
        code, out, message = _invoke(["pending", "--root", root], bundle)
        check("the text form names the overturned id",
              (code, "CAND-0004 (from VULNERABLE)" in out), (0, True))
        # A candidate file that cannot be read makes every count short, so the
        # command says so in its exit status and not only in a trailing line.
        broken = os.path.join(review, "candidates", "zz-broken.json")
        with open(broken, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        code, got = pending()
        check("an unreadable candidate file is a problem and a refusal, in --json",
              (code, len(got["problems"])), (EXIT_REFUSED, 1))
        code, out, message = _invoke(["pending", "--root", root], bundle)
        check("and in the text form",
              (code, "problem:" in out), (EXIT_REFUSED, True))
        os.remove(broken)

    # ---- suppressions ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        key = "src/parse.c::parse_tlv_record::0"
        soon = stamp(now_utc() + datetime.timedelta(days=30))[:10]
        far = stamp(now_utc() + datetime.timedelta(days=900))[:10]
        past = stamp(now_utc() - datetime.timedelta(days=5))[:10]

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", key, "--rule", "MEM-002",
             "--author", "a@example.com", "--reason", "ISSUE-441"], bundle)
        check("a suppression with no expiry is refused", code, EXIT_REFUSED)
        check("and the refusal says there is no permanent suppression",
              "no permanent suppression" in message, True)
        check("nothing was written", os.path.isfile(suppressions_path(root)), False)

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", key, "--rule", "MEM-002",
             "--author", "a@example.com", "--reason", "ISSUE-441",
             "--expires", past], bundle)
        check("an expiry already in the past is refused", code, EXIT_USAGE)

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", key, "--rule", "MEM-002",
             "--author", "a@example.com", "--reason", "ISSUE-441",
             "--expires", far], bundle)
        check("an expiry past --max-expiry-days is refused", code, EXIT_REFUSED)
        check("and the refusal names the limit", "180" in message, True)

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", key, "--rule", "MEM-002",
             "--author", "a@example.com", "--reason", "ISSUE-441",
             "--expires", far, "--force"], bundle)
        check("--force allows it", code, 0)
        rows, _ = read_jsonl(suppressions_path(root))
        check("and records that it was forced", rows[0]["forced"], True)
        check("with the limit it was forced past", rows[0]["max_expiry_days"], 180)
        check("the hash is measured from the extract, not asserted",
              rows[0]["content_hash_at_creation"], "fbb8544c6c43791a")

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", "src/parse.c::nope::0",
             "--rule", "MEM-002", "--author", "a@example.com", "--reason", "x",
             "--expires", soon], bundle)
        check("a function_key the corpus does not hold is refused", code, EXIT_USAGE)

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", key, "--rule", "MEM-99",
             "--author", "a@example.com", "--reason", "x", "--expires", soon], bundle)
        check("a rule id that cannot exist is refused", code, EXIT_USAGE)

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", "src/parse.c::f",
             "--rule", "MEM-002", "--author", "a@example.com", "--reason", "x",
             "--expires", soon], bundle)
        check("a malformed function_key is refused", code, EXIT_USAGE)

        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key",
             "src/parse.c::handle_conn::0", "--rule", "MEM-003",
             "--author", "b@example.com", "--reason", "constant table",
             "--expires", soon], bundle)
        check("an ordinary suppression is recorded", code, 0)
        check("and says the function is still counted",
              "still counted" in out, True)
        rows, _ = read_jsonl(suppressions_path(root))
        check("ids are allocated in order",
              [r["suppression_id"] for r in rows], ["SUP-0001", "SUP-0002"])
        check("and forced is false when nothing was forced", rows[1]["forced"], False)

        # ---- revocation appends ---- #
        before_bytes = _raw(suppressions_path(root))
        code, out, message = _invoke(
            ["revoke", "--root", root, "--suppression", "SUP-0002",
             "--author", "a@example.com", "--reason", "the clamp came out"], bundle)
        check("a revocation is recorded", code, 0)
        check("exactly one line was added",
              len(_lines(suppressions_path(root))) - len(before_bytes.splitlines()), 1)
        ledger = load_ledger(root)
        check("the ending lives in a revocation record",
              (ledger["revocations"][0]["suppression_id"],
               ledger["revocations"][0]["author"]),
              ("SUP-0002", "a@example.com"))
        # The half that used to be missing. enrich_candidates.py and
        # export_sarif.py read only this field when it was added, and without it
        # the revoked suppression went on suppressing the candidate until its
        # expiry. Both honour the revocation line now; the field is the
        # contract's all the same.
        revoked_record = ledger["suppressions"][1]
        check("and revoked_at is set on the suppression's own line, where contract "
              "§8 puts it",
              (bool(revoked_record["revoked_at"]), revoked_record["revoked_by"],
               revoked_record["revoked_reason"]),
              (True, "a@example.com", "the clamp came out"))
        untouched = [json.loads(line) for line in before_bytes.decode().splitlines()]
        check("every other field on that line is exactly as it was written",
              dict((k, v) for k, v in revoked_record.items()
                   if k in untouched[1] and k not in ("revoked_at",)),
              dict((k, v) for k, v in untouched[1].items()
                   if k not in ("revoked_at",)))
        check("and the suppression that was not revoked is byte-identical",
              _lines(suppressions_path(root))[0], before_bytes.decode().splitlines(True)[0])
        states = dict((s["suppression_id"], s)
                      for s in resolve_suppressions(ledger, load_corpus(root),
                                                    now_utc()))
        check("the folded view reports it revoked", states["SUP-0002"]["state"],
              "revoked")

        code, out, message = _invoke(
            ["revoke", "--root", root, "--suppression", "SUP-0002",
             "--author", "a@example.com", "--reason", "again"], bundle)
        check("revoking twice is refused", code, EXIT_REFUSED)
        code, out, message = _invoke(
            ["revoke", "--root", root, "--suppression", "SUP-9999",
             "--author", "a@example.com", "--reason", "x"], bundle)
        check("revoking something that is not there is a usage error", code, EXIT_USAGE)
        code, out, message = _invoke(
            ["revoke", "--root", root, "--suppression", "SUP-0001",
             "--author", "a@example.com"], bundle)
        check("revoking with no reason is refused", code, EXIT_REFUSED)

        # ---- staleness ---- #
        states = dict((s["suppression_id"], s)
                      for s in resolve_suppressions(load_ledger(root),
                                                    load_corpus(root),
                                                    now_utc()))
        check("an unchanged function keeps its suppression active",
              states["SUP-0001"]["state"], "active")
        functions_path = os.path.join(run_dir(root), "extract", "functions.jsonl")
        text = open(functions_path, encoding="utf-8").read()
        with open(functions_path, "w", encoding="utf-8") as fh:
            fh.write(text.replace("fbb8544c6c43791a", "0000111122223333"))
        states = dict((s["suppression_id"], s)
                      for s in resolve_suppressions(load_ledger(root),
                                                    load_corpus(root),
                                                    now_utc()))
        check("an edited body makes the suppression stale",
              states["SUP-0001"]["state"], "stale")
        check("and staleness says what changed",
              ("created against fbb8544c6c43791a" in states["SUP-0001"]["stale_reason"]
               and "0000111122223333" in states["SUP-0001"]["stale_reason"]), True)
        check("a forced suppression is stale like any other - rule 3 has no flag",
              states["SUP-0001"]["forced"], True)

        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        payload = json.loads(out)
        check("status reports it stale", payload["suppressions"]["by_state"]["stale"], 1)
        check("and no longer active",
              payload["suppressions"]["by_state"].get("active", 0), 0)

        # A renamed or deleted function cannot be shown unchanged either.
        with open(functions_path, "w", encoding="utf-8") as fh:
            fh.write("")
        states = dict((s["suppression_id"], s)
                      for s in resolve_suppressions(load_ledger(root),
                                                    load_corpus(root),
                                                    now_utc()))
        check("a function that left the corpus makes its suppression stale too",
              states["SUP-0001"]["state"], "stale")
        check("with the reason saying so",
              "not in this run's extract" in states["SUP-0001"]["stale_reason"], True)

        with open(functions_path, "w", encoding="utf-8") as fh:
            fh.write(text)
        code, out, message = _invoke(["status", "--root", root], bundle)
        check("the terminal report leads with stale suppressions",
              out.index("STALE SUPPRESSIONS") < out.index("ACTIVE SUPPRESSIONS"), True)
        check("it marks the forced one", "[forced]" in out, True)
        check("it groups active suppressions by expiry horizon",
              "beyond 90 days" in out, True)
        check("it names the revoked one", "REVOKED" in out, True)
        check("and it restates rule 4 every time",
              "still extracted" in out and "never from coverage" in out, True)

    # ---- the one way past rule 2 that records nothing of its own ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        far = stamp(now_utc() + datetime.timedelta(days=900))[:10]
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", "src/app.py::run_cmd::0",
             "--rule", "INJ-002", "--author", "a@example.com", "--reason", "later",
             "--expires", far, "--max-expiry-days", "3650"], bundle)
        check("raising --max-expiry-days gets past the refusal", code, 0)
        rows, _ = read_jsonl(suppressions_path(root))
        check("and records forced: false, because nothing was forced",
              rows[0]["forced"], False)
        check("but records the ceiling it was created under",
              rows[0]["max_expiry_days"], 3650)
        states = dict((s["suppression_id"], s)
                      for s in resolve_suppressions(load_ledger(root),
                                                    load_corpus(root),
                                                    now_utc()))
        check("the folded view measures the span against the default, not the flag",
              states["SUP-0001"]["long_unforced"], True)
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("check reports a long expiry that was never forced",
              (code, "was never forced" in out), (EXIT_REFUSED, True))
        code, out, message = _invoke(["status", "--root", root], bundle)
        check("and status marks it in the listing",
              "past the default 180, never forced" in out, True)

        # Lowering the ceiling is the direction nobody has to be told about.
        soon = stamp(now_utc() + datetime.timedelta(days=30))[:10]
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key",
             "src/parse.c::handle_conn::0", "--rule", "MEM-003",
             "--author", "a@example.com", "--reason", "x", "--expires", soon,
             "--max-expiry-days", "60"], bundle)
        check("a tightened ceiling is honoured", code, 0)
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key",
             "src/parse.c::parse_tlv_record::0", "--rule", "MEM-002",
             "--author", "a@example.com", "--reason", "x", "--expires", far,
             "--max-expiry-days", "60"], bundle)
        check("and refuses past its own lower limit", code, EXIT_REFUSED)
        states = dict((s["suppression_id"], s)
                      for s in resolve_suppressions(load_ledger(root),
                                                    load_corpus(root),
                                                    now_utc()))
        check("a 30-day suppression is not marked whatever the ceiling was",
              states["SUP-0002"]["long_unforced"], False)

    # ---- export ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        for candidate in ("CAND-0001", "CAND-0002"):
            _invoke(["confirm", "--root", root, "--candidate", candidate,
                     "--author", "a@example.com", "--reason", "len is unbounded"],
                    bundle)
        _invoke(["reject", "--root", root, "--candidate", "CAND-0004",
                 "--author", "a@example.com", "--reason-code", "FP-GUARDED",
                 "--reason", "clamped at parse.c:14"], bundle)

        out_path = os.path.join(ledger_dir(root), "training", "export.jsonl")
        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path], bundle)
        check("export writes", code, 0)
        samples, _ = read_jsonl(out_path)
        check("two candidates on one body and cwe make ONE sample", len(samples), 2)
        check("and the tool says it folded one", "1 duplicate(s) folded" in out, True)
        by_label = dict((s["label"], s) for s in samples)
        check("a confirmation is labelled vulnerable",
              sorted(by_label), ["not_vulnerable", "vulnerable"])
        check("with human-confirmed provenance",
              by_label["vulnerable"]["provenance"], "human-confirmed")
        check("a rejection is human-rejected",
              by_label["not_vulnerable"]["provenance"], "human-rejected")
        check("and carries the code it was rejected under",
              by_label["not_vulnerable"]["reason_code"], "FP-GUARDED")
        check("the sample carries the context the score was computed over",
              (by_label["vulnerable"]["context_profile"],
               by_label["vulnerable"]["context_sha256"]),
              ("default-v1", "8084e2b7"))
        check("ids are allocated in order",
              [s["sample_id"] for s in samples], ["SMP-0001", "SMP-0002"])
        check("a decision made after the freeze postdates it",
              by_label["vulnerable"]["postdates_eval_freeze"], True)
        check("and the sample names the freeze it was measured against",
              by_label["vulnerable"]["eval_freeze"]["id"], "evalset-v1")

        # A decision older than the freeze, appended straight to the trail. It
        # is about the body handle_conn had in 2020: a confirmation of today's
        # body, which CAND-0004's rejection covers, is one body labelled both
        # ways, and the export leaves that out.
        old = dict(json.loads(_lines(decisions_path(root))[0]))
        old.update({"decision_id": "DEC-9001", "at": "2020-01-01T00:00:00Z",
                    "candidate_id": "CAND-OLD", "cwe": "CWE-125",
                    "function_key": "src/parse.c::handle_conn::0",
                    "content_hash": "0f81682d7bcfeac2"})
        append_jsonl(decisions_path(root), old)
        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path], bundle)
        samples, _ = read_jsonl(out_path)
        old_sample = [s for s in samples if s["cwe"] == "CWE-125"][0]
        check("a decision predating the freeze is marked",
              old_sample["postdates_eval_freeze"], False)
        check("and sorts first, so ids follow the decision order",
              old_sample["sample_id"], "SMP-0001")

        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path,
             "--label-filter", "vulnerable"], bundle)
        samples, _ = read_jsonl(out_path)
        check("--label-filter exports one side only",
              sorted(set(s["label"] for s in samples)), ["vulnerable"])

        # needs_info is not a label
        _invoke(["needs-info", "--root", root, "--candidate", "CAND-0002",
                 "--author", "a@example.com", "--reason", "need the caller"], bundle)
        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path], bundle)
        check("a needs_info decision is not a sample",
              "1 needs_info decision(s) are not samples" in out, True)

        # a rejection with no code, hand-appended, blocks the export
        broken = dict(json.loads(_lines(decisions_path(root))[0]))
        broken.update({"decision_id": "DEC-9002", "at": "2026-02-01T00:00:00Z",
                       "candidate_id": "CAND-BAD", "decision": "rejected",
                       "reason_code": None, "reason": "no code",
                       "function_key": "src/app.py::run_cmd::0",
                       "content_hash": "fb7eb9b971430def", "cwe": "CWE-78"})
        append_jsonl(decisions_path(root), broken)
        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path], bundle)
        check("export refuses a rejection with no reason code", code, EXIT_REFUSED)
        check("and names the decision and the fix",
              "DEC-9002" in message and "--reason-code" in message, True)
        corrected = dict(broken)
        corrected.update({"decision_id": "DEC-9003", "at": "2026-02-02T00:00:00Z",
                          "reason_code": "FP-TRUSTED", "reason": "internal only"})
        append_jsonl(decisions_path(root), corrected)
        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path], bundle)
        check("appending a correction unblocks it - the trail is never edited",
              code, 0)

        # no evaluation set registered at all
        empty_bundle = _bundle(os.path.join(tmp, "b2"), frozen_at=None)
        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path], empty_bundle)
        samples, _ = read_jsonl(out_path)
        check("with nothing frozen, the flag is null rather than a guess",
              sorted(set(str(s["postdates_eval_freeze"]) for s in samples)), ["None"])
        check("and export says why", "no evaluation set is registered" in out, True)

        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com", "--reason", "fixed",
             "--fix-commit", "deadbeef"], bundle)
        code, out, message = _invoke(
            ["export", "--root", root, "--out", out_path], bundle)
        samples, _ = read_jsonl(out_path)
        fixed = [s for s in samples if s["function_key"].endswith("parse_tlv_record::0")]
        check("a confirmation with a fix commit exports as verified-fix",
              sorted(set(s["provenance"] for s in fixed)), ["verified-fix"])

    # ---- §9 rule 2: nothing this tool writes lands outside .security-review ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
        os.makedirs(os.path.join(root, "src"), exist_ok=True)
        into_tree = os.path.join(root, "src", "samples.jsonl")
        code, out, message = _invoke(
            ["export", "--root", root, "--out", into_tree], bundle)
        check("an --out inside the scanned tree is refused", code, EXIT_USAGE)
        check("and the refusal cites §9 rule 2", "§9 rule 2" in message, True)
        check("and nothing was written there", os.path.exists(into_tree), False)

        outside = os.path.join(tmp, "escaped.jsonl")
        code, out, message = _invoke(
            ["export", "--root", root, "--out", outside], bundle)
        check("an --out anywhere else on the filesystem is refused too",
              (code, os.path.exists(outside)), (EXIT_USAGE, False))

        climb = os.path.join(run_dir(root), "ledger", "..", "..", "..", "up.jsonl")
        code, out, message = _invoke(
            ["export", "--root", root, "--out", climb], bundle)
        check("and so is one that climbs out with ..", code, EXIT_USAGE)

        # A symlink planted in the run directory does not widen it either.
        link = os.path.join(run_dir(root), "ledger", "elsewhere")
        try:
            os.symlink(tmp, link)
        except (OSError, NotImplementedError):
            link = None
        if link:
            code, out, message = _invoke(
                ["export", "--root", root, "--out",
                 os.path.join(link, "through-a-link.jsonl")], bundle)
            check("nor one that leaves through a symlink", code, EXIT_USAGE)
            check("and the link led nowhere",
                  os.path.exists(os.path.join(tmp, "through-a-link.jsonl")), False)

        code, out, message = _invoke(["export", "--root", root], bundle)
        check("the default out is inside the run directory and is written",
              (code, os.path.isfile(samples_path(root))), (0, True))

    # ---- an extract that is there but cannot be read whole ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        soon = stamp(now_utc() + datetime.timedelta(days=30))[:10]
        _invoke(["suppress", "--root", root, "--function-key",
                 "src/parse.c::handle_conn::0", "--rule", "MEM-003",
                 "--author", "a@example.com", "--reason", "constant table",
                 "--expires", soon], bundle)
        functions_path = os.path.join(run_dir(root), "extract", "functions.jsonl")
        text = open(functions_path, encoding="utf-8").read()
        # Records this tool refuses to read rather than guess at. The corpus is
        # then EMPTY, and an empty corpus used to say every suppression was
        # stale because "the function was renamed, moved or removed" - a sentence
        # about a repository nobody measured.
        with open(functions_path, "w", encoding="utf-8") as fh:
            fh.write(text.replace('"schema_version": 1', '"schema_version": 2'))
        states = dict((s["suppression_id"], s)
                      for s in resolve_suppressions(load_ledger(root),
                                                    load_corpus(root), now_utc()))
        check("an unreadable extract leaves staleness unverified, not stale",
              states["SUP-0001"]["state"], "unverified")
        check("and says the absence proves nothing",
              "proves nothing" in (states["SUP-0001"]["unverified_reason"] or ""),
              True)
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        payload = json.loads(out)
        check("status calls the corpus incomplete rather than empty",
              (payload["corpus_measured"], payload["corpus_complete"]),
              (True, False))
        check("and carries the lines it could not read",
              len(payload["corpus_problems"]), 3)
        code, out, message = _invoke(["status", "--root", root], bundle)
        check("the terminal report says the corpus is incomplete",
              "INCOMPLETE" in out, True)
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", "src/app.py::run_cmd::0",
             "--rule", "INJ-002", "--author", "a@example.com", "--reason", "x",
             "--expires", soon], bundle)
        check("and a new suppression is not refused as 'not in the extract'",
              (code, "could not be read" in message), (EXIT_USAGE, True))
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("check fails while rule 3 cannot be measured",
              (code, "contract §8 rule 3" in out), (EXIT_REFUSED, True))

        # A function whose extract record carries no content_hash cannot be
        # suppressed: the record would never compare equal to anything.
        with open(functions_path, "w", encoding="utf-8") as fh:
            fh.write(text.replace('"content_hash": "fb7eb9b971430def"',
                                  '"content_hash": null'))
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key", "src/app.py::run_cmd::0",
             "--rule", "INJ-002", "--author", "a@example.com", "--reason", "x",
             "--expires", soon], bundle)
        check("a function with no measured hash cannot be suppressed",
              (code, "suppress nothing" in message), (EXIT_USAGE, True))

    # ---- bounded reads: this tool's inputs come out of the scanned tree ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        path = decisions_path(root)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"decision_id": "DEC-0001", "at": "2026-09-19T00:00:00Z", '
                     '"author": "a@example.com", "candidate_id": "CAND-0001", '
                     '"function_key": "src/parse.c::parse_tlv_record::0", '
                     '"content_hash": "fbb8544c6c43791a", "decision": "confirmed", '
                     '"reason": "%s"}\n' % ("x" * (MAX_LINE_BYTES + 64)))
            fh.write('{"decision_id": "DEC-0002", "at": "2026-09-19T00:00:01Z", '
                     '"author": "a@example.com", "candidate_id": "CAND-0002", '
                     '"function_key": "src/parse.c::handle_conn::0", '
                     '"content_hash": "f81682d7bcfeac28", "decision": "confirmed"}\n')
        rows, problems = read_jsonl(path)
        check("a line past the bound is not read", [r["decision_id"] for r in rows],
              ["DEC-0002"])
        check("it is reported with its number and its size, not dropped",
              (len(problems), problems[0][1], "past the %d-byte line limit"
               % MAX_LINE_BYTES in problems[0][2]), (1, 1, True))
        check("and the line after it keeps its own number", rows[0]["__line"], 2)
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("check fails on it rather than counting a shorter ledger",
              (code, "was not read" in out), (EXIT_REFUSED, True))

        big = os.path.join(run_dir(root), "candidates", "huge.json")
        block = "y" * (1024 * 1024)
        with open(big, "w", encoding="utf-8") as fh:
            fh.write('[{"candidate_id": "CAND-PAD", "pad": "')
            for _ in range(MAX_JSON_BYTES // len(block) + 1):
                fh.write(block)
            fh.write('"}]')
        document, why = read_json(big)
        check("a JSON document past the bound is refused rather than loaded",
              (document, "was not read" in (why or "")), (None, True))

    # ---- ids are allocated under the lock that writes them ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = _fixture(tmp)
        path = decisions_path(root)
        for _ in range(3):
            append_jsonl(path, {"schema_version": 1, "decision_id": None,
                                "decision": "confirmed"},
                         allocate=("decision_id", "DEC"))
        rows, _ = read_jsonl(path)
        check("each append allocates the next id from the file as it stands",
              [r["decision_id"] for r in rows], ["DEC-0001", "DEC-0002", "DEC-0003"])
        with open(path, "rb+") as fh:             # an editor ate the final newline
            fh.truncate(os.path.getsize(path) - 1)
        append_jsonl(path, {"schema_version": 1, "decision_id": None,
                            "decision": "confirmed"},
                     allocate=("decision_id", "DEC"))
        rows, problems = read_jsonl(path)
        check("an append after a line with no newline starts a line of its own",
              ([r["decision_id"] for r in rows], problems),
              (["DEC-0001", "DEC-0002", "DEC-0003", "DEC-0004"], []))

    # ---- needs_info is the ONE skip the export is allowed to make silently ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
        append_jsonl(decisions_path(root), {
            "schema_version": 1, "decision_id": "DEC-9100",
            "at": "2026-03-01T00:00:00Z", "author": "a@example.com",
            "candidate_id": "CAND-ODD",
            "function_key": "src/parse.c::handle_conn::0",
            "content_hash": "f81682d7bcfeac28", "decision": "probably",
            "cwe": "CWE-125"})
        code, out, message = _invoke(["export", "--root", root], bundle)
        samples, _ = read_jsonl(samples_path(root))
        check("a decision value this tool does not know is not exported",
              len(samples), 1)
        check("and the export says how many it left behind, rather than dropping "
              "them quietly",
              ("1 standing decision(s) carry a decision value" in out
               and "probably" in out), True)
        code, out, message = _invoke(["status", "--root", root], bundle)
        check("status names it too, so the three counts still add up to standing",
              ("unrecognised" in out and "'probably' 1" in out), True)
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        payload = json.loads(out)
        check("and the json carries it as its own count",
              payload["decisions"]["unrecognised_decisions"], {"probably": 1})
        check("the standing total still equals the sum of every bucket",
              sum(payload["decisions"]["by_decision"].values()),
              payload["decisions"]["standing"])
        code, out, message = _invoke(
            ["export", "--root", root, "--label-filter", "not_vulnerable"], bundle)
        check("and --label-filter says what it left out",
              "left out by --label-filter" in out, True)

    # ---- check ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
        _invoke(["suppress", "--root", root, "--function-key",
                 "src/parse.c::handle_conn::0", "--rule", "MEM-003",
                 "--author", "a@example.com", "--reason", "constant table",
                 "--expires", stamp(now_utc() + datetime.timedelta(days=30))[:10]],
                bundle)
        _invoke(["export", "--root", root], bundle)
        # The fixture contract holds only three of the fourteen codes, so check it
        # against the real one; the fixture's job was the parser, not the drift.
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("a ledger this tool wrote passes check", (code, "0 problem(s)" in out),
              (0, True))

        with open(decisions_path(root), "a", encoding="utf-8") as fh:
            fh.write('{"decision_id": "DEC-0002", "decision": "confirmed"\n')
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("a truncated JSON line is caught", code, EXIT_REFUSED)
        check("and the line number is named", "decisions.jsonl:2:" in out, True)

    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        append_jsonl(decisions_path(root), {
            "schema_version": 1, "decision_id": "DEC-0001", "at": "2026-09-19T00:00:00Z",
            "author": "a@example.com", "candidate_id": "CAND-0001",
            "function_key": "src/parse.c::parse_tlv_record::0",
            "content_hash": "fbb8544c6c43791a", "decision": "rejected",
            "reason_code": None})
        append_jsonl(decisions_path(root), {
            "schema_version": 1, "decision_id": "DEC-0001", "at": "nope",
            "author": "a@example.com", "candidate_id": "CAND-0002",
            "function_key": "src/parse.c::handle_conn::0",
            "content_hash": "zz", "decision": "maybe", "reason_code": "FP-GUARDED"})
        append_jsonl(decisions_path(root), {
            "schema_version": 4, "decision_id": "DEC-0003", "decision": "confirmed"})
        append_jsonl(suppressions_path(root), {
            "schema_version": 1, "record_type": "suppression",
            "suppression_id": "SUP-0001", "created_at": "2026-01-01T00:00:00Z",
            "author": "a@example.com", "function_key": "src/parse.c::f::0",
            "rule_id": "MEM-002", "content_hash_at_creation": "fbb8544c6c43791a",
            "reason": "x", "expires_at": "2030-01-01T00:00:00Z",
            "forced": False, "max_expiry_days": 180})
        append_jsonl(suppressions_path(root), {
            "schema_version": 1, "record_type": "revocation",
            "suppression_id": "SUP-9999", "revoked_at": "2026-02-01T00:00:00Z",
            "author": "a@example.com", "reason": "x"})
        # A revoke does two writes. This is what the second one failing leaves:
        # the trail says revoked, the field the pipeline reads says otherwise.
        append_jsonl(suppressions_path(root), {
            "schema_version": 1, "record_type": "revocation",
            "suppression_id": "SUP-0001", "revoked_at": "2026-02-01T00:00:00Z",
            "author": "a@example.com", "reason": "the clamp came out"})
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("a malformed ledger fails check", code, EXIT_REFUSED)
        check("a rejection with no code is reported",
              "rejects with no reason_code" in out, True)
        check("an unknown decision value is reported",
              "is not one of confirmed" in out, True)
        check("a reused decision_id is reported", "reuses decision_id" in out, True)
        check("an unparseable timestamp is reported",
              "not an ISO-8601 timestamp" in out, True)
        check("a content hash of the wrong shape is reported",
              "is not sha256(body)[:16]" in out, True)
        check("a record from a newer schema is refused rather than read",
              "schema_version 4" in out, True)
        check("a reason code on a non-rejection is reported",
              "means 'why this is not a bug'" in out, True)
        check("a long expiry with forced: false is caught after the fact",
              "without forced: true" in out, True)
        check("a revocation of a suppression that is not there is reported",
              "which is not a suppression in this file" in out, True)
        check("a revocation whose suppression still says revoked_at: null is "
              "reported - the line contradicts its own trail",
              "still carries revoked_at: null" in out, True)

    # ---- a revoke that stopped between its two writes ---- #
    # `check` says to run the revoke again, and the revoke refused that as a
    # second revocation: the one command the message named could not finish it.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        soon = stamp(now_utc() + datetime.timedelta(days=30))[:10]
        for rule in ("MEM-003", "MEM-004"):
            _invoke(["suppress", "--root", root, "--function-key",
                     "src/parse.c::handle_conn::0", "--rule", rule,
                     "--author", "a@example.com", "--reason", "constant table",
                     "--expires", soon], bundle)
        append_jsonl(suppressions_path(root), {
            "schema_version": 1, "record_type": "revocation",
            "suppression_id": "SUP-0001", "revoked_at": "2026-09-10T00:00:00Z",
            "author": "a@example.com", "reason": "the clamp came out"})
        append_jsonl(suppressions_path(root), {
            "schema_version": 1, "record_type": "revocation",
            "suppression_id": "SUP-0002", "revoked_at": "2026-09-10T00:00:00Z",
            "author": "a@example.com"})
        before = len(_lines(suppressions_path(root)))
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("check names the half-finished revoke and the command that finishes it",
              ("still carries revoked_at: null" in out,
               "`ledger.py revoke --suppression SUP-0001 --author <you>` again"
               in out), (True, True))
        code, out, message = _invoke(
            ["revoke", "--root", root, "--suppression", "SUP-0001",
             "--author", "b@example.com", "--reason", "finishing it"], bundle)
        check("and that command finishes it", (code, message), (EXIT_OK, ""))
        finished = load_ledger(root)["suppressions"][0]
        check("from the revocation already recorded, never from this invocation",
              (finished["revoked_at"], finished["revoked_by"],
               finished["revoked_reason"]),
              ("2026-09-10T00:00:00Z", "a@example.com", "the clamp came out"))
        check("appending nothing: one decision gets one ending",
              len(_lines(suppressions_path(root))), before)
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("and check no longer reports it",
              "revokes SUP-0001, but" in out, False)
        before_bytes = _raw(suppressions_path(root))
        code, out, message = _invoke(
            ["revoke", "--root", root, "--suppression", "SUP-0002",
             "--author", "b@example.com", "--reason", "x"], bundle)
        check("a revocation with no reason to fill the field from is refused, "
              "and nothing is written",
              (code, "has no reason" in message, _raw(suppressions_path(root))),
              (EXIT_REFUSED, True, before_bytes))

        # ---- MEM-WFS follows the function's other rules ---- #
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key",
             "src/parse.c::handle_conn::0", "--rule", "mem-wfs",
             "--author", "a@example.com", "--reason", "whole function reviewed",
             "--expires", soon], bundle)
        check("a suppression naming MEM-WFS is refused, saying what to do instead",
              (code, "Suppress the function's other rules" in message,
               _raw(suppressions_path(root))), (EXIT_USAGE, True, before_bytes))
        # One the ledger wrote before that refusal existed is still in
        # committed ledgers, and status listed it as simply active.
        older = dict(load_ledger(root)["suppressions"][0],
                     suppression_id="SUP-0003", rule_id=WFS_RULE,
                     revoked_at=None, revoked_by=None, revoked_reason=None)
        append_jsonl(suppressions_path(root), older)
        code, out, message = _invoke(["status", "--root", root], bundle)
        check("status marks a MEM-WFS record as applying only with its siblings",
              [line for line in out.splitlines() if "SUP-0003" in line][0]
              .endswith("[only while every other rule on it is suppressed]"),
              True)

    # ---- LOG-TRI is an ordinary rule to suppress ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        soon = stamp(now_utc() + datetime.timedelta(days=30))[:10]
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key",
             "src/parse.c::handle_conn::0", "--rule", "LOG-TRI",
             "--author", "a@example.com", "--reason", "ISSUE-502 reviewed by hand",
             "--expires", soon], bundle)
        check("a suppression naming LOG-TRI is accepted: it is the only candidate on "
              "its function, so nothing has to follow it", code, 0)
        rows, _ = read_jsonl(suppressions_path(root))
        check("and it is recorded under the rule it names",
              [r["rule_id"] for r in rows], ["LOG-TRI"])
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key",
             "src/parse.c::handle_conn::0", "--rule", "LOG-TR1",
             "--author", "a@example.com", "--reason", "x", "--expires", soon], bundle)
        check("LOG-TR1 cannot exist and is refused", code, EXIT_USAGE)

    # ---- the constant, against a contract that has moved on ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        code, out, message = _invoke(["check", "--root", root], bundle)
        check("a contract holding codes ledger.py does not know fails check",
              code, EXIT_REFUSED)
        check("and the drift is reported in both directions",
              ("will not accept on a rejection" in out
               and "no longer defines" in out), True)

    # ---- an ignore that swallows the ledger ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        ignore_path = os.path.join(run_dir(root), ".gitignore")
        with open(ignore_path, "w", encoding="utf-8") as fh:
            fh.write("*\n!.gitignore\n")     # stage 1's carve-out, deleted by hand
        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com", "--reason", "real"], bundle)
        check("a .gitignore that swallows the ledger is called out on the write",
              (code, "WARNING" in out and "!ledger/" in out), (0, True))
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("and `check` fails on it - the trail would not survive a clone",
              (code, "does not carve out" in out), (EXIT_REFUSED, True))
        with open(ignore_path, "w", encoding="utf-8") as fh:
            fh.write("# only the run artefacts are listed, so nothing is swallowed\n"
                     "extract/\nscores/\n")
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("an ignore that never says `*` is left alone", code, EXIT_OK)

        # Judged as git judges it. One of `!ledger`, `!ledger/` or
        # `!ledger/**` used to pass the check, and under `*` git still
        # ignores every file in the ledger with any one of them alone -
        # checked against git itself, as is every case here.
        def verdict(text):
            with open(ignore_path, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            return gitignore_problem(root)
        for text, lost in (
                ("*\n!ledger\n", "ignores ledger/decisions.jsonl."),
                ("*\n!ledger/\n", "ignores ledger/decisions.jsonl."),
                ("*\n!ledger/**\n", "ignores ledger/, and git never looks "
                                    "inside a directory it has excluded"),
                ("**\n!ledger/\n", "ignores ledger/decisions.jsonl."),
                ("!ledger/\n!ledger/**\n*\n", "line 3, `*`, ignores ledger/,"),
                # samples_path is ledger/training/samples.jsonl.
                ("*\n!ledger/\n!ledger/*\n",
                 "ignores ledger/training/samples.jsonl."),
                ("*\n!ledger/\n!ledger/**\n*.jsonl\n",
                 "line 4, `*.jsonl`, ignores ledger/decisions.jsonl."),
                ("*\n!ledger/\n!ledger/**\nledger/training/\n",
                 "line 4, `ledger/training/`, ignores ledger/training/,"),
                ("/*\n", "line 1, `/*`, ignores ledger/,"),
                ("ledger\n", "line 1, `ledger`, ignores ledger/,"),
                # A range written backwards is empty and keeps its first
                # member, so `[d-a]` is `d`.
                ("*\n!ledger/\n!ledger/**\n[d-a]ecisions.jsonl\n",
                 "line 4, `[d-a]ecisions.jsonl`, ignores "
                 "ledger/decisions.jsonl.")):
            problem = verdict(text)
            check("%r keeps the ledger out of git, and says which line" % text,
                  (problem is not None and "does not carve out" in problem
                   and lost in problem), True)
        for text in ("*\n!.gitignore\n!ledger/\n!ledger/**\n",
                     "*\n!ledger\n!ledger/**\n",
                     "*\n!ledger/**\n!ledger/\n",
                     "*  \r\n!ledger/  \r\n!ledger/**\r\n",
                     "\ufeff*\n!/ledger/\n!/ledger/**\n",
                     "*\n![l]edger/\n!**/ledger/**\n",
                     "*\n!ledger/\n!ledger/**\n\\#ledger\nsamples.json[\n",
                     # Backwards ranges git reads without complaint, which
                     # re.compile refused with a traceback out of `check`
                     # and out of every write, after its record was appended.
                     "*\n!ledger/\n!ledger/**\n[z-a]\n[a--]\n[a-\\]]x\n"
                     "[e-a]ecisions.jsonl\n",
                     "# nothing is ignored at all\n"):
            check("%r keeps the ledger" % text, verdict(text), None)
        with open(ignore_path, "wb") as fh:
            fh.write(b"*\n!ledger/\n!ledger/**\n# caf\xe9\n")
        check("a byte that is not UTF-8 is read, not a traceback",
              gitignore_problem(root), None)

    # ---- status with no run directory ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["suppress", "--root", root, "--function-key",
                 "src/parse.c::handle_conn::0", "--rule", "MEM-003",
                 "--author", "a@example.com", "--reason", "x",
                 "--expires", stamp(now_utc() + datetime.timedelta(days=10))[:10]],
                bundle)
        os.remove(os.path.join(run_dir(root), "extract", "functions.jsonl"))
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        payload = json.loads(out)
        check("with no extract, staleness is unknown rather than assumed",
              payload["suppressions"]["by_state"], {"unverified": 1})
        check("and status says the corpus was not measured",
              payload["corpus_measured"], False)
        code, out, message = _invoke(["status", "--root", root], bundle)
        check("the terminal report says nothing is suppressed meanwhile",
              "nothing is suppressed" in out, True)
        code, out, message = _invoke(
            ["suppress", "--root", root, "--function-key",
             "src/parse.c::handle_conn::0", "--rule", "MEM-003",
             "--author", "a@example.com", "--reason", "x",
             "--expires", stamp(now_utc() + datetime.timedelta(days=10))[:10]],
            bundle)
        check("and a new suppression cannot be created without a measured hash",
              code, EXIT_USAGE)

    # ---- a decision supersedes its own run's candidate, not the next run's ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "len is unbounded"], bundle)
        # Run 2. Stage 3 numbers from CAND-0001 again, and this time CAND-0001
        # is handle_conn, which the validator cleared.
        review = run_dir(root)
        with open(os.path.join(review, "run.json"), encoding="utf-8") as fh:
            run_json = json.load(fh)
        run_json["run_id"] = "2026-10-01T00-00-00Z"
        with open(os.path.join(review, "run.json"), "w", encoding="utf-8") as fh:
            json.dump(run_json, fh)
        with open(os.path.join(review, "candidates", "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump([{"candidate_id": "CAND-0001", "category": "memory-safety",
                        "rule_id": "MEM-003", "cwe": "CWE-119", "language": "c",
                        "file": "src/parse.c", "line": 17,
                        "function_id": "src/parse.c::handle_conn::0@f81682d7bcfeac28",
                        "sink_text": "read(fd, buf, n);"}], fh)
        with open(os.path.join(review, "findings", "CAND-0001.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": "CAND-0001", "rule_id": "MEM-003",
                       "cwe": "CWE-119", "verdict": "NOT_VULNERABLE",
                       "confidence": "high", "severity": "medium",
                       "primary_location": "src/parse.c:17"}, fh)
        os.remove(os.path.join(review, "arbitration", "ARB-CAND-0001.json"))
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com", "--reason-code", "FP-GUARDED",
             "--reason", "n is clamped by the caller"], bundle)
        check("run 2's CAND-0001 is recorded", code, 0)
        check("and does not claim to supersede run 1's CAND-0001, another function",
              "supersedes" in out, False)
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        decisions = json.loads(out)["decisions"]
        check("both decisions stand, and the confirmation is still counted",
              (decisions["standing"], decisions["superseded"],
               decisions["by_decision"]["confirmed"],
               decisions["by_decision"]["rejected"]), (2, 0, 1, 1))
        _invoke(["export", "--root", root], bundle)
        samples, _ = read_jsonl(samples_path(root))
        check("and both reach the training export",
              sorted((s["function_key"], s["label"]) for s in samples),
              [("src/parse.c::handle_conn::0", "not_vulnerable"),
               ("src/parse.c::parse_tlv_record::0", "vulnerable")])

    # ---- --label-filter applies to what the dedup decided, not before it ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "len is unbounded"], bundle)
        # CAND-0002 is the same body under the same CWE; its rejection is the
        # later word on that sample.
        _invoke(["reject", "--root", root, "--candidate", "CAND-0002",
                 "--author", "a@example.com", "--reason-code", "FP-GUARDED",
                 "--reason", "clamped at parse.c:14"], bundle)
        _invoke(["export", "--root", root], bundle)
        plain, _ = read_jsonl(samples_path(root))
        check("the later rejection is the one sample",
              [(s["label"], s["decision_id"]) for s in plain],
              [("not_vulnerable", "DEC-0002")])
        code, out, message = _invoke(
            ["export", "--root", root, "--label-filter", "vulnerable"], bundle)
        samples, _ = read_jsonl(samples_path(root))
        check("a vulnerable-only export does not resurrect the overturned label",
              (len(samples), "1 sample(s) were left out by --label-filter" in out),
              (0, True))
        _invoke(["export", "--root", root, "--label-filter", "not_vulnerable"], bundle)
        samples, _ = read_jsonl(samples_path(root))
        check("and the other side is exactly the unfiltered sample",
              [(s["label"], s["decision_id"]) for s in samples],
              [(s["label"], s["decision_id"]) for s in plain])

    # ---- revoke's rewrite and every append share one lock ---- #
    if fcntl is not None:
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root, bundle = _fixture(tmp), _bundle(tmp)
            soon = stamp(now_utc() + datetime.timedelta(days=30))[:10]
            _invoke(["suppress", "--root", root, "--function-key",
                     "src/parse.c::handle_conn::0", "--rule", "MEM-003",
                     "--author", "a@example.com", "--reason", "constant table",
                     "--expires", soon], bundle)
            spath = suppressions_path(root)
            held, children = [], []
            real_replace = os.replace

            def replace_under_watch(src, dst):
                if dst == spath:
                    probe = os.open(os.path.dirname(spath), os.O_RDONLY)
                    try:
                        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        held.append(False)
                    except OSError:
                        held.append(True)
                    finally:
                        os.close(probe)
                    # A second writer, arriving inside the window the rename
                    # used to erase. Not waited for here: it must block on the
                    # lock until this revoke is done.
                    children.append(subprocess.Popen(
                        [sys.executable, os.path.join(_HERE, "ledger.py"),
                         "suppress", "--root", root, "--function-key",
                         "src/app.py::run_cmd::0", "--rule", "INJ-002",
                         "--author", "b@example.com", "--reason", "sandboxed",
                         "--expires", soon],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                return real_replace(src, dst)

            os.replace = replace_under_watch
            try:
                code, out, message = _invoke(
                    ["revoke", "--root", root, "--suppression", "SUP-0001",
                     "--author", "a@example.com", "--reason", "the table is writable"],
                    bundle)
            finally:
                os.replace = real_replace
            for child in children:
                child.wait(timeout=60)
            check("revoke rewrites suppressions.jsonl under the ledger lock",
                  (code, held), (0, [True]))
            rows, problems = read_jsonl(spath)
            check("an append arriving during the rewrite survives it",
                  sorted(r["suppression_id"] for r in rows
                         if r.get("record_type") == "suppression"),
                  ["SUP-0001", "SUP-0002"])
            check("and the revoked suppression is still stamped",
                  [bool(r.get("revoked_at")) for r in rows
                   if r.get("record_type") == "suppression"], [True, False])

    # ---- no write goes through a link the scanned tree committed ---- #
    def linked(target, link):
        try:
            os.symlink(target, link)
            return True
        except (OSError, NotImplementedError):
            return False

    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        victim = os.path.join(tmp, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("untouched\n")
        os.makedirs(ledger_dir(root), exist_ok=True)
        if linked(victim, decisions_path(root)):
            code, out, message = _invoke(
                ["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
            check("a decisions.jsonl that is a symlink is refused", code, EXIT_USAGE)
            check("naming the link, where it points and the rule it would break",
                  (decisions_path(root) in message, victim in message,
                   "§9 rule 2" in message), (True, True, True))
            check("and what it points at is untouched", _raw(victim), b"untouched\n")
            code, out, message = _invoke(["check", "--root", root],
                                         os.path.dirname(_HERE))
            check("check reports the link before anybody writes through it",
                  (code, "is a symlink to" in out), (EXIT_REFUSED, True))
            if _NOFOLLOW:
                try:
                    append_jsonl(decisions_path(root), {"decision_id": "DEC-0001"})
                    refused = False
                except LedgerError:
                    refused = True
                check("and the append's own open refuses it too (O_NOFOLLOW)",
                      (refused, _raw(victim)), (True, b"untouched\n"))
            os.remove(decisions_path(root))
        if linked(victim, suppressions_path(root)):
            code, out, message = _invoke(
                ["suppress", "--root", root, "--function-key",
                 "src/parse.c::handle_conn::0", "--rule", "MEM-003",
                 "--author", "a@example.com", "--reason", "x",
                 "--expires", stamp(now_utc() + datetime.timedelta(days=9))[:10]],
                bundle)
            check("so is a suppressions.jsonl that is one",
                  (code, _raw(victim)), (EXIT_USAGE, b"untouched\n"))
            code, out, message = _invoke(
                ["revoke", "--root", root, "--suppression", "SUP-0001",
                 "--author", "a@example.com", "--reason", "x"], bundle)
            check("and a revoke through it", (code, _raw(victim)),
                  (EXIT_USAGE, b"untouched\n"))

    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        elsewhere = os.path.join(tmp, "elsewhere")
        os.makedirs(elsewhere)
        if linked(elsewhere, ledger_dir(root)):
            code, out, message = _invoke(
                ["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
            check("a ledger/ directory that is a symlink is refused",
                  (code, os.listdir(elsewhere)), (EXIT_USAGE, []))

    with tempfile.TemporaryDirectory() as tmp:
        real = _fixture(os.path.join(tmp, "real"))
        bundle = _bundle(tmp)
        root = os.path.join(tmp, "repo")
        os.makedirs(root)
        if linked(run_dir(real), run_dir(root)):
            code, out, message = _invoke(
                ["export", "--root", root, "--out",
                 os.path.join(run_dir(root), "ledger", "training", "x.jsonl")], bundle)
            check("with .security-review itself a link, --out into it is refused",
                  code, EXIT_USAGE)
            code, out, message = _invoke(
                ["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
            check("and so is every write through it",
                  (code, os.path.exists(decisions_path(real))), (EXIT_USAGE, False))
        alias = os.path.join(tmp, "alias")
        if linked(real, alias):
            code, out, message = _invoke(
                ["confirm", "--root", alias, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
            check("a --root that is a link is fine: only the run directory down is "
                  "checked, never the root or above it",
                  (code, os.path.isfile(decisions_path(real))), (0, True))
            code, out, message = _invoke(
                ["export", "--root", real, "--out",
                 os.path.join(run_dir(alias), "ledger", "training", "x.jsonl")], bundle)
            check("and so is an --out spelled through another name for the root - "
                  "/tmp/repo for a `--root .` that resolved to /private/tmp/repo",
                  (code, os.path.isfile(os.path.join(ledger_dir(real), "training",
                                                     "x.jsonl"))), (0, True))

    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001",
                 "--author", "a@example.com", "--reason", "real"], bundle)
        os.makedirs(os.path.dirname(samples_path(root)), exist_ok=True)
        victim = os.path.join(tmp, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("untouched\n")
        # The temporary's old name was predictable, so a committed link could
        # sit at it.
        if linked(victim, samples_path(root) + ".tmp-%d" % os.getpid()):
            code, out, message = _invoke(["export", "--root", root], bundle)
            check("a link at the old temporary name is not written through",
                  (code, _raw(victim)), (0, b"untouched\n"))
            check("and the export lands as a plain 0644 file",
                  (os.path.islink(samples_path(root)),
                   oct(os.stat(samples_path(root)).st_mode & 0o777)),
                  (False, "0o644"))
            os.remove(samples_path(root))
        trail = _raw(decisions_path(root))
        if linked(decisions_path(root), samples_path(root)):
            code, out, message = _invoke(["export", "--root", root], bundle)
            check("a samples.jsonl linked to the trail is refused, not replaced",
                  (code, _raw(decisions_path(root))), (EXIT_USAGE, trail))
            code, out, message = _invoke(
                ["export", "--root", root, "--out", samples_path(root)], bundle)
            check("and --out naming it is refused the same way, though it resolves "
                  "inside the run directory", (code, _raw(decisions_path(root))),
                  (EXIT_USAGE, trail))

    # ---- rule 2 holds for a record shaped exactly like contract §8's ---- #
    contract_shaped = {
        "schema_version": 1, "suppression_id": "SUP-0001",
        "created_at": "2026-09-18T19:05:00Z", "author": "you@example.com",
        "function_key": "src/parse.c::parse_tlv_record::0", "rule_id": "MEM-002",
        "content_hash_at_creation": "fbb8544c6c43791a",
        "reason": "Input is a compile-time constant table; tracked in ISSUE-441.",
        "expires_at": "2026-12-18T00:00:00Z", "revoked_at": None}
    for label, changes, want in (
            ("the contract's own 91-day example passes check", {}, (EXIT_OK, None)),
            ("a ten-year expiry with no max_expiry_days fails check",
             {"expires_at": "2036-09-18T00:00:00Z"}, (EXIT_REFUSED, "was never forced")),
            ("and so does one whose max_expiry_days is not a number",
             {"expires_at": "2036-09-18T00:00:00Z", "max_expiry_days": "180"},
             (EXIT_REFUSED, "is not a number"))):
        with tempfile.TemporaryDirectory() as tmp:
            root = _fixture(tmp)
            append_jsonl(suppressions_path(root), dict(contract_shaped, **changes))
            code, out, message = _invoke(["check", "--root", root],
                                         os.path.dirname(_HERE))
            check(label, (code, want[1] in out if want[1] else "0 problem(s)" in out),
                  (want[0], True))

    # ---- a queued verdict the arbiter never reached is not adjudicated ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        queue_path = os.path.join(run_dir(root), "arbitration", "queue.json")
        with open(queue_path, "w", encoding="utf-8") as fh:
            json.dump({"summary": {}, "queue": [{"candidate_id": "CAND-0001"},
                                                {"candidate_id": "CAND-0004"}]}, fh)
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason-code", "FP-GUARDED",
             "--reason", "clamped upstream"], bundle)
        check("a candidate queued for the arbiter with no ARB record is refused",
              code, EXIT_UNADJUDICATED)
        check("and the refusal names the queue and the ARB record it waits for",
              ("queue.json" in message and "ARB-CAND-0004.json" in message), True)
        check("nothing was appended", os.path.exists(decisions_path(root)), False)
        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com", "--reason", "real"], bundle)
        check("a queued candidate the arbiter did reach is decided as before", code, 0)
        with open(queue_path, "w", encoding="utf-8") as fh:
            json.dump({"summary": {}, "queue": [{"candidate_id": "CAND-0001"}]}, fh)
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004",
             "--author", "a@example.com", "--reason-code", "FP-GUARDED",
             "--reason", "clamped upstream"], bundle)
        check("and a verdict the queue never sent on is still an adjudication",
              code, 0)

    # ---- the ledger never carries key material ---- #
    # Built at run time, so a secret sweep over this skill does not read the
    # source as leaking.
    canary = "sk-live-" + "LEAKCANARY99887766554433221100"
    password = "Winter" + "2026Payroll"
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        soon = stamp(now_utc() + datetime.timedelta(days=30))[:10]
        for what, argv in (
                ("confirm", ["confirm", "--candidate", "CAND-0001",
                             "--reason", 'confirmed: api_key = "%s" is live' % canary]),
                ("reject", ["reject", "--candidate", "CAND-0004",
                            "--reason-code", "FP-GUARDED",
                            "--reason", "the value is %s" % canary]),
                ("suppress", ["suppress", "--function-key",
                              "src/parse.c::handle_conn::0", "--rule", "MEM-003",
                              "--reason", "rotating %s" % canary,
                              "--expires", soon])):
            code, out, message = _invoke(
                argv + ["--root", root, "--author", "a@example.com"], bundle)
            check("%s refuses a reason that quotes a live credential" % what,
                  code, EXIT_REFUSED)
            check("and the refusal shows it redacted, never whole",
                  (canary in message, "sk-l…" in message), (False, True))
        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com",
             "--reason", 'password = "%s" is hardcoded' % password], bundle)
        check("a quoted password with no family and no entropy is refused too",
              code, EXIT_REFUSED)
        check("nothing was written by any of them",
              (os.path.exists(decisions_path(root)),
               os.path.exists(suppressions_path(root))), (False, False))
        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com",
             "--reason", "fixed in a83fcd7b2e9c4f1a0d5e6b7c8d9e0f1a2b3c4d5e against "
                         "fbb8544c6c43791a; the key sk-l…1100 was rotated"], bundle)
        check("a commit, a content hash and a redacted quote are not key material",
              code, 0)
        commit_url = ("https://github.com/acme/widget/commit/"
                      "a83fcd7b2e9c4f1a0d5e6b7c8d9e0f1a2b3c4d5e")
        check("nor is a fix-commit URL, though `/` joins its path into one run",
              (key_material("fixed in %s" % commit_url),
               key_material("see %s/src/parse.c#L42"
                            % commit_url.replace("/commit/", "/blob/"))), ([], []))
        # The query form, which is how kernel, glibc and OpenSSL advisories
        # cite a fix: cgit's `commit/?id=`, gitweb's `;h=`. `=` is in the
        # secret alphabet, so the run began at the parameter's name.
        sha = "59f5e75f3bced8fc0e130d72a3f582cf7b480b46"
        kernel = ("https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
                  "linux.git/commit/?id=")
        check("nor is a cgit, gitweb or Gerrit citation of a fix commit",
              [key_material(text) for text in (
                  "fixed in %s%s" % (kernel, sha),
                  "see https://sourceware.org/git/?p=glibc.git;a=commit;h=" + sha,
                  "https://git.kernel.org/pub/scm/linux/kernel/git/stable/"
                  "linux.git/commit/?h=linux-6.1.y&id=%s#n12" % sha,
                  "Change-Id: I" + sha)], [[], [], [], []])
        hex64 = sha + "0e130d72a3f582cf7b480b46"
        check("while a digest-shaped value under any other name is still a key: "
              "an OAuth token, an HMAC key, one beside a commit, an id= that is "
              "only the tail of grid=, and an id= outside any URL",
              [len(key_material(text)) for text in (
                  "https://api.github.com/user?access_token=" + sha,
                  "https://api.example.com/v1?key=" + hex64,
                  "https://x.example/?id=%s&token=%s" % (sha, sha),
                  "https://x.example/?grid=" + sha,
                  "the commit id=" + sha,
                  "see I" + sha)], [1, 1, 1, 1, 1, 1])
        code, out, message = _invoke(
            ["confirm", "--root", root, "--candidate", "CAND-0001",
             "--author", "a@example.com",
             "--reason", "fixed in %s%s" % (kernel, sha)], bundle)
        check("and a decision citing a kernel.org fix is recorded", code, 0)
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("which check then passes", "key material" in out, False)
        webhook_token = "Xq7vK2pL9mN4rT8wZ1yB" + "3cD5fG6hJ0kQeRsUaVbWcYdE"
        check("while a token that is a URL path segment is still caught",
              len(key_material("https://chat.example.com/api/webhooks/1234/%s"
                               % webhook_token)), 1)
        hex_user = "0f3a9c7e1b2d4f6a" + "8c0e2b4d6f8a1c3e5b7d9f0a"
        check("and so is a digest-shaped token as a clone URL's user, which is "
              "in no commit's position",
              len(key_material("cloned with https://%s@github.com/acme/p.git"
                               % hex_user)), 1)
        check("while words under a secret-shaped name are left, as the report "
              "gate leaves them: a refusal here refuses check and export too",
              key_material('the form shows password: "Enter a new one" only'), [])
        _invoke(["suppress", "--root", root, "--function-key",
                 "src/parse.c::handle_conn::0", "--rule", "MEM-003",
                 "--author", "a@example.com", "--reason", "constant table",
                 "--expires", soon], bundle)
        before = _raw(suppressions_path(root))
        code, out, message = _invoke(
            ["revoke", "--root", root, "--suppression", "SUP-0001",
             "--author", "a@example.com", "--reason", "leaked: %s" % canary], bundle)
        check("revoke refuses one too, and writes nothing",
              (code, _raw(suppressions_path(root))), (EXIT_REFUSED, before))

        # One already there - hand-appended, or older than this check.
        leaked = dict(json.loads(_lines(decisions_path(root))[0]))
        leaked.update({"decision_id": "DEC-9500",
                       "at": stamp(now_utc() + datetime.timedelta(days=1)),
                       "reason": "the key is %s" % canary})
        append_jsonl(decisions_path(root), leaked)
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("check reports a ledger line carrying key material, redacted",
              (code, "carries key material" in out, canary in out),
              (EXIT_REFUSED, True, False))
        code, out, message = _invoke(["export", "--root", root], bundle)
        check("and export will not copy it into the training set",
              (code, "DEC-9500" in message, canary in message),
              (EXIT_REFUSED, True, False))
        os.makedirs(os.path.dirname(samples_path(root)), exist_ok=True)
        with open(samples_path(root), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"label": "vulnerable", "provenance": "human-confirmed",
                                 "explanation": "the key is %s" % canary}) + "\n")
        code, out, message = _invoke(["check", "--root", root],
                                     os.path.dirname(_HERE))
        check("nor does check pass a training sample that carries it",
              "samples.jsonl:1: `explanation` carries key material" in out, True)

    # ---- FP-TEST and FP-GENERATED are held to their path facts ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        for code in ("FP-TEST", "FP-GENERATED"):
            got = _invoke(["reject", "--root", root, "--candidate", "CAND-0004",
                           "--author", "a@example.com", "--reason-code", code,
                           "--reason", "not product code"], bundle)
            check("%s on src/parse.c, which no path fact bears out, is refused "
                  "and points at out-of-scope" % code,
                  (got[0], "out-of-scope" in got[2], "--path-override" in got[2],
                   os.path.exists(decisions_path(root))), (EXIT_REFUSED, True, True, False))
        os.makedirs(os.path.join(root, "src"), exist_ok=True)
        with open(os.path.join(root, "src", "parse.c"), "w", encoding="utf-8") as fh:
            fh.write("/* Generated by bison 3.8. DO NOT EDIT. */\nint x;\n")
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004", "--author",
             "a@example.com", "--reason-code", "FP-GENERATED", "--reason",
             "bison output, parse.c:1"], bundle)
        check("FP-GENERATED on a file whose head carries a generated marker is "
              "recorded, with no override", (code, read_jsonl(decisions_path(root))[0][-1]
                                              .get("path_override")), (0, None))
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0001", "--author",
             "a@example.com", "--reason-code", "FP-TEST", "--reason", "harness only",
             "--path-override", "built only into the fuzz harness, Makefile:88"], bundle)
        override = read_jsonl(decisions_path(root))[0][-1].get("path_override") or {}
        check("--path-override records the facts it overrode and why",
              (code, override.get("code"), override.get("paths"),
               override.get("in_test_tree"), override.get("reason")),
              (0, "FP-TEST", ["src/parse.c"], False,
               "built only into the fuzz harness, Makefile:88"))
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("and check passes both", (code, "0 problem(s)" in out), (0, True))
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0004", "--author",
             "a@example.com", "--reason-code", "OOS-TEST-INFRA", "--reason", "x"], bundle)
        check("a scope code handed to reject is refused, naming out-of-scope",
              (code, "ledger.py out-of-scope --scope-code OOS-TEST-INFRA" in message),
              (EXIT_REFUSED, True))

    # A validator's primary_location on a harness or a generated file is not the
    # path of the body the decision labels. Accepted on it, the decision was
    # then reported by `check`, which has only the snapshot's file.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        for code, location in (("FP-TEST", "tests/fixtures/conn_harness.c:40"),
                               ("FP-GENERATED", "src/proto/msg.pb.c:12")):
            _rewrite(root, "findings", "CAND-0004.json", primary_location=location)
            got = _invoke(["reject", "--root", root, "--candidate", "CAND-0004",
                           "--author", "a@example.com", "--reason-code", code,
                           "--reason", "shown only in %s" % location], bundle)
            check("%s on src/parse.c is refused though the finding's primary_location "
                  "is %s - the path of the body labelled is what is judged"
                  % (code, location),
                  (got[0], "src/parse.c is under none" in got[2]
                   or "src/parse.c matches no" in got[2],
                   os.path.exists(decisions_path(root))), (EXIT_REFUSED, True, False))

    # ---- a body can hold a real defect beside a correct dismissal ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0001", "--author",
                 "a@example.com", "--reason", "len is unbounded"], bundle)
        first = json.loads(_lines(decisions_path(root))[0])
        for seconds, (decision_id, rule, cwe, code, reason) in enumerate((
                ("DEC-0002", "MEM-WFS", "CWE-119", "FP-WFS-CLEAN",
                 "seven answers, parse.c:1-40, nothing past the copy at :8"),
                ("DEC-0003", "INJ-001", "CWE-134", "FP-TEST", "only the test build")), 1):
            append_jsonl(decisions_path(root), dict(
                first, decision_id=decision_id, candidate_id="CAND-%s" % decision_id,
                rule_id=rule, cwe=cwe, decision="rejected", reason_code=code,
                reason=reason, at=stamp(now_utc() + datetime.timedelta(seconds=seconds))))
            if decision_id == "DEC-0002":
                code, out, message = _invoke(["export", "--root", root], bundle)
                check("a confirmed MEM-002 overflow beside a clean whole-function sweep "
                      "under another CWE is two samples, not a conflict",
                      (sorted((s["cwe"], s["label"]) for s in
                              read_jsonl(samples_path(root))[0]),
                       "LABEL CONFLICTS" in out),
                      ([("CWE-119", "not_vulnerable"), ("CWE-787", "vulnerable")], False))
                code, out, message = _invoke(["check", "--root", root],
                                             os.path.dirname(_HERE))
                check("and check agrees", (code, "0 problem(s)" in out), (0, True))
        code, out, message = _invoke(["export", "--root", root], bundle)
        check("while a claim about the whole function - FP-TEST - contradicts the "
              "defect under any CWE, and only those two are left out",
              ([s["decision_id"] for s in read_jsonl(samples_path(root))[0]],
               "fbb8544c6c43791a cross-cwe: not_vulnerable DEC-0003; vulnerable DEC-0001"
               in out), (["DEC-0002"], True))

    # ---- out-of-scope: real, and outside what the project defends ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        os.makedirs(os.path.join(root, "tools", "sim"), exist_ok=True)
        with open(os.path.join(root, "tools", "sim", "README.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("# sim\n\nA simulator for tests; it is not secure.\n")
        base = ["out-of-scope", "--root", root, "--candidate", "CAND-0001",
                "--author", "a@example.com", "--reason", "simulator only"]
        for label, extra, want in (
                ("with no scope code", ["--basis", "tools/sim/README.md:3"], EXIT_REFUSED),
                ("under an FP-* code, which says never real",
                 ["--scope-code", "FP-TEST", "--basis", "tools/sim/README.md:3"],
                 EXIT_REFUSED),
                ("with no basis", ["--scope-code", "OOS-TEST-INFRA"], EXIT_USAGE),
                ("on a basis line past the end of the file",
                 ["--scope-code", "OOS-TEST-INFRA", "--basis", "tools/sim/README.md:9"],
                 EXIT_USAGE),
                ("on a blank basis line",
                 ["--scope-code", "OOS-TEST-INFRA", "--basis", "tools/sim/README.md:2"],
                 EXIT_USAGE),
                ("on a basis outside the scanned root",
                 ["--scope-code", "OOS-TEST-INFRA", "--basis", "../x.md:1"], EXIT_USAGE),
                ("on a basis inside the run directory",
                 ["--scope-code", "OOS-TEST-INFRA", "--basis",
                  ".security-review/run.json:1"], EXIT_USAGE)):
            check("out-of-scope is refused %s" % label,
                  _invoke(base + extra, bundle)[0], want)
        check("and none of those wrote anything", os.path.exists(decisions_path(root)),
              False)
        code, out, message = _invoke(base + ["--scope-code", "oos-test-infra", "--basis",
                                             "tools/sim/README.md:3"], bundle)
        record = read_jsonl(decisions_path(root))[0][-1]
        check("out-of-scope is recorded with its code and the basis line quoted from "
              "the tree, not typed",
              (code, record["decision"], record["scope_code"], record["reason_code"],
               record["scope_basis"]),
              (0, "out_of_scope", "OOS-TEST-INFRA", None,
               {"file": "tools/sim/README.md", "line": 3,
                "text": "A simulator for tests; it is not secure."}))
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        decisions = json.loads(out)["decisions"]
        check("status counts it by scope code, and not as a rejection",
              (decisions["by_decision"]["out_of_scope"],
               decisions["by_decision"]["rejected"], decisions["by_scope_code"]),
              (1, 0, {"OOS-TEST-INFRA": 1}))
        code, out, message = _invoke(["export", "--root", root], bundle)
        check("the export leaves it out and says so",
              (code, len(read_jsonl(samples_path(root))[0]),
               "1 out_of_scope decision(s) are not samples" in out), (0, 0, True))
        code, out, message = _invoke(["export", "--root", root,
                                      "--include-out-of-scope"], bundle)
        samples = read_jsonl(samples_path(root))[0]
        check("and writes it on request as out_of_scope, defect present",
              [(s["label"], s["defect_present"], s["provenance"], s["scope_code"])
               for s in samples],
              [("out_of_scope", True, "human-out-of-scope", "OOS-TEST-INFRA")])
        check("--label-filter out_of_scope asks for it too",
              (_invoke(["export", "--root", root, "--label-filter", "out_of_scope"],
                       bundle)[0], len(read_jsonl(samples_path(root))[0])), (0, 1))
        code, out, message = _invoke(["check", "--root", root], os.path.dirname(_HERE))
        check("and a ledger holding it passes check", (code, "0 problem(s)" in out),
              (0, True))
        with open(decisions_path(root), encoding="utf-8") as fh:
            text = fh.read()
        with open(decisions_path(root), "a", encoding="utf-8") as fh:
            fh.write(text.replace('"DEC-0001"', '"DEC-0002"')
                     .replace('"OOS-TEST-INFRA"', '"OOS-VIBES"'))
            fh.write(text.replace('"DEC-0001"', '"DEC-0003"')
                     .replace('"decision": "out_of_scope"', '"decision": "confirmed"'))
        code, out, message = _invoke(["check", "--root", root], os.path.dirname(_HERE))
        check("check reports a scope code no contract defines, and one on a "
              "confirmation", (code, "not one of OOS-TEST-INFRA" in out,
                               "belongs to out_of_scope alone" in out),
              (EXIT_REFUSED, True, True))
        with tempfile.TemporaryDirectory() as other:
            drifted = _bundle(other)
            with open(ledger_contract_path(drifted), "w", encoding="utf-8") as fh:
                fh.write("## 8. `ledger/`\n\n| `OOS-TEST-INFRA` | x |\n\n## 8b. up\n")
            check("and a contract whose table drifted from SCOPE_CODES",
                  "SCOPE_CODES holds" in _invoke(["check", "--root", root], drifted)[1],
                  True)
    real_contract = ledger_contract_path(os.path.dirname(_HERE))
    if os.path.isfile(real_contract):
        check("the shipped pipeline contract's §8 table is exactly SCOPE_CODES",
              contract_scope_codes(real_contract), (SCOPE_CODES, None))

    # ---- the Mbed TLS session of 2026-09-29, as the ledger of that run took it --- #
    # Twelve decisions, 0 problems from check, and an export that labelled
    # psasim's process_response vulnerable at one path and not_vulnerable at
    # its byte-identical copy under one hash and one CWE. The same lines, read
    # by this version.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        rows = dict((row[0], row) for row in MBEDTLS_ROWS)
        legacy = [_mbedtls_legacy(i, rows[c], d, code, r)
                  for i, (c, d, code, r) in enumerate(MBEDTLS_SESSION)]
        check("the fixture writes a decision exactly as the ledger.py of that run did",
              json.dumps(legacy[3], sort_keys=True), MBEDTLS_LEGACY_LINE)
        os.makedirs(os.path.join(ledger_dir(root), "training"))
        with open(decisions_path(root), "w", encoding="utf-8") as fh:
            for index, record in enumerate(legacy):
                fh.write((MBEDTLS_LEGACY_LINE if index == 3
                          else json.dumps(record, sort_keys=True)) + "\n")
        with open(samples_path(root), "w", encoding="utf-8") as fh:
            for sample_id, index, label in (("SMP-0001", 0, "vulnerable"),
                                            ("SMP-0003", 3, "not_vulnerable")):
                fh.write(json.dumps({"schema_version": 1, "sample_id": sample_id,
                                     "label": label, "provenance": "human-" + (
                                         "confirmed" if index == 0 else "rejected"),
                                     "function_key": legacy[index]["function_key"],
                                     "content_hash": "33bd5b6cc79c1924",
                                     "cwe": "CWE-119",
                                     "explanation": legacy[index]["reason"]}) + "\n")
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        decisions = json.loads(out)["decisions"]
        check("the legacy ledger loads: twelve standing, as that session left them",
              (code, decisions["standing"], decisions["by_decision"]["confirmed"],
               decisions["by_decision"]["rejected"],
               decisions["by_decision"]["out_of_scope"]), (0, 12, 5, 7, 0))
        check("and status counts the three contradictions nobody acknowledged",
              decisions["unacknowledged_conflicts"], 3)
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("check no longer passes it", code, EXIT_REFUSED)
        check("it names each FP-TEST on psasim, and not the ACVP harness under test/",
              sorted(d for d in ("DEC-0004", "DEC-0007", "DEC-0008", "DEC-0009",
                                 "DEC-0010", "DEC-0011", "DEC-0012")
                     if "%s rejects" % d in out),
              ["DEC-0004", "DEC-0008", "DEC-0009", "DEC-0010", "DEC-0011", "DEC-0012"])
        check("the byte-identical twins labelled both ways",
              "DEC-0001 (confirmed CAND-0031" in out
              and "DEC-0004 (rejected CAND-0010" in out
              and "byte-identical copies of one body under MEM-WFS" in out, True)
        check("the survivor rejected while its MERGED sinks were confirmed - read off "
              "this run's ARB records, the ledger of that run not recording merged_into",
              sum(1 for line in out.splitlines()
                  if "one MERGED cluster" in line and "DEC-0004" in line), 2)
        check("and the samples.jsonl that labelled one body both ways",
              "holds 33bd5b6cc79c1924 both as a defect (SMP-0001) and as "
              "not_vulnerable (SMP-0003)" in out, True)
        code, out, message = _invoke(["export", "--root", root], bundle)
        samples = read_jsonl(samples_path(root))[0]
        check("re-exported, the contradicted body is left out and listed with its "
              "decisions",
              (code, [s for s in samples if s["content_hash"] == "33bd5b6cc79c1924"],
               "33bd5b6cc79c1924 same-cwe: not_vulnerable DEC-0004; vulnerable DEC-0001, "
               "DEC-0003, DEC-0006" in out), (0, [], True))
        check("the two folds are named, and the twins written once each",
              ("DEC-0002 into DEC-0003, DEC-0005 into DEC-0006" in out,
               sorted((s["decision_id"], s["also_decision_ids"]) for s in samples)),
              (True, [("DEC-0007", []), ("DEC-0008", []), ("DEC-0010", ["DEC-0009"]),
                      ("DEC-0012", ["DEC-0011"])]))
        check("with the other path in also_at",
              [s["also_at"] for s in samples if s["decision_id"] == "DEC-0010"],
              [[MBEDTLS_FW + "psa_ff_server.c::psa_wait::0"]])
        check("and the explanations that only restate their code are named",
              "4 sample(s) carry an explanation that only restates" in out
              and "DEC-0007 'reject - FP-TEST'" in out, True)

    # ---- the same twelve decisions, through this version ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        session = dict((c, (d, code, r)) for c, d, code, r in MBEDTLS_SESSION)

        def decide(candidate_id, *extra, **kw):
            decision, code, reason = session[candidate_id]
            verb = kw.get("verb") or {"confirmed": "confirm",
                                      "rejected": "reject"}[decision]
            argv = [verb, "--root", root, "--candidate", candidate_id, "--author", "MP",
                    "--reason", kw.get("reason") or reason]
            if code and verb == "reject":
                argv += ["--reason-code", code]
            return _invoke(argv + list(extra), bundle)

        def trail():
            return read_jsonl(decisions_path(root))[0]

        code, out, message = _invoke(["pending", "--root", root, "--json"], bundle)
        shape = json.loads(out)["review_set_shape"]
        check("pending says what the twelve were: 8 findings, 4 merged sinks, 5 bodies "
              "at 8 paths",
              (shape["findings"], len(shape["merged"]), shape["bodies"], shape["paths"],
               shape["merged_into"]),
              (8, 4, 5, 8, {"CAND-0031": ["CAND-0041", "CAND-0047"],
                            "CAND-0010": ["CAND-0020", "CAND-0026"]}))
        check("and names each body that sits at two paths",
              [(t["name"], len(t["function_keys"])) for t in shape["twins"]],
              [("process_response", 2), ("psa_call", 2), ("psa_wait", 2)])
        code, out, message = _invoke(["pending", "--root", root], bundle)
        check("the text form leads with the same breakdown",
              "review set: 12 = 8 finding(s) + 4 merged sink(s); 5 distinct function "
              "bodies at 8 path(s)" in out, True)

        for candidate_id in ("CAND-0031", "CAND-0047", "CAND-0041"):
            decide(candidate_id)
        first = trail()[0]
        check("DEC-0001 records the CWE the verdict was given under, the rule's beside it",
              (first["cwe"], first["rule_cwe"], first["snapshot"]["cwe_source"]),
              ("CWE-787", "CWE-119", "finding"))
        check("and the merged sinks name their survivor",
              [r["snapshot"]["merged_into"] for r in trail()],
              [None, "CAND-0031", "CAND-0031"])

        code, out, message = decide("CAND-0010")
        check("DEC-0004's FP-TEST on framework/psasim/ is refused without an override",
              (code, "TEST_PATH" in message, "OOS-TEST-INFRA" in message, len(trail())),
              (EXIT_REFUSED, True, True, 3))
        code, out, message = decide("CAND-0010", "--path-override",
                                    "the reviewer holds psasim to be test code")
        check("with one, it is refused for disagreeing with its confirmed twin, DEC-0001",
              (code, "DEC-0001  confirmed" in message,
               "the same body (33bd5b6cc79c1924) and rule MEM-WFS" in message,
               len(trail())), (EXIT_REFUSED, True, True, 3))
        code, out, message = decide("CAND-0010", "--path-override",
                                    "the reviewer holds psasim to be test code",
                                    "--acknowledge-conflict",
                                    "the reviewer rules the framework copy separately")
        fourth = trail()[-1]
        check("and with both it is recorded, carrying each",
              (code, (fourth.get("path_override") or {}).get("code"),
               (fourth.get("conflict_acknowledged") or {}).get("decision_ids")),
              (0, "FP-TEST", ["DEC-0001"]))
        code, out, message = decide("CAND-0026")
        check("confirming CAND-0026 after its survivor CAND-0010 was rejected is refused",
              (code, "DEC-0004  rejected (FP-TEST)  CAND-0010" in message,
               "survivor the arbiter MERGED this one into" in message, len(trail())),
              (EXIT_REFUSED, True, True, 4))
        code, out, message = decide("CAND-0052")
        check("the ACVP harness's FP-TEST is recorded: test/ is a test path",
              (code, trail()[-1]["path_override"]), (0, None))
        code, out, message = decide("CAND-0123")
        check("CAND-0123's FP-TEST on psasim is refused like CAND-0010's", code,
              EXIT_REFUSED)
        for candidate_id, path in (("CAND-0123", MBEDTLS_FW + "psa_ff_client.c"),
                                   ("CAND-0132", MBEDTLS_FW + "psa_ff_server.c"),
                                   ("CAND-0146", MBEDTLS_TF + "psa_ff_server.c"),
                                   ("CAND-0162", MBEDTLS_FW + "psa_ff_client.c"),
                                   ("CAND-0164", MBEDTLS_TF + "psa_ff_client.c")):
            number = MBEDTLS_NOTES[os.path.basename(path)][0]
            code, out, message = decide(candidate_id, "--scope-code", "OOS-TEST-INFRA",
                                        "--basis", "%s:%d" % (path, number),
                                        verb="out-of-scope", reason="test code only")
            check("%s is recorded out of scope on %s:%d" % (candidate_id, path, number),
                  (code, trail()[-1]["scope_basis"]["text"]),
                  (0, MBEDTLS_NOTES[os.path.basename(path)][1]))
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("an acknowledged disagreement and an overridden path pass check",
              (code, "0 problem(s)" in out), (0, True))
        code, out, message = _invoke(["export", "--root", root], bundle)
        samples = read_jsonl(samples_path(root))[0]
        check("the export holds no label conflict for process_response: the body "
              "labelled both ways is left out, and listed",
              ([s for s in samples if s["content_hash"] == "33bd5b6cc79c1924"],
               "33bd5b6cc79c1924 cross-cwe: not_vulnerable DEC-0004; vulnerable "
               "DEC-0002, DEC-0003" in out), ([], True))
        check("the out-of-scope decisions are not samples, and the one hard negative "
              "left is the ACVP harness",
              ([(s["decision_id"], s["label"]) for s in samples],
               "5 out_of_scope decision(s) are not samples" in out),
              ([("DEC-0005", "not_vulnerable")], True))
        code, out, message = _invoke(["export", "--root", root, "--include-conflicts",
                                      "--include-out-of-scope"], bundle)
        samples = read_jsonl(samples_path(root))[0]
        check("--include-conflicts writes the body marked, with what it conflicts with",
              sorted((s["decision_id"], s["conflict_kind"], s["conflict_with"])
                     for s in samples if s["conflict"]),
              [("DEC-0002", "cross-cwe", ["DEC-0004"]),
               ("DEC-0003", "cross-cwe", ["DEC-0004"]),
               ("DEC-0004", "cross-cwe", ["DEC-0002", "DEC-0003"])])
        check("and the psa_wait twins given one answer are one out_of_scope sample",
              [(s["decision_id"], s["also_at"]) for s in samples
               if s["content_hash"] == MBEDTLS_BODY["psa_wait"][0]],
              [("DEC-0008", [MBEDTLS_FW + "psa_ff_server.c::psa_wait::0"])])
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("an export that marks its conflicts passes check",
              (code, "0 problem(s)" in out), (0, True))

    # ---- the same session, decided the way the tool now steers it ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        for row in MBEDTLS_ROWS:
            candidate_id, path, name = row[0], row[3], os.path.basename(row[3])
            argv = (["reject", "--reason-code", "FP-TEST", "--reason",
                     "stack overflow in the ACVP test harness, acvp_mldsa.c:648"]
                    if candidate_id == "CAND-0052" else
                    ["out-of-scope", "--scope-code", "OOS-TEST-INFRA", "--basis",
                     "%s:%d" % (os.path.dirname(path) + "/" + name,
                                MBEDTLS_NOTES[name][0]),
                     "--reason", "real, in the psasim simulator, which says it is "
                                 "not secure"])
            code, out, message = _invoke(argv + ["--root", root, "--candidate",
                                                 candidate_id, "--author", "MP"], bundle)
            if code:
                check("%s is recorded without a refusal" % candidate_id, message, "")
        check("twelve decisions, one answer per question, no refusal on the way",
              len(read_jsonl(decisions_path(root))[0]), 12)
        code, out, message = _invoke(["export", "--root", root,
                                      "--include-out-of-scope"], bundle)
        samples = read_jsonl(samples_path(root))[0]
        check("process_response exports with one label, collapsed across its copies",
              sorted((s["cwe"], s["label"], len(s["also_at"])) for s in samples
                     if s["content_hash"] == "33bd5b6cc79c1924"),
              [("CWE-119", "out_of_scope", 0), ("CWE-125", "out_of_scope", 1),
               ("CWE-787", "out_of_scope", 1)])
        check("and no label conflict anywhere", ("LABEL CONFLICTS" in out,
                                                 [s for s in samples if s["conflict"]]),
              (False, []))
        # The operator can declare psasim a test tree at stage 0; stage 1 then
        # marks it in_test_tree, stage 3 says the globs put it there, and
        # FP-TEST is true of it by the pipeline's own facts.
        path = os.path.join(run_dir(root), "candidates", "memory-safety.json")
        with open(path, encoding="utf-8") as fh:
            records = json.load(fh)
        for record in records:
            record["in_test_tree"] = True
            record["exposure"] = {"path_class": "test",
                                  "path_class_basis": "test-tree-globs"}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh)
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0123", "--author", "MP",
             "--reason-code", "FP-TEST", "--reason", "psasim is a declared test tree",
             "--acknowledge-conflict", "the operator declared psasim a test tree"],
            bundle)
        record = read_jsonl(decisions_path(root))[0][-1]
        check("FP-TEST on a path the operator declared a test tree needs no override",
              (code, record["path_override"], record["snapshot"]["in_test_tree"]),
              (0, None, True))
        check("and superseding its own out-of-scope is a correction, not a conflict",
              (record["conflict_acknowledged"], "supersedes DEC-0008" in out),
              (None, True))

    # ---- a later run's decision retires the earlier run's answer ---- #
    # decision_key() keeps a supersede inside one run. The export's
    # (function_key, content_hash, cwe) dedup folded a correction across runs
    # until `cwe` became the adjudicated CWE: then a legacy confirmation under
    # the rule's CWE-119 and its correction under the validator's CWE-787 were
    # both written, as vulnerable and not_vulnerable, for one body at one path.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        os.makedirs(os.path.join(root, "tools", "sim"), exist_ok=True)
        with open(os.path.join(root, "tools", "sim", "README.md"), "w",
                  encoding="utf-8") as fh:
            fh.write("# sim\n\nA harness for tests; it is not secure.\n")
        legacy = {"schema_version": 1, "decision_id": "DEC-0001",
                  "at": "2026-09-19T05:00:00Z", "author": "a@example.com",
                  "run_id": "2026-09-19T04-31-46Z", "candidate_id": "CAND-0004",
                  "function_key": "src/parse.c::handle_conn::0",
                  "content_hash": "f81682d7bcfeac28", "rule_id": "MEM-003",
                  "cwe": "CWE-119", "final_verdict": "VULNERABLE",
                  "decision": "confirmed", "reason_code": None,
                  "reason": "n is unbounded from the peer", "fix_commit": None,
                  "tool_version": "1.0.0",
                  "snapshot": {"file": "src/parse.c", "rule_ids": ["MEM-003"]}}
        _rerun(root, "2026-10-01T00-00-00Z")
        for verb, extra, want in (
                ("out-of-scope", ["--scope-code", "OOS-TEST-INFRA", "--basis",
                                  "tools/sim/README.md:3", "--reason",
                                  "real, and only the test harness reaches it"], []),
                ("reject", ["--reason-code", "FP-GUARDED", "--reason",
                            "n is clamped at parse.c:14"],
                 [("not_vulnerable", "CWE-787")])):
            os.makedirs(ledger_dir(root), exist_ok=True)
            with open(decisions_path(root), "w", encoding="utf-8") as fh:
                fh.write(json.dumps(legacy) + "\n")
            code, out, message = _invoke([verb, "--root", root, "--candidate",
                                          "CAND-0004", "--author", "a@example.com"]
                                         + extra, bundle)
            check("%s in the next run retires the legacy confirmation of the same "
                  "question, and says so" % verb,
                  (code, "retires DEC-0001 (confirmed CAND-0004" in out), (0, True))
            code, out, message = _invoke(["export", "--root", root], bundle)
            check("and the export writes the correction alone, naming what it retired",
                  (code, [(s["label"], s["cwe"])
                          for s in read_jsonl(samples_path(root))[0]],
                   "DEC-0001 into DEC-0002" in out), (0, want, True))
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        decisions = json.loads(out)["decisions"]
        check("status counts the correction as standing and the old line as retired",
              (decisions["standing"], decisions["superseded"],
               decisions["retired_by_later_run"], decisions["by_decision"]["confirmed"]),
              (1, 1, 1, 0))
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["reject", "--root", root, "--candidate", "CAND-0004", "--author",
                 "a@example.com", "--reason-code", "FP-GUARDED", "--reason",
                 "n is clamped at parse.c:14"], bundle)
        _rerun(root, "2026-10-01T00-00-00Z")
        _rewrite(root, "findings", "CAND-0004.json", cwe="CWE-120", verdict="VULNERABLE")
        code, out, message = _invoke(["confirm", "--root", root, "--candidate",
                                      "CAND-0004", "--author", "a@example.com",
                                      "--reason", "the clamp at parse.c:14 is gone"],
                                     bundle)
        code, out, message = _invoke(["export", "--root", root], bundle)
        check("two decisions by this version, the validator narrowing to CWE-787 in one "
              "run and CWE-120 in the next, export the later label alone",
              (code, [(s["label"], s["cwe"]) for s in read_jsonl(samples_path(root))[0]],
               "DEC-0001 into DEC-0002" in out), (0, [("vulnerable", "CWE-120")], True))
        check("and check agrees", _invoke(["check", "--root", root],
                                          os.path.dirname(_HERE))[0], 0)

    # ---- the Mbed TLS ledger, carried into the next run ---- #
    # Its old run's answers stood for ever beside the new run's: check reported
    # the psasim FP-TESTs after each was re-decided out of scope, and every
    # decision on a twin of an old answer was refused over it. Then each pair
    # whose answer flips was refused both ways round - each copy over the
    # other's old answer - until one was recorded under an acknowledgement of
    # a difference nobody claimed.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        rows = dict((row[0], row) for row in MBEDTLS_ROWS)
        os.makedirs(ledger_dir(root))
        with open(decisions_path(root), "w", encoding="utf-8") as fh:
            for index, (c, d, code, r) in enumerate(MBEDTLS_SESSION):
                fh.write(json.dumps(_mbedtls_legacy(index, rows[c], d, code, r),
                                    sort_keys=True) + "\n")
        _rerun(root, "2026-10-06T09-00-00Z")
        check("in the next run, nothing re-decided yet, check still reports the old "
              "run's answers", _invoke(["check", "--root", root], real_bundle)[0],
              EXIT_REFUSED)
        refused, pending, acknowledged_ids = [], [], []
        for row in MBEDTLS_ROWS:
            candidate_id, path = row[0], row[3]
            name = os.path.basename(path)
            argv = (["reject", "--reason-code", "FP-TEST", "--reason",
                     "stack overflow in the ACVP test harness, acvp_mldsa.c:648"]
                    if candidate_id == "CAND-0052" else
                    ["out-of-scope", "--scope-code", "OOS-TEST-INFRA", "--basis",
                     "%s:%d" % (path, MBEDTLS_NOTES[name][0]), "--reason",
                     "real, in the psasim simulator, which says it is not secure"])
            argv += ["--root", root, "--candidate", candidate_id, "--author", "MP"]
            code, out, message = _invoke(argv, bundle)
            if code:
                refused.append(candidate_id)
            if "asks again in this run: decide it there too" in out:
                pending.append(candidate_id)
            if read_jsonl(decisions_path(root))[0][-1].get("conflict_acknowledged"):
                acknowledged_ids.append(candidate_id)
        check("no copy is refused and none needs an acknowledgement: the first copy "
              "of each pair whose answer flips names its twin as still to decide, "
              "and the second retires the old answer the first disagreed with",
              (refused, acknowledged_ids, pending),
              ([], [], ["CAND-0031", "CAND-0047", "CAND-0041", "CAND-0132",
                        "CAND-0162"]))
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("once each question has its new answer, check passes it", (code, out[-30:]),
              (0, "\ncheck: 0 problem(s)\n"))
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        decisions = json.loads(out)["decisions"]
        check("and status counts twelve standing, twelve retired, nothing unacknowledged",
              (decisions["standing"], decisions["retired_by_later_run"],
               decisions["unacknowledged_conflicts"]), (12, 12, 0))
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        for row in MBEDTLS_ROWS:
            candidate_id, path, name = row[0], row[3], os.path.basename(row[3])
            argv = (["reject", "--reason-code", "FP-TEST", "--reason",
                     "stack overflow in the ACVP test harness, acvp_mldsa.c:648"]
                    if candidate_id == "CAND-0052" else
                    ["out-of-scope", "--scope-code", "OOS-TEST-INFRA", "--basis",
                     "%s:%d" % (path, MBEDTLS_NOTES[name][0]), "--reason",
                     "real, in the psasim simulator, which says it is not secure"])
            _invoke(argv + ["--root", root, "--candidate", candidate_id, "--author",
                            "MP"], bundle)

        def confirm(candidate_id, *extra):
            return _invoke(["confirm", "--root", root, "--candidate", candidate_id,
                            "--author", "MP", "--reason",
                            "psasim ships in the product after all, CMakeLists.txt:12"]
                           + list(extra), bundle)

        _rerun(root, "2026-10-06T09-00-00Z")
        code, out, message = confirm("CAND-0031")
        check("the next run's confirmation of one copy is recorded over the other "
              "copy's earlier-run out-of-scope, which CAND-0010 asks again in this "
              "run, retiring its own old answer and naming the copy still to decide",
              (code, "retires DEC-0001" in out,
               "disagrees with DEC-0004 (out_of_scope CAND-0010" in out,
               "CAND-0010 asks again in this run" in out,
               read_jsonl(decisions_path(root))[0][-1]["conflict_acknowledged"]),
              (0, True, True, True, None))
        code, out, message = _invoke(["check", "--root", root], os.path.dirname(_HERE))
        check("until it is decided, check reports the pair and names CAND-0010",
              (code, "Record a new decision on CAND-0010" in out), (EXIT_REFUSED, True))
        code, out, message = confirm("CAND-0010")
        check("the other copy's confirmation needs no acknowledgement either: it "
              "retires the out-of-scope it disagreed with", (code, message), (0, ""))
        _rerun(root, "2026-10-13T09-00-00Z")
        check("and a run later both are confirmed again with nothing to acknowledge",
              (confirm("CAND-0031")[0], confirm("CAND-0010")[0]), (0, 0))
        check("with check passing", _invoke(["check", "--root", root],
                                            os.path.dirname(_HERE))[0], 0)

    # ---- a legacy FP-TEST on a stage 1 test file whose function is gone ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        os.makedirs(ledger_dir(root))
        with open(decisions_path(root), "w", encoding="utf-8") as fh:
            for index, key in enumerate(("pkg/server/conn_test.go::TestReplay::0",
                                         "app/__tests__/x.test.js::helper::0",
                                         "spec/foo_spec.rb::run::0",
                                         MBEDTLS_FW + "psa_ff_server.c::psa_wait::0"), 1):
                fh.write(json.dumps({
                    "schema_version": 1, "decision_id": "DEC-%04d" % index,
                    "at": "2026-09-19T05:00:0%dZ" % index, "author": "a@example.com",
                    "run_id": "2026-09-19T04-31-46Z",
                    "candidate_id": "CAND-%04d" % (index + 10), "function_key": key,
                    "content_hash": "%016x" % index, "rule_id": "MEM-WFS",
                    "cwe": "CWE-119", "decision": "rejected", "reason_code": "FP-TEST",
                    "reason": "only the test build links it",
                    "snapshot": {"file": key.split("::")[0], "rule_ids": ["MEM-WFS"]}})
                    + "\n")
        for label, drop in (("its function missing from the extract", False),
                            ("no extract at all", True)):
            if drop:
                os.remove(os.path.join(run_dir(root), "extract", "functions.jsonl"))
            code, out, message = _invoke(["check", "--root", root], real_bundle)
            # Stage 1's own rules place the first three in its test tree, and
            # whether that bears FP-TEST out is the findings gate's answer for
            # a validator's on the same file, whatever that answer is today.
            gate = _sibling("verify_findings")
            contradicted = ["DEC-%04d" % index for index, path in enumerate(
                ("pkg/server/conn_test.go", "app/__tests__/x.test.js",
                 "spec/foo_spec.rb"), 1)
                if not (gate and gate.fp_test_basis(path, {
                    "file": path, "in_test_tree": True,
                    "exposure": {"path_class_basis": "in-test-tree"}}))]
            check("a line written before in_test_tree, with %s: _test.go, __tests__/ "
                  "and spec/ are reported exactly where the findings gate contradicts "
                  "a validator's FP-TEST on stage 1's own test names, saying so, and "
                  "psasim is reported without claiming in_test_tree false" % label,
                  (sorted(d for d in ("DEC-0001", "DEC-0002", "DEC-0003", "DEC-0004")
                          if "%s rejects" % d in out),
                   "stage 1's own test-tree rules do not place it in one either" in out,
                   "in_test_tree false" in out,
                   bool(contradicted) == ("by stage 1's own test names alone" in out)),
                  (contradicted + ["DEC-0004"], True, False, True))

    # ---- the arbiter's CWE, read as the twin gate reads it ---- #
    gate = _sibling("verify_findings")
    pre = {"verdict": "VULNERABLE", "severity": "high", "cwe": "CWE-119"}
    for spelling in ("cwe", "CWE", "final_cwe", "original_cwe", " cwe ", " Final_CWE "):
        arb = {"arbitration": "UPHELD_MODIFIED", "final_verdict": "VULNERABLE",
               "final_severity": "high",
               "changes": [{"field": spelling, "from": "CWE-119", "to": "CWE-787",
                            "reason": "the copy writes past the end"}]}
        got = adjudicated_cwe({"cwe": "CWE-119"}, pre, arb)
        check("a changes[] entry on %r is the arbiter's CWE" % spelling, got,
              ("CWE-787", "arbitration"))
        if gate is not None:
            check("and verify_findings' twin gate reads the same one",
                  gate.arb_final_state(arb, pre)[2], got[0])
    top = {"arbitration": "UPHELD", "final_verdict": "VULNERABLE", "final_cwe": "CWE-787"}
    check("a top-level final_cwe, a field the ARB schema does not have, is read by "
          "neither", (adjudicated_cwe({"cwe": "CWE-119"}, pre, top),
                      gate.arb_final_state(top, pre)[2] if gate else "CWE-119"),
          (("CWE-119", "finding"), "CWE-119"))
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        rows = dict((row[0], row) for row in MBEDTLS_ROWS)
        for spelling in ("final_cwe", "CWE"):
            _rewrite(root, "arbitration", "ARB-CAND-0162.json",
                     arbitration="UPHELD_MODIFIED",
                     changes=[{"field": spelling, "from": "CWE-119", "to": "CWE-787",
                               "reason": "the copy writes past buf, as its twin does"}])
            if os.path.exists(decisions_path(root)):
                os.remove(decisions_path(root))
            for candidate_id in ("CAND-0162", "CAND-0164"):
                _invoke(["out-of-scope", "--root", root, "--candidate", candidate_id,
                         "--author", "MP", "--scope-code", "OOS-TEST-INFRA", "--basis",
                         "%s:%d" % (rows[candidate_id][3],
                                    MBEDTLS_NOTES["psa_ff_client.c"][0]),
                         "--reason", "real, in the psasim simulator, which says it is "
                                     "not secure"], bundle)
            first = read_jsonl(decisions_path(root))[0][0]
            _invoke(["export", "--root", root, "--include-out-of-scope"], bundle)
            check("the psa_call CWE the gate aligned under %r is the one the ledger "
                  "records, and the twins export as one sample" % spelling,
                  (first["cwe"], first["snapshot"]["cwe_source"],
                   [(s["cwe"], s["also_at"]) for s in read_jsonl(samples_path(root))[0]]),
                  ("CWE-787", "arbitration",
                   [("CWE-787", [_mbedtls_key(rows["CAND-0162"])])]))

    # ---- pending names the copies already answered, and the ones dismissed ---- #
    fw_key = MBEDTLS_FW + "psa_ff_client.c::process_response::0"
    tf_key = MBEDTLS_TF + "psa_ff_client.c::process_response::0"
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)

        def shape():
            code, out, message = _invoke(["pending", "--root", root, "--json"], bundle)
            return [t for t in json.loads(out)["review_set_shape"]["twins"]
                    if t["name"] == "process_response"], json.loads(out)

        for candidate_id in ("CAND-0031", "CAND-0047", "CAND-0041"):
            _invoke(["confirm", "--root", root, "--candidate", candidate_id, "--author",
                     "MP", "--reason", "no guard bounds the memcpy size"], bundle)
        twin, got = shape()
        check("a resumed session: process_response is still one body at two paths, its "
              "undecided copy listed with the three decisions on the other",
              [(t["function_keys"], t["candidate_ids"],
                [(c["decision_id"], c["decision"], c["function_key"])
                 for c in t.get("decided") or []]) for t in twin],
              [([fw_key], [["CAND-0010", "CAND-0020", "CAND-0026"]],
                [("DEC-0001", "confirmed", tf_key), ("DEC-0002", "confirmed", tf_key),
                 ("DEC-0003", "confirmed", tf_key)])])
        shape_now = got["review_set_shape"]
        check("while the counts stay over what is undecided",
              (shape_now["findings"], len(shape_now["merged"]), shape_now["bodies"],
               shape_now["paths"]), (7, 2, 5, 7))
        code, out, message = _invoke(["pending", "--root", root], bundle)
        check("the text form names each decided copy by id and path",
              ("one body at 2 paths: 33bd5b6cc79c1924 process_response - CAND-0010, "
               "CAND-0020, CAND-0026" in out,
               "decided: DEC-0001 confirmed CAND-0031 MEM-WFS at %s" % tf_key in out),
              (True, True))
        _rerun(root, "2026-10-06T09-00-00Z")
        twin, got = shape()
        check("in the next run both copies are undecided again, and the earlier run's "
              "answers are still named beside them",
              [(t["function_keys"], [c["decision_id"] for c in t.get("decided") or []])
               for t in twin], [([fw_key, tf_key], ["DEC-0001", "DEC-0002", "DEC-0003"])])
        code, out, message = _invoke(["pending", "--root", root], bundle)
        check("with the run they were given in",
              "decided in run %s: DEC-0001 confirmed CAND-0031" % MBEDTLS_RUN in out, True)
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        for candidate_id in ("CAND-0010", "CAND-0020", "CAND-0026"):
            _rewrite(root, "arbitration", "ARB-%s.json" % candidate_id,
                     arbitration="UPHELD", final_verdict="NOT_VULNERABLE",
                     merged_into=None)
        twin, got = shape()
        check("a copy dismissed at the other path is named beside the one still to "
              "decide, as held back",
              [(t["function_keys"], [(c["candidate_id"], c["verdict"])
                                     for c in t.get("held_back") or []]) for t in twin],
              [([tf_key], [("CAND-0010", "NOT_VULNERABLE"),
                           ("CAND-0020", "NOT_VULNERABLE"),
                           ("CAND-0026", "NOT_VULNERABLE")])])
        check("and the counts stay over the review set",
              (got["review_set_shape"]["bodies"], got["review_set_shape"]["paths"]),
              (5, 7))
        code, out, message = _invoke(["pending", "--root", root], bundle)
        check("the text form names it, with its verdict",
              "held back: CAND-0010 NOT_VULNERABLE MEM-WFS at %s" % fw_key in out, True)

    # ---- two sinks of one rule at two copies are two questions ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        rows = dict((row[0], row) for row in MBEDTLS_ROWS)

        def legacy_ledger(*decided):
            os.makedirs(ledger_dir(root), exist_ok=True)
            with open(decisions_path(root), "w", encoding="utf-8") as fh:
                for index, (candidate_id, decision, code) in enumerate(decided):
                    fh.write(json.dumps(_mbedtls_legacy(
                        index, rows[candidate_id], decision, code,
                        "len is bounded by the caller, psa_ff_client.c:140" if code
                        else "no guard bounds the memcpy size"), sort_keys=True) + "\n")

        # CAND-0047 is the tf copy's MEM-002 sink at +82, CAND-0020 the framework
        # copy's other MEM-002 sink, at +54, and CAND-0026 the framework copy's +82.
        legacy_ledger(("CAND-0047", "confirmed", None),
                      ("CAND-0020", "rejected", "FP-SIZED-CORRECTLY"))
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("legacy decisions on two different MEM-002 sinks of the two copies are "
              "two questions: this run's candidates say where each sink is",
              (code, "0 problem(s)" in out), (0, True))
        code, out, message = _invoke(["status", "--root", root, "--json"], bundle)
        check("and status agrees",
              json.loads(out)["decisions"]["unacknowledged_conflicts"], 0)
        code, out, message = _invoke(
            ["reject", "--root", root, "--candidate", "CAND-0020", "--author", "MP",
             "--reason-code", "FP-SIZED-CORRECTLY", "--reason",
             "len is bounded by the caller, psa_ff_client.c:140"], bundle)
        check("re-deciding the +54 sink is no conflict with the +82 one", code, 0)
        legacy_ledger(("CAND-0047", "confirmed", None),
                      ("CAND-0026", "rejected", "FP-SIZED-CORRECTLY"))
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("while the same sink at the two copies, answered two ways, is still "
              "reported, with no doubt about the sink",
              (code, "DEC-0001 (confirmed CAND-0047" in out
               and "DEC-0002 (rejected CAND-0026" in out,
               "may be different sinks" in out), (EXIT_REFUSED, True, False))
        legacy_ledger(("CAND-0047", "confirmed", None),
                      ("CAND-0020", "rejected", "FP-SIZED-CORRECTLY"))
        _rerun(root, "2026-10-06T09-00-00Z")
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("from a run whose candidates are gone the offsets cannot be read back, "
              "so the pair is reported, saying it may be two sinks",
              (code, "DEC-0001 and DEC-0002 record no sink offset" in out),
              (EXIT_REFUSED, True))
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)

        def decide(candidate_id, verb, *extra):
            return _invoke([verb, "--root", root, "--candidate", candidate_id, "--author",
                            "MP", "--reason", "len is bounded by the caller, "
                            "psa_ff_client.c:140"] + list(extra), bundle)[0]

        check("decisions this version records carry their offsets: the +54 sink is "
              "no twin of the +82 one, and the other copy's +82 is",
              (decide("CAND-0047", "confirm"),
               decide("CAND-0020", "reject", "--reason-code", "FP-SIZED-CORRECTLY"),
               decide("CAND-0026", "reject", "--reason-code", "FP-SIZED-CORRECTLY")),
              (0, 0, EXIT_REFUSED))

    # ---- a decision on a renumbered candidate retires its own run's answer ---- #
    # Re-running stage 3 under one run_id renumbers the candidates. A rejection
    # of CAND-0004 with FP-GUARDED and a confirmation of the same sink as
    # CAND-0009, the validator now naming CWE-120, were both exported: the
    # adjudicated CWEs kept the dedup from folding them, and one run's two
    # candidates were never read as one question.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["reject", "--root", root, "--candidate", "CAND-0004", "--author",
                 "a@example.com", "--reason-code", "FP-GUARDED", "--reason",
                 "n is clamped at parse.c:14"], bundle)
        path = os.path.join(run_dir(root), "candidates", "memory-safety.json")
        with open(path, encoding="utf-8") as fh:
            records = json.load(fh)
        for record in records:
            if record["candidate_id"] == "CAND-0004":
                record["candidate_id"] = "CAND-0009"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(records, fh)
        os.rename(os.path.join(run_dir(root), "findings", "CAND-0004.json"),
                  os.path.join(run_dir(root), "findings", "CAND-0009.json"))
        _rewrite(root, "findings", "CAND-0009.json", candidate_id="CAND-0009",
                 verdict="VULNERABLE", cwe="CWE-120")
        code, out, message = _invoke(["confirm", "--root", root, "--candidate",
                                      "CAND-0009", "--author", "a@example.com",
                                      "--reason", "the clamp at parse.c:14 misses n"],
                                     bundle)
        check("confirming the same sink under its renumbered id retires this run's "
              "rejection, and says why",
              (code, "retires DEC-0001 (rejected CAND-0004) - this run's answer to the "
                     "same sink" in out), (0, True))
        code, out, message = _invoke(["export", "--root", root], bundle)
        check("and the export writes the correction alone, naming what it retired",
              (code, [(s["decision_id"], s["label"], s["cwe"])
                      for s in read_jsonl(samples_path(root))[0]],
               "DEC-0001 into DEC-0002" in out),
              (0, [("DEC-0002", "vulnerable", "CWE-120")], True))
        decisions = json.loads(_invoke(["status", "--root", root, "--json"],
                                       bundle)[1])["decisions"]
        check("status counts the rejection as retired on a renumbered candidate, not "
              "by a later run",
              (decisions["standing"], decisions["retired_on_renumbered_candidate"],
               decisions["retired_by_later_run"], decisions["by_decision"]["rejected"]),
              (1, 1, 0, 0))
        check("and check agrees", _invoke(["check", "--root", root],
                                          os.path.dirname(_HERE))[0], 0)

    def _one_run(candidate_id, decision, line, at):
        snapshot = {"candidate_line": line} if line is not None else {}
        return {"decision_id": "DEC-%s" % candidate_id[-4:], "at": at,
                "run_id": "R1", "candidate_id": candidate_id,
                "function_key": "src/parse.c::handle_conn::0",
                "content_hash": "f81682d7bcfeac28", "rule_id": "MEM-003",
                "decision": decision, "snapshot": snapshot}

    for label, lines, want in (
            ("two sinks of one rule in one function, one run", (17, 21), 2),
            ("the same sink, twice, in one run", (17, 17), 1),
            ("lines written before candidate_line, in one run", (None, None), 2)):
        current, _ = current_answers([
            _one_run("CAND-0004", "rejected", lines[0], "2026-09-19T05:00:00Z"),
            _one_run("CAND-0009", "confirmed", lines[1], "2026-09-19T05:00:01Z")])
        check("%s: %d current answer(s)" % (label, want), len(current), want)

    # ---- a later run's needs-info is no answer, and retires none ---- #
    # It retired the earlier run's confirmation: the export dropped the sample,
    # status stopped counting it, and on the Mbed TLS ledger `check` dropped the
    # FP-TEST hard negative and the twin and MERGED conflicts it was part of,
    # with no answer given and nothing acknowledged.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        _invoke(["confirm", "--root", root, "--candidate", "CAND-0004", "--author",
                 "a@example.com", "--reason", "n is unbounded"], bundle)
        _rerun(root, "2026-10-01T00-00-00Z")
        code, out, message = _invoke(["needs-info", "--root", root, "--candidate",
                                      "CAND-0004", "--author", "b@example.com",
                                      "--reason", "need to see the caller"], bundle)
        check("a later run's needs-info on the same question is recorded and retires "
              "nothing", (code, "retires" in out), (0, False))
        code, out, message = _invoke(["export", "--root", root], bundle)
        check("the export still writes the confirmation",
              [(s["decision_id"], s["label"]) for s in read_jsonl(samples_path(root))[0]],
              [("DEC-0001", "vulnerable")])
        decisions = json.loads(_invoke(["status", "--root", root, "--json"],
                                       bundle)[1])["decisions"]
        check("and status counts both", (decisions["standing"],
                                         decisions["by_decision"]["confirmed"],
                                         decisions["by_decision"]["needs_info"]),
              (2, 1, 1))
        code, out, message = _invoke(["reject", "--root", root, "--candidate",
                                      "CAND-0004", "--author", "b@example.com",
                                      "--reason-code", "FP-GUARDED", "--reason",
                                      "n is clamped at parse.c:14"], bundle)
        check("an answer after it supersedes it and retires the confirmation",
              (code, "supersedes DEC-0002" in out, "retires DEC-0001" in out),
              (0, True, True))
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        rows = dict((row[0], row) for row in MBEDTLS_ROWS)
        os.makedirs(ledger_dir(root))
        with open(decisions_path(root), "w", encoding="utf-8") as fh:
            for index, (c, d, code, r) in enumerate(MBEDTLS_SESSION):
                fh.write(json.dumps(_mbedtls_legacy(index, rows[c], d, code, r)) + "\n")
        _rerun(root, "2026-10-06T09-00-00Z")
        before = _invoke(["check", "--root", root], real_bundle)[1]
        _invoke(["needs-info", "--root", root, "--candidate", "CAND-0010", "--author",
                 "MP", "--reason", "need to know whether psasim ships"], bundle)
        after = _invoke(["check", "--root", root], real_bundle)[1]
        check("on the Mbed TLS ledger a next-run needs-info on CAND-0010 leaves every "
              "problem reported, DEC-0004's FP-TEST and its twin conflict included",
              (after.splitlines()[-1] == before.splitlines()[-1],
               "DEC-0004 rejects CAND-0010 with FP-TEST" in after,
               "DEC-0001 (confirmed CAND-0031" in after and "DEC-0004 (rejected" in after),
              (True, True, True))

    # ---- an answer nothing can answer again is withdrawn by name ---- #
    # The Mbed TLS FP-TEST on psasim's psa_wait, carried into a run where that
    # body had been edited: every psasim candidate was recorded out of scope, as
    # check advised, and check went on reporting it in every session after,
    # since the edited body is another question and no command reached it.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        real_bundle = os.path.dirname(_HERE)
        rows = dict((row[0], row) for row in MBEDTLS_ROWS)
        os.makedirs(ledger_dir(root))
        with open(decisions_path(root), "w", encoding="utf-8") as fh:
            for index, (c, d, code, r) in enumerate(MBEDTLS_SESSION):
                line = _mbedtls_legacy(index, rows[c], d, code, r)
                if c == "CAND-0132":
                    line["content_hash"] = "00000000deadbeef"   # the body since edited
                fh.write(json.dumps(line) + "\n")
        _rerun(root, "2026-10-06T09-00-00Z")

        def withdraw(decision_id, *reason):
            return _invoke(["withdraw", "--root", root, "--decision", decision_id,
                            "--author", "MP"] + (["--reason", reason[0]] if reason
                                                 else []), bundle)

        code, out, message = withdraw("DEC-0001", "psasim ships after all")
        check("a withdrawal is refused while a candidate of this run asks the same "
              "question, naming it", (code, "CAND-0031 asks DEC-0001's question again"
                                      in message), (EXIT_REFUSED, True))
        for row in MBEDTLS_ROWS:
            candidate_id, path = row[0], row[3]
            argv = (["reject", "--reason-code", "FP-TEST", "--reason",
                     "stack overflow in the ACVP test harness, acvp_mldsa.c:648"]
                    if candidate_id == "CAND-0052" else
                    ["out-of-scope", "--scope-code", "OOS-TEST-INFRA", "--basis",
                     "%s:%d" % (path, MBEDTLS_NOTES[os.path.basename(path)][0]),
                     "--reason", "real, in the psasim simulator, which says it is "
                                 "not secure"])
            _invoke(argv + ["--root", root, "--candidate", candidate_id, "--author",
                            "MP"], bundle)
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("every psasim candidate re-decided, check reports the edited body's "
              "FP-TEST alone and names withdraw, not a candidate that is not there",
              (code, out.splitlines()[-1], "DEC-0009 rejects CAND-0132" in out,
               "`ledger.py withdraw --decision DEC-0009" in out),
              (EXIT_REFUSED, "check: 1 problem(s)", True, True))
        check("a withdrawal with no reason is refused", withdraw("DEC-0009")[0],
              EXIT_REFUSED)
        code, out, message = withdraw("DEC-0009", "psasim is no test code; the body "
                                                  "this labelled is gone")
        check("withdrawn, it is superseded on its own key", (code, "supersedes DEC-0009"
                                                            in out), (0, True))
        withdrawal = read_jsonl(decisions_path(root))[0][-1]
        check("the line names what it withdraws and the run it was withdrawn in",
              (withdrawal["decision"], withdrawal["withdraws"],
               withdrawal["withdrawn_in_run"], decision_key(withdrawal)
               == decision_key(read_jsonl(decisions_path(root))[0][8])),
              (WITHDRAWN, "DEC-0009", "2026-10-06T09-00-00Z", True))
        check("and check passes", _invoke(["check", "--root", root], real_bundle)[0], 0)
        code, out, message = _invoke(["export", "--root", root], bundle)
        check("the export leaves it out and counts it",
              ([s for s in read_jsonl(samples_path(root))[0]
                if s["decision_id"] == "DEC-0009"],
               "1 withdrawn decision(s) are not samples" in out), ([], True))
        check("status counts it", json.loads(_invoke(
            ["status", "--root", root, "--json"], bundle)[1])["decisions"]["by_decision"]
              [WITHDRAWN], 1)
        check("an answer already withdrawn, and a withdrawal, cannot be withdrawn",
              (withdraw("DEC-0009", "again")[0],
               withdraw(withdrawal["decision_id"], "again")[0]),
              (EXIT_REFUSED, EXIT_REFUSED))
        with open(decisions_path(root), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(withdrawal, decision_id="DEC-0099",
                                     withdraws="DEC-9999")) + "\n")
        code, out, message = _invoke(["check", "--root", root], real_bundle)
        check("check reports a withdrawal that names no decision in the trail",
              (code, "withdraws 'DEC-9999', which is no decision in this file" in out),
              (EXIT_REFUSED, True))
    # An earlier run's answer on a twin that no candidate of this run asks: the
    # refusal named "a new decision on that function's candidate in this run"
    # as the way through, and there was no such candidate.
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _fixture(tmp), _bundle(tmp)
        os.makedirs(ledger_dir(root))
        with open(decisions_path(root), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({
                "schema_version": 1, "decision_id": "DEC-0001",
                "at": "2026-09-01T05:00:00Z", "author": "a@example.com",
                "run_id": "2026-09-01T04-00-00Z", "candidate_id": "CAND-0007",
                "function_key": "vendor/parse.c::handle_conn::0",
                "content_hash": "f81682d7bcfeac28", "rule_id": "MEM-003",
                "cwe": "CWE-787", "decision": "rejected", "reason_code": "FP-GUARDED",
                "reason": "n is clamped by the vendor caller",
                "snapshot": {"file": "vendor/parse.c", "rule_ids": ["MEM-003"]}}) + "\n")

        def confirm():
            return _invoke(["confirm", "--root", root, "--candidate", "CAND-0004",
                            "--author", "a@example.com", "--reason",
                            "n is unbounded from the peer"], bundle)

        code, out, message = confirm()
        check("a confirmation disagreeing with an earlier run's answer on a twin no "
              "candidate of this run asks is refused, naming withdraw as the way to "
              "replace it", (code, "`ledger.py withdraw --decision DEC-0001`" in message),
              (EXIT_REFUSED, True))
        code, out, message = _invoke(["withdraw", "--root", root, "--decision",
                                      "DEC-0001", "--author", "a@example.com",
                                      "--reason", "the vendored copy was removed"],
                                     bundle)
        check("withdrawn, the twin's old answer no longer stands in the way",
              (code, confirm()[0]), (0, 0))

    # ---- the arbiter's CWE, spelled as the twin gate compares it ---- #
    # The gate compares _cwe_number(cwe), so an arbiter's `to: "cwe-787"`
    # aligned a copy with its twin's CWE-787 there; the ledger recorded the
    # string as written and the export wrote the twins as two samples.
    gate = _sibling("verify_findings")
    pre = {"verdict": "VULNERABLE", "severity": "high", "cwe": "CWE-119"}
    for value in ("cwe-787", "CWE 787", "CWE-787 (Out-of-bounds Write)", " CWE-787 ",
                  ["CWE-787", "CWE-120"]):
        arb = {"arbitration": "UPHELD_MODIFIED", "final_verdict": "VULNERABLE",
               "final_severity": "high",
               "changes": [{"field": "cwe", "from": "CWE-119", "to": value,
                            "reason": "the copy writes past the end"}]}
        got = adjudicated_cwe({"cwe": "CWE-119"}, pre, arb)
        check("an arbiter's %r is recorded as CWE-787" % (value,), got,
              ("CWE-787", "arbitration"))
        if gate is not None:
            check("and the twin gate compares the same",
                  gate._cwe_number(gate.arb_final_state(arb, pre)[2]), got[0])
    for value in ("CWE-787", "cwe-121", "CWE 20", "787", ["CWE-125"], None, "", "b", 42):
        if gate is not None:
            check("cwe_id(%r) reads as verify_findings._cwe_number does" % (value,),
                  cwe_id(value), gate._cwe_number(value))
    check("a CWE with no number is kept as written, not recorded as null",
          (spelled_cwe("b"), spelled_cwe(None)), ("b", None))
    with tempfile.TemporaryDirectory() as tmp:
        root, bundle = _mbedtls_fixture(tmp), _bundle(tmp)
        rows = dict((row[0], row) for row in MBEDTLS_ROWS)
        _rewrite(root, "arbitration", "ARB-CAND-0162.json", arbitration="UPHELD_MODIFIED",
                 changes=[{"field": "cwe", "from": "CWE-119", "to": "cwe-787",
                           "reason": "the copy writes past buf, as its twin does"}])
        for candidate_id in ("CAND-0162", "CAND-0164"):
            _invoke(["out-of-scope", "--root", root, "--candidate", candidate_id,
                     "--author", "MP", "--scope-code", "OOS-TEST-INFRA", "--basis",
                     "%s:%d" % (rows[candidate_id][3], MBEDTLS_NOTES["psa_ff_client.c"][0]),
                     "--reason", "real, in the psasim simulator, which says it is "
                                 "not secure"], bundle)
        check("both copies of psa_call record CWE-787",
              [r["cwe"] for r in read_jsonl(decisions_path(root))[0]],
              ["CWE-787", "CWE-787"])
        with open(decisions_path(root), encoding="utf-8") as fh:
            lines = [json.loads(line) for line in fh]
        lines[0]["cwe"] = "cwe-787"                  # as the last version wrote it
        with open(decisions_path(root), "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(line) + "\n" for line in lines))
        code, out, message = _invoke(["export", "--root", root,
                                      "--include-out-of-scope"], bundle)
        check("and the export writes the twins once, an older line's spelling "
              "included", [(s["cwe"], len(s["also_at"]))
                           for s in read_jsonl(samples_path(root))[0]],
              [("CWE-787", 1)])

    # ---- a person's FP-TEST is borne out where a validator's is ---- #
    # ledger.py took any in_test_tree after the findings gate stopped taking
    # stage 1's own test names: a person's FP-TEST on OpenSSL's
    # providers/fips/self_test.c, in the test tree by the `_test.` rule alone,
    # was recorded, where a validator's is disqualifier_contradicted.
    gate = _sibling("verify_findings")
    fips = "providers/fips/self_test.c"
    for basis in ("in-test-tree", "test-tree-globs", None):
        with tempfile.TemporaryDirectory() as tmp:
            root, bundle = _fixture(tmp), _bundle(tmp)
            path = os.path.join(run_dir(root), "candidates", "memory-safety.json")
            with open(path, encoding="utf-8") as fh:
                records = json.load(fh)
            for record in records:
                if record["candidate_id"] == "CAND-0004":
                    record.update(file=fips, in_test_tree=True,
                                  exposure={"path_class": "test",
                                            "path_class_basis": basis})
                    asked_of_gate = dict(record)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(records, fh)
            code, out, message = _invoke(["reject", "--root", root, "--candidate",
                                          "CAND-0004", "--author", "a@example.com",
                                          "--reason-code", "FP-TEST", "--reason",
                                          "the FIPS self-test"], bundle)
            borne = bool(gate and gate.fp_test_basis(fips, asked_of_gate))
            check("a person's FP-TEST on %s, in stage 1's test tree by %s, is recorded "
                  "exactly when the findings gate bears a validator's out there"
                  % (fips, basis or "an unrecorded basis"),
                  code, 0 if borne else EXIT_REFUSED)
            if not borne:
                check("and the refusal says how stage 1 put it there",
                      "stage 1 placed it in its test tree" in message, True)
                os.makedirs(ledger_dir(root), exist_ok=True)
                with open(decisions_path(root), "w", encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "schema_version": 1, "decision_id": "DEC-0001",
                        "at": "2026-09-19T05:00:00Z", "author": "a@example.com",
                        "run_id": "2026-09-19T04-31-46Z", "candidate_id": "CAND-0004",
                        "function_key": fips + "::handle_conn::0",
                        "content_hash": "f81682d7bcfeac28", "rule_id": "MEM-003",
                        "decision": "rejected", "reason_code": "FP-TEST",
                        "reason": "the FIPS self-test",
                        "snapshot": {"file": fips, "in_test_tree": True,
                                     "path_class_basis": basis}}) + "\n")
                check("and check reports the same line when it is in the ledger",
                      "DEC-0001 rejects CAND-0004 with FP-TEST" in _invoke(
                          ["check", "--root", root], os.path.dirname(_HERE))[1], True)

    print("\nselftest: %d failure(s)" % failures)
    return EXIT_REFUSED if failures else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
