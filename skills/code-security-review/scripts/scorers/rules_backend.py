#!/usr/bin/env python3
"""
rules_backend.py - the scoring backend that exists today, and the one the whole
pipeline falls back to when nothing else is configured.

It is a weighted sum. That is not an apology: the alternative is a model reading
a function and writing down a number between 0 and 1, and when that number is
wrong there is nothing to inspect, nothing to tune, and no way to tell a flat
ranking from a confident one.
An opaque heuristic nobody can tune is worse than a crude one that they can, so
every weight this backend applies is in WEIGHTS below, in one dict, documented in
the table under it, and printed into scorer-report.json on every run.

What it is not: a model of exploitability. A vulnerable function that trips no
rule, sits far from a measured entry point and has not been touched in two years
scores near the bottom here and a run that stops at 400 candidates never reaches
it. README says so in those words, `not_selected_is_not_a_clean_bill` says so in
the artefact, and the fine-tuned backend is the thing meant to narrow it.

THE SCORE IS A RANK FRACTION. The weighted sum has no scale anybody can read -
"11.5" is not 11.5 of anything - so the backend declares `rank_normalised` and
score_functions.py replaces the sum with its position in the corpus. A reader who
notices that `score` and `percentile` then track each other has understood the
backend exactly: the number IS the ordering, which is what `score_kind:
"ordinal"` has been saying all along.

score_kind is ALWAYS "ordinal" here. There is no configuration that changes it,
because there is no evaluation set that could calibrate a sum of hand-set weights
into a probability of anything.

Stdlib only. Python 3.8+.
"""

import collections
import json
import math
import os

from . import base

# --------------------------------------------------------------------------- #
# the weighting, in one place, so it can be argued with
# --------------------------------------------------------------------------- #
#
#   component                       range      what it reads
#   ------------------------------- ---------- --------------------------------
#   rule weight, diminishing and     0 .. 16   per rule: rule.weight x f(n) over
#   saturating                                 the function's n emitted hits of
#                                              it, then summed and capped
#   high-signal bonus                0 ..  4   distinct high_signal rules hit
#   entry-point reachability         0 ..  3   scope/graph.json, per FILE
#   churn                            0 .. 2.25 the record's git block
#   test-tree penalty               -6 ..  0   in_test_tree
#   generated-file penalty          -3 ..  0   generated_file
#   sample-tree penalty             -3 ..  0   a directory of `file` named in
#                                              SAMPLE_DIR_NAMES
#
# Four decisions in that table are worth the sentences they cost.
#
# Repeats of one rule DIMINISH. f(n) = (1 - d)*n + d*(1 + log2 n), with d the
# `repeat_decay` weight: at d = 1, 1, 2, 4 and 8 hits of a rule count 1, 2, 3
# and 4 times its weight, and at d = 0 the sum is the linear one rules@1.0.0
# shipped. A linear count ranks by size: HW-001 matches every switch and
# else-if, HW-004 every loop and INJ-001 every printf, so libxml2's xmlShell
# collected 91 INJ-001 hits, while the vulnerable functions of the golden
# cases are mostly 25 to 180 lines with 3 to 13 hits over 3 to 8 distinct
# rules. Breadth of evidence is the signal; the tenth printf is not. A single
# hit counts exactly its weight at any d, because log2(1) is 0, so decay never
# lifts a lone hit above what rules@1.0.0 gave it: before any high-signal
# bonus, one hit of a weight-1 or weight-2 rule stays under an entry-point
# file (reach_0_1_hops, 3), and one of weight 3 ties it. The selftest pins
# both.
#
# The rule sum still SATURATES, at 16 now rather than 12. A parser with forty
# memcpy calls is not forty times more interesting than one with four; without
# a cap, file size creeps back into the ranking. At 12 the linear sum
# saturated for 90% of golden's top-200 functions, so the order inside that
# plateau fell to the function_id hash and the cut landed inside a tie of up
# to 208 functions. Re-scored from the same 13 cases' stage-1 output against
# rules@1.0.0, with the decay and the sample directories below held as
# shipped (the re-scoring reproduces the end-to-end run exactly): a cap of 16
# ranks six at 6.8% more stage-4 calls at the same cut, a cap of 20 ranks the
# same six at 13.7% more, and no cap at all ranks the same six at 23% more and
# drops CVE-2018-0487 from rank 8 to 67.
#
# Sample code is DEMOTED, not dropped. docs/examples/ held 46 to 58 of curl's
# top 200, and a project does not ship its examples. Only DIRECTORY names
# count, lower-cased, so `src/docs.c` is not a sample. contrib/ and programs/
# are deliberately not in the list: zlib's contrib/minizip is shipped code
# with CVEs of its own.
#
# Reachability only ever ADDS. build_graph.py's own docstring requires it: that
# graph is a textual over-approximation applied as a floor and never as a
# ceiling, so a function the graph cannot reach scores no bonus rather than a
# penalty. Function pointers, macro-generated dispatch and every language the
# graph does not index all land in "not reached", and penalising that would rank
# a callback-dispatched subsystem as dead code.
#
# Every new weight has a neutral value - repeat_decay 0, rule_weight_cap 12,
# sample_tree_penalty 0 - and together those reproduce rules@1.0.0 exactly, so
# the old ordering is one --config away and an A/B needs no second bundle.
WEIGHTS = {
    "rule_weight_cap": 16.0,
    "repeat_decay": 1.0,
    "high_signal_first": 2.0,
    "high_signal_each": 1.0,
    "high_signal_cap": 4.0,
    "reach_0_1_hops": 3.0,
    "reach_2_hops": 1.5,
    "reach_far": 0.5,
    "reach_unmeasured": 0.0,
    "churn_commits_5": 1.5,
    "churn_commits_1": 0.75,
    "churn_touched_30d": 0.75,
    "churn_touched_90d": 0.25,
    "test_tree_penalty": -6.0,
    "generated_penalty": -3.0,
    "sample_tree_penalty": -3.0,
    # A `window` record is a fixed range around a hit, not a function (contract
    # §4). It is still scored - dropping it would hide it - but it is not
    # allowed to outrank a parsed function on an equal sum, because its line
    # range is the one thing about it that is known to be wrong.
    "window_confidence_penalty": -1.0,
}

# Directory names that hold code a project documents or demonstrates rather
# than ships. Compared against each directory of a function's `file`,
# lower-cased; the file name itself is never compared.
SAMPLE_DIR_NAMES = frozenset(("example", "examples", "sample", "samples",
                              "demo", "demos", "doc", "docs"))


class RulesBackend(base.Backend):

    name = "rules"
    version = "1.1.0"
    score_kind = base.KIND_ORDINAL      # always, unconditionally
    calibration = None
    trained_context_profile = None      # reads no context window at all
    requires_explanations = False

    batch_size = 4096
    thread_safe = True
    rank_normalised = True
    requires_context_text = False
    # Nothing to resume. prepare() computes the sum for the whole corpus every
    # run, so a cache hit saves no work - and it is the only way to be served a
    # stale number, because the sum reads the config's weights, the rule
    # table, scope/graph.json and each record's git block, and none of those
    # moves a content hash. Re-running after a tuning change with --resume
    # served the old ordering back, 7 of 7 records marked valid.
    resumable = False

    def __init__(self, config=None):
        base.Backend.__init__(self, config)
        self.weights = dict(WEIGHTS)
        for key, value in (self.config.get("weights") or {}).items():
            if key not in WEIGHTS:
                raise base.BackendError(
                    "scorer config: unknown rules weight %r. Known weights: %s"
                    % (key, ", ".join(sorted(WEIGHTS))))
            self.weights[key] = float(value)
        decay = self.weights["repeat_decay"]
        if not 0.0 <= decay <= 1.0:
            # Outside [0, 1] the per-rule count is no longer between the log and
            # the linear one: above 1 it turns negative for a large n, which
            # would rank a function BELOW one with no hit at all.
            raise base.BackendError(
                "scorer config: rules weight repeat_decay is %r; it must be "
                "between 0 (hits count linearly, as rules@1.0.0) and 1 (log2)"
                % decay)
        self.rule_weight = {}
        self.rule_high_signal = {}
        self.file_hops = {}
        self._raw = {}

    def declaration(self):
        """base's declaration plus the weights this run actually applied.

        The module docstring promises every weight is in scorer-report.json,
        and a tuned config is only legible there if the report shows what it
        changed: the effective weights, config overrides included, and the
        directory names the sample-tree penalty matches.
        """
        out = base.Backend.declaration(self)
        out["weights"] = dict(self.weights)
        out["sample_dir_names"] = sorted(SAMPLE_DIR_NAMES)
        return out

    # -- lifecycle ---------------------------------------------------------- #

    def prepare(self, functions, rule_hits, config):
        run = config.get("_run") or {}
        self._load_rule_table(run.get("bundle_root"))
        self._load_graph(run.get("root"))

        index = base.index_hits(rule_hits)
        for fn in functions:
            hits = base.hits_for(fn, index)
            self._raw[fn["function_id"]] = (self._raw_score(fn, hits), hits)

    def raw_scores(self):
        """function_id -> the weighted sum, after prepare().

        Public because `llm-triage` orders inside its verdict buckets with it,
        and a second implementation of the weighting there would drift from this
        one the first time a weight is tuned.
        """
        return dict((fid, raw) for fid, (raw, _hits) in self._raw.items())

    def score_batch(self, items):
        out = []
        for item in items:
            fn = item["function"]
            raw, hits = self._raw.get(fn["function_id"], (None, item["rule_hits"]))
            if raw is None:                       # not seen by prepare(); score it now
                raw = self._raw_score(fn, hits)
            hit = base.top_hit(hits, weight_of=self.rule_weight.get)
            out.append({
                "score": raw,                     # replaced by the rank fraction
                "raw_score": raw,
                "weakness_class": (hit or {}).get("cwe"),
                "localized_line": self._line_in_range(fn, (hit or {}).get("line")),
                # No explanation. The rule hit IS the explanation and it is already
                # on the record as evidence_rule_hits; restating it as prose would
                # be a sentence a person could mistake for an assessment.
                "explanation": None,
            })
        return out

    # -- the weighting ------------------------------------------------------ #

    def _raw_score(self, fn, hits):
        w = self.weights
        total = 0.0

        rule_sum = 0.0
        high = set()
        decay = w["repeat_decay"]
        # Sorted, so one multiset of hits always sums in one order: log2 makes
        # the terms inexact, and hit order must not split a tie by a rounding
        # error.
        for rid, n in sorted(collections.Counter(
                hit.get("rule_id") or "" for hit in hits).items()):
            repeats = (1.0 - decay) * n + decay * (1.0 + math.log2(n))
            rule_sum += float(self.rule_weight.get(rid, 1.0)) * repeats
            if self.rule_high_signal.get(rid):
                high.add(rid)
        total += min(rule_sum, w["rule_weight_cap"])

        if high:
            bonus = w["high_signal_first"] + w["high_signal_each"] * (len(high) - 1)
            total += min(bonus, w["high_signal_cap"])

        total += self._reach_points(fn.get("file"))
        total += self._churn_points(fn.get("git") or {})

        if fn.get("in_test_tree"):
            total += w["test_tree_penalty"]
        if fn.get("generated_file"):
            total += w["generated_penalty"]
        if self.in_sample_tree(fn.get("file")):
            total += w["sample_tree_penalty"]
        if (fn.get("extractor") or {}).get("confidence") == "window":
            total += w["window_confidence_penalty"]
        return total

    @staticmethod
    def in_sample_tree(rel_path):
        """True when a DIRECTORY of `rel_path` is named in SAMPLE_DIR_NAMES."""
        parts = str(rel_path or "").replace("\\", "/").lower().split("/")[:-1]
        return any(part in SAMPLE_DIR_NAMES for part in parts)

    def _reach_points(self, rel_path):
        w = self.weights
        if not rel_path or not self.file_hops:
            return w["reach_unmeasured"]
        hops = self.file_hops.get(rel_path)
        if hops is None:
            return w["reach_unmeasured"]
        if hops <= 1:
            return w["reach_0_1_hops"]
        if hops == 2:
            return w["reach_2_hops"]
        return w["reach_far"]

    def _churn_points(self, git):
        w = self.weights
        points = 0.0
        commits = git.get("commits_90d")
        if isinstance(commits, int):
            if commits >= 5:
                points += w["churn_commits_5"]
            elif commits >= 1:
                points += w["churn_commits_1"]
        days = git.get("last_modified_days")
        if isinstance(days, int):
            if days <= 30:
                points += w["churn_touched_30d"]
            elif days <= 90:
                points += w["churn_touched_90d"]
        return points

    @staticmethod
    def _line_in_range(fn, line):
        lo, hi = fn.get("line_start"), fn.get("line_end")
        if not isinstance(line, int):
            return None
        if isinstance(lo, int) and isinstance(hi, int) and not (lo <= line <= hi):
            # The hit joined to this function by function_id, so a line outside
            # its range means stage 1's join and its boundaries disagree. Say
            # nothing rather than localise into another body.
            return None
        return line

    # -- inputs ------------------------------------------------------------- #

    def _load_rule_table(self, bundle_root):
        """rule_id -> (weight, high_signal), read through rules_lib.

        Read through rules_lib and not by hand, for the reason that module's own
        docstring gives: two loaders for one ruleset eventually disagree, and the
        checker built to catch the disagreement becomes the disagreement.
        """
        if not bundle_root:
            self.notes.append("no skill root was given, so every rule was weighted 1.0")
            return
        rules_dir = os.path.join(bundle_root, "assets", "rules")
        try:
            import rules_lib                      # sibling tool, same directory
            rules = rules_lib.load_rules(rules_dir)
        except Exception as exc:                  # noqa: BLE001
            self.notes.append(
                "%s: the rule table could not be read (%s), so every rule was "
                "weighted 1.0 and no high-signal bonus was applied"
                % (rules_dir, exc))
            return
        for rule in rules:
            # MEM-WFS is weighed like any rule, and since it became a C, C++ and
            # Rust pass its hit lands only on a function in one of those with a
            # candidate. In a tree that mixes them with other languages that is
            # a tilt of its weight toward them, on purpose: such a function
            # carries one more question for a validator to answer. In a tree of
            # only C, C++ and Rust it adds the same to every candidate-producing
            # function short of rule_weight_cap, as it always did, and in a tree
            # of none of them it adds nothing to any.
            self.rule_weight[rule["rule_id"]] = float(rule.get("weight") or 1.0)
            self.rule_high_signal[rule["rule_id"]] = bool(rule.get("high_signal"))

    def _load_graph(self, root):
        """scope/graph.json, if stage 0 produced one. Absent is normal, not an error."""
        if not root:
            return
        path = os.path.join(root, ".security-review", "scope", "graph.json")
        if not os.path.isfile(path):
            self.notes.append(
                "no .security-review/scope/graph.json, so reachability contributed "
                "nothing to any score; run build_graph.py to get it")
            return
        try:
            with open(path, encoding="utf-8") as fh:
                graph = json.load(fh)
        except (OSError, ValueError) as exc:
            raise base.BackendError("%s: %s" % (path, exc))
        files = graph.get("files")
        if not isinstance(files, dict):
            raise base.BackendError("%s:1: no `files` map; not a build_graph.py graph"
                                    % path)
        for rel, entry in files.items():
            hops = (entry or {}).get("hops")
            if isinstance(hops, int):
                self.file_hops[rel] = hops
        warning = (graph.get("health") or {}).get("warning")
        if warning:
            # build_graph refuses to let a flat index look healthy. Carry its own
            # words forward rather than applying its distances as if they held.
            self.notes.append("scope/graph.json carries a health warning, so its "
                              "reachability points are suspect: %s" % warning)
