#!/usr/bin/env python3
"""
base.py - what a scoring backend is, and what it is not allowed to conclude
about its own numbers.

The fine-tuned function-level classifier this pipeline is built around does not
exist yet. Every seam that would have to move when it lands is a seam that will
not move if it is cut now, against a backend that already runs - so this file
defines the interface twice over: once for the deterministic `rules` backend
that ships today, and once for a classifier that will answer over HTTP with a
log-probability nobody has trained yet.

The failure it prevents is specific. A backend that computes its own rank,
writes its own record and decides for itself whether its number is a probability
is a backend whose swap-in is a rewrite of stage 2 - and the first thing a
rewrite under deadline drops is the refusal in pipeline-contract §6. Where the
code that produces the numbers is also the code that describes them, one run can
record 111 mechanical problems and still report that the pipeline looks well
calibrated: nothing in it is positioned to notice the contradiction.

So a backend here DECLARES what it is (name, version, score_kind, calibration,
trained_context_profile, requires_explanations) and COMPUTES a number per
function. It never writes a score record, never picks the operating point, and
never gets to decide that its own output is calibrated. score_functions.py holds
those three, once, for all backends - which is why adopting a new one is a
config change and nothing else in the pipeline moves.

Stdlib only. Python 3.8+.
"""

import hashlib
import json
import math
import os
import tempfile

SCHEMA_VERSION = 1

KIND_ORDINAL = "ordinal"
KIND_PROBABILITY = "probability"
SCORE_KINDS = (KIND_ORDINAL, KIND_PROBABILITY)


class BackendError(Exception):
    """A backend that cannot produce a trustworthy number for this run.

    Always raised with the artefact that caused it - a source file and line, a
    verdict file, or an endpoint - because "the scorer failed" sends a reader
    through 18,000 records looking for the one that is wrong.
    """


class HandshakePending(Exception):
    """A backend that needs a turn from the driving agent before it can score.

    `llm-triage` is the only one today: it writes prompt files and reads verdict
    files back, and the model that answers them is the agent running the
    stage, not this process. score_functions.py catches this and exits 3 with
    the directory and the count, so re-running the identical command after the
    verdicts are written finishes the stage.
    """

    def __init__(self, message, directory, pending, examples=(), batch=(), route=None):
        Exception.__init__(self, message)
        self.directory = directory
        self.pending = pending
        self.examples = list(examples)
        # The manifests of the batches still to answer, relative to
        # `directory`. Each is answered as a unit, by a subagent whose context
        # holds that batch alone: one session answering them all re-sends every
        # earlier batch on every turn, and that is most of the bill.
        self.batch = list(batch)
        # Who should answer them: "workers" (one subagent per batch) or
        # "session" (the driving agent, one batch per turn), whichever the
        # backend estimated cheaper for this many.
        self.route = route


class RunPathError(Exception):
    """A write under .security-review/ that a symbolic link would redirect.

    Its own class rather than a BackendError, because it is not the scorer
    failing: it is the run directory being unfit to write into, and
    score_functions.py exits 2 on it - the setup code - whichever of stage 2's
    writers found the link, the tool itself or a backend writing under scores/.
    """


# --------------------------------------------------------------------------- #
# writing under the run directory
# --------------------------------------------------------------------------- #
#
# The run directory lives inside the SCANNED tree, and a repository can
# legitimately commit `.security-review/ledger/` (contract §1) - so a hostile
# clone can commit links under `.security-review/` too, and git keeps them. A
# write that follows one lands wherever it points: a planted
# `scores/operating-point.json -> ~/.bashrc` had stage 2 overwrite the
# operator's shell profile with its JSON and exit 0, and a predictable
# `path + ".tmp"` is the same hole one name over.
#
# So every file stage 2 writes goes through the functions below. They refuse
# (a) a run directory, or any existing directory under it on the write path,
# that is a link; (b) a target that is itself a link; (c) a run directory whose
# real path is not <real root>/.security-review. The root itself and its
# ancestors are never checked: --root may be a link, and on macOS /var is one.
# A whole file is written to a temp file mkstemp creates beside it - O_EXCL, so
# it never follows anything - and renamed into place.
#
# Every tool that writes under .security-review/ carries the same rule: this
# is stage 2's copy, shared by score_functions.py and the backends that write
# under scores/, and the others (snapshot.py, extract_functions.py,
# sweep_secrets.py, enrich_candidates.py, ledger.py, run_status.py,
# export_sarif.py) keep their own rather than import one another's.

def _refuse_link(link, run_dir):
    try:
        target = os.readlink(link)
    except OSError:
        target = "(unreadable)"
    raise RunPathError(
        "%s is a symbolic link to %s. Nothing is written through a link at or "
        "under the run directory: %s sits in the scanned tree, where a "
        "repository can ship links, and a write that followed this one would "
        "land outside it (pipeline-contract §1, §9 rule 2). Remove the link "
        "and re-run."
        % (link, target, run_dir))


def check_run_dir(root, run_dir):
    """Refuse a run directory that is a link, or that resolves anywhere else."""
    if os.path.islink(run_dir):
        _refuse_link(run_dir, run_dir)
    if not os.path.lexists(run_dir):
        return
    want = os.path.join(os.path.realpath(root), ".security-review")
    real = os.path.realpath(run_dir)
    if real != want:
        raise RunPathError(
            "%s resolves to %s, not to %s. The run directory must be the real "
            "`.security-review/` of the tree under review, or a write into it "
            "lands somewhere else (pipeline-contract §1, §9 rule 2)."
            % (run_dir, real, want))


def check_write_path(path, root, run_dir):
    """Refuse a write to `path` that a link under the run directory would redirect.

    Also used on a directory about to be created, so that os.makedirs never
    walks through a planted link either.
    """
    check_run_dir(root, run_dir)
    rel = os.path.relpath(path, run_dir)
    if os.path.isabs(rel) or rel == os.pardir or rel.startswith(os.pardir + os.sep):
        raise RunPathError("%s is outside the run directory %s, and stage 2 writes "
                           "nowhere else (pipeline-contract §9 rule 2)"
                           % (path, run_dir))
    current = run_dir
    for part in rel.split(os.sep)[:-1]:
        current = os.path.join(current, part)
        if os.path.islink(current):
            _refuse_link(current, run_dir)
    if os.path.islink(path):
        _refuse_link(path, run_dir)


def make_run_dirs(path, root, run_dir):
    """os.makedirs for a directory under the run directory, never through a link."""
    check_write_path(path, root, run_dir)
    os.makedirs(path, exist_ok=True)


def _umask():
    """The process umask. It can only be read by setting it, so it is set back
    at once; this module runs no threads. (Same helper as run_status._umask.)"""
    mask = os.umask(0o077)
    os.umask(mask)
    return mask


def write_text(path, text, root=None, run_dir=None):
    """Write `text` to `path` whole, through a temp file nothing can pre-empt.

    With `run_dir`, the three refusals above are applied first. Without it -
    the selftests' fixtures and configs, written outside any run - the write is
    still atomic and still never opens a predictable name.
    """
    if run_dir is not None:
        check_write_path(path, root, run_dir)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                               prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        # mkstemp makes the file 0600; the artefacts are read by later stages
        # and agents as they always were, so give it the mode open(path, "w")
        # gave it: 0666 under the umask, never a fixed 0644 that would widen an
        # operator's `umask 077`. A filesystem that refuses chmod (vfat, some
        # network mounts) keeps whatever mode it gives - the same user reads it
        # either way - rather than failing a write open() used to make.
        try:
            os.chmod(tmp, 0o666 & ~_umask())
        except OSError:
            pass
        # Replacing a link AT `path` swaps the link, never writes through it.
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def open_run_file(path, root, run_dir, append):
    """A text handle on a file under the run directory that is written as it goes.

    For the one file that cannot be written whole - partial scores, flushed per
    batch so a failure keeps what was paid for. O_NOFOLLOW backs the check up.
    """
    check_write_path(path, root, run_dir)
    flags = (os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
             | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags, 0o644)
    except OSError:
        if os.path.islink(path):
            _refuse_link(path, run_dir)
        raise
    return os.fdopen(fd, "a" if append else "w", encoding="utf-8")


def fingerprint(settings):
    """sha256 over canonical JSON - what a cached score was computed under."""
    text = json.dumps(settings, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# the item a backend scores
# --------------------------------------------------------------------------- #

def make_item(function, rule_hits, context_text=None):
    """One unit of work handed to `score_batch`.

    `function` is the functions.jsonl record verbatim (contract §4), `rule_hits`
    the rules.jsonl records that joined to it with `disposition == "emitted"`,
    and `context_text` the materialised context window - present only when the
    backend declared `requires_context_text`, because materialising it means
    re-reading the tree for every function and the `rules` backend has no use
    for it.
    """
    return {
        "function_id": function["function_id"],
        "function": function,
        "rule_hits": list(rule_hits),
        "context_text": context_text,
    }


class Backend(object):
    """The interface. Subclass, set the declarations, implement the three calls.

    Lifecycle: prepare() once over the whole corpus, score_batch() over the
    functions the cache did not serve, refresh_cached() over the ones it did,
    close(), and then corpus_notes() once over every record the run built.

    Declarations - read by score_functions.py, never by the backend itself:

      name                     registry key, and the `backend` field on every record
      version                  backend_version is written as "<name>@<version>"
      score_kind               "ordinal" | "probability" - what the backend CLAIMS.
                               Contract §6 decides what it is allowed to KEEP.
      calibration              None, or "calibrated@<evalset_id>" naming a frozen
                               evaluation set under assets/evalsets/
      trained_context_profile  None, or the context profile the backend was
                               trained under. A run extracted under a different
                               one cannot carry a probability (§6).
      requires_explanations    True when every result must carry a non-empty
                               explanation, checked here rather than trusted

    Operational, with defaults that suit a local deterministic backend:

      batch_size               items per score_batch call
      thread_safe              may score_batch run concurrently on one instance
      rank_normalised          the reported score is the rank fraction of the
                               returned number over the scored population;
                               score_functions.py applies it, so the cache and
                               the merge use one denominator
      requires_context_text    materialise context.parts for every item
      resumable                may `--resume` serve a score from an earlier run.
                               A backend whose prepare() recomputes every number
                               anyway gains nothing from a cache and can only be
                               served a stale one, so it says no
    """

    name = "base"
    version = "0.0.0"
    score_kind = KIND_ORDINAL
    calibration = None
    trained_context_profile = None
    requires_explanations = False

    batch_size = 256
    thread_safe = True
    rank_normalised = False
    requires_context_text = False
    resumable = True

    def __init__(self, config=None):
        self.config = dict(config or {})
        self.notes = []            # honest asides for scorer-report.json

    # -- lifecycle ---------------------------------------------------------- #

    def prepare(self, functions, rule_hits, config):
        """Called once, before any scoring.

        `functions` is the WHOLE corpus, including functions this run will not
        re-score, because a backend that buckets or normalises needs the
        denominator and `--resume` would otherwise shrink it silently.
        `config["_run"]` carries the run context score_functions.py injects:
        root, run_dir, scores_dir, bundle_root, run_id, started_at,
        context_profile, `to_score` - the set of function_ids that will actually
        reach score_batch - and, for a backend that declared
        `requires_context_text`, `context_text`: function_id -> the materialised
        context window, already checked against the record's text_sha256. A
        config file cannot set `_run`; it is overwritten.
        """

    def score_batch(self, items):
        """Score `items` (from make_item) and return one result each, in order.

        A result is a dict:
          score            float. In [0,1] unless `rank_normalised`, where it is
                           any comparable number and the rank fraction replaces it.
          weakness_class   CWE string or None
          localized_line   1-based line inside the function, or None
          explanation      short string, or None
          raw_score        optional: the pre-normalisation number, kept in the
                           cache so a `--resume` merge re-ranks against one scale
        """
        raise NotImplementedError

    def close(self):
        """Release whatever prepare() acquired. Always called, even after a raise."""

    # -- the resume cache --------------------------------------------------- #

    def cache_fingerprint(self):
        """sha256 over the settings that move this backend's numbers.

        `backend_version` is the version of the CODE and `model` the checkpoint;
        neither moves when a weight, a verdict token or a prompt template in the
        config does, and a cached score computed under the old one is a
        different scorer's number wearing this one's name. score_functions.py
        stamps this on every record and serves a cached score only when it
        matches. The default is the whole config the backend was handed, which
        can only over-invalidate; a backend overrides it to name exactly what
        its numbers depend on.
        """
        return fingerprint(dict((k, v) for k, v in self.config.items()
                                if not str(k).startswith("_")))

    def refresh_cached(self, function, result):
        """A cached result, brought up to date with what this run's prepare() computed.

        Called after prepare() for every score --resume serves. The default
        returns it unchanged. A backend whose number mixes a cached part with
        something prepare() recomputes over the whole corpus - llm-triage's
        tie-break inside a band - recomputes that part here, so a resumed run
        and a fresh one over the same inputs agree.
        """
        return result

    # -- the whole population ----------------------------------------------- #

    def corpus_notes(self, records):
        """Notes about the whole scored population, for scorer-report.json's `notes`.

        Called once per completed run, after every record - fresh and --resume
        served alike - is built and its score rounded, and before it is ranked.
        Not in score_batch: that sees only the functions the cache did not
        serve, in slices that may run concurrently, and a resume that serves
        every score never calls it at all, so a check there judges a subset or
        nothing. A note never changes a score, a downgrade or the exit code.
        The default says nothing.
        """
        return []

    # -- declaration -------------------------------------------------------- #

    # Ordered [(label, lo, hi), ...] when the backend's scale has NAMED bands a
    # human can choose between - llm-triage's high/medium/low/none. None when
    # the score is a bare ordering with no meaning between the numbers, which is
    # the honest answer for a weighted-sum backend. score_functions.py reports a
    # distribution over these so the operator picks a cut that means something
    # instead of a round number.
    bands = None

    # True when the backend's score is a verdict the host model drew from reading the
    # function (llm-triage's high / medium / low / none) and `triage_verdict()` can
    # name it. Stage 3 derives a LOG-TRI candidate from a `high` verdict on a function
    # no rule matched, so a backend that records none derives nothing - `rules` orders
    # by rule weight and `finetuned` by a log-probability, and neither says "high".
    triage_verdicts = False

    def triage_verdict(self, result):
        """The verdict word behind `result`'s score ("high", "medium", "low" or "none"),
        or None for a backend that records none. Called on fresh and cached results
        alike, so it must be a function of the result and nothing else."""
        return None

    def declaration(self):
        """What the backend says about itself, for scorer-report.json."""
        return {
            "name": self.name,
            "version": self.version,
            "backend_version": "%s@%s" % (self.name, self.version),
            "declared_score_kind": self.score_kind,
            "declared_calibration": self.calibration,
            "trained_context_profile": self.trained_context_profile,
            "requires_explanations": bool(self.requires_explanations),
            "rank_normalised": bool(self.rank_normalised),
            "requires_context_text": bool(self.requires_context_text),
            "triage_verdicts": bool(self.triage_verdicts),
            "batch_size": int(self.batch_size),
            "model": self.model_name(),
            "bands": [{"label": b[0], "lo": b[1], "hi": b[2]} for b in (self.bands or [])] or None,
        }

    def model_name(self):
        """The model identifier to write on every record, or None."""
        return None


# --------------------------------------------------------------------------- #
# result validation - enforced here so no backend has to be trusted for it
# --------------------------------------------------------------------------- #

def validate_results(backend, items, results):
    """Return `results` normalised, or raise BackendError naming the function.

    The localized_line range check is the one worth reading twice. Contract §4
    says a range off by one function points a validator at a different body,
    whose guards then look sufficient; a line outside the function is the same
    error arriving one stage later, and it comes from a model often enough that
    trusting it is not an option.
    """
    if not isinstance(results, list) or len(results) != len(items):
        raise BackendError(
            "backend %s returned %s results for %d items; score_batch must "
            "return one result per item, in order"
            % (backend.name,
               len(results) if isinstance(results, list) else type(results).__name__,
               len(items)))

    out = []
    for item, res in zip(items, results):
        fn = item["function"]
        where = "%s:%s" % (fn.get("file", "?"), fn.get("line_start", "?"))
        if not isinstance(res, dict):
            raise BackendError("%s: backend %s returned %r for %s, not a result dict"
                               % (where, backend.name, type(res).__name__,
                                  fn.get("function_id")))
        try:
            score = float(res["score"])
        except (KeyError, TypeError, ValueError):
            raise BackendError("%s: backend %s returned no usable `score` for %s"
                               % (where, backend.name, fn.get("function_id")))
        if math.isnan(score) or math.isinf(score):
            raise BackendError("%s: backend %s scored %s as %r; a score that is not "
                               "a finite number cannot be ranked"
                               % (where, backend.name, fn.get("function_id"), score))
        if not backend.rank_normalised and not (0.0 <= score <= 1.0):
            raise BackendError("%s: backend %s scored %s as %r, outside [0,1]. Declare "
                               "rank_normalised if the number is a raw magnitude."
                               % (where, backend.name, fn.get("function_id"), score))

        line = res.get("localized_line")
        if line is not None:
            try:
                line = int(line)
            except (TypeError, ValueError):
                raise BackendError("%s: backend %s returned localized_line %r for %s, "
                                   "which is not a line number"
                                   % (where, backend.name, res.get("localized_line"),
                                      fn.get("function_id")))
            lo, hi = fn.get("line_start"), fn.get("line_end")
            if isinstance(lo, int) and isinstance(hi, int) and not (lo <= line <= hi):
                raise BackendError(
                    "%s: backend %s localised %s to line %d, outside the function's "
                    "own range %d-%d. A line outside the body points the validator "
                    "at other code, whose guards then look sufficient."
                    % (where, backend.name, fn.get("function_id"), line, lo, hi))

        explanation = res.get("explanation")
        if explanation is not None:
            explanation = str(explanation).strip() or None
        if backend.requires_explanations and not explanation:
            raise BackendError("%s: backend %s declares requires_explanations but "
                               "returned none for %s"
                               % (where, backend.name, fn.get("function_id")))

        weakness = res.get("weakness_class")
        raw = res.get("raw_score", score)
        try:
            raw = float(raw)
        except (TypeError, ValueError):
            raw = score
        out.append({
            "score": score,
            "raw_score": raw,
            "weakness_class": str(weakness) if weakness else None,
            "localized_line": line,
            "explanation": explanation,
        })
    return out


# --------------------------------------------------------------------------- #
# rank normalisation - one implementation, used by the tool and the backends
# --------------------------------------------------------------------------- #

def rank_normalise(values):
    """Map raw numbers to [0,1] by rank. Ties get one value; order is preserved.

    `(strictly_below + half_the_ties) / (n - 1)` rather than `below / n`, so that
    a corpus where 11,000 of 18,000 functions trip no rule at all - the normal
    shape of a real tree - does not hand all of them the identical 0.0 that then
    sorts alphabetically downstream and reads as a ranking.
    """
    n = len(values)
    if n == 0:
        return []
    if n == 1:
        return [1.0]
    ordered = sorted(values)
    below = {}
    equal = {}
    i = 0
    while i < n:
        j = i
        while j < n and ordered[j] == ordered[i]:
            j += 1
        below[ordered[i]] = i
        equal[ordered[i]] = j - i
        i = j
    span = float(n - 1)
    out = []
    for v in values:
        frac = (below[v] + 0.5 * (equal[v] - 1)) / span
        out.append(min(1.0, max(0.0, frac)))
    return out


# --------------------------------------------------------------------------- #
# joining rule hits to functions - ONE definition, used by every caller
# --------------------------------------------------------------------------- #

def index_hits(rule_hits):
    """`function_id`/`function_key` -> the emitted hits carrying it. Contract §5.

    Skipped and deferred hits are not indexed: a skipped hit is not evidence and
    must not move a score.
    """
    index = {}
    for hit in rule_hits:
        if hit.get("disposition") != "emitted":
            continue
        for key in (hit.get("function_id"), hit.get("function_key")):
            if key:
                index.setdefault(key, []).append(hit)
    return index


def hits_for(function, index):
    """The hits that join to `function`, under both of its keys, deduplicated.

    There used to be three spellings of this join - score_functions.py looked up
    function_id and fell back to function_key, the rules and finetuned backends
    indexed each hit under only ONE of its two keys, and llm-triage matched
    either key exactly - and on a hit whose function_id carried a content hash
    the corpus no longer holds they disagreed: the hit joined by function_key
    into `evidence_rule_hits` while contributing nothing to the score the record
    published beside it. A record whose evidence and whose number were produced
    by two different joins is the shape of failure contract §0 exists for, so
    there is one join and every caller uses it.
    """
    out, seen = [], set()
    for key in (function.get("function_id"), function.get("function_key")):
        if not key:
            continue
        for hit in index.get(key) or ():
            mark = hit.get("rule_hit_id") or id(hit)
            if mark in seen:
                continue
            seen.add(mark)
            out.append(hit)
    return out


def top_hit(rule_hits, weight_of=None):
    """The rule hit a record should be labelled by: heaviest rule, then earliest line.

    Deterministic on purpose. Two runs over the same tree must label a function
    the same way or the ledger's `(function_key, content_hash, cwe)` dedup key
    silently splits in two.
    """
    if not rule_hits:
        return None

    def key(hit):
        w = 0.0
        if weight_of is not None:
            w = float(weight_of(hit.get("rule_id")) or 0.0)
        line = hit.get("line")
        return (-w, line if isinstance(line, int) else 1 << 30,
                str(hit.get("rule_id") or ""), str(hit.get("rule_hit_id") or ""))

    return sorted(rule_hits, key=key)[0]
