#!/usr/bin/env python3
"""
verify_findings.py - check every finding against the source and against the report,
then build the arbiter's queue.

Runs before the arbiter reads a word, and costs no model tokens. Five families of
check:

1.  CITATIONS.  Every `evidence[].code` and every `grounds[].quote` must be at the
    file and line it is cited at. A verdict resting on a line that is not there is
    unsound no matter how good the argument was.

2.  CLAIM GROUNDING.  Every symbol a finding names must be traceable to
    `claims.json` - what the REPORT said - or to `advisory.namedSymbols` for a
    dependency finding. A symbol from the analyst's memory of a CVE, or one picked
    up from the tree because it looked close enough, is reported here.

3.  NEAR-MISS SUBSTITUTION.  The specific failure this pipeline exists to catch.
    The reporter writes `parse_header`; this tree has `parse_headers`; the analyst
    analyses the second, cites a real line and passes every check that only looks
    at the repository. If the analysed symbol is a near miss of an ABSENT claimed
    symbol and the finding did not declare `symbol_source: "mapped"` with mapping
    evidence, it is flagged and queued.

4.  VERSION ARITHMETIC.  A `version-not-affected` ground is recomputed from the
    advisory's own bounds. A conclusion the arithmetic contradicts is blocked, and
    so is a stated range whose numbers appear nowhere in the advisory - which
    catches a remembered range even when it reaches the right answer.

5.  LENS LEAKAGE.  The exploit finding is produced by an agent that cannot read the
    report. If its text carries the reporter's claimed impact wording or CVSS
    vector anyway, the isolation did not hold and the derived attacker model is not
    independent.

    python3 -I -B scripts/verify_findings.py --root .

Run from the repository being triaged (the workspace), with the command written
relative to the skill folder; `--root` is the workspace and defaults to ".".
Run state is read from, and the arbiter's queue written to, <root>/.report-triage/.
The skill folder itself is never written.

Stdlib only. Python 3.9+.
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

# The skill root: read-only, never written. scripts/ is one level below it. The
# workspace is --root (default "."), the repository being triaged.
SKILL_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from report import (_plausible_symbol, in_range, parse_version, cmp_version,
                        RE_CALL, RE_BACKTICK, _norm, _lev, exploit_packet_leaks,
                        citable_problem, read_arbiter)
except ImportError:  # standalone use
    def read_arbiter(root, rid, arb_dir=None):
        """Without report.py: the file as plain JSON, and a refusal that says why."""
        path = os.path.join(arb_dir or os.path.join(root, ".report-triage",
                                                    "arbitration"),
                            "ARB-%s.json" % rid)
        if not os.path.lexists(path):
            return None, [], None
        record = jload(path)
        if isinstance(record, dict):
            return record, [], None
        why = ("%s cannot be read as a JSON object (report.py is not importable, "
               "so a code fence around it is not read either)" % path)
        return None, [("unreadable", why)], why
    citable_problem = lambda root, rel, meta=None: None  # noqa: E731
    exploit_packet_leaks = lambda packet, copies=(): []  # noqa: E731
    _plausible_symbol = lambda t: len(t) > 2  # noqa: E731
    RE_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,63})\s*\(")
    RE_BACKTICK = re.compile(r"``([^`\n]{1,120})``|`([^`\n]{1,120})`")
    _norm = lambda s: s.lower().replace("_", "")  # noqa: E731
    in_range = lambda v, r: (None, "report.py not importable")  # noqa: E731
    parse_version = lambda v: (None, "report.py not importable")  # noqa: E731
    cmp_version = None
    _lev = None

DRIFT_WINDOW = 25
CONFIDENCE_VALUES = frozenset(("high", "medium", "low"))

SAMPLE_PERCENT = 15

# Two sets, because they answer two different questions and conflating them
# broke the ground schema: `already-fixed` points AT a commit and a guarded
# line, so it must quote one, and it was being told not to.
#
# ABSENCE: the contract's own list of grounds that assert something does not
# exist. These have no line to quote and carry `searched` instead.
ABSENCE_GROUNDS = {
    "symbol-absent", "never-vulnerable", "not-vendored", "not-called",
    "no-callers", "not-reachable", "not-compiled", "not-linked", "dead-code",
    "vulnerable-api-unused", "no-attacker-input", "different-product",
    "platform-not-shipped", "precondition-absent",
}

# DISMISSAL: every ground that closes or downgrades a report, from BOTH contract
# tables. Used for queueing, because every dismissal direction is the expensive
# direction - `guarded`, `requires-privilege` and `mitigated-by-config` are
# legal NOT_EXPLOITABLE grounds and were queued by nothing.
DISMISSAL_GROUNDS = ABSENCE_GROUNDS | {
    "guarded", "requires-privilege", "mitigated-by-config", "test-only",
    "not-shipped", "version-not-affected", "already-fixed", "code-differs",
}

CODE_VERDICTS = {"PRESENT", "ABSENT", "UNDECIDED", "NEEDS_REPORTER_INPUT"}
EXPLOIT_VERDICTS = {"EXPLOITABLE", "NOT_EXPLOITABLE", "UNDECIDED"}
SEVERITIES = ["info", "low", "medium", "high", "critical"]


UNREADABLE = object()


def jload(path, default=None, distinguish=False):
    """Parsed JSON, or `default`.

    With distinguish=True a file that exists but cannot be parsed returns
    UNREADABLE rather than the default. Collapsing "not there" and "truncated
    JSON" into the same None meant a lens whose verdict file was corrupt read
    as a lens that had not run, and a run over a damaged findings directory
    reported an empty queue and exit 0.
    """
    if not os.path.isfile(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001
        return UNREADABLE if distinguish else default


def read_lines(root, rel, meta=None):
    """
    Read a cited file, but only from inside the repository.

    Every citation check funnels through here, and `rel` arrives from a finding -
    which is model output, shaped by an attacker-authored report. Without a
    containment check, `os.path.join(root, "../../../etc/passwd")` resolves
    happily and the verifier will confirm a quoted line from it as valid
    evidence, so a finding could cite arbitrary host files and be blessed. An
    absolute path is refused for the same reason: join() silently discards `root`
    when the second argument is absolute.
    """
    if not rel or os.path.isabs(rel) or (os.name == "nt" and re.match(r"^[A-Za-z]:", rel)):
        return None
    base = os.path.realpath(root)
    path = os.path.realpath(os.path.join(base, rel))
    if path != base and not path.startswith(base + os.sep):
        return None
    # Inside the repository is not enough: the run directory, the installed skill
    # and the other installed skills are text this pipeline walks around, and a
    # cited line there is not the product's code (`report.citable_problem`). `meta`
    # is the report's meta.json: with it a byte-identical copy of the report in the
    # tree is refused as well, so a line of the reporter's own text is never
    # confirmed as evidence for the reporter's claim.
    if citable_problem(root, rel, meta):
        return None
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        if b"\x00" in raw[:8192]:
            return None
        return raw.decode("utf-8", "replace").split("\n")
    except (OSError, IOError):
        return None


# --------------------------------------------------------------------------
# 1. citations
# --------------------------------------------------------------------------

def check_citation(root, rel, line, quote, meta=None):
    if not rel or not quote:
        return {"status": "incomplete", "detail": "no file or no quote"}
    lines = read_lines(root, rel, meta)
    if lines is None:
        why = citable_problem(root, rel, meta)
        return {"status": "file_not_found",
                "detail": "%s %s" % (rel, why) if why else rel}
    want = quote.strip()
    if not want:
        return {"status": "incomplete", "detail": "empty quote"}
    try:
        n = int(line)
    except (TypeError, ValueError):
        n = 0

    def matches(idx):
        if idx < 1 or idx > len(lines):
            return False
        have = lines[idx - 1].strip()
        # Exact, or the quote is a fragment of the line. NOT the reverse: a
        # quote that CONTAINS the line used to pass as `ok`, which made the
        # check non-falsifiable - any invented text was accepted at a cited
        # line as long as the real line appeared somewhere inside it, and the
        # arbiter reads `ok` as "do not look". The contract asks for the line
        # verbatim; a superset is not that.
        return have == want or (len(want) >= 8 and want in have)

    if n and matches(n):
        return {"status": "ok", "line": n}
    if n and (n < 1 or n > len(lines)):
        near = [i for i in range(1, len(lines) + 1) if matches(i)]
        if near:
            return {"status": "drift", "line": near[0], "citedLine": n,
                    "detail": "cited line is past the end of the file"}
        return {"status": "line_out_of_range",
                "detail": "%s has %d lines, citation said %d" % (rel, len(lines), n)}
    for delta in range(1, DRIFT_WINDOW + 1):
        for cand in (n - delta, n + delta):
            if matches(cand):
                return {"status": "drift", "line": cand, "citedLine": n,
                        "detail": "found %d lines away" % abs(cand - n)}
    anywhere = [i for i in range(1, len(lines) + 1) if matches(i)]
    if anywhere:
        return {"status": "wrong_line", "line": anywhere[0], "citedLine": n,
                "detail": "text exists at %s but not near the cited line"
                          % ",".join(str(x) for x in anywhere[:5])}
    return {"status": "not_found", "citedLine": n,
            "detail": "no line in %s carries this text" % rel}


def check_all_citations(root, finding, meta=None):
    out = []
    for i, e in enumerate(finding.get("evidence") or []):
        r = check_citation(root, e.get("file"), e.get("line"), e.get("code"), meta)
        r.update({"where": "evidence[%d]" % i, "file": e.get("file"),
                  "role": e.get("role")})
        out.append(r)
    for i, g in enumerate(finding.get("grounds") or []):
        # An absence ground has no line to quote - the contract now asks it for
        # the searches instead, and asking for a citation of a line that does
        # not exist only ever produced a citation of an unrelated one.
        if isinstance(g, dict) and g.get("code") in ABSENCE_GROUNDS \
                and not g.get("quote"):
            continue
        r = check_citation(root, g.get("file"), g.get("line"), g.get("quote"), meta)
        r.update({"where": "grounds[%d]" % i, "file": g.get("file"),
                  "code": g.get("code")})
        out.append(r)
    for i, m in enumerate(finding.get("mapping_evidence") or []):
        r = check_citation(root, m.get("file"), m.get("line"), m.get("code"), meta)
        r.update({"where": "mapping_evidence[%d]" % i, "file": m.get("file")})
        out.append(r)
    for i, p in enumerate(finding.get("path") or []):
        r = check_citation(root, p.get("file"), p.get("line"), p.get("code"), meta)
        r.update({"where": "path[%d]" % i, "file": p.get("file")})
        out.append(r)
    for i, e in enumerate(finding.get("inference_evidence") or []):
        r = check_citation(root, e.get("file"), e.get("line"), e.get("code"), meta)
        r.update({"where": "inference_evidence[%d]" % i, "file": e.get("file")})
        out.append(r)
    for i, e in enumerate(finding.get("entry_points") or []):
        if not isinstance(e, dict) or not e.get("code"):
            continue
        r = check_citation(root, e.get("file"), e.get("line"), e.get("code"), meta)
        r.update({"where": "entry_points[%d]" % i, "file": e.get("file")})
        out.append(r)
    # `guards`, `guards_considered` and `preconditions` all carry cited code by
    # the contract's own output template, and only `guards` was ever resolved -
    # while symbols_in_cited_code harvested identifiers out of the unverified
    # ones into the grounding vocabulary, so an invented guard both escaped the
    # citation check and licensed the symbol it named.
    for field in ("guards", "guards_considered", "preconditions"):
        for i, g in enumerate(finding.get(field) or []):
            if not isinstance(g, dict):
                # A model writing `"guards": ["the clamp dominates"]` is
                # ordinary prose, and it used to raise AttributeError here and
                # take the whole verification down - which is a clean queue and
                # exit 0 to anyone reading the summary.
                out.append({"status": "malformed", "line": None,
                            "where": "%s[%d]" % (field, i), "file": None,
                            "detail": "%s[%d] is %s, not an object with file, "
                                      "line and code"
                                      % (field, i, type(g).__name__)})
                continue
            if not g.get("code"):
                continue
            r = check_citation(root, g.get("file"), g.get("line"), g.get("code"), meta)
            r.update({"where": "%s[%d]" % (field, i), "file": g.get("file")})
            out.append(r)
    return out


# --------------------------------------------------------------------------
# 2 & 3. claim grounding and near-miss substitution
# --------------------------------------------------------------------------

PROSE_FIELDS = ("reason", "impact", "suggested_reply", "summary",
                "derived_attacker_model", "anchor_check", "claim_check",
                "exploitability_ceiling")


def symbols_in_prose(finding):
    out = {}
    for field in PROSE_FIELDS:
        text = finding.get(field)
        if not isinstance(text, str):
            continue
        for m in RE_CALL.finditer(text):
            tok = m.group(1)
            if _plausible_symbol(tok):
                out.setdefault(tok, field)
        for m in RE_BACKTICK.finditer(text):
            inner = (m.group(1) or m.group(2) or "").strip()
            if "/" in inner or "." in inner and not inner.replace(".", "").isalnum():
                continue
            for sub in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,63}", inner):
                if _plausible_symbol(sub):
                    out.setdefault(sub, field)
    return out


# `src/http/parse.c:7` or `src/http/parse.c:7-9`, inside backticks. Requires a
# dot-extension so a bare `foo:7` in prose is not mistaken for a location.
RE_ANCHOR = re.compile(
    r"`([A-Za-z0-9_][A-Za-z0-9_./+-]*\.[A-Za-z0-9_+-]{1,12}):(\d{1,7})(?:-(\d{1,7}))?`")

# Prose that carries an argument about code the finding says IS there. These are
# the fields where a reviewer expects to be able to click through.
ANCHORABLE_PROSE = ("reason", "claim_restated", "impact", "reporter_claim_check",
                    "deciding_facts", "exploitability_ceiling",
                    "derived_attacker_model", "independent_answer",
                    "claim_vs_derived", "crux", "substitution_audit")

# Verdicts that rest on code being present, so a line to point at exists by
# definition. Absence verdicts carry their citation in `grounds` instead.
PRESENCE_VERDICTS = ("PRESENT", "EXPLOITABLE")


def anchors_in(text):
    if not isinstance(text, str):
        return []
    return [{"path": m.group(1), "line": int(m.group(2)),
             "end": int(m.group(3)) if m.group(3) else None, "raw": m.group(0)}
            for m in RE_ANCHOR.finditer(text)]


def check_prose_anchors(root, finding, meta=None):
    """
    Resolve every `path:line` written in prose. This does not check that the
    anchor is apt - only that it points at a real file and a line inside it, so a
    fabricated location, or one copied from the report's tree, is caught rather
    than shipped to a reviewer who will click it.
    """
    results, problems = [], []
    seen, pairs = set(), []
    nested = []
    for entry in (finding.get("corrections") or []):
        if isinstance(entry, dict) and isinstance(entry.get("why"), str):
            nested.append(("corrections[].why", entry["why"]))
    for field in ("guards", "guards_considered", "mapping_evidence"):
        for entry in (finding.get(field) or []):
            if not isinstance(entry, dict):
                continue
            for key in ("why", "why_insufficient"):
                if isinstance(entry.get(key), str):
                    nested.append(("%s[].%s" % (field, key), entry[key]))

    for field in ANCHORABLE_PROSE + ("arithmetic",):
        value = finding.get(field)
        texts = []
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, dict):
            texts.extend(v for v in value.values() if isinstance(v, str))
        for text in texts:
            pairs.append((field, text))

    for field, text in pairs + nested:
        for a in anchors_in(text):
            key = (field, a["raw"])
            if key in seen:
                continue
            seen.add(key)
            lines = read_lines(root, a["path"], meta)
            if lines is None:
                why = citable_problem(root, a["path"], meta)
                st = {"status": "file_not_found",
                      "detail": "%s %s" % (a["path"], why) if why else a["path"]}
            elif a["line"] < 1 or a["line"] > len(lines):
                st = {"status": "line_out_of_range",
                      "detail": "%s has %d lines, anchor said %d"
                                % (a["path"], len(lines), a["line"])}
            elif a["end"] is not None and (a["end"] < a["line"]
                                           or a["end"] > len(lines)):
                st = {"status": "line_out_of_range",
                      "detail": "%s has %d lines, anchor range ended at %d"
                                % (a["path"], len(lines), a["end"])}
            else:
                st = {"status": "ok"}
            st.update({"where": field, "anchor": a["raw"]})
            results.append(st)
            if st["status"] != "ok":
                problems.append({"kind": "broken_anchor", "field": field,
                                 "detail": "%s: %s" % (a["raw"], st["detail"])})

    # A presence verdict whose reasoning names code but points at nothing is the
    # failure this rule exists to stop: the reviewer gets an assertion and no way
    # to check it. The arbiter records its verdict under different keys, and its
    # prose is the prose a person actually reads, so it is held to the same rule.
    verdicts = {finding.get(k) for k in
                ("verdict", "final_code_verdict", "final_exploit_verdict")}
    if verdicts & set(PRESENCE_VERDICTS):
        for field in ("reason", "claim_restated", "independent_answer",
                      "claim_vs_derived"):
            text = finding.get(field)
            if not isinstance(text, str) or not text.strip():
                continue
            if anchors_in(text):
                continue
            if any(_plausible_symbol(t) for t in RE_CALL.findall(text)) or \
                    RE_BACKTICK.search(text):
                problems.append({
                    "kind": "unanchored_prose", "field": field,
                    "detail": "names code but carries no `path:line`; a %s verdict "
                              "has a line to point at"
                              % "/".join(sorted(v for v in verdicts if v))})
    return results, problems


CITED_CODE_FIELDS = (("evidence", "code"), ("guards", "code"),
                     ("guards_considered", "code"), ("path", "code"),
                     ("entry_points", "code"), ("grounds", "quote"),
                     ("mapping_evidence", "code"), ("inference_evidence", "code"))


def symbols_in_cited_code(finding):
    """
    Identifiers inside lines the finding quoted from the repository. These are
    grounded by the citation check itself: if the analyst quotes
    `open(os.path.join(TEMPLATE_ROOT, name))` as verified evidence, naming `open`
    in the reasoning is describing the code, not importing a symbol from memory.
    """
    out = set()
    for field, key in CITED_CODE_FIELDS:
        for entry in (finding.get(field) or []):
            if isinstance(entry, dict) and entry.get(key):
                out.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,63}", entry[key]))
    return out


def check_inferred(finding, claims, probe):
    """
    A symbol the probe suggested was chosen by a word search, not by the
    reporter. That is a weaker provenance than any other source here, and it
    fails in the direction that costs most: a search for "mqtt config off-by-one"
    will find SOMETHING resembling one in most codebases, and a lens that treats
    the resemblance as confirmation closes a real report by answering a question
    nobody asked.
    """
    problems = []
    claimed = {s["symbol"] for s in (claims.get("symbols") or [])}
    source = finding.get("symbol_source")
    sym = finding.get("analysed_symbol") or finding.get("vulnerable_symbol")
    verdict = finding.get("verdict")

    nothing_claimed = not (claims.get("symbols") or claims.get("files") or
                           claims.get("cves") or claims.get("packages"))

    if nothing_claimed and sym and source not in ("inferred", "not-established"):
        problems.append({
            "kind": "undeclared_inference", "symbol": sym, "field": "symbol_source",
            "detail": "the report named no symbol, file, package or CVE, so %r came "
                      "from the probe or from the analyst - declare it as "
                      "'inferred' rather than %r" % (sym, source)})

    if source == "inferred":
        if not finding.get("inference_evidence") and finding.get("lens") != "exploit":
            problems.append({
                "kind": "inference_without_evidence", "symbol": sym,
                "detail": "symbol_source 'inferred' requires inference_evidence: "
                          "which concepts from the report this region carries, and "
                          "why it is the region the report describes"})
        if verdict == "ABSENT":
            problems.append({
                "kind": "inferred_absence", "symbol": sym,
                "detail": "an inferred symbol cannot support ABSENT. Not finding the "
                          "defect at a region the search guessed at says the guess "
                          "was wrong, not that the product is unaffected; that is "
                          "NEEDS_REPORTER_INPUT"})
        if sym and sym in claimed:
            problems.append({
                "kind": "inference_mislabelled", "symbol": sym,
                "detail": "the report did name %r, so the source is 'reporter'; "
                          "labelling it inferred hides that the claim was direct"
                          % sym})

    # An absence verdict on a report that located nothing is the exact shape of
    # the expensive error, whatever the declared source.
    if nothing_claimed and verdict == "ABSENT":
        problems.append({
            "kind": "absence_without_a_claim",
            "detail": "the report named nothing locatable, so there is no claim to "
                      "find absent. The honest verdict is NEEDS_REPORTER_INPUT"})

    if probe and not (probe.get("candidates") or []) and verdict in ("ABSENT",):
        problems.append({
            "kind": "empty_probe_read_as_absence",
            "detail": "the probe located no candidate region; that is a failed "
                      "search, not a clean tree"})
    return problems


def symbols_in_probe(probe):
    """Identifiers on the lines the probe surfaced - the lens was handed these."""
    out = set()
    for c in ((probe or {}).get("candidates") or []):
        for h in (c.get("hits") or []):
            out.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,63}", h.get("code") or ""))
        out.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,63}", c.get("file") or ""))
    return out


def check_grounding(finding, claims, advisory, established=None):
    """
    Every symbol named must be traceable to the report, the advisory, a line the
    finding quoted from the tree, or - for the exploit lens - the symbol the code
    lens already established.
    """
    claimed = {s["symbol"] for s in (claims.get("symbols") or [])}
    claimed_tails = {re.split(r"::|->|\.", s)[-1] for s in claimed}
    adv = {s["symbol"] for s in ((advisory or {}).get("namedSymbols") or [])}
    vocabulary = (claimed | claimed_tails | adv | symbols_in_cited_code(finding)
                  | set(established or []))

    problems = []
    named = {}
    for field in ("analysed_symbol", "vulnerable_symbol"):
        if finding.get(field):
            named[finding[field]] = field
    from_prose = set()
    no_claim_vocabulary = not claimed and not adv
    for tok, field in symbols_in_prose(finding).items():
        if tok not in named:
            from_prose.add(tok)
        named.setdefault(tok, field)

    source = finding.get("symbol_source")
    for tok, field in named.items():
        if tok in from_prose and no_claim_vocabulary:
            continue
        tail = re.split(r"::|->|\.", tok)[-1]
        if tok in vocabulary or tail in vocabulary:
            continue
        if source in ("mapped", "inferred") and \
                field in ("analysed_symbol", "vulnerable_symbol"):
            continue
        problems.append({"kind": "symbol_not_claimed", "symbol": tok, "field": field,
                         "detail": "named in %s but the report, the advisory and the "
                                   "lines this finding cited all name it nowhere"
                                   % field})

    # `searched_for` is judged as a SET, not entry by entry. Searching more than
    # the report named is good practice - a route decorator, a build symbol, a
    # string form - and holding it against the analyst teaches them to search less.
    # What matters is whether a verdict resting on absence searched for any of the
    # things that were actually claimed.
    grounds = {g.get("code") for g in (finding.get("grounds") or [])}
    if grounds & ABSENCE_GROUNDS:
        searched = set(finding.get("searched_for") or [])
        if not searched:
            problems.append({"kind": "absence_without_search",
                             "detail": "a ground asserting absence with an empty "
                                       "searched_for has recorded no search at all"})
        elif claimed or adv:
            wanted = claimed | adv | set(established or [])
            if not (searched & wanted):
                problems.append({
                    "kind": "searched_nothing_claimed",
                    "detail": "searched %s, none of which the report or advisory "
                              "named (%s)" % (sorted(searched)[:5],
                                              sorted(wanted)[:5])})
    return problems, named


def check_near_miss(finding, anchors):
    """
    The analysed symbol is a near miss of a claimed symbol that is NOT in the tree,
    and the substitution was not declared. This is the failure that survives every
    check which only looks at the repository.
    """
    target = finding.get("analysed_symbol") or finding.get("vulnerable_symbol")
    if not target:
        return []
    problems = []
    for rec in (anchors.get("symbols") or []):
        if rec.get("status") != "absent":
            continue
        for nm in (rec.get("nearMisses") or []):
            if nm["symbol"] != target:
                continue
            if finding.get("symbol_source") == "mapped" and finding.get("mapping_evidence"):
                continue
            problems.append({
                "kind": "near_miss_substitution",
                "claimed": rec["symbol"], "analysed": target,
                "detail": "the report names `%s`, which is not in this tree. The "
                          "finding analysed `%s` (%s) without declaring "
                          "symbol_source \"mapped\" and citing what makes them the "
                          "same code." % (rec["symbol"], target, nm["why"])})
    return problems


# --------------------------------------------------------------------------
# 4. version arithmetic
# --------------------------------------------------------------------------

def check_version(finding, advisory, version_assessment):
    problems = []
    grounds = {g.get("code") for g in (finding.get("grounds") or [])}
    if "version-not-affected" not in grounds:
        return problems
    resolved = finding.get("resolved_version")
    stated = finding.get("vulnerable_range")
    if not resolved:
        problems.append({"kind": "version_ground_without_version",
                         "detail": "version-not-affected without resolved_version"})
        return problems
    ranges = (advisory or {}).get("affectedRanges") or []
    if ranges:
        ok, why = in_range(resolved, ranges)
        if ok is True:
            problems.append({"kind": "version_arithmetic_contradicted",
                             "detail": "the finding dismissed on version, but %s is %s"
                                       % (resolved, why)})
        elif ok is None:
            problems.append({"kind": "version_comparison_refused",
                             "detail": why})
    else:
        problems.append({"kind": "version_ground_without_advisory_range",
                         "detail": "no advisory range was available, so the dismissal "
                                   "rests on a range from somewhere else"})
    if stated and (advisory or {}).get("text"):
        nums = re.findall(r"\d+(?:\.\d+)+", str(stated))
        text = advisory["text"]
        missing = [n for n in nums if n not in text]
        if nums and missing:
            problems.append({"kind": "stated_range_not_in_advisory",
                             "detail": "the stated range cites %s, which appears "
                                       "nowhere in the advisory text"
                                       % ", ".join(missing)})
    if version_assessment and version_assessment.get("resolvedVersion") and resolved:
        if version_assessment["resolvedVersion"] != resolved:
            problems.append({"kind": "version_disagrees_with_lockfile",
                             "detail": "the tool read %s from %s, the finding says %s"
                                       % (version_assessment["resolvedVersion"],
                                          version_assessment.get("readAt"), resolved)})
    return problems


# --------------------------------------------------------------------------
# 5. lens leakage
# --------------------------------------------------------------------------

NGRAM = 8


def _ngrams(text, n=NGRAM):
    words = re.findall(r"[a-z0-9']+", (text or "").lower())
    return {" ".join(words[i:i + n]) for i in range(max(0, len(words) - n + 1))}


def _plain_path(path):
    """A path with backslashes as slashes and one leading "./" removed.

    Not `lstrip("./")`: that strips every leading dot and slash, so ".hidden/x"
    and "../x" became "hidden/x" and "x".
    """
    path = path.replace("\\", "/")
    return path[2:] if path.startswith("./") else path


def _cited_names(node, found=None, depth=0):
    """Every string a finding gives under a `file` or `path` key, at any depth."""
    found = set() if found is None else found
    if depth > 12:
        return found
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("file", "path") and isinstance(value, str):
                found.add(_plain_path(value) or value)
            elif isinstance(value, (dict, list)):
                _cited_names(value, found, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _cited_names(item, found, depth + 1)
    return found


def check_lens(finding, claims, report_text, copies=()):
    """
    The exploit lens had no access to the report. Did any of it arrive anyway?

    Naming the defect class is not a leak - the exploit agent gets that from the
    code finding, and an exploit finding about a buffer overflow will say "buffer
    overflow". What it cannot have got by itself is the reporter's own wording, so
    the test is a run of %d consecutive words shared with the report text, plus the
    CVSS vector, which is unmistakable. A finding that cites a line of a copy of the
    report (`copies`, as `anchor` listed them) shows the lens read it, whatever it
    then wrote: a copy sitting in the tree is readable by the lens's own searches,
    which the packet cannot prevent, and this is the one way that read can show.
    """ % NGRAM
    problems = []
    names = {_plain_path(c) or c for c in (copies or ()) if isinstance(c, str)}
    cited = sorted(_cited_names(finding) & names) if names else []
    if cited:
        problems.append({"kind": "lens_leak",
                         "detail": "the exploit finding cites a copy of the report "
                                   "(%s), which the exploit lens is not given: it "
                                   "read the reporter's text through its own "
                                   "search of the tree" % ", ".join(cited[:3])})
    blob = json.dumps(finding).lower()
    claimed = claims.get("claimed") or {}
    if claimed.get("cvss") and claimed["cvss"].lower() in blob:
        problems.append({"kind": "lens_leak",
                         "detail": "the exploit finding carries the reporter's CVSS "
                                   "vector, which the exploit packet withholds"})
    if report_text:
        prose = " ".join(str(finding.get(f) or "") for f in PROSE_FIELDS)
        shared = _ngrams(prose) & _ngrams(report_text)
        if shared:
            problems.append({"kind": "lens_leak",
                             "detail": "the exploit finding repeats the reporter's own "
                                       "wording verbatim: \"%s\"" % sorted(shared)[0]})
    return problems


def check_packet_isolation(rdir, anchors):
    """
    Did the packet the exploit lens was handed hold what it declares withheld?

    `check_lens` looks at what the lens WROTE. This looks at what it was GIVEN,
    on disk, after the fact: a packet that carried the report's text, path,
    endpoints or a hit quoting a copy of the report means the lens could have
    seen the framing it exists to be without, whatever its finding says.
    """
    packet = jload(os.path.join(rdir, "packet.exploit.json"))
    if not isinstance(packet, dict):
        return []
    leaks = exploit_packet_leaks(packet, (anchors or {}).get("reportCopiesSkipped") or [])
    if not leaks:
        return []
    return [{"kind": "lens_leak",
             "detail": "the exploit packet handed to the lens carried %s, which it "
                       "declares withheld" % "; ".join(leaks)}]


# --------------------------------------------------------------------------
# schema
# --------------------------------------------------------------------------

def _ground_ok(g):
    """A ground carries either a quote or the searches, by kind (contract 6)."""
    if not isinstance(g, dict):
        return False
    if g.get("code") in ABSENCE_GROUNDS:
        return bool(g.get("searched"))
    return bool(g.get("quote"))


def check_schema(finding, lens):
    problems = []
    verdict = finding.get("verdict")
    allowed = CODE_VERDICTS if lens == "code" else EXPLOIT_VERDICTS
    if verdict not in allowed:
        problems.append({"kind": "bad_verdict",
                         "detail": "%r is not one of %s" % (verdict, sorted(allowed))})
    if not finding.get("report_id"):
        problems.append({"kind": "missing_report_id",
                         "detail": "a finding without report_id matches no report"})
    if verdict in ("ABSENT", "NOT_EXPLOITABLE") and not finding.get("grounds"):
        problems.append({"kind": "dismissal_without_ground",
                         "detail": "%s requires at least one cited ground" % verdict})
    for i, g in enumerate(finding.get("grounds") or []):
        # By kind, per contract 6. An absence ground has no line to quote -
        # demanding one was demanding a citation of something that by definition
        # is not there, and the only way to satisfy it was the unrelated line
        # the split existed to stop. It carries its searches instead.
        if not _ground_ok(g):
            absence = isinstance(g, dict) and g.get("code") in ABSENCE_GROUNDS
            problems.append({
                "kind": "ground_without_searches" if absence
                        else "ground_without_quote",
                "detail": ("grounds[%d] (%s) asserts something does not exist "
                           "and records no `searched`, so nothing about it is "
                           "checkable" % (i, (g or {}).get("code")))
                          if absence else
                          ("grounds[%d] (%s) has no quote, so nothing about it "
                           "is checkable" % (i, (g or {}).get("code")))})
    if verdict == "UNDECIDED" and not finding.get("missing_information"):
        problems.append({"kind": "undecided_without_gap",
                         "detail": "UNDECIDED must name what would settle it"})
    if verdict == "NEEDS_REPORTER_INPUT" and not finding.get("reporter_questions"):
        problems.append({"kind": "no_questions_for_reporter",
                         "detail": "NEEDS_REPORTER_INPUT must carry the questions"})
    if verdict == "PRESENT" and not finding.get("evidence"):
        problems.append({"kind": "present_without_evidence",
                         "detail": "PRESENT with no evidence has traced nothing"})
    # The gate below was a raw string comparison against "low", so "LOW" and
    # "lowish" both walked a definite verdict past it. Contract section 5 defines
    # a closed vocabulary; hold a STATED confidence to it, case-insensitively.
    # An absent one is left alone - the contract does not require the field, and
    # inventing that requirement here is a different change.
    conf = finding.get("confidence")
    conf_norm = conf.strip().lower() if isinstance(conf, str) else None
    if "confidence" in finding and conf_norm not in CONFIDENCE_VALUES:
        problems.append({
            "kind": "bad_confidence",
            "detail": "confidence %r is not one of %s; contract section 5 defines a "
                      "closed vocabulary" % (conf, sorted(CONFIDENCE_VALUES))})
    if conf_norm == "low" and verdict in ("PRESENT", "ABSENT",
                                          "EXPLOITABLE",
                                          "NOT_EXPLOITABLE"):
        problems.append({"kind": "confidence_conflict",
                         "detail": "a definite verdict at low confidence should be "
                                   "UNDECIDED"})
    if finding.get("symbol_source") == "mapped" and not finding.get("mapping_evidence"):
        problems.append({"kind": "mapping_without_evidence",
                         "detail": "symbol_source \"mapped\" needs mapping_evidence "
                                   "showing the two names are the same code"})
    if finding.get("symbol_source") == "not-established":
        grounds = {g.get("code") for g in (finding.get("grounds") or [])}
        if grounds & ABSENCE_GROUNDS:
            problems.append({"kind": "contradictory_source",
                             "detail": "cannot establish that something is not reached "
                                       "without establishing what it is"})
    return problems


# --------------------------------------------------------------------------
# severity comparison  (the inflated-report check)
# --------------------------------------------------------------------------

def severity_gap(finding, claims):
    claimed = (claims.get("claimed") or {}).get("severity")
    derived = finding.get("severity")
    norm = {"moderate": "medium", "informational": "info"}
    claimed = norm.get(claimed, claimed)
    if not claimed or not derived:
        return None
    if claimed not in SEVERITIES or derived not in SEVERITIES:
        return None
    gap = SEVERITIES.index(claimed) - SEVERITIES.index(derived)
    if abs(gap) >= 2:
        return {"claimed": claimed, "derived": derived, "steps": gap,
                "detail": "the report claims %s, the analysis derived %s"
                          % (claimed, derived)}
    return None


# --------------------------------------------------------------------------
# queue
# --------------------------------------------------------------------------

def sampled(report_id):
    h = hashlib.sha256(report_id.encode("utf-8")).hexdigest()
    return int(h[:8], 16) % 100 < SAMPLE_PERCENT


def check_dismissal_gate(rdir, finding):
    """Is this ABSENT one anybody tried to disprove?

    The orchestrator is told to run the challenge stage before a dismissal, and
    `report.py dismissal` decides whether it was earned. This is the check that
    does not depend on the orchestrator having done either. An ABSENT with no
    dismissal record is a dismissal nobody tested, and it is the single most
    expensive thing this pipeline can emit.
    """
    problems = []
    dj = jload(os.path.join(rdir, "dismissal.json"))
    if dj is None:
        problems.append({
            "kind": "dismissal_untested",
            "detail": "the code verdict is ABSENT and no dismissal record exists: "
                      "the challenge stage never ran, so nobody tried to find the "
                      "defect before it was called absent. Run `report.py "
                      "challenge`, run the hunter role on every angle, then "
                      "`report.py dismissal`."})
        return problems
    if not dj.get("dismissalStands"):
        problems.append({
            "kind": "dismissal_not_earned",
            "detail": "the code verdict is ABSENT but the dismissal gate refused "
                      "it: %s" % (dj.get("why") or "no reason recorded")})
    if dj.get("nothingClaimedByReporter"):
        problems.append({
            "kind": "absent_on_inferred_search",
            "detail": "the reporter named no symbol, file, package or CVE, so "
                      "every region examined was inferred by this pipeline. Not "
                      "finding the defect where a search pointed means the "
                      "pointing was wrong. This is NEEDS_REPORTER_INPUT, not "
                      "ABSENT."})
    for angle in dj.get("anglesNotRun") or []:
        problems.append({"kind": "dismissal_angle_not_run",
                         "detail": "hunt angle %r never ran" % angle})
    for angle in dj.get("anglesWithThinSearches") or []:
        problems.append({"kind": "dismissal_search_too_thin",
                         "detail": "hunt angle %r recorded almost no searches, so "
                                   "it does not test the dismissal" % angle})
    return problems


def check_panel(rdir, lens, finding):
    """Did anybody try to break this finding?

    Returns (problems, gaps). The split matters. A finding the panel KILLED and
    that is still recorded as PRESENT is a contradiction in the record, and that
    is a problem with the finding. A finding nobody refuted is not wrong - it is
    untested, which is a fact about the run rather than a defect in the analysis,
    and the two-lens profile in TUNING.md skips the panel on purpose. So an
    untested finding goes to the arbiter's queue and is named in the assessment;
    it does not get marked defective.

    An untested ABSENT is treated differently, and check_dismissal_gate says why.
    """
    problems, gaps = [], []
    pj = jload(os.path.join(rdir, "panel.%s.json" % lens))
    if pj is None:
        gaps.append("%s: %s is an assertion no refuter has tried to break"
                    % (lens, finding.get("verdict")))
        return problems, gaps
    if pj.get("outcome") == "REFUTED":
        problems.append({"kind": "panel_refuted",
                         "detail": "the refutation panel killed this finding on "
                                   "%s, and it is still recorded as %s"
                                   % (", ".join(pj.get("refuted") or []),
                                      finding.get("verdict"))})
    for angle in pj.get("anglesNotRun") or []:
        gaps.append("%s: refutation angle %r never ran" % (lens, angle))
    return problems, gaps


def queue_reasons(rec):
    reasons = []
    fatal = {"not_found", "file_not_found", "line_out_of_range", "wrong_line"}
    for lens in ("code", "exploit"):
        block = rec.get(lens) or {}
        if not block.get("present"):
            if block.get("unreadable"):
                reasons.append("%s: the finding file exists but could not be "
                               "parsed - the verdict has been lost" % lens)
            continue
        if any(c["status"] == "malformed" for c in block["citations"]):
            reasons.append("%s: a cited field is the wrong shape" % lens)
        if any(c["status"] in fatal for c in block["citations"]):
            reasons.append("%s: a citation is not where the finding says it is" % lens)
        if any(c["status"] == "drift" for c in block["citations"]):
            reasons.append("%s: a citation drifted" % lens)
        for p in block["problems"]:
            reasons.append("%s: %s" % (lens, p["kind"]))
        for gap in block.get("stageGaps") or []:
            reasons.append(gap)
        v = block["verdict"]
        if lens == "code" and v == "ABSENT":
            reasons.append("code: ABSENT closes an external report - the expensive "
                           "direction")
        if lens == "exploit" and v == "NOT_EXPLOITABLE":
            reasons.append("exploit: NOT_EXPLOITABLE downgrades a real defect on a "
                           "reachability argument")
        if lens == "code" and v == "NEEDS_REPORTER_INPUT":
            reasons.append("code: NEEDS_REPORTER_INPUT is the cheap exit")
        if lens == "exploit" and v == "EXPLOITABLE":
            reasons.append("exploit: EXPLOITABLE creates an embargo and a public "
                           "statement")
        if block["finding"].get("symbol_source") == "inferred":
            reasons.append("%s: the symbol was inferred from a word search, not "
                           "named by the reporter" % lens)
        grounds = {g.get("code") for g in (block["finding"].get("grounds") or [])}
        for g in sorted(grounds & DISMISSAL_GROUNDS):
            reasons.append("%s: ground %r closes or downgrades the report" % (lens, g))
        if block.get("severityGap"):
            reasons.append("%s: severity gap - %s" % (lens, block["severityGap"]["detail"]))
    if not reasons and sampled(rec["report_id"]):
        reasons.append("calibration sample (%d%%)" % SAMPLE_PERCENT)
    return reasons


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def verify_one(root, report_id, reports_dir, findings_dir):
    rdir = os.path.join(reports_dir, report_id)
    claims = jload(os.path.join(rdir, "claims.json"), {}) or {}
    anchors = jload(os.path.join(rdir, "anchors.json"), {}) or {}
    packet = jload(os.path.join(rdir, "packet.code.json"), {}) or {}
    advisory = packet.get("advisory")
    version_assessment = packet.get("versionAssessment")

    report_text = None
    # The report's own metadata. It is how a byte-identical copy of the report in
    # the tree is recognised, so a citation into it is refused like one into the
    # run directory (`report.citable_problem`).
    meta = jload(os.path.join(rdir, "meta.json"), {}) or {}
    if not isinstance(meta, dict):
        meta = {}
    rpath = os.path.join(rdir, "report.txt")
    if os.path.isfile(rpath):
        try:
            with open(rpath, "r", encoding="utf-8", errors="replace") as fh:
                report_text = fh.read()
        except (OSError, IOError):
            report_text = None

    probe = jload(os.path.join(reports_dir, report_id, "probe.json"))
    code_finding = jload(os.path.join(findings_dir, "%s-code.json" % report_id)) or {}
    established = [s for s in (code_finding.get("analysed_symbol"),
                               code_finding.get("vulnerable_symbol")) if s]
    # the exploit packet carries the code finding's cited lines, so anything
    # written on them is grounded for that lens as well
    established += sorted(symbols_in_cited_code(code_finding))

    rec = {"report_id": report_id}
    for lens in ("code", "exploit"):
        path = os.path.join(findings_dir, "%s-%s.json" % (report_id, lens))
        finding = jload(path, distinguish=True)
        if finding is UNREADABLE:
            rec[lens] = {"present": False, "unreadable": True,
                         "problems": [{"kind": "finding_unreadable",
                                       "detail": "%s exists but is not valid "
                                                 "JSON; the verdict for this "
                                                 "lens has been lost, and an "
                                                 "empty queue here means "
                                                 "nothing" % path}]}
            continue
        if finding is None:
            rec[lens] = {"present": False}
            continue
        problems = check_schema(finding, lens)
        problems += check_inferred(finding, claims, probe)
        vocab_extra = list(established) if lens == "exploit" else []
        vocab_extra += sorted(symbols_in_probe(probe))
        g, _named = check_grounding(finding, claims, advisory, vocab_extra)
        problems += g
        prose_anchors, anchor_problems = check_prose_anchors(root, finding, meta)
        problems += anchor_problems
        problems += check_near_miss(finding, anchors)
        problems += check_version(finding, advisory, version_assessment)
        if lens == "exploit":
            problems += check_lens(finding, claims, report_text,
                                   (anchors or {}).get("reportCopiesSkipped") or [])
            problems += check_packet_isolation(rdir, anchors)
        # The stages that only exist to test a conclusion. These run against the
        # record on disk rather than against the orchestrator's account of what
        # it did, which is the point: a stage that was skipped leaves no file,
        # and a skipped stage is exactly what this catches.
        gaps = []
        # NOT_EXPLOITABLE is included because it is a dismissal too: it says a
        # real defect cannot be reached, and the angles that test it are the
        # ones that go looking for the caller text search cannot see.
        if finding.get("verdict") in ("PRESENT", "EXPLOITABLE", "NOT_EXPLOITABLE"):
            panel_problems, gaps = check_panel(rdir, lens, finding)
            problems += panel_problems
        if lens == "code" and finding.get("verdict") == "ABSENT":
            problems += check_dismissal_gate(rdir, finding)
        rec[lens] = {
            "stageGaps": gaps,
            "present": True,
            "verdict": finding.get("verdict"),
            "confidence": finding.get("confidence"),
            "citations": check_all_citations(root, finding, meta),
            "proseAnchors": prose_anchors,
            "problems": problems,
            "severityGap": severity_gap(finding, claims),
            "finding": finding,
        }
        # The precheck record is written under .report-triage/arbitration/, and
        # it embeds severityGap - which reads claims.claimed.severity, the
        # reporter's own word. The exploit lens is denied that everywhere else;
        # this file used to hand it back. Its own record now carries the gap
        # only as a direction, and the arbiter (which is allowed the claim)
        # reads the reporter's number from the packet.
        if lens == "exploit" and rec[lens].get("severityGap"):
            gap = rec[lens]["severityGap"]
            steps = gap.get("steps")
            rec[lens]["severityGap"] = {
                "rows": abs(steps) if isinstance(steps, int) else None,
                "direction": (None if not isinstance(steps, int) else
                              "claimed-higher" if steps > 0 else
                              "claimed-lower" if steps < 0 else "level"),
                "detail": "withheld from this record: the reporter's claimed "
                          "severity is not shown beside a reachability verdict"}
    rec["queue"] = queue_reasons(rec)
    rec["queued"] = bool(rec["queue"])
    return rec


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="verify_findings.py",
        description="Check findings against the source and the report; build the "
                    "arbiter queue.")
    ap.add_argument("pos_id", nargs="?", default=None, metavar="REPORT_ID",
                    help="check one report only (or give it as --id, the form "
                         "report.py also takes)")
    ap.add_argument("--root", default=".", help="repository root")
    ap.add_argument("--reports", default=None, help="reports directory")
    ap.add_argument("--findings", default=None, help="findings directory")
    ap.add_argument("--out", default=None, help="where to write precheck.json")
    ap.add_argument("--id", default=None, help="check one report only")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    # The report id goes first or after --id, as in every report.py command.
    if args.pos_id and args.id and args.pos_id != args.id:
        print("two different report ids were given (%r and --id %r); give one"
              % (args.pos_id, args.id), file=sys.stderr)
        return 2
    args.id = args.id or args.pos_id

    root = args.root
    ws, skill = os.path.realpath(root), os.path.realpath(str(SKILL_ROOT))
    if ws == skill or ws.startswith(skill + os.sep):
        print("the workspace (%s) is inside the skill folder (%s). The skill "
              "folder is read-only and shared; run from the root of the "
              "repository being triaged instead." % (ws, skill), file=sys.stderr)
        return 2
    # An id becomes a path under the run directory (the precheck file is named
    # for it), so it must be a plain name, as report.py requires.
    if args.id is not None and not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
                                            args.id):
        print("refusing the report id %r: it must be a plain name - letters, "
              "digits, dot, dash or underscore, no separators and no leading dot."
              % args.id, file=sys.stderr)
        return 2
    reports_dir = args.reports or os.path.join(root, ".report-triage", "reports")
    findings_dir = args.findings or os.path.join(root, ".report-triage", "findings")
    out_dir = args.out or os.path.join(root, ".report-triage", "arbitration")

    if not os.path.isdir(reports_dir):
        print("no reports directory at %s" % reports_dir, file=sys.stderr)
        return 2
    ids = [args.id] if args.id else sorted(os.listdir(reports_dir))

    records = []
    for rid in ids:
        if not os.path.isdir(os.path.join(reports_dir, rid)):
            continue
        records.append(verify_one(root, rid, reports_dir, findings_dir))

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)

    # One precheck per report, so two triages running against the same tree
    # cannot erase each other. The combined file is written only by a full
    # sweep, where it is a superset rather than a replacement - a scoped run
    # writing it would delete every other report's entry, which is the opposite
    # of what --id looks like it does.
    by_report = {}
    for rec in records:
        rid = rec["report_id"]
        rp = os.path.join(out_dir, "precheck-%s.json" % rid)
        with open(rp, "w", encoding="utf-8") as fh:
            json.dump({"records": [rec], "samplePercent": SAMPLE_PERCENT},
                      fh, indent=2)
            fh.write("\n")
        by_report[rid] = rp.replace(os.sep, "/")

    path = os.path.join(out_dir, "precheck.json")
    if args.id:
        path = by_report.get(args.id, path)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"records": records, "samplePercent": SAMPLE_PERCENT},
                      fh, indent=2)
            fh.write("\n")

    # The arbiter's record is terminal - nothing overturns it - but it is also
    # the prose a person actually reads, so its anchors are resolved too and
    # reported for the orchestrator to surface before it writes the assessment.
    arb_problems, arb_unreadable, arb_notes = [], [], []
    for name in sorted(os.listdir(out_dir)) if os.path.isdir(out_dir) else []:
        if not (name.startswith("ARB-") and name.endswith(".json")):
            continue
        # the reader every role's reply goes through: a fenced file is read, and
        # one that cannot be read is named, not skipped
        record, found, why = read_arbiter(root, name[len("ARB-"):-len(".json")],
                                          out_dir)
        for _kind, text in found:
            print("reply note (arbiter): %s" % text, file=sys.stderr)
        if why:
            arb_unreadable.append({"arbitration": name, "problem": why})
        elif found:
            arb_notes.extend({"arbitration": name, "note": text} for _k, text in found)
        if not isinstance(record, dict):
            continue
        arb_id = record.get("report_id") if isinstance(record.get("report_id"), str) \
            else name[len("ARB-"):-len(".json")]
        arb_meta = jload(os.path.join(reports_dir, arb_id, "meta.json"), {}) \
            if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", arb_id) else {}
        _res, probs = check_prose_anchors(
            root, record, arb_meta if isinstance(arb_meta, dict) else {})
        for pr in probs:
            arb_problems.append(dict(pr, arbitration=name))

    problems = sum(len((r.get(l) or {}).get("problems") or [])
                   for r in records for l in ("code", "exploit"))
    bad_cites = sum(1 for r in records for l in ("code", "exploit")
                    for c in ((r.get(l) or {}).get("citations") or [])
                    if c["status"] in ("not_found", "file_not_found",
                                       "line_out_of_range", "wrong_line"))
    summary = {
        "checked": len(records),
        "queued": [r["report_id"] for r in records if r["queued"]],
        "problems": problems,
        "failedCitations": bad_cites,
        "precheck": path.replace(os.sep, "/"),
        "precheckByReport": by_report,
        "queue": [{"report_id": r["report_id"], "reasons": r["queue"]}
                  for r in records if r["queued"]],
    }
    if arb_problems:
        summary["arbitrationAnchorProblems"] = arb_problems
    if arb_unreadable:
        summary["arbitrationUnreadable"] = arb_unreadable
    if arb_notes:
        summary["arbitrationNotes"] = arb_notes
    if not args.quiet:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
