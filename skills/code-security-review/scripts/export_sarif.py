#!/usr/bin/env python3
"""
export_sarif.py - the run, as SARIF 2.1.0, for anything that is not a person.

This skill already READS SARIF: stage 3 ingests semgrep, cppcheck and CodeQL and
joins their findings to functions. It had no way to write any, which meant the
one artifact the pipeline produces for a machine was `REPORT.md` - a document
whose whole design is to be read by a human, parsed by nobody, and diffed by
nothing.

Three things that costs, and each is the sort of thing that only hurts after the
hundredth finding:

  * **Nothing can tell two runs apart.** "Is this the same finding as last week's,
    or a new one?" has no mechanical answer when the record is prose. SARIF's
    `partialFingerprints` gives it one, and this writes a fingerprint that
    survives the line moving - it is keyed on the function and the rule, not on
    a line number, because a finding that renumbers itself on every unrelated
    edit above it is a finding nobody can track. A second sink of the same rule
    in the same function gets an occurrence suffix, so two findings are never
    one fingerprint.
  * **Nothing else can show the findings.** GitHub's Security tab, an IDE, a
    dashboard - all of them speak SARIF and none of them speak ours.
  * **The suppressions had nowhere to go.** SARIF models a suppression natively,
    with a justification and a status, which is very close to what the ledger
    already records: an author, a reason and an expiry.

What this refuses to do is as important. It exports **adjudicated findings only**
(contract §9 rule 3), and it carries the coverage qualification into the run's
own properties and into a tool-execution notification, so that a consumer showing
the results cannot show a count of findings without the sentence saying what was
not examined (§9 rule 5). A SARIF file that says "6 results" and nothing about
the 18,012 functions below the operating point is the most misread artifact this
pipeline could emit.

Stdlib only. Python 3.8+.

Usage
  python3 export_sarif.py --root .
  python3 export_sarif.py --root . --out /tmp/findings.sarif
  python3 export_sarif.py --root . --include-dismissed     # NOT_VULNERABLE too
  python3 export_sarif.py --selftest

Exit codes
  0  written
  1  the run directory is incomplete, or a symlink sits on the path the file
     would be written through (contract §1, §9 rule 2), or --out names a path
     inside the scanned tree and outside its .security-review/ (§9 rule 2), or
     --selftest failed
  2  nothing adjudicated to export
  7  refused before reading or writing anything: the scanned repository commits
     files under .security-review/ other than .gitignore and regular files
     under ledger/, git cannot say whether it does, or --root is this installed
     skill or an old copy of the scanner rather than a repository
     (rules_lib.run_dir_gate).
     Checked first, so it outranks every other code
"""

import argparse
import datetime
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True      # the skill folder is read-only: no __pycache__ in it
sys.path.insert(0, HERE)
import rules_lib                                       # noqa: E402
import sweep_secrets                                   # noqa: E402

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = ("https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/"
                "schemas/sarif-schema-2.1.0.json")
TOOL_NAME = "Security Review (Agent Skill)"
TOOL_URI = "https://github.com/Martyx00/Security-Skills-Collection"
BUNDLE_VERSION = rules_lib.skill_version()

RUN_DIR = ".security-review"

# The whole-function pass, derived from a function's other candidates. The same
# literal as enrich_candidates.WFS_RULE and ledger.WFS_RULE.
WFS_RULE = "MEM-WFS"

# SARIF has three levels and this skill has five severities, so the mapping is
# lossy in one direction and the `security-severity` property carries the detail.
# GitHub reads that property, as a number, and ignores `level` when ranking.
LEVEL_BY_SEVERITY = {
    "critical": "error", "high": "error",
    "medium": "warning",
    "low": "note", "info": "note",
}
SECURITY_SEVERITY = {
    "critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0",
}

# Which verdicts are a result at all. NEEDS_HUMAN_REVIEW is exported because it
# is the bucket a person most needs to see, and it is exported as a `note` with
# the unresolved gate in the message rather than as a finding anyone can action.
EXPORTED_VERDICTS = ("VULNERABLE", "ACCEPTED_RISK", "NEEDS_HUMAN_REVIEW")
DISMISSED_VERDICTS = ("NOT_VULNERABLE",)

EVIDENCE_ROLE_TEXT = {
    "source": "attacker-controlled source",
    "propagation": "propagation",
    "allocation": "allocation",
    "free": "free",
    "guard": "guard considered",
    "sink": "sink",
    "config": "configuration",
    "caller": "caller",
    "declaration": "declaration",
}



# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #
#
# THIS EXISTS BECAUSE IT WAS A LIVE LEAK. A LOG-005 finding quotes the line it
# flagged, and the line it flagged is the one holding the credential. That quote
# travelled verbatim into `evidence[].code`, out of this exporter as a SARIF
# snippet, and into whatever consumes the file - which for SARIF means GitHub's
# Security tab. The most public artifact the pipeline produces was carrying the
# secret the pipeline had just found. Reproduced with a canary before this was
# written, and the canary came out the other end whole.
#
# The detection is `sweep_secrets`', not a second copy: sweep_secrets.export_spans,
# the one detector the REPORT.md gate and the ledger also read. A scrubber with
# its own idea of what a secret looks like drifts from the tool that finds them,
# and it did. This file used to carry its own copies of the quoted-assignment,
# key-array and URL-password detectors, and it and the report gate judged the
# same string differently: `password = "Pr0dPassw0rd…"` - a truncation read as
# a redaction - came out of here whole while the gate refused it, and a
# fix-commit URL was mangled here while the gate refused the report quoting it.
# Same reason the language table lives in rules_lib.
#
# Before that the scrub was the families and the entropy run alone, and its
# docstring said a credential that is neither "is one this pipeline could not
# have found in the first place". That was false for the very findings the
# scrub exists for: LOG-005 flags a quoted value of six characters or more
# under a password/secret/token name WHATEVER its entropy, and HW-010 flags a
# key byte array, where every byte is its own four-character run. export_spans
# covers both, and says in its docstring what it covers.
#
# Scrubbing is applied to EVERY string this file writes that came from a finding
# or from the tree: messages, snippets, taint paths, impacts, remediations and
# the arbiter's prose. A field added later is scrubbed by default because
# `_scrub_obj` walks the structure rather than naming fields.


def scrub(text):
    """A string with anything that looks like key material redacted in place.

    Every span sweep_secrets.export_spans() returns, of every kind: a
    known-token family (only its `secret` part where it names one, so a URL
    keeps its host), a quoted value under a secret-shaped name (LOG-005), a key
    byte array and its continuation lines (HW-010), and a high-entropy run.
    What that detector lets through - an interpolation, a value already
    redacted, a name that describes the secret rather than holding it - the
    REPORT.md gate lets through too. What the gate leaves and this takes are
    the REDACT_ONLY_KINDS: a value that reads as words, a passphrase or
    `"changeme"`, which LOG-005 flags and which the gate leaves only because it
    refuses a whole report on a hit. So no line the gate refuses leaves here
    whole. Unlike that gate, nothing here excuses a bare digest as provenance:
    a redacted commit costs a dashboard nothing.
    """
    if not isinstance(text, str) or not text:
        return text
    return sweep_secrets.redact_spans(
        text, [(start, end) for start, end, _kind in sweep_secrets.export_spans(text)])


def _scrub_obj(obj):
    """Every string anywhere in the structure, scrubbed.

    Walks rather than naming fields, so a property added to a result later is
    covered without anybody remembering to add it here.
    """
    if isinstance(obj, str):
        return scrub(obj)
    if isinstance(obj, list):
        return [_scrub_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _scrub_obj(v) for k, v in obj.items()}
    return obj


class Incomplete(Exception):
    """The run directory does not hold what an export needs."""


# --------------------------------------------------------------------------- #
# reading the run
# --------------------------------------------------------------------------- #

def _read_json(path, what):
    if not os.path.isfile(path):
        raise Incomplete("%s is missing, so %s cannot be exported" % (path, what))
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _maybe_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# Same per-line bound as ledger.py's: suppressions.jsonl is committed, so a
# hostile tree ships it, and `for line in fh` on a file with no newline in it is
# an unbounded read.
MAX_LINE_BYTES = 4 * 1024 * 1024


def _read_jsonl(path):
    """(records, unreadable) - the objects in a .jsonl file, and how many lines
    were not one.

    suppressions.jsonl is committed and hand-edited, and this used to crash the
    whole export on it: a line that was a JSON list reached active_suppression()
    as a list, and a byte that is not UTF-8 raised while the file was iterated.
    ledger.py reports those same lines as problems, so this counts them - an
    unreadable line suppresses nothing, which is the safe direction - and the
    count goes into the file as a warning rather than into a traceback.
    """
    rows, unreadable = [], 0
    if not os.path.isfile(path):
        return rows, unreadable
    try:
        handle = open(path, "rb")
    except OSError:
        return rows, 1
    with handle as fh:
        while True:
            line = fh.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_LINE_BYTES:
                unreadable += 1
                while not line.endswith(b"\n"):     # drained, never held
                    line = fh.readline(MAX_LINE_BYTES + 1)
                    if not line:
                        break
                continue
            if not line.strip():
                continue
            try:
                row = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                unreadable += 1
                continue
            if not isinstance(row, dict):
                unreadable += 1
                continue
            rows.append(row)
    return rows, unreadable


def load_run(root):
    """Everything the export reads, or Incomplete with which part is missing."""
    base = os.path.join(root, RUN_DIR)
    findings_dir = os.path.join(base, "findings")
    arb_dir = os.path.join(base, "arbitration")
    if not os.path.isdir(findings_dir):
        raise Incomplete("%s is missing: stage 4 has not run, and an export of a "
                         "run with no verdicts in it would be an empty file "
                         "claiming a clean repository" % findings_dir)

    findings = {}
    for name in sorted(os.listdir(findings_dir)):
        if not name.endswith(".json"):
            continue
        obj = _maybe_json(os.path.join(findings_dir, name))
        if isinstance(obj, dict) and obj.get("candidate_id"):
            findings[obj["candidate_id"]] = obj

    arbitrations = {}
    if os.path.isdir(arb_dir):
        for name in sorted(os.listdir(arb_dir)):
            if not (name.startswith("ARB-") and name.endswith(".json")):
                continue
            obj = _maybe_json(os.path.join(arb_dir, name))
            if isinstance(obj, dict) and obj.get("candidate_id"):
                arbitrations[obj["candidate_id"]] = obj

    candidates = {}
    cand_dir = os.path.join(base, "candidates")
    if os.path.isdir(cand_dir):
        for name in sorted(os.listdir(cand_dir)):
            if not name.endswith(".json") or name == "coverage.json":
                continue
            obj = _maybe_json(os.path.join(cand_dir, name))
            rows = obj if isinstance(obj, list) else (obj or {}).get("candidates", [])
            for row in rows or []:
                if isinstance(row, dict) and row.get("candidate_id"):
                    candidates[row["candidate_id"]] = row
    # A derived MEM-WFS finding has no candidate record of its own: it is read against its
    # source's (rules_lib.derived_record).
    for cid, finding in findings.items():
        if cid not in candidates and finding.get("derived_from"):
            record = rules_lib.derived_record(
                finding, candidates.get(str(finding["derived_from"])))
            if record is not None:
                candidates[cid] = record

    suppressions, unreadable = _read_jsonl(
        os.path.join(base, "ledger", "suppressions.jsonl"))
    return {
        "run": _maybe_json(os.path.join(base, "run.json")) or {},
        "manifest": _maybe_json(os.path.join(base, "manifest.json")) or {},
        "operating_point": _maybe_json(
            os.path.join(base, "scores", "operating-point.json")) or {},
        "scorer_report": _maybe_json(
            os.path.join(base, "scores", "scorer-report.json")) or {},
        "coverage": _maybe_json(os.path.join(cand_dir, "coverage.json")) or {},
        "findings": findings,
        "arbitrations": arbitrations,
        "candidates": candidates,
        "suppressions": suppressions,
        "suppressions_unreadable": unreadable,
    }


# --------------------------------------------------------------------------- #
# the pieces of a SARIF run
# --------------------------------------------------------------------------- #

def rule_descriptors(rules_dir):
    """One reportingDescriptor per rule this skill ships.

    Declared whether or not the run produced a result for it: a consumer that
    knows the full ruleset can tell "this rule found nothing" from "this rule
    does not exist", and those mean opposite things - which is the same
    distinction `zero_hit_cause` draws inside the pipeline.
    """
    try:
        rules = rules_lib.load_rules(rules_dir)
    except Exception:                                  # noqa: BLE001
        return [], {}
    out, index = [], {}
    for rule in sorted(rules, key=lambda r: r["rule_id"]):
        cwe = rule.get("cwe") or ""
        tags = ["security", rule.get("category") or "uncategorised"]
        if cwe:
            tags.append("external/cwe/%s" % cwe.lower().replace(" ", ""))
        if rule.get("high_signal"):
            tags.append("high-signal")
        if rule.get("threat_model"):
            tags.append("threat-model/%s" % rule["threat_model"])
        # A rule stage 3 derives from a triage verdict (LOG-TRI) is not a pattern anybody
        # grepped for: a consumer should be able to tell a result that exists because a
        # model rated a function high from one a rule matched.
        if rule.get("derived_at") == "enrich":
            tags.append("derived/triage")
        descriptor = {
            "id": rule["rule_id"],
            "name": "".join(w.title() for w in
                            (rule.get("title") or rule["rule_id"]).split()),
            "shortDescription": {"text": rule.get("title") or rule["rule_id"]},
            "fullDescription": {
                "text": rule.get("flag_condition")
                        or rule.get("why_flagged")
                        or rule.get("title") or rule["rule_id"]},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "tags": tags,
                "category": rule.get("category"),
                "cwe": cwe,
                "high-signal": bool(rule.get("high_signal")),
                "match-target": rule.get("match_target"),
            },
        }
        if rule.get("derived_at") == "enrich":
            descriptor["properties"]["derived"] = "enrich"
        out.append(descriptor)
        index[rule["rule_id"]] = descriptor
    return out, index


def _region(finding, candidate):
    loc = finding.get("primary_location") or ""
    path, line = None, None
    if isinstance(loc, str) and ":" in loc:
        path, _, tail = loc.rpartition(":")
        try:
            line = int(tail)
        except ValueError:
            path, line = loc, None
    if not path:
        path = (candidate or {}).get("file")
    if line is None:
        line = (candidate or {}).get("line")
    return path, line


def _artifact_location(path):
    return {"uri": (path or "").replace(os.sep, "/"), "uriBaseId": "%SRCROOT%"}


def _physical(path, line, snippet=None):
    region = {"startLine": max(1, int(line or 1))}
    if snippet:
        region["snippet"] = {"text": snippet}
    return {"physicalLocation": {"artifactLocation": _artifact_location(path),
                                 "region": region}}


def fingerprint(finding, candidate):
    """Stable across a line moving, and across a re-run of the same code.

    Keyed on the function and the rule rather than the line, because a finding
    that renumbers itself whenever somebody adds an import above it is a finding
    no consumer can follow between runs. The content hash is deliberately NOT in
    it: an edit inside the function should update the same finding, not open a
    second one and silently close the first.

    This is the BASE. fingerprints() is what a result carries, because stage 3
    emits one candidate per (rule, line) and two sinks of one rule in one
    function would otherwise share it.
    """
    key = ((candidate or {}).get("function_key") or (candidate or {}).get("file")
           or _region(finding, candidate)[0] or "")
    rid = finding.get("rule_id") or (candidate or {}).get("rule_id") or ""
    return "%s::%s" % (key, rid)


def fingerprints(data):
    """{candidate_id: fingerprint} for every finding in the run.

    Two memcpy sinks in one function are two candidates, two findings and two
    results, and they used to carry ONE fingerprint - which a SARIF consumer
    reads as one logical result, so GitHub showed one alert for two adjudicated
    findings, or let them swap identity between runs. So within a base the
    findings are ordered by sink line and numbered: the first keeps the base
    unchanged, which keeps every single-sink finding's existing dashboard
    identity, and the n-th gets `::n`. A rule id never contains `::`, so a
    suffixed value cannot collide with another base.

    The line is stage 1's - the candidate record's `line`, where the rule hit -
    and not the validator's `primary_location`, which is only the fallback when
    there is no candidate record. A model writes that location, and not the
    same way twice: §7 tells a dismissal to locate itself at the guard or the
    caller rather than the sink, and a VULNERABLE finding may be located at its
    source in another file. Ordered on it, a sibling turning NOT_VULNERABLE, or
    one run citing a source where the last cited the sink, swapped the two
    identities over code nobody changed - the very swap this numbering exists
    to stop. Stage 3 emits one candidate per (rule, line), so the stage-1 line
    orders a group completely; the sink text and the id only break a tie in
    hand-made data.

    Computed over EVERY finding, whatever its verdict, so neither
    --include-dismissed nor a sibling turning NOT_VULNERABLE renumbers the rest.
    Not keyed on candidate_id, which stage 3 renumbers from CAND-0001 every run.
    The trade-off is codeql-action's own for its `:N` counter: a new, earlier
    sink of the same rule in the same function shifts the ones after it.
    Hashing the sink text instead would not survive an edit to that line, and
    two identical `memcpy(d, s, n);` lines would still collide.
    """
    groups = {}
    for cid, finding in data["findings"].items():
        candidate = data["candidates"].get(cid)
        line = (candidate or {}).get("line")
        if line is None:
            line = _region(finding, candidate)[1]
        try:
            line = int(line or 0)
        except (TypeError, ValueError):
            line = 0
        sink = (candidate or {}).get("sink_text")
        groups.setdefault(fingerprint(finding, candidate), []).append(
            (line, sink if isinstance(sink, str) else "", cid))
    out = {}
    for base, members in groups.items():
        for ordinal, (_line, _sink, cid) in enumerate(sorted(members), 1):
            out[cid] = base if ordinal == 1 else "%s::%d" % (base, ordinal)
    return out


def _dismissal_code(finding, arb):
    """The disqualifier a NOT_VULNERABLE verdict was reached under, as text.

    The first `false_positive_reasons` entry, in either of the Validator
    Contract's two shapes - `{"code": "FP-GUARDED", ...}` or a string whose
    leading token is the code, which is how verify_findings.fp_reason() reads
    it. Inlined rather than imported: verify_findings is a very large module to
    load for one token. The list can be empty when the arbiter overturned a
    VULNERABLE, and the text says so rather than printing nothing.
    """
    reasons = finding.get("false_positive_reasons") or []
    if not isinstance(reasons, list):
        reasons = [reasons]
    for entry in reasons:
        code = None
        if isinstance(entry, dict):
            code = entry.get("code")
        elif isinstance(entry, str) and entry.strip():
            code = re.split(r"[:\s]", entry.strip(), maxsplit=1)[0]
        if isinstance(code, str) and code.strip():
            return code.strip().upper()
    if (arb or {}).get("arbitration") == "OVERTURNED":
        return "overturned by the arbiter"
    return "reason not recorded"


def result_for(finding, arb, candidate, suppressed, fp=None):
    """One SARIF result, built from the adjudicated state."""
    verdict = (arb or {}).get("final_verdict") or finding.get("verdict")
    severity = ((arb or {}).get("final_severity")
                or finding.get("severity") or "medium").lower()
    confidence = ((arb or {}).get("final_confidence")
                  or finding.get("confidence") or "medium")
    path, line = _region(finding, candidate)

    text = finding.get("title") or "%s finding" % finding.get("rule_id", "security")
    if verdict == "NEEDS_HUMAN_REVIEW":
        unresolved = finding.get("unresolved") or []
        text = ("NEEDS HUMAN REVIEW - %s. Unresolved: %s"
                % (text, "; ".join(str(u) for u in unresolved) or "not stated"))
    elif verdict == "ACCEPTED_RISK":
        text = "ACCEPTED RISK - %s" % text
    elif verdict in DISMISSED_VERDICTS:
        text = "NOT VULNERABLE (dismissed, %s) - %s" % (
            _dismissal_code(finding, arb), text)

    # The level said "error" for a dismissed high and for an unresolved high
    # alike, because it came from severity alone - so --include-dismissed put a
    # finding the pipeline CLEARED on a dashboard as an error-level alert with
    # nothing in its message to say so. Neither is a finding anyone can action:
    # both are notes, as the comment on EXPORTED_VERDICTS and the
    # --include-dismissed help always said. `kind` stays the default `fail`,
    # because SARIF 2.1.0 allows no level but `none` beside any other kind.
    if verdict == "NEEDS_HUMAN_REVIEW" or verdict in DISMISSED_VERDICTS:
        level = "note"
    else:
        level = LEVEL_BY_SEVERITY.get(severity, "warning")

    result = {
        "ruleId": finding.get("rule_id"),
        "level": level,
        "message": {"text": text},
        "locations": [_physical(path, line)],
        "partialFingerprints": {
            "securityReviewFindingV1": fp or fingerprint(finding, candidate)},
        "properties": {
            "security-severity": SECURITY_SEVERITY.get(severity, "5.5"),
            "candidate_id": finding.get("candidate_id"),
            "verdict": verdict,
            "confidence": confidence,
            "severity": severity,
            "cwe": finding.get("cwe"),
            "function_key": (candidate or {}).get("function_key"),
            "content_hash": (candidate or {}).get("content_hash"),
            "adjudicated": bool(arb),
            "arbitration": (arb or {}).get("arbitration"),
            "attacker_model": finding.get("attacker_model"),
            # The arbiter's corrected impact where its claim audit found the
            # validator's refuted or overstated, as the report prints it; a
            # dashboard showing the lowered severity beside the impact that
            # justified the higher one would say both at once.
            "impact": (arb or {}).get("final_impact") or finding.get("impact"),
            # The contract moved remediation to an object with a summary; the precheck
            # still accepts the bare string and flags it, so a run that carried on past
            # that flag exports the string as it is rather than dying on `.get`.
            "remediation": (finding["remediation"].get("summary")
                            if isinstance(finding.get("remediation"), dict)
                            else finding.get("remediation")
                            if isinstance(finding.get("remediation"), str) else None),
        },
    }
    if verdict in DISMISSED_VERDICTS:
        # A number a consumer ranks by does not belong on a result the pipeline
        # cleared; `severity` and `verdict` still say what it was.
        del result["properties"]["security-severity"]

    # The evidence chain, in order, as related locations. This is the part a
    # reviewer actually needs and the part prose loses: source, propagation and
    # sink as three clickable lines rather than a sentence describing them.
    related = []
    for item in finding.get("evidence") or []:
        if not isinstance(item, dict) or not item.get("file"):
            continue
        role = EVIDENCE_ROLE_TEXT.get(item.get("role"), item.get("role") or "evidence")
        loc = _physical(item["file"], item.get("line"), item.get("code"))
        loc["message"] = {"text": role}
        related.append(loc)
    for guard in finding.get("guards_considered") or []:
        if not isinstance(guard, dict) or not guard.get("file"):
            continue
        loc = _physical(guard["file"], guard.get("line"), guard.get("code"))
        loc["message"] = {"text": "guard considered - %s"
                                  % (guard.get("why_insufficient") or "insufficient")}
        related.append(loc)
    if related:
        result["relatedLocations"] = related

    if finding.get("taint_path"):
        result["properties"]["taint_path"] = finding["taint_path"]
    if arb and arb.get("crux"):
        result["properties"]["arbiter_crux"] = arb["crux"]
        result["properties"]["arbiter_independent_answer"] = arb.get("independent_answer")

    if suppressed is not None:
        # SARIF models this natively, which is a close fit for what the ledger
        # already records. `kind: external` is the honest one: the suppression
        # lives outside the tool, in a file a person wrote and signed.
        result["suppressions"] = [{
            "kind": "external",
            "status": "accepted",
            "justification": "%s (expires %s, by %s)"
                             % (suppressed.get("reason") or "no reason recorded",
                                suppressed.get("expires_at") or "no expiry",
                                suppressed.get("author") or "unknown"),
            "properties": {"suppression_id": suppressed.get("suppression_id")},
        }]
    return result


def coverage_statement(data):
    """The sentence a consumer must not be able to show findings without."""
    op = data["operating_point"]
    selected = op.get("selected")
    not_selected = op.get("not_selected")
    kind = op.get("score_kind") or "ordinal"
    calibration = op.get("calibration") or "uncalibrated"
    if selected is None and not_selected is None:
        return ("This run's operating point was not recorded, so what was examined "
                "and what was not cannot be stated. Treat the results as a sample "
                "of unknown size.")
    return (
        "%s candidate(s) were adjudicated. %s function(s) ranked below the "
        "operating point and were NOT examined and NOT cleared - the score is "
        "%s and %s, so it orders the queue and supports no false-positive-rate "
        "claim. An absence of results here is not evidence of absence."
        % (selected if selected is not None else "an unrecorded number of",
           not_selected if not_selected is not None else "an unrecorded number of",
           kind, calibration))


def _parse_time(value):
    """An ISO-8601 stamp or a bare date as an aware UTC datetime, or None.

    The same reading as ledger.parse_time, so the two tools agree on which
    suppressions have expired.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        moment = datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone(datetime.timezone.utc)


# What a suppression line must carry to suppress anything, as stage 3 reads it
# (enrich_candidates.load_suppressions). `expires_at` is the fifth, and is
# parsed below rather than only tested for presence.
SUPPRESSION_FIELDS = ("suppression_id", "function_key", "rule_id",
                      "content_hash_at_creation")


def active_suppression(suppressions, candidate, now=None, candidates=None):
    """The ledger suppression covering this candidate, if one still applies.

    A suppression whose function has changed since it was written does NOT
    suppress (contract §8 rule 3), and returning it here would re-hide a finding
    the pipeline deliberately brought back.

    Nor does one that has expired, and this used to be missing. Stage 3 drops an
    expired suppression and dispatches the candidate again, so a suppression
    that reaches this function unapplied is BY CONSTRUCTION one stage 3 did not
    apply - and the arbiter can uphold that finding VULNERABLE, which the export
    then marked `accepted` on the strength of an expired ledger line. Every
    unrevoked suppression expires (§8 rule 1), so that was the normal lifecycle,
    not an edge case. An expiry that is missing or unparseable fails closed: §8
    rule 1 says there is no permanent suppression, and here the only cost of
    refusing one is a result that stays visible.

    Nor does a revoked one, by EITHER half of the revoke. `ledger.py revoke`
    appends a `record_type: "revocation"` line first and stamps `revoked_at` on
    the suppression's own line second, and ledger.py and stage 3 both honour
    the first alone. This read only the stamp, so a revoke that stopped between
    its two writes - or a revocation appended by hand - left the SARIF marking
    `accepted` a result the rest of the skill calls revoked. And a record that
    is missing what a suppression needs - an id to revoke it by, a function
    key, a rule, a creation hash - suppresses nothing, as stage 3 lists it
    under `suppressions_unusable`: compared as absent, a record with no rule
    matched a candidate with none.

    Nor does a record naming MEM-WFS while another candidate on the function
    is unsuppressed, which is stage 3's rule (enrich_candidates.
    group_suppressions): the whole-function pass follows its siblings and is
    not suppressed on its own, so stage 3 lists the record under
    `suppressions_ignored` and dispatches the candidate. This matched on key,
    rule and hash alone, and marked the arbiter's upheld VULNERABLE `accepted`
    - a confirmed finding a dashboard hides, which run_status and REPORT.md
    both count. `candidates` is every candidate the run holds, and a sibling
    is judged here as it is now, as every suppression is; one that is not
    there was suppressed at stage 3 or never existed, and either way stage 3
    applied the record. The pre-repair ledger accepted `--rule MEM-WFS`, so
    committed ledgers hold these.
    """
    if not candidate:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    key = candidate.get("function_key")
    rule = candidate.get("rule_id")
    now_hash = candidate.get("content_hash")
    revoked = set(record.get("suppression_id") for record in suppressions
                  if isinstance(record, dict)
                  and record.get("record_type") == "revocation"
                  and isinstance(record.get("suppression_id"), str))
    for record in suppressions:
        if not isinstance(record, dict):
            continue
        # The revocation records live in the same file; a row without the
        # marker predates it and is a suppression, as ledger.py reads it.
        if record.get("record_type", "suppression") != "suppression":
            continue
        if any(not isinstance(record.get(field), str) or not record.get(field)
               for field in SUPPRESSION_FIELDS):
            continue                                   # unusable: stage 3 skips it
        if record.get("revoked_at") or record["suppression_id"] in revoked:
            continue
        if record.get("function_key") != key or record.get("rule_id") != rule:
            continue
        if record.get("content_hash_at_creation") != now_hash:
            continue                                   # stale: it does not suppress
        expires = _parse_time(record.get("expires_at"))
        if expires is None or expires <= now:
            continue                                   # expired: nor does this
        if rule == WFS_RULE and candidates:
            # Each sibling judged without `candidates`, so this goes one
            # level deep and no further; a sibling is never MEM-WFS anyway.
            siblings = [c for c in candidates.values()
                        if isinstance(c, dict) and c.get("function_key") == key
                        and c.get("rule_id") != WFS_RULE]
            if not all(active_suppression(suppressions, c, now)
                       for c in siblings):
                continue                               # stage 3 ignored it
        return record
    return None


def build_sarif(data, rules_dir, include_dismissed=False, now=None):
    descriptors, _ = rule_descriptors(rules_dir)
    wanted = tuple(EXPORTED_VERDICTS) + (
        tuple(DISMISSED_VERDICTS) if include_dismissed else ())
    fps = fingerprints(data)

    results, exported, skipped_unadjudicated = [], 0, 0
    for cid in sorted(data["findings"]):
        finding = data["findings"][cid]
        arb = data["arbitrations"].get(cid)
        candidate = data["candidates"].get(cid)
        verdict = (arb or {}).get("final_verdict") or finding.get("verdict")
        if verdict not in wanted:
            continue
        if arb is None:
            # Contract §9 rule 3. An unadjudicated verdict is a model's first
            # answer, and putting it in the file every dashboard reads is exactly
            # the thing that rule exists to stop.
            skipped_unadjudicated += 1
            continue
        # Scrubbed HERE, at the one point every result passes through, rather
        # than inside result_for(): a field added to that function later is
        # covered automatically instead of depending on somebody remembering.
        results.append(_scrub_obj(result_for(
            finding, arb, candidate,
            active_suppression(data["suppressions"], candidate, now,
                               data["candidates"]),
            fps.get(cid))))
        exported += 1

    op = data["operating_point"]
    statement = coverage_statement(data)
    notifications = [{
        "level": "note",
        "message": {"text": statement},
        "descriptor": {"id": "coverage"},
    }]
    for downgrade in (data["scorer_report"].get("downgrades") or []):
        notifications.append({
            "level": "warning",
            "descriptor": {"id": "scorer-downgrade"},
            "message": {"text": "%s: %s" % (downgrade.get("code", "downgrade"),
                                            downgrade.get("reason", ""))},
        })
    if skipped_unadjudicated:
        notifications.append({
            "level": "warning",
            "descriptor": {"id": "unadjudicated-withheld"},
            "message": {"text": "%d verdict(s) had no adjudication and were withheld "
                                "from this export; an unadjudicated verdict is not a "
                                "finding." % skipped_unadjudicated},
        })
    unreadable = data.get("suppressions_unreadable") or 0
    if unreadable:
        notifications.append({
            "level": "warning",
            "descriptor": {"id": "ledger-unreadable"},
            "message": {"text": "%d line(s) of ledger/suppressions.jsonl could not "
                                "be read and suppress nothing; `ledger.py check` "
                                "names them." % unreadable},
        })

    run = {
        "tool": {"driver": {
            "name": TOOL_NAME,
            "version": data["run"].get("bundle_version") or BUNDLE_VERSION,
            "informationUri": TOOL_URI,
            "rules": descriptors,
        }},
        "automationDetails": {"id": "security-review/%s"
                                    % (data["run"].get("run_id") or "unknown")},
        "invocations": [{
            "executionSuccessful": True,
            "toolExecutionNotifications": notifications,
        }],
        "results": results,
        "properties": {
            "coverage_statement": statement,
            "not_selected_is_not_a_clean_bill": True,
            "selected": op.get("selected"),
            "not_selected": op.get("not_selected"),
            "score_kind": op.get("score_kind"),
            "calibration": op.get("calibration"),
            "scorer_backend": data["scorer_report"].get("backend"),
            "exported": exported,
            "withheld_unadjudicated": skipped_unadjudicated,
            "threat_model": data["manifest"].get("threat_model"),
            "physical_attacker": data["manifest"].get("physical_attacker"),
        },
    }
    started = data["run"].get("started_at")
    if started:
        run["invocations"][0]["startTimeUtc"] = started
    git = data["run"].get("git") or {}
    if git.get("commit"):
        # In the run's property bag, NOT in versionControlProvenance. SARIF
        # 2.1.0 §3.23.3 makes repositoryUri a required, absolute URI on every
        # versionControlDetails object, and the run records the commit it
        # scanned, not where the repository is hosted. Emitting the object
        # without it wrote a file that fails the schema - which a strict
        # consumer, GitHub's upload among them, may reject whole - and inventing
        # a URL would put a guess into the field a consumer links back through.
        run["properties"]["git"] = dict(
            (k, git[k]) for k in ("commit", "branch", "dirty") if k in git)

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


# --------------------------------------------------------------------------- #
# writing it
# --------------------------------------------------------------------------- #

def run_dir_write_problem(root, path):
    """A sentence if writing `path` would break contract §1 or §9 rule 2, else
    None.

    The run directory lives inside the scanned tree, and that tree may
    legitimately commit `.security-review/ledger/` - so it can commit a link
    beside it too, and a write through one lands wherever the repository under
    review chose. Refused when `.security-review` or any existing component
    beneath it on the way to `path` is a symlink, when `path` itself is one, or
    when the run directory does not resolve to `<realpath(root)>/.security-review`.
    `root` and its ancestors are never checked: --root may legitimately be a
    link, and on macOS /var is one.

    An --out outside the run directory may be anywhere outside the scanned
    tree - `$RUNNER_TEMP` for a code-scanning upload - and nowhere inside it:
    §9 rule 2, "no tool in this skill writes to the scanned tree". This one
    did - `--out src/findings.sarif`, or the usage line's own `--out
    findings.sarif` run from the repository root, wrote into the code under
    review and exited 0, while ledger.py and run_status.py refused the same
    --out - and because the write is an os.replace, `--out src/app.py`
    replaced a source file with SARIF. The policy is run_status.status_path's.
    Only the directory part is resolved: a link AT the target is swapped out
    by the write, never written through, so where it points does not matter,
    and where it sits does.

    The sibling copy is ledger.run_dir_write_problem, for the run-directory
    walk; the tools avoid a new shared import for eight lines, so a change to
    that walk is a change to both. What lies outside the run directory differs
    on purpose: ledger.py's confined_output has already bounded its --out.
    """
    real_run = os.path.join(os.path.realpath(root), RUN_DIR)
    target = os.path.abspath(path)
    spelled = _run_dir_as_spelled(root, target)
    if spelled is None:
        real_root = os.path.realpath(root)
        resolved = os.path.join(os.path.realpath(os.path.dirname(target)),
                                os.path.basename(target))
        if resolved == real_run or resolved.startswith(real_run + os.sep):
            # Reached the run directory by another road - a link in the tree
            # pointing into it: the same walk, on the path it lands on.
            return run_dir_write_problem(root, resolved)
        if resolved == real_root or resolved.startswith(real_root + os.sep):
            return ("--out %s resolves to %s, which is inside the scanned tree "
                    "at %s and outside its %s/. Contract §9 rule 2: no tool in "
                    "this skill writes to the tree under review, and a SARIF "
                    "file dropped into the code being reviewed is exactly that. "
                    "Write it under %s, or anywhere outside the tree (--out "
                    "/tmp/findings.sarif)."
                    % (path, resolved, real_root, RUN_DIR, real_run))
        return None
    base, rel = spelled
    current = base
    for part in [""] + ([] if rel == os.curdir else rel.split(os.sep)):
        current = os.path.join(current, part) if part else current
        if os.path.islink(current):
            return ("%s is a symlink to %s. The run directory is inside the "
                    "scanned tree, so a link in it lets the repository under review "
                    "choose where this tool writes. Contract §1 puts the run "
                    "directory at the scanned root's .security-review/ and §9 rule 2 "
                    "confines every write to it. Remove the link - and look at what "
                    "it points at - then run this again."
                    % (current, os.readlink(current)))
    if os.path.lexists(base) and os.path.realpath(base) != real_run:
        return ("%s resolves to %s, not %s. Contract §1 puts the run directory at "
                "the scanned root's .security-review/ and §9 rule 2 confines every "
                "write to it." % (base, os.path.realpath(base), real_run))
    return None


def _run_dir_as_spelled(root, target):
    """(base, rel): the run directory as `target` spells it, and the rest of
    `target` below it - or None when `target` is under it by no spelling.

    Tried under abspath(root), under realpath(root), and then under any other
    spelling of the root itself - a link ABOVE .security-review, which is
    allowed. From /tmp/repo on macOS `--root .` is /private/tmp/repo, and an
    --out written /tmp/repo/.security-review/... is the same directory: read
    as "outside the run directory", it skipped the walk below. The sibling is
    ledger._run_dir_as_spelled.
    """
    real_root = os.path.realpath(root)
    bases = [os.path.join(os.path.abspath(root), RUN_DIR),
             os.path.join(real_root, RUN_DIR)]
    head = target
    while True:
        parent, name = os.path.split(head)
        if not name or parent == head:
            break
        if name == RUN_DIR and os.path.realpath(parent) == real_root:
            bases.append(head)
        head = parent
    for base in bases:
        rel = os.path.relpath(target, base)
        if rel != os.pardir and not rel.startswith(os.pardir + os.sep):
            return base, rel
    return None


def _umask():
    """The process umask. It can only be read by setting it, so it is set back
    at once; this tool runs no threads. (Same helper as run_status._umask.)"""
    mask = os.umask(0o077)
    os.umask(mask)
    return mask


def write_atomic(path, text):
    """Write `text` to `path` without following a link on the way.

    Never through a predictable `path + ".tmp"`: a link planted at that name
    redirects the write wherever it points. mkstemp creates the temporary with
    O_EXCL in the target's own directory, and os.replace swaps a link at `path`
    out rather than writing through it.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
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


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def _fixture(tmp, with_arb=True, suppression=None):
    base = os.path.join(tmp, RUN_DIR)
    for sub in ("findings", "arbitration", "candidates", "scores", "ledger"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)

    def put(path, obj):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)

    put(os.path.join(base, "run.json"),
        {"run_id": "2026-09-19T00-00-00Z", "bundle_version": "2.0.0",
         "started_at": "2026-09-19T00:00:00Z",
         "git": {"commit": "abc123", "branch": "main"}})
    put(os.path.join(base, "manifest.json"),
        {"threat_model": "remote unauthenticated", "physical_attacker": False})
    put(os.path.join(base, "scores", "operating-point.json"),
        {"selected": 400, "not_selected": 18012, "score_kind": "ordinal",
         "calibration": "uncalibrated", "not_selected_is_not_a_clean_bill": True})
    put(os.path.join(base, "scores", "scorer-report.json"),
        {"backend": "rules",
         "downgrades": [{"code": "no_evalset", "reason": "no frozen evaluation set"}]})
    put(os.path.join(base, "candidates", "memory-safety.json"),
        [{"candidate_id": "CAND-0001", "rule_id": "MEM-002", "file": "src/a.c",
          "line": 12, "function_key": "src/a.c::f::0", "content_hash": "deadbeef"}])
    put(os.path.join(base, "findings", "CAND-0001.json"),
        {"candidate_id": "CAND-0001", "rule_id": "MEM-002", "cwe": "CWE-787",
         "verdict": "VULNERABLE", "confidence": "high", "severity": "critical",
         "title": "Heap overflow", "primary_location": "src/a.c:12",
         "evidence": [{"role": "source", "file": "src/b.c", "line": 5,
                       "code": "n = recv(fd, buf, sizeof buf, 0);"},
                      {"role": "sink", "file": "src/a.c", "line": 12,
                       "code": "memcpy(d, s, n);"}],
         "guards_considered": [{"file": "src/a.c", "line": 10,
                                "code": "if (n == 0) return -1;",
                                "why_insufficient": "rejects only zero"}],
         "taint_path": "b.c:5 -> a.c:12",
         "impact": "n attacker bytes of the attacker's choosing overwrite the heap",
         "remediation": {"summary": "clamp n"}})
    if with_arb:
        put(os.path.join(base, "arbitration", "ARB-CAND-0001.json"),
            {"candidate_id": "CAND-0001", "final_verdict": "VULNERABLE",
             "final_severity": "high", "final_confidence": "high",
             "arbitration": "UPHELD_MODIFIED", "crux": "Is n bounded?",
             "independent_answer": "No.",
             "final_impact": "n is the peer's; the bytes written are whatever follows buf"})
    if suppression is not None:
        with open(os.path.join(base, "ledger", "suppressions.jsonl"),
                  "w", encoding="utf-8") as fh:
            fh.write(json.dumps(suppression) + "\n")
    return tmp


def selftest():
    failures = 0

    def ok(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    rules_dir = rules_lib.default_rules_dir()

    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp)
        doc = build_sarif(load_run(tmp), rules_dir)
        run = doc["runs"][0]
        ok("the document declares SARIF 2.1.0", doc["version"], "2.1.0")
        ok("one adjudicated finding becomes one result", len(run["results"]), 1)
        res = run["results"][0]
        ok("severity comes from the ARB record, not the validator",
           (res["properties"]["severity"], res["level"]), ("high", "error"))
        ok("GitHub's security-severity rides along",
           res["properties"]["security-severity"], "8.0")
        ok("the fingerprint is the function and the rule, not the line",
           res["partialFingerprints"]["securityReviewFindingV1"], "src/a.c::f::0::MEM-002")
        ok("the evidence chain becomes related locations",
           len(res["relatedLocations"]), 3)
        ok("and the first one keeps its role",
           res["relatedLocations"][0]["message"]["text"],
           "attacker-controlled source")
        ok("the arbiter's crux is carried, because it is the deciding question",
           res["properties"]["arbiter_crux"], "Is n bounded?")
        ok("the impact is the arbiter's final_impact, the one the report prints",
           res["properties"]["impact"],
           "n is the peer's; the bytes written are whatever follows buf")
        ok("and the validator's where the arbiter confirmed every claim",
           result_for({"verdict": "VULNERABLE", "impact": "heap overwrite"},
                      {"final_verdict": "VULNERABLE", "final_impact": None},
                      None, None, fp="x")["properties"]["impact"], "heap overwrite")
        ok("a bare-string remediation, which the precheck accepts and flags, exports as it is",
           (result_for({"verdict": "VULNERABLE", "remediation": "clamp n"},
                       {"final_verdict": "VULNERABLE"}, None, None, fp="x")
            ["properties"]["remediation"],
            result_for({"verdict": "VULNERABLE", "remediation": {"summary": "clamp n"}},
                       {"final_verdict": "VULNERABLE"}, None, None, fp="x")
            ["properties"]["remediation"],
            result_for({"verdict": "VULNERABLE", "remediation": 7},
                       {"final_verdict": "VULNERABLE"}, None, None, fp="x")
            ["properties"]["remediation"]), ("clamp n", "clamp n", None))
        ok("nothing is suppressed without a ledger record",
           "suppressions" in res, False)
        ok("every shipped rule is declared, not only the ones that fired",
           len(run["tool"]["driver"]["rules"]) > 40, True)
        by_rule = {d["id"]: d for d in run["tool"]["driver"]["rules"]}
        ok("LOG-TRI is declared, tagged as derived from a triage verdict, and says so",
           (by_rule["LOG-TRI"]["properties"]["tags"].count("derived/triage"),
            by_rule["LOG-TRI"]["properties"].get("derived"),
            by_rule["LOG-TRI"]["properties"]["cwe"]), (1, "enrich", "CWE-693"))
        ok("MEM-WFS, which stage 1 derives, and an ordinary rule carry neither",
           ["derived/triage" in by_rule[r]["properties"]["tags"]
            or "derived" in by_rule[r]["properties"] for r in ("MEM-WFS", "MEM-002")],
           [False, False])
        ok("a LOG-TRI result is fingerprinted by the function and the rule, with no ordinal",
           fingerprints({"findings": {"CAND-9": {"rule_id": "LOG-TRI"}},
                         "candidates": {"CAND-9": {"function_key": "src/shop/views.py::"
                                                   "handle_webhook::0", "line": 8,
                                                   "rule_id": "LOG-TRI"}}}),
           {"CAND-9": "src/shop/views.py::handle_webhook::0::LOG-TRI"})
        text = run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
        ok("the coverage notification says what was not examined",
           "NOT examined and NOT cleared" in text, True)
        ok("and names the 18012", "18012" in text, True)
        ok("the run properties carry the literal qualification",
           run["properties"]["not_selected_is_not_a_clean_bill"], True)
        ok("a scorer downgrade becomes a warning notification",
           any(n["descriptor"]["id"] == "scorer-downgrade"
               for n in run["invocations"][0]["toolExecutionNotifications"]), True)
        ok("the commit is recorded in the run's properties",
           run["properties"]["git"], {"commit": "abc123", "branch": "main"})
        ok("and no versionControlProvenance entry lacks the repositoryUri SARIF "
           "2.1.0 requires of it",
           all("repositoryUri" in v for v in run.get("versionControlProvenance", [])),
           True)

    # Redaction. This was a live leak, reproduced with a canary: a LOG-005
    # finding quotes the line holding the credential, and that quote travelled
    # whole into the SARIF a consumer uploads to a security dashboard.
    CANARY = "sk-live-LEAKCANARY99887766554433221100"
    AWS = "AKIAIOSFODNN7EXAMPLE"
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp)
        base = os.path.join(tmp, RUN_DIR)
        with open(os.path.join(base, "findings", "CAND-0001.json"),
                  encoding="utf-8") as fh:
            finding = json.load(fh)
        finding["title"] = "Hardcoded key %s in config" % CANARY
        finding["evidence"] = [{"role": "sink", "file": "src/a.c", "line": 12,
                                "code": 'KEY = "%s";' % CANARY}]
        finding["impact"] = "The key %s is readable by anyone" % AWS
        finding["taint_path"] = "conf.py:1 %s -> auth.py:9" % CANARY
        with open(os.path.join(base, "findings", "CAND-0001.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(finding, fh)
        doc = build_sarif(load_run(tmp), rules_dir)
        blob = json.dumps(doc)
        ok("a high-entropy literal never reaches the SARIF", CANARY in blob, False)
        ok("nor does a known-shape token (AWS id)", AWS in blob, False)
        res = doc["runs"][0]["results"][0]
        ok("the message is still readable around the redaction",
           res["message"]["text"].startswith("Hardcoded key sk-l"), True)
        ok("the snippet keeps its shape so a human can still find the line",
           res["relatedLocations"][0]["physicalLocation"]["region"]["snippet"]["text"]
           .startswith('KEY = "sk-l'), True)
        ok("and the elision is visible, never a silent truncation",
           "\u2026" in res["message"]["text"], True)
        ok("a property added later is scrubbed too, because the walk is generic",
           CANARY in json.dumps(res["properties"]), False)

    ok("scrub leaves ordinary prose alone",
       scrub("memcpy(dst, src, len) with no bound"),
       "memcpy(dst, src, len) with no bound")
    ok("and leaves a short identifier alone", scrub("short_name"), "short_name")

    # What the scrub used to let through, reproduced with canaries: the shapes
    # LOG-005 and HW-010 exist to flag, which a validator quotes verbatim. Built
    # at run time so a secret sweep over this skill does not read the source
    # as leaking.
    password = "Winter" + "2026Payroll"
    six = "hun" + "t3r"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
    short_token = "q8ZxT3vLp2" + "Nk9Rw"
    url_pw = "S3cr3t" + "Passw0rd"
    key_bytes = ("0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, "
                 "0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c")
    canaries = (
        ("a quoted password of no particular entropy (LOG-005)",
         'password = "%s"' % password, password),
        ("a six-character one, at LOG-005's own floor",
         'pwd = "%s";' % six, six),
        ("an identifier-shaped secret access key",
         'aws_secret_access_key = "%s"' % aws_secret, aws_secret),
        ("a random token shorter than twenty characters",
         '{"token": "%s"}' % short_token, short_token),
        ("a URL password with no user before the colon",
         'REDIS_URL = "redis://:%s@cache.internal:6379/0"' % url_pw, url_pw),
        ("a key byte array (HW-010)",
         "static const uint8_t aes_key[16] = {%s};" % key_bytes, "0xab, 0xf7"),
        ("and that array's continuation line, quoted on its own",
         "    %s," % key_bytes, "0xab, 0xf7"),
    )
    for label, line, secret in canaries:
        ok("scrub redacts %s" % label, secret in scrub(line), False)
    ok("the assignment keeps its name, so a human can still find the line",
       scrub('password = "%s"' % password).startswith('password = "Wint'), True)
    ok("a URL keeps its host, which says whether this is production",
       "@cache.internal:6379/0" in scrub(canaries[4][1]), True)
    ok("a key array keeps its declaration",
       scrub(canaries[5][1]).startswith("static const uint8_t aes_key[16] = {"), True)
    for line in ('password = os.environ["DB_PASSWORD"]',
                 'password = "${DB_PASSWORD}"',
                 'password = "<redacted>"',
                 'password = "Wint…roll"',
                 'if (token_len > sizeof(buf)) return -1;',
                 "uint8_t key_len = sizeof(buf);"):
        ok("and leaves %r alone" % line, scrub(line), line)

    # One detector with the REPORT.md gate (sweep_secrets.export_spans). These
    # are the lines the two used to judge differently: a truncation this scrub
    # read as a redaction and let out whole, and a fix-commit URL - `/` joins
    # its path into one entropy run - that it mangled while the gate refused
    # the report quoting it.
    truncated = 'password = "Pr0dPassw0rd…"'
    ok("an ellipsis that only truncates a password does not redact it",
       "Pr0dPassw0rd" in scrub(truncated), False)
    commit_url = ("fixed in https://github.com/acme/widget/commit/"
                  "a83fcd7b2e9c4f1a0d5e6b7c8d9e0f1a2b3c4d5e")
    ok("and a fix-commit URL comes out as it went in",
       scrub(commit_url), commit_url)
    # The values the gate leaves because it refuses a whole report on a hit -
    # a passphrase, a dictionary word - are what LOG-005 flags, and they were
    # redacted here before the two shared a detector. They still are.
    worded = ('password = "correct horse battery"', 'password = "change' + 'me"')
    for line in worded:
        ok("scrub still redacts %r, which the gate leaves" % line,
           line.split('"')[1] in scrub(line), False)
    hex_user = "0f3a9c7e1b2d4f6a" + "8c0e2b4d6f8a1c3e5b7d9f0a"
    ok("and a digest-shaped token as a clone URL's user is not taken for a commit",
       hex_user in scrub("https://%s@github.com/acme/p.git" % hex_user), False)
    import verify_findings                             # noqa: PLC0415
    judged = [line for _label, line, _secret in canaries] + [
        truncated, commit_url, "    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,",
        'TOKEN_URL = "http://auth.internal/oauth/token"',
        'PASSWORD_HASH_ALGO = "pbkdf2_sha1"', 'password = "${DB_PASSWORD}"',
        'password = "Wint…roll"', "uint8_t key[32] = {0};",
        "https://%s@github.com/acme/p.git" % hex_user] + list(worded)
    ok("the scrub changes every line the report gate refuses, and the gate "
       "refuses every other line the scrub changes",
       [line for line in judged
        if (scrub(line) != line) != bool(list(verify_findings.secretish_spans(line)))],
       list(worded))

    # An unadjudicated verdict is withheld - contract §9 rule 3.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, with_arb=False)
        run = build_sarif(load_run(tmp), rules_dir)["runs"][0]
        ok("an unadjudicated verdict is not exported", len(run["results"]), 0)
        ok("and the file says it was withheld rather than saying nothing",
           run["properties"]["withheld_unadjudicated"], 1)
        ok("with a notification a consumer can surface",
           any(n["descriptor"]["id"] == "unadjudicated-withheld"
               for n in run["invocations"][0]["toolExecutionNotifications"]), True)

    # A live suppression rides on the result; a stale one does not suppress.
    # The expiry is computed, not written down: a fixed date turns this test
    # red on the day it passes, now that an expired suppression is enforced.
    moment = datetime.datetime.now(datetime.timezone.utc)
    future = (moment + datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    live = {"suppression_id": "SUP-0001", "function_key": "src/a.c::f::0",
            "rule_id": "MEM-002", "content_hash_at_creation": "deadbeef",
            "reason": "tracked in ISSUE-441", "expires_at": future,
            "author": "me", "revoked_at": None}
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, suppression=live)
        res = build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"][0]
        ok("a live suppression becomes a SARIF suppression",
           res["suppressions"][0]["status"], "accepted")
        ok("and carries the reason, the expiry and the author",
           all(s in res["suppressions"][0]["justification"]
               for s in ("ISSUE-441", future, "me")), True)
        later = moment + datetime.timedelta(days=31)
        res = build_sarif(load_run(tmp), rules_dir, now=later)["runs"][0]["results"][0]
        ok("the same ledger line stops suppressing the day it expires",
           "suppressions" in res, False)

    # Stage 3 drops an expired suppression and dispatches the candidate again,
    # so the arbiter can uphold it - and the export used to mark that upheld
    # finding `accepted` on the strength of the expired line.
    for label, record in (
            ("an expired suppression does not suppress",
             dict(live, expires_at="2025-01-01T00:00:00Z")),
            ("nor does one with no expiry - §8 rule 1, there is no permanent one",
             dict(live, expires_at=None)),
            ("nor one whose expiry is not a date",
             dict(live, expires_at="never")),
            ("nor a revocation record that happens to carry the same key",
             dict(live, record_type="revocation"))):
        with tempfile.TemporaryDirectory() as tmp:
            _fixture(tmp, suppression=record)
            res = build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"][0]
            ok(label, "suppressions" in res, False)

    # suppressions.jsonl is committed and hand-edited. A line that is not a
    # record object, or not UTF-8, used to take the whole export down with a
    # traceback; ledger.py reports those lines instead, and so does this.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp)
        with open(os.path.join(tmp, RUN_DIR, "ledger", "suppressions.jsonl"),
                  "wb") as fh:
            fh.write(b'["SUP-0001"]\n')
            fh.write(b'{"suppression_id": "SUP-0002", "reason": "caf\xe9"}\n')
            fh.write(b'"just a string"\n')
            fh.write(json.dumps(live).encode("utf-8") + b"\n")
        try:
            run = build_sarif(load_run(tmp), rules_dir)["runs"][0]
            ok("malformed ledger lines do not crash the export", True, True)
            ok("the readable suppression still applies",
               run["results"][0]["suppressions"][0]["properties"]["suppression_id"],
               "SUP-0001")
            ok("and the unreadable lines are counted in a warning, not dropped",
               [n["message"]["text"].split(" ")[0]
                for n in run["invocations"][0]["toolExecutionNotifications"]
                if n["descriptor"]["id"] == "ledger-unreadable"], ["3"])
        except Exception as exc:                       # noqa: BLE001
            ok("malformed ledger lines do not crash the export", repr(exc), None)

    stale = dict(live, content_hash_at_creation="0000000000000000")
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, suppression=stale)
        res = build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"][0]
        ok("a suppression written against different content does NOT suppress",
           "suppressions" in res, False)

    revoked = dict(live, revoked_at="2026-09-18T00:00:00Z")
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, suppression=revoked)
        res = build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"][0]
        ok("a revoked suppression does not suppress either",
           "suppressions" in res, False)

    # `ledger.py revoke` appends the revocation line first and stamps the
    # suppression's own line second. ledger.py and stage 3 honour the first
    # alone; this read only the second, and kept marking the result accepted.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, suppression=live)
        with open(os.path.join(tmp, RUN_DIR, "ledger", "suppressions.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({"schema_version": 1, "record_type": "revocation",
                                 "suppression_id": "SUP-0001",
                                 "revoked_at": "2026-09-18T00:00:00Z",
                                 "author": "me", "reason": "the clamp came out"})
                     + "\n")
        res = build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"][0]
        ok("an appended revocation line revokes, though the suppression's own "
           "line still says revoked_at: null", "suppressions" in res, False)
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, suppression=dict(live, suppression_id=None))
        res = build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"][0]
        ok("a record with no suppression_id - nothing can revoke it - suppresses "
           "nothing, as stage 3 lists it unusable", "suppressions" in res, False)

    def rewrite(path, **changes):
        with open(path, encoding="utf-8") as fh:
            obj = json.load(fh)
        obj.update(changes)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return obj

    # A ledger record naming MEM-WFS while a sibling on the function still
    # dispatches: stage 3 lists it under `suppressions_ignored` and dispatches
    # the whole-function pass, and the arbiter can uphold what it finds. The
    # export matched on key, rule and hash alone and marked that confirmed
    # finding `accepted`. The pre-repair ledger.py wrote such records.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp, suppression=dict(live, rule_id=WFS_RULE))
        base = os.path.join(tmp, RUN_DIR)
        cand_path = os.path.join(base, "candidates", "memory-safety.json")
        with open(cand_path, encoding="utf-8") as fh:
            sibling = json.load(fh)[0]
        whole = dict(sibling, candidate_id="CAND-0002", rule_id=WFS_RULE, line=9)

        def candidates(*rows):
            with open(cand_path, "w", encoding="utf-8") as fh:
                json.dump(list(rows), fh)

        with open(os.path.join(base, "findings", "CAND-0001.json"),
                  encoding="utf-8") as fh:
            upheld = dict(json.load(fh), candidate_id="CAND-0002",
                          rule_id=WFS_RULE)
        with open(os.path.join(base, "findings", "CAND-0002.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(upheld, fh)
        with open(os.path.join(base, "arbitration", "ARB-CAND-0002.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"candidate_id": "CAND-0002", "final_verdict": "VULNERABLE",
                       "final_severity": "high", "arbitration": "UPHELD"}, fh)

        def wfs_suppressions():
            run = build_sarif(load_run(tmp), rules_dir)["runs"][0]
            return [[(s["status"], s["properties"]["suppression_id"])
                     for s in r.get("suppressions", [])]
                    for r in run["results"] if r["ruleId"] == WFS_RULE]

        candidates(sibling, whole)
        ok("a MEM-WFS record does not suppress while a sibling on the function "
           "still dispatches - stage 3 ignored it, and the finding is upheld",
           wfs_suppressions(), [[]])
        candidates(whole)
        ok("it does where no other candidate is left on the function",
           wfs_suppressions(), [[("accepted", "SUP-0001")]])
        candidates(sibling, whole)
        ledger_path = os.path.join(base, "ledger", "suppressions.jsonl")
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(live, suppression_id="SUP-0002",
                                     expires_at="2025-01-01T00:00:00Z")) + "\n")
        ok("nor while the sibling's own suppression has expired",
           wfs_suppressions(), [[]])
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(dict(live, suppression_id="SUP-0003")) + "\n")
        ok("and it does once every sibling is suppressed too",
           wfs_suppressions(), [[("accepted", "SUP-0001")]])

    # A cleared finding and an unresolved one are notes, whatever the severity:
    # the level used to come from severity alone, so a dismissed high went onto
    # a dashboard as an error-level alert with nothing to say it was cleared.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp)
        arb_path = os.path.join(tmp, RUN_DIR, "arbitration", "ARB-CAND-0001.json")
        finding_path = os.path.join(tmp, RUN_DIR, "findings", "CAND-0001.json")
        rewrite(arb_path, final_verdict="NEEDS_HUMAN_REVIEW")
        res = build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"][0]
        ok("a NEEDS_HUMAN_REVIEW high is a note, not an error",
           (res["level"], res["message"]["text"].startswith("NEEDS HUMAN REVIEW")),
           ("note", True))
        rewrite(arb_path, final_verdict="NOT_VULNERABLE")
        rewrite(finding_path, verdict="NOT_VULNERABLE", false_positive_reasons=[
            {"code": "FP-GUARDED", "file": "src/a.c", "line": 10,
             "why": "n is clamped"}])
        ok("a dismissal is not exported by default",
           len(build_sarif(load_run(tmp), rules_dir)["runs"][0]["results"]), 0)
        res = build_sarif(load_run(tmp), rules_dir,
                          include_dismissed=True)["runs"][0]["results"][0]
        ok("with --include-dismissed a cleared high is a note, not an error alert",
           res["level"], "note")
        ok("whose message says it was dismissed, and under which code",
           res["message"]["text"],
           "NOT VULNERABLE (dismissed, FP-GUARDED) - Heap overflow")
        ok("and which carries no security-severity to be ranked by",
           "security-severity" in res["properties"], False)
        rewrite(finding_path, false_positive_reasons=["fp-const: src/a.c:3 a literal"])
        res = build_sarif(load_run(tmp), rules_dir,
                          include_dismissed=True)["runs"][0]["results"][0]
        ok("the string form of a reason gives its code too",
           res["message"]["text"].startswith("NOT VULNERABLE (dismissed, FP-CONST)"),
           True)
        rewrite(finding_path, false_positive_reasons=[])
        res = build_sarif(load_run(tmp), rules_dir,
                          include_dismissed=True)["runs"][0]["results"][0]
        ok("and no reason at all says so rather than printing nothing",
           "(dismissed, reason not recorded)" in res["message"]["text"], True)

    # Two sinks of one rule in one function are two results, and they used to
    # share one fingerprint - which a SARIF consumer reads as ONE result.
    with tempfile.TemporaryDirectory() as tmp:
        _fixture(tmp)
        base = os.path.join(tmp, RUN_DIR)
        cand_path = os.path.join(base, "candidates", "memory-safety.json")
        with open(cand_path, encoding="utf-8") as fh:
            cands = json.load(fh)
        cands.append(dict(cands[0], candidate_id="CAND-0002", line=40))
        with open(cand_path, "w", encoding="utf-8") as fh:
            json.dump(cands, fh)
        with open(os.path.join(base, "findings", "CAND-0001.json"),
                  encoding="utf-8") as fh:
            second = json.load(fh)
        second.update(candidate_id="CAND-0002", primary_location="src/a.c:40")
        with open(os.path.join(base, "findings", "CAND-0002.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(second, fh)
        with open(os.path.join(base, "arbitration", "ARB-CAND-0001.json"),
                  encoding="utf-8") as fh:
            arb = json.load(fh)
        with open(os.path.join(base, "arbitration", "ARB-CAND-0002.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(dict(arb, candidate_id="CAND-0002"), fh)

        def fps_of(**kwargs):
            run = build_sarif(load_run(tmp), rules_dir, **kwargs)["runs"][0]
            return dict((r["properties"]["candidate_id"],
                         r["partialFingerprints"]["securityReviewFindingV1"])
                        for r in run["results"])

        want = {"CAND-0001": "src/a.c::f::0::MEM-002",
                "CAND-0002": "src/a.c::f::0::MEM-002::2"}
        ok("two sinks of one rule in one function are two fingerprints, and the "
           "first keeps the single-sink identity it always had", fps_of(), want)
        rewrite(os.path.join(base, "findings", "CAND-0001.json"),
                primary_location="src/a.c:17")
        rewrite(os.path.join(base, "findings", "CAND-0002.json"),
                primary_location="src/a.c:45")
        ok("both survive the lines moving", fps_of(), want)
        # The order is stage 1's sink line, not the location the validator
        # wrote: a model does not write it the same way twice, and ordered on
        # it the two identities swapped over code nobody changed.
        rewrite(os.path.join(base, "findings", "CAND-0001.json"),
                primary_location="src/net/server.c:88")
        ok("a finding located at its source in another file keeps its ordinal",
           fps_of(), want)
        rewrite(os.path.join(base, "findings", "CAND-0001.json"),
                primary_location="src/a.c:17")
        # A dismissal is told to cite the guard, the declaration or the caller
        # rather than the sink (validator-contract §7), so turning
        # NOT_VULNERABLE usually moves the location as well.
        rewrite(os.path.join(base, "arbitration", "ARB-CAND-0001.json"),
                final_verdict="NOT_VULNERABLE")
        rewrite(os.path.join(base, "findings", "CAND-0001.json"),
                verdict="NOT_VULNERABLE", primary_location="include/limits.h:99")
        ok("a sibling that stops being exported does not renumber the other",
           fps_of(), {"CAND-0002": "src/a.c::f::0::MEM-002::2"})
        rewrite(os.path.join(base, "findings", "CAND-0001.json"),
                primary_location="src/a.c:17")
        os.remove(cand_path)
        ok("with no candidate record the key is the finding's file, never ''",
           sorted(fps_of(include_dismissed=True).values()),
           ["src/a.c::MEM-002", "src/a.c::MEM-002::2"])

    # Writes. The run directory is inside the scanned tree, and that tree may
    # commit .security-review/ - so it can commit a link in it (contract §1,
    # §9 rule 2).
    def quiet_main(argv):
        import contextlib
        import io
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, err.getvalue()

    def slurp(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        os.makedirs(root)
        _fixture(root)
        victim = os.path.join(tmp, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("untouched\n")
        sarif = os.path.join(root, RUN_DIR, "findings.sarif")
        try:
            os.symlink(victim, sarif + ".tmp")
            linked = True
        except (OSError, NotImplementedError):
            linked = False
        if linked:
            code, err = quiet_main(["--root", root])
            ok("a planted findings.sarif.tmp link is not written through",
               (code, slurp(victim)), (0, "untouched\n"))
            ok("and the SARIF lands where it was asked to, as a plain 0644 file",
               (os.path.isfile(sarif), os.path.islink(sarif),
                oct(os.stat(sarif).st_mode & 0o777)), (True, False, "0o644"))
            os.remove(sarif)
            os.symlink(victim, sarif)
            code, err = quiet_main(["--root", root])
            ok("an output that is itself a symlink is refused, naming the link",
               (code, "is a symlink to %s" % victim in err, "§9 rule 2" in err),
               (1, True, True))
            ok("and the file it points at is untouched", slurp(victim), "untouched\n")

    with tempfile.TemporaryDirectory() as tmp:
        elsewhere = os.path.join(tmp, "elsewhere")
        os.makedirs(elsewhere)
        _fixture(elsewhere)
        root = os.path.join(tmp, "repo")
        os.makedirs(root)
        try:
            os.symlink(os.path.join(elsewhere, RUN_DIR), os.path.join(root, RUN_DIR))
            linked = True
        except (OSError, NotImplementedError):
            linked = False
        if linked:
            code, err = quiet_main(["--root", root])
            ok("a .security-review that is itself a symlink is refused",
               (code, "is a symlink to" in err), (1, True))
            ok("and nothing is written through it",
               os.path.exists(os.path.join(elsewhere, RUN_DIR, "findings.sarif")),
               False)
            alias = os.path.join(tmp, "alias")
            os.symlink(elsewhere, alias)
            code, err = quiet_main(["--root", alias])
            ok("a --root that is a symlink is fine: only the run directory is "
               "checked, never the root or above it", code, 0)
            # --root . resolves (/private/tmp/repo on macOS) while an --out can
            # be written through the other name (/tmp/repo): the same run
            # directory, so the same walk below it.
            spelled = os.path.join(alias, RUN_DIR, "findings.sarif")
            code, err = quiet_main(["--root", elsewhere, "--out", spelled])
            ok("an --out spelled through another name for the root is written",
               (code, os.path.isfile(os.path.join(elsewhere, RUN_DIR,
                                                  "findings.sarif"))), (0, True))
            outside = os.path.join(tmp, "outside")
            os.makedirs(outside)
            os.symlink(outside, os.path.join(elsewhere, RUN_DIR, "out"))
            code, err = quiet_main(["--root", elsewhere, "--out",
                                    os.path.join(alias, RUN_DIR, "out", "f.sarif")])
            ok("and a link below the run directory is refused whichever name the "
               "--out reaches it by", (code, os.listdir(outside)), (1, []))

    # §9 rule 2: no tool in this skill writes to the scanned tree. `--out
    # src/findings.sarif` did, and exited 0, while ledger.py and run_status.py
    # refused the same --out; and the write is an os.replace, so `--out
    # src/app.c` replaced a source file with SARIF. Absolute paths throughout:
    # the selftest's working directory is anybody's.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        src = os.path.join(root, "src")
        os.makedirs(src)
        _fixture(root)
        app = os.path.join(src, "app.c")
        with open(app, "w", encoding="utf-8") as fh:
            fh.write("int main(void) { return 0; }\n")
        code, err = quiet_main(["--root", root, "--out",
                                os.path.join(src, "f.sarif")])
        ok("--out inside the scanned tree is refused, citing §9 rule 2",
           (code, "§9 rule 2" in err, sorted(os.listdir(src))),
           (1, True, ["app.c"]))
        ok("...and so is the root itself",
           quiet_main(["--root", root, "--out", root])[0], 1)
        code, err = quiet_main(["--root", root, "--out", app])
        ok("...so a source file is never replaced with SARIF",
           (code, slurp(app)), (1, "int main(void) { return 0; }\n"))
        outside = os.path.join(tmp, "out", "f.sarif")
        code, err = quiet_main(["--root", root, "--out", outside])
        ok("--out outside the tree is written (a code-scanning upload's "
           "$RUNNER_TEMP)", (code, os.path.isfile(outside)), (0, True))
        deeper = os.path.join(root, RUN_DIR, "sub", "f.sarif")
        code, err = quiet_main(["--root", root, "--out", deeper])
        ok("--out under .security-review/ is written",
           (code, os.path.isfile(deeper)), (0, True))
        try:
            os.symlink(os.path.join(root, RUN_DIR), os.path.join(src, "rl"))
            linked = True
        except (OSError, NotImplementedError):
            linked = False
        if linked:
            code, err = quiet_main(["--root", root, "--out",
                                    os.path.join(src, "rl", "g.sarif")])
            ok("an --out that a link in the tree takes into the run directory "
               "is written there", (code, os.path.isfile(
                   os.path.join(root, RUN_DIR, "g.sarif"))), (0, True))
            ext = os.path.join(tmp, "ext")
            os.makedirs(ext)
            os.symlink(ext, os.path.join(src, "ln"))
            code, err = quiet_main(["--root", root, "--out",
                                    os.path.join(src, "ln", "f.sarif")])
            ok("and one a link takes out of the tree is written where it lands",
               (code, os.listdir(ext)), (0, ["f.sarif"]))
            alias = os.path.join(tmp, "alias")
            os.symlink(root, alias)
            code, err = quiet_main(["--root", root, "--out",
                                    os.path.join(alias, "src", "x.sarif")])
            ok("an --out into the tree by another name for the root is refused",
               (code, "x.sarif" in os.listdir(src)), (1, False))
            victim = os.path.join(tmp, "victim.txt")
            with open(victim, "w", encoding="utf-8") as fh:
                fh.write("untouched\n")
            evil = os.path.join(src, "evil")
            os.symlink(victim, evil)
            code, err = quiet_main(["--root", root, "--out", evil])
            ok("a link in the tree pointing out of it is not a way out: the "
               "write would replace the link inside the tree",
               (code, slurp(victim), os.path.islink(evil)),
               (1, "untouched\n", True))

    # A run with no findings directory refuses rather than writing an empty file.
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, RUN_DIR), exist_ok=True)
        try:
            load_run(tmp)
            ok("a run with no verdicts refuses", False, True)
        except Incomplete as exc:
            ok("a run with no verdicts refuses",
               "empty file claiming a clean repository" in str(exc), True)

    print()
    print("selftest: %d failure(s)" % failures)
    return 1 if failures else 0


# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Export the adjudicated findings of a run as SARIF 2.1.0.")
    p.add_argument("--root", default=".",
                   help="scanned repository root, holding .security-review/")
    p.add_argument("--out", default=None,
                   help="output path (default: .security-review/findings.sarif); "
                        "outside the scanned tree or under its .security-review/, "
                        "nowhere else in it")
    p.add_argument("--rules-dir", default=rules_lib.default_rules_dir(),
                   help="rule files, for the tool's rule declarations")
    p.add_argument("--include-dismissed", action="store_true",
                   help="also export NOT_VULNERABLE verdicts, as notes")
    p.add_argument("--selftest", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    # Before anything under the run directory is read: the scanned repository
    # never answers for the run (rules_lib.run_dir_gate).
    shipped, _gate = rules_lib.enforce_run_dir_gate(os.path.abspath(args.root))
    if shipped:
        return shipped
    out = args.out or os.path.join(args.root, RUN_DIR, "findings.sarif")
    # Checked before anything is read, so a refused path refuses the command
    # rather than the last step of it.
    unsafe = run_dir_write_problem(args.root, out)
    if unsafe:
        print("REFUSED: %s" % unsafe, file=sys.stderr)
        return 1
    try:
        data = load_run(args.root)
    except Incomplete as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return 1
    doc = build_sarif(data, args.rules_dir, args.include_dismissed)
    run = doc["runs"][0]
    if not run["results"] and not run["properties"]["withheld_unadjudicated"]:
        print("nothing adjudicated to export", file=sys.stderr)
        return 2
    write_atomic(out, json.dumps(doc, indent=1) + "\n")
    print("%d result(s) -> %s" % (len(run["results"]), out))
    print("  %s" % run["properties"]["coverage_statement"])
    if run["properties"]["withheld_unadjudicated"]:
        print("  %d unadjudicated verdict(s) withheld"
              % run["properties"]["withheld_unadjudicated"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
