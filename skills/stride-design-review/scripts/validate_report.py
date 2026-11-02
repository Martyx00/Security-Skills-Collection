#!/usr/bin/env python3
"""Validate JSON artifacts and mechanical Markdown report invariants."""
from __future__ import annotations

import argparse, json, re, sys
from collections import Counter
from pathlib import Path

# `python3 -I` drops the script's own folder from sys.path; the sibling module is imported by name.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import replyread  # noqa: E402
from jsonschema_subset import validate  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]  # the skill root: read-only, holds VERSION and assets/
INSTALLED_VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
# Every reported issue carries the same four-part record, in this order.
RECORD_LABELS = ["From specification:", "Issue:", "Impact:", "Recommendation:"]
# Specification facts are tagged by the direction in which they bear on the issue.
RECORD_TAGS = ("Supports:", "Contradicts:")
RECORD_HEADING = re.compile(r"^###\s+(?P<id>[A-Za-z0-9-]+)\s+—\s+(?P<title>\S.*?)\s*$")
# The one bullet that may cite no evidence: an explicit, searched-for absence.
RECORD_NULL = re.compile(r"^Contradicts:\s+None identified\s*[—-]\s*\S.+$")
# Every applicable coverage-matrix cell names where the threat went; nothing drops silently.
COVERAGE_CELL = re.compile(r"^(?:Threat — (?:S[123]|F)-[0-9]{3,}|Covered — C-[0-9]{3,}|N/A — \S.*|MI — MI-S[123]-[0-9]{3,})$")
STRIDE_COLUMNS = ["spoofing", "tampering", "repudiation", "information disclosure", "denial of service", "elevation of privilege"]
EVIDENCE_COLUMNS = ["id", "document title", "relative path", "locator", "quote", "proposition"]
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Undetermined": 4}
# The §0 outcome is rule-driven from the final tables; the validator recomputes it.
OUTCOMES = ("Insufficient documentation", "Approve with conditions", "Approve")
OUTCOME_LINE = re.compile(r"^\s*\**Outcome\**\s*:\s*\**\s*(?P<outcome>Insufficient documentation|Approve with conditions|Approve)\b")
CONTRACTS = {
    "stage1": ("# Stage 1 — Comprehensive STRIDE Security Design Review", [
        "## 1. Review Inputs and Corpus Integrity", "## 2. Documented Model, Adversaries, and Assumptions",
        "## 3. STRIDE Coverage", "## 4. Finding Register", "## 5. Control and Claim Validation",
        "## 6. Missing Information Register", "## 7. Requirement Traceability and Limitations"]),
    "stage2": ("# Stage 2 — Adversarial STRIDE Completeness Review", [
        "## 1. Review Inputs and Corpus Integrity", "## 2. Independent Reconstruction and Crosswalk",
        "## 3. Gap Finding Register", "## 4. Missing Information Register and Validation",
        "## 5. Requirement Traceability, Re-scoping, and Limitations"]),
    "final": ("# Final — Verified STRIDE Security Design Review", [
        "## 0. Decision Summary", "## 1. Inputs, Environment, and Corpus Integrity",
        "## 2. Verified Model, Adversaries, and Assumptions", "## 3. Verified STRIDE Coverage",
        "## 4. Final Finding Register", "## 5. Control, Claim, and Requirement Traceability",
        "## 6. Verification and Calibration", "## 7. Missing Information Register",
        "## 8. Verification Defect Register and Limitations"]),
}
# The tables each report kind must carry: a table whose nearest heading line contains the phrase (any case) and whose header row
# has at least these columns (any order). `references/report-shapes.md` shows them and a test keeps the two together.
REQUIRED_TABLES = {
    "stage1": [
        ("evidence register", {"id", "relative path", "quote"}), ("model element register", {"id", "type", "name"}), ("threat actor register", {"id", "actor", "position"}),
        ("assumption register", {"id", "assumption"}), ("claim register", {"id", "claim", "status"}),
        ("stride coverage", {"element", "spoofing", "tampering", "repudiation", "information disclosure", "denial of service", "elevation of privilege"}),
        ("finding register", {"id", "severity", "rubric", "confidence", "evidence ids"}), ("control and claim validation", {"control", "mechanism", "status"}), ("missing information register", {"id", "status"}),
        ("requirement traceability", {"requirement", "status", "references"})],
    "stage2": [
        ("evidence register", {"id", "relative path", "quote"}), ("model element register", {"id", "type", "name"}), ("model crosswalk", {"stage 2 id", "stage 1 id", "status"}),
        ("gap finding register", {"id", "materiality", "severity", "rubric", "confidence", "evidence ids"}),
        ("missing information register", {"id", "status"}), ("requirement traceability", {"requirement", "status", "references"})],
    "final": [
        ("decision summary", {"metric", "count"}), ("evidence register", {"id", "relative path", "quote"}),
        ("threat actor register", {"id", "actor", "position"}), ("assumption register", {"id", "assumption", "status"}),
        ("verified stride coverage", {"interaction", "spoofing", "tampering", "repudiation", "information disclosure", "denial of service", "elevation of privilege"}),
        ("final finding register", {"id", "severity", "rubric", "confidence", "evidence ids"}),
        ("control, claim, and requirement traceability", {"control", "mechanism", "status"}),
        ("requirement traceability", {"requirement", "status", "references"}),
        ("per-stage correction", {"stage", "confirmed", "corrected", "false positive", "unverifiable", "blocked"}),
        ("missing information register", {"id", "verdict"}), ("verification defect register", {"id", "type"})],
}
ID_PATTERNS = {
    "A": re.compile(r"^A-[0-9]{3,}$"), "EE": re.compile(r"^EE-[0-9]{3,}$"),
    "P": re.compile(r"^P-[0-9]{3,}$"), "DS": re.compile(r"^DS-[0-9]{3,}$"),
    "DF": re.compile(r"^DF-[0-9]{3,}$"), "TB": re.compile(r"^TB-[0-9]{3,}$"),
    "INT": re.compile(r"^INT-[0-9]{3,}$"), "EP": re.compile(r"^EP-[0-9]{3,}$"),
    "EV": re.compile(r"^EV-(?:S1|S2|S3|F)-[0-9]{3,}$"),
    "C": re.compile(r"^C-[0-9]{3,}$"), "REQ": re.compile(r"^REQ-[0-9]{3,}$"),
    "F": re.compile(r"^F-[0-9]{3,}$"), "S1": re.compile(r"^S1-[0-9]{3,}$"),
    "S2": re.compile(r"^S2-[0-9]{3,}$"), "S3": re.compile(r"^S3-[0-9]{3,}$"),
    "MI": re.compile(r"^MI-S[123]-[0-9]{3,}$"),
    "TA": re.compile(r"^TA-[0-9]{3,}$"), "AS": re.compile(r"^AS-[0-9]{3,}$"),
    "VD": re.compile(r"^VD-[0-9]{3,}$"), "SC": re.compile(r"^SC-S[123]-[0-9]{3,}$"),
}
# What a register ID looks like, in words, for the namespaces whose pattern a model gets wrong (a plain EV-001 or SC-001).
ID_FORMAT_HINT = {
    "EV": "EV-S1-001, EV-S2-001 or EV-S3-001 in a stage report, EV-F-001 in the final report",
    "SC": "SC-S1-001, SC-S2-001 or SC-S3-001 (the origin is part of the ID)",
    "MI": "MI-S1-001, MI-S2-001 or MI-S3-001 (the origin is part of the ID)",
}
REGISTER_NAMESPACE = {
    "evidence register": "EV", "final finding register": "F", "gap finding register": "S2", "finding register": "S1",
    "missing information register": "MI", "threat actor register": "TA",
    "assumption register": "AS", "verification defect register": "VD", "claim register": "SC",
}

# The schemas of the two replies a delegated role writes to its reply file; the file is read the way `sweep-record` and
# `verify-record` read it, so the role's own check and the ingest agree.
REPLY_SCHEMAS = ("sweep-result-1.0.json", "verifier-result-1.0.json")

def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))

def data_errors(data: object, schema_path: Path) -> list[str]:
    errors=validate(data, load_json(schema_path))
    if schema_path.name=="verifier-result-1.0.json": errors.extend(verifier_result_errors(data))
    return errors

def schema_errors(path: Path, schema_path: Path) -> list[str]:
    return data_errors(load_json(path), schema_path)

def parse_tables(lines: list[str]) -> tuple[list[tuple[str, list[str], list[list[str]]]], list[str]]:
    tables, errors, heading, index = [], [], "", 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("#"):
            heading = line.strip()
        if line.strip().startswith("|"):
            block = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                block.append(lines[index].strip())
                index += 1
            rows = [[cell.strip() for cell in row.strip("|").split("|")] for row in block]
            widths = {len(row) for row in rows}
            if len(widths) != 1:
                errors.append(f"malformed table under {heading}: inconsistent column counts {sorted(widths)}")
            if len(rows) < 2 or not all(re.fullmatch(r":?-{3,}:?", cell) for cell in rows[1]):
                errors.append(f"malformed table under {heading}: missing separator row")
            else:
                tables.append((heading, rows[0], rows[2:]))
            continue
        index += 1
    return tables, errors

BASE_REGISTER_SPECS = {
    "stage1": {
        "heading": "## 4. Finding Register",
        "sourceReport": "stage-1-review.md",
        "origin": "stage1",
        "headers": ["id", "claim", "affected scope", "threat actors", "stride", "severity", "rubric", "confidence", "evidence ids"],
        "idPattern": ID_PATTERNS["S1"],
        "evidencePattern": re.compile(r"^EV-S1-[0-9]{3,}$"),
    },
    "stage2": {
        "heading": "## 3. Gap Finding Register",
        "sourceReport": "stage-2-gap-review.md",
        "origin": "stage2",
        "headers": ["id", "category", "claim", "affected scope", "threat actors", "stride", "materiality", "severity", "rubric", "confidence", "evidence ids"],
        "idPattern": ID_PATTERNS["S2"],
        "evidencePattern": re.compile(r"^EV-S2-[0-9]{3,}$"),
    },
}
STRIDE_VALUES = {"Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"}
SEVERITY_RUBRIC = {"Critical":"SR-Critical","High":"SR-High","Medium":"SR-Medium","Low":"SR-Low","Undetermined":"SR-Undetermined"}

def verifier_result_errors(data: object) -> list[str]:
    """Severity semantics the JSON Schema cannot express: rubric pairing and the conditional ceiling."""
    if not isinstance(data, dict) or not isinstance(data.get("severity"), dict):
        return []
    errors: list[str] = []
    severity=data["severity"]; base,rubric=severity.get("base"),severity.get("rubricCell")
    if base in SEVERITY_RUBRIC and rubric!=SEVERITY_RUBRIC[base]:
        errors.append(f"$.severity: base {base!r} requires rubricCell {SEVERITY_RUBRIC[base]!r}, got {rubric!r}")
    verdict=data.get("verdict")
    if verdict=="Blocked":
        return errors                                   # a blocked result carries no severity judgment
    ceiling,condition,gated=severity.get("conditionalCeiling"),severity.get("condition"),severity.get("gatedBy") or []
    if ceiling is not None:
        # The rubric: keep the supported base, then state a separate ceiling, one-clause condition, and gating MI.
        if not condition: errors.append("$.severity: a conditionalCeiling requires its one-clause condition")
        if not gated: errors.append("$.severity: a conditionalCeiling requires the gating MI in gatedBy")
        if ceiling in SEVERITY_RANK and base in SEVERITY_RANK and SEVERITY_RANK[ceiling]>=SEVERITY_RANK[base]:
            errors.append(f"$.severity: conditionalCeiling {ceiling!r} must be strictly higher than base {base!r}")
    elif condition:
        errors.append("$.severity: condition is meaningless without a conditionalCeiling")
    if base=="Undetermined" and verdict in {"Confirmed","Partially confirmed"} and not gated and not data.get("missingInformation"):
        errors.append("$.severity: an Undetermined base on a confirmed issue must name the MI that gates the bound (gatedBy or missingInformation)")
    return errors

def stated_outcome(text: str) -> tuple[str | None, list[str]]:
    """The single `Outcome:` statement of a final report's decision summary."""
    found=[match.group("outcome") for match in map(OUTCOME_LINE.match, text.splitlines()) if match]
    if len(found)!=1:
        return None,[f"decision summary must state exactly one 'Outcome: <{' | '.join(OUTCOMES)}>' line, found {len(found)}"]
    return found[0],[]

def expected_outcome(severities: dict[str, str], gated: set[str], active_mi: bool, unreadable_source: bool=False) -> str:
    """The §0 rule: Insufficient documentation if a Critical/High finding is gated by active MI or a
    required source is unreadable; else Approve with conditions if Medium+ findings or MI remain; else Approve."""
    if unreadable_source or any(severities.get(finding) in {"Critical","High"} for finding in gated):
        return "Insufficient documentation"
    if active_mi or any(value in {"Critical","High","Medium"} for value in severities.values()):
        return "Approve with conditions"
    return "Approve"

def record_impact_mi(lines: list[str]) -> dict[str, set[str]]:
    """For each reported-issue record, the MI IDs its Impact section names as gating the bound."""
    gating: dict[str, set[str]] = {}
    current: str | None = None
    for line in lines:
        heading = RECORD_HEADING.match(line)
        if heading:
            current = heading.group("id"); gating.setdefault(current, set()); continue
        if line.startswith("#"):
            current = None; continue
        if current is not None and line.strip().startswith("**Impact:**"):
            gating[current].update(re.findall(r"\bMI-S[123]-[0-9]{3,}\b", line))
    return gating

def _json_string_array(cell: str, label: str, errors: list[str], *, nonempty: bool = False) -> list[str]:
    try:
        value = json.loads(cell)
    except json.JSONDecodeError:
        errors.append(f"{label}: must be a compact JSON string array")
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        errors.append(f"{label}: must be a JSON array of non-empty strings")
        return []
    if nonempty and not value:
        errors.append(f"{label}: must not be empty")
    if len(value) != len(set(value)):
        errors.append(f"{label}: duplicate values are forbidden")
    return value

def extract_base_findings(path: Path, kind: str) -> tuple[list[dict], list[str]]:
    """Project active Stage 1/2 report rows into canonical blinded records."""
    if kind not in BASE_REGISTER_SPECS:
        return [], [f"base finding extraction is unsupported for {kind}"]
    spec, errors = BASE_REGISTER_SPECS[kind], []
    tables, table_errors = parse_tables(path.read_text(encoding="utf-8").splitlines())
    errors.extend(table_errors)
    evidence_by_id: dict[str, dict] = {}
    for heading, header, rows in tables:
        normalized = [cell.strip().lower() for cell in header]
        if "evidence register" not in heading.lower() or not {"id", "relative path", "locator", "quote"} <= set(normalized):
            continue
        indexes = {name: normalized.index(name) for name in ["id", "relative path", "locator", "quote"]}
        for row_number, row in enumerate(rows, start=1):
            if len(row) != len(header):
                continue
            evidence_id = row[indexes["id"]].strip("` ")
            if evidence_id in evidence_by_id:
                errors.append(f"{heading} row {row_number}: duplicate evidence ID {evidence_id!r}")
                continue
            evidence_by_id[evidence_id] = {
                "relativePath": row[indexes["relative path"]].strip("` "),
                "locator": row[indexes["locator"]].strip("` "),
                "quote": row[indexes["quote"]].strip("` “”—\""),
            }
    matches = [(heading, header, rows) for heading, header, rows in tables if heading == spec["heading"]]
    if len(matches) != 1:
        errors.append(f"expected exactly one canonical register table under {spec['heading']!r}")
        return [], errors
    heading, header, rows = matches[0]
    normalized = [cell.strip().lower() for cell in header]
    if normalized != spec["headers"]:
        errors.append(f"{heading}: exact columns must be {spec['headers']}")
        return [], errors
    column = {name: normalized.index(name) for name in normalized}
    findings, occurrences = [], Counter()
    for row_number, row in enumerate(rows, start=1):
        if len(row) != len(header):
            errors.append(f"{heading} row {row_number}: cannot project malformed row")
            continue
        issue_id = row[column["id"]].strip("` ")
        occurrences[issue_id] += 1
        if not spec["idPattern"].fullmatch(issue_id):
            errors.append(f"{heading} row {row_number}: malformed active ID {issue_id!r}")
        claim = row[column["claim"]].strip()
        if not claim:
            errors.append(f"{heading} row {row_number}: Claim must not be empty")
        affected = _json_string_array(row[column["affected scope"]], f"{heading} row {row_number} Affected Scope", errors)
        actors = _json_string_array(row[column["threat actors"]], f"{heading} row {row_number} Threat Actors", errors)
        stride = _json_string_array(row[column["stride"]], f"{heading} row {row_number} STRIDE", errors, nonempty=True)
        invalid_stride = sorted(set(stride) - STRIDE_VALUES)
        if invalid_stride:
            errors.append(f"{heading} row {row_number}: invalid STRIDE values {invalid_stride}")
        evidence_ids = _json_string_array(row[column["evidence ids"]], f"{heading} row {row_number} Evidence IDs", errors, nonempty=True)
        resolved = []
        for evidence_id in evidence_ids:
            if not spec["evidencePattern"].fullmatch(evidence_id):
                errors.append(f"{heading} row {row_number}: malformed evidence ID {evidence_id!r}")
            evidence = evidence_by_id.get(evidence_id)
            if evidence is None:
                errors.append(f"{heading} row {row_number}: unresolved evidence ID {evidence_id!r}")
            else:
                resolved.append(evidence)
        locator = f"{heading}::row={row_number}::id={issue_id}::occurrence={occurrences[issue_id]}"
        findings.append({
            "origin": spec["origin"], "sourceReport": spec["sourceReport"], "sourceLocator": locator,
            "sourceOccurrence": occurrences[issue_id], "issueId": issue_id,
            "blindedRecord": {
                "claim": claim,
                "scope": {"affectedScope": affected, "threatActors": actors, "stride": stride},
                "sourceLocators": [f"{item['relativePath']}::{item['locator']}" for item in resolved],
                "sourceQuotes": resolved,
            },
        })
    return findings, errors

def corpus_sources(manifest_path: Path) -> set[str]:
    """The relative paths a bound corpus manifest declares; nothing else may be resolved."""
    return {str(source["relativePath"]) for source in json.loads(manifest_path.read_text(encoding="utf-8"))["sources"]}

def corpus_has_unreadable_source(manifest_path: Path) -> bool:
    """An unreadable required source forces the §0 outcome to Insufficient documentation."""
    return any(source.get("fidelity") == "unreadable" for source in json.loads(manifest_path.read_text(encoding="utf-8"))["sources"])

def validate_quotes(data: object, docs_root: Path, allowed: set[str] | None = None) -> list[str]:
    errors = []
    def visit(node: object, path: str) -> None:
        if isinstance(node, dict):
            if {"relativePath", "quote"} <= node.keys():
                quote, relative = node["quote"], node["relativePath"]
                if not isinstance(quote, str) or not 1 <= len(quote.split()) <= 25:
                    errors.append(f"{path}.quote: must contain 1–25 words")
                if allowed is not None and str(relative) not in allowed:
                    errors.append(f"{path}.relativePath: not a source in the bound corpus: {relative}")
                    for key, value in node.items(): visit(value, f"{path}.{key}")
                    return
                source = (docs_root / str(relative)).resolve()
                try:
                    source.relative_to(docs_root.resolve())
                except ValueError:
                    errors.append(f"{path}.relativePath: escapes docs root")
                else:
                    if not source.is_file():
                        errors.append(f"{path}: source not found: {relative}")
                    elif quote not in source.read_text(encoding="utf-8", errors="replace"):
                        errors.append(f"{path}: exact quote not found in {relative}")
            for key, value in node.items(): visit(value, f"{path}.{key}")
        elif isinstance(node, list):
            for i, value in enumerate(node): visit(value, f"{path}[{i}]")
    visit(data, "$")
    return errors

def finding_record_errors(lines: list[str], active: list[str], evidence: set[str]) -> list[str]:
    """Every reported issue states specification facts both ways, then issue, impact, recommendation."""
    errors: list[str] = []
    records: dict[str, list[str]] = {}
    order: list[str] = []
    current: str | None = None
    for line in lines:
        heading = RECORD_HEADING.match(line)
        if heading:
            current = heading.group("id")
            if current in records:
                errors.append(f"duplicate finding record for {current}")
            records.setdefault(current, [])
            order.append(current)
            continue
        if line.startswith("#"):
            current = None
            continue
        if current is not None:
            records[current].append(line)
    for finding in active:
        if finding not in records:
            errors.append(f"{finding}: missing a '### {finding} — <title>' record with the four-part contract")
    for finding in order:
        if finding not in active:
            errors.append(f"finding record {finding} does not resolve to an active register row")
            continue
        body = records[finding]
        positions = {}
        for index, line in enumerate(body):
            for label in RECORD_LABELS:
                if line.strip().startswith(f"**{label}**"):
                    positions.setdefault(label, index)
        missing = [label for label in RECORD_LABELS if label not in positions]
        if missing:
            errors.append(f"{finding}: record is missing {', '.join(repr(label) for label in missing)}")
            continue
        found_order = [positions[label] for label in RECORD_LABELS]
        if found_order != sorted(found_order):
            errors.append(f"{finding}: record sections must appear in the order {', '.join(RECORD_LABELS)}")
            continue
        for label in RECORD_LABELS[1:]:
            line = body[positions[label]].strip()
            if not line[len(f"**{label}**"):].strip():
                errors.append(f"{finding}: '{label}' must state its content on the same line")
        bullets = [line.strip()[1:].strip() for line in body[positions[RECORD_LABELS[0]] + 1:positions[RECORD_LABELS[1]]]
                   if line.strip().startswith("- ")]
        if not bullets:
            errors.append(f"{finding}: 'From specification:' requires at least one '- Supports:'/'- Contradicts:' bullet")
            continue
        tags = []
        for number, bullet in enumerate(bullets, start=1):
            tag = next((candidate for candidate in RECORD_TAGS if bullet.startswith(candidate)), None)
            if tag is None:
                errors.append(f"{finding} specification bullet {number}: must begin with {' or '.join(RECORD_TAGS)}")
                continue
            tags.append(tag)
            cited = set(re.findall(r"EV-(?:S1|S2|S3|F)-[0-9]{3,}", bullet))
            if cited:
                unresolved = sorted(cited - evidence)
                if unresolved:
                    errors.append(f"{finding} specification bullet {number}: evidence {unresolved} is not in this report's evidence register")
            elif not RECORD_NULL.fullmatch(bullet):
                errors.append(f"{finding} specification bullet {number}: cite an evidence ID, or state 'Contradicts: None identified — <scope searched>'")
        for tag in RECORD_TAGS:
            if tag not in tags:
                errors.append(f"{finding}: 'From specification:' must include at least one '{tag}' fact; "
                              f"state 'Contradicts: None identified — <scope searched>' when the corpus offers none")
    return errors

def validate_markdown(path: Path, kind: str, docs_root: Path | None, allowed: set[str] | None = None,
                      unreadable_source: bool = False) -> list[str]:
    text, errors = path.read_text(encoding="utf-8"), []
    lines = text.splitlines()
    title, chapter_prefixes = CONTRACTS[kind]
    if not lines or lines[0].strip() != title:
        errors.append(f"exact title must be {title!r}")
    positions = []
    for prefix in chapter_prefixes:
        matches = [i for i, line in enumerate(lines) if line.strip() == prefix]
        if len(matches) != 1:
            errors.append(f"expected exactly one chapter heading {prefix!r}")
        else: positions.append(matches[0])
    if positions != sorted(positions): errors.append("chapters are out of order")
    actual_chapters=[line.strip() for line in lines if line.startswith("## ")]
    if actual_chapters!=chapter_prefixes: errors.append("chapter hierarchy contains missing, extra, or misplaced level-2 headings")
    tables, table_errors = parse_tables(lines); errors.extend(table_errors)
    def require_table(heading_phrase: str, columns: set[str]) -> None:
        allow_empty={"finding register","gap finding register","final finding register","missing information register","verification defect register"}
        for heading, header, rows in tables:
            if heading_phrase in heading.lower() and columns <= {cell.strip().lower() for cell in header}:
                if rows or heading_phrase in allow_empty:
                    return
                errors.append(f"required table under {heading_phrase!r} must contain at least one substantive row")
                return
        errors.append(f"missing required table: a table whose nearest heading line contains {heading_phrase!r} (any case) and whose "
                      f"header row has at least the columns {', '.join(sorted(columns))} (any order). A subheading between the "
                      "chapter heading and the table becomes the nearest heading, so put the table directly under the heading")
    for heading_phrase, columns in REQUIRED_TABLES[kind]:
        require_table(heading_phrase, columns)
    for heading, header, rows in tables:
        normalized = [cell.strip().lower() for cell in header]
        if "evidence register" in heading.lower() and normalized != EVIDENCE_COLUMNS:
            errors.append(f"{heading}: evidence register columns must be exactly {EVIDENCE_COLUMNS}")
        if kind in {"stage1", "final"} and "coverage" in heading.lower() and set(STRIDE_COLUMNS) <= set(normalized):
            for row_number, row in enumerate(rows, start=1):
                for name in STRIDE_COLUMNS:
                    cell = row[normalized.index(name)].strip() if len(row) > normalized.index(name) else ""
                    if not all(COVERAGE_CELL.fullmatch(part.strip()) for part in cell.split(";")):
                        errors.append(f"{heading} row {row_number} {name}: cell {cell!r} must be 'Threat — <ID>', "
                                      "'Covered — C-nnn', 'N/A — <reason>', or 'MI — MI-S[123]-nnn'")
    if kind in BASE_REGISTER_SPECS:
        _, projection_errors = extract_base_findings(path, kind)
        errors.extend(projection_errors)
    digest_matches = re.findall(r"(?i)corpus(?: aggregate)? digest[^a-f0-9]+`?([a-f0-9]{64})`?", text)
    if not digest_matches:
        errors.append("report must contain a 64-hex corpus aggregate digest")
    for label, pattern, example in (
        ("package version", rf"(?i)package(?: version)?[^\n]*{re.escape(INSTALLED_VERSION)}", f"Package version: {INSTALLED_VERSION}"),
        ("protocol version", r"(?i)protocol(?: version)?[^\n]*2\.0", "Protocol version: 2.0"),
        ("model identity", r"(?i)model(?:s| identity)?\s*[:=]", "Model: <the model ID>"),
        ("runtime identity", r"(?i)runtime\s*[:=]", "Runtime: <the host or runtime name>"),
        ("validated model tier", r"(?i)(?:validated )?model tier\s*[:=]", "Validated model tier: unvalidated-reference"),
    ):
        if re.search(pattern, text) is None:
            errors.append(f"report missing {label}: write a plain line such as {example!r} (the colon or equals sign directly "
                          "after the word, with no ** or backtick between them)")
    # Registry definitions are rows whose first column is the ID in a named register.
    definitions: dict[str, list[str]] = {key: [] for key in ID_PATTERNS}
    defined_in: dict[tuple[str, str], list[str]] = {}
    for heading, header, rows in tables:
        heading_lower = heading.lower()
        expected_namespace = next((namespace for phrase, namespace in REGISTER_NAMESPACE.items() if phrase in heading_lower), None)
        if expected_namespace and (not header or header[0].strip().lower() != "id"):
            errors.append(f"{heading}: active register must use ID as its first column")
        for row in rows:
            if not row: continue
            value = row[0].strip("` ")
            if expected_namespace:
                if not ID_PATTERNS[expected_namespace].fullmatch(value):
                    errors.append(f"{heading}: malformed {expected_namespace} ID {value!r}"
                                  + (f" (write it like {ID_FORMAT_HINT[expected_namespace]})" if expected_namespace in ID_FORMAT_HINT else ""))
                else:
                    definitions[expected_namespace].append(value)
                    defined_in.setdefault((expected_namespace, value), []).append(heading)
            else:
                namespaces = ID_PATTERNS if "register" in heading_lower else {key: ID_PATTERNS[key] for key in ("C","REQ")}
                for key, pattern in namespaces.items():
                    if pattern.fullmatch(value):
                        definitions[key].append(value)
                        defined_in.setdefault((key, value), []).append(heading)
    for key, values in definitions.items():
        duplicates = sorted({value for value in values if values.count(value) > 1})
        if duplicates:
            where = "; ".join(f"{value} in {' | '.join(repr(h) for h in defined_in[(key, value)])}" for value in duplicates[:5])
            errors.append(f"duplicate active {key} definitions: {duplicates} ({where}). An ID is a definition when it is the "
                          "first cell of a table row; define it in one table only and write it in a later column, or with "
                          "its name after it (for example 'REQ-001 Name'), in every other table")
    for heading, header, rows in tables:
        normalized=[cell.strip().lower() for cell in header]
        if "severity" in normalized and "rubric" in normalized:
            severity_index,rubric_index=normalized.index("severity"),normalized.index("rubric")
            for row_number,row in enumerate(rows,start=1):
                if len(row)<=max(severity_index,rubric_index): continue
                severity,rubric=row[severity_index].strip(),row[rubric_index].strip("` ")
                expected=SEVERITY_RUBRIC.get(severity)
                if expected is None: errors.append(f"{heading} row {row_number}: invalid severity {severity!r}")
                elif rubric!=expected: errors.append(f"{heading} row {row_number}: severity {severity!r} requires rubric {expected!r}, got {rubric!r}")
    for namespace,pattern in ID_PATTERNS.items():
        body=pattern.pattern[1:-1]
        references=set(re.findall(rf"(?<![A-Za-z0-9-])(?:{body})(?![A-Za-z0-9-])",text))
        unresolved=sorted(references-set(definitions[namespace]))
        if unresolved:
            def first_use(value: str) -> int:
                return next((number for number, line in enumerate(lines, start=1)
                             if re.search(rf"(?<![A-Za-z0-9-]){re.escape(value)}(?![A-Za-z0-9-])", line)), 0)
            errors.append(f"unresolved {namespace} references: {unresolved} (first use: "
                          + ", ".join(f"{value} on line {first_use(value)}" for value in unresolved[:4])
                          + (", ..." if len(unresolved) > 4 else "") + ")")
            if not any(error.startswith("hint: an ID is defined") for error in errors):
                errors.append("hint: an ID is defined only as the first cell of a row of a table under a heading that contains the "
                              "word 'register' (a C- or REQ- ID: of any table); every use elsewhere refers to it")
    active_findings = definitions["F"] + definitions["S1"] + definitions["S2"] + definitions["S3"]
    errors.extend(finding_record_errors(lines, active_findings, set(definitions["EV"])))
    evidence_rows = 0
    if docs_root is None:
        errors.append("--docs-root is required for Markdown quote validation")
    else:
        root = docs_root.resolve()
        for heading, header, rows in tables:
            normalized = [cell.strip().lower() for cell in header]
            if "relative path" not in normalized or "quote" not in normalized:
                continue
            path_index, quote_index = normalized.index("relative path"), normalized.index("quote")
            evidence_rows += len(rows)
            for row_number, row in enumerate(rows, start=1):
                relative = row[path_index].strip("` ")
                quote = row[quote_index].strip("` “”—\"")
                if not quote or len(quote.split()) > 25:
                    errors.append(f"{heading} row {row_number}: quote must contain 1–25 words")
                    continue
                if allowed is not None and relative not in allowed:
                    errors.append(f"{heading} row {row_number}: not a source in the bound corpus: {relative}")
                    continue
                source = (root / relative).resolve()
                try:
                    source.relative_to(root)
                except ValueError:
                    errors.append(f"{heading} row {row_number}: relative path escapes docs root")
                else:
                    if not source.is_file():
                        errors.append(f"{heading} row {row_number}: source not found: {relative}")
                    elif quote not in source.read_text(encoding="utf-8", errors="replace"):
                        errors.append(f"{heading} row {row_number}: exact quote not found in {relative}")
    if active_findings and evidence_rows == 0:
        errors.append("active findings require a machine-checkable evidence table with Relative path and Quote columns")
    if kind == "final":
        threats = set(re.findall(r"Threat\s+—\s+(F-[0-9]{3,})", text))
        missing = sorted(threats - set(definitions["F"]))
        if missing: errors.append(f"matrix threat references do not resolve: {missing}")
        # Final IDs are assigned by severity first, so the register reads Critical to Undetermined.
        severities: dict[str, str] = {}
        for heading, header, rows in tables:
            normalized = [cell.strip().lower() for cell in header]
            if "final finding register" in heading.lower() and "severity" in normalized:
                column = normalized.index("severity")
                ordered = [(row[0].strip("` "), row[column].strip()) for row in rows if len(row) > column]
                severities.update(ordered)
                numbers = [int(finding.split("-")[1]) for finding, _ in ordered if ID_PATTERNS["F"].fullmatch(finding)]
                if numbers != sorted(numbers): errors.append(f"{heading}: rows must be in ascending F-ID order")
                ranks = [SEVERITY_RANK.get(value, len(SEVERITY_RANK)) for _, value in ordered]
                if ranks != sorted(ranks):
                    errors.append(f"{heading}: F-* IDs must be assigned in severity order (Critical first); "
                                  "a higher-severity finding cannot carry a higher ID than a lower-severity one")
        outcome, outcome_errors = stated_outcome(text); errors.extend(outcome_errors)
        active_mi = set(definitions["MI"])
        gated = {finding for finding, names in record_impact_mi(lines).items() if names & active_mi}
        expected = expected_outcome(severities, gated, bool(active_mi), unreadable_source)
        if outcome is not None and outcome != expected:
            errors.append(f"decision outcome states {outcome!r} but the §0 rule derives {expected!r} from the final tables"
                          + (" and an unreadable corpus source" if unreadable_source else ""))
    mi_refs = set(re.findall(r"\bMI-S[123]-[0-9]{3,}\b", text))
    unresolved_mi = sorted(mi_refs - set(definitions["MI"]))
    if unresolved_mi: errors.append(f"MI references do not resolve to exactly one active register row: {unresolved_mi}")
    # Summary Metric|Count rows are mechanically compared with active registries.
    actual = {"Final findings": len(definitions["F"]), "Active missing information": len(definitions["MI"]), "Verification defects": len(definitions["VD"])}
    for heading, header, rows in tables:
        if [h.lower() for h in header[:2]] == ["metric", "count"]:
            for row in rows:
                if row[0] in actual:
                    try: stated = int(row[1])
                    except ValueError: errors.append(f"{heading}: non-integer count for {row[0]}")
                    else:
                        if stated != actual[row[0]]: errors.append(f"{heading}: {row[0]} states {stated}, recomputed {actual[row[0]]}")
    return errors

def _utf8_stdio() -> None:
    """Read standard input and print as UTF-8 whatever the console code page is: reports and quotes contain
    em dashes and section signs, and a legacy code page would turn a correct quote into a false mismatch."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try: stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError): pass

def main() -> int:
    _utf8_stdio()
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path, nargs="?")
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--kind", choices=CONTRACTS)
    parser.add_argument("--docs-root", type=Path)
    parser.add_argument("--corpus-manifest", type=Path,
                        help="restrict quote resolution to the sources this corpus manifest declares")
    parser.add_argument("--stdin-json", action="store_true",
                        help="validate a JSON document read from standard input, for a role that has no file-writing tool; a role that can write its reply file validates it by passing the file as the artifact together with --schema")
    args = parser.parse_args()
    # Quote resolution walks the filesystem from a caller-chosen root, and a shell-permitted
    # subprocess is not bound by the calling agent's fs_read rules. Confine every path.
    if args.docs_root and not args.corpus_manifest:
        parser.error("--docs-root requires --corpus-manifest so quote resolution stays inside the bound corpus")
    allowed = corpus_sources(args.corpus_manifest) if args.corpus_manifest else None
    unreadable = corpus_has_unreadable_source(args.corpus_manifest) if args.corpus_manifest else False
    errors = []
    if args.stdin_json:
        if args.artifact: parser.error("--stdin-json reads the document from standard input; omit the artifact path")
        if args.kind: parser.error("--stdin-json validates JSON artifacts, not Markdown reports")
        if not args.schema: parser.error("--stdin-json requires --schema")
        data, _text, problem, notes = replyread.parse_text(sys.stdin.read())
        for _kind, sentence in notes: print(f"NOTE: {sentence}", file=sys.stderr)
        if problem:
            print(f"ERROR: standard input: {problem}", file=sys.stderr)
            return 1
        errors.extend(data_errors(data, args.schema))
        if args.docs_root: errors.extend(validate_quotes(data, args.docs_root, allowed))
        label = "<stdin>"
    else:
        if not args.artifact: parser.error("provide an artifact path or --stdin-json")
        if args.schema:
            try:
                if args.schema.name in REPLY_SCHEMAS:       # a role's reply file is read the way the ingest reads it
                    data, _text, problem, notes = replyread.parse_bytes(args.artifact.read_bytes())
                    for _kind, sentence in notes: print(f"NOTE: {sentence}", file=sys.stderr)
                    if problem:
                        print(f"ERROR: {args.artifact} is not a readable reply: {problem}", file=sys.stderr)
                        return 1
                else: data = load_json(args.artifact)
            except (OSError, ValueError) as exc:           # a role's reply file: say so, do not print a traceback
                print(f"ERROR: {args.artifact} is not valid JSON: {exc}", file=sys.stderr)
                return 1
            errors.extend(data_errors(data, args.schema))
            if args.docs_root: errors.extend(validate_quotes(data, args.docs_root, allowed))
        if args.kind: errors.extend(validate_markdown(args.artifact, args.kind, args.docs_root, allowed, unreadable))
        if not args.schema and not args.kind: parser.error("provide --schema and/or --kind")
        label = str(args.artifact)
    if errors:
        for error in errors: print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"valid: {label}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
