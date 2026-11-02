# Review shapes: the chapters, tables and lines of the three review documents

This file is the shape of the Stage 1 document, the Stage 2 document and the final document, **with no content**. Every `<...>`
is yours to fill from the corpus you were given; nothing here is a finding, a quote or a sample of what a design looks like, and
no finished review of a real or example design is shipped for you to copy. Use it instead of reading `validate_report.py` (a
host run had subagents read the validator's source ten times to learn these shapes). The validator is still the authority: it
checks every rule below, and a test keeps this file and the validator together.

## Rules every document follows

- **Title and chapters.** The first line is the exact `# ...` title. The level-2 headings are exactly the `## ...` lines of
  the skeleton below, once each, in that order; no other level-2 heading exists. Anything finer is level 3 (`###`).
- **A table sits directly under the heading line that names it.** The validator finds a table by the nearest heading line above
  it, so a subheading between a chapter heading and its table (or a line of text that is a heading) makes the table
  unfindable. A table has a header row, a separator row (`|---|---|`) and rows that all have the header's column count. A
  register that may be empty (finding, gap finding, final finding, missing information, verification defect registers) still
  needs its header and separator.
- **Lines of metadata**, each on a line of its own in chapter 1, in plain text, the colon directly after the words (no `**`, no
  backticks between them): `Corpus aggregate digest: <the 64 hex characters>`, `Package version: <the package version your role
  file names>`, `Protocol version: 2.0`, `Model: <your model ID>`, `Runtime: <the host>`, `Validated model tier:
  unvalidated-reference`. The digest, the lens and the paths are in your invocation record.
- **Evidence register**, in every document: `| ID | Document title | Relative path | Locator | Quote | Proposition |`, exactly these
  columns in this order. A quote is 1 to 25 words and appears byte for byte in the document at `Relative path`, which must be a
  source of the bound corpus. IDs: `EV-S1-nnn` (Stage 1), `EV-S2-nnn` (Stage 2), `EV-F-nnn` (final).
- **An ID is defined once**, as the first cell of one row of a table whose heading contains the word `register` (a `C-` or `REQ-`
  ID may be defined in any table). Everywhere else it is only written, in another column or in prose; a second row that starts
  with the same ID is a duplicate, and an ID that no register defines is unresolved. `SC-` and `MI-` IDs carry the origin
  (`SC-S1-001`, `MI-S2-003`). **This holds for IDs carried over from an earlier document too:** a Stage 2 document that writes a
  Stage 1 control `C-001`, claim `SC-S1-001` or model element `P-001` defines it in a table of its own (the model element register
  and the claim register are where they go) or names it in prose instead; a Stage 1 finding `S1-nnn` has no register in Stage 2,
  so a Stage 2 document names that finding by its claim. The final document defines every model element ID (`A-`, `EE-`, `P-`,
  `DS-`, `DF-`, `TB-`, `INT-`, `EP-`) that it writes in a model element register of its own.
- **A register with nothing in it has no row.** Keep its header and separator; a row that says `None` in a register whose first
  column is an ID is a malformed ID. (`None supplied` in the requirement traceability table is fine: that table has no ID column.)
- **Coverage cells** are exactly one of `Threat — <ID of a finding>`, `Covered — C-nnn`, `N/A — <reason>`, `MI — MI-S1-nnn` (or
  `MI-S2-`, `MI-S3-`). Several may share a cell, joined by `;`, and each part is a complete cell of its own: `Covered — C-001;
  Covered — C-002`, never `Covered — C-001; C-002`. Every applicable cell says where the threat went; none is left empty.
- **Findings**: each active row of a finding register is followed by its four-part record (`### <ID> — <title>`, then
  `From specification:`, `Issue:`, `Impact:`, `Recommendation:`; `references/finding-record.md`). Severity and rubric are a
  pair (`references/severity-rubric.md`). Array columns hold compact JSON arrays of strings.
- **The final document defines only its own IDs.** It never writes a source ID `S1-nnn`, `S2-nnn` or `S3-nnn`, not even in prose.

## Stage 1 (`designer`, `stage-1-review.md`)

```markdown
# Stage 1 — Comprehensive STRIDE Security Design Review
## 1. Review Inputs and Corpus Integrity
Corpus aggregate digest: <64 hex>
Package version: <package version>
Protocol version: 2.0
Model: <model ID>
Runtime: <host>
Validated model tier: unvalidated-reference
<domain lens; per-source extent read; delta provenance; limitations; the source/extraction/extent table>
### Evidence register
| ID | Document title | Relative path | Locator | Quote | Proposition |
|---|---|---|---|---|---|
| EV-S1-001 | <title> | <relative path> | <locator> | <exact quote> | <what the quote supports> |
## 2. Documented Model, Adversaries, and Assumptions
### Model element register
| ID | Type | Name |
|---|---|---|
| <A-nnn, EE-nnn, P-nnn, DS-nnn, DF-nnn, TB-nnn, INT-nnn or EP-nnn> | <type> | <name> |
### Threat actor register
| ID | Actor | Position | Capabilities | Basis |
|---|---|---|---|---|
| TA-001 | <actor> | <position> | <capabilities> | <Documented or Inference> |
### Assumption register
| ID | Assumption | Basis | Dependency | Failure consequence |
|---|---|---|---|---|
| AS-001 | <assumption> | <basis> | <dependency> | <consequence> |
### Claim register
| ID | Claim | Status |
|---|---|---|
| SC-S1-001 | <claim> | <status> |
## 3. STRIDE Coverage
<baseline applicability with the rationale and home of every No; selected-lens question coverage>
| Element | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
|---|---|---|---|---|---|---|
| <element or interaction ID and name> | <cell> | <cell> | <cell> | <cell> | <cell> | <cell> |
## 4. Finding Register
| ID | Claim | Affected Scope | Threat Actors | STRIDE | Severity | Rubric | Confidence | Evidence IDs |
|---|---|---|---|---|---|---|---|---|
| S1-001 | <claim as one sentence> | ["<ID>"] | ["TA-001"] | ["<category>"] | <severity> | <SR-cell> | <High, Medium or Low> | ["EV-S1-001"] |
### S1-001 — <title>
**From specification:**
- Supports: <fact> (`EV-S1-001`)
- Contradicts: <fact> (`EV-S1-002`), or: None identified — <what you searched for, corpus-wide>
**Issue:** <the root cause and the threat condition>
**Impact:** <the supported consequence; name a gating MI-S1-nnn here when one bounds it>
**Recommendation:** <the remediation, with an observable acceptance criterion>
## 5. Control and Claim Validation
| Control | Mechanism | Status |
|---|---|---|
| C-001 | <documented mechanism> | <status and limitation> |
## 6. Missing Information Register
| ID | Question | Blocks | Status |
|---|---|---|---|
| MI-S1-001 | <question> | <what it blocks> | <status> |
## 7. Requirement Traceability and Limitations
### Requirement traceability
| Requirement | Status | References |
|---|---|---|
| <REQ-nnn or: None supplied> | <covered, violated or undetermined> | <finding and MI IDs> |
```

## Stage 2 (`gap`, `stage-2-gap-review.md`)

```markdown
# Stage 2 — Adversarial STRIDE Completeness Review
## 1. Review Inputs and Corpus Integrity
Corpus aggregate digest: <64 hex>
Package version: <package version>
Protocol version: 2.0
Model: <model ID>
Runtime: <host>
Validated model tier: unvalidated-reference
<domain lens; per-source extent; the Stage 1 digest; delta provenance; limitations>
### Evidence register
| ID | Document title | Relative path | Locator | Quote | Proposition |
|---|---|---|---|---|---|
| EV-S2-001 | <title> | <relative path> | <locator> | <exact quote> | <what the quote supports> |
## 2. Independent Reconstruction and Crosswalk
### Model element register
| ID | Type | Name |
|---|---|---|
| <canonical A-nnn, EE-nnn, P-nnn, DS-nnn, DF-nnn, TB-nnn, INT-nnn or EP-nnn> | <type> | <name> |
### Model crosswalk
| Stage 2 ID | Stage 1 ID | Status |
|---|---|---|
| <R2-... ID> | <Stage 1 ID, or none> | <Matched, Stage 2 only, Stage 1 only, ...> |
### Threat actor register
| ID | Actor | Position | Status |
|---|---|---|---|
| TA-001 | <actor> | <position> | <matched to Stage 1, or new> |
<the assumption, claim and requirement registers; the coverage diff against Stage 1>
## 3. Gap Finding Register
| ID | Category | Claim | Affected Scope | Threat Actors | STRIDE | Materiality | Severity | Rubric | Confidence | Evidence IDs |
|---|---|---|---|---|---|---|---|---|---|---|
| S2-001 | <A, B, C, D or E, with its name> | <claim as one sentence> | ["<ID>"] | ["TA-001"] | ["<category>"] | <Material or Non-material> | <severity> | <SR-cell> | <High, Medium or Low> | ["EV-S2-001"] |
### S2-001 — <title>
**From specification:**
- Supports: <fact> (`EV-S2-001`)
- Contradicts: <fact> (`EV-S2-002`), or: None identified — <what you searched for, corpus-wide>
**Issue:** <the gap>
**Impact:** <the supported consequence>
**Recommendation:** <the remediation, with an observable acceptance criterion>
## 4. Missing Information Register and Validation
| ID | Question | Blocks | Status |
|---|---|---|---|
| <MI-S2-nnn for a new item; every MI-S1-nnn of Stage 1 exactly once> | <question> | <what it blocks> | <Confirmed missing, Present, Partially present, Unsupported premise or Duplicate (and of what)> |
## 5. Requirement Traceability, Re-scoping, and Limitations
### Requirement traceability
| Requirement | Status | References |
|---|---|---|
| <REQ-nnn or: None supplied> | <covered, violated or undetermined> | <finding and MI IDs> |
```

## Final (`final-review.md`, written by the coordinator)

```markdown
# Final — Verified STRIDE Security Design Review
## 0. Decision Summary
| Metric | Count |
|---|---|
| Final findings | <number of rows of the final finding register> |
| Active missing information | <number of rows of the missing information register> |
| Verification defects | <number of rows of the verification defect register> |
Outcome: **<Insufficient documentation, Approve with conditions or Approve, by the rule in references/roles/orchestrator.md>**
<the top findings by severity; the blocking MI>
## 1. Inputs, Environment, and Corpus Integrity
Corpus aggregate digest: <64 hex>
Package version: <package version>
Protocol version: 2.0
Model: <the models of the coordinator, the stages, the sweep and the verifiers, as `stride_run.py summary` prints them>
Runtime: <host>
Validated model tier: unvalidated-reference
<paths; extraction and extents; lens; baseline delta; queue and cost; retries; the dispatch record, the disclosure line, the limitations line and any reply notes of `stride_run.py summary`>
### Evidence register
| ID | Document title | Relative path | Locator | Quote | Proposition |
|---|---|---|---|---|---|
| EV-F-001 | <title> | <relative path> | <locator> | <exact quote> | <what the quote supports> |
## 2. Verified Model, Adversaries, and Assumptions
### Model element register
| ID | Type | Name |
|---|---|---|
| <A-nnn, EE-nnn, P-nnn, DS-nnn, DF-nnn, TB-nnn, INT-nnn or EP-nnn, each one the document writes> | <type> | <name> |
### Threat actor register
| ID | Actor | Position |
|---|---|---|
| TA-001 | <actor> | <position> |
### Assumption register
| ID | Assumption | Status |
|---|---|---|
| AS-001 | <assumption> | <status after verification> |
## 3. Verified STRIDE Coverage
| Interaction | Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege |
|---|---|---|---|---|---|---|
| <interaction> | <cell, with Threat — F-nnn for a final finding> | <cell> | <cell> | <cell> | <cell> | <cell> |
## 4. Final Finding Register
| ID | Title | Actor | Severity | Rubric | Confidence | Evidence IDs |
|---|---|---|---|---|---|---|
| F-001 | <title> | <TA-nnn> | <severity> | <SR-cell> | <High, Medium or Low> | EV-F-001 |
### F-001 — <title>
**From specification:**
- Supports: <fact> (`EV-F-001`)
- Contradicts: <fact> (`EV-F-002`), or: None identified — <what you searched for, corpus-wide>
**Issue:** <the verified issue; name an origin in prose ("the Stage 1 claim"), never by its S1-nnn, S2-nnn or S3-nnn ID>
**Impact:** <the supported consequence; name a gating MI-S1-nnn here when one bounds it>
**Recommendation:** <the remediation, with an observable acceptance criterion>
## 5. Control, Claim, and Requirement Traceability
| Control | Mechanism | Status |
|---|---|---|
| C-001 | <documented mechanism> | <status and limitation> |
### Requirement traceability
| Requirement | Status | References |
|---|---|---|
| <REQ-nnn or: None supplied> | <covered, violated or undetermined> | <F- and MI IDs> |
## 6. Verification and Calibration
### 6.1 Per-stage correction and false-positive rates
<the calibration table below is printed by `stride_run.py calibration`: paste it unchanged; add the attempts, retries and inline rate in prose>
| Stage | Confirmed | Corrected | False positive | Unverifiable | Blocked |
|---|---|---|---|---|---|
| Stage 1 | <n> | <n> | <n> | <n> | <n> |
| Stage 2 | <n> | <n> | <n> | <n> | <n> |
| Stage 3 | <n> | <n> | <n> | <n> | <n> |
## 7. Missing Information Register
| ID | Question | Blocks | Verdict |
|---|---|---|---|
| MI-S1-001 | <question> | <what it blocks> | <Confirmed missing, Present, Partially present, Unsupported premise or Duplicate> |
## 8. Verification Defect Register and Limitations
| ID | Type | Affected reference | Resolution |
|---|---|---|---|
| VD-001 | <defect type, for example VD-PROMPT-INJECTION> | <document and locator> | <resolution> |
<limitations>
```

In the final document the finding IDs are assigned by severity, Critical first (`F-001` is never lower than `F-002`), the rows are in
ascending ID order, the Metric/Count rows equal the register row counts, the per-stage table equals the one `calibration`
prints, and `Outcome:` is the value the rule derives from the final tables (the validator recomputes it).
