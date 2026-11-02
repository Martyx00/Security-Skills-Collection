# Fact-checker: the standalone Stage 3 coordinator and finalizer

Source agent: `stride-fact-checker`. This is a **coordinator** role: the agent that runs the skill reads it and performs it itself, and never dispatches it as a subagent. Use it when the person already has a validated Stage 1 and Stage 2 report and wants Stage 3 only (verify the queue, finalize). In a full run the orchestrator (`references/roles/orchestrator.md`) performs these duties itself, last, with the same protocol, and never dispatches this role.

**Start here.** Read this file in full, then the files under "Read first", then `references/stages/stage3-finalize.md`, which holds the commands of each step in order. The skill folder is the folder that holds `SKILL.md`, `scripts/`, `references/` and `assets/`; the host told you where it is when it loaded the skill. All four are read-only. Your working directory is the workspace root and stays there; every path in the envelope (`docsRoot`, `runRoot`, ...) is relative to it. Write each command with the skill folder's absolute path in front of `scripts/`. Nothing is ever written inside the skill folder.

## Read first

- `references/input-preparation.md`
- `references/severity-rubric.md`
- `references/stage3-protocol-2.0.md`
- `references/finding-record.md`
- `references/review-shapes.md` (the final skeleton and the rules every document follows)
- the selected domain lens, `references/lenses/<domainLens>.md` (`none` selects no lens)

## Step 0: start the run

Run this with your shell tool, from the workspace root, before anything else. It checks corpus hygiene (no symlink, no instruction or configuration file, no secret in the corpus; the envelope is well formed), binds the corpus, validates the two reports you were given against it, copies them into the run folder as the immutable Stage 1 and Stage 2 inputs, and writes `envelope.json` and `run-manifest.json`:

```text
python3 -I -B <skill folder>/scripts/stride_run.py init --mode stage3 --docs-root <docsRoot> --run-root <runRoot> --stage1-report <stage1Report> --stage2-report <stage2Report> --lens <domainLens> --dispatch <subagent|inline> --because "<why>" --inherited <what your context loaded, one flag each, or none> --model <your model ID>
```

If `python3` is not found, use `python -I -B`, then `py -3 -I -B`. Optional: `--fallback inline`, `--verification-mode standard` (the default is blinded), `--max-queue N` (default 100, maximum 500), `--baseline-report FILE`, `--extraction-map FILE`, `--runtime NAME`. If `init` refuses, stop with the exact problem; the Stage 1 and Stage 2 inputs are immutable and are never repaired here, and a report that does not carry this corpus's digest belongs to another corpus. A resumed run continues with `next`.

---

# Role

You are the standalone Stage 3 coordinator/finalizer for package `0.1.2` and `stage3-protocol 2.0`. Validate two immutable prior reports against the digest-bound corpus, coordinate fresh read-only verification, and emit the final auditable report. Never modify the corpus, the package or the prior reports.

# Run and isolation records

The package version, every schema version and SHA-256 digest, the self-reported coordinator, sweep and verifier models, the runtime and the validated model tier are recorded in `run-manifest.json` by `stride_run.py` and must agree with every report. The only model tier this package claims is `unvalidated-reference`; do not imply measured model quality. The Stage 1 and Stage 2 model IDs of reports you did not produce are `external-unattested` unless the person tells you the upstream IDs; never copy your own model ID into those fields.

The envelope records how this run is isolated: `resourceIsolationMethod` is `host-subagent` (the sweep and the verifiers run as subagents the host starts; that each has a fresh context is the host's claim, unverified) or `interactive-inventoried` (you verify every item yourself, serially, in your own context, because the host has no subagent tool: `references/inline-mode.md`); `resourceIsolationConfirmed` is always `false`, and `inheritedResources` is your inventory of what your own context loaded. Never change them and never claim isolation the envelope does not state. An inline run discloses reduced isolation and must not delegate. Optional inputs: `domainLens` (default `none`), `verificationFallback` (`fail-closed|inline`, default fail-closed), `verificationMode` (`standard|blinded`, default blinded), `maxQueueSize` (default 100, maximum 500) and `baselineReport`.

# Canonical protocol and validation

Use the single ledger, recovery ladder, ordering, cap, cost, merge, MI, blinded, and reconciliation rules of `references/stage3-protocol-2.0.md`; the tool implements them and the validators check them. Recompute the corpus digest at every checkpoint (every `unit-check` does). Model inspection never substitutes for code validation: `stride_run.py` runs `corpus_manifest.py --verify`, JSON schema validation for the manifest, index, ledger and results, exact quote validation, and the final Markdown validation with `validate_report.py` and `validate_run.py`. Every required SHA-256 is computed by `digest.py` through the tool, never asserted; `stride_run.py check` reports validator digest errors with the recomputed value, so converge on it instead of guessing.

Resume a compatible run folder only after `stride_run.py check` returns zero errors for the ledger, index, request, result and artifact reconciliation. The Stage 1 and Stage 2 inputs are immutable; if their report validator fails, `init` stops with the exact diff. The queue freezes after a fresh `sweep` role (`references/roles/sweep.md`). Queue overflow fails closed. Every request and raw result is persisted, rejected attempts included.

## Queue and recovery summary

The queue is S1 and S2 plus a bounded sweep S3; the cap is `min(15, max(1, ceil(.20×(|S1|+|S2|))))`, the priority is deterministic, the default `maxQueueSize` is 100, and the cost is `N..2N` delegated calls and ≤N inline. Both coordinators use `stage-3/verification-ledger.json`. For each item: a fresh attempt 1; one fresh attempt 2 only for a transient failure, a malformed or schema-invalid result, or an invalid-invocation result (`verify-record <queueKey> --no-reply --defect "<what happened>"` journals a crashed or timed-out unit); `Blocked — unreadable source` or a second failure is terminal unless the explicit inline fallback is on (`verify-record --inline`). Any corpus or artifact digest mismatch is unconditionally terminal and needs a fresh run. Every request and raw result is persisted, including rejected attempts.

Adjudicate only after `next` says every queue item has an accepted result (`stride_run.py queue` lists them). MI outcomes are `Confirmed missing | Present | Partially present | Unsupported premise | Duplicate`. Merge only same root cause **and** remediation **and** affected scope. Assign `F-*`, `MI-S3-*`, `VD-*`, canonical controls and model IDs deterministically by final severity, primary STRIDE order, earliest queue origin and exact queue-key bytes. Preserve MI aliases.

# Final report

Shape reference: `references/review-shapes.md` holds the exact chapters, tables and metadata lines of the final document with no content, and the rules every document follows. Use it for the format instead of reading `validate_report.py`: a table must sit directly under the heading line that names it, and the model, runtime and tier lines are plain `Name: value` lines. Every finding, ID, quote and number in your document comes from this corpus, and the validator checks the quotes against it.

Write `final-review.md` in `runRoot` with exactly the structure below, then run `stride_run.py finalize`: it runs `validate_report.py --kind final` and `validate_run.py`, and only its `"done": true` ends the run.

# Final — Verified STRIDE Security Design Review
## 0. Decision Summary
Derived only from final tables: a Metric/Count table, the top N by severity, the blocking MI, and the rule-driven outcome stated on one line as `Outcome: **<value>**`: `Insufficient documentation` if any Critical/High finding is gated by active MI (named in its record's `Impact:`) or any required source is unreadable; else `Approve with conditions` if active Medium+ findings/MI exist; else `Approve`. `validate_report.py` recomputes the outcome from the final tables and rejects a stated outcome that disagrees.
## 1. Inputs, Environment, and Corpus Integrity
Paths/digests, package/protocol/models/runtime/tier, extraction/extents, machine-checkable evidence register (`ID | Document title | Relative path | Locator | Quote | Proposition`), lens, baseline delta, queue/cost and retry disclosure, and the dispatch record (copy the `dispatch` block, the `disclosure` line, the `limitations` line and any `replyNotes` of `stride_run.py summary`).
## 2. Verified Model, Adversaries, and Assumptions
Canonical model plus `TA-*`, `AS-*`, claims, requirements, and mappings.
## 3. Verified STRIDE Coverage
Applicability matrix with every `No` rationale/home, interactions, lens questions; cells use `Threat — F-nnn`, `Covered — C-nnn`, `N/A — reason`, or `MI — MI-S[123]-nnn`.
## 4. Final Finding Register
One active row per `F-*`, complete evidence/quotes, actor, scope, severity/rubric, confidence, controls, requirements, acceptance criteria, and origin reconciliation (name an origin in prose, "the Stage 1 claim", never by its `S1-nnn`, `S2-nnn` or `S3-nnn` ID: no register of the final report defines those IDs and the validator rejects them). Each row is followed by its record, as `references/finding-record.md` defines it.
## 5. Control, Claim, and Requirement Traceability
Control support/limitations; claim corrections; requirement→`covered|violated|undetermined`→F/MI.
## 6. Verification and Calibration
### 6.1 Per-stage correction and false-positive rates
Publish confirmed, partial/corrected, false-positive, unverifiable, blocked, attempts, retries, inline rate; distinguish standard/blinded. The per-stage table is printed by `stride_run.py calibration`; copy it.
Include citation-integrity metrics, validation commands/results, and run-to-run agreement if measured. Never claim deterministic extraction; only traversal/ID assignment is deterministic given identical extracted records.
## 7. Missing Information Register
Exactly one active row per `MI-S1|S2|S3-*`, unified verdict/reconciliation, aliases, blockers, searches, quotes, and disposition.
## 8. Verification Defect Register and Limitations
One row per `VD-*`, including prompt injection and unreadable/chunk limitations; ledger/digest reconciliation and late observations.
