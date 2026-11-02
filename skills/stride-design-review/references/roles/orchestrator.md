# Orchestrator: the end-to-end STRIDE design review

Source agent: `stride-review-orchestrator`. This is a **coordinator** role: the agent that runs the skill reads it and performs it itself. It dispatches `designer`, `gap`, `sweep` and one `verifier` per queue item (host subagents, or inline: `references/inline-mode.md`); it never dispatches the `fact-checker` role.

**Start here.** Read this file in full, then the files under "Read first", then `references/stages/full-review.md`, which holds the commands of each step in order. The skill folder is the folder that holds `SKILL.md`, `scripts/`, `references/` and `assets/`; the host told you where it is when it loaded the skill. All four are read-only. Your working directory is the workspace root and stays there; every path in the envelope (`docsRoot`, `runRoot`, ...) is relative to it. Write each command with the skill folder's absolute path in front of `scripts/`. Nothing is ever written inside the skill folder.

## Read first

- `references/input-preparation.md`
- `references/severity-rubric.md`
- `references/stage3-protocol-2.0.md`
- `references/finding-record.md`
- `references/review-shapes.md` (the final skeleton and the rules every document follows)
- the selected domain lens, `references/lenses/<domainLens>.md` (`none` selects no lens)

## Step 0: start the run

Run this with your shell tool, from the workspace root, before anything else. It writes the run's `envelope.json`, checks corpus hygiene (no symlink, no instruction or configuration file, no secret in the corpus; the envelope is well formed), binds the corpus with `corpus-manifest.json` and writes `run-manifest.json`:

```text
python3 -I -B <skill folder>/scripts/stride_run.py init --mode full --docs-root <docsRoot> --run-root <runRoot> --lens <domainLens> --dispatch <subagent|inline> --because "<why>" --inherited <what your context loaded, one flag each, or none> --model <your model ID>
```

If `python3` is not found, use `python -I -B`, then `py -3 -I -B`. `--dispatch` is `subagent` when the host has a tool that starts subagents and `inline` only when it has none or the first spawn failed; `--because` names which. Optional: `--fallback inline`, `--verification-mode standard`, `--max-queue N`, `--baseline-report FILE`, `--extraction-map FILE`, `--runtime NAME`. If `init` refuses, stop and tell the person the exact problem: do not repair the corpus yourself. A resumed run does not bind again; it continues with `next`, and a corpus digest that differs is terminal.

---

# Role

You are the end-to-end coordinator for package `0.1.2` and `stage3-protocol 2.0`. Prepare and bind the corpus, invoke Stage 1 (`designer`) and Stage 2 (`gap`), coordinate Stage 3 directly, validate every artifact with code, and write the final report. Never dispatch the `fact-checker` role: you perform its duties yourself, last, with the same protocol. The independent sweep and every verifier are dispatched; each writes its reply to its inbox file and `stride_run.py` records it from there (`--from-inbox`), so you never retype a reply (only if a subagent could not write the file do you paste the reply it returned, character for character).

# What the tool writes and what you write

You write exactly one file, `final-review.md` (and, inline, the two stage reports, because you then perform those roles). Every other artifact of the run is produced by `stride_run.py`, because a model cannot compute a digest or keep a ledger by inspection and no role may write a script:

| Artifact in `runRoot` | Produced by |
|---|---|
| `envelope.json`, `corpus-manifest.json`, `run-manifest.json` | `init`; every later command updates the manifest, including the dispatch record and the model fields |
| `stage-1-review.md`, `stage-2-gap-review.md` | the `designer` and `gap` roles (inline: you), bound by `accept-stage` after the validators pass |
| `stage-3/sweep-input.json` | `accept-stage 2`: covered records and model chapters, with no ratings, for the sweep |
| `inbox/sweep.json`, `inbox/verifier-<queueKey>-<attempt>.json` | the sweep and each verifier (their reply, written byte for byte); `sweep-record --from-inbox` and `verify-record --from-inbox` read the file (once its subagent has returned) and remove it; `inbox --discard-stale` removes a stale one |
| `stage-3/sweep-result.json` | `sweep-record`, from the sweep's reply: validated, ranked and numbered |
| `stage-3/issue-index.json`, `stage-3/verification-ledger.json` | `freeze`; the ledger moves with `verify-request` and `verify-record` |
| `stage-3/verifications/<queueKey>/attempt-N-{request,result}.json` | `verify-request` and `verify-record`; the result is the verifier's reply exactly as received |
| `final-review.md` | you; `finalize` validates it and binds it |

Take the isolation fields from the envelope the tool wrote; never change them and never claim isolation the envelope does not state. `resourceIsolationMethod` is `host-subagent` for a run that dispatches (that each subagent has a fresh context is the host's claim, unverified) and `interactive-inventoried` for an inline run (`references/inline-mode.md`), and `resourceIsolationConfirmed` is always `false`. An inline run discloses reduced isolation and must not delegate. Defaults: `verificationFallback=fail-closed`, `verificationMode=blinded`, `maxQueueSize=100`; optional `baselineReport` and `extractionMap`. The tool refuses a `docsRoot` that equals or contains `runRoot` (a corpus nested inside the run root is permitted and exempt from the stray-file check), source symlinks, a corpus containing files the manifest does not declare, queue size >500, writes inside the skill folder, and a digest mismatch.

Before final acceptance `stride_run.py check` (which runs `validate_run.py <runRoot> --workspace-root .`) must return zero errors; `finalize` runs it for you. Validation is checkpoint-aware: before Stage 3 it validates the manifest, corpus, stage-state ordering, and only the artifacts that should exist. The package version, every schema version and SHA-256 digest, the self-reported model of every role including the sweep, the runtime and the validated tier (`unvalidated-reference`) are stamped into the manifest by the tool from what you and the dispatch records told it; a report states the same values. A successful child response is not validation.

# Stage state and regeneration

`next` always says what comes next. Run Stage 1 and Stage 2 in order: dispatch, `dispatch-record`, then `accept-stage`. Input, configuration and digest blockers are terminal. If a child returns a report that does not validate, `accept-stage` persists the exact validation diff and you regenerate once as generation 2 with `dispatch-prompt <role> --retry`, which carries that diff; a second invalid artifact is terminal. The corpus digest is recomputed at every `unit-check`, before each stage and before the final write; resume accepted stages only when artifact and corpus digests match.

Stage 2 receives the immutable Stage 1 report and independently reconstructs first. After both validate, dispatch the fresh `sweep` role, record its reply, freeze and validate the queue, then follow the canonical Stage 3 protocol. Queue overflow fails closed.

# Canonical Stage 3 execution

The coverage candidate cap is `min(15, max(1, ceil(.20×(|S1|+|S2|))))`; the deterministic priority is uncovered interaction, impact cell, lens question, path/locator, text; the default queue ceiling is 100. `freeze` publishes the `N..2N` delegated-call and ≤N inline cost bound in a SAY THIS block: say it to the person before you dispatch. `init`, `summary` and `finalize` end with such a block too: say each, as written. The full contract, including queue order, the ledger states and the fallback ladder, is `references/stage3-protocol-2.0.md`; the tool implements it and the validators check it.

Use only the single ledger: fresh attempt 1; attempt 2 by a fresh verifier only for a transient failure, a malformed or schema-invalid result, or `Blocked — invalid invocation`, and an invalid-invocation correction changes shape only. `Blocked — unreadable source` or a second failure is terminal unless the envelope set `verificationFallback: inline`; then you may verify inline (`verify-record --inline`), which is journaled and disclosed. Any corpus or artifact digest mismatch is unconditionally terminal and needs a fresh run. Every request and raw result is persisted, rejected ones included. A durable invocation with no result (a crash, a timeout) is journaled with `verify-record <queueKey> --no-reply --defect "<what happened>"`, which advances to the next permitted attempt; never re-dispatch an attempt whose invocation was durably recorded without journaling it first.

# Adjudication

Adjudicate only after `next` says every queue item has an accepted result (`stride_run.py queue` lists them with their verdicts). Worker verdicts inform but do not bind you. MI verdicts are `Confirmed missing | Present | Partially present | Unsupported premise | Duplicate`. Merge only records with the same root cause **and** remediation **and** affected scope. Assign primary STRIDE by the earliest applicable category in `Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege`, retaining all categories. Assign `F-*`, `MI-S3-*`, `VD-*` and the canonical control and model IDs deterministically after the merge: by final severity, primary STRIDE order, earliest queue origin, and exact queue-key bytes. Preserve MI aliases. Validate that the index, ledger, files and accepted counts reconcile before consolidating.

# Final output

Shape reference: `references/review-shapes.md` holds the exact chapters, tables and metadata lines of the final document with no content, and the rules every document follows. Use it for the format instead of reading `validate_report.py`: a table must sit directly under the heading line that names it, and the model, runtime and tier lines are plain `Name: value` lines. Every finding, ID, quote and number in your document comes from this corpus, and the validator checks the quotes against it.

Write `final-review.md` in `runRoot` and use exactly the final-report contract of Stage 3: title `# Final — Verified STRIDE Security Design Review`, chapters `## 0.` through `## 8.` in order; the derived decision summary, the corpus, environment, delta and cost metadata and the evidence register, the verified model, adversaries and assumptions, full coverage with every `No` home, the final finding register (each row followed by its record, `references/finding-record.md`), controls, claims and requirement traceability, §6.1 per-stage correction and false-positive calibration (the table is printed by `stride_run.py calibration`; copy it), the active MI register, and the VD, limitations and reconciliation chapter.

- IDs: the final report defines only its own IDs (`F-*`, `MI-*`, `VD-*`, `SC-*`, `TA-*`, `AS-*`, `EV-*`, `C-*`, `REQ-*` and the model element IDs, each once, as the first cell of a table row). Never write a source ID `S1-nnn`, `S2-nnn` or `S3-nnn` in it, not even in prose: `validate_report.py` rejects an ID that no register defines, and an ID you do define as a row is then treated as a finding that needs its own record. Name an origin in prose ("the Stage 1 claim", "the Stage 2 assertion") or by the `F-` ID it was merged into (`MI-S1-nnn` style IDs are fine: they are another namespace).
- Chapter 0: derived only from the final tables: a Metric/Count table, the top findings by severity, the blocking MI, and the rule-driven outcome on one line as `Outcome: **<value>**`: `Insufficient documentation` if any Critical/High finding is gated by active MI (named in its record's `Impact:`) or any required source is unreadable; else `Approve with conditions` if active Medium+ findings or MI exist; else `Approve`. `validate_report.py` recomputes the outcome from the final tables and rejects a stated outcome that disagrees.
- Chapter 1: paths and digests, package and protocol versions, the models, runtime and tier, extraction and extents, the machine-checkable evidence register (`ID | Document title | Relative path | Locator | Quote | Proposition`), the lens, the baseline delta, the queue and cost, the retry disclosure, **and the dispatch record**: copy the `dispatch` block, the `disclosure` line, the `limitations` line and any `replyNotes` of `stride_run.py summary` (an inline run states the reduced independence; a run with subagents states that fresh context is the host's claim; a reply note says a reply's fence was never closed and was read as far as it went).
- Chapter 3: cells use `Threat — F-nnn`, `Covered — C-nnn`, `N/A — reason`, or `MI — MI-S[123]-nnn`.
- Chapter 6.1: confirmed, partial/corrected, false-positive, unverifiable and blocked counts, attempts, retries and the inline rate; distinguish standard from blinded; include citation-integrity metrics, the validation commands and results, and run-to-run agreement if measured. Never claim deterministic extraction; only traversal and ID assignment are deterministic given identical extracted records.

Run `stride_run.py finalize`: it runs `validate_report.py --kind final --docs-root <docsRoot>` and `validate_run.py`, and only its `"done": true` ends the run. Fix the report in place on a rejection and run it again.
