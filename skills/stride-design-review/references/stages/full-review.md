# Full review: Stage 1, Stage 2, sweep, verification, final report

Mode `full`: the whole method on one folder of design documents. This is the procedure; the judgement text is in
`references/roles/orchestrator.md` (read it first, with the files it lists under "Read first"). Run every command from the
workspace root. Below, `stride_run.py` stands for `python3 -I -B <skill folder>/scripts/stride_run.py` with the skill
folder's absolute path (if `python3` is not found, `python -I -B`, then `py -3 -I -B`). `next` and the other commands print
every follow-up command in full, so copy those rather than retyping.

**The run is done only when `stride_run.py finalize` prints `"done": true`**: `<runRoot>/final-review.md` then exists, has passed
`validate_report.py --kind final`, and the whole run folder has passed `validate_run.py`. Reading the documents yourself and
answering in the chat is not a review, and no request is too small for the procedure.

## 1. Gather the inputs

- `docsRoot`: the folder of design documents (the corpus), inside the workspace. It holds only what is to be reviewed: no
  `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, hidden tool folders, `.git`, `.env` files or keys. `init` refuses them and names them.
- `domainLens`: `protocol` (network or message protocols), `device-embedded` (devices, firmware, hardware), `cloud-saas`
  (cloud services, multi-tenant SaaS), `ml-ai` (machine-learning or AI systems), or `none`. Choose from the documents; ask the
  person only when you cannot tell.
- `runRoot`: a new folder for the run inside the workspace and outside `docsRoot` (for example `review-runs/<name>`). Everything
  the run produces lives there, and nothing else does.
- Optional: `--extraction-map FILE` for sources that are not plain text (PDF, office, image), `--baseline-report FILE` for a
  delta review of a changed corpus, `--fallback inline` to allow the explicit inline verification fallback,
  `--verification-mode standard`, `--max-queue N`.

## 2. Decide the dispatch mode once, and start the run

If the host has a tool that starts a subagent with its own context, the mode is `subagent`. Only if it has none, or the first
spawn failed, is it `inline` (`references/inline-mode.md`). Repository size, speed and cost are never reasons. Then:

```text
stride_run.py init --mode full --docs-root <docsRoot> --run-root <runRoot> --lens <domainLens> --dispatch <subagent|inline> --because "<the tool, or the missing tool / failed spawn>" --inherited <one instruction, memory or skill file your context loaded from outside this skill> [--inherited ...] --model <your model ID> --runtime <the host>
```

Pass `--inherited none` when nothing outside this skill is in your context. If the first spawn fails after a `subagent` init and
nothing has been recorded as a subagent yet, `stride_run.py mode inline --because "<the error>"` switches the run; modes are never
mixed. `init` prints the corpus digest, the source count and `next_action`, and ends with a SAY THIS block (the dispatch mode and
why, your inventory, the digest and the source count, the disclosure): say it, as written, before you dispatch anything.

If `init` refuses, say exactly what it printed and stop: the corpus is the person's, so you do not repair it.

## 3. Follow `next`

After every command run `stride_run.py next`. Its `next_action` is `dispatch` (units to run), `run` (a command), `write` (the final
report), `stop` (tell the person) or `done`. The steps below say what each means.

## 4. Stage 1 and Stage 2

For the unit `designer`:

1. `stride_run.py dispatch-prompt designer` prints the dispatch prompt. **Subagent mode:** start a subagent with that text,
   unchanged (`SKILL.md` prints the template), and wait until it has returned. **Inline:** `stride_run.py inline-unit designer`
   writes the unit's brief (the role file in full and the task) into the run folder and prints its path; read that file in full and
   perform the role yourself.
2. `stride_run.py dispatch-record designer <subagent|inline> [--model NAME]` once the unit has run. Give `--model` only when the
   host reported the model that ran that unit; otherwise leave it off (the record then says unknown).
3. When the role has written `<runRoot>/stage-1-review.md`: `stride_run.py accept-stage 1`. It runs the report validators and
   binds the report into the manifest, and prints `"done": false` (more stages follow). If it rejects the report it prints the
   exact diff and the regeneration command: dispatch the role again once with `dispatch-prompt designer --retry` (which carries
   the diff) and `accept-stage 1` again. A second rejection is terminal: tell the person. So is a corpus that is no longer the
   bound one: every command that accepts something checks the corpus digest first, fails the run closed on a mismatch and refuses.

Then the same for `gap`, with `accept-stage 2`. Stage 2 starts only after Stage 1 is accepted, and its role reconstructs the
corpus before it reads Stage 1 in detail.

## 5. The independent sweep

`accept-stage 2` has written `stage-3/sweep-input.json`: the covered records (without ratings) and the model chapters. Dispatch
the `sweep` unit the same way (`dispatch-prompt sweep`, `dispatch-record sweep ...` once it has returned). The sweep writes its
one JSON object to `inbox/sweep.json` in the run folder (step 0 prints the path), checks it with `sweep-record --check` (the dry run
of the ingest, which records nothing) and ends its message with the same object. Once the subagent has returned, the tool reads
the file:

```text
stride_run.py sweep-record --from-inbox
```

If the file is missing (the subagent had no file-writing tool), pass the reply it returned on standard input, unchanged (a quoted
heredoc keeps every character): `stride_run.py sweep-record <<'EOF'`, the reply, `EOF`. Inline, you are the sweep: run the dry run
(`sweep-record --check`, the object on standard input) first, then the same heredoc without `--check`.

The tool validates schema, quotes, digest and cap, ranks and numbers the candidates by the protocol's order and writes
`stage-3/sweep-result.json`. The sweep has one generation: a reply the tool refuses fails the run closed (the refused reply is
kept as `stage-3/sweep-rejected.json`), and no other sweep may be started. Tell the person; `next` then prints a `restart`
command that starts a new run from the accepted Stage 1 and Stage 2 reports, for the person to choose. A reply file that does not
validate when you record it from the inbox is first left alone (it may be a draft the sweep is still correcting): wait for the
subagent to return, then pass `--returned` to record it as final.

## 6. Freeze the queue

`stride_run.py freeze` builds `stage-3/issue-index.json` and the ledger and prints the published cost: `N` to `2N` delegated
verifier calls (plus up to `N` inline fallbacks when the envelope allows them); in an inline run, which delegates nothing, `N` to
`2N` verifier units performed inline in this context (plus up to `N` more under the explicit inline fallback; `issue-index.json` keeps
the protocol's field names `minimumDelegatedCalls` and `maximumDelegatedCalls` for these bounds). It ends with a SAY THIS block that
holds the bound: say it before you dispatch. A queue larger than `maxQueueSize` fails closed: the tool refuses and says so; never truncate.

## 7. Verify every item

1. `stride_run.py verify-request --all` persists the attempt-1 request of every pending item and opens its ledger entry. In an
   inline run it opens only the first waiting item: one context performs every unit, so the next item's blinded request is not
   written until you have recorded the one at hand. Run it again after each `verify-record`.
2. Dispatch **one fresh verifier per item**, the units of the stage together as one batch: `dispatch-prompt
   verifier/<queueKey>/1 verifier/<queueKey>/1 ...` (every unit in one call; each prompt comes under an `=== <unit> ===` header line
   that is not part of it). Each verifier is done when its subagent has returned, not when its reply file appears: run
   `dispatch-record verifier/<queueKey>/1 <subagent|inline>` for a unit after it returned. Inline, do the items one after another:
   `inline-unit verifier/<queueKey>/1` writes each item's brief (the blinded request and the verifier role file) and prints its path.
3. Pass each reply to the tool, one command per reply:

   ```text
   stride_run.py verify-record <queueKey> --from-inbox
   ```

   Each verifier wrote its reply to `inbox/verifier-<queueKey>-<attempt>.json` and ended its message with the same object; the
   tool reads the file, so nothing is retyped (the `record_reply` field of each unit in `next` is this command). Record a reply only
   after its subagent has returned: the verifier checks its file after it wrote it and may rewrite it, so a file that appears
   earlier may be a draft. (A file that does not validate is left alone, with nothing recorded, until you pass `--returned`; the
   rejection it then records spends the item's one retry.) If the file is missing (the subagent had no file-writing tool), pass the reply it returned on standard input:
   `stride_run.py verify-record <queueKey> <<'EOF'`, the reply, `EOF`. Paste it character for character: do not retype, trim or
   reword any part of it (coordinators did in three of seven first runs, and the tool cannot tell; if you did, say so in the
   report). Inline, you are the verifier: the heredoc, with the result you validated. A bare JSON object or one fenced `json`
   block both work. The tool validates schema, the severity/rubric pair and every quote,
   saves the reply exactly as received, and moves the ledger: accepted, or rejected with a defect code. A reply that answers a
   different unit is refused and nothing is recorded.
4. A unit that returned nothing (timeout, crash): `stride_run.py verify-record <queueKey> --no-reply --defect "<what happened>"`.
5. A retryable rejection (malformed or schema-invalid reply, `Blocked — invalid invocation`, a transient failure) owes one
   corrected attempt by a new verifier: `verify-request --all` opens attempt 2, and `dispatch-prompt verifier/<queueKey>/2 --retry`
   carries the defect; except after `invalid invocation` it tells the new verifier to verify afresh, without reading the first
   reply. There is never a third delegated attempt.
6. `Blocked — unreadable source` or a second rejection is terminal, unless the envelope has `verificationFallback: inline`: then
   the item waits (`next` says so) for you to verify it in your own context, recorded with
   `verify-record <queueKey> --inline` (the reply's `attempt` is `inline`), or to be given up with `--terminal`. A digest
   mismatch is always terminal.
7. Repeat `next` until no unit is open. A terminal item means the run cannot complete: report it and run
   `stride_run.py fail --because "<item and reason>"`. A reply file left in `inbox/` that no open unit expects (a verifier that
   rewrote its reply after it was recorded) is removed with `stride_run.py inbox --discard-stale`.

## 8. Adjudicate and write the final report

`stride_run.py queue` lists every item with its accepted verdict, severity and disposition; read the result files it names for the
evidence. Adjudicate as `references/roles/orchestrator.md` says (merge only on the same root cause, remediation and scope;
deterministic IDs; unified MI verdicts). `stride_run.py calibration` prints the §6.1 per-stage table counted from the ledger; copy
it. Write `<runRoot>/final-review.md` (the exact structure is in the role file) and nothing else in the run folder. Do not write a
source ID (`S1-nnn`, `S2-nnn`, `S3-nnn`) anywhere in it, prose included: the final report defines only its own IDs, and
`validate_report.py` rejects an ID that no register defines. Name an origin in prose ("the Stage 1 claim") or by the `F-` ID it was merged into.

## 9. Finalize and report

`stride_run.py finalize` validates the final report and the whole run. Fix the report in place on a rejection and run it again.
When it prints `"done": true` it ends with a SAY THIS block: the `Outcome:` line of chapter 0, the finding counts, where
`final-review.md` and the run folder are, the dispatch record (a unit that ran inline, or that was never recorded, is said
plainly), any reply note, the disclosure and the pointer to `references/limitations.md`. Say it, as written. Add no recommendation
beyond the report. (`stride_run.py summary` prints the same block at any time.)
