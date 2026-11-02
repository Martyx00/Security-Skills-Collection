# Stage 2 only: the independent adversarial gap review of a Stage 1 report

Mode `stage2`. Use it when the person already has a Stage 1 report of this corpus and wants the independent completeness review:
an independent reconstruction of the system, a crosswalk to Stage 1, omissions, overstated or false claims, and a verdict on every
Stage 1 missing-information item. Read `references/roles/gap.md` (and the files it lists) and `references/stages/full-review.md`
sections 1 to 4.

**The run is done only when `stride_run.py accept-stage 2` prints `"accepted": true` and `"done": true`**:
`<runRoot>/stage-2-gap-review.md` then exists, has passed `validate_report.py --kind stage2`, and the run folder has passed
`validate_run.py` (`"done": false` with a `fix` as `next_action` says what is wrong with the run folder).

```text
stride_run.py init --mode stage2 --docs-root <docsRoot> --run-root <runRoot> --stage1-report <the Stage 1 report> --lens <domainLens> --dispatch <subagent|inline> --because "<why>" --inherited <...> --model <your model ID>
stride_run.py dispatch-prompt gap
stride_run.py dispatch-record gap <subagent|inline> [--model NAME]
stride_run.py accept-stage 2
stride_run.py summary
```

On a rejection `accept-stage 2` prints the exact diff; regenerate once with `dispatch-prompt gap --retry` (inline: `inline-unit gap
--retry`, which writes the brief of the regeneration).

- `init` validates the Stage 1 report against this corpus before anything is written, copies it into the run folder as the
  immutable `stage-1-review.md` and records it as accepted. A report that does not carry this corpus's digest, or that does not
  validate, is refused with the diff: it belongs to another corpus or another version, and you do not repair it. Use the same
  `--lens` Stage 1 used.
- One unit, `gap`. The role reconstructs the corpus **before** it reads Stage 1 in detail. In inline mode that discipline is yours
  to keep (`references/inline-mode.md`), and a Stage 1 report you read earlier in the same context weakens it; the SAY THIS
  block of an inline run says so.
- The Stage 1 model ID is recorded as `external-unattested`.
- `accept-stage 2` ends with a SAY THIS block when it prints `"done": true`: say it. It gives the person
  `<runRoot>/stage-2-gap-review.md`, the dispatch record (for an inline run also the sentence about the reconstruction that
  nothing checks) and the pointer to `references/limitations.md`.
