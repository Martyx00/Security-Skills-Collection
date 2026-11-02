# Stage 3 only: verify and finalize from a Stage 1 and a Stage 2 report

Mode `stage3`. Use it when the person already has a Stage 1 report and a Stage 2 report of the same corpus and wants Stage 3: the
independent sweep, one fresh verifier per issue, the ledger and the final report with its derived decision. The coordinator is the
`fact-checker` role: read `references/roles/fact-checker.md` (and the files it lists) and `references/stages/full-review.md`,
sections 1 to 3 and 5 to 9 (everything except the two stage dispatches). This file says what differs. Never dispatch the
`fact-checker` role: you perform it.

**The run is done only when `stride_run.py finalize` prints `"done": true`**: `<runRoot>/final-review.md` then exists, has passed
`validate_report.py --kind final`, and the run folder has passed `validate_run.py`.

```text
stride_run.py init --mode stage3 --docs-root <docsRoot> --run-root <runRoot> --stage1-report <Stage 1 report> --stage2-report <Stage 2 report> --lens <domainLens> --dispatch <subagent|inline> --because "<why>" --inherited <...> --model <your model ID>
stride_run.py next
```

then the sweep, `freeze`, `verify-request --all`, the verifiers, `queue`, `calibration`, the final report and `finalize`, exactly as in
`references/stages/full-review.md` sections 5 to 9.

- `init` validates both reports against this corpus before anything is written, copies them into the run folder as the immutable
  `stage-1-review.md` and `stage-2-gap-review.md`, records them as accepted and writes `stage-3/sweep-input.json`. A report that
  does not carry this corpus's digest, or that does not validate, is refused with the diff; you do not repair it.
- The Stage 1 and Stage 2 model IDs are recorded as `external-unattested`; never copy your own model ID into them.
- Use the same `--lens` the stages used; ask the person when you do not know it.
- The final report's chapter 1 states the dispatch block, the disclosure line, any reply note and the limitations pointer of
  `stride_run.py summary`. `finalize` ends with the SAY THIS block: say it.
