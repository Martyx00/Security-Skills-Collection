# Stage 1 only: the documented model and the comprehensive STRIDE review

Mode `stage1`. Use it when the person wants only the first stage: the documented system model, the adversaries and assumptions,
the STRIDE coverage and the findings, without the independent gap review or the verification. Read
`references/roles/designer.md` (and the files it lists) and `references/stages/full-review.md` sections 1 to 4, which hold the
commands; this file says what differs.

**The run is done only when `stride_run.py accept-stage 1` prints `"accepted": true` and `"done": true`**: `<runRoot>/stage-1-review.md`
then exists, has passed `validate_report.py --kind stage1` against the digest-bound corpus, and the run folder has passed
`validate_run.py` (`"done": false` with a `fix` as `next_action` says what is wrong with the run folder). Reading the documents and describing the
threats in the chat is not this review.

```text
stride_run.py init --mode stage1 --docs-root <docsRoot> --run-root <runRoot> --lens <domainLens> --dispatch <subagent|inline> --because "<why>" --inherited <...> --model <your model ID>
stride_run.py dispatch-prompt designer
stride_run.py dispatch-record designer <subagent|inline> [--model NAME]
stride_run.py accept-stage 1
stride_run.py summary
```

`dispatch-prompt designer` prints the prompt: hand it unchanged to a subagent, or, inline, run `inline-unit designer`, read the brief
file it writes (the role file in full and the task) and perform the role yourself. On a rejection `accept-stage 1` prints the exact diff; regenerate once with `dispatch-prompt designer --retry`.

- One unit, `designer`. There is no sweep, queue or ledger, and no `final-review.md`.
- `accept-stage 1` ends with a SAY THIS block when it prints `"done": true`: say it. It gives the person
  `<runRoot>/stage-1-review.md`, the sentence that this review has not been independently checked (the gap review and the
  per-issue verification are what test it), the dispatch record (in inline mode the reduced-independence disclosure of
  `references/inline-mode.md`) and the pointer to `references/limitations.md`.
- The report is the Stage 1 input of a later `stage2` or `stage3` request: keep the run folder, or give the report file to
  `init --stage1-report`.
