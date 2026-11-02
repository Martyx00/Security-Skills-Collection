# Verify one issue

Mode `verify-one`. Use it when the person wants one issue of a STRIDE review checked against the corpus: "is S1-004 real", "verify
this finding", "does the spec really say that". It runs the `verifier` role once on one blinded issue record and returns a
validated verifier result. Read `references/roles/verifier.md` and `references/stage3-protocol-2.0.md`.

**The run is done only when `stride_run.py verify-record` prints `"outcome": "accepted"` and `"done": true`**: the verifier result
then exists in the run folder, schema-valid, with every quote checked byte for byte against the corpus, and the run folder has
passed `validate_run.py`. A verdict you reasoned out yourself in the
chat is not a verification.

```text
stride_run.py init --mode verify-one --docs-root <docsRoot> --run-root <runRoot> --issue-report <report> --issue-id <S1-004 or S2-002> --lens <domainLens> --dispatch <subagent|inline> --because "<why>" --inherited <...> --model <your model ID>
stride_run.py dispatch-prompt verifier/<issueId>/1
stride_run.py dispatch-record verifier/<issueId>/1 <subagent|inline> [--model NAME]
stride_run.py verify-record <issueId> --from-inbox       # the reply file the verifier wrote (step 0 prints its path), once its subagent has returned
stride_run.py verify-record <issueId> <<'EOF'            # only when the file is missing: the reply it returned, exactly as received
<the verifier's reply, exactly as received>
EOF
stride_run.py summary
```

- Run `dispatch-record` and `verify-record` after the verifier's subagent has returned: a reply file that exists earlier may be a
  draft (a file that does not validate is left alone until you pass `--returned`).
- The issue comes from a row of a Stage 1 or Stage 2 report (`--issue-report`, `--issue-id`) or from a blinded issue record the
  person supplies (`--issue-file`: claim, scope, source locators and exact source quotes as JSON; its ID is then `S3-001`). The
  tool projects the row into the blinded record (claim, scope, locators, quotes; no prior verdict, severity or confidence) and
  writes the attempt-1 request. The report must carry this corpus's digest and validate; it is read where it is and not copied.
- There is no queue, no ledger and no final report. A retryable rejection (malformed or schema-invalid reply, `Blocked — invalid
  invocation`, a transient failure) owes one corrected attempt by a new verifier (`dispatch-prompt verifier/<issueId>/2 --retry`);
  a second failure fails closed. A `Blocked` result is never an answer.
- `verify-record` ends with a SAY THIS block when it prints `"done": true` (the verdict, the severity, the dispatch record, any reply
  note and the pointer to `references/limitations.md`): say it. Then give the person the corrected claim if any, the rubric cell, the
  evidence (each with its exact quote and locator) and the path of the result file. A verifier that ran inline is not independent of
  you. Inline, `inline-unit verifier/<issueId>/1` writes the brief (the blinded request and the role file) and prints its path.
