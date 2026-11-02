# Reported issue record — canonical contract

Every issue this package reports uses the same record, whatever stage discovered it. This is the one copy of the contract: the `designer`, `gap`, `orchestrator` and `fact-checker` role files list it under "Read first" and do not repeat it.

## Reported issue record

Each active register row is followed by one record, headed `### <ID> — <title>` with an em
dash and a short title, containing exactly these four labelled sections in this order:

- `**From specification:**` — a bullet list of facts taken from the corpus, each tagged
  `Supports:` or `Contradicts:` according to the direction in which it bears on the issue,
  and each citing at least one evidence ID that resolves in this report's evidence register.
  At least one bullet of each tag is required, so a record always states what argues against
  the issue as well as what argues for it. When the corpus genuinely supplies no contradicting
  fact, write exactly `Contradicts: None identified — <scope searched>`; never invent a
  mitigating fact, and never omit the tag.
- `**Issue:**` — what the issue is and why it exists, stated on the label's own line.
- `**Impact:**` — the consequence of successful exploitation, consistent with the impact-only
  `SR-*` cell and naming any MI that gates the bound.
- `**Recommendation:**` — a brief, high-level direction for addressing it.

Documented controls, authorization scopes, rate limits, and similar mitigations are
`Contradicts:` facts: cite them rather than leaving severity to imply them. A control that
caps consequence belongs in the record and in the severity rationale both.

`scripts/validate_report.py` enforces the heading, the four labels and their order, one record
per active finding, the bullet tags, the presence of both directions, and evidence resolution.
