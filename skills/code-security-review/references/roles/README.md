# Roles

A role is a Markdown file in this folder that holds the instructions for one kind of
work in the review: a stage procedure the orchestrator follows itself, or a unit of
work a subagent does in a fresh context. Roles are **files, not skills**: there is no
`SKILL.md` below `references/`, and a role has no frontmatter. The orchestrator in
`SKILL.md` dispatches a unit role by *reference* (a host subagent is told to read
`references/roles/<role>.md`, or the orchestrator reads it itself when the host has no
subagents: `references/inline-mode.md`). The fixed prompt for that is printed in
`SKILL.md` and by `review_run.py dispatch-prompt`.

## Index of roles

Two kinds, and the difference matters:

| Role file | Kind | Used for | Units | Reads first |
|---|---|---|---|---|
| `scope.md` | stage | stage 0: attack-surface map and a proposed scope (the person picks a profile) | none: the orchestrator follows it | `pipeline-contract-stage1.md` |
| `extract.md` | stage | stage 1: recon, manifest, snapshot, extraction, the secrets pass | none (dispatches `secret-sweeper`) | `contract.md`, `pipeline-contract-stage1.md` |
| `triage.md` | stage | stages 2 and 3: scoring, **the cut (the person picks)**, enrichment | none (dispatches `triage-worker`) | `pipeline-contract-stages.md` §6, §7 |
| `scout.md` | stage | stage 4: candidate gate, validator waves, arbitration, `REPORT.md`, report gate | none (dispatches `validator` and `arbiter`) | `pipeline-contract-stages.md` §7 |
| `review.md` | stage | stage 5: the person walks the findings; decisions into the ledger | none: the orchestrator follows it | `pipeline-contract-stage5.md` §8 |
| `secret-sweeper.md` | unit | judge `secrets/candidates.json`, write `secrets/inventory.json` | `secret-sweeper` | `pipeline-contract-stage1.md` §4a |
| `triage-worker.md` | unit | answer one `llm-triage` batch | `triage-worker/B-NNN` | its manifest |
| `validator.md` | unit | decide up to five candidates of one rule and one file | `validator/<category>/NNN`, `.../redo-<id>`, `.../manual-<id>` | `validator-contract.md`, then its domain file in `validator-domains/` (one level up), then `validator-reference.md` |
| `arbiter.md` | unit | audit the validators' verdicts; re-derive the crux first | `arbiter/S-NNN` (a slice of a long queue), `arbiter`, `arbiter/return` | `validator-contract.md`, `validator-reference.md` |

A **stage** role is followed by the orchestrator in its own context because it has a
stop for a person (the scope choice, the cut, the ledger review) or drives other
units. A **unit** role is the work of one subagent, or of the orchestrator inline.

The six validator domains are `references/validator-domains/{memory-safety,injection-input,
crypto-auth,other-hygiene,logic-flaws,hw-hardening}.md`: one file per rule family,
sharing the one validator contract. The unit id names the category, and `review_run.py
unit-task` names the domain file; the validator reads that one. The identifiers
`sec-val-<domain>` that appear in `precheck.json` and the arbitration summary are the
same six domains, kept as identifiers in the data. The single-candidate dispatcher of
the original design is `references/orchestrator.md` §4 (`review_run.py manual`).

## Why one validator role and six domain files

The six validators share one contract, one budget, one output schema and one verdict
vocabulary, and differ only in the rules they own. Merging them into one role file
would make a 150 KB prompt every validator reads six times over; six role files would
be six copies of the contract. So the role is one short file (how a unit starts, what
it writes, what it must not open) and the per-rule gates live in the domain file the
unit's task names. Adding a rule is a row in that domain file, never a new role.

## Rules for every unit role file

- Open with "read the contract first" and the step-0 command, `review_run.py
  unit-task <unit id> --root .`, which runs the run-directory check
  (`rules_lib.py --check-run-dir`) before it prints anything. A role that fails step 0
  refuses with one `REFUSED step 0:` line, and a role whose prompt names a run
  directory or a role file that does not exist refuses too: it never searches for one.
- Name every file the role may write. The dispatch prompt says "write only the files
  your role file names", so the list in the role file is the whole permission. Scratch
  (a long output you want to keep, a helper script) has one place, `.security-review/tmp/`,
  which a unit role says in its own words; it is not committed and is never evidence. A
  validator writes exactly one file, its reply; the sweeper writes the inventory; a
  triage worker its answers file; the arbiter its `ARB-*.json` records, `summary.json`
  and `cross-findings.md`. The chat reply is `DELIVERED <unit id>` (plus the short
  summary the sweeper and the arbiter owe), and the orchestrator runs
  `review_run.py ingest <unit id>`, which reads the file. A validator with no tool that
  can write a file replies with the JSON itself and the orchestrator pipes it in
  (`--stdin` is the validator's alone); the other unit roles reply `NOT WRITTEN: no
  file-writing tool`, and the orchestrator re-dispatches once and then records
  `--fallback`.
- Say which run-directory files the role must not open. These were read-deny rules on
  agent profiles; they are conventions now (`references/limitations.md`).
- Harness-neutral wording: "your shell tool", "your file-reading tool". No product's
  tool names, and no path outside the skill folder or the run directory.
- Every `rg` carries an explicit path operand (`.`, or the snapshot path): an `rg` with
  none searches standard input when the shell has one, and answers "no matches" without
  looking at the tree.
- A role never dispatches another role. Only the orchestrator dispatches.

## Rules for stage role files

A stage role opens with the same "start here" paragraph: the orchestrator follows it
in its own context, step 0 already ran with `review_run.py init`, and every script
repeats the check. Stage roles do not write replies; they run scripts and write the
few files the stage owns, and they stop where the person decides.
