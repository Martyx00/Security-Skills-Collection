# Roles

A role is a Markdown file in this folder that holds the instructions for one
kind of unit of work (a scout, an adjudicator, an arbiter, ...). Roles are
**files, not skills**: there is no `SKILL.md` below `references/`, and a role has
no frontmatter. The orchestrator in `SKILL.md` dispatches a role by *reference*:
a host subagent is told to read `references/roles/<role>.md`, or the orchestrator
reads it itself when the host has no subagents (`references/inline-mode.md`). The
fixed prompt for that is printed in `SKILL.md`.

## Index of roles

| Role file | Used for | Units | Reads the contract? | Tier (`references/models.md`) |
|---|---|---|---|---|
| `scout.md` | one search strategy, returns leads (never a verdict) | 8 per round: `<report_id>/scout/<strategy>` | yes | B |
| `adjudicator.md` | is the reported defect in THIS region? | one per region: `<report_id>/adjudicator/<n>` | yes | A |
| `refuter.md` | try to kill an established finding from one angle | 6 against `PRESENT`, 3 against `EXPLOITABLE` or `NOT_EXPLOITABLE`: `<report_id>/refuter/<lens>/<angle>` | yes | A |
| `hunter.md` | find what an earlier pass called absent, from one assumption | 5 on a would-be dismissal: `<report_id>/hunter/<angle>` | yes | A |
| `val-code.md` | the code lens: is the defect in this repository? (named-symbol path, remand target) | `<report_id>/val-code` | yes | B |
| `val-exploit.md` | the exploit lens: can it be reached, from a packet that withholds the report | `<report_id>/val-exploit` | yes | B |
| `arbiter.md` | re-derive the crux before reading the argument; audit absences and substitutions | `<report_id>/arbiter` | yes | A |

Every role reads `references/contract.md` first. No role is exempt.

## Lenses: why there is one file per role and no per-lens files

The scout has 8 strategies, the hunter 5 angles and the refuter 9. The
granularity rule asks for one role file plus per-lens files where roles share a
contract and differ only in domain, and these do share one contract, one budget
and one output schema each. They still get **no** per-lens files, because:

1. **The per-lens text already has one source of truth.** Each strategy's
   question and brief is a row of `STRATEGIES` in `scripts/report.py`, each hunter
   assumption a row of `CHALLENGE_ANGLES`, each refuter angle a row of
   `REFUTE_ANGLES`. `scoutpacket`, `challenge` and `refutepacket` write that row
   into the unit's packet. A per-lens file would be a second copy that drifts.
   Adding a lens is a table row, never a new file.
2. **The dispatch prompt is fixed and names only the role and the unit.** It
   cannot name a lens file. A per-lens file would need the role file to say
   "now open the file for the lens in your packet", one more step that a model
   can skip, with no error anywhere.
3. **What stays in the role file is short.** The hunter's five "take as given"
   rows and the refuter's two angle tables are a few lines each and are the
   human-facing counterpart of the packet's text.

## Rules for every role file

- Open with "read `references/contract.md` first" and the step-0 run-directory
  check (`contract.md` section 13). A role that fails step 0 refuses with one
  `REFUSED step 0:` line, and a role whose prompt names a run directory or a role
  file that does not exist refuses too: it never searches for one.
- Name every file the role may write. The dispatch prompt says "write only the
  files your role file names", so the list in the role file is the whole
  permission. Every role writes exactly one file: its reply, at the `replyFile`
  that step 0 prints (`<run dir>/reports/<report_id>/replies/<role>[.<qualifier>...].json`;
  the arbiter's is `arbitration/ARB-<report_id>.json`). Its chat reply is the one
  line `DELIVERED <unit id>`, and the orchestrator runs
  `report.py <lead|adjudication|hunt|refutation|finding> --unit <unit id>`, which
  reads the file. The orchestrator never receives, retypes or saves a reply, so no
  long analysis passes through the model that runs the pipeline. A role with no
  tool that can write a file replies with the JSON object itself and the
  orchestrator pipes it in, the old way.
- Say which run-directory files the role must not open. These were read-deny
  rules on agent profiles; they are conventions now (`references/limitations.md`).
- Harness-neutral wording: "your shell tool", "your file-reading tool". No
  product's tool names, no paths outside the skill folder or the run directory.
- A role never dispatches another role. Only the orchestrator dispatches.
