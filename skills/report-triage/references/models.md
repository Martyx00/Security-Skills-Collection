# Models (advisory)

The universal skills cannot pin a model: that was a per-harness feature and it
is gone (see `limitations.md`). When the host lets the orchestrator choose the
model of a subagent, follow these tiers. When it does not, ignore this file and
run everything on the session's model. Nothing here is enforced.

## Tiers

| Tier | What it means | Typical use |
|---|---|---|
| **A** | the strongest reasoning model the host offers | arbiters and adjudicators; any unit whose mistake is not caught by a later check |
| **B** | a strong general model | the orchestrator, scouts, the two lenses |
| **C** | a fast, inexpensive model | mechanical extraction, summaries checked by a script; optionally the exploit lens at volume |

## Roles

The assignment the pipeline was designed around (the source ran two model
families: the stronger one for everything that decides, the other for the
orchestrator, the scouts and the two lenses). Effort is advisory in the same way
as the tier: use more of it for tier A roles when the host exposes a setting.

| Role | Preferred tier | Effort | Dispatches | Notes |
|---|---|---|---|---|
| orchestrator | B | high | 1 | mostly bookkeeping; it inherits the session's model |
| `scout` | B | high | 8 | breadth over depth: the accuracy comes from eight independent passes disagreeing. Tier A in the deep profile (`tuning.md`) |
| `val-code` | B | high | 0 to 1 | the named-symbol path and the remand target. Do not go below B: judging whether a near miss is the same code degrades into a confident wrong answer |
| `val-exploit` | B (C at volume) | high | 0 to 1 | more traversal than judgement; if you drop it to C, watch the arbiter's overturn rate on `not-reachable` and `no-callers` |
| `adjudicator` | A | max | one per region | the deepest judgement: is this the region, is the mechanism the described one |
| `refuter` | A | max | 6 + 3 | adversarial; resistance to a well-written argument is the first thing that degrades at lower effort |
| `hunter` | A | max | 5 | the last line against the expensive error, a wrong "not affected"; never the place to save a tier |
| `arbiter` | A | max | about 1 | it sees a queue, not every report. Prefer summarized thinking if the host exposes the choice: this is the stage whose reasoning you most want to audit |
| inline mode (one context) | A | max | 1 | it carries reproduction, impact and the self-check; there is no cheaper agent to fall back to |

## Rules

- **Arbiter on a different model family.** If the host lets you choose, run the
  arbiter on a different model family than the lenses and adjudicators it
  audits, so one family's blind spots are not shared by both. If you cannot
  choose, say so in the run output. An arbiter on the lenses' tier shares their
  blind spots and adds cost without signal.
- **Record what ran.** When the host reports which model a subagent used, record
  it with the dispatch record (`report.py dispatch-record <unit> <mode> --model
  <name>`). When it does not, the record says "unknown".
- **Do not downgrade silently.** If a tier is unavailable, use the nearest
  stronger one, never a weaker one, and note the substitution.
- **A model name is not a pin.** The host may ignore the request. Treat the
  recorded model as what the host said, not as what you asked for.
