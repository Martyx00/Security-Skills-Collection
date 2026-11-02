# Models (advisory)

A universal skill cannot pin a model: that was a per-harness feature and it is gone
(`limitations.md`). When the host lets the orchestrator choose the model of a
subagent, follow these tiers. When it does not, ignore this file and run everything
on the session's model. Nothing here is enforced.

| Tier | What it means | Typical use |
|---|---|---|
| **A** | the strongest reasoning model the host offers | the worker role: reading an IDE project or a linker map correctly is the hardest judgement of the run |
| **B** | a strong general model | the orchestrator, and the `usage`, `trace_build` and `hint` adjudications it answers itself |
| **C** | a fast, inexpensive model | nothing in this skill: do not use it for the worker, whose mistakes the review file shows to the person but cannot always catch |

- **Record what ran.** When the host says which model a subagent used, record it:
  `dispatch-record <unit> subagent --model NAME`. Otherwise the record says
  "unknown". The mode and the model are what the host reported, not something the
  script can check.
- **Do not downgrade silently.** If tier A is unavailable use the nearest stronger or
  equal model, never a weaker one, and say so.
- **Several workers at once.** `dispatch-prompt --stage worker` prints one prompt per
  repository still to do. Start at most four subagents at a time and wait for all of
  them; each subagent reads only its own repository.
- **A different family for the review is not available here**: the arbiter of the
  other skills has no counterpart. The person who edits the review file is the
  independent check on what the worker reports.
