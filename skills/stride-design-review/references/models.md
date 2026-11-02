# Models (advisory)

A universal skill cannot pin a model: that was a per-harness feature of the source packages (profile `model` fields, a pin
tool, `models/*.json` assignments) and it is gone (see `limitations.md`). When the host lets you choose the model of a subagent,
follow these tiers. When it does not, ignore this file and run everything on the session's model. Nothing here is enforced, and
nothing here has been measured: the manifest's `validatedModelTier` stays `unvalidated-reference`.

Product names go stale, so this file names tiers. The sources' own guidance (Kiro-Design-Review and Vibe-Secure-Design-Reviewer
`docs/model-selection.md`, 2026-08/09) put the strongest available model on every role that runs once or twice, and the only
trade-off on the verifier.

## Tiers

| Tier | What it means |
|---|---|
| **A** | the strongest reasoning model the host offers |
| **B** | a strong general model, a step below A |
| **C** | a fast, inexpensive model; not used for any role here |

## Roles

| Role | Calls per run | Preferred tier | Notes |
|---|---|---|---|
| `designer` (Stage 1) | 1, at most 2 (one regeneration) | A | The originator: every later stage is measured against it |
| `gap` (Stage 2) | 1, at most 2 | A | Its product is disagreement with Stage 1 |
| `sweep` | exactly 1 | A | One generation; a bad reply cannot be repeated |
| `verifier` | `N` to `2N`, `N` the queue size (default cap 100) | B, or A if the budget allows | The only role whose call count scales with the review, so the only one where cost pressure bites. In the sources' accounting it is about 85 to 90 percent of a run's spend |
| `orchestrator`, `fact-checker` | one long-lived context, plus up to `N` inline fallbacks | A | You, the agent that runs the skill |

## Rules

- **The verifier on a different model family than the originator, if the host lets you choose.** Stage 2's product is
  disagreement with Stage 1, and the verifier adjudicates both. A checker that shares the originator's family prior is the least
  likely to catch a family-level blind spot, so the source packages shipped a split-verifier assignment (originator and
  coordinator on one family, the verifier on another) as their default. The independence is already structural (a fresh
  verifier per item, a blinded request, byte-checked quotes); a second family adds decorrelation on top, and nothing here
  establishes how much. A verifier from a family with a weaker indirect-prompt-injection record is the predicted failure mode:
  the corpus is untrusted and the fixtures plant reviewer-directed text. If you cannot choose, say so in the run output.
- **Do not trade down the one-call roles.** Four of the five roles are one or two calls per run, so a cheaper model saves almost
  nothing and risks failures no validator catches (a shallow model, a missed interaction, an overstated control).
- **Record what ran.** Pass `--model NAME` to `dispatch-record` when the host says which model ran a unit; the manifest's
  `environment.stage1Model`, `stage2Model`, `sweepModel` and `verifierModel` follow those records (`mixed: a, b` when a role ran
  on several), `coordinatorModel` is what you gave `init --model`, and a unit with no model is `unknown`. The values are
  self-reported strings, not proof of which weights served the request: a host can route or fall back without telling you.
- **A Stage 1 or Stage 2 report you did not produce** carries `external-unattested` for its model; never copy your own ID into it.
- **Do not downgrade silently.** If a tier is unavailable, use the nearest stronger one, never a weaker one, and note the
  substitution.
- **Reasoning effort** is advisory in the same way: use more for tier A roles when the host exposes a setting. The manifest's
  optional `environment.reasoningEffort` is not written by the tool; a `measured` tier would need it.
- **A free or constrained plan** can run the method, but a run on a model that cannot hold the corpus and a queue item at once is
  a methodology exercise, not a reliable review. Disclose it.
