# Models (advisory)

A host skill cannot pin a model. In the original scanner each agent was bound to a
model, a tier and, on one host, a reasoning-effort setting, and a script rewrote the
agent files from a table; that machinery is gone (`references/limitations.md`). When the
host lets the orchestrator choose the model of a subagent, follow these tiers. When it
does not, ignore this file and run everything on the session's model. Nothing here is
enforced, and no model id is named: the tiers are about what the work needs, and the
ids change faster than this file.

## Tiers

| Tier | What it is for | Who runs on it |
|---|---|---|
| **deep** | adversarial reasoning: hold a claim up and try to break it | the arbiter; the memory-safety and logic-flaws validators |
| **standard** | judgement over tool output: decide what a script cannot | the stage procedures (scope, extract, scout, review); the secret sweeper; the crypto-auth and hw-hardening validators |
| **light** | lookup and relay: match, cite and pass on, do not derive | the injection-input and other-hygiene validators; the stage 2 and 3 procedure |

## Roles

The assignment the pipeline was designed around. Effort is advisory in the same way as
the tier: on a host that exposes a reasoning-effort setting, use the column below; on
one that does not, a tier is a model and nothing else.

| Role | Preferred tier | Effort | Units | Notes |
|---|---|---|---|---|
| orchestrator, stage roles (`scope`, `extract`, `scout`, `review`) | standard | high | the session | mostly bookkeeping and judgement over tool output; it is the session's own model unless you spawn it |
| `triage` (stages 2–3) | standard or light | medium | the session | tool work; see the triage worker row |
| `triage-worker` | **standard, not light, when you can choose** | medium | one per batch | under the default `llm-triage` backend the worker's per-function verdict *is* the ranking, and a function it scores `none` is never validated. On one tree the `rules` backend ranked a known-vulnerable function 32nd against a cutoff of 12, while a strong model doing the per-function scoring put it 1st. A light model draws the bands cheaply and the measured result does not carry over as written; say which model drew them |
| `secret-sweeper` | standard | high | 1 | a read-and-classify task over a list a script already built |
| `validator` memory-safety, logic-flaws | deep | max | many | the high-volume categories where a wrong dismissal is the expensive error |
| `validator` crypto-auth, hw-hardening | standard | high | some | |
| `validator` injection-input, other-hygiene | light | medium | some | match a playbook and cite it |
| `arbiter` | deep | max | 1 (+1 return trip) | it sees a queue, not every finding; prefer summarized thinking if the host exposes the choice: this is the stage whose reasoning you most want to audit |
| inline mode (one context) | deep | max | the session | it carries every role; there is no cheaper agent to fall back to |

## Profiles, as prose

Three ways to move the dial; choose by what you are short of.

- **Volume onto the fast model.** The orchestrator's stages and the high-volume memory
  and logic validators go one tier down; the crypto-auth and hw-hardening validators
  move up to deep so that some judgement stays strong; the arbiter stays deep and now
  audits the memory and logic validators on a model that is not its own. Cheapest, with
  the least coverage per call.
- **Everything one step up.** The triage workers that rank the corpus and every light
  validator one tier up, the stage roles one tier up. Use it whenever the triage ranking
  has to be trusted.
- **One model everywhere.** Simplest, and the arbiter then shares every blind spot with
  the validators it audits. Say so in the run output.

## Rules

- **Arbiter on a different model family.** If the host lets you choose, run the arbiter
  on a different model family than the validators it audits, so one family's blind
  spots are not shared by both. If you cannot choose, say so in the run output. For the
  categories whose validator shares the arbiter's model, the audit is an independent
  context and a different prompt, not an independent model: read the arbiter's agreement
  rate on those categories with that discount applied (`references/tuning.md`, "The
  arbiter's independence"). An arbiter that agrees with essentially everything is a
  rubber stamp, and `verify_findings.py` reports the rate either way.
- **Record what ran.** When the host reports which model a subagent used, pass it as
  `review_run.py ingest <unit> --model <name>`. When it does not, the record says
  `unknown`. The summary prints what was recorded and never guesses.
- **Do not downgrade silently.** If a tier is unavailable, use the nearest stronger one,
  never a weaker one, and note the substitution.
- **A model name is not a pin.** The host may ignore the request. Treat the recorded
  model as what the host said, not as what you asked for.
- **The scoring cost is paid up front.** Stage 2 under `llm-triage` is linear in the
  whole corpus and was 57% of one measured run's input tokens, more than the validators
  and the arbiter put together (6,196 functions on a mid-size C repository). That is the
  reason a model fine-tuned for the four-way triage call belongs on the cheap end, and
  the reason the handshake prints an estimate before the first call. The estimate is a
  token-volume figure at reference prices: this skill knows no price of your model, so
  it prints none of its own.
