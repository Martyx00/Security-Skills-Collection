# Tuning — models and cost

## The model setup, in one place

A host skill cannot pin a model, so there is no model file and no script that applies one:
`references/models.md` gives three advisory tiers (deep, standard, light) and says which role
prefers which, for a host that lets the orchestrator choose a subagent's model. On a host that
does not, everything runs on the session's model, and the rest of this page still applies; read
"the tier" below as "the model the unit ran on". The orchestrator records the model each unit
ran on when the host says (`review_run.py ingest --model`), and `review_run.py summary` prints
it.

| Tier | Give it the work whose failure is… | Roles |
|---|---|---|
| deep | a confident wrong answer — adversarial reasoning with no lookup table to fall back on | the arbiter; the memory-safety and logic-flaws validators |
| standard | a silent miss — judgement over tool output that biases the whole run and is not checkable afterwards | the stage procedures (scope, extract, scout, review); the secret sweeper; the crypto-auth and hw-hardening validators |
| light | cheap and visible — match, cite and pass on: lookup, relay, reading a tool's report | the stage 2–3 procedure; the injection-input and other-hygiene validators |

The triage worker is the exception: its per-function verdict is the ranking, so treat it as
standard work when you can choose (below). "Recommended tier by role" gives the reason for every
row above. Everything else in this file is why those three tiers are three and not one.

## Recommended tier by role

| Role | Tier | Why |
|---|---|---|
| arbiter | deep | The arbiter's value is entirely in the adversarial step — re-deriving the crux from source *before* reading the validator's argument. Anchoring resistance is the first thing to degrade when a judge model is rushed. It also sees the smallest volume (20–40% of findings, which are themselves a fraction of candidates), so this is the one place the strongest model is cheap. |
| validator, memory-safety | deep | Aliasing analysis for use-after-free, signed/unsigned and overflow reasoning, and the seven-question whole-function pass. This category punishes shallow reasoning with *confident wrong answers* rather than with "I don't know", which is the expensive failure. |
| validator, logic-flaws | deep | The hardest category by a distance. M1–M5 asks the model to state an invariant, enumerate every exit, and find an input that breaks it. There is no lookup table to fall back on. On an auth- or protocol-heavy codebase this is the right tier regardless of budget. |
| scope | standard | Pure judgement: reachability estimation, scoring, and deciding what is safe to defer. Runs once per repository and reads structure rather than file contents, so it costs little. |
| scout | standard | Discovery is not this agent's work: it runs no patterns and writes no candidate records. What is left is dispatch, carrying a remand intact, cross-finding correlation and the report — and the last two improve with a stronger model. The token volume sits in the validators rather than here. |
| extract | standard | Stage 1's tool does the counting. What is left is the part that fails silently: resolving which project functions stand in for `memcpy`, `snprintf`, `malloc` and `memcmp`. Miss `mbedtls_calloc` and every allocation rule in the run matches nothing while `coverage.json` records a true zero that reads downstream exactly like a codebase with no allocations in it. Entry-point selection is the other half, and it biases the whole ranking without being checkable afterwards. |
| triage | light | Stages 2 and 3 are tool work. The agent picks a backend, reads `scorer-report.json`'s downgrade reasons, and refuses to proceed when the extractor's `window` share says the corpus was not parsed well enough to rank. The exception is the `llm-triage` backend, where the model doing the per-function pass is its subagent — see the next row. |
| triage worker | light, or standard when you can choose | Answers one batch of `llm-triage` prompts: a four-way bucket call per function, over the whole corpus. On a large corpus this is the whole cost of stage 2, which is why it sits on the fast model — and it is also the operating point, which is why a stronger model there is the first thing to buy when the triage ranking has to be trusted (`references/models.md`). |
| review | standard | It is presenting an adjudicated finding to a person and recording what they decide. The failure mode is compression: summarising the arbiter's argument into something more confident than it was, or picking an `FP-*` code the reviewer did not choose. The volume is tiny — a few dozen findings, once. |
| validator, injection-input | light | Taint tracing is multi-step but mechanical, and the playbook supplies the sanitiser table and the bypass lists. |
| validator, hw-hardening | standard | Structural recognition is the easy half — is there a `default:`, is the loop count checked, behind a threat-model gate. The hard half is `HW-009`, which asks whether the value behind a non-constant-time comparison is one the attacker already holds. On a TLS library the light tier called public key names and certificate digests secret and the arbiter overturned every one, so this moved to standard. |
| validator, crypto-auth | standard | Most of it is table lookup — is this MD5, is `VERIFYPEER` zero, is the IV static — and used to sit on the light tier for that reason. `CRY-005` is not: deciding whether a comparison leaks anything needs the contract's relevance test, and on a TLS library the light tier raised three timing findings on values transmitted in cleartext, all overturned. Moved to standard. |
| validator, other-hygiene | light | Same shape: is the privilege-drop order right, is this RNG security-relevant. |

crypto-auth and hw-hardening were on the light tier and were moved out: a
measured run found that every one of the seven positives they produced between
them needed correcting, while both positives from the deep validators survived,
and the guidance they needed was already inlined in their prompts. That is a
capability limit, not a guidance gap. Split the tiers further if a category's
precheck output says you should.

### The knob that decides a run's cost is not in this file

It is `--budget` on stage 2, and it is worth saying plainly because everything
above is about model tiers and none of it is the biggest lever any more. Stage 2
records it in `operating-point.json` as `budget.max_adjudicated`, and stage 3
cuts the loose tier to it in rank order, deferring the rest to
`candidates/<category>-deferred.json`; the strict tier is never deferred.
`enrich_candidates.py --budget` overrides it for one stage-3 run.

Stage 1 costs one tool run over the tree — minutes, no tokens. Stage 2 with the
`rules` backend costs nothing in tokens either. Stage 3 is a tool. **Stage 4
costs roughly one validator conversation per BATCH of up to five queued
candidates sharing a `rule_id` and a file** (`references/roles/scout.md`'s isolation
rule), which on a measured tree made 504 candidates 142 calls, plus an
arbitration pass over 20–40% of the findings those produce. So:

```
run cost ≈ budget × (validator call) + 0.3 × budget × (arbiter call)
```

Under `llm-triage` the candidates include one `LOG-TRI` for each function the model
rated high that no rule matched, and they are in the row's `cumulative_candidates` (the
number `--budget` is set from) and in its calls, which the corpus table shows as
`incl. N LOG-TRI`. They are real validator calls on the deep logic-flaws tier, plus an
arbiter read of every one closed as "nothing here to protect" (`FP-NOT-SECURITY` is an
absence code). On a corpus where the model rates many functions high that no rule
matched they can be most of a row, so look at the figure before choosing.
`--no-triage-candidates` (on `score_functions.py`, and on `review_run.py cut --row <label>`)
takes them out of every row, and `--triage-candidates-max N` keeps the first N by rank, a
fixed order and not a judgement: both are part of the person's cut, and an opted-out
function is listed as selected without a candidate, unexamined. The `rules` backend
derives none.

`--budget 400` is the shipped default and a reasonable first run on an unfamiliar
tree is half that. Doubling the budget doubles the review; moving every validator
down a tier saves far less and costs you the categories that answer confidently
and wrongly when rushed.

**The arbiter's slice size is a time limit, not a cost knob.** A queue longer than 20 items is
cut into slice units (`review_run.py init --arbiter-slice N`, default 20) so that no unit runs
longer than a host lets a subagent run; one headless host stopped the single arbiter unit at
about twelve minutes. A slice costs a fresh read of the arbiter's role file and the contract
(about the size of one validator's), so a smaller slice is a few more reads, not a different
run. Lower `N` (10, say) if units are being stopped; raise it only on a host known to allow long
units, because a unit that is stopped costs its slice again from the records it had written.

Two caveats.

**The `llm-triage` backend breaks this arithmetic, and it is the default.** It
is one model judgement per *function*, not per candidate. Each batch of prompts
goes to a fresh triage worker whose context holds that batch alone, and
the handshake estimates ~3.3M input tokens on a 778-function tree and ~24M at
6,196 functions. Whatever the host bills (credits, a subscription, tokens), the handshake's
figures are a token-volume estimate at reference prices ($1.50 input, $0.15 cached, $3.50 output
per million: ~$2.50–$5 and ~$17–$39 on those two trees); it says that it used them and why,
because this skill knows no price of the model your subagents run on. Read the token volume
against your own plan. A stronger model for the workers costs more per token and changes
nothing about the volume.
On an 18,000-function corpus it is by an order of
magnitude the most expensive thing in the pipeline. One session
answering every batch itself would re-send the earlier ones on every turn —
~25M and ~181M on the same two trees — which is why it does not. Unlike stage 4 it is linear in the whole corpus rather than in the cut,
and it is spent before the operating point is chosen, so the operator cannot
shrink it after the fact.

It is the default anyway, because `rules` produces a bare ordering and on a real
tree `rules@1.0.0` made that a 245-function tie at the top — an operating point
chosen from it is arbitrary. llm-triage draws bands the model committed to, and
orders inside each band by the `rules` score, so a change to the rules weights
reorders llm-triage's bands from the inside as well.

The handshake quotes the figure before the first call. On a corpus large enough
for it to matter, decline and pass `--backend rules`: the ranking is worse but
the bill is zero. And whatever you choose, the band quality is the model running the
triage workers, not the backend — the measured rank-1 result came from a
strong model, and a fast model (or a small session model that the subagents inherit) draws
cheaper bands that the measured result does not describe.

**A bigger budget does not fix a bad ranking.** If the interesting findings are
not in the top 400 under the shipped scorer, they are probably not in the top 800
either, and the fix is the ranking — better wrapper resolution in stage 1, a
static analyzer joined in stage 3, or eventually a backend that was trained for
this — not more adjudication of the same ordering.

### The scoring backend, and what changes when the fine-tuned one arrives

The model of each role is advisory (`references/models.md`). The scoring backend is picked
separately, because it is not a model choice — it is a class in `scripts/scorers/` selected by
name, with its configuration in the file `--config` names (`assets/scorers.example.json` shows the
shape).

| backend | token cost | what it claims |
|---|---|---|
| `rules` | none | an ordering, and says so |
| `llm-triage` | one cheap judgement per function, a batch per subagent | an ordering, and says so — a verdict token from a general model is not calibrated |
| `finetuned` | one forward pass per function on your own endpoint | an ordering, **unless** a frozen evaluation set is registered for it |

The last row is the only one that can ever say `score_kind: "probability"`, and
it does not get to decide that for itself: `score_functions.py` checks that the
evaluation set exists under `assets/evalsets/`, that the set is a
calibration — `"kind": "calibration"`, a measured `base_rate`, at least one
operating point — that its `frozen_at` predates the run, that the corpus's
context profile is the one the backend was trained on and its context budget is
the one that profile defines, and that fewer than 10% of the corpus came back as
windows rather than parsed functions. Any of those failing downgrades the score
to an ordering and records the reason in `scorer-report.json`. There is no flag
that relaxes this, and adding one would be the single most damaging change
anybody could make to this skill.

When you do have an endpoint, the three things to get right are in
`scorers.example.json`: the `context_profile` must name the profile
`extract_functions.py` was run with, `verdict_tokens` must be the exact token
strings the model was trained to emit, and `evalset_id` must be the bare id (a
name, never a path) of a calibration file under `assets/evalsets/`
that was frozen *before* the feedback ledger started producing samples. That
last one is what keeps the flywheel honest — improvement measured on data the
loop never touched. A population such as `baseline-2026-09` is refused as a
calibration: it measured which advisories were reached, not a rate.

### The arbiter's independence, stated plainly

Ideally the arbiter shares a model with **no** validator: a model auditing
itself at the same depth shares its blind spots and adds cost without signal.
On a host that gives every subagent the session's model it shares one with all six, and with
the recommended tiers it still shares one with two of them: the memory-safety and logic-flaws
validators sit on the deep tier beside the arbiter, so on MEM and LOG the audit is an
independent *context* and a different *prompt*, not an independent model.

The mechanical half is unaffected — a fabricated citation is caught by
`verify_findings.py`, which uses no model at all — and the anti-anchoring
ordering still does real work. What weakens is agreement: validator and arbiter
concurring on a MEM or LOG finding means less than it does on the other four
categories. Read, and report, the dismissal-sample overturn rate on those two
with that discount applied.

Both halves of that discount are emitted rather than left to be re-derived. The number is in
`.security-review/arbitration/arbitration-precheck.json` under `summary.computed.per_category`,
written by the `--arbitration` run of `verify_findings.py` and echoed on its stdout: adjudicated,
upheld, overturned and calibration-sampled counts per category, so the categories that share the
arbiter's model can be read against the ones that do not. Which validators ran on which model is
what `review_run.py summary` records (the dispatch records carry the model when the host said
it); this script reads artifacts and cannot see it. Neither fails a run, and neither should: the
counts are counts and not a rate because the calibration sample split six ways leaves
denominators of one or two, and the one run measured here agreed with the validator on 100% of
MEM and LOG, which was the correct outcome — an agreement threshold set to catch this would have
failed it.

Restoring the property costs nothing structural, where the host lets you choose: run the two
deep validators on a different strong model than the arbiter's (`references/models.md`: the
arbiter on a different model family than the validators it audits). The "volume onto the fast
model" arrangement does the reverse on purpose: it moves those two validators to the standard
tier, onto another model than the arbiter's.

If your account has only one capable model, that is a real limit and no config
trick fixes it. Say so in the report rather than implying a review that did not
happen.

## Profiles

`references/models.md` describes three arrangements in prose (volume onto the fast model,
everything one step up, one model everywhere). There is no script that applies one: the
orchestrator chooses a subagent's model when it starts the unit, if the host lets it, and
records what the host reported.

| Arrangement | What it does | What you give up |
|---|---|---|
| volume onto the fast model | the stage procedures, the secret sweeper and the high-volume memory-safety and logic-flaws validators go one tier down; crypto-auth and hw-hardening move up to deep so that some judgement stays strong; the arbiter stays deep | the recon and wrapper resolution (the silent miss the standard tier exists to prevent) and the secret sweeper land on the fast model, where the light tier was measured calling public keys and certificate digests secret; the scout's cross-finding correlation is on the fast model; the two categories that answer confidently and wrongly when rushed lose the deep tier. Watch `arbitration/precheck.json`: climbing `vacuous_gate_basis` and `evidence_sink_only` counts mean the saving is being paid for in false positives you now triage by hand. The arbiter stays deep, because a cheap arbiter is a rubber stamp |
| everything one step up | the light tier on the standard model — every light validator and the triage workers' per-function scoring with it — and the standard tier on the deep model | cost. Also worth doing on a deep run: raise `--budget` (and choose a deeper operating point) in stage 2, and raise `SAMPLE_PERCENT` in `verify_findings.py` from 15 to 40 so more dismissals get audited — changing the "~15% sample" row of `references/roles/arbiter.md` §2 in the same edit, so the two stay equal |
| one model everywhere | the same strong model across all three tiers | the arbiter's independence on every category, not just two. The stage separation, the independent context per candidate and the mechanical citation checks all still work |

## Other knobs

- **`--no-triage-candidates` and `--triage-candidates-max N`** (stage 2, and `review_run.py
  cut`): leave the `LOG-TRI` candidates out of the cut, or keep the first N. Neither flag is
  passed by default (`LOG-TRI` is on under `llm-triage`): the candidates are the point of the
  pass. The choice is recorded in `operating-point.json` (`triage_candidates`) so stage 3 and
  the candidate gate agree with the rows. Pass a flag only when the person asked.
- **Wave size on validator dispatch** is 5 units by default (`review_run.py dispatch-prompt
  --stage validator --limit N`). Subagent calls issued in one turn can run side by side, so a wave
  of N costs about one validator run of wall clock rather than N, and at the shipped `--budget
  400` the serial alternative is hours. It is a knob rather than a fixed number because rate
  limits are per-account and cannot be read out of the skill: a wave that trips one turns the
  speedup into a queue of retries. Lower it when calls start coming back rate-limited, and raise
  it only against a measured account.
- **Context compaction.** The orchestrator holds the plan and every returned reply's summary, so
  it is the one context that will actually reach the host's limit on a large repository. The
  artifacts and `dispatch/` are the state: after a compaction, `review_run.py next` says where
  the run is, and nothing needs to be reconstructed from memory. A compacted candidate list has
  lost the `sink_text` strings the validators need; the units read them from `candidates/`, never
  from the conversation.
- **Long-running commands.** `build_graph.py` and `extract_functions.py` on a large tree, and a
  repository-wide `rg` sweep, run for minutes. A command that times out surfaces as a failed
  command, not as a wrong answer.

## Severity: the exposure ceiling and the step-downs

There is no switch for this, on purpose. Stage 3 computes an `exposure` object
and a severity ceiling on every candidate. `verify_findings.py` checks each
`VULNERABLE` rating against that ceiling, and no tool ever rewrites a rating to
fit it. The way past the ceiling is per finding: an override that cites the
line the ceiling missed, which the arbiter's gate reads back off the source.

It exists because of the zlib field test. Every confirmed finding was in
`contrib/`, whose README says "All files under this contrib directory are
UNSUPPORTED", and the root build compiles none of it. The pipeline shipped 2
high, 3 medium and 2 low. A person verified 1 medium, 4 low, 1 info and 1 false
positive. Run over the same tree (zlib 1.2.11), the ceiling puts minizip's
exported `zipRemoveExtraInfoBlock` and `unzReadCurrentFile` at medium
(`not-built`, `unsupported-marker`), and every `main()` under contrib/ and
examples/ at low. Over all 656 extracted functions, each read at its first
line: at the root, 157 of 159 are uncapped and the other two are zutil.c's
Turbo C allocators (`legacy-platform`, low); contrib/ has 140 at medium and 244
at low; examples/ (67) and test/ (46) are all at low.

| Reason | Applies when | Cap |
|---|---|---|
| `advisory-only` | `physical_attacker: false` stamped the `HW-*` hit | low |
| `disabled-guard` | an `#if 0` branch encloses the sink | info |
| `test-or-sample-path` | the first matching directory is a test, fuzz, bench, examples or docs name | low |
| `not-built` | no root build file names the file, its object or a directory above it whose own CMakeLists.txt reaches it | medium |
| `unsupported-marker` | the nearest README above the file (never a project root's) says the code is unsupported, unmaintained or untested | medium |
| `documented-insecure` | the file's comments above its first function, or that README, say the code is not secure, test-only or not for production | low |
| `not-built-internal` | not built, no core caller, no unread line, and not an exported API | low |
| `legacy-platform` | an `#if` on MSDOS, OS/2, VMS, Windows CE and the like encloses the sink | low |

The validator then lowers its rubric row one level for each step-down it cites
at a line it read: `not-built`, `no-production-callers`, `caller-parameter`,
`content-not-controlled` and `legacy-platform`. That closed set lives in
`verify_findings.py` (`STEP_DOWNS`) and validator-reference §6a. Adding a token
means editing both, plus the arbiter's Step D.

When the ceiling misfires, look at where it came from before you change it:

- **`not-built` on code your build does compile.** The check reads the root
  build files as text. A root `add_subdirectory()`, Automake `SUBDIRS` or Meson
  `subdir()` naming a directory above the file counts, and so does its object
  file under any build directory. A generated build file, a glob, a recursive
  `$(MAKE) -C dir`, or a Bazel package the root does not name does not. The
  fix per finding is an override citing that build line. If a layout is misread run after run,
  the tables are constants in `enrich_candidates.py`: `ROOT_BUILD_FILES`,
  `PATH_CLASS_BY_SEGMENT`, the two platform macro tables and `CEILING_CAPS`.
  Bump its `TOOL_VERSION` when you change them, because the records change.
  A root `add_subdirectory()` counts only as far as that directory's own
  `CMakeLists.txt` reaches the file, and `build_dead_ends` names where the
  chain stopped: `blank`, or `names-nothing`. The chain reads the project's
  own modules a bare `include()` names (`cmake/<Name>.cmake`, or a literal
  `CMAKE_MODULE_PATH` entry), takes `crypto/${m}.c` as the glob
  `crypto/*.c`, and reads a `list(TRANSFORM)` as reaching everything below
  it. A helper the chain calls is read by its `function()` or `macro()` in
  the root's or a parent directory's CMake files: one that builds a target
  settles by the sources, globs or lists its call hands over (OpenEXR's
  `openexr_define_library(... SOURCES ...)`), takes its call's words as
  stems when it compiles `${F}.c` (netCDF's `build_bin_test`), and reaches
  everything below when handed nothing (`add_component(lib)`), whatever
  else the directory builds. A command nothing read defines reaches
  everything below only in a directory with no target of its own. What
  still reads as not built: a file only a sibling directory compiles
  (mongo-c-driver's bundled zlib), a file below a nested dead end whose
  parent reaches it only through a variable glob, and a file only a helper
  defined where no chain reads compiles, called beside the directory's own
  `add_library()`. The override is the line that compiles it.
- **A contrib/ tree your project ships.** A path alone never caps. Only a
  README that disowns the code, or a root build that leaves it out, does.
- **`documented-insecure` on code you ship.** `insecure_marker` quotes the
  line that set it. A README bullet about one helper ("the `randombytes()` in
  `test_only_rng/` is for TESTING ONLY") caps everything the README sits
  above; the override is the build line that compiles the file into the
  library, or, in a tree with no root build file (Go, Python, Rust, npm), the
  marker line itself with a `why` naming what else it is about. On Mbed TLS
  the cap lands on psasim, the sample programs (whose README puts them
  outside the project's security process), mldsa-native's examples and two
  test helpers, and on no function the library compiles: the two test-hook
  headers in drivers/builtin that carry it define none. A marker with no
  noun for a subject ("This is ...", "They should not be used ...", "Do not
  use it ...", "Not for production") counts only where it opens a sentence:
  Go's net/http/cookiejar/jar.go:31 "useful for testing but it is not
  secure", a comment about another type, capped the whole cookie jar, and
  Poco's "Or disable monitoring (not recommended for production)" all of
  Poco::MongoDB, until it did. A clause whose subject is on the line above
  ("This driver is not as well tested ..." / "and is not intended for
  production use!", netCDF's H5FDhttp.c) is not read, and caps nothing.
- **A test tree the tables do not name.** Put it in the manifest's
  `test_tree_globs` at stage 1. The function is then `test` to the score, to
  the ceiling (`path_class_basis: test-tree-globs`) and to FP-TEST, and still
  reviewed; every FP-TEST dismissal only the glob bears out goes to the
  arbiter. Stage 1's own test file names (`self_test.c` matches `_test.`) cap
  the ceiling but do not bear an FP-TEST out on their own, except where the
  language's test runner uses them too: Go's `_test.go` and `testdata/`,
  pytest's `test_*.py`, jest's `*.test.js` and `__tests__/`, rspec's `spec/`.
  A directory the tables already name — `testing/`, a C `spec/` — takes no
  glob (its record's basis stays `segment`): Go's own `testing` package is
  one, so an FP-TEST there reaches the arbiter as `disqualifier_contradicted`.
- **`caller-parameter` on a library's data.** The bytes a library is handed to
  parse are `untrusted-data` whatever API delivers them. The arbiter re-derives
  `input_origin` independently for exactly this reason. A run where it keeps
  undoing the step-down is a validator playbook to fix, not an arbiter to
  loosen.

The arbitration gate's summary counts `severities_capped_by_ceiling` and the
claim audit's `confirmed`, `refuted`, `overstated` and `unsettled` results.
They are calibration signal, not gates.

## What to watch after the first run

The arbiter's summary is the feedback signal for all of this:

| Symptom | Likely cause | Fix |
|---|---|---|
| `citation_not_found` above ~5% | validator model too weak for the category | run that category's units on a stronger model |
| Many `vacuous_gate_basis` | validator model too weak for the category | run that category on a deeper model — MEM and LOG are already on the deepest tier, so there the fix is the playbook, not the tier |
| `dismissal_sample_overturn_rate` > 0.10 | validators giving up | run that category's units on a stronger model, starting with the cheapest move |
| `dismissal_sample_overturn_rate` 0.0 with `dismissal_sample_upper_95` above 0.10 | a sample too small to say anything: 0 of 5 bounds the rate only at 0.451 | read the bound, not the rate. It takes 29 clean draws to bound it under 0.10, so on a small pool the trigger is mostly silent whatever the validators are doing |
| Arbiter agrees with essentially everything | the tier split is not real | `computed.arbiter_agreement` in `arbitration-precheck.json` counts it. Widen the gap, or drop the arbiter from stage 4 and say the findings are unadjudicated. Expect it on MEM and LOG first — those two share the arbiter's model, so there is no gap left to be real, and on a host that gives every subagent the session's model, on every category |
| Many `severity_without_boundary`, `attacker_model_incomplete` or `test_path_confidence` | validators labelling a value `ATTACKER` by where it arrives from, and rating a same-uid process or a harness's own argv as a local attacker | contract §6's attacker paragraph is the text to sharpen; check first that the scanned scope is the product and not its test tooling |
| The stage procedures are slow and expensive but the findings are fine | orchestrator model stronger than it needs | run the session on a lighter model; the units' models are chosen separately |
| Many `severity_over_ceiling`, or a large `severities_capped_by_ceiling` | validators rating the rubric row and skipping the exposure step | the playbook's CONTRACT DIGEST bullet and reference §6a are the text to sharpen; first check that the ceilings are right (the section above) |
| `claim_audit` shows many `refuted` or `overstated` | validators describing mechanisms they did not read (the callee's body, the guard on a length) | run that validator on a stronger model; `impact_claim_unsourced` counts say whether it is the callee half |
