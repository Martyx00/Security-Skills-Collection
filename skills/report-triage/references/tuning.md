# Tuning

Which dials exist, what they cost, and how to tell whether they are set right.

**Where the dials live.** Most are constants in `scripts/report.py` and
`scripts/verify_findings.py`, and the role files and `references/contract.md`
hold the rest. The skill folder is read-only while a run is in progress and, in a
global install, shared by every project on the machine, so a dial is changed
deliberately and outside a run: edit a project-level install of the skill (or a
fork of this repository) and re-run `scripts/selftest.py`. Never edit the scripts
mid-run, and never from a run's own tooling.

---

## 1. Models and effort (advisory)

A plain skill cannot pin a model or a reasoning effort: the host decides, and the
only lever is what the orchestrator asks the host for when it starts a subagent
(`references/models.md` has the tiers and the rules). The allocation the pipeline
was designed around, in tiers rather than product names:

| role | tier | effort | dispatches | why |
|---|---|---|---|---|
| orchestrator | B | high | 1 | mostly bookkeeping; inherits the session |
| `scout` | B | high | 8 | breadth, not depth — the accuracy comes from eight of them disagreeing |
| `val-code` | B | high | 0–1 | the named-symbol path; superseded by the adjudicators on a survey report |
| `val-exploit` | B | high | 0–1 | reachability is more traversal than judgement |
| `adjudicator` | A | max | N | the deepest judgement here: is this the region, and is the mechanism the described one |
| `refuter` | A | max | 6 + 3 | adversarial; six angles against the code finding, three more against the exploit verdict |
| `hunter` | A | max | 5 | last line against the expensive error |
| `arbiter` | A | max | ~1 | the adversarial half |
| inline mode (one context) | A | max | 1 | carries reproduction, impact and the self-check itself; there is no cheaper agent to fall back to |

The allocation is deliberate and is the first thing to argue with. Scouts are
searching — traversal work where eight independent passes beat one clever one, so
they take the cheaper tier and the parallelism buys the accuracy. Everything that
*decides* something runs at the top tier, because those are the stages where a
shallow pass produces a confident wrong answer rather than no answer.

`val-exploit` sharing a tier with `val-code` is a cost choice, not a finding. The
code lens needs the tier: deciding whether a near miss is the same code, and
whether a described mechanism is the one in the tree, is judgement that degrades
badly at low effort into a confident wrong answer. Reachability work is more
traversal than judgement and would probably survive a tier down (tier C). If you
run this at volume, that is the first thing to change; watch the arbiter's
overturn rate on `not-reachable` and `no-callers` grounds, and if it climbs, put
it back.

None of this is enforced. A host that offers no choice runs every role on the
session's model, and `report.py summary` prints which model each unit used when it
was recorded (`dispatch-record --model`).

## 2. Profiles

### Budget — a busy inbox, or a first look

- the `val-exploit` role → tier C at medium effort, where the host allows it.
- `SAMPLE_PERCENT` in `verify_findings.py` → `5`.
- Skip the exploit lens entirely for anything the code lens rates below `high`,
  and record `AFFECTED_EXPLOITABILITY_UNKNOWN`. That is an honest verdict and it
  is often all a triage queue needs to route the ticket.

### Deep — a report you are going to publish an advisory about

- the `scout` role → tier A, so every strategy runs at `max`.
- Both lenses (`val-code`, `val-exploit`) → tier A.
- `SAMPLE_PERCENT` → `100`.
- Raise the budgets in `scoutpacket` and `candidatepacket` (60/50 and 40/30 by
  default). The budgets exist to stop a shallow pass from wandering; on a report
  you are committing to in public, the wandering is the point.
- Run a second swarm round even if the first converged: `report.py round --id
  <id> --advance` reports `converged` after two dry rounds, and forcing one more
  costs eight calls and occasionally finds the region the vocabulary from round
  one made searchable. The cap (`SCOUT_ROUND_CAP`, below) is three rounds; raising
  it is a source edit in a read-only folder, so it is a decision for whoever
  maintains the skill, not for a run.

### Swarm off — the original two-lens pipeline

The swarm is additive; the old path still works. On a report that names a symbol
and a file, `anchors` resolves it, and dispatching the `val-code` role against
`packet.code.json` is both cheaper and no less accurate — there is nothing for
eight strategies to disagree about. The orchestrator is told to go to Phase C
regardless because the cost is irrelevant in this mode; if it is not irrelevant
for you, skip Phase C when `anchors.summary.symbolsPresent` is non-zero.

**Do not skip Phase G on that basis.** The hunters run only on reports that were
about to be dismissed, which is exactly the population where the saving is worth
the least.

### Fastest useful pass

Intake, extract, anchor, and stop. Read `anchors.summary`. On a report about
another product, or one with nothing locatable, that costs zero model calls and
answers it. The orchestrator's prompt is written to stop there rather than push
on, and this is why.

## 2b. Swarm dials

| dial | where | default | effect |
|---|---|---|---|
| `STRATEGIES` | `report.py` | 8 entries | the search strategies. A new one is a table row and a `scoutpacket` dispatch — never a new role file (the brief travels in the packet). Adding one costs one call per report |
| `REGION_WINDOW` | `report.py` | 40 | how far apart two leads may be and still count as one region when no enclosing definition is found. Generous on purpose: two scouts pointing at opposite ends of a function have converged, and splitting them inflates the count that does the ranking |
| `PROBE_MAX_CANDIDATES` | `report.py` | 12 | leads the lexical probe returns |
| `--max` on `candidatepacket` | CLI | 12 | regions adjudicated per round. This is the main cost dial: it is one Opus call each |
| `REFUTE_ANGLES` | `report.py` | 9 | refutation angles. Each is a distinct way a finding of this kind is usually wrong; adding a tenth identical skeptic buys nothing, adding a tenth *lens* buys coverage |
| `PANEL_ANGLES` | `report.py` | per verdict | which angles run against which verdict. `PRESENT` gets the six that kill a claim; `NOT_EXPLOITABLE` gets the three that **find a path**, because refuting a dismissal is the opposite job and the claim-killing angles would just argue in the direction that is already the expensive one |
| `CHALLENGE_ANGLES` | `report.py` | 5 | hunter assumptions. Every one must run before a dismissal stands, so this is a floor on the cost of any `NOT_AFFECTED` |
| thin-search floor | `cmd_dismissal` | 3 | fewer recorded searches than this and the hunter does not count toward the dismissal. A floor against an empty gesture, not a measure of thoroughness |
| dry-round rule | `cmd_round` | 2 | consecutive rounds adding no new region before the search is called converged |
| `SCOUT_ROUND_CAP` | `report.py` | 3 | the most scout rounds one report gets, whether or not the search converged. `round --advance` prints `roundCapReached` and `scoutpacket` refuses a fourth round. A host run without a cap took six rounds, 118 subagents and about four times the cost of the other samples on ten source files, because every round surfaced one more marginal helper and the dry-round rule never fired. Each scout round is eight calls plus one adjudicator per new region; past the cap `CANDIDATE_ABSENT` and `NEEDS_REPORTER_INPUT` go to the hunters (five calls, once), the second search, and an `UNDECIDED` goes to `val-code` or stays open |
| `BRIDGE_WINDOW` | `report.py` | 8 | lines either side of a doc's concept match that are read for paths and identifiers |
| `BRIDGE_MAX_SYMBOLS` | `report.py` | 24 | identifiers taken from docs and Kconfig and searched for in source |
| `DOC_EXT` / `BUILD_EXT` / `BUILD_NAMES` | `report.py` | see source | which files count as bridges. **Add your own**: a house documentation format or a build system not listed here is a translation layer the probe cannot read |

## 3. What to watch

**The arbiter's overturn rate on sampled findings.** Above roughly one in ten,
stop expanding coverage: that is a signal about a lens prompt or a model tier, and
the fix belongs there rather than in more arbitration. The arbiter is told to say
so in `calibration_flag`.

**The `near_miss_substitution` rate.** A few are normal and healthy — it means
forks and renames are being caught. A lot means the reports are consistently
against a different release than the tree you are triaging, and the cheaper fix is
to check out the version the reporter tested.

**`NEEDS_REPORTER_INPUT` as a share of outcomes.** High is not necessarily wrong;
a public bug-bounty inbox produces a lot of unlocatable prose. But if it is high
*and* the reports have symbols in them, the extraction is under-collecting and the
stoplist in `report.py` is where to look.

**Severity gaps.** Persistent one-directional inflation is a fact about your
reporting channel, not your pipeline. Understatement in the other direction is
rarer and worth reading every time.

**Convergence.** `leads.converged` on a healthy run holds one or two regions. If
it is routinely empty, the strategies are not finding the same thing and the
ranking is doing nothing — usually a vocabulary problem, and `CONCEPT_LEXICON`
plus `DOC_EXT` are where to look. If *every* region converges, the strategies are
not independent enough to be worth eight calls; the usual cause is an
orchestrator relaying one scout's leads into another's dispatch, which its prompt
forbids twice.

**The hunters' hit rate.** How often the challenge stage finds something the
adjudicators missed. This is the direct measure of whether the swarm is working:
near zero over many reports means the earlier stages are already thorough and the
stage is cheap insurance; consistently non-zero means the scouts or the
adjudicators are missing regions and the fix belongs there, not in more hunters.

**Strategies that never contribute.** `leads.strategiesRun` against which
strategies actually produced the winning region, over time. A strategy that has
never once been the one that found it is a candidate for removal — but check
first that it is not the one producing the `vocabulary` entries that make the
others work, which is `vocabulary`'s whole job and is invisible in the lead
counts.

## 4. Dials worth knowing

| dial | where | default | effect |
|---|---|---|---|
| `SAMPLE_PERCENT` | `verify_findings.py` | 15 | share of unremarkable findings the arbiter audits for calibration |
| `NGRAM` | `verify_findings.py` | 8 | consecutive words shared with the report that count as a lens leak. Lower catches more paraphrase and more coincidence |
| `DRIFT_WINDOW` | `verify_findings.py` | 25 | how far from a cited line a quote may be found and still count as drift rather than fabrication |
| `MAX_HITS_PER_SYMBOL` | `report.py` | 40 | anchoring stops here; a symbol with more hits is a homonym problem |
| `MAX_INDEX_SYMBOLS` | `report.py` | 300000 | near-miss index cap |
| `SKIP_DIRS` | `report.py` | build output | note that `vendor/` and `third_party/` are deliberately **not** skipped |
| budgets | `references/contract.md` §2.7 | 20 reads / 15 searches / 3 levels | per report, per lens |
| `REPORT_TRIAGE_OFFLINE` | environment | unset | `1` forces every advisory lookup offline regardless of flags |

## 5. The concept lexicon

`CONCEPT_LEXICON` in `report.py` maps a domain word to the fragments that carry
it in code. It is the highest-leverage table in the bundle and it is meant to be
edited: a concept your codebase spells differently is a lead you will not get.

```python
"persistent": ["nvs", "flash", "eeprom", "nvram", "persist", "storage", ...],
```

Add your own vocabulary — a product name, an internal subsystem prefix, the
abbreviation your team uses for a component. The cost of a wrong entry is a
low-scoring candidate the lens discards; the cost of a missing one is silence.

`probe.conceptsNotLocated` is the feedback loop. A concept that matched nothing
anywhere is either vocabulary to add here, or a signal the report is about a
different product. Watch that field for a week and the table writes itself.

| dial | effect |
|---|---|
| `CONCEPT_LEXICON` | domain word → code fragments |
| `CONCEPT_STOP` | words with no locating power. Kept short on purpose: a surviving term that matches nothing scores zero, but a domain word wrongly filtered here is invisible all run |
| `DEFECT_SIGNATURES` | defect class → line patterns. Marks lines inside files the concepts already chose; never selects files alone. The `off-by-one` and `buffer-overflow` sets recognise the bounded `*_s`/`*_n` copy family (`strcpy_s`, `memcpy_s`, `snprintf`, …) and a `sizeof(x)+1` / `*_SIZE+1` bound, because a run against embedded code missed exactly that shape — `strcpy_s(buf, sizeof(buf)+1, s)` — when the patterns only knew plain `strcpy(` and array-index shapes |
| `DEFECT_PHRASES` | prose spelling → defect class |
| `VENDOR_HINTS` | path fragments (`sdk-`, `thirdparty`, `mbedtls`, `freertos`, …) that mark vendored code. Vendored files are not excluded but sort **below** product code, so the candidate slots fill with the product's own files first. In a run against a repo with a full vendored SDK, 10 of 12 candidates were vendored and the product file never made the list; product-first ordering fixes that. Add your own vendored roots here |
| `TEST_HINTS` | path fragments (`/test/`, `test_`, `/examples/`, `/mock/`, …) that mark test, example and mock code. Candidates are flagged `isTest`, and `probe --exclude-tests` drops them entirely — use it when the report scopes them out ("do not consider test or example code"), since a defect in a test fixture is not a shipped vulnerability. Both hint checks pad the path with slashes so a leading-directory match (`examples/…` at the repo root) is caught, not only `.../examples/...` |
| `PROBE_MAX_CANDIDATES` | leads returned, default 12 |

`DEFECT_PHRASES` maps the report's prose to a defect class, which selects the
signatures that mark candidate lines. It recognises the length and crash
vocabulary — `arbitrary long`, `oversized`, `unbounded`, and, as a **last-checked
fallback** so a specific class always wins first, a bare `crash` / `segfault` /
`denial of service`. A real report — "crash when the config is altered to an
arbitrary long value" — matched none of the original phrases and so selected no
signatures; now it resolves to `buffer-overflow` and the copy sinks get marked.

`probe` also skips this skill's own folder, wherever it is installed under the
workspace (compared by real path, so a symlinked install counts), any
`skills` folder directly inside a dot-folder (`.<host>/skills/`, where hosts keep
installed skills), and any dot-folder that holds a copy of this tool in one of its
folders — the old bundle, dropped into a project as a whole `.<host>/` folder
with its agent profiles and settings, is skipped whole. Without that it ranked
`report.py` itself, and then the profiles, as the top candidates, because this
file's lexicon (and their long descriptions) literally contain the words `aws`,
`mqtt`, `config`. A repository's own top-level `skills/` folder is a product and
is scanned. The same identity applies to every walk (`probe`, `anchor`, `surface`,
the near-miss index, dependency discovery) and to the dirty-tree flag.

The candidate floor is two distinct **fragments**, or one defect signature. Not
two concepts — a single directory called `storage/` satisfies both `persistent`
and `storage`, and counting concepts would let one path component promote a file
with nothing in it.

## 6. Anchor enforcement

Two checks in `verify_findings.py` back contract section 9.

| dial | where | effect |
|---|---|---|
| `ANCHORABLE_PROSE` | `verify_findings.py` | which prose fields get their anchors resolved. Add a field name here if you add one to the schema. |
| `PRESENCE_VERDICTS` | `verify_findings.py` | which verdicts must anchor their reasoning. Defaults to `PRESENT` and `EXPLOITABLE`, where a line exists by definition. |

If `unanchored_prose` fires on findings you consider fine, the usual cause is a
dependency claim whose reasoning is about a manifest rather than source. The
right fix is to anchor the manifest — `package-lock.json:412` is exactly the kind
of thing a reviewer wants to click — rather than to loosen the check. To disable
it anyway, empty `PRESENCE_VERDICTS`; `broken_anchor` keeps working, and that is
the one that catches invented locations.

## 7. Adding a defect family

Two places, and only two:

1. `references/contract.md` §8, the traps table, if the family has a boundary
   error that is specific to it.
2. `references/roles/val-code.md` §2, the deciding-facts table — one row saying
   what settles whether that family of defect is *present*.

If the family also changes what "reachable" means — a supply-chain claim, say,
where the entry point is the build rather than the running program — add a row to
`references/roles/val-exploit.md` §1 as well. Otherwise leave that file alone; reachability is
mostly family-independent.

Do not add a verdict value. The six overall outcomes map onto what a triage queue
actually does with a report, and `report.py`'s composition table assumes exactly
the lens verdicts in the contract.
