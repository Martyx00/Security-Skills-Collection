# Pipeline contract — stages 2 and 3 (§6–§7)

> Part of `contract.md`, moved here unchanged. §9, what never
> happens, is in that file and binds you too: read it.

## 6. `scores/scores.jsonl` and `operating-point.json` — stage 2

### The score record

```json
{
  "schema_version": 1,
  "function_id": "src/proto/parse.c::parse_tlv_record::0@9f2c1ab4e0d73516",
  "function_key": "src/proto/parse.c::parse_tlv_record::0",
  "content_hash": "9f2c1ab4e0d73516",
  "context_profile": "default-v1",
  "context_sha256": "3f9a…",
  "backend": "rules",
  "backend_version": "rules@1.1.0",
  "model": null,
  "score": 0.62,
  "score_kind": "ordinal",
  "calibration": "uncalibrated",
  "rank": 17,
  "percentile": 0.99983,
  "weakness_class": "CWE-787",
  "localized_line": 214,
  "explanation": null,
  "triage_verdict": null,
  "evidence_rule_hits": ["RH-000042", "RH-000051"],
  "scored_at_budget_tokens": 4096,
  "cache_fingerprint": "…64 hex…",
  "rule_hits_sha256": "…64 hex…"
}
```

`triage_verdict` is the verdict word behind the score for a backend that draws one
(`llm-triage`: `high` | `medium` | `low` | `none`, read back from the band the score is
in) and `null` for one that does not (`rules`, `finetuned`). It is what stage 3 derives a
`LOG-TRI` candidate from, on a `high` for a function no rule matched (§7). A record
written before 0.1.3 has no such key at all, which is not the same as `null`: stage 3
tells them apart, and the free remedy for the first is to re-run the score command with
`--resume`, which serves every verdict from the cache. The schema stays at 1 (contract §0
permits added fields).

`cache_fingerprint` is a sha256 of the backend settings the score was computed
under — for `finetuned` the endpoint, model, verdict tokens, prompt template and
top-k depth; by default the whole scorer config. `--resume` re-uses a
record only when `backend_version`, `model` and `cache_fingerprint` all match
and `rule_hits_sha256` — a digest of what a backend is shown of the function's
hits (rule, line within the function, sink text, reason, CWE), which
`llm-triage`'s prompt and `finetuned`'s `{{RULE_HITS}}` both render — is the one
this run would hand the backend. A rule edit or a matcher change that gives a
function a new hit therefore re-scores that function, and for `llm-triage` that
is a handshake for those functions only. A record from before the field existed
is re-used without the check, and the report counts it: re-asking it would
re-bill the corpus, because `llm-triage` numbers its prompts within the set
being asked. It also reads `scores/partial.jsonl`, which a stopped run leaves behind
batch by batch, skipping a torn last line rather than discarding the file. The
`rules` backend re-uses nothing; `llm-triage` keeps a cached verdict and
recomputes the order inside its band.

A cached record is re-checked as a fresh score is — in range, localized inside
its own function — and a record that fails is scored again, not served;
`scorer-report.json` notes how many. Beyond that the cache is trusted as this
run's own, because the run-directory check (`contract.md` §1)
guarantees git tracks nothing under `scores/`. In a tree whose provenance is
unverified it is not protected: a `scores.jsonl` or `partial.jsonl` that came
with the tree is read as if this run had written it.

### The honesty mechanism, stated as a rule the code enforces

`score_kind` ∈ `ordinal` | `probability`.

- **`ordinal`** — the number orders candidates and means nothing else. It is not
  a probability, it does not support a false-positive-rate claim, and thresholds
  over it may only be expressed as `top_k` or `top_percent`.
- **`probability`** — the number is a calibrated P(vulnerable), and
  `calibration` names the frozen evaluation set that calibrated it.

`score_functions.py` **refuses** to write `score_kind: "probability"` unless the
backend supplies a `calibration` of the form `calibrated@<evalset_id>` **and**
that evaluation set is registered in `assets/evalsets/<id>.json`
(`<id>` a bare name, never a path) with `"kind": "calibration"`, a measured
`base_rate` strictly between 0 and 1, at least one measured operating point,
and a `frozen_at` predating the run. A population, such as `baseline-2026-09`,
is not a calibration and is refused as one. There is no flag to
override this. An uncalibrated number presented as a probability is the failure
this pipeline is built to avoid, and a config option is not a defence.

Additional refusals:
- a corpus whose `extractor.confidence == "window"` share exceeds 10% cannot
  carry `score_kind: "probability"`, because the model was not trained on windows
  that are not functions — and one with records whose confidence is none of the
  three values cannot either, because its window share is not measurable;
- a run whose `context.profile` differs from the profile the backend declares it
  was trained on, or whose `context.budget_tokens` differs from the budget that
  profile defines (`extract_functions.py --budget-tokens`), cannot carry
  `score_kind: "probability"`.

Each downgrades to `ordinal` with the reason recorded in `scorer-report.json`.
None stops the run. A corpus that mixes context profiles or context budgets is
different: it is refused outright, because a ranking across two windows orders
functions by how much of their surroundings each was shown.

### `distribution` — the shape the operator cuts

`scorer-report.json` carries a `distribution` block, and `score_functions.py`
prints it as `CORPUS SHAPE`. It exists because the operating point is the one
decision that sets the price of the whole review — stage 4 is roughly linear in
stage-4 CALLS — and `--strict-k 200` is a round number, not a fact about the
repository under review.

A backend declares `bands` when its scale has boundaries a human can choose
between, and `null` when the score is a bare ordering:

| `kind` | rows are | when |
|---|---|---|
| `bands` | the backend's named bands, each with `cumulative_k` | the backend declares `bands` (`llm-triage`: high/medium/low/none) |
| `plateaus` | the largest runs of functions sharing one score | no bands — the number orders and means nothing else |

Each row carries `count`, `share`, `cumulative_k`, `cumulative_candidates`,
`cumulative_calls`, and the LOG-TRI share of the last two,
`cumulative_derived_candidates` and `cumulative_derived_calls`. **`print_distribution`
prints exactly one cost column and it is `cumulative_calls`**, with `incl. N LOG-TRI`
beside it on a row that includes some (`LOG-TRI off (+N)` when the person left them out).

**The cost column counts rule hits, plus one `LOG-TRI` candidate for each function the
triage model rated `high` that no rule matched.** `rules_lib.triage_owed` is the one
computation of who owes one (verdict `high`, no emitted hit, not a `<module>` or
`<window>` record, not in the test tree, not generated, not under `third_party`, `vendor`
or `node_modules`, and within `--triage-candidates-max` when given): stage 2 prices it into
every row before the person chooses, stage 3 builds from it, and the candidate gate
recomputes it. A function with no emitted hit adds no call unless it is owed one.
`cumulative_calls` and `cumulative_candidates` are as applied (they include the LOG-TRI
ones iff `operating-point.json` says `triage_candidates.enabled`), so `--budget`, which is
the row's `cumulative_candidates`, already includes them; the derived figures are carried
either way so a row can say what switching them off changes. `(logic-flaws, LOG-TRI, file)`
groups in fives like any rule's group. `distribution.triage_candidates` is the block the
table and the cut read: `rule_id`, `records_verdicts`, `enabled`, `max`, `basis`, `owed`
(within the ceiling), `over_cap`, `high_without_hit`, `excluded` (a count per reason a
high-rated function with no hit is left out: `not-a-function`, `test-tree`, `generated`,
`vendored`) and `note` (a sentence when they are over 5% of a corpus of 50 or more, or
more than half of a row's calls: open a few verdict files before paying for them). With a
backend that records no verdict `records_verdicts` is false and nothing is derived.

**Calls, because calls are what the run is billed for.** `references/roles/scout.md`
dispatches "one subagent call per candidate, or per batch of at most 5 candidates
that share the same `rule_id` and the same file", so the billed unit is a
`(rule_id, file)` group capped at five and the exact count is

    sum over groups of ceil(len(group) / 5)

On a measured tree that is 142 calls for 504 candidates — a fill factor of 3.55,
because 38 of 82 groups held one or two candidates and could never fill a
five-slot call. Quoting candidates at the operator overstates the bill by that
factor; quoting functions understates it. Neither is shown. The figure is exact,
not modelled: it reproduces the call count that run actually issued.

`cumulative_calls` is recomputed over the union of every row down to that one
rather than summed, because two rows can contribute candidates to the same
batch.

**`cumulative_candidates` is carried but not printed, and it exists for one
reason.** `--budget` is a *candidate* cap, a different unit from the column the
operator reads, so it can silently re-cut a choice already made — a measured run
selected 200 functions, hit a budget of 504 candidates, and never adjudicated
past the 12th function. the triage stage must therefore set `--budget` from the
chosen row's `cumulative_candidates`, or state before running that the cut will
be truncated. Showing the operator both numbers instead would hand them
arithmetic the tool has already done.

**The plateau form is a warning, not decoration.** A round `k` cuts through a
tie block blindly. On a real tree the *first* plateau under `rules@1.0.0` was
245 functions at one identical score, so "the top 20" there is not a cut but
an arbitrary slice of a tie. `rules@1.1.0` splits more of them, but a plateau
can still form. Showing the plateaus is how an operator sees that before paying
for it.

**A degenerate band shape is a note, never a downgrade.** When `llm-triage`
scores 50 or more functions and one band holds at least 95% of them, or one
explanation covers at least 90% (a null counts as one value; case, whitespace,
a trailing full stop and the value of every run of digits are ignored), `notes`
carries a line with the prefix `triage_degenerate:` and `score_functions.py`
prints it under the table. It is computed over every record in the report,
cached ones included, because `score_batch` sees only the functions the cache
did not serve. It moves no score, adds no downgrade and changes no exit code: a
quiet corpus produces that shape, and so does a batch answered without reading.
the triage stage relays it with the table and on its summary's `Notes:` line. It is
`llm-triage`'s alone: `rules` and `finetuned` never carry an explanation.

the triage stage must present this and stop. An operating point nobody chose is a
bill nobody agreed to and a coverage claim nobody made.

### Backends

| `backend` | What it is | Available |
|---|---|---|
| `rules` | deterministic score from rule hits: rule weight with diminishing repeats per rule, capped; high-signal bonus; reachability; churn; test-tree, generated-file and sample-tree penalties. `scorer-report.json` carries the weights it applied | today |
| `llm-triage` | one cheap LLM judgement per function, answered a batch per triage-worker subagent; verdict token, coarse bucket | today |
| `finetuned` | the fine-tuned classifier, scored from the log-probability of the verdict token | when it exists |

A backend is a class in `scripts/scorers/` (in the skill folder), registered by name.
Selecting one is `--backend <name>` or a `backend` key in the `--config` file;
`llm-triage` is the default. **Nothing else in the pipeline changes when the
backend changes** — that is the whole point of this section.

`llm-triage` reads its answers and verdicts back from `scores/triage/`. It
refuses a symbolic link where a verdict should be, and does not read an answers
file that is a link or larger than 4 MB, far more than one batch's answers. A
prompt digest ties a verdict or an answer to the prompt it answers, not to who
wrote it: they are trusted as this run's because the run-directory check
guarantees git tracks nothing there, and in an unverified tree they are not
protected.

The `finetuned` backend speaks OpenAI-compatible `/v1/completions` with
`logprobs`, which vLLM, TGI and `llama-server` all serve. Its config carries the
endpoint, the model name, the verdict tokens to read, the context profile it was
trained on, and the evaluation set that calibrated it.

### `operating-point.json`

```json
{
  "schema_version": 1,
  "calibration": "uncalibrated",
  "score_kind": "ordinal",
  "strict": { "mode": "top_k", "k": 200, "cutoff_rank": 200, "cutoff_score": 0.62 },
  "loose":  { "mode": "top_percent", "percent": 2.0, "cutoff_rank": 1840, "cutoff_score": 0.19 },
  "budget": { "max_adjudicated": 400 },
  "selected": 400,
  "not_selected": 96431,
  "fpr_claim": null,
  "recall_claim": null,
  "provenance": "rank-based; no frozen evaluation set is bound to backend 'rules', so no false-positive-rate claim is made",
  "not_selected_is_not_a_clean_bill": true,
  "triage_candidates": { "rule_id": "LOG-TRI", "records_verdicts": false, "enabled": false, "max": null,
                         "basis": "backend rules records no triage verdict" }
}
```

`triage_candidates` is the LOG-TRI setting this run applied, and part of the person's cut:
`records_verdicts` is true for a backend that draws verdicts (`llm-triage`); `enabled` is
then true unless `--no-triage-candidates` said otherwise, `max` is `--triage-candidates-max`
(or null), and `basis` is `default for llm-triage`, `--no-triage-candidates` or
`backend <name> records no triage verdict`. A point from before 0.1.3 has no such block:
nothing is derived from it and nothing compares the person's choice with it.

`mode` ∈ `top_k` | `top_percent` | `score`. `score` mode is refused when
`score_kind` is `ordinal`.

The scorer config's `operating_point` chooses each tier's mode, and the flags
choose its size: `--strict-k` and `--loose-percent`, when given, beat a `k` or
`percent` in the config, which is the fallback, then 200 and 2.0. A size flag
for a tier the config puts in another mode is refused (exit 2) rather than
ignored. `budget.max_adjudicated` is `--budget` (default 400): the candidate cap
stage 3 cuts the loose tier to, in rank order, deferring the rest; the strict
tier is never deferred.

`not_selected_is_not_a_clean_bill` is a literal field and it is always `true`. It
exists so the number next to it cannot be reported without the sentence that
qualifies it, and `verify_findings.py` fails a `REPORT.md` that gives a
`not_selected` count without carrying the qualification in the same paragraph
(`report_selection_unqualified`).

---

## 7. `enrich/` — stage 3

### `analyzer-findings.jsonl`

```json
{
  "schema_version": 1,
  "finding_id": "AN-000012",
  "analyzer": "semgrep",
  "analyzer_version": "1.86.0",
  "rule": "c.lang.security.insecure-use-strcpy",
  "level": "error",
  "file": "src/proto/parse.c",
  "line": 214,
  "end_line": 214,
  "message": "Use of memcpy with non-constant size",
  "cwe": ["CWE-787"],
  "function_id": "src/proto/parse.c::parse_tlv_record::0@9f2c1ab4e0d73516",
  "function_key": "src/proto/parse.c::parse_tlv_record::0",
  "join": "line-in-range"
}
```

`analyzer` ∈ `semgrep` | `cppcheck` | `codeql` | `other`. Input is SARIF 2.1.0 for
all of them; `cppcheck --output-format=sarif` and `semgrep --sarif` both emit it,
and CodeQL's `database analyze --format=sarif-latest` does too.

`join` ∈ `line-in-range` | `file-only` | `unjoined`. A finding whose line falls
in no extracted function is `file-only`; one whose file is not in the corpus at
all is `unjoined`. Both are kept — an analyzer finding the extractor could not
place is a signal about the extractor.

### Agreement

```json
{ "model": true, "analyzer": true, "both": true, "analyzers": ["semgrep", "cppcheck"], "same_line": true }
```

`both` requires `model && analyzer`. `same_line` requires an analyzer finding
within ±3 lines of the scorer's `localized_line`. Agreement raises queue
priority; it never creates a candidate that the operating point did not select,
and it never suppresses one.

### `queue.json`

```json
{
  "schema_version": 1,
  "generated_by": { "tool": "enrich_candidates.py", "version": "1.0.0" },
  "run_id": "2026-09-19T00-00-00Z",
  "previous_numbering_archived": { "path": ".security-review/previous/2026-09-18T18-49-03Z", "files": 14 },
  "operating_point": { "…": "verbatim copy of operating-point.json" },
  "entries": [
    {
      "candidate_id": "CAND-0001",
      "function_id": "…",
      "function_key": "…",
      "rank": 1,
      "score": 0.94,
      "tier": "strict",
      "category": "memory-safety",
      "rule_id": "MEM-002",
      "agreement": { "model": true, "analyzer": true, "both": true, "analyzers": ["semgrep"], "same_line": true },
      "priority": 9.5,
      "suppressed": false,
      "suppression": null,
      "twin_group": null
    }
  ],
  "counts": { "total": 400, "strict": 200, "loose": 200, "suppressed": 3, "deferred": 0,
              "selected_without_candidate": 14, "triage_derived": 12, "triage_derived_dispatched": 11,
              "triage_derived_suppressed": 1, "triage_derived_deferred": 0 },
  "triage_candidates": { "rule_id": "LOG-TRI", "enabled": true, "owed": 12, "dispatched": 11, "…": "…" },
  "selected_without_candidate": [
    { "function_key": "…", "file": "…", "rank": 311, "score": 0.52, "tier": "loose",
      "not_derived_because": "verdict-medium", "reason": "selected by score; stage 1 emitted no rule hit in this function, and no LOG-TRI was derived: the triage model rated it medium, and only high derives a LOG-TRI" }
  ],
  "budget": { "max_adjudicated": 400, "taken": 397, "strict_only": false, "overrun_by_strict": false },
  "analyzers": { "ingested": true, "default_dir_read": false, "files": ["…"], "…": "…" },
  "suppressions_stale": [
    { "suppression_id": "SUP-0003", "function_key": "…", "reason": "content_hash differs from creation" }
  ],
  "suppressions_expired": [
    { "suppression_id": "SUP-0005", "function_key": "…", "expires_at": "2026-06-01T00:00:00Z" }
  ],
  "suppressions_unusable": [
    { "suppression_id": "SUP-0007", "function_key": "…", "rule_id": null,
      "reason": "no rule_id, so it cannot be matched to one rule on one function as it is now, or revoked …" }
  ],
  "suppressions_ignored": [
    { "suppression_id": "SUP-0008", "function_key": "…", "rule_id": "MEM-WFS",
      "reason": "MEM-WFS is derived from the function's other candidates and at least one of them still dispatches; …" }
  ],
  "suppressions_revoked": 1
}
```

**`LOG-TRI`.** Stage 3 gives each selected function that the operating point's
`triage_candidates` owes one a single candidate (`rules_lib.triage_derivation`: verdict
`high`, no emitted hit, not excluded). It has `rule_id: "LOG-TRI"`, `category:
"logic-flaws"`, `cwe: "CWE-693"`, no `rule_hit_id`, and `line` and `sink_text` are the
function's first line with text, read off disk when stage 3 ran (nothing from the verdict
chooses it). `sink_matches_extract` is `null` on it: there is no stage-1 copy to compare.
Its record and its packet carry none of the verdict's explanation, CWE or line (the
packet's `score` leaves them out and says so). It is the only candidate on its function,
it appears in `candidates/logic-flaws.json` (or `logic-flaws-deferred.json`), and it has
no row in `coverage.json` or in `coverage-selection.json`'s `rules`; it is accounted for in
`coverage-selection.json` `triage_derived` (`enabled`, `max`, `basis`, `owed`,
`dispatched`, `deferred`, `suppressed`, `anchor_unreadable`, and `functions`: one
`{function_key, candidate_id, disposition}` per owed function, `disposition` ∈ `dispatched` |
`deferred` | `suppressed` | `anchor-unreadable`, the last with an `anchor_reason` ∈
`unreadable` | `oversize` | `no-text-line`). `counts.triage_derived` is the `LOG-TRI`
candidates this run numbered (dispatched, suppressed and deferred); `counts.triage_derived_dispatched`,
`triage_derived_suppressed` and `triage_derived_deferred` split it, and only the dispatched
ones went to a validator: every sentence that says a `LOG-TRI` function was reviewed
(`run-status.json`, the summary, `REPORT.md`) is read off the dispatched count, and the
suppressed and the deferred are said apart, as not examined. A selected function with no
emitted hit and no LOG-TRI is in `selected_without_candidate` with `not_derived_because` ∈ `no-verdict`,
`verdict-medium` | `verdict-low` | `verdict-none`, `not-a-function`, `test-tree`,
`generated`, `vendored`, `opted-out`, `over-cap`, `anchor-unreadable` or
`scored-before-0.1.3`: unexamined, not clean. The candidate gate (`verify_findings.py`,
invariant I8) recomputes the owed set from `scores.jsonl`, `operating-point.json`,
`functions.jsonl` and `rules.jsonl` and refuses a LOG-TRI that no recorded `high` verdict
owes, a record that is duplicated or missing, a line outside its function, and a record
carrying the verdict's reading; I1, I3 and I5 do not count it (it has no coverage row, and
it is not a candidate MEM-WFS follows).

`tier` ∈ `strict` | `loose`. `previous_numbering_archived` is `null` when there
was nothing to archive (§1). `analyzers.default_dir_read` is `true` only when
neither `--sarif` nor `--sarif-dir` named anything and stage 3 read
`enrich/analyzers/` on its own; beside an explicit `--sarif` that directory is
the archive of earlier runs' inputs, not an input. An entry's `suppression`
block carries the `suppression_id`, `author`, `reason` and `expires_at` of the
ledger record that applied — or, for a `MEM-WFS` suppressed with its siblings
(§8), `suppression_id: null` and a `derived_from` naming the records it
follows. An entry's `twin_group` is `TWIN-<content_hash>` when the function's
body is at another path in the corpus, else null; the `twins` block counts
the groups (`groups`, `functions`, `groups_with_candidates`, `candidates`,
`dispatched`, `copies_not_selected`, `context_differs`) and lists up to 50 as
`{group, aliases: [function_key…], candidates: [candidate_id…]}`.

### `candidates/<category>.json`

Written by `enrich_candidates.py`, **not by a model**, in the exact shape the
Validator Contract documents — every field it names, populated from the packet.
That the writer is a tool is the point: a candidate record a model composes is
an assertion, and everything downstream would have to be audited as such.

`hints` carry locations and declarations only, never an assessment. The tool
emits, at most: where a length was assigned, the declared size of a destination,
the type of a variable. It has no way to express "the bounds check at line 3375
covers this", which is the hint that ruins a validator, and that is deliberate.

`exposure` is on every record, the deferred ones included, and the packet
carries the same object. It follows the hints' discipline: enums, counts and
`{file, line, text}` lines quoted verbatim, plus one severity ceiling read off
them through a closed table (validator-reference §6a). This is
`zipRemoveExtraInfoBlock` in zlib 1.2.11:

```json
"exposure": {
  "path_class": "contrib", "path_class_segment": "contrib", "path_class_basis": "segment",
  "support_marker": { "file": "contrib/README.contrib", "line": 1,
                      "text": "All files under this contrib directory are UNSUPPORTED. There were" },
  "insecure_marker": null,
  "default_build": "not-referenced", "build_references": [],
  "build_reference_kind": null, "build_chain": [], "build_dead_ends": [],
  "build_files_read": ["CMakeLists.txt", "Makefile", "Makefile.in"],
  "own_build_files": ["contrib/minizip/Makefile", "contrib/minizip/Makefile.am", "contrib/minizip/configure.ac"],
  "callers": { "total": 0, "by_class": {}, "lines_unread": 0 },
  "linkage": "external",
  "declared_in": [ { "file": "contrib/minizip/zip.h", "line": 340,
                     "text": "extern int ZEXPORT zipRemoveExtraInfoBlock OF((char* pData, int* dataLen, short sHeader));" } ],
  "guards": [],
  "ceiling": "medium", "ceiling_reasons": ["not-built", "unsupported-marker"]
}
```

- `path_class` ∈ `core` | `contrib` | `examples` | `test` | `fuzz` | `bench` |
  `vendored` | `tools` | `docs`. It is the first directory segment found in
  the tool's own closed table, compared case-insensitively, and it is `core`
  when none matches — except that a function stage 1 marked `in_test_tree`
  (its test directory names, its test file-name pattern, the manifest's
  `test_tree_globs`) is `test` unless the table already found a test or
  sample class. `path_class_basis` ∈ `segment` | `test-tree-globs` |
  `in-test-tree`, null for core. It redefines neither FP-TEST's path test nor
  `in_test_tree`. FP-TEST accepts the record's `in_test_tree` when the basis
  is `test-tree-globs` (`verify_findings.fp_test_basis`), so an operator's
  glob reaches both, and every dismissal only a glob bears out is queued for
  the arbiter; stage 1's own names (`in-test-tree`) cap the ceiling, and bear
  FP-TEST out only where the language's test runner uses them too
  (`TEST_RUNNER_NAMES`: Go's `_test.go`, pytest's `test_*.py`, jest's
  `__tests__/`), never on a C file's name alone.
- `support_marker` is the first line of the nearest README* above the file
  that says the code there is unsupported, unmaintained or untested — a
  subject that is the code, not a platform (`Mixed-endian platforms are not
  supported` is not one) — or null. The walk stops at the first directory
  with a README, and never reads a project root's: the root, a `.gitmodules`
  path (a submodule's own `.gitmodules` included) or a directory holding a
  `.git` entry. The text is capped at 200 characters.
- `insecure_marker` is the first line saying the code is not secure, is for
  testing only or is not for production (`INSECURE_MARKER`) — with a subject
  that is the code; a pronoun or no subject (`This is`, `They should not be
  used`, `Not for production`) only opening a sentence, never a mid-sentence
  `it is` or a `not for production` after a comma or in parentheses — from
  the file's own comments above its first extracted function
  (at most 120 lines), else from the same README; or null. Recorded
  verbatim, like every marker: it caps the rating and never dismisses.
- `default_build` ∈ `referenced` | `not-referenced` | `unknown`. It reads only
  the root build files that exist (`build_files_read`), and `unknown` means
  there were none. A reference is the file's relative path, its `.o`, `.lo`
  or `.obj` under any directory (spelled with the file's own directory when
  another extracted source shares the stem), or an `add_subdirectory()`,
  `SUBDIRS` or `subdir()` line naming a directory above it. Comment lines,
  deleting recipes and every line of a `*clean*` target are skipped, because
  zlib's clean rule named `contrib/infback9`; a glob's own word and a trailing
  comment are blanked. `build_references` holds up to five.
  An `add_subdirectory()` counts only as far as the directory's own
  `CMakeLists.txt` (with what it `include()`s, a bare name read as the
  project's own `<Name>.cmake` when there is one) reaches the file: by name,
  by a glob (`crypto/${m}.c` read as `crypto/*.c`), by `${exe}.c` over a list
  holding its stem, through a nested literal `add_subdirectory()`, through an
  include directory above it or an `#include` of it from a source there, or
  through a line text cannot settle (a variable `add_subdirectory()`, an
  unresolvable `include()`, a `list(TRANSFORM)`, a call handing nothing to a
  helper whose `function()` above builds a target, and in a directory with
  no target call of its own a command nothing read defines). A helper
  handed its sources settles by them, and one compiling `${F}.c` by its
  call's words as stems. A header is
  never left out this way. `build_reference_kind` ∈ `named` | `named-below` |
  `included` | `directory`, null when not referenced; `build_chain` holds the
  `{file, line, text}` lines followed from the root line; `build_dead_ends`
  holds up to five `{chain, stops_at, why}`, `why` ∈ `blank` |
  `names-nothing`. Meson's `subdir()` and Automake's `SUBDIRS` are not
  followed.
  `own_build_files` lists build files beside the source file; they are facts
  and cap nothing.
- `callers` counts distinct callers from the call index by `path_class`, with
  `<module>` left out. A class with none is absent. `lines_unread` counts the
  calls of this name on lines the index did not read.
- `linkage` ∈ `static` | `external` | `unknown`, from a leading `static` in the
  signature. `declared_in` holds up to five header prototype lines, including
  the `OF((...))` spelling. `guards` are the `#if` branches open at the sink
  line, include guards left out, with `kind` ∈ `platform-legacy` |
  `platform-mainstream` | `disabled` | `feature`. All three are for C and C++
  only; any other language gets `unknown`, `[]` and `[]`.
- `ceiling_reasons` ⊆ `advisory-only`, `disabled-guard`,
  `test-or-sample-path`, `not-built`, `unsupported-marker`,
  `documented-insecure`, `not-built-internal`, `legacy-platform`. `ceiling` is the least severe of
  their caps, or null when none applies. It caps a rating the finding can
  override with a cited line. It never dismisses, defers or reorders a
  candidate.

`twins` is on every record too: null when no other corpus function has the
same `content_hash`, else the group. Mbed TLS vendors its framework at
`framework/` and `tf-psa-crypto/framework/`, and one run adjudicated every
psasim defect twice, at two severities:

```json
"twins": {
  "group": "TWIN-33bd5b6cc79c1924", "functions": 2, "context_differs": false,
  "copies": [ { "function_key": "framework/psasim/src/psa_ff_client.c::process_response::0",
                "file": "framework/psasim/src/psa_ff_client.c", "line": 178,
                "candidate_id": "CAND-0010", "status": "dispatched",
                "exposure_ceiling": null, "ceiling_reasons": [], "context_matches": true } ],
  "copies_total": 1, "copies_truncated": false
}
```

- A copy's `line` is its own start plus this sink's offset; its `status` ∈
  `dispatched` | `deferred` | `suppressed` (a candidate for the same rule at
  that offset, `candidate_id` set) | `not-selected` | `no-hit` (none). For a
  `LOG-TRI`, `no-hit` means the copy was selected and got no `LOG-TRI` at its path
  (the model rated it lower, or it is excluded). A copy that was reviewed under
  another rule is not clustered with a `LOG-TRI` (the rule is part of the identity), so
  a body can be dismissed there and flagged here; `run_status.py` names such a twin on
  the remainder, so a reviewed body is not listed as unexamined without saying so.
- `exposure_ceiling` and `ceiling_reasons` repeat the copy's own record for
  comparison. Each record keeps its own `exposure`: copies differ in build,
  README and callers legitimately.
- `context_matches` compares the two stage-1 windows without paths or caller
  parts, as a set: `context_sha256` hashes the path into every part, so it
  never matches across copies. `context_differs` is true when a copy's does not
  match, null when one could not be compared and none differed.
- Up to 12 copies. Nothing here changes dispatch: every copy is adjudicated
  on its own path, and the arbiter holds the copies to one answer or cites the
  location fact that separates them (verify_findings `twin_divergent`,
  `arb_twin_divergent`).

---

### Two classes of analyzer, because they answer different questions

`analyzer_class` ∈ `corroborating` | `independent`.

**Corroborating** — semgrep, cppcheck, CodeQL. They read the same code the rules
read, so their findings are a second opinion on ground this pipeline already
covers. They join to a function, they set `agreement`, and **they never admit a
candidate the operating point did not select**. That restriction is what keeps
the operating point meaning something.

**Independent** — osv-scanner, grype and trivy for dependencies. These find what
a function-scoped ruleset *structurally cannot*: a vulnerable version in a
lockfile. Holding them to the corroborating rule would be holding a signal to a
restriction written about a different signal.

| analyzer | class | where it goes |
|---|---|---|
| semgrep, cppcheck, codeql | `corroborating` | agreement on an existing candidate |
| gitleaks, trufflehog, detect-secrets, ggshield, noseyparker, secretscanner | — | **stage 1.** Input to `sweep_secrets.py`, judged by the secret-sweeper role, landing in §4a's inventory |
| osv-scanner, grype, trivy | `independent` | the dependency track, §7a |

### The middle row used to be an admission mechanism, and that was wrong

An earlier version of this contract let a secrets scanner **admit** its function
into stage 3's queue, routed under `LOG-005`. It worked, and it was the wrong
shape, for a reason worth recording so nobody rebuilds it.

A secret is a file-and-line fact. Making one fit a function-shaped pipeline took
three accommodations: a synthetic `<module>` scope to give it a home, an
admission path into a queue it was never ranked for, and a routing decision to
borrow a playbook written for something else. Three accommodations is a design
saying the work does not belong here. And it was inconsistent — §7a already
conceded that a dependency is not a function, on exactly the same grounds.

Stage 2 did no work for an admitted candidate either; they carried `tier: null`.
A secret does not need ranking. It is there or it is not.

So secrets belong to stage 1, where §4a's sweeper judges them once, and where the
inventory it produces does something the admission path never could: it tells
`LOG-007`, `LOG-008`, `HW-009` and `CRY-005` which values are secret and which
are merely named like one.

**Stage 3 therefore ignores a secrets scanner's findings, and says so.** It
counts them, reports `N finding(s) from gitleaks are stage 1's — see
secrets/inventory.json`, and does not join, admit or adjudicate them. Silently
dropping them would be the failure this skill refuses everywhere else; treating
them as corroborating would be worse, because a secrets scanner has not read the
ground the rules read and its agreement means nothing.

### §7a. The dependency track

A vulnerable dependency is not a function, has no `content_hash`, and cannot be
adjudicated by a playbook: asking the memory-safety validator whether
`lodash@4.17.15` is affected by an advisory is a category error, and an LLM
answering it is guessing at a database lookup.

So dependency findings bypass stages 4 and 5's function machinery entirely and
land in `enrich/dependencies.jsonl`:

```json
{
  "schema_version": 1,
  "finding_id": "DEP-000004",
  "analyzer": "osv-scanner",
  "analyzer_version": "2.0.2",
  "advisory": "GHSA-35jh-r3h4-6jhm",
  "aliases": ["CVE-2021-23337"],
  "package": { "ecosystem": "npm", "name": "lodash", "version": "4.17.15" },
  "fixed_in": "4.17.21",
  "severity": "high",
  "manifest": "package-lock.json",
  "line": 1204,
  "adjudicated": false,
  "provenance": "deterministic database match; not a judgement of this pipeline"
}
```

`REPORT.md` carries them in their own section, headed so that nobody mistakes
them for adjudicated findings, and every row names the analyzer, its version and
the advisory id. `adjudicated` is `false` and stays `false`.

**This is not an exception to §9 rule 3.** That rule stops an unverified *model
output* being shown as fact. A dependency finding is a database match by a pinned
tool — it is not this pipeline's opinion, it says whose opinion it is, and it
says so in the record and in the report.
