# Scripts

The programmatic tools of the skill: the deterministic spine that counts, ranks, checks and
persists. SKILL.md tells the model which command to run; the scripts decide what is allowed next,
and `review_run.py` holds the part a harness's workflow file and agent profiles used to hold (the
stage order, the stops, the fixed prompts, the dispatch record).

## Rules

- **Standard library only.** Every import is stdlib, local to this folder, or inside
  `try: ... except ImportError:` with a stdlib fallback (tree-sitter is optional; the extractor falls
  back to a language-aware brace and indentation walk). The floor is the `python-min` in the SKILL.md
  frontmatter (`3.11`). The scripts themselves run on 3.9 and newer: the declared floor is the
  owner's choice.
- **Two roots, never derived from each other.** The *skill root* comes from `__file__`
  (`rules_lib.SKILL_ROOT`) and is read-only: it holds code, rules, evaluation sets and the fixture.
  Global installs are shared and plugin caches can be read-only, so nothing is ever written there
  (`sys.dont_write_bytecode` and `python3 -I -B` keep `__pycache__` out). The *workspace root* is the
  repository under review, the working directory (`--root`, default `.`), and holds all state and
  output in `.security-review/`.
- **Run with `python3 -I -B`**, written with the skill folder's absolute path in front of `scripts/`.
  Isolated mode drops the script's own folder from `sys.path`, so each script adds its folder itself.
  If `python3` is not found, use `python -I -B`, then `py -3 -I -B`.
- **Step 0.** Every script that reads `.security-review/` first calls `rules_lib.enforce_run_dir_gate`
  and exits **7** before reading or writing anything when the scanned repository commits files there
  (other than `.gitignore` and regular files under `ledger/`), when git cannot say whether it does,
  or when `--root` is this skill or an old copy of the scanner. `rules_lib.py --check-run-dir --root .`
  is the same check on its own. Exit 7 outranks every other code.
- **No host paths, no home directory.** The lint rejects `.kiro` and `.vibe` (`PY-HOSTPATH`),
  absolute user paths, host variables and home-directory lookups (`PY-HOME`).
- **Encoding.** Text files are opened with an explicit `encoding="utf-8"` (a reply file or a JSON file
  a role wrote is decoded as `utf-8-sig`, so a byte-order mark from a Windows shell redirect is not
  part of it); the scripts have not run on Windows, and the roles' POSIX shell patterns would not
  (`references/limitations.md`).
- **Links and pipes in the selftests.** `os.symlink` exists on Windows and raises without Developer
  Mode, and `os.mkfifo` does not exist there. `rules_lib.can_symlink()` and `can_mkfifo()` ask by
  doing the call once, and a selftest case that needs one is skipped, named and counted
  (`skip_case`; the last line says `N case(s) skipped`) rather than run into a traceback.
- **Exit codes** are per script and documented in each docstring (`--help`). Common ground: 0 success,
  1 refused or failed, 2 usage or a gate failure, 7 the run-directory gate. `verify_findings.py` uses
  1 (could not run) and 2, 3, 4, 5 for its four gates; `run_status.py` uses 0, 1, 3, 4 as the *run's*
  status.
- **Selftests.** Every script has a `--selftest` that builds its fixtures in a temporary
  directory; `rules_lib.py --selftest` and `smoke_test.py` also read the shipped fixture in
  `tests/fixture/`.

## Tools

| Script | Stage | Purpose |
|---|---|---|
| `review_run.py` | all | the orchestrator's script: `init [--through STAGE] [--arbiter-slice N]`, `next`, `mode`, `scope-skip`, `scope-choose`, `cut [--list \| --row LABEL [--no-triage-candidates \| --triage-candidates-max N] [--quote WORDS]]`, `units`, `manual (--file CAND.json \| --source FILE --function NAME [--line N] [--rule ID])`, `verdicts` (the answer to a `manual` check: every verdict and derived verdict, each in a fenced block of its own), `dispatch-prompt UNIT \| --stage ROLE` (also marks the units as handed out), `wait [UNIT ... \| --stage ROLE] [--seconds N]` (at most 110), `unit-task UNIT`, `inline-unit UNIT` (writes the unit's brief, the role file and the task, to `dispatch/<stage>/<unit>.brief.md` and prints its path), `ingest UNIT \| --stage ROLE --dispatch MODE` (the wave form also takes in the one-off units of a `manual` check), `dispatch-record UNIT MODE [--attempt-failed WHY]`, `summary`, `hygiene`. State is `.security-review/dispatch/`; `.security-review/tmp/` is scratch. It prints JSON, a key to a line, and `ingest` ends with `# exit N: ...` and `wait` with `# wait: STATUS (...)` (`dispatch-prompt`, `unit-task` and `verdicts` print text, because JSON escapes every newline and a model that copies an escaped prompt re-flows it). `init`, `mode`, `verdicts`, `summary` and, at a stop for the person, `next` and `cut --list` end with a block from `SAY THIS TO THE PERSON` to `==== END OF WHAT TO SAY ====`; `unit-task` prints the leave-outs for the validators' searches (this skill's folder, every installed skill, the other skills' run folders) as ripgrep globs and grep base names |
| `rules_lib.py` | 1 | the one loader of `assets/rules/*.json`; the run-directory gate (`--check-run-dir`); the identity-based tooling skip every walk uses (this skill, installed skills and old copies of the scanner, and the run folders of the other skills: `SIBLING_RUN_DIRS`); `can_symlink`, `can_mkfifo` and `skip_case` for the selftests; `parse_json_reply_noted` (and `parse_json_reply`, without its cautions), the one reader of a role's fenced JSON reply (`review_run.py ingest` uses it) |
| `extract_functions.py` | 1 | one record per function in the repository, every rule hit joined to one, and an account of what every pattern found (`functions.jsonl`, `rules.jsonl`, `coverage.json`, `extract-report.json`) |
| `snapshot.py` | 1 | freeze the tree into `.security-review/snapshot/` (`--verify` re-hashes it) so every file:line resolves against bytes that cannot move |
| `build_graph.py` | 0, 1 | call distance from the entry points (the reachability stage 0 and the `rules` backend use) |
| `sweep_secrets.py` | 1 | `candidates` (the deterministic half of the secret sweep), `check` (hold the sweeper's inventory to contract §4a), `status` |
| `score_functions.py` + `scorers/` | 2 | score every function through a pluggable backend (`rules`, `llm-triage`, `finetuned`), set the operating point, and refuse to call an ordering a probability. Under `llm-triage` it records each verdict (`triage_verdict`) and prices the `LOG-TRI` candidates a `high` on a function no rule matched will become into every CORPUS SHAPE row; `--no-triage-candidates` and `--triage-candidates-max N` are the person's, and the `rules` backend derives none |
| `enrich_candidates.py` | 3 | join analyzer SARIF, build the packets, rank the queue, write the candidate records, including one `LOG-TRI` candidate for each selected function the triage model rated high that no rule matched (`candidates/coverage-selection.json` `triage_derived` accounts for them; `queue.json` lists the rest with why) |
| `verify_findings.py` | 3, 4 | the four gates: `--candidates` (invariants I1-I8; I8 recomputes the `LOG-TRI` set), `--findings` (with `--out`: the mechanical pass and the arbiter's queue), `--arbitration`, `--report` |
| `ledger.py` | 5 | the human's answers, kept: `confirm`, `reject`, `out-of-scope`, `needs-info`, `suppress`, `revoke`, `withdraw`, `status`, `pending`, `check`, `export` |
| `upstream_check.py` | 5 | optional: `plan` and `show` are offline; `query` is the reviewer's command (a person types a confirmation word at a terminal; exit 4 otherwise) |
| `run_status.py` | 4 | the run in one file and one exit code (0 clean, 1 findings, 3 incomplete, 4 setup or gate failure) |
| `export_sarif.py` | after 4 | the adjudicated findings as SARIF 2.1.0 |
| `smoke_test.py` | test | the deterministic stages end to end over the tagged fixture |

The tools are not runnable from inside the skill folder: every script refuses a `--root` that is
the skill folder or an old copy of the scanner (exit 7), because the skill folder is read-only and
may be shared.
