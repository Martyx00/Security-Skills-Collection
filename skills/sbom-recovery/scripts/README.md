# Scripts

The programmatic tools of the skill: the deterministic spine that owns the state
machine, validation and file writes. SKILL.md tells the model which subcommand to
run; the script decides what is allowed next.

## Rules

- **Standard library only.** Every import is stdlib or local to this folder. The
  floor is Python 3.9 (`python-min` in the SKILL.md frontmatter); `sbom.py`
  prints a JSON error and exits 3 on an older interpreter. git is needed at run
  time and is only ever run through `sbomlib/gitro.py`, which accepts a fixed
  list of read-only plumbing subcommands.
- **Two roots, never derived from each other.**
  - The *skill root* comes from `__file__` (`sbomlib/context.default_skill_root`)
    and is read-only. It holds code, assets and references. Nothing is ever
    written there, and a pack manifest taken by `start` lets the audit notice if
    it changed during a run.
  - The *workspace* is the current working directory. It must be a plain folder
    whose subfolders are the repositories. All state and output go to
    `<workspace>/sbom-out/` (`<workspace>/sbom-out-pilot/` for a pilot run; the
    two names are a closed set, `context.OUT_NAMES`). `sbomlib/paths.resolve_layout` refuses a workspace
    inside the skill folder (`WORKSPACE_IN_SKILL`), inside a git work tree
    (`PARENT_IN_GIT_WORKTREE`), a script that is not a regular file
    (`BAD_SCRIPT_LOCATION`) and an unsafe `sbom-out` (`UNSAFE_OUTPUT_DIR`).
- **No host paths, no home directory.** Neither the folder the skill is
  installed in nor the user's home directory is read. The only literal host
  folder names are the list of folders to skip when walking a workspace
  (`enumerate.AGENT_DIR_NAMES`, with the lint pragma).
- **Run with `python3 -I -B`.** `sbom.py` adds its own folder to `sys.path`, so
  isolated mode works; `-B` keeps `__pycache__` out of the skill folder.
- **JSON in, `next_action` out.** Every subcommand except `summary` and
  `explain` prints exactly one JSON object (under 10 KB) on stdout, with
  `next_action` one of `run_again`, `adjudicate`, `stop_for_approval`, `done`,
  `error`. Diagnostics go to `sbom-out/.state/sbom.log`, not to stderr.
- **Exit codes.** 0 whenever a result object was printed (the agent acts on the
  JSON, including `next_action: error`), 2 for a usage error, 3 for an unsafe
  layout or old Python, 1 for an internal error. `human_approve.py`: 0 approved,
  1 refused, 2 not a terminal.
- **Human-only actions.** Approval of the review file is `human_approve.py` run
  in a terminal (evidence `tty`) or `sbom.py approve` run by the agent after a
  chat reply (evidence `agent-relayed`, always warned about). The level is
  recorded in every output. A terminal check is a speed bump, not a boundary.
- **Bounded steps.** `next` runs units until about 40 s have passed (80 s is the
  hard limit), then returns `run_again`. A unit that overruns the hard limit
  twice fails its repository (or returns a retryable `BUDGET_EXCEEDED` for a
  global unit). State is saved after every unit, so a killed process resumes.
- **Encoding.** Every text file is opened with an explicit encoding; CSV is
  UTF-8 with BOM and CRLF.

## Tools

| Script | Subcommands | Purpose |
|---|---|---|
| `sbom.py` | `selfcheck`, `start [--abandon] [--scope product\|all]`, `pilot <repo>...`, `status`, `next`, `approve`, `audit`, `explain`, `summary`, `dispatch-prompt (<unit> \| --stage worker)`, `dispatch-record <unit> <subagent\|inline> [--model NAME]`, `inline-unit <unit>`, `reply <unit>` (standard input), `check-unit <unit>` | the state machine; the only entry point of the agent. `check-unit` is the worker role's own step 0 and read-only validation of its reply |
| `sbom.py` (reserved) | `stage`, `gate-status`, `validate`; the switches `--carry-stale`, `--no-upstream-match`, `--sandbox-configure`, `--determineversion` | the subcommands print `NOT_IMPLEMENTED_M2`; the switches are refused as a `USAGE` error with exit 2; features of a later stage |
| `human_approve.py` | none | shows the review file summary and diff, asks for `APPROVE` on a terminal, then approves with evidence `tty` |

## The library, `sbomlib/`

| Module | What it does |
|---|---|
| `cli_core.py`, `commands.py` | argument parsing, layout checks, dispatch, the one-JSON-object output, the subcommand handlers |
| `driver.py` | the ordered unit plan (the `worker:<repo>` units come after the adjudication units), the budget loop, per-repository failure isolation, the adjudication sequence (input file, one corrective retry, fall back to `INCONCLUSIVE`), `dispatch-record`, and the holds on a worker reply: of a unit the script has no record of (`DISPATCH_RECORD_MISSING`) and one that comes before the unit had its turn (`REPLY_NOT_YET_WRITTEN`: for a subagent until it is recorded as finished, for an inline unit until a reply file exists, whatever attempt wrote it) |
| `lifecycle.py`, `state.py`, `baseline.py` | `start` and resume (a completed run rotates to `previous/`, the older one to `history/`, a dropped or failed one to `abandoned/`); `run.json`, `queue.json`, the run lock with driver and heartbeat, the operation mutex, the audit log; the read-only view of `previous/` (components, commits, changed paths, validated worker claims) |
| `worker.py` | the worker role's script side: the request and the tracked-file list, validation of the reply (paths, citations, versions, forbidden keys), the merge into candidates, verdicts and evidence, carry-over from the baseline, the dispatch prompt, the inline brief, the ready search flags, `check-unit` |
| `replyread.py` | the one tolerant reader of a role's JSON: the worker reply, the decisions files, the hints file and `reply` on standard input (a code fence of any spelling, a byte order mark, CRLF; an unclosed fence is read and noted) |
| `siblings.py` | the installed skills (`<dot-folder>/skills/<name>` holding a `SKILL.md`) and the run folders of the sibling skills (fixed names) in the workspace and one level below it, for the search flags of the worker role (`worker.leave_out_paths`, `worker.search_flags`); lists folders and opens, at most, a `run-manifest.json` (4 MiB) per folder of the workspace that is not a git repository, to recognise a design-review run folder, whatever it holds (a manifest inside a repository never counts; `in_package` marks the paths below a repository, which get no grep base name); a folder whose name has a control character, a backtick or an undecodable byte is not listed, because the names go into the brief |
| `delta.py` | what changed since the baseline per repository (`NEW`, `REMOVED`, `UPDATED`, with the cause) |
| `approval.py`, `human_approve.py` | binds an approval to the review file digest, numbered approval snapshots, stale detection, evidence level |
| `integrity.py`, `gitindex.py`, `pack.py` | `lstat`-only snapshots of the repositories (init, gate, each approval, final) and their comparison; the pack manifest of the skill folder |
| `runfiles.py` | the run-folder ledger (`.state/runfiles.json`): the SHA-256 of every file the script wrote below `sbom-out/`, checked when a command takes the operation mutex and sealed when it is done; a changed or deleted script file fails the audit, a file the script did not write is a warning; after the run finished, `closed_check` compares the folder with the sealed ledger read-only for `next`, `status`, `summary`, `explain` and `audit` (detect-only; `references/limitations.md`) |
| `audit.py`, `validate.py`, `jsonschema_lite.py` | phase 10: snapshots, per-repository validation (SPDX 2.3 and 2.3.1 schemas, CSV and SPDX agreement), promotion out of `.staging/` only on PASS |
| `enumerate.py`, `discover/` | which top-level folders are repositories; build systems, manifests, vendored copies, submodules, includes, licences |
| `verify/` | the rule engine that classifies each candidate (`USED`, `TEST_ONLY`, ...) and builds the evidence summaries and the decision validation for the adjudication |
| `cpe/` | the review file, hints, the curated CPE map, local decisions, and the NVD queries after approval |
| `emit/` | components, CSV, SPDX 2.3 JSON, CycloneDX 1.6 JSON (`cyclonedx.py`, checked by `cdxcheck.py`), the delta, the merged CSV, staging |
| `report.py` | the texts the agent relays and the files a person reads: gate and adjudication messages, `report.md`, `validation-report.txt`, `summary`, `explain` |
| `guardlib.py`, `humaninput.py` | what is left of the hook guard in a skill that ships no hook (readers that answer "no hook"); `sbomlib` still imports them |
| `context.py`, `paths.py`, `fsio.py`, `gitro.py`, `csvio.py`, `norm.py`, `ids.py`, `urls.py`, `versions.py`, `purl.py`, `errors.py`, `model.py`, `log.py`, `net.py`, `assets.py`, `selfcheck.py`, `csource.py`, `miniyaml.py` | layout, clocks and the HTTP interface; atomic and write-once file output; the read-only git wrapper; CSV; identifiers; the constants and record shapes; the only network code (`net.py`); asset loading; the environment probes |
