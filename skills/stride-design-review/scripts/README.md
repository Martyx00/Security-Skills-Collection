# Scripts

The programmatic tools of the skill: the deterministic spine that runs a STRIDE design review, validates every artifact of
it and produces every digest. `stride_run.py` is the run driver: it starts a run and writes every file of it that is not a
model's judgement. The roles and the coordinator tell the model which command to run; the tools decide whether an artifact is
acceptable. No tool writes or reads a model's judgement, and none may be replaced by a script the model writes.

## Rules

- **Standard library only.** Every import is stdlib or local to this folder. The
  skill declares Python 3.9 (`metadata.python-min`): the scripts pass on 3.9 to 3.13, and nothing kept from the
  sources needs more (the Kiro package's `pyproject.toml` says 3.10; the Vibe package needs 3.11 only for the `tomllib` of its
  dropped profile code).
- **Two roots, never derived from each other.** The *skill root* (`Path(__file__).resolve().parents[1]`) is read-only: it
  holds `VERSION`, `assets/schemas/` and these scripts. The *workspace* is the working directory: the corpus, the run
  directory (`runRoot`) and every output live there. A tool refuses an `--output` below the skill root
  (`corpus_manifest.py`, `corpus_diff.py`), and `preflight.py` refuses a `runRoot` inside it.
- **Run with `python3 -I -B`** (fallbacks `python -I -B`, `py -3 -I -B`) from the workspace root, writing the skill
  folder's absolute path in front of `scripts/`. Isolated mode drops the script's own folder from `sys.path`, so each tool
  that imports a sibling adds its folder itself.
- **Plain output.** A tool prints one result on stdout (`valid: <path>`, a digest, JSON) and every problem on stderr as
  `ERROR: ...` lines; the exit status is 0 for success and non-zero for any problem. The validators never repair.
- **UTF-8.** Every text file is read and written as UTF-8, and `validate_report.py` reads standard input as UTF-8, because
  reports and quotes contain em dashes and section signs.
- **No host paths, no home directory.** `digest.py` holds the one list of paths a review must not read or bind (credentials,
  history, and the files and folders agent hosts load as instructions or configuration), compared case-insensitively on
  path parts. A file inside the corpus is judged by the part below the corpus root; the corpus folder itself is judged from
  the workspace (the working directory, or `--workspace-root`) down, so `--docs-root .ssh` is refused while a workspace
  that sits under a host's folder still works.

## Tools

| Script | What it does | Typical call |
|---|---|---|
| `stride_run.py` | the run driver (below): `init`, `next`, `mode`, `dispatch-prompt`, `inline-unit`, `dispatch-record`, `unit-check`, `accept-stage`, `sweep-record`, `freeze`, `verify-request`, `verify-record`, `queue`, `calibration`, `finalize`, `check`, `summary`, `inbox`, `fail` | `stride_run.py next` |
| `corpus_manifest.py` | create or verify the byte-bound corpus manifest: per-source SHA-256, bytes, extraction metadata, the aggregate digest; refuses a corpus holding a refused path, a symlink, or the skill folder, and a corpus folder that is itself a refused path (`--workspace-root` says what it is judged against; default the working directory) | `corpus_manifest.py <docsRoot> --output <runRoot>/corpus-manifest.json`, then `--verify <manifest> --allow-unreadable` before every stage |
| `preflight.py` | corpus hygiene before a run: envelope shape, paths inside the workspace, no overlap of corpus and run root, no symlink, no refused path, optional files exist, `resourceIsolationConfirmed` false. It does **not** attest the host's isolation | `preflight.py <runRoot>/envelope.json --workspace-root .` |
| `validate_report.py` | validate a JSON artifact against a schema in `assets/schemas/`, or a Markdown report (`--kind stage1\|stage2\|final`) against its mechanical contract: chapters, tables, ID resolution, counts, the four-part issue record, exact quotes (bound to the corpus manifest), the derived decision outcome. `--stdin-json` validates a reply that is not written to a file; a reply file checked with `--schema` is read the same way. The reply may be a bare object or one fenced block, read by `replyread.py` | `validate_report.py <report> --kind stage1 --docs-root <docsRoot> --corpus-manifest <manifest>` |
| `validate_run.py` | the cross-artifact validator for a complete or resumable run: manifest (schema 1.1), digests, queue projection, sweep ranking, ledger legality, dispatch records, calibration, and the rule that the run root holds nothing the run does not reference, in every mode and at every stage (the one exemption is the reply file of a delegated unit that is still open) | `validate_run.py <runRoot> --workspace-root .` |
| `digest.py` | every SHA-256 a coordinator must stamp (`file`, `canonical`, `schemas`) and the Stage 3 digest reconciliation (`stage3 <runRoot> --check`); the one list of paths a review must not read or bind | `digest.py stage3 <runRoot> --check` |
| `corpus_diff.py` | the deterministic source delta between two corpus manifests (delta mode) | `corpus_diff.py <old manifest> <new manifest>` |
| `replyread.py` | the one reader for the JSON a role hands back: any fence spelling (info string and case, backticks or tildes, a closing fence on the object's line), a byte order mark, a fence left open read and noted, two answers refused; a library, imported by `stride_run.py` and `validate_report.py` | |
| `jsonschema_subset.py` | the JSON Schema subset the validators need; a library, imported by the others | |

## The run driver

`stride_run.py` is the only writer of the run's mechanical files, so nobody types a digest, a manifest, an index, a ledger or a
request by hand (a model cannot compute a digest by inspection). It imports the other tools as libraries and runs
`validate_run.py` itself after every step that could leave a run the validator rejects (`init`, `accept-stage`, `freeze`,
`finalize`, an accepted `verify-one` result), and prints `"done": true` only when the whole run passed it. Every command that
accepts something into a run (`accept-stage`, `sweep-record`, `verify-record`, `finalize`) first recomputes the corpus digest:
a mismatch fails the run closed.

| Command | Writes | Refuses |
|---|---|---|
| `init --mode M --docs-root D --run-root R --lens L --dispatch subagent\|inline --because TEXT --inherited TEXT\|none` | `envelope.json`, `corpus-manifest.json`, `run-manifest.json`; for a later mode also the copied Stage 1/2 reports, `stage-3/sweep-input.json`, or the verify-one request | a hostile corpus, a run folder that is not empty, a report that does not validate against this corpus, a missing dispatch reason or inventory |
| `next` | nothing | |
| `mode inline --because TEXT` | the dispatch mode, the envelope | after a unit was recorded as a subagent, and back to subagent |
| `dispatch-prompt UNIT [UNIT ...] [--retry]` | nothing (prints the prompt; several units print a batch, each under an `=== UNIT ===` header line) | a unit the run is not ready for (one such unit refuses the whole batch) |
| `inline-unit UNIT [--retry]` | `dispatch/<unit>.brief.md` (the task, the commands that finish the unit, for a verifier its blinded request, then the role file in full), bound into the manifest; prints only its path and one instruction | a subagent run (except the explicit inline fallback verification), a unit the run is not ready for |
| `dispatch-record UNIT subagent\|inline [--model NAME]` | the dispatch record, the stage state, the model fields | a mode that is not the run's |
| `unit-check UNIT` | nothing (prints the invocation record) | a corpus that is hostile or no longer the bound one |
| `accept-stage 1\|2` | binds the stage report into the manifest; prints `done` (true for a `stage1` or `stage2` run whose folder validates) | a report that does not validate (one regeneration, then terminal); a corpus that is no longer the bound one (terminal) |
| `sweep-record [--from-inbox [--returned]\|--from-file F\|--check]` | `stage-3/sweep-result.json`, ranked and numbered; `--from-inbox` reads `inbox/sweep.json` (the sweep's own reply file) and removes it; `--check` applies every rule and records nothing | an invalid reply (a file from the inbox is left alone until `--returned`; then the run fails closed and the reply is kept as `stage-3/sweep-rejected.json`), a second reply, a missing reply file |
| `freeze` | `stage-3/issue-index.json`, `stage-3/verification-ledger.json` | a queue over `maxQueueSize`, a second freeze |
| `verify-request [KEY...\|--all]` | `stage-3/verifications/<key>/attempt-N-request.json`, the ledger entry | a request that is not owed |
| `verify-record KEY [--from-inbox [--returned]\|--from-file F\|--no-reply\|--inline\|--terminal]` | the reply exactly as received (from stdin, or the role's `inbox/verifier-KEY-N.json`, which is then removed), the ledger entry; for `verify-one` also the run status and `done` | a reply for another unit (nothing is recorded), a missing reply file, a file from the inbox that does not validate until `--returned` (a draft), a corpus that is no longer the bound one (terminal) |
| `inbox [--discard-stale]` | removes the reply files in `inbox/` that no open unit expects (never a file that is not a reply file) | |
| `queue`, `calibration`, `summary`, `check` | nothing (`summary` also prints `runCheck`: the result of `validate_run.py`) | |
| `finalize` | binds `final-review.md`, sets the run completed | an item without an accepted result, a final report or run that does not validate |
| `fail --because TEXT` | the run status | |

`init`, `mode`, `freeze`, `finalize` and `summary` (and `accept-stage` or `verify-record` when they print `"done": true` in a narrower mode) end with a plain-text block headed `==== SAY THIS TO THE PERSON ... ====`: the sentences the person is to be told, built from the run's files, the last thing the command prints. The JSON before it is unchanged. Nothing can make a model say it (`references/limitations.md`).

Units are `designer`, `gap`, `sweep` and `verifier/<queueKey>/<1|2|inline>`. Exit status: 0 done, 1 an artifact or a reply was
not acceptable (the JSON on standard output says why: `errors`, `next_action`), 2 usage or order. `--run-root` is optional when the
workspace holds exactly one run folder; every command the tool prints names it.

## Exit conditions worth knowing

- `validate_run.py` is checkpoint-aware: before Stage 3 it validates the manifest, corpus, stage-state ordering and only
  the artifacts that should exist. A digest it cannot reconcile is terminal, never repaired.
- `corpus_manifest.py --verify` compares only the aggregate digest, so it passes whatever extraction metadata is on file;
  `--allow-unreadable` stops it demanding metadata for non-text sources it is only re-hashing.
- `digest.py file` refuses a path on the deny list (and a directory or a missing file) rather than hashing it.
