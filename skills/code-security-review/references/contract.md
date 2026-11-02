# Pipeline Contract — the artifacts every stage reads and writes

This file is normative. Every script in `scripts/` and every role file in
`references/roles/` is written against it. A stage may add fields; it may not rename or repurpose one.

Schema version for everything below: **`schema_version: 1`**. A tool reading a
record with a higher `schema_version` than it knows must refuse, not guess.

---

> **This contract is four files.** Here (`contract.md`): why it exists (§0),
> the run directory (§1), the identity keys (§2) and what never happens (§9).
> Stage 1's artifacts (§3–§5) are in `pipeline-contract-stage1.md`; stages
> 2 and 3 (§6–§7) are in `pipeline-contract-stages.md`; stage 5 (§8–§8b) is
> in `pipeline-contract-stage5.md`. Section numbers are unique across all
> four. It was one file of 79401 bytes; read each part whole, with your
> file-reading tool, by line range when one read does not return all of it.
> The validator's own contract is `validator-contract.md` and
> `validator-reference.md`.

## 0. Why the contract exists at all

A model asked to run `ripgrep`, count its own hits and write the candidate
records is doing bookkeeping, and bookkeeping by a model drifts without saying
so. Measured, not hypothetical: one run of that shape pushed 2652 of 2750 hits
through `skipped` on a widened skip clause the rule never granted, and another
recorded 111 mechanical problems and still reported that the pipeline looked
well calibrated. A checker then has to re-run every pattern and refuse the run
when the counts disagree — which catches it, but only afterwards.

Here, discovery, candidate construction and ranking are **tool output**. The
model does recon, wrapper resolution, adjudication and reporting — the work that
needs judgement. Everything a script can do deterministically, a script does, and
the artifact carries the hash that proves what was scored.

---

## 1. Run directory

All run output lives at `.security-review/` in the **scanned repository's** root:
the working directory every command is run from. It is never written inside the
skill folder, which is read-only (the skill root comes from the scripts' own
location, the workspace from the working directory, and neither is derived from
the other). `review_run.py init` writes a `.gitignore` there on its first write
(stage 1 does too, when it is the first writer) that ignores everything but itself
and `ledger/` (below). Every path below is relative to the repository root.

```
.security-review/
├── .gitignore                      stage 1 — ignores everything but itself and ledger/
├── snapshot/                       stage 1 — the frozen working tree the run reads
├── snapshot-manifest.json          stage 1 — what was taken, what was refused, and why
├── run.json                        stage 1 — run identity, tool versions, git state, provenance
├── manifest.json                   stage 1 — roots, languages, exclusions, included paths, entry points, threat model
├── scope/
│   ├── scope.json                  stage 0 — the scoping pass, if it ran; stage 1 applies an approved profile
│   ├── attack-surface.md           stage 0 — the analyst's briefing: the map, the open questions, the profiles
│   └── graph.json                  stage 0 — entry points and reachability, if it ran
├── secrets/
│   ├── candidates.json             stage 1 — every literal a regex can find, redacted, and where a secret enters - §4a
│   └── inventory.json              stage 1 — the sweeper's verdict per secret - §4a
├── extract/
│   ├── functions.jsonl             stage 1 — ONE RECORD PER FUNCTION IN THE REPOSITORY
│   ├── rules.jsonl                 stage 1 — deterministic rule hits, joined to functions
│   ├── coverage.json               stage 1 — per-rule accounting
│   └── extract-report.json         stage 1 — parser used, fallbacks, unparsed files
├── scores/
│   ├── scores.jsonl                stage 2 — one score per function
│   ├── operating-point.json        stage 2 — the thresholds applied, and their provenance
│   ├── scorer-report.json          stage 2 — backend, calibration, timing
│   ├── partial.jsonl               stage 2 — what a stopped run had already paid for; --resume reads it
│   └── triage/                     stage 2 — the llm-triage backend's prompts, batches, answers and verdicts, if that backend ran
├── enrich/
│   ├── analyzers/
│   │   └── <analyzer>.sarif        stage 3 — raw analyzer output, copied in
│   ├── analyzer-findings.jsonl     stage 3 — normalised, joined to functions
│   ├── analyzer-runs.json          stage 3 — per-run completeness, never inferred from exit status
│   ├── dependencies.jsonl          stage 3 — the dependency track - §7a, never adjudicated
│   ├── packets/
│   │   └── <candidate_id>.json     stage 3 — the adjudication packet
│   └── queue.json                  stage 3 — the ranked dispatch queue
├── candidates/
│   ├── <category>.json             stage 3 — Validator Contract candidate records
│   ├── <category>-deferred.json    stage 3 — what the budget cut
│   ├── coverage.json               stage 3 — copied from extract/coverage.json
│   └── coverage-selection.json     stage 3 — the same rules, reconciled against what was dispatched
├── findings/
│   └── <candidate_id>.json         stage 4 — validator verdicts (a derived MEM-WFS one: <candidate_id>_WFS.json)
├── arbitration/
│   ├── precheck.json               stage 4 — mechanical results for every finding
│   ├── queue.json                  stage 4 — what the arbiter must review, and why
│   ├── ARB-<candidate_id>.json     stage 4 — one adjudication per queued finding
│   ├── summary.json                stage 4 — the arbiter's summary and calibration_flag
│   ├── cross-findings.md           stage 4 — root-cause clusters
│   ├── coverage-precheck.json      gate — verify_findings.py --candidates, written where it is told to
│   ├── arbitration-precheck.json   gate — verify_findings.py --arbitration, likewise
│   └── report-precheck.json        gate — verify_findings.py --report, likewise
├── previous/                       stage 3 — the last numbering's stage-4 artifacts, moved aside
├── upstream/
│   ├── plan.json                   stage 5 — optional: the upstream check's exact requests and local-history hints, shown before anything is sent
│   └── matches.json                stage 5 — optional: possible upstream reports - hints, never verdicts
├── ledger/
│   ├── decisions.jsonl             stage 5 — confirm / reject / needs-info
│   ├── suppressions.jsonl          stage 5 — author, reason, expiry
│   └── training/
│       └── samples.jsonl           stage 5 — export, training-sample shaped
├── dispatch/                       every stage — review_run.py: state.json (stop points the person settled, the mode), each unit's dispatch record, the validator batch plan, the arbiter's slice plan, the hand-out marks and the reply files
├── tmp/                            every stage — scratch: the one place a unit or the orchestrator may write anything the pipeline does not (a helper script, a dump of a long file); never read as the run's own, never committed, and listed by `review_run.py hygiene`
├── run-status.json                 every stage — how the run went, and the exit code for it
├── findings.sarif                  export — SARIF 2.1.0 for a code-scanning dashboard
└── REPORT.md                       stage 4 — the scout's report, and the artifact that leaves the building
```

That tree is not prose. It is rendered from `rules_lib.RUN_LAYOUT`.

`.security-review/ledger/` is the one directory that is **not** run-scoped: it
persists across runs and is meant to be committed. Everything else is a run
artifact and is never committed: while git lists anything there but the
`.gitignore` and `ledger/`, every tool that reads the run directory refuses
with exit `7` (below).

**Stage 3 renumbers candidates on every run**, from `CAND-0001`. Before it
writes, it moves every stage-4-and-later artifact keyed on the old ids into
`previous/<run_id>/`, where `<run_id>` is the one the last numbering was minted
under (read from the last `enrich/queue.json`): `findings/`, the `ARB-*.json`
records, `precheck.json`, `queue.json`, `summary.json`, `cross-findings.md` and
the three gate records under `arbitration/`, `upstream_check.py`'s
`upstream/plan.json` and `upstream/matches.json`, `REPORT.md`,
`findings.sarif` and `run-status.json`, and `review_run.py`'s validator plan and
the dispatch records of the validators and the arbiter (`dispatch/validate/` and
`dispatch/arbitrate/`; the sweeper's and the triage workers' records stay, because
stage 3 does not redo stages 1 and 2). A second archive under the same run
id is numbered beside the first rather than merged into it. It deletes
nothing and never touches `ledger/`. `enrich/queue.json` records where the
archive went, as `previous_numbering_archived`.

**The `.gitignore`.** Stage 1 writes `*`, `!.gitignore`, `!ledger/` and
`!ledger/**`, so the run artifacts stay out of git and the ledger does not. An
existing `.gitignore` there that ignores everything without carving out
`ledger/` has `!.gitignore`, `!ledger/` and `!ledger/**` appended; it is never
overwritten. The `.gitignore` un-ignores itself so that it is committed, by
design, which is why the run-directory check below carves it out.

**No tool writes through a link under the run directory.** The run directory
lives in the scanned tree, and that tree may commit files under
`.security-review/` — `ledger/` is meant to be committed. So a tool refuses,
with a non-zero exit and before anything is written, when `.security-review`
itself, any existing directory on the way to a file it writes, or that file is a
symbolic link, or when an in-tree run directory does not resolve to
`<realpath(root)>/.security-review`. `--root` itself may be a link. Writes go
to a temporary file created with `O_EXCL` in the target's own directory
(`mkstemp`), which then replaces the target through `os.replace`; nothing is
written through a predictable `<name>.tmp`, and a new artifact takes the mode
`open()` would have given it, `0666` less the umask.

**No tool reads what the scanned repository committed under the run
directory.** Every stage reads the files there as this run's own, so a
repository that commits them steers the run: a triage verdict or answer with
the right prompt digest, a `scores.jsonl` for `--resume`, an "approved"
`scope/scope.json`, a `secrets/inventory.json` that calls its key public, a
decoy `snapshot/`, SARIF, findings. A `git pull` between two stages also
replaces the run's own ignored artifacts with committed ones, silently. So
before anything under `.security-review/` is read, `rules_lib.run_dir_gate`
asks git, with the repository's config neutralised
(`pipeline-contract-stage1.md` §3), what the repository commits there.
Anything git lists under `.security-review/` in the index or in `HEAD` — in any
letter case, and with the code points HFS+ ignores, because on a Mac those
name the same directory; a file, a symbolic link or a submodule; on disk or
not — is refused, except exactly `.security-review/.gitignore` and regular
files under `.security-review/ledger/`, the two the `.gitignore` un-ignores on
purpose. A link or a submodule is refused even there. The check never reads
content, because a committed `.gitattributes` can make a shipped file look
locally modified. It ignores whether the file is still on disk, because a pull
puts it back. It asks `HEAD` as well as the index, because `git rm --cached`
empties the index and leaves the committed bytes on disk, untracked, where
nothing could tell them from the run's own.

| State | When | Outcome |
|---|---|---|
| `git` | git tracks the tree and was asked | passes when nothing but the carve-out is listed |
| `untracked-tree` | a repository encloses the tree but `HEAD` lists none of it: an unborn `HEAD`, or a directory not yet committed or under an ignored one. Only the index is asked | passes when the index lists nothing but the carve-out, with a note that provenance is unverified; refused otherwise |
| `no-git` | no `.git` at or above the tree | passes, with the same note |
| `unanswerable` | a `.git` is there and git cannot answer: git is not installed, git refuses the repository (dubious ownership: `git config --global --add safe.directory` with the path the refusal prints, the checkout's resolved top level), the `.git` is corrupt, or `HEAD` names no commit | refused |
| `bundle` | `--root` is this installed skill, an old copy of the scanner, or a directory inside one: not a repository under review. Git is not asked | refused |
| `missing` | `--root` is not a directory. Git is not asked | refused |

A refusal is exit `7` (`rules_lib.EXIT_SHIPPED`), the same in every reader —
`extract_functions.py`, `snapshot.py`, `score_functions.py`,
`sweep_secrets.py`, `enrich_candidates.py`, `verify_findings.py`, `ledger.py`,
`run_status.py`, `export_sarif.py`, `upstream_check.py` — before it reads or
writes anything under the run directory. `build_graph.py` reads nothing
there — it only writes `scope/graph.json` — and is exempt. The refusal names
each path, control characters escaped, and prints the remedy, which is the
operator's and never an agent's: `git rm -r -f -q -- <paths>`, plus
`rm -rf -- <paths>` for bytes a `git rm --cached` left behind, then
`git commit`, then a re-run from stage 1.
Not `git rm --cached`: it leaves the committed bytes on disk, where the check
refuses them while `HEAD` lists them and, once the removal is committed, can no
longer tell them from the run's own. A refusal on a repository nobody expected
it on is itself worth reporting: the repository is supplying the review's own
state. Every stage and every role runs the same check, `rules_lib.py
--check-run-dir --root .`, as its first action (step 0), and so does every
`review_run.py` command.

An unverified tree is reported as unverified, not as clean. The check passes
with a `note: run-directory provenance unverified` line, stage 1 records the
state as `run.json`'s `run_dir` (`pipeline-contract-stage1.md` §3), and
`run_status.py` adds the coverage limitation "the run directory's provenance is
unverified". Content under `.security-review/` is still trusted there, so an
operator scanning a tree that came from someone else empties
`.security-review/` before stage 1, keeping `ledger/` only if they trust
whoever wrote it. A committed ledger stays readable by design; the check
prints a note naming its files, because its suppressions hide findings and its
decisions count as a person's.

Two lines of the tree want a word the tree has no room for.
`manifest.json`'s `suspicious_content` holds `{file, line, text, source}` rows
— repository text addressed to the review — and `source` names who wrote each
one: the extract role, plus the scope role on the stage-0 `unverified_claims` it
copies in; the triage role; `enrich_candidates.py`, which replaces only its own
entries on each run; and at stage 4 the scout role, or the validator whose
verdict carried the text (`review_run.py ingest` copies it in). `claims_found` is a legacy spelling a manifest
written before the key was settled may still carry, and the candidates gate
folds it in as the same key, once per file:line. The gate counts them, and
`REPORT.md` must carry them in its Suspicious content section. And the gate
records under `arbitration/` go there unless `verify_findings.py --out` names
another directory inside `.security-review/`; any other `--out`, or one
reached through a link, is refused with exit `1`.

`manifest.json`'s `declared_scope` holds the same `{file, line, text,
source}` rows for what the project says about its own security scope — a
`SECURITY.md` threat model, a README or file header calling a component not
secure or test-only — and may carry the `proposed_test_tree_glob` stage 1
asked the operator about. It is a record, never an instruction: stage 1
moves a glob into `test_tree_globs` only on the operator's yes (with
`test_tree_globs_basis`), and that makes the code `test` to the score, the
ceiling and `FP-TEST` without removing it from review. No tool can check the
yes, so the findings gate queues for the arbiter every `FP-TEST` only a glob
bears out (`dismissal rests on the manifest's test_tree_globs`).

`manifest.json` is also stage 1's record of how it walked the tree. Each
exclusion is `{path, reason}`, plus `risk_if_skipped` when the entry stage 1
was given carried one, and stage 1 writes two fields for the stages that walk
the tree again: `included_paths`, the `--include` paths it honoured, and
`max_file_bytes`, the size above which it skipped a file. `exclusions` still
lists `vendor` after `--include lib/vendor`, because the pattern is waived only
under that path, so a stage that pruned by `exclusions` alone would walk past
code stage 1 scanned. Stage 3's declaration walk and `verify_findings.py`'s
coverage recount therefore both walk the recorded exclusions and
`included_paths` with stage 1's own matching (`extract_functions.is_excluded`,
copied into each and held to it by their selftests), and the recount skips
files over `max_file_bytes` too. Both fields are written on every run and never
read back by stage 1: a re-run without `--include` excludes the directory again.

### `snapshot/` and `snapshot-manifest.json` — what a line reference points at

Stage 1 records a line, stage 3 quotes it into a packet, stage 4 cites it in a
verdict, and a person reads it days later. Between any two of those, the working
tree is a directory somebody is still editing. One real run reported **19
candidate(s) quote a line that changed since stage 1 read it; the tree moved
under the run** — detected, reported, and unfixable after the fact, because every
one of those citations pointed at a file:line that no longer meant what the
finding said it meant.

So `snapshot.py` copies the tree to `.security-review/snapshot/` before stage 1
reads a byte, and `extract_functions.py --snapshot` scans that copy. The rules it
enforces are normative:

| | |
|---|---|
| **copy, never hardlink** | a hardlink is a second name for one inode, so an in-place edit rewrites the "snapshot" and its recorded hash, silently |
| **`.git` is never walked** | this pipeline is working-tree-only by design. The directory and a worktree's gitfile are both excluded, and neither is enumerated |
| **every exclusion carries a reason** | from a closed vocabulary, never prose. An exclusion nobody can see is a coverage hole that reads as a clean result |
| **the target's ignore files are not honoured** | `.gitignore` is read by nobody here. Modified, staged, untracked and ignored files are all taken, because "ignored by Git" is not "out of security scope" — an ignored `.env` is exactly what a working-tree secret sweep is for, and letting the audited repository choose what the audit may look at is the whole failure. Exclusions are pipeline-owned: the defaults above, plus `--exclude` |
| **symlinks resolve or are refused** | a link to a regular file inside the root is materialised as a copy; one that escapes the root, points at a directory, points into an excluded area, or dangles is refused and recorded. A link out of the root is never opened |
| **special files are named** | fifos, sockets and devices are refused with their kind recorded, never skipped silently |
| **mid-run movement is detected** | discovery stats every path, the copy re-stats the same inode and the path again, and a file that moved between them is listed in `changed_during_snapshot` |
| **caps are recorded when hit** | reaching `--max-files` or `--max-bytes` stops admission, records every path kept out, and exits non-zero. An incomplete snapshot must not read as a complete one |
| **the snapshot never widens read access** | each copy keeps its source's read bits and loses every write bit, owner read always kept; `snapshot/` is `0700`. A `0600` `.env` is not made world-readable by being copied |

**Paths stay relative to the original tree.** `--snapshot` changes where bytes
are *read*, never what is *recorded*: `run.json.repo_root`, the git state and
per-file churn come from the real repository, and every `file` in
`functions.jsonl` is relative to it — `src/proto/parse.c`, never
`.security-review/snapshot/src/proto/parse.c`. That is what lets a human open the
repository and find the line, while the bytes behind the citation cannot move.
`--emit-context` reads the snapshot automatically when `run.json` names one, so
a window's `text_sha256` still verifies after the tree has moved on. It follows
`run.json`'s `snapshot.root` only to the run directory's own `snapshot/`, and
not when that is a link: a `run.json` the tool did not write would otherwise
make it print files from wherever it said.

The gates read the snapshot the same way. The candidates gate recounts every
rule over the snapshot when `run.json` names one, keeping repository-relative
paths. The findings gate records `citation_source` (`snapshot` or the working
tree) and `tree_drift` — how many snapshot files the working tree has since
moved or lost — in its precheck summary; drift is a note, not a failure. A
cited line found in the working tree and not in the snapshot the run read is
`citation_live_tree`: neither verified nor fabricated, and queued for the
arbiter.

**One line model, everywhere.** A line number is 1-based and counts the
`"\n"`-delimited segments of the file's bytes decoded as UTF-8 with
`errors="replace"` — exactly as stage 1 counts them; the empty segment after a
final newline is not a line, and the `"\r"` of a CRLF line is part of its line.
Every later stage and gate uses the same model. `str.splitlines()`, which also
breaks on a lone `\r`, `\f`, `\v`, `\x1c`–`\x1e`, `\x85`, U+2028 and U+2029, is
not that model: a stage that used it quoted the wrong line for every hit below
the first such character.

**The snapshot is optional and the pipeline works without it.** A run with no
snapshot records `"snapshot": null` in `run.json` — a weaker provenance claim
stated explicitly, rather than an absent field nobody notices — and says so in
`REPORT.md` as well, which the report gate enforces
(`report_no_snapshot_unqualified`).

The manifest's shape:

```json
{
  "schema_version": 1,
  "tool": "snapshot.py",
  "tool_version": "1.0.0",
  "snapshot_id": "473367cc14267f10",
  "created_at": "2026-09-19T10:47:29Z",
  "source_root": "/abs/path/to/repo",
  "snapshot_root": "/abs/path/to/repo/.security-review/snapshot",
  "policy": { "materialisation": "copy", "git": "excluded: …", "symlinks": "…",
              "special_files": "refused and named", "excludes": [],
              "file_mode": "the source's read bits, never its write bits (0444 at most, 0400 at least)",
              "snapshot_dir_mode": "0700" },
  "counts": { "files": 2, "bytes": 91, "directories_walked": 3,
              "symlinks_materialised": 0, "excluded": 2, "copy_failed": 0,
              "changed_during_snapshot": 0 },
  "caps": { "max_files": 200000, "max_bytes": 4294967296, "hit": null, "stopped_at": null },
  "files": [{ "path": "src/proto/parse.c", "bytes": 6180,
              "sha256": "…64 hex…", "kind": "file" }],
  "exclusions": [{ "path": ".git", "reason": "git-metadata",
                   "detail": "git history is out of scope; the directory is not walked" }],
  "changed_during_snapshot": []
}
```

`kind` ∈ `file` | `symlink-materialised`; the second carries `symlink_target`.
`reason` is one of `git-metadata`, `run-directory`, `scanner-tooling`,
`sibling-run-directory`, `excluded-by-flag`, `symlink-escapes-root`, `symlink-to-directory`,
`symlink-to-excluded`, `symlink-broken`, `special-file`, `unreadable`,
`copy-failed`, `cap-max-files`, `cap-max-bytes` — and nothing else.

The scanner's own folders are excluded as `scanner-tooling`: this installed skill,
a skill installed for a host (a folder with a `SKILL.md` directly inside
`<dot folder>/skills/`; the `skills` folder around it and a folder in it with no
`SKILL.md` are the product's), and an old copy of the scanner inside a dot folder
(`rules_lib.tooling_reason`, found by identity and by the line `rules_lib.py` opens
with, never by a host's folder name). A project
install puts the skill inside the repository it reviews, so without this the
snapshot copied the scanner's rule tables and planted fixtures into the corpus,
and the stages after the snapshot imported the skill and rewrote its bytecode
mid-run, which read as the working tree moving. The run folders of the other skills
of this portfolio are excluded as `sibling-run-directory`: `.report-triage/` (which
holds the quarantined, possibly embargoed, report being judged), `sbom-out/`,
`sbom-out-pilot/`, `.binary-vuln-research/` (findings quoting decompiled code, and
extracted vendor archives), and a stride-design-review run folder, which has no fixed
name and is recognised the way that skill finds it, by a `run-manifest.json`
whose `envelope` names a `runRoot` and a `docsRoot` (`rules_lib.SIBLING_RUN_DIRS`,
`holds_design_run`). Each holds a copy of the product or a text about it, never the
product: read as source it doubled every function with a twin, and the secret sweep
reported the quarantined report's tokens as the product's. The extractor walks the same
folders the same way and lists each one it left out as `tooling_skipped` in
`extract/extract-report.json`; on a `--snapshot` run, where its own walk never meets
them, it copies the snapshot's `scanner-tooling` and `sibling-run-directory` exclusions
there (`path`, and the words in `detail` before the parenthesis as `reason`), and
`run.json`'s `snapshot` block carries them as `scanner_tooling`. `secrets/candidates.json` lists what its own
walk skipped under the same name, `run-status.json` states the folders as a coverage
limitation, and `review_run.py summary` names them in `tellThePerson`.

`unreadable` and `copy-failed` are two sides of one `OSError` and the
distinction is the point: `unreadable` is a fact about the tree being scanned,
`copy-failed` is a fact about the machine doing the scanning. They used to be
one term, so ENOSPC halfway through a copy was recorded as the repository's
fault and the run still exited 0 — against this tool's own rule that an
incomplete snapshot must not read as a complete one. Any `copy_failed` is now
exit 4, the same code a cap gets, for the same reason.

`files`, `bytes`, `symlinks_materialised`, `excluded`, `copy_failed` and
`changed_during_snapshot` are recomputed from `files` and `exclusions`, never
asserted beside them. `directories_walked` is the one count that cannot be: it
is an independent walk counter with no list beside it, and it counts
directories in the SOURCE rather than in the snapshot — a `--max-files 0` run
records 1 walked and 0 files. It is spelled for what it counts, because spelled
`directories` it read as a third summary of the lists below and was not one.

`snapshot_id` is `sha256` over `<path>\0<sha256>\n` for every file, sorted by
path, truncated to 16 characters. Two snapshots share an id if and only if they
hold the same bytes at the same paths, so "same id" is not reachable by quietly
dropping something. `snapshot.py --verify` re-hashes the directory against this
manifest and exits 5 if they disagree.

**Stage 1 reads the run directory's snapshot only as `snapshot.py` wrote it.**
`--snapshot` refuses a symbolic link at `snapshot/` or at
`snapshot-manifest.json`, a manifest whose `tool` is not `snapshot.py` or whose
`source_root` or `snapshot_root` is not an absolute path, and one whose roots
are not this snapshot and this `--root`. `snapshot.py` records both roots as
absolute real paths; a relative one would resolve against the working
directory, where a committed decoy `snapshot/` beside `"source_root": "."`
passes both comparisons without knowing where the checkout is, and becomes the
corpus.

### `run-status.json` — how the run went, for whatever has to act on it

Written by `run_status.py`, from artifacts and **never from prose**. It is the
only authoritative answer to "how did the run go?", and the only exit code in
this skill that is about the run rather than about a tool.

The failure it prevents is the one §6 already names inside the report and
nothing named outside it. A run that stopped after stage 3 has its candidates
dispatched, no verdicts, and every artifact on disk parsing cleanly. Count the
findings in it and the answer is zero — which is also what a clean repository
looks like. `not_selected_is_not_a_clean_bill` stops "unexamined" being read as
"cleared" inside `REPORT.md`; this file stops an *incomplete run* being read as
a clean one from outside, where the reader is a CI job that only ever sees an
exit code.

```json
{
  "schema_version": 1,
  "generated_at": "2026-09-19T11:05:14Z",
  "generated_by": { "tool": "run_status.py", "version": "1.0.0" },
  "run_id": "2026-09-18T18-49-03Z",
  "execution_state": "incomplete",
  "stages_completed": ["extract", "score", "enrich"],
  "stages_missing": ["adjudicate", "arbitrate"],
  "confirmed_findings": 0,
  "review_candidates": 3,
  "dismissed": 12,
  "accepted_risk": 1,
  "incomplete_tasks": 95,
  "tool_failures": 0,
  "gate_failures": [],
  "coverage_limitations": ["18012 function(s) scored below the operating point and were never adjudicated: …"],
  "secrets_findings": null,
  "dependency_findings": 0,
  "not_selected": 18012,
  "not_selected_is_not_a_clean_bill": true,
  "exit_code": 3,
  "exit_reason": "Required analysis is incomplete: …"
}
```

`execution_state` ∈ `complete` | `incomplete` | `setup_failed`.

### Where every number comes from

| Field | Derived from |
|---|---|
| `stages_completed` / `stages_missing` | `run.json.stages_completed` for `extract`, `score`, `enrich`; **artifacts** for `adjudicate` and `arbitrate` |
| `confirmed_findings` / `review_candidates` / `dismissed` / `accepted_risk` | the ARB record's `final_verdict` where there is one, the validator's `verdict` otherwise — counting only records that belong to this run's candidate of the same id (the same `rule_id`, citing the candidate's file). Candidate ids restart at `CAND-0001` every run, so a previous run's record under a reused id adjudicates nothing and is a `gate_failure` |
| `incomplete_tasks` | dispatched, unsuppressed `enrich/queue.json` entries with no `findings/<id>.json` of this run's, plus `arbitration/queue.json` entries with no matching `ARB-<id>.json` |
| `tool_failures` | `enrich/analyzer-runs.json` runs whose `status` is `failed` or `partial` |
| `secrets_findings` | `secrets/inventory.json` entries that §4a's rule makes findings — `kind == "secret"` and `origin == "literal"` — and no others |
| `dependency_findings` | records in `enrich/dependencies.jsonl` |
| `not_selected` | `scores/operating-point.json` |
| `gate_failures` | the `problems` recorded by `verify_findings.py`'s four prechecks, plus any artifact a completed stage says it wrote that is absent, does not parse, or is on disk in a shape its writer never emits (JSON `null` included), plus any verdict or ARB record that does not belong to this run's candidate of the same id |

**`stages_completed` is not a copy of `run.json`'s.** Only `extract`, `score` and
`enrich` ever append their own name; stages 4 and 5 are a model and a person, so
nothing appends theirs. A tool that read only that list would call a run complete
the moment stage 3 finished, which is the exact misreading this file exists to
stop. `adjudicate` and `arbitrate` are established from the artifacts instead: a
candidate that was dispatched and has no verdict, and a finding the precheck
queued that the arbiter never adjudicated, are tasks that did not reach a
terminal state.

**`secrets_findings` is `null` when there is nothing countable**, and `0` only
when the sweep ran and found no hardcoded secret. Collapsing the two would make a
stage that never ran report a clean one, which is this file's whole subject. An
inventory that is *on disk* and is not one — no `entries`, an `entries` that is
not an array, an entry that is not an object — is also `null`, and is a
`gate_failure` saying the file exists, because "the sweep did not run" is a false
sentence about a file somebody wrote.

**`secrets_findings` is computed from §4a's rule, never read off `is_finding`.**
That field is written by the agent that judged the candidates and it is the one
field in the inventory that can be wrong; `sweep_secrets.py`'s `status` records
both directions of it going wrong on a real run, which is why that command
computes the rule too. A hardcoded secret filed as `is_finding: false` must not
become a `0` in the one artifact a CI job reads, and the two tools must not print
different numbers from the same file. Every entry whose `is_finding` contradicts
the rule is a `gate_failure` as well — the count is right, and the artifact it
came from is not.

**`accepted_risk` is counted apart from `dismissed`.** `ACCEPTED_RISK` exists so
that "real, and knowingly accepted" is not filed as "not a bug"; folding it into
`dismissed` would undo that in the one artifact a machine reads. It is not folded
into `confirmed_findings` either — exiting non-zero on a risk somebody already
accepted is how a gate gets switched off.

**`coverage_limitations` is populated, not empty-by-default.** One actionable
sentence per hole, drawn at minimum from: functions below the operating point,
every analyzer run whose `status` is not `complete`, any `window`-tier extraction
share, deferred candidates, stale and expired suppressions, languages present in
the tree that the extractor has no parser for, files the walk could not read,
stat or fit under the size cap, rule hits that joined to no function record,
functions the operating point selected that produced no candidate (with why no
`LOG-TRI` was derived for them), the functions that were reviewed only because a triage
model rated them high (`LOG-TRI`), and candidates whose quoted sink line drifted since
stage 1 or could not be re-read.
An empty list is a claim, and on a real repository it is usually a false one.

### The exit policy, and its precedence

| Code | Meaning |
|---|---|
| `0` | required analysis completed; nothing blocking under policy |
| `1` | completed, with findings or candidates requiring action |
| `3` | required analysis incomplete |
| `4` | setup, configuration or gate failure |

```text
setup failure > incomplete analysis > policy findings > no policy findings
```

The precedence is normative and is the reason the field exists. **A run that is
both incomplete and has findings exits `3`, not `1`** — an incomplete run with
findings looks exactly like a successful run with findings, right down to the
non-zero exit, and `1` is the code a CI job is most likely to have an exception
for. Counts stay in the file when the exit code can only express one condition.

`run_status.py --check` recomputes the status and exits non-zero when
`run-status.json` disagrees with the artifacts beside it, so the file cannot
drift from what produced it. Its exit codes for that — `2` for drift, `5` for a
tool failure — are deliberately outside the four above, so that a wrapper cannot
mistake one for a verdict about the run. `5` covers every way the tool itself
fails, including one nobody predicted: an escaping exception would leave through
`sys.exit(main())` as `1`, and `1` in the table above says the run *completed*.
`7` is outside them too: like every reader, `run_status.py` refuses a run
directory the scanned repository commits into before it reads anything (§1),
and a refused run directory is not a run it can report on.

---

## 2. Identity — three keys, and why there are three

A single ID cannot do all three jobs, and conflating them is how a scanner either
loses its cache or silently keeps suppressing a function somebody rewrote.

| Key | Shape | Stable across | Used for |
|---|---|---|---|
| `function_key` | `<rel_path>::<name>::<ordinal>` | edits to the body | suppressions, cross-run joins, the ledger |
| `content_hash` | `sha256(normalised_body)[:16]` | nothing — changes with the body | cache invalidation, staleness detection |
| `function_id` | `<function_key>@<content_hash>` | nothing | the identity written into run records |

`ordinal` is the 0-based index of this definition among definitions **with the
same name in the same file**, ordered by `line_start`. It exists for C statics,
C++ overloads, and Python methods sharing a name across classes. A file with one
`parse_tlv_record` gives it ordinal `0`.

`normalised_body` for hashing is the function's source text with:
1. trailing whitespace stripped from every line,
2. runs of blank lines collapsed to one,
3. a trailing newline enforced.

Comments are **not** stripped. A comment change is a change: a `/* safe: bounded
by caller */` that stops being true is exactly the edit a stale suppression must
not survive.

**Suppression staleness.** A suppression records the `content_hash` it was
created against. When the current hash differs, the suppression is reported
`stale` and **does not suppress**. This is not configurable.

---

## 3. `run.json` — stage 1
**Moved, unchanged, to `pipeline-contract-stage1.md` §3.**

## 4. `extract/functions.jsonl` — stage 1
**Moved, unchanged, to `pipeline-contract-stage1.md` §4.**

## 4a. `secrets/inventory.json` — stage 1, and the one rule it turns on
**Moved, unchanged, to `pipeline-contract-stage1.md` §4a.**

## 5. `extract/rules.jsonl` and `extract/coverage.json` — stage 1
**Moved, unchanged, to `pipeline-contract-stage1.md` §5.**

## 6. `scores/scores.jsonl` and `operating-point.json` — stage 2
**Moved, unchanged, to `pipeline-contract-stages.md` §6.**

## 7. `enrich/` — stage 3
**Moved, unchanged, to `pipeline-contract-stages.md` §7.**

## 8. `ledger/` — stage 5
**Moved, unchanged, to `pipeline-contract-stage5.md` §8.**

## 8b. `upstream/` — stage 5, optional
**In `pipeline-contract-stage5.md` §8b.**

## 9. What never happens

These hold for every stage, and the tools enforce the ones a tool can enforce.

1. **The scanner never navigates the repository.** Stages 1–3 are deterministic
   tools. The only stage with a model that chooses where to look is stage 4, and
   it looks where the queue sends it.
2. **No stage auto-fixes.** No script in this skill writes to the scanned tree,
   and no role is told to: every role writes inside `.security-review/` and
   nothing else (each role file names the files it may write). **The scripts
   enforce that for what they write; nothing enforces it for what a model writes
   with its own tools** (`references/limitations.md`). The run directory itself
   lives in the scanned tree, which may commit `.security-review/ledger/`, so a
   script writing under it refuses when `.security-review`, any existing
   component beneath it on the write path, or the target file is a symlink, or
   when the run directory does not resolve to `<realpath(root)>/.security-review`
   (§1); `--root` itself may be a link. A role does not write the ledger: only
   the review stage's `ledger.py` commands do. A role whose run-directory check
   refuses, or whose reply path or role file does not exist, stops with a one-line
   refusal; it never writes the file some other way, and never goes looking for a
   path it was not given.
3. **No unadjudicated score is ever shown to a person as a finding.** A score is
   a ranking. `REPORT.md` carries adjudicated findings; scores appear only as the
   ordering and the coverage account, and `verify_findings.py` fails a report
   whose confirmed-findings section presents a finding with no ARB record
   (`report_unadjudicated_finding`) or one whose ARB record's `final_verdict` is
   not `VULNERABLE` (`report_unconfirmed_finding`).
4. **An uncalibrated number is never called a probability.** §6, enforced in
   code, with no override flag.
5. **What was not selected is never reported as clean.** §6, enforced by the
   report gate.
6. **The scanned repository never answers for the run.** Before any tool reads
   the run directory, git is asked, with the repository's config neutralised,
   what the repository commits under `.security-review/`, and anything but the
   `.gitignore` and regular files under `ledger/` stops every reader with exit
   `7` (§1), as does a `.git` git cannot answer for. The fix is the operator's,
   never an agent's. A tree git does not track cannot be asked, and is reported
   as unverified, not as clean.
7. **Nothing leaves the machine unless the operator saw exactly what would be
   sent and said yes.** The model calls the operator configured are the
   exception they chose: every stage talks to its model provider, and the
   `finetuned` backend to its endpoint. The one step that sends anything
   anywhere else is the optional upstream check at stage 5
   (`pipeline-contract-stage5.md` §8b): `upstream_check.py plan` prints every
   request, offline, with a digest over them; `query` re-derives them and
   sends them only when that digest matches.
   `query` is a person's command: it refuses unless standard input is a
   terminal and the person types a confirmation word, shown beside the plan, that
   changes on every run (`upstream_check.py`, exit 4). A host's own approval prompt
   used to be a third lock; a plain skill install has none, and a terminal check
   is a speed bump rather than a boundary (`references/limitations.md`).
