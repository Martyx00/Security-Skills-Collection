# Limitations: what this skill does not enforce

This is a plain Agent Skill. It runs on any host that loads skills, and in
exchange it gives up the controls an agent harness can enforce: hooks that block
a shell command or a write, per-agent allowlists, read denies, tool denylists
and a record of what a person typed. What the **scripts** enforce is still
enforced. What the **harness** used to enforce is now convention, and a model or
a hostile input can ignore a convention.

The table says, row by row, what holds and what does not. A reader of any
output of this skill should be able to see what was and was not protected for
that run: the approval evidence level and the enforcement statement are written
into `run.json`, `approval.json`, the audit log, the SPDX creation comment,
`report.md` and the summary. Nothing here is hidden or softened. The hardened,
Kiro-specific variant still exists in the frozen source repository.

## How to read "Strength now"

| Label | Meaning |
|---|---|
| **kept** | enforced by a script on every host |
| **same as before** | it was always a prose rule, and still is |
| **weakened, recorded** | enforced less strongly than before, and the evidence level is written into the run output |
| **detect-only** | a violation can be noticed after the fact, not prevented |
| **host-dependent, recorded** | depends on what the host provides; the result is recorded per unit |
| **lost** | nothing enforces it any more; it is a convention |

## Table

| Property | Was enforced by | In this skill | Strength now |
|---|---|---|---|
| Phase order, the approval gate, the run lock and operation mutex, file writes by the pipeline, staging of outputs and promotion only when the audit passes | the script state machine | same | **kept** |
| Schema validation of every output (SPDX 2.3 and 2.3.1 JSON schemas, CSV and SPDX agreement, evidence references), strict read-back of the review file, digests of the review file at approval, per-repository failure isolation | scripts | same | **kept** |
| Nothing leaves the machine before approval; afterwards only the names and versions of rows with `include=yes` and `action=lookup` go to the NVD API, through the script | the script, and the harness's network rules | the script (`net.py` is the only network code, and `sbom.py next` reaches it only after an approval is recorded) | **kept** for the script. The agent's own tools (web fetch, web search, a shell command) are not blocked: **lost**, convention only |
| The repositories stay unchanged. The script reads them only through a read-only git wrapper (an allowlist of plumbing subcommands, no hooks, no filters, no index refresh, no network) and compares integrity snapshots taken at `start`, at the gate, at each approval and at the end | the same wrapper and snapshots, plus the guard hook, which blocked an agent's writes and shell commands while a run was pending | the wrapper and the snapshots only | **kept** for what the script does. An agent's own write or git command is no longer prevented: **detect-only** (the audit fails when a tracked or untracked file, the index, a ref, a hook or the git configuration of a repository changed; a change made while the run waited for the person is reported as "paused", and one the IDE's Source Control view is known to cause as such, neither attributed). Object stores are compared at directory level. Git work trees the script cannot see (an ignored path outside the repositories) are invisible |
| The skill folder is unchanged during a run | `.kiro` git blob check | `start` records a manifest of `scripts/`, `assets/`, `references/`, `SKILL.md` and `VERSION` (`.state/pack.json`); the audit compares it with the folder as it is then and fails the validation when it differs | **detect-only**, and only for those files. A change followed by a restoration within one run is not seen. |
| Writes confined to `sbom-out/` and, for the agent, to the one file an `adjudicate` block names | guard hook and agent profile write rules | prose rules in `SKILL.md`; the script reads back only the file a block names and validates it (an unknown class, identity, version option or evidence id is refused; after a second invalid answer the item becomes `INCONCLUSIVE`) | **lost** as a block. Inside `sbom-out/`, the repositories and the skill folder **detect-only** (the rows above and below); anywhere else a write is invisible |
| Every file below `sbom-out/` is written by the script: no SBOM hand-built beside the real ones, no edited or repaired state file | guard hook and agent profile write rules | `.state/runfiles.json` holds the SHA-256 of every file the script has written. Each command that takes the operation mutex first checks the folder against the ledger the previous command sealed, and seals it again when it is done. The agent acts between two commands, so a difference is not the script's doing. A script file that was **changed or deleted** fails the check `run_folder_unchanged`: nothing is promoted, and the finding stays even when the file is put back (derived files may already rest on it). A **file the script did not write** is an ACTION REQUIRED warning in the gate message, `report.md` and the summary; it is not part of the SBOM and nothing is deleted or changed. After the run finished the ledger is not touched again, and every `next`, `status`, `summary`, `explain` and `audit` compares the folder with it, read-only: a script file that was changed or deleted since then makes the first line of the answer `RUN FOLDER CHANGED since the run finished: ...` (and the first warning, `RUN_FOLDER_CHANGED`), because the verdict and the outputs those answers quote may rest on it. The verdict of `summary` is PASS only if `run.json` and `validation.json` both say PASS; a disagreement is stated and shown as FAIL. No command writes to a finished run, so the script itself never causes this alarm. A file added after the run finished is mentioned, not a change. A person who edits `report.md` or an output of a finished run causes the alarm too | **detect-only, inside `sbom-out/`** (`sbom-out-pilot/` for a pilot). **Not covered:** the files an agent or a person legitimately writes (the `output` files of `adjudicate` blocks, `repos/<repo>/llm/` and `review/hints.json`, which the script validates when it reads them; the review file, whose digest the approval binds), `previous/`, `history/`, `abandoned/`, `.cache/` and `.tmp/`, and the logs. An agent that rewrites the ledger too is not seen (the two-file verdict above is the only thing left that it would also have to forge). A command killed before it sealed makes the next one take the folder as it finds it (INFORMATIONAL warning, no failure). A file reported as foreign is not tracked further, so removing it is not a failure. Writes outside `sbom-out/` stay invisible |
| No other command is run while a run is pending (the hook refused every shell command that was not an `sbom.py` subcommand) | guard hook | prose rule, and the command forms SKILL.md and the worker role forbid (`cd`, a pipe, a redirect, chaining, a shell variable or loop) | **lost**: convention only. The host re-check of 0.2.3 saw them anyway: `cd` into a repository in 17 of 44 worker shell calls and in forced-inline runs, `check-unit` piped into `grep` in 12 of 27 calls, a variable prefix and a loop in the orchestrator; every reply still validated, because the script checks the reply, not the command that produced it. Re-checked on 2.1.301 with this version: 0 of 10 shell calls of the three worker subagents used `cd`, a pipe or a chain; the forced-inline orchestrator ran 3 shell commands chained with `;` or `&&` in 1 of 3 sessions (one of them `cd` into a repository with a `| head`, one `cd` back) and said so itself |
| The agent never edits the review file | agent profile write deny and the guard hook | prose rule in `SKILL.md` and `review-file.md`; the approval records which cells differ from what the script wrote (`approval.json`, `report.md`) | **lost** as a block. **Detect-only** for the content (a changed cell shows in the diff), not for who changed it |
| **Human approval of the gate** | a hook that recorded what the person typed (`hook` evidence), or `human_approve.py` run in a terminal (`tty`) | `human_approve.py` in a terminal, recorded as `tty`; otherwise the agent runs `approve` after a chat reply, recorded as `agent-relayed` with an ACTION REQUIRED warning | **weakened, recorded.** A terminal check is a speed bump, not a boundary: an agent that can run shell commands can allocate a pseudo-terminal and type the word. `agent-relayed` means the script cannot tell who wrote the reply; if a hostile text in a repository made the agent run `approve`, the run would record the same thing as an honest reply. The strong form is the terminal, and `SKILL.md` says so |
| Text in the repositories is data, never instructions | prose; the router and the agent prompt repeated it | prose in `SKILL.md`; the script marks agent instruction files and host folders in the workspace as ignored and never analyses them | **same as before** (always prose). It is not a guarantee: a model can still be steered by what it reads in an `evidence_summary.json` or a build file |
| Fresh context and independence of the adjudicating agent | none: the Kiro version told the agent not to use sub-agents | the `usage`, `trace_build` and `hint` blocks are answered by the orchestrating agent itself and recorded as `inline`. The per-repository `worker` unit is dispatched to a host subagent when the host has one (`dispatch-record worker:<repo> subagent`), otherwise run inline: `inline-unit <unit>` writes the unit's brief (its paths and the role file, verbatim) to `repos/<repo>/worker.brief.md` and prints only that path and one instruction to read it in full. The script reads no worker reply of a unit it has no record of (`DISPATCH_RECORD_MISSING`) and none before the unit had its turn (`REPLY_NOT_YET_WRITTEN`); neither hold costs an attempt. For a subagent unit "had its turn" means the subagent of this attempt is recorded as finished (one that is still working has not failed, and the file attempt 1 left is not its answer). For an inline unit it means only that a reply file exists: the script does not know which attempt wrote the file and compares no file times (that would be a proof of reading by another name), so **an inline unit's existing reply file is judged at the next `next` whatever attempt wrote it**, the file a failed subagent left for attempt 1 included when the retry is moved to `inline-unit` (SKILL.md allows it after a failed spawn). If `next` runs before the file is written again, the old file fails again and the unit ends INCOMPLETE with an ACTION REQUIRED `WORKER_FAILED`; nothing is silent. The brief says to write the whole reply file again, and the text of `inline-unit` says that the file of the earlier attempt is still there and will be judged. An unchanged repository carries its claims over from the baseline (`carried`) | **host-dependent, recorded** per unit. Inline means the answer has the same context as the orchestrator and no independent second look. **The discipline of an inline unit is convention only and cannot be verified:** that the brief was read, that it was read in full, that each repository got its own call and its own reading, that nothing was carried over from the unit before, and that units were not batched. The script records the order of two files (`brief_first`, counted in the summary as "the order of two files, not a check that it was read") and refuses nothing for it: a reply written before the brief is judged on its content, because a check of file times is a proof of reading by another name (0.2.4 held such a reply once per attempt and counted `role_first`; both are gone). **Measured on Claude Code 2.1.301** (`claude -p`, no subagent tool, `claude-sonnet-5-5`; three sessions of three repositories): `inline-unit` was run for 9 of 9 units, bare, its output never piped or cut; the brief was read in full for 3 of 9 units (the first of each session: 361 lines, the unit's own paths in the first 21), for 5 of 9 only a window of 14 to 25 lines at its top (the unit's own paths, not the role text after them, which the model had read for the first unit), and for 1 of 9 not at all. An earlier session of the same design read it in full for 1 of 3 units and the top 22 lines for 2 of 3. With the older design that printed the role (0.2.1 to 0.2.4) the model piped or discarded the print for 2 of 3 units and in a clean rerun skipped the third `inline-unit` call. Every reply validated either way: the script checks the reply, not how it was prepared. Which model ran a subagent is not known either (the host does not say, so `model` stays `unknown`). What a model can decide is narrow (choices the script offered, evidence ids the script produced, `INCONCLUSIVE`; for the worker, claims whose paths and citations the script re-reads from the tree), and what it settles without proof is not shipped unedited (`verification=declared`, `include=no`) |
| What the model says to the person: the dispatch mode and why, the sentences at the start of a run, the gate text, the summary | prose in `SKILL.md`; the Kiro router repeated it | the script prints each as a block headed `==== SAY THIS TO THE PERSON ... ====` and ending `==== END OF WHAT TO SAY ====`, the last thing the command prints: `start` and `pilot` (three sentences), `dispatch-prompt` and `inline-unit` (the mode line, with the host tool to name, once, before the first worker unit), `next` and `approve` at the approval gate (the gate text; the `message` field of the JSON carries the same words) and `summary`, which is itself the text to post | **lost** as a block: no script can make a model speak. **Measured on Claude Code 2.1.301** (four sessions: three with no subagent tool, one with; two of them with the skills then installed for two hosts): the gate block was posted byte for byte in a fenced block as the first thing of the reply 4 of 4; the mode and its reason were said 4 of 4 (in the model's words or the block's); the summary was posted whole in a fenced block 4 of 4 (byte for byte 3 of 4; 17 of 18 lines in the fourth), with the `Enforcement:` and limitations lines; **the three sentences printed by `start` were said 0 of 4** (the model ran `next` at once and spoke first at the mode statement). Before the blocks, 8 of 8 earlier finishing replies dropped the `Enforcement:` line |
| A role's JSON reply is read the way a model writes it (`llm/worker.json`, the decisions files, `review/hints.json`, `reply` on standard input) | none: a plain `json.loads` | one reader, `sbomlib/replyread.py`: a fence of any spelling (`json`, `JSON`, `Json`, `jsonc`, an info attribute such as `json title="x"`, none; backticks or tildes, three or more, indented), CRLF and CR line ends, a byte order mark, a closing fence at the end of the object's last line. Nothing is dropped silently: an unclosed fence is read as far as it goes and noted; the lines of text outside the one fenced block are not read and are noted with their count; a second JSON object outside the block (a draft before it, an afterthought behind it), two fenced objects, a block that is not JSON and text with more `{` than the check can look at are refused with a message that names the cause and never echoes the content. A note goes to the unit's record in `run.json`, to an INFORMATIONAL `REPLY_NOTE` warning, to `worker_validated.json`, to `report.md` and to the "Replies read with a caveat" lines of `summary` | **kept.** What the reader cannot do is know which of two answers the model meant: it refuses |
| A search of the repositories does not return the skills installed beside them (this one included) | none: in the Kiro source the agent was denied the folder the skill lived in | `.ignore` in the skill folder tells ripgrep, and the search tools built on it (Claude Code's Grep tool is one), to skip `references/`, `scripts/` and `assets/` (anchored to the skill folder: a `tests/` of a repository under analysis is still searched; `SKILL.md` stays visible). The flags that `check-unit` and the brief print (`search_flags`, ready for `rg` and `grep`) name the run folder, this skill, every installed skill (`<dot-folder>/skills/<name>` holding a `SKILL.md`: ten folders for five skills on two hosts) and the run folders of the sibling skills (`.report-triage`, `.security-review`, `sbom-out`, `sbom-out-pilot`, `.binary-vuln-research`), at the workspace and one level below it, and a design-review run folder found by its `run-manifest.json` in a folder of the workspace that is not a git repository (a folder inside a repository is never recognised by a manifest, and a repository never is: in 0.2.6 a manifest under `src` in one repository put `--exclude-dir=src` on the grep flags and hid every `src` folder of every repository from the worker; a folder whose name holds a control character, a backtick or a byte that is not UTF-8 is not listed: a repository chooses such names, and they would be written into the brief; the same goes for a `run-manifest.json` that cannot be parsed) | **mitigated, not closed.** `.ignore` hides nothing from a model that opens a file by its path, from `rg --no-ignore`, from `grep`, from a host search tool not built on ripgrep or from the Glob tool (file names); **the other skills' files are hidden only if each of them ships its own `.ignore`**; the flags are put on a command by the model (convention), and a search the host's own tool makes takes none. **A repository can still choose what its own worker leaves out, by name (not enforced, because the listing looks one level into repositories on purpose, for a sibling skill that was run inside one):** a folder in its root named `.report-triage`, `.security-review`, `sbom-out`, `sbom-out-pilot` or `.binary-vuln-research`, or an installed skill in it (`.claude/skills/<name>/SKILL.md`), is left out of the worker's searches, by path for ripgrep and, for the first kind, by base name for grep (a folder of that name in another repository is left out too; a skill folder inside a repository gets no grep flag, because its name is the repository's choice). A design-review run folder inside a repository is not left out at all. The worker's claims are re-checked and never ship unedited, so the effect is less evidence from the second reader, not a wrong SBOM. Measured, the skills then installed for `.claude` and `.agents`, a fixture of three repositories, a search for `zlib`: `rg --hidden -l` returned 131 skill files (89 of this skill) against 9 product files with the version before this one (no `.ignore`; flags for this skill only), 42 (none of this skill) with `.ignore` and no flags, and 0 with the flags; `grep -rl` returned 46 and then 0. Claude Code 2.1.301's Grep tool, pattern `zlib`: 220 skill files (178 of this skill) against 6 product files before, 42 skill files (none of this skill) now. |
| The worker role reads only its repository, writes only its reply file and runs no git command | the Vibe worker profile: three writable files, no mutating command, read denies | `references/roles/worker.md` states the rules; the reply goes to one file the script names (`llm/worker.json`) and is validated in full (paths must be tracked files, citations are re-read, a CPE or purl is refused); the integrity snapshots would catch a change in a repository | **lost** as a block; **detect-only** for the repositories (rows above). A worker that read outside its repository cannot be seen, and a claim built on text it was fed by a hostile file is only as good as the citations the script could check |
| Per-agent tool allowlists of the Vibe `config.toml` (35 permission entries, one comment) | the Vibe harness | none: dropped as policy | **lost**, convention only |
| Model choice and reasoning effort | per-agent model pins | advisory only; the model is recorded when the host says which ran | **lost** on most hosts |
| Permission prompts and "never trust-all" advice | host permission prompts | the host's own; this skill cannot ask for them | **lost**: advise the person to approve each command, not to trust all tools |

## What the person should do about it

- **Approve in a terminal** (`scripts/human_approve.py`, the line is in the gate
  message) when the repositories or the result matter. Treat an `agent-relayed`
  approval as "the agent says the person approved".
- **Keep the workspace a plain folder** of repositories, not itself inside a git
  work tree (the script refuses that). Do not install this skill, or a copy of
  it, inside a repository you are analysing: code from that repository could
  then be the tool that runs.
- **Read the ACTION REQUIRED list for files the script did not write.** A hand-made SBOM
  beside the real ones is the thing to look for; remove what is not yours. A failed
  `run_folder_unchanged` means a file of the script was edited: start again.
- **Look at `git status` in each repository** after a run if you do not trust
  the agent; the audit already did the same comparison, but only as far as the
  snapshot goes.
- **Read `report.md`** first. ACTION REQUIRED items come first, then what was
  not covered.

## What every run summary must say

`sbom.py summary` and `report.md` print, in this order:

1. the validation verdict and whether the repositories are unchanged (and, when there
   are any, how many files in `sbom-out/` the script did not write);
2. the repositories and their status, and the promoted files (or, after a
   failed audit, that nothing was promoted);
3. the ACTION REQUIRED warnings (an `agent-relayed` approval, a repository that
   failed, an offline NVD) and the replies read with a caveat;
4. the approval evidence level;
5. the dispatch mode of each adjudication and worker unit (how many ran inline, how many were carried over, and how many inline worker units had their brief written before the reply file: the order of two files, not a check that it was read);
6. the enforcement statement ("harness enforcement: none") and the sentence "Not enforced on a plain skill install: see
   <absolute path of `references/limitations.md`>" (the path of the running skill: a bare name resolves to nothing from the
   workspace or from a saved report, and a project with two hosts holds two copies);
7. the NVD notice.

## Known limits of the analysis

These are about what the pipeline can know, not about what a host enforces. They
held for the Kiro original too and nothing here claims to have closed them.

- **The worker is a second reader, not a prover.** It can point at a component an IDE project or a map file shows, with citations the script re-reads; it cannot make a row ship. What it reads is also the model's own reading of text: a wrong but well-cited claim becomes a review row (pre-set `include=no`), never an SBOM entry.
- **Static analysis only.** No compiler, no configure step, no sandbox: the
  build is read, not run (`analysis_mode=static`). A macro or CMake variable
  that configure-time checks could set is `unknown`, never false.
- **Build systems it does not parse** (Kconfig, IDE project files, Bazel, Meson
  introspection, several lockfiles) make a repository `coverage=partial`; their
  unsettled rows go through `trace_build` adjudication and are not shipped
  unedited.
- **Incremental runs compare, they do not shortcut.** Every phase runs again over the whole tree; the baseline adds the changed paths, the delta and the carried-over worker claims of an unchanged repository. A baseline whose commit is no longer in the repository's history is reported as `unverified`, not guessed. A stale (failed) repository is not carried over from the baseline: it contributes nothing.
- **Archives and prebuilt binaries are not opened.** Link-line archives without
  a map stay `verification=declared` (`include` pre-set `no`). A binary scanner
  is a separate tool and is out of scope.
- **Versions.** Only a normalized release goes into the `version` field. A
  snapshot, a range, an unpinned reference or an uninitialized submodule gives
  `NOASSERTION` with the raw string and commit kept in `notes` and
  `upstream_commit`. No upstream repository is cloned.
- **The curated CPE map is small** (142 entries) and hand-seeded. A row
  with no entry gets a keyword search whose candidates are listed in
  `cpe_resolution.csv` and never emitted unedited. A CPE with an unknown version
  is `*` and flagged `cpe_version_wildcard=yes`. The NVD dictionary is not used
  before approval, so `version_in_dictionary` is `unknown` in the review file.
- **Licence and supplier** come only from the component's own top-level licence
  file (a fixed set of fingerprints) and from vendored SPDX or CycloneDX
  documents. Everything else is `NOASSERTION`.
- **The model's judgement is bounded, not removed.** Usage decisions can only
  choose among what the input offers and cite evidence the script produced;
  hints fill `alternatives`, which never ship unedited. A confident wrong choice
  among the offered options is possible.
- **NVD terms.** The notice wording ("This product uses the NVD API but is not
  endorsed or certified by the NVD.") was taken from a research note because the
  NVD page was unreachable when the tool was written; re-check it against the
  NVD terms of use page before redistributing outputs.
- **Platforms.** Run and tested on Linux, Python 3.9 to 3.13. It has not been run on
  macOS or Windows, so both are unverified, and a first run there can still show failures
  that need a skip or a fix.
  On Windows the integrity snapshots rely on weaker change times
  (`ctime_reliable: false`, stated in `report.md`).
- **Size.** The integrity walk is `lstat` only and stays well inside the time
  budget for ordinary workspaces; very large workspaces may hit
  `BUDGET_EXCEEDED`, which is retryable (reply "continue"). The run-folder ledger
  hashes every file below `sbom-out/` twice per command (288 MB took 0.3 s per pass
  on the machine of the review), outside the time budget of the units.
