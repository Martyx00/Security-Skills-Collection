# Scripts

The programmatic tools of the skill: the deterministic spine that owns the state
machine, validation and file writes. SKILL.md tells the model which subcommand to
run; the script decides what is allowed next.

## Rules

- **Standard library only.** Every import is stdlib, local to this folder, or
  inside `try: ... except ImportError:` with a stdlib fallback. The floor is the
  `python-min` in the SKILL.md frontmatter (portfolio floor 3.9).
- **Two roots, never derived from each other.**
  - The *skill root* comes from `__file__` and is read-only: it holds code,
    rules and assets. Global installs are shared and plugin caches can be
    read-only, so nothing is ever written there.
  - The *workspace root* is the current working directory and holds all state
    and output (`.<skill-name>/`, a run directory, reports).

  ```python
  from pathlib import Path

  SKILL_ROOT = Path(__file__).resolve().parents[1]   # scripts/ is one level below
  WORKSPACE = Path.cwd()
  ```
- **No host paths, no home directory.** The lint rejects, in string literals and
  calls: `.kiro` and `.vibe` (`PY-HOSTPATH`), absolute user paths such as
  `/Users/...`, `/home/...` or a drive letter (`PY-ABSPATH`), host variables such
  as `${CLAUDE_SKILL_DIR}` (`PY-HOSTVAR`), and home-directory lookups:
  `~/...`, `$HOME`, `%USERPROFILE%`, `Path.home()`, `expanduser("~...")` and
  reading `HOME` or `USERPROFILE` (`PY-HOME`). A line that has to name one on
  purpose (a test of the lint, a deny-list entry) carries the pragma
  `check-skills: allow-path` in a comment.
- **Run with `python3 -I -B`.** Isolated mode drops the script's own folder from
  `sys.path`, so a script that imports a sibling module adds its folder itself:
  `sys.path.insert(0, str(Path(__file__).resolve().parent))`. `-B` keeps
  `__pycache__` out of the skill folder.
- **JSON out, validation errors on stderr.** Subcommands print one JSON object on
  stdout (`dispatch-prompt` prints the prompt text itself). Several commands follow
  that object with plain text for a model to copy whole, and a reader that parses
  the first JSON document is unaffected: the packet commands (`scoutpacket`,
  `candidatepacket`, `challenge`, `refutepacket`, `packet --lens exploit`) print one
  delimited dispatch prompt per unit they just built (the first `scoutpacket` of a
  run puts a block of what to say to the person before them), `inline-unit` prints
  the path of the unit's brief file and one instruction, and `summary` ends with the
  block to say to the person. Text and not JSON, because JSON escapes every newline
  and a model that copies an escaped prompt re-flows it. A reply from a role
  that does not validate is refused with a message on stderr that names what to
  fix. There is no `next_action` state machine and no scripted approval gate: the
  order of the stages is held by what each command refuses (for example `finding`
  will not record an `ABSENT` unless `dismissal` passed, and `dismissal` will not
  stand unless every hunter angle ran), and the procedure is in
  `references/orchestrator.md`. `check-run-dir` is the one command that prints
  `next_action` (`continue` or a `STOP` line). Nothing here asks a person to
  confirm anything: the skill sends nothing, and a person reads the assessment and
  sends any reply.
- **Exit codes.** 0 success. 1 `check-run-dir` (or `inline-unit`, which runs it)
  refused the run directory, or `finding --check` found no valid finding file. 2 a
  usage error (a `--unit` that names no reply file, a unit of the wrong role, an
  inline unit that was not begun, one begun while another is open), or a reply that
  did not validate (the report id, the unit id, a lead, an adjudication, a
  refutation, a hunt). `finding` alone also uses 3 (the reply is not valid JSON),
  4 (not a valid verdict) and 5 (refused by the dismissal gate).
  `verify_findings.py` exits 0 and reports what it queued in its output, and 2 on
  a usage error.
- **Encoding.** Open every text file with an explicit `encoding="utf-8"` and
  `newline` handling that works with `\r\n`; the scripts are written to run on Windows
  and have not been run there.
- **Self-test.** `scripts/selftest.py` builds its fixture in a temporary directory and
  runs offline.

## Tools

All of them run from the workspace root (the repository being triaged) as
`python3 -I -B scripts/report.py ...` (or another script in the table), with the
path resolved against the skill folder. State goes under `<workspace>/.report-triage/`; nothing is written in the
skill folder.

| Script | Subcommands | Purpose |
|---|---|---|
| `report.py` | `init`, `intake`, `extract`, `anchor`, `probe`, `deps`, `advisory`, `packet`, `surface`, `list`, `summary`, `report` | intake and quarantine, claim extraction (regex, never a model), anchoring and near-miss detection (a report whose every claimed symbol is absent, with no near miss, CVE, package, file or endpoint that is here, gets its one waiting question printed as a block, last: `differentProductShape`), the concept probe, dependency resolution, the assessment |
| `report.py` | `scoutpacket`, `lead`, `leads`, `candidatepacket` (`--from-hunts` for what the hunters found), `round`, `adjudication`, `synthesise`, `refutepacket`, `refutation`, `panel`, `challenge`, `hunt`, `dismissal`, `finding` | the swarm: packets out, validated replies in, convergence ranking, the code answer by table (`synthesise` and `round --advance` refuse while a packet of the round has no adjudication or `--fallback`; at most three scout rounds, `roundCapReached`), the refutation panel, the dismissal gate. Every command that takes a report id takes it first or as `--id` |
| `report.py` | `check-run-dir`, `dispatch-prompt`, `dispatch-record`, `inline-unit`, `suspicious` | step 0 (is the run directory ours and unplanted, what appeared outside it since `init`, which copies of a report sit in the repository where an exploit-side search can read them, and, for a unit, `replyFile`, `leaveOutOfSearches` (the run directory, every installed skill, the sibling skills' run folders, an in-tree copy of the report) and `searchFlags`, the ripgrep and grep flags that keep those paths out of a search, ready to paste; a grep flag whose base name the product also uses is not printed, `grepLeftOut`), the subagent prompt for a unit or for every unit of a stage (`--stage <report_id>/<role>`) with its paths filled in, the dispatch record (`subagent` or `inline`, per unit, with the in-tree copies for exploit-side units) that `summary` and the assessment print (for the arbiter it also reads the file the arbiter wrote, as every ingest command reads a reply, and exits 2 with the cause when it cannot), `inline-unit` (an inline run's step 0, brief file and open mark for one unit: the brief holds the role file, the packet paths, the reply file and the finishing command, and only its path is printed; a reply already on disk is moved aside; never for a refuter or the arbiter), and the report lines addressed to a reviewing tool |
| `report.py` | `lead`, `adjudication`, `hunt`, `refutation`, `finding` with `--unit <unit id>` and `--dispatch <subagent\|inline> [--model NAME]` | the five commands that take a role's reply read it from the file the role wrote (`reports/<id>/replies/<role>[.<qualifier>...].json`; refuses a symbolic link or a path outside the run directory; the used file is renamed `*.recorded.json`, a rejected one `*.rejected.json`) and, once the reply is accepted, record how the unit ran, so one command carries one exit status and nothing is piped or redirected. `--from-file` and stdin remain |
| `verify_findings.py` | `--root . [<report_id> \| --id <report_id>]` | citation, grounding, near-miss, version and lens-leak checks; builds the arbiter's queue; resolves the anchors in the arbiter's prose and names (`arbitrationUnreadable`, `arbitrationNotes`) an `ARB-<id>.json` it could not read or read from an unclosed fence |
| `selftest.py` | `[--verbose] [--keep]` | offline exercise of the tool surface against a fixture built in a temporary directory. Run it on an install to tell a broken install from a bad input |

The tools are not runnable from inside the skill folder: `report.py` refuses a
workspace that is the skill folder or below it (exit 2), because the skill folder
is read-only and may be shared.
