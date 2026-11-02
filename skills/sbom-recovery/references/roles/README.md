# Roles

A role is a Markdown file in this folder that holds the instructions for one kind of
unit of work. Roles are **files, not skills**: there is no `SKILL.md` below
`references/`, and a role has no frontmatter. The orchestrator in `SKILL.md`
dispatches a role by *reference*: a host subagent is told to read
`references/roles/<role>.md`, or the orchestrator reads it itself when the host has
no subagent tool (`inline-unit` writes a brief for the unit, the role file and the unit's
paths in one file, and prints its path; the script reads no worker reply of a unit that
was neither recorded as a subagent run nor begun with `inline-unit`, and cannot tell
whether the brief was read). The prompt for that is built by the script
(`dispatch-prompt`), never typed.

## Index of roles

| Role file | Used for | Units | Tier (`references/models.md`) |
|---|---|---|---|
| `worker.md` | the second reader of one repository: IDE projects, linker maps, toolchain runtimes, co-flashed images, and the places where the script's picture looks wrong. Returns claims with citations, never an SBOM entry | one per analysed repository: `worker:<repo>` | A when the host lets you choose |

The `usage`, `trace_build` and `hint` adjudications are not roles: the orchestrator
answers them itself from the rubric an `adjudicate` block names (`usage-rubric.md`,
`cpe-rules.md`), because they choose among options the script offered and cite
evidence ids the script produced. If a later version moves one of them into a
role, it becomes a file here and a unit kind in `driver.py`.

## Rules for every role file

- Open with the step-0 check (`check-unit`). A role that fails step 0, or whose prompt
  names a run directory or role file that does not exist, refuses with one
  `REFUSED step 0:` line and never searches for another.
- Name every file the role may write. The dispatch prompt says "write only the files
  your role file names", so the list in the role file is the whole permission. The
  worker writes exactly one file, `reply_file`, and answers `DELIVERED <unit id>`; a
  role with no tool that can write a file replies with the JSON itself and the
  orchestrator gives it to `reply <unit id>`.
- Harness-neutral wording: "your shell tool", "your file-reading tool". No product's
  tool names, no paths outside the skill folder, the run directory and the repository.
- The worker never dispatches another role. Only the orchestrator dispatches.
- What a role may do is a convention: nothing in a plain skill install stops it from
  reading or writing elsewhere. The script checks the reply and, at the end, that the
  repositories and the skill folder are unchanged (`limitations.md`).
