# Inline mode — the units, run in one context

Read `references/orchestrator.md` first. This file replaces only its §3 ("Dispatching
units") for a host that has **no tool that starts a subagent**, or whose first spawn
failed. Everything else is the same: the loop, the stages, the three stops, the
scripts, the gates, the record of how each unit ran.

**Inline is the fallback, not a shortcut.** Size, speed and cost are never reasons for
it. It keeps every mechanical guarantee (the candidate gate, citations checked against
the snapshot, schema checks on every verdict, the report gate) and gives up one thing
the pipeline is built on: that the validator reaches its verdict from the candidate
and the source alone, in a context nobody has coloured. Here one context plays the
validator, then the arbiter that audits it. The arbiter's check of a verdict it has
just watched you reach is one context agreeing with itself, and **the person is the
arbiter** of whatever the inline units concluded. The summary says so, and so do you.

## What changes

1. Record the mode once, with the reason named:
   `review_run.py mode inline --because "<the missing tool, or the failed spawn>"`.
2. Run each unit yourself, one at a time, in the order `next` gives. Start every unit with
   `python3 -I -B <skill folder>/scripts/review_run.py inline-unit <unit id>`
   It runs the step-0 check, writes the unit's **brief** to a file under
   `.security-review/dispatch/` (the unit's role file in full, then the unit's task: the candidate
   or the queue, and the files you write), marks the unit open, and prints that file's path and
   one instruction. **Read the file in full with your file-reading tool**, as many reads as the tool
   needs, not through the shell: not with `cat`, `head`, `sed`, `rg` or a pipe. A host run did
   all of these to what `inline-unit` used to print: 42 of its 46 commands were filtered (line 1
   kept with `head -1` or `sed -n 1p`, the role file dropped, fields such as `guards`, `ceiling`,
   `linkage` and `callers` cut from the candidate), and a first-line key stopped none of it. That
   is why the output is now a path: there is nothing in it to keep or to cut. The brief is the
   one file under `dispatch/` you open besides your reply file; the role file's rule about
   `dispatch/` is about everyone else's. The tool refuses to begin another unit while one is
   open, so no unit's reasoning carries into the next.
3. Do the unit exactly as its role file says. Step 0 is already done (the script ran
   the run-directory check before it wrote anything); everything else in the role
   file applies, including what it forbids you to open: a validator unit does not
   read `findings/`, `arbitration/` or `dispatch/`, however easy it would be here.
   Write the unit's file with your file-writing tool, at the path the unit's task
   printed, in one call. Your reply to yourself is the `DELIVERED <unit id>` line.
4. Finish it with the command that takes the work in, with `--dispatch inline`:
   `review_run.py ingest <unit id> --dispatch inline`. It refuses `--dispatch inline` for a unit
   that was not begun with `inline-unit`; it asks for nothing else, because nothing a script can
   ask for shows that the brief was read. Read the next unit's task only after it has accepted
   the work. (`ingest --stage` is for units that ran in subagents; an inline unit is taken in by
   name.)
5. Never compress: a validator unit is the same call, with the same candidates and the
   same playbook, as it would be in a subagent. A batch of five is five verdicts in one
   reply file, worked one at a time (`validator-contract.md` §2 rule 6).

## What is a convention here, and cannot be checked

Reading the brief in full before every unit, doing one unit at a time, forgetting between units and
reading nothing a role forbids: none of it is verified by anything. The tool can refuse to begin a
second unit while one is open and can refuse an `ingest --dispatch inline` for a unit that was
never begun; it cannot see what the model read, in what order, or whether a unit's reasoning
leaked into the next. Nor does it compare the time a reply file was written with the time the unit
was begun: that check was weighed and left out (no reply in 179 inline units of four host-run sets
was written before its begin, and a model set on getting past it rewrites the file).
`references/limitations.md` has the row, with what a host run measured.

## What to keep apart, because nothing else will

- **Forget between units.** After `ingest`, do not carry a unit's reasoning, its
  conclusion or its candidate into the next. The next unit is a different question.
  Re-read its role file even when it is the same role as the last one: `inline-unit`
  prints it for exactly that reason.
- **The arbiter unit is the hardest.** It audits verdicts you reached in this same
  context. Follow its role file's ordering literally (mechanical results, then the
  independent re-derivation of the crux, then the validator's argument), and expect to
  agree with yourself. If you notice you are agreeing with everything, say so in its
  `notes` (the role file asks for that), and the summary and the review session will
  show the rate.
- **Triage batches** are the same: one batch per `inline-unit`, answered from the
  manifest and its parts only, the answers written in one call.
- **The secret sweeper** is one unit, run after the extractor and `sweep_secrets.py
  candidates`.

## Telling the person

The final output says that units ran inline and which ones (`review_run.py summary`
counts them and its `tellThePerson` says it), that the independence the validators and
the arbiter are meant to have was not there, and that the findings are therefore a
list for a person to decide, not a list that two independent contexts agreed on. A
mix is possible only when a spawn failed part-way: the units that did run in a
subagent are recorded as such, and the rest as inline.

If the host lets you choose a model for later subagents, `references/models.md` says
which tier each role prefers.
