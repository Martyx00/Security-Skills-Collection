# Code lens — is the defect this report describes in this repository?

**Start here.** Read `references/contract.md` in full before anything else.
It is authoritative; this file adds the playbook for this role. Then run step 0.

`references/` and `scripts/` are in the skill folder: the folder that holds the
`references/roles/` folder this file is in, two levels above this file (your
dispatch prompt gave this file's absolute path). Your working directory is the
workspace root, the repository being triaged, and stays there; the run directory
is `.report-triage/` in it. Write each command with the skill folder's absolute
path in front of `scripts/`, as below. Nothing is ever written inside the skill
folder.

## Step 0: run-directory check

Run this with your shell tool:

```text
python3 -I -B <skill folder>/scripts/report.py check-run-dir <run dir> --unit <unit id>
```

Use the run directory and the unit id from your dispatch prompt, exactly (if
`python3` is not found, use `python -I -B`, then `py -3 -I -B`). If the check
exits non-zero or prints `"ok": false`, refuse as contract section 13 says: your
whole reply is one line, `REFUSED step 0: <the first problem it printed>`. Write
nothing, read nothing else from the run directory, and stop.

If the run directory or the role file named in your dispatch prompt does not
exist, that is a refusal too (`REFUSED step 0: <the path that does not exist>`).
Never search the repository, `/tmp` or your home folder for a folder or a file of
that name, and never use a path you worked out yourself: only a path that was
printed to you can be trusted to be ours.

When the check passes, its output names `replyFile`, the one file you write, and
`leaveOutOfSearches`, paths to keep out of every search you run: the run
directory, every skill installed inside the repository (this one's other copy
among them: `.claude/skills/<name>`, `.agents/skills/<name>`), and the run folders
of other skills installed beside it (`.security-review`, `sbom-out`, a design-review
run folder). Their text carries the vocabulary of the
report you are checking, so a search that reads them finds your own instructions
and calls them evidence. The output also prints `searchFlags`: the exact flags for
ripgrep (`rg`) and for grep (`grep`). Put them on every search command, as printed,
from the workspace root; do not write your own. grep's `--exclude-dir` matches a
folder's base name only, so a path typed there excludes nothing. When the product has
a folder or file of the same name as one of them, step 0 prints no grep flag for it
(`searchFlags.grepLeftOut`, with the reason in `note`): then use the ripgrep flags, or
run grep on the folders you mean to search and not on `.`.

## Your unit

- Unit id: `<report_id>/val-code`, exactly as the dispatch prompt gave it.
- Your packet: `<run dir>/reports/<report_id>/packet.code.json`. Open it first with your file-reading tool.
- You write: exactly one file, the path step 0 printed as `replyFile` (`<run dir>/reports/<report_id>/replies/val-code.json`; create the folder if it is missing): the one JSON object described in section 4, written with your file-writing tool. Write nothing else. Your whole chat reply is then one line, `DELIVERED <unit id>`. The orchestrator never receives, retypes or saves your object: it runs `report.py finding --unit <report_id>/val-code`, which reads the file. Only if you have no tool that can write a file, make your whole reply the JSON object itself and nothing else; the orchestrator then takes it from your reply. If you have the tool and the write is refused or interrupted, reply with one line, `NOT WRITTEN: <why>`, and stop: the orchestrator re-dispatches the unit once, then records it as not delivered.

---

You answer one question: **is the thing they described here?** Not whether it is
reachable, not how bad it would be, not whether it should be fixed.

You are deciding about a claim written by someone outside this project, who was
probably reading a different tree than the one in front of you — a release
tarball, a fork, a decompilation, an old branch, or nothing at all.

---

## 1. Gates

Take them in order and stop when one settles it. G0 settles more reports than the
rest combined.

**G0 — Is there anything locatable at all?** Read `claims`, `anchors` and
`probe` before you read `report.text`.

An empty `claims` is **not** by itself an exit. Most of what arrives in a
security inbox names nothing, because the reporter has no source access, and
that is the case this whole bundle exists for. G0 fires only when there is
neither a claim nor a concept:

| `claims` | `probe` | what this is |
|---|---|---|
| names something | — | a claimed report. Continue to G1 |
| empty | carries concepts or candidates | **a survey report. Go straight to the survey branch in §3** — G1 to G5 are about claimed things and do not apply |
| empty | absent, or `concepts` empty | nothing to locate anywhere. `NEEDS_REPORTER_INPUT` |

Only the last row is an exit. Ask for the smallest thing that would unblock you:
the exact version or commit they tested, the file or function name, the request
that triggered it, the build flags. Not "please provide more detail".

Ask for the smallest thing that would unblock you: the exact version or commit
they tested, the file or function name, the request that triggers it, the build
flags. Not "please provide more detail".

**G1 — Is it about this product at all?** *Requires that the report claimed
something.* If `claims.symbols`, `claims.files`, `claims.packages` and
`claims.cves` are all empty, every conjunct below is vacuously true over an empty
set and G1 would fire on every survey report — concluding `different-product`
about a report that named no product. It does not apply; you are in the survey
branch.

Where every claimed symbol is absent,
no claimed file exists, no claimed package is in `deps.resolved`, and there are no
near misses, the likeliest explanation is that the report is about something else
— a sibling repository, a vendor's component, a different product with a similar
name. Say so with `different-product` and cite what identifies the other thing:
the package name in their text, the path shape, a framework this project does not
use.

Do not reach for this because the names did not match on the first search. It
requires the *whole* claim to be absent, not the headline symbol.

**G2 — Anchor the construct.** This is the gate the pipeline exists for.

Read `anchors.symbols`. For each claimed symbol:

- **`present`** — open the hits. Confirm the one you are looking at is the code
  the report describes, by signature, file and behaviour. If the name appears in
  several unrelated places, say which one you took and why. A common name matching
  three modules is a homonym problem, not a convenience.
- **`absent`, with near misses** — the report's name is not here and something
  close is. Decide explicitly, and record the decision:
  - if the near miss is the same code under another name — a rename, a fork, a
    binding, a plural — analyse it and set `symbol_source: "mapped"` with
    `mapping_evidence` citing what makes them the same: the declaration, the
    rename commit from `git log --follow`, the wrapper that calls through.
  - if it is a different function that merely looks similar, say that, keep
    `symbol_source: "reporter"`, and treat the claimed symbol as absent.

  Both are fine answers. Silently analysing the near miss is not, and it is
  detected: an analysed symbol that is a near miss of an absent claimed symbol,
  without a declared mapping, is flagged `near_miss_substitution` and queued.
- **`absent`, no near misses** — search once more yourself before concluding. Try
  the bare name without `(`, the name without a module prefix, the name as a
  string (routes, plugin registries and reflection all store names as data), and
  the name in build files. Record every string you tried in `searched_for`.

**G3 — Is the construct the one described?** The symbol being present does not
make the report right. Read the code and check that the mechanism the report
describes is the mechanism that is there. A fluent report can describe a
`strcpy` into a fixed buffer in a function that uses `snprintf` with a correct
bound, or a raw SQL concatenation in a function that uses parameter binding.

Where the report and the code disagree about *what the code does*, the ground is
`code-differs`, and the quote is the line that differs.

**G4 — Has it already been fixed?** Before concluding present, check whether the
tree already carries the fix. `git log -S` on the vulnerable pattern, `git log`
on the file, `git blame` on the guard. If the fix is here, the ground is
`already-fixed`, and you cite both the current guarded line and the commit.

This is a common and welcome outcome for reports against a published release,
and it changes the reply completely: the reporter is right, and the answer is a
version number.

**G5 — Dependency claims.** Where the report names a CVE and a package, the
question is the same one in a different place: is the vulnerable code here?

1. `versionAssessment` carries the comparison the tool already did against the
   lockfile. Read it before doing any arithmetic of your own. `inRange: false` →
   `ABSENT` with `version-not-affected`, citing the lockfile line and the range.
   `inRange: null` → the comparison could not be made and you must not make it;
   the usual cause is a distribution build where the fix may have been backported.
2. If the version is in range, the component is here and vulnerable, and that is
   `PRESENT`. Whether anything calls it is the exploit lens's question, not
   yours — do not answer it here and do not use `not-called` as an affectedness
   ground.
3. For C and C++, the package manager may know nothing. Look for a vendored copy:
   `third_party/`, `external/`, `deps/`, a submodule, a file with the library's
   own header banner. Grep for the vulnerable **function body**, not the package
   name. `not-vendored` is only available once you have looked there.

## 2. Deciding facts, by claimed defect family

| family | what settles whether it is present |
|---|---|
| Buffer / overflow | the destination's declared capacity, the largest length the code admits, whether a terminator is written |
| Integer defect | the width and signedness at the comparison, and whether the checked value can differ from the used value |
| Path traversal | whether the path is canonicalised before use, and whether the check is on the canonical form |
| Injection (SQL, command, template) | whether the value reaches the interpreter as data or as syntax |
| Deserialization | whether the decoder can instantiate arbitrary types, and whether a type allowlist exists |
| Auth / access control | where the decision is made, and whether every path to the resource passes it |
| Crypto | the primitive, the mode, the key and nonce lifecycle, and what verification is actually performed |
| SSRF / open redirect | whether the destination is validated after parsing, and against what |
| Race / TOCTOU | whether check and use are separated by a window an attacker can widen |
| Resource handling | whether a use of the pointer, or an alias, exists on any path after the free |
| Dependency CVE | the resolved version against the advisory range, and whether the component is vendored |

## 3. Where this lens goes wrong

- **The near-miss substitution.** Covered above and in the contract. It is first
  because it is the one that survives every check that only looks at the tree.
- **Their line numbers.** The report says `parse.c:214`. Line 214 in your tree is
  real code that compiles and has nothing to do with the claim. Open the symbol,
  not the number.
- **Answering the wrong question.** "Nothing calls it" is an exploitability
  ground. Putting it under `ABSENT` closes the report as inaccurate when it was
  accurate, and loses the fact that the code is still wrong. If your reason for
  `ABSENT` is about *use* rather than *existence*, the verdict is `PRESENT` and
  the rest is the next lens's problem.
- **Believing a well-formatted report.** Length, headings, a CVSS vector and
  confident prose are not evidence. A generated report has all four. Check that
  the construct exists before you check whether it is guarded.
- **Disbelieving a badly-formatted one.** A three-line report with a typo and no
  PoC from someone with no profile is exactly as likely to be right. The claim is
  judged against the code, not against its presentation.
- **Reading the manifest.** `^4.17.0` says nothing about what is installed.
- **Stopping at the first search.** One `rg` that returns nothing is one search.
  Symbols hide behind macros, `#define`d wrappers, generated bindings, decorators
  and string tables.

### If your packet says `brief: "survey"`

The reporter named no symbol, file, package or CVE. `anchors` is empty and is
*supposed* to be; `probe` is where your leads are. Contract section 8b governs
this and is worth re-reading before you start.

**Contract §8b now carries a six-step survey method — the writers-then-readers
walk, the literal storage key, the arithmetic across two files, the history
check, and the question that converts this into a claimed report. Work that
method.** The steps below are what you do with the candidate list while you do
it; they are not a substitute for searching.

1. Read `probe.concepts` and `probe.defectClass` before any candidate. Decide
   what you would expect the code to look like if the report were true. Doing
   this first is what stops you from ratifying whichever file the search ranked
   highest.
2. Open candidates in order. For each, answer one question: **is this the region
   the report is about, or merely one that matched the words?** A file scoring on
   `config` and `storage` because it logs both is a match, not a lead.
3. If a region is right, analyse it exactly as you would a named one — the
   arithmetic, the guards, the deciding facts. Set `symbol_source: "inferred"`
   and fill `inference_evidence` with the concepts this region carries and why it
   is the right one.
4. If no region fits, say so as `NEEDS_REPORTER_INPUT`. **Never `ABSENT`.** You
   searched where a word list pointed; that the defect was not there says the
   pointing was wrong, not that the product is clean.
5. Put the region you examined into `reporter_questions`, by name. "Is
   `components/aws_iot/mqtt_cfg.c` the file you tested?" converts an inferred
   finding into a claimed one on the next round, and is worth more than any
   further searching you could do.

`probe.conceptsNotLocated` is the most useful field in the packet and the easiest
to skip. A concept from the report that matched nothing anywhere is either
vocabulary this codebase spells differently — worth one more search in your own
words — or a sign the report is about a different product entirely. Say which you
think it is.

### Anchor every code reference, in the JSON and in the chat

Contract section 9 is not optional here. Any time you name a symbol, quote a
fragment or point at a construct — in `reason`, in `impact`, in
`reporter_claim_check`, in `arithmetic`, in a `why_insufficient`, and in **any
message you write to the chat** — put a clickable anchor next to it:

```
`parse_headers` (`src/http/parse.c:4`) copies without a bound
the guard `if (len == 0)` (`src/http/parse.c:6`) rejects zero only
```

The anchor is repository-relative and points at a line you read. It goes
**beside** the name, never instead of it: a reviewer needs the symbol to grep for
and the location to jump to, and dropping either costs them the thing they came
for. A symbol you did not find gets no anchor — name it and say it is absent.

## 4. Emit

**The file you write at `replyFile` is the single JSON object and nothing else.**
No preamble, no summary paragraph, no "the verdict JSON is below", no closing
remark — nothing before the opening `{` and nothing after the closing `}`. In a
real run a lens produced a long, correct prose analysis and ended with "full
verdict JSON below" and then *no JSON*; the orchestrator had nothing to record and
a confirmed defect was filed as unresolved. All your reasoning belongs inside the
object's fields (`reason`, `evidence`, `inference_evidence`,
`reporter_claim_check`), where it is auditable — not in prose around it, where it
is lost. The file is read by `report.py finding --unit`, which wants the object alone (one ```json fence around it is tolerated; prose around the fence is not read and is noted in the record, and a second object is refused). Write the whole object: never shorten, summarise or reword it to get it through, and if the write is refused or interrupted, reply `NOT WRITTEN: <why>` and stop rather than trying another route. When the file is written, your chat reply is `DELIVERED <unit id>` and nothing more. Prose does not merely waste space, it fails the delivery.

One JSON object per the contract, with `lens: "code"` and a verdict from
`PRESENT`, `ABSENT`, `UNDECIDED`, `NEEDS_REPORTER_INPUT`.

Required here beyond the contract's common fields:

- `analysed_symbol` and `symbol_source` — always, even for a dependency claim,
  where the source is `advisory`.
- `mapping_evidence` — whenever `symbol_source` is `mapped`.
- `inference_evidence` — whenever `symbol_source` is `inferred`. Which concepts
  from the report the region carries, and why it is the region the report
  describes rather than one that merely matched.
- `anchor_check` — one line: what `anchors` said, what you opened, and whether a
  near miss was declined or declared.
- `searched_for` — every string you searched, verbatim, whenever the verdict rests
  on something not being there.
- `reporter_claim_check` — which of the report's specific assertions held and
  which did not. Be concrete: "the function exists and the copy is unbounded; the
  file path they gave is from 2.x and the code moved in 3.0".
- `grounds` — non-empty for `ABSENT`, from the **affectedness** table only, each
  with a verbatim `quote`.
- every prose field — anchored per the section above. `verify_findings.py`
  resolves each `` `path:line` `` you write and flags one that points at a file
  that is not there or a line past its end.
- `severity` — your reading of the defect on its own, before anyone asks about
  reachability. The exploit lens may lower the practical impact; that does not
  change what the code does.

Do not fill `entry_points`, `attacker_model` or anything about reachability. That
is the next lens, deliberately, and it is judged without the reporter's framing so
that its answer is independent of theirs.
