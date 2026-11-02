# The run folder and its files

Read this before writing the first file in `.binary-vuln-research/`. Everything here is
embargoed: never commit it, copy it out, or paste it anywhere (SKILL.md, Hard rules).

## Layout

```text
.binary-vuln-research/
  .gitignore                 "*", written before anything else
  run-log.md                 intake record, gate answers, sessions, sweep log, suspicious text,
                             correction log
  artifacts.md               one row per artifact
  candidates.md              one row per candidate, KILLs and OPENs included
  candidates/BVR-NNNN/       notes.md (working record; kill evidence quoted in blocks),
                             packet.md and reply.md (Phase 3)
  findings/BVR-NNNN.md       one per RAISE
  briefs/BVR-NNNN-E<k>.md    one per experiment, written before Gate C
  summary-<round>.md         the round summary
  addendum-<round>-<k>.md    a correction to something the person saw
  work/                      everything else: extract/<first 12 hex of SHA-256>/, decompiler
                             projects, dumps, probe and debugger logs, runs/BVR-NNNN-E<k>-<m>/
```

Every file here that quotes an address, offset, symbol, file:line, hash or secret (a finding,
brief, summary, addendum, packet, reply or notes) quotes it in `citations` or `excerpt` blocks, which
`scripts/verify_citations.py` re-reads against the artifacts: grammar and bases in
`references/citations.md`.

IDs `BVR-NNNN` are zero-padded, assigned in sweep order, and never reused or renumbered across
rounds. Experiments are numbered per candidate (`E1`, `E2`), runs per experiment.

## run-log.md

```markdown
# Run log

## Intake record
- Request (verbatim):
- Target, vendor, component, version:
- Authorisation basis (the person's words):
- Active-work targets by identifier, or "none: static only":
- Out of scope:
- Attacker model, each boundary in / out / open:
- Preconditions known at intake (each one):
- Scoring rule (the programme's, or "none named: CVSS v3.1"):
- Shipped source may be built (isolated): yes / no
- Hours allowed for this round:
- Licence, NDA or programme terms seen:
- Coverage plan: see artifacts.md

## Gate answers
| Gate (A, refutation order, B, C) | Time (UTC) | The person's words, verbatim | SHA-256 of the approved brief (Gate C) |
|---|---|---|---|

## Sessions
| Date | Tool | Version | Target connection (only under a Gate C brief) |
|---|---|---|---|

## Sweep log
| Pattern | Artifact | Query or script | Hits |
|---|---|---|---|

## Suspicious text
| Location | Text (secrets redacted) | Named in summary |
|---|---|---|

## Correction log
| Date | ID | What was stated | Now | Why | Seen by the person (then an addendum) |
|---|---|---|---|---|---|
```

## artifacts.md

```markdown
| Path | SHA-256 (64 hex) | Kind | Size | ISA, mode, endianness | Load base (evidence) | Memory map (evidence) | Coverage method | Status |
|---|---|---|---|---|---|---|---|---|
```

One row per file, however its path is spelled; a source tree is registered file by file (only
the files cited), its coverage in the intake record. Load base starts with the base as `0x` and
hex, then its evidence in parentheses; the checker reads that first `0x` number as a raw image's
load base. Memory map lists ranges as `0x<first>-0x<last> <name>`, separated by `;`, evidence in
parentheses; an address inside a range that the file holds no bytes for is cited with `region`.
An archive member gets a row as `<archive>!<member>`, with the archive's hash or its own.

Coverage method is one of: read in full (say whether in disassembly or decompiler output),
scanned (name the queries or scripts), not covered (say why).

## candidates.md

```markdown
| ID | Pattern (1-16, or B) | Location (artifact, function@offset or file:line) | Tier | Refuter outcome | Dispatch mode, model | Verdict and reason | Primary (for FOLD-dup) |
|---|---|---|---|---|---|---|---|
```

## Finding file: findings/BVR-NNNN.md

````markdown
<defect> in <component> <version>: <tier>, <rung>; preconditions: <every one, or "none">

# BVR-NNNN: <short title>

- Artifact: <path>, member <member>, SHA-256 <64 hex>
- Defect: <what is wrong, in one paragraph>
- Excerpt: the `excerpt` block under Citations (the compare, branch, load width and length
  register), pasted from objdump unchanged
- Reproducing command: <the command that printed the excerpt; secrets as offset, length and hash>
- Attacker model and preconditions: <each one>
- Tier and evidence: <route, enabler or influence path, searches>
- Rung reached: <R0-R5 with labels>; what each unreached rung needs: <...>
- Score: <version> <vector> = <score> (<band>); preconditions in the vector: <...>; printed
  beside it: <...>
  <arithmetic copied from scripts/cvss31.py for v3.1>

## Citations

```citations
# the artifact of the headline: for a member, the archive as `sha256 <archive> <its hash>`
sha256 <artifact ref> <64 hex>
symbol <artifact ref> <function> @ <address> <image | section+offset object>
# a sink in shipped source:
line <path>:<n> = <the line, verbatim>
```

```excerpt <artifact ref> image | file | object <section>
<objdump lines, pasted unchanged>
```

## What this does not show
<every claim this finding does not establish>
````

## Brief: briefs/BVR-NNNN-E<k>.md

Every field listed in `references/verification.md` ("The brief"), in that order, each on its
own line, with "none" written out where nothing applies.

## Round summary: summary-<round>.md

```markdown
# Round <n> summary (draft | final)

## Verdicts
| ID | Verdict and reason | Tier | Rung | Score and band | Preconditions |
|---|---|---|---|---|---|

## Coverage
- Per artifact: read or scanned, and how
- Configurations covered:
- Searches behind every T4:
- Excluded as not the product, and why:
- Not established:
- External duplicate check: done | not done

## Dispatch
| ID | Mode | Model |
|---|---|---|

## Citation check
<the last line of scripts/verify_citations.py, run on the final summary>

## Gate answers (approval evidence: the person's chat messages, relayed by the agent)
## Suspicious text found
## Correction log

Not enforced on a plain skill install: see <absolute skill folder>/references/limitations.md
```

## Cover email (only when the person asks)

At most 10 sentences. The first line is the headline of the finding it covers, preconditions
included; every detail is in the attached package, not in the email. The person sends it.

## Addendum: addendum-<round>-<k>.md

What was said, what is now true, why, and every file that the correction touches. A file the
person has seen is never edited in place.
