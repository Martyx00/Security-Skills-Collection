# Static analyzers — run them yourself, then hand the SARIF to stage 3

`enrich_candidates.py` reads SARIF 2.1.0 from semgrep, cppcheck and CodeQL, joins
each finding to the function that contains it, and records where an analyzer and
the scorer landed on the same line. It does **not** run any of them, and no role
of this skill may.

---

## 1. Why the skill does not run them

Not a style preference. Each of the three needs something this skill's threat
model does not grant:

- **`semgrep --config=auto` fetches a ruleset over the network** at the moment it
  runs, from a registry, into a process that is about to read every file in a
  repository somebody asked you to audit. Every `--config=p/...` pack does the
  same. A review skill whose scanning step is a remote code fetch has a supply
  chain, and it is not one you chose.
- **CodeQL builds the tree.** `codeql database create` for a compiled language
  runs the project's own build — `make`, `cmake`, a configure script, whatever
  the repository says — which is arbitrary code execution from the artefact under
  audit, by definition.
- **cppcheck needs neither**, but it is left out for symmetry and for a duller
  reason: it is usually pointed at `compile_commands.json`, which a build
  produces.

So no role may run an analyzer. In the original scanner that was structural: the triage role's
shell had no entry for `semgrep`, `cppcheck`, `codeql`, `curl`, `wget`, `make`, `cmake`, `docker` or
any package manager, and the command was refused before it reached a prompt. A plain skill install
has no such list, so here it is a rule the roles keep (`references/roles/triage.md` §3.1,
`references/limitations.md`), and the reason to keep it is the two bullets above.

You are not under those constraints. Run them, and hand the output over.

---

## 2. The commands

Run each from the **repository root**, so the paths in the SARIF are
repository-relative. That is what the join keys on (see §4).

Write the output where stage 3 looks by default:

```bash
mkdir -p .security-review/enrich/analyzers
```

### semgrep

```bash
# Offline: a rules directory you already trust.
semgrep scan --config ./semgrep-rules --metrics=off \
    --sarif --output .security-review/enrich/analyzers/semgrep.sarif .

# Registry rulesets — these FETCH. Read §1 before running it on a tree you do
# not trust, and pin the pack rather than using --config=auto.
semgrep scan --config=p/c --config=p/security-audit --metrics=off \
    --sarif --output .security-review/enrich/analyzers/semgrep.sarif .
```

### cppcheck

```bash
# cppcheck 2.13+ writes SARIF; diagnostics go to stderr.
cppcheck --output-format=sarif --enable=warning,portability --inline-suppr \
    --std=c11 --quiet . 2> .security-review/enrich/analyzers/cppcheck.sarif

# With a compilation database, which gets you the real include paths and macros:
cppcheck --output-format=sarif --project=compile_commands.json --quiet \
    2> .security-review/enrich/analyzers/cppcheck.sarif
```

If your cppcheck predates `--output-format=sarif`, it only speaks
`--xml --xml-version=2`. Stage 3 reads SARIF and nothing else; convert it or
upgrade, and do not hand it XML with a `.sarif` name — the parse failure is
deliberate (§5).

### CodeQL

```bash
# Compiled languages: this RUNS THE BUILD. See §1.
codeql database create .codeql-db --language=cpp --command='make -j"$(nproc)"'

# Interpreted languages need no build command.
codeql database create .codeql-db --language=python

codeql database analyze .codeql-db \
    codeql/cpp-queries:codeql-suites/cpp-security-extended.qls \
    --format=sarif-latest --sarif-add-snippets \
    --output=.security-review/enrich/analyzers/codeql.sarif
```

Version drift is real in all three: these are the documented invocations, not a
guarantee about the build you have installed. If a flag is rejected, check
`--help` rather than assuming the skill is wrong — and if the SARIF comes out
in a shape stage 3 mis-reads, that is worth reporting, because the CWE encodings
below are the part most likely to move.

---

## 3. Handing it over

From the repository root (the working directory the review runs in):

```bash
# Everything in the default directory:
python3 -I -B <skill folder>/scripts/enrich_candidates.py --root . \
    --sarif-dir .security-review/enrich/analyzers

# Or file by file, from anywhere (paths are relative to where you run it):
python3 -I -B <skill folder>/scripts/enrich_candidates.py --root . \
    --sarif out/semgrep.sarif --sarif out/cppcheck.sarif
```

Files named with `--sarif` are copied into
`.security-review/enrich/analyzers/` so the run directory holds the raw input it
was given. `--no-analyzers` skips ingest entirely.

**That directory is read on its own only when nothing else is named.** With no
`--sarif` and no `--sarif-dir`, stage 3 reads `enrich/analyzers/`. Beside an
explicit `--sarif` it is not read at all: it is the archive of earlier runs'
inputs, and reading it there ingested a re-scan's new `semgrep.sarif` beside
last run's copy, so a finding at an old line number set `agreement` on a
function it no longer described. To combine the two, name the directory with
`--sarif-dir`; byte-identical files are read once. `enrich/queue.json` records
which happened as `analyzers.default_dir_read`.

The run the triage role makes names neither `--sarif` nor `--sarif-dir`, so it
reads every SARIF file in `enrich/analyzers/` whenever that directory exists,
and a `--sarif-dir` run naming the directory does the same. Delete stale copies
there before a re-scan. That includes the `<name>.<8 hex>.sarif` copies an
older run made when two inputs shared a basename: they are still SARIF, and
they are still read.

**Keep that directory out of git.** What is in `enrich/analyzers/` is the
operator's input to this run and has to stay untracked; the `.gitignore` stage 1
writes into `.security-review/` keeps it so unless someone forces an add. A
SARIF file the scanned repository commits there would be read as yours: its
findings would set `agreement` and reorder the queue. So while git lists one —
in the index or in `HEAD` — every tool that reads the run directory refuses
with exit `7` before reading anything, from the first stage on, and names the
file and the remedy: `git rm -r -f -q -- <path>`, `git commit`, then a re-run
from stage 1 (GUIDE.md, *What a run writes*). Analyzer output you want under
version control belongs outside `.security-review/`, handed over with
`--sarif`.

The normalised findings land in `.security-review/enrich/analyzer-findings.jsonl`,
one record per result, and the counts are summarised in `enrich/queue.json` under
`analyzers`.

### The CWE encodings that are read

The three tools record the weakness three different ways, and all three are read,
in this order, for every finding regardless of which tool produced it:

| Where | Shape | Who writes it |
|---|---|---|
| `rules[].properties.cwe` | `["CWE-787: Out-of-bounds Write"]`, or one string | semgrep |
| `rules[].properties.tags` | `"external/cwe/cwe-787"` | CodeQL (its rules sit under `tool.extensions[]`, not under the driver) |
| `rules[].properties.cwe` | a bare `"788"` | cppcheck |
| `result.taxa[]` | `{"toolComponent": {"name": "CWE"}, "id": "787"}` | the SARIF standard taxonomy; any tool may start using it |
| the rule id itself | `"cwe787-arrayIndexOutOfBounds"` | cppcheck builds that carry it nowhere else — read only as a last resort |

A finding whose SARIF carries no CWE anywhere gets `"cwe": []`. It is not
guessed at from the message text.

---

## 4. What the join is, and what it is not

Each finding is placed by **file and line** against the function ranges stage 1
extracted:

| `join` | Meaning |
|---|---|
| `line-in-range` | the finding's line falls inside an extracted function |
| `file-only` | the file is in the corpus, the line is in no function (a declaration, a macro, a header block) |
| `unjoined` | the file is not in the corpus at all |

**All three are kept.** An analyzer finding the extractor could not place is a
signal about the extractor: a large `unjoined` share usually means the analyzer
ran over paths the extraction excluded, and a large `file-only` share means the
boundaries are not where one of the two tools thinks they are. Dropping them
would hide exactly that.

If the SARIF's paths are absolute and outside `--root` — an analyzer that ran in
a container, recording `/build/src/parse.c` — a finding is rebased onto a corpus
file only when **exactly one** corpus path is a suffix of it, and the record says
`path_rebased: true`. Anything ambiguous stays `unjoined` rather than being
attached to a plausible-looking file. Running the analyzer from the repository
root avoids the question.

### Agreement is a prior, not a proof

Where an analyzer finding lands within ±3 lines of the scorer's `localized_line`,
the candidate's `agreement` block records `same_line: true` and its queue
priority goes up. That is worth something — the two tools fail differently, the
analyzer knowing dataflow and missing semantics, the scorer knowing patterns and
missing dataflow — and it is worth much less than it looks:

- **The join is location-based.** Two tools pointing at line 214 agree about a
  *line*. They may be describing different properties of it, and neither has been
  asked whether the defect is real. Nothing here is evidence about the code.
- **An analyzer finding is not a verdict.** semgrep's `insecure-use-memcpy` fires
  on every `memcpy` with a non-constant size, which is most of them.
- **Agreement never changes the candidate set.** It reorders the queue and does
  nothing else: it cannot admit a candidate the operating point did not select,
  and it cannot remove one. The budget cut is taken on score *before* agreement
  is applied, precisely so that an analyzer finding on one candidate cannot push
  another out of dispatch.

If you find yourself wanting to promote something on analyzer evidence alone,
the operating point is too strict. Widen it in stage 2, where the change is
recorded, rather than reaching around it here.

---

## 5. When ingest refuses

A file that does not parse as JSON, or that has no `runs` array, stops the run
(exit 1) instead of contributing zero findings. The failure that prevents:
someone ran an analyzer, pointed stage 3 at the console log or at an XML report
named `.sarif`, and got a queue with no agreement in it and nothing saying why —
which reads exactly like an analyzer that agreed with nothing. A run in the
wrong shape — a `message` that is a string, a null location, a `rule` that is
not an object — is refused the same way, and the refusal names the file, the
run and the result.

A SARIF file with zero results is fine and says so. No SARIF at all is fine too:

```
analyzers: no SARIF found. Agreement is a bonus signal, not a dependency.
```
