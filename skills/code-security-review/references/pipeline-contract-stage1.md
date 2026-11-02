# Pipeline contract — stage 1's artifacts (§3–§5)

> Part of `contract.md` (this skill's pipeline contract), moved here unchanged. §9, what never
> happens, is in that file and binds you too: read it.

## 3. `run.json` — stage 1

```json
{
  "schema_version": 1,
  "run_id": "2026-09-18T18-49-03Z",
  "started_at": "2026-09-18T18:49:03Z",
  "repo_root": "/abs/path/to/repo",
  "git": { "commit": "a1b2c3d…", "branch": "main", "dirty": false },
  "bundle_version": "0.1.4",
  "tools": {
    "snapshot.py": "1.0.0",
    "extract_functions.py": "1.0.0",
    "score_functions.py": "1.0.0",
    "enrich_candidates.py": "1.0.0"
  },
  "rules_hash": "85e67df5f1ce7ed4",
  "snapshot": {
    "id": "473367cc14267f10",
    "files": 2,
    "bytes": 91,
    "created_at": "2026-09-19T10:47:29Z",
    "cap_hit": null,
    "changed_during_snapshot": 0,
    "root": "/abs/path/to/repo/.security-review/snapshot",
    "tool_version": "1.0.0"
  },
  "environment": {
    "python": "3.11.15",
    "platform": "Linux-6.18.44-x86_64-with-glibc2.39",
    "machine": "x86_64",
    "tree_sitter": true
  },
  "run_dir": {
    "check": "git",
    "committed": [".security-review/.gitignore"],
    "shipped": []
  },
  "stages_completed": ["extract"]
}
```

Each stage appends its name to `stages_completed` when it finishes cleanly. A
stage whose predecessor is absent from that list must refuse to run. A stage that
rewrites `run.json` touches that list and its own entry in `tools`, and nothing
else: the identity of a run must not depend on which stage wrote last.

**`repo_root` is the repository, never the snapshot.** Every `file` in the run is
relative to it, whether or not the bytes were read from `snapshot/`.

**`git.dirty` comes from `git status` over the scanned tree**, leaving out
`.security-review/`, which the scan never reads. It is `null` when
status could not answer safely — a corrupt index, a failure, a timeout, or a
filter driver that could not be disarmed — because `false` is a claim that the
scanned bytes are the recorded commit.

**Stage 1's git calls run with the repository's config neutralised.** A `.git/`
that arrived with the tree is the attacker's: `core.fsmonitor` and the hooks run
on `git status`, a filter driver the attributes select runs there too, and
`gpg.program` runs on `git log` under `log.showSignature`. So every call passes
`-c` overrides for the fsmonitor, the hooks path, the pager, the external diff
and signature display, gives every filter driver the repository defines the
operator's global program or none, runs with the system config off and with no
inherited `GIT_*` variable that names a repository (`GIT_DIR`, `GIT_WORK_TREE`,
`GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY` and the rest). The operator's own
`GIT_CONFIG_GLOBAL`, `GIT_CONFIG_COUNT`/`KEY_n`/`VALUE_n` and
`GIT_CONFIG_PARAMETERS` are kept, so a CI job's `safe.directory` still applies,
and the `-c` overrides on the command line still outrank them. That hardens the scripts' own calls only; the `git`
commands a role runs itself run as git configures them, which is one more reason
an untrusted tree is reviewed from a fresh clone. The run-directory check's git
calls carry the same overrides, environment and system-config setting — not the
filter ones, which it does not need, because none of its git commands reads a
file's content. Those now live in `rules_lib.py`, where every reader's check
can reach them, and stage 1 takes its own from there.

**`run_dir` is what git said the scanned repository commits under the run
directory** (`contract.md` §1). `check` is `git` when git tracks the
tree and was asked, `untracked-tree` when a repository encloses the tree but
`HEAD` lists none of it - an unborn `HEAD`, or a directory not yet committed or
under an ignored one, where only the index is asked - and `no-git` when there
is no `.git` at or above it. The
last two are a run directory whose provenance is unverified, and `run_status.py`
carries that as a coverage limitation. `committed` names the carve-out paths
git lists — the `.gitignore` and files under `ledger/` — and `shipped` is empty
in every `run.json` stage 1 writes, because anything in it stops stage 1 with
exit `7` before a byte is written.

### The three provenance fields, and what each one makes checkable

A run used to pin its tools by version and its scored bytes by `content_hash`,
and to say nothing at all about the other three things that decide what it found.

**`rules_hash`** — one 16-character digest over every `assets/rules/*.json`,
computed by `rules_lib.rules_hash`, hashing each file's name alongside its
content so that adding or renaming a rule file moves it. `coverage.json` already
records each rule's resolved `pattern`, `languages`, `weight` and
`high_signal`, which looks like provenance and is not: it carries no
`skip_pattern`, so an edit that widened a skip clause left two runs looking
identically provenanced. A pinned tool with an unpinned ruleset is not a reproducible scan.
Two runs carrying the same `rules_hash` read byte-identical rules.

**`snapshot`** — the block above when the run read a snapshot, `null` when it
read the live working tree. `cap_hit` and `changed_during_snapshot` are carried
here, not only in `snapshot-manifest.json`, because a run whose snapshot was
incomplete or taken while the tree moved has to say so where the provenance is
read. `null` is a weaker claim stated out loud, which is the point of the field
existing on every run rather than only on the ones that can boast. `REPORT.md`
states a `null` too (the scout role's template puts it on a `Tree read:` line),
because it is the file a person reads days later; the report gate fails a report
that never says so in words such as "no snapshot" or "live working tree",
wherever they stand (`report_no_snapshot_unqualified`). The block is copied only
from a manifest `snapshot.py` wrote — `tool` `snapshot.py`, both roots absolute
and naming this snapshot and this `--root`, and no symbolic link at `snapshot/`
or at the manifest (`contract.md` §1). A decoy that does not know where
the checkout is can only name it relatively, and is refused rather than scanned.

**`environment`** — `python`, `platform`, `machine`, and whether tree-sitter was
**importable** on the machine the run happened on. A corpus whose boundaries are
`heuristic` because no grammar could be imported is a different artifact from one
where they are `exact`, and §6 branches on the difference. `tree_sitter` is
`null` — not `false` — for a run invoked with `--no-tree-sitter`: the run
declined to ask, and "we did not look" is not "it is not there". `extract-report.json` splits the same
ground into two fields, because one field could not carry both answers:
`parser.tree_sitter_available` says a grammar module IMPORTED, and
`parser.tree_sitter_parsed` says one actually PARSED something in this run.

They were one field, and it was wrong on every default run. Availability was
read off the parent process's parser cache, but extraction happens in a worker
pool and the parent never parses a file, so the cache is always empty. Measured
on curl at `fb4415d8`: 5294 of 5301 boundaries `exact`, and the report said
`tree_sitter_available: false` and told the operator to install a package they
already had. The same bytes under `--jobs 1` said `true`. A field that reports
"we could not" about work that was done is the failure this whole document is
written against, and the note stage 1 prints is now keyed on
`tree_sitter_parsed`, which is what that sentence actually claims.

---

## 4. `extract/functions.jsonl` — stage 1

**One record per function in the repository.** Not per sink, not per pattern hit
— per function. This is the coverage claim the pipeline makes, and it is why
extraction is not driven off the rule hits: a scanner that only ever examines
functions already containing a matched sink can say nothing at all about the
ones no pattern matched, which is most of the tree.

```json
{
  "schema_version": 1,
  "function_id": "src/proto/parse.c::parse_tlv_record::0@9f2c1ab4e0d73516",
  "function_key": "src/proto/parse.c::parse_tlv_record::0",
  "content_hash": "9f2c1ab4e0d73516",
  "file": "src/proto/parse.c",
  "language": "c",
  "name": "parse_tlv_record",
  "qualified_name": "parse_tlv_record",
  "line_start": 180,
  "line_end": 262,
  "byte_start": 4021,
  "byte_end": 6180,
  "loc": 83,
  "signature": "static int parse_tlv_record(struct rec *rec, const uint8_t *cur, size_t n)",
  "extractor": { "parser": "tree-sitter", "grammar": "c", "confidence": "exact" },
  "context": {
    "profile": "default-v1",
    "budget_tokens": 4096,
    "estimated_tokens": 1180,
    "truncated": false,
    "parts": [
      { "role": "function",  "file": "src/proto/parse.c", "line_start": 180, "line_end": 262 },
      { "role": "type_decl", "file": "src/proto/parse.h", "line_start": 25,  "line_end": 40 },
      { "role": "caller",    "file": "src/net/server.c",  "line_start": 190, "line_end": 200 }
    ],
    "text_sha256": "3f9a…"
  },
  "in_test_tree": false,
  "generated_file": false,
  "git": { "last_modified_days": 37, "commits_90d": 3 }
}
```

### `extractor.confidence` — three values, and they mean different things

| Value | Meaning | Produced by |
|---|---|---|
| `exact` | the parser resolved a real function node | tree-sitter |
| `heuristic` | boundaries derived from a language-aware regex/brace or indentation walk | the stdlib fallback |
| `window` | no boundary could be resolved; the range is a fixed window around a hit | last resort |

A record with `confidence: "window"` is still a real record and still gets
scored. What it must **never** do is claim a `line_end` it did not measure — a
range off by one function points a validator at a different body, whose guards
then look sufficient. `extract-report.json` counts the three, per language, and
stage 2 refuses to report a calibrated score on a corpus whose `window` share
exceeds 10% (see §6).

### `extract-report.json` — what the walk could not turn into records

Beside the parser block (§3) and the confidence counts, the report names every
way a file or a function left the corpus. Each `count` / `list` pair below is
a count in `counts` and up to 25 entries beside it:

- `files_unreadable` / `unreadable_files` — each with its reason, among them
  `binary content, not scanned` and `UTF-16LE text (byte-order mark), not
  scanned: re-encode it as UTF-8 to scan it` (and the same for UTF-16BE,
  UTF-32LE and UTF-32BE);
- `files_too_large` / `too_large_files`, and `files_unstattable` /
  `unstattable_files`;
- `functions_unclosed` / `unclosed_files` — named functions the brace walk
  still had open at the end of a file: it lost count of the braces, and those
  functions are not in the corpus;
- `hits_unjoined` in `counts`, with `files_with_hits_no_functions` and up to 25
  of those files in `hits_outside_functions_files` — rule hits that reached no
  record of any kind;
- `unsupported_extensions` — a file count for every extension the extractor
  does not read, `.md` and `.png` included; `run_status.py` names only the
  source languages among them;
- `extensionless_files` — `{files, scripts, readable_languages, script_files}`
  for the files with no extension, which `unsupported_extensions` has no key
  for (`Makefile`, `LICENSE`, `.envrc`, `bin/tool`): `files` counts every one
  the exclude patterns leave in; `scripts` counts, by language, the ones whose
  first line is a `#!` naming an interpreter; `readable_languages` lists the
  labels in `scripts` this run extracts when the file has their extension
  (the `--language` selection when one is given, else every language the
  extractor parses); and up to 25 `script_files[]` rows are
  `{file, language, extracted: false}`. The language is read from the `#!`
  line, never the execute bit, because a snapshot drops execute bits. These
  files are counted, never extracted, and are not written to the manifest's
  `unsupported_languages`;
- `excluded_dirs[]` — `{dir, files, languages, patterns}`: every directory an
  exclude pattern removed that held scannable source, plus the directories of
  files a glob or a single-file exclusion removed one by one, each row naming
  the `patterns` that did it.

Stage 1 prints the unread, the unclosed and the extensionless scripts on
stderr as well, and `run_status.py` turns the unreadable, too-large,
unstattable, unclosed, unjoined, unsupported and excluded ones, and the
extensionless scripts, into `coverage_limitations` sentences: one per script
language, and none for an extensionless file without a `#!` line.

### `<module>` — the scope a file-level hit is joined to

A hit that lands outside every function has nowhere to be scored, ranked or
adjudicated, and a pipeline that drops it silently drops the whole of `LOG-005`:
a hardcoded key is written at module scope, not inside a function. On the shipped
fixture both of `LOG-005`'s hits were module-level and both were unreportable.

So a file with at least one otherwise-unjoined hit gets one synthetic record:

```json
{
  "function_key": "src/app.py::<module>::0",
  "name": "<module>",
  "module_scope": true,
  "line_start": 1,
  "line_end": 47,
  "extractor": { "parser": "module-scope", "grammar": null, "confidence": "exact" }
}
```

The boundaries are the file's, so the tier is `exact` — they are measured, not
estimated. The name is bracketed because no language this skill reads permits
`<` in an identifier, which is what lets `verify_findings.py` exempt the literal
from its "every named function appears in the file it cites" check without
exempting a fabricated name too. It is created only where something actually landed outside a function;
a `<module>` per file would double a corpus mostly to say nothing.

`<module>` is one of a closed set of names stage 1 invents, all bracketed for
the same reason:

| name | emitted for |
|---|---|
| `<module>` | the file-scope record above |
| `<window>` | a tier-3 `window` record — a fixed range around a hit |
| `<arrow>` | a JavaScript or TypeScript arrow function bound to no name, by tree-sitter and the brace walk alike |
| `<anonymous>` | a JavaScript or TypeScript function expression bound to no name, by both; and, by tree-sitter only, any other function node it reads neither a name nor a binding for, such as a Java, C# or Rust lambda or closure, bound or not, because no binding is read in those languages (the brace walk does not extract them at all) |
| `<closure>` | a Go func literal bound to no name, by both; and every PHP closure, bound or not, because no PHP binding is read: `function (...)` by both, `fn (...) =>` by tree-sitter only (the brace walk has no brace to find there) |

Bound to a name means the function is the value in `const f =` (or `let`,
`var`), `f =`, `x.f =`, `{ f: ... }` or a class field `f = ...` in JavaScript
and TypeScript, or in `f :=`, `f =` or `var f =` in Go. Such a record is named
`f` and takes nothing from this table. Tree-sitter reads the binding off the
parse and the brace walk off the text before the function, and in Go the two
still draw the line in different places: tree-sitter takes a binding only when
one plain identifier is assigned the func literal alone, and the brace walk
takes the last identifier before the `=`, so `x.f = func` and `a, b := func`
are `f` and `b` in the brace walk and `<closure>` under tree-sitter.

`extract_functions.SYNTHETIC_FUNCTION_NAMES` is the list in that table, and
`verify_findings.py` carries the same literal. The candidate gate exempts
exactly these names from `candidate_function_absent`, and looks for every
other name as an identifier anywhere in the cited file — not as `name(`, which
the correct names of an arrow binding, a Ruby `def` without parentheses or a
C++ `~Foo` never show.

### `context.parts` — the window is described, not embedded

`functions.jsonl` stays small because the context window is recorded as file and
line ranges, not as text. `extract_functions.py --emit-context <function_id>`
materialises it, and `text_sha256` is the SHA-256 of exactly that materialised
text, so the thing that was scored is reproducible byte for byte.

**This is the seam the fine-tuned model drops into.** When the model arrives, its
training extractor's windowing rules become a named profile —
`--context-profile finetune-v1` — and `context.profile` on every record says
which rules produced it. A score carrying a profile the model was not trained on
is a score whose calibration does not hold, and §6 makes that refusable rather
than merely regrettable.

`role` is drawn from: `function`, `caller`, `callee`, `type_decl`, `header`,
`macro`, `file_preamble`.

---

## 4a. `secrets/inventory.json` — stage 1, and the one rule it turns on

Four rules in this skill — `LOG-007`, `LOG-008`, `HW-009` and `CRY-005` — turn
on whether the value in front of them is secret. Two of them answer that question
**by its name** (shown in outline; the rule files spell them in full, with the
leading `\w*` bounded or dropped so a long line cannot make them quadratic, and
`LOG-008`'s keyword the last segment of the name, or `otp`/`pin` before `code`,
so `hash_len` is not a hash and `pin_code` is a PIN; a MAC's byte against
another array's, `hmac[i] != hmac_calc[i]`, and a MAC named `_out` or `_calc`
against a lowercase name, not `NULL`, count too):

```
LOG-008   \w*(secret|token|hash|mac|hmac|signature|sig|password|pin|digest|otp)s?
HW-009    \w*(mac|tag|hmac|digest|signature|pin|passcode|token|secret|key|otp)\w*
```

The other two match on the operation rather than the operand — `CRY-005` on
`memcmp|strncmp|strcmp`, `LOG-007` on `mod_exp|montgomery|scalar_mult|bn_*` — and
then leave the same question to a validator squinting at an identifier. All four
read the inventory; these two are where the guess is written down.

That is a guess about what a secret is *called*, and it fails in both directions.
It misses a key held in `buf`, `tmp`, `expected` or `v`. And `references/tuning.md` records
it failing the other way on a real run: *"the light tier called public key names
and certificate digests secret and the arbiter overturned every one."* Those are
values the attacker already holds. A name list cannot tell them apart, and no
amount of arbitration fixes a rule whose premise is wrong.

So stage 1 builds an inventory of what is actually secret in this repository, and
the four side-channel rules consult it instead of guessing.

### The rule that governs what is a finding

**A hardcoded secret is a finding. Holding a secret is not.**

A program that does cryptography holds keys, tags and nonces in variables — that
is what the program is for. An inventory that reported each one as an issue would
produce a report with two hundred findings in it and no signal, which is worse
than no inventory. So:

| | |
|---|---|
| `origin: "literal"` — the secret is written in the source | **a finding**, reported on the secrets track |
| any other origin — env, file, KDF, key store, fuse, wire | **never a finding on its own.** It is inventory: evidence the side-channel rules read |

A secret-holding value becomes a finding only when something is done wrong with
it — compared in non-constant time, exponentiated without blinding, written to a
log — and that finding belongs to the rule that governs the wrongdoing, not to
the sweeper.

This is enforced, not asked for. `is_finding` must be `true` **if and only if**
`kind == "secret"` and `origin == "literal"`; the checker refuses any other
combination, and the report gate fails a `REPORT.md` whose secrets section names
an entry with `is_finding: false`.

### The record

```json
{
  "entry_id": "SEC-0001",
  "kind": "secret",
  "class": "long-term-key",
  "origin": "literal",
  "is_finding": true,
  "identifiers": ["API_KEY"],
  "evidence": { "file": "src/app.py", "line": 39,
                "code": "API_KEY = \"sk-live-9f2c" },
  "redacted": "sk-live-…3516",
  "touched_by": ["src/app.py::<module>::0", "src/app.py::authenticate::0"],
  "corroborated_by": [{ "analyzer": "gitleaks", "rule": "generic-api-key" }],
  "why": "A live-prefixed API key written into the source and compared in authenticate()."
}
```

`kind` ∈ `secret` | `public`.
`class` ∈ `long-term-key` | `session-token` | `password-or-pin` | `mac-or-tag` |
`nonce-or-iv` | `device-unique` | `other-secret`, and is `null` when
`kind == "public"`.
`origin` ∈ `literal` | `env` | `file` | `kdf` | `key-store` | `fuse-otp` |
`wire` | `derived` | `unknown`.

**`kind: "public"` entries are the point of the file, not an afterthought.**
Recording that `peer_public_key`, `cert_digest` and `server_random` are values the
attacker already holds is what stops the false positives `references/tuning.md` measured. A
sweeper that lists only secrets has not done the job.

`evidence` is checked the way a finding's citation is checked: the text must be at
the line cited. An inventory entry nobody can look up is an assertion, and this
skill does not take assertions.

**`redacted` never carries the secret.** At most the first four and last four
characters, with the middle elided. The run directory is written to disk and read
by a model; copying a live credential into it turns the scanner into a second
place the secret leaks from.

**Nor does `evidence.code`,** which is the same rule on the field that is easier
to forget, because a citation is supposed to be the line as it stands. Quote the
line truncated a few characters into the secret, or with the middle elided: the
citation check reconciles a redacted quote against the real line, so either
verifies, and `sweep_secrets.py check` refuses a record carrying nine
consecutive characters of key material in either field, or a whole literal the
tool's own families find on the cited line (a known-token secret, a
secret-assignment value, an env-assignment value) — `public` entries exempt —
and, for `origin: "literal"`, a `redacted` with neither an elision mark nor a
`<shape>` token such as `<6 digits>`. The record above is written that way for
that reason — an example that quoted the key whole would teach the opposite of
the rule beside it.

**Nor does anything the pipeline hands a reader.** `export_sarif.py`, which
redacts in place every string it writes that came from a finding or the tree,
the report gate (`verify_findings.py --report`), which fails a `REPORT.md` that
carries key material (`report_carries_secret`), and `ledger.py`, which refuses
a reason or an export that does, all use one detector,
`sweep_secrets.export_spans`. It finds a known token family (only the part the
family names as the secret, so a URL keeps its host); a quoted value of six
characters or more under a secret-shaped name, whatever its entropy (LOG-005's
floor); the body of a key or secret byte-array initialiser of four or more
elements, not all zero, and any run of eight or more `0xNN` bytes, which is
that array's continuation lines (HW-010); and a high-entropy run of twenty
characters or more, held to 3.0 bits per character where the sweeper uses 3.6,
unless it is a URL path whose every segment is a digest or a word. It skips a
span already redacted, an interpolation, and a name that describes the secret
rather than holding it (`TOKEN_URL`). The readers differ only in what they
excuse. The report gate and the ledger, which refuse the whole text on a hit,
leave a value that reads as words (a phrase, a passphrase, `"Bearer"`), and
pass an entropy run that is a digest: the ledger any 16-, 40- or 64-hex run,
the gate a 16-hex one, or a 40- or 64-hex one that `run.json` records or that
the text before it names as a commit, sha, digest or hash. The SARIF scrub
excuses neither. When `sweep_secrets.py` cannot be imported the gate fails with
`report_secret_check_unavailable` rather than read an unrun check as clean.

### How the four rules read it

`enrich_candidates.py` stamps every candidate whose function appears in an
entry's `touched_by`:

```json
"secret_status": "in-inventory:mac-or-tag"
```

∈ `in-inventory:<class>` | `in-inventory:public` | `not-in-inventory`.

**It refines the validator's gate. It does not gate emission.** Stage 1 stays
recall-biased: `LOG-008` still emits on a name match, and a candidate whose value
the sweeper never found still reaches a validator. What changes is that the
validator's "is this operand actually secret" question has evidence attached
instead of a name to squint at — and `in-inventory:public` is a cited
disqualifier rather than a judgement call.

Gating emission on the inventory would convert every miss by the sweeper into a
silent false negative, which is the trade this pipeline refuses everywhere else.

## 5. `extract/rules.jsonl` and `extract/coverage.json` — stage 1

The rule tables that used to live in a role's prompt are now data in
`assets/rules/*.json`, run by the extractor. Every hit becomes a record;
every hit is accounted for.

```json
{
  "schema_version": 1,
  "rule_hit_id": "RH-000042",
  "rule_id": "MEM-002",
  "category": "memory-safety",
  "cwe": "CWE-787",
  "file": "src/proto/parse.c",
  "line": 214,
  "column": 5,
  "sink_text": "memcpy(rec->payload, cur, len);",
  "function_id": "src/proto/parse.c::parse_tlv_record::0@9f2c1ab4e0d73516",
  "function_key": "src/proto/parse.c::parse_tlv_record::0",
  "why_flagged": "third argument is a variable, not sizeof(dest)",
  "disposition": "emitted",
  "skip_reason": null,
  "pattern_source": "canonical",
  "language": "c"
}
```

`disposition` ∈ `emitted` | `skipped` | `deferred`. `skip_reason` is required
when `skipped` and must be the rule's own written skip clause verbatim from the
rule file — not a paraphrase, and not a judgement about whether the hit looked
interesting. A hit is `skipped` only when the rule's `skip_pattern` matches the
hit's own stretch of the line — from where the rule matched to where it next
matches on that line, or the line's end — so a clause another call on the same
line satisfies does not skip this one.

`sink_text` is read from the file at `line`, never reconstructed.

`match_target` on the hit records which of the rule's patterns produced it —
`line` or `function_or_path` — because stage 4 re-runs them differently and
cannot recount a name match against source lines.

### Where a rule's pattern runs, and the second pattern some rules carry

`match_target` ∈ `line` | `function_or_path`.

- **`line`** — against each source line. The default.
- **`function_or_path`** — against `"<file>::<function>"`. Right for the
  logical-flaw rules, whose patterns are name fragments: `LOG-003` is `key\w*`,
  and running that over source lines flags every line in the tree containing the
  word "key".

A name pattern is run **segment-aware**: every `\b` in it is read as an
identifier-segment boundary — an ordinary word boundary, either side of an
underscore, any word character but `_` or a capital before an ASCII capital
(`isAuth`, `caféKey`), and the last capital of an acronym before a lowercase
letter (`HTTPAuth`) — and `\B` as its negation. So `LOG-001`'s `\b(?:auth…|login|…)\b` selects
`pam_authenticate`, `Curl_http_auth_act`, `isAuthenticated`, `login_handler` and
every function in `src/user_auth.c`, and still not `unauthorized`: a keyword
inside one lowercase segment is not a boundary match, which is what keeps
`key\w*` off `monkey`. Read as a plain `\b`, the rule saw only names that open
with the keyword; LOG-001 selected 15 of curl's functions where 140 carry an
auth segment. The rewrite is `rules_lib.compile_name_pattern`, and stage 1's
hits, its zero-hit diagnosis and stage 4's recount all go through it; the rule
files keep the plain `\b`, and ripgrep cannot reproduce a segment match.
`coverage.json` records how a name rule was run as `name_match` (`segment`;
null on a line rule), and stage 4 recounts the name half that way — a run from
before this field counted plain `\b`, and is recounted plain.

A `function_or_path` rule may also carry **`line_pattern`**, a second regex run
over source lines. Four rules need it, because their sinks and their name
fragments are different regexes doing different jobs, and matching only against
names left the sink half as dead code — `LOG-005`'s hardcoded-secret regex and
`-----BEGIN` marker have never appeared in a function name, so the rule matched
nothing on any tree while `coverage.json` recorded `absent-from-tree`, which was
true.

It is a second **field** rather than a third `match_target` because merging the
halves costs too much: run `LOG-004`'s `verify|sign|cert` over lines and it
returns 201 hits across 243 functions on a codebase with no cryptography in it.
The sinks are specific and belong on lines; the fragments are vague and belong on
names. A rule carrying both is deduplicated on `(rule_id, line)`, and the line
pass wins because it points at the sink rather than at the definition.

`coverage.json` therefore records `line_pattern`, `canonical_line_pattern`,
`line_pattern_source`, and **`hits_by_target`** — `{"line": n,
"function_or_path": m}`. Stage 4 recounts each half against what it actually ran
over, honours `multiline`, restricts both recounts to the rule's own
`languages`, and runs the name half the way `name_match` says. A recount that
does any of those four wrongly accuses a correct run.

`coverage.json`'s shape is the one `verify_findings.py` reads, and the counts in
it are produced by the same code that produced the hits:

```json
{
  "schema_version": 1,
  "scanned_roots": ["src", "lib"],
  "wrapper_resolution": { "alloc": ["mbedtls_calloc"], "printf": [], "copy": [], "compare": [], "read": [] },
  "rules": [
    {
      "rule_id": "MEM-002",
      "category": "memory-safety",
      "languages": ["c", "cpp"],
      "pattern": "\\b(memcpy|mbedtls_memcpy)\\s*\\(",
      "canonical_pattern": "\\b(memcpy)\\s*\\(",
      "pattern_source": "wrapper-resolved",
      "hits": 196, "emitted": 190, "skipped": 6, "deferred": 0,
      "skip_reason": "third argument is literally sizeof(<dest>)",
      "skipped_sample": [{ "file": "src/a.c", "line": 44, "class": "sizeof-bounded" }],
      "zero_hit_cause": null,
      "wrapper_blind": false,
      "wrapper_blind_extra": 0,
      "wrapper_blind_examples": [],
      "wrapper_blind_remedy": true
    }
  ]
}
```

`verify_findings.py`'s I5 reads `MEM-WFS`'s `languages` from this file to
decide which candidate-producing functions are owed a whole-function pass: the
skill's own list (C, C++ and Rust as shipped), widened by what the run
recorded, so a run recorded with all eleven is held to all eleven, and never
narrowed by it.

`zero_hit_cause` ∈ `absent-from-tree` | `pattern-unmatchable` | `null`, and is
**required** when `hits == 0`. The extractor determines it by re-running the
pattern unanchored; it is not a judgement call any more. For a name rule the
unanchored pattern runs over the same `<file>::<function>` targets with only
the anchors its fragments OPEN with dropped (`rules_lib.loosen_name`; the
trailing ones stay), so `pattern-unmatchable` there means the keyword closes a
lowercase segment (`reauth`, `hotkey`) — the tree has the family, spelled in a
way the rule does not select — never a missed wrapper. A tail a rule was
narrowed to leave out (`signal` for `LOG-004`'s `sign`) is not the family, and a
tree whose only such names are those is `absent-from-tree`. A name rule's
`line_pattern` is loosened the same way over source lines, by both stages,
where `_` is part of a word: a keyword behind a prefix or inside a longer
identifier (`LOG-006`'s `php_unserialize(`, `LOG-008`'s `cursig ==`) is
`pattern-unmatchable` with the line as its evidence, and
`X509_verify_cert_error_string`, which `LOG-004`'s `X509_verify(?:|_cert)\b`
leaves out, is not the family. A run recorded with no `name_match` is loosened
by dropping every anchor, as it was.

`wrapper_blind`, `wrapper_blind_extra`, `wrapper_blind_examples` and
`wrapper_blind_remedy` are the blindness `zero_hit_cause` cannot speak for,
because that field is `null` for a rule that matched: a rule can match 74 sites
and be blind to 171 more that sit inside a prefixed name its leading `\b`
cannot open a match in (`tfm_crypto_operation_release` under `free`/`release`,
`its_flash_nand_read` under `read`, `null_printf` under `printf`). They are
written for **every** rule, and are `false` / `0` / `[]` for one with no
call-shaped branch to ask the question of (a word list, a derived rule, a name
rule with no `line_pattern`):

| field | meaning |
|---|---|
| `wrapper_blind` | `true` when the rule's call-shaped branches match `n` times as written and `n + extra` times with the anchor in front of the call name dropped, `extra >= 5` and `extra >= n`. `n` must be non-zero: a rule that matched nothing is `zero_hit_cause`'s. This is exactly the predicate stage 4's candidate gate refuses on (`coverage_pattern_blind`), `rules_lib.is_wrapper_blind`. |
| `wrapper_blind_extra` | The sites the anchored pattern missed, `extra` above. Recorded even when `wrapper_blind` is `false`. |
| `wrapper_blind_examples` | Up to three `file:line: identifier` strings, one per distinct identifier the unanchored match sits in, the most frequent first, each at the first line it appears on. Only listed when `wrapper_blind` is `true`. An identifier and not the line, because `coverage.json` is copied beside the records and a line can be the one that holds a credential; the identifier is also put through the secret scrub the gate puts on every line it quotes (`sweep_secrets`), and reads `<withheld: …>` when that cannot be imported. |
| `wrapper_blind_remedy` | `true` when the rule names a `wrapper_class`, so a `wrapper_resolution` entry can close the blindness; `false` when it cannot, and the gate then reports the rule (`blind_without_remedy`) instead of refusing the run. |

The shared helpers (`call_shaped`, `word_list_shaped`, `top_level_branches`,
`drop_call_anchor`, `wrapper_blind_forms`, the two thresholds and
`is_wrapper_blind`) live in `rules_lib.py`, and the extractor and the gate both
use them. The extractor counts what the gate counts, over the same bytes: the
snapshot when there is one, the rule's own `languages`, line by line,
and a line over `blindness_scan.max_line_chars` read by neither form (counted in
`blindness_scan.wrapper_blind_units_skipped`). the extract role reads these and
resolves what it can (`references/roles/extract.md`, Phase D) before stage 4 would refuse the run.

`skipped_sample` is every Nth skipped hit, N chosen so that it holds 2% of them,
never fewer than 5 (or all of them, when there are fewer) and never more than
25. Each entry is `{file, line, class}`, and `class` ∈ `comment` |
`string-literal` | `declaration` | `sizeof-bounded` | `skip-pattern` |
`wrapper-unrelated` | `other`. Stage 1 decides the class from the line rather
than asserting it: `comment`, `sizeof-bounded` or `string-literal` when the
line shows one, and otherwise `skip-pattern`, because a rule's `skip_pattern`
is the only thing that skips a hit at all.

The candidate gate reads every sampled line back and fails it
(`coverage_skip_unverifiable`) when it cannot be read or the rule's own pattern
does not match there. Four classes it then re-checks mechanically: `comment`
(the line opens a comment, or the match sits after a `//`), `string-literal`
(every match on the line is inside double quotes), `sizeof-bounded` (a
`sizeof(` from the match on), and `skip-pattern`, by re-running the rule's own
`skip_pattern` — taken from the skill's rule tables, never from anything
the run directory holds — over each hit's own stretch of the line, the search
stage 1 ran to skip it. `declaration` needs a parser and is accepted as
written. `other` and `wrapper-unrelated` carry no test at all, and a sample
in which those two make up more than 20% fails the gate.

---

