# Validator Contract — reference sections

Two sections of `validator-contract.md`, moved here unchanged, and §6a, the
exposure step contract §6 points to. Section numbers are kept, so "§7" and
"§8a" mean what they always meant.

They are kept out of the contract so that the file every validator reads first
stays short. These two sections were most of it and are parsed by no tool but
the one that follows them. Read this file with your file-reading tool, by line
range when needed.

**Read this file once, at the start of your session, before your first
verdict.** §6a turns the rubric row into the severity you emit and splits
`impact` into cited claims; §7 is the output schema every verdict must match;
§8a is the test every `FP-NOT-SECURITY` rests on. The read is session setup and does not count
against the per-candidate read budget in `validator-contract.md` §2 rule 7.

## 6a. Exposure and mechanism

Contract §6 picks the row; this section turns it into the severity you emit,
and splits `impact` into claims a reader can check one at a time. One run rated
contrib/ code the root build never compiles at `high`, and wrote "gzread floods
the buffer with up to 4 GiB" where gzread rejects any length that does not fit
an int. Every citation checked out; the severity and the mechanism did not.

**What the candidate record gives you.** Stage 3 writes `exposure` on every
candidate from facts a tool can see:
- `path_class` is core, contrib, examples, test, fuzz, bench, vendored, tools
  or docs, from the first directory name in stage 3's own closed list
  (`path_class_segment`), or `test` when stage 1 put the file in its test tree
  (`path_class_basis`). It is not FP-TEST's path list.
- `support_marker` is the first line of the nearest README above the file
  (never a project root's) that calls the code unsupported, unmaintained or
  untested, verbatim; or null. `insecure_marker` quotes its own comment or that
  README calling it not secure, test-only or not for production.
- `default_build` is `referenced` when a root build file (`build_files_read`)
  names the file, its object file or a directory above it that it adds to
  the build, `not-referenced` when none does, and `unknown` when there is no
  root build file; a CMake directory counts only as far as its own
  `CMakeLists.txt` reaches the file (`build_reference_kind`, `build_chain`,
  `build_dead_ends`). `build_references` quotes up to five of those lines.
  `own_build_files` lists build files beside the file; they cap nothing.
- `callers` counts distinct callers by `path_class`, from a textual index
  blind to function pointers and macros; `lines_unread` counts lines too long
  for it to read.
- `linkage` (static, external, unknown) and `declared_in` (header prototypes)
  are for C and C++. `guards` are the `#if` branches open at the sink line:
  `platform-legacy`, `platform-mainstream`, `disabled` (`#if 0`) or `feature`.
- `ceiling` is the least severe cap among the `ceiling_reasons` that apply:

| Reason | Applies when | Cap |
|---|---|---|
| `advisory-only` | the manifest says no physical attacker (`HW-*`) | low |
| `disabled-guard` | a `disabled` branch encloses the sink | info |
| `test-or-sample-path` | `path_class` is test, fuzz, bench, examples or docs | low |
| `not-built` | `default_build` is `not-referenced` | medium |
| `unsupported-marker` | `support_marker` is set | medium |
| `documented-insecure` | `insecure_marker` is set | low |
| `not-built-internal` | not-referenced, no core caller and no unread line, and not exported (external linkage plus a header prototype) | low |
| `legacy-platform` | a `platform-legacy` branch encloses the sink | low |

A contrib/ path alone is not a reason, because some projects build and ship
their contrib. "No callers" alone is not a reason for an exported API either,
because a library's API has no callers in its own tree.

Exposure never dismisses a candidate and never stands in for
`FP-NOT-COMPILED` or `FP-DEAD-CODE`, which still cite the build file or the
`#ifdef`: a file no root build names may be built by its directory's own rule.

**`severity_basis`** is required on every `VULNERABLE`:

```json
"severity_basis": { "rubric_row": "high",
  "step_downs": [ { "token": "content-not-controlled", "file": "contrib/minizip/zip.c", "line": 1980 } ],
  "ceiling": "medium", "override": null }
```

- `rubric_row` is the contract §6 row, or the playbook rule's `Severity:` line.
- Each step-down lowers the row one level and cites the line that makes it
  true, a line also in `evidence` (`legacy-platform` may cite the record's
  guard line). The tokens are a closed set:
  - `not-built`: the build line that leaves the file out, or the option that
    defaults it OFF.
  - `no-production-callers`: only tests, examples or unshipped code call it;
    cite one caller, or the function's first line when there is none.
  - `caller-parameter`: the only attacker-influenced value is a size, count or
    flag the calling application chooses, not data bytes, and no in-tree
    caller feeds it untrusted input; cite the parameter's declaration.
  - `content-not-controlled`: the attacker chooses the length but not the
    bytes written; cite where the bytes come from.
  - `legacy-platform`: only a legacy platform compiles the sink.
- A mainstream platform guard (`_WIN32`, `__APPLE__`, `__linux__` and the
  like) is NOT a step-down. The title and `impact` must name the platform.
- `ceiling` copies the record's `exposure.ceiling` (null when none); the
  checker compares the two.
- `override` is null or `{file, line, code, why}`: a line also in `evidence`
  that the ceiling's facts missed — a production caller the textual index
  cannot see (a function pointer, a macro), a build line that compiles the
  file by default (against `documented-insecure`, into a library the project
  ships), or the `insecure_marker` line, `why` naming what else it is about.
  It lifts the ceiling and nothing else.
- `severity` = min(ceiling, or no cap under an override; the row lowered once
  per step-down), never below `info`. Lower is your call; higher is
  `severity_basis_inconsistent`, or `severity_over_ceiling` past the ceiling.

**`input_origin`** is where the value that makes the defect exploitable comes
from: `untrusted-data`, `caller-parameter`, `local-config`, `argv-env` or
`internal`. The bytes a library is handed to parse (an inflate stream, a zip
entry, a TLV record) are `untrusted-data`, whichever API delivers them.
`caller-parameter` covers only a size, count or flag that the calling program
picks, and it requires the `caller-parameter` step-down.

**`impact_claims`** splits `impact` into atomic claims:

```json
{ "id": "C1", "claim": "…", "element": "length", "controlled_by": "attacker", "via_callee": false, "settled_by": "src/proto/parse.c:203" }
```

- `element` is one of `length`, `content`, `offset`, `destination`, `count`,
  `pointer`, `control-flow`, `availability`, `disclosure`, `timing`,
  `privilege` or `other`. `controlled_by` is `attacker`, `caller`, `internal`
  or `n/a`.
- `settled_by` is a file:line that is also in `evidence`: the relevance_test
  rule, applied to each claim.
- `via_callee: true` marks a claim about what a called function does ("gzread
  fills buf with len bytes"). It rests on a `declaration` evidence entry at
  `settled_by` quoting the callee's own body — the line that writes, or the
  guard that refuses: §7's return-convention rule, applied to effects. A body
  you cannot read goes in `unresolved`, not in a claim.
- `impact` and `exploit_sketch` may assert nothing that is not a claim.
  "Attacker-chosen length and content" is two claims, and the second needs a
  line of its own.

The precheck reports a gap in any of this as `severity_over_ceiling`,
`severity_basis_inconsistent`, `missing_impact_claims`, `impact_claim_uncited`
or `impact_claim_unsourced`. None of them is a remand. The arbiter audits every
claim against the code and corrects the rating or the impact itself.

## 7. Output format

For each candidate, in the task's order, emit at most three lines of plain-text
working notes and then its fenced `json` block: **exactly one**, plus one more
for each derived `MEM-WFS` finding (the memory-safety validator only); nothing after
the last block.

**A derived `MEM-WFS` finding** is the whole-function pass finding a defect the
candidate's own rule did not. Its block is a complete verdict like any other, with
`"rule_id": "MEM-WFS"`, its own `cwe`, `primary_location` and `evidence`, and
`"derived_from": "<the candidate_id you were validating>"`. Its `candidate_id` may be that
same id or omitted: `review_run.py ingest` does not read it. The tool files the block as
`findings/<candidate_id>_WFS.json` (`_WFS2` for a second one on the same candidate) with
that name as its `candidate_id`, keeps `derived_from`, and every later stage reads it as
a finding of its own, against the source candidate's function and exposure
(`rules_lib.derived_record`). It goes to the arbiter if it is positive, to the report,
the ledger review and the SARIF export like any other. A derived block that is missing a
required field, or whose `derived_from` is not a candidate of your unit, is not filed and
the ingest says so; the candidate's own verdict stands either way. In a one-off
validation (`review_run.py manual`) the same block is returned to the analyst beside the
candidate's verdict, as `<candidate_id>_WFS`, and filed under `dispatch/manual/`, never
under `findings/`.

```json
{
  "candidate_id": "CAND-0042",
  "rule_id": "MEM-002",
  "cwe": "CWE-787",
  "verdict": "VULNERABLE",
  "confidence": "high",
  "severity": "critical",
  "title": "Heap overflow: attacker-controlled TLV length copied into fixed 256-byte payload",
  "primary_location": "src/proto/parse.c:214",
  "evidence": [
    { "role": "source",     "file": "src/net/server.c", "line": 88,  "code": "n = recv(fd, buf, sizeof buf, 0);" },
    { "role": "propagation","file": "src/proto/parse.c","line": 203, "code": "len = ntohs(*(uint16_t *)(cur + 2));" },
    { "role": "allocation", "file": "src/proto/parse.c","line": 190, "code": "rec = calloc(1, sizeof *rec);" },
    { "role": "sink",       "file": "src/proto/parse.c","line": 214, "code": "memcpy(rec->payload, cur, len);" }
  ],
  "guards_considered": [
    { "file": "src/proto/parse.c", "line": 205, "code": "if (len == 0) return -1;", "why_insufficient": "rejects only zero, not values above sizeof(rec->payload)" }
  ],
  "gates_evaluated": [
    { "gate": "G1", "result": "pass", "basis": "DEST is char payload[256], declared at src/proto/parse.h:31" },
    { "gate": "G2", "result": "pass", "basis": "len derives from ntohs() on recv'd bytes, src/net/server.c:88" },
    { "gate": "G3", "result": "pass", "basis": "no comparison of len against 256 anywhere in parse.c:180-214, nor in either caller" },
    { "gate": "G4", "result": "n/a",  "basis": "no guard exists to be defeated" }
  ],
  "arithmetic": {
    "largest_admitted":  { "value": 65535, "from_guard": "src/proto/parse.c:205 `if (len == 0)` rejects only zero, so every other uint16_t passes" },
    "smallest_violating":{ "value": 257,   "from_dest":  "src/proto/parse.h:31 `char payload[256]`; memcpy appends nothing, so 257 bytes is the first write past the end" },
    "overflows": true
  },
  "taint_path": "server.c:88 recv() -> parse.c:196 parse_tlv_record(buf,n) -> parse.c:203 len=ntohs(...) -> parse.c:214 memcpy",
  "attacker_model": { "principal": "unauthenticated remote peer",
    "lacks": "any access to the server process", "boundary_crossed": "network -> server process",
    "basis": "src/net/server.c:88" },
  "relevance_test": {
    "claim": "not-an-8a-claim",
    "principal": "unauthenticated remote peer",
    "gain": "asserts an out-of-bounds write, not a disclosure, a timing leak or a missing control",
    "settled_by": "src/proto/parse.c:214"
  },
  "severity_basis": { "rubric_row": "critical", "step_downs": [], "ceiling": null, "override": null },
  "input_origin": "untrusted-data",
  "impact_claims": [
    { "id": "C1", "claim": "len is the peer's 16-bit length field, up to 65535", "element": "length", "controlled_by": "attacker", "via_callee": false, "settled_by": "src/proto/parse.c:203" },
    { "id": "C2", "claim": "the bytes copied are the peer's own", "element": "content", "controlled_by": "attacker", "via_callee": false, "settled_by": "src/net/server.c:88" },
    { "id": "C3", "claim": "the 256-byte field lies in a heap allocation", "element": "destination", "controlled_by": "internal", "via_callee": false, "settled_by": "src/proto/parse.c:190" }
  ],
  "preconditions": ["listener reachable", "no length clamp applied by caller"],
  "impact": "Writes up to 65535 peer-chosen bytes past a 256-byte field inside a heap allocation.",
  "exploit_sketch": "Send a TLV with type=0x01 and length=0xFFFF followed by 65535 bytes.",
  "remediation": {
    "summary": "Clamp len to sizeof(rec->payload) and to remaining input before copying.",
    "patch": "if (len > sizeof rec->payload || len > (size_t)(end - cur)) return -1;"
  },
  "fix_is_caller_side": false,
  "false_positive_reasons": [],
  "unresolved": [],
  "out_of_scope_observations": [],
  "files_read": ["src/proto/parse.c", "src/net/server.c"]
}
```

Rules for the object:
- `severity_basis`, `input_origin` and `impact_claims` are required on a
  `VULNERABLE` verdict, as §6a defines them, and `attacker_model` as contract
  §6 does.
- `cwe`, `confidence`, `severity`, `taint_path` and `remediation` are required
  on a `VULNERABLE` only (`verify_findings.py` `REQUIRED_IF_VULN`). A dismissal
  owes what the bullets below ask of it: the dismissal bullet's three fields,
  `gates_evaluated`, and `arithmetic` and `relevance_test` where their bullets
  say so. A `NEEDS_HUMAN_REVIEW` owes a non-empty `unresolved`. Still give
  every verdict a `confidence`, because the review stage orders each verdict
  by it. Give an `ACCEPTED_RISK` the `severity` the defect it accepts would
  carry (contract §6 and your playbook), because `export_sarif.py` sets its
  level from that. **A `NOT_VULNERABLE` rates nothing:** `severity`,
  `severity_basis`, `input_origin`, `impact_claims`, `attacker_model`,
  `impact`, `exploit_sketch`, `remediation` and `fix_is_caller_side` describe
  a defect, so leave them out of it rather than writing `info` or null. An
  `ACCEPTED_RISK` or a `NEEDS_HUMAN_REVIEW` leaves `remediation` out when it
  recommends nothing, and carries `remediation` as an object, with
  `fix_is_caller_side` beside it at the top level, when it recommends a change.
- `evidence` roles are drawn from: `source`, `propagation`, `allocation`, `free`,
  `guard`, `sink`, `config`, `caller`, `declaration`.
- `code` must be the line verbatim, trimmed of leading whitespace only. A
  statement broken over several lines — up to five — may be quoted joined onto
  one, with single spaces, and cited at any of those lines that holds eight
  characters or more. Nothing else may run past the cited line: a quote longer
  than its line verifies only when the whole of that line is in it and every
  extra character is on the lines really next to it.
- Every `evidence` entry carries a `file` and a `code`. One that lacks either —
  a quote under another key such as `snippet` included — is a citation nobody
  can check, and it counts as `citation_not_found` exactly as a line that is not
  in the file does.
- `gates_evaluated` is **required** for every verdict that decides the candidate
  — `VULNERABLE`, `NOT_VULNERABLE` and `ACCEPTED_RISK` alike. `NEEDS_HUMAN_REVIEW`
  is the one exemption, because it names the gate it could not settle in
  `unresolved` instead. §2 rule 4 decides a dismissal by the same playbook gates
  as a positive — "unproven gate ⇒ not vulnerable" is a claim about the gate
  walk, so a dismissal with no gate walk has not made the argument it says it
  made, and the arbiter remands any finding that leaves it no gates to audit
  whatever that finding concluded. List one entry per gate in the rule's
  playbook, with `result` in
  `pass` / `fail` / `n/a` and a `basis` that names the file:line or the search
  that settled it. A basis that restates the gate ("the size is unbounded") or
  that is empty is treated as a gate you did not evaluate, and the finding is
  rejected. If you did not check a gate, say `"result": "unchecked"` — that is
  honest and survives; a fabricated pass does not.
- A verdict whose `evidence` contains only a `sink` role has not traced
  anything, and that holds for a dismissal as much as for a positive. On a
  positive, add the source and the guard. On a dismissal the sink is the line in
  question, so citing it back proves nothing: cite what makes the disqualifier
  true — the guard that dominates every path, the declaration that fixes the
  size, the caller that passes the constant. Otherwise change the verdict.
- **A verdict that turns on what a call returns cites the definition that
  produces the value, not the wrapper.** If your reasoning says "returns 0 on
  success", "non-zero means error" or "`rc` is negative on failure", `evidence`
  carries a `declaration` quoting the `return` that computes it. Follow it
  transitively: a wrapper that forwards, negates or re-maps a status is no
  terminus, nor is a header comment, a doc block or the tree's habit; stop at a
  `return` you can evaluate. **A definition in the repository but outside the
  scanned scope is `NEEDS_HUMAN_REVIEW`**, naming it and its path in
  `unresolved` (worked example below). A library **not in the repository at
  all** (system OpenSSL, libc, Node's `crypto`) is cited by its documented
  public-API convention: `"return_conventions": [{"call": "X509_verify_cert",
  "library": "OpenSSL", "basis": "documented-public-api", "source":
  "X509_verify_cert(3)", "returns": "1 verified; 0 not verified; negative on
  error"}]`, the call site in `evidence` — never for a call the tree defines.
  `call` is one callee spelled exactly as that evidence line writes it, its
  qualifier or receiver included, without parentheses, arguments or prose:
  `lru_cache`, not `functools.lru_cache`, where the line reads `lru_cache(`;
  `crypto.verify`, not `verify`, where it reads `crypto.verify(`;
  `dec.Decode`, not `json.Decoder.Decode` or `dec.Decode()`, where it reads
  `dec.Decode(`. The checker matches `<call>(` on an evidence line as text, so
  an expression or an operator (`isinstance(s, Sequence)`, `x in s`) is no
  `call`, and one entry documents one call. `source` names where the
  convention is documented (a man page, an API reference), and `returns`
  states what it says.
- `arithmetic` is **required** for every buffer, index, or integer finding
  (`MEM-001` through `MEM-006`, `MEM-010`, `INJ-006`, `HW-008`) on a
  `VULNERABLE`, `NOT_VULNERABLE` or `ACCEPTED_RISK` verdict — the block is what
  makes a dismissal falsifiable as well as a positive. `NEEDS_HUMAN_REVIEW` is
  exempt, because there the missing artefact is often the bound itself. See §9a.
- `relevance_test` is **required** on every finding whose rule appears in one of
  §8a's three lists, and on every finding whose claim §8a governs whatever rule
  it arrived under — on a `VULNERABLE` exactly as much as on a dismissal, the
  positive being the direction §8a never reached. `claim` is `disclosure`, `side-channel` or
  `missing-control` (§8a's (1), (2) and (3)), or `not-an-8a-claim`; `principal`
  is who reads, learns or does the thing; `gain` is what that buys them that
  they did not already have; `settled_by` is the file:line **in this
  repository** that settles it, and that line must also appear in `evidence`, so
  §10's mechanical check verifies the line your relevance argument rests on.
  `not-an-8a-claim` is a legitimate answer and not an escape hatch: it costs one
  sentence in `gain` saying what the finding asserts instead, which the arbiter
  reads back against the finding itself.
- `remediation` is an object, not a sentence. `summary` is what a reader acts
  on; `patch` is the concrete change — a diff sketch, the function to call
  instead, the exact guard to add and where. `verify_findings.py` flags a bare
  string as `remediation_shape`, and a `summary` with no `patch` the same way,
  because the patch is the half that can be checked against the tree: a run that
  recommended defining `MBEDTLS_TIMING_ALT` — a macro that replaces the timing
  module and cannot define `MBEDTLS_HAVE_TIME` — reached the final report
  unchallenged because nothing in the finding had to name a line it would
  change. If you cannot write the patch, the gate you could not close belongs in
  `unresolved`.
- `fix_is_caller_side` is a boolean on every finding that carries a
  `remediation`, and `remediation.summary` says in one line why it has that
  value. It is `true` when the patch changes no line inside the scanned scope:
  the caller must pass a bound, the integrator must set a build option, the
  consumer must stop handing this function attacker-controlled data. This
  pipeline scans libraries as often as applications, and a fix that lands
  outside the target is advice to the consumer rather than a defect in the
  target — the report can only say which if you do.
- **A dismissal carries `primary_location`, `evidence` and
  `false_positive_reasons`**, on `NOT_VULNERABLE` and `ACCEPTED_RISK` alike — the
  dismissal-side counterpart of the list a `VULNERABLE` carries, applied on the
  branch that closes the candidate. Both verdicts end the candidate's life, and a
  reader who wants to reopen one needs somewhere it was looking, a line that was
  read, and a reason. Each of those three used to be asked for only on the
  positive branch, and in the audited run 90 of 98 verdicts shipped
  `evidence: []`, `gates_evaluated: []`, `primary_location: ""` and no file:line
  anywhere — arguing nothing, citing nothing, and tripping no check, because
  every check was written for the other branch.
- `false_positive_reasons` takes either shape, and the object form is preferred
  because then nothing has to be parsed back out of prose:
  `{"code": "FP-GUARDED", "file": "boot/x.c", "line": 123, "why": "…"}`. The
  string form `"FP-GUARDED: … boot/x.c:123 …"` is still accepted — the code is
  read as the leading token up to the first colon or space, and the citation as
  any `path.ext:NNN` in the text — so the two shapes let exactly the same things
  past — which is why it stays rather than being deprecated: the string form is
  what the cheap validators actually emit, and taking it away would close nothing
  the object form does not leave open too. Either way **the entry must carry a
  real file:line, and that same file and line must appear in your own
  `evidence`**, where the checker reads it back off disk. The disqualifier is the
  argument and the `evidence` entry is the line you opened to make it true, so a
  reason resting on a line `evidence` never goes near closes the candidate
  somewhere nobody looked. `verify_findings.py` reports that as
  `dismissal_uncited` — the same code as a reason carrying no citation at all,
  because it fails the same way — and on `NOT_VULNERABLE` the code must also be
  one of §8's.
- **A clean `MEM-WFS` sweep closes on `FP-WFS-CLEAN`, and its seven answers are
  its evidence.** `FP-GUARDED` and `FP-SIZED-CORRECTLY` answer the sibling
  candidate's question and are refused here (`wfs_dismissal_by_sibling`), and no
  other §8 code describes a pass that found nothing, so the code carries the
  pass itself. In the field a validator read `unzReadCurrentFile` whole, had 26
  citations verified, found it clean, had no code to say so, shipped an empty
  `false_positive_reasons`, and the finding ended on a person's desk as
  `NEEDS_HUMAN_REVIEW`. The rules, each checked by `verify_findings.py`:
  - `gates_evaluated` holds one object per playbook question, `"gate": "Q1"`
    to `"Q7"`, numbered in the playbook's order (`Q5` is division or modulo by
    zero). A question missing or answered twice is `missing_gates_evaluated`.
  - `"result": "fail"` means the construct is in the function and you checked
    it: the question's defect is not there. The basis cites the line that
    settles it — the `+ 1` in the allocation, the NULL check after the
    `malloc`, the `!= 0` that dominates the divide — as `file:line`, and that
    same file:line is an `evidence` entry the checker reads back off disk. A
    basis resting on a line `evidence` does not hold is `dismissal_uncited`.
  - `"result": "n/a"` means the function has no such construct: no `/` or `%`
    with a variable divisor, no freeing call. The basis cites the range you
    read as `file:start-end` (a hyphen or an en dash), and the range covers the
    candidate's `function_range`. "Lines 120-176 of x.c" is not a range the
    checker can read, and a range that stops short of `function_range` claims
    an absence over lines you did not read; both are `missing_gates_evaluated`.
  - `pass` (the defect is there) and `unchecked` cannot close on this code. A
    defect is its own `MEM-WFS` verdict; a question you could not settle is
    `NEEDS_HUMAN_REVIEW`, naming the question in `unresolved`.
  - The seven bases differ from one another, since two answers resting on one
    basis have answered one question (`missing_gates_evaluated`). Seven answers
    that read the same on three functions once line numbers are stripped are
    `templated_dismissal`: that is a sentence about the rule again.
  - The `false_positive_reasons` entry cites the function's opening line — the
    candidate's `line`: `function_range[0]`, or the first line with text
    after it when the record opens on a blank one — and `evidence` carries
    that line with role `declaration`. Keep its `why` short; the argument is in
    the seven answers.
  - Valid only on `NOT_VULNERABLE` under `rule_id` `MEM-WFS`; anywhere else it is
    `unknown_disqualifier`. It is not an absence code: it is not queued on
    sight, it joins the dismissals the arbiter samples, and the checker demands
    no `relevance_test` of it (contract §4 Step 5's `not-an-8a-claim` answer is
    still the one to write).

  Illustrative only — the shape to copy, not the numbers:

  ```json
  {
    "rule_id": "MEM-WFS",
    "verdict": "NOT_VULNERABLE",
    "confidence": "high",
    "primary_location": "src/x.c:120",
    "evidence": [
      { "role": "declaration", "file": "src/x.c", "line": 120, "code": "int x_read(struct x *s, char *buf, unsigned len)" },
      { "role": "allocation",  "file": "src/x.c", "line": 131, "code": "p = malloc(len + 1);" },
      { "role": "guard",       "file": "src/x.c", "line": 132, "code": "if (p == NULL) goto fail;" },
      { "role": "guard",       "file": "src/x.c", "line": 140, "code": "if (n > s->avail) n = s->avail;" },
      { "role": "free",        "file": "src/x.c", "line": 170, "code": "free(p);" }
    ],
    "gates_evaluated": [
      { "gate": "Q1", "result": "fail", "basis": "one allocation, len + 1, terminator written at p[len], src/x.c:131" },
      { "gate": "Q2", "result": "fail", "basis": "n clamped to s->avail, the bytes actually received, src/x.c:140" },
      { "gate": "Q3", "result": "fail", "basis": "malloc result NULL-checked before first use, src/x.c:132" },
      { "gate": "Q4", "result": "fail", "basis": "p freed once, after its last use, never read again, src/x.c:170" },
      { "gate": "Q5", "result": "n/a",  "basis": "no / or % anywhere in the body, src/x.c:120-176" },
      { "gate": "Q6", "result": "n/a",  "basis": "no local declared without an initialiser, src/x.c:120-176" },
      { "gate": "Q7", "result": "n/a",  "basis": "no read, write, snprintf, fseek or ftell call, src/x.c:120-176" }
    ],
    "relevance_test": {
      "claim": "not-an-8a-claim",
      "principal": "caller of x_read",
      "gain": "asserts no memory-safety defect in x_read, not a disclosure, a timing leak or a missing control",
      "settled_by": "src/x.c:120"
    },
    "false_positive_reasons": [
      { "code": "FP-WFS-CLEAN", "file": "src/x.c", "line": 120, "why": "seven answers in gates_evaluated Q1-Q7" }
    ]
  }
  ```
- **A `LOG-TRI` verdict is four answers, and a function with nothing to protect closes
  on them.** `LOG-TRI` is a whole function that no rule matched, handed to you because
  a triage model rated it high; the model's reading is not in the record and is no
  evidence. `gates_evaluated` holds one object per absent-control checklist, named
  `LOG-001`, `LOG-002`, `LOG-004` and `LOG-009` (the playbook's four questions). A
  checklist missing, answered twice or named otherwise is `missing_gates_evaluated`,
  with its own detail, exactly as `MEM-WFS`'s `Q1`–`Q7` are; no new code was added to
  the arbiter's remand list. Each result is `pass` (the control is missing on some
  path), `fail` (it is there on every path; the basis cites its `file:line`, which is
  also in `evidence`), `n/a` (no operation this checklist protects; the basis cites a
  range `file:start-end` covering `function_range`, as `Q5`–`Q7`'s do) or `unchecked`,
  which a dismissal cannot close on. The four bases differ. Every `LOG-TRI` verdict
  carries `relevance_test` (§8a claim 3, `missing-control`) and keeps `rule_id`
  `LOG-TRI`, narrowing only `cwe`. A function with no protected operation in it
  closes as `NOT_VULNERABLE` with `FP-NOT-SECURITY` cited at the function's opening
  line (the candidate's `line`, carried in `evidence` as a `declaration`), all four
  answers `n/a` over a range that covers `function_range`, and `relevance_test`
  `{"claim": "missing-control", "principal": "any caller", "gain": "nothing: no
  protected operation in <range>", "settled_by": "<the opening line>"}`; as an absence
  code it is always read by the arbiter. The playbook has the example.
- **`ACCEPTED_RISK` uses `FP-ACCEPTED`, and it is the one code that does not mean
  "not a bug".** §8's codes are disqualifiers: every one of them says the finding
  was never real. `ACCEPTED_RISK` says the opposite — the defect is real and the
  codebase knowingly carries it — so labelling it with a disqualifier would
  record a live bug as a false positive, which is the distinction §2 created this
  verdict to preserve. Cite the line that shows the acceptance is deliberate: the
  comment, the configuration flag, the compensating control. Without one it is a
  `VULNERABLE`, not an accepted risk. The old check asked only whether a colon appeared anywhere in the
  entry, which a code prefix supplies for free: `"FP-GUARDED: whole-function
  scan"` — no file, no line, nothing a reader can look up — satisfied it, and the
  count of uncited dismissals fell from 35 to 0 over a run in which the
  dismissals got strictly worse. A citation is a path and a line number. The
  colon in your own prefix is not one.
- For `NEEDS_HUMAN_REVIEW`, `unresolved` must be non-empty and each entry must
  state what artefact would resolve it (e.g. "build flags for `HAVE_TPM`",
  "linker script for `.secure_ram` placement").
- Omit `exploit_sketch` for anything you rate below `high`.

### Worked example — the return convention that cancels

A run against MCUboot reported an inverted success check at
`boot/bootutil/src/encrypted.c:491` and prescribed flipping the condition. The
call and the check, at `encrypted.c:489-493`:

```c
    rc = bootutil_ecdh_x25519_shared_secret(&pk_ctx, &buf[EC_PUBK_INDEX], private_key, shared);
    bootutil_ecdh_x25519_drop(&pk_ctx);
    if (!rc) {
        return -1;
    }
```

The validator opened the wrapper, read the bottom of it, and stopped —
`boot/bootutil/include/bootutil/crypto/ecdh_x25519.h:45-50`:

```c
    rc = X25519(z, sk, pk);
    if (rc != 0) {
        return -1;
    }

    return 0;
```

A `return 0;` at the end of a C function reads as "0 is success", which makes
`if (!rc) return -1;` read as "bail out when it succeeded". Obvious inversion,
obvious patch, and wrong. The terminus is one call further down, at
`ext/fiat/src/curve25519.c:1308-1314`:

```c
int X25519(uint8_t out_shared_key[32], const uint8_t private_key[32],
           const uint8_t peer_public_value[32]) {
  static const uint8_t kZeros[32] = {0};
  x25519_scalar_mult_generic(out_shared_key, private_key, peer_public_value);
  // The all-zero output results when the input is a point of small order.
  return CRYPTO_memcmp(kZeros, out_shared_key, 32) != 0;
}
```

`X25519` returns **1** on success and 0 when the shared secret came out all-zero.
So the wrapper maps success to −1 and failure to 0 — one inversion — and
`if (!rc) return -1;` at the call site inverts it back: `rc == 0` is exactly
X25519's failure case, and the caller bails on it. The composition is correct as
written, and the prescribed patch would have failed every successful decryption
of an encrypted image. Two inversions cancelled; reading either one alone gives
the opposite answer, which is why a wrapper is never the terminus.

`ext/` is outside that run's `scanned_roots`, so line 1313 was unreadable to the
validator and to the arbiter after it, and its source is in the repository. That
is precisely the case the rule above covers: `NEEDS_HUMAN_REVIEW` naming `X25519`
and `ext/fiat/src/curve25519.c` in `unresolved` — not a `VULNERABLE` inferred
from the wrapper's literal, and not a quiet dismissal either. Whichever way your
reasoning was running, an out-of-scope terminus is the one thing that has to be
said out loud.

## 8a. The relevance test — what does the attacker actually gain?

Many rules fire on the *shape* of code: a value whose name suggests a secret, a
comparison that exits early, a control that is absent. A shape is what stage 3
hands you; it is a candidate, not a finding.

This section governs **three kinds of claim**, and each has its own question.
Work out which one you are making and answer *that* question — the tests are not
interchangeable, and applying the wrong one is how a real bug gets closed.

**Which claim you are making follows from what your finding asserts, not from
the `rule_id` stage 3 stamped on the candidate.** The rule lists below say
where each claim usually lands; they do not route. A finding that asserts a
timing leak is a claim (2) finding whatever rule it arrived under, and one that
asserts a value is exposed is a claim (1) finding likewise. So "`CRY-005` is not
governed by this claim" below is about the attacker-chosen comparison length
that `CRY-005` names; it does not leave a timing claim you raised under
`CRY-005` with no test to answer, and that gap is how two of the false positives
this section exists to stop reached the arbiter as positives.

**These three are exhaustive of what this section governs.** If your finding is
none of them — a predictable key derivation, one key on every device, a missing
zeroisation, an absent key rotation or key revocation path (`LOG-005`; a
session's revocation is claim (3)), an unchecked return value — §8a does not
apply and is **not** a ground for dismissal: record `"claim":
"not-an-8a-claim"` with one sentence saying what the finding asserts instead,
and go on to the rule's own gates. Closed because the value is no secret at
all, it answers (1): `disclosure`.

### (1) Disclosure — "this value is exposed"

`LOG-005` (hardcoded secrets, and secrets in the wrong place), `LOG-009`
(storage and transport), `HW-008`, `HW-010`, `HW-012`, and any `MEM-WFS`
over-read reported as memory disclosure.

**Name the principal first.** Confidentiality is relative to a reader, never
absolute. Write down who can read the value *at this sink* and could not
otherwise: an on-path network observer, a log reader, a log-shipping vendor, a
local unprivileged user, a co-tenant, whoever receives the core dump. "It is
exposed" with no reader named is not a claim.

Then say what reading it buys them. Two answers close the finding:

- **They can already obtain it, at least this widely.** Cite the line **in this
  repository** that makes it obtainable — not an RFC. An RFC says what a
  protocol requires; the finding is a claim about what this program does, and
  the gap between the two is what you are here to find.

  Two conditions on that citation. It must be a **different sink** from the one
  you are reporting: if the exposure you are dismissing *is* the act that makes
  the value obtainable — a credential on a command line, in a URL, in a
  world-readable file, on an unencrypted channel — this branch does not apply.
  "The attacker can read it because this program publishes it" is the finding,
  not the dismissal. And the exposure you report must be **no wider** than the
  one that already exists: a value visible to a transient on-path observer is
  not thereby public in a durable log, a core dump, or a third-party log sink.

- **It buys them nothing.** Holding the value lets them do nothing they could not
  already do, because every operation it takes part in is still gated by
  something they do not have. Cite that gate at file:line **in this repository**,
  show it is on every path, and show it is correct at the boundary and not
  satisfiable while the attack still works (§4 step 4). A gate you did not open
  and read is not a citation. A value named like an identifier, in a codebase
  that checks nothing else, is a credential whatever it is called.

  Evaluate the value alongside the others in this review. If the gate you cite is
  itself disclosed somewhere in this codebase — including in a candidate you or a
  sibling validator closed — the gate does not hold. Where you cannot check, that
  is `NEEDS_HUMAN_REVIEW`, not a dismissal.

Either answer → `NOT_VULNERABLE` with `FP-NOT-SECURITY`, citing the line.

### (2) Side channel — "this leaks through timing"

`LOG-007`, `LOG-008`, `HW-009`.

**Do not apply the test in (1) here.** A MAC, a tag, a password hash, a PIN and
an OTP are not values whose possession authenticates anybody, so a
"is it a credential?" test would dismiss precisely the comparisons these rules
exist to protect. The variable-time HMAC comparison is the canonical finding of
this class. Do not talk yourself out of it.

The question is about the **operand the attacker cannot compute**, not the one
they hold. In `memcmp(computed, supplied, n)` the leaked value is `computed`;
of course the attacker holds `supplied` — they sent it. If the timing reveals
bytes of the locally computed or locally stored reference value, it is a
finding, whatever they hold on the other side.

- Timing reveals a value the attacker is trying to produce or guess — a MAC,
  tag, signature, password hash, PIN, OTP, token, key → **finding**.
- Timing reveals nothing, because **both** operands are values they already
  hold and producing a match wins them nothing — a cleartext protocol
  identifier, a public certificate field, an OID → `FP-NOT-SECURITY`, however
  early it exits. A secret compared against a public constant is *not* this
  case: `memcmp(otp_root_key, ALL_ZERO_32, 32)` leaks the key, not the constant.
- The leaked quantity need not be the value itself. A distinguishable early
  return that reveals the secret's *length*, or whether an account, key or
  record exists at all, is a finding — say what the metadata narrows, and by
  how much.

Be careful with "cache key". It means a handle whose disclosure *and* forgery
both buy nothing because a separate secret gates every use — cite that gate, on
every path. A lookup handle the attacker is trying to *find* rather than one
they already hold, or one whose match alone authorises the operation, is a
credential whatever the code calls it.

`LOG-007` turns on the same distinction. "Secret key material" means a private
scalar, a private exponent, a symmetric key, a nonce that must not repeat — not
a public modulus, a public exponent, or a peer's public share, however plainly
the variable is called a key. Variable-time arithmetic on the public path of a
verify operation is deliberate and is not a finding.

**`CRY-005` is not governed by this claim.** A comparison whose *length* comes
from the attacker is an authentication bypass, not a leak: it reveals nothing
and simply succeeds. Judge it on consequence.

### (3) Missing control — "there is no X"

`LOG-009` (fixation, predictable identifiers, revocation), `OTH-003`, and every
`LOG-TRI` (a whole function no rule matched, asked whether the control that
protects its operation is absent: a function with no such operation answers
`FP-NOT-SECURITY`, claim `missing-control`, gain "nothing").

Absence is always true somewhere, so **name the attack the missing control would
have stopped, and show this codebase is subject to it**: who the attacker is,
what they do, what they get. If the control is missing because the threat does
not exist here, that is `FP-NOT-SECURITY`.

For a library, framework or SDK the threat model belongs to the consumer. Name
the attack against a *plausible consumer* — "any application that stores this
cookie in a browser" is a sufficient showing. `FP-NOT-SECURITY` is available
only when no plausible consumer is subject to it, never merely because this
repository contains no deployment.

**`HW-001`–`HW-007` are exempt from the showing.** Those missing controls are
countermeasures against fault injection, whose applicability is a fact about
silicon and deployment, not about source. Do not demand a demonstration from
this repository: state the assumed `attacker_model` per the hardware playbook's
threat-model gate and let it set severity. `FP-NOT-SECURITY` is available there
only when the guarded value is not an asset at all, never because the physical
model is merely unproven.

The trap in this claim is importing a threat model along with the vocabulary.
"Session fixation" and "no revocation on password change" are web-application
findings, where the session cookie *is* the credential. In a protocol library
there is usually no password and no logout, and the identifier authenticates
nobody — but check which case you are in rather than asserting it: in TLS 1.2
without tickets the server chooses the session identifier (RFC 5246 §7.4.1.3)
and a client cannot plant one, while a client presenting a ticket supplies an
identifier the server echoes (RFC 5077 §3.4), and in TLS 1.3
middlebox-compatibility mode the client generates the `legacy_session_id` that
the server echoes (RFC 8446 §4.1.2). Even in those cases the value authenticates
nobody, so planting one wins nothing — but say that, rather than saying the
client cannot choose it.

Predictability is the same question in another form: an identifier has to be
unpredictable only when guessing it wins something. Say what guessing wins, or
do not raise it.

**Expiry is not on this list**, so an expiry finding, positive or dismissal,
records `"claim": "not-an-8a-claim"`. A session or resumption cache with no
absolute lifetime and no flush path is a finding in a protocol library as much
as in a web application — say what the unbounded window costs.

### Worked example — the false positive this section exists to stop

A run against Mbed-TLS reported "disclosure of the session id" against
`library/ssl_client.c`:

```c
memcpy(p, ssl->session_negotiate->id, ssl->session_negotiate->id_len);
p += ssl->session_negotiate->id_len;

MBEDTLS_SSL_DEBUG_BUF(3, "session id", ssl->session_negotiate->id,
                      ssl->session_negotiate->id_len);
```

A disclosure claim, so (1) applies. The principal is whoever reads the debug
log. The two lines above copy those same bytes into the outgoing ClientHello —
a different sink from the one being reported, and not itself a finding, so the
first branch is available. And it buys the reader nothing: the identifier is a
lookup handle, and resumption still requires proving knowledge of the secret it
stands for — the master secret in the Finished MAC under TLS 1.2 (RFC 5246
§7.4.9), the resumption PSK in the binder under TLS 1.3 (RFC 8446 §4.2.11.2).
`FP-NOT-SECURITY`, citing the `memcpy`.

The same value under (2): a `memcmp` of a session id in a cache lookup leaks
nothing, because both operands are values the attacker holds and a match wins
nothing. Under (3): "never regenerated" is not fixation here, because planting
the identifier wins nothing.

### Values this section never excuses

- **Keys, of every kind.** Symmetric keys, private keys, KDF inputs,
  key-wrapping keys, STEKs, TOTP/HOTP seeds. You do not *present* a key, you
  compute with it, so no "does possession authenticate?" argument reaches one.
- **Passwords, passphrases and account credentials in any form** — plaintext or
  hashed, user or service, including default and factory credentials, keystore
  and key-file passphrases, and connection strings that embed one. The plaintext
  is never less protected than the hash.
- **Anything offline-attackable**: password hashes, wrapped keys. The check that
  gates the live operation does not survive disclosure of what it checks against.
- **Every factor of a multi-factor scheme.** A second factor is not saved by the
  first factor's check; that check falls with the value.
- **Any credential this program itself puts somewhere readable** — a command
  line, a URL, an environment variable, a world-readable file, an unencrypted
  channel. Publishing it is the finding; see the branch-1 conditions above.
- **Session tickets, and TLS 1.3 resumption PSK identities.** A ticket *is* on
  the wire in the clear, so "it is transmitted in cleartext" does not close it —
  apply the breadth rule instead: a durable log or a core dump is a far wider
  exposure than a transient observer. Holding a ticket is not by itself enough
  to resume; it stands for a secret sealed under a key the holder does not have.
  It matters anyway: a STEK that is never rotated or is replicated across a fleet
  turns every ticket into a durable ciphertext that one key compromise unseals
  retroactively, along with any recorded traffic from those sessions; a ticket
  whose seal is worthless — state stored unencrypted, or sealed under a
  hardcoded, default or all-zero STEK — hands its holder the secret directly; and
  a ticket is long-lived and links one user across connections. In TLS 1.3 these
  bytes travel in `PskIdentity.identity` (RFC 8446 §4.2.11), so in source they
  are usually called an identity rather than a ticket.
- **Bearer tokens, API keys, and web session cookies** — there the cookie *is*
  the authenticator.
- **Anything a privacy mechanism is specifically protecting**, such as the inner
  ClientHello's `server_name` under Encrypted ClientHello. Check the protocol
  version before calling a value public: a client `Certificate` is unprotected in
  TLS 1.2 and travels inside the encrypted handshake in TLS 1.3 (RFC 8446 §4.4.2,
  §2), and DTLS 1.2 carries a cleartext record sequence number where DTLS 1.3
  encrypts it (RFC 9147 §4.2.3) — that one is a linkability protection, so report
  a leak of it as linkability rather than as disclosure.
- **Anything whose name in code is broader than the value you checked.** A
  variable, struct or file called `certificate` or `cert` very often carries the
  private key alongside the certificate.

A PSK binder and a `Finished` value belong in neither list, and not because both
are public — the binder does travel in the cleartext ClientHello (RFC 8446
§4.2.11), while `Finished` never travels in the clear in any version. They are
not disclosure findings because `verify_data` is ephemeral: a MAC over one
transcript under one secret, worthless once that handshake ends. They are
exactly what claim (2) is about, because forging one is the attack.

### What this section does not do

It answers "is this a disclosure, a leak, or a real missing control?". It never
answers "is this value security-relevant at all?". A value you classify as
public here still has to be generated by a CSPRNG wherever the protocol needs
unpredictability (`OTH-002`), and a session cache keyed on a public identifier
with no binding to SNI, cipher suite or peer certificate is still cross-origin
resumption. Dismissing the disclosure does not dismiss the value.

If the harm you are reporting is **linkability** rather than confidentiality — a
stable identifier in a durable or exported sink lets a reader correlate one user
across sessions — none of the three claims applies. That is a real `low`/`info`
privacy finding. Say so; do not file it as a disclosure and do not close it as
`FP-NOT-SECURITY`.

Every verdict under this section — the positives as much as the dismissals —
records in `relevance_test` which claim you were answering, the principal, the
gain, and the file:line that settles it. "It looks like an identifier" is not a
citation. `FP-NOT-SECURITY` is in the always-reviewed set, so the arbiter reads
every one of these.

### The seven marked "absence" are claims about what does *not* exist

`FP-NO-CALLERS`, `FP-UNREACHABLE`, `FP-NOT-COMPILED`, `FP-DEAD-CODE`,
`FP-NO-ATTACKER-INPUT`, `FP-TRUSTED`, `FP-NOT-SECURITY`. These are the cheapest exit when you are
out of budget, and the arbiter audits every one of them. Before you use one:

- **An empty caller set is weak evidence, not a fact.** `rg` finds textual call
  sites. It does not find a function reached through a pointer stored in a
  dispatch or vtable, a symbol aliased in a linker script or a `#define`, a
  caller in a language you did not search, a call through a macro that pastes the
  name together, or a symbol exported for something outside this repository.
- **Search for the bare name as text, not just `name(`, across everything stage
  1 scanned.** The absence search is exactly this, run through the shell:

  ```sh
  rg --no-ignore --hidden --binary -w -n -g '!.git' -g '!.hg' -g '!.svn' -g '!.security-review' 'parse_hdr' .
  ```

  `-w` on the bare name finds `.handler = parse_hdr` and `ops->parse =
  parse_hdr`; `rg 'parse_hdr\s*\('` does not. The flags are the other half. A
  plain `rg` honours the scanned repository's `.gitignore`, `.ignore` and
  `.rgignore`, `.git/info/exclude` and the analyst's global excludes, skips
  hidden directories, and gives up on a file at its first NUL byte. Stage 1
  reads no ignore file, walks hidden directories, and scans a file whose first
  NUL lies past its first 8 KiB — so a caller in any of those is one the
  pipeline scanned and a plain `rg` cannot see, and a repository chooses what
  it misses by committing one `.ignore`. The `-g` globs skip only what stage 1
  always skips and, as extra `-g '!<folder>'` globs, the folders your step 0 told
  you to leave out (this scanner's own installed folder: its rule tables and
  fixtures are not callers), and the trailing `.` keeps `rg` off stdin. In a snapshot
  run (§4) the path is `.security-review/snapshot` instead of
  `.`, with every `-g` glob kept: a glob with no `/` is tested against
  the names of what `rg` finds below the path you name, never against the
  directories in that path, so `-g '!.security-review'` hides only a
  `.security-review` inside the snapshot, as stage 1 does. `rg` prints every
  hit under that prefix, and you cite it without. A `binary file matches` line
  is a hit: open that file. Do the bare-name search before concluding nothing
  calls it, and say in your evidence that you did.
- **`git ls-files` and a plain `rg` are not evidence of absence.**
  The first lists tracked files only, and the second does not search ignored
  or hidden files. Neither can stand behind an absence code.
- **If your dismissal would collapse were a caller present, it is not a
  dismissal.** It is `NEEDS_HUMAN_REVIEW` with the caller you could not find
  named in `unresolved`.
- `FP-NOT-COMPILED` and `FP-DEAD-CODE` require citing the build file, the
  `#ifdef`, or the target — not an inference from the directory name.

