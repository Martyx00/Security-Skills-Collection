# Pipeline contract — stage 5 (§8–§8b)

> Part of `contract.md`, moved here unchanged. §9, what never
> happens, is in that file and binds you too: read it.

## 8. `ledger/` — stage 5

The ledger persists across runs and is meant to be committed. It is the only part
of the pipeline whose value compounds.

### `decisions.jsonl`

```json
{
  "schema_version": 1,
  "decision_id": "DEC-0001",
  "at": "2026-09-18T19:00:00Z",
  "author": "you@example.com",
  "run_id": "2026-09-18T18-49-03Z",
  "candidate_id": "CAND-0001",
  "function_key": "src/proto/parse.c::parse_tlv_record::0",
  "content_hash": "9f2c1ab4e0d73516",
  "rule_id": "MEM-002",
  "cwe": "CWE-787",
  "rule_cwe": "CWE-787",
  "final_verdict": "VULNERABLE",
  "decision": "confirmed",
  "reason_code": null,
  "reason": "Confirmed by hand; len is unbounded from the wire.",
  "fix_commit": null,
  "scope_code": null,
  "scope_basis": null,
  "path_override": null,
  "conflict_acknowledged": null
}
```

`decision` ∈ `confirmed` | `rejected` | `out_of_scope` | `needs_info` |
`withdrawn`. `reason_code` is required when `rejected` and must be one of the
Validator Contract's `FP-*` codes — a rejection that cannot name a
disqualifier code is a rejection nobody can learn from, and the training
export will not take it.

`cwe` is the CWE the verdict was given under, taken with the verdict's own
precedence: the ARB record's (the last `changes[]` entry on `cwe`, its field
spelled with or without `final_`/`original_` in any case, as
`verify_findings.py`'s twin gate reads it; the ARB schema has no CWE field of
its own), then the finding's, then the candidate's — and spelled as that gate
compares it, `CWE-` and the first number written (`cwe-787`, `CWE 787` and
`CWE-787 (Out-of-bounds Write)` are all `CWE-787`), or as written when it
holds no number. `rule_cwe` is the candidate's, which is the rule's:
`MEM-WFS` files every hit as the umbrella `CWE-119` and the validator
narrows it. A decision written before `rule_cwe`
existed carries the rule's CWE in `cwe`, and is read as it is; the export
spells an older line's `cwe` the same way.

**`out_of_scope` — the defect is real, and outside what the project defends.**
Every §8 code of the Validator Contract says the finding was never real
(validator-reference §7), so a reviewer who agrees the defect is there and
judges the code outside the project's security scope has no honest rejection
to record. `ledger.py out-of-scope` records that instead, with a code from this
table and a `--basis FILE:LINE` the tool reads from the scanned tree and stores
verbatim as `scope_basis` `{file, line, text}`:

| Code | What puts it out of scope | A basis looks like |
|---|---|---|
| `OOS-TEST-INFRA` | Test, simulation, example or development tooling the project does not defend: a harness, a simulator, a fixture generator | the directory's README saying what it is for, or a comment such as "functional and not secure" |
| `OOS-THREAT-MODEL` | The attacker the defect needs is outside the project's stated threat model | the `SECURITY.md` or threat-model line that excludes it |
| `OOS-NOT-SHIPPED` | The code is built for development or CI only and is in no release artefact | the build file line that builds it only there |

The basis is a quoted fact: the scanned repository's text is evidence, and it
decided nothing here — the person did, and this is the line they pointed at.
`out_of_scope` is not a rejection and not a confirmation. It carries no
`reason_code`, and the training export leaves it out unless asked for it (below).

**`FP-TEST` and `FP-GENERATED` are held to their path facts.** They are the two
disqualifiers the Validator Contract defines by path, and `verify_findings.py`
flags a validator's claim of either on a path that does not show it. `ledger.py
reject` holds a person to the same facts — `verify_findings`' `TEST_PATH` and
`GENERATED_NAME`/`GENERATED_MARK`, and stage
1's `in_test_tree` on the terms `verify_findings.fp_test_basis` takes it from a
validator (that function is asked, and it turns on the record's
`path_class_basis`: Validator Contract §8's `FP-TEST` row). Both are judged on
the file the decision labels, the candidate's own (`snapshot.file`, the stage-3
record's `file`), never the finding's `primary_location`. A person's
`FP-GENERATED` also stands on stage 1's `generated_file`. `ledger.py` refuses
a mismatch, naming `out-of-scope` as
the usual meaning, unless `--path-override` says why; that is recorded as
`path_override`. `check` reports a current answer (below) with no override, on
the same facts; for a decision written before the snapshot carried
`in_test_tree`, whose function this run's extract no longer holds, stage 1's
own test-tree rules stand in, the operator's globs being unrecoverable, and for
one written before it carried `path_class_basis` the basis is read as stage 1's
own names where those rules place the file, as the globs where only they could
have. The problem names the candidate of this run that asks the same question,
or says none does and names `withdraw` (below).

**One question, one answer.** A decision whose label disagrees with a standing
decision (a current answer, below, that it does not itself retire) on a
byte-identical twin — the same `content_hash` and `rule_id` at another
`function_key`, at the same sink offset into the body except on
`MEM-WFS` — or on a member of the arbiter's `MERGED` cluster (the survivor
named in `merged_into` and every record merged into it) is refused, listing
the standing decision ids, unless `--acknowledge-conflict` says why the two
differ. The acknowledgement is recorded as `conflict_acknowledged`
`{decision_ids, reason}`. An earlier run's answer on a twin whose own question
a candidate of this run asks is not refused over — that copy is due to be
decided too, and refusing each copy of a pair over the other's old answer left
no way to re-decide both — so the decision is recorded, naming that candidate
as still to decide. `check` reports every disagreeing pair nobody
acknowledged. The decision's `snapshot` carries `merged_into`, `line_offset`,
`candidate_line`, `in_test_tree`, `path_class_basis`, `generated_file` and
`cwe_source`, so the ledger answers these after the run directory is gone. A
decision written before `line_offset` has
its offset read back off its candidate while its run is the current one; one
from an earlier run is paired with any sink of its rule, and the refusal and
`check` say the two may be different sinks.

`ledger.py` records a decision only on a candidate stage 4 adjudicated: it
refuses one with neither a validator verdict (`findings/<id>.json`) nor an
`ARB-<id>.json`, and one that `arbitration/queue.json` sent to the arbiter and
that has no `ARB-<id>.json` yet. `export_sarif.py` is stricter and exports only
ARB-backed findings.

A later decision supersedes an earlier one only when both carry the same
`run_id`, `candidate_id`, `function_key`, `content_hash` and `rule_id`: stage 3
renumbers candidate ids from `CAND-0001` on every run, so an id alone joins
nothing across runs. Across runs, a later decision on the same question — the
same `function_key`, `content_hash` and `rule_id`, and the same sink offset
where both record one (never compared on `MEM-WFS`) — **retires** the earlier
run's, which stays in the trail. Within one run so does a decision on another
candidate id whose sink both decisions measured as the same — offset, or
`candidate_line` — since re-running stage 3 under one `run_id` renumbers the
ids; two unmeasured ones stay two answers. A decision with no label
(`needs_info`, `withdrawn`) retires no labelled one: it is no answer. `check`,
`status`, the conflict refusal, `pending` and the export all read these
current answers, so a correction is recorded on the candidate of the later run
that asks the question; the adjudicated `cwe` never decides it, since a model
picks it anew each run. `--label-filter` is applied after the export's folds.
No ledger field carries key material: `ledger.py` refuses a `--reason` that
does, and `check` reports one already there.

**An answer nothing can answer again is withdrawn.** A current answer whose
question no candidate of this run asks — its body was edited or is gone — can
be decided again by nobody, so `check` reported it for ever. `ledger.py
withdraw --decision DEC-… --reason …` appends a `withdrawn` line carrying that
decision's `run_id`, `candidate_id`, `function_key`, `content_hash` and
`rule_id`, so it supersedes it, with `withdraws` (the id) and
`withdrawn_in_run`. It has no label: the export leaves it out and counts it,
and a later decision on the question retires it. `ledger.py` refuses one while
a candidate of this run asks the question — decide that instead — and one on
an answer already superseded, retired or withdrawn; `check` reports a
withdrawal naming no decision on its own key.

`reason_code` `FP-WFS-CLEAN` is accepted only when the candidate, its finding or
its ARB record carries `rule_id` `MEM-WFS` — the whole-function pass is the one
thing that code describes — and `check` reports one stored on a decision whose
`rule_id` and `snapshot.rule_ids` name no `MEM-WFS`.

`ledger.py pending [--json]` is read-only and is the count stage 5 opens with.
For every candidate in `candidates/` (the deferred queues excepted) with no
standing decision for this `run_id`, it takes the verdict the way a decision
does — the ARB record's `final_verdict` where there is one, the finding's
`verdict` otherwise — and counts by verdict. A candidate `queue.json` sent to
the arbiter that has no ARB record is `awaiting_arbiter`; one with neither
record is `unadjudicated`. `NOT_VULNERABLE` is split into validator-only,
arbiter `UPHELD` (or `UPHELD_MODIFIED`) and arbiter `OVERTURNED`, the last with
each candidate id and the validator verdict it overturned. The review set is
broken down in `review_set_shape`: the findings, the `MERGED` sinks and the
survivor each was merged into, the distinct function bodies and paths, and each
body that sits at more than one path counting its copies outside the review
set — under `decided`, every current answer on that body from any run, and
under `held_back`, this run's adjudicated copies outside the review set with
their verdicts; the counts stay over the review set. A missing
`candidates/` or a candidate file it cannot read is listed under `problems` and
exits 1, because every count beside it is short by what was not read. Stage 5
holds the `NOT_VULNERABLE` records back unless the reviewer asks for them, so the
training export carries a human label on one only from a session that did.

### `suppressions.jsonl`

```json
{
  "schema_version": 1,
  "suppression_id": "SUP-0001",
  "created_at": "2026-09-18T19:05:00Z",
  "author": "you@example.com",
  "function_key": "src/proto/parse.c::parse_tlv_record::0",
  "rule_id": "MEM-002",
  "content_hash_at_creation": "9f2c1ab4e0d73516",
  "reason": "Input is a compile-time constant table; tracked in ISSUE-441.",
  "expires_at": "2026-12-18T00:00:00Z",
  "revoked_at": null
}
```

Enforced by `ledger.py`, not by convention:

1. **A suppression without `expires_at` is refused.** There is no permanent
   suppression. An indefinite one is a decision nobody revisits.
2. **An expiry beyond `--max-expiry-days` (default 180) is refused** unless
   `--force` is passed, which records `forced: true` on the record.
3. **A suppression whose `content_hash_at_creation` differs from the function's
   current hash does not suppress.** It is listed in
   `queue.json.suppressions_stale` and reported.

   Stage 3 re-checks every record where it takes effect, because nothing forces
   a ledger file through `ledger.py`. A record with no `expires_at` that parses,
   no `rule_id`, no `content_hash_at_creation`, no `function_key` or no
   `suppression_id` (without one, `ledger.py revoke` cannot end it) suppresses
   nothing and is listed in `queue.json.suppressions_unusable` with the reason.
   One past its expiry (`expires_at <= now`) suppresses nothing and is listed in
   `suppressions_expired`. One revoked by either half — `revoked_at` on its own
   line, or an appended `record_type: "revocation"` line — suppresses nothing;
   a revocation line is a trail entry, never itself a suppression.
4. **A suppressed candidate is still extracted, still scored, and still counted.**
   Suppression removes it from the dispatch queue and from the report's findings
   — never from the coverage numbers. A scanner that forgets what it stopped
   looking at cannot tell you when it should start again.

   **`MEM-WFS` follows its siblings.** When every other candidate on a function
   is suppressed, its `MEM-WFS` candidate is suppressed too — by its own record
   if it has one, otherwise with a derived block (`suppression_id: null`,
   `derived_from` naming the records). `ledger.py suppress --rule MEM-WFS` is
   refused, with exit `2` and the advice to suppress the function's other rules,
   because stage 3 derives the whole-function pass from those candidates. A
   record naming `MEM-WFS` that reached the file some other way is not applied
   while a sibling still dispatches, and is listed in
   `queue.json.suppressions_ignored`, which `run_status.py` turns into a
   coverage limitation: the whole-function pass cannot be switched off on its
   own.

### `ledger/training/samples.jsonl`

The export the flywheel needs, written today so that the format is settled before
there is anything to train.

```json
{
  "schema_version": 1,
  "sample_id": "SMP-0001",
  "label": "vulnerable",
  "provenance": "human-confirmed",
  "repo": "github.com/org/repo",
  "commit": "a1b2c3d…",
  "function_key": "src/proto/parse.c::parse_tlv_record::0",
  "content_hash": "9f2c1ab4e0d73516",
  "context_profile": "default-v1",
  "context_sha256": "3f9a…",
  "cwe": "CWE-787",
  "localized_line": 214,
  "explanation": "len derives from ntohs() on wire bytes and is never compared to sizeof(rec->payload).",
  "approved_by": "you@example.com",
  "approved_at": "2026-09-18T19:10:00Z",
  "postdates_eval_freeze": true,
  "decision_id": "DEC-0001",
  "reason_code": null,
  "defect_present": true,
  "rule_cwe": "CWE-787",
  "scope_code": null,
  "scope_basis": null,
  "also_at": [],
  "also_decision_ids": [],
  "conflict": false
}
```

`label` ∈ `vulnerable` | `not_vulnerable`, and `out_of_scope` only when the
export is asked for it (`--include-out-of-scope`, or `--label-filter
out_of_scope`). `provenance` ∈ `human-confirmed` | `human-rejected` |
`verified-fix` | `human-out-of-scope`. `defect_present` is what the label says
about the body — true for `vulnerable` and `out_of_scope` — and is what two
labels are compared on.

**A body labelled both ways is left out.** Samples that share `content_hash`
and `cwe` with opposite `defect_present` are one input taught both answers,
whatever path each came under (`same-cwe`). Across CWEs a body can carry both
honestly — a real overflow beside a guarded copy, a `MEM-002` defect beside a
clean `MEM-WFS` sweep — so there it is a conflict only when the negative is a
claim about the whole function, `FP-TEST`, `FP-GENERATED`, `FP-NOT-COMPILED`,
`FP-NO-CALLERS` or `FP-UNREACHABLE`, which no defect in the body survives
(`cross-cwe`). The export leaves those samples out and lists each body with the
decision ids on either side; `--include-conflicts` writes them marked
`conflict: true`, with `conflict_kind` and `conflict_with`. `check` reports an
unmarked conflict in an existing `samples.jsonl`.

**Twins are one sample.** Samples that agree on `content_hash`, `cwe` and
`label` at different `function_key`s — byte-identical copies given one answer —
are written once, the latest decision standing, with the other paths in
`also_at` and their decisions in `also_decision_ids`.

`postdates_eval_freeze` is computed against
`assets/evalsets/*.json.frozen_at`. A sample that predates the freeze of
an evaluation set is marked, so that a future training run can exclude it and
measure improvement on data the loop never touched. The export reads the
current answers (a retired decision is not one, and a `needs_info` or
`withdrawn` one is no sample), then deduplicates on `(function_key,
content_hash, cwe)`, latest decision standing, and names
each decision it retired or folded into another.

## 8b. `upstream/` — stage 5, optional

**A match is a hint, never a verdict; no match is not novelty.** The upstream
check asks whether a finding may already be reported upstream. It changes no
verdict, no order and no ledger record, and "none found" means only that the
results fetched held nothing matching.

It is the only step in the skill that sends anything to a host other than the
model provider the operator configured, so it is split in two and runs only
with a person's yes at a terminal (§9 rule 7). `upstream_check.py plan` is offline: it
takes the adjudicated set the way `ledger.py` does (the ARB `final_verdict`
over the validator's `verdict`; a candidate queued for the arbiter with no ARB
record left out; the review set only unless `--include-dismissed`), reads the
repository's remote through `rules_lib.run_git`, and writes the exact requests.
`query` re-derives the plan from the run and the options `plan.json` recorded,
never from its `requests`, and refuses (exit 1) unless the recomputed digest,
`--plan-digest` and `plan.json.digest` are equal and `run_id` is still the
run's. v1 plans requests only for a `github.com` upstream, sends no
Authorization header, and refuses redirects and plain HTTP.

### `upstream/plan.json`

```json
{
  "schema_version": 1,
  "tool_version": "1.0.0",
  "run_id": "2026-09-25T10-02-11Z",
  "created_at": "2026-09-25T11:40:03Z",
  "options": {"upstream": null, "remote": null, "sources": ["github"],
              "include_dismissed": false, "max_requests": 30},
  "upstream": {"host": "github.com", "owner": "madler", "repo": "zlib",
               "derived_from": "remote origin",
               "remotes_seen": [{"name": "origin", "host": "github.com",
                                 "url": "https://github.com/madler/zlib.git"}]},
  "destinations": [{"host": "api.github.com", "party": "code-host",
                    "purpose": "search madler/zlib's issues and pull requests for each function name"}],
  "requests": [{"id": "R01", "source": "github", "method": "GET", "body": null,
                "url": "https://api.github.com/search/issues?q=repo:madler/zlib+%22zipRemoveExtraInfoBlock%22&per_page=100",
                "terms_sent": ["madler/zlib", "zipRemoveExtraInfoBlock"],
                "for_candidates": ["CAND-0007"]}],
  "withheld_terms": [],
  "excused_terms": [],
  "left_out": [],
  "not_planned": [],
  "local_hints": {"available": true, "shallow": true, "commits_in_history": 1,
                  "detail": "local history has 1 commits; nothing to compare (a shallow clone holds no history before its tip)",
                  "per_candidate": [{"candidate_id": "CAND-0007",
                                     "file": "contrib/minizip/zip.c",
                                     "later_commits": 0, "truncated": false,
                                     "commits": []}]},
  "candidates": [{"candidate_id": "CAND-0007", "verdict": "VULNERABLE", "...": "..."}],
  "digest": "3f9a0c1d2b4e5f60"
}
```

`digest` is the first 16 hex digits of sha256 over the canonical JSON (sorted
keys, no whitespace) of `{upstream, requests, run_id}`. `party` is `code-host`
for the host that already holds the code and `third-party` for anyone else.
`--source` repeats and defaults to `github` alone; `--source osv` is one
`POST https://api.osv.dev/v1/query` with body `{"commit": "<run.json
git.commit>"}`, matched locally on the function name or file path in each
advisory's summary or details, and is never asked unless named. GitHub search
is one request per unique function name, in review order, capped by
`--max-requests` (default 30); what the cap cut is listed under `left_out`.
Every function name and the repository identity go through
`sweep_secrets.export_spans`, and one it flags is withheld: `withheld_terms`
records which candidates lost a term and which detector fired, never the term.
The scanned commit in the OSV body is screened too, and is the one term sent
past an `entropy` hit — a git object id, held to hex by the tool, that the
entropy test flags on every real commit — while any other kind withholds it;
`excused_terms` records it (`term`, `request`, `detector`, `why`) and `plan`
prints it. Remote URLs carry no userinfo, query or port. `not_planned` lists
why a request was not planned: no upstream derivable — no such remote, a local
path, or a remote that names no OWNER/REPO (exit 2, nothing planned) — a
network host v1 does not query (exit 1, nothing planned), or no scanned commit
to ask OSV about.

`local_hints` is offline and always computed: `git log --all --not <scanned
commit> -- :(literal)<file>` for each finding's file, bounded, never fetched.
`later_commits` counts commits on local refs after the scanned one that touch
the file; `commits` keeps those whose subject names the function at
identifier-segment boundaries. On a shallow clone `detail` says how many
commits the history holds and that there is nothing to compare — never "no
match".

### `upstream/matches.json`

```json
{
  "schema_version": 1,
  "run_id": "2026-09-25T10-02-11Z",
  "plan_digest": "3f9a0c1d2b4e5f60",
  "queried_at": "2026-09-25T11:42:40Z",
  "not_a_verdict": "A match is a hint that an upstream report may concern the same code. It is not a verdict, and no match does not mean the finding is new.",
  "sources": [{"source": "github", "status": "ok", "requests_made": 1,
               "items_seen": 1, "complete": true, "detail": null}],
  "candidates": {
    "CAND-0007": {
      "function_key": "contrib/minizip/zip.c::zipRemoveExtraInfoBlock::0",
      "content_hash": "9f2c1ab4e0d73516",
      "rule_id": "MEM-002",
      "coverage": "complete",
      "coverage_detail": null,
      "results_seen": 1,
      "later_commits_on_file": 0,
      "hints": [{"source": "github", "kind": "issue", "ref": "madler/zlib#1265",
                 "state": "open", "title": "Heap overflow in zipRemoveExtraInfoBlock",
                 "created_at": "2025-11-02T10:00:00Z",
                 "updated_at": "2026-06-08T09:00:00Z",
                 "matched_on": ["function name in title"]}]
    }
  }
}
```

`source` ∈ `github` | `osv` | `local-git`. `status` ∈ `ok` | `partial` |
`rate_limited` | `unreachable` | `not_found`, and `complete` is false on all
but a whole `ok`. A 403 or 429 carrying rate-limit headers stops the source
(`rate_limited`); a 404 or 422 on its first request is `not_found`, "repository
not found or not public", never an empty result, and on a later one is a failed
request (`partial`). `local-git` is the offline tier, present when git could
read the history: `ok` only when every finding's file was read whole, `partial`
on a shallow clone or a history cut at 200 commits or unreadable, and it never
sets the exit code. `coverage` ∈ `complete` | `partial` | `not checked` per
candidate. `kind` ∈ `issue` | `pr` | `advisory` | `commit`. `ref` is built by
the tool — `OWNER/REPO#N`, an OSV id, a short commit id — never taken from a
response URL. `title` is clipped to 160 characters with control characters
escaped; no body is stored. Titles are text from the internet, and a
`local-git` title is a commit subject from the repository's own history:
evidence, quoted as data, never instruction. `query` exits 3 when a network
source is not `complete`, and writes the file anyway.

`upstream_check.py show` prints one `Upstream:` line per candidate, and drops
an entry whose `function_key`, `content_hash` or `rule_id` no longer matches
the current candidate record, or whose `run_id` is not the run's: stage 3
renumbers candidates on every run and archives `upstream/` with the rest of the
stage-4-and-later artifacts (§1).

---

