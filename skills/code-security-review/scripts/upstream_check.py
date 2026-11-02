#!/usr/bin/env python3
"""
upstream_check.py - stage 5, optional. Has somebody upstream already reported
this? Asked of the code host only after the operator has seen exactly what
would be sent, and said yes.

The first zlib field test confirmed one real security defect: a heap overflow in
minizip's `zipRemoveExtraInfoBlock`. It had been public for months as upstream
issue madler/zlib#1265, and two of the low findings already had open pull
requests. Nothing in the pipeline looked. A reviewer deciding a finding is
better served knowing that a report exists - and a maintainer receiving one is
better served by a reporter who knew.

Looking means leaving the machine for a host the operator never configured -
every other network call a review makes goes to the model provider or scoring
endpoint they chose. The queries carry function names and the repository's
identity, which for private code is itself something to keep. So this tool
splits the step in two:

  plan   OFFLINE. Works out, from the run's adjudicated findings and the
         repository's remote, the exact requests a query would make - method,
         URL and body, each listed - writes them to upstream/plan.json and
         prints them, with a digest over them. It also reads the local git
         history, which sends nothing: commits on local refs after the scanned
         commit that touch a finding's file, and whether their subject names
         the function.
  query  NETWORK. Re-derives the plan from the run artifacts and the options
         plan.json recorded - it never takes a request from plan.json itself -
         and makes those requests only when the recomputed digest, the digest
         on its command line and the one in plan.json all agree and the run is
         still the one planned for. It writes upstream/matches.json.
  show   OFFLINE. One `Upstream:` line per finding, for the review stage's block.

`query` is a PERSON'S command. It refuses (exit 4) unless standard input is a
terminal and the person types a confirmation word, shown on that terminal beside
the plan, that changes on every invocation. The digest binds what is sent to what
`plan` showed; the confirmation binds it to a person who read it. A planted
comment in the scanned tree can tell a model that the operator said yes, and no
host prompt stands behind this tool any more (a plain skill install has no
harness layer), so the tool asks itself. This is a speed bump, not a boundary: a
model with a shell can allocate a pseudo-terminal and read the prompt, and nothing
here can tell that from a person. What it does is stop the unattended, headless
and piped invocations, make the confirmation a recorded event (`approval` in
matches.json), and make going around it a deliberate act the transcript shows.
With no terminal the command prints the line for the person to run themselves
(`handoff`), and the review goes on without the upstream check:
references/limitations.md says the host's own approval prompt, which was the
third lock, is gone.

What it will not do:

  * Send anything but the queries listed. No source, no file contents, no
    finding text, no Authorization header - there is no token support, so a
    private repository answers 404 or 422, which is reported as "repository not
    found or not public" and never as "no match".
  * Send a function name or the repository identity when the outbound secret
    detector flags it (sweep_secrets.export_spans, the same one the SARIF, the
    report gate and the ledger use). A flagged term is withheld, and plan.json
    records that one was, never what it was. The scanned commit in the OSV
    body is screened too, and is the one exception: a git object id, held to
    hex, which the entropy test flags on every real commit. It is sent past an
    `entropy` hit and no other, and plan.json (`excused_terms`) and the
    printed plan say so.
  * Talk to a host the scanned repository chose. The remote URL comes out of
    the scanned tree's .git/config, which is the sender's; it only selects
    OWNER/REPO. The API hosts are module constants, never flags, and v1 plans
    requests only for a github.com remote. Userinfo in a remote URL - a token
    in `https://user:token@...` - is stripped before anything is printed,
    stored or sent.
  * Follow a redirect, speak plain HTTP, or wait out a rate limit. A 403 or 429
    carrying rate-limit headers stops the source and says `rate_limited`.
  * Store a body. Titles are kept, clipped to 160 characters with control
    characters escaped; `ref` is built here from OWNER/REPO and the number, or
    from the advisory id, never copied from a response's URL.
  * Call anything a verdict. A match is a hint that an upstream report may
    concern the same code; no match does not mean a finding is new. `show`
    drops a hint whose candidate no longer has the function_key, content_hash
    and rule_id it was fetched for, because stage 3 renumbers candidates from
    CAND-0001 on every run.
  * Fetch. The local tier reads history already on disk through
    rules_lib.run_git, which neutralises the repository's own config; `git
    fetch` would run the scanned repository's transport settings. A shallow
    clone is reported as "local history has N commits; nothing to compare".

The adjudicated set is the one ledger.py records decisions on: the ARB record's
final_verdict where there is one, the validator's verdict otherwise, and a
candidate queue.json sent to the arbiter with no ARB record yet is left out. By
default only the review set - VULNERABLE, NEEDS_HUMAN_REVIEW, ACCEPTED_RISK - is
queried; NOT_VULNERABLE only with --include-dismissed.

Stdlib only. Python 3.8+.

Usage
  python3 upstream_check.py plan  --root .
  python3 upstream_check.py plan  --root . --source github --source osv
  python3 upstream_check.py plan  --root . --upstream github:madler/zlib
  python3 upstream_check.py query --root . --plan-digest 3f9a0c1d2b4e5f60
  python3 upstream_check.py show  --root . [--candidate CAND-0042] [--json]
  python3 upstream_check.py --selftest

Reads   .security-review/run.json                         (run_id, git.commit)
        .security-review/candidates/<category>.json       (stage 3)
        .security-review/findings/<candidate>.json        (stage 4, validator)
        .security-review/arbitration/ARB-<candidate>.json (stage 4, arbiter)
        .security-review/arbitration/queue.json           (what awaits the arbiter)
        .security-review/upstream/plan.json, matches.json (query, show)
        the scanned repository's remotes and local history, through git
Writes  .security-review/upstream/plan.json               (plan)
        .security-review/upstream/matches.json            (query)
Sends   only what `plan` printed, and only from `query`

Exit codes
  0  done
  1  refused: the digests disagree, the run changed since the plan, the
     upstream host is not one v1 queries, or a write path is unsafe (a symlink
     at or under .security-review/ on the way to the file)
  2  usage: nothing adjudicated to check, no upstream derivable (pass
     --upstream github:OWNER/REPO), no plan to query, or a malformed flag
  3  partial: a request failed or was rate-limited; matches.json is still
     written, with `complete: false` on what it did not cover
  4  `query` only: no person confirmed it. Standard input is not a terminal, or
     the confirmation word was not typed. Nothing was sent
  7  refused before reading or writing anything: the scanned repository commits
     files under .security-review/ other than .gitignore and regular files
     under ledger/, git cannot say whether it does, or --root is this installed
     skill or an old copy of the scanner rather than a repository
     (rules_lib.run_dir_gate). Checked first, so it outranks every other code
"""

import argparse
import contextlib
import datetime
import hashlib
import http.client
import io
import ipaddress
import json
import os
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True      # the skill folder is read-only: no __pycache__ in it
sys.path.insert(0, HERE)
import rules_lib                                       # noqa: E402
import sweep_secrets                                   # noqa: E402

TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 1

RUN_DIR = ".security-review"
UPSTREAM_DIR = "upstream"
PLAN_FILE = "plan.json"
MATCHES_FILE = "matches.json"

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3
EXIT_PERSON = 4          # `query`: no person confirmed it at a terminal; nothing sent

# Where requests go. Constants and never flags: a flag is something a prompt,
# or text planted in the scanned tree, can ask an agent to change. The selftest
# points them at a 127.0.0.1 stub; nothing else does.
GITHUB_API = "https://api.github.com"
OSV_API = "https://api.osv.dev"

# The remote hosts v1 derives an upstream from. Any other host plans nothing.
SUPPORTED_HOSTS = ("github.com",)

SOURCES = ("github", "osv")
DEFAULT_SOURCES = ("github",)
PARTY = {"github": "code-host", "osv": "third-party"}

DEFAULT_MAX_REQUESTS = 30
MAX_REQUESTS_CEILING = 100
REQUEST_TIMEOUT = 20
# Unauthenticated search allows 10 requests a minute. Spacing them keeps a
# 30-request plan inside that without ever sleeping out a limit.
SEARCH_SPACING = 6.5
USER_AGENT = "security-review-skill-upstream-check/%s" % rules_lib.skill_version()
GITHUB_ACCEPT = "application/vnd.github+json"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_DOC_BYTES = 256 * 1024 * 1024
TITLE_LIMIT = 160
SUBJECT_LIMIT = 160
# Commits read per file from local history, and commit hints kept per finding.
LOCAL_LOG_LIMIT = 200
LOCAL_HINTS_PER_CANDIDATE = 10

REVIEW_SET = ("VULNERABLE", "NEEDS_HUMAN_REVIEW", "ACCEPTED_RISK")
DISMISSED = "NOT_VULNERABLE"
VERDICT_ORDER = REVIEW_SET + (DISMISSED,)

NOT_A_VERDICT = ("A match is a hint that an upstream report may concern the same "
                 "code. It is not a verdict, and no match does not mean the "
                 "finding is new.")
NOTHING_ELSE = ("Nothing else is sent: no source, no file contents, no finding "
                "text. Your IP address and the queries are visible to %s.")

DIGEST = re.compile(r"^[0-9a-f]{16}$")
COMMIT = re.compile(r"^[0-9a-f]{7,64}$")
UPSTREAM_SPEC = re.compile(r"^github:([^/\s]+)/([^/\s]+)$")
# GitHub's own limits: an owner is letters, digits and single hyphens; a
# repository name adds `.` and `_`. Anything else is not a repository this
# tool will put into a URL path.
OWNER_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SYNTHETIC_NAME = re.compile(r"^<[^>]*>$")
OSV_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
ISO_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}(?:T[0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$")
SCP_REMOTE = re.compile(r"^(?:[^@/\s]+@)?([A-Za-z0-9.-]+):(?!//)(.+)$")


class Refused(Exception):
    """A refusal, with the exit code it carries."""

    def __init__(self, message, code=EXIT_REFUSED):
        Exception.__init__(self, message)
        self.code = code


# --------------------------------------------------------------------------- #
# reading the run
# --------------------------------------------------------------------------- #

def run_dir(root):
    return os.path.join(root, RUN_DIR)


def upstream_path(root, name):
    return os.path.join(run_dir(root), UPSTREAM_DIR, name)


def read_json(path):
    """The document at `path`, or None when it is absent, oversize or not JSON.
    Every file here comes out of the scanned tree's run directory."""
    try:
        if os.path.getsize(path) > MAX_DOC_BYTES:
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _record_for(document, candidate_id):
    items = document if isinstance(document, list) else [document]
    for item in items:
        if isinstance(item, dict) and item.get("candidate_id") in (None, candidate_id):
            return item
    return None


def load_candidates(root):
    """(records by id, unreadable files): every candidate stage 3 dispatched.

    The deferred queues and the coverage files hold no dispatched candidate,
    as in ledger.run_candidates; the first record under an id wins, as
    ledger.load_candidate resolves it.
    """
    directory = os.path.join(run_dir(root), "candidates")
    records, unreadable = {}, []
    if not os.path.isdir(directory):
        return records, unreadable
    for name in sorted(os.listdir(directory)):
        if (not name.endswith(".json") or name.startswith("coverage")
                or name.endswith("-deferred.json")):
            continue
        document = read_json(os.path.join(directory, name))
        if document is None:
            unreadable.append(os.path.join(directory, name))
            continue
        rows = document if isinstance(document, list) else \
            (document.get("candidates") if isinstance(document, dict) else None)
        for row in rows or []:
            if isinstance(row, dict) and row.get("candidate_id"):
                records.setdefault(str(row["candidate_id"]), row)
    return records, unreadable


def arbitration_queued(root):
    """The candidate ids arbitration/queue.json sent to the arbiter."""
    document = read_json(os.path.join(run_dir(root), "arbitration", "queue.json"))
    queue = document.get("queue") if isinstance(document, dict) else None
    if not isinstance(queue, list):
        return frozenset()
    return frozenset(str(entry["candidate_id"]) for entry in queue
                     if isinstance(entry, dict) and entry.get("candidate_id"))


def adjudicated_set(root, include_dismissed=False):
    """(entries, unreadable): the findings a person reviews, in review order.

    The rule is ledger.py's (record_decision, pending): the ARB record's
    final_verdict wins over the validator's verdict, a candidate with neither
    record is not adjudicated, and one queue.json sent to the arbiter that has
    no ARB record yet is still waiting and is left out.
    """
    candidates, unreadable = load_candidates(root)
    queued = arbitration_queued(root)
    base = run_dir(root)
    wanted = REVIEW_SET + ((DISMISSED,) if include_dismissed else ())
    entries = []
    for candidate_id, record in candidates.items():
        arb = read_json(os.path.join(base, "arbitration", "ARB-%s.json" % candidate_id))
        arb = _record_for(arb, candidate_id) if arb is not None else None
        finding = read_json(os.path.join(base, "findings", "%s.json" % candidate_id))
        finding = _record_for(finding, candidate_id) if finding is not None else None
        if arb is None and finding is None:
            continue
        if arb is None and candidate_id in queued:
            continue
        verdict = str((arb or {}).get("final_verdict") or (finding or {}).get("verdict")
                      or "")
        if verdict not in wanted:
            continue
        span = record.get("function_range")
        entries.append({
            "candidate_id": candidate_id,
            "verdict": verdict,
            "function": record.get("function"),
            "function_key": record.get("function_key"),
            "content_hash": record.get("content_hash"),
            "file": record.get("file"),
            "function_range": span if isinstance(span, list) else None,
            "rule_id": record.get("rule_id"),
        })
    entries.sort(key=lambda e: (VERDICT_ORDER.index(e["verdict"]), e["candidate_id"]))
    return entries, unreadable


def load_run_json(root):
    document = read_json(os.path.join(run_dir(root), "run.json"))
    return document if isinstance(document, dict) else None


def scanned_commit(run_json):
    """run.json's git.commit when it is a commit id, else None. It goes onto a
    git command line and into the OSV body, so a value that is not hex - an
    option, say - is never used."""
    commit = ((run_json or {}).get("git") or {}).get("commit")
    if isinstance(commit, str) and COMMIT.match(commit):
        return commit
    return None


# --------------------------------------------------------------------------- #
# where upstream is
# --------------------------------------------------------------------------- #

def _clean(text):
    """A remote URL or name as it may be printed and stored: control characters
    escaped, anything the outbound secret detector flags redacted."""
    text = rules_lib._printable(text, 300)
    spans = sweep_secrets.export_spans(text)
    if not spans:
        return text
    return sweep_secrets.redact_spans(text, [(s, e) for s, e, _k in spans])


def parse_remote(url):
    """{host, owner, repo, url} out of a remote URL, with userinfo gone.

    The https, http, ssh and git schemes and the scp form (`git@host:o/r.git`)
    are read. `url` in the result is scheme, host and path only - no user, no
    password, no port, no query - and is the only spelling that is ever
    printed. owner and repo are None unless the path is exactly two segments
    GitHub would accept.
    """
    raw = (url or "").strip()
    host, path, scheme = None, None, None
    if "://" in raw:
        try:
            parts = urllib.parse.urlsplit(raw)
            host = parts.hostname
        except ValueError:
            parts, host = None, None
        if parts is not None and host:
            scheme = parts.scheme.lower()
            path = parts.path
    else:
        match = SCP_REMOTE.match(raw)
        if match and not os.path.isabs(raw):
            host, path = match.group(1), match.group(2)
    if not host:
        return {"host": None, "owner": None, "repo": None,
                "url": _clean("(local path or unreadable URL)")}
    host = host.lower().rstrip(".")
    path = (path or "").strip("/")
    shown = ("%s://%s/%s" % (scheme, host, path)) if scheme else "%s:%s" % (host, path)
    owner = repo = None
    segments = path.split("/")
    if len(segments) == 2:
        name = segments[1][:-4] if segments[1].endswith(".git") else segments[1]
        if OWNER_NAME.match(segments[0]) and REPO_NAME.match(name) \
                and name not in (".", ".."):
            owner, repo = segments[0], name
    return {"host": host, "owner": owner, "repo": repo, "url": _clean(shown)}


def read_remotes(root, git_config=()):
    """[(name, url)] from the repository's own config, raw: `--local` reads
    .git/config only, and --get-regexp does no insteadOf rewriting. Read through
    rules_lib.run_git, so the repository's config runs nothing on the way.

    `git_config` is rules_lib.git_trusted_config(), as every other caller
    passes it: run_git drops the system gitconfig, and with it the
    safe.directory a CI image sets so root can read a checkout another user
    owns. Without it the gate passes and every call here fails."""
    raw = rules_lib.run_git(root, ["config", "--local", "-z", "--get-regexp",
                                   r"^remote\..*\.url$"], config=git_config)
    remotes = []
    for item in (raw or b"").split(b"\0"):
        if not item:
            continue
        key, _, value = os.fsdecode(item).partition("\n")
        if key.startswith("remote.") and key.endswith(".url"):
            remotes.append((key[len("remote."):-len(".url")], value))
    return remotes


def derive_upstream(root, spec=None, remote=None, git_config=()):
    """(upstream, sentence, exit code): the upstream to ask, as recorded in
    plan.json, and a sentence when there is none this tool may query (None, and
    EXIT_OK, when there is one). A host v1 does not query is EXIT_REFUSED; no
    OWNER/REPO to put into a URL, from any host, is EXIT_USAGE.

    `--upstream github:OWNER/REPO` wins. Otherwise a remote: the one --remote
    names, else `upstream` - the name a fork gives the project it forked - else
    `origin`. Every remote seen is listed, userinfo stripped, so the operator
    can see which one was taken and why.
    """
    seen = []
    parsed = {}
    for name, url in read_remotes(root, git_config):
        info = parse_remote(url)
        parsed.setdefault(name, info)
        seen.append({"name": _clean(name), "url": info["url"],
                     "host": _clean(info["host"]) if info["host"] else None})
    upstream = {"host": None, "owner": None, "repo": None, "derived_from": None,
                "remotes_seen": seen}
    if spec:
        match = UPSTREAM_SPEC.match(spec)
        if not match or not OWNER_NAME.match(match.group(1)) \
                or not REPO_NAME.match(match.group(2)) or match.group(2) in (".", ".."):
            raise Refused("--upstream %s is not github:OWNER/REPO with a GitHub owner "
                          "and repository name" % rules_lib._printable(spec, 120),
                          EXIT_USAGE)
        upstream.update(host="github.com", owner=match.group(1), repo=match.group(2),
                        derived_from="--upstream")
        return upstream, None, EXIT_OK
    order = [remote] if remote else ["upstream", "origin"]
    for name in order:
        if name in parsed:
            info = parsed[name]
            upstream.update(host=info["host"], owner=info["owner"], repo=info["repo"],
                            derived_from="remote %s" % _clean(name))
            break
    else:
        if remote:
            return upstream, ("there is no remote named %s (remotes seen: %s). Pass "
                              "--upstream github:OWNER/REPO."
                              % (_clean(remote), ", ".join(r["name"] for r in seen)
                                 or "none")), EXIT_USAGE
        return upstream, ("no remote named `upstream` or `origin`, and no --upstream "
                          "(remotes seen: %s). Pass --upstream github:OWNER/REPO, or "
                          "--remote NAME."
                          % (", ".join(r["name"] for r in seen) or "none")), EXIT_USAGE
    if upstream["host"] not in SUPPORTED_HOSTS:
        # A local path has no host at all, so no upstream is derivable from it;
        # a network host this version does not query is a refusal.
        return upstream, ("the remote's host is %s. This version queries %s only, so "
                          "no request is planned. Pass --upstream github:OWNER/REPO "
                          "if the project is mirrored there."
                          % (upstream["host"] or "not a network host",
                             ", ".join(SUPPORTED_HOSTS))), \
            EXIT_USAGE if upstream["host"] is None else EXIT_REFUSED
    if not (upstream["owner"] and upstream["repo"]):
        return upstream, ("the %s does not name an OWNER/REPO this tool can put into "
                          "a URL. Pass --upstream github:OWNER/REPO."
                          % upstream["derived_from"]), EXIT_USAGE
    return upstream, None, EXIT_OK


# --------------------------------------------------------------------------- #
# local history - offline
# --------------------------------------------------------------------------- #

def name_pattern(name):
    """`name` at identifier-segment boundaries (rules_lib.SEGMENT_BOUNDARY): the
    rule the name rules run by, so `inflate` is found in `inflate()` and in
    `fix inflate_fast`, and not inside `deflate`."""
    return rules_lib.compile_name_pattern(r"\b%s\b" % re.escape(name))


def path_pattern(path):
    """A repository path as a whole path in free text: not the tail of a longer
    one, and not the head of one either."""
    return re.compile(r"(?<![\w./-])%s(?![\w/-])" % re.escape(path))


def searchable_name(name):
    """A function name that can go into a quoted search term as itself."""
    return (isinstance(name, str) and name.strip() == name and 0 < len(name) <= 200
            and not SYNTHETIC_NAME.match(name) and name.isprintable()
            and '"' not in name)


def local_history(root, entries, commit, git_config=()):
    """What the local git history says, offline. Nothing is fetched."""
    hints = {"available": False, "shallow": None, "commits_in_history": None,
             "detail": None, "per_candidate": []}
    if not commit:
        hints["detail"] = ("run.json records no scanned commit, so there is nothing to "
                           "compare local history against")
        return hints
    shallow = rules_lib.run_git(root, ["rev-parse", "--is-shallow-repository"],
                                config=git_config)
    if shallow is None:
        hints["detail"] = "git could not read the repository's history"
        return hints
    hints["available"] = True
    hints["shallow"] = shallow.strip() == b"true"
    count = rules_lib.run_git(root, ["rev-list", "--count", "--all"], config=git_config)
    try:
        hints["commits_in_history"] = int(count.strip()) if count else None
    except ValueError:
        hints["commits_in_history"] = None
    by_file = {}
    for entry in entries:
        path = entry.get("file")
        if not isinstance(path, str) or not path or path in by_file:
            continue
        raw = rules_lib.run_git(root, [
            "log", "--all", "--not", commit, "--max-count=%d" % (LOCAL_LOG_LIMIT + 1),
            "--format=%H%x1f%cI%x1f%s", "--", ":(literal)" + path], config=git_config)
        if raw is None:
            by_file[path] = None
            continue
        rows = []
        for line in os.fsdecode(raw).splitlines():
            parts = line.split("\x1f")
            if len(parts) == 3 and COMMIT.match(parts[0]):
                rows.append({"commit": parts[0], "subject": parts[2],
                             "committed_at": _iso(parts[1])})
        by_file[path] = rows
    for entry in entries:
        rows = by_file.get(entry.get("file"))
        record = {"candidate_id": entry["candidate_id"], "file": entry.get("file"),
                  "later_commits": None, "truncated": False, "commits": []}
        if rows is not None:
            record["truncated"] = len(rows) > LOCAL_LOG_LIMIT
            rows = rows[:LOCAL_LOG_LIMIT]
            record["later_commits"] = len(rows)
            rx = None
            if searchable_name(entry.get("function")):
                rx = name_pattern(entry["function"])
            for row in rows:
                if rx is not None and rx.search(row["subject"]):
                    record["commits"].append({
                        "commit": row["commit"], "committed_at": row["committed_at"],
                        "subject": rules_lib._printable(row["subject"], SUBJECT_LIMIT)})
            record["commits"] = record["commits"][:LOCAL_HINTS_PER_CANDIDATE]
        hints["per_candidate"].append(record)
    if hints["shallow"]:
        hints["detail"] = ("local history has %s commits; nothing to compare (a shallow "
                           "clone holds no history before its tip)"
                           % (hints["commits_in_history"]
                              if hints["commits_in_history"] is not None else "few"))
    return hints


# --------------------------------------------------------------------------- #
# the plan
# --------------------------------------------------------------------------- #

def _host(base):
    return urllib.parse.urlsplit(base).hostname or base


def _withheld(term):
    """The detector kinds that flag `term`, or [] when it may be sent."""
    return sorted({kind for _s, _e, kind in sweep_secrets.export_spans(term)})


def plan_requests(entries, upstream, sources, max_requests, commit):
    """(requests, withheld_terms, excused_terms, left_out): exactly what a query
    sends.

    GitHub search is one request per unique function name, in review order, so
    the cap drops the least urgent names. OSV is one request for the scanned
    commit.
    """
    requests, withheld, excused, left_out = [], [], [], []
    identity = "%s/%s" % (upstream["owner"], upstream["repo"])
    if _withheld(identity):
        withheld.append({"term": "repository identity", "for_candidates":
                         [e["candidate_id"] for e in entries],
                         "detector": _withheld(identity)})
        return requests, withheld, excused, left_out
    if "github" in sources:
        order, users = [], {}
        for entry in entries:
            name = entry.get("function")
            if not searchable_name(name):
                continue
            if name not in users:
                order.append(name)
                users[name] = []
            users[name].append(entry["candidate_id"])
        for name in order:
            kinds = _withheld(name)
            if kinds:
                withheld.append({"term": "function name", "for_candidates": users[name],
                                 "detector": kinds})
                continue
            if len(requests) >= max_requests:
                left_out.append({"term": "function name", "for_candidates": users[name]})
                continue
            query = 'repo:%s "%s"' % (identity, name)
            url = "%s/search/issues?q=%s&per_page=100" % (
                GITHUB_API, urllib.parse.quote_plus(query, safe=":/"))
            requests.append({"id": "R%02d" % (len(requests) + 1), "source": "github",
                             "method": "GET", "url": url, "body": None,
                             "terms_sent": [identity, name],
                             "for_candidates": users[name]})
    if "osv" in sources and commit:
        everyone = [e["candidate_id"] for e in entries]
        # The one term sent past the detector. A real commit id is 40 or 64
        # hex digits, and the entropy test flags every one (it cannot tell a
        # git object id from a key), so screening it like a function name
        # would withhold every OSV request there is. It is excused for that
        # kind alone, only because scanned_commit() already held it to COMMIT -
        # hex and nothing else, so it can carry no credential's text - and it
        # is recorded and printed as excused. Any other kind still withholds it.
        kinds = _withheld(commit)
        if [k for k in kinds if k != "entropy"]:
            withheld.append({"term": "scanned commit", "for_candidates": everyone,
                             "detector": kinds})
        elif len(requests) >= max_requests:
            left_out.append({"term": "scanned commit", "for_candidates": everyone})
        else:
            requests.append({"id": "R%02d" % (len(requests) + 1), "source": "osv",
                             "method": "POST", "url": "%s/v1/query" % OSV_API,
                             "body": {"commit": commit}, "terms_sent": [commit],
                             "for_candidates": everyone})
            if kinds:
                excused.append({"term": "scanned commit", "request": requests[-1]["id"],
                                "detector": kinds,
                                "why": "a git object id: hex only, which the entropy "
                                       "test flags on every real commit"})
    return requests, withheld, excused, left_out


def digest_of(upstream, requests, run_id):
    """The first 16 hex of sha256 over canonical JSON of what would be sent."""
    blob = json.dumps({"upstream": upstream, "requests": requests, "run_id": run_id},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def build_plan(root, options):
    """(plan, exit code, sentence): the whole plan, derived from the run.

    `plan` and `query` both come through here, from the same options, so what
    a query sends is what a plan printed or the digests disagree.
    """
    run_json = load_run_json(root)
    if run_json is None:
        raise Refused("%s is missing or unreadable: there is no run here to check"
                      % os.path.join(run_dir(root), "run.json"), EXIT_USAGE)
    run_id = run_json.get("run_id")
    commit = scanned_commit(run_json)
    entries, unreadable = adjudicated_set(root, options["include_dismissed"])
    for path in unreadable:
        print("warning: %s could not be read; its candidates are not in the plan"
              % path, file=sys.stderr)
    if not entries:
        raise Refused("nothing adjudicated to check: no candidate in this run has a "
                      "verdict in %s%s" % (
                          ", ".join(REVIEW_SET),
                          "" if options["include_dismissed"] else
                          " (NOT_VULNERABLE needs --include-dismissed)"), EXIT_USAGE)
    git_config = rules_lib.git_trusted_config()
    upstream, why, code = derive_upstream(root, options["upstream"], options["remote"],
                                          git_config)
    requests, withheld, excused, left_out = [], [], [], []
    if code == EXIT_OK:
        requests, withheld, excused, left_out = plan_requests(
            entries, upstream, options["sources"], options["max_requests"], commit)
    not_planned = [why] if why else []
    if "osv" in options["sources"] and not commit and why is None:
        not_planned.append("run.json records no scanned commit, so no OSV request is "
                           "planned")
    destinations = []
    for source in options["sources"]:
        if any(r["source"] == source for r in requests):
            base = GITHUB_API if source == "github" else OSV_API
            destinations.append({
                "host": _host(base), "party": PARTY[source],
                "purpose": ("search %s/%s's issues and pull requests for each function "
                            "name" % (upstream["owner"], upstream["repo"])
                            if source == "github" else
                            "advisories recorded against the scanned commit")})
    plan = {
        "schema_version": SCHEMA_VERSION,
        "tool": "upstream_check.py",
        "tool_version": TOOL_VERSION,
        "run_id": run_id,
        "created_at": _now(),
        "options": options,
        "upstream": upstream,
        "destinations": destinations,
        "requests": requests,
        "withheld_terms": withheld,
        "excused_terms": excused,
        "left_out": left_out,
        "not_planned": not_planned,
        "local_hints": local_history(root, entries, commit, git_config),
        "candidates": [{k: e[k] for k in ("candidate_id", "verdict", "function_key",
                                          "content_hash", "rule_id", "file")}
                       for e in entries],
        "not_a_verdict": NOT_A_VERDICT,
    }
    plan["digest"] = digest_of(upstream, requests, run_id)
    return plan, code, why


def options_from_args(args):
    if not 1 <= args.max_requests <= MAX_REQUESTS_CEILING:
        raise Refused("--max-requests must be between 1 and %d"
                      % MAX_REQUESTS_CEILING, EXIT_USAGE)
    sources = []
    for source in args.source or DEFAULT_SOURCES:
        if source not in sources:
            sources.append(source)
    return {"upstream": args.upstream, "remote": args.remote,
            "sources": sorted(sources, key=SOURCES.index),
            "include_dismissed": bool(args.include_dismissed),
            "max_requests": args.max_requests}


def options_from_plan(plan):
    """plan.json's options, held to what `plan` could have written. A value
    that is not is a plan somebody edited, and the query refuses it."""
    options = plan.get("options") if isinstance(plan, dict) else None
    if not isinstance(options, dict) or set(options) != {
            "upstream", "remote", "sources", "include_dismissed", "max_requests"}:
        raise Refused("upstream/plan.json has no options this tool wrote; run `plan` "
                      "again")
    sources = options["sources"]
    ok = (isinstance(sources, list) and sources and all(s in SOURCES for s in sources)
          and len(set(sources)) == len(sources)
          and isinstance(options["include_dismissed"], bool)
          and isinstance(options["max_requests"], int)
          and not isinstance(options["max_requests"], bool)
          and 1 <= options["max_requests"] <= MAX_REQUESTS_CEILING
          and (options["upstream"] is None or isinstance(options["upstream"], str))
          and (options["remote"] is None or (isinstance(options["remote"], str)
                                             and len(options["remote"]) <= 200)))
    if not ok:
        raise Refused("upstream/plan.json's options are not ones `plan` writes; run "
                      "`plan` again")
    return dict(options)


def print_plan(plan):
    requests = plan["requests"]
    local = plan["local_hints"]
    print("upstream check plan for run %s" % plan["run_id"])
    up = plan["upstream"]
    if up["host"]:
        print("upstream: %s/%s on %s (from %s)" % (up["owner"] or "?", up["repo"] or "?",
                                                   up["host"], up["derived_from"]))
    for remote in up["remotes_seen"]:
        print("  remote %s  %s" % (remote["name"], remote["url"]))
    print("findings: %d (%s)" % (len(plan["candidates"]), ", ".join(
        "%s %d" % (v, sum(1 for c in plan["candidates"] if c["verdict"] == v))
        for v in VERDICT_ORDER if any(c["verdict"] == v for c in plan["candidates"]))))
    print("")
    print("Local history (offline, nothing sent):")
    if not local["available"] or local["shallow"]:
        print("  %s" % local["detail"])
    if local["available"]:
        later = [c for c in local["per_candidate"] if c["later_commits"]]
        unread = sorted({c["file"] for c in local["per_candidate"]
                         if c["later_commits"] is None and c["file"]})
        if unread:
            print("  git could not read the history of %d file(s) against the scanned "
                  "commit, so nothing is said about them: %s"
                  % (len(unread), ", ".join(rules_lib._printable(f, 120)
                                            for f in unread)))
        elif not later and not local["shallow"]:
            print("  no commit on a local ref after the scanned commit touches a "
                  "finding's file")
        for record in later:
            print("  %s %s: %d later commit(s) touch the file%s, %d name the function"
                  % (record["candidate_id"], record["file"], record["later_commits"],
                     " (first %d read)" % LOCAL_LOG_LIMIT if record["truncated"] else "",
                     len(record["commits"])))
    print("")
    for sentence in plan["not_planned"]:
        print("Not planned: %s" % sentence)
    if not requests:
        print("No request is planned.")
    else:
        print("Requests (%d):" % len(requests))
        print("  %-4s %-16s %-11s %s" % ("id", "destination", "party", "request"))
        for request in requests:
            source = request["source"]
            base = GITHUB_API if source == "github" else OSV_API
            print("  %-4s %-16s %-11s %s %s" % (request["id"], _host(base), PARTY[source],
                                                request["method"], request["url"]))
            if request["body"] is not None:
                print("  %-4s %-16s %-11s body %s" % ("", "", "", json.dumps(
                    request["body"], sort_keys=True)))
        print("Headers on every request: User-Agent: %s, Accept; no Authorization "
              "header, no cookie." % USER_AGENT)
    for item in plan["withheld_terms"]:
        print("withheld: a %s for %s, flagged by the outbound secret detector (%s); "
              "not sent" % (item["term"], ", ".join(item["for_candidates"]),
                            ", ".join(item["detector"])))
    for item in plan["excused_terms"]:
        print("sent although the outbound secret detector flags it (%s): the %s in "
              "%s's body - %s" % (", ".join(item["detector"]), item["term"],
                                  item["request"], item["why"]))
    for item in plan["left_out"]:
        print("left out by --max-requests %d: the %s for %s"
              % (plan["options"]["max_requests"], item["term"],
                 ", ".join(item["for_candidates"])))
    if requests:
        hosts = sorted({d["host"] for d in plan["destinations"]})
        print("")
        print(NOTHING_ELSE % " and ".join(hosts))
    print("digest: %s" % plan["digest"])


def cmd_plan(args):
    options = options_from_args(args)
    plan, code, _why = build_plan(args.root, options)
    write_json(upstream_path(args.root, PLAN_FILE), plan)
    print_plan(plan)
    if plan["requests"] and code == 0:
        # `query` is the reviewer's command (person_gate): this is the line they run.
        print("")
        print("To send these requests, the reviewer types this in their own terminal "
              "(query asks them to type a word and sends nothing otherwise):")
        print("  %s" % handoff_line(args.root, plan["digest"]))
    return code


# --------------------------------------------------------------------------- #
# the query - the one request a review makes to a host nobody configured
# --------------------------------------------------------------------------- #

class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    """Follow nothing. Returning None hands the 3xx to the default error handler,
    which raises it as an HTTPError before any second request is made. (The
    same handler as scorers/finetuned_backend.py's.)"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _loopback(url):
    host = urllib.parse.urlsplit(url).hostname or ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def fetch(method, url, body):
    """(status, headers, payload, error). HTTPS to a planned host only.

    The URL must start with one of the API constants - the plan built it from
    them, and this is the last place to notice that it did not - and use
    https. Loopback is exempt from https and from any proxy because it never
    leaves the machine, which is what the selftest's stub relies on.
    """
    if not (url.startswith(GITHUB_API + "/") or url.startswith(OSV_API + "/")):
        return None, {}, None, "not a planned destination"
    if urllib.parse.urlsplit(url).scheme != "https" and not _loopback(url):
        return None, {}, None, "not https"
    headers = {"User-Agent": USER_AGENT,
               "Accept": GITHUB_ACCEPT if url.startswith(GITHUB_API + "/")
               else "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body, sort_keys=True).encode("utf-8")
        headers["Content-Type"] = "application/json"
    handlers = [_RefuseRedirect]
    if _loopback(url):
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                return response.status, dict(response.headers), None, "response too large"
            return response.status, dict(response.headers), payload, None
    except urllib.error.HTTPError as exc:
        status = exc.code
        detail = ("redirect refused" if 300 <= status < 400 else "HTTP %d" % status)
        return status, dict(exc.headers or {}), None, detail
    except (urllib.error.URLError, socket.timeout, OSError,
            http.client.HTTPException) as exc:
        reason = getattr(exc, "reason", exc)
        return None, {}, None, "unreachable: %s" % rules_lib._printable(str(reason), 120)


def _rate_limited(status, headers):
    if status not in (403, 429):
        return False
    lower = {str(k).lower(): v for k, v in headers.items()}
    return (lower.get("x-ratelimit-remaining") == "0" or "retry-after" in lower
            or status == 429)


def _iso(value):
    return value if isinstance(value, str) and ISO_TIME.match(value) else None


def _matched(text, rx):
    return isinstance(text, str) and rx is not None and bool(rx.search(text))


def github_hints(payload, upstream, entries_by_id, request):
    """(hints by candidate, items seen, complete) out of a search response.

    Titles are clipped and escaped, bodies are read for matching and never
    kept, and the ref is OWNER/REPO#N built here.
    """
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}, 0, False
    items = doc.get("items") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        return {}, 0, False
    total = doc.get("total_count")
    complete = (isinstance(total, int) and total <= len(items)
                and not doc.get("incomplete_results"))
    out = {}
    for candidate_id in request["for_candidates"]:
        entry = entries_by_id[candidate_id]
        rx_name = name_pattern(entry["function"])
        rx_path = path_pattern(entry["file"]) if entry.get("file") else None
        hints = []
        for item in items:
            if not isinstance(item, dict):
                continue
            number = item.get("number")
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0:
                continue
            title = item.get("title") if isinstance(item.get("title"), str) else ""
            body = item.get("body") if isinstance(item.get("body"), str) else ""
            matched = []
            if _matched(title, rx_name):
                matched.append("function name in title")
            if _matched(body, rx_name):
                matched.append("function name in body")
            if _matched(title, rx_path) or _matched(body, rx_path):
                matched.append("file path in %s" % ("title" if _matched(title, rx_path)
                                                    else "body"))
            if not matched:
                matched.append("GitHub search for the function name; not found in the "
                               "title or body")
            state = item.get("state")
            hints.append({
                "source": "github",
                "kind": "pr" if isinstance(item.get("pull_request"), dict) else "issue",
                "ref": "%s/%s#%d" % (upstream["owner"], upstream["repo"], number),
                "state": state if state in ("open", "closed") else None,
                "title": rules_lib._printable(title, TITLE_LIMIT),
                "created_at": _iso(item.get("created_at")),
                "updated_at": _iso(item.get("updated_at")),
                "matched_on": matched,
            })
        out[candidate_id] = hints
    return out, len(items), complete


def osv_hints(payload, entries_by_id, request):
    """(hints by candidate, advisories seen, complete): advisories recorded
    against the scanned commit, matched here on the function name or the file
    path at segment boundaries in their summary or details."""
    try:
        doc = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}, 0, False
    vulns = doc.get("vulns", []) if isinstance(doc, dict) else None
    if not isinstance(vulns, list):
        return {}, 0, False
    complete = not (isinstance(doc, dict) and doc.get("next_page_token"))
    out = {}
    for candidate_id in request["for_candidates"]:
        entry = entries_by_id[candidate_id]
        rx_name = name_pattern(entry["function"]) \
            if searchable_name(entry.get("function")) else None
        rx_path = path_pattern(entry["file"]) if entry.get("file") else None
        hints = []
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            ident = vuln.get("id")
            if not isinstance(ident, str) or not OSV_ID.match(ident):
                continue
            summary = vuln.get("summary") if isinstance(vuln.get("summary"), str) else ""
            details = vuln.get("details") if isinstance(vuln.get("details"), str) else ""
            matched = []
            if _matched(summary, rx_name) or _matched(details, rx_name):
                matched.append("function name in %s" % ("summary" if _matched(
                    summary, rx_name) else "details"))
            if _matched(summary, rx_path) or _matched(details, rx_path):
                matched.append("file path in %s" % ("summary" if _matched(
                    summary, rx_path) else "details"))
            if not matched:
                continue
            hints.append({
                "source": "osv", "kind": "advisory", "ref": ident,
                "state": "withdrawn" if vuln.get("withdrawn") else "published",
                "title": rules_lib._printable(summary or details, TITLE_LIMIT),
                "created_at": _iso(vuln.get("published")),
                "updated_at": _iso(vuln.get("modified")),
                "matched_on": matched,
            })
        out[candidate_id] = hints
    return out, len(vulns), complete


def run_query(plan, entries_by_id):
    """Make the plan's requests, in order. (sources, per-candidate results)

    A source that answers rate-limited, or not found or unreachable on its first
    request, is stopped there: the requests after it would get the same answer,
    and a limit is recorded rather than waited out.
    """
    per = {cid: {"hints": [], "results_seen": 0, "missed": []} for cid in entries_by_id}
    requests = plan["requests"]
    states, stopped = {}, {}
    last_search = None

    def miss(request, why):
        for cid in request["for_candidates"]:
            if why not in per[cid]["missed"]:
                per[cid]["missed"].append(why)

    for index, request in enumerate(requests, 1):
        source = request["source"]
        state = states.setdefault(source, {
            "source": source, "status": "ok", "requests_made": 0, "items_seen": 0,
            "complete": True, "detail": None})
        planned = sum(1 for r in requests if r["source"] == source)
        if source in stopped:
            miss(request, stopped[source])
            continue
        if source == "github" and last_search is not None:
            wait = SEARCH_SPACING - (time.time() - last_search)
            if wait > 0:
                time.sleep(wait)
        status, headers, payload, error = fetch(request["method"], request["url"],
                                                request["body"])
        if source == "github":
            last_search = time.time()
        state["requests_made"] += 1
        print("[%d/%d] %s %s -> %s" % (index, len(requests), request["method"],
                                       request["url"], error or status), file=sys.stderr)
        if error is None and status == 200:
            reader = github_hints if source == "github" else osv_hints
            if source == "github":
                hints, seen, complete = reader(payload, plan["upstream"],
                                               entries_by_id, request)
            else:
                hints, seen, complete = reader(payload, entries_by_id, request)
            state["items_seen"] += seen
            for cid in request["for_candidates"]:
                per[cid]["hints"].extend(hints.get(cid, []))
                per[cid]["results_seen"] += seen
            if not complete:
                state["complete"] = False
                if state["status"] == "ok":
                    state["status"] = "partial"
                state["detail"] = ("a response held fewer results than it counted, or "
                                   "could not be read")
                miss(request, "more results than one response held")
            continue
        state["complete"] = False
        if _rate_limited(status, headers):
            state["status"] = "rate_limited"
            state["detail"] = ("rate-limited after %d of %d requests"
                               % (state["requests_made"] - 1, planned))
            stopped[source] = state["detail"]
        elif status in (404, 422) and source == "github" \
                and state["requests_made"] == 1:
            # Only on the first request is a 404 or 422 about the repository.
            # After a search has come back, the repository is there, and a 422
            # is GitHub rejecting that one query (one over its 256-character
            # limit, say): a failed request, and the rest still go out.
            state["status"] = "not_found"
            state["detail"] = ("repository not found or not public (HTTP %d); nothing "
                               "was searched" % status)
            stopped[source] = state["detail"]
        elif status is None and state["requests_made"] == 1:
            state["status"] = "unreachable"
            state["detail"] = "%s %s" % (_host(GITHUB_API if source == "github"
                                               else OSV_API), error)
            stopped[source] = state["detail"]
        else:
            if state["status"] == "ok":
                state["status"] = "partial"
            state["detail"] = "a request failed: %s" % error
        miss(request, state["detail"])
    sources = [states[s] for s in plan["options"]["sources"] if s in states]
    return sources, per


def _not_checked_reason(plan, candidate_id):
    for item in plan["withheld_terms"]:
        if candidate_id in item["for_candidates"]:
            return "its %s was withheld by the outbound secret detector" % item["term"]
    for item in plan["left_out"]:
        if candidate_id in item["for_candidates"]:
            return "left out by --max-requests %d" % plan["options"]["max_requests"]
    return "no function name to search for"


# --------------------------------------------------------------------------- #
# the person gate: `query` is confirmed at a terminal (see the module docstring)
# --------------------------------------------------------------------------- #

CONFIRM_WORD = "query"


def stdin_is_terminal():
    try:
        return bool(sys.stdin) and sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def handoff_line(root, digest):
    """The command a person runs themselves, with this script's absolute path."""
    import shlex
    return "python3 -I -B %s query --root %s --plan-digest %s" % (
        shlex.quote(os.path.abspath(__file__)), shlex.quote(os.path.abspath(root)),
        digest)


def confirm_at_terminal(plan, root):
    """Show the plan on the terminal and ask the person to type the confirmation
    word. Returns the evidence record, or None when they did not confirm. The
    caller has already checked that standard input is a terminal."""
    import secrets
    word = "%s-%s" % (CONFIRM_WORD, secrets.token_hex(2))
    err = sys.stderr
    err.write("\n")
    shown = io.StringIO()
    with contextlib.redirect_stdout(shown):
        print_plan(plan)
    err.write(shown.getvalue())
    err.write("\nType %s to send exactly these %d request(s). Anything else cancels: "
              % (word, len(plan["requests"])))
    err.flush()
    try:
        answer = sys.stdin.readline()
    except (OSError, ValueError):
        answer = ""
    err.write("\n")
    if (answer or "").strip() != word:
        return None
    return {"evidence": "tty", "confirmed_at": _now(), "plan_digest": plan["digest"],
            "requests": len(plan["requests"])}


# `query` calls this; the selftest replaces it, because a selftest has no terminal.
_CONFIRM = confirm_at_terminal


def person_gate(plan, root):
    """The evidence that a person confirmed the plan, or a Refused (exit 4)."""
    if not stdin_is_terminal():
        raise Refused(
            "`query` sends requests to hosts nobody configured, which is for a person "
            "to decide, at a terminal, after reading the plan. Standard input here "
            "is not a terminal, so nothing was sent. Do not look for a way around this "
            "and do not run it on the person's behalf; say the review goes on without "
            "the upstream check, and give the person this line to run themselves "
            "(handoff):\n  %s" % handoff_line(root, plan["digest"]), EXIT_PERSON)
    evidence = _CONFIRM(plan, root)
    if not evidence:
        raise Refused("cancelled: the confirmation word was not typed. Nothing was "
                      "sent.", EXIT_PERSON)
    return evidence


def cmd_query(args):
    if not DIGEST.match(args.plan_digest or ""):
        raise Refused("--plan-digest %s is not the 16-hex-digit digest `plan` printed"
                      % rules_lib._printable(args.plan_digest or "", 40), EXIT_USAGE)
    stored = read_json(upstream_path(args.root, PLAN_FILE))
    if not isinstance(stored, dict):
        raise Refused("%s is missing or unreadable: run `upstream_check.py plan` first "
                      "and show the operator what it prints"
                      % upstream_path(args.root, PLAN_FILE), EXIT_USAGE)
    run_json = load_run_json(args.root) or {}
    if stored.get("run_id") != run_json.get("run_id"):
        raise Refused("the plan was made for run %s and this is run %s: the run changed "
                      "since the operator saw it. Run `plan` again and show them."
                      % (stored.get("run_id"), run_json.get("run_id")))
    options = options_from_plan(stored)
    plan, code, why = build_plan(args.root, options)
    if not (plan["digest"] == args.plan_digest == stored.get("digest")):
        raise Refused("digest mismatch: --plan-digest %s, plan.json %s, and the plan "
                      "re-derived from this run %s. Nothing was sent. What would be "
                      "sent is not what the operator approved; run `plan` again and "
                      "show them." % (args.plan_digest,
                                      rules_lib._printable(str(stored.get("digest")), 40),
                                      plan["digest"]))
    if code != EXIT_OK:
        raise Refused("nothing to query: %s" % why, code)
    entries = {c["candidate_id"]: c for c in adjudicated_set(
        args.root, options["include_dismissed"])[0]}
    approval = person_gate(plan, args.root)
    sources, per = run_query(plan, entries)
    local = plan["local_hints"]
    candidates = {}
    for candidate_id, entry in entries.items():
        result = per[candidate_id]
        planned = [r["id"] for r in plan["requests"]
                   if candidate_id in r["for_candidates"]]
        hints = list(result["hints"])
        record = next((r for r in local["per_candidate"]
                       if r["candidate_id"] == candidate_id), None)
        for row in (record or {}).get("commits", []):
            hints.append({"source": "local-git", "kind": "commit",
                          "ref": row["commit"][:12], "state": None,
                          "title": row["subject"], "created_at": row["committed_at"],
                          "updated_at": None,
                          "matched_on": ["function name in commit subject",
                                         "file changed after the scanned commit"]})
        if not planned:
            coverage = "not checked"
            detail = _not_checked_reason(plan, candidate_id)
        elif result["missed"]:
            coverage = "partial"
            detail = "; ".join(result["missed"])
        else:
            coverage = "complete"
            detail = None
        candidates[candidate_id] = {
            "function_key": entry["function_key"],
            "content_hash": entry["content_hash"],
            "rule_id": entry["rule_id"],
            "coverage": coverage,
            "coverage_detail": detail,
            "results_seen": result["results_seen"],
            "later_commits_on_file": (record or {}).get("later_commits"),
            "hints": hints,
        }
    if local["available"]:
        # Offline, and never part of the exit code, but held to the same rule
        # as the network sources: `ok` only when the whole history was read.
        whole = not local["shallow"] and not any(
            r["truncated"] or r["later_commits"] is None for r in local["per_candidate"])
        sources.append({"source": "local-git", "status": "ok" if whole else "partial",
                        "requests_made": 0,
                        "items_seen": sum(dict(
                            (r["file"], r["later_commits"] or 0)
                            for r in local["per_candidate"]).values()),
                        "complete": whole,
                        "detail": local["detail"] or (
                            None if whole else "a finding's file had more than %d later "
                            "commits, or git could not read its history"
                            % LOCAL_LOG_LIMIT)})
    matches = {
        "schema_version": SCHEMA_VERSION,
        "tool": "upstream_check.py",
        "tool_version": TOOL_VERSION,
        "run_id": plan["run_id"],
        "plan_digest": plan["digest"],
        "approval": approval,
        "queried_at": _now(),
        "not_a_verdict": NOT_A_VERDICT,
        "sources": sources,
        "candidates": candidates,
    }
    write_json(upstream_path(args.root, MATCHES_FILE), matches)
    with_hints = sum(1 for c in candidates.values() if c["hints"])
    print("%d finding(s), %d with a possible upstream match (hint) -> %s"
          % (len(candidates), with_hints, upstream_path(args.root, MATCHES_FILE)))
    for state in sources:
        print("  %s: %s, %d request(s), %d result(s)%s"
              % (state["source"], state["status"], state["requests_made"],
                 state["items_seen"], "; " + state["detail"] if state["detail"] else ""))
    print(NOT_A_VERDICT)
    network = [s for s in sources if s["source"] != "local-git"]
    return EXIT_PARTIAL if any(not s["complete"] for s in network) else EXIT_OK


# --------------------------------------------------------------------------- #
# show
# --------------------------------------------------------------------------- #

KIND_TEXT = {"issue": "issue", "pr": "pull request", "advisory": "advisory",
             "commit": "local commit"}


def _hint_text(hint):
    parts = [KIND_TEXT.get(hint.get("kind"), "report"), str(hint.get("ref"))]
    if hint.get("state"):
        parts.append(str(hint["state"]))
    when = hint.get("updated_at") or hint.get("created_at")
    text = " ".join(parts)
    if when:
        text += ", %s %s" % ("updated" if hint.get("updated_at") else "dated",
                             str(when)[:10])
    text += ", %s" % json.dumps(rules_lib._printable(str(hint.get("title") or ""),
                                                     TITLE_LIMIT), ensure_ascii=False)
    return "%s; matched on: %s" % (text, ", ".join(str(m) for m in
                                                    hint.get("matched_on") or []))


def _rank(hint):
    matched = " ".join(hint.get("matched_on") or [])
    return (0 if "function name in title" in matched or "in summary" in matched else
            1 if "function name" in matched and hint.get("source") != "local-git" else
            2 if hint.get("source") == "local-git" else 3,
            0 if hint.get("state") == "open" else 1, str(hint.get("ref")))


def upstream_line(entry, queried_at, full=False):
    """The `Upstream:` text for one candidate's matches entry, or not checked."""
    if entry is None:
        return ["not checked"]
    hints = sorted(entry.get("hints") or [], key=_rank)
    later = entry.get("later_commits_on_file")
    tail = ""
    if isinstance(later, int) and later > 0:
        tail = "; %d later commit(s) on local refs touch the file" % later
    coverage = entry.get("coverage")
    detail = entry.get("coverage_detail")
    if hints:
        first = "possible match (hint) - %s" % _hint_text(hints[0])
        if len(hints) > 1:
            first += "; %d more%s" % (len(hints) - 1, "" if full else
                                      " (show --candidate for all)")
        if coverage == "partial":
            first += "; partial: %s" % detail
        lines = [first + tail]
        if full:
            lines += ["            also: %s" % _hint_text(h) for h in hints[1:]]
        return lines
    if coverage == "complete":
        return ["none found in %d results fetched %s (complete)%s"
                % (entry.get("results_seen") or 0, str(queried_at)[:10], tail)]
    if coverage == "partial":
        # "None found" only over results that came back: a rate limit or a 404
        # fetched nothing, and nothing fetched is not a search that came up empty.
        seen = entry.get("results_seen") or 0
        return ["partial: %s%s%s" % (detail, "; none found in the %d results fetched %s"
                                     % (seen, str(queried_at)[:10]) if seen else "",
                                     tail)]
    return ["not checked (%s)%s" % (detail or "no request covered it", tail)]


def cmd_show(args):
    candidates, _unreadable = load_candidates(args.root)
    run_json = load_run_json(args.root) or {}
    matches = read_json(upstream_path(args.root, MATCHES_FILE))
    note = None
    if not isinstance(matches, dict):
        matches, note = None, "no upstream check was run for this run"
    elif matches.get("run_id") != run_json.get("run_id"):
        note = ("upstream/matches.json is from run %s, not this run %s; its hints are "
                "not shown" % (matches.get("run_id"), run_json.get("run_id")))
        matches = None
    stored = (matches or {}).get("candidates")
    stored = stored if isinstance(stored, dict) else {}
    valid, dropped = {}, []
    for candidate_id, entry in stored.items():
        current = candidates.get(candidate_id)
        if (not isinstance(entry, dict) or current is None
                or any(entry.get(k) != current.get(k)
                       for k in ("function_key", "content_hash", "rule_id"))):
            dropped.append(candidate_id)
            continue
        valid[candidate_id] = entry
    if args.candidate:
        ids = [args.candidate]
    elif matches is not None:
        ids = sorted(valid)
    else:
        ids = [e["candidate_id"] for e in adjudicated_set(args.root)[0]]
    queried_at = (matches or {}).get("queried_at")
    rows = []
    for candidate_id in ids:
        lines = upstream_line(valid.get(candidate_id), queried_at,
                              full=bool(args.candidate))
        rows.append({"candidate_id": candidate_id, "lines": lines,
                     "hints": (valid.get(candidate_id) or {}).get("hints", [])})
    if args.json:
        print(json.dumps({"run_id": run_json.get("run_id"), "note": note,
                          "not_a_verdict": NOT_A_VERDICT, "dropped_stale": dropped,
                          "candidates": rows}, indent=1, sort_keys=True))
        return EXIT_OK
    print(NOT_A_VERDICT)
    if note:
        print(note)
    if matches is not None:
        print("queried %s, plan %s" % (rules_lib._printable(str(queried_at), 40),
                                       rules_lib._printable(str(
                                           matches.get("plan_digest")), 40)))
    for state in (matches or {}).get("sources") or []:
        if isinstance(state, dict):
            print("source %s: %s%s" % (state.get("source"), state.get("status"),
                                       "; %s" % state.get("detail")
                                       if state.get("detail") else ""))
    for row in rows:
        prefix = "" if args.candidate else "%-10s " % row["candidate_id"]
        print("%sUpstream:   %s" % (prefix, row["lines"][0]))
        for extra in row["lines"][1:]:
            print("%s%s" % (prefix, extra))
    if dropped:
        print("dropped %d stale entr%s whose candidate no longer has the function_key, "
              "content_hash and rule_id it was checked for: %s"
              % (len(dropped), "y" if len(dropped) == 1 else "ies",
                 ", ".join(sorted(dropped))))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------------- #

def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_dir_write_problem(root, path):
    """A sentence if writing `path` would go through a link, else None.

    Every file this tool writes is under `.security-review/upstream/`, so the
    walk is the run-directory half of export_sarif.run_dir_write_problem: a
    symlink at `.security-review`, at `upstream/` or at the file, or a run
    directory that does not resolve to `<realpath(root)>/.security-review`,
    refuses the write. The scanned tree can commit a link there as easily as a
    file, and a write through one lands wherever the repository chose.
    """
    base = os.path.join(os.path.abspath(root), RUN_DIR)
    real_run = os.path.join(os.path.realpath(root), RUN_DIR)
    rel = os.path.relpath(os.path.abspath(path), base)
    current = base
    for part in [""] + rel.split(os.sep):
        current = os.path.join(current, part) if part else current
        if os.path.islink(current):
            return ("%s is a symlink to %s. The run directory is inside the scanned "
                    "tree, so a link in it lets the repository under review choose "
                    "where this tool writes (contract §1, §9 rule 2). Remove the link "
                    "- and look at what it points at - then run this again."
                    % (current, os.readlink(current)))
    if os.path.lexists(base) and os.path.realpath(base) != real_run:
        return ("%s resolves to %s, not %s (contract §1)."
                % (base, os.path.realpath(base), real_run))
    return None


def _umask():
    mask = os.umask(0o077)
    os.umask(mask)
    return mask


def write_json(path, document):
    """mkstemp in the target's directory, then os.replace: nothing is written
    through a predictable name or a link. (export_sarif.write_atomic.)"""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix="." + os.path.basename(path) + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(document, fh, indent=1, sort_keys=True)
            fh.write("\n")
        os.chmod(temporary, 0o666 & ~_umask())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def _stub():
    """A 127.0.0.1 server standing in for both APIs. (url, seen, behaviour, stop)"""
    import http.server
    import threading

    seen = []
    behaviour = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8") if length else None
            seen.append({"method": self.command, "path": self.path, "body": body,
                         "headers": {k.lower(): v for k, v in self.headers.items()}})
            rule = behaviour.get("github" if self.path.startswith("/gh/") else "osv",
                                 {"status": 200, "json": {}})
            if callable(rule):
                rule = rule(self.path)
            status = rule.get("status", 200)
            payload = json.dumps(rule.get("json", {})).encode("utf-8")
            self.send_response(status)
            for key, value in (rule.get("headers") or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = _answer                        # noqa: N815

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return ("http://127.0.0.1:%d" % server.server_address[1], seen, behaviour,
            server.shutdown)


def _git(cwd, *args):
    import subprocess
    return subprocess.run(
        ["git", "-c", "user.name=selftest", "-c", "user.email=selftest@test.invalid",
         "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull,
         "-c", "init.defaultBranch=main"] + list(args),
        cwd=cwd, capture_output=True, text=True, timeout=60)


def _fixture(root, commit=None, functions=None):
    """A repository with an adjudicated run in it: CAND-0001 VULNERABLE (ARB),
    CAND-0002 NOT_VULNERABLE (validator-only, unqueued), CAND-0003 queued with no
    ARB record yet, CAND-0004 NEEDS_HUMAN_REVIEW."""
    base = os.path.join(root, RUN_DIR)
    for sub in ("candidates", "findings", "arbitration"):
        os.makedirs(os.path.join(base, sub), exist_ok=True)
    functions = functions or ["zipRemoveExtraInfoBlock", "unzReadCurrentFile",
                              "gz_look", "inflate_fast"]

    def put(rel, obj):
        with open(os.path.join(base, rel), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)

    put("run.json", {"run_id": "2026-09-25T00-00-00Z",
                     "git": {"commit": commit or "a" * 40, "branch": "main"}})
    files = ["contrib/minizip/zip.c", "contrib/minizip/unzip.c", "gzread.c",
             "inffast.c"]
    rows = []
    for index, (name, path) in enumerate(zip(functions, files), 1):
        rows.append({"candidate_id": "CAND-%04d" % index, "rule_id": "MEM-002",
                     "file": path, "function": name, "function_range": [10, 40],
                     "function_key": "%s::%s::0" % (path, name),
                     "content_hash": "%016x" % index})
    put(os.path.join("candidates", "memory-safety.json"), rows)
    put(os.path.join("candidates", "memory-safety-deferred.json"),
        [{"candidate_id": "CAND-0099", "function": "deferred_one"}])
    put(os.path.join("findings", "CAND-0001.json"),
        {"candidate_id": "CAND-0001", "verdict": "NEEDS_HUMAN_REVIEW"})
    put(os.path.join("arbitration", "ARB-CAND-0001.json"),
        {"candidate_id": "CAND-0001", "final_verdict": "VULNERABLE"})
    put(os.path.join("findings", "CAND-0002.json"),
        {"candidate_id": "CAND-0002", "verdict": "NOT_VULNERABLE"})
    put(os.path.join("findings", "CAND-0003.json"),
        {"candidate_id": "CAND-0003", "verdict": "VULNERABLE"})
    put(os.path.join("findings", "CAND-0004.json"),
        {"candidate_id": "CAND-0004", "verdict": "NEEDS_HUMAN_REVIEW"})
    put(os.path.join("arbitration", "queue.json"),
        {"queue": [{"candidate_id": "CAND-0001"}, {"candidate_id": "CAND-0003"}]})


def _listing(top):
    """{path under top: sha256} for every file under `top`, .git included."""
    out = {}
    for directory, _dirs, files in os.walk(top):
        for name in files:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                out[os.path.relpath(path, top)] = "link:" + os.readlink(path)
                continue
            with open(path, "rb") as fh:
                out[os.path.relpath(path, top)] = hashlib.sha256(fh.read()).hexdigest()
    return out


def selftest():
    global GITHUB_API, OSV_API, SEARCH_SPACING, _CONFIRM, stdin_is_terminal
    import shutil

    failures = 0

    def check(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    def run(argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, out.getvalue() + err.getvalue()

    def plan_of(root):
        return read_json(upstream_path(root, PLAN_FILE))

    def matches_of(root):
        return read_json(upstream_path(root, MATCHES_FILE))

    # -- URL forms, and userinfo never survives ------------------------------ #
    for url, want in (
            ("https://github.com/madler/zlib.git", ("github.com", "madler", "zlib")),
            ("https://x-token:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r",
             ("github.com", "o", "r")),
            ("ssh://git@github.com:22/madler/zlib.git", ("github.com", "madler", "zlib")),
            ("git@github.com:madler/zlib.git", ("github.com", "madler", "zlib")),
            ("https://gitlab.com/group/sub/proj.git", ("gitlab.com", None, None)),
            ("/srv/mirror/zlib.git", (None, None, None)),
            ("https://github.com/o/../x", ("github.com", None, None))):
        got = parse_remote(url)
        check("remote %s parses as %r" % (url[:40], want),
              (got["host"], got["owner"], got["repo"]), want)
    shown = parse_remote("https://bob:hunter2secret@github.com/o/r.git?x=1")["url"]
    check("userinfo and query are stripped from the URL kept",
          (shown, "bob" in shown or "hunter2" in shown), ("https://github.com/o/r.git",
                                                          False))
    check("the placeholder DIGEST parses, for the contract parity tests",
          build_parser().parse_args(["query", "--root", ".", "--plan-digest",
                                     "DIGEST"]).plan_digest, "DIGEST")

    if shutil.which("git") is None:
        print("  skip everything below: git is not on PATH")
        print("selftest: %d failure(s)" % failures)
        return 1 if failures else 0

    url, seen, behaviour, stop = _stub()
    saved = (GITHUB_API, OSV_API, SEARCH_SPACING)
    saved_gate = (_CONFIRM, stdin_is_terminal)
    GITHUB_API, OSV_API, SEARCH_SPACING = url + "/gh", url + "/osv", 0
    try:
        with tempfile.TemporaryDirectory() as tmp:
            # -- a repository with a later commit naming a function ---------- #
            root = os.path.join(tmp, "repo")
            os.makedirs(os.path.join(root, "contrib", "minizip"))
            with open(os.path.join(root, ".gitignore"), "w", encoding="utf-8") as fh:
                fh.write(".security-review/\n")
            with open(os.path.join(root, "contrib", "minizip", "zip.c"), "w",
                      encoding="utf-8") as fh:
                fh.write("int zipRemoveExtraInfoBlock(void) { return 0; }\n")
            _git(root, "init", "-q")
            _git(root, "add", "-A")
            _git(root, "commit", "-q", "-m", "scanned")
            scanned = _git(root, "rev-parse", "HEAD").stdout.strip()
            with open(os.path.join(root, "contrib", "minizip", "zip.c"), "a",
                      encoding="utf-8") as fh:
                fh.write("/* bound the header */\n")
            _git(root, "commit", "-q", "-am",
                 "minizip: bound the length in zipRemoveExtraInfoBlock")
            _git(root, "remote", "add", "origin",
                 "https://someone:hunter2secret@github.com/madler/zlib.git")
            _git(root, "remote", "add", "mirror", "https://gitlab.com/madler/zlib.git")
            _fixture(root, commit=scanned)

            code, out = run(["plan", "--root", root])
            plan = plan_of(root)
            check("plan exits 0 and writes plan.json", (code, isinstance(plan, dict)),
                  (0, True))
            check("the set is the review set, ARB over validator, queued-unarbitrated "
                  "left out",
                  [(c["candidate_id"], c["verdict"]) for c in plan["candidates"]],
                  [("CAND-0001", "VULNERABLE"), ("CAND-0004", "NEEDS_HUMAN_REVIEW")])
            check("one GitHub search per function, nothing else by default",
                  [(r["method"], r["source"], r["for_candidates"])
                   for r in plan["requests"]],
                  [("GET", "github", ["CAND-0001"]), ("GET", "github", ["CAND-0004"])])
            check("the URL is the quoted repo:OWNER/REPO search",
                  plan["requests"][0]["url"],
                  GITHUB_API + '/search/issues?q=repo:madler/zlib+%22'
                  'zipRemoveExtraInfoBlock%22&per_page=100')
            check("origin was taken, and every remote is listed without userinfo",
                  (plan["upstream"]["derived_from"],
                   "hunter2" in json.dumps(plan) or "someone" in json.dumps(plan),
                   "hunter2" in out),
                  ("remote origin", False, False))
            check("the printout lists the request, the nothing-else sentence and "
                  "the digest",
                  (plan["requests"][0]["url"] in out, "Nothing else is sent" in out,
                   "digest: %s" % plan["digest"] in out), (True, True, True))
            hint = plan["local_hints"]["per_candidate"][0]
            check("local history: the later commit on the file, naming the function",
                  (hint["later_commits"], [c["subject"] for c in hint["commits"]]),
                  (1, ["minizip: bound the length in zipRemoveExtraInfoBlock"]))

            # -- the person gate: nothing is sent without a person ----------- #
            stdin_is_terminal = lambda: False                    # noqa: E731
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            check("with no terminal, query refuses (exit 4), sends nothing and writes "
                  "no matches.json",
                  (code, seen, matches_of(root)), (EXIT_PERSON, [], None))
            check("and it hands the person the command, with this script's absolute path",
                  ("handoff" in out, "query --root" in out,
                   "--plan-digest %s" % plan["digest"] in out,
                   os.path.abspath(__file__) in out), (True, True, True, True))
            stdin_is_terminal = lambda: True                     # noqa: E731
            _CONFIRM = lambda plan_, root_: None                 # noqa: E731
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            check("at a terminal where the word is not typed, it cancels: exit 4, nothing sent",
                  (code, seen, "cancelled" in out), (EXIT_PERSON, [], True))
            _CONFIRM = lambda plan_, root_: {                    # noqa: E731
                "evidence": "tty", "confirmed_at": "2026-10-15T00:00:00Z",
                "plan_digest": plan_["digest"], "requests": len(plan_["requests"])}

            # -- query: a match, built refs, no Authorization, only the plan - #
            issue = {"number": 1265, "state": "open",
                     "title": "Heap overflow in zipRemoveExtraInfoBlock\x1b[2J",
                     "body": "see contrib/minizip/zip.c", "created_at":
                     "2025-11-02T10:00:00Z", "updated_at": "2026-06-08T09:00:00Z",
                     "html_url": "https://evil.example/phish", "pull_request": None}
            behaviour["github"] = lambda path: {"status": 200, "json": {
                "total_count": 1 if "zipRemove" in path else 0,
                "incomplete_results": False,
                "items": [issue] if "zipRemove" in path else []}}
            before = _listing(tmp)
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            after = _listing(tmp)
            matches = matches_of(root)
            check("query exits 0 and writes matches.json",
                  (code, isinstance(matches, dict)), (0, True))
            check("matches.json records who confirmed it, and for which digest",
                  ((matches.get("approval") or {}).get("evidence"),
                   (matches.get("approval") or {}).get("plan_digest")),
                  ("tty", plan["digest"]))
            check("exactly the planned requests were made",
                  [s["method"] + " " + url + s["path"] for s in seen],
                  ["GET " + r["url"] for r in plan["requests"]])
            check("no Authorization header, and the User-Agent is set",
                  [("authorization" in s["headers"], s["headers"].get("user-agent"))
                   for s in seen], [(False, USER_AGENT)] * 2)
            first = matches["candidates"]["CAND-0001"]["hints"]
            check("the ref is built from OWNER/REPO#N, never the response's URL",
                  [h["ref"] for h in first if h["source"] == "github"],
                  ["madler/zlib#1265"])
            check("the title is escaped and no body is stored",
                  (first[0]["title"], "body" in first[0],
                   "contrib/minizip/zip.c" in json.dumps(first)),
                  ("Heap overflow in zipRemoveExtraInfoBlock\\x1b[2J", False, False))
            check("matched on the title and on the file path in the body",
                  first[0]["matched_on"], ["function name in title", "file path in body"])
            check("the local commit is a hint too",
                  [h["kind"] for h in first], ["issue", "commit"])
            # The whole temporary tree, the repository's .git included: the
            # query's only write is matches.json, and plan.json is left as the
            # operator saw it.
            check("nothing is written outside upstream/, and only matches.json in it",
                  sorted(set(after) ^ set(before)) + sorted(
                      k for k in set(before) & set(after) if before[k] != after[k]),
                  [os.path.join("repo", RUN_DIR, UPSTREAM_DIR, MATCHES_FILE)])
            code, out = run(["show", "--root", root])
            check("show prints the hint line with the ref, state and match",
                  ('CAND-0001  Upstream:   possible match (hint) - issue '
                   'madler/zlib#1265 open, updated 2026-06-08, "Heap overflow in '
                   'zipRemoveExtraInfoBlock\\\\x1b[2J"; matched on: function name in '
                   'title, file path in body' in out, NOT_A_VERDICT in out),
                  (True, True))
            check("and one with none says what was fetched, not 'no match'",
                  "CAND-0004  Upstream:   none found in 0 results fetched %s (complete)"
                  % matches["queried_at"][:10] in out, True)

            # -- refusals ---------------------------------------------------- #
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", "0" * 16])
            check("a digest mismatch is refused, and nothing is sent",
                  (code, "digest mismatch" in out, len(seen)), (1, True, 0))
            code, out = run(["query", "--root", root, "--plan-digest", "DIGEST"])
            check("the placeholder itself is a usage error", code, 2)
            run_json = os.path.join(root, RUN_DIR, "run.json")
            doc = read_json(run_json)
            doc["run_id"] = "2026-09-26T00-00-00Z"
            with open(run_json, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            check("a run_id change is refused, and nothing is sent",
                  (code, "run changed" in out, len(seen)), (1, True, 0))
            code, out = run(["show", "--root", root])
            check("show will not attach another run's hints",
                  ("not this run" in out, "possible match" in out), (True, False))
            doc["run_id"] = "2026-09-25T00-00-00Z"
            with open(run_json, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)

            # -- show drops an entry whose candidate changed ------------------ #
            cands = os.path.join(root, RUN_DIR, "candidates", "memory-safety.json")
            rows = read_json(cands)
            rows[0]["content_hash"] = "ffffffffffffffff"
            with open(cands, "w", encoding="utf-8") as fh:
                json.dump(rows, fh)
            code, out = run(["show", "--root", root, "--candidate", "CAND-0001"])
            check("show drops a stale entry and says so",
                  ("Upstream:   not checked" in out, "dropped 1 stale entry" in out,
                   "1265" in out), (True, True, False))
            rows[0]["content_hash"] = "%016x" % 1
            with open(cands, "w", encoding="utf-8") as fh:
                json.dump(rows, fh)

            # -- 429 is partial, and stops the source ------------------------- #
            behaviour["github"] = {"status": 429, "json": {"message": "slow down"},
                                   "headers": {"X-RateLimit-Remaining": "0",
                                               "Retry-After": "60"}}
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            matches = matches_of(root)
            github = [s for s in matches["sources"] if s["source"] == "github"][0]
            check("429 gives exit 3, rate_limited, complete false, after 1 request",
                  (code, github["status"], github["complete"], len(seen),
                   matches["candidates"]["CAND-0004"]["coverage"]),
                  (3, "rate_limited", False, 1, "partial"))
            code, out = run(["show", "--root", root, "--candidate", "CAND-0004"])
            check("show says partial: rate-limited after X of Y requests",
                  "Upstream:   partial: rate-limited after 0 of 2 requests\n" in out,
                  True)

            # -- a redirect is refused, never followed ------------------------ #
            behaviour["github"] = {"status": 302, "headers": {
                "Location": url + "/gh/elsewhere"}}
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            check("a redirect is refused: no request goes to the Location",
                  (code, [s["path"] for s in seen if "elsewhere" in s["path"]],
                   matches_of(root)["sources"][0]["status"]), (3, [], "partial"))

            # -- 404 is not_found, never 'no match' --------------------------- #
            behaviour["github"] = {"status": 404, "json": {"message": "Not Found"}}
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            github = matches_of(root)["sources"][0]
            check("404 gives not_found, one request, and says not public",
                  (code, github["status"], len(seen), "not public" in github["detail"]),
                  (3, "not_found", 1, True))
            code, out = run(["show", "--root", root])
            check("and show never reads it as none found",
                  ("none found" in out, "not public" in out), (False, True))

            # -- a 422 after a search came back is that query's, not the repo's #
            behaviour["github"] = lambda path: (
                {"status": 200, "json": {"total_count": 0, "items": []}}
                if "zipRemove" in path else {"status": 422, "json": {}})
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", plan["digest"]])
            matches = matches_of(root)
            check("a later 422 is a failed request: partial, the rest still asked",
                  (code, matches["sources"][0]["status"], len(seen),
                   matches["sources"][0]["detail"],
                   matches["candidates"]["CAND-0001"]["coverage"],
                   matches["candidates"]["CAND-0004"]["coverage_detail"]),
                  (3, "partial", 2, "a request failed: HTTP 422", "complete",
                   "a request failed: HTTP 422"))

            # -- OSV, opt-in, matched locally -------------------------------- #
            behaviour["github"] = {"status": 200, "json": {"total_count": 0,
                                                           "items": []}}
            behaviour["osv"] = {"status": 200, "json": {"vulns": [
                {"id": "OSV-2026-1", "summary": "zlib: overflow in inflate_fast",
                 "details": "gz_look is fine", "published": "2026-01-01T00:00:00Z",
                 "modified": "2026-02-01T00:00:00Z"},
                {"id": "GHSA-xxxx", "summary": "unrelated",
                 "details": "contrib/minizip/zip.c: zipRemoveExtraInfoBlock overflow"},
                {"id": "../../evil", "summary": "zipRemoveExtraInfoBlock"}]}}
            code, out = run(["plan", "--root", root, "--source", "github",
                             "--source", "osv"])
            plan2 = plan_of(root)
            check("osv is one POST of the scanned commit, labelled third-party",
                  ([(r["method"], r["body"]) for r in plan2["requests"]
                    if r["source"] == "osv"],
                   [d["party"] for d in plan2["destinations"]]),
                  ([("POST", {"commit": scanned})], ["code-host", "third-party"]))
            check("the commit id the entropy test flags is sent as excused, and "
                  "the plan says so",
                  ([(e["term"], e["request"], e["detector"])
                    for e in plan2["excused_terms"]], plan2["withheld_terms"],
                   "sent although the outbound secret detector flags it (entropy): "
                   "the scanned commit in R03's body" in out),
                  ([("scanned commit", "R03", ["entropy"])], [], True))
            del seen[:]
            code, out = run(["query", "--root", root, "--plan-digest", plan2["digest"]])
            osv = [h for h in matches_of(root)["candidates"]["CAND-0001"]["hints"]
                   if h["source"] == "osv"]
            check("an OSV advisory naming the function or the file is a hint, and "
                  "an id that is not one is dropped",
                  (code, [(h["ref"], h["matched_on"]) for h in osv]),
                  (0, [("GHSA-xxxx", ["function name in details",
                                      "file path in details"])]))
            check("the body sent is the plan's body",
                  [json.loads(s["body"]) for s in seen if s["method"] == "POST"],
                  [{"commit": scanned}])

            # -- a secret-like term is withheld, and not named ---------------- #
            secret = os.path.join(tmp, "secret")
            os.makedirs(secret)
            _git(secret, "init", "-q")
            _git(secret, "remote", "add", "origin", "git@github.com:o/r.git")
            _fixture(secret, functions=["AKIAIOSFODNN7EXAMPLE", "b", "c", "d"])
            code, out = run(["plan", "--root", secret])
            planned = plan_of(secret)
            check("a secret-like function name is withheld: recorded, never written",
                  ([w["for_candidates"] for w in planned["withheld_terms"]],
                   "AKIAIOSFODNN7EXAMPLE" in json.dumps(planned["requests"]),
                   "AKIAIOSFODNN7EXAMPLE" in json.dumps(planned["withheld_terms"]),
                   "AKIAIOSFODNN7EXAMPLE" in out),
                  ([["CAND-0001"]], False, False, False))
            check("the other name is still asked for",
                  [r["for_candidates"] for r in planned["requests"]], [["CAND-0004"]])
            check("history git cannot read against the scanned commit is said so, "
                  "never 'no later commit'",
                  ("git could not read the history of 2 file(s)" in out,
                   "no commit on a local ref" in out), (True, False))

            # -- a host v1 does not query plans nothing ---------------------- #
            other = os.path.join(tmp, "other")
            os.makedirs(other)
            _git(other, "init", "-q")
            _git(other, "remote", "add", "origin", "https://gitlab.com/o/r.git")
            _fixture(other)
            code, out = run(["plan", "--root", other, "--source", "osv"])
            check("a non-GitHub remote plans zero requests, exits 1, and says why",
                  (code, plan_of(other)["requests"], "queries github.com only" in out),
                  (1, [], True))
            code, out = run(["plan", "--root", other, "--upstream", "github:o/r",
                             "--max-requests", "1"])
            check("--upstream overrides it, and the cap says what it left out",
                  (code, len(plan_of(other)["requests"]),
                   "left out by --max-requests 1" in out), (0, 1, True))
            deep = os.path.join(tmp, "deep")
            os.makedirs(deep)
            _git(deep, "init", "-q")
            _git(deep, "remote", "add", "origin", "https://github.com/o/r/extra")
            _fixture(deep)
            code, out = run(["plan", "--root", deep])
            check("a github.com remote with no OWNER/REPO is no upstream: exit 2",
                  (code, plan_of(deep)["requests"],
                   "Not planned: the remote origin does not name an OWNER/REPO" in out),
                  (2, [], True))
            _git(other, "remote", "add", "upstream", "https://github.com/up/proj.git")
            run(["plan", "--root", other])
            check("a remote named upstream is preferred over origin",
                  plan_of(other)["upstream"]["derived_from"], "remote upstream")

            # -- every git call carries the operator's safe.directory -------- #
            # run_git drops the system gitconfig, so a CI image's safe.directory
            # reaches git only as the `-c` items git_trusted_config() returns;
            # the gate passes them, and a call here without them fails on a
            # checkout another user owns.
            trusted = ["safe.directory=" + os.path.join(tmp, "selftest-trusted")]
            calls = []
            real_run_git, real_trusted = rules_lib.run_git, rules_lib.git_trusted_config

            def recording(root_, args_, **kwargs):
                calls.append((args_[0], list(kwargs.get("config") or ())))
                return real_run_git(root_, args_, **kwargs)
            rules_lib.run_git = recording
            rules_lib.git_trusted_config = lambda: list(trusted)
            try:
                run(["plan", "--root", root])
            finally:
                rules_lib.run_git, rules_lib.git_trusted_config = \
                    real_run_git, real_trusted
            check("every git call plan makes carries git_trusted_config()",
                  ({c[0] for c in calls} >= {"config", "rev-parse", "rev-list", "log"},
                   [c for c in calls if c[1] != trusted]), (True, []))

            # -- a shallow clone is not 'no match' --------------------------- #
            shallow = os.path.join(tmp, "shallow")
            _git(tmp, "clone", "-q", "--depth", "1", "file://" + root, shallow)
            head = _git(shallow, "rev-parse", "HEAD").stdout.strip()
            _fixture(shallow, commit=head)
            code, out = run(["plan", "--root", shallow])
            check("a shallow clone is reported as such, never as no match",
                  ("local history has 1 commits; nothing to compare" in out,
                   plan_of(shallow)["local_hints"]["shallow"]), (True, True))

            # -- links refuse the write -------------------------------------- #
            if rules_lib.can_symlink():
                outside = os.path.join(tmp, "outside")
                os.makedirs(outside)
                shutil.rmtree(os.path.join(other, RUN_DIR, UPSTREAM_DIR))
                os.symlink(outside, os.path.join(other, RUN_DIR, UPSTREAM_DIR))
                code, out = run(["plan", "--root", other, "--upstream", "github:o/r"])
                check("a link at upstream/ refuses the plan and writes nothing through it",
                      (code, os.listdir(outside)), (1, []))
            else:
                rules_lib.skip_case("a link at upstream/ refuses the plan")
    finally:
        GITHUB_API, OSV_API, SEARCH_SPACING = saved
        _CONFIRM, stdin_is_terminal = saved_gate
        stop()

    print("selftest: %d failure(s)%s" % (failures, rules_lib.skipped_note()))
    return 1 if failures else 0


# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Optional stage-5 check for upstream reports of the adjudicated "
                    "findings. `plan` and `show` are offline; `query` sends exactly "
                    "what `plan` printed, and only when its digest matches.")
    p.add_argument("--selftest", action="store_true")
    sub = p.add_subparsers(dest="command")

    plan = sub.add_parser("plan", help="work out and print the exact requests "
                                       "(offline), and write upstream/plan.json")
    plan.add_argument("--root", default=".",
                      help="scanned repository root, holding .security-review/")
    plan.add_argument("--upstream", default=None, metavar="github:OWNER/REPO",
                      help="the repository to ask, overriding the remotes")
    plan.add_argument("--remote", default=None, metavar="NAME",
                      help="the remote to take OWNER/REPO from (default: upstream, "
                           "then origin)")
    plan.add_argument("--source", action="append", choices=SOURCES,
                      help="where to look; repeat for more (default: github). osv is "
                           "a third party and is never asked unless named")
    plan.add_argument("--include-dismissed", action="store_true",
                      help="also check NOT_VULNERABLE findings")
    plan.add_argument("--max-requests", type=int, default=DEFAULT_MAX_REQUESTS,
                      help="cap on requests (default %d, at most %d)"
                           % (DEFAULT_MAX_REQUESTS, MAX_REQUESTS_CEILING))

    query = sub.add_parser("query", help="send the planned requests (network) and "
                                         "write upstream/matches.json")
    query.add_argument("--root", default=".",
                       help="scanned repository root, holding .security-review/")
    # A string, checked in cmd_query: tests/test_role_commands.py parses the role files'
    # `--plan-digest DIGEST` with this parser, and a hex type= would reject it.
    query.add_argument("--plan-digest", required=True, type=str, metavar="DIGEST",
                       help="the digest `plan` printed")

    show = sub.add_parser("show", help="one Upstream: line per finding (offline)")
    show.add_argument("--root", default=".",
                      help="scanned repository root, holding .security-review/")
    show.add_argument("--candidate", default=None, metavar="CAND-0001",
                      help="one candidate, with every hint it has")
    show.add_argument("--json", action="store_true")
    return p


def dispatch(args):
    handler = {"plan": cmd_plan, "query": cmd_query, "show": cmd_show}[args.command]
    try:
        return handler(args)
    except Refused as exc:
        print("REFUSED: %s" % exc, file=sys.stderr)
        return exc.code


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.command:
        parser.print_usage(sys.stderr)
        return EXIT_USAGE
    # Before anything under the run directory is read: the scanned repository
    # never answers for the run (rules_lib.run_dir_gate).
    shipped, _gate = rules_lib.enforce_run_dir_gate(os.path.abspath(args.root))
    if shipped:
        return shipped
    target = {"plan": PLAN_FILE, "query": MATCHES_FILE}.get(args.command)
    if target:
        # Checked before anything is read or sent, so a refused path refuses
        # the command rather than the last step of it.
        unsafe = run_dir_write_problem(args.root, upstream_path(args.root, target))
        if unsafe:
            print("REFUSED: %s" % unsafe, file=sys.stderr)
            return EXIT_REFUSED
    return dispatch(args)


if __name__ == "__main__":
    sys.exit(main())
