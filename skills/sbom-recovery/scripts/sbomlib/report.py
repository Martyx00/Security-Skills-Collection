"""Texts of the run: the gate message, the adjudication message, ``report.md``, ``validation-report.txt``, ``summary`` and
``explain`` (contract sections 3.14, 4.27, 5.3).

Everything here is derived from files the pipeline wrote; nothing is judged. Every text states the approval evidence level
and what a plain skill install does not enforce (``references/limitations.md``).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from sbomlib import delta, errors, fsio, model, runfiles, state
from sbomlib.context import RunContext
from sbomlib.state import RunState

LIMITATIONS_REL = "references/limitations.md"
MAX_LIST = 20
MAX_OPT_IN = 10
DISCLOSURE = "Approval authorizes sending the names and versions of rows with include=yes and action=lookup to the NVD API."
# What the person is told at the start of a run, as sentences the script prints last (`start`, `pilot`): a model repeats words it
# was just handed more reliably than words it has to remember from SKILL.md. Nothing makes it say them (limitations.md).
START_SAY = (
    "The repositories are only read; nothing in them is modified.",
    "The only step that needs you is one CSV review file, at the approval gate.",
    "The NVD sees names and versions only after you approve, and only for the rows you include.",
)
INCLUSION_RULE = "include=no excludes a row everywhere; include=yes with include_in limits it to the listed repositories."


# --------------------------------------------------------------------------------------------------- small helpers

def _quote(path: Any) -> str:
    text = str(path)
    return '"%s"' % text if " " in text else text


def limitations_path(ctx: RunContext) -> str:
    """Absolute path of this skill's ``references/limitations.md``: a bare ``references/...`` resolves to nothing from the
    workspace or from a saved report, and a project with two hosts holds two copies of the skill."""
    return ctx.layout.skill_path(LIMITATIONS_REL)


def limitations_note(ctx: RunContext) -> str:
    return "Not enforced on a plain skill install: see %s" % limitations_path(ctx)


def enforcement_note(ctx: RunContext) -> str:
    return model.ENFORCEMENT_NOTE.replace(LIMITATIONS_REL, limitations_path(ctx))


def say_block(heading: str, lines: Sequence[str]) -> str:
    """A ready-to-relay block for the model to repeat to the person, printed as the last thing a command prints. The header and
    the footer are the wording every skill of the portfolio uses."""
    return "\n==== SAY THIS TO THE PERSON %s, as written ====\n%s\n==== END OF WHAT TO SAY ====" % (
        heading, "\n".join("- " + line for line in lines))


def say_text(heading: str, text: str) -> str:
    """The same block around a text that is to be posted whole, line breaks and all (the approval gate)."""
    return "\n==== SAY THIS TO THE PERSON %s, as written ====\n%s\n==== END OF WHAT TO SAY ====" % (heading, text)


# Where the model says which dispatch mode it runs and why. It is printed once, by the command that starts the first worker unit
# (`dispatch-prompt` for subagents, `inline-unit` for inline), where it is read; whether it is said cannot be enforced
# (references/limitations.md).
MODE_SUBAGENT = ("Mode: subagents, because this host has a subagent tool (%s). The worker role reads each repository in a fresh "
                 "context of its own." % "name the tool you start the workers with")
MODE_INLINE = ("Mode: inline, because this host has no subagent tool (%s). The worker role is then your own second reading in "
               "your own context, which is weaker evidence, and the summary says so." % "name the missing tool, or the failed "
               "spawn")


def mode_said_block(run: RunState, mode: str) -> str:
    """The block that carries the mode line, or an empty string when a worker unit has been recorded already (it was said)."""
    if any(str(key).startswith("worker:") for key in (run.data.get("dispatch") or {})):
        return ""
    line = MODE_SUBAGENT if mode == "subagent" else MODE_INLINE
    return say_block("NOW, once, in the message that starts the worker units; do not wait for an answer", [line])


def human_approve_command(ctx: RunContext) -> str:
    return "%s %s" % (ctx.python_prefix, _quote(ctx.layout.scripts / "human_approve.py"))


def _load_queue(ctx: RunContext) -> Dict[str, Any]:
    try:
        return state.load_queue(ctx)
    except errors.StateError:
        return state.empty_queue(ctx.run_id)


def _components(ctx: RunContext, repo: str) -> Optional[Dict[str, Any]]:
    try:
        doc = fsio.read_json(ctx.layout.repo_out(repo) / "components.json")
    except (errors.StateError, OSError):
        return None
    return doc if isinstance(doc, dict) else None


def _warnings_sorted(run: RunState) -> List[Dict[str, Any]]:
    items = [w for w in run.data.get("warnings") or [] if isinstance(w, dict)]
    return sorted(items, key=lambda w: (0 if w.get("tier") == "ACTION_REQUIRED" else 1, str(w.get("code")), str(w.get("repo"))))


def _warning_line(w: Dict[str, Any]) -> str:
    tier = "ACTION REQUIRED" if w.get("tier") == "ACTION_REQUIRED" else "INFORMATIONAL"
    return "%s [%s]%s %s" % (tier, w.get("code"), (" (%s)" % w["repo"]) if w.get("repo") else "", w.get("message"))


def _reply_notes(run: RunState) -> List[str]:
    """What the reply reader tolerated in a role's reply (a code fence that was never closed, or lines of text outside the one
    block of the object), as the lines ``summary`` and ``report.md`` print: a reply accepted with a caveat is said so, never
    accepted quietly."""
    return [str(w.get("message")) for w in _warnings_sorted(run) if w.get("code") == "REPLY_NOTE"]


def _repo_status_line(run: RunState) -> str:
    names = run.all_repos()
    return ", ".join("%s %s" % (n, run.repo(n).get("status")) for n in names) if names else "none"


def mode_line(run: RunState) -> Optional[str]:
    """``PILOT RUN limited to: a, b`` for a pilot run, None for a full run."""
    if run.data.get("mode") == "pilot":
        return "PILOT RUN limited to: %s. Its results are in a folder of their own and are never the baseline of a full run." % (
            ", ".join(run.data.get("pilot_repos") or []) or "(none)")
    return None


def baseline_line(run: RunState) -> str:
    """What the run was compared with, as a sentence fragment (the caller puts "Baseline:" in front)."""
    info = run.data.get("baseline") or {}
    if not info.get("present"):
        return "none; this is the first finished run of this folder, so there is nothing to compare with"
    return "run %s (finished %s); an incremental run compares every repository with it" % (
        info.get("run_id") or "?", info.get("closed_at") or "?")


def worker_sentence(run: RunState) -> str:
    """How many repositories went through the worker role, and how each unit ran."""
    summaries = {n: run.repo(n).get("worker") for n in run.all_repos() if run.repo(n).get("worker")}
    if not summaries:
        return "the worker role has not run yet"
    parts: List[str] = []
    for status in ("DONE", "FAILED", "INVALID"):
        names = sorted(n for n, w in summaries.items() if w.get("status") == status and w.get("source") != "carried")
        if names:
            parts.append("%d %s" % (len(names), status.lower() if status == "DONE" else "without a usable analysis"))
    carried = sorted(n for n, w in summaries.items() if w.get("source") == "carried")
    if carried:
        parts.append("%d carried over from the baseline (same commit, claims re-checked)" % len(carried))
    return "worker role: " + ", ".join(parts)


def _commit_text(run: RunState, repo: str) -> str:
    head = run.repo(repo).get("head")
    return str(head)[:12] if head else "no commit"


def _latest_approval(run: RunState) -> Optional[Dict[str, Any]]:
    approvals = run.data.get("approvals") or []
    return approvals[-1] if approvals else None


def evidence_sentence(evidence: Optional[str]) -> str:
    if evidence == "tty":
        return "tty (a person typed APPROVE at a terminal through human_approve.py; the strong form)"
    if evidence == "agent-relayed":
        return ("agent-relayed (the agent ran approve after a reply in the conversation; this skill has no hook, so the "
                "script cannot tell who wrote the reply)")
    return "none (the review file was not approved)"


# --------------------------------------------------------------------------------------------------- messages

def _opt_in_lines(ctx: RunContext) -> List[str]:
    """The review rows that are pre-set ``include=no``: the SBOM leaves them out unless the person sets ``include=yes``."""
    try:
        rows = state_names_rows(ctx)
    except errors.SbomError:
        return []
    left_out = [r for r in rows if r.get("include") != "yes"]
    if not left_out:
        return []
    shown = []
    for row in left_out[:MAX_OPT_IN]:
        codes = sorted(set((row.get("reason") or {}).values()))
        shown.append("%s %s%s" % (row.get("name"), row.get("version"), (" (%s)" % ", ".join(codes)) if codes else ""))
    more = "; ... and %d more in the file" % (len(left_out) - MAX_OPT_IN) if len(left_out) > MAX_OPT_IN else ""
    return ["Pre-set include=no, so the SBOM leaves these out unless you set include=yes (%d): %s%s" % (
        len(left_out), "; ".join(shown), more)]


def gate_message(ctx: RunContext, run: RunState) -> str:
    """The exact text posted at ``stop_for_approval`` (contract section 5.3)."""
    review = run.data.get("review") or {}
    approvals = run.data.get("approvals") or []
    queue = _load_queue(ctx)
    lines = ["SBOM recovery is paused for your approval.", ""]
    if mode_line(run):
        lines.extend([mode_line(run) or "", ""])
    info = run.data.get("baseline") or {}
    if info.get("present"):
        lines.extend(["Baseline: run %s (finished %s). What changed since then is in report.md and in each repository's "
                      "delta.csv." % (info.get("run_id") or "?", info.get("closed_at") or "?"), ""])
    else:
        lines.extend(["Baseline: %s." % baseline_line(run), ""])
    path = review.get("path") or ctx.layout.shown("review/cpe-lookup-names.csv")
    lines.append("Review file: %s (%s rows; %s pre-set include=yes)" % (path, review.get("rows", "?"), review.get("rows_included", "?")))
    lines.extend(_opt_in_lines(ctx))
    lines.append("Editable columns: %s" % ", ".join(model.EDITABLE_COLUMNS))
    lines.append(INCLUSION_RULE)
    lines.append(DISCLOSURE)
    lines.append("Repositories: %s" % _repo_status_line(run))
    lines.append("%s." % worker_sentence(run).capitalize())
    warnings = list(queue.get("checkout_warnings") or [])
    if warnings:
        lines.append("")
        lines.append("CHECKOUT WARNINGS (%d):" % len(warnings))
        for item in warnings[:MAX_LIST]:
            lines.append("- %s%s: %s" % (item.get("code"), (" (%s)" % item["repo"]) if item.get("repo") else "", item.get("message")))
        if len(warnings) > MAX_LIST:
            lines.append("- ... and %d more" % (len(warnings) - MAX_LIST))
    folder = [w for w in run.data.get("warnings") or [] if isinstance(w, dict) and w.get("code") in ("RUN_FOLDER_CHANGED", "RUN_FOLDER_EXTRA_FILE")]
    if folder:
        lines.append("")
        lines.append("RUN FOLDER (%d): something other than the script wrote or changed files in %s/:" % (len(folder), ctx.layout.out_name))
        lines.extend("- %s" % w.get("message") for w in folder[:MAX_LIST])
        if len(folder) > MAX_LIST:
            lines.append("- ... and %d more" % (len(folder) - MAX_LIST))
    ignored = list(queue.get("ignored") or [])
    if ignored:
        lines.append("")
        lines.append("IGNORED: %d item(s) (agent files, host folders and SBOM documents are data and are not analysed)." % len(ignored))
    if approvals and approvals[-1].get("stale"):
        lines.append("")
        lines.append("The review file changed after approval; approve again.")
    refusal = review.get("last_refusal")
    if isinstance(refusal, dict) and refusal.get("message"):
        lines.append("")
        lines.append(str(refusal["message"]))
    lines.append("")
    lines.append("To approve: edit and save the file (or leave it unchanged), then reply \"approved\" in this conversation. "
                 "The agent then runs approve; that approval is recorded as agent-relayed.")
    lines.append("Strong alternative: run `%s` in a terminal from %s, type APPROVE, then type \"continue\" here; that approval "
                 "is recorded as tty." % (human_approve_command(ctx), ctx.layout.parent))
    return "\n".join(lines)


def adjudicate_message(ctx: RunContext, block: Dict[str, Any]) -> str:
    """What the agent must do for an ``adjudicate`` block."""
    kind = block.get("kind")
    if kind == "worker":
        return _worker_message(ctx, block)
    where = "repository %s" % block["repo"] if block.get("repo") else "the review rows"
    lines = ["Adjudication needed: %s for %s (attempt %s, %s item(s))." % (kind, where, block.get("attempt", 1), block.get("items"))]
    lines.append("Read only %s and the rubric %s." % (block.get("input"), block.get("rubric")))
    if kind == "trace_build":
        files = block.get("build_files") or []
        lines.append("Also read, read-only, the build files listed in the input (inside %s): %s." % (
            block.get("repo"), ", ".join(files[:10]) if files else "none"))
    lines.append("Write only %s, as JSON, with your file-writing tool (never a shell command)." % block.get("output"))
    lines.append("Choose only among the options the input offers, cite only evidence ids from the item, answer INCONCLUSIVE "
                 "when the evidence does not settle it, and never type a CPE.")
    messages = [str(m) for m in block.get("messages") or []]
    if messages:
        lines.append("This is attempt 2. Fix exactly these problems and write the whole file again:")
        lines.extend("- %s" % m for m in messages[:MAX_LIST])
    lines.append("Then run next.")
    return "\n".join(lines)


def _worker_message(ctx: RunContext, block: Dict[str, Any]) -> str:
    unit = block.get("unit") or "worker:%s" % block.get("repo")
    messages = [str(m) for m in block.get("messages") or []]
    hold = block.get("hold")
    if isinstance(hold, dict) and hold.get("text"):
        # the reply was not rejected; the script only lacks a record. No dispatch instruction here: it would send the agent
        # to start the work again
        lines = ["Worker unit %s is ON HOLD (%s, attempt %s)." % (unit, hold.get("code"), block.get("attempt", 1)), hold["text"]]
        if messages:
            lines.append("This is attempt 2. The reply had these problems; the role fixes exactly these and writes the whole file again:")
            lines.extend("- %s" % m for m in messages[:MAX_LIST])
        return "\n".join(lines)
    lines = ["Worker analysis needed: repository %s (unit %s, attempt %s, %s lead(s) from the script)." % (
        block.get("repo"), unit, block.get("attempt", 1), block.get("items"))]
    lines.append("This unit is for the worker role, not for you to answer from your own reading of the repository. With a host "
                 "that has a subagent tool: run dispatch-prompt --stage worker (or dispatch-prompt %s), give each printed block, "
                 "whole and unchanged, to one subagent, wait, then run dispatch-record <unit> subagent for each unit. With "
                 "no subagent tool, or after a failed spawn: run inline-unit %s, read the brief file it names in full with your "
                 "file-reading tool, and follow it, one repository at a time." % (unit, unit))
    lines.append("The role reads %s and writes only %s." % (block.get("input"), block.get("output")))
    if messages:
        lines.append("This is attempt 2. The reply had these problems; the role fixes exactly these and writes the whole file again:")
        lines.extend("- %s" % m for m in messages[:MAX_LIST])
    lines.append("Then run next.")
    return "\n".join(lines)


def progress_message(ctx: RunContext, run: RunState) -> str:
    from sbomlib import driver
    units = driver.plan(ctx, run)
    done = sum(1 for u in units if run.unit_state(u) == "done")
    return "%s: %d of %d steps done. Run next again." % (run.phase, done, len(units))


# --------------------------------------------------------------------------------------------------- report.md

def _nvd_query_count(ctx: RunContext) -> int:
    try:
        events = fsio.read_jsonl(ctx.layout.state / "audit.jsonl")
    except (errors.StateError, OSError):
        return 0
    return sum(1 for e in events if isinstance(e, dict) and e.get("event") == "nvd_query")


def _cisa_rows(comps: List[Dict[str, Any]]) -> List[Tuple[str, str]]:
    total = len(comps)

    def count(predicate: Any) -> int:
        return sum(1 for c in comps if predicate(c))

    def cov(n: int) -> str:
        return "%d of %d components" % (n, total)

    return [
        ("Supplier", cov(count(lambda c: c.get("supplier") not in (None, "", "NOASSERTION")))),
        ("Component name", cov(count(lambda c: bool(c.get("name"))))),
        ("Component version", cov(count(lambda c: c.get("version") not in (None, "", "NOASSERTION")))),
        ("Other unique identifiers (CPE or purl)", cov(count(lambda c: bool(c.get("cpes")) or bool(c.get("purls"))))),
        ("Dependency relationships", cov(count(lambda c: bool(c.get("relationships"))))),
        ("SBOM author", "every document names the tool as creator"),
        ("Timestamp", "every document carries a creation time"),
        ("Component hash", cov(count(lambda c: bool(c.get("sha256"))))),
        ("License", cov(count(lambda c: c.get("license_declared") not in (None, "", "NOASSERTION")))),
        ("Tool name", "every document names the tool as creator"),
        ("Generation context", "every document states 'SBOM Generation Context: Source'"),
    ]


def _queue_entry(queue: Dict[str, Any], repo: str) -> Dict[str, Any]:
    for entry in queue.get("repos") or []:
        if entry.get("name") == repo:
            return entry
    return {}


def _submodule_lines(queue: Dict[str, Any], docs: Dict[str, Optional[Dict[str, Any]]], run: RunState) -> List[str]:
    """One line per submodule of every repository: its state, the pinned commit, and what became of it. A submodule that is
    not checked out is an exclusion from the analysis, and it is reported as such (never silently dropped)."""
    lines: List[str] = []
    for repo in run.all_repos():
        entry = _queue_entry(queue, repo)
        accounted = {g.get("path"): g.get("accounted_by") for g in ((docs.get(repo) or {}).get("gitlinks") or [])}
        for sub in entry.get("submodules") or []:
            state_name = sub.get("state")
            pinned = str(sub.get("pinned") or "")[:12]
            path = sub.get("path")
            if state_name == "uninitialized":
                fate = "NOT CHECKED OUT: excluded from the analysis; its contents are unanalysed (pinned %s)" % pinned
                if accounted.get(path):
                    fate += "; accounted for as %s" % accounted[path]
            elif state_name == "different_commit":
                fate = "analysed as checked out (%s), but the repository pins %s" % (str(sub.get("checked_out") or "")[:12], pinned)
            elif state_name == "conflict":
                fate = "merge conflict in the index; analysed as it is on disk"
            else:
                fate = "analysed (commit %s)" % pinned
            lines.append("- %s: %s (%s): %s" % (repo, path, state_name, fate))
    return lines[:200]


def _delta_lines(ctx: RunContext, run: RunState) -> List[str]:
    lines: List[str] = []
    info = run.data.get("baseline") or {}
    if not info.get("present"):
        return ["- Baseline: %s" % baseline_line(run)]
    for repo in run.all_repos():
        doc = delta.read(ctx, repo)
        if doc is None:
            if run.repo(repo).get("status") in ("DONE", "INCOMPLETE"):
                lines.append("- %s: not in the baseline (first time it is analysed)" % repo)
            continue
        base = doc.get("baseline_commit")
        lines.append("- %s: baseline commit %s, now %s; %s file(s) changed (%s). %s" % (
            repo, str(base)[:12] if base else "unknown", str(doc.get("head"))[:12], doc.get("changed_files"),
            doc.get("changed_files_status"), delta.summary_line(doc)))
        for item in doc["entries"][:50]:
            was = " (was %s)" % item["baseline_version"] if item["change"] == "UPDATED" else ""
            lines.append("  - %s %s %s%s [%s]" % (item["change"], item["name"], item["version"], was, item["cause"]))
        if len(doc["entries"]) > 50:
            lines.append("  - ... and %d more in %s.delta.csv" % (len(doc["entries"]) - 50, repo))
    lines.append("- cause: code = a file the component lies in changed between the two commits; analysis = the component is "
                 "different but its files are not (a better rule, a worker claim, a corrected version); unverified = the "
                 "baseline commit is not in the local history")
    return lines


def write_report(ctx: RunContext, run: RunState, outcome: Dict[str, Any]) -> str:
    """``report.md`` of the output folder (contract section 4.27); written on PASS and FAIL. Returns the relative path."""
    from sbomlib import verify
    from sbomlib.emit import merge
    integrity_result = outcome.get("integrity") or {}
    pack_result = outcome.get("pack") or {}
    folder_result = outcome.get("run_folder") or {}
    validation = outcome.get("validation") or {}
    queue = _load_queue(ctx)
    repos = merge.contributing_repos(run)
    docs = {r: _components(ctx, r) for r in repos}
    lines: List[str] = ["# %sSBOM recovery report" % ("PILOT RUN: " if run.data.get("mode") == "pilot" else ""), ""]
    lines.append("Run %s, validation **%s**, integrity **%s**." % (run.run_id, validation.get("verdict"), integrity_result.get("verdict")))
    if mode_line(run):
        lines.append(mode_line(run) or "")
    lines.append("Baseline: %s." % baseline_line(run))
    lines.append("")

    lines.append("## Integrity result")
    lines.append("")
    windows = integrity_result.get("windows") or []
    if not windows:
        lines.append("- no comparison window")
    for window in windows:
        lines.append("- %s (%s): %s violation(s), %s host Source Control, %s changed while paused" % (
            window.get("window"), window.get("kind"), window.get("violations"), window.get("host_source_control"),
            window.get("paused")))
        for diff in (window.get("differences") or [])[:MAX_LIST]:
            lines.append("  - %s %s %s %s (%s)%s" % (diff.get("class"), diff.get("repo") or "(workspace)", diff.get("path"),
                                                   diff.get("change"), ", ".join(diff.get("fields") or []),
                                                   (" - " + diff["note"]) if diff.get("note") else ""))
    for change in integrity_result.get("head_changes") or []:
        lines.append("- HEAD changed (%s): %s %s -> %s" % (change.get("kind"), change.get("repo"), change.get("before"), change.get("after")))
    for problem in integrity_result.get("errors") or []:
        lines.append("- ERROR: %s" % problem)
    if not integrity_result.get("ctime_reliable", True):
        lines.append("- on this platform ctime is the creation time, so the unchanged-targets check detects fewer changes")
    pack_status = pack_result.get("status")
    lines.append("- the skill folder itself: %s%s" % (pack_status, ("; " + "; ".join(pack_result["errors"][:5])) if pack_result.get("errors") else ""))
    lines.append("- the run folder itself: %s; %d file(s) the script wrote were checked against the ledger of %s" % (
        folder_result.get("status", "not checked"), int(folder_result.get("checked") or 0), ctx.layout.shown(".state/runfiles.json")))
    for problem in (folder_result.get("errors") or [])[:MAX_LIST]:
        lines.append("  - %s" % problem)
    extra = [str(p) for p in folder_result.get("added") or []]
    if extra:
        lines.append("- %d file(s) in the run folder were not written by the script (not part of the SBOM; nothing was deleted):" % (
            int(folder_result.get("added_count") or len(extra))))
        lines.extend("  - %s" % ctx.layout.shown(p) for p in extra[:MAX_LIST])
        if len(extra) > MAX_LIST:
            lines.append("  - ... and %d more" % (len(extra) - MAX_LIST))
    lines.append("")

    lines.append("## Checkout warnings")
    lines.append("")
    warnings = queue.get("checkout_warnings") or []
    lines.extend("- %s%s: %s" % (w.get("code"), (" (%s)" % w["repo"]) if w.get("repo") else "", w.get("message")) for w in warnings)
    if not warnings:
        lines.append("- none")
    lines.append("")

    lines.append("## Known unknowns")
    lines.append("")
    unknowns: List[str] = []
    for repo in repos:
        try:
            spots = verify.blindspots(ctx, repo)
        except (errors.SbomError, OSError):
            spots = []
        for spot in spots:
            where = " at %s" % spot["loc"] if spot.get("loc") else ""
            unknowns.append("%s: %s%s: %s" % (repo, spot.get("code"), where, spot.get("message")))
        doc = docs.get(repo) or {}
        for item in doc.get("excluded") or []:
            if item.get("class") in ("INCONCLUSIVE", "UNANALYZED"):
                unknowns.append("%s: %s %s is %s (%s)" % (repo, item.get("name"), item.get("version"), item.get("class"), item.get("reason_code")))
        for comp in doc.get("components") or []:
            if comp.get("condition"):
                unknowns.append("%s: %s is conditional (%s)" % (repo, comp.get("name"), comp.get("condition")))
            if any(c.get("wildcard") for c in comp.get("cpes") or []):
                unknowns.append("%s: %s has a wildcard CPE version (no exact version known)" % (repo, comp.get("name")))
    nvd = run.data.get("nvd") or {}
    if nvd.get("source") == "offline" or nvd.get("status") == "offline":
        unknowns.append("NVD was unreachable: CPE names were constructed and not checked against the NVD dictionary")
    for repo in run.all_repos():
        entry = run.repo(repo)
        for reason in entry.get("incomplete") or []:
            unknowns.append("%s: %s" % (repo, reason))
    lines.extend("- %s" % u for u in unknowns[:200])
    if not unknowns:
        lines.append("- none recorded")
    if len(unknowns) > 200:
        lines.append("- ... and %d more" % (len(unknowns) - 200))
    lines.append("")

    lines.append("## Per-repository status")
    lines.append("")
    for repo in run.all_repos():
        entry = run.repo(repo)
        detail = "; ".join([str(entry["reason"])] if entry.get("reason") else [])
        extra = "; ".join(list(entry.get("incomplete") or []) + [str(e) for e in entry.get("emit_errors") or []][:3])
        branch = _queue_entry(queue, repo).get("branch")
        lines.append("- %s: %s%s%s - commit %s%s" % (repo, entry.get("status"), (" - " + detail) if detail else "",
                                                     (" (" + extra + ")") if extra else "", _commit_text(run, repo),
                                                     (", branch %s" % branch) if branch else ""))
        work = entry.get("worker")
        if work:
            lines.append("  - worker: %s%s, %d claim(s) accepted, %d rejected" % (
                work.get("status"), " (carried over from the baseline)" if work.get("source") == "carried" else "",
                work.get("components", 0), work.get("rejected", 0)))
    if not run.all_repos():
        lines.append("- none")
    lines.append("")
    reply_notes = _reply_notes(run)
    if reply_notes:
        lines.append("## Replies read with a caveat")
        lines.append("")
        lines.extend("- %s" % note for note in reply_notes)
        lines.append("")

    lines.append("## Submodules")
    lines.append("")
    sub_lines = _submodule_lines(queue, docs, run)
    lines.extend(sub_lines or ["- none"])
    lines.append("")

    lines.append("## Changes since the baseline")
    lines.append("")
    change_lines = _delta_lines(ctx, run)
    lines.extend(change_lines or ["- none"])
    lines.append("")

    lines.append("## CPE coverage")
    lines.append("")
    comps_all = [c for r in repos for c in (docs.get(r) or {}).get("components") or []]
    with_cpe = sum(1 for c in comps_all if c.get("cpes"))
    wildcard = sum(1 for c in comps_all if any(x.get("wildcard") for x in c.get("cpes") or []))
    lines.append("- components: %d; with at least one CPE: %d; intentionally without CPE: %d; wildcard version: %d" % (
        len(comps_all), with_cpe, len(comps_all) - with_cpe, wildcard))
    lines.append("- data source: %s; NVD queries made after approval: %d" % (nvd.get("source") or "not-needed", _nvd_query_count(ctx)))
    lines.append("")

    lines.append("## Ignored")
    lines.append("")
    ignored = queue.get("ignored") or []
    lines.extend("- %s%s: %s" % ((item["repo"] + ":") if item.get("repo") else "", item.get("path"), item.get("reason")) for item in ignored[:100])
    from sbomlib import worker as worker_mod
    for repo in run.all_repos():
        validated = worker_mod.read_validated(ctx, repo)
        for item in ((validated or {}).get("exclusions") or [])[:50]:
            if item.get("kind") in ("IGNORED", "EXCLUDED"):
                lines.append("- %s:%s (%s by the worker): %s" % (repo, item.get("path") or "-", item["kind"], item.get("reason")))
    if not ignored and not any(worker_mod.read_validated(ctx, r) for r in run.all_repos()):
        lines.append("- none")
    lines.append("")

    lines.append("## Approval and enforcement")
    lines.append("")
    approvals = run.data.get("approvals") or []
    if not approvals:
        lines.append("- approval evidence: none")
    for item in approvals:
        lines.append("- approval %s: %s, review file sha256 %s%s" % (item.get("n"), evidence_sentence(item.get("evidence")),
                                                                      str(item.get("sha256"))[:16], " (stale, superseded)" if item.get("stale") else ""))
    lines.append("- %s" % enforcement_note(ctx))
    lines.append("- %s" % limitations_note(ctx))
    for key, item in sorted((run.data.get("dispatch") or {}).items()):
        lines.append("- dispatch %s: %s%s" % (key, item.get("mode"), " (recorded by the script)" if item.get("automatic") else ""))
    lines.append("")

    lines.append("## Output paths")
    lines.append("")
    outputs = validation.get("outputs") or {}
    promoted = validation.get("verdict") == "PASS"
    for rel in sorted(outputs):
        lines.append("- %s%s" % (ctx.layout.shown(rel), "" if promoted else " (staged, not promoted)"))
    lines.append("- %s" % ctx.layout.shown("report.md"))
    lines.append("- %s" % ctx.layout.shown("validation-report.txt"))
    lines.append("")

    lines.append("## Conformance and limits")
    lines.append("")
    lines.append("CISA 2026 minimum elements, coverage over the %d component(s) of this run:" % len(comps_all))
    for name, coverage in _cisa_rows(comps_all):
        lines.append("- %s: %s" % (name, coverage))
    lines.append("")
    lines.append("- analysis mode: static (%s)" % model.ANALYSIS_MODE_REASON)
    lines.append("- no forge or registry was contacted; the NVD was queried only after approval, %d query(ies)" % _nvd_query_count(ctx))
    try:
        entries = len((ctx.asset("cpe_map.json") or {}).get("entries") or [])
    except errors.SbomError:
        entries = 0
    try:
        rows = state_names_rows(ctx)
        unmapped = sum(1 for r in rows if not r.get("map_entry"))
        lines.append("- curated CPE map: %d entries; %d of %d review rows had no map entry" % (entries, unmapped, len(rows)))
    except errors.SbomError:
        lines.append("- curated CPE map: %d entries" % entries)
    lines.append("- components are recovered from source; the list may be incomplete (see Known unknowns)")
    lines.append("")
    lines.append(model.NVD_NOTICE)
    text = "\n".join(lines) + "\n"
    path = ctx.layout.out / "report.md"
    fsio.atomic_write_text(path, text, root=ctx.layout.out)
    return ctx.layout.rel(path)


def state_names_rows(ctx: RunContext) -> List[Dict[str, Any]]:
    from sbomlib.cpe import store
    return list(store.load_names_doc(ctx)["rows"])


def write_validation_report(ctx: RunContext, run: RunState, validation: Dict[str, Any]) -> str:
    """``validation-report.txt`` of the output folder: one line per check, then the verdict."""
    lines: List[str] = []
    for name, check in (validation.get("checks") or {}).items():
        status = str(check.get("status", "fail")).upper()
        first = "; ".join(str(e) for e in (check.get("errors") or [])[:3])
        lines.append("%s %s%s" % (status, name, (": " + first) if first else ""))
    lines.append("verdict %s" % validation.get("verdict"))
    path = ctx.layout.out / "validation-report.txt"
    fsio.atomic_write_text(path, "\n".join(lines) + "\n", root=ctx.layout.out)
    return ctx.layout.rel(path)


# --------------------------------------------------------------------------------------------------- summary / explain

def _integrity_lines(run: RunState, verdict: str, checks: Dict[str, Any], doubted: bool = False) -> List[str]:
    """The first line of the summary and the lines that qualify it. ``checks.targets_unchanged`` says whether the run itself
    changed anything in the repositories; the pause window (the time spent waiting for the person) is reported apart,
    because a change there is not the run's doing but can make the outputs describe an older state."""
    check = checks.get("targets_unchanged") or {}
    status = check.get("status", "unknown")
    moved = [m for m in check.get("head_moved_while_paused") or [] if isinstance(m, dict)]
    paused = int(check.get("paused") or 0)
    if status != "pass":
        fact = "the repositories are unchanged: NOT CONFIRMED (%s)" % status
    elif paused or moved:
        fact = "the run changed nothing in the repositories, but they changed while it waited for approval"
    else:
        fact = "the repositories are unchanged: yes"
    lines = ["%sSBOM recovery %s: validation %s; %s." % (
        "PILOT RUN. " if run.data.get("mode") == "pilot" else "",
        "as recorded when it finished, and doubted since" if doubted else "finished", verdict, fact)]
    if status == "pass" and (paused or moved):
        lines.append("While the run waited for approval, %d path(s) in the repositories changed (not caused by the run; "
                     "report.md lists them)." % paused)
    for change in moved[:MAX_LIST]:
        before = str(change.get("before") or "no commit")[:12]
        lines.append("HEAD of %s moved %s -> %s after the analysis, so the outputs describe %s; run again to cover the new "
                     "commit." % (change.get("repo"), before, str(change.get("after") or "no commit")[:12], before))
    return lines


def read_validation(ctx: RunContext) -> Dict[str, Any]:
    """``.state/validation.json`` as a dict; empty when it is missing or unreadable."""
    try:
        doc = fsio.read_json(ctx.layout.state / "validation.json")
    except (errors.StateError, OSError):
        return {}
    return doc if isinstance(doc, dict) else {}


def closed_verdict(ctx: RunContext, run: RunState) -> Tuple[str, Optional[str]]:
    """``(verdict, disagreement)`` of a finished run. Two files say how the audit ended, ``run.json`` (``audit``) and
    ``validation.json`` (``verdict``); an edit of one of them must not turn a FAIL into a PASS, so the verdict is PASS only
    when both say PASS, and a disagreement is returned as a sentence for the first lines of the answer. A missing
    ``validation.json`` says nothing (the ledger reports a deleted file)."""
    recorded = "PASS" if run.audit == "pass" else "FAIL"
    filed = read_validation(ctx).get("verdict")
    if filed is None or filed == recorded:
        return (recorded, None)
    return ("FAIL", "VERDICT DISAGREES: run.json says the audit %s, validation.json says %s. One of the two files was changed "
                    "after the audit wrote it; the verdict is shown as FAIL. Run audit." % (
                        "passed" if recorded == "PASS" else "failed", filed))


def summary_text(ctx: RunContext, run: Optional[RunState]) -> str:
    """The text posted at ``done``. A fixed-size block: the verdicts, one line per repository, the changes since the baseline,
    what needs the person's attention, the approval evidence, how each unit ran, and what a plain install does not enforce.
    The list of every output file is in ``report.md``; it is not repeated here, so the disclosure lines stay short enough
    to be posted unchanged."""
    if run is None:
        return "No run. Run start."
    if not run.completed:
        return "The run is not finished: phase %s. Run next." % run.phase
    validation = read_validation(ctx)
    folder = runfiles.closed_check(ctx, run)             # a finished run is compared with the ledger sealed at its end
    verdict, disagreement = closed_verdict(ctx, run)
    checks = validation.get("checks") or {}
    lines = [] if folder["ok"] else [runfiles.closed_line(ctx, folder)]
    lines.extend(_integrity_lines(run, verdict, checks, doubted=not folder["ok"]))
    if disagreement:
        lines.append(disagreement)
    if folder["added_count"]:
        lines.append("%d file(s) in %s/ appeared after the run finished and were not written by the script; they are not part "
                     "of the SBOM and nothing was deleted (audit lists them)." % (folder["added_count"], ctx.layout.out_name))
    extra_files = int((checks.get("run_folder_unchanged") or {}).get("added_count") or 0)
    if extra_files:
        lines.append("%d file(s) in %s/ were not written by the script (ACTION REQUIRED below); they are not part of the SBOM "
                     "and nothing was deleted." % (extra_files, ctx.layout.out_name))
    if mode_line(run):
        lines.append(mode_line(run) or "")
    failed = [n for n, c in checks.items() if c.get("status") == "fail"]
    if failed:
        lines.append("Failed checks: %s. The staged files were not promoted; see %s." % (
            ", ".join(failed), ctx.layout.shown("report.md")))
    lines.append("")
    lines.append("Repositories:")
    from sbomlib.emit import merge
    contributing = merge.contributing_repos(run)
    names = sorted(run.all_repos(), key=lambda n: (run.repo(n).get("status") == "DONE", n))     # trouble first
    for repo in names[:MAX_LIST]:
        entry = run.repo(repo)
        doc = _components(ctx, repo) if repo in contributing else None
        count = len((doc or {}).get("components") or [])
        lines.append("- %s: %s%s - commit %s" % (repo, entry.get("status"), (", %d component(s)" % count) if doc is not None else
                                                 ((" - " + str(entry.get("reason"))) if entry.get("reason") else ""),
                                                 _commit_text(run, repo)))
    if len(names) > MAX_LIST:
        lines.append("- ... and %d more repositories in %s" % (len(names) - MAX_LIST, ctx.layout.shown("report.md")))
    lines.append("")
    lines.append("Baseline: %s." % baseline_line(run))
    shown = 0
    for repo in run.all_repos():
        changes = delta.read(ctx, repo)
        if changes is not None:
            shown += 1
            if shown <= MAX_LIST:
                lines.append("- %s: %s" % (repo, delta.summary_line(changes)))
    if shown > MAX_LIST:
        lines.append("- ... and %d more in %s" % (shown - MAX_LIST, ctx.layout.shown("report.md")))
    submodules = _submodule_lines(_load_queue(ctx), {r: _components(ctx, r) for r in run.all_repos()}, run)
    excluded = [text for text in submodules if "NOT CHECKED OUT" in text]
    if excluded:
        lines.append("")
        lines.append("Submodules excluded from the analysis (not checked out): %d" % len(excluded))
        lines.extend(excluded[:10])
    lines.append("")
    outputs = validation.get("outputs") or {}
    lines.append("Outputs (%s): %d file(s) below %s/; the exact list is in %s. Open %s first, then %s and %s. Each "
                 "repository has its CSV, SPDX 2.3 and CycloneDX 1.6 files in %s/<repository>/." % (
                     "promoted" if verdict == "PASS" else "staged, not promoted", len(outputs), ctx.layout.out_name,
                     ctx.layout.shown("report.md"), ctx.layout.shown("report.md"), ctx.layout.shown("merged-sbom.csv"),
                     ctx.layout.shown("validation-report.txt"), ctx.layout.shown("repos")))
    action = [w for w in _warnings_sorted(run) if w.get("tier") == "ACTION_REQUIRED"]
    if action:
        lines.append("")
        lines.append("ACTION REQUIRED:")
        lines.extend("- %s" % _warning_line(w) for w in action[:MAX_LIST])
        if len(action) > MAX_LIST:
            lines.append("- ... and %d more in %s" % (len(action) - MAX_LIST, ctx.layout.shown("report.md")))
    notes = _reply_notes(run)
    if notes:
        lines.append("")
        lines.append("Replies read with a caveat (accepted, not hidden):")
        lines.extend("- %s" % note for note in notes[:MAX_LIST])
        if len(notes) > MAX_LIST:
            lines.append("- ... and %d more in %s" % (len(notes) - MAX_LIST, ctx.layout.shown("report.md")))
    lines.append("")
    approvals = run.data.get("approvals") or []
    latest = approvals[-1] if approvals else None
    lines.append("Approval: %s" % evidence_sentence(latest.get("evidence") if latest else None))
    lines.append("Worker: %s." % worker_sentence(run))
    lines.append("Dispatch: %s" % _dispatch_sentence(run))
    lines.append("Enforcement: %s." % enforcement_note(ctx))
    lines.append(limitations_note(ctx))               # no full stop: a model keeps the path and drops the dot
    lines.append("")
    lines.append(model.NVD_NOTICE)
    return "\n".join(lines)


def _dispatch_sentence(run: RunState) -> str:
    table = run.data.get("dispatch") or {}
    if not table:
        return "no adjudication or worker unit was needed"
    modes: Dict[str, int] = {}
    for item in table.values():
        modes[str(item.get("mode"))] = modes.get(str(item.get("mode")), 0) + 1
    text = ", ".join("%d %s" % (n, m) for m, n in sorted(modes.items()))
    note = ""
    if modes.get("inline"):
        note = (" (inline means the agent that ran the unit decided in its own context; independence from the orchestrator is "
                "not established")
        workers = [v for k, v in table.items() if str(k).startswith("worker:") and v.get("mode") == "inline"]
        if workers:
            note += ("; brief written by inline-unit before the reply file: %d of %d inline worker unit(s), the order of two "
                     "files, not a check that it was read" % (sum(1 for v in workers if v.get("brief_first")), len(workers)))
        note += ")"
    return "%d adjudication and worker unit(s): %s%s" % (len(table), text, note)


def explain_text(ctx: RunContext, run: Optional[RunState]) -> str:
    """Plain-language state of the run, for a user who asks what is going on."""
    if run is None:
        return "No run. The agent starts one with start; it runs next until the script stops for your approval."
    last = run.data.get("last_result") or {}
    lines = ["Run %s is in phase %s (gate: %s)." % (run.run_id, run.phase, run.gate)]
    if last:
        lines.append("The last command was %s; the script answered %s: %s" % (
            last.get("cmd"), last.get("next_action"), str(last.get("message") or "").splitlines()[0] if last.get("message") else ""))
    if run.completed:
        folder = runfiles.closed_check(ctx, run)
        if not folder["ok"]:
            lines.insert(0, runfiles.closed_line(ctx, folder))
        lines.append("The run is complete (audit %s). Nothing is left to do except reading the summary." % run.audit)
        lines.append("Agent: run summary and post it. You: open %s and the per-repository files." % ctx.layout.shown("report.md"))
    elif run.gate == "awaiting_approval":
        lines.append("The script is waiting for you. Open %s, edit it if you want, save it." % (
            (run.data.get("review") or {}).get("path") or ctx.layout.shown("review/cpe-lookup-names.csv")))
        lines.append("Then reply \"approved\" (the agent runs approve; recorded as agent-relayed) or run %s in a terminal "
                     "(recorded as tty) and type \"continue\"." % human_approve_command(ctx))
    else:
        lines.append("Agent: run next until it says stop_for_approval, adjudicate or done. You: nothing yet.")
    action = [w for w in _warnings_sorted(run) if w.get("tier") == "ACTION_REQUIRED"]
    if action:
        lines.append("Open items: " + "; ".join(_warning_line(w) for w in action[:5]))
    lines.append("%s." % enforcement_note(ctx))
    return "\n".join(lines)
