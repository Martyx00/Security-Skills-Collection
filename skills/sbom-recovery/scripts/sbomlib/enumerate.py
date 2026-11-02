"""Phase 1: enumerate the top-level repositories of the workspace folder (contract sections 3.7, 4.5, 5.4).

Everything here is read-only. Git is reached only through ``gitro``; the dirty check is computed in Python from the
index blob ids (``git status``, ``diff`` and ``diff-files`` are forbidden because they rewrite ``.git/index``).
"""
from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sbomlib import errors, fsio, gitro, model, norm, state, urls
from sbomlib.context import OUT_NAMES, Layout, RunContext
from sbomlib.model import PhaseResult
from sbomlib.state import RunState

MAX_HASH_BYTES = 256 * 1024 * 1024
DIRTY_FILE_CAP = 50
DIR_SUMMARY_CAP = 20
DIRTY_CUTOFF_FRACTION = 0.6
DIRTY_ATTRS = ("filter", "ident", "working-tree-encoding", "text", "eol", "crlf")
CONVERTING_ATTRS = ("filter", "ident", "working-tree-encoding")
AGENT_FILE_NAMES = ("AGENTS.md", "CLAUDE.md")
# Folders in which agent hosts keep their own configuration and installed skills. Listed as IGNORED (data, never followed);
# a skill installed in the workspace folder lives in one of them.
AGENT_DIR_NAMES = (".kiro", ".cursor", ".claude", ".agents", ".vibe", ".codex", ".gemini", ".opencode", ".cline",  # check-skills: allow-path
                   ".qwen", ".windsurf", ".devin")
QUEUE_REL = ".state/queue.json"

REASON_NOT_IN_PILOT = "not named in this pilot run"
REASON_PARENT_AGENT = "agent instruction file in parent/ (an agent host may load it as instructions)"
REASON_PARENT_OTHER = "agent configuration in parent/ (not analysed)"
REASON_REPO_AGENT = "in-repo agent instructions (treated as data, not analysed)"
REASON_REPO_AGENT_DIR = "in-repo agent configuration directory (treated as data, not analysed)"
REASON_REPO_SKILL = "installed agent skill (treated as data, not analysed)"
REASON_REPO_SBOM = "repository-level SBOM document (treated as data, not analysed)"
REASON_IGNORED_DIR = "ignored by the repository's ignore rules (not analysed)"
REASON_UNTRACKED_DIR = "untracked directory (not tracked, not analysed)"


@dataclass
class TopEntry:
    name: str
    kind: str                 # "repo" | "skipped"
    reason: Optional[str]     # for skipped: "dot-directory" | "output directory" | "symlink" | "not a directory" |
                              # "not a git repository" | "bare repository" | "unsupported directory name" |
                              # "duplicate name after Unicode normalization" (D15)
    git_file: bool            # .git is a file (gitdir: ...)


# --------------------------------------------------------------------------------------------------- scan_parent

def _is_bare(path: str) -> bool:
    return (os.path.isfile(os.path.join(path, "HEAD")) and os.path.isdir(os.path.join(path, "objects"))
            and os.path.isdir(os.path.join(path, "refs")))


def _classify(parent: str, name: str) -> TopEntry:
    full = os.path.join(parent, name)
    try:
        st = os.lstat(full)
    except OSError:
        return TopEntry(name, "skipped", "not a git repository", False)
    if stat.S_ISLNK(st.st_mode):
        return TopEntry(name, "skipped", "symlink", False)
    if not stat.S_ISDIR(st.st_mode):
        return TopEntry(name, "skipped", "not a directory", False)
    if name in OUT_NAMES:
        return TopEntry(name, "skipped", "output directory", False)
    if name.startswith("."):
        return TopEntry(name, "skipped", "dot-directory", False)
    git_path = os.path.join(full, ".git")
    try:
        gst = os.lstat(git_path)
    except OSError:
        gst = None
    git_file = False
    if gst is None:
        return TopEntry(name, "skipped", "bare repository" if _is_bare(full) else "not a git repository", False)
    if stat.S_ISDIR(gst.st_mode):
        git_file = False
    elif stat.S_ISREG(gst.st_mode):
        try:
            with open(git_path, "rb") as handle:
                head = handle.read(64)
        except OSError:
            head = b""
        if not head.startswith(b"gitdir:"):
            return TopEntry(name, "skipped", "not a git repository", False)
        git_file = True
    else:
        return TopEntry(name, "skipped", "not a git repository", False)
    if not norm.is_valid_repo_name(name):
        return TopEntry(name, "skipped", "unsupported directory name", git_file)
    return TopEntry(name, "repo", None, git_file)


def scan_parent(layout: Layout) -> List[TopEntry]:
    """Classify every entry of the workspace folder, sorted by name (NFC, then exact spelling). Lstat only."""
    try:
        names = os.listdir(str(layout.parent))
    except OSError:
        return []
    entries: List[TopEntry] = []
    seen = set()
    for name in sorted(names, key=norm.repo_sort_key):
        entry = _classify(str(layout.parent), name)
        if entry.kind == "repo":
            key = norm.nfc(name)
            if key in seen:
                entry = TopEntry(name, "skipped", "duplicate name after Unicode normalization", entry.git_file)
            else:
                seen.add(key)
        entries.append(entry)
    return entries


# --------------------------------------------------------------------------------------------------- helpers

def _git(ctx: RunContext) -> Dict[str, Any]:
    """Keyword arguments every gitro call of this module gets: the context's environment (so the user's real home
    directory is not consulted when the context says otherwise) and a timeout that cannot outlive the command budget."""
    return {"env": ctx.env, "timeout": gitro.budget_timeout(ctx)}


def _cw(code: str, message: str, repo: Optional[str]) -> Dict[str, Any]:
    return model.warning("INFORMATIONAL", code, message, repo)


def _sorted_warnings(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda w: (w.get("repo") or "", w.get("code") or "", w.get("message") or ""))


def _sorted_ignored(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(items, key=lambda i: (i.get("repo") or "", i.get("path") or "", i.get("reason") or ""))


def _parent_ignored(layout: Layout) -> List[Dict[str, Any]]:
    items = []
    for name in AGENT_FILE_NAMES:
        if os.path.isfile(str(layout.parent / name)):
            reason = REASON_PARENT_AGENT if name == "AGENTS.md" else REASON_PARENT_OTHER
            items.append({"repo": None, "path": name, "reason": reason})
    for name in AGENT_DIR_NAMES:
        if os.path.isdir(str(layout.parent / name)) and not os.path.islink(str(layout.parent / name)):
            items.append({"repo": None, "path": name + "/", "reason": REASON_PARENT_OTHER})
    return items


# --------------------------------------------------------------------------------------------------- scan

def scan(ctx: RunContext, run: RunState) -> PhaseResult:
    """Unit ``enumerate:scan``: write the ``queue.json`` skeleton (repos, skipped, parent-level IGNORED). A pilot run
    (``run.json`` ``pilot_repos``) keeps only the repositories it names; the others are listed as skipped."""
    layout = ctx.layout
    entries = scan_parent(layout)
    repos = [e for e in entries if e.kind == "repo"]
    skipped = [{"name": e.name, "reason": e.reason} for e in entries if e.kind == "skipped"]
    pilot = run.data.get("pilot_repos")
    if pilot:                                    # a pilot run looks at the repositories it was asked for and nothing else
        wanted = set(str(name) for name in pilot)
        skipped.extend({"name": e.name, "reason": REASON_NOT_IN_PILOT} for e in repos if e.name not in wanted)
        repos = [e for e in repos if e.name in wanted]
    warnings: List[Dict[str, Any]] = []
    for e in entries:
        if e.kind != "skipped" or e.reason in ("dot-directory", "output directory", "not a directory", REASON_NOT_IN_PILOT):
            continue
        if e.reason == "symlink" and not os.path.isdir(str(layout.parent / e.name)):
            continue
        warnings.append(_cw("SKIPPED_FOLDER", 'folder "%s" was skipped: %s' % (e.name, e.reason), None))
    queue = {
        "schema": state.SCHEMA,
        "run_id": run.run_id,
        "repos": [{"name": e.name, "status": "QUEUED", "reason": None, "git_file": e.git_file} for e in repos],
        "skipped": skipped,
        "checkout_warnings": _sorted_warnings(warnings),
        "ignored": _sorted_ignored(_parent_ignored(layout)),
    }
    sha = state.save_queue(ctx, queue)
    return PhaseResult(outputs={QUEUE_REL: sha}, info={"repos": [e.name for e in repos]})


# --------------------------------------------------------------------------------------------------- dirty check

def _safe_tracked_path(path: str) -> bool:
    if not path or path.startswith("/") or "\x00" in path:
        return False
    segments = path.split("/")
    return not any(s in ("", ".", "..") or s.lower() == ".git" for s in segments)


def _hash_file(full: str) -> Optional[Tuple[str, bool]]:
    """(git blob sha1, contains CR) of a regular file, read once without following symlinks; None if it changed."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(full, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_HASH_BYTES:
            return None
        digest = hashlib.sha1(b"blob %d\0" % info.st_size)
        has_cr = False
        total = 0
        with os.fdopen(fd, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
                if not has_cr and b"\r" in chunk:
                    has_cr = True
        if total != info.st_size:
            return None
        return digest.hexdigest(), has_cr
    finally:
        os.close(fd)


def _leading_dirs_are_real(root: str, path: str, cache: Dict[str, bool]) -> bool:
    """True when every leading directory of the tracked ``path`` is a real directory (``lstat``, never followed).

    ``lstat`` and ``O_NOFOLLOW`` guard only the last component. When a parent directory was replaced by a symlink, the
    file behind it is not the tracked file (git itself reports such a path as deleted), and reading it would follow
    a link out of the target.
    """
    prefix = ""
    for part in path.split("/")[:-1]:
        prefix = prefix + "/" + part if prefix else part
        known = cache.get(prefix)
        if known is None:
            try:
                known = stat.S_ISDIR(os.lstat(os.path.join(root, prefix)).st_mode)
            except OSError:
                known = False
            cache[prefix] = known
        if not known:
            return False
    return True


def _eol_possible(attrs: Dict[str, str], global_possible: bool) -> bool:
    text = attrs.get("text", "unspecified")
    eol = attrs.get("eol", "unspecified")
    crlf = attrs.get("crlf", "unspecified")
    if text == "unset" or (text == "unspecified" and crlf == "unset"):
        return False
    if text != "unspecified" or eol != "unspecified" or crlf != "unspecified":
        return True
    return global_possible


def _global_eol_possible(ctx: RunContext, repo_dir: Path) -> bool:
    autocrlf = (gitro.config_get(repo_dir, "core.autocrlf", layout=ctx.layout, **_git(ctx)) or "").strip().lower()
    eol = (gitro.config_get(repo_dir, "core.eol", layout=ctx.layout, **_git(ctx)) or "").strip().lower()
    return autocrlf in ("true", "input") or eol == "crlf" or (eol == "native" and os.name == "nt")


def _dirty_check(ctx: RunContext, repo_dir: Path,
                 stage_entries: List[Tuple[str, str, int, str]]) -> Dict[str, Any]:
    """Compare tracked files with their index blob ids (contract section 4.5)."""
    entries = sorted(((mode, blob, path) for mode, blob, stage, path in stage_entries
                      if stage == 0 and mode != "160000"), key=lambda e: e[2])
    root = str(repo_dir)
    found: List[Tuple[str, str]] = []                      # (path, state) of every non-clean file
    pending: List[Tuple[str, str]] = []                    # (path, blob) of regular files to hash
    real_dirs: Dict[str, bool] = {}                        # leading directory -> is a real directory
    for number, (mode, blob, path) in enumerate(entries):
        if number % 200 == 0:
            ctx.check_deadline()
        if not _safe_tracked_path(path):
            found.append((path, "unknown"))
            continue
        if not _leading_dirs_are_real(root, path, real_dirs):
            found.append((path, "deleted"))                # git: a path behind a symlinked directory is not the tracked file
            continue
        full = os.path.join(root, path)
        try:
            st = os.lstat(full)
        except (FileNotFoundError, NotADirectoryError):
            found.append((path, "deleted"))
            continue
        except OSError:
            found.append((path, "unknown"))
            continue
        if mode == "120000":
            if not stat.S_ISLNK(st.st_mode):
                found.append((path, "modified"))
                continue
            try:
                target = os.readlink(full)
            except OSError:
                found.append((path, "unknown"))
                continue
            if gitro.blob_sha1(os.fsencode(target)) != blob:
                found.append((path, "modified"))
            continue
        if not stat.S_ISREG(st.st_mode):
            found.append((path, "modified"))
            continue
        if st.st_size > MAX_HASH_BYTES:
            found.append((path, "unknown"))
            continue
        pending.append((path, blob))

    attrs: Dict[str, Dict[str, str]] = {}
    global_possible = False
    if pending:
        try:
            attrs = gitro.check_attr(repo_dir, [p for p, _ in pending], DIRTY_ATTRS, layout=ctx.layout, env=ctx.env,
                                     timeout=gitro.budget_timeout(ctx, gitro.CHECK_ATTR_TIMEOUT))
            global_possible = _global_eol_possible(ctx, repo_dir)
        except errors.GitUnreadable:
            raise
        except errors.GitError as exc:
            ctx.log.warning("enumerate.check_attr_failed", error=exc.message[:200])
            found.extend((p, "unknown") for p, _ in pending)
            pending = []

    cutoff = DIRTY_CUTOFF_FRACTION * ctx.budget_hard_s
    truncated = False
    for number, (path, blob) in enumerate(pending):
        if truncated or ctx.unit_elapsed() >= cutoff:
            truncated = True
            found.append((path, "unknown"))
            continue
        if number % 50 == 0:
            ctx.check_deadline()
        values = attrs.get(path, {})
        if any(values.get(name, "unspecified") not in ("unspecified", "unset") for name in CONVERTING_ATTRS):
            found.append((path, "unknown"))
            continue
        try:
            hashed = _hash_file(os.path.join(root, path))
        except FileNotFoundError:
            found.append((path, "deleted"))
            continue
        except OSError:
            found.append((path, "unknown"))
            continue
        if hashed is None:
            found.append((path, "unknown"))
            continue
        sha, has_cr = hashed
        if has_cr and _eol_possible(values, global_possible):
            found.append((path, "unknown"))
        elif sha != blob:
            found.append((path, "modified"))

    found.sort(key=lambda item: item[0])
    counts = {"modified": 0, "deleted": 0, "unknown": 0}
    for _, kind in found:
        counts[kind] += 1
    return {"modified": counts["modified"], "deleted": counts["deleted"], "unknown": counts["unknown"],
            "truncated": truncated, "files": [{"path": p, "state": s} for p, s in found[:DIRTY_FILE_CAP]]}


# --------------------------------------------------------------------------------------------------- submodules

def _is_initialized_submodule(ctx: RunContext, sub_dir: Path) -> bool:
    """A submodule counts as initialized only when the directory is the top level of its own repository."""
    if not os.path.lexists(str(sub_dir / ".git")):
        return False
    try:
        result = gitro.run(sub_dir, ["rev-parse", "--show-toplevel"], layout=ctx.layout, check=False, **_git(ctx))
    except errors.GitUnreadable:
        return False
    except errors.SbomError:
        return False
    if result.returncode != 0:
        return False
    top = result.stdout.decode("utf-8", "surrogateescape").strip()
    return bool(top) and os.path.realpath(top) == os.path.realpath(str(sub_dir))


def _submodule_git_dir(ctx: RunContext, repo_dir: Path, sub_dir: Path) -> Optional[str]:
    """PARENT-relative object-store path of an initialized submodule when it lives below <repo>/.git/modules."""
    try:
        result = gitro.run(sub_dir, ["rev-parse", "--git-dir"], layout=ctx.layout, check=False, **_git(ctx))
    except errors.SbomError:
        return None
    if result.returncode != 0:
        return None
    text = result.stdout.decode("utf-8", "surrogateescape").strip()
    if not text:
        return None
    real = Path(os.path.realpath(os.path.join(str(sub_dir), text)))
    modules = Path(os.path.realpath(str(repo_dir / ".git" / "modules")))
    if real == modules or modules not in real.parents:
        return None
    try:
        return ctx.layout.rel(real)
    except ValueError:
        return None


def _gitmodules(ctx: RunContext, repo_dir: Path) -> Dict[str, Dict[str, Any]]:
    """``path -> {name, url, sbom}`` from the committed .gitmodules file."""
    pairs = gitro.config_get_regexp(repo_dir, r"^submodule\..*\.(path|url|branch|sbom-.*)$", layout=ctx.layout,
                                    file=".gitmodules", **_git(ctx))
    by_name: Dict[str, Dict[str, Any]] = {}
    for key, value in pairs:
        if not key.startswith("submodule.") or key.count(".") < 2:
            continue
        name = key[len("submodule."):key.rindex(".")]
        variable = key[key.rindex(".") + 1:]
        record = by_name.setdefault(name, {"name": name, "url": None, "path": None, "sbom": {}})
        if variable == "path":
            record["path"] = value
        elif variable == "url":
            record["url"] = value
        elif variable.startswith("sbom-"):
            record["sbom"][variable[len("sbom-"):]] = value[:200]
    return {rec["path"]: rec for rec in by_name.values() if rec["path"]}


def _submodules(ctx: RunContext, repo: str, repo_dir: Path, stage_entries: List[Tuple[str, str, int, str]],
                origin: Optional[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    links: Dict[str, Dict[str, Any]] = {}
    for mode, blob, stage, path in stage_entries:
        if mode != "160000":
            continue
        record = links.setdefault(path, {"pinned": None, "conflict": False})
        if stage == 0:
            record["pinned"] = blob
        else:
            record["conflict"] = True
            record["pinned"] = record["pinned"] or blob
    if not links:
        return [], []
    declared = _gitmodules(ctx, repo_dir)
    submodules: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    for path in sorted(links):
        meta = declared.get(path, {})
        name = meta.get("name") or path
        pinned = links[path]["pinned"]
        sub_dir = repo_dir / path
        checked_out: Optional[str] = None
        git_dir: Optional[str] = None
        if links[path]["conflict"]:
            sub_state = "conflict"
        elif not _safe_tracked_path(path) or not _is_initialized_submodule(ctx, sub_dir):
            sub_state = "uninitialized"
        else:
            checked_out = gitro.rev_parse_head(sub_dir, layout=ctx.layout, **_git(ctx))
            if checked_out is None:
                sub_state = "uninitialized"
            else:
                sub_state = "initialized" if checked_out == pinned else "different_commit"
                git_dir = _submodule_git_dir(ctx, repo_dir, sub_dir)
        submodules.append({"name": name, "path": path, "state": sub_state, "pinned": pinned, "checked_out": checked_out,
                           "url": urls.scrub_url(meta.get("url"), base=origin), "git_dir": git_dir,
                           "sbom": dict(meta.get("sbom", {}))})
        if sub_state == "uninitialized":
            warnings.append(_cw("SUBMODULE_UNINITIALIZED", 'submodule "%s" is not initialized' % name, repo))
        elif sub_state == "different_commit":
            warnings.append(_cw("SUBMODULE_MISMATCH",
                                'submodule "%s" is checked out at %s but the repository pins %s'
                                % (name, (checked_out or "")[:12], (pinned or "")[:12]), repo))
        elif sub_state == "conflict":
            warnings.append(_cw("SUBMODULE_CONFLICT", 'submodule "%s" has a merge conflict in the index' % name, repo))
    return submodules, warnings


# --------------------------------------------------------------------------------------------------- ignored

def _is_sbom_document(base: str) -> bool:
    lowered = base.lower()
    return (lowered.endswith(".spdx.json") or lowered.endswith(".cdx.json") or lowered == "bom.json"
            or (lowered.startswith("sbom") and lowered.endswith(".json")))


def _in_vendored_dir(segments: List[str]) -> bool:
    return any(segment in model.VENDORED_PARENT_DIRS for segment in segments[:-1])


def ignored_dirs(paths: Iterable[str]) -> Dict[str, str]:
    """The folders of a repository that are agent tooling, not product: ``{folder with a trailing slash: reason}``.

    Two kinds, both found from the tracked paths alone: a folder named like an agent host's own (``AGENT_DIR_NAMES``, at any
    depth) and an installed skill, a folder that holds a ``SKILL.md`` directly below ``<dot folder>/skills/``. A suite of skills
    installed in a project and committed there (this skill included) is the case: its tests, fixtures and scripts are not the
    product, and an ``#include <openssl/...>`` in one of its fixtures is not a dependency of the product. The folders are IGNORED
    items, and ``discover`` leaves every file below them out of the inventory, the usage checks and the worker's file list, so
    that the IGNORED line is true."""
    found: Dict[str, str] = {}
    for path in paths:
        segments = path.split("/")
        for index, segment in enumerate(segments[:-1]):
            if segment in AGENT_DIR_NAMES:
                found["/".join(segments[:index + 1]) + "/"] = REASON_REPO_AGENT_DIR
                break
        else:                                  # not below a host folder already: is it an installed skill of some other dot folder?
            if segments[-1] == "SKILL.md" and len(segments) >= 4 and segments[-3] == "skills" and segments[-4].startswith("."):
                found["/".join(segments[:-1]) + "/"] = REASON_REPO_SKILL
    return found


def under_ignored(path: str, folders: Iterable[str]) -> bool:
    """Is ``path`` inside one of ``folders`` (as ``ignored_dirs`` returns them)?"""
    return any(path.startswith(folder) for folder in folders)


def _ignored_items(repo: str, tracked: List[str], untracked: List[str], ignored_dirs_: List[str],
                   untracked_dirs: List[str]) -> List[Dict[str, Any]]:
    found: Dict[Tuple[str, str], str] = {}
    for folder, reason in ignored_dirs(list(tracked) + [u for u in untracked if not u.endswith("/")]).items():
        found[(folder, reason)] = reason
    for path in list(tracked) + [u for u in untracked if not u.endswith("/")]:
        segments = path.split("/")
        base = segments[-1]
        if base in AGENT_FILE_NAMES:
            found[(path, REASON_REPO_AGENT)] = REASON_REPO_AGENT
        if _is_sbom_document(base) and not _in_vendored_dir(segments):
            found[(path, REASON_REPO_SBOM)] = REASON_REPO_SBOM
    for entry in untracked:
        if entry.endswith("/") and entry.rstrip("/").split("/")[-1] in AGENT_DIR_NAMES:
            found[(entry, REASON_REPO_AGENT_DIR)] = REASON_REPO_AGENT_DIR
    for entry in ignored_dirs_:
        found[(entry, REASON_IGNORED_DIR)] = REASON_IGNORED_DIR
    for entry in untracked_dirs:
        found[(entry, REASON_UNTRACKED_DIR)] = REASON_UNTRACKED_DIR
    return [{"repo": repo, "path": path, "reason": reason} for (path, reason) in sorted(found)]


def _gitdir_external(repo_dir: Path) -> bool:
    """True when the ``.git`` file of a repository points outside the repository folder."""
    try:
        with open(str(repo_dir / ".git"), "rb") as handle:
            line = handle.read(4096).split(b"\n", 1)[0]
    except OSError:
        return False
    text = line.decode("utf-8", "surrogateescape")
    if not text.startswith("gitdir:"):
        return False
    target = text[len("gitdir:"):].strip()
    real = Path(os.path.realpath(os.path.join(str(repo_dir), target)))
    return repo_dir != real and repo_dir not in real.parents


# --------------------------------------------------------------------------------------------------- describe_repo

def _empty_entry_fields() -> Dict[str, Any]:
    return {"head": None, "describe": None, "branch": None, "detached": False, "origin": None,
            "dirty": {"modified": 0, "deleted": 0, "unknown": 0, "truncated": False, "files": []},
            "untracked": {"count": 0, "dirs": []}, "ignored": {"count": 0, "dirs": []}, "submodules": []}


def _dir_summary(entries: List[str]) -> Dict[str, Any]:
    return {"count": len(entries), "dirs": sorted(e for e in entries if e.endswith("/"))[:DIR_SUMMARY_CAP]}


def describe_repo(ctx: RunContext, run: RunState, repo: str) -> PhaseResult:
    """Unit ``enumerate:<repo>``: fill the queue entry (HEAD, describe, branch, scrubbed origin, dirty state, untracked
    and ignored counts, submodules, checkout warnings, IGNORED). An unreadable or empty repository becomes
    ``NOT ANALYZED`` (``PhaseResult.repo_status``)."""
    layout = ctx.layout
    queue = state.load_queue(ctx)
    entry = next((e for e in queue["repos"] if e.get("name") == repo), None)
    if entry is None:
        raise errors.StateError("queue.json has no repository %r" % repo, repo=repo)
    repo_dir = layout.parent / repo
    result = PhaseResult()
    fields = _empty_entry_fields()
    warnings: List[Dict[str, Any]] = []
    ignored_items: List[Dict[str, Any]] = []
    reason: Optional[str] = None
    head: Optional[str] = None

    try:
        head = gitro.rev_parse_head(repo_dir, layout=layout, **_git(ctx))
        if head is None:
            probe = gitro.run(repo_dir, ["rev-parse", "--git-dir"], layout=layout, check=False, **_git(ctx))
            reason = ("the repository has no commits" if probe.returncode == 0
                      else "git does not recognise this folder as a repository")
    except errors.GitUnreadable as exc:
        reason = "git refuses to read this repository (ownership or safe.directory): %s" % exc.message[:120]
    except errors.GitError as exc:
        reason = "git could not read this repository: %s" % exc.message[:150]

    if reason is None:
        try:
            fields["head"] = head
            fields["describe"] = gitro.describe(repo_dir, "HEAD", layout=layout, tags=True, always=True, **_git(ctx))
            branch = gitro.abbrev_ref(repo_dir, layout=layout, **_git(ctx))
            fields["branch"] = branch
            fields["detached"] = branch is None
            fields["origin"] = urls.scrub_url(gitro.config_get(repo_dir, "remote.origin.url", layout=layout, **_git(ctx)))
            stage_entries = gitro.ls_files_stage(repo_dir, layout=layout, **_git(ctx))
            fields["dirty"] = _dirty_check(ctx, repo_dir, stage_entries)
            untracked = gitro.ls_files_others(repo_dir, layout=layout, ignored=False, **_git(ctx))
            ignored = gitro.ls_files_others(repo_dir, layout=layout, ignored=True, **_git(ctx))
            fields["untracked"] = _dir_summary(untracked)
            fields["ignored"] = _dir_summary(ignored)
            submodules, sub_warnings = _submodules(ctx, repo, repo_dir, stage_entries, fields["origin"])
            fields["submodules"] = submodules
            warnings.extend(sub_warnings)
            tracked = gitro.ls_files_z(repo_dir, layout=layout, **_git(ctx))
            ignored_items = _ignored_items(repo, tracked, untracked, fields["ignored"]["dirs"],
                                           fields["untracked"]["dirs"])
        except errors.GitUnreadable as exc:
            fields = _empty_entry_fields()
            warnings, ignored_items = [], []
            reason = "git refuses to read this repository (ownership or safe.directory): %s" % exc.message[:120]

    if reason is not None:
        entry.update(fields)
        entry["status"] = "NOT ANALYZED"
        entry["reason"] = reason
        warnings = [_cw("NOT_ANALYZED", "repository %s was not analysed: %s" % (repo, reason), repo)]
        result.repo_status = "NOT ANALYZED"
        result.repo_reason = reason
        result.warnings.append(model.warning("INFORMATIONAL", "REPO_NOT_ANALYZED",
                                             "repository %s was not analysed: %s" % (repo, reason), repo))
    else:
        entry.update(fields)
        entry["status"] = "QUEUED"
        entry["reason"] = None
        dirty = fields["dirty"]
        if fields["detached"]:
            warnings.append(_cw("DETACHED_HEAD", "repository %s is on a detached HEAD" % repo, repo))
        changed = dirty["modified"] + dirty["deleted"]
        if changed:
            warnings.append(_cw("DIRTY_TRACKED",
                                "%d tracked file(s) of %s differ from HEAD; they are analysed as they are on disk"
                                % (changed, repo), repo))
        if dirty["unknown"]:
            warnings.append(_cw("DIRTY_UNKNOWN",
                                "%d tracked file(s) of %s could not be compared with HEAD (filters, line-ending "
                                "conversion or size)" % (dirty["unknown"], repo), repo))
        if dirty["truncated"]:
            result.warnings.append(model.warning(
                "INFORMATIONAL", "DIRTY_TRUNCATED",
                "the dirty check of %s stopped at the time limit; the remaining files count as unknown" % repo, repo))
        if fields["untracked"]["count"]:
            warnings.append(_cw("UNTRACKED_FILES", "%d untracked entr%s in %s are not analysed"
                                % (fields["untracked"]["count"], "y" if fields["untracked"]["count"] == 1 else "ies",
                                   repo), repo))
        if entry.get("git_file") and _gitdir_external(repo_dir):
            warnings.append(_cw("GIT_DIR_EXTERNAL", "the git directory of %s is stored outside its folder" % repo, repo))
        result.info["head"] = head

    queue["checkout_warnings"] = _sorted_warnings(
        [w for w in queue.get("checkout_warnings", []) if w.get("repo") != repo] + warnings)
    queue["ignored"] = _sorted_ignored([i for i in queue.get("ignored", []) if i.get("repo") != repo] + ignored_items)
    result.outputs[QUEUE_REL] = state.save_queue(ctx, queue)
    return result
