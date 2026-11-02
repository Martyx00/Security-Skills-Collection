#!/usr/bin/env python3
r"""
snapshot.py - freeze the working tree so a finding's line reference stops moving.

Stage 1 reads a line and records it, stage 3 quotes it into a packet, stage 4
cites it in a verdict, and a person reads it days later. Between any two of those
the tree is a mutable directory somebody is still editing. We measured the
consequence on a real run: *19 candidate(s) quote a line that changed since
stage 1 read it; the tree moved under the run.* The pipeline detected that and
said so, which is the right behaviour and not a fix - every one of those 19
findings still pointed at a file:line that no longer meant what the finding said
it meant, and the only honest thing left to do with them was throw them away.

So the pipeline gets an immutable target. This tool copies the working tree into
`.security-review/snapshot/`, hashes every byte it took, records every path it
refused and why, and writes `.security-review/snapshot-manifest.json`. Stage 1
then runs against the snapshot (`extract_functions.py --snapshot`) while still
recording paths relative to the original tree, so a file:line in the report
resolves for a human opening the repository and the bytes behind it cannot move.

**Copy, not hardlink.** A hardlink costs nothing and is the obvious choice until
you notice what it is: a second name for the same inode. `sed -i`, `>>`, a
compiler writing an object file over a source path, any editor that truncates
and rewrites in place - all of those change the "snapshot" through the link, and
they change it silently, because the manifest's hash was taken before the edit
and nothing re-reads it. A snapshot that an ordinary edit can rewrite is not a
snapshot; it is the working tree wearing a second path. Copying costs disk and
one pass over the bytes, and it is the only materialisation that survives the
failure this file exists to prevent. Copied files then lose every write bit - not
a security boundary (the owner can chmod back), just a guard rail that turns an
accidental write into an error instead of a silent divergence - and keep only
the read bits their source had. A fixed 0444 made a 0600 `.env` or deploy key
readable by every local user in the snapshot, which is a second, less protected
copy of every credential in the tree; the snapshot directory itself is 0700 for
the same reason.

**The run directory is never reached through a link.** It lives inside the
scanned tree, and a repository can legitimately commit `.security-review/` -
contract §1 commits the ledger there - so it can also commit a symlink in it.
`.security-review -> src` wrote the snapshot into src/ and excluded all of src/
from it as `run-directory`; `.security-review -> ../elsewhere` copied the whole
tree out of the root. Both exited 0. A link at, or under, the run directory on
the path this tool writes is refused before anything is written.

**Git history is never read.** `.git` is excluded entirely - the directory and
the gitfile a worktree or submodule leaves in its place. Working-tree-only is a
scope decision, not an optimisation, and a tool that walked `.git` to enumerate
what it was declining to take would have read the thing it declined to take.

**Every exclusion is recorded with a reason.** An exclusion nobody can see is a
coverage hole that reads as a clean result. The reasons come from a closed
vocabulary (below), so downstream accounting can group them instead of parsing
prose.

**Symlink policy**, enforced, not asked for:

  - resolves outside the source root  -> refused, `symlink-escapes-root`.
    Never followed. This is the classic escape: a link named `config.py`
    pointing at `/etc/shadow` turns a source scanner into an exfiltration tool.
  - resolves to a directory            -> refused, `symlink-to-directory`.
    Following it would duplicate a subtree, or cycle.
  - resolves into an excluded area     -> refused, `symlink-to-excluded`.
    Otherwise `hist -> .git` is a side door into the history we just excluded.
  - dangling                           -> refused, `symlink-broken`.
  - resolves to a regular file inside  -> MATERIALISED: the target's bytes are
    copied to the link's path, and the manifest records `symlink_target`. A
    snapshot that stored the link would re-resolve it against the live tree at
    read time, which is the mutability this tool exists to remove.

Unsupported special files - fifos, sockets, devices - are refused and NAMED
(`special-file`, with the kind in `detail`). Skipping them silently is how a
scanner reports full coverage of a tree it did not fully read.

**Changes during creation are detected.** Discovery stats every path; copying
re-stats the same inode through the open descriptor and the path again
afterwards. A file that was rewritten, truncated or replaced between the two is
listed in `changed_during_snapshot` with the fields that differ, and the run
exits 3. The snapshot still holds the bytes that were actually read and hashed -
it is a coherent artifact - but it is not a picture of any single instant, and
that is a fact about the run, not a detail to swallow.

**Caps.** `--max-files` and `--max-bytes` bound the copy. When one is reached the
snapshot stops admitting anything further, rather than cherry-picking whatever
still fits: a snapshot whose contents depend on the order small files happened
to appear in is not reproducible. The cap, and every path it kept out, are
recorded, and the run exits 4 - an incomplete snapshot must not read as a
complete one.

**What is NOT excluded by default.** Only `.git`, the run directory, and the
scanner's own folders (reason `scanner-tooling`, found by identity through
`rules_lib.is_tooling_dir`: this installed skill, a skill (a folder with a
SKILL.md) installed in a host's `<dot folder>/skills/`, an old copy of the
scanner; a `skills` folder with product code in it is not) and the run folders of the
other skills of the portfolio (reason `sibling-run-directory`: `.report-triage`, `sbom-out`,
`sbom-out-pilot`, `.binary-vuln-research`, a design-review run folder). The skill installs inside the project it
reviews, so without this the snapshot copied the scanner's rule tables and planted
fixtures into the corpus, and the stages after this one import the skill, so
Python's bytecode cache under it is rewritten mid-run and the drift check reported
the pipeline's own files as the working tree moving. Not `vendor/`, not
`node_modules/`, not `build/` - the extractor excludes those from the SCAN
(`DEFAULT_EXCLUDES` there), and that is the right place for it, because a file
excluded from the scan is still evidence: it is what a coverage claim about it
is checked against. Pass `--exclude` to narrow the snapshot itself, and the
manifest will say you did.

Stdlib only. Python 3.8+.

Exit codes
  0  the snapshot was written and nothing moved under it
  1  the snapshot could not be created: the root is unreadable, the destination
     exists and was not written by this tool, the destination is not writable,
     or --selftest failed
  2  usage: --root is not a directory, --out would put the snapshot inside the
     scanned tree under a name other than .security-review, or the run
     directory - or a path this tool writes under it - is a symlink
  3  written, and the tree moved under the run: at least one source file changed
     between discovery and the copy. `changed_during_snapshot` names every one
  4  written, and INCOMPLETE: a cap was reached. Every path it kept out is
     recorded as an exclusion
  5  --verify only: the snapshot on disk no longer matches its manifest, or a
     record in the manifest's file list is malformed
  7  refused before reading or writing anything: the scanned repository commits
     files under .security-review/ other than .gitignore and regular files
     under ledger/, git cannot say whether it does, or --root is this installed
     skill or an old copy of the scanner rather than a repository
     (rules_lib.run_dir_gate). Checked first, so it outranks every other code

  Precedence, when more than one holds: 7 > 1 > 2 > 4 > 3 > 0. An incomplete
  snapshot outranks a moved one because "some of the tree is missing" is the
  worse thing to discover after the fact.

Usage
  python3 snapshot.py --root .
  python3 snapshot.py --root . --exclude vendor --exclude '*.iso'
  python3 snapshot.py --root . --max-bytes 500000000
  python3 snapshot.py --root . --verify
  python3 snapshot.py --selftest
"""

import argparse
import errno
import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True      # the skill folder is read-only: no __pycache__ in it

TOOL = "snapshot.py"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 1

RUN_DIR_NAME = ".security-review"
SNAPSHOT_DIR_NAME = "snapshot"
MANIFEST_NAME = "snapshot-manifest.json"

BYTECODE_DIR_NAME = "__pycache__"

_RULES_LIB = None


def _rules_lib():
    """rules_lib, imported on first use rather than at module level.

    This tool runs the run-directory gate as a process of its own and refuses
    (exit 7) when that process cannot give a clean answer, a rules_lib.py that is
    missing or broken included (smoke_test.py's gate shims hold it to that). A
    module-level import would crash with exit 1 first. Every use is after the
    gate, so by then the import has already been proved to work once.
    """
    global _RULES_LIB
    if _RULES_LIB is None:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        import rules_lib                                   # noqa: PLC0415
        _RULES_LIB = rules_lib
    return _RULES_LIB

# 200k files and 4 GiB. Large enough that no ordinary repository meets them, small
# enough that a tree with a DVD image or a checked-in dependency cache stops and
# says so instead of filling the disk. Both are recorded in the manifest whether
# or not they were reached, so a reader never has to guess what bound applied.
DEFAULT_MAX_FILES = 200_000
DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024

COPY_CHUNK = 1 << 20

# The closed vocabulary. A reason outside this set is a bug, and the selftest
# checks that every recorded exclusion names one of these - left to prose, an
# exclusion reason degenerates into a free-text `skip_reason` field whose only
# constraint is being non-empty, which neither a reader nor a tool can count on.
REASONS = (
    "git-metadata",          # .git directory, or the gitfile a worktree leaves
    "run-directory",         # .security-review: pipeline output, not target source
    "scanner-tooling",       # this skill installed in the tree, another copy of
                             # it, or an old bundle (rules_lib.is_tooling_dir):
                             # not the product, and its own imports rewrite its
                             # bytecode mid-run, which would read as drift
    "sibling-run-directory", # the run folder of another skill of this portfolio
                             # (.report-triage, sbom-out, sbom-out-pilot,
                             # .binary-vuln-research, a stride run folder): a
                             # quarantined report or a copy of the
                             # product, never the product
    "excluded-by-flag",      # an --exclude pattern matched; detail names it
    "symlink-escapes-root",  # resolves outside --root. Never followed
    "symlink-to-directory",  # would duplicate a subtree, or cycle
    "symlink-to-excluded",   # a side door into something already excluded
    "symlink-broken",        # dangling
    "special-file",          # fifo, socket, device; detail names the kind
    "unreadable",            # lstat/open/read failed; detail carries the errno
    "copy-failed",           # the write into the SNAPSHOT failed - our disk,
                             # not the target tree. Never "unreadable": that
                             # blames the repository for the scanner's ENOSPC
    "cap-max-files",         # the file-count cap was already reached
    "cap-max-bytes",         # the total-size cap was already reached
)

# Written into .security-review/ when nothing is there yet. snapshot.py runs
# BEFORE extract_functions.py, so it, not stage 1, is usually the first writer -
# and a snapshot of a tree showing up as thousands of untracked files is how one
# gets committed. Byte-identical to extract_functions.GITIGNORE; the selftest
# asserts that, so the two cannot drift into disagreeing about what is ignored.
GITIGNORE = """\
# Written by the security-review pipeline. Run artifacts are not committed; the ledger is.
*
!.gitignore
!ledger/
!ledger/**
"""

# What `ensure_gitignore` appends to an existing .gitignore that ignores
# everything and gives the ledger nothing back. Stage 0's prompt writes a bare
# `*`, the stage 1 writers used to write their own file only when none existed,
# and so a run that started at stage 0 kept `*` for good: the ledger contract §1
# says to commit was ignored, and `ledger.py check` failed every stage-5 session.
# Appended, never overwritten, so an operator's own lines survive; after the
# `*`, because the last matching line wins. What counts as already carved out
# is ledger_carved_out(), which extract_functions.ensure_gitignore and
# `ledger.gitignore_problem` have to agree with.
GITIGNORE_REPAIR = """\
# Appended by the security-review pipeline. Run artifacts are not committed; the ledger is.
!.gitignore
!ledger/
!ledger/**
"""
GITIGNORE_EVERYTHING = ("*", "**")
# A carve-out takes both lines, after the last everything line. `*` matches
# every file at every depth, so `!ledger` or `!ledger/` alone gives back the
# directory and not one file in it; `!ledger/**` alone gives back nothing,
# because git never looks inside a directory it has excluded; and `!ledger/*`
# misses `ledger/training/samples.jsonl`. Any ONE of these lines used to count
# as keeping the ledger, so `*` and `!ledger` was left alone, and every
# decision was lost on the next clone - the failure this repair exists for.
# Each case was checked against git (`check-ignore`, `add --dry-run`).
GITIGNORE_LEDGER_DIR = ("!ledger/", "!ledger")
GITIGNORE_LEDGER_CONTENTS = ("!ledger/**",)
GITIGNORE_MAX_BYTES = 1 << 20


def ledger_carved_out(lines):
    """Do these stripped .gitignore lines give the ledger back after their last `*`?"""
    last = max((i for i, line in enumerate(lines) if line in GITIGNORE_EVERYTHING),
               default=-1)
    after = lines[last + 1:]
    return (any(line in GITIGNORE_LEDGER_DIR for line in after)
            and any(line in GITIGNORE_LEDGER_CONTENTS for line in after))


class SnapshotError(Exception):
    pass


class DestinationError(Exception):
    """A write into the snapshot failed: our disk, not the tree being scanned.

    copy_file touches two filesystems and OSError from either one used to arrive
    at the caller looking identical. It recorded both as `unreadable`, an
    exclusion OF THE SOURCE - so ENOSPC halfway through a copy blamed the target
    repository for the scanner's full disk, and the run still exited 0 while
    this tool's own stated principle is that an incomplete snapshot must not
    read as a complete one.
    """

    def __init__(self, exc):
        Exception.__init__(self, str(exc))
        self.cause = exc


def fail(where, msg):
    raise SnapshotError("%s: %s" % (where, msg))


def _iso(stamp):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def is_excluded(rel, patterns):
    """Path-component match, prefix match, or glob - same semantics as the scan.

    Deliberately identical to `extract_functions.is_excluded`, so that
    `--exclude vendor` means the same thing to the snapshot and to the extractor
    that reads it. They are separate copies because neither tool should import
    the other (stage 1 imports this module for the manifest, not the reverse);
    the selftest imports both and checks they agree on a table of cases, which
    catches the drift without creating the dependency.
    """
    # Patterns are written with "/" and `rel` comes off os.path.relpath, which has
    # backslashes on Windows: a multi-segment directory pattern (`src/legacy`,
    # `src/legacy/`) matched nothing there. Both sides are compared with "/".
    rel = rel.replace(os.sep, "/")
    parts = rel.split("/")
    for pat in patterns:
        pat = pat.replace(os.sep, "/")
        clean = pat.rstrip("/")
        if clean in parts:
            return True
        if rel == clean or rel.startswith(clean + "/"):
            return True
        if fnmatch.fnmatch(rel, pat):
            return True
    return False


def check_out_dir(root, out):
    """The run directory, refused when it would write into the scanned tree.

    Contract §1 puts every run artifact at `.security-review/` in the scanned
    repository and §9.2 forbids writing to the tree under review. `--out src`
    satisfies neither, and here it is worse than it is for the extractor: the
    walk below would then discover the snapshot it is in the middle of writing
    and copy it into itself.
    """
    out_dir = os.path.normpath(
        out if os.path.isabs(out) else os.path.join(root, out))
    root = os.path.normpath(root)
    inside = out_dir == root or out_dir.startswith(root + os.sep)
    if inside and os.path.basename(out_dir) != RUN_DIR_NAME:
        fail("--out",
             "%r is inside the scanned tree at %s and is not named %s. The walk "
             "would discover the snapshot it is writing and copy it into itself; "
             "§1 fixes the run directory and §9.2 forbids writing to the tree "
             "under review" % (out, root, RUN_DIR_NAME))
    if inside:
        # Lexically inside is not the same as inside. A committed link on the
        # way to any file this tool writes is refused; see linked_write_path.
        # An --out OUTSIDE the tree is the operator's own directory and is not
        # second-guessed here.
        problem = linked_write_path(root, out_dir, [
            os.path.join(out_dir, name)
            for name in (SNAPSHOT_DIR_NAME, MANIFEST_NAME, ".gitignore")])
        if problem:
            fail("--out", problem)
    return out_dir


_LINKED = ("%s is a symlink (-> %s). Nothing is written through a link under "
           "the run directory: the scanned repository can commit one there, and "
           "a write through it lands in the source under review or outside the "
           "root (pipeline-contract §1, §9 rule 2). Remove the link and run again")
_RELOCATED = ("%s resolves to %s, not to %s. Nothing is written into a run "
              "directory that is not where it is spelled: the scanned repository "
              "can arrange that with a link, and a write through it lands in the "
              "source under review or outside the root (pipeline-contract §1, "
              "§9 rule 2)")


def _readlink(path):
    try:
        return os.readlink(path)
    except OSError as exc:
        return "unreadable: %s" % exc


def linked_write_path(root, run_dir, targets=()):
    """Why a write into `run_dir` would not land where it is spelled, or None.

    The run directory lives inside the scanned tree, and the scanned tree is
    attacker-supplied. A repository can legitimately commit `.security-review/`
    - contract §1 commits the ledger there - so it can also commit a symlink in
    it, and every writer in this skill used to follow one:

      - `.security-review -> src` put the snapshot and its manifest in src/, and
        the walk then excluded ALL of src/ as `run-directory`, because its
        realpath is the run directory's. One committed link hid a subtree from
        the review and exited 0;
      - `.security-review -> ../elsewhere` copied the whole tree out of the root;
      - `.security-review/secrets -> ../src`, or a link at a file this tool is
        about to write, sent the write wherever the link pointed.

    Refused, in three shapes: the run directory, or any existing directory on
    the way from the root to a target, is a symlink; a target itself is one; or
    the run directory's realpath is not where it is spelled. `targets` are the
    files and subdirectories the caller writes under `run_dir`.

    Components are checked from BELOW the root down, never the root or anything
    above it: `--root` may legitimately be a symlink, and on macOS /var and
    /tmp are. sweep_secrets.py calls this one rather than keeping a copy -
    it already loads this module through extract_functions - so there is one
    definition of what the run directory may be.
    """
    root = os.path.normpath(os.path.abspath(root))
    prefix = root if root.endswith(os.sep) else root + os.sep
    run_dir = os.path.normpath(os.path.abspath(run_dir))
    for path in [run_dir] + [os.path.normpath(os.path.abspath(t)) for t in targets]:
        if not path.startswith(prefix):
            continue
        probe = root
        for part in os.path.relpath(path, root).split(os.sep):
            probe = os.path.join(probe, part)
            if os.path.islink(probe):
                return _LINKED % (probe, _readlink(probe))
            if not os.path.lexists(probe):
                break
    if run_dir.startswith(prefix) and os.path.lexists(run_dir):
        want = os.path.join(os.path.realpath(root), os.path.relpath(run_dir, root))
        real = os.path.realpath(run_dir)
        if real != want:
            return _RELOCATED % (run_dir, real, want)
    return None


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #

def _stat_facts(st):
    """The fields a mid-snapshot rewrite moves. Compared, never displayed raw."""
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
            "ctime_ns": st.st_ctime_ns, "inode": st.st_ino}


def _special_kind(mode):
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    if stat.S_ISDIR(mode):
        return "directory"
    return "unknown-file-type"


def discover(source_root, out_dir, excludes, max_files=DEFAULT_MAX_FILES,
             max_bytes=DEFAULT_MAX_BYTES):
    """Walk the tree and decide, per path, admit or refuse-with-a-reason.

    Split from `materialise` for two reasons. It is the shape of the problem -
    what to take is a policy question, taking it is an I/O question - and it is
    what makes the mid-snapshot race testable: the selftest can edit a file
    between the two phases and watch the copy notice, which is exactly the
    window a slow walk over a large tree opens on a machine somebody is working
    on.
    """
    admitted, excluded = [], []
    caps = {"max_files": max_files, "max_bytes": max_bytes,
            "hit": None, "stopped_at": None}
    total = {"bytes": 0, "dirs": 0}
    out_real = os.path.realpath(out_dir)

    def deny(rel, reason, detail=None):
        # The reason is the point of the record. A caller passing something
        # outside REASONS is a programming error, and it is caught here rather
        # than discovered in a report six stages later.
        if reason not in REASONS:
            raise SnapshotError("internal: %r is not one of %s"
                                % (reason, ", ".join(REASONS)))
        excluded.append({"path": rel, "reason": reason, "detail": detail})

    def inside(path):
        return path == source_root or path.startswith(source_root + os.sep)

    def in_excluded_area(real):
        """Is this resolved path somewhere the walk would never have gone?"""
        if real == out_real or real.startswith(out_real + os.sep):
            return "run-directory"
        rel = os.path.relpath(real, source_root)
        parts = rel.split(os.sep)
        if ".git" in parts:
            return "git-metadata"
        here = source_root
        for i, part in enumerate(parts[:-1]):
            why = _rules_lib().tooling_reason(source_root, here, part)
            if why:
                return _rules_lib().tooling_exclusion_reason(why)
            here = os.path.join(here, part)
        if is_excluded(rel, excludes):
            return "excluded-by-flag"
        return None

    def walk_error(exc):
        target = getattr(exc, "filename", None) or source_root
        deny(os.path.relpath(target, source_root), "unreadable", str(exc))

    for dirpath, dirnames, filenames in os.walk(source_root, topdown=True,
                                                onerror=walk_error,
                                                followlinks=False):
        total["dirs"] += 1
        keep = []
        for name in sorted(dirnames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, source_root)
            if name == ".git":
                # Recorded once, by name. Walking it to enumerate what we are
                # declining to read would be reading it.
                deny(rel, "git-metadata",
                     "git history is out of scope; the directory is not walked")
            elif os.path.realpath(path) == out_real:
                deny(rel, "run-directory", "pipeline output, not target source")
            elif _rules_lib().tooling_reason(source_root, dirpath, name):
                # The scanner's own folder, by identity. The stages AFTER this one
                # import it, so its bytecode is rewritten mid-run and the drift
                # check named it as the working tree moving when nobody had
                # touched the project; and its rule tables and planted fixtures
                # would be copied into the corpus. Nothing in it is scanned or cited.
                # Or the run folder of another skill (`sibling-run-directory`): a
                # quarantined report or a copy of the product, which the secret sweep
                # would report as the product's secrets and a caller search would find.
                why = _rules_lib().tooling_reason(source_root, dirpath, name)
                deny(rel, _rules_lib().tooling_exclusion_reason(why),
                     "%s (rules_lib.is_tooling_dir); not part of the product" % why)
            elif is_excluded(rel, excludes):
                deny(rel, "excluded-by-flag", "matched an --exclude pattern")
            elif os.path.islink(path):
                deny(rel, "symlink-to-directory",
                     "-> %s (not followed: would duplicate a subtree, or cycle)"
                     % os.readlink(path))
            else:
                keep.append(name)
        dirnames[:] = keep

        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, source_root)
            if name == ".git":
                # A worktree or submodule leaves a `.git` FILE holding `gitdir:
                # ...`. It is git metadata pointing out of the tree, and taking
                # it would put a path to the history inside the snapshot.
                deny(rel, "git-metadata", "gitfile: `gitdir:` pointer")
                continue
            if is_excluded(rel, excludes):
                deny(rel, "excluded-by-flag", "matched an --exclude pattern")
                continue
            try:
                st = os.lstat(path)
            except OSError as exc:
                deny(rel, "unreadable", str(exc))
                continue

            read_from, link_target = path, None
            if stat.S_ISLNK(st.st_mode):
                real = os.path.realpath(path)
                if not inside(real):
                    # The classic escape, and the one place this tool would do
                    # real damage if it were lax: the target is NEVER opened.
                    deny(rel, "symlink-escapes-root",
                         "-> %s resolves outside the root" % os.readlink(path))
                    continue
                area = in_excluded_area(real)
                if area is not None:
                    deny(rel, "symlink-to-excluded",
                         "-> %s, which is excluded (%s)"
                         % (os.path.relpath(real, source_root), area))
                    continue
                try:
                    tst = os.stat(path)
                except OSError as exc:
                    deny(rel, "symlink-broken",
                         "-> %s (%s)" % (os.readlink(path), exc))
                    continue
                if not stat.S_ISREG(tst.st_mode):
                    reason = ("symlink-to-directory" if stat.S_ISDIR(tst.st_mode)
                              else "special-file")
                    deny(rel, reason, "-> %s is a %s"
                         % (os.path.relpath(real, source_root),
                            _special_kind(tst.st_mode)))
                    continue
                read_from = real
                link_target = os.path.relpath(real, source_root)
                st = tst
            elif not stat.S_ISREG(st.st_mode):
                deny(rel, "special-file",
                     "%s: this pipeline reads regular files"
                     % _special_kind(st.st_mode))
                continue

            if caps["hit"]:
                deny(rel, "cap-" + caps["hit"].replace("_", "-"),
                     "the %s cap was reached at %s"
                     % (caps["hit"], caps["stopped_at"]))
                continue
            if len(admitted) >= max_files:
                caps.update(hit="max_files", stopped_at=rel)
                deny(rel, "cap-max-files", "%d file(s) already admitted" % max_files)
                continue
            if total["bytes"] + st.st_size > max_bytes:
                caps.update(hit="max_bytes", stopped_at=rel)
                deny(rel, "cap-max-bytes",
                     "%d byte(s) already admitted, this file is %d"
                     % (total["bytes"], st.st_size))
                continue

            total["bytes"] += st.st_size
            admitted.append({"path": rel, "read_from": read_from,
                             "symlink_target": link_target,
                             "before": _stat_facts(st)})

    admitted.sort(key=lambda e: e["path"])
    excluded.sort(key=lambda e: (e["path"], e["reason"]))
    return {"admitted": admitted, "excluded": excluded, "caps": caps,
            "copy_failures": 0,
            "directories_walked": total["dirs"], "declared_bytes": total["bytes"]}


# --------------------------------------------------------------------------- #
# materialisation
# --------------------------------------------------------------------------- #

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def open_source(source_root, rel):
    """A read descriptor on `rel`, opened one component at a time beneath the root.

    Discovery and the copy are separate phases on purpose (see `discover`), and
    the walk's promise that it never descends into a symlinked directory holds
    only while the walk runs. A parent swapped for a link between the two made
    the copy read `src/config.py` through `src -> /somewhere/else`: bytes from
    outside the root went into the snapshot, and the run called it a file that
    moved and a coherent artifact. O_NOFOLLOW on a full path covers its last
    component and nothing above it. So every directory is opened relative to
    its parent's descriptor with O_NOFOLLOW, and a link anywhere on the path is
    an OSError - an `unreadable` exclusion, never a read.

    The other thing a swap can do is leave a FIFO where a file was, and opening
    that for reading blocks until somebody writes: the copy hung forever. So the
    leaf is opened O_NONBLOCK and anything that is not a regular file once
    opened is refused. Where the platform has no dir_fd (Windows), the path is
    opened whole with the same flags - the old behaviour, and the best on offer.
    """
    flags = os.O_RDONLY | _NOFOLLOW | _NONBLOCK
    if not (_NOFOLLOW and _DIRECTORY and os.open in os.supports_dir_fd):
        fd = os.open(os.path.join(source_root, rel), flags)
    else:
        parts = rel.split(os.sep)
        cur = os.open(source_root, os.O_RDONLY | _DIRECTORY)
        try:
            for part in parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW,
                              dir_fd=cur)
                os.close(cur)
                cur = nxt
            fd = os.open(parts[-1], flags, dir_fd=cur)
        finally:
            os.close(cur)
    try:
        mode = os.fstat(fd).st_mode
        if not stat.S_ISREG(mode):
            raise OSError(errno.EINVAL,
                          "no longer a regular file (%s): replaced between "
                          "discovery and the copy" % _special_kind(mode), rel)
    except BaseException:
        os.close(fd)
        raise
    return fd


def copy_file(src, dest, fd=None):
    """Copy `src` to `dest`, hashing as it goes. Returns (sha256, bytes, before, after).

    `fd`, when given, is a descriptor on the source already open for reading -
    `open_source`'s, which is how `materialise` calls this - and copy_file owns
    it from here and closes it. Without one, `src` is opened by path.

    `before` and `after` are taken with fstat on the SAME descriptor the bytes
    came out of, so they describe the inode that was read rather than whatever
    the path points at now - the two questions differ, and both are asked (the
    caller compares the path again afterwards).
    """
    if fd is None:
        fd = os.open(src, os.O_RDONLY | _NOFOLLOW | _NONBLOCK)
    digest = hashlib.sha256()
    written = 0
    try:
        opened = os.fstat(fd)
        before = _stat_facts(opened)
        source_mode = stat.S_IMODE(opened.st_mode)
        parent = os.path.dirname(dest)
        try:
            if parent:
                os.makedirs(parent, exist_ok=True)
            out = open(dest, "wb")
        except OSError as exc:
            raise DestinationError(exc)
        try:
            while True:
                # Reads are the SOURCE's errors and propagate as OSError; every
                # write below is ours, and is relabelled so the manifest cannot
                # blame the repository for the scanner's disk.
                chunk = os.read(fd, COPY_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
                try:
                    out.write(chunk)
                except OSError as exc:
                    raise DestinationError(exc)
                written += len(chunk)
            try:
                out.close()            # a buffered write can fail here and only here
            except OSError as exc:
                raise DestinationError(exc)
        finally:
            if not out.closed:
                try:
                    out.close()
                except OSError:
                    pass               # already unwinding; the real error is above
        after = _stat_facts(os.fstat(fd))
    finally:
        os.close(fd)
    # No write bits: an accidental write becomes an error instead of a silent
    # divergence from the hash in the manifest. Not a security boundary - the
    # owner can chmod it back - and `--verify` is what actually proves the bytes.
    # The READ bits are the source's, never more: this used to be a flat 0444,
    # and a 0600 `.env` or deploy key - which the snapshot takes on purpose -
    # came out readable by every local user. Owner read is always kept, because
    # --verify and the extractor have to read the copy.
    try:
        os.chmod(dest, (source_mode & 0o444) | 0o400)
    except OSError as exc:
        raise DestinationError(exc)
    return digest.hexdigest(), written, before, after


def materialise(plan, source_root, snapshot_root):
    """Copy every admitted path. Returns (file records, changed_during_snapshot)."""
    files, moved = [], []
    for entry in plan["admitted"]:
        rel, src = entry["path"], entry["read_from"]
        dest = os.path.join(snapshot_root, rel)
        try:
            # Opened beneath the root, not by path: see open_source. A
            # materialised link is opened at its target's in-root path, which
            # discovery recorded as `symlink_target`.
            fd = open_source(source_root, entry["symlink_target"] or rel)
            digest, written, before, after = copy_file(src, dest, fd)
        except DestinationError as exc:
            # OUR disk, not theirs. Still an exclusion, because the coverage
            # account must not be short a path - but named for what happened, and
            # counted, because build() turns any of these into an incomplete
            # snapshot rather than a clean exit.
            plan["excluded"].append({"path": rel, "reason": "copy-failed",
                                     "detail": str(exc)})
            plan["copy_failures"] += 1
            continue
        except OSError as exc:
            # Discovered, then unreadable. It is not in the snapshot, so it is an
            # exclusion like any other - the coverage account must not be short
            # one path because an error happened late rather than early.
            plan["excluded"].append({"path": rel, "reason": "unreadable",
                                     "detail": str(exc)})
            continue

        record = {"path": rel, "bytes": written, "sha256": digest,
                  "kind": "file" if entry["symlink_target"] is None
                          else "symlink-materialised"}
        if entry["symlink_target"] is not None:
            record["symlink_target"] = entry["symlink_target"]
        files.append(record)

        try:
            final = _stat_facts(os.lstat(src))
        except OSError as exc:
            final = {"error": str(exc)}
        differs = sorted(
            {k for k in ("size", "mtime_ns", "ctime_ns", "inode")
             if entry["before"].get(k) != after.get(k)
             or after.get(k) != final.get(k)})
        if differs:
            # Three stats, two comparisons, two different moves. before vs after
            # is the same inode rewritten under us; after vs final is the path
            # replaced by a different file, which an editor that writes a temp
            # file and renames does every time you hit save.
            moved.append({"path": rel, "differs": differs,
                          "at_discovery": entry["before"],
                          "after_read": after, "now": final})
    plan["excluded"].sort(key=lambda e: (e["path"], e["reason"]))
    files.sort(key=lambda f: f["path"])
    return files, moved


def snapshot_id(files):
    r"""sha256 over `<path>\\0<sha256>\\n` for every file, sorted by path, [:16].

    Derived from the per-file content hashes, so two snapshots share an id if
    and only if they hold the same bytes at the same paths. Excluding a file
    changes the set and therefore the id - which is the behaviour you want:
    "same id" must not be reachable by quietly dropping something.

    16 hex characters, the same width as the contract's `content_hash`, because
    a second hash width in the same run record teaches a reader that the width
    means something.

    `os.fsencode`, not `.encode("utf-8")`: a filename is bytes on POSIX, and
    `os.walk` hands back anything undecodable as lone surrogates. One
    `src/café.c` written in latin-1 - which is ordinary in an old test corpus -
    made `"\udce9".encode("utf-8")` raise, AFTER the whole tree had already been
    copied and BEFORE the manifest was written, so the tool crashed with a
    traceback and left a populated snapshot directory that its own
    `prepare_destination` then refused to touch on every subsequent run.
    `os.fsencode` round-trips those bytes exactly, which is also what makes the
    id a fact about the tree rather than about the locale that read it.
    """
    digest = hashlib.sha256()
    for record in sorted(files, key=lambda f: f["path"]):
        digest.update(os.fsencode(record["path"]))
        digest.update(b"\0")
        digest.update(record["sha256"].encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()[:16]


# --------------------------------------------------------------------------- #
# destination
# --------------------------------------------------------------------------- #

def _read_manifest(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def load_manifest(out_dir):
    """The manifest beside a snapshot, refused unless this build can read it.

    Stage 1 calls this: `extract_functions.py --snapshot` must not scan a
    directory whose provenance it cannot state, because the whole value of the
    flag is that run.json can say which frozen bytes produced the corpus.
    """
    path = os.path.join(out_dir, MANIFEST_NAME)
    doc = _read_manifest(path)
    if doc is None:
        fail(path, "no readable %s beside the snapshot" % MANIFEST_NAME)
    version = doc.get("schema_version")
    if version != SCHEMA_VERSION:
        fail(path, "schema_version is %r, this tool knows %d"
                   % (version, SCHEMA_VERSION))
    for key in ("snapshot_id", "snapshot_root", "source_root", "created_at"):
        if not doc.get(key):
            fail(path, "no %r; this is not a snapshot manifest" % key)
    return doc


def _rmtree(path):
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for name in filenames:
            target = os.path.join(dirpath, name)
            try:
                os.unlink(target)
            except OSError:
                os.chmod(target, 0o600)
                os.unlink(target)
        for name in dirnames:
            os.rmdir(os.path.join(dirpath, name))
    os.rmdir(path)


def prepare_destination(snapshot_root, out_dir):
    """Clear the destination - but only one this tool wrote, or an empty one.

    A `--out` typo should not be able to delete a directory. So the only thing
    that authorises a recursive removal here is a manifest beside the target
    naming that exact path as a snapshot this tool produced; anything else with
    content in it is refused and the operator decides.
    """
    if os.path.islink(snapshot_root) or (os.path.exists(snapshot_root)
                                         and not os.path.isdir(snapshot_root)):
        fail(snapshot_root, "exists and is not a directory")
    if os.path.isdir(snapshot_root):
        if os.listdir(snapshot_root):
            previous = _read_manifest(os.path.join(out_dir, MANIFEST_NAME)) or {}
            ours = (previous.get("tool") == TOOL
                    and os.path.normpath(previous.get("snapshot_root") or "")
                    == os.path.normpath(snapshot_root))
            if not ours:
                fail(snapshot_root,
                     "is not empty and no %s beside it says this tool wrote it. "
                     "Refusing to remove a directory somebody else owns; delete "
                     "it yourself if that is what you meant" % MANIFEST_NAME)
            _rmtree(snapshot_root)
        else:
            os.rmdir(snapshot_root)
    # 0700, and chmod'ed because umask applies to makedirs. The copy keeps each
    # file's read bits, but the directories under this one are made fresh with
    # the umask default, so a key that sat in a 0700 directory would otherwise
    # land in a 0755 one. This directory is where that stops mattering.
    os.makedirs(snapshot_root, mode=0o700)
    os.chmod(snapshot_root, 0o700)


# --------------------------------------------------------------------------- #
# build / verify
# --------------------------------------------------------------------------- #

def build(root, out, excludes=(), max_files=DEFAULT_MAX_FILES,
          max_bytes=DEFAULT_MAX_BYTES):
    """The whole tool. Returns the manifest it wrote."""
    started = time.time()
    # realpath, not abspath: --root may itself be a symlink, and every
    # containment check below compares resolved paths. Comparing a resolved
    # target against an unresolved root is how an escape check passes by
    # accident.
    source_root = os.path.realpath(root)
    if not os.path.isdir(source_root):
        fail(root, "not a directory")
    out_dir = check_out_dir(source_root, out)
    snapshot_root = os.path.join(out_dir, SNAPSHOT_DIR_NAME)

    os.makedirs(out_dir, exist_ok=True)
    ensure_gitignore(os.path.join(out_dir, ".gitignore"), GITIGNORE)
    prepare_destination(snapshot_root, out_dir)
    # Claim the destination BEFORE a byte is copied. prepare_destination will
    # only clear a directory a manifest beside it says this tool wrote, which is
    # the right rule and used to have a hole in it: any failure between the copy
    # and the manifest write - a full disk, an interrupt, one undecodable
    # filename - left a populated snapshot directory with nothing claiming it,
    # so every later run refused the destination and the operator had to delete
    # it by hand. The stub is deliberately NOT a usable manifest: it carries no
    # snapshot_id, source_root or created_at, so `load_manifest` (and therefore
    # `extract_functions.py --snapshot`) refuses a half-written snapshot rather
    # than scanning it.
    _write(os.path.join(out_dir, MANIFEST_NAME),
           json.dumps({"schema_version": SCHEMA_VERSION, "tool": TOOL,
                       "tool_version": TOOL_VERSION,
                       "snapshot_root": snapshot_root,
                       "incomplete": "this snapshot is still being written"},
                      indent=1) + "\n")

    plan = discover(source_root, out_dir, list(excludes), max_files, max_bytes)
    files, moved = materialise(plan, source_root, snapshot_root)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "snapshot_id": snapshot_id(files),
        "created_at": _iso(started),
        "elapsed_seconds": round(time.time() - started, 2),
        "source_root": source_root,
        "snapshot_root": snapshot_root,
        "policy": {
            "materialisation": "copy",
            "materialisation_why": "a hardlink aliases the original inode, so an "
                                   "in-place edit to the working tree rewrites "
                                   "the snapshot and its recorded hash silently",
            "git": "excluded: .git directories and gitfiles, never walked",
            "symlinks": "materialised when they resolve to a regular file inside "
                        "the root; refused otherwise, never followed out",
            "special_files": "refused and named",
            "excludes": sorted(set(excludes)),
            "file_mode": "the source's read bits, never its write bits "
                         "(0444 at most, 0400 at least)",
            "snapshot_dir_mode": "0700",
        },
        "counts": {
            "files": len(files),
            "bytes": sum(f["bytes"] for f in files),
            "directories_walked": plan["directories_walked"],
            "symlinks_materialised": sum(
                1 for f in files if f["kind"] == "symlink-materialised"),
            "excluded": len(plan["excluded"]),
            "copy_failed": plan["copy_failures"],
            "changed_during_snapshot": len(moved),
        },
        "caps": plan["caps"],
        # Every path, not a sample. The counts above are summaries of these two
        # lists and are recomputed from them, never asserted beside them - with
        # one exception, named rather than hidden: `directories_walked` is an
        # independent walk counter with no list beside it, and it counts
        # directories in the SOURCE, not in the snapshot (a --max-files 0 run
        # records 1 walked and 0 files). It is spelled `directories_walked`
        # because it was spelled `directories`, which read as the third summary
        # of the three lists below and is not.
        "files": files,
        "exclusions": plan["excluded"],
        "changed_during_snapshot": moved,
    }
    _write(os.path.join(out_dir, MANIFEST_NAME),
           json.dumps(manifest, indent=1) + "\n")
    return manifest


def verify(out_dir):
    """Re-hash the snapshot and compare it with its manifest. Returns problems.

    The manifest is a claim about bytes on disk, and a claim nobody rechecks is
    the failure mode this whole bundle is written against. Cheap enough to run
    before stage 4 cites anything.

    It hashes the directory BESIDE the manifest, not the absolute
    `snapshot_root` the manifest recorded when it was written. That path is
    where the snapshot was created, which is not the same question as where it
    is now, and trusting it made `--verify` answer about a directory nobody
    asked about: copy or move a checkout and `snapshot.py --root <copy>
    --verify` re-hashed the ORIGINAL, so a tampered snapshot in the copy exited
    0 and an intact one exited 5 the moment the original was deleted. A
    snapshot's identity is its bytes at their relative paths - that is exactly
    what `snapshot_id` is derived from - so relocating it does not invalidate
    it, and the recorded path is reported as a note rather than checked as a
    hash.
    """
    manifest = load_manifest(out_dir)
    snapshot_root = os.path.join(out_dir, SNAPSHOT_DIR_NAME)
    snapshot_real = os.path.realpath(snapshot_root)
    problems = []
    seen = set()
    files = manifest.get("files")
    if files is None:
        files = []
    elif not isinstance(files, list):
        problems.append("files: the manifest's file list is a %s, not a list, so "
                        "no file in it could be checked" % type(files).__name__)
        files = []
    malformed = 0
    for index, record in enumerate(files):
        # The same edited file, one level down. Indexing a record that has no
        # `sha256`, or is not an object at all, raised KeyError or TypeError out
        # of main() - a traceback and exit 1, which the exit table reserves for
        # "could not be created" - where a manifest that no longer describes
        # its snapshot is exactly what exit 5 is for.
        why = _malformed_record(record)
        if why:
            malformed += 1
            named = isinstance(record, dict) and isinstance(record.get("path"), str)
            if named:
                seen.add(record["path"])
            printable = named and record["path"] and "\0" not in record["path"]
            problems.append("%s: malformed manifest record (%s), so it was not "
                            "checked" % (record["path"] if printable
                                         else "files[%d]" % index, why))
            continue
        rel = record["path"]
        seen.add(rel)
        path = os.path.join(snapshot_root, rel)
        # A manifest is a file on disk that somebody may have edited, and this
        # is the one place a path out of it is opened. `../../../../etc/passwd`
        # would be opened and hashed - the leak is a hash rather than content,
        # which is not a reason to allow it. The tree's own containment rule
        # applies to its manifest too.
        if os.path.realpath(path) != snapshot_real and not os.path.realpath(
                path).startswith(snapshot_real + os.sep):
            problems.append("%s: the manifest names a path outside the snapshot, "
                            "so it was not read" % rel)
            continue
        try:
            digest = hashlib.sha256()
            size = 0
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(COPY_CHUNK)
                    if not chunk:
                        break
                    digest.update(chunk)
                    size += len(chunk)
        except OSError as exc:
            problems.append("%s: %s" % (rel, exc))
            continue
        if digest.hexdigest() != record["sha256"]:
            problems.append("%s: sha256 is %s, the manifest says %s"
                            % (rel, digest.hexdigest()[:16],
                               record["sha256"][:16]))
        elif size != record["bytes"]:
            problems.append("%s: %d byte(s), the manifest says %d"
                            % (rel, size, record["bytes"]))
    for dirpath, _dirnames, filenames in os.walk(snapshot_root):
        for name in filenames:
            rel = os.path.relpath(os.path.join(dirpath, name), snapshot_root)
            if rel not in seen:
                problems.append("%s: present in the snapshot, absent from the "
                                "manifest" % rel)
    # The id is derived from every record, so it cannot be recomputed from a
    # list with a malformed one in it - and each of those is already a problem.
    if not malformed:
        recomputed = snapshot_id(files)
        if recomputed != manifest["snapshot_id"]:
            problems.append("snapshot_id is %s, the file list derives %s"
                            % (manifest["snapshot_id"], recomputed))
    return sorted(problems)


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _malformed_record(record):
    """Why a manifest `files` entry cannot be checked, or None."""
    if not isinstance(record, dict):
        return "a %s, not an object" % type(record).__name__
    path = record.get("path")
    if not isinstance(path, str) or not path:
        return "no `path`"
    if "\0" in path:
        return "`path` holds a NUL byte"
    digest = record.get("sha256")
    if not isinstance(digest, str) or not _SHA256_HEX.fullmatch(digest):
        return "`sha256` is not 64 lowercase hex characters"
    size = record.get("bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        return "`bytes` is not a non-negative integer"
    return None


def _umask():
    """The process umask. It can only be read by setting it, so it is set back
    at once; none of the tools that write through here runs threads."""
    mask = os.umask(0o077)
    os.umask(mask)
    return mask


def write_text(path, text):
    """Replace `path` with `text`, atomically, never writing through a link.

    It used to write `path + ".tmp"` and rename that over `path`. A predictable
    name in a directory the scanned repository can commit to is a name it can
    plant a symlink at, and `open()` follows one: a committed
    `.security-review/snapshot-manifest.json.tmp -> ~/.bashrc` had its target
    truncated and replaced with this tool's JSON, and the run exited 0. mkstemp
    creates the temp file with O_CREAT|O_EXCL - a fresh name, never a link -
    and `os.replace` renames it over `path`, which swaps a link found there
    rather than writing through it. The temp file does not outlive a failure.
    sweep_secrets.py writes through this too.

    The mode is the one `open(path, "w")` gave: 0666 under the umask. mkstemp
    makes 0600, which later stages run as somebody else could not read, and a
    flat 0644 in its place ignored a umask of 077 - the manifest, which holds
    the sha256 of every `.env` in the tree, went from 0600 to world-readable.
    """
    directory = os.path.dirname(path) or os.curdir
    fd, tmp = tempfile.mkstemp(dir=directory,
                               prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o666 & ~_umask())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# The spelling this file has always used for it.
_write = write_text


def ensure_gitignore(path, text):
    """Write the run directory's .gitignore when absent; repair one that ate the ledger.

    Returns "written", "repaired" or None (left alone). `lexists`, not `exists`:
    a dangling link reads as absent to `exists`, and the write that followed
    created whatever file it pointed at. The caller has already refused a link
    here (`linked_write_path`), so what is read below is a regular file in the
    run directory, and it is read bounded, because it came out of the scanned
    tree like everything else in it.

    An existing file is never overwritten - an operator may have added lines -
    but one that ignores everything (`*` or `**`) and does not carve the ledger
    back out after it (ledger_carved_out: `!ledger/` AND `!ledger/**`) gets
    GITIGNORE_REPAIR appended. See that constant for why it exists. Appending
    is always safe: the lines are negations, they come last, and a file they
    were appended to passes the test and is left alone the next time.
    """
    if not os.path.lexists(path):
        write_text(path, text)
        return "written"
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        with open(path, "rb") as fh:
            raw = fh.read(GITIGNORE_MAX_BYTES + 1)
    except OSError:
        return None
    if len(raw) > GITIGNORE_MAX_BYTES:
        return None                    # not an ignore file anybody wrote by hand
    try:
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None                    # rewriting it would change bytes we did not write
    lines = [line.strip() for line in body.splitlines()]
    if not any(line in GITIGNORE_EVERYTHING for line in lines):
        return None
    if ledger_carved_out(lines):
        return None
    if body and not body.endswith("\n"):
        body += "\n"
    write_text(path, body + GITIGNORE_REPAIR)
    return "repaired"


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def selftest():                                        # noqa: C901
    import socket
    import tempfile

    rl = _rules_lib()
    # What this platform can make (rules_lib.can_symlink: asked by doing it). A case that
    # needs a link, a pipe or a unix socket is skipped, named and counted where it cannot
    # be made, never run into a traceback (Windows without Developer Mode raises on os.symlink).
    links, pipes = rl.can_symlink(), rl.can_mkfifo()
    sockets = hasattr(socket, "AF_UNIX")

    failures = [0]

    def check(label, got, want):
        if got == want:
            print("  ok   %s" % label)
        else:
            failures[0] += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    def write(path, body):
        parent = os.path.dirname(path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)

    def reasons_for(manifest, path):
        return sorted(e["reason"] for e in manifest["exclusions"]
                      if e["path"] == path)

    # ---- a whole tree, taken once ---- #
    with tempfile.TemporaryDirectory() as tmp:
        outside = os.path.join(tmp, "outside")
        os.makedirs(outside)
        write(os.path.join(outside, "secret.txt"), "ESCAPED CONTENT\n")

        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "src", "a.c"), "int a(void) { return 1; }\n")
        write(os.path.join(root, "src", "b.py"), "def b():\n    return 2\n")
        write(os.path.join(root, "vendor", "big.c"), "int v(void) { return 3; }\n")
        write(os.path.join(root, ".git", "config"), "[core]\n")
        write(os.path.join(root, ".git", "HEAD"), "ref: refs/heads/main\n")
        write(os.path.join(root, "sub", ".git"), "gitdir: ../.git/modules/sub\n")
        if links:
            os.symlink(os.path.join(outside, "secret.txt"),
                       os.path.join(root, "escape.txt"))
            os.symlink(os.path.join(root, "src", "a.c"),
                       os.path.join(root, "alias.c"))
            os.symlink(os.path.join(root, "src"), os.path.join(root, "src-link"))
            os.symlink(os.path.join(root, "nowhere.c"),
                       os.path.join(root, "dangling.c"))
            os.symlink(os.path.join(root, ".git", "config"),
                       os.path.join(root, "hist.txt"))
        if pipes:
            os.mkfifo(os.path.join(root, "pipe"))
        sock = None
        if sockets:
            # By a relative name from inside root: sun_path holds 104-108 bytes, and
            # a long TMPDIR (sandboxes, CI runners, Nix builds) pushed the absolute
            # path over it, so bind() raised and the whole selftest died with a
            # traceback before a single check ran.
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            cwd = os.getcwd()
            try:
                os.chdir(root)
                sock.bind("sock")
            finally:
                os.chdir(cwd)

        manifest = build(root, RUN_DIR_NAME)
        snap = manifest["snapshot_root"]
        taken = {f["path"]: f for f in manifest["files"]}

        check("the snapshot lands under the run directory",
              os.path.relpath(snap, root),
              os.path.join(RUN_DIR_NAME, SNAPSHOT_DIR_NAME))
        check("every ordinary source file is taken",
              sorted(p for p in taken if p.endswith((".c", ".py"))),
              (["alias.c"] if links else [])
              + [os.path.join("src", "a.c"),
                 os.path.join("src", "b.py"), os.path.join("vendor", "big.c")])

        # ---- .git, both spellings ---- #
        check(".git is excluded as git-metadata",
              reasons_for(manifest, ".git"), ["git-metadata"])
        check("a worktree gitfile is excluded too",
              reasons_for(manifest, os.path.join("sub", ".git")),
              ["git-metadata"])
        check("nothing under .git reached the snapshot",
              [p for p in taken if ".git" in p.split(os.sep)], [])
        check("the snapshot directory holds no .git at all",
              os.path.exists(os.path.join(snap, ".git")), False)

        # ---- symlinks ---- #
        if links:
            check("a symlink escaping the root is refused",
                  reasons_for(manifest, "escape.txt"), ["symlink-escapes-root"])
            check("and its target's bytes are nowhere in the snapshot",
                  os.path.exists(os.path.join(snap, "escape.txt")), False)
            escaped = "ESCAPED CONTENT\n"
            body = ""
            for dirpath, _d, names in os.walk(snap):
                for name in names:
                    with open(os.path.join(dirpath, name), encoding="utf-8") as fh:
                        body += fh.read()
            check("no byte of the escaped file was read into the snapshot",
                  escaped in body, False)

            check("a symlink inside the root is materialised, not stored as a link",
                  (os.path.islink(os.path.join(snap, "alias.c")),
                   taken["alias.c"]["kind"]),
                  (False, "symlink-materialised"))
            check("and it records the target it was taken from",
                  taken["alias.c"]["symlink_target"], os.path.join("src", "a.c"))
            check("a materialised symlink carries the target's bytes",
                  taken["alias.c"]["sha256"],
                  taken[os.path.join("src", "a.c")]["sha256"])
            check("a symlink to a directory is refused, not walked",
                  reasons_for(manifest, "src-link"), ["symlink-to-directory"])
            check("a dangling symlink is named",
                  reasons_for(manifest, "dangling.c"), ["symlink-broken"])
            check("a symlink into .git is refused as a side door",
                  reasons_for(manifest, "hist.txt"), ["symlink-to-excluded"])
        else:
            rl.skip_case("the symlink cases (escape, materialised, to a directory, dangling, into .git)",
                         n=9)

        # ---- special files ---- #
        if pipes:
            check("a fifo is named, not skipped silently",
                  reasons_for(manifest, "pipe"), ["special-file"])
            check("and the record says what kind of file it was",
                  [e["detail"].split(":")[0] for e in manifest["exclusions"]
                   if e["path"] == "pipe"], ["fifo"])
        else:
            rl.skip_case("a fifo is named, not skipped silently", "a named pipe")
        if sockets:
            check("a unix socket is named too",
                  reasons_for(manifest, "sock"), ["special-file"])
        else:
            rl.skip_case("a unix socket is named too", "a unix socket")
        if sock is not None:
            sock.close()

        # ---- every exclusion carries a reason from the vocabulary ---- #
        check("every exclusion has a reason from the closed vocabulary",
              sorted({e["reason"] for e in manifest["exclusions"]}
                     - set(REASONS)), [])
        check("no exclusion has an empty reason",
              [e["path"] for e in manifest["exclusions"] if not e["reason"]], [])
        check("the exclusion count matches the list",
              manifest["counts"]["excluded"], len(manifest["exclusions"]))
        check("the run directory excludes itself",
              reasons_for(manifest, RUN_DIR_NAME), ["run-directory"])

        # ---- copy, not hardlink: the decision the docstring argues for ---- #
        original = os.path.join(root, "src", "a.c")
        copied = os.path.join(snap, "src", "a.c")
        check("the copy is a different inode from the original",
              os.stat(original).st_ino == os.stat(copied).st_ino, False)
        # Pinned as "no write bit, owner can read" rather than 0444: the read
        # bits now follow the source, and the fixture's source mode follows
        # the umask the selftest happens to run under.
        copied_mode = stat.S_IMODE(os.stat(copied).st_mode)
        check("the snapshot's copy is read-only",
              (copied_mode & 0o222, bool(copied_mode & 0o400)), (0, True))
        check("and the snapshot directory is the owner's alone",
              stat.S_IMODE(os.stat(snap).st_mode), 0o700)
        with open(original, "a", encoding="utf-8") as fh:
            fh.write("int appended(void) { return 9; }\n")
        with open(copied, encoding="utf-8") as fh:
            after_edit = fh.read()
        check("an in-place edit to the working tree does NOT reach the snapshot",
              after_edit, "int a(void) { return 1; }\n")
        check("so the manifest's hash still describes the snapshot",
              verify(os.path.join(root, RUN_DIR_NAME)), [])

        # ---- the id ---- #
        check("the snapshot id is 16 hex characters",
              (len(manifest["snapshot_id"]),
               all(c in "0123456789abcdef" for c in manifest["snapshot_id"])),
              (16, True))
        check("the id is derivable from the file list alone",
              snapshot_id(manifest["files"]), manifest["snapshot_id"])

        # ---- --verify catches tampering ---- #
        os.chmod(copied, 0o644)
        with open(copied, "a", encoding="utf-8") as fh:
            fh.write("/* tampered */\n")
        problems = verify(os.path.join(root, RUN_DIR_NAME))
        check("--verify notices an edited snapshot file",
              len(problems) == 1 and problems[0].startswith(
                  os.path.join("src", "a.c") + ": sha256"), True)
        write(os.path.join(snap, "planted.c"), "int planted(void) { return 0; }\n")
        check("--verify notices a file nobody put in the manifest",
              any("absent from the manifest" in p
                  for p in verify(os.path.join(root, RUN_DIR_NAME))), True)

    # ---- --verify answers about the snapshot it was pointed at ---- #
    #
    # It used to answer about `manifest["snapshot_root"]`, the absolute path the
    # snapshot was CREATED at. Copy the checkout - which is what a CI job and
    # `cp -a` both do - and `--verify` on the copy re-hashed the original:
    # tampering with the copy exited 0, and deleting the original made the
    # intact copy exit 5. Both directions are fixtured.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
        build(root, RUN_DIR_NAME)

        copy_root = os.path.join(tmp, "copy")
        for dirpath, _d, names in os.walk(root):
            for name in names:
                src = os.path.join(dirpath, name)
                dest = os.path.join(copy_root, os.path.relpath(src, root))
                if not os.path.isdir(os.path.dirname(dest)):
                    os.makedirs(os.path.dirname(dest))
                with open(src, "rb") as fh:
                    body = fh.read()
                with open(dest, "wb") as fh:
                    fh.write(body)
        check("a relocated snapshot still verifies where it now lives",
              verify(os.path.join(copy_root, RUN_DIR_NAME)), [])

        tampered = os.path.join(copy_root, RUN_DIR_NAME, SNAPSHOT_DIR_NAME, "a.c")
        os.chmod(tampered, 0o644)
        with open(tampered, "a", encoding="utf-8") as fh:
            fh.write("/* tampered in the copy */\n")
        check("tampering with the COPY is caught, not the original's bytes",
              [p.split(":")[0] for p in verify(os.path.join(copy_root, RUN_DIR_NAME))],
              ["a.c"])
        check("and the original is still reported clean",
              verify(os.path.join(root, RUN_DIR_NAME)), [])

        _rmtree(os.path.join(root, RUN_DIR_NAME, SNAPSHOT_DIR_NAME))
        with open(tampered, "w", encoding="utf-8") as fh:
            fh.write("int a(void) { return 1; }\n")
        check("deleting the original does not fail the copy",
              verify(os.path.join(copy_root, RUN_DIR_NAME)), [])

    # ---- a filename that is not valid UTF-8 ---- #
    #
    # `os.walk` hands undecodable names back as lone surrogates, and
    # `"\udce9".encode("utf-8")` raises. It raised in snapshot_id, which runs
    # AFTER the tree has been copied and BEFORE the manifest is written, so one
    # latin-1 filename crashed the tool with a traceback and left a populated
    # snapshot directory that prepare_destination then refused on every later
    # run. Both halves are fixtured: the run completes, and it is re-runnable.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(root, "src"))
        odd = os.path.join(os.fsencode(root), b"src", b"caf\xe9.c")
        with open(odd, "wb") as fh:
            fh.write(b"int cafe(void) { return 0; }\n")
        write(os.path.join(root, "src", "plain.c"), "int p(void) { return 1; }\n")
        try:
            manifest = build(root, RUN_DIR_NAME)
        except UnicodeError as exc:
            failures[0] += 1
            print("  FAIL an undecodable filename crashed the snapshot: %s" % exc)
        else:
            check("a filename that is not valid UTF-8 is taken, not fatal",
                  len(manifest["files"]), 2)
            check("and its bytes survive the copy",
                  os.path.exists(os.fsdecode(
                      os.path.join(os.fsencode(manifest["snapshot_root"]),
                                   b"src", b"caf\xe9.c"))), True)
            check("and the manifest it wrote verifies",
                  verify(os.path.join(root, RUN_DIR_NAME)), [])
            check("and the run is re-runnable, not bricked",
                  build(root, RUN_DIR_NAME)["snapshot_id"],
                  manifest["snapshot_id"])

    # ---- a destination this tool half-wrote is still this tool's ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
        out_dir = os.path.join(root, RUN_DIR_NAME)
        snap = os.path.join(out_dir, SNAPSHOT_DIR_NAME)
        os.makedirs(snap)
        write(os.path.join(snap, "half.c"), "int half(void) { return 0; }\n")
        _write(os.path.join(out_dir, MANIFEST_NAME),
               json.dumps({"schema_version": SCHEMA_VERSION, "tool": TOOL,
                           "snapshot_root": snap,
                           "incomplete": "this snapshot is still being written"}) + "\n")
        try:
            manifest = build(root, RUN_DIR_NAME)
            check("a half-written snapshot is reclaimed, not refused forever",
                  sorted(f["path"] for f in manifest["files"]), ["a.c"])
        except SnapshotError as exc:
            check("a half-written snapshot is reclaimed, not refused forever",
                  str(exc), "")
        # ...and while it IS half-written, stage 1 must not scan it.
        _write(os.path.join(out_dir, MANIFEST_NAME),
               json.dumps({"schema_version": SCHEMA_VERSION, "tool": TOOL,
                           "snapshot_root": snap,
                           "incomplete": "this snapshot is still being written"}) + "\n")
        try:
            load_manifest(out_dir)
            check("a half-written snapshot is refused by stage 1", False, True)
        except SnapshotError as exc:
            check("a half-written snapshot is refused by stage 1",
                  "snapshot_id" in str(exc), True)

    # ---- a write into the snapshot that fails ---- #
    # ENOSPC halfway through a copy used to be recorded as `unreadable`: an
    # exclusion OF THE SOURCE, blaming the repository for the scanner's disk,
    # and the run exited 0 while this tool's own rule is that an incomplete
    # snapshot must not read as a complete one.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "src", "ok.c"), "int ok(void) { return 1; }\n")
        write(os.path.join(root, "src", "doomed.c"), "int d(void) { return 2; }\n")

        # A module global shadows the builtin for every function in this file,
        # which is the only way to make a write fail deterministically: chmod
        # does nothing when the tests run as root, and filling a disk is not a
        # thing a selftest may do.
        real_open = open

        def failing_open(path, mode="r", *a, **kw):
            if "w" in mode and str(path).endswith(
                    os.path.join("src", "doomed.c")):
                raise OSError(28, "No space left on device")
            return real_open(path, mode, *a, **kw)

        def with_full_disk(fn):
            globals()["open"] = failing_open
            try:
                return fn()
            finally:
                globals().pop("open", None)

        manifest = with_full_disk(lambda: build(root, RUN_DIR_NAME))

        by_reason = {e["path"]: e["reason"] for e in manifest["exclusions"]}
        check("a failed write is copy-failed, not unreadable",
              by_reason.get(os.path.join("src", "doomed.c")), "copy-failed")
        check("and the detail carries the errno rather than prose",
              "No space left on device" in "".join(
                  e["detail"] for e in manifest["exclusions"]
                  if e["reason"] == "copy-failed"), True)
        check("it is counted, so the caller does not have to grep reasons",
              manifest["counts"]["copy_failed"], 1)
        check("the file is not in the snapshot",
              [f["path"] for f in manifest["files"]],
              [os.path.join("src", "ok.c")])
        check("and the coverage account is not short a path",
              manifest["counts"]["files"] + manifest["counts"]["excluded"],
              2 + sum(1 for e in manifest["exclusions"]
                      if e["reason"] == "run-directory"))

        argv = sys.argv
        sys.argv = ["snapshot.py", "--root", root, "--quiet"]
        try:
            code = with_full_disk(main)
        finally:
            sys.argv = argv
        check("an incomplete snapshot exits 4, not 0", code, 4)

    # ---- every reason the code can emit is in the contract's vocabulary ---- #
    with open(os.path.abspath(__file__), encoding="utf-8") as _fh:
        emitted = set(re.findall(r'"reason": "([a-z-]+)"', _fh.read()))
    check("no reason is emitted that the closed vocabulary does not carry",
          sorted(emitted - set(REASONS)), [])

    # ---- a manifest naming a path outside the snapshot ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "src", "a.c"), "int a(void) { return 1; }\n")
        outside = os.path.join(tmp, "outside.txt")
        write(outside, "NOT PART OF THE SNAPSHOT\n")
        manifest = build(root, RUN_DIR_NAME)
        out_dir = os.path.join(root, RUN_DIR_NAME)

        check("the honest snapshot verifies", verify(out_dir), [])
        manifest["files"].append({
            "path": os.path.join(os.pardir, os.pardir, os.pardir, "outside.txt"),
            "bytes": 24, "sha256": "0" * 64, "kind": "file"})
        manifest["snapshot_id"] = snapshot_id(manifest["files"])
        _write(os.path.join(out_dir, MANIFEST_NAME),
               json.dumps(manifest, indent=1) + "\n")
        problems = verify(out_dir)
        check("a manifest path escaping the snapshot is refused, not hashed",
              any("outside the snapshot" in p for p in problems), True)
        check("and nothing reports it as a mere hash mismatch",
              any("sha256 is" in p for p in problems), False)

    # ---- the same tree twice, and an --exclude ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
        write(os.path.join(root, "vendor", "v.c"), "int v(void) { return 2; }\n")

        first = build(root, RUN_DIR_NAME)
        second = build(root, RUN_DIR_NAME)
        check("an unchanged tree snapshots to the same id",
              second["snapshot_id"], first["snapshot_id"])
        check("re-running over our own snapshot directory is allowed",
              second["counts"]["files"], first["counts"]["files"])

        write(os.path.join(root, "a.c"), "int a(void) { return 2; }\n")
        third = build(root, RUN_DIR_NAME)
        check("a one-character edit changes the id",
              third["snapshot_id"] == first["snapshot_id"], False)

        excluded = build(root, RUN_DIR_NAME, excludes=["vendor"])
        check("--exclude narrows the snapshot",
              sorted(f["path"] for f in excluded["files"]), ["a.c"])
        check("and the exclusion is recorded with its reason",
              reasons_for(excluded, "vendor"), ["excluded-by-flag"])
        check("and the policy block says what was excluded",
              excluded["policy"]["excludes"], ["vendor"])
        check("dropping a file changes the id",
              excluded["snapshot_id"] == third["snapshot_id"], False)

        # A destination this tool did not write is not deleted for you.
        stranger = os.path.join(tmp, "stranger")
        os.makedirs(os.path.join(stranger, RUN_DIR_NAME, SNAPSHOT_DIR_NAME))
        write(os.path.join(stranger, RUN_DIR_NAME, SNAPSHOT_DIR_NAME, "keep.txt"),
              "not ours\n")
        try:
            build(stranger, RUN_DIR_NAME)
            check("a destination nobody claims is refused", False, True)
        except SnapshotError as exc:
            check("a destination nobody claims is refused",
                  MANIFEST_NAME in str(exc), True)
        check("and its contents are still there",
              os.path.exists(os.path.join(stranger, RUN_DIR_NAME,
                                          SNAPSHOT_DIR_NAME, "keep.txt")), True)

        try:
            build(root, "src")
            check("--out inside the scanned tree is refused", False, True)
        except SnapshotError as exc:
            check("--out inside the scanned tree is refused",
                  str(exc).startswith("--out:"), True)

    # ---- a file that moves between discovery and the copy ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "still.c"), "int still(void) { return 0; }\n")
        write(os.path.join(root, "moves.c"), "int moves(void) { return 0; }\n")
        write(os.path.join(root, "swapped.c"), "int swapped(void) { return 0; }\n")
        out_dir = os.path.join(root, RUN_DIR_NAME)
        snap = os.path.join(out_dir, SNAPSHOT_DIR_NAME)
        os.makedirs(snap)

        plan = discover(os.path.realpath(root), out_dir, [])
        # The window this tool is about: discovery has stat'ed the tree, the copy
        # has not run yet, and somebody saves a file. One is rewritten in place,
        # one is replaced by a rename - which is what most editors actually do.
        time.sleep(0.01)
        with open(os.path.join(root, "moves.c"), "w", encoding="utf-8") as fh:
            fh.write("int moves(void) { return 99; }\n")
        write(os.path.join(root, "swapped.new"), "int swapped(void) { return 7; }\n")
        os.replace(os.path.join(root, "swapped.new"),
                   os.path.join(root, "swapped.c"))

        files, moved = materialise(plan, os.path.realpath(root), snap)
        check("a file rewritten between discovery and the copy is detected",
              sorted(m["path"] for m in moved), ["moves.c", "swapped.c"])
        check("a file that did not move is not reported",
              [m for m in moved if m["path"] == "still.c"], [])
        check("the report names which stat fields differ",
              all(m["differs"] for m in moved), True)
        check("a path replaced by a rename is caught by the inode",
              "inode" in [m for m in moved
                          if m["path"] == "swapped.c"][0]["differs"], True)
        check("the snapshot still holds the bytes that were hashed",
              len(files), 3)
        for record in files:
            with open(os.path.join(snap, record["path"]), "rb") as fh:
                on_disk = hashlib.sha256(fh.read()).hexdigest()
            if on_disk != record["sha256"]:
                failures[0] += 1
                print("  FAIL %s: hashed bytes are not the copied bytes"
                      % record["path"])
                break
        else:
            print("  ok   every recorded hash is the hash of the copied bytes")

    # ---- the working tree, which is the whole point ---- #
    #
    # Research §6.1: "include current modified and untracked files". §6.2: an
    # ignored `.env` is still in scope for a secret scan - "ignored by Git" does
    # not mean "out of security scope", and inheriting the target's exclusions
    # would let the audited repository decide what the audit may look at.
    # Nothing here reads git; these assertions exist to prove that a real
    # checkout with a real index does not change what is taken.
    import subprocess
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        os.makedirs(root)

        def git(*argv):
            return subprocess.run(["git"] + list(argv), cwd=root,   # noqa: S603
                                  capture_output=True).returncode

        if git("init", "-q", ".") != 0:
            print("  skip working-tree cases: no usable git")
        else:
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            write(os.path.join(root, "committed.c"), "int c(void) { return 0; }\n")
            write(os.path.join(root, ".gitignore"), ".env\n")
            git("add", "-A")
            git("commit", "-qm", "base")

            write(os.path.join(root, "committed.c"),
                  "int c(void) { return 1; }  /* uncommitted edit */\n")
            write(os.path.join(root, "untracked.c"), "int u(void) { return 2; }\n")
            write(os.path.join(root, ".env"), "API_KEY=sk-live-0000\n")
            staged = os.path.join(root, "staged.c")
            write(staged, "int s(void) { return 3; }\n")
            git("add", "staged.c")

            manifest = build(root, RUN_DIR_NAME)
            snap = manifest["snapshot_root"]
            taken = sorted(f["path"] for f in manifest["files"])
            check("modified, untracked, staged and gitignored files are all taken",
                  taken,
                  [".env", ".gitignore", "committed.c", "staged.c", "untracked.c"])
            with open(os.path.join(snap, "committed.c"), encoding="utf-8") as fh:
                current = fh.read()
            check("a modified file is taken as the WORKING TREE has it, not HEAD",
                  current.strip().endswith("/* uncommitted edit */"), True)
            check("and .git is still the only thing git contributes",
                  sorted({e["reason"] for e in manifest["exclusions"]}),
                  ["git-metadata", "run-directory"])

    # ---- caps ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        for index in range(6):
            write(os.path.join(root, "f%d.c" % index), "x" * 100)

        capped = build(root, RUN_DIR_NAME, max_files=3)
        check("the file cap stops the snapshot at the cap",
              capped["counts"]["files"], 3)
        check("and the cap is recorded as hit",
              (capped["caps"]["hit"], capped["caps"]["max_files"]),
              ("max_files", 3))
        check("and every path it kept out is an exclusion with a reason",
              sorted(e["path"] for e in capped["exclusions"]
                     if e["reason"] == "cap-max-files"),
              ["f3.c", "f4.c", "f5.c"])
        check("the cap names where it stopped",
              capped["caps"]["stopped_at"], "f3.c")

        sized = build(root, RUN_DIR_NAME, max_bytes=250)
        check("the size cap is recorded when hit",
              (sized["caps"]["hit"], sized["caps"]["max_bytes"],
               sized["counts"]["files"]),
              ("max_bytes", 250, 2))
        check("and the size cap's exclusions carry their own reason",
              sorted({e["reason"] for e in sized["exclusions"]
                      if e["reason"].startswith("cap-")}), ["cap-max-bytes"])
        check("an uncapped run records the caps it did not reach",
              build(root, RUN_DIR_NAME)["caps"]["hit"], None)

    def quiet_main(argv):
        """main() under `argv`, its stderr swallowed: only the exit code is asserted."""
        import io
        held_argv, held_err = sys.argv, sys.stderr
        sys.argv, sys.stderr = ["snapshot.py"] + list(argv), io.StringIO()
        try:
            return main()
        finally:
            sys.argv, sys.stderr = held_argv, held_err

    def read(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    # ---- the read bits follow the source; the snapshot never widens them ---- #
    #
    # A flat 0444 made a 0600 .env and a deploy key in a 0700 directory readable
    # by every local user, in a copy the snapshot takes on purpose.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, ".env"), "API_KEY=sk-live-0000\n")
        write(os.path.join(root, "deploy", "id_ed25519"), "not a real key\n")
        write(os.path.join(root, "src", "open.c"), "int o(void) { return 0; }\n")
        os.chmod(os.path.join(root, ".env"), 0o600)
        os.chmod(os.path.join(root, "deploy", "id_ed25519"), 0o600)
        os.chmod(os.path.join(root, "deploy"), 0o700)
        os.chmod(os.path.join(root, "src", "open.c"), 0o644)
        snap = build(root, RUN_DIR_NAME)["snapshot_root"]

        def mode_of(rel):
            return stat.S_IMODE(os.stat(os.path.join(snap, rel)).st_mode)

        check("an owner-only source stays owner-only in the snapshot",
              (mode_of(".env"), mode_of(os.path.join("deploy", "id_ed25519"))),
              (0o400, 0o400))
        check("a world-readable source keeps its read bits and loses its write bits",
              mode_of(os.path.join("src", "open.c")), 0o444)
        check("and the snapshot directory is 0700 whatever the umask",
              stat.S_IMODE(os.stat(snap).st_mode), 0o700)

    # The manifest and the other artifacts get the mode open() gave them. A flat
    # 0644 after mkstemp made them world-readable under a umask of 077.
    with tempfile.TemporaryDirectory() as tmp:
        held = os.umask(0o077)
        try:
            write_text(os.path.join(tmp, "private"), "x\n")
            os.umask(0o022)
            write_text(os.path.join(tmp, "shared"), "x\n")
        finally:
            os.umask(held)
        check("an artifact is written under the umask, as open() wrote it",
              (stat.S_IMODE(os.stat(os.path.join(tmp, "private")).st_mode),
               stat.S_IMODE(os.stat(os.path.join(tmp, "shared")).st_mode)),
              (0o600, 0o644))

    # ---- a parent swapped for a link between discovery and the copy ---- #
    #
    # The walk never descends into a symlinked directory, but discovery and the
    # copy are two phases, and O_NOFOLLOW on a full path guards only its last
    # component. `src` renamed away and replaced by `src -> ../outside` in that
    # window made the copy read the outside file into the snapshot.
    if _NOFOLLOW and _DIRECTORY and os.open in os.supports_dir_fd:
        if links:
            with tempfile.TemporaryDirectory() as tmp:
                root = os.path.join(tmp, "repo")
                outside = os.path.join(tmp, "outside")
                write(os.path.join(root, "src", "config.py"), "DEBUG = False\n")
                write(os.path.join(root, "kept.c"), "int k(void) { return 0; }\n")
                write(os.path.join(root, "piped.c"), "int p(void) { return 0; }\n")
                write(os.path.join(outside, "config.py"), "OUTSIDE-THE-ROOT SECRET\n")
                out_dir = os.path.join(root, RUN_DIR_NAME)
                snap = os.path.join(out_dir, SNAPSHOT_DIR_NAME)
                os.makedirs(snap)
                real_root = os.path.realpath(root)

                plan = discover(real_root, out_dir, [])
                os.rename(os.path.join(root, "src"), os.path.join(root, "src.old"))
                os.symlink(outside, os.path.join(root, "src"))
                swapped_fifo = pipes
                if swapped_fifo:
                    # If the copy opened this blocking, the call below would never
                    # return to fail - which is the bug.
                    os.remove(os.path.join(root, "piped.c"))
                    os.mkfifo(os.path.join(root, "piped.c"))
                files, _moved = materialise(plan, real_root, snap)
                taken = [f["path"] for f in files]
                why = {e["path"]: e["reason"] for e in plan["excluded"]}

                config = os.path.join("src", "config.py")
                check("a file whose parent became a link out of the root is not copied",
                      (config in taken,
                       os.path.exists(os.path.join(snap, "src", "config.py"))),
                      (False, False))
                check("and it is recorded as unreadable, not dropped",
                      why.get(config), "unreadable")
                check("an untouched file beside it is still taken",
                      "kept.c" in taken, True)
                if swapped_fifo:
                    check("a file replaced by a FIFO is refused, not waited on",
                          ("piped.c" in taken, why.get("piped.c")),
                          (False, "unreadable"))
        else:
            rl.skip_case("a parent swapped for a link between discovery and copy", n=4)

    # ---- a link at, or under, the run directory ---- #
    #
    # The run directory is inside the scanned tree, and a repository may commit
    # one - the ledger lives there. Every one of these used to exit 0: the first
    # hid src/ from the snapshot as `run-directory` and wrote the manifest into
    # it, the second copied the tree out of the root, and the planted .tmp link
    # had its target truncated and overwritten with the manifest.
    if not links:
        rl.skip_case("a link at, or under, the run directory (ten checks)", n=10)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            outside = os.path.join(tmp, "outside")
            victim = os.path.join(outside, "victim.txt")
            write(victim, "VICTIM\n")

            def refusal(root):
                try:
                    build(root, RUN_DIR_NAME)
                except SnapshotError as exc:
                    return str(exc)
                return ""

            root = os.path.join(tmp, "into-src")
            write(os.path.join(root, "src", "main.c"), "int main(void) { return 0; }\n")
            write(os.path.join(root, "README"), "hello\n")
            os.symlink("src", os.path.join(root, RUN_DIR_NAME))
            said = refusal(root)
            check("a committed `.security-review -> src` is refused, not followed",
                  (said.startswith("--out:"), "symlink" in said,
                   "§9 rule 2" in said), (True, True, True))
            check("and nothing was written into src/",
                  sorted(os.listdir(os.path.join(root, "src"))), ["main.c"])
            check("and the command exits 2, as for any unusable --out",
                  quiet_main(["--root", root, "--quiet"]), 2)

            root = os.path.join(tmp, "out-of-root")
            write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
            away = os.path.join(outside, "away")
            os.makedirs(away)
            os.symlink(away, os.path.join(root, RUN_DIR_NAME))
            check("a run directory linked out of the root is refused",
                  refusal(root).startswith("--out:"), True)
            check("and nothing landed outside the root", os.listdir(away), [])

            root = os.path.join(tmp, "planted-tmp")
            write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
            os.makedirs(os.path.join(root, RUN_DIR_NAME))
            os.symlink(victim, os.path.join(root, RUN_DIR_NAME,
                                            MANIFEST_NAME + ".tmp"))
            build(root, RUN_DIR_NAME)
            check("a planted `<manifest>.tmp` link is never written through",
                  read(victim), "VICTIM\n")
            check("and the manifest is a regular file of our own",
                  os.path.islink(os.path.join(root, RUN_DIR_NAME, MANIFEST_NAME)),
                  False)

            root = os.path.join(tmp, "linked-manifest")
            write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
            os.makedirs(os.path.join(root, RUN_DIR_NAME))
            os.symlink(victim, os.path.join(root, RUN_DIR_NAME, MANIFEST_NAME))
            check("a link AT a file this tool writes is refused",
                  (refusal(root).startswith("--out:"), read(victim)),
                  (True, "VICTIM\n"))

            root = os.path.join(tmp, "dangling-gitignore")
            write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
            os.makedirs(os.path.join(root, RUN_DIR_NAME))
            created = os.path.join(outside, "created-by-gitignore")
            os.symlink(created, os.path.join(root, RUN_DIR_NAME, ".gitignore"))
            check("a dangling .gitignore link is refused, and creates nothing",
                  (refusal(root).startswith("--out:"), os.path.lexists(created)),
                  (True, False))

            clean = os.path.join(tmp, "clean")
            write(os.path.join(clean, "a.c"), "int a(void) { return 1; }\n")
            os.symlink(clean, os.path.join(tmp, "via-link"))
            check("--root may itself be a link: only what is BELOW it is checked",
                  build(os.path.join(tmp, "via-link"), RUN_DIR_NAME)["counts"]["files"],
                  1)

    # ---- a .gitignore that swallowed the ledger is given it back ---- #
    #
    # Stage 0 writes a bare `*`, and this tool wrote its own file only when none
    # existed, so a run that started at stage 0 left the ledger ignored for good
    # and `ledger.py check` failed every stage-5 session.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
        ignore = os.path.join(root, RUN_DIR_NAME, ".gitignore")
        write(ignore, "*\n")
        build(root, RUN_DIR_NAME)
        body = read(ignore)
        lines = body.split("\n")
        check("a stage-0 `*` gets the ledger carved back out, after the `*`",
              ("!.gitignore" in lines, "!ledger/" in lines, "!ledger/**" in lines,
               "!ledger/" in lines and lines.index("!ledger/") > lines.index("*")),
              (True, True, True, True))
        check("by appending, not by overwriting", body.startswith("*\n"), True)
        build(root, RUN_DIR_NAME)
        check("and a repaired file is not repaired twice", read(ignore), body)

        custom = "# mine\n*\n!.gitignore\n!ledger\n!ledger/**\nscratch/\n"
        write(ignore, custom)
        build(root, RUN_DIR_NAME)
        check("an operator's file that already keeps the ledger is left alone",
              read(ignore), custom)

        # Under `*`, `!ledger` gives back the directory and none of the files
        # in it, `!ledger/**` alone gives back nothing, and a carve-out before
        # the `*` is undone by it. Any one line used to count, and the ledger
        # stayed ignored while this said it was kept - checked against git.
        for label, body in (
                ("an operator's `!ledger` alone",
                 "# mine\n*\n!.gitignore\n!ledger\nscratch/\n"),
                ("`!ledger/` alone", "*\n!ledger/\n"),
                ("`!ledger/**` alone", "*\n!ledger/**\n"),
                ("`**` and `!ledger/`", "**\n!ledger/\n"),
                ("`!ledger/*`, which misses training/", "*\n!ledger/\n!ledger/*\n"),
                ("a carve-out the `*` comes after", "!ledger/\n!ledger/**\n*\n")):
            write(ignore, body)
            build(root, RUN_DIR_NAME)
            repaired = read(ignore)
            build(root, RUN_DIR_NAME)
            check("%s: the ledger is not kept, so the file is repaired, once" % label,
                  (repaired, read(ignore)), (body + GITIGNORE_REPAIR,) * 2)
        check("and the test is the lines after the last everything line",
              [ledger_carved_out(body.split("\n")) for body in (
                  "*\n!ledger/\n!ledger/**", "**\n!ledger\n!ledger/**",
                  "*\n!ledger/\n", "!ledger/\n!ledger/**\n*",
                  "*\n!ledger/**\n!ledger/\n*",
                  GITIGNORE.strip(), ("*\n" + GITIGNORE_REPAIR).strip())],
              [True, True, False, False, False, True, True])
        os.remove(ignore)
        build(root, RUN_DIR_NAME)
        check("and an absent one is written whole", read(ignore), GITIGNORE)

    # ---- the scanner's own folders are not the product ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        old = os.path.join(root, ".hostdir", "security-review", "tools")
        write(os.path.join(old, "rules_lib.py"), _rules_lib().TOOL_SIGNATURE + "\n")
        write(os.path.join(old, BYTECODE_DIR_NAME, "rules_lib.cpython-311.pyc"),
              "bytecode\n")
        write(os.path.join(root, ".hostdir", "settings.json"), "{}\n")
        write(os.path.join(root, ".hostdir", "skills", "other", "SKILL.md"), "---\n---\n")
        write(os.path.join(root, ".hostdir", "skills", "other", "tool.py"), "x = 1\n")
        write(os.path.join(root, ".hostdir", "skills", "build-helpers", "pay.c"), "int pay;\n")
        write(os.path.join(root, "src", "a.py"), "x = 1\n")
        write(os.path.join(root, "src", BYTECODE_DIR_NAME, "a.cpython-311.pyc"),
              "bytecode\n")
        manifest = build(root, RUN_DIR_NAME)
        taken = [f["path"] for f in manifest["files"]]
        check("an old copy of the scanner is not snapshotted",
              [p for p in taken if p.startswith(os.path.join(".hostdir", "security-review"))],
              [])
        check("and it is recorded under its own reason",
              reasons_for(manifest, os.path.join(".hostdir", "security-review")),
              ["scanner-tooling"])
        check("so is a skill installed in a dot folder's skills folder",
              (reasons_for(manifest, os.path.join(".hostdir", "skills", "other")),
               [p for p in taken
                if p.startswith(os.path.join(".hostdir", "skills", "other"))]),
              (["scanner-tooling"], []))
        check("but a folder there with no SKILL.md is the project's own code, taken",
              (reasons_for(manifest, os.path.join(".hostdir", "skills")),
               os.path.join(".hostdir", "skills", "build-helpers", "pay.c") in taken),
              ([], True))
        check("the dot folder's other files and the project's own bytecode are taken",
              (os.path.join(".hostdir", "settings.json") in taken,
               os.path.join("src", BYTECODE_DIR_NAME, "a.cpython-311.pyc") in taken),
              (True, True))

    # ---- --verify on a hand-edited manifest record ---- #
    #
    # A record missing a key, or not an object at all, raised KeyError or
    # TypeError out of main(): a traceback and exit 1, the code for "could not
    # be created", where a manifest that no longer describes its snapshot is
    # what exit 5 is for.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        write(os.path.join(root, "a.c"), "int a(void) { return 1; }\n")
        write(os.path.join(root, "b.c"), "int b(void) { return 2; }\n")
        manifest = build(root, RUN_DIR_NAME)
        out_dir = os.path.join(root, RUN_DIR_NAME)
        good = manifest["files"]

        def verify_edited(files):
            _write(os.path.join(out_dir, MANIFEST_NAME),
                   json.dumps(dict(manifest, files=files)) + "\n")
            try:
                return verify(out_dir)
            except Exception as exc:                   # noqa: BLE001
                return ["CRASHED %r" % exc]

        def without(record, key):
            record = dict(record)
            del record[key]
            return record

        shapes = [
            ("a record with no sha256", [without(good[0], "sha256"), good[1]]),
            ("a record with no path", [without(good[0], "path"), good[1]]),
            ("a record that is not an object", ["x", good[1]]),
            ("a record whose size is a string",
             [dict(good[0], bytes=str(good[0]["bytes"])), good[1]]),
            ("a sha256 of null", [dict(good[0], sha256=None), good[1]]),
            ("a path holding a NUL byte", [dict(good[0], path="a\0.c"), good[1]]),
            ("a file list that is not a list", 5),
        ]
        for label, files in shapes:
            problems = verify_edited(files)
            check("--verify reports %s as a problem, not a traceback" % label,
                  (any(p.startswith("CRASHED") for p in problems),
                   any("malformed" in p or "not a list" in p for p in problems)),
                  (False, True))
        problems = verify_edited([without(good[0], "sha256"), good[1]])
        check("and the record it could not check is not ALSO absent from the manifest",
              [p for p in problems if "absent from the manifest" in p], [])
        check("and the command exits 5, not 1",
              quiet_main(["--root", root, "--verify", "--quiet"]), 5)
        verify_edited(good)
        check("the unedited list still verifies", verify(out_dir), [])

    # ---- the two drift guards ---- #
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import extract_functions
    except ImportError as exc:                          # pragma: no cover
        print("  skip drift guards: extract_functions did not import (%s)" % exc)
    else:
        check("the .gitignore text matches stage 1's, byte for byte",
              GITIGNORE, extract_functions.GITIGNORE)
        cases = [("vendor/x.c", ["vendor"]), ("src/a.c", ["vendor"]),
                 ("a/b/c.c", ["a/b"]), ("x.iso", ["*.iso"]),
                 ("deep/node_modules/q.js", ["node_modules"]),
                 ("srcx/a.c", ["src"])]
        check("is_excluded agrees with stage 1's on every case",
              [is_excluded(rel, pats) for rel, pats in cases],
              [extract_functions.is_excluded(rel, pats) for rel, pats in cases])
        # `rel` comes off os.path.relpath, which has backslashes on Windows, and the patterns are
        # written with "/": a multi-segment directory exclude (`src/legacy`, `src/legacy/`)
        # matched nothing there, and only `src/legacy/*` and single names did. Both copies
        # compare with "/" on both sides; os.sep is set to the Windows one for the call.
        windows = [("src\\legacy\\a.c", ["src/legacy"]), ("src\\legacy\\a.c", ["src/legacy/"]),
                   ("src\\legacy\\a.c", ["src/legacy/*"]), ("src\\legacy\\a.c", ["legacy"]),
                   ("src\\legacy\\a.c", ["src\\legacy"]), ("src\\legacyx\\a.c", ["src/legacy"]),
                   ("src\\other\\a.c", ["src/legacy"])]
        real_sep = os.sep
        os.sep = "\\"
        try:
            here = [is_excluded(rel, pats) for rel, pats in windows]
            there = [extract_functions.is_excluded(rel, pats) for rel, pats in windows]
        finally:
            os.sep = real_sep
        check("a multi-segment directory exclude matches a path written with backslashes",
              here, [True, True, True, True, True, False, False])
        check("and stage 1's copy gives the same answers", there, here)

    print("\nselftest: %d failure(s)%s" % (failures[0], rl.skipped_note()))
    return 1 if failures[0] else 0


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def build_parser():
    ap = argparse.ArgumentParser(
        description="Freeze the working tree into .security-review/snapshot/ so "
                    "every downstream file:line points at bytes that cannot move.")
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--out", default=RUN_DIR_NAME,
                    help="run directory (default: %s under --root)" % RUN_DIR_NAME)
    ap.add_argument("--exclude", action="append", default=[], metavar="PATH",
                    help="exclude a path or glob from the SNAPSHOT (repeatable). "
                         "Only .git and the run directory are excluded by default")
    ap.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES,
                    help="stop admitting after this many files (default: %d)"
                         % DEFAULT_MAX_FILES)
    ap.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES,
                    help="stop admitting once this total is reached (default: %d)"
                         % DEFAULT_MAX_BYTES)
    ap.add_argument("--verify", action="store_true",
                    help="re-hash an existing snapshot against its manifest and exit")
    ap.add_argument("--quiet", action="store_true", help="only report problems")
    ap.add_argument("--selftest", action="store_true",
                    help="run the fixtures and exit")
    return ap


# The run-directory gate, rules_lib.run_dir_gate: nothing under .security-review/
# is read while git says the scanned repository commits anything there but
# .gitignore and ledger/. This tool imports nothing from the skill, so it runs
# the gate as a process of its own - `-I`, which imports the standard library
# and nothing else, and `-B`, which leaves no bytecode in the scanned tree - and
# takes anything but a clean pass as a refusal: a gate that could not run has
# not said the directory is safe. tests/test_contract_parity.py holds every copy of this
# function to the same text.
EXIT_SHIPPED = 7


def _run_dir_gate(root):
    """(None, result) when the run directory may be read, else (refusal, result)."""
    gate = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules_lib.py")
    try:
        ran = subprocess.run([sys.executable, "-B", "-I", gate, "--check-run-dir",
                              "--root", os.path.abspath(root), "--json"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return ("REFUSED: the run-directory check could not run (%s: %s), so "
                "nothing under .security-review/ is read. (exit %d)"
                % (gate, exc, EXIT_SHIPPED)), None
    try:
        result = json.loads(ran.stdout.decode("utf-8"))
    except ValueError:
        result = None
    if ran.returncode == 0 and isinstance(result, dict):
        return None, result
    said = ran.stderr.decode("utf-8", "replace").strip()
    return (said or "REFUSED: the run-directory check exited %d without saying why, "
            "so nothing under .security-review/ is read. (exit %d)"
            % (ran.returncode, EXIT_SHIPPED)), result


def main():
    args = build_parser().parse_args()
    if args.selftest:
        return selftest()

    root = os.path.realpath(args.root)
    if not os.path.isdir(root):
        print("%s: not a directory" % args.root, file=sys.stderr)
        return 2

    # Before anything under the run directory is read (_run_dir_gate).
    refusal, _gate = _run_dir_gate(root)
    if refusal:
        print(refusal, file=sys.stderr)
        return EXIT_SHIPPED

    # An --exclude typed from the folder that holds the repository
    # (`payments-api/private`) matches nothing, and the path the operator said
    # must not be copied is copied. Same rule as extract_functions.root_prefixed.
    name = os.path.basename(root)
    for value in args.exclude or []:
        text = value.replace("\\", "/")
        while text.startswith("./"):
            text = text[2:]
        head, _, rest = text.partition("/")
        if head == name and not os.path.isdir(os.path.join(root, name)):
            print("--exclude: %r starts with the repository's own name. Paths are "
                  "relative to --root %s, not to the folder holding it: write %r"
                  % (value, name, rest or "."), file=sys.stderr)
            return 2

    if args.verify:
        try:
            out_dir = check_out_dir(root, args.out)
            problems = verify(out_dir)
        except SnapshotError as exc:
            print("%s" % exc, file=sys.stderr)
            return 2 if str(exc).startswith("--out:") else 1
        # Stated, never silently assumed: the manifest may have been written
        # somewhere else. verify() hashes what is here, so say so.
        here = os.path.join(out_dir, SNAPSHOT_DIR_NAME)
        recorded = (_read_manifest(os.path.join(out_dir, MANIFEST_NAME))
                    or {}).get("snapshot_root")
        if recorded and os.path.normpath(recorded) != os.path.normpath(here):
            print("note: this snapshot was written at %s and is being verified "
                  "at %s; the id is derived from bytes and relative paths, so a "
                  "move does not invalidate it" % (recorded, here),
                  file=sys.stderr)
        if problems:
            print("%d problem(s) verifying the snapshot%s:"
                  % (len(problems),
                     ", first 25" if len(problems) > 25 else ""),
                  file=sys.stderr)
            for line in problems[:25]:
                print("  %s" % line, file=sys.stderr)
            return 5
        if not args.quiet:
            print("snapshot verifies against %s" % MANIFEST_NAME)
        return 0

    try:
        manifest = build(root, args.out, args.exclude, args.max_files,
                         args.max_bytes)
    except SnapshotError as exc:
        print("%s" % exc, file=sys.stderr)
        return 2 if str(exc).startswith("--out:") else 1
    except OSError as exc:
        print("%s" % exc, file=sys.stderr)
        return 1

    counts, caps = manifest["counts"], manifest["caps"]
    if not args.quiet:
        print("snapshot %s: %d file(s), %d byte(s) -> %s"
              % (manifest["snapshot_id"], counts["files"], counts["bytes"],
                 manifest["snapshot_root"]))
        by_reason = {}
        for entry in manifest["exclusions"]:
            by_reason[entry["reason"]] = by_reason.get(entry["reason"], 0) + 1
        print("excluded: %d path(s)%s"
              % (counts["excluded"],
                 " - " + ", ".join("%s %d" % (r, n)
                                   for r, n in sorted(by_reason.items()))
                 if by_reason else ""))

    if counts["copy_failed"]:
        # Ahead of the cap check and of the movement check, because this is the
        # one incompleteness that is OUR fault. A cap is a policy the operator
        # set; a failed write is a machine that could not do the job, and the
        # operator has to know which of the two they are looking at.
        failed = [e for e in manifest["exclusions"] if e["reason"] == "copy-failed"]
        print("INCOMPLETE: %d file(s) could not be written into the snapshot - "
              "this is the scanning machine, not the tree being scanned (%s%s). "
              "They are recorded as `copy-failed` exclusions; this snapshot is "
              "not the whole tree and must not be reported as one"
              % (counts["copy_failed"],
                 "; ".join("%s: %s" % (e["path"], e["detail"]) for e in failed[:3]),
                 ", ... - %s names all %d" % (MANIFEST_NAME, len(failed))
                 if len(failed) > 3 else ""), file=sys.stderr)
        return 4
    if caps["hit"]:
        print("INCOMPLETE: the %s cap was reached at %s. %d path(s) were kept "
              "out and are recorded as exclusions; this snapshot is not the "
              "whole tree and must not be reported as one"
              % (caps["hit"], caps["stopped_at"],
                 sum(1 for e in manifest["exclusions"]
                     if e["reason"].startswith("cap-"))), file=sys.stderr)
        return 4
    if counts["changed_during_snapshot"]:
        moved_paths = [m["path"] for m in manifest["changed_during_snapshot"]]
        print("the tree moved under the run: %d file(s) changed between "
              "discovery and the copy (%s%s). The snapshot holds the bytes that "
              "were read and hashed, so it is coherent - but it is not a "
              "picture of one instant"
              % (counts["changed_during_snapshot"],
                 ", ".join(moved_paths[:5]),
                 ", ... - %s names all %d" % (MANIFEST_NAME, len(moved_paths))
                 if len(moved_paths) > 5 else ""),
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
