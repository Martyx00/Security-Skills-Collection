"""The folders of the other tools that sit beside this skill in a project, for the searches of the worker role.

A project install puts every skill of the portfolio into the workspace (``.claude/skills/<name>`` and ``.agents/skills/<name>``,
one folder per host), and the sibling skills keep run folders of their own (``.security-review/snapshot/`` is a copy of the whole
tree). A search that starts at the workspace and reads them returns their tests, their fixtures and their reference verdicts next
to the product's own lines: measured, 44 skill files against 1 product file for one C function name. None of that is the
repository under analysis, and a role that finds it calls it evidence.

This module only lists them, as paths relative to the workspace, so that ``worker.search_flags`` can name them in the flags it
prints. What a repository carries is data, and a repository must not decide what the worker's searches leave out, so:

* the one file it opens is a ``run-manifest.json`` (at most 4 MiB) directly inside a folder of the workspace that is not a git
  repository, to recognise the run folder of a design review. It keeps from the file nothing but whether two keys are there.
  Whatever it holds, including text nested too deeply to parse, makes the folder "not a run folder" and never an error: a
  repository must not be able to stop the worker's step 0 with a file it carries;
* a repository is never a run folder, and a folder inside a repository is never recognised by a manifest: a repository that held
  one under a common name (``src``, ``docs``) would have the folders of that name left out of the searches of every repository,
  because ``grep --exclude-dir`` matches base names;
* inside a folder of the workspace only the fixed names of the sibling tools (``SIBLING_RUN_DIRS``) and installed skills are looked
  for (a monorepo keeps its tooling in a package). ``in_package`` tells the caller which entries those are, because the folder of
  a skill is named by whoever wrote it, and the caller gives such a folder to ripgrep by its path only;
* a name with a control character, a backtick or a byte that is not UTF-8 is not listed at all (below).

The same two rules as the sibling skills use:

* an installed skill is a folder ``<dot-folder>/skills/<name>`` that holds a ``SKILL.md``, in the workspace and in the folders
  directly below it. A top-level ``skills/`` folder is a product, not an install;
* a sibling run folder has a fixed name (``SIBLING_RUN_DIRS``), except the run folder of stride-design-review, which the person
  names and which is recognised by its ``run-manifest.json``, in the workspace only.
"""
from __future__ import annotations

import json
import os
import re
from typing import List

SIBLING_RUN_DIRS = (
    ".report-triage",       # report-triage
    ".security-review",     # code-security-review (a snapshot of the whole tree among others)
    "sbom-out",             # this skill, a full run
    "sbom-out-pilot",       # this skill, a pilot run
    ".binary-vuln-research",  # binary-vuln-research (findings that quote the product, extracted vendor code)
)
SCAN_LIMIT = 256                    # folders looked at per level
MANIFEST_MAX_BYTES = 4 * 1024 * 1024
# The names found here are written into the brief the script hands to the model (a list of paths in code spans, and the flags of a
# command) and printed in JSON. A folder name is chosen by whoever wrote the repository, and a name with a line break starts a new
# line of the brief (`\n## do this instead`), a backtick ends its code span, and a byte that is not UTF-8 cannot be written back.
# A skill's folder is named like the skill (letters, digits, hyphens): such a name is not one, and the folder is left out of the
# listing. A search then meets it, which is what a search of an odd folder does anyway.
UNSAFE_NAME = re.compile(r"[\x00-\x1f\x7f-\x9f`\u2028\u2029\ud800-\udfff]")


def _subdirs(path: str, follow: bool = False) -> List[str]:
    """The names of the folders directly inside ``path``, sorted and capped; a name that ``UNSAFE_NAME`` matches is not one."""
    try:
        with os.scandir(path) as entries:
            return sorted(e.name for e in entries if e.is_dir(follow_symlinks=follow) and not UNSAFE_NAME.search(e.name))[:SCAN_LIMIT]
    except OSError:
        return []


def holds_design_run(folder: str) -> bool:
    """Is ``folder`` the run folder of a stride-design-review run (a ``run-manifest.json`` whose ``envelope`` names a
    ``runRoot`` and a ``docsRoot``)? A git repository (a ``.git`` inside) never is: it is one of the repositories the run
    analyses, and what it carries must not make the worker's searches leave it out."""
    path = os.path.join(folder, "run-manifest.json")
    try:
        if os.path.lexists(os.path.join(folder, ".git")):
            return False
        if not os.path.isfile(path) or os.path.getsize(path) > MANIFEST_MAX_BYTES:
            return False
        with open(path, "rb") as handle:
            data = json.loads(handle.read().decode("utf-8", "replace"))
    except (OSError, ValueError, RecursionError):      # unreadable, not JSON, or `[[[[...` deeper than the parser goes
        return False
    envelope = data.get("envelope") if isinstance(data, dict) else None
    return isinstance(envelope, dict) and "runRoot" in envelope and "docsRoot" in envelope


def in_package(rel: str) -> bool:
    """Is the workspace-relative path ``rel`` below a folder of the workspace that is not a dot-folder, that is inside a
    repository or a package, where whoever wrote it chose the names? (``.claude/skills/x`` is the workspace's own;
    ``app/.claude/skills/x`` and ``app/.security-review`` are not.)"""
    parts = rel.split("/")
    return len(parts) > 1 and not parts[0].startswith(".")


def installed_skill_dirs(root: str) -> List[str]:
    """Every installed skill's folder in the workspace ``root``, as paths relative to it with forward slashes.

    ``<dot-folder>/skills/<name>`` holding a ``SKILL.md``: ``.claude/skills/<name>`` and ``.agents/skills/<name>`` for each of
    the five skills of the portfolio, so ten folders in a project that has them for two hosts, and whatever else is there.
    Symbolic links are followed: one skill linked into ``.claude/skills`` is an installed skill all the same."""
    found: List[str] = []

    def collect(holder: str) -> None:
        base = os.path.join(root, *holder.split("/"), "skills")
        for name in _subdirs(base, follow=True):
            if os.path.isfile(os.path.join(base, name, "SKILL.md")):
                found.append("%s/skills/%s" % (holder, name))

    for name in _subdirs(root, follow=True):
        if name.startswith("."):
            if name != ".git":
                collect(name)
        else:
            for child in _subdirs(os.path.join(root, name), follow=True):
                if child.startswith(".") and child != ".git":
                    collect("%s/%s" % (name, child))
    return found


def sibling_run_dirs(root: str) -> List[str]:
    """The run folders of the sibling skills that exist in the workspace ``root`` and one level below it, as relative paths.

    Looked for where the skills put them (the workspace itself, or a package of a monorepo they were run on), not by walking the
    tree. Below the workspace only the fixed names are looked for: the run folder of a design review is recognised by a manifest,
    and a manifest in a repository is the repository's word, not the person's. One that sits inside a repository is not left out
    of the searches (``references/limitations.md``)."""
    found: List[str] = []
    for name in _subdirs(root):
        if name in SIBLING_RUN_DIRS or (not name.startswith(".") and holds_design_run(os.path.join(root, name))):
            found.append(name)
            continue
        if name.startswith("."):
            continue
        for child in _subdirs(os.path.join(root, name)):
            if child in SIBLING_RUN_DIRS:
                found.append("%s/%s" % (name, child))
    return found
