#!/usr/bin/env python3
"""Security-Skills installer.

Usage:
    python3 -I -B install.py <harness> <target>
                        [--skill <name>[,<name>...]] [--source <repo-root>]

Positional arguments:
    <harness>   One of: claude, kiro, vibe, opencode, cursor, codex,
                copilot, agents, cline, gemini, qwen. `agents` is the shared
                `.agents/skills/` store read by most hosts; Claude Code and
                Kiro need their own.
    <target>    Installation scope. `~` (or the home directory) installs
                into the harness's global discovery path; any other path
                is treated as a project root and the harness's project
                discovery path under that root is used.

Options:
    --skill <names>   Comma-separated list of skills to install
                      (default: all of them). Run with --help to list the
                      skills available in the source tree.
    --source <repo-root>  Repository root holding `skills/`
                          (default: this script's directory).

Examples:
    python3 install.py vibe ~                     # all skills, global for Vibe
    python3 install.py kiro ~/work/my-project     # all skills, project .kiro/
    python3 install.py claude ~/work/my-project --skill report-triage
    python3 install.py agents ~/work/my-project --skill report-triage,sbom-recovery

What it does:
    Copies every skill (a folder holding a SKILL.md) under the repository's
    `skills/` tree into the chosen harness's skill discovery directory.
    Bytecode caches (`__pycache__`, `*.pyc`) are not copied. Files that already exist
    under the destination are overwritten only for the skill folders being
    installed; unrelated content in the destination is left untouched.
    Nothing is deleted; the source tree is never modified.

Exit codes:
    0 success · 1 usage error · 2 harness/target unsupported · 3 failure
"""

import argparse
import shutil
import sys
from pathlib import Path

# harness -> (project skill dir, global skill dir, notes)
# Notes are printed after a successful install; they state each harness's
# caveats.
HARNESSES = {
    "claude": (
        ".claude/skills",
        ".claude/skills",
        "Claude Code does NOT read `.agents/skills/`; it reads `.claude/skills/`\n"
        "(project, cwd up to the repo root) and `~/.claude/skills/`. Skills are\n"
        "picked up live; run /reload-skills if the folder was created\n"
        "mid-session.",
    ),
    "kiro": (
        ".kiro/skills",
        ".kiro/skills",
        "Kiro loads `.kiro/skills/` and `~/.kiro/skills/` (IDE and CLI). The\n"
        "default agent sees skills automatically; a custom agent only when its\n"
        "profile lists \"resources\": [\"skill://.kiro/skills/**/SKILL.md\"].",
    ),
    "vibe": (
        ".agents/skills",
        ".agents/skills",
        "Mistral Vibe reads `.agents/skills/` (and `.vibe/skills/`) only in\n"
        "TRUSTED folders: answer the trust prompt on first launch, or the\n"
        "skills are silently skipped. Globally it reads `~/.agents/skills/`.",
    ),
    "opencode": (
        ".agents/skills",
        ".agents/skills",
        "OpenCode reads `.agents/skills/` (cwd up to the worktree) and\n"
        "`~/.agents/skills/`, next to its own `.opencode/skills/`. Restart it\n"
        "after installing. The frontmatter `name` matches the folder name.",
    ),
    "cursor": (
        ".cursor/skills",
        ".cursor/skills",
        "Cursor (2.4+) reads `.cursor/skills/` and `~/.cursor/skills/` (and\n"
        "also `.agents/skills/`). It ignores the `license` and\n"
        "`compatibility` frontmatter fields.",
    ),
    "codex": (
        ".agents/skills",
        ".agents/skills",
        "Codex CLI scans `.agents/skills/` from the working directory up to\n"
        "the project root and `~/.agents/skills/` globally (`~/.codex/skills/`\n"
        "is deprecated). Restart Codex if a new skill does not show up.",
    ),
    "copilot": (
        ".agents/skills",
        ".agents/skills",
        "GitHub Copilot (CLI, cloud agent, VS Code) reads `.agents/skills/`\n"
        "and `~/.agents/skills/`; the first skill found under a name wins.",
    ),
    "agents": (
        ".agents/skills",
        ".agents/skills",
        "The shared Agent Skills store, read by Codex, Copilot, VS Code,\n"
        "Cursor, Gemini CLI, Vibe, OpenCode, Cline, Qwen Code and\n"
        "Devin/Windsurf, but NOT by Claude Code (use `claude`) and not\n"
        "confirmed for Kiro (use `kiro`).",
    ),
    "cline": (
        ".agents/skills",
        ".agents/skills",
        "Cline reads `.agents/skills/` and `~/.agents/skills/` (next to\n"
        "`.cline/skills/`); a global skill wins over a project one of the\n"
        "same name. Each skill can be toggled on/off in Cline.",
    ),
    "gemini": (
        ".agents/skills",
        ".agents/skills",
        "Gemini CLI reads `.agents/skills/` (alias of `.gemini/skills/`) and\n"
        "`~/.agents/skills/`. Workspace skills load only in TRUSTED folders;\n"
        "activation asks for consent. `/skills reload` after installing.",
    ),
    "qwen": (
        ".agents/skills",
        ".agents/skills",
        "Qwen Code reads `.agents/skills/` and `~/.agents/skills/` (next to\n"
        "`.qwen/skills/`).",
    ),
    "muse": (
        ".agents/skills",
        ".agents/skills",
        "Muse Code reads `.agents/skills/` and `~/.agents/skills/`.",
    ),
}

GLOBAL_HINT = "global"
PROJECT_HINT = "project"


def fail(code, message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(code)


def normalize_harness(name):
    aliases = {
        "claude-code": "claude",
        "mistral-vibe": "vibe",
        "codex-cli": "codex",
        "openclaw": "agents",
    }
    key = name.strip().lower()
    return aliases.get(key, key)


SKIP_NAMES = {"__pycache__", ".DS_Store"}
SKIP_SUFFIXES = {".pyc", ".pyo"}


def available_skills(skills_dir):
    """Sorted names of the skill folders (folders holding a SKILL.md) under skills_dir."""
    return sorted(p.name for p in skills_dir.iterdir() if p.is_dir() and (p / "SKILL.md").is_file())


def parse_args(argv):
    repo_root = Path(__file__).resolve().parent
    default_skills = available_skills(repo_root / "skills") if (repo_root / "skills").is_dir() else []
    parser = argparse.ArgumentParser(
        prog="install.py",
        description="Install Security-Skills into a harness's discovery path.",
        epilog=(
            "harness types: "
            + ", ".join(sorted(HARNESSES))
            + "\ninstallable skills: "
            + (", ".join(default_skills) if default_skills else "(none found next to this script; pass --source)")
            + "\n\nexamples:\n"
            "  python3 install.py vibe ~\n"
            "  python3 install.py kiro ~/work/my-project\n"
            "  python3 install.py claude ~/work/my-project --skill report-triage,sbom-recovery\n"
            "  python3 install.py agents ~                  # shared store for most hosts"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "harness",
        metavar="harness",
        help="harness type: " + ", ".join(sorted(HARNESSES)),
    )
    parser.add_argument(
        "target",
        metavar="target",
        help="`~` for global install, or a project root path",
    )
    parser.add_argument(
        "--skill",
        default=None,
        metavar="NAMES",
        help="comma-separated skills to install (default: all). Available: "
        + (", ".join(default_skills) if default_skills else "(see --source)"),
    )
    parser.add_argument(
        "--source",
        default=None,
        help="repository root holding skills/ (default: this script's folder)",
    )
    args = parser.parse_args(argv)

    key = normalize_harness(args.harness)
    if key not in HARNESSES:
        fail(2, f"unknown harness {args.harness!r}. valid: {', '.join(sorted(HARNESSES))}")
    args.harness = key

    args.target = Path(args.target).expanduser().resolve()
    if not args.target.is_dir():
        fail(1, f"target {str(args.target)!r} is not an existing directory")

    if args.source is None:
        args.source = Path(__file__).resolve().parent
    else:
        args.source = Path(args.source).expanduser().resolve()
    if not args.source.is_dir():
        fail(1, f"source {str(args.source)!r} is not an existing directory")
    skills_dir = args.source / "skills"
    if not skills_dir.is_dir():
        fail(3, f"no skills/ directory under {args.source} — nothing to install")
    installable = available_skills(skills_dir)
    if not installable:
        fail(3, f"{skills_dir} holds no skill folders — nothing to install")
    args.skills_dir = skills_dir

    if args.skill is None:
        args.selected = installable
    else:
        requested = [s.strip() for s in args.skill.split(",") if s.strip()]
        unknown = [s for s in requested if s not in installable]
        if unknown:
            fail(
                1,
                f"unknown skill(s): {', '.join(unknown)}. "
                f"available: {', '.join(installable)}",
            )
        args.selected = requested
    return args


def install_one_skill(skill_src, dest_root):
    """Copy one skill folder into dest_root/<skill-name>/.

    Overwrites files of the same skill that are already there; never touches
    anything else. Returns (name, files_copied).
    """
    dest = dest_root / skill_src.name
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted(skill_src.rglob("*")):
        rel = path.relative_to(skill_src)
        if any(part in SKIP_NAMES for part in rel.parts) or path.suffix in SKIP_SUFFIXES:
            continue
        if path.is_dir():
            (dest / path.relative_to(skill_src)).mkdir(parents=True, exist_ok=True)
            continue
        target = dest / path.relative_to(skill_src)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        count += 1
    return skill_src.name, count


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    project_rel, global_rel, notes = HARNESSES[args.harness]

    home = Path.home().resolve()
    if args.target == home:
        if global_rel is None:
            fail(
                2,
                f"{args.harness} has no global (user-level) skills directory; "
                "pass a project root instead",
            )
        mode = GLOBAL_HINT
        dest = home / global_rel
    else:
        mode = PROJECT_HINT
        dest = args.target / project_rel

    skills = [args.skills_dir / name for name in args.selected]
    print(f"Security-Skills -> {args.harness} ({mode})")
    print(f"  source: {args.skills_dir}")
    print(f"  destination: {dest}")
    print(f"  skills: {', '.join(args.selected)}")
    print()
    total = 0
    for skill in skills:
        name, count = install_one_skill(skill, dest)
        print(f"  installed {name} ({count} files)")
        total += count
    print()
    print(f"done: {len(skills)} skill(s), {total} file(s) installed.")
    print(notes)


if __name__ == "__main__":
    main()
