"""The hardened, read-only git wrapper (contract sections 3.5 and 6.7).

All git access to target repositories, to their submodule object stores and to the pack itself goes through
``run`` and the helpers built on it. ``run`` accepts only an allowlist of read-only plumbing subcommands and options,
starts git with a scrubbed environment and command-scope configuration that disables fsmonitor, hooks, filters,
the untracked cache, external diff, signature verification programs and every network protocol, and never lets git refresh
the index.

git itself is started by an absolute path found on the safe part of ``PATH`` (``safe_path``, ``resolve_git``): the child's
working directory is a target repository, so a relative or empty ``PATH`` entry must never be able to find a file that
the repository contains. Callers pass the environment to derive the child's from (``env=ctx.env``) and, when they have a
context, a timeout from ``budget_timeout(ctx)`` so that no call can outlive the command's budget.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from sbomlib import errors, norm
from sbomlib.context import Layout

MIN_GIT = (2, 25, 0)
ENV_CONFIG_MIN = (2, 31, 0)

_REV_RE = re.compile(r"^[A-Za-z0-9_./^{}~@:-]+$")
_DIGITS_RE = re.compile(r"^[0-9]{1,9}$")
_REF_PATTERN_RE = re.compile(r"^refs/[A-Za-z0-9_./*?@{}^~+-]*$")
_VERSION_RE = re.compile(r"git version (\d+)\.(\d+)(?:\.(\d+))?")
_CHECK_ATTRS = ("filter", "eol", "text", "crlf", "working-tree-encoding", "ident")
_MAX_CONFIG_ARG = 200
DEFAULT_TIMEOUT = 60.0
CHECK_ATTR_TIMEOUT = 75.0        # below the hard budget (80 s) and far below the 120 s terminal timeout (section 5.5)

# Command-scope configuration injected into every call (contract section 6.7). Later entries override earlier ones.
# The gpg.*.program entries stop a repository-configured program from running when git verifies a signature (the
# for-each-ref %(signature...) atoms); the allowlist refuses those atoms as well, this is the second layer.
CONFIG_OVERRIDES: Tuple[Tuple[str, str], ...] = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", os.devnull),
    ("core.untrackedCache", "false"),
    ("protocol.allow", "never"),
    ("diff.external", ""),
    ("log.showSignature", "false"),
    ("gc.auto", "0"),
    ("maintenance.auto", "false"),
    ("gpg.program", os.devnull),
    ("gpg.openpgp.program", os.devnull),
    ("gpg.x509.program", os.devnull),
    ("gpg.ssh.program", os.devnull),
)

# Atoms that for-each-ref may print or sort by. Everything else is refused; in particular the %(signature...) atoms and
# --sort=signature:... verify a commit signature and so run the program named by the repository's gpg.* configuration.
_REF_ATOMS = frozenset((
    "refname", "objectname", "objecttype", "objectsize", "object", "type", "tag", "symref",
    "creatordate", "creator", "taggerdate", "tagger", "taggeremail", "committerdate", "committer", "committeremail",
    "authordate", "author", "authoremail", "subject",
))
_ATOM_MODIFIERS_RE = re.compile(r"^[A-Za-z0-9=,_.-]+(?::[A-Za-z0-9=,_.-]+)*$")
_FORMAT_ATOM_RE = re.compile(r"%\(([^()]*)\)")
_HEX_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_version_cache: Dict[Tuple[str, int, int], Tuple[int, int, int]] = {}
_filter_cache: Dict[Tuple[str, str, Tuple[int, int], Tuple[str, str]], List[str]] = {}


@dataclass
class GitResult:
    args: List[str]
    returncode: int
    stdout: bytes
    stderr: bytes


# --------------------------------------------------------------------------------------------------- environment

def _base_env(base_env: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    source = os.environ if base_env is None else base_env
    return {key: value for key, value in source.items() if not key.upper().startswith("GIT_")}


def _is_inside(real: Path, base: Path) -> bool:
    return real == base or base in real.parents


def safe_path(path_value: Optional[str], parent: Optional[Path] = None) -> str:
    """``PATH`` reduced to its safe entries: absolute ones that are not inside the workspace folder ``parent``.

    Relative entries (``.``, ``bin``) and empty entries mean "the current directory" to many exec searches, and a
    child started with ``cwd`` inside a target repository would then run a file committed to that repository. A
    ``None`` value stands for the platform default search path.
    """
    text = os.defpath if path_value is None else str(path_value)
    base = _resolved(parent) if parent is not None else None
    keep: List[str] = []
    for entry in text.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        if base is not None and _is_inside(_resolved(entry), base):
            continue
        keep.append(entry)
    return os.pathsep.join(keep)


def find_executable(name: str, env: Optional[Mapping[str, str]] = None, parent: Optional[Path] = None) -> Optional[str]:
    """Absolute path of ``name`` found on the safe part of ``env['PATH']`` (see ``safe_path``), or None.

    A result whose real path lies inside ``parent`` (a symlink into a target, say) is refused: binaries and scripts from
    the targets are never executed.
    """
    source = os.environ if env is None else env
    safe = safe_path(source.get("PATH"), parent)
    if not safe:
        return None                                  # never fall back to the process PATH (shutil.which(path=None))
    found = shutil.which(name, path=safe)
    if not found or not os.path.isabs(found):
        return None
    if parent is not None and _is_inside(_resolved(found), _resolved(parent)):
        return None
    return found


def resolve_git(env: Optional[Mapping[str, str]] = None, parent: Optional[Path] = None) -> str:
    """The absolute path git is started with. ``GitMissing`` when it is not on the safe part of ``PATH``."""
    exe = find_executable("git", env, parent)
    if exe is None:
        raise errors.GitMissing("git was not found on PATH")
    return exe


def config_pairs(filter_drivers: Sequence[str]) -> List[Tuple[str, str]]:
    """The hardening ``key=value`` pairs, including the blanked filter drivers."""
    pairs = list(CONFIG_OVERRIDES)
    for name in sorted(set(filter_drivers)):
        for variable, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")):
            pairs.append(("filter.%s.%s" % (name, variable), value))
    return pairs


def uses_env_config(version: Optional[Tuple[int, int, int]] = None) -> bool:
    """True when this git reads GIT_CONFIG_COUNT (2.31+); older versions get ``-c key=value`` pairs."""
    return (version or git_version()) >= ENV_CONFIG_MIN


def hardened_env(base_env: Mapping[str, str], filter_drivers: Sequence[str], *, parent: Optional[Path] = None,
                 env_config: Optional[bool] = None) -> Dict[str, str]:
    """Environment for a git child process.

    Starts from ``base_env`` minus every variable beginning with ``GIT_`` (HOME, XDG_CONFIG_HOME and PATH are kept, so
    the global and system configuration stay readable for ``safe.directory``), then sets the variables of contract
    section 6.7. ``parent`` adds ``GIT_CEILING_DIRECTORIES``; ``env_config`` (default: git >= 2.31) adds the
    ``GIT_CONFIG_COUNT``/``KEY``/``VALUE`` command-scope configuration.
    """
    env = _base_env(base_env)
    env.update({
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_ASKPASS": "",
        "SSH_ASKPASS": "",
        "GIT_PAGER": "cat",
        "PAGER": "cat",
        "LC_ALL": "C",
        "LANG": "C",
    })
    if "PATH" in env:
        cleaned = safe_path(env["PATH"], parent)
        if cleaned:
            env["PATH"] = cleaned
        else:
            del env["PATH"]               # an empty PATH means "the current directory" to some exec searches
    if parent is not None:
        env["GIT_CEILING_DIRECTORIES"] = str(parent)
    if env_config is None:
        env_config = uses_env_config()
    if env_config:
        pairs = config_pairs(filter_drivers)
        env["GIT_CONFIG_COUNT"] = str(len(pairs))
        for index, (key, value) in enumerate(pairs):
            env["GIT_CONFIG_KEY_%d" % index] = key
            env["GIT_CONFIG_VALUE_%d" % index] = value
    return env


def _exe_signature(exe: str) -> Tuple[str, int, int]:
    try:
        st = os.stat(exe)
    except OSError:
        return (exe, 0, 0)
    return (exe, st.st_mtime_ns, st.st_size)


def _probe_version(exe: str, env: Optional[Mapping[str, str]], parent: Optional[Path]) -> Tuple[int, int, int]:
    child_env = _base_env(env)
    child_env.update({"LC_ALL": "C", "LANG": "C", "GIT_TERMINAL_PROMPT": "0"})
    child_env["PATH"] = safe_path(child_env.get("PATH"), parent)
    try:
        proc = subprocess.run([exe, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=child_env, timeout=15)
    except FileNotFoundError as exc:
        raise errors.GitMissing("git was not found on PATH") from exc
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise errors.GitMissing("git could not be started: %s" % exc) from exc
    text = proc.stdout.decode("utf-8", "surrogateescape")
    match = _VERSION_RE.search(text)
    if proc.returncode != 0 or not match:
        raise errors.GitMissing("git --version gave an unexpected answer: %s" % text.strip()[:100])
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def _cached_version(env: Optional[Mapping[str, str]], parent: Optional[Path],
                    exe: Optional[str] = None) -> Tuple[int, int, int]:
    """Version of the git that ``env``'s PATH resolves to, probed once per executable (path, mtime, size)."""
    exe = exe or resolve_git(env, parent)
    key = _exe_signature(exe)
    version = _version_cache.get(key)
    if version is None:
        version = _probe_version(exe, env, parent)
        _version_cache[key] = version
    return version


def git_version(env: Optional[Mapping[str, str]] = None, *, refresh: bool = False,
                parent: Optional[Path] = None) -> Tuple[int, int, int]:
    """Version of the git that ``env`` (default: the process environment) resolves to. Raises ``GitMissing``.

    git is started by its absolute path found on the safe part of ``PATH`` (``safe_path``, ``resolve_git``), never by a
    bare name. Without ``env`` the answer is cached per executable; an explicit ``env`` (the selfcheck probe) or
    ``refresh=True`` is probed fresh and leaves the cache alone.
    """
    if env is None:
        if refresh:
            _version_cache.pop(_exe_signature(resolve_git(None, parent)), None)
        return _cached_version(None, parent)
    return _probe_version(resolve_git(env, parent), env, parent)


def reset_caches() -> None:
    """Forget the cached git versions and filter-driver lists (tests)."""
    _version_cache.clear()
    _filter_cache.clear()


def blob_sha1(data: bytes) -> str:
    """The git blob id of ``data``."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


# --------------------------------------------------------------------------------------------------- allowlist

def _forbidden(args: Sequence[str], why: str) -> errors.GitForbidden:
    return errors.GitForbidden("git %s is not allowed: %s" % (" ".join(args[:3]), why), args=list(args))


def _is_rev(token: str) -> bool:
    return bool(token) and not token.startswith("-") and bool(_REV_RE.match(token))


def _config_text_ok(text: str) -> bool:
    return bool(text) and not text.startswith("-") and "\x00" not in text and len(text) <= _MAX_CONFIG_ARG


def _split_paths(args: List[str], index: int) -> Tuple[List[str], List[str]]:
    """Split at the first literal '--': (before, pathspecs). Pathspecs must be safe relative paths."""
    if "--" in args[index:]:
        pos = args.index("--", index)
        before, after = args[index:pos], args[pos + 1:]
        for spec in after:
            if not norm.is_safe_relative_path(spec):
                raise _forbidden(args, "unsafe pathspec %r" % (spec,))
        return before, after
    return args[index:], []


def validate_args(args: Sequence[str], *, has_input: bool = False) -> List[str]:
    """Check ``args`` against the allowlist of contract section 6.7; ``GitForbidden`` on anything else."""
    items = [a for a in args]
    if not items or not all(isinstance(a, str) for a in items):
        raise errors.GitForbidden("git arguments must be a non-empty list of strings", args=list(map(str, items)))
    if any("\x00" in a for a in items):
        raise _forbidden(items, "NUL byte in an argument")
    sub = items[0]
    if sub == "--version":
        if len(items) != 1:
            raise _forbidden(items, "--version takes no arguments")
        return items
    if sub.startswith("-"):
        raise _forbidden(items, "global options are not allowed")
    handler = _HANDLERS.get(sub)
    if handler is None:
        raise _forbidden(items, "subcommand %r is not on the allowlist" % sub)
    handler(items, has_input)
    return items


def _check_options(items: List[str], allowed: Sequence[str], start: int = 1, extra_ok: Any = None) -> List[str]:
    """Return the positional tokens of items[start:] after accepting only ``allowed`` options (and ``extra_ok``)."""
    positional: List[str] = []
    for token in items[start:]:
        if token.startswith("-") and token != "--":
            if token in allowed or (extra_ok is not None and extra_ok(token)):
                continue
            raise _forbidden(items, "option %r is not allowed" % token)
        positional.append(token)
    return positional


def _v_rev_parse(items: List[str], has_input: bool) -> None:
    allowed = ("--verify", "-q", "--quiet", "--abbrev-ref", "--short", "--symbolic-full-name", "--git-dir",
               "--git-common-dir", "--show-toplevel", "--is-inside-work-tree", "--is-shallow-repository")
    before, paths = _split_paths(items, 1)
    positional = _check_options(["rev-parse"] + before, allowed, 1,
                                lambda t: bool(re.match(r"^--short=[0-9]{1,2}$", t)))
    for token in positional:
        if not _is_rev(token):
            raise _forbidden(items, "invalid revision token %r" % token)


def _v_ls_files(items: List[str], has_input: bool) -> None:
    allowed = ("-z", "--recurse-submodules", "-s", "--stage", "--cached", "-o", "--others", "--directory", "-i",
               "--ignored", "--exclude-standard", "--full-name")
    before, _ = _split_paths(items, 1)
    positional = _check_options(["ls-files"] + before, allowed)
    if positional:
        raise _forbidden(items, "ls-files takes pathspecs only after a literal '--'")


def _v_check_attr(items: List[str], has_input: bool) -> None:
    rest = items[1:]
    if "--stdin" not in rest:
        raise _forbidden(items, "check-attr requires --stdin")
    if "--" in rest:
        raise _forbidden(items, "check-attr paths must come from stdin")
    attrs = []
    for token in rest:
        if token in ("-z", "--stdin"):
            continue
        if token.startswith("-"):
            raise _forbidden(items, "option %r is not allowed" % token)
        attrs.append(token)
    if not attrs or any(a not in _CHECK_ATTRS for a in attrs):
        raise _forbidden(items, "check-attr attributes must be among %s" % ", ".join(_CHECK_ATTRS))
    if not has_input:
        raise _forbidden(items, "check-attr --stdin needs input_bytes")


def _v_ls_tree(items: List[str], has_input: bool) -> None:
    allowed = ("-r", "-z", "-t", "-l", "--long", "--name-only", "--full-tree", "--full-name")
    before, _ = _split_paths(items, 1)
    positional = _check_options(["ls-tree"] + before, allowed)
    if len(positional) != 1 or not _is_rev(positional[0]):
        raise _forbidden(items, "ls-tree needs exactly one tree-ish")


def _v_cat_file(items: List[str], has_input: bool) -> None:
    rest = items[1:]
    if len(rest) == 1 and rest[0] in ("--batch-check", "--batch"):
        return
    if len(rest) == 2 and rest[0] in ("-t", "-s", "-e", "-p", "blob", "tree", "commit", "tag") and _is_rev(rest[1]):
        return
    raise _forbidden(items, "cat-file allows only -t/-s/-e/-p or a type with one object, or --batch/--batch-check")


def _v_rev_list(items: List[str], has_input: bool) -> None:
    before, _ = _split_paths(items, 1)
    allowed = ("--count", "--first-parent", "--no-commit-header", "--format=%ct")
    positional: List[str] = []
    index = 0
    while index < len(before):
        token = before[index]
        if token == "-n":
            if index + 1 >= len(before) or not _DIGITS_RE.match(before[index + 1]):
                raise _forbidden(items, "-n needs a number")
            index += 2
            continue
        if token.startswith("-"):
            if token in allowed or re.match(r"^--max-count=[0-9]{1,9}$", token):
                index += 1
                continue
            raise _forbidden(items, "option %r is not allowed" % token)
        positional.append(token)
        index += 1
    for token in positional:
        if not _is_rev(token):
            raise _forbidden(items, "invalid revision token %r" % token)


def _atom_ok(atom: str) -> bool:
    """``name`` or ``name:modifier[:modifier]`` (optionally ``*name`` for the dereferenced object) of the atom allowlist."""
    if atom.startswith("*"):
        atom = atom[1:]
    name, _, modifiers = atom.partition(":")
    if name not in _REF_ATOMS:
        return False
    return not modifiers or bool(_ATOM_MODIFIERS_RE.match(modifiers))


def _ref_format_ok(fmt: str) -> bool:
    """A for-each-ref ``--format`` value: literal text, ``%%``, ``%xx`` and ``%(atom)`` with allowlisted atoms only."""
    pos = 0
    while True:
        index = fmt.find("%", pos)
        if index < 0:
            return True
        if fmt.startswith("%%", index):
            pos = index + 2
        elif fmt.startswith("%(", index):
            match = _FORMAT_ATOM_RE.match(fmt, index)
            if match is None or not _atom_ok(match.group(1)):
                return False
            pos = match.end()
        elif _HEX_ESCAPE_RE.match(fmt, index):
            pos = index + 3
        else:
            return False


def _ref_sort_ok(key: str) -> bool:
    """A for-each-ref ``--sort`` key: optional ``-``, optional ``version:``/``v:``, then an allowlisted atom."""
    if key.startswith("-"):
        key = key[1:]
    for prefix in ("version:", "v:"):
        if key.startswith(prefix):
            key = key[len(prefix):]
            break
    return _atom_ok(key)


def _v_for_each_ref(items: List[str], has_input: bool) -> None:
    for token in items[1:]:
        if token.startswith("--format="):
            if not _ref_format_ok(token[len("--format="):]):
                raise _forbidden(items, "for-each-ref --format may use only the atoms: %s" % ", ".join(sorted(_REF_ATOMS)))
            continue
        if token.startswith("--sort="):
            if not _ref_sort_ok(token[len("--sort="):]):
                raise _forbidden(items, "for-each-ref --sort may use only the atoms: %s" % ", ".join(sorted(_REF_ATOMS)))
            continue
        if token.startswith("--points-at="):
            if not _is_rev(token[len("--points-at="):]):
                raise _forbidden(items, "invalid --points-at revision")
            continue
        if re.match(r"^--count=[0-9]{1,9}$", token):
            continue
        if token.startswith("-"):
            raise _forbidden(items, "option %r is not allowed" % token)
        if not _REF_PATTERN_RE.match(token):
            raise _forbidden(items, "for-each-ref patterns must be under refs/")


def _v_config(items: List[str], has_input: bool) -> None:
    actions = 0
    scopes = 0
    positional: List[str] = []
    index = 1
    while index < len(items):
        token = items[index]
        if token in ("--get", "--get-all", "--get-regexp"):
            actions += 1
        elif token in ("-z", "--null"):
            pass
        elif token in ("--local", "--global", "--system"):
            scopes += 1
        elif token in ("-f", "--file", "--blob"):
            scopes += 1
            index += 1
            value = items[index] if index < len(items) else ""
            _check_config_value(items, token, value)
        elif token.startswith("--file=") or token.startswith("--blob="):
            scopes += 1
            _check_config_value(items, token.split("=", 1)[0], token.split("=", 1)[1])
        elif token.startswith("-"):
            raise _forbidden(items, "option %r is not allowed" % token)
        else:
            positional.append(token)
        index += 1
    if actions != 1:
        raise _forbidden(items, "config needs exactly one of --get, --get-all, --get-regexp")
    if scopes > 1:
        raise _forbidden(items, "config allows at most one of --local, --global, --system, --file, --blob")
    if len(positional) != 1 or not _config_text_ok(positional[0]):
        raise _forbidden(items, "config needs exactly one valid key or regexp")


def _check_config_value(items: List[str], option: str, value: str) -> None:
    if option in ("-f", "--file"):
        if not norm.is_safe_relative_path(value):
            raise _forbidden(items, "--file must be a repository-relative path")
    elif not _config_text_ok(value):
        raise _forbidden(items, "invalid --blob value")


def _v_describe(items: List[str], has_input: bool) -> None:
    allowed = ("--tags", "--always", "--long", "--exact-match")
    positional: List[str] = []
    for token in items[1:]:
        if token.startswith("-"):
            if token in allowed or re.match(r"^--abbrev=[0-9]{1,2}$", token) or re.match(r"^--candidates=[0-9]{1,4}$", token):
                continue
            if (token.startswith("--match=") or token.startswith("--exclude=")) and len(token) <= 400:
                continue
            raise _forbidden(items, "option %r is not allowed" % token)
        positional.append(token)
    if len(positional) > 1 or any(not _is_rev(t) for t in positional):
        raise _forbidden(items, "describe takes at most one valid revision")


def _v_diff_tree(items: List[str], has_input: bool) -> None:
    required = ("--no-renames", "--no-textconv", "--no-ext-diff")
    allowed = required + ("-r", "-z", "-t", "--name-only", "--name-status", "--root", "--no-commit-id")
    before, _ = _split_paths(items, 1)
    for need in required:
        if need not in before:
            raise _forbidden(items, "diff-tree requires %s" % need)
    positional = _check_options(["diff-tree"] + before, allowed)
    for token in positional:
        if not _is_rev(token):
            raise _forbidden(items, "invalid revision token %r" % token)


_HANDLERS = {
    "rev-parse": _v_rev_parse,
    "ls-files": _v_ls_files,
    "check-attr": _v_check_attr,
    "ls-tree": _v_ls_tree,
    "cat-file": _v_cat_file,
    "rev-list": _v_rev_list,
    "for-each-ref": _v_for_each_ref,
    "config": _v_config,
    "describe": _v_describe,
    "diff-tree": _v_diff_tree,
}


# --------------------------------------------------------------------------------------------------- execution

def _resolved(path: Any) -> Path:
    return Path(os.path.realpath(os.fspath(path)))


def _check_repo(repo: Any, layout: Layout) -> Path:
    real = _resolved(repo)
    parent = _resolved(layout.parent)
    if real == parent or parent not in real.parents:
        raise errors.GitForbidden("repository path is not inside the workspace folder", path=os.fspath(repo))
    if not real.is_dir():
        raise errors.GitError("repository directory does not exist", path=os.fspath(repo))
    return real


def _check_git_dir(git_dir: Any, repo: Path, layout: Layout) -> Path:
    real = _resolved(git_dir)
    parent = _resolved(layout.parent)
    relative = repo.relative_to(parent)
    top = parent / relative.parts[0]
    allowed = [top / ".git" / "modules", _resolved(layout.cache) / "upstream"]
    for base in allowed:
        if real != base and base in real.parents:
            return real
    raise errors.GitForbidden("git_dir must be below <repository>/.git/modules or the upstream cache",
                              git_dir=os.fspath(git_dir))


def _exec(cwd: Path, args: Sequence[str], layout: Layout, git_dir: Optional[Path], input_bytes: Optional[bytes],
          timeout: float, drivers: Sequence[str],
          env: Optional[Mapping[str, str]] = None) -> "subprocess.CompletedProcess[bytes]":
    source = os.environ if env is None else env
    exe = resolve_git(source, layout.parent)                      # absolute: cwd is a target, nothing there may be found
    version = _cached_version(source, layout.parent, exe)
    env_mode = uses_env_config(version)
    child_env = hardened_env(source, drivers, parent=layout.parent, env_config=env_mode)
    cmd: List[str] = [exe]
    if not env_mode:
        for key, value in config_pairs(drivers):
            cmd += ["-c", "%s=%s" % (key, value)]
    if git_dir is not None:
        cmd.append("--git-dir=%s" % git_dir)
    cmd += list(args)
    kwargs: Dict[str, Any] = {"cwd": str(cwd), "env": child_env, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
                              "timeout": timeout}
    if input_bytes is not None:
        kwargs["input"] = input_bytes
    else:
        kwargs["stdin"] = subprocess.DEVNULL
    try:
        return subprocess.run(cmd, **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise errors.GitError("git %s timed out after %.0f s" % (args[0], timeout), args=list(args), returncode=None,
                              stderr="") from exc
    except FileNotFoundError as exc:
        raise errors.GitMissing("git was not found on PATH") from exc


def _filter_drivers(cwd: Path, layout: Layout, git_dir: Optional[Path], timeout: float,
                    env: Optional[Mapping[str, str]] = None) -> List[str]:
    """Names of the filter drivers the repository configuration defines (base configuration, no filter blanking)."""
    signature = _config_signature(cwd, git_dir)
    source = os.environ if env is None else env
    homes = (source.get("HOME", ""), source.get("XDG_CONFIG_HOME", ""))
    key = (str(cwd), str(git_dir or ""), signature, homes) if signature is not None else None
    if key is not None and key in _filter_cache:
        return list(_filter_cache[key])
    proc = _exec(cwd, ["config", "-z", "--get-regexp", r"^filter\."], layout, git_dir, None, timeout, [], env)
    _raise_if_unreadable(proc, ["config"])
    names: List[str] = []
    if proc.returncode == 0:
        for entry in proc.stdout.split(b"\0"):
            if not entry:
                continue
            name_key = entry.split(b"\n", 1)[0].decode("utf-8", "surrogateescape")
            if name_key.startswith("filter.") and name_key.count(".") >= 2:
                name = name_key[len("filter."):name_key.rindex(".")]
                if name not in names:
                    names.append(name)
    names.sort()
    if key is not None:
        _filter_cache[key] = list(names)
    return names


def _config_signature(cwd: Path, git_dir: Optional[Path]) -> Optional[Tuple[int, int]]:
    """Stat signature of the repository's own config file; None when it cannot be located (no caching then)."""
    candidates = []
    if git_dir is not None:
        candidates.append(git_dir / "config")
    candidates.append(cwd / ".git" / "config")
    for candidate in candidates:
        try:
            st = os.stat(str(candidate))
        except OSError:
            continue
        return (st.st_mtime_ns, st.st_size)
    return None


def _raise_if_unreadable(proc: Any, args: Sequence[str]) -> None:
    stderr = (proc.stderr or b"").decode("utf-8", "surrogateescape")
    lowered = stderr.lower()
    if "dubious ownership" in lowered or "unsafe repository" in lowered:
        raise errors.GitUnreadable("git refuses to read this repository: %s" % stderr.strip()[:200],
                                   args=list(args), returncode=proc.returncode, stderr=stderr[:500])


def budget_timeout(ctx: Any, default: float = DEFAULT_TIMEOUT, margin: float = 5.0, floor: float = 10.0) -> float:
    """A git timeout that cannot outlive the command's hard budget: ``min(default, ctx.remaining() - margin)``, but at
    least ``floor`` seconds (the 120 s terminal timeout leaves 40 s of slack beyond the 80 s hard budget, and a git call
    on a healthy repository needs milliseconds). ``ctx`` is a ``RunContext`` (anything with ``remaining()``); without one
    ``default`` is returned."""
    try:
        left = float(ctx.remaining()) - margin
    except (AttributeError, TypeError, ValueError):
        return default
    return max(floor, min(default, left))


def run(repo: Path, args: Sequence[str], *, layout: Layout, git_dir: Optional[Path] = None,
        input_bytes: Optional[bytes] = None, timeout: float = DEFAULT_TIMEOUT, check: bool = True,
        env: Optional[Mapping[str, str]] = None) -> GitResult:
    """Run one allowlisted git command in ``repo`` with the hardened environment.

    ``repo`` must resolve to a directory inside ``layout.parent`` (a target, a submodule work tree inside a target, or
    the pack). ``git_dir``, if given, must resolve inside ``<top-level repo>/.git/modules/`` or the upstream cache and
    is passed as ``--git-dir=<path>``. ``env`` is the environment the child is derived from (callers pass ``ctx.env``;
    the default is ``os.environ``). ``timeout`` covers the whole call including the filter-driver lookup.
    ``GitForbidden`` for anything outside the allowlist, ``GitUnreadable`` for "dubious ownership", ``GitError`` for a
    non-zero exit when ``check`` is true.
    """
    items = validate_args(args, has_input=input_bytes is not None)
    cwd = _check_repo(repo, layout)
    resolved_gd = _check_git_dir(git_dir, cwd, layout) if git_dir is not None else None
    started = time.monotonic()
    drivers = [] if items[0] == "--version" else _filter_drivers(cwd, layout, resolved_gd, timeout, env)
    left = max(1.0, timeout - (time.monotonic() - started))
    proc = _exec(cwd, items, layout, resolved_gd, input_bytes, left, drivers, env)
    _raise_if_unreadable(proc, items)
    result = GitResult(args=items, returncode=proc.returncode, stdout=proc.stdout or b"", stderr=proc.stderr or b"")
    if check and result.returncode != 0:
        text = result.stderr.decode("utf-8", "surrogateescape")
        raise errors.GitError("git %s failed with exit code %d: %s" % (items[0], result.returncode, text.strip()[:200]),
                              args=items, returncode=result.returncode, stderr=text[:500])
    return result


# --------------------------------------------------------------------------------------------------- helpers
# Every helper takes ``env`` (the environment to derive the child's from; callers pass ``ctx.env``) and ``timeout``
# (seconds; callers with a context pass ``budget_timeout(ctx)``).

def _decode(data: bytes) -> str:
    return data.decode("utf-8", "surrogateescape")


def _split_z(data: bytes) -> List[str]:
    return [_decode(part) for part in data.split(b"\0") if part]


def _opts(env: Optional[Mapping[str, str]], timeout: Optional[float],
          default: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    return {"env": env, "timeout": default if timeout is None else timeout}


def ls_files_z(repo: Path, *, layout: Layout, recurse_submodules: bool = False,
               env: Optional[Mapping[str, str]] = None, timeout: Optional[float] = None) -> List[str]:
    """Tracked paths (``ls-files -z``), optionally with the files of initialized submodules."""
    args = ["ls-files", "-z"] + (["--recurse-submodules"] if recurse_submodules else [])
    return _split_z(run(repo, args, layout=layout, **_opts(env, timeout)).stdout)


def ls_files_stage(repo: Path, *, layout: Layout, env: Optional[Mapping[str, str]] = None,
                   timeout: Optional[float] = None) -> List[Tuple[str, str, int, str]]:
    """``(mode, blob, stage, path)`` for every index entry."""
    out: List[Tuple[str, str, int, str]] = []
    for entry in _split_z(run(repo, ["ls-files", "-s", "-z"], layout=layout, **_opts(env, timeout)).stdout):
        meta, _, path = entry.partition("\t")
        fields = meta.split(" ")
        if len(fields) != 3 or not path:
            continue
        out.append((fields[0], fields[1], int(fields[2]), path))
    return out


def ls_files_others(repo: Path, *, layout: Layout, ignored: bool = False, env: Optional[Mapping[str, str]] = None,
                    timeout: Optional[float] = None) -> List[str]:
    """Untracked (``ignored=False``) or ignored entries; wholly untracked directories end in '/'."""
    args = ["ls-files", "-o"] + (["-i"] if ignored else []) + ["--directory", "--exclude-standard", "-z"]
    return _split_z(run(repo, args, layout=layout, **_opts(env, timeout)).stdout)


def rev_parse_head(repo: Path, *, layout: Layout, git_dir: Optional[Path] = None,
                   env: Optional[Mapping[str, str]] = None, timeout: Optional[float] = None) -> Optional[str]:
    """Commit id of HEAD, or None when the repository has no commits."""
    result = run(repo, ["rev-parse", "--verify", "-q", "HEAD"], layout=layout, git_dir=git_dir, check=False,
                 **_opts(env, timeout))
    if result.returncode != 0:
        return None
    text = _decode(result.stdout).strip()
    return text if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", text) else None


def abbrev_ref(repo: Path, *, layout: Layout, env: Optional[Mapping[str, str]] = None,
               timeout: Optional[float] = None) -> Optional[str]:
    """Current branch name; None when HEAD is detached (or unborn)."""
    result = run(repo, ["rev-parse", "--abbrev-ref", "HEAD"], layout=layout, check=False, **_opts(env, timeout))
    if result.returncode != 0:
        return None
    text = _decode(result.stdout).strip()
    return None if text in ("", "HEAD") else text


def describe(repo: Path, rev: str = "HEAD", *, layout: Layout, git_dir: Optional[Path] = None, tags: bool = True,
             always: bool = True, exact: bool = False, env: Optional[Mapping[str, str]] = None,
             timeout: Optional[float] = None) -> Optional[str]:
    """``git describe``; ``tags=True`` counts lightweight tags. None when git finds nothing and ``always`` is false."""
    args = ["describe"] + (["--tags"] if tags else []) + (["--always"] if always else []) \
        + (["--exact-match"] if exact else []) + [rev]
    result = run(repo, args, layout=layout, git_dir=git_dir, check=False, **_opts(env, timeout))
    if result.returncode != 0:
        return None
    text = _decode(result.stdout).strip()
    return text or None


def _config_args(action: str, key: str, file: Optional[str], scope: Optional[str], blob: Optional[str] = None) -> List[str]:
    args = ["config", "-z", action]
    if scope is not None:
        if scope not in ("local", "global", "system"):
            raise errors.GitForbidden("unknown config scope %r" % (scope,))
        args.append("--" + scope)
    elif file is not None:
        args += ["-f", file]
    elif blob is not None:
        args += ["--blob", blob]
    args.append(key)
    return args


def _check_repo_file(repo: Path, layout: Layout, file: str) -> bool:
    """True when ``<repo>/<file>`` exists as a regular file whose real path stays inside the repository."""
    base = _check_repo(repo, layout)
    target = base / file
    if not os.path.isfile(str(target)):
        return False
    real = _resolved(target)
    if base not in real.parents:
        raise errors.GitForbidden("config file resolves outside the repository", file=file)
    return True


def config_get(repo: Path, key: str, *, layout: Layout, file: Optional[str] = None,
               scope: Optional[str] = None, env: Optional[Mapping[str, str]] = None,
               timeout: Optional[float] = None) -> Optional[str]:
    """One config value or None. ``scope`` local/global/system reads only that file, without the injected
    command-scope overrides (core.fsmonitor=false ...); ``scope=None`` reads the effective value."""
    if file is not None and scope is not None:
        raise errors.GitForbidden("file and scope are mutually exclusive")
    if file is not None and not _check_repo_file(repo, layout, file):
        return None
    result = run(repo, _config_args("--get", key, file, scope), layout=layout, check=False, **_opts(env, timeout))
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        text = _decode(result.stderr)
        if scope in ("global", "system") and ("No such file" in text or "unable to read config file" in text):
            return None                                   # that configuration file simply does not exist
        raise errors.GitError("git config failed with exit code %d" % result.returncode, args=result.args,
                              returncode=result.returncode, stderr=text[:500])
    value = _decode(result.stdout)
    return value[:-1] if value.endswith("\0") else value


def config_get_regexp(repo: Path, regexp: str, *, layout: Layout, file: Optional[str] = None,
                      blob: Optional[str] = None, env: Optional[Mapping[str, str]] = None,
                      timeout: Optional[float] = None) -> List[Tuple[str, str]]:
    """``(key, value)`` pairs matching ``regexp`` (keys lowercased by git, a key without value gets '')."""
    if file is not None and blob is not None:
        raise errors.GitForbidden("file and blob are mutually exclusive")
    if file is not None and not _check_repo_file(repo, layout, file):
        return []
    result = run(repo, _config_args("--get-regexp", regexp, file, None, blob), layout=layout, check=False,
                 **_opts(env, timeout))
    if result.returncode == 1:
        return []
    if result.returncode != 0:
        raise errors.GitError("git config failed with exit code %d" % result.returncode, args=result.args,
                              returncode=result.returncode, stderr=_decode(result.stderr)[:500])
    pairs: List[Tuple[str, str]] = []
    for entry in _split_z(result.stdout):
        key, _, value = entry.partition("\n")
        pairs.append((key, value))
    return pairs


def check_attr(repo: Path, paths: Sequence[str], attrs: Sequence[str], *, layout: Layout,
               env: Optional[Mapping[str, str]] = None, timeout: Optional[float] = None) -> Dict[str, Dict[str, str]]:
    """Attribute values per path (``unspecified``, ``set``, ``unset`` or the value), from one batched call.

    The default timeout is ``CHECK_ATTR_TIMEOUT``, below the hard budget; callers with a context pass
    ``budget_timeout(ctx, CHECK_ATTR_TIMEOUT)`` so that the call cannot outlive the command.
    """
    out: Dict[str, Dict[str, str]] = {}
    if not paths:
        return out
    payload = b"".join(os.fsencode(p) + b"\0" for p in paths)
    result = run(repo, ["check-attr", "-z", "--stdin"] + list(attrs), layout=layout, input_bytes=payload,
                 **_opts(env, timeout, CHECK_ATTR_TIMEOUT))
    fields = result.stdout.split(b"\0")
    for index in range(0, len(fields) - 2, 3):
        path = _decode(fields[index])
        attr = _decode(fields[index + 1])
        value = _decode(fields[index + 2])
        out.setdefault(path, {})[attr] = value
    return out


def diff_tree_names(repo: Path, old: str, new: str, *, layout: Layout, env: Optional[Mapping[str, str]] = None,
                    timeout: Optional[float] = None) -> List[str]:
    """Paths whose blob or mode differs between the commits ``old`` and ``new`` (``diff-tree -r --name-only``; a moved
    gitlink is listed by its path). Plumbing only: no index refresh, no filters, no renames."""
    args = ["diff-tree", "-r", "--no-renames", "--no-textconv", "--no-ext-diff", "--name-only", "--no-commit-id", "-z",
            old, new]
    return _split_z(run(repo, args, layout=layout, **_opts(env, timeout)).stdout)


def cat_file_exists(repo: Path, obj: str, *, layout: Layout, git_dir: Optional[Path] = None,
                    env: Optional[Mapping[str, str]] = None, timeout: Optional[float] = None) -> bool:
    """True when ``obj`` exists in the repository's object store."""
    result = run(repo, ["cat-file", "-e", obj], layout=layout, git_dir=git_dir, check=False, **_opts(env, timeout))
    return result.returncode == 0
