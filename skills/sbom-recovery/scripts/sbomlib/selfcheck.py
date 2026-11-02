"""Phase 0: environment probes (contract section 3.7). ``probe`` returns the ``env.json`` body and writes nothing.

The only subprocesses are the three interpreter probes (git is probed through ``gitro``).
Every executable is started by the absolute path found on the safe part of ``PATH`` (``gitro.find_executable``): relative
and empty ``PATH`` entries and entries inside the workspace folder are ignored, because the probes run with a working
directory inside it and must never execute a file that a target repository contains.
"""
from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import errors, gitro, model
from sbomlib.context import RunContext

MIN_GIT = (2, 25, 0)
TOOL_NAMES = ("cc", "gcc", "clang", "cmake", "meson", "bwrap", "unshare", "osv-scanner", "syft", "trivy")
PARENT_AGENT_NAMES = ("AGENTS.md", "README.md")
PROBE_CODE = "import sys;print('%d.%d.%d' % sys.version_info[:3])"
# (display prefix, argv head) in preference order
INTERPRETERS = (("python3 -I -B", ["python3"]), ("python -I -B", ["python"]), ("py -3 -I -B", ["py", "-3"]))


def _version_tuple(text: str) -> Optional[Tuple[int, int, int]]:
    parts = text.strip().split(".")
    try:
        nums = [int(p) for p in parts[:3]]
    except ValueError:
        return None
    while len(nums) < 3:
        nums.append(0)
    return (nums[0], nums[1], nums[2])


def _child_env(env: Dict[str, str], parent: Path) -> Dict[str, str]:
    """``env`` with ``PATH`` reduced to its safe entries (see ``gitro.safe_path``)."""
    child = dict(env)
    safe = gitro.safe_path(env.get("PATH"), parent)
    if safe:
        child["PATH"] = safe
    else:
        child.pop("PATH", None)
    return child


def _probe_interpreter(prefix: str, head: List[str], cwd: Path, env: Dict[str, str], parent: Path) -> Dict[str, Any]:
    exe = gitro.find_executable(head[0], env, parent)
    if exe is None:
        return {"prefix": prefix, "ok": False, "error": "not found"}
    cmd = [exe] + head[1:] + ["-I", "-B", "-c", PROBE_CODE]
    child_env = _child_env(env, parent)
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), env=child_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10)
    except FileNotFoundError:
        return {"prefix": prefix, "ok": False, "error": "not found"}
    except subprocess.TimeoutExpired:
        return {"prefix": prefix, "ok": False, "error": "timed out after 10 s"}
    except OSError as exc:
        return {"prefix": prefix, "ok": False, "error": "cannot run: %s" % exc.__class__.__name__}
    out = proc.stdout.decode("utf-8", "replace").strip()
    version = _version_tuple(out.splitlines()[0]) if out else None
    if proc.returncode != 0 or version is None:
        return {"prefix": prefix, "ok": False, "error": "exit code %d" % proc.returncode}
    if version < (3, 9, 0):
        return {"prefix": prefix, "ok": False, "version": out.splitlines()[0], "error": "Python 3.9 or newer is required"}
    return {"prefix": prefix, "ok": True, "version": out.splitlines()[0]}


def probe(ctx: RunContext) -> Dict[str, Any]:
    """The ``env.json`` body (contract section 4.4). Writes nothing."""
    env = dict(ctx.env)
    parent = ctx.layout.parent
    cwd = ctx.layout.tmp if os.path.isdir(str(ctx.layout.tmp)) else ctx.layout.parent
    warnings: List[Dict[str, Any]] = []

    candidates = [_probe_interpreter(prefix, head, cwd, env, parent) for prefix, head in INTERPRETERS]
    chosen = next((c for c in candidates if c["ok"]), None)
    python = {"version": chosen["version"] if chosen else None,
              "prefix": chosen["prefix"] if chosen else INTERPRETERS[0][0],
              "python3_IB_works": bool(candidates[0]["ok"]),
              "candidates": candidates}

    git: Dict[str, Any]
    try:
        version = gitro.git_version(env, parent=parent)
        text = "%d.%d.%d" % version
        if version < MIN_GIT:
            git = {"version": text, "ok": False, "config_mode": None,
                   "error": "git %s is older than the required 2.25.0" % text}
        else:
            git = {"version": text, "ok": True,
                   "config_mode": "GIT_CONFIG_COUNT" if gitro.uses_env_config(version) else "-c"}
    except errors.GitMissing as exc:
        git = {"version": None, "ok": False, "config_mode": None, "error": exc.message}

    tools = {name: gitro.find_executable(name, env, parent) for name in TOOL_NAMES}
    parent_files = [n for n in PARENT_AGENT_NAMES if os.path.isfile(str(ctx.layout.parent / n))]
    if parent_files:
        warnings.append(model.warning(
            "INFORMATIONAL", "PARENT_AGENT_FILES",
            "the workspace folder contains %s, which an agent host may load as instructions; the files are not analysed"
            % ", ".join(parent_files)))
    ctime_reliable = os.name != "nt"
    if not ctime_reliable:
        warnings.append(model.warning(
            "INFORMATIONAL", "CTIME_UNRELIABLE",
            "on Windows ctime is the creation time, so the unchanged-targets check detects fewer changes"))

    return {
        "schema": 1,
        "probed_at": ctx.now_iso(),
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                     "os_name": os.name},
        "python": python,
        "git": git,
        "git_lfs": {"present": bool(gitro.find_executable("git-lfs", env, parent))},
        "network": {"nvd": "deferred"},
        "nvd_api_key": bool(env.get("NVD_API_KEY")),
        "tools": tools,
        "sandbox": {"available": None, "reason": "not probed in this version"},
        "analysis_mode": "static",
        "analysis_mode_reason": model.ANALYSIS_MODE_REASON,
        "parent_agent_files": parent_files,
        "ctime_reliable": ctime_reliable,
        "warnings": warnings,
    }
