"""File inventory, file classes, build-system detection (contract sections 3.9, 4.6, 6.9).

The file list comes from ``git ls-files -z --recurse-submodules`` and ``git ls-files -s -z`` through ``gitro`` and nothing
else: discovery never walks the disk for evidence. Dirty tracked files are analysed as they are on disk.
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import errors, gitro
from sbomlib.discover import session as sess
from sbomlib.discover.session import Session

#: names of build files by system (contract section 6.9)
CMAKE_NAMES = ("CMakeLists.txt", "CMakePresets.json")
MESON_NAMES = ("meson.build", "meson_options.txt", "meson.options")
AUTOTOOLS_NAMES = ("configure.ac", "configure.in", "Makefile.am", "Makefile.in")
MAKE_NAMES = ("Makefile", "makefile", "GNUmakefile")
BAZEL_NAMES = ("MODULE.bazel", "BUILD", "BUILD.bazel")
UNCOVERED_NAMES = ("SConstruct", "SConscript", "wscript", "build.ninja", "xmake.lua", "platformio.ini")
UNCOVERED_PATTERNS = ("premake*.lua", "*.uvprojx", "*.ewp", "*.cproject", "build*.sh")
MANIFEST_NAMES = ("conanfile.txt", "conanfile.py", "conan.lock", "vcpkg.json", "vcpkg-configuration.json", "west.yml",
                  "idf_component.yml", "dependencies.lock", "xmake-requires.lock", "spack.lock", "package-lock.cmake")
#: lockfiles of other ecosystems; inside a vendored directory they only produce a note
OTHER_LOCKFILES = ("Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "go.mod", "Gemfile.lock",
                   "poetry.lock", "Pipfile.lock", "composer.lock", "pubspec.lock", "requirements.txt")
BINARY_EXT = (".a", ".lib", ".bin", ".hex", ".elf", ".axf", ".o", ".obj", ".so", ".dll", ".dylib", ".img", ".exe",
              ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".pdf", ".zip", ".gz", ".tar", ".xz", ".bz2", ".7z", ".jar")
PREBUILT_EXT = (".a", ".lib", ".bin", ".hex", ".elf", ".axf", ".o", ".so", ".dll", ".img")
_SO_VERSIONED_RE = re.compile(r"\.so(?:\.\d+)+$")
DOC_EXT = (".md", ".txt", ".rst", ".adoc", ".html", ".htm", ".tex", ".1", ".3")
DOC_NAMES = ("README", "LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "AUTHORS", "CHANGELOG", "CHANGES", "NEWS",
             "THANKS", "TODO", "INSTALL", "CONTRIBUTING")
RELEASE_PREFIXES = ("release", "package", "flash", "dist")
_PRESET_RE = re.compile(r"--preset(?:=|\s+)([A-Za-z0-9_.+\-]+)")
_TEMPLATE_MACRO_RE = re.compile(r"^\s*(?:#\s*undef|#\s*cmakedefine01|#\s*cmakedefine|#\s*mesondefine)\s+([A-Za-z_]\w*)", re.M)


def is_build_file(path: str) -> bool:
    base = posixpath.basename(path)
    if base in CMAKE_NAMES or base.endswith(".cmake") or base in MESON_NAMES or base in AUTOTOOLS_NAMES:
        return True
    if base in MAKE_NAMES or base.endswith(".mk") or base in BAZEL_NAMES or base.startswith("WORKSPACE"):
        return True
    if base in MANIFEST_NAMES or base in UNCOVERED_NAMES or base == ".project":
        return True
    if path.endswith(".wrap") and ("/subprojects/" in "/" + path):
        return True
    return any(fnmatch.fnmatchcase(base, pattern) for pattern in UNCOVERED_PATTERNS)


def build_system_of(path: str) -> Optional[str]:
    """``cmake``, ``meson``, ``autotools``, ``make``, ``bazel``, ``uncovered`` or None (not a build-system file)."""
    base = posixpath.basename(path)
    if base in CMAKE_NAMES or base.endswith(".cmake"):
        return "cmake"
    if base in MESON_NAMES or (path.endswith(".wrap") and "/subprojects/" in "/" + path):
        return "meson"
    if base in AUTOTOOLS_NAMES:
        return "autotools"
    if base in MAKE_NAMES or base.endswith(".mk"):
        return "make"
    if base in BAZEL_NAMES or base.startswith("WORKSPACE"):
        return "bazel"
    if base in UNCOVERED_NAMES or any(fnmatch.fnmatchcase(base, p) for p in UNCOVERED_PATTERNS):
        return "uncovered"
    return None


def _timeout(S: Session) -> float:
    return gitro.budget_timeout(S.ctx)


# --------------------------------------------------------------------------------------------------- collect

def collect(S: Session) -> None:
    """List the tracked files, the gitlinks and the files of initialized submodules; fill ``S.paths`` and the raw
    ``S.inv`` (classes are filled by ``classify`` once the candidate directories are known)."""
    ctx, layout = S.ctx, S.layout
    kwargs = {"env": ctx.env, "timeout": _timeout(S)}
    stage = gitro.ls_files_stage(S.repo_dir, layout=layout, **kwargs)
    gitlinks: Dict[str, Tuple[str, int]] = {}
    supers: Dict[str, Tuple[str, str]] = {}
    for mode, blob, stage_no, path in stage:
        if mode == "160000":
            if path not in gitlinks or stage_no == 0:
                gitlinks[path] = (blob, stage_no)
        elif stage_no == 0 or path not in supers:
            supers[path] = (mode, blob)
    try:
        everything = gitro.ls_files_z(S.repo_dir, layout=layout, recurse_submodules=True, **kwargs)
    except errors.GitUnreadable:
        raise
    except errors.GitError as exc:
        S.log("discover.recurse_submodules_failed", error=exc.message[:200])
        everything = list(supers)
    # agent tooling committed into the repository (a host folder, an installed skill) is data: IGNORED, and absent from every
    # list below, so that no file in it becomes evidence, a test directory or a line of the worker's file list
    from sbomlib import enumerate as enum
    skipped = enum.ignored_dirs(list(supers) + list(everything) + [g + "/" for g in gitlinks])
    S.dropped_dirs = skipped
    if skipped:
        folders = tuple(skipped)
        supers = {p: v for p, v in supers.items() if not enum.under_ignored(p, folders)}
        everything = [p for p in everything if not enum.under_ignored(p, folders)]
        gitlinks = {p: v for p, v in gitlinks.items() if not enum.under_ignored(p + "/", folders)}
        S.submodules = [m for m in S.submodules if not enum.under_ignored(str(m.get("path")) + "/", folders)]
    sub_files: Dict[str, List[str]] = {}
    gl_set = set(gitlinks)
    for path in everything:
        if path in supers or path in gl_set:
            continue
        probe = posixpath.dirname(path)
        while probe and probe not in gl_set:
            probe = posixpath.dirname(probe)
        if probe:
            sub_files.setdefault(probe, []).append(path[len(probe) + 1:])
    dirty = {item.get("path"): item.get("state") for item in (S.entry.get("dirty") or {}).get("files", [])}
    files: List[Dict[str, Any]] = []
    scan_paths: List[str] = []
    for index, path in enumerate(sorted(supers)):
        if index % 500 == 0:
            ctx.check_deadline()
        mode, blob = supers[path]
        info = S.fs.lstat(path) if mode != "120000" else None
        state = dirty.get(path, "clean")
        if mode != "120000" and info is None and not S.fs.is_symlink(path) and state == "clean":
            state = "deleted"
        files.append({"path": path, "mode": mode, "blob": blob, "state": state, "class": "other",
                      "size": info.st_size if info is not None else None})
        if mode != "120000" and state != "deleted" and info is not None:
            scan_paths.append(path)
    for sub, rels in sub_files.items():
        rels.sort()
        for rel in rels:
            scan_paths.append(sub + "/" + rel)
    S.gitlink_paths = gl_set
    S.set_paths(scan_paths)
    states = {g.get("path"): g.get("state") for g in S.submodules}
    gitlink_list = [{"path": path, "sha": gitlinks[path][0], "state": states.get(path) or "uninitialized"}
                    for path in sorted(gitlinks)]
    S.inv = {"schema": 1, "repo": S.repo, "head": S.entry.get("head"), "files": files,
             "submodule_files": {k: sorted(v) for k, v in sorted(sub_files.items())}, "gitlinks": gitlink_list}


# --------------------------------------------------------------------------------------------------- classification

def file_class(S: Session, path: str, mode: str) -> str:
    """Class of a tracked file (contract sections 4.6 and 6.9)."""
    if mode == "120000":
        return "other"
    owner = S.reg.owner_of(path)
    if owner is not None:
        if owner["detected_as"] == "submodule":
            return "submodule"
        if owner["location"]["kind"] in ("dir", "file"):
            return "binary" if owner["detected_as"] == "prebuilt" else "vendored"
    lowered = path.lower()
    if lowered.endswith(BINARY_EXT) or _SO_VERSIONED_RE.search(lowered):
        return "binary"
    scope = sess.scope_of_path(path)
    if scope == "test":
        return "test"
    if scope == "dev":
        return "dev"
    if is_build_file(path):
        return "build"
    if sess.is_c_source(path):
        return "first_party_source"
    if sess.is_c_header(path):
        return "first_party_header"
    base = posixpath.basename(path)
    stem = base.split(".", 1)[0].upper()
    if lowered.endswith(DOC_EXT) or stem in DOC_NAMES:
        return "doc"
    return "other"


def classify(S: Session) -> None:
    for index, item in enumerate(S.inv["files"]):
        if index % 1000 == 0:
            S.ctx.check_deadline()
        item["class"] = file_class(S, item["path"], item["mode"])


def detect_build_systems(S: Session) -> Dict[str, List[str]]:
    systems: Dict[str, List[str]] = {"cmake": [], "meson": [], "autotools": [], "make": [], "bazel": [], "uncovered": []}
    for path in S.paths:
        system = build_system_of(path)
        if system is None:
            continue
        systems[system].append(path)
    if any(posixpath.basename(p) == ".cproject" for p in S.paths):
        for path in S.paths:
            if posixpath.basename(path) in (".cproject", ".project"):
                systems["uncovered"].append(path)
    for key in systems:
        systems[key] = sorted(set(systems[key]))
    return systems


_MESON_SUPPORT_DIRS = ("packagefiles", "packagecache")        # Meson overlay files and download cache: not libraries


def vendored_parent_children(S: Session) -> List[str]:
    """Child directories of vendored parent directories that hold at least one tracked file, sorted."""
    found = set()
    for path in S.paths:
        parts = path.split("/")
        for index, part in enumerate(parts[:-2]):
            if part in S.vendored_parents and not (part == "subprojects" and parts[index + 1] in _MESON_SUPPORT_DIRS):
                found.add("/".join(parts[:index + 2]))
    return sorted(found - S.gitlink_paths)


def test_dirs(S: Session) -> List[str]:
    found = set()
    for path in S.paths:
        parts = path.split("/")
        for index, part in enumerate(parts[:-1]):
            if part.lower() in sess.TEST_COMPONENTS:
                found.add("/".join(parts[:index + 1]))
                break
    return sorted(found)


def find_release_scripts(S: Session) -> List[Dict[str, Any]]:
    """Tracked release scripts (contract section 6.9) with the presets each one names."""
    scripts: List[Dict[str, Any]] = []
    for path in S.paths:
        if S.reg.owner_of(path) is not None:
            continue
        base = posixpath.basename(path)
        lowered = base.lower()
        workflow = path.startswith(".github/workflows/") and (
            "release" in lowered or "publish" in lowered) and lowered.endswith((".yml", ".yaml"))
        named = any(lowered.startswith(prefix) for prefix in RELEASE_PREFIXES) and not sess.is_c_file(path)
        if not (workflow or named):
            continue
        presets: List[str] = []
        text = S.fs.text(path)
        if text:
            presets = sorted(set(_PRESET_RE.findall(text)))
        scripts.append({"path": path, "presets": presets})
    return scripts


def template_macros(S: Session) -> List[Dict[str, Any]]:
    """Macros that configure-time templates may define (``config.h.in``, ``*.h.in``, ``*.h.cmake``)."""
    out: List[Dict[str, Any]] = []
    for path in S.paths:
        base = posixpath.basename(path)
        if not (base == "config.h.in" or base.endswith(".h.in") or base.endswith(".h.cmake")):
            continue
        if S.reg.owner_of(path) is not None:
            continue
        text = S.fs.text(path)
        if text is None:
            continue
        macros = sorted(set(_TEMPLATE_MACRO_RE.findall(text)))
        out.append({"path": path, "macros": macros})
    return out


def finalize_inventory(S: Session, systems: Dict[str, List[str]]) -> None:
    """Complete ``S.inv`` once every channel has run (classes, build systems, vendored dirs, generated macros ...)."""
    classify(S)
    vendored = sorted(c["location"]["path"] for c in S.reg.dir_candidates() if c["detected_as"] == "vendored")
    S.inv["build_systems"] = systems
    S.inv["vendored_dirs"] = vendored
    S.inv["test_dirs"] = test_dirs(S)
    S.generated_macros["templates"] = template_macros(S)
    unique: Dict[Tuple[Any, Any, Any], Dict[str, Any]] = {}
    for item in S.generated_macros["checks"]:
        unique[(item["path"], item["line"], item["macro"])] = item
    S.generated_macros["checks"] = [unique[k] for k in sorted(unique, key=lambda k: (k[0], k[1] or 0, k[2]))]
    S.inv["generated_macros"] = S.generated_macros
    S.inv["release_scripts"] = S.release_scripts
    S.inv.setdefault("ignored", [])
