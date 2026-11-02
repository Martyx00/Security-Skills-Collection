"""Committed binaries, tracked build by-products, linker maps, ``dlopen`` literals, toolchain runtimes (contract section 3.9).

Binaries are hashed (SHA-256, at most 256 MiB, symlinks skipped) and never executed or parsed. Build by-products
(``compile_commands.json``, ``*.d``, ``objects.list``, ``subdir.mk``) are strong evidence unless stale: when their last
commit is older than the newest build file their strength drops one level. GNU ld maps give ``LINK_PROOF`` only for kept
input sections of size > 0 (``.comment``, ``.note*``, ``.debug*`` and ``.ARM.attributes`` do not count); ``LOAD`` lines and
"Archive member included" entries are ``LINK_LINE`` only.
"""
from __future__ import annotations

import json
import posixpath
import re
from typing import Any, Dict, List, Optional, Tuple

from sbomlib import csource, errors, gitro
from sbomlib.discover import buildrefs, inventory
from sbomlib.discover import session as sess
from sbomlib.discover.session import Session
from sbomlib.norm import norm_library

MAX_PREBUILT = 400
MAX_MAP_BYTES = 2 * 1024 * 1024
_LIB_FILE_RE = re.compile(r"^lib(.+?)\.(?:a|lib|so(?:\.\d+)*|dll|dylib)$", re.I)
_PLAIN_LIB_RE = re.compile(r"^(.+?)\.(?:lib|dll|dylib|so(?:\.\d+)*)$", re.I)
_DOWNGRADE = {"strong": "medium", "medium": "weak", "weak": "weak"}
_SECTION_SKIP = (".comment", ".note", ".debug", ".ARM.attributes", ".stab", ".gnu.build.attributes")
_SECTION_RE = re.compile(r"^\s*(\.\S+|COMMON)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S.*?)\s*$")
_SECTION_NAME_ONLY_RE = re.compile(r"^\s*(\.\S+|COMMON)\s*$")
_SECTION_CONT_RE = re.compile(r"^\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(\S.*?)\s*$")
_LOAD_RE = re.compile(r"^LOAD\s+(\S.*?)\s*$")
_ARCHIVE_MEMBER_RE = re.compile(r"^(\S.*?\.(?:a|lib|o|obj))(?:\(([^)]+)\))?\s*$")
_DLOPEN_RE = re.compile(r'\b(dlopen|dlmopen|LoadLibrary(?:A|W|ExA|ExW)?|g_module_open|SDL_LoadObject|uv_dlopen)\s*\(\s*'
                        r'(?:\w+\s*,\s*)?(?:(?:TEXT|_T)\s*\(\s*)?(?:L|u8|u|U)?"([^"\n]+)"')
_QLIBRARY_RE = re.compile(r'\bQLibrary\b\s*(?:\w+\s*)?\(\s*"([^"\n]+)"')
_DLOPEN_QUICK = ("dlopen", "dlmopen", "LoadLibrary", "g_module_open", "SDL_LoadObject", "uv_dlopen", "QLibrary")
_RUNTIME_LIBS_IGNORED = frozenset((
    "c", "m", "dl", "pthread", "rt", "gcc_s", "stdc++", "util", "resolv", "nsl", "crypt", "kernel32", "user32", "advapi32",
    "ws2_32", "shell32", "ole32", "gdi32", "ntdll", "msvcrt", "ucrtbase", "comctl32", "winmm", "shlwapi", "version",
    "wininet", "psapi", "iphlpapi", "ld-linux", "libc", "libm", "libdl", "libpthread", "winhttp", "crypt32", "bcrypt",
    "secur32", "oleaut32", "comdlg32", "imm32", "setupapi", "ntoskrnl", "dbghelp", "netapi32", "mswsock", "wsock32"))
_RUNTIME_FLAGS = [
    (re.compile(r"--specs=nano\.specs"), "newlib", "nano.specs"),
    (re.compile(r"--specs=nosys\.specs"), "newlib", "nosys.specs"),
    (re.compile(r"--specs=rdimon\.specs"), "newlib", "rdimon.specs"),
    (re.compile(r"(?<![\w-])-lc_nano\b"), "newlib", "-lc_nano"),
    (re.compile(r"(?<![\w-])-lnosys\b"), "newlib", "-lnosys"),
    (re.compile(r"(?<![\w-])-l(?:stdc\+\+|supc\+\+)(?:_nano)?(?![\w+])"), "libstdc++", "-lstdc++"),
    (re.compile(r"(?<![\w-])-lgcc\b"), "libgcc", "-lgcc"),
]
_MAP_RUNTIME_ARCHIVES = {"libgcc.a": "libgcc", "libc_nano.a": "newlib", "libnosys.a": "newlib", "libstdc++.a": "libstdc++",
                         "libstdc++_nano.a": "libstdc++", "libsupc++.a": "libstdc++", "libc.a": "newlib", "libg.a": "newlib",
                         "libg_nano.a": "newlib", "librdimon.a": "newlib", "libm.a": "newlib"}


# --------------------------------------------------------------------------------------------------- prebuilt binaries

def prebuilt(S: Session) -> None:
    """Pass 1: committed binaries become ``prebuilt`` candidates (identity from the file name)."""
    count = 0
    for path in S.paths:
        low = path.lower()
        if not (low.endswith(inventory.PREBUILT_EXT) or inventory._SO_VERSIONED_RE.search(low)):
            continue
        if S.fs.lstat(path) is None:
            continue
        if count >= MAX_PREBUILT:
            S.log("discover.prebuilt_cap", cap=MAX_PREBUILT)
            break
        S.check_budget()
        digest = S.fs.sha256(path)
        base = posixpath.basename(path)
        match = _LIB_FILE_RE.match(base)
        unidentified = False
        if match:
            stem = match.group(1)
        else:
            plain = _PLAIN_LIB_RE.match(base)
            stem = plain.group(1) if plain else posixpath.splitext(base)[0]
            unidentified = not bool(S.identity.canonical_or_none(stem) or S.imap.link_lib(stem))
        canon = S.identity.resolve_name(stem) or S.imap.link_lib(stem) or stem
        canon = S.identity.canonical(canon)
        owner = S.reg.owner_of(path)
        if owner is not None and owner["location"]["kind"] in ("dir", "gitlink") and owner["norm_name"] == norm_library(canon):
            cand = owner
        else:
            cand = S.reg.create(canon, "prebuilt", "file", path, None, map_entry=S.identity.map_entry_name(canon),
                                aliases=[base, stem], sha256=digest, first_party=False,
                                identity_confidence="low" if unidentified else "medium")
            if digest and not cand.get("sha256"):
                cand["sha256"] = digest
            upstream = S.identity.upstream_url(canon)
            if upstream and not cand["upstream"]["url"]:
                cand["upstream"]["url"] = upstream
        count += 1
        evid = S.ev("PREBUILT", path=path, symbol=stem, value=digest, candidate=cand["id"], quote=False,
                    detail="committed binary %s%s" % (base, "" if digest else " (not hashed)"),
                    scope=sess.scope_of_path(path))
        S.reg.claim_identity(cand, canon, [evid])
        if unidentified and cand is not owner:
            S.reg.blind("PREBUILT_UNIDENTIFIED", "binary %s cannot be identified from its file name" % base, path, cand["id"])


# --------------------------------------------------------------------------------------------------- staleness

def _commit_time(S: Session, paths: List[str]) -> Optional[int]:
    newest: Optional[int] = None
    for start in range(0, len(paths), 200):
        chunk = paths[start:start + 200]
        try:
            result = gitro.run(S.repo_dir, ["rev-list", "--max-count=1", "--format=%ct", "HEAD", "--"] + chunk,
                               layout=S.layout, check=False, env=S.ctx.env, timeout=gitro.budget_timeout(S.ctx))
        except errors.GitUnreadable:
            raise
        except errors.SbomError:
            return None
        if result.returncode != 0:
            continue
        lines = [ln.strip() for ln in result.stdout.decode("utf-8", "replace").split("\n") if ln.strip()]
        if not lines:
            continue
        try:
            value = int(lines[-1])                    # git < 2.33 prints a "commit <sha>" header line first
        except ValueError:
            continue
        newest = value if newest is None else max(newest, value)
    return newest


class Staleness:
    def __init__(self, S: Session) -> None:
        self.S = S
        self._newest_build: Optional[int] = None
        self._computed = False

    def newest_build(self) -> Optional[int]:
        if not self._computed:
            self._computed = True
            files = [p for p in self.S.paths if inventory.is_build_file(p) and not _is_byproduct(p)
                     and self.S.reg.owner_of(p) is None][:400]
            self._newest_build = _commit_time(self.S, files) if files else None
        return self._newest_build

    def strength(self, paths: List[str], base: str = "strong") -> str:
        if not paths:
            return base
        newest = self.newest_build()
        if newest is None:
            return base
        changed = _commit_time(self.S, paths)
        if changed is not None and changed < newest:
            return _DOWNGRADE.get(base, base)
        return base


def _is_byproduct(path: str) -> bool:
    base = posixpath.basename(path)
    return base in ("compile_commands.json", "objects.list", "subdir.mk", "objects.mk", "sources.mk") or base.endswith(".d")


def _suffix_match(S: Session, raw: str) -> Optional[str]:
    parts = [p for p in raw.replace("\\", "/").split("/") if p not in ("", ".")]
    stack: List[str] = []
    for part in parts:
        if part == "..":
            if stack:
                stack.pop()
        else:
            stack.append(part)
    for index in range(len(stack)):
        suffix = "/".join(stack[index:])
        if suffix in S.path_set and (len(stack) - index >= 2 or len(S.by_base.get(suffix, [])) == 1):
            return suffix
    return None


# --------------------------------------------------------------------------------------------------- compile lists

def _compile_evidence(S: Session, source: str, path: str, line: Optional[int], strength: str, target: Optional[str]) -> None:
    owner = S.reg.owner_of(source)
    if owner is None or not S.reg.count_compile(owner["id"], "byproduct:" + path):
        return
    S.ev("COMPILE_LIST", path=path, line=line, symbol=source, value=source, candidate=owner["id"], strength=strength,
         target=target, scope=sess.scope_of_path(path))


def byproduct_lists(S: Session) -> None:
    stale = Staleness(S)
    for path in S.paths:
        base = posixpath.basename(path)
        if base == "compile_commands.json":
            _compile_commands(S, path, stale)
        elif base == "objects.list":
            _objects_list(S, path, stale)
        elif base == "subdir.mk":
            _subdir_mk(S, path, stale)
    dep_files = [p for p in S.paths if p.endswith(".d") and S.fs.lstat(p) is not None]
    if dep_files:
        strength = stale.strength(dep_files[:400])
        for path in dep_files:
            S.check_budget()
            _dependency_file(S, path, strength)


def _compile_commands(S: Session, path: str, stale: Staleness) -> None:
    data = S.fs.read_bytes(path)
    if data is None:
        return
    try:
        entries = json.loads(data.decode("utf-8", "replace"))
    except ValueError:
        return
    if not isinstance(entries, list):
        return
    text = data.decode("utf-8", "replace")
    strength = stale.strength([path])
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            continue
        raw = entry["file"]
        if not raw.startswith("/") and isinstance(entry.get("directory"), str):
            raw = posixpath.join(entry["directory"], raw)
        source = _suffix_match(S, raw)
        if source is None or not sess.is_c_source(source):
            continue
        escaped = json.dumps(entry["file"])[1:-1]
        key = re.search(r'"file"\s*:\s*"%s"' % re.escape(escaped), text)
        offset = key.start() if key else text.find(escaped)
        line = text.count("\n", 0, offset) + 1 if offset >= 0 else 1
        output = entry.get("output")
        _compile_evidence(S, source, path, line, strength, posixpath.basename(output) if isinstance(output, str) else None)


def _objects_list(S: Session, path: str, stale: Staleness) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    strength = stale.strength([path])
    directory = posixpath.dirname(path)
    for number, line in enumerate(text.split("\n"), start=1):
        obj = line.strip().strip("\"'")
        if not obj.endswith((".o", ".obj")):
            continue
        stem = posixpath.normpath(obj)[: -len(posixpath.splitext(obj)[1])]
        base = directory
        found = None
        while True:
            for ext in inventory_c_ext():
                candidate = posixpath.normpath(posixpath.join(base or ".", stem + ext))
                candidate = "" if candidate == "." else candidate
                if candidate and not candidate.startswith("..") and S.tracked(candidate):
                    found = candidate
                    break
            if found or not base:
                break
            base = posixpath.dirname(base)
        if found:
            _compile_evidence(S, found, path, number, strength, None)


def inventory_c_ext() -> Tuple[str, ...]:
    return sess.C_SOURCE_EXT


def _logical_words(text: str) -> List[Tuple[int, List[Tuple[str, int]]]]:
    """Logical lines (``\\`` continuations joined) as ``(first line, [(word, physical line)])``."""
    out: List[Tuple[int, List[Tuple[str, int]]]] = []
    current: List[Tuple[str, int]] = []
    start = 0
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        continued = line.endswith("\\")
        body = line[:-1] if continued else line
        if not current and not start:
            start = number
        current.extend((word, number) for word in body.split())
        if not continued:
            if current:
                out.append((start, current))
            current, start = [], 0
    if current:
        out.append((start, current))
    return out


def _subdir_mk(S: Session, path: str, stale: Staleness) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    strength = stale.strength([path])
    directory = posixpath.dirname(path)
    for _first, words in _logical_words(text):
        if not re.match(r"^[A-Z_]*SRCS\s*\+?=", " ".join(word for word, _line in words)):
            continue
        for item, number in words:
            if not item.lower().endswith(inventory_c_ext()):
                continue
            base = directory
            found = None
            while True:
                candidate = posixpath.normpath(posixpath.join(base or ".", item))
                if candidate and not candidate.startswith("..") and S.tracked(candidate):
                    found = candidate
                    break
                if not base:
                    break
                base = posixpath.dirname(base)
            if found:
                _compile_evidence(S, found, path, number, strength, None)


def _dependency_file(S: Session, path: str, strength: str) -> None:
    text = S.fs.text(path)
    if text is None or ":" not in text:
        return
    directory = posixpath.dirname(path)
    for _first, words in _logical_words(text):
        if not words or words[0][0].startswith("#"):
            continue
        seen_colon = False
        for dep, number in words:
            if not seen_colon:
                seen_colon = ":" in dep
                tail = dep.partition(":")[2]
                if not tail:
                    continue
                dep = tail
            if not dep.lower().endswith(sess.C_SOURCE_EXT):
                continue
            joined = posixpath.normpath(posixpath.join(directory or ".", dep)) if not dep.startswith("/") else dep
            source = joined if joined in S.path_set else _suffix_match(S, dep if dep.startswith("/") else joined)
            if source:
                _compile_evidence(S, source, path, number, strength, None)
            break


# --------------------------------------------------------------------------------------------------- linker maps

def _skip_section(name: str) -> bool:
    return any(name == skip or name.startswith(skip) for skip in _SECTION_SKIP)


def _owner_of_map_path(S: Session, raw: str) -> Optional[Dict[str, Any]]:
    path = raw.replace("\\", "/")
    padded = "/" + path
    best: Optional[Dict[str, Any]] = None
    best_len = -1
    for cand in S.reg.cands.values():
        loc = cand["location"]
        if loc["kind"] in ("dir", "gitlink") and loc["path"] and ("/" + loc["path"] + "/") in padded:
            if len(loc["path"]) > best_len:
                best, best_len = cand, len(loc["path"])
    if best is not None:
        return best
    archive = posixpath.basename(path.split("(", 1)[0])
    for cand in S.reg.cands.values():
        loc = cand["location"]
        if cand["detected_as"] == "prebuilt" and loc["path"] and posixpath.basename(loc["path"]) == archive:
            return cand
    match = _LIB_FILE_RE.match(archive)
    if match:
        stem = match.group(1)
        lib = S.imap.link_lib(stem) or S.identity.canonical_or_none(stem)
        if lib:
            return S.reg.find(norm_library(S.identity.canonical(lib)), None)
    return None


def _runtime_of_archive(raw: str) -> Optional[str]:
    archive = posixpath.basename(raw.replace("\\", "/").split("(", 1)[0])
    return _MAP_RUNTIME_ARCHIVES.get(archive)


def _is_ld_map(text: str) -> bool:
    head = text[:60000]
    return "Linker script and memory map" in head or "Memory Configuration" in head or "Archive member included" in head


def linker_maps(S: Session) -> None:
    stale = Staleness(S)
    for path in S.paths:
        if not path.lower().endswith(".map"):
            continue
        data = S.fs.read_bytes(path, MAX_MAP_BYTES)
        if data is None:
            continue
        text = data.decode("utf-8", "replace")
        if not _is_ld_map(text):
            continue
        S.check_budget()
        _parse_map(S, path, text, stale.strength([path], "strong"))


def _parse_map(S: Session, path: str, text: str, strength: str) -> None:
    lines = text.split("\n")
    state = ""
    kept: Dict[str, Dict[str, Any]] = {}
    link_lines: Dict[str, Tuple[int, Dict[str, Any]]] = {}
    runtimes: Dict[str, int] = {}
    gc = False
    keep = "KEEP(" in text
    pending_name: Optional[str] = None
    pending_line = 0
    for number, line in enumerate(lines, start=1):
        if line.startswith("Archive member included"):
            state = "archive"
            continue
        if line.startswith("Discarded input sections"):
            state = "discarded"
            continue
        if line.startswith("Memory Configuration"):
            state = "memcfg"
            continue
        if line.startswith("Linker script and memory map"):
            state = "map"
            continue
        if state == "archive":
            if line and not line[0].isspace():
                match = _ARCHIVE_MEMBER_RE.match(line.strip())
                if match:
                    runtime = _runtime_of_archive(line)
                    if runtime:
                        runtimes.setdefault(runtime, number)
                    else:
                        owner = _owner_of_map_path(S, line.strip())
                        if owner is not None and owner["id"] not in link_lines:
                            link_lines[owner["id"]] = (number, owner)
            continue
        if state == "discarded":
            match = _SECTION_RE.match(line)
            if match and int(match.group(3), 16) > 0:
                gc = True
            continue
        if state != "map":
            continue
        load = _LOAD_RE.match(line)
        if load:
            runtime = _runtime_of_archive(load.group(1))
            if runtime:
                runtimes.setdefault(runtime, number)
                continue
            owner = _owner_of_map_path(S, load.group(1))
            if owner is not None and owner["id"] not in link_lines:
                link_lines[owner["id"]] = (number, owner)
            continue
        section = None
        match = _SECTION_RE.match(line)
        if match:
            section = (match.group(1), int(match.group(3), 16), match.group(4), number)
            pending_name = None
        else:
            name_only = _SECTION_NAME_ONLY_RE.match(line)
            if name_only:
                pending_name, pending_line = name_only.group(1), number
                continue
            cont = _SECTION_CONT_RE.match(line)
            if cont and pending_name:
                section = (pending_name, int(cont.group(2), 16), cont.group(3), pending_line)
            pending_name = None
        if section is None:
            continue
        name, size, owner_text, at = section
        if size <= 0 or _skip_section(name) or owner_text.startswith("*"):
            continue
        runtime = _runtime_of_archive(owner_text)
        if runtime:
            runtimes.setdefault(runtime, at)
            continue
        owner = _owner_of_map_path(S, owner_text)
        if owner is None:
            continue
        item = kept.setdefault(owner["id"], {"cand": owner, "line": at, "bytes": 0, "members": set(), "sections": []})
        item["bytes"] += size
        item["members"].add(owner_text)
        if len(item["sections"]) < 5:
            item["sections"].append(name)
    for cid in sorted(kept):
        item = kept[cid]
        S.ev("LINK_PROOF", path=path, line=item["line"], symbol=posixpath.basename(sorted(item["members"])[0].split("(")[0]),
             value={"bytes": item["bytes"], "members": len(item["members"]), "sections": item["sections"],
                    "gc_sections": gc, "keep": keep}, candidate=cid, strength=strength, scope="product")
    for cid in sorted(link_lines):
        if cid in kept:
            continue
        at, owner = link_lines[cid]
        S.ev("LINK_LINE", path=path, line=at, symbol=owner["norm_name"], value={"gc_sections": gc, "keep": keep},
             candidate=cid, strength="medium" if strength == "strong" else _DOWNGRADE.get(strength, strength),
             scope="product")
    for runtime, at in sorted(runtimes.items()):
        _toolchain_runtime(S, runtime, path, at, "linker map")


# --------------------------------------------------------------------------------------------------- toolchain runtimes

def _toolchain_runtime(S: Session, runtime: str, path: str, line: int, how: str) -> None:
    canon = S.identity.canonical(runtime)
    cand = S.reg.create(canon, "toolchain_runtime", "toolchain", "toolchain/" + norm_library(canon), None,
                        map_entry=S.identity.map_entry_name(canon), aliases=[runtime], identity_confidence="medium")
    S.ev("TOOLCHAIN_RUNTIME", path=path, line=line, symbol=runtime, value=how, candidate=cand["id"],
         scope=sess.scope_of_path(path))


def toolchain_flags(S: Session) -> None:
    """``--specs=nano.specs``, ``-lstdc++``, ``-lgcc``, ``-lc_nano`` ... in build files outside candidate directories."""
    counts: Dict[str, int] = {}
    for path in S.paths:
        if not inventory.is_build_file(path) and not path.endswith((".ewp", ".uvprojx", ".cproject")):
            continue
        if S.reg.owner_of(path) is not None:
            continue
        text = S.fs.text(path)
        if text is None or ("-l" not in text and "--specs" not in text):
            continue
        for number, line in enumerate(text.split("\n"), start=1):
            if "-l" not in line and "--specs" not in line:
                continue
            for regex, runtime, how in _RUNTIME_FLAGS:
                if regex.search(line) and counts.get(runtime, 0) < 5:
                    counts[runtime] = counts.get(runtime, 0) + 1
                    _toolchain_runtime(S, runtime, path, number, how)


# --------------------------------------------------------------------------------------------------- dlopen

def _soname_stem(raw: str) -> Optional[str]:
    name = raw.replace("\\", "/").rsplit("/", 1)[-1].strip()
    lowered = name.lower()
    match = re.match(r"^lib(.+?)\.(?:so(?:\.\d+)*|dylib)$", name, re.I)
    if match:
        return match.group(1)
    match = re.match(r"^(.+?)\.(?:dll|dylib|so(?:\.\d+)*)$", name, re.I)
    if match:
        return match.group(1)
    if re.match(r"^[A-Za-z0-9_.+\-]+$", name) and "." not in lowered:
        return name[3:] if lowered.startswith("lib") and len(name) > 3 else name
    return None


def dlopen(S: Session) -> None:
    for path in S.paths:
        if not sess.is_c_file(path) or S.reg.owner_of(path) is not None:
            continue
        data = S.fs.read_bytes(path)
        if data is None or not any(token.encode() in data for token in _DLOPEN_QUICK):
            continue
        S.check_budget()
        text = csource.strip_comments(data.decode("utf-8", "replace"))
        matches: List[Tuple[int, str, str]] = []
        for match in _DLOPEN_RE.finditer(text):
            matches.append((text.count("\n", 0, match.start()) + 1, match.group(1), match.group(2)))
        for match in _QLIBRARY_RE.finditer(text):
            matches.append((text.count("\n", 0, match.start()) + 1, "QLibrary", match.group(1)))
        for line, func, literal in sorted(set(matches)):
            stem = _soname_stem(literal)
            if not stem or stem.lower() in _RUNTIME_LIBS_IGNORED or norm_library(stem) in _RUNTIME_LIBS_IGNORED:
                continue
            lib = S.imap.link_lib(stem) or S.imap.package_lib(stem) or S.identity.canonical_or_none(stem)
            scope = sess.scope_of_path(path)
            if lib:
                cand = buildrefs.find_or_create_system(S, lib, path, alias=stem)
            else:
                canon = S.identity.canonical(stem)
                existing = S.reg.find(norm_library(canon), path)
                cand = existing or S.reg.create(canon, "declared_unresolved", "system", None, None, aliases=[stem],
                                                identity_confidence="low")
                if existing is None:
                    S.reg.blind("DLOPEN_UNMAPPED", "%s loads %s at runtime and the library is not in the curated map"
                                % (path, literal), "%s:%d" % (path, line), cand["id"])
            evid = S.ev("DLOPEN", path=path, line=line, symbol=literal, value=literal, candidate=cand["id"], scope=scope,
                        detail="%s(\"%s\")" % (func, literal))
            S.reg.claim_identity(cand, cand["name"], [evid])
