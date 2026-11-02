"""Package-manager manifests and lockfiles, CI install lines (contract section 3.9).

Conan (``conanfile.txt``, ``conanfile.py`` through ``ast``, ``conan.lock``), vcpkg (``vcpkg.json``), Zephyr
``west.yml``, ESP-IDF (``idf_component.yml``, ``dependencies.lock``), Bazel ``MODULE.bazel`` (through ``ast``),
PlatformIO ``lib_deps``. Nothing is executed. Manifests inside a candidate directory are the vendored project's own
tooling and are not read. Branch or ``HEAD`` references become ``declared_unresolved`` candidates plus an
``UNPINNED_REF`` blind spot. The dispatch table is keyed by file name so further formats can be added.
"""
from __future__ import annotations

import ast
import configparser
import json
import posixpath
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from sbomlib import miniyaml, model, urls, versions
from sbomlib.discover.session import Session
from sbomlib.norm import norm_library

_BAZEL_SKIP = frozenset(("platforms", "bazel_skylib", "apple_support", "bazel_features", "stardoc", "gazelle",
                         "buildifier_prebuilt", "aspect_bazel_lib", "toolchains_llvm", "hermetic_cc_toolchain",
                         "bazel_tools", "rules_license"))
_PIN_STRENGTH = {"tag": "strong", "commit": "strong", "version": "strong", "url": "strong", "branch": "weak"}


# --------------------------------------------------------------------------------------------------- shared helper

def _line_containing(S: Session, path: str, needle: str, start: int = 1) -> int:
    text = S.fs.text(path)
    if text is None:
        return start
    offset = text.find(needle)
    if offset < 0:
        return start
    return text.count("\n", 0, offset) + 1


def resolve_package_name(S: Session, name: str) -> Tuple[str, Optional[str]]:
    """``(display name, map entry)`` of a package-manager name (``libcurl`` -> ``curl``, ``espressif/led_strip`` kept)."""
    last = name.rsplit("/", 1)[-1]
    mapped = S.imap.package_lib(name) or S.imap.package_lib(last) or S.imap.link_lib(last)
    canon = S.identity.canonical_or_none(mapped) if mapped else None
    if canon is None:
        canon = S.identity.canonical_or_none(name) or S.identity.canonical_or_none(last)
    if canon is None:
        canon = mapped or name
    return canon, S.identity.map_entry_name(canon)


def declare(S: Session, etype: str, name: str, path: str, line: int, *, raw_version: Optional[str] = None,
            channel: str = "generic", source: Optional[str] = None, ref_kind: Optional[str] = "version",
            url: Optional[str] = None, scope: str = "product", commit: Optional[str] = None,
            notes: Tuple[str, ...] = (), condition: Any = None,
            detected: Optional[str] = None) -> Optional[Tuple[Dict[str, Any], str]]:
    """One declaration or pin of a package: finds or creates the candidate, records the evidence and the version claim."""
    if not name:
        return None
    canon, entry = resolve_package_name(S, name)
    from_url = S.identity.from_url(url) if url else None
    if from_url:
        canon, entry = from_url, S.identity.map_entry_name(from_url)
    branch = ref_kind == "branch"
    detected = "declared_unresolved" if branch else (detected or ("lockfile" if etype == "LOCK_PIN" else "package_manager"))
    cand = S.reg.find(norm_library(canon), path)
    if cand is None:
        cand = S.reg.create(canon, detected, "manifest", path, line, map_entry=entry,
                            aliases=[name, name.rsplit("/", 1)[-1]], first_party=S.is_first_party_name(norm_library(canon)),
                            identity_confidence="medium" if S.identity.canonical_or_none(name) or from_url else "low")
        upstream = (urls.https_form(url) or urls.scrub_url(url)) if url else None
        if upstream:
            cand["upstream"]["url"] = upstream
        elif S.identity.upstream_url(canon):
            cand["upstream"]["url"] = S.identity.upstream_url(canon)
    else:
        S.reg.add_alias(cand, name)
    strength = _PIN_STRENGTH.get(ref_kind or "", "medium" if etype == "MANIFEST_DECL" else "strong")
    if etype == "MANIFEST_DECL" and ref_kind != "branch":
        strength = "medium"
    value = raw_version if raw_version is not None else (commit or url)
    evid = S.ev(etype, path=path, line=line, symbol=name, value=value, ref_kind=ref_kind, strength=strength,
                candidate=cand["id"], scope=scope, condition=condition)
    S.reg.claim_identity(cand, canon, [evid])
    if commit:
        cand["upstream"]["commit"] = cand["upstream"]["commit"] or commit
    for note in notes:
        S.reg.add_note(cand, note)
    if branch:
        canon_v = {"version": "NOASSERTION", "version_raw": raw_version or "", "version_kind": "unpinned_ref",
                   "cpe_version": None, "cpe_update": None, "notes": ["follows branch %s" % (raw_version or "HEAD")]}
        S.reg.claim_version(cand, canon_v, "none", "declared", [evid])
        S.reg.blind("UNPINNED_REF", "%s follows branch %s" % (name, raw_version or "HEAD"), "%s:%d" % (path, line), cand["id"])
    elif raw_version:
        src = source or (channel if channel in model.VERSION_SOURCES else "generic")
        canon_v = versions.canonicalize(raw_version, library=canon, channel=channel, rules=S.rules)
        S.reg.claim_version(cand, canon_v, src, "declared", [evid])
    elif commit:
        canon_v = versions.canonicalize("", rules=S.rules)
        S.reg.claim_version(cand, canon_v, "none", "declared", [evid], ["pinned to commit %s" % commit[:12]])
    return cand, evid


def _conan_ref(ref: str) -> Optional[Tuple[str, str]]:
    text = ref.strip().strip("\"'")
    if "/" not in text:
        return None
    name, rest = text.split("/", 1)
    version = re.split(r"[@#%]", rest, maxsplit=1)[0]
    if not name or not version or not re.match(r"^[A-Za-z0-9_.+\-]+$", name):
        return None
    return name, version


def _conan_channel(version: str) -> str:
    return "constraint" if (version.startswith("[") or re.search(r"[<>~^*]", version)) else "conan"


# --------------------------------------------------------------------------------------------------- conan

def conanfile_txt(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    section = ""
    for number, line in enumerate(text.split("\n"), start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continue
        if section not in ("requires", "tool_requires", "build_requires", "test_requires"):
            continue
        parsed = _conan_ref(stripped)
        if parsed is None:
            continue
        scope = "build" if section in ("tool_requires", "build_requires") else ("test" if section == "test_requires" else "product")
        declare(S, "MANIFEST_DECL", parsed[0], path, number, raw_version=parsed[1], channel=_conan_channel(parsed[1]),
                scope=scope)


def conanfile_py(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        S.ev("BUILD_FILE_UNPARSED", path=path, symbol="conanfile.py", value="conanfile.py", quote=False)
        return
    scopes = {"requires": "product", "tool_requires": "build", "build_requires": "build", "test_requires": "test"}

    def strings(node: ast.AST) -> List[Tuple[str, int]]:
        found: List[Tuple[str, int]] = []
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.append((node.value, node.lineno))
        elif isinstance(node, (ast.Tuple, ast.List)):
            for item in node.elts:
                found.extend(strings(item))
        return found

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in scopes:
                    for ref, line in strings(node.value):
                        parsed = _conan_ref(ref)
                        if parsed:
                            declare(S, "MANIFEST_DECL", parsed[0], path, line, raw_version=parsed[1],
                                    channel=_conan_channel(parsed[1]), scope=scopes[target.id])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in scopes and node.args:
            for ref, line in strings(node.args[0]):
                parsed = _conan_ref(ref)
                if parsed:
                    declare(S, "MANIFEST_DECL", parsed[0], path, line, raw_version=parsed[1],
                            channel=_conan_channel(parsed[1]), scope=scopes[node.func.attr])


def conan_lock(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    try:
        data = json.loads(text)
    except ValueError:
        S.ev("BUILD_FILE_UNPARSED", path=path, symbol="conan.lock", value="conan.lock", quote=False)
        return
    refs: List[Tuple[str, str]] = []
    if isinstance(data, dict):
        for key, scope in (("requires", "product"), ("build_requires", "build"), ("python_requires", "build")):
            for ref in data.get(key) or []:
                if isinstance(ref, str):
                    refs.append((ref, scope))
        nodes = ((data.get("graph_lock") or {}).get("nodes") or {}) if isinstance(data.get("graph_lock"), dict) else {}
        for key in sorted(nodes, key=lambda k: (len(k), k)):
            node = nodes[key]
            ref = node.get("ref") or node.get("pref") if isinstance(node, dict) else None
            if key == "0" or not isinstance(ref, str):
                continue
            refs.append((ref, "build" if node.get("context") == "build" else "product"))
    seen = set()
    for ref, scope in refs:
        parsed = _conan_ref(ref.split(":", 1)[0])
        if parsed is None or (parsed, scope) in seen:
            continue
        seen.add((parsed, scope))
        declare(S, "LOCK_PIN", parsed[0], path, _line_containing(S, path, ref), raw_version=parsed[1], channel="conan",
                scope=scope)


# --------------------------------------------------------------------------------------------------- vcpkg

_VCPKG_PLATFORMS = {"windows": ({"var": "WIN32", "op": "truthy"}, {"var": "WIN32", "op": "falsy"}),
                    "uwp": ({"var": "WINDOWS_STORE", "op": "truthy"}, {"var": "WINDOWS_STORE", "op": "falsy"}),
                    "mingw": ({"var": "MINGW", "op": "truthy"}, {"var": "MINGW", "op": "falsy"})}
_VCPKG_SYSTEMS = {"linux": "Linux", "osx": "Darwin", "android": "Android", "ios": "iOS", "freebsd": "FreeBSD", "openbsd": "OpenBSD"}


def vcpkg_platform(expression: Any) -> Any:
    """Condition for a vcpkg ``platform`` expression: names (optionally negated) joined by ``&`` map to platform variables,
    anything else (``|``, parentheses, architectures) becomes one ``unknown`` clause."""
    if not isinstance(expression, str) or not expression.strip():
        return None
    clauses: List[Dict[str, Any]] = []
    for part in expression.split("&"):
        word = part.strip()
        negate = word.startswith("!")
        name = word.lstrip("!").strip()
        if name in _VCPKG_PLATFORMS:
            clauses.append(dict(_VCPKG_PLATFORMS[name][1 if negate else 0]))
        elif name in _VCPKG_SYSTEMS:
            clauses.append({"var": "CMAKE_SYSTEM_NAME", "op": "ne" if negate else "eq", "value": _VCPKG_SYSTEMS[name]})
        else:
            return {"all": [{"op": "unknown", "raw": "platform %s" % expression.strip()[:100]}]}
    return {"all": clauses}


def vcpkg_json(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    try:
        data = json.loads(text)
    except ValueError:
        S.ev("BUILD_FILE_UNPARSED", path=path, symbol="vcpkg.json", value="vcpkg.json", quote=False)
        return
    if not isinstance(data, dict):
        return
    baseline = data.get("builtin-baseline")
    notes = ("vcpkg builtin-baseline %s pins the port versions" % baseline[:12],) if isinstance(baseline, str) else ()
    for dep in data.get("dependencies") or []:
        name = dep if isinstance(dep, str) else (dep.get("name") if isinstance(dep, dict) else None)
        if not isinstance(name, str):
            continue
        line = _line_containing(S, path, '"%s"' % name)
        constraint = dep.get("version>=") if isinstance(dep, dict) else None
        host = isinstance(dep, dict) and bool(dep.get("host"))
        declare(S, "MANIFEST_DECL", name, path, line, raw_version=(">=" + constraint) if constraint else None,
                channel="constraint", source="constraint", ref_kind="version", scope="build" if host else "product",
                notes=notes, condition=vcpkg_platform(dep.get("platform")) if isinstance(dep, dict) else None)
    for override in data.get("overrides") or []:
        if not isinstance(override, dict) or not isinstance(override.get("name"), str):
            continue
        version = next((override[k] for k in ("version", "version-semver", "version-string", "version-date")
                        if isinstance(override.get(k), str)), None)
        if not version:
            continue
        port = override.get("port-version")
        raw = version + ("#%s" % port if isinstance(port, int) and port > 0 else "")
        line = _line_containing(S, path, '"%s"' % override["name"])
        declare(S, "LOCK_PIN", override["name"], path, line, raw_version=raw, channel="vcpkg")


# --------------------------------------------------------------------------------------------------- west

def _classify_west_revision(rev: str) -> str:
    if versions.looks_like_sha(rev):
        return "commit"
    if versions.is_branch_like(rev) or rev.endswith("-branch") or rev.endswith("_branch"):
        return "branch"
    return "tag"


def _west_projects(S: Session, path: str, text: str) -> List[Dict[str, Any]]:
    projects: List[Dict[str, Any]] = []
    try:
        data = miniyaml.load(text)
    except miniyaml.YamlUnsupported:
        return _west_projects_regex(text)
    manifest = data.get("manifest") if isinstance(data, dict) else None
    if not isinstance(manifest, dict):
        return projects
    remotes: Dict[str, str] = {}
    for remote in manifest.get("remotes") or []:
        if isinstance(remote, dict) and isinstance(remote.get("name"), str):
            remotes[remote["name"]] = str(remote.get("url-base") or "")
    defaults = manifest.get("defaults") if isinstance(manifest.get("defaults"), dict) else {}
    items = manifest.get("projects")
    if not isinstance(items, list):
        return projects
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        remote = item.get("remote") or defaults.get("remote")
        url = item.get("url")
        if not url and remote in remotes and remotes[remote]:
            url = remotes[remote].rstrip("/") + "/" + str(item.get("repo-path") or item["name"])
        rev = item.get("revision") or defaults.get("revision")
        line = item.lines.get("revision") if hasattr(item, "lines") else None
        if not line:
            line = items.lines[index] if hasattr(items, "lines") else 1
        projects.append({"name": item["name"], "url": url, "revision": rev, "line": line})
    return projects


def _west_projects_regex(text: str) -> List[Dict[str, Any]]:
    projects: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for number, line in enumerate(text.split("\n"), start=1):
        match = re.match(r"^\s*-\s*name:\s*['\"]?([^'\"\s#]+)", line)
        if match:
            current = {"name": match.group(1), "url": None, "revision": None, "line": number}
            projects.append(current)
            continue
        if current is None:
            continue
        for key in ("revision", "url"):
            match = re.match(r"^\s+%s:\s*['\"]?([^'\"\s#]+)" % key, line)
            if match:
                current[key] = match.group(1)
                if key == "revision":
                    current["line"] = number
    return projects


def west_yml(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    for project in _west_projects(S, path, text):
        rev = project["revision"] or "master"
        kind = _classify_west_revision(rev)
        scope = "product"
        if kind == "commit":
            declare(S, "LOCK_PIN", project["name"], path, project["line"], url=project["url"], ref_kind="commit",
                    commit=rev, scope=scope)
        elif kind == "tag":
            declare(S, "LOCK_PIN", project["name"], path, project["line"], url=project["url"], ref_kind="tag",
                    raw_version=rev, channel="west", scope=scope)
        else:
            declare(S, "LOCK_PIN", project["name"], path, project["line"], url=project["url"], ref_kind="branch",
                    raw_version=rev, scope=scope)


# --------------------------------------------------------------------------------------------------- ESP-IDF

def idf_component_yml(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    try:
        data = miniyaml.load(text)
    except miniyaml.YamlUnsupported:
        S.ev("BUILD_FILE_UNPARSED", path=path, symbol="idf_component.yml", value="idf_component.yml", quote=False)
        return
    deps = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(deps, dict):
        return
    for name, spec in deps.items():
        if name == "idf":
            continue
        line = deps.lines.get(name, 1) if hasattr(deps, "lines") else 1
        version: Optional[str] = None
        url: Optional[str] = None
        if isinstance(spec, str):
            version = spec
        elif isinstance(spec, dict):
            if spec.get("path") or spec.get("override_path"):
                continue                                         # a local component, not a dependency
            version = spec.get("version") if isinstance(spec.get("version"), str) else None
            url = spec.get("git") if isinstance(spec.get("git"), str) else None
            line = spec.lines.get("version", spec.lines.get("git", line)) if hasattr(spec, "lines") else line
        raw = None
        if version is not None:
            raw = ("==" + version) if re.match(r"^\d+(?:\.\d+){1,3}$", version.strip()) else version
        declare(S, "MANIFEST_DECL", name, path, line, raw_version=raw, channel="constraint", source="constraint", url=url)


def idf_lock(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    try:
        data = miniyaml.load(text)
    except miniyaml.YamlUnsupported:
        S.ev("BUILD_FILE_UNPARSED", path=path, symbol="dependencies.lock", value="dependencies.lock", quote=False)
        return
    deps = data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(deps, dict):
        return                                                   # the top-level ``version`` is the lock-format version
    for name, entry in deps.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
            continue
        source = entry.get("source") if isinstance(entry.get("source"), dict) else {}
        if source.get("type") == "local":
            continue
        line = entry.lines.get("version", 1) if hasattr(entry, "lines") else 1
        display = "ESP-IDF" if name == "idf" else name
        declare(S, "LOCK_PIN", display, path, line, raw_version=entry["version"], channel="idf",
                url=source.get("git") if isinstance(source.get("git"), str) else None)


# --------------------------------------------------------------------------------------------------- Bazel

def _call_name(node: ast.Call) -> Optional[str]:
    return node.func.id if isinstance(node.func, ast.Name) else None


def _kwargs(node: ast.Call) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for keyword in node.keywords:
        if keyword.arg is not None and isinstance(keyword.value, ast.Constant):
            out[keyword.arg] = keyword.value.value
    return out


def module_bazel(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        S.ev("BUILD_FILE_UNPARSED", path=path, symbol="MODULE.bazel", value="MODULE.bazel", quote=False)
        return
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _call_name(n)]
    overrides: Dict[str, Dict[str, Any]] = {}
    for node in calls:
        name = _call_name(node)
        if name in ("git_override", "archive_override", "single_version_override", "local_path_override"):
            args = _kwargs(node)
            module = args.get("module_name")
            if isinstance(module, str):
                overrides[module] = dict(args, _kind=name, _line=node.lineno)
    for node in sorted(calls, key=lambda n: n.lineno):
        if _call_name(node) != "bazel_dep":
            continue
        args = _kwargs(node)
        if node.args and isinstance(node.args[0], ast.Constant) and "name" not in args:
            args["name"] = node.args[0].value
        if len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and "version" not in args:
            args["version"] = node.args[1].value
        name = args.get("name")
        if not isinstance(name, str) or name in _BAZEL_SKIP or name.startswith("rules_"):
            continue
        scope = "dev" if args.get("dev_dependency") else "product"
        override = overrides.get(name)
        version = args.get("version") if isinstance(args.get("version"), str) else None
        if override and override["_kind"] == "git_override" and isinstance(override.get("commit"), str):
            declare(S, "LOCK_PIN", name, path, override["_line"], ref_kind="commit", commit=override["commit"],
                    url=override.get("remote") if isinstance(override.get("remote"), str) else None, scope=scope)
        elif override and override["_kind"] == "single_version_override" and isinstance(override.get("version"), str):
            declare(S, "LOCK_PIN", name, path, override["_line"], raw_version=override["version"], channel="bcr", scope=scope)
        elif version:
            declare(S, "LOCK_PIN", name, path, node.lineno, raw_version=version, channel="bcr", scope=scope)
        else:
            declare(S, "LOCK_PIN", name, path, node.lineno, ref_kind="version", scope=scope)


# --------------------------------------------------------------------------------------------------- PlatformIO

def platformio_ini(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    parser = configparser.RawConfigParser(strict=False, allow_no_value=True, interpolation=None)
    parser.optionxform = str                                    # type: ignore[assignment]
    try:
        parser.read_string(text)
    except configparser.Error:
        return
    seen = set()
    for section in parser.sections():
        raw = parser.get(section, "lib_deps", fallback=None)
        if not raw:
            continue
        for entry in raw.split("\n"):
            spec = entry.split(";", 1)[0].strip().lstrip(",").strip()
            if not spec or spec.startswith(("${", "symlink://", "file://")):
                continue
            url = None
            name = spec
            version: Optional[str] = None
            if re.match(r"^(?:https?|git)://", spec) or spec.startswith("git@"):
                url = spec.split("#", 1)[0]
                tag = spec.split("#", 1)[1] if "#" in spec else None
                name = urls.scrub_url(url) or url
                name = (name or url).rstrip("/").rsplit("/", 1)[-1].replace(".git", "")
                version = tag
                kind = "tag" if tag and not versions.is_branch_like(tag) and not versions.looks_like_sha(tag) else (
                    "commit" if tag and versions.looks_like_sha(tag) else "branch")
                key = (name, url, tag)
                if key in seen:
                    continue
                seen.add(key)
                line = _line_containing(S, path, spec.split("#", 1)[0])
                if kind == "tag":
                    declare(S, "MANIFEST_DECL", name, path, line, raw_version=version, channel="git_tag", url=url, ref_kind="tag")
                elif kind == "commit":
                    declare(S, "MANIFEST_DECL", name, path, line, url=url, ref_kind="commit", commit=version)
                else:
                    declare(S, "MANIFEST_DECL", name, path, line, raw_version=version or "HEAD", url=url, ref_kind="branch")
                continue
            if "@" in spec:
                name, _sep, version = spec.partition("@")
            name = name.strip()
            version = version.strip() if version else None
            if not name or (name, version) in seen:
                continue
            seen.add((name, version))
            line = _line_containing(S, path, spec)
            if version and re.match(r"^\d+(?:\.\d+)*[a-z]?$", version):
                declare(S, "MANIFEST_DECL", name, path, line, raw_version=version, channel="generic")
            else:
                declare(S, "MANIFEST_DECL", name, path, line, raw_version=version or None, channel="constraint",
                        source="constraint")


# --------------------------------------------------------------------------------------------------- CI install lines

_INSTALL_RES = [
    re.compile(r"\b(?:apt-get|apt|aptitude)\s+(?:-\S+\s+)*install\s+(.*)"),
    re.compile(r"\b(?:yum|dnf|microdnf|zypper)\s+(?:-\S+\s+)*install\s+(.*)"),
    re.compile(r"\bbrew\s+install\s+(.*)"),
    re.compile(r"\bapk\s+(?:--?\S+\s+)*add\s+(.*)"),
    re.compile(r"\bpacman\s+-S\S*\s+(.*)"),
]


def is_ci_file(path: str) -> bool:
    base = posixpath.basename(path)
    if path.startswith(".github/workflows/") and base.endswith((".yml", ".yaml")):
        return True
    if base == ".gitlab-ci.yml" or base.startswith("Dockerfile") or base.endswith(".Dockerfile"):
        return True
    parts = path.split("/")
    return base.endswith(".sh") and any(p.lower() == "ci" for p in parts[:-1])


def ci_installs(S: Session, path: str) -> None:
    text = S.fs.text(path)
    if text is None:
        return
    lines = text.split("\n")
    index = 0
    while index < len(lines):
        start = index + 1
        logical = lines[index]
        while logical.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            logical = logical.rstrip()[:-1] + " " + lines[index].strip()
        index += 1
        for regex in _INSTALL_RES:
            match = regex.search(logical)
            if match is None:
                continue
            tail = re.split(r"&&|\|\||;|\|", match.group(1))[0]
            for token in tail.split():
                token = token.strip("\"'").split("=", 1)[0]
                if not token or token.startswith(("-", "$", "{", "(")) or token in ("\\",):
                    continue
                lib = S.imap.distro_lib(token) or S.imap.package_lib(token)
                if not lib:
                    continue
                canon = S.identity.canonical(lib)
                cand = S.reg.find(norm_library(canon), path)
                if cand is None:
                    continue                                    # D14: CI install lines never create candidates
                S.ev("CI_INSTALL", path=path, line=start, symbol=token, value=token, candidate=cand["id"], scope="build")


# --------------------------------------------------------------------------------------------------- dispatch

Handler = Callable[[Session, str], None]


def _unparsed(S: Session, path: str) -> None:
    S.ev("BUILD_FILE_UNPARSED", path=path, symbol=posixpath.basename(path), value=posixpath.basename(path), quote=False)


DISPATCH: Dict[str, Handler] = {
    "conanfile.txt": conanfile_txt, "conanfile.py": conanfile_py, "conan.lock": conan_lock, "vcpkg.json": vcpkg_json,
    "west.yml": west_yml, "idf_component.yml": idf_component_yml, "dependencies.lock": idf_lock,
    "MODULE.bazel": module_bazel, "platformio.ini": platformio_ini,
    "xmake-requires.lock": _unparsed, "spack.lock": _unparsed, "package-lock.cmake": _unparsed,
}


def run(S: Session) -> None:
    """Pass 2: read every manifest and lockfile outside candidate directories; CI install lines corroborate."""
    for path in S.paths:
        base = posixpath.basename(path)
        handler = DISPATCH.get(base)
        if handler is None or S.reg.owner_of(path) is not None:
            continue
        S.check_budget()
        try:
            handler(S, path)
        except (ValueError, KeyError, TypeError, AttributeError, IndexError) as exc:
            S.log("discover.manifest_error", file=path, error="%s: %s" % (type(exc).__name__, str(exc)[:120]))


def run_ci(S: Session) -> None:
    """Pass 3: CI install lines (corroboration of candidates the other channels created)."""
    for path in S.paths:
        if is_ci_file(path) and S.reg.owner_of(path) is None:
            S.check_budget()
            ci_installs(S, path)
