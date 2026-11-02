"""The single shared version canonicalizer (contract sections 3.9, 6.4 and 4.28; report "Normalized version").

``canonicalize`` turns the raw version text of any channel into the pieces every later phase needs: the normalized
version (a *release* or ``NOASSERTION``), its kind, the CPE version and update, and notes. Only a normalized release
goes into the ``version`` field (D5); snapshots, ranges, constraints, tags between releases and unrecognized strings
write ``NOASSERTION`` and keep the raw text in ``version_raw``.

Pure functions, no I/O. The rule tables come from ``assets/version_rules.json`` (callers pass
``ctx.asset("version_rules.json")``); ``DEFAULT_RULES`` holds the generic part so the module works without them.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from sbomlib.norm import norm_library

NOASSERTION = "NOASSERTION"

CHANNELS = ("generic", "header_macro", "project_version", "version_file", "git_tag", "describe", "banner", "conan",
            "vcpkg", "wrapdb", "hunter", "bcr", "fetchcontent_tag", "west", "idf", "bazel", "constraint")

#: channels whose raw text is a git tag (or a ref that may be one)
TAG_CHANNELS = ("git_tag", "fetchcontent_tag", "west")

DEFAULT_RULES: Dict[str, Any] = {
    "schema": 1,
    "rules": [],
    "tag_patterns": [{"library": "*", "regex": r"^v?(\d+(?:\.\d+){1,3})$", "format": "{1}"}],
    "snapshot_suffixes": ["-DEV", "-dev", "-motley", ".git", "-SNAPSHOT", "-snapshot"],
    "channel_suffixes": {"vcpkg": r"#\d+$", "wrapdb": r"-\d+$", "hunter": r"-p\d+$", "bcr": r"\.bcr\.\d+$"},
    "prerelease": r"^(\d+(?:\.\d+)+)[-._]?((?:rc|alpha|beta)[.]?\d*)$",
    "release_scheme": r"^\d+(?:\.\d+){0,3}(?:[a-z]|p\d+|-(?:rc|alpha|beta)\d*)?$",
}

_PLACEHOLDER_RE = re.compile(r"@[A-Za-z_][A-Za-z0-9_]*@|\$\{[^}]*\}|\$\([^)]*\)|%[A-Z_]{3,}%|--[A-Z]{3,}--")
_DESCRIBE_RE = re.compile(r"^(.+)-(\d+)-g([0-9a-f]{4,64})$")
_CONSTRAINT_OP_RE = re.compile(r"^(>=|<=|==|=|!=|~>|>|<|~|\^)\s*v?(.*)$")
_CONSTRAINT_HINT_RE = re.compile(r"[<>^~*!,|]|^\[|\]$|\s(?:-|\|\|)\s|\bx\b")
_PREFIX_RE = re.compile(r"^(?:release|rel|version|ver|v)[-_ ]?(?=\d)", re.I)
_UNDERSCORE_VERSION_RE = re.compile(r"^(\d+(?:_\d+){1,3}[a-z]?)$")
_BRANCH_NAMES = ("master", "main", "develop", "dev", "head", "trunk", "stable", "next", "latest", "nightly", "default")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")


def _rule(rules: Optional[Dict[str, Any]], key: str) -> Any:
    if rules is not None and key in rules:
        return rules[key]
    return DEFAULT_RULES[key]


def _regex(rules: Optional[Dict[str, Any]], key: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(_rule(rules, key), flags)


def release_scheme_ok(version: str, rules: Optional[Dict[str, Any]] = None) -> bool:
    """True when ``version`` matches the release scheme of the rules (also used by the output validator)."""
    return bool(version) and _regex(rules, "release_scheme").match(version) is not None


def describe_parts(describe: str) -> Optional[Tuple[str, int, str]]:
    """``"v1.0.0-2-gabc1234"`` -> ``("v1.0.0", 2, "abc1234")``; None when the text is not a ``git describe --long`` form."""
    match = _DESCRIBE_RE.match((describe or "").strip())
    if match is None:
        return None
    return match.group(1), int(match.group(2)), match.group(3)


def looks_like_sha(text: str) -> bool:
    """A full or abbreviated commit id (7-64 hex digits containing at least one letter or being 40 long)."""
    value = (text or "").strip()
    if not _SHA_RE.match(value):
        return False
    return len(value) >= 40 or bool(re.search(r"[a-fA-F]", value))


def is_branch_like(ref: str) -> bool:
    """A ref that names a moving branch rather than a tag or commit (``master``, ``origin/main``, ``HEAD`` ...)."""
    value = (ref or "").strip()
    if not value:
        return True
    lowered = value.lower()
    if lowered.startswith(("origin/", "refs/heads/", "heads/", "remotes/")):
        return True
    return lowered in _BRANCH_NAMES


def _format_tag(fmt: str, groups: Tuple[Optional[str], ...]) -> str:
    return re.sub(r"\{(\d+)\}", lambda m: (groups[int(m.group(1)) - 1] or "") if 0 < int(m.group(1)) <= len(groups) else "", fmt)


def _normalize_prerelease(version: str, rules: Optional[Dict[str, Any]]) -> Tuple[str, Optional[str], Optional[str]]:
    """``(normalized version, cpe_version, cpe_update)`` of a text that already passed the release checks."""
    match = _regex(rules, "prerelease", re.I).match(version)
    if match is not None and match.group(2):
        suffix = re.sub(r"[.]", "", match.group(2).lower())
        return "%s-%s" % (match.group(1), suffix), match.group(1), suffix
    return version, version, None


def tag_to_version(tag: str, library: Optional[str], rules: Dict[str, Any]) -> Optional[str]:
    """Release version named by a git tag, or None.

    Library specific ``tag_patterns`` come first (``OpenSSL_1_1_1w`` -> ``1.1.1w``, ``curl-8_9_1`` -> ``8.9.1``,
    ``STABLE-2_1_2_RELEASE`` -> ``2.1.2``), then the ``"*"`` patterns, then a leading ``<library>[-_]`` or
    ``release-``/``v`` prefix is stripped and the plain release scheme is tried.
    """
    text = (tag or "").strip()
    if text.startswith("refs/tags/"):
        text = text[len("refs/tags/"):]
    if not text:
        return None
    lib_key = norm_library(library) if library else None
    patterns = _rule(rules, "tag_patterns")
    ordered: List[Dict[str, Any]] = []
    if lib_key:
        ordered += [p for p in patterns if p.get("library") not in (None, "*") and norm_library(p["library"]) == lib_key]
    ordered += [p for p in patterns if p.get("library") in (None, "*")]
    for pattern in ordered:
        try:
            match = re.match(pattern["regex"], text)
        except re.error:
            continue
        if match is None:
            continue
        candidate = _format_tag(pattern.get("format", "{1}"), match.groups())
        normalized = _plain_release(candidate, rules)
        if normalized is not None:
            return normalized
    stripped = text
    if lib_key:
        for sep_match in re.finditer(r"[-_ ]", stripped):
            head = stripped[:sep_match.start()]
            if head and norm_library(head) == lib_key:
                stripped = stripped[sep_match.end():]
                break
        else:
            if norm_library(stripped) == lib_key:
                return None
    stripped = _PREFIX_RE.sub("", stripped, count=1)
    under = _UNDERSCORE_VERSION_RE.match(stripped)
    if under is not None:
        stripped = under.group(1).replace("_", ".")
    return _plain_release(stripped, rules)


def _fill(template: Optional[str], match: "re.Match[str]") -> Optional[str]:
    """``{0}`` is the whole match, ``{n}`` the n-th group."""
    if template is None:
        return None
    return re.sub(r"\{(\d+)\}", lambda m: (match.group(int(m.group(1))) or "") if int(m.group(1)) <= (match.re.groups or 0)
                  else "", template)


def _spelling(text: str, library: Optional[str], rules: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """A ``cpe_spellings`` rule of the rules asset that fits ``library`` and the whole of ``text``: the version it stands
    for and the CPE version and update NVD uses for it (a LodePNG date, a FreeRTOS LTS patch)."""
    if not library:
        return None
    key = norm_library(library)
    for rule in (rules or {}).get("cpe_spellings") or []:
        if norm_library(str(rule.get("library", ""))) != key:
            continue
        try:
            match = re.fullmatch(rule["regex"], text, re.I)
        except (re.error, KeyError):
            continue
        if match is None:
            continue
        found = {"version": _fill(rule.get("version", "{0}"), match), "cpe_version": _fill(rule.get("cpe_version"), match),
                 "cpe_update": _fill(rule.get("cpe_update"), match), "note": _fill(rule.get("note"), match)}
        if found["version"]:
            return found
    return None


def _spelled_release(raw: str, text: str, library: Optional[str], rules: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The canonical result for a text a ``cpe_spellings`` rule covers, else None."""
    spelled = _spelling(text, library, rules)
    if spelled is None:
        return None
    version = _plain_release(spelled["version"] or "", rules)
    if version is None:
        return None
    result = _empty(raw, "release")
    result.update(version=version, cpe_version=spelled["cpe_version"] or version, cpe_update=spelled["cpe_update"],
                  notes=[spelled["note"]] if spelled["note"] else [])
    return result


def strip_library_prefix(text: str, library: Optional[str]) -> str:
    """``nanopb-0.4.9.1`` -> ``0.4.9.1`` for the library ``nanopb``: a leading ``<library>`` followed by ``-``, ``_`` or a
    space is dropped. Nothing else changes, so the release checks still decide whether what is left is a version."""
    if not library:
        return text
    key = norm_library(library)
    for sep_match in re.finditer(r"[-_ ]", text):
        head = text[:sep_match.start()]
        if head and norm_library(head) == key:
            rest = text[sep_match.end():]
            return rest if rest[:1].isdigit() or (rest[:1] in "vV" and rest[1:2].isdigit()) else text
    return text


def _plain_release(text: str, rules: Optional[Dict[str, Any]]) -> Optional[str]:
    """Normalized release for a version-looking text, None when it is not a release (snapshots included)."""
    value = text.strip()
    if value[:1] in ("v", "V") and value[1:2].isdigit():
        value = value[1:]
    if not value or _is_snapshot(value, rules):
        return None
    if _regex(rules, "prerelease", re.I).match(value) is not None:
        return _normalize_prerelease(value, rules)[0]
    if release_scheme_ok(value, rules):
        return value
    return None


def _is_snapshot(text: str, rules: Optional[Dict[str, Any]]) -> bool:
    return any(text.endswith(suffix) for suffix in _rule(rules, "snapshot_suffixes"))


def _empty(raw: Any, kind: str = "none") -> Dict[str, Any]:
    return {"version": NOASSERTION, "version_raw": raw if isinstance(raw, str) else "", "version_kind": kind,
            "cpe_version": None, "cpe_update": None, "notes": []}


def _release(raw: Any, version: str, rules: Optional[Dict[str, Any]], notes: List[str]) -> Dict[str, Any]:
    normalized, cpe_version, cpe_update = _normalize_prerelease(version, rules)
    result = _empty(raw, "release")
    result.update({"version": normalized, "cpe_version": cpe_version, "cpe_update": cpe_update, "notes": notes})
    return result


def _format_constraint(text: str) -> str:
    value = text.strip()
    if value in ("", "*"):
        return "any version"
    match = _CONSTRAINT_OP_RE.match(value)
    if match is not None and match.group(2) and not re.search(r"[\s,|]", match.group(2)):
        op = "==" if match.group(1) == "=" else match.group(1)
        return "%s%s" % (op, match.group(2)) if op in ("^", "~") else "%s %s" % (op, match.group(2))
    return value


def _canonicalize_constraint(raw: str, text: str, rules: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    text = text.strip()
    if len(text) > 1 and text.startswith("[") and text.endswith("]"):          # Conan range syntax
        text = text[1:-1].strip()
    match = re.match(r"^==?\s*v?(\d+(?:\.\d+)*[a-z]?)$", text)
    if match is not None:
        exact = _plain_release(match.group(1), rules)
        if exact is not None:
            return _release(raw, exact, rules, ["exact version required: %s" % exact])
    result = _empty(raw, "constraint")
    if text and re.match(r"^v?\d", text) and not _CONSTRAINT_HINT_RE.search(text):
        result["notes"] = ["constraint: >= %s" % text.lstrip("vV")]   # a bare version in a requirement is a minimum
    else:
        result["notes"] = ["constraint: %s" % _format_constraint(text)]
    return result


def _strip_channel_suffix(text: str, channel: str, rules: Optional[Dict[str, Any]], notes: List[str]) -> str:
    suffixes = _rule(rules, "channel_suffixes")
    key = "bcr" if channel in ("bazel", "bcr") else channel
    pattern = suffixes.get(key) if isinstance(suffixes, dict) else None
    if not pattern:
        return text
    match = re.search(pattern, text)
    if match is None:
        return text
    notes.append("stripped %s packaging suffix %s" % (key, match.group(0)))
    return text[:match.start()]


def canonicalize(raw: str, *, library: Optional[str] = None, channel: str = "generic",
                 rules: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Normalize a raw version string of ``channel``.

    Returns ``{"version", "version_raw", "version_kind", "cpe_version", "cpe_update", "notes"}``. ``version`` is the
    normalized release when ``version_kind == "release"`` and ``"NOASSERTION"`` for every other kind. A pre-release
    (``2.0.0-rc1``) is a release whose ``cpe_version`` is ``2.0.0`` and ``cpe_update`` ``rc1``.
    """
    if channel not in CHANNELS:
        raise ValueError("unknown version channel: %r" % (channel,))
    if not isinstance(raw, str):
        return _empty("")
    text = raw.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    if not text:
        result = _empty(raw)
        result["notes"] = ["no version text"]
        return result
    placeholders = []
    for rule in _rule(rules, "rules") or []:
        placeholders.extend(rule.get("placeholders") or [])
    if any(p in text for p in placeholders) or _PLACEHOLDER_RE.search(text):
        result = _empty(raw)
        result["notes"] = ["version template placeholder, not a version: %s" % text[:60]]
        return result
    notes: List[str] = []

    if channel == "constraint":
        return _canonicalize_constraint(raw, text, rules)

    if channel != "describe":
        spelled_result = _spelled_release(raw, text, library, rules)
        if spelled_result is not None:
            return spelled_result
    if channel not in TAG_CHANNELS and channel != "describe":
        stripped_text = strip_library_prefix(text, library)
        if stripped_text != text and _plain_release(stripped_text.lstrip("vV") if stripped_text[:1] in "vV" and stripped_text[1:2].isdigit() else stripped_text, rules) is not None:
            text = stripped_text

    if channel == "describe" or (channel in TAG_CHANNELS and describe_parts(text) is not None):
        parts = describe_parts(text)
        if parts is not None and parts[1] > 0:
            result = _empty(raw, "between_releases")
            result["notes"] = ["git describe %s: %d commit(s) after tag %s" % (text, parts[1], parts[0])]
            return result
        if parts is not None:
            text = parts[0]
        channel = "git_tag"

    if channel in TAG_CHANNELS:
        if text.lower() in _BRANCH_NAMES or looks_like_sha(text):
            result = _empty(raw, "unpinned_ref" if text.lower() in _BRANCH_NAMES else "none")
            result["notes"] = ["ref is %s, not a release tag: %s" % ("a moving branch" if result["version_kind"] == "unpinned_ref"
                                                                      else "a commit id", text[:60])]
            return result
        version = tag_to_version(text, library, rules or DEFAULT_RULES)
        if version is None:
            if _is_snapshot(text, rules):
                result = _empty(raw, "snapshot")
                result["notes"] = ["snapshot tag: %s" % text]
                return result
            result = _empty(raw)
            result["notes"] = ["tag does not follow a known release scheme: %s" % text[:60]]
            return result
        spelled_result = _spelled_release(raw, version, library, rules)
        if spelled_result is not None:
            return spelled_result
        return _release(raw, version, rules, notes)

    if channel in ("conan", "vcpkg", "wrapdb", "hunter", "bcr", "bazel"):
        if channel == "conan":
            text = re.split(r"[#%]", text, maxsplit=1)[0].split("@", 1)[0].strip()
            if text.startswith("[") or _CONSTRAINT_HINT_RE.search(text):
                return _canonicalize_constraint(raw, text.strip("[]"), rules)
        text = _strip_channel_suffix(text, channel, rules, notes)

    lowered = text.lstrip("vV") if text[:1] in ("v", "V") and text[1:2].isdigit() else text
    if _is_snapshot(lowered, rules):
        result = _empty(raw, "snapshot")
        result["notes"] = ["snapshot, not a release: %s" % text]
        return result
    parts = describe_parts(lowered)
    if parts is not None:
        result = _empty(raw, "between_releases")
        result["notes"] = ["git describe %s: %d commit(s) after tag %s" % (text, parts[1], parts[0])]
        return result
    if channel != "banner" and (_CONSTRAINT_OP_RE.match(lowered) or lowered.startswith("[") or lowered == "*"):
        return _canonicalize_constraint(raw, lowered, rules)
    release = _plain_release(lowered, rules)
    if release is None:
        under = _UNDERSCORE_VERSION_RE.match(lowered)
        release = _plain_release(under.group(1).replace("_", "."), rules) if under and channel in ("header_macro", "version_file") else None
    if release is None:
        result = _empty(raw)
        result["notes"] = notes + ["unrecognized version string: %s" % text[:60]]
        return result
    return _release(raw, release, rules, notes)
