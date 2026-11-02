"""URL scrubbing: every URL written anywhere passes ``scrub_url`` (contract section 3.6)."""
from __future__ import annotations

import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlsplit

_ACCEPTED_SCHEMES = ("http", "https", "ssh", "git")
_SCP_RE = re.compile(r"^(?:(?P<user>[^@/\s:]+)@)?(?P<host>[A-Za-z0-9][A-Za-z0-9.\-]*):(?P<path>\S+)$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_DOWNLOAD_PATH_RE = re.compile(r"^[A-Za-z0-9._~/-]+$")
_TLD_RE = re.compile(r"^[a-z]{2,5}$")
# DOWNLOAD_LOCATION_RE of contract Appendix C (fullmatch)
DOWNLOAD_LOCATION_RE = re.compile(
    r"NONE|NOASSERTION|git\+https?://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
    r"\.[a-z]{2,5}/[A-Za-z0-9._~/-]+@[0-9a-f]{7,64}")


def _format(scheme: str, host: str, port: Optional[int], path: str) -> str:
    shown = "[%s]" % host if ":" in host else host
    if port is not None:
        shown += ":%d" % port
    return "%s://%s%s" % (scheme, shown, path)


def _resolve_relative(text: str, base: Optional[str]) -> Optional[str]:
    """Git's rule for relative submodule URLs: each leading '../' drops one path component of the remote URL,
    './' keeps the remote URL as it is, and the rest is appended."""
    if not base:
        return None
    scrubbed_base = scrub_url(base)
    if scrubbed_base is None:
        return None
    parts = urlsplit(scrubbed_base)
    segments: List[str] = [s for s in parts.path.split("/") if s]
    rest = text
    while True:
        if rest.startswith("./"):
            rest = rest[2:]
        elif rest.startswith("../"):
            rest = rest[3:]
            if not segments:
                return None
            segments.pop()
        elif rest == "..":
            rest = ""
            if not segments:
                return None
            segments.pop()
        elif rest == ".":
            rest = ""
        else:
            break
    rest = rest.split("?", 1)[0].split("#", 1)[0]
    tail = [s for s in rest.split("/") if s]
    if any(s in (".", "..") for s in tail):
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname or ""
    if not host:
        return None
    return _format(parts.scheme, host, port, "/" + "/".join(segments + tail) if segments or tail else "")


def scrub_url(url: Optional[str], *, base: Optional[str] = None) -> Optional[str]:
    """Scheme, host, port and path of a remote URL; userinfo, query and fragment are dropped.

    Accepts http, https, ssh, git (case-insensitive scheme) and scp-like ``user@host:path`` (-> ``ssh://host/path``).
    Relative ``./`` and ``../`` URLs are resolved against ``base`` when given. Local paths and ``file://`` -> None.
    """
    if not isinstance(url, str):
        return None
    text = url.strip()
    if not text or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in text):
        return None
    if text in (".", "..") or text.startswith("./") or text.startswith("../"):
        return _resolve_relative(text, base)
    if "://" not in text:
        match = _SCP_RE.match(text)
        if match and (match.group("user") or "." in match.group("host")) and not text.startswith("/"):
            path = match.group("path").split("?", 1)[0].split("#", 1)[0].lstrip("/")
            if not path:
                return None
            return "ssh://%s/%s" % (match.group("host").lower(), path)
        return None
    try:
        parts = urlsplit(text)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if scheme not in _ACCEPTED_SCHEMES or not host:
        return None
    return _format(scheme, host.lower(), port, parts.path)


def https_form(url: Optional[str]) -> Optional[str]:
    """ssh/git/http(s) forge URL -> 'https://host/owner/repo' (no '.git'); None if it is not a forge-shaped URL."""
    scrubbed = scrub_url(url)
    if scrubbed is None:
        return None
    parts = urlsplit(scrubbed)
    host = parts.hostname
    if not host:
        return None
    path = parts.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    segments = path.split("/") if path else []
    if len(segments) < 2 or any(not s for s in segments):
        return None
    shown = "[%s]" % host if ":" in host else host
    if parts.scheme in ("http", "https"):
        try:
            port = parts.port
        except ValueError:
            return None
        if port is not None:
            shown += ":%d" % port
    return "https://%s/%s" % (shown, "/".join(segments))


def spdx_download_location(url: Optional[str], sha: Optional[str]) -> str:
    """'git+https://<host>/<path>.git@<sha>', or NOASSERTION.

    NOASSERTION when: no url or sha; the host is an IP address or 'localhost'; a port is present; the TLD does not
    match [a-z]{2,5}; the path has characters outside [A-Za-z0-9._~/-].
    """
    if not url or not sha or not _SHA_RE.match(sha):
        return "NOASSERTION"
    scrubbed = scrub_url(url)
    if scrubbed is None:
        return "NOASSERTION"
    parts = urlsplit(scrubbed)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        return "NOASSERTION"
    if not host or port is not None or host == "localhost":
        return "NOASSERTION"
    try:
        ipaddress.ip_address(host)
        return "NOASSERTION"
    except ValueError:
        pass
    if "." not in host or not _TLD_RE.match(host.rsplit(".", 1)[1]):
        return "NOASSERTION"
    path = parts.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    if not path or not _DOWNLOAD_PATH_RE.match(path):
        return "NOASSERTION"
    result = "git+https://%s/%s.git@%s" % (host, path, sha.lower())
    return result if DOWNLOAD_LOCATION_RE.fullmatch(result) else "NOASSERTION"
