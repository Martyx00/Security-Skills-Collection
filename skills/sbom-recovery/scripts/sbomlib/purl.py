"""Package URLs from evidence, never invented (contract sections 3.11 and 6.11, Appendix C).

Rules (the report's anti-invention rules):

* ``pkg:github/<owner>/<repo>@<revision>`` only for a github.com repository that is dedicated to the component
  (``dedicated=True``, the map's ``purl_type == "github"``), with a lowercase owner and repository name and the exact tag,
  else the commit, as the version. No owner is ever guessed.
* ``pkg:conan/<name>@<version>`` and ``pkg:vcpkg/<name>@<version>`` with the manager's own name and version.
* Otherwise ``pkg:generic/<name>@<version>?vcs_url=git%2Bhttps://...`` (or ``download_url=``) when an upstream is known.
* Nothing else: ``None``. A name or version the grammar cannot carry also gives ``None``.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import quote, urlsplit

from sbomlib import urls

# Appendix C
PURL_RE = re.compile(
    r"pkg:(?P<type>[a-z][a-z0-9.+\-]*)/(?:(?P<ns>[A-Za-z0-9.\-_~%]+(?:/[A-Za-z0-9.\-_~%]+)*)/)?"
    r"(?P<name>[A-Za-z0-9.\-_~%]+)(?:@(?P<version>[A-Za-z0-9.\-_~%+:]+))?"
    r"(?:\?(?P<q>[A-Za-z0-9.\-_]+=[^&#\s]+(?:&[A-Za-z0-9.\-_]+=[^&#\s]+)*))?(?:#(?P<sub>\S+))?")
_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_NO_VERSION = (None, "", "NOASSERTION")
_MANAGERS = ("conan", "vcpkg")


def _enc(text: str) -> str:
    return quote(text, safe="")


def is_valid_purl(s: str) -> bool:
    """Appendix C grammar plus the extra rules: the name is non-empty (``pkg:x/@1`` fails), ``pkg:github`` carries a
    lowercase owner and repository, every ``%`` starts a valid escape."""
    if not isinstance(s, str):
        return False
    match = PURL_RE.fullmatch(s)
    if match is None or _BAD_PERCENT_RE.search(s):
        return False
    if match.group("type") == "github":
        namespace, name = match.group("ns"), match.group("name")
        if not namespace or "/" in namespace or namespace != namespace.lower() or name != name.lower():
            return False
    return True


def _github_owner_repo(upstream_url: Optional[str]) -> Optional[str]:
    form = urls.https_form(upstream_url) if upstream_url else None
    if not form:
        return None
    parts = urlsplit(form)
    if (parts.hostname or "").lower() != "github.com":
        return None
    segments = [s for s in parts.path.split("/") if s]
    if len(segments) != 2:
        return None
    return "%s/%s" % (_enc(segments[0].lower()), _enc(segments[1].lower()))


def _vcs_url(upstream_url: Optional[str], revision: Optional[str]) -> Optional[str]:
    form = urls.https_form(upstream_url) if upstream_url else None
    if form is None:
        scrubbed = urls.scrub_url(upstream_url) if upstream_url else None
        if scrubbed is None or not scrubbed.startswith(("https://", "http://")):
            return None
        form = scrubbed[:-4] if scrubbed.endswith(".git") else scrubbed
    text = "git+" + form + ".git"
    if revision:
        text += "@" + revision
    return quote(text, safe="/:")


def make_purl(*, name: str, version: Optional[str], tag: Optional[str] = None, commit: Optional[str] = None,
              upstream_url: Optional[str] = None, manager: Optional[str] = None, manager_name: Optional[str] = None,
              manager_version: Optional[str] = None, download_url: Optional[str] = None,
              dedicated: bool = True) -> Optional[str]:
    """The purl of a component, or ``None`` when the evidence supports none.

    ``dedicated`` says that a github.com ``upstream_url`` holds only this component (the curated map's
    ``purl_type: "github"``); a repository that holds several components never gets a ``pkg:github`` purl.
    """
    purl: Optional[str] = None
    real_version = version if version not in _NO_VERSION else None
    if manager in _MANAGERS and manager_name and manager_version and manager_version != "NOASSERTION":
        purl = "pkg:%s/%s@%s" % (manager, _enc(manager_name), _enc(manager_version))
    if purl is None and dedicated:
        owner_repo = _github_owner_repo(upstream_url)
        revision = tag or commit
        if owner_repo and revision:
            purl = "pkg:github/%s@%s" % (owner_repo, _enc(revision))
    if purl is None and name:
        revision = tag or commit
        generic_version = real_version or revision
        vcs = _vcs_url(upstream_url, revision)
        qualifier = None
        if vcs:
            qualifier = "vcs_url=" + vcs
        elif download_url:
            scrubbed = urls.scrub_url(download_url)
            if scrubbed and scrubbed.startswith(("https://", "http://")):
                qualifier = "download_url=" + quote(scrubbed, safe="/:")
        if generic_version and qualifier:
            segments = [seg for seg in name.strip().split("/") if seg]
            if segments:
                purl = "pkg:generic/%s@%s?%s" % ("/".join(_enc(seg) for seg in segments), _enc(generic_version), qualifier)
    if purl is not None and not is_valid_purl(purl):
        return None
    return purl
