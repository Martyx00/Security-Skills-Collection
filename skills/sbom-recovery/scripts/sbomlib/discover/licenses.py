"""Licence of a component from its own top-level licence file (contract section 1.3 S15).

Only ``LICENSE*`` / ``LICENCE*`` / ``COPYING*`` / ``UNLICENSE`` files at the top of a candidate directory are read, and only
fingerprints of the common texts are recognized: MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, Zlib, curl, ISC, BSL-1.0,
Unlicense, GPL-2.0, GPL-3.0, LGPL-2.1, LGPL-3.0, MPL-2.0. Anything else (or a directory whose files disagree) stays
``NOASSERTION``.
"""
from __future__ import annotations

import posixpath
import re
from typing import List, Optional, Tuple

from sbomlib.discover.session import Session

_LICENSE_NAME_RE = re.compile(r"^(?:licen[cs]e|copying|unlicense)(?:[-_.].*)?$", re.I)
_NAME_ORDER = ("license", "licence", "copying", "unlicense")


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9.,;:'\"()/-]+", " ", text.lower())).strip()


def identify(text: str) -> Optional[str]:
    """SPDX id of a licence text, or None when it matches none (or several incompatible) fingerprints."""
    t = _norm(text)
    found: List[str] = []

    def has(*needles: str) -> bool:
        return all(_norm(n) in t for n in needles)

    if has("gnu lesser general public license"):
        if "version 2.1" in t:
            found.append("LGPL-2.1")
        elif "version 3" in t:
            found.append("LGPL-3.0")
    elif has("gnu general public license"):
        if "version 3, 29 june 2007" in t:
            found.append("GPL-3.0")
        elif "version 2, june 1991" in t:
            found.append("GPL-2.0")
    if has("mozilla public license", "version 2.0"):
        found.append("MPL-2.0")
    if has("apache license", "version 2.0"):
        found.append("Apache-2.0")
    if has("boost software license", "version 1.0"):
        found.append("BSL-1.0")
    if has("this is free and unencumbered software released into the public domain"):
        found.append("Unlicense")
    if has("copyright and permission notice", "permission to use, copy, modify, and distribute this software for any purpose"):
        found.append("curl")
    elif has("permission to use, copy, modify, and/or distribute this software for any purpose with or without fee"):
        found.append("ISC")
    if has("this software is provided 'as-is', without any express or implied warranty",
           "altered source versions must be plainly marked as such"):
        found.append("Zlib")
    if has("permission is hereby granted, free of charge, to any person obtaining a copy"):
        found.append("MIT")
    if has("redistribution and use in source and binary forms", "redistributions of source code must retain"):
        if has("neither the name of"):
            found.append("BSD-3-Clause")
        elif has("redistributions in binary form must reproduce"):
            found.append("BSD-2-Clause")
    unique = sorted(set(found))
    return unique[0] if len(unique) == 1 else None


def _license_files(S: Session, directory: str) -> List[str]:
    prefix = directory + "/" if directory else ""
    found = []
    for path in S.files_under(directory):
        rest = path[len(prefix):]
        if "/" in rest:
            continue
        if _LICENSE_NAME_RE.match(rest):
            found.append(path)

    def order(path: str) -> Tuple[int, str]:
        base = posixpath.basename(path).lower()
        for index, key in enumerate(_NAME_ORDER):
            if base.startswith(key):
                return index, path
        return len(_NAME_ORDER), path

    return sorted(found, key=order)


def run(S: Session) -> None:
    for cand in list(S.reg.cands.values()):
        if cand["location"]["kind"] not in ("dir", "gitlink") or cand["location"]["path"] is None:
            continue
        directory = cand["location"]["path"]
        S.check_budget()
        results: List[Tuple[str, str, int]] = []
        for path in _license_files(S, directory):
            text = S.fs.text(path)
            if text is None:
                continue
            spdx = identify(text)
            if spdx is None:
                results.append(("", path, 1))
                continue
            first = next((i for i, line in enumerate(text.split("\n"), start=1) if line.strip()), 1)
            results.append((spdx, path, first))
        if not results:
            continue
        recognized = {r[0] for r in results if r[0]}
        chosen = next((r for r in results if r[0]), None)
        if chosen is None or len(recognized) != 1:
            S.reg.add_note(cand, "licence file(s) %s not recognized or ambiguous" % ", ".join(r[1] for r in results[:3]))
            continue
        spdx, path, line = chosen
        evid = S.ev("LICENSE_FILE", path=path, line=line, symbol=spdx, value=spdx, candidate=cand["id"], quote=True)
        cand["license"] = {"id": spdx, "loc": "%s:%d" % (path, line)}
        S.reg.attach(cand, evid)
