"""``#include`` scanning (contract sections 3.9 and 4.6, ``includes.py`` row).

The include lines of first-party C/C++ files and of the sources of every candidate are stored in ``inventory.json``
(``includes``); the ``#define`` lines of first-party files go to ``macro_defs``. A header that ``include_map.json`` maps to a
library for which the repository has no candidate yet creates a ``system`` candidate (no discover evidence, a note
``created from include_map: <header>``); the include sites themselves become ``INCLUDE`` records in phase 3.
"""
from __future__ import annotations

from typing import Any, Dict, List

from sbomlib import csource
from sbomlib.discover import buildrefs
from sbomlib.discover import session as sess
from sbomlib.discover.session import Session
from sbomlib.norm import norm_library

MAX_MACRO_DEFS = 60000


def run(S: Session) -> None:
    includes: Dict[str, List[Dict[str, Any]]] = {}
    macro_defs: Dict[str, List[Dict[str, Any]]] = {}
    total_macros = 0
    created: Dict[str, str] = {}
    for index, path in enumerate(S.paths):
        if not sess.is_c_file(path):
            continue
        if index % 200 == 0:
            S.check_budget()
        owner = S.reg.owner_of(path)
        first_party = owner is None
        data = S.fs.read_bytes(path)
        if data is None or b"#" not in data:
            continue
        has_include = b"include" in data or b"import" in data
        has_define = first_party and b"define" in data
        if not has_include and not has_define:
            continue
        text = data.decode("utf-8", "replace")
        if has_include:
            found = csource.scan_includes(text)
            if found:
                includes[path] = found
                for item in found:
                    lib = S.imap.header_lib(item["header"])
                    if lib is None:
                        continue
                    canon = S.identity.canonical(lib)
                    if S.reg.find(norm_library(canon)) is None and norm_library(canon) not in created:
                        cand = buildrefs.find_or_create_system(S, canon, path)
                        S.reg.add_note(cand, "created from include_map: %s" % item["header"])
                        created[norm_library(canon)] = cand["id"]
        if has_define and total_macros < MAX_MACRO_DEFS:
            macros = csource.defined_macros(text)
            if macros:
                macro_defs[path] = [{"line": line, "macro": macro, "guards": guards} for line, macro, guards in macros]
                total_macros += len(macros)
    S.inv["includes"] = dict(sorted(includes.items()))
    S.inv["macro_defs"] = dict(sorted(macro_defs.items()))
    if total_macros >= MAX_MACRO_DEFS:
        S.inv["macro_defs_truncated"] = True
