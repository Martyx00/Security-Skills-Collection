"""Lookups over ``assets/include_map.json`` (contract section 4.28): header ownership, system headers, packages, link names."""
from __future__ import annotations

import posixpath
from typing import Any, Dict, List, Optional, Set

_SYSTEM_PREFIXES = ("sys/", "linux/", "asm/", "asm-generic/", "bits/", "netinet/", "arpa/", "net/", "scsi/", "mach/",
                    "machine/", "x86_64-linux-gnu/", "c++/")


class IncludeMap:
    def __init__(self, data: Dict[str, Any]) -> None:
        headers = data.get("headers") or {}
        self.exact: Dict[str, str] = {}
        self.wild: Dict[str, str] = {}
        self._exact_by_base: Dict[str, List[str]] = {}
        self._wild_last: Dict[str, List[str]] = {}
        for key, lib in headers.items():
            if key.endswith("/*"):
                directory = key[:-2].strip("/")
                self.wild[directory] = lib
                self._wild_last.setdefault(directory.rsplit("/", 1)[-1], []).append(directory)
            else:
                self.exact[key] = lib
                self._exact_by_base.setdefault(posixpath.basename(key), []).append(key)
        self.system: Set[str] = set(data.get("system_headers") or [])
        self.packages: Dict[str, str] = {k.lower(): v for k, v in (data.get("packages") or {}).items()}
        self.link_names: Dict[str, str] = dict(data.get("link_names") or {})
        self._link_ci: Dict[str, str] = {k.lower(): v for k, v in self.link_names.items()}
        self.link_namespaces: Dict[str, str] = {k.lower(): v for k, v in (data.get("link_namespaces") or {}).items()}
        self.distro: Dict[str, str] = {k.lower(): v for k, v in (data.get("distro_packages") or {}).items()}

    # ------------------------------------------------------------------ headers
    def header_lib(self, header: str) -> Optional[str]:
        """Library that owns an ``#include`` argument: exact header, then ``dir/*``, then the header without leading directories."""
        text = header.replace("\\", "/").strip()
        while text.startswith("./"):
            text = text[2:]
        if text in self.exact:
            return self.exact[text]
        parts = text.split("/")
        for count in range(len(parts) - 1, 0, -1):
            key = "/".join(parts[:count])
            if key in self.wild:
                return self.wild[key]
        for index in range(1, len(parts)):
            suffix = "/".join(parts[index:])
            if suffix in self.exact:
                return self.exact[suffix]
            head = "/".join(parts[index:-1])
            if head and head in self.wild:
                return self.wild[head]
        return None

    def path_libs(self, path: str) -> List[str]:
        """Libraries that own a tracked header ``path`` (suffix match of exact headers, directory match of ``dir/*``)."""
        libs: List[str] = []
        base = posixpath.basename(path)
        for key in self._exact_by_base.get(base, ()):
            if "/" not in key or path == key or path.endswith("/" + key):
                lib = self.exact[key]
                if lib not in libs:
                    libs.append(lib)
        directory = "/" + posixpath.dirname(path) + "/"
        for last in {d.rsplit("/", 1)[-1] for d in self.wild}:
            if "/" + last + "/" not in directory:
                continue
            for key in self._wild_last.get(last, ()):
                if "/" + key + "/" in directory:
                    lib = self.wild[key]
                    if lib not in libs:
                        libs.append(lib)
        return libs

    def is_system(self, header: str) -> bool:
        text = header.replace("\\", "/").strip()
        return text in self.system or text.startswith(_SYSTEM_PREFIXES)

    # ------------------------------------------------------------------ packages and link names
    def package_lib(self, name: str) -> Optional[str]:
        return self.packages.get((name or "").lower())

    def distro_lib(self, name: str) -> Optional[str]:
        return self.distro.get((name or "").lower())

    def link_lib(self, item: str) -> Optional[str]:
        """Library named by a link item: exact (then case-insensitive) ``link_names``, ``-l<name>``, ``<ns>::<x>`` namespaces."""
        text = (item or "").strip()
        if text.startswith("-l"):
            text = text[2:]
        if not text:
            return None
        if text in self.link_names:
            return self.link_names[text]
        lowered = text.lower()
        if lowered in self._link_ci:
            return self._link_ci[lowered]
        if "::" in text:
            ns = text.split("::", 1)[0].lower()
            if ns in self.link_namespaces:
                return self.link_namespaces[ns]
        return None
