"""Candidates, evidence and blind spots of one repository while discovery runs (contract sections 3.9, 4.8, 4.9).

``Registry`` is the single place where candidates are created, found ("attach by identity"), enriched and finally
serialized. Evidence ids come from ``ids.evidence_id`` (stable across runs); two records with the same id and the same
content are one record, a different record with the same id gets the suffix ``-2``, ``-3`` (contract section 6.3).
"""
from __future__ import annotations

import hashlib
import posixpath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from sbomlib import ids, model
from sbomlib.norm import norm_library

IN_TREE = ("vendored", "single_file", "submodule", "prebuilt")
FETCHED = ("fetchcontent", "cpm", "external_project", "lockfile", "package_manager")
#: evidence types whose location is listed in ``candidate.locations``
LOCATION_TYPES = frozenset(("FILE_PRESENT", "VERSION_MACRO", "BANNER", "PROJECT_VERSION", "VERSION_FILE", "GITLINK",
                            "LOCK_PIN", "FETCH_PIN", "MANIFEST_DECL", "FIND_PACKAGE", "SUBDIR_BUILD", "DECLARED_ID",
                            "PREBUILT", "TOOLCHAIN_RUNTIME", "DLOPEN"))
_GROUP_RANK = {"tree": 0, "declared": 1}
_KIND_RANK = {kind: index for index, kind in enumerate(model.VERSION_KINDS)}
_SOURCE_RANK = {"header_macro": 0, "version_file": 1, "project_version": 2, "banner": 3, "git_tag": 4, "describe": 5,
                "generic": 6, "bcr": 10, "conan": 10, "vcpkg": 10, "wrapdb": 10, "hunter": 10, "west": 10, "bazel": 10,
                "idf": 10, "fetchcontent_tag": 11, "constraint": 20, "none": 30}
_CONFLICT_KINDS = ("release", "snapshot", "between_releases", "closest_modified")
_STRONG_SOURCES = ("header_macro", "version_file", "project_version", "git_tag", "describe", "bcr", "conan", "vcpkg",
                   "wrapdb", "hunter", "west", "bazel", "idf", "fetchcontent_tag")
EVIDENCE_PER_CANDIDATE_TARGET = 20


class CandMeta:
    """Internal bookkeeping of a candidate (never serialized)."""

    def __init__(self) -> None:
        self.aliases: Set[str] = set()
        self.dir: Optional[str] = None
        self.file: Optional[str] = None
        self.locs: Set[str] = set()
        self.ev_ids: Set[str] = set()
        self.version_claims: List[Dict[str, Any]] = []
        self.identity_claims: List[Dict[str, Any]] = []
        self.declared_ids: Set[str] = set()
        self.notes: List[str] = []
        self.compile_counts: Dict[str, int] = {}


def _tier(candidate: Dict[str, Any]) -> int:
    kind = candidate["detected_as"]
    if kind in IN_TREE:
        return 0
    if kind in FETCHED:
        return 1
    return 2


def _common_dir_depth(a: str, b: str) -> int:
    pa = a.split("/") if a else []
    pb = b.split("/") if b else []
    depth = 0
    for x, y in zip(pa[:-1], pb[:-1]):
        if x != y:
            break
        depth += 1
    return depth


def sha256_text(data: Optional[bytes]) -> Optional[str]:
    return hashlib.sha256(data).hexdigest() if data is not None else None


class Registry:
    def __init__(self, repo: str) -> None:
        self.repo = repo
        self.cands: Dict[str, Dict[str, Any]] = {}
        self.meta: Dict[str, CandMeta] = {}
        self.order: List[str] = []
        self.evidence: Dict[str, Dict[str, Any]] = {}
        self.blindspots: List[Dict[str, Any]] = []
        self._by_norm: Dict[str, List[str]] = {}
        self._dir_idx: Dict[str, str] = {}
        self._file_idx: Dict[str, str] = {}

    # ------------------------------------------------------------------ candidates
    def create(self, name: str, detected_as: str, kind: str, path: Optional[str], line: Optional[int] = None, *,
               map_entry: Optional[str] = None, aliases: Iterable[str] = (), notes: Iterable[str] = (),
               upstream: Optional[Dict[str, Any]] = None, submodule: Optional[Dict[str, Any]] = None,
               fork_of: Optional[str] = None, first_party: bool = False, sha256: Optional[str] = None,
               identity_confidence: str = "low") -> Dict[str, Any]:
        norm_name = norm_library(name)
        cid = ids.candidate_id(self.repo, norm_name, kind, path or "")
        existing = self.cands.get(cid)
        if existing is not None:
            for alias in aliases:
                self.add_alias(existing, alias)
            for note in notes:
                self.add_note(existing, note)
            return existing
        cand = model.new_candidate(
            id=cid, name=name, norm_name=norm_name, map_entry=map_entry, detected_as=detected_as,
            location={"kind": kind, "path": path, "line": line}, upstream=upstream, submodule=submodule,
            fork_of=fork_of, first_party=first_party, sha256=sha256, identity_confidence=identity_confidence)
        # new_candidate requires a truthy path; system candidates have none
        cand["location"] = {"kind": kind, "path": path, "line": line}
        meta = CandMeta()
        meta.aliases.add(norm_name)
        for alias in aliases:
            if alias:
                meta.aliases.add(norm_library(alias))
        if kind in ("dir", "gitlink"):
            meta.dir = path
            if path:
                self._dir_idx.setdefault(path, cid)
        elif kind == "file":
            meta.file = path
            if path:
                self._file_idx.setdefault(path, cid)
        self.cands[cid] = cand
        self.meta[cid] = meta
        self.order.append(cid)
        self._by_norm.setdefault(norm_name, []).append(cid)
        for note in notes:
            self.add_note(cand, note)
        return cand

    def add_alias(self, cand: Dict[str, Any], name: Optional[str]) -> None:
        if name:
            self.meta[cand["id"]].aliases.add(norm_library(name))

    def add_note(self, cand: Dict[str, Any], note: str) -> None:
        notes = self.meta[cand["id"]].notes
        if note and note not in notes:
            notes.append(note)

    def by_norm(self, norm_name: str) -> List[Dict[str, Any]]:
        return [self.cands[c] for c in self._by_norm.get(norm_name, [])]

    def find(self, norm_name: str, near: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Attach by identity: in-tree candidates first (nearest directory first), then fetched or declared ones, then
        system ones. ``near`` is the repository-relative path of the referencing file."""
        found = self.by_norm(norm_name)
        if not found:
            return None
        near_path = near or ""

        def key(cand: Dict[str, Any]) -> Tuple[int, int, int, str]:
            path = cand["location"]["path"] or ""
            return (_tier(cand), -_common_dir_depth(near_path, path), path.count("/"), path)

        return sorted(found, key=key)[0]

    def find_alias(self, norm_name: str, near: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """A candidate that is known under ``norm_name`` (declared name, directory name, canonical name)."""
        direct = self.find(norm_name, near)
        if direct is not None:
            return direct
        matches = [self.cands[c] for c in self.order if norm_name in self.meta[c].aliases]
        if not matches:
            return None
        return sorted(matches, key=lambda c: (_tier(c), c["location"]["path"] or "", c["id"]))[0]

    def owner_of(self, path: str) -> Optional[Dict[str, Any]]:
        """The candidate whose directory (or file) contains ``path`` (the deepest one); ``path`` itself may be a directory."""
        if not path:
            return None
        file_owner = self._file_idx.get(path)
        if file_owner is not None:
            return self.cands[file_owner]
        probe = path
        while probe:
            cid = self._dir_idx.get(probe)
            if cid is not None:
                return self.cands[cid]
            slash = probe.rfind("/")
            probe = probe[:slash] if slash >= 0 else ""
        return None

    def dir_candidates(self) -> List[Dict[str, Any]]:
        return [self.cands[c] for c in self.order if self.meta[c].dir is not None]

    # ------------------------------------------------------------------ evidence
    def ev(self, repo_etype: str, **fields: Any) -> str:
        """Record evidence; returns its id. ``quote`` (the exact line bytes) becomes ``quote_sha256``."""
        quote = fields.pop("quote", None)
        candidate = fields.get("candidate")
        record_fields = dict(fields)
        record_fields["quote_sha256"] = sha256_text(quote) if quote is not None else record_fields.get("quote_sha256")
        base_id = ids.evidence_id("e", self.repo, repo_etype, record_fields.get("path"), record_fields.get("line"),
                                  record_fields.get("symbol"), candidate)
        record = model.new_evidence(id=base_id, repo=self.repo, type=repo_etype, **record_fields)
        signature = self._signature(record)
        evid = base_id
        suffix = 1
        while evid in self.evidence:
            if self._signature(self.evidence[evid]) == signature:
                return evid
            suffix += 1
            evid = "%s-%d" % (base_id, suffix)
        record["id"] = evid
        self.evidence[evid] = record
        if candidate and candidate in self.meta:
            meta = self.meta[candidate]
            meta.ev_ids.add(evid)
            if repo_etype in LOCATION_TYPES:
                loc = self.location_of(record, self.cands[candidate])
                if loc:
                    meta.locs.add(loc)
        return evid

    @staticmethod
    def _signature(record: Dict[str, Any]) -> Tuple[Any, ...]:
        return tuple((k, repr(record.get(k))) for k in sorted(record) if k != "id")

    @staticmethod
    def location_of(record: Dict[str, Any], cand: Dict[str, Any]) -> Optional[str]:
        path = record.get("path")
        if not path:
            return None
        if (record["type"] == "FILE_PRESENT" and cand["location"]["kind"] == "dir") or record["type"] == "GITLINK":
            return path.rstrip("/") + "/"
        if record.get("line"):
            return "%s:%d" % (path, record["line"])
        return path

    def attach(self, cand: Dict[str, Any], evidence_id: str) -> None:
        self.meta[cand["id"]].ev_ids.add(evidence_id)

    def count_compile(self, cand_id: str, target: str) -> bool:
        """True while fewer than ``EVIDENCE_PER_CANDIDATE_TARGET`` COMPILE_LIST records exist for the pair."""
        counts = self.meta[cand_id].compile_counts
        counts[target] = counts.get(target, 0) + 1
        return counts[target] <= EVIDENCE_PER_CANDIDATE_TARGET

    # ------------------------------------------------------------------ claims
    def claim_version(self, cand: Dict[str, Any], canon: Dict[str, Any], source: str, group: str,
                      evidence_ids: Sequence[str], notes: Sequence[str] = ()) -> None:
        meta = self.meta[cand["id"]]
        all_notes = list(canon.get("notes") or []) + [n for n in notes if n]
        claim = {"version": canon["version"], "version_raw": canon.get("version_raw") or None,
                 "version_kind": canon["version_kind"], "version_source": source,
                 "cpe_version": canon.get("cpe_version"), "cpe_update": canon.get("cpe_update"),
                 "evidence_ids": sorted(set(evidence_ids)), "notes": all_notes, "group": group,
                 "order": len(meta.version_claims)}
        for old in meta.version_claims:
            same = (old["version"], old["version_kind"], old["version_raw"], old["version_source"], old["group"])
            if same == (claim["version"], claim["version_kind"], claim["version_raw"], claim["version_source"], group):
                old["evidence_ids"] = sorted(set(old["evidence_ids"]) | set(claim["evidence_ids"]))
                for note in all_notes:
                    if note not in old["notes"]:
                        old["notes"].append(note)
                return
        meta.version_claims.append(claim)

    def claim_identity(self, cand: Dict[str, Any], name: str, evidence_ids: Sequence[str] = ()) -> None:
        meta = self.meta[cand["id"]]
        for old in meta.identity_claims:
            if norm_library(old["name"]) == norm_library(name):
                old["evidence_ids"] = sorted(set(old["evidence_ids"]) | set(evidence_ids))
                return
        meta.identity_claims.append({"name": name, "evidence_ids": sorted(set(evidence_ids))})

    def blind(self, code: str, message: str, loc: Optional[str] = None, candidate: Optional[str] = None) -> None:
        if code not in model.BLINDSPOT_CODES:
            raise ValueError("unknown blind spot code: %r" % (code,))
        entry = {"code": code, "message": message[:200], "loc": loc, "candidate": candidate}
        if entry not in self.blindspots:
            self.blindspots.append(entry)

    # ------------------------------------------------------------------ finalization
    def _finish_version(self, cand: Dict[str, Any]) -> None:
        meta = self.meta[cand["id"]]
        claims = sorted(meta.version_claims, key=lambda c: (
            _GROUP_RANK.get(c["group"], 9), _KIND_RANK.get(c["version_kind"], 9),
            _SOURCE_RANK.get(c["version_source"], 25), c["order"]))
        options: List[Dict[str, Any]] = []
        for index, claim in enumerate(claims):
            options.append({"id": "v%d" % index, "version": claim["version"], "version_raw": claim["version_raw"],
                            "version_kind": claim["version_kind"], "version_source": claim["version_source"],
                            "cpe_version": claim["cpe_version"], "cpe_update": claim["cpe_update"],
                            "evidence_ids": list(claim["evidence_ids"]), "notes": list(claim["notes"])})
        if not options:
            options = [{"id": "v0", "version": "NOASSERTION", "version_raw": None, "version_kind": "none",
                        "version_source": "none", "cpe_version": None, "cpe_update": None, "evidence_ids": [],
                        "notes": []}]
        top = options[0]
        first_group = claims[0]["group"] if claims else None
        compared = {(c["version"] if c["version_kind"] == "release" else (c["version_kind"], c["version_raw"]))
                    for c in claims if c["group"] == first_group and c["version_kind"] in _CONFLICT_KINDS}
        version = {"version": top["version"], "version_raw": top["version_raw"], "version_kind": top["version_kind"],
                   "version_source": top["version_source"], "cpe_version": top["cpe_version"],
                   "cpe_update": top["cpe_update"], "evidence_ids": list(top["evidence_ids"]),
                   "conflict": len(compared) > 1, "notes": list(top["notes"]), "options": options}
        cand["version"] = version
        if top["version_kind"] == "release":
            cand["version_confidence"] = "high" if top["version_source"] in _STRONG_SOURCES else "medium"
        elif top["version_kind"] in ("snapshot", "between_releases", "closest_modified"):
            cand["version_confidence"] = "medium"
        elif top["version_kind"] == "constraint":
            cand["version_confidence"] = "low"
        else:
            cand["version_confidence"] = "none"

    def finalize(self) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        dirs = [(self.meta[c].dir, c) for c in self.order if self.meta[c].dir is not None]
        for cid in self.order:
            cand = self.cands[cid]
            meta = self.meta[cid]
            self._finish_version(cand)
            loc = cand["location"]
            base_loc = None
            if loc["kind"] in ("dir", "gitlink") and loc["path"]:
                base_loc = loc["path"].rstrip("/") + "/"
            elif loc["kind"] in ("file", "manifest") and loc["path"]:
                base_loc = "%s:%d" % (loc["path"], loc["line"]) if loc.get("line") else loc["path"]
            if base_loc:
                meta.locs.add(base_loc)
            cand["locations"] = sorted(meta.locs)
            cand["evidence_ids"] = sorted(meta.ev_ids)
            cand["declared_ids"] = sorted(meta.declared_ids)
            cand["notes"] = list(meta.notes)
            claims = list(meta.identity_claims)
            names = [c["name"] for c in claims]
            if cand["name"] not in names and not any(norm_library(n) == cand["norm_name"] for n in names):
                claims.insert(0, {"name": cand["name"], "evidence_ids": []})
            claims.sort(key=lambda c: (norm_library(c["name"]) != cand["norm_name"], c["name"]))
            cand["identity_options"] = [{"name": c["name"], "evidence_ids": sorted(c["evidence_ids"])} for c in claims]
            within: Optional[str] = None
            path = loc["path"] or ""
            if path and loc["kind"] in ("dir", "file", "gitlink"):
                best = -1
                for dpath, other in dirs:
                    if other != cid and dpath and path.startswith(dpath + "/") and len(dpath) > best:
                        within, best = other, len(dpath)
            cand["within"] = within
        candidates = [self.cands[c] for c in sorted(self.order, key=lambda c: (
            self.cands[c]["location"]["kind"], self.cands[c]["location"]["path"] or "", self.cands[c]["norm_name"], c))]
        blind = sorted(self.blindspots, key=lambda b: (b["code"], b["loc"] or "", b["candidate"] or ""))
        evidence = [self.evidence[e] for e in sorted(self.evidence)]
        return candidates, blind, evidence

    @staticmethod
    def parent_dir(path: str) -> str:
        return posixpath.dirname(path)
