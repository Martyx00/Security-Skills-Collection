"""Phase 5: review rows, pre-fill, the review CSV and its strict read-back (contract sections 4.12, 4.13, 6.11).

``build_rows`` turns the final verdicts of every DONE/INCOMPLETE repository into one row per review key. Pre-fill follows
the single precedence list of the report: local decisions, the curated map, declared identifiers, model hints (added
later by ``hints``). Nothing here talks to the network.
"""
from __future__ import annotations

import os
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from sbomlib import csvio, errors, fsio, ids, model, purl as purl_mod
from sbomlib.context import RunContext
from sbomlib.cpe import cpemap, cpestr, decisions, store
from sbomlib.norm import join_list, norm_library, repo_kv, split_list

HEADER = ("id", "include", "include_in", "action", "search_name", "vendor_hint", "product_hint", "part_hint", "cpe_override",
          "cpe_version_override", "cpe_update_override", "extra_vendor_products", "name", "version", "version_kind",
          "upstream_commit", "verification", "reason", "repositories", "proposed_vendor_products", "tier", "basis",
          "alternatives", "version_in_dictionary", "nvd_cve_count", "version_confidence", "upstream_url", "purl",
          "previously_approved", "evidence_summary")
EDITABLE = model.EDITABLE_COLUMNS
READ_ONLY = tuple(c for c in HEADER if c != "id" and c not in EDITABLE)
PREAMBLE = (
    "# Approval authorizes sending the name and version (and search_name) of every row with include=yes and action=lookup "
    "to the NVD Products API.",
    "# Approval emits the pairs in proposed_vendor_products (replaced by cpe_override when that cell is set) plus every pair "
    "typed into extra_vendor_products or entered as vendor_hint with product_hint. Pairs listed only in alternatives are "
    "never emitted unless you copy them into one of those cells.",
    "# Editable columns: include, include_in, action, search_name, vendor_hint, product_hint, part_hint, cpe_override, "
    "cpe_version_override, cpe_update_override, extra_vendor_products. include=no excludes the row from every repository; "
    "include=yes with include_in limits it to the listed repositories. All other columns are ignored when the file is read "
    "back. Do not delete rows; set include=no instead.",
)
ENUMS = {"include": ("yes", "no"), "action": ("lookup", "skip", "manual"), "part_hint": ("", "a", "o", "h")}
SEARCH_NAME_MAX = 128
SUMMARY_MAX = 300
PACKAGE_DECLARATIONS = ("package_manager", "lockfile", "fetchcontent", "cpm", "external_project")
VERIFICATION_RANK = {"proven": 3, "declared": 2, "unresolved": 1}
EVIDENCE_TYPE_ORDER = ("COMPILE_LIST", "LINK_PROOF", "LINK_LINE", "API_HIT", "INCLUDE", "TRANSITIVE", "SUBDIR_BUILD",
                       "LINK_REF", "FIND_PACKAGE", "DLOPEN", "BUILD_REF_UNPARSED", "PREBUILT", "GITLINK")
STRENGTH_RANK = {"strong": 0, "medium": 1, "weak": 2, "none": 3, "absence": 4}
VERSION_EVIDENCE_TYPES = ("VERSION_MACRO", "PROJECT_VERSION", "VERSION_FILE", "GIT_DESCRIBE", "LOCK_PIN", "FETCH_PIN",
                          "BANNER", "MANIFEST_DECL", "GITLINK", "DECLARED_ID", "FILE_PRESENT", "FIND_PACKAGE", "PREBUILT")


def _verify() -> Any:
    """``sbomlib.verify`` (imported on use: WP-verify's package is only needed when rows are built)."""
    from sbomlib import verify
    return verify


# ------------------------------------------------------------------------------------------------- cell validation

def _explain(column: str, code: str) -> str:
    return {
        "BAD_VALUE": {"include": "include must be yes or no", "action": "action must be lookup, skip or manual",
                      "search_name": "search_name must be at most %d characters without control characters"
                                     % SEARCH_NAME_MAX},
        "BAD_INCLUDE_IN": {"include_in": "include_in must list repositories of the row's repositories cell, separated by ;"},
        "BAD_CPE": {"cpe_override": "cpe_override must be empty or a full 13-field CPE 2.3 string such as "
                                    "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                    "cpe_version_override": "cpe_version_override must be empty or a CPE attribute value such as 1.2.3 or *",
                    "cpe_update_override": "cpe_update_override must be empty or a CPE attribute value such as rc1 or *"},
        "BAD_PAIR": {"extra_vendor_products": "extra_vendor_products must be ;-separated [part:]vendor:product items"},
        "BAD_HINT": {"vendor_hint": "vendor_hint must be empty or 1-100 characters of A-Z a-z 0-9 . _ -",
                     "product_hint": "product_hint must be empty or 1-100 characters of A-Z a-z 0-9 . _ -",
                     "part_hint": "part_hint must be empty, a, o or h"},
    }[code][column]


def _has_control(text: str) -> bool:
    return any(unicodedata.category(ch) == "Cc" for ch in text)


def normalize_cell(column: str, value: str, repositories: Sequence[str]) -> Tuple[str, Optional[str]]:
    """``(normalized value, error code)`` of one editable cell. Enums are lowercased, lists split and re-joined sorted,
    surrounding white space is removed; the error code is one of the section 4.13 codes or None."""
    text = (value or "").strip()
    if column == "include":
        text = text.lower()
        return (text, None if text in ENUMS["include"] else "BAD_VALUE")
    if column == "action":
        text = text.lower()
        return (text, None if text in ENUMS["action"] else "BAD_VALUE")
    if column == "include_in":
        items = split_list(text, ";")
        if any(item not in repositories for item in items):
            return (text, "BAD_INCLUDE_IN")
        return (join_list(items), None)
    if column == "search_name":
        if len(text) > SEARCH_NAME_MAX or _has_control(text):
            return (text, "BAD_VALUE")
        return (text, None)
    if column in ("vendor_hint", "product_hint"):
        if text and not cpestr.HINT_CELL_RE.fullmatch(text):
            return (text, "BAD_HINT")
        return (text, None)
    if column == "part_hint":
        text = text.lower()
        return (text, None if text in ENUMS["part_hint"] else "BAD_HINT")
    if column == "cpe_override":
        if text and not cpestr.is_valid_cpe23(text):
            return (text, "BAD_CPE")
        return (text, None)
    if column in ("cpe_version_override", "cpe_update_override"):
        if text and not cpestr.ATTR_RE.fullmatch(text):
            return (text, "BAD_CPE")
        return (text, None)
    if column == "extra_vendor_products":
        pairs: List[str] = []
        for item in split_list(text, ";"):
            if not cpestr.PAIR_RE.fullmatch(item):
                return (text, "BAD_PAIR")
            part, vendor, product = cpestr.parse_pair(item)
            pairs.append(cpestr.pair_str(part, vendor, product))
        return (join_list(pairs), None)
    raise ValueError("not an editable column: %r" % (column,))


def cell_value(row: Dict[str, Any], column: str) -> str:
    """The text of an editable cell as stored in a names row (normalized without raising)."""
    raw = row.get(column)
    if column == "include_in":
        text = join_list(raw or [])
    else:
        text = str(raw or "")
    normalized, error = normalize_cell(column, text, row.get("repositories") or [])
    return normalized if error is None else text


def _join_pairs(items: Iterable[Dict[str, Any]]) -> str:
    return join_list([item["pair"] for item in items], sort=False)


def _basis_text(row: Dict[str, Any]) -> str:
    items = ["%s=%s" % (p["pair"], p["basis"]) for p in list(row.get("proposals") or []) + list(row.get("alternatives") or [])]
    if row.get("map_status") == "no-nvd-cpe":
        items.append("map:no-nvd-cpe")
    return join_list(items, sort=False)


def _reason_text(row: Dict[str, Any]) -> str:
    items = ["%s:%s" % (repo, code) for repo, code in sorted((row.get("reason") or {}).items())]
    items.extend("*:%s" % note.replace(";", ",") for note in row.get("notes") or [])
    return join_list(items)


def row_cells(row: Dict[str, Any]) -> List[str]:
    """The cells of one review row in header order (unguarded)."""
    values = {
        "id": row["id"],
        "include": row.get("include", "no"), "include_in": join_list(row.get("include_in") or []),
        "action": row.get("action", "lookup"), "search_name": row.get("search_name", ""),
        "vendor_hint": row.get("vendor_hint", ""), "product_hint": row.get("product_hint", ""),
        "part_hint": row.get("part_hint", ""), "cpe_override": row.get("cpe_override", ""),
        "cpe_version_override": row.get("cpe_version_override", ""),
        "cpe_update_override": row.get("cpe_update_override", ""),
        "extra_vendor_products": row.get("extra_vendor_products", ""),
        "name": row["name"], "version": row["version"], "version_kind": row.get("version_kind", "none"),
        "upstream_commit": row.get("upstream_commit", ""), "verification": repo_kv(row.get("verification") or {}),
        "reason": _reason_text(row), "repositories": join_list(row.get("repositories") or []),
        "proposed_vendor_products": _join_pairs(row.get("proposals") or []), "tier": row.get("tier", "none"),
        "basis": _basis_text(row), "alternatives": _join_pairs(row.get("alternatives") or []),
        "version_in_dictionary": row.get("version_in_dictionary", "unknown"), "nvd_cve_count": row.get("nvd_cve_count", ""),
        "version_confidence": row.get("version_confidence", "none"), "upstream_url": row.get("upstream_url", ""),
        "purl": row.get("purl", ""), "previously_approved": row.get("previously_approved", "no"),
        "evidence_summary": row.get("evidence_summary", ""),
    }
    return [str(values[column]) for column in HEADER]


# ------------------------------------------------------------------------------------------------- building rows

class _Member:
    """One review-eligible verdict of one repository."""

    def __init__(self, repo: str, cand: Dict[str, Any], verdict: Dict[str, Any], identity: str, version: Dict[str, Any],
                 verification: str) -> None:
        self.repo = repo
        self.cand = cand
        self.verdict = verdict
        self.identity = identity
        self.version = version
        self.verification = verification


def _effective_verification(verdict: Dict[str, Any], scope_all: bool) -> Optional[str]:
    cls = verdict.get("class")
    verification = verdict.get("verification")
    if cls == "USED":
        return verification if verification in model.VERIFICATION else "declared"
    if cls == "INCONCLUSIVE":
        return verification if verification in ("declared", "unresolved") else None
    if cls == "UNANALYZED":
        return verification if verification in model.VERIFICATION else "unresolved"
    if scope_all and cls in ("TEST_ONLY", "BUILD_ONLY", "DEV_ONLY"):
        return "proven"
    return None


class _Evidence:
    """Lazy evidence index of one repository (discover and verify records by id)."""

    def __init__(self, ctx: RunContext, repo: str) -> None:
        self.ctx = ctx
        self.repo = repo
        self._records: Optional[Dict[str, Dict[str, Any]]] = None

    def get(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        if self._records is None:
            self._records = {}
            base = self.ctx.layout.repo_out(self.repo)
            for name in ("evidence.jsonl", "verify_evidence.jsonl", "worker_evidence.jsonl"):
                path = base / name
                if os.path.lexists(str(path)):
                    for rec in fsio.read_jsonl(path):
                        if isinstance(rec, dict) and "id" in rec:
                            self._records[rec["id"]] = rec
        return self._records.get(evidence_id)


def _known_identities(ctx: RunContext) -> Set[str]:
    """Normalized library names the shipped version rules and include map know (identity evidence of the report)."""
    names: Set[str] = set()
    try:
        for rule in ctx.asset("version_rules.json").get("rules") or []:
            names.add(norm_library(str(rule.get("library", ""))))
        imap = ctx.asset("include_map.json")
        for table in ("headers", "packages", "link_names", "link_namespaces", "distro_packages"):
            for value in (imap.get(table) or {}).values():
                if isinstance(value, str):
                    names.add(norm_library(value))
    except errors.SbomError:
        pass
    names.discard("")
    return names


def _find_entry(cmap: cpemap.CpeMap, members: List[_Member]) -> Optional[Dict[str, Any]]:
    for member in members:
        for name in (member.identity, member.cand.get("map_entry"), member.cand.get("name")):
            if name:
                found = cmap.entry(str(name))
                if found is not None:
                    return found
    for member in members:
        url = (member.cand.get("upstream") or {}).get("url")
        if url:
            found = cmap.entry_for_url(url)
            if found is not None:
                return found
    return None


def _most_common(names: List[str]) -> str:
    counts: Dict[str, int] = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    return sorted(counts, key=lambda n: (-counts[n], n))[0]


def _best_confidence(values: List[str]) -> str:
    return max(values or ["none"], key=lambda v: store.CONFIDENCE_RANK.get(v, 0))


def _declared_pairs(ev: _Evidence, cand: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for evidence_id in cand.get("declared_ids") or []:
        rec = ev.get(evidence_id)
        if not rec or not isinstance(rec.get("value"), dict):
            continue
        value = rec["value"]
        cpe = value.get("cpe23")
        if not cpe:
            continue
        try:
            part, vendor, product = cpestr.pair_of_cpe23(cpe)
        except ValueError:
            continue
        if not cpestr.PAIR_RE.fullmatch(cpestr.pair_str(part, vendor, product)):
            continue
        fields = cpestr.split_cpe23(cpe)
        where = "%s:%s" % (rec.get("path"), rec.get("line")) if rec.get("line") else str(rec.get("path"))
        out.append({"pair": cpestr.pair_str(part, vendor, product), "loc": store.clean_text(where).replace(";", ","),
                    "cpe_version": fields[5], "hash": value.get("hash")})
    return out


def _tag_of(ev: _Evidence, member: _Member) -> Optional[str]:
    """An exact upstream tag named by the version evidence (a FetchContent/CPM tag, a lock-file tag, an exact git tag)."""
    for evidence_id in member.version.get("evidence_ids") or []:
        rec = ev.get(evidence_id)
        if rec and rec.get("ref_kind") == "tag":
            tag = rec.get("value") if isinstance(rec.get("value"), str) else rec.get("symbol")
            if tag:
                return str(tag)
    return None


def _package_manager(ev: _Evidence, member: _Member) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """``(manager, name, version)`` when conan or vcpkg declared the component (version evidence from a lock file)."""
    for evidence_id in member.version.get("evidence_ids") or []:
        rec = ev.get(evidence_id)
        if not rec:
            continue
        source = member.version.get("version_source")
        if source in ("conan", "vcpkg") and rec.get("type") in ("LOCK_PIN", "MANIFEST_DECL"):
            name = rec.get("symbol") or member.cand.get("name")
            return (str(source), str(name) if name else None, member.version.get("version"))
    return (None, None, None)


def _row_purl(cmap: cpemap.CpeMap, entry: Optional[Dict[str, Any]], members: List[_Member],
              evs: Dict[str, _Evidence], row_version: str, name: str) -> str:
    entry_up = entry["upstream"] if entry else None
    for member in members:
        ev = evs[member.repo]
        cand = member.cand
        cand_url = (cand.get("upstream") or {}).get("url")
        url = cand_url or (entry_up["url"] if entry_up else None)
        manager, manager_name, manager_version = _package_manager(ev, member)
        tag = _tag_of(ev, member)
        dedicated = False
        if entry_up and entry_up.get("purl_type") == "github" and url:
            dedicated = cpemap.url_key(url) == cpemap.url_key(entry_up["url"])
        if tag is None and entry is not None and dedicated:
            tag = cmap.upstream_tag(entry, row_version)
        commit = (cand.get("upstream") or {}).get("commit")
        made = purl_mod.make_purl(name=name, version=row_version, tag=tag, commit=commit, upstream_url=url, manager=manager,
                                  manager_name=manager_name, manager_version=manager_version, dedicated=dedicated)
        if made:
            return made
    return ""


def _evidence_text(member: _Member, ev: _Evidence) -> str:
    parts: List[str] = []
    best: Optional[Dict[str, Any]] = None
    candidates: List[Dict[str, Any]] = []
    for evidence_id in member.version.get("evidence_ids") or []:
        rec = ev.get(evidence_id)
        if rec:
            candidates.append(rec)
    if not candidates:
        for evidence_id in member.cand.get("evidence_ids") or []:
            rec = ev.get(evidence_id)
            if rec and rec.get("type") in VERSION_EVIDENCE_TYPES:
                candidates.append(rec)
    candidates.sort(key=lambda r: (STRENGTH_RANK.get(r.get("strength"), 9), str(r.get("path") or ""), r.get("line") or 0,
                                   str(r.get("id"))))
    if candidates:
        best = candidates[0]
        where = ""
        if best.get("path"):
            where = " %s%s" % (best["path"], (":%s" % best["line"]) if best.get("line") else "")
        elif best.get("symbol"):
            where = " %s" % best["symbol"]
        parts.append("%s%s" % (best["type"], where))
    types: Set[str] = set()
    for evidence_id in member.verdict.get("evidence_ids") or []:
        rec = ev.get(evidence_id)
        if rec:
            types.add(str(rec.get("type")))
    shown = best["type"] if best else None
    extra = [t for t in EVIDENCE_TYPE_ORDER if t in types and t != shown][:3]
    parts.extend(extra)
    return ", ".join(parts)


def _skip_reason(entry: Optional[Dict[str, Any]], members: List[_Member], norm_name: str, known: Set[str],
                 siblings: Set[str], has_proposals: bool) -> Optional[str]:
    if entry is not None and entry["status"] == "no-nvd-cpe":
        return "no NVD product (curated map)"
    if entry is not None or has_proposals:
        return None
    if norm_name in siblings:
        return "name equals a sibling repository"
    kinds = {m.cand.get("detected_as") for m in members}
    if kinds == {"prebuilt"} and norm_name not in known:
        return "proprietary binary without identity"
    upstream = (norm_name in known
                or any((m.cand.get("upstream") or {}).get("url") for m in members)
                or any(m.cand.get("declared_ids") for m in members)
                or any(m.cand.get("detected_as") in PACKAGE_DECLARATIONS for m in members))
    if not upstream:
        return "no upstream evidence (likely internal)"
    return None


def _local_proposals(decision: Optional[Dict[str, Any]], cmap: cpemap.CpeMap, entry: Optional[Dict[str, Any]],
                     never: Set[str]) -> List[Dict[str, Any]]:
    if not decision:
        return []
    roles: Dict[str, str] = {}
    if entry is not None:
        for pair in cmap.pairs_of(entry):
            roles.setdefault(cmap.pair_text(pair), pair["role"])
    out: List[Dict[str, Any]] = []
    for text in decisions.split_emitted(str(decision.get("emitted_pairs") or "")):
        try:
            part, vendor, product = cpestr.parse_pair(text)
        except ValueError:
            continue
        pair = cpestr.pair_str(part, vendor, product)
        if pair in never:
            continue
        role = roles.get(pair)
        if role is None:
            role = "primary" if not any(p["role"] == "primary" for p in out) else "also_emit"
        out.append({"pair": pair, "role": role, "tier": "high", "basis": "local"})
    return out


def _sort_proposals(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [p for _, p in sorted(enumerate(items), key=lambda it: (store.pair_role_rank(it[1]["role"]), it[0]))]


def _build_group(ctx: RunContext, key: Tuple[str, ...], members: List[_Member], cmap: cpemap.CpeMap,
                 local: Optional[Dict[str, Any]], evs: Dict[str, _Evidence], known: Set[str], siblings: Set[str]) -> Dict[str, Any]:
    members.sort(key=lambda m: (m.repo, str(m.cand["id"])))
    row_id = ids.row_id(key)
    norm_name = key[0]
    version = key[1]
    name = _most_common([cmap.canonical(m.identity) or m.identity for m in members])
    repositories = sorted({m.repo for m in members})
    # verification and reason per repository: the strongest member decides
    verification: Dict[str, str] = {}
    reason: Dict[str, str] = {}
    candidates: Dict[str, List[str]] = {}
    for member in members:
        candidates.setdefault(member.repo, []).append(str(member.cand["id"]))
        rank = VERIFICATION_RANK.get(member.verification, 0)
        if rank > VERIFICATION_RANK.get(verification.get(member.repo, ""), 0):
            verification[member.repo] = member.verification
            code = member.verdict.get("reason_code")
            if code:
                reason[member.repo] = str(code)
            else:
                reason.pop(member.repo, None)
    for repo in list(candidates):
        candidates[repo] = sorted(candidates[repo])
    proven_repos = sorted(r for r, v in verification.items() if v == "proven")
    include = "yes" if proven_repos else "no"
    include_in = list(proven_repos) if include == "yes" else []
    for repo in repositories:
        if repo not in proven_repos and repo not in reason:
            reason[repo] = "NOT_VERIFIED"
    # curated map and proposals
    entry = _find_entry(cmap, members)
    detected = sorted({str(m.cand.get("detected_as")) for m in members})
    version_kind = str(members[0].version.get("version_kind") or "none")
    never: Set[str] = set(cmap.never_emit_pairs(entry)) if entry else set()
    proposals: List[Dict[str, Any]] = []
    alternatives: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def add(target: List[Dict[str, Any]], item: Dict[str, Any]) -> None:
        if item["pair"] not in seen:
            seen.add(item["pair"])
            target.append(item)

    for item in _local_proposals(local, cmap, entry, never):
        add(proposals, item)
    withheld: Optional[str] = None
    if entry is not None:
        proposed, alts = cmap.proposals(entry, version, version_kind, detected)
        for item in proposed:
            add(proposals, item)
        for item in alts:
            withheld = withheld or item.get("withheld")
            add(alternatives, dict(item))
    notes: List[str] = []
    map_pairs = {cmap.pair_text(p) for p in cmap.pairs_of(entry)} if entry else set()
    for member in members:
        for dec in _declared_pairs(evs[member.repo], member.cand):
            pair = dec["pair"]
            basis = "declared:%s" % dec["loc"]
            if entry is None:
                add(proposals, {"pair": pair, "role": "primary" if not proposals else "also_emit", "tier": "high",
                                "basis": basis})
            elif pair not in map_pairs:
                add(alternatives, {"pair": pair, "role": "also_emit", "tier": "low", "basis": basis})
                notes.append("declared pair %s differs from the curated map (%s)" % (pair, dec["loc"]))
            fields = dec["cpe_version"]
            if fields not in ("*", "-") and version != "NOASSERTION" and cpestr.unescape_attr(fields) != version:
                notes.append("declared CPE version %s differs from the recovered version %s (%s)"
                             % (cpestr.unescape_attr(fields), version, dec["loc"]))
            commit = (member.cand.get("upstream") or {}).get("commit")
            declared_hash = dec.get("hash")
            if declared_hash and commit and not (str(commit).startswith(str(declared_hash))
                                                 or str(declared_hash).startswith(str(commit))):
                notes.append("declared hash %s differs from the pinned commit (%s)" % (str(declared_hash)[:12], dec["loc"]))
    proposals = _sort_proposals(proposals)
    # action and editable pre-fill
    skip = _skip_reason(entry, members, norm_name, known, siblings, bool(proposals) or bool(alternatives))
    editable = {c: "" for c in decisions.CARRIED_COLUMNS}
    if local:
        for column in decisions.CARRIED_COLUMNS:
            normalized, error = normalize_cell(column, str(local.get(column) or ""), repositories)
            editable[column] = normalized if error is None else ""
        if editable["action"] not in ENUMS["action"]:
            editable["action"] = ""
        if editable["action"] == "skip":
            notes.append("skipped by a previous approval")
    if not editable["action"]:
        editable["action"] = "skip" if skip else "lookup"
        if skip:
            notes.append(skip)
    if not local and editable["action"] == "lookup" and not proposals:
        editable["search_name"] = store.clean_text(name)[:SEARCH_NAME_MAX]
    if editable["action"] == "skip" and not local:
        editable["search_name"] = ""
    # version details for the resolver
    first = members[0]
    tiers = [p["tier"] for p in proposals]
    if tiers:
        tier = max(tiers, key=lambda t: store.TIER_RANK.get(t, 0))
    else:
        tier = "low" if alternatives else "none"
    cve_count = ""
    if entry is not None and (proposals or alternatives):
        count = entry["provenance"].get("nvd_cve_count")
        cve_count = str(count) if isinstance(count, int) else ""
    upstream_url = ""
    for member in members:
        url = (member.cand.get("upstream") or {}).get("url")
        if url:
            upstream_url = str(url)
            break
    if not upstream_url and entry is not None and entry["upstream"]:
        upstream_url = entry["upstream"]["url"]
    commit_text = ""
    if len(key) == 3 and key[1] == "NOASSERTION" and not str(key[2]).startswith("repo:"):
        commit_text = str(key[2])
    # evidence summary
    prefix = ""
    for member in members:
        if member.verdict.get("adjudicated") and (member.verdict.get("adjudication") or {}).get("source") == "model":
            rationale = store.clean_text((member.verdict.get("adjudication") or {}).get("rationale"))
            if rationale:
                prefix = "model: %s; " % rationale
                break
    prefix += decisions.previous_run_note(local, include, include_in)
    per_repo = []
    for repo in repositories:
        member = next(m for m in members if m.repo == repo)
        text = _evidence_text(member, evs[repo])
        per_repo.append("%s: %s" % (repo, text) if text else repo)
    summary = store.clean_text(prefix + "; ".join(per_repo), SUMMARY_MAX)
    row: Dict[str, Any] = {
        "id": row_id, "key": list(key), "name": store.clean_text(name), "norm_name": norm_name, "version": version,
        "version_kind": version_kind, "upstream_commit": commit_text,
        "verification": verification, "reason": reason, "notes": sorted(set(store.clean_text(n) for n in notes)),
        "repositories": repositories, "include": include, "include_in": include_in,
        "action": editable["action"], "search_name": editable["search_name"], "vendor_hint": editable["vendor_hint"],
        "product_hint": editable["product_hint"], "part_hint": editable["part_hint"],
        "cpe_override": editable["cpe_override"], "cpe_version_override": editable["cpe_version_override"],
        "cpe_update_override": editable["cpe_update_override"],
        "extra_vendor_products": editable["extra_vendor_products"],
        "proposals": proposals, "alternatives": alternatives, "tier": tier, "version_in_dictionary": "unknown",
        "nvd_cve_count": cve_count,
        "version_confidence": _best_confidence([str(m.cand.get("version_confidence") or "none") for m in members]),
        "upstream_url": store.clean_text(upstream_url), "purl": "",
        "previously_approved": "yes" if local else "no", "evidence_summary": summary,
        "candidates": candidates, "map_entry": entry["name"] if entry else None,
        "map_status": entry["status"] if entry else None, "withheld": withheld,
        "cpe_version": first.version.get("cpe_version"), "cpe_update": first.version.get("cpe_update"),
        "detected_as": detected,
    }
    return row


def build_rows(ctx: RunContext, run: Any) -> List[Dict[str, Any]]:
    """The review rows of the run, sorted by (norm_name, version, key). No file is written."""
    verify = _verify()
    cmap = cpemap.load(ctx)
    local_decisions = decisions.load_local_decisions(ctx)
    scope_all = (run.data.get("scope") or ctx.scope) == "all"
    repos = [r for r in run.all_repos() if run.repo(r).get("status") in ("DONE", "INCOMPLETE")]
    siblings = {norm_library(r) for r in run.all_repos()}
    known = _known_identities(ctx)
    evs: Dict[str, _Evidence] = {r: _Evidence(ctx, r) for r in repos}
    groups: Dict[Tuple[str, ...], List[_Member]] = {}
    for repo in repos:
        ctx.check_deadline()
        base = ctx.layout.repo_out(repo)
        try:
            cand_doc = fsio.read_json(base / "candidates.json")
        except FileNotFoundError as exc:
            raise errors.StateError("repos/%s/candidates.json is missing although the repository is %s" % (
                repo, run.repo(repo).get("status")), repo=repo) from exc
        cands = {c["id"]: c for c in cand_doc.get("candidates") or []}
        for verdict in verify.final_verdicts(ctx, repo):
            cand = cands.get(verdict.get("candidate"))
            effective = _effective_verification(verdict, scope_all)
            if cand is None or effective is None:
                continue
            identity = verify.chosen_identity(cand, verdict)
            version = verify.chosen_version(cand, verdict)
            version_text = str(version.get("version") or "NOASSERTION")
            commit = (cand.get("upstream") or {}).get("commit")
            fold = ids.fold_key(norm_library(identity), version_text, commit or None)
            key = ids.review_key(fold, repo)
            groups.setdefault(key, []).append(_Member(repo, cand, verdict, identity, version, effective))
    rows = []
    for key in sorted(groups):
        rows.append(_build_group(ctx, key, groups[key], cmap, local_decisions.get(key), evs, known, siblings))
    # purls: computed after the rows exist so that two rows never share one
    entries_by_row: Dict[str, Optional[Dict[str, Any]]] = {}
    for row in rows:
        entries_by_row[row["id"]] = cmap.entry(row["map_entry"]) if row["map_entry"] else None
    used: Set[str] = set()
    for row in rows:
        members = groups[tuple(row["key"])]
        text = _row_purl(cmap, entries_by_row[row["id"]], members, evs, row["version"], row["name"])
        if text and text not in used:
            used.add(text)
            row["purl"] = text
    rows.sort(key=lambda r: (r["norm_name"], r["version"], tuple(r["key"])))
    return rows


def hint_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rows that need model hints: ``action=lookup`` and no High or Medium proposal, whatever their ``include`` (max 50)."""
    wanted = [r for r in rows if r["action"] == "lookup" and not r["proposals"]]
    return wanted[:store.MAX_HINT_ROWS]


# ------------------------------------------------------------------------------------------------- writing

def render_review(rows: Sequence[Dict[str, Any]]) -> bytes:
    ordered = sorted(rows, key=lambda r: (r["norm_name"], r["version"], tuple(r["key"])))
    return csvio.render_csv(HEADER, [row_cells(r) for r in ordered], preamble=PREAMBLE)


def write_review(ctx: RunContext, run: Any) -> Dict[str, Any]:
    """Write ``review/cpe-lookup-names.csv``; returns the dict that becomes ``run.json.review``."""
    doc = store.load_names_doc(ctx)
    rows = doc["rows"]
    data = render_review(rows)
    path = store.review_path(ctx)
    sha = fsio.atomic_write_bytes(path, data, root=ctx.layout.out)
    return {"path": ctx.layout.rel(path), "sha256": sha, "rows": len(rows),
            "rows_included": sum(1 for r in rows if store.included_repos(r)),
            "names_written_at": ctx.now_iso(), "names_written_at_ns": ctx.clock.wall_ns()}


def load_written_rows(ctx: RunContext) -> List[Dict[str, Any]]:
    """The rows of ``.state/names_rows.json``."""
    return list(store.load_names_doc(ctx)["rows"])


def row_for_candidate(ctx: RunContext) -> Dict[Tuple[str, str], str]:
    """``(repo, candidate id)`` -> review row id, from ``names_rows.json``."""
    out: Dict[Tuple[str, str], str] = {}
    for row in store.load_names_doc(ctx)["rows"]:
        for repo, cids in (row.get("candidates") or {}).items():
            for cid in cids:
                out[(repo, cid)] = row["id"]
    return out


# ------------------------------------------------------------------------------------------------- read-back

SAVE_HINT = "Save it as CSV UTF-8 (Excel: File > Save As > CSV UTF-8)."


def refusal(code: str, explanation: str, *, line: Optional[int] = None, row_id: Optional[str] = None,
            column: Optional[str] = None) -> errors.ReviewRefused:
    """A ``ReviewRefused`` whose message has the format of section 4.13."""
    where = []
    if line is not None:
        where.append("line %d" % line)
    if row_id:
        where.append("row %s" % row_id)
    if column:
        where.append("column %s" % column)
    text = "Review file refused (%s)%s: %s. Fix the file, save it, then reply \"approved\" again." % (
        code, (" at " + ", ".join(where)) if where else "", explanation.rstrip(". "))
    if code == "NON_UTF8":
        text += " " + SAVE_HINT
    return errors.ReviewRefused(text, reason=code, line=line, row_id=row_id, column=column)


def read_back(ctx: RunContext, data: bytes, written_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Strict read-back of the review file (section 4.13); raises ``errors.ReviewRefused``.

    Returns ``{"rows": {row_id: {editable column: value}}, "diff": [{"id", "column", "old", "new"}],
    "readonly_changes": [{"id", "column"}], "delimiter": "," | ";"}``. ``include_in`` is returned as ``;``-joined text.
    """
    try:
        table = csvio.parse_csv_strict(data, HEADER)
    except errors.CsvReadError as exc:
        reason = str(exc.detail.get("reason") or "BAD_HEADER")
        line = exc.detail.get("line")
        explanations = {
            "NON_UTF8": "the file is not valid UTF-8",
            "BAD_HEADER": "the header row does not match the review file; do not change, add, remove or reorder columns",
            "BAD_ROW_LENGTH": "a row does not have one cell per column",
            "EMPTY": "the file is empty",
        }
        raise refusal(reason, explanations.get(reason, exc.message), line=line if isinstance(line, int) else None) from exc
    written = {r["id"]: r for r in written_rows}
    seen: Dict[str, int] = {}
    # ids: unique, known, none missing
    for cells, line in zip(table.rows, table.line_numbers):
        row_id = cells["id"].strip()
        if not row_id:
            raise refusal("MISSING_ID", "a row has no id", line=line, column="id")
        if row_id in seen:
            raise refusal("DUPLICATE_ID", "the id appears twice (first on line %d)" % seen[row_id], line=line, row_id=row_id,
                          column="id")
        seen[row_id] = line
    for cells, line in zip(table.rows, table.line_numbers):
        row_id = cells["id"].strip()
        if row_id not in written:
            raise refusal("UNKNOWN_ID", "this id is not in the review file the script wrote", line=line, row_id=row_id,
                          column="id")
    for row_id in sorted(written):
        if row_id not in seen:
            raise refusal("MISSING_ID", "this row was deleted; set include=no instead of deleting rows", row_id=row_id)
    # editable values
    edited: Dict[str, Dict[str, str]] = {}
    readonly: List[Dict[str, str]] = []
    diff: List[Dict[str, str]] = []
    by_id = {c["id"].strip(): (c, line) for c, line in zip(table.rows, table.line_numbers)}
    for row in written_rows:
        cells, line = by_id[row["id"]]
        repositories = row.get("repositories") or []
        values: Dict[str, str] = {}
        for column in EDITABLE:
            normalized, error = normalize_cell(column, cells[column], repositories)
            if error is not None:
                raise refusal(error, _explain(column, error), line=line, row_id=row["id"], column=column)
            values[column] = normalized
        edited[row["id"]] = values
        expected = dict(zip(HEADER, row_cells(row)))
        for column in READ_ONLY:
            if cells[column] != expected[column]:
                readonly.append({"id": row["id"], "column": column})
        for column in EDITABLE:
            old = cell_value(row, column)
            if values[column] != old:
                diff.append({"id": row["id"], "column": column, "old": old, "new": values[column]})
    return {"rows": edited, "diff": diff, "readonly_changes": readonly, "delimiter": table.delimiter}


def approved_rows(ctx: RunContext, run: Any) -> Dict[str, Dict[str, Any]]:
    """The rows of the latest approval: ``names_rows`` rows with the approved editable values (read-only values always from
    ``names_rows``). ``include_in`` is a list in the result."""
    approvals = run.data.get("approvals") or []
    if not approvals:
        raise errors.StateError("the run has no approval yet")
    n = int(approvals[-1]["n"])
    path = store.approved_copy_path(ctx, n)
    try:
        with open(os.fspath(path), "rb") as handle:
            data = handle.read()
    except FileNotFoundError as exc:
        raise errors.StateError("the approved copy %s is missing" % path.name, path=str(path)) from exc
    written = load_written_rows(ctx)
    result = read_back(ctx, data, written)
    out: Dict[str, Dict[str, Any]] = {}
    for row in written:
        merged = dict(row)
        values = result["rows"][row["id"]]
        for column in EDITABLE:
            merged[column] = values[column]
        merged["include_in"] = split_list(values["include_in"], ";")
        out[row["id"]] = merged
    return out

