"""Adjudication helpers of phase 4: summaries the agent reads, decision validation, verdict merging (contract 4.11, 5.7).

The model sees only what the rules left open (``needs == "usage"`` or ``"trace_build"``), at most ten script-curated
evidence records per item, and answers with evidence ids. Everything it writes is validated here; an invalid answer gets one
corrective retry, after which the invalid items fall back to ``INCONCLUSIVE``. Decisions are cached by ``input_sha256``.
"""
from __future__ import annotations

import copy
import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from sbomlib import errors, fsio, model, replyread
from sbomlib.context import RunContext
from sbomlib.verify.inputs import DISCOVER_EVIDENCE_FILES
from sbomlib.verify.rules import POSITIVE_TYPES, STRENGTH_RANK, usage_list

SCHEMA = 1
MAX_ITEMS = 50
MAX_BYTES = 40 * 1024
MAX_EVIDENCE = 10
MAX_RATIONALE = 300
MAX_MESSAGES = 20
KINDS = ("usage", "trace_build")
FILES = {"usage": ("evidence_summary.json", "llm/decisions.json"), "trace_build": ("trace_request.json", "llm/trace_build.json")}
RUBRIC = "references/usage-rubric.md"
ALLOWED_CLASSES = ["USED", "OPTIONAL", "TEST_ONLY", "DEV_ONLY", "BUILD_ONLY", "UNUSED_DEAD_COPY", "INCONCLUSIVE"]
USED_LEVELS = ("vendored_compiled", "static", "dynamic", "header_only", "linked", "runtime_loaded", "toolchain_runtime",
               "co_flashed_image")
NEGATIVE_LEVELS = ("none", "present", "declared")
SCOPE_OF_CLASS = {"TEST_ONLY": "test", "DEV_ONLY": "dev", "BUILD_ONLY": "build"}
CLASS_REASON = {"TEST_ONLY": "TEST_ONLY", "DEV_ONLY": "DEV_ONLY", "BUILD_ONLY": "BUILD_ONLY", "OPTIONAL": "CONDITIONAL_DISABLED"}
D3_REASONS = ("REVIEW_IDENTITY", "REVIEW_VERSION_CONFLICT")
TRACE_TYPES = ("BUILD_REF_UNPARSED", "BUILD_FILE_UNPARSED")
IN_TREE = ("vendored", "single_file", "submodule", "prebuilt")

# diversity order when an item has more evidence than fits: one record per type first, strongest first
TYPE_ORDER = ("API_HIT", "INCLUDE", "ABSENCE", "CONDITION", "TEST_SCOPE", "COMPILE_LIST", "LINK_PROOF", "LINK_REF",
              "SUBDIR_BUILD", "FIND_PACKAGE", "DLOPEN", "BUILD_REF_UNPARSED", "BUILD_FILE_UNPARSED", "TRANSITIVE", "LINK_LINE",
              "VERSION_MACRO", "PROJECT_VERSION", "VERSION_FILE", "BANNER", "GIT_DESCRIBE", "DECLARED_ID", "FETCH_PIN",
              "LOCK_PIN", "MANIFEST_DECL", "GITLINK", "PREBUILT", "TOOLCHAIN_RUNTIME", "FILE_PRESENT", "INCLUDE_DIR",
              "CI_INSTALL")
IDENTITY_TYPES = ("VERSION_MACRO", "PROJECT_VERSION", "VERSION_FILE", "BANNER", "GIT_DESCRIBE", "DECLARED_ID", "GITLINK")

QUESTIONS = {
    "REVIEW_NO_BUILD_REF": "first-party code includes and calls this library, but no build file links it.",
    "REVIEW_IDENTITY": "the evidence supports more than one identity for this location; choose the identity it supports.",
    "REVIEW_VERSION_CONFLICT": "version evidence conflicts inside this location while the library is used; choose the "
                               "version option the evidence supports.",
    "REVIEW_DLOPEN": "the code loads a library by name at run time that the script cannot map; is it a dependency of the "
                     "product?",
    "REVIEW_CONFLICT": "the evidence points both ways or the rules cannot settle it; decide from the cited records.",
    "REVIEW_CONDITION_UNKNOWN": "every use sits behind conditions the script cannot evaluate; is it enabled in a shipping "
                                "build?",
    "REVIEW_UNCOVERED_BUILD": "the repository builds with a system the script does not parse; read the listed build files "
                              "and decide whether this library is built into the product.",
}

SNIPPET_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


# ------------------------------------------------------------------------------------------------------ data pool

class Pool:
    """Verdicts, candidates and evidence of one repository, as plain JSON data."""

    def __init__(self, repo: str, verdicts: List[Dict[str, Any]], candidates: List[Dict[str, Any]],
                 evidence: List[Dict[str, Any]], shipping: Dict[str, Any]) -> None:
        self.repo = repo
        self.verdicts = verdicts
        self.cands = {c["id"]: c for c in candidates}
        self.ev_by_id = {e["id"]: e for e in evidence}
        self.ev_by_cand: Dict[str, List[Dict[str, Any]]] = {}
        for ev in evidence:
            if ev.get("candidate"):
                self.ev_by_cand.setdefault(ev["candidate"], []).append(ev)
        self.shipping = shipping
        self.build_files = sorted({(e["path"], e["id"]) for e in evidence
                                   if e.get("type") == "BUILD_FILE_UNPARSED" and e.get("path")})
        self.verdict_by_cand = {v["candidate"]: v for v in verdicts}


def _normalize(obj: Any) -> Any:
    return json.loads(fsio.dumps_compact(obj))


def pool_from_memory(repo: str, verdicts: Sequence[Dict[str, Any]], candidates: Sequence[Dict[str, Any]],
                     evidence: Sequence[Dict[str, Any]], shipping: Dict[str, Any]) -> Pool:
    return Pool(repo, _normalize(list(verdicts)), _normalize(list(candidates)), _normalize(list(evidence)),
                _normalize(shipping))


def _read_json(path: Any) -> Optional[Any]:
    if not os.path.lexists(str(path)):
        return None
    return fsio.read_json(path)


def _checked(doc: Any, name: str) -> Dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise errors.StateError("%s has an unsupported schema" % name)
    return doc


def load_pool(ctx: RunContext, repo: str) -> Pool:
    out = ctx.layout.repo_out(repo)
    verdicts_doc = _checked(fsio.read_json(out / "verdicts.json"), "verdicts.json")
    candidates_doc = _checked(fsio.read_json(out / "candidates.json"), "candidates.json")
    evidence: List[Dict[str, Any]] = []
    for name in DISCOVER_EVIDENCE_FILES + ("verify_evidence.jsonl", "worker_evidence.jsonl"):
        if os.path.lexists(str(out / name)):
            evidence.extend(r for r in fsio.read_jsonl(out / name) if isinstance(r, dict))
    return Pool(repo, list(verdicts_doc.get("verdicts") or []), list(candidates_doc.get("candidates") or []), evidence,
                verdicts_doc.get("shipping") or {})


# ------------------------------------------------------------------------------------------------------ summaries

def _loc(ev: Dict[str, Any]) -> str:
    path = ev.get("path")
    if path:
        return "%s:%d" % (path, ev["line"]) if ev.get("line") else str(path)
    if ev.get("object_store") and ev.get("object"):
        return "%s@%s" % (ev["object_store"], str(ev["object"])[:12])
    return "-"


def _snippet(ev: Dict[str, Any], limit: int) -> str:
    text = ev.get("detail")
    if not text:
        kind = ev.get("type")
        value = ev.get("value")
        symbol = ev.get("symbol")
        if kind == "LINK_REF":
            text = "link item %s" % (value if isinstance(value, str) else symbol or "")
        elif kind in ("FIND_PACKAGE", "SUBDIR_BUILD", "LOCK_PIN", "FETCH_PIN", "MANIFEST_DECL", "DLOPEN"):
            text = "%s %s" % (kind, value if isinstance(value, str) else symbol or "")
        elif kind in ("VERSION_MACRO", "PROJECT_VERSION", "VERSION_FILE", "BANNER", "GIT_DESCRIBE"):
            text = "%s %s" % (symbol or kind, value if isinstance(value, str) else "")
        elif kind == "CONDITION" and isinstance(value, dict):
            text = "enabled in %s; disabled in %s" % (", ".join(value.get("enabled_in") or []) or "none",
                                                      ", ".join(value.get("disabled_in") or []) or "none")
        else:
            text = str(symbol or kind or "")
    text = SNIPPET_CTRL.sub(" ", str(text)).strip()
    return text[:limit]


def _item_question(verdict: Dict[str, Any]) -> str:
    code = verdict.get("reason_code") or (verdict.get("review_codes") or ["REVIEW_CONFLICT"])[0]
    return "%s: %s" % (code, QUESTIONS.get(code, QUESTIONS["REVIEW_CONFLICT"]))


def _candidate_location(cand: Dict[str, Any]) -> str:
    loc = cand.get("location") or {}
    kind = loc.get("kind")
    if kind in ("system", "toolchain") or not loc.get("path"):
        return kind or "system"
    return "%s:%d" % (loc["path"], loc["line"]) if loc.get("line") else str(loc["path"])


def _version_options(cand: Dict[str, Any]) -> List[Dict[str, Any]]:
    version = cand.get("version") or {}
    options = version.get("options") or []
    if not options:
        return [{"id": "v0", "version": version.get("version", "NOASSERTION"),
                 "version_kind": version.get("version_kind", "none")}]
    return [{"id": o["id"], "version": o.get("version", "NOASSERTION"), "version_kind": o.get("version_kind", "none")}
            for o in options]


def _identity_options(cand: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    for option in cand.get("identity_options") or []:
        name = option.get("name")
        if name and name not in names:
            names.append(name)
    if cand.get("name") and cand["name"] not in names:
        names.insert(0, cand["name"])
    return names


def _pool_for_item(pool: Pool, cid: str, kind: str, verdict: Dict[str, Any]) -> List[Dict[str, Any]]:
    cand = pool.cands[cid]
    records = [e for e in pool.ev_by_cand.get(cid, []) if e.get("type") not in ("LICENSE_FILE",)]
    seen = {e["id"] for e in records}
    if kind == "trace_build":
        # the unparsed build files themselves are always citable, even when no record names this candidate
        for _path, eid in pool.build_files[:3]:
            if eid not in seen and eid in pool.ev_by_id:
                records.append(pool.ev_by_id[eid])
                seen.add(eid)
    if verdict.get("reason_code") in D3_REASONS or "REVIEW_IDENTITY" in (verdict.get("review_codes") or []) or \
            "REVIEW_VERSION_CONFLICT" in (verdict.get("review_codes") or []):
        for eid in _identity_evidence_ids(cand):
            if eid not in seen and eid in pool.ev_by_id:
                records.append(pool.ev_by_id[eid])
                seen.add(eid)
    return records


def _identity_evidence_ids(cand: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for option in cand.get("identity_options") or []:
        out.extend(option.get("evidence_ids") or [])
    for option in (cand.get("version") or {}).get("options") or []:
        out.extend(option.get("evidence_ids") or [])
    return out


def _rank(ev: Dict[str, Any]) -> Tuple[int, int, str, str]:
    order = TYPE_ORDER.index(ev["type"]) if ev.get("type") in TYPE_ORDER else len(TYPE_ORDER)
    return (-STRENGTH_RANK.get(str(ev.get("strength")), 0), order, _loc(ev), ev["id"])


def select_evidence(pool: Pool, cid: str, kind: str, verdict: Dict[str, Any], cap: int, snippet: int) -> List[Dict[str, Any]]:
    records = _pool_for_item(pool, cid, kind, verdict)
    must: List[Dict[str, Any]] = []
    if kind == "trace_build":
        must = sorted([e for e in records if e.get("type") in TRACE_TYPES], key=lambda e: (
            0 if e["type"] == "BUILD_REF_UNPARSED" else 1, _loc(e), e["id"]))[:2]
    chosen: List[Dict[str, Any]] = list(must)
    taken = {e["id"] for e in chosen}
    review = set(verdict.get("review_codes") or [])
    if review & set(D3_REASONS):
        for eid in _identity_evidence_ids(pool.cands[cid]):
            ev = pool.ev_by_id.get(eid)
            if ev is not None and ev["id"] not in taken and len(chosen) < cap:
                chosen.append(ev)
                taken.add(ev["id"])
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for ev in sorted(records, key=_rank):
        by_type.setdefault(ev["type"], []).append(ev)
    ordered_types = [t for t in TYPE_ORDER if t in by_type] + sorted(t for t in by_type if t not in TYPE_ORDER)
    for t in ordered_types:                                           # one record per type first
        ev = by_type[t][0]
        if ev["id"] not in taken and len(chosen) < cap:
            chosen.append(ev)
            taken.add(ev["id"])
    for ev in sorted(records, key=_rank):                              # then the strongest remaining
        if ev["id"] not in taken and len(chosen) < cap:
            chosen.append(ev)
            taken.add(ev["id"])
    chosen.sort(key=_rank)
    return chosen[:cap]


def _params_for(n: int) -> Tuple[int, int]:
    """``(evidence per item, snippet length)`` as a function of the item count only, so selection is idempotent."""
    if n <= 8:
        return MAX_EVIDENCE, 200
    if n <= 16:
        return 8, 160
    if n <= 25:
        return 6, 120
    if n <= 40:
        return 4, 100
    return 3, 80


def _build_item(pool: Pool, verdict: Dict[str, Any], kind: str, cap: int, snippet: int) -> Dict[str, Any]:
    cid = verdict["candidate"]
    cand = pool.cands[cid]
    evidence = select_evidence(pool, cid, kind, verdict, cap, snippet)
    return {"item_id": cid, "name": cand["name"], "location": _candidate_location(cand),
            "question": _item_question(verdict), "allowed_classes": list(ALLOWED_CLASSES),
            "identity_options": _identity_options(cand), "version_options": _version_options(cand),
            "evidence": [{"id": e["id"], "type": e["type"], "strength": e.get("strength") or "none", "loc": _loc(e),
                          "snippet": _snippet(e, snippet)} for e in evidence]}


def _sorted_needs(pool: Pool, kind: str) -> List[Dict[str, Any]]:
    wanted = [v for v in pool.verdicts if v.get("needs") == kind and v["candidate"] in pool.cands]
    return sorted(wanted, key=lambda v: (pool.cands[v["candidate"]]["name"].casefold(), v["candidate"]))


def _doc_for(ctx: Optional[RunContext], pool: Pool, kind: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    out_name = FILES[kind][1]
    if ctx is not None:
        out_rel = ctx.layout.rel(ctx.layout.repo_out(pool.repo) / out_name)
    else:
        out_rel = "sbom-out/repos/%s/%s" % (pool.repo, out_name)
    rubric = RUBRIC                      # relative to the skill folder; the block carries the absolute path
    doc: Dict[str, Any] = {"schema": SCHEMA, "repo": pool.repo, "kind": kind, "rubric": rubric, "output": out_rel,
                           "items": items}
    if kind == "trace_build":
        doc["build_files"] = [{"path": p, "evidence_id": eid} for p, eid in pool.build_files[:50]]
    doc["input_sha256"] = ""
    return doc


def input_sha256(doc: Dict[str, Any]) -> str:
    body = {k: v for k, v in doc.items() if k != "input_sha256"}
    return fsio.sha256_bytes(fsio.dumps_compact(body).encode("utf-8"))


def build_summary(ctx: Optional[RunContext], pool: Pool, kind: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """The summary document of ``kind`` (``None`` when no verdict needs it) and the candidate ids that did not fit
    (``ADJUDICATION_CAPACITY``). Deterministic: ``(items, params)`` depend only on the sorted list of needing verdicts."""
    wanted = _sorted_needs(pool, kind)
    if not wanted:
        return None, []
    top = wanted[:MAX_ITEMS]
    n = len(top)
    memo: Dict[Tuple[str, int, int], Dict[str, Any]] = {}
    while True:
        cap, snippet = _params_for(n)
        items = []
        for v in wanted[:n]:
            key = (v["candidate"], cap, snippet)
            if key not in memo:
                memo[key] = _build_item(pool, v, kind, cap, snippet)
            items.append(memo[key])
        doc = _doc_for(ctx, pool, kind, items)
        doc["input_sha256"] = input_sha256(doc)
        if n <= 1 or len(fsio.dumps_pretty(doc).encode("utf-8")) <= MAX_BYTES:
            break
        n -= 1
    overflow = [v["candidate"] for v in wanted[n:]]
    return doc, overflow


def apply_capacity(pool: Pool) -> Tuple[Dict[str, Optional[str]], List[Dict[str, Any]]]:
    """Run at verify time: items beyond the capacity stay ``INCONCLUSIVE`` (``needs`` cleared, blind spot
    ``ADJUDICATION_CAPACITY``). Returns the ``input_sha256`` per kind and the blind spots."""
    hashes: Dict[str, Optional[str]] = {}
    spots: List[Dict[str, Any]] = []
    for kind in KINDS:
        doc, overflow = build_summary(None, pool, kind)
        for cid in overflow:
            pool.verdict_by_cand[cid]["needs"] = None
            spots.append({"code": "ADJUDICATION_CAPACITY", "candidate": cid, "loc": None,
                          "message": ("%s: not sent to the model; at most %d items (or 40 KB) fit one adjudication file"
                                      % (pool.cands[cid]["name"], MAX_ITEMS))[:200]})
        if overflow:                      # rebuild: the kept items are the same, the hash is of the final selection
            doc, _ = build_summary(None, pool, kind)
        hashes[kind] = doc["input_sha256"] if doc else None
    return hashes, spots


# ------------------------------------------------------------------------------------------------------ validation

def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(x, str) for x in value)


def check_decision(decision: Any, item: Dict[str, Any], kind: str, pool: Pool) -> Tuple[List[str], bool]:
    """Problems of one decision (``item_id`` is known) and whether a ``trace_build`` decision lacks its citation."""
    problems: List[str] = []
    if not isinstance(decision, dict):
        return ["item %s: decision is not an object" % item["item_id"]], False
    tag = "item %s" % item["item_id"]
    cls = decision.get("class")
    if cls not in item["allowed_classes"]:
        problems.append("%s: class %r is not one of %s" % (tag, cls, ", ".join(item["allowed_classes"])))
    level = decision.get("usage_level")
    if level not in model.USAGE_LEVELS:
        problems.append("%s: usage_level %r is not a known level" % (tag, level))
    elif cls == "USED" and level not in USED_LEVELS:
        problems.append("%s: class USED needs a usage_level of %s" % (tag, ", ".join(USED_LEVELS)))
    elif cls in ALLOWED_CLASSES and cls != "USED" and level not in NEGATIVE_LEVELS:
        problems.append("%s: class %s needs usage_level none, present or declared" % (tag, cls))
    if decision.get("identity") not in item["identity_options"]:
        problems.append("%s: identity %r is not one of the identity_options" % (tag, decision.get("identity")))
    if decision.get("version_option") not in [o["id"] for o in item["version_options"]]:
        problems.append("%s: version_option %r is not one of the version_options ids" % (tag, decision.get("version_option")))
    cited = decision.get("evidence_ids")
    offered = {e["id"]: e for e in item["evidence"]}
    if not _is_str_list(cited):
        problems.append("%s: evidence_ids must be a list of strings" % tag)
        cited = []
    unknown = [c for c in cited if c not in offered]
    if unknown:
        problems.append("%s: evidence id(s) not offered for this item: %s" % (tag, ", ".join(unknown[:5])))
    rationale = decision.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        problems.append("%s: rationale is required" % tag)
    elif len(rationale) > MAX_RATIONALE:
        problems.append("%s: rationale is longer than %d characters" % (tag, MAX_RATIONALE))
    uncited = False
    if not problems:
        records = [offered[c] for c in cited]
        types = {r["type"] for r in records}
        if cls == "USED":
            if not types & set(POSITIVE_TYPES + ("BUILD_REF_UNPARSED",)):
                problems.append("%s: class USED must cite at least one positive record (%s)"
                                % (tag, ", ".join(POSITIVE_TYPES + ("BUILD_REF_UNPARSED",))))
        elif cls in SCOPE_OF_CLASS:
            if not any(_record_scope(pool, r["id"]) in ("test", "dev", "build") for r in records):
                problems.append("%s: class %s must cite at least one record with test, dev or build scope" % (tag, cls))
        elif cls == "OPTIONAL":
            if not any(r["type"] == "CONDITION" or _record_has_condition(pool, r["id"]) for r in records):
                problems.append("%s: class OPTIONAL must cite a CONDITION record or a record that has a condition" % tag)
        elif cls == "UNUSED_DEAD_COPY":
            if not types & {"ABSENCE", "FILE_PRESENT"}:
                problems.append("%s: class UNUSED_DEAD_COPY must cite an ABSENCE or FILE_PRESENT record" % tag)
        if kind == "trace_build" and cls != "INCONCLUSIVE" and not problems and not types & set(TRACE_TYPES):
            uncited = True
    return problems, uncited


def _record_scope(pool: Pool, eid: str) -> str:
    return str((pool.ev_by_id.get(eid) or {}).get("scope") or "product")


def _record_has_condition(pool: Pool, eid: str) -> bool:
    ev = pool.ev_by_id.get(eid) or {}
    return bool((ev.get("condition") or {}).get("all")) or bool(ev.get("guards"))


def parse_document(raw: Optional[bytes], summary: Dict[str, Any], kind: str, repo: str
                   ) -> Tuple[Optional[Dict[str, Any]], List[str], List[Tuple[str, str]]]:
    """Document-level checks: parses, size, schema, repo, kind, input hash. ``(None, problems, notes)`` when unusable. The
    reader is ``replyread`` (a code fence of any spelling, a byte order mark, CRLF); ``notes`` is what it tolerated (an
    unclosed fence), for the caller to record."""
    name = FILES[kind][1]
    if raw is None:
        return None, ["%s does not exist or cannot be read; write it (a regular file under %d bytes) with one decision per "
                      "item of the input file" % (name, MAX_BYTES)], []
    if len(raw) > MAX_BYTES:
        return None, ["%s is %d bytes; keep it under %d bytes" % (name, len(raw), MAX_BYTES)], []
    doc, problem, notes = replyread.parse_bytes(raw)
    if problem is not None:
        return None, ["%s is not valid UTF-8 JSON: %s" % (name, problem)], notes
    if not isinstance(doc, dict):
        return None, ["%s must be a JSON object" % name], notes
    problems: List[str] = []
    if doc.get("schema") != SCHEMA:
        problems.append("schema must be 1")
    if doc.get("repo") != repo:
        problems.append("repo must be %r" % repo)
    if doc.get("kind") != kind:
        problems.append("kind must be %r" % kind)
    if doc.get("input_sha256") != summary["input_sha256"]:
        problems.append("input_sha256 must equal %s (copy it from the input file)" % summary["input_sha256"])
    if not isinstance(doc.get("decisions"), list):
        problems.append("decisions must be a list")
    return doc, problems, notes


def validate(summary: Dict[str, Any], doc: Dict[str, Any], kind: str, pool: Pool
             ) -> Tuple[Dict[str, Dict[str, Any]], List[str], Set[str], Set[str]]:
    """Per-item validation: ``(valid decisions by item, messages, ids of items with problems, uncited trace items)``."""
    items = {i["item_id"]: i for i in summary["items"]}
    messages: List[str] = []
    valid: Dict[str, Dict[str, Any]] = {}
    bad: Set[str] = set()
    uncited: Set[str] = set()
    seen: Set[str] = set()
    for index, decision in enumerate(doc.get("decisions") or []):
        item_id = decision.get("item_id") if isinstance(decision, dict) else None
        if not isinstance(item_id, str) or item_id not in items:
            messages.append("decision %d: item_id %r is not an item of the input file" % (index, item_id))
            continue
        if item_id in seen:
            messages.append("item %s: more than one decision" % item_id)
            bad.add(item_id)
            continue
        seen.add(item_id)
        problems, missing_cite = check_decision(decision, items[item_id], kind, pool)
        if problems:
            messages.extend(problems)
            bad.add(item_id)
        else:
            valid[item_id] = decision
            if missing_cite:
                uncited.add(item_id)
    for item_id in items:
        if item_id not in seen:
            messages.append("item %s: no decision was given" % item_id)
            bad.add(item_id)
    # a duplicated item is not applied at all
    for item_id in list(valid):
        if item_id in bad:
            del valid[item_id]
    return valid, messages, bad, uncited


# ------------------------------------------------------------------------------------------------------ verdict merge

def _cites_strong_positive(pool: Pool, cited: Sequence[str]) -> bool:
    for eid in cited:
        ev = pool.ev_by_id.get(eid) or {}
        etype = ev.get("type")
        if etype in ("COMPILE_LIST", "LINK_PROOF"):
            return True
        if etype == "API_HIT" and ev.get("weight") == "strong":
            return True
        if etype == "INCLUDE" and isinstance(ev.get("value"), dict) and ev["value"].get("header_only_code"):
            return True
    return False


def decision_verification(decision: Dict[str, Any], verdict: Dict[str, Any], pool: Pool, scope_all: bool) -> Optional[str]:
    """D3 / D21 for an accepted decision."""
    cls = decision["class"]
    if cls == "USED":
        codes = set(verdict.get("review_codes") or []) | ({verdict["reason_code"]} if verdict.get("reason_code") else set())
        if codes & set(D3_REASONS) and verdict.get("used_by") and _cites_strong_positive(pool, decision.get("evidence_ids") or []):
            return "proven"
        return "declared"
    if cls == "INCONCLUSIVE":
        return verdict.get("verification")                      # D21 was decided by the rule pass
    if cls in SCOPE_OF_CLASS:
        return "declared" if scope_all else None
    return None


def _reason_for(decision: Dict[str, Any], verdict: Dict[str, Any], cand: Dict[str, Any]) -> Optional[str]:
    cls = decision["class"]
    if cls == "USED":
        # a model-decided USED that the script could not prove keeps the review code that sent it to the model, so the
        # review file can say why the row is not pre-set to include=yes (oracle: SQLite -> REVIEW_NO_BUILD_REF)
        code = verdict.get("reason_code")
        if decision.get("verification") != "proven" and isinstance(code, str) and code.startswith("REVIEW_"):
            return code
        return None
    if cls in CLASS_REASON:
        return CLASS_REASON[cls]
    if cls == "UNUSED_DEAD_COPY":
        return "PRESENT_NOT_BUILT" if cand.get("detected_as") in IN_TREE else "DECLARED_NOT_USED"
    if decision.get("source") == "script" and decision.get("reason_code"):
        return decision["reason_code"]
    review = verdict.get("review_codes") or []
    return decision.get("reason_code") or (review[0] if review else verdict.get("reason_code"))


def apply_decision(verdict: Dict[str, Any], decision: Dict[str, Any], cand: Dict[str, Any], kind: str,
                   shipping: Dict[str, Any]) -> Dict[str, Any]:
    """The verdict after an accepted (or forced) decision; ``verdict`` is not modified."""
    out = copy.deepcopy(verdict)
    cls = decision["class"]
    level = decision.get("usage_level") or "none"
    out["class"] = cls
    out["usage_level"] = level
    out["usage"] = usage_list(level) if cls == "USED" else []
    out["scope"] = SCOPE_OF_CLASS.get(cls, "product")
    out["reason_code"] = _reason_for(decision, verdict, cand)
    out["verification"] = decision.get("verification")
    out["identity"] = decision.get("identity") or verdict.get("identity")
    out["version_option"] = decision.get("version_option") or verdict.get("version_option")
    out["needs"] = None
    out["evidence_ids"] = sorted(set(verdict.get("evidence_ids") or []) | set(decision.get("evidence_ids") or []))
    if cls == "USED" and not out.get("configs"):
        out["configs"] = list(shipping.get("configs") or [])
    out["adjudicated"] = True
    out["adjudication"] = {"kind": kind, "source": decision.get("source", "model"),
                           "rationale": decision.get("rationale", ""), "evidence_ids": list(decision.get("evidence_ids") or [])}
    notes = list(verdict.get("notes") or [])
    if decision.get("source", "model") == "model" and decision.get("rationale"):
        notes.insert(0, "model: " + str(decision["rationale"]))
    elif decision.get("rationale"):
        notes.append(str(decision["rationale"]))
    out["notes"] = notes
    return out


def final_verdicts_from(verdicts_doc: Dict[str, Any], validated: Optional[Dict[str, Any]],
                        cands: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    inputs = verdicts_doc.get("adjudication_inputs") or {}
    out = [copy.deepcopy(v) for v in verdicts_doc.get("verdicts") or []]
    if not validated:
        return out
    shipping = verdicts_doc.get("shipping") or {}
    for kind in KINDS:
        section = validated.get(kind)
        if not section or section.get("input_sha256") != inputs.get(kind):
            continue
        by_id = {d["item_id"]: d for d in section.get("decisions") or []}
        for index, verdict in enumerate(out):
            decision = by_id.get(verdict["candidate"])
            if decision is None or verdict.get("needs") != kind:
                continue
            out[index] = apply_decision(verdict, decision, cands.get(verdict["candidate"], {}), kind, shipping)
    return out


# ------------------------------------------------------------------------------------------------------ orchestration

def _validated_path(ctx: RunContext, repo: str) -> Any:
    return ctx.layout.repo_out(repo) / "decisions_validated.json"


def _read_validated(ctx: RunContext, repo: str) -> Dict[str, Any]:
    doc = _read_json(_validated_path(ctx, repo))
    if isinstance(doc, dict) and doc.get("schema") == SCHEMA:
        return doc
    return {"schema": SCHEMA, "repo": repo, "usage": None, "trace_build": None, "blindspots": []}


def _write_section(ctx: RunContext, repo: str, kind: str, section: Dict[str, Any]) -> None:
    doc = _read_validated(ctx, repo)
    doc["repo"] = repo
    doc[kind] = section
    spots: List[Dict[str, Any]] = []
    for k in KINDS:
        spots.extend((doc.get(k) or {}).get("blindspots") or [])
    unique = {(s["code"], s.get("loc") or "", s.get("candidate") or ""): s for s in spots}
    doc["blindspots"] = [unique[k] for k in sorted(unique)]
    fsio.atomic_write_json(_validated_path(ctx, repo), doc, root=ctx.layout.out)


def _section(summary: Dict[str, Any], decisions: List[Dict[str, Any]], forced: List[str], attempts: int,
             spots: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = sorted(decisions, key=lambda d: d["item_id"])
    return {"input_sha256": summary["input_sha256"], "attempts": attempts, "decisions": ordered,
            "forced_inconclusive": sorted(forced), "blindspots": spots}


def _accepted_record(decision: Dict[str, Any], verdict: Dict[str, Any], pool: Pool, scope_all: bool) -> Dict[str, Any]:
    rec = {k: decision.get(k) for k in ("item_id", "class", "usage_level", "identity", "version_option", "rationale")}
    rec["evidence_ids"] = list(decision.get("evidence_ids") or [])
    rec["source"] = "model"
    rec["verification"] = decision_verification(decision, verdict, pool, scope_all)
    return rec


def _forced_record(item: Dict[str, Any], verdict: Dict[str, Any], reason: Optional[str], why: str) -> Dict[str, Any]:
    return {"item_id": item["item_id"], "class": "INCONCLUSIVE", "usage_level": "none",
            "identity": verdict.get("identity") or (item["identity_options"][0] if item["identity_options"] else None),
            "version_option": verdict.get("version_option") or item["version_options"][0]["id"],
            "evidence_ids": [], "verification": verdict.get("verification"), "source": "script",
            "reason_code": reason, "rationale": why[:MAX_RATIONALE]}


def _summary_and_pool(ctx: RunContext, repo: str, kind: str) -> Tuple[Optional[Dict[str, Any]], Pool]:
    pool = load_pool(ctx, repo)
    summary, _ = build_summary(ctx, pool, kind)
    return summary, pool


def apply_validated(ctx: RunContext, pool: Pool, summary: Dict[str, Any], doc: Optional[Dict[str, Any]],
                    doc_problems: List[str], kind: str, attempt: int, *, write: bool = True
                    ) -> Tuple[bool, List[str], int, List[str]]:
    """Validate and, when allowed, apply. Returns ``(ok, messages, applied, forced item ids)``."""
    items = {i["item_id"]: i for i in summary["items"]}
    scope_all = ctx.scope == "all"
    messages = list(doc_problems)
    valid: Dict[str, Dict[str, Any]] = {}
    bad: Set[str] = set(items) if (doc is None or doc_problems) else set()
    uncited: Set[str] = set()
    if doc is not None and not doc_problems:
        valid, item_messages, bad, uncited = validate(summary, doc, kind, pool)
        messages.extend(item_messages)
    if messages and attempt == 1:
        return False, messages[:MAX_MESSAGES], 0, []
    decisions: List[Dict[str, Any]] = []
    forced: List[str] = []
    spots: List[Dict[str, Any]] = []
    for item_id in sorted(items):
        verdict = pool.verdict_by_cand[item_id]
        if item_id in valid and item_id not in uncited:
            decisions.append(_accepted_record(valid[item_id], verdict, pool, scope_all))
            continue
        forced.append(item_id)
        name = pool.cands[item_id]["name"]
        if item_id in uncited:
            decisions.append(_forced_record(items[item_id], verdict, verdict.get("reason_code"),
                                            "the decision cited no BUILD_REF_UNPARSED or BUILD_FILE_UNPARSED record"))
            spots.append({"code": "TRACE_UNCITED", "candidate": item_id, "loc": None,
                          "message": ("%s: the build trace cited no build-file evidence; the item stays inconclusive"
                                      % name)[:200]})
        else:
            decisions.append(_forced_record(items[item_id], verdict, "REVIEW_ADJUDICATION_FAILED",
                                            "no valid decision after the corrective retry"))
            spots.append({"code": "ADJUDICATION_FAILED", "candidate": item_id, "loc": None,
                          "message": ("%s: the model's decision was missing or invalid after one retry" % name)[:200]})
    if write:
        _write_section(ctx, pool.repo, kind, _section(summary, decisions, forced, attempt, spots))
    applied = len(decisions) - len(forced)
    return True, messages[:MAX_MESSAGES], applied, forced


def summary_block(ctx: RunContext, summary: Dict[str, Any], kind: str) -> Dict[str, Any]:
    in_name = FILES[kind][0]
    block = {"kind": kind, "repo": summary["repo"],
             "input": ctx.layout.rel(ctx.layout.repo_out(summary["repo"]) / in_name),
             "output": summary["output"], "rubric": ctx.layout.skill_path(summary["rubric"]),
             "input_sha256": summary["input_sha256"],
             "items": len(summary["items"])}
    if kind == "trace_build":
        block["build_files"] = [b["path"] for b in summary.get("build_files") or []]
    return block


def evidence_summary(ctx: RunContext, run: Any, repo: str, kind: str) -> Optional[Dict[str, Any]]:
    """Section 3.10: write the input file of ``kind`` and return the ``adjudicate`` block (``None`` when no item needs it
    or the crash-recovery cache already applied a complete decisions file)."""
    if kind not in KINDS:
        raise ValueError("unknown adjudication kind: %r" % (kind,))
    pool = load_pool(ctx, repo)
    summary, _ = build_summary(ctx, pool, kind)
    in_name, out_name = FILES[kind]
    out_dir = ctx.layout.repo_out(repo)
    summary_path = out_dir / in_name
    if summary is None:
        fsio.remove_file(summary_path, root=ctx.layout.out)
        return None
    entries = (getattr(run, "data", None) or {}).get("adjudication") or {}
    if "%s:%s" % (repo, kind) not in entries:
        raw = None
        decisions_path = out_dir / out_name
        if os.path.lexists(str(decisions_path)):
            from sbomlib.verify.inputs import read_target_bytes
            raw = read_target_bytes(out_dir, out_name, MAX_BYTES + 1)
        if raw is not None:
            doc, problems, notes = parse_document(raw, summary, kind, repo)
            if doc is not None and not problems and not notes and doc.get("input_sha256") == summary["input_sha256"]:
                _valid, messages, bad, _uncited = validate(summary, doc, kind, pool)
                if not messages and not bad:
                    apply_validated(ctx, pool, summary, doc, [], kind, 1)
                    return None
    fsio.ensure_dir(out_dir / "llm", root=ctx.layout.out)        # the one directory the agent may write into
    fsio.atomic_write_json(summary_path, summary, root=ctx.layout.out)
    return summary_block(ctx, summary, kind)


def apply_decisions(ctx: RunContext, run: Any, repo: str, kind: str, attempt: int) -> model.ApplyResult:
    """Section 3.10: attempt 1 is all-or-nothing, attempt 2 applies the valid decisions and forces the rest."""
    if kind not in KINDS:
        raise ValueError("unknown adjudication kind: %r" % (kind,))
    pool = load_pool(ctx, repo)
    summary, _ = build_summary(ctx, pool, kind)
    if summary is None:
        return model.ApplyResult(True, [], 0, [])
    _, out_name = FILES[kind]
    from sbomlib.verify.inputs import read_target_bytes
    raw = read_target_bytes(ctx.layout.repo_out(repo), out_name, MAX_BYTES + 1)
    doc, problems, notes = parse_document(raw, summary, kind, repo)
    ok, messages, applied, forced = apply_validated(ctx, pool, summary, doc, problems, kind, attempt)
    found = replyread.note_records(notes, attempt=attempt)
    if not ok:
        return model.ApplyResult(False, messages, 0, [], found)
    return model.ApplyResult(True, messages, applied, forced, found)


def final_verdicts(ctx: RunContext, repo: str) -> List[Dict[str, Any]]:
    out = ctx.layout.repo_out(repo)
    verdicts_doc = _checked(fsio.read_json(out / "verdicts.json"), "verdicts.json")
    validated = _read_json(_validated_path(ctx, repo))
    if validated is None:
        return final_verdicts_from(verdicts_doc, None, {})                 # nothing adjudicated: no need to read candidates
    if not isinstance(validated, dict) or validated.get("schema") != SCHEMA:
        raise errors.StateError("decisions_validated.json has an unsupported schema")
    candidates_doc = _checked(fsio.read_json(out / "candidates.json"), "candidates.json")
    cands = {c["id"]: c for c in candidates_doc.get("candidates") or []}
    return final_verdicts_from(verdicts_doc, validated, cands)


def blindspots(ctx: RunContext, repo: str) -> List[Dict[str, Any]]:
    out = ctx.layout.repo_out(repo)
    spots: List[Dict[str, Any]] = []
    for name in ("candidates.json", "verdicts.json", "decisions_validated.json"):
        doc = _read_json(out / name)
        if isinstance(doc, dict):
            if doc.get("schema") != SCHEMA:
                raise errors.StateError("%s has an unsupported schema" % name)
            spots.extend(s for s in doc.get("blindspots") or [] if isinstance(s, dict))
    unique: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for spot in spots:
        key = (str(spot.get("code")), str(spot.get("loc") or ""), str(spot.get("candidate") or ""))
        unique.setdefault(key, spot)
    return [unique[k] for k in sorted(unique)]
