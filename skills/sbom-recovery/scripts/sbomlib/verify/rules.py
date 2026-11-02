"""The rule engine of Appendix D: classes, usage levels, reason codes, verification and the transitive fixpoint.

``Engine.run`` takes the phase-2 data, the build analysis and the include/identifier scan of ``usage`` and returns the
verdicts (section 4.10), the extra verification records (``CONDITION``, ``TEST_SCOPE``, ``ABSENCE``, ``TRANSITIVE``) and
the blind spots. Predicates are evaluated per shipping configuration; ``platform`` counts as enabled (D20); a record whose
condition is ``unknown`` never makes code ``disabled`` and never proves use (it feeds row 11).
"""
from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

from sbomlib import ids, model, norm
from sbomlib.context import RunContext
from sbomlib.verify import configs
from sbomlib.verify.configs import DISABLED, ENABLED, UNKNOWN, any_of, combine, is_enabled
from sbomlib.verify.inputs import IN_TREE, RepoData, compile_source, path_scope, within
from sbomlib.verify.usage import Build, Scan, Scanner, Site, parent_dir

POSITIVE_TYPES = ("COMPILE_LIST", "LINK_PROOF", "LINK_LINE", "API_HIT", "INCLUDE", "SUBDIR_BUILD", "LINK_REF",
                  "FIND_PACKAGE", "DLOPEN", "TRANSITIVE")
SUPPORT_TYPES = POSITIVE_TYPES + ("BUILD_REF_UNPARSED",)          # the support list of section 4.11 / D21
BUILD_REF_TYPES = ("LINK_REF", "FIND_PACKAGE", "SUBDIR_BUILD", "LINK_LINE")
PIN_TYPES = ("MANIFEST_DECL", "LOCK_PIN", "FETCH_PIN")
BUILD_LEVEL_TYPES = ("COMPILE_LIST", "LINK_REF", "FIND_PACKAGE", "SUBDIR_BUILD", "LINK_LINE", "LINK_PROOF") + PIN_TYPES
BUILD_REFERENCED_TYPES = ("SUBDIR_BUILD", "LINK_REF", "FIND_PACKAGE", "COMPILE_LIST", "LINK_LINE", "LINK_PROOF",
                          "BUILD_REF_UNPARSED")
USED_PREDICATES = ("compile", "link", "header", "code", "dlopen", "toolchain")
WEAK_DISTINCT_NEEDED = 3
SCOPE_CLASS = {"test": "TEST_ONLY", "dev": "DEV_ONLY", "build": "BUILD_ONLY"}
NEGATIVE_CLASSES = ("BUILD_ONLY", "TEST_ONLY", "DEV_ONLY", "OPTIONAL", "UNUSED_DEAD_COPY")
LEVEL_USAGE = {"vendored_compiled": ["static"], "static": ["static"], "dynamic": ["dynamic"], "header_only": ["header_only"],
               "runtime_loaded": ["runtime_loaded"]}
STRENGTH_RANK = {"strong": 3, "medium": 2, "weak": 1, "absence": 0, "none": 0}


def usage_list(level: str) -> List[str]:
    """``usage`` list of a verdict derived from its ``usage_level`` (section 3.6): other levels leave the kind unknown."""
    return list(LEVEL_USAGE.get(level, []))


class Ev:
    """A piece of evidence of one candidate with the values the rules read."""

    __slots__ = ("d", "type", "status", "terms", "scope", "positive", "origin", "site", "idx")

    def __init__(self, d: Dict[str, Any], status: Dict[str, str], terms: Sequence[str], scope: str, positive: bool,
                 origin: Optional[str] = None, site: Optional[Site] = None, idx: Optional[int] = None) -> None:
        self.d = d
        self.type = d["type"]
        self.status = status
        self.terms = list(terms)
        self.scope = scope
        self.positive = positive
        self.origin = origin
        self.site = site
        self.idx = idx

    @property
    def conditional(self) -> bool:
        cond = self.d.get("condition")
        return bool((cond or {}).get("all")) or bool(self.d.get("guards")) or bool(self.terms) or any(
            v != ENABLED for v in self.status.values())


class Use:
    """Outcome of ``Engine.uses``: which predicates hold in which configurations."""

    def __init__(self) -> None:
        self.per_config: Dict[str, Dict[str, List[Ev]]] = {}
        self.used_by: Optional[str] = None
        self.configs: List[str] = []
        self.support: List[Ev] = []
        self.wired = False
        self.code_any = False
        self.build_ref_any = False

    def holds(self, predicate: str) -> bool:
        return any(self.per_config[c].get(predicate) for c in self.per_config)


class CandView:
    def __init__(self, cand: Dict[str, Any], evs: List[Ev]) -> None:
        self.cand = cand
        self.id = cand["id"]
        self.evs = evs
        self.by_type: Dict[str, List[Ev]] = {}
        for ev in evs:
            self.by_type.setdefault(ev.type, []).append(ev)
        # own positive records: first-party code and build-level records (origin-candidate sites feed the transitive step)
        self.pos = [e for e in evs if e.type in POSITIVE_TYPES and e.positive and e.origin is None]

    def of(self, *types: str) -> List[Ev]:
        out: List[Ev] = []
        for t in types:
            out.extend(self.by_type.get(t, []))
        return out


class RuleResult:
    def __init__(self) -> None:
        self.verdicts: List[Dict[str, Any]] = []
        self.records: List[Dict[str, Any]] = []
        self.blindspots: List[Dict[str, Any]] = []
        self.coverage: Dict[str, str] = {}


class Engine:
    def __init__(self, ctx: RunContext, data: RepoData, shipping: Dict[str, Any], build: Build, scanner: Scanner) -> None:
        self.ctx = ctx
        self.data = data
        self.shipping = shipping
        self.build = build
        self.scanner = scanner
        self.scan: Scan = scanner.scan
        self.ship: List[str] = list(shipping["configs"])
        self.all_configs: List[str] = list(shipping["all"])
        self.repo = data.repo
        bm = data.buildmodel
        self.coverage = {"build": bm.get("coverage") if bm.get("coverage") in ("complete", "partial", "none") else "none",
                         "sources": self.scan.coverage_sources}
        self.tests_enabled_by = {str(n) for n in bm.get("tests_enabled_by") or []}
        self.pkg_kind: Dict[str, str] = {p["evidence_id"]: p.get("kind") for p in bm.get("packages") or []
                                         if isinstance(p, dict) and p.get("evidence_id")}
        self.ev_by_id: Dict[str, Dict[str, Any]] = {e["id"]: e for e in data.evidence}
        self.new_records: List[Dict[str, Any]] = []
        self.blindspots: List[Dict[str, Any]] = []
        self.views: Dict[str, CandView] = {}
        self.verdicts: Dict[str, Dict[str, Any]] = {}
        self.scope_all = ctx.scope == "all"

    # ================================================================== evidence views
    def _scope_for_build_record(self, rec: Dict[str, Any], idx: Optional[int], path: Optional[str]) -> str:
        scope = rec.get("scope") or "product"
        if scope != "product":
            return scope
        clauses = (rec.get("condition") or {}).get("all") or []
        if any(c.get("var") in self.tests_enabled_by and c.get("op") == "truthy" for c in clauses if isinstance(c, dict)):
            return "test"
        if idx is not None and self.build.target_scope(idx) != "product":
            return self.build.target_scope(idx)
        if rec.get("type") == "FIND_PACKAGE" and self.pkg_kind.get(rec.get("id", "")) == "find_program":
            return "build"
        if path:
            owner = self.data.owner_of(path)
            base = self.data.dir_of.get(owner) if owner else ""
            return path_scope(path, self.data.test_dirs, base=base or "")
        return scope

    def _make_ev(self, rec: Dict[str, Any]) -> Ev:
        build = self.build
        rtype = rec["type"]
        path = (compile_source(rec) if rtype == "COMPILE_LIST" else
                norm.normalize_path(str(rec["path"])) if rec.get("path") else None)
        idx: Optional[int] = None
        indices: List[Tuple[int, Optional[Dict[str, Any]]]] = []
        if rtype in ("COMPILE_LIST", "LINK_REF") or rtype in PIN_TYPES:
            idx = build.resolve_target(rec.get("target"), path if rtype == "COMPILE_LIST" else None)
            if idx is not None:
                src = next((s for i, s in build.by_source().get(path or "", []) if i == idx), None)
                indices = [(idx, src)]
            elif rtype == "COMPILE_LIST" and path:
                indices = [(i, s) for i, s in build.by_source().get(path, [])]
        status: Dict[str, str] = {}
        terms = configs.condition_terms(rec.get("condition"))
        if idx is not None:
            for t in configs.condition_terms(build.targets[idx].get("condition")):
                if t not in terms:
                    terms.append(t)
        positive = True
        if rtype == "DLOPEN" and path:
            code_status, code_terms, scope, state = self.scanner.code_status(path, rec.get("guards") or [])
            positive = state in ("yes", "assumed")
            for config in build.configs:
                status[config] = combine([build.cond(rec.get("condition"), config), code_status[config]])
            terms = sorted(set(terms) | set(code_terms))
            if rec.get("scope") not in (None, "product"):
                scope = rec["scope"]
            return Ev(rec, status, terms, scope, positive)
        for config in build.configs:
            parts = [build.cond(rec.get("condition"), config)]
            if rtype in ("COMPILE_LIST", "LINK_REF") or rtype in PIN_TYPES:
                if indices:
                    values = []
                    for i, src in indices:
                        v = build.active_status(i, config)
                        if src is not None:
                            v = combine([v, build.cond(src.get("condition"), config)])
                        values.append(v)
                    parts.append(any_of(values))
                elif rtype != "COMPILE_LIST" and path:
                    parts.append(build.dir_status(parent_dir(path), config))
            elif rtype in ("FIND_PACKAGE", "SUBDIR_BUILD") and path:
                parts.append(build.dir_status(parent_dir(path), config))
            status[config] = combine(parts)
        scope = self._scope_for_build_record(rec, idx, path if rtype != "COMPILE_LIST" else None)
        if rtype == "COMPILE_LIST" and scope == "product" and indices and all(build.is_test_target(i) for i, _ in indices):
            scopes = {build.target_scope(i) for i, _ in indices}
            scope = "test" if "test" in scopes else "dev"
        if rtype in PIN_TYPES and idx is None:
            positive = False                                  # a bare declaration is not use evidence
        return Ev(rec, status, terms, scope, positive, idx=idx)

    def _site_ev(self, site: Site) -> Ev:
        return Ev(site.rec, site.status, site.terms, site.scope, site.positive, origin=site.origin, site=site)

    def _build_views(self) -> None:
        by_cand: Dict[str, List[Ev]] = {c["id"]: [] for c in self.data.candidates}
        for index, rec in enumerate(self.data.evidence):
            if index % 500 == 0:
                self.ctx.check_deadline()
            cid = rec.get("candidate")
            if cid in by_cand:
                by_cand[cid].append(self._make_ev(rec))
        for site in self.scan.includes + self.scan.hits:
            if site.cand in by_cand:
                by_cand[site.cand].append(self._site_ev(site))
        for cand in self.data.candidates:
            self.views[cand["id"]] = CandView(cand, by_cand[cand["id"]])

    # ================================================================== predicates
    def _usage_by_identifier(self, hits: Sequence[Ev]) -> bool:
        if any(h.d.get("weight") == "strong" for h in hits):
            return True
        return len({h.d.get("symbol") for h in hits if h.d.get("weight") == "weak"}) >= WEAK_DISTINCT_NEEDED

    def uses(self, cv: CandView, accept: Callable[[str], bool], *, assumed_ok: bool = True,
             ambiguous_ok: bool = True, config_list: Optional[Sequence[str]] = None) -> Use:
        cand = cv.cand
        use = Use()
        config_list = list(config_list) if config_list is not None else self.ship
        toolchain = bool(cv.by_type.get("TOOLCHAIN_RUNTIME")) or cand.get("detected_as") == "toolchain_runtime"
        header_only = self.scanner.is_header_only_with_code(cand)

        def site_ok(ev: Ev) -> bool:
            if ev.origin is not None or not ev.positive or ev.scope != "product":
                return False
            if not assumed_ok and ev.site is not None and ev.site.compiled == "assumed":
                return False
            if not ambiguous_ok and ev.site is not None and ev.site.ambiguous:
                return False
            return True

        for config in config_list:
            def ok(ev: Ev, _c: str = config) -> bool:
                return accept(ev.status.get(_c, DISABLED))

            comp = [e for e in cv.by_type.get("COMPILE_LIST", []) if e.scope == "product" and e.d.get("strength") == "strong"
                    and ok(e)]
            link = [e for e in cv.by_type.get("LINK_PROOF", []) if e.scope == "product" and e.d.get("strength") == "strong"
                    and ok(e)]
            incs = [e for e in cv.by_type.get("INCLUDE", []) if site_ok(e) and ok(e)]
            hits = [e for e in cv.by_type.get("API_HIT", []) if site_ok(e) and ok(e)]
            header = [e for e in incs if header_only and e.site is not None and e.site.header_only_code]
            code = (incs + hits) if (incs and self._usage_by_identifier(hits)) else []
            refs = [e for e in cv.of(*BUILD_REF_TYPES, *PIN_TYPES) if e.positive and e.scope == "product" and ok(e)]
            dlopen = [e for e in cv.by_type.get("DLOPEN", []) if e.positive and e.scope == "product" and ok(e)
                      and cand.get("detected_as") != "declared_unresolved"]
            use.per_config[config] = {"compile": comp, "link": link, "header": header, "code": code, "refs": refs,
                                      "dlopen": dlopen, "toolchain": list(cv.by_type.get("TOOLCHAIN_RUNTIME", [])),
                                      "toolchain_flag": toolchain}
        for config in config_list:
            row = self.per_config_flags(use, config)
            if any(row.values()):
                use.configs.append(config)
        use.used_by = None
        for predicate in USED_PREDICATES:
            for config in config_list:
                if self.per_config_flags(use, config)[predicate]:
                    use.used_by = {"code": "P_code+build_ref", "compile": "P_compile", "link": "P_link", "header": "P_header",
                                   "dlopen": "P_dlopen", "toolchain": "toolchain"}[predicate]
                    pc = use.per_config[config]
                    use.support = list(pc["code"] + pc["refs"] if predicate == "code" else pc[predicate])
                    break
            if use.used_by:
                break
        for config in config_list:
            pc = use.per_config[config]
            if pc["refs"]:
                use.build_ref_any = True
            if pc["code"]:
                use.code_any = True
        use.wired = use.build_ref_any
        return use

    @staticmethod
    def per_config_flags(use: Use, config: str) -> Dict[str, bool]:
        pc = use.per_config[config]
        return {"compile": bool(pc["compile"]), "link": bool(pc["link"]), "header": bool(pc["header"]),
                "code": bool(pc["code"] and pc["refs"]), "dlopen": bool(pc["dlopen"]),
                "toolchain": bool(pc["toolchain_flag"])}

    # ================================================================== small helpers
    def _build_referenced(self, cv: CandView) -> bool:
        if any(cv.by_type.get(t) for t in BUILD_REFERENCED_TYPES):
            return True
        return any(e.d.get("target") for e in cv.of(*PIN_TYPES))

    def _positive_product(self, cv: CandView) -> bool:
        return any(e.type in SUPPORT_TYPES and e.scope == "product" for e in cv.evs if e.origin is None) or bool(
            cv.by_type.get("BUILD_REF_UNPARSED"))

    def _d21(self, cv: CandView) -> Optional[str]:
        return "unresolved" if (self._positive_product(cv) or self._build_referenced(cv)) else None

    def _new_verdict(self, cand: Dict[str, Any]) -> Dict[str, Any]:
        return {"candidate": cand["id"], "class": "INCONCLUSIVE", "usage_level": "none", "usage": [], "scope": "product",
                "reason_code": None, "verification": None, "configs": [], "artifacts": [], "condition": None,
                "evidence_ids": [], "negative": [], "needs": None, "review_codes": [], "used_by": None, "tool": False,
                "build_referenced": False, "transitive_via": None, "identity": cand["name"],
                "version_option": self._version_option(cand), "notes": []}

    @staticmethod
    def _version_option(cand: Dict[str, Any]) -> str:
        version = cand.get("version") or {}
        options = version.get("options") or []
        for option in options:
            if (option.get("version") == version.get("version") and option.get("version_kind") == version.get("version_kind")
                    and list(option.get("evidence_ids") or []) == list(version.get("evidence_ids") or [])):
                return str(option["id"])
        for option in options:
            if option.get("version") == version.get("version") and option.get("version_kind") == version.get("version_kind"):
                return str(option["id"])
        return str(options[0]["id"]) if options else "v0"

    def _is_first_party(self, cv: CandView) -> Optional[str]:
        cand = cv.cand
        if cand.get("first_party"):
            return "marked as the repository's own"
        names = {norm.norm_library(str(cand.get("name", ""))), str(cand.get("norm_name") or "")}
        for option in cand.get("identity_options") or []:
            names.add(norm.norm_library(str(option.get("name", ""))))
        names.discard("")
        for sibling in self.data.siblings:
            if norm.norm_library(sibling) in names:
                return "name equals the sibling repository %s" % sibling
        for ev in cv.by_type.get("DECLARED_ID", []):
            value = ev.d.get("value")
            if isinstance(value, dict) and (value.get("own") or value.get("first_party") or value.get("self")):
                return "a declared identifier marks it as the repository's own"
        return None

    def _identity_ambiguous(self, cv: CandView) -> bool:
        strong: Set[str] = set()
        for option in cv.cand.get("identity_options") or []:
            key = norm.norm_library(str(option.get("name", "")))
            for eid in option.get("evidence_ids") or []:
                rec = self.ev_by_id.get(eid)
                if rec is not None and rec.get("strength") == "strong":
                    strong.add(key)
                    break
        return len(strong) >= 2

    def _level(self, cv: CandView, use: Use) -> str:
        cand = cv.cand
        used_by = use.used_by
        if used_by == "P_compile":
            if self.data.in_tree(cand):
                return "vendored_compiled"
            return self._link_kind(cv, use.support)
        if used_by == "P_link":
            return "static"
        if used_by == "P_header":
            return "header_only"
        if used_by == "P_code+build_ref":
            if self.data.in_tree(cand) and self.scanner.has_sources(cand):
                return "vendored_compiled"
            return self._link_kind(cv, use.support)
        if used_by == "P_dlopen":
            return "runtime_loaded"
        if used_by == "toolchain":
            return "toolchain_runtime"
        return "none"

    def _link_kind(self, cv: CandView, support: Sequence[Ev]) -> str:
        """``static`` / ``dynamic`` when the linked target type or the prebuilt file name tells, else ``linked``."""
        kinds: Set[str] = set()
        cand = cv.cand
        loc = (cand.get("location") or {}).get("path") or ""
        if cand.get("detected_as") == "prebuilt":
            low = str(loc).lower()
            if low.endswith((".a", ".lib")):
                return "static"
            if ".so" in low or low.endswith((".dll", ".dylib")):
                return "dynamic"
        for ev in list(support) + cv.of("LINK_REF", "COMPILE_LIST"):
            if ev.type == "LINK_REF":
                name = str(ev.d.get("value") or "")
                idx = self.build.resolve_target(name) if name else None
            elif ev.type == "COMPILE_LIST":
                idx = ev.idx
            else:
                idx = None
            if idx is not None:
                kinds.add(str(self.build.targets[idx].get("kind")))
        if kinds and kinds <= {"static_library", "object_library"}:
            return "static"
        if kinds and kinds <= {"shared_library", "module_library"}:
            return "dynamic"
        return "linked"

    def _artifacts(self, use: Use) -> List[str]:
        names: Set[str] = set()
        build = self.build
        for config in use.configs or self.ship:
            reach = build.root_reach(config)
            for ev in use.support:
                indices: List[int] = []
                if ev.idx is not None:
                    indices.append(ev.idx)
                elif ev.type in ("INCLUDE", "API_HIT", "DLOPEN") and ev.d.get("path"):
                    indices.extend(i for i, _ in build.by_source().get(str(ev.d["path"]), []))
                elif ev.type == "LINK_REF" and ev.d.get("target"):
                    i = build.resolve_target(ev.d.get("target"))
                    if i is not None:
                        indices.append(i)
                for i in indices:
                    if build.is_test_target(i):
                        continue
                    for root in reach.get(i, []):
                        names.add(str(build.targets[root].get("name")))
        return sorted(names)

    def _platform_condition(self, use: Use) -> Optional[str]:
        """Section 6.10: platform terms shared by every code-level supporting record plus those shared by every build-level one."""
        code = [e for e in use.support if e.type in ("INCLUDE", "API_HIT", "COMPILE_LIST", "LINK_PROOF", "DLOPEN")]
        build = [e for e in use.support if e.type in ("LINK_REF", "FIND_PACKAGE", "SUBDIR_BUILD", "LINK_LINE") + PIN_TYPES]
        terms: Set[str] = set()
        for group in (code, build):
            if not group:
                continue
            shared = set(group[0].terms)
            for ev in group[1:]:
                shared &= set(ev.terms)
            terms |= shared
        return configs.render_terms(terms)

    def _tool(self, cv: CandView) -> bool:
        uses = [e for e in cv.evs if e.type in POSITIVE_TYPES and e.origin is None]
        if not uses:
            return False
        return all(e.type == "FIND_PACKAGE" and self.pkg_kind.get(e.d["id"]) == "find_program" for e in uses)

    # ================================================================== the rule table
    def decide(self, cv: CandView) -> Dict[str, Any]:
        cand = cv.cand
        v = self._new_verdict(cand)
        v["build_referenced"] = self._build_referenced(cv)
        v["tool"] = self._tool(cv)
        strict = self.uses(cv, is_enabled)
        no_assumed = self.uses(cv, is_enabled, assumed_ok=False)
        no_ambiguous = self.uses(cv, is_enabled, ambiguous_ok=False)
        v["used_by"] = strict.used_by                                   # computed for every candidate (D3)
        sub = cand.get("submodule") or {}

        # row 1: uninitialized submodule
        if sub.get("state") == "uninitialized":
            reference = "build-referenced" if v["build_referenced"] else (
                "referenced only by tests" if any(e.scope == "test" for e in cv.evs if e.type in SUPPORT_TYPES) else "unreferenced")
            v.update({"class": "UNANALYZED", "reason_code": "UNINITIALIZED_SUBMODULE", "verification": "unresolved",
                      "notes": ["uninitialized submodule; " + reference]})
            return v
        # row 2: first party
        reason = self._is_first_party(cv)
        if reason:
            v.update({"class": "FIRST_PARTY", "reason_code": "FIRST_PARTY", "notes": [reason]})
            return v
        # row 3: identity ambiguous (two identities with strong evidence for one location, or an include tied between two
        # candidates when that include is all the code-level proof there is)
        tied_only = bool(strict.used_by in ("P_header", "P_code+build_ref") and no_ambiguous.used_by is None)
        if self._identity_ambiguous(cv) or tied_only:
            v.update({"class": "INCONCLUSIVE", "reason_code": "REVIEW_IDENTITY", "needs": "usage",
                      "verification": self._d21(cv), "review_codes": ["REVIEW_IDENTITY"]})
            if tied_only:
                v["notes"].append("an include resolves to more than one candidate (ambiguous header)")
            return v
        # row 4: version conflict while rows 5-6 would apply
        if (cand.get("version") or {}).get("conflict") and strict.used_by in (
                "P_compile", "P_link", "P_header", "P_code+build_ref", "P_dlopen"):
            level = self._level(cv, strict)
            v.update({"class": "INCONCLUSIVE", "usage_level": level, "usage": usage_list(level),
                      "reason_code": "REVIEW_VERSION_CONFLICT", "needs": "usage", "verification": self._d21(cv),
                      "review_codes": ["REVIEW_VERSION_CONFLICT"]})
            return v
        # rows 5-7: USED
        if strict.used_by is not None:
            level = self._level(cv, strict)
            declared = no_assumed.used_by is None
            v.update({"class": "USED", "usage_level": level, "usage": usage_list(level),
                      "verification": "declared" if declared else "proven", "configs": list(strict.configs),
                      "artifacts": self._artifacts(strict), "condition": self._platform_condition(strict)})
            if declared:
                v["notes"].append("compiled status assumed: the build names no sources")
            return v
        # row 8: dlopen of an unmapped soname
        if any(e.positive and e.scope == "product" for e in cv.by_type.get("DLOPEN", [])) and (
                cand.get("detected_as") == "declared_unresolved"):
            v.update({"class": "INCONCLUSIVE", "reason_code": "REVIEW_DLOPEN", "needs": "usage",
                      "verification": self._d21(cv), "review_codes": ["REVIEW_DLOPEN"]})
            return v
        pos = cv.pos
        product_pos = [e for e in pos if e.scope == "product"]
        covered_sources = self.coverage["sources"] in ("complete", "assumed")
        # row 9: only test, dev or build scope evidence
        if pos and not product_pos and covered_sources:
            scopes = {e.scope for e in pos}
            scope = "test" if "test" in scopes else ("dev" if "dev" in scopes else "build")
            if scope not in SCOPE_CLASS:
                scope = "test"
            cls = SCOPE_CLASS[scope]
            v.update({"class": cls, "reason_code": cls, "scope": scope,
                      "verification": "proven" if self.scope_all else None})
            return v
        # row 10: positive product evidence exists and is switched off in every shipping configuration
        if product_pos and all(e.status.get(c, DISABLED) == DISABLED for e in product_pos for c in self.ship):
            v.update({"class": "OPTIONAL", "reason_code": "CONDITIONAL_DISABLED"})
            return v
        # row 11: use depends on conditions the static analysis cannot evaluate
        loose = self.uses(cv, lambda s: s != DISABLED)
        if loose.used_by is not None:
            v.update({"class": "INCONCLUSIVE", "reason_code": "REVIEW_CONDITION_UNKNOWN", "needs": "usage",
                      "verification": self._d21(cv), "review_codes": ["REVIEW_CONDITION_UNKNOWN"],
                      "configs": [c for c in self.ship if any(self.per_config_flags(loose, c).values())]})
            return v
        # row 12: statically wired (a link reference or find_package, no code proof)
        if strict.wired:
            v.update({"class": "INCONCLUSIVE", "usage_level": "statically_wired", "reason_code": "REVIEW_INCLUDE_ONLY",
                      "verification": "declared", "review_codes": ["REVIEW_INCLUDE_ONLY"]})
            return v
        # row 13: code proof without a build reference while the build is fully covered
        if strict.code_any and self.coverage["build"] == "complete":
            v.update({"class": "INCONCLUSIVE", "reason_code": "REVIEW_NO_BUILD_REF", "needs": "usage",
                      "verification": self._d21(cv), "review_codes": ["REVIEW_NO_BUILD_REF"]})
            return v
        # row 14: a stale by-product disagrees with the current build
        if self._stale_conflict(cv):
            v.update({"class": "INCONCLUSIVE", "reason_code": "REVIEW_CONFLICT", "needs": "usage",
                      "verification": self._d21(cv), "review_codes": ["REVIEW_CONFLICT"],
                      "notes": ["a stale by-product reports use, the current build does not reference it"]})
            return v
        # row 15: the build is not (fully) covered and nothing beyond presence or declaration was seen
        beyond = [e for e in pos if e.type in ("COMPILE_LIST", "LINK_PROOF", "DLOPEN", "INCLUDE", "API_HIT")]
        if self.coverage["build"] != "complete" and (not beyond or strict.code_any):
            v.update({"class": "INCONCLUSIVE", "reason_code": "REVIEW_UNCOVERED_BUILD", "needs": "trace_build",
                      "verification": self._d21(cv), "review_codes": ["REVIEW_UNCOVERED_BUILD"]})
            return v
        full = self.coverage["build"] == "complete" and covered_sources
        no_code = not [e for e in cv.evs if e.type in ("INCLUDE", "API_HIT") and e.origin is None and e.positive
                       and e.scope == "product"]
        # row 16: a vendored, single-file or prebuilt copy nothing uses
        if full and no_code and not strict.wired and cand.get("detected_as") in IN_TREE:
            v.update({"class": "UNUSED_DEAD_COPY", "usage_level": "present", "reason_code": "PRESENT_NOT_BUILT"})
            return v
        # row 17: declared, but neither consumed nor used
        if full and no_code and not strict.wired and cand.get("detected_as") not in IN_TREE:
            v.update({"class": "UNUSED_DEAD_COPY", "usage_level": "declared", "reason_code": "DECLARED_NOT_USED"})
            return v
        # row 18: anything else
        v.update({"class": "INCONCLUSIVE", "reason_code": "REVIEW_CONFLICT", "needs": "usage",
                  "verification": self._d21(cv), "review_codes": ["REVIEW_CONFLICT"]})
        return v

    def _stale_conflict(self, cv: CandView) -> bool:
        if self.coverage["build"] != "complete":
            return False
        for ev in cv.of("COMPILE_LIST", "LINK_PROOF", "LINK_LINE"):
            default = model.EVIDENCE_DEFAULTS[ev.type][0]
            if STRENGTH_RANK.get(str(ev.d.get("strength")), 0) < STRENGTH_RANK.get(default, 0):
                current = [e for e in cv.of(*BUILD_REF_TYPES) if e.positive and e.d.get("strength") != "weak"
                           and e.type != "LINK_LINE"]
                return not current
        return False

    # ================================================================== transitive fixpoint
    def _own_kind_level(self, cand: Dict[str, Any]) -> str:
        if self.scanner.is_header_only_with_code(cand):
            return "header_only"
        if self.data.in_tree(cand) and self.scanner.has_sources(cand):
            return "vendored_compiled"
        return "linked"

    def transitive(self) -> None:
        """Appendix D: a candidate used only by another ``USED`` candidate's enabled build is ``USED`` (iterate to stable)."""
        eligible_reasons = ("REVIEW_IDENTITY", "REVIEW_VERSION_CONFLICT")
        changed = True
        while changed:
            changed = False
            used = {cid for cid, v in self.verdicts.items() if v["class"] == "USED"}
            for cid in sorted(self.views):
                verdict = self.verdicts[cid]
                if verdict["class"] in ("USED", "FIRST_PARTY", "UNANALYZED") or verdict["reason_code"] in eligible_reasons:
                    continue
                found = self._transitive_via(self.views[cid], used)
                if found is None:
                    continue
                via, how, ev, cfgs = found
                cand = self.views[cid].cand
                level = self._own_kind_level(cand)
                rec = model.new_evidence(
                    id=ids.evidence_id("u", self.repo, "TRANSITIVE", ev.d.get("path"), ev.d.get("line"), via + ":" + how, cid),
                    repo=self.repo, type="TRANSITIVE", candidate=cid, path=ev.d.get("path"), line=ev.d.get("line"),
                    symbol=how, detail=("used through %s (%s)" % (self.data.cand_by_id[via]["name"], how))[:200],
                    value={"via": via, "how": how}, scope="product")
                self.new_records.append(rec)
                self.views[cid].evs.append(Ev(rec, {c: ENABLED for c in self.all_configs}, [], "product", True))
                verdict.update({"class": "USED", "usage_level": level, "usage": usage_list(level), "reason_code": None,
                                "verification": "proven", "configs": cfgs, "used_by": "transitive", "transitive_via": via,
                                "needs": None, "review_codes": [], "condition": None,
                                "notes": verdict["notes"] + ["used through %s" % self.data.cand_by_id[via]["name"]]})
                changed = True
                used.add(cid)

    def _transitive_via(self, cv: CandView, used: Set[str]) -> Optional[Tuple[str, str, Ev, List[str]]]:
        cand = cv.cand
        header_only = self.scanner.is_header_only_with_code(cand)
        for outer in sorted(used):
            odir = self.data.dir_of.get(outer)
            # (a) a compiled source of the outer candidate includes a header of this one and uses its identifiers
            incs = [e for e in cv.by_type.get("INCLUDE", []) if e.origin == outer and e.positive and e.scope == "product"]
            hits = [e for e in cv.by_type.get("API_HIT", []) if e.origin == outer and e.positive and e.scope == "product"]
            for config in self.ship:
                ok_incs = [e for e in incs if is_enabled(e.status.get(config, DISABLED))]
                ok_hits = [e for e in hits if is_enabled(e.status.get(config, DISABLED))]
                if ok_incs and header_only:
                    return outer, "include", ok_incs[0], [c for c in self.ship if any(
                        is_enabled(e.status.get(c, DISABLED)) for e in incs)]
                if ok_incs and self._usage_by_identifier(ok_hits):
                    return outer, "api", ok_hits[0] if ok_hits else ok_incs[0], [c for c in self.ship if any(
                        is_enabled(e.status.get(c, DISABLED)) for e in incs)]
            if not odir:
                continue
            # (b) a target of the outer build lists this candidate's sources
            for ev in cv.by_type.get("COMPILE_LIST", []):
                if ev.idx is None or ev.scope != "product" or not within(self.build.tdir[ev.idx], odir):
                    continue
                if STRENGTH_RANK.get(str(ev.d.get("strength")), 0) < STRENGTH_RANK["medium"]:
                    continue
                cfgs = [c for c in self.ship if is_enabled(ev.status.get(c, DISABLED))]
                if cfgs:
                    return outer, "compile", ev, cfgs
            # (c) a build file inside the outer candidate, consumed by the product, links or builds this one
            for ev in cv.of("LINK_REF", "SUBDIR_BUILD", "FIND_PACKAGE"):
                path = str(ev.d.get("path") or "")
                if ev.scope != "product" or not within(path, odir) or within(path, self.data.dir_of.get(cand["id"])):
                    continue
                cfgs = [c for c in self.ship if is_enabled(ev.status.get(c, DISABLED))]
                if cfgs:
                    return outer, "link", ev, cfgs
        return None

    # ================================================================== derived records
    def _make_record(self, rtype: str, cid: str, *, path: Optional[str], line: Optional[int], symbol: str,
                     detail: str, value: Any = None, **kw: Any) -> Dict[str, Any]:
        rec = model.new_evidence(id=ids.evidence_id("u", self.repo, rtype, path, line, symbol, cid), repo=self.repo,
                                 type=rtype, candidate=cid, path=path, line=line, symbol=symbol or None,
                                 detail=detail[:model.DETAIL_MAX], value=value, **kw)
        self.new_records.append(rec)
        return rec

    def _primary_build_file(self) -> Optional[str]:
        systems = self.data.inventory.get("build_systems") or {}
        for key in ("cmake", "meson", "autotools", "make", "bazel"):
            files = systems.get(key) or []
            if files:
                return str(sorted(files, key=lambda p: (p.count("/"), p))[0])
        return None

    def _absence(self, cv: CandView, verdict: Dict[str, Any]) -> None:
        if verdict["class"] in ("USED", "FIRST_PARTY", "UNANALYZED"):
            return
        name = cv.cand["name"]
        sources_cov = "all_first_party_sources" if self.coverage["sources"] in ("complete", "assumed") else "partial"
        build_cov = "all_build_files" if self.coverage["build"] == "complete" else "partial"

        def accepted(ev: Ev) -> bool:
            return any(is_enabled(ev.status.get(c, DISABLED)) for c in self.ship)

        product = [e for e in cv.evs if e.scope == "product" and e.origin is None]
        checks = [
            ("build_refs", build_cov,
             not [e for e in product if e.type in BUILD_REF_TYPES and e.positive and accepted(e)],
             "no enabled product build file references %s (%s)" % (name, build_cov), self._primary_build_file()),
            ("include_scan", sources_cov,
             not [e for e in product if e.type == "INCLUDE" and e.positive and accepted(e)],
             "no enabled product source includes a header of %s (%s)" % (name, sources_cov), None),
            ("api_scan", sources_cov,
             not [e for e in product if e.type == "API_HIT" and e.positive and accepted(e)],
             "no enabled product source uses an identifier of %s (%s)" % (name, sources_cov), None)]
        for check, coverage, absent, detail, path in checks:
            if not absent:
                continue
            rec = self._make_record("ABSENCE", cv.id, path=path, line=None, symbol=check, detail=detail, check=check,
                                    coverage=coverage, scope="product")
            verdict["negative"].append({"check": check, "coverage": coverage, "evidence_id": rec["id"]})
            cv.evs.append(Ev(rec, {c: ENABLED for c in self.all_configs}, [], "product", False))

    def _condition_record(self, cv: CandView) -> None:
        positives = [e for e in cv.pos if e.scope == "product"] or list(cv.pos)
        conditional = [e for e in positives if e.conditional]
        if not conditional:
            return
        enabled, disabled, unknown, terms = [], [], [], set()
        strict = self.uses(cv, is_enabled, config_list=self.all_configs)
        loose = self.uses(cv, lambda s: s != DISABLED, config_list=self.all_configs)
        for config in self.all_configs:
            if any(self.per_config_flags(strict, config).values()):
                value = ENABLED
            elif any(self.per_config_flags(loose, config).values()):
                value = UNKNOWN
            else:
                value = any_of([e.status.get(config, DISABLED) for e in positives])
            if is_enabled(value):
                enabled.append(config)
            elif value == UNKNOWN:
                unknown.append(config)
            else:
                disabled.append(config)
        for ev in positives:
            terms.update(ev.terms)
        first = conditional[0]
        value = {"enabled_in": enabled, "disabled_in": disabled, "unknown_in": unknown, "platform": sorted(terms)}
        rec = self._make_record("CONDITION", cv.id, path=first.d.get("path"), line=first.d.get("line"), symbol="",
                                detail=("enabled in %s; disabled in %s; unknown in %s" % (
                                    ", ".join(enabled) or "none", ", ".join(disabled) or "none",
                                    ", ".join(unknown) or "none")), value=value, scope="product")
        cv.evs.append(Ev(rec, {c: ENABLED for c in self.all_configs}, [], "product", False))

    def _scope_record(self, cv: CandView, verdict: Dict[str, Any]) -> None:
        other = [e for e in cv.pos if e.scope != "product"]
        if not other:
            return
        scopes = sorted({e.scope for e in other})
        for scope in scopes:
            group = [e for e in other if e.scope == scope]
            first = group[0]
            why = "%d positive record(s) lie in %s paths or %s targets" % (len(group), scope, scope)
            rec = self._make_record("TEST_SCOPE", cv.id, path=first.d.get("path"), line=first.d.get("line"), symbol=scope,
                                    detail=why, value={"scope": scope, "why": why}, scope=scope)
            cv.evs.append(Ev(rec, {c: ENABLED for c in self.all_configs}, [], scope, False))

    # ================================================================== run
    def run(self) -> RuleResult:
        self._build_views()
        for cid in sorted(self.views):
            self.verdicts[cid] = self.decide(self.views[cid])
        self.transitive()
        for cid in sorted(self.views):
            cv = self.views[cid]
            verdict = self.verdicts[cid]
            self._condition_record(cv)
            self._scope_record(cv, verdict)
            self._absence(cv, verdict)
            verdict["evidence_ids"] = sorted({e.d["id"] for e in cv.evs} | set(cv.cand.get("evidence_ids") or []))
            verdict["negative"].sort(key=lambda n: (n["check"], n["evidence_id"]))
            if verdict["reason_code"] and verdict["reason_code"].startswith("REVIEW_") and not verdict["review_codes"]:
                verdict["review_codes"] = [verdict["reason_code"]]
        result = RuleResult()
        result.verdicts = [self.verdicts[cid] for cid in sorted(self.verdicts)]
        result.records = list(self.new_records)
        result.coverage = dict(self.coverage)
        result.blindspots = self._blindspots()
        return result

    def _blindspots(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        def add(code: str, message: str, loc: Optional[str], cand: Optional[str]) -> None:
            out.append({"code": code, "message": message[:200], "loc": loc, "candidate": cand})

        for cid in sorted(self.verdicts):
            verdict = self.verdicts[cid]
            if verdict["reason_code"] == "REVIEW_CONDITION_UNKNOWN":
                cv = self.views[cid]
                first = next((e for e in cv.pos if any(v == UNKNOWN for v in e.status.values())), None)
                loc = None
                if first is not None and first.d.get("path"):
                    loc = str(first.d["path"]) + (":%d" % first.d["line"] if first.d.get("line") else "")
                add("CONDITION_UNKNOWN", "%s: all use sits behind conditions that cannot be evaluated statically"
                    % cv.cand["name"], loc, cid)
        if self.scan.assumed:
            add("SOURCES_ASSUMED", "The build names no sources, so every product-scope first-party source is assumed "
                "compiled", None, None)
        if self.scan.unresolved:
            heads = sorted({h for _, _, h in self.scan.unresolved})[:3]
            add("UNRESOLVED_INCLUDES", "%d includes resolved to neither a file nor a known library (for example %s)"
                % (len(self.scan.unresolved), ", ".join(heads)), None, None)
        if self.scan.unreadable:
            add("COVERAGE_PARTIAL", "%d first-party source(s) could not be scanned (symlink, over 2 MiB or unreadable)"
                % len(self.scan.unreadable), sorted(self.scan.unreadable)[0], None)
        out.sort(key=lambda b: (b["code"], b["loc"] or "", b["candidate"] or ""))
        return out
