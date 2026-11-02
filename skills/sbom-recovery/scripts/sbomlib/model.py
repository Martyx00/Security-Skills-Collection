"""Enums, constants and record constructors shared by every work package (contract section 3.6).

Only WP-core edits this module. A work package that needs a new warning, blind-spot, evidence-type or reason
code lists it in its hand-off note and WP-core adds it here.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CLASSES = ("USED", "BUILD_ONLY", "TEST_ONLY", "DEV_ONLY", "OPTIONAL", "UNUSED_DEAD_COPY", "INCONCLUSIVE", "UNANALYZED",
           "FIRST_PARTY")
USAGE_LEVELS = ("vendored_compiled", "static", "dynamic", "header_only", "linked", "runtime_loaded", "toolchain_runtime",
                "co_flashed_image", "statically_wired", "declared", "present", "none")
VERIFICATION = ("proven", "declared", "unresolved")
REASON_CODES = ("DECLARED_NOT_USED", "PRESENT_NOT_BUILT", "TEST_ONLY", "BUILD_ONLY", "DEV_ONLY", "CONDITIONAL_DISABLED",
                "FIRST_PARTY", "UNINITIALIZED_SUBMODULE", "HUMAN_EXCLUDED", "NOT_VERIFIED",
                "REVIEW_INCLUDE_ONLY", "REVIEW_DLOPEN", "REVIEW_CONFLICT", "REVIEW_IDENTITY", "REVIEW_NO_BUILD_REF",
                "REVIEW_UNCOVERED_BUILD", "REVIEW_VERSION_CONFLICT", "REVIEW_CONDITION_UNKNOWN",
                "REVIEW_ADJUDICATION_FAILED", "REVIEW_WORKER_CLAIM")
DETECTED_AS = ("vendored", "single_file", "submodule", "system", "fetchcontent", "cpm", "external_project",
               "package_manager", "lockfile", "prebuilt", "toolchain_runtime", "co_flashed_image", "declared_unresolved")
VERSION_KINDS = ("release", "snapshot", "between_releases", "closest_modified", "constraint", "unpinned_ref", "none")
CONFIDENCE = ("high", "medium", "low", "none")
STRENGTHS = ("strong", "medium", "weak", "absence", "none")
SCOPES = ("product", "test", "dev", "build", "unknown")

EVIDENCE_TYPES = (
    "FILE_PRESENT", "VERSION_MACRO", "BANNER", "PROJECT_VERSION", "VERSION_FILE", "GIT_DESCRIBE", "GITLINK", "LOCK_PIN",
    "FETCH_PIN", "MANIFEST_DECL", "FIND_PACKAGE", "LINK_REF", "SUBDIR_BUILD", "COMPILE_LIST", "INCLUDE_DIR", "LINK_PROOF",
    "LINK_LINE", "DLOPEN", "CI_INSTALL", "DECLARED_ID", "PREBUILT", "TOOLCHAIN_RUNTIME", "BUILD_FILE_UNPARSED",
    "BUILD_REF_UNPARSED", "LICENSE_FILE", "INCLUDE", "API_HIT", "CONDITION", "TEST_SCOPE", "ABSENCE", "TRANSITIVE",
    "WORKER_CLAIM")

TECHNIQUES = ("source-code-analysis", "binary-analysis", "manifest-analysis", "ast-fingerprint", "hash-comparison",
              "instrumentation", "dynamic-analysis", "filename", "attestation", "other")    # CycloneDX 1.6 enum

# type -> (default strength, technique) as in the table of contract section 4.9. Types whose strength depends on the
# record (GIT_DESCRIBE exact tag / medium, FETCH_PIN tag / branch, API_HIT weight) default to the strongest value; the
# producer downgrades.
EVIDENCE_DEFAULTS = {
    "FILE_PRESENT": ("weak", "filename"),
    "VERSION_MACRO": ("strong", "source-code-analysis"),
    "BANNER": ("medium", "source-code-analysis"),
    "PROJECT_VERSION": ("strong", "manifest-analysis"),
    "VERSION_FILE": ("strong", "manifest-analysis"),
    "GIT_DESCRIBE": ("strong", "other"),
    "GITLINK": ("strong", "manifest-analysis"),
    "LOCK_PIN": ("strong", "manifest-analysis"),
    "FETCH_PIN": ("strong", "manifest-analysis"),
    "MANIFEST_DECL": ("medium", "manifest-analysis"),
    "FIND_PACKAGE": ("medium", "manifest-analysis"),
    "LINK_REF": ("medium", "manifest-analysis"),
    "SUBDIR_BUILD": ("medium", "manifest-analysis"),
    "COMPILE_LIST": ("strong", "manifest-analysis"),
    "INCLUDE_DIR": ("weak", "manifest-analysis"),
    "LINK_PROOF": ("strong", "binary-analysis"),
    "LINK_LINE": ("medium", "binary-analysis"),
    "DLOPEN": ("medium", "source-code-analysis"),
    "CI_INSTALL": ("weak", "manifest-analysis"),
    "DECLARED_ID": ("strong", "attestation"),
    "PREBUILT": ("medium", "hash-comparison"),
    "TOOLCHAIN_RUNTIME": ("medium", "manifest-analysis"),
    "BUILD_FILE_UNPARSED": ("none", "manifest-analysis"),
    "BUILD_REF_UNPARSED": ("weak", "manifest-analysis"),
    "LICENSE_FILE": ("none", "filename"),
    "INCLUDE": ("medium", "source-code-analysis"),
    "API_HIT": ("strong", "source-code-analysis"),
    "CONDITION": ("none", "source-code-analysis"),
    "TEST_SCOPE": ("none", "manifest-analysis"),
    "ABSENCE": ("absence", "source-code-analysis"),
    "TRANSITIVE": ("medium", "source-code-analysis"),
    "WORKER_CLAIM": ("weak", "other"),          # a worker reply's claim; "medium" only when the script verified its citations
}

REPO_STATUS = ("QUEUED", "DONE", "INCOMPLETE", "FAILED", "NOT ANALYZED")
REPO_PHASES = ("enumerate", "discover", "verify", "adjudicate", "worker", "emit")
REPO_PHASE_VALUES = ("pending", "done", "failed", "skipped")
UNIT_STATES = ("done", "failed", "partial", "pending")
NEXT_ACTIONS = ("run_again", "adjudicate", "stop_for_approval", "done", "error")
ADJUDICATE_KINDS = ("usage", "trace_build", "hint", "worker")
PHASES = ("enumerate", "discover", "verify", "adjudicate", "worker", "names", "approve", "cpe", "emit", "merge", "audit", "done")
STAGES = ("analyze", "judge", "propose", "lookup", "emit")
STAGE_VALUES = ("pending", "running", "done", "failed")
GATES = ("none", "awaiting_approval", "approved")
DRIVERS = ("none", "chat", "workflow")
SCOPE_VALUES = ("product", "all")
TIERS = ("high", "medium", "low", "none")
ROLES = ("primary", "also_emit", "cve_only", "never_emit")         # map roles; emitted roles add "override", "extra"
PAIR_SOURCES = ("override", "local", "declared", "alias", "index", "api", "manual")
CPE_NAME_SOURCES = ("dictionary", "constructed")
APPROVAL_EVIDENCE = ("tty", "agent-relayed")      # "hook" (a hook-bound human reply) exists only in the hardened variant
WARNING_TIERS = ("ACTION_REQUIRED", "INFORMATIONAL")
ANALYSIS_MODES = ("static", "static+cpp", "configured-sandbox", "built-sandbox")
USAGE_VALUES = ("static", "dynamic", "header_only", "runtime_loaded")   # verdict/component "usage" list items
VERSION_SOURCES = ("generic", "header_macro", "project_version", "version_file", "git_tag", "describe", "banner", "conan",
                   "vcpkg", "wrapdb", "hunter", "bcr", "fetchcontent_tag", "west", "idf", "bazel", "constraint", "none")
CONDITION_VALUES = ("enabled", "disabled", "unknown", "platform")        # result of verify.configs.evaluate (section 6.10, D20)
LOCATION_KINDS = ("dir", "file", "gitlink", "manifest", "system", "toolchain")
REF_KINDS = ("tag", "commit", "branch", "version", "url")
EVIDENCE_WEIGHTS = ("strong", "weak")
SUBMODULE_STATES = ("initialized", "different_commit", "conflict", "uninitialized")
PLATFORM_MACROS = ("_WIN32", "_WIN64", "WIN32", "_WINDOWS", "__CYGWIN__", "__MINGW32__", "__MINGW64__", "__linux__",
                   "__linux", "linux", "__gnu_linux__", "__unix__", "__unix", "unix", "__APPLE__", "__MACH__",
                   "TARGET_OS_IPHONE", "TARGET_OS_MAC", "__FreeBSD__", "__NetBSD__", "__OpenBSD__", "__DragonFly__",
                   "__sun", "__hpux", "_AIX", "__HAIKU__", "__ANDROID__", "__EMSCRIPTEN__", "__wasm__", "__ZEPHYR__",
                   "_MSC_VER", "__GNUC__", "__GNUC_MINOR__", "__clang__", "__INTEL_COMPILER", "__MINGW_GCC_VERSION",
                   "__ARMCC_VERSION", "__ICCARM__", "__TI_COMPILER_VERSION__", "__x86_64__", "__amd64__", "_M_X64",
                   "_M_AMD64", "__i386__", "_M_IX86", "__arm__", "_M_ARM", "__aarch64__", "_M_ARM64", "__riscv",
                   "__powerpc__", "__ppc64__", "__mips__", "__s390x__", "__BYTE_ORDER__", "__LP64__", "_LP64",
                   "__SIZEOF_POINTER__", "__cplusplus", "__STDC__", "__STDC_VERSION__", "__OBJC__")
CMAKE_PLATFORM_VARS = ("WIN32", "WINCE", "WINDOWS_PHONE", "WINDOWS_STORE", "APPLE", "IOS", "UNIX", "LINUX", "BSD",
                       "CYGWIN", "MINGW", "MSYS", "MSVC", "MSVC_VERSION", "ANDROID", "EMSCRIPTEN", "XCODE",
                       "CMAKE_SYSTEM_NAME", "CMAKE_SYSTEM_PROCESSOR", "CMAKE_SYSTEM_VERSION", "CMAKE_HOST_SYSTEM_NAME",
                       "CMAKE_HOST_SYSTEM_PROCESSOR", "CMAKE_HOST_WIN32", "CMAKE_HOST_UNIX", "CMAKE_HOST_APPLE",
                       "CMAKE_CROSSCOMPILING", "CMAKE_SIZEOF_VOID_P", "CMAKE_C_COMPILER_ID", "CMAKE_CXX_COMPILER_ID",
                       "CMAKE_C_COMPILER_VERSION", "CMAKE_CXX_COMPILER_VERSION", "CMAKE_GENERATOR",
                       "CMAKE_C_BYTE_ORDER", "CMAKE_CXX_BYTE_ORDER")
GENERATED_NAME_RE = r"(?:HAVE|USE|ENABLE|WITH|CONFIG)_\w+|\w+_FOUND"   # names configure-time checks typically produce
FIND_PACKAGE_TOOLS = ("Threads", "PkgConfig", "Git", "Doxygen", "Python", "Python2", "Python3", "PythonInterp",
                      "PythonLibs", "Perl", "BISON", "FLEX", "SWIG", "Sphinx", "Java", "Ruby", "Patch", "Subversion")
BLINDSPOT_CODES = ("UNPINNED_REF", "UNRESOLVED_INCLUDES", "COVERAGE_PARTIAL", "SOURCES_ASSUMED", "CONDITION_UNKNOWN",
                   "ADJUDICATION_CAPACITY", "ADJUDICATION_FAILED", "TRACE_UNCITED", "UNINITIALIZED_SUBMODULE",
                   "PREBUILT_UNIDENTIFIED", "DLOPEN_UNMAPPED", "BUILD_FILE_UNPARSED", "DIRTY_UNKNOWN", "WORKER_REPORTED")
WARNING_CODES = ("PARENT_AGENT_FILES", "APPROVAL_AGENT_RELAYED", "HEAD_MOVED_WHILE_PAUSED", "NVD_OFFLINE",
                 "NVD_API_ERRORS",
                 "SHIPPING_CONFIG_ASSUMED", "REPO_FAILED", "REPO_NOT_ANALYZED", "COVERAGE_PARTIAL", "ADJUDICATION_FAILED",
                 "HINTS_DROPPED", "DIRTY_TRUNCATED", "CTIME_UNRELIABLE", "PACK_NOT_RECORDED", "MODULE_MISSING",
                 "SUBMODULE_UNINITIALIZED", "SUBMODULE_MISMATCH", "SUBMODULE_CONFLICT", "DETACHED_HEAD",
                 "DIRTY_TRACKED", "DIRTY_UNKNOWN", "UNTRACKED_FILES", "SKIPPED_FOLDER", "NOT_ANALYZED",
                 "GIT_DIR_EXTERNAL", "INTEGRITY_VIOLATION", "VALIDATION_FAIL", "WORKER_FAILED", "WORKER_REJECTED",
                 "WORKER_DISAGREES", "RUN_FOLDER_CHANGED", "RUN_FOLDER_EXTRA_FILE", "RUN_FOLDER_REBASELINED",
                 "REPLY_NOTE")
# The codes enumerate puts into queue.json "checkout_warnings" (contract section 4.5).
CHECKOUT_WARNING_CODES = ("SUBMODULE_UNINITIALIZED", "SUBMODULE_MISMATCH", "SUBMODULE_CONFLICT", "DETACHED_HEAD",
                          "DIRTY_TRACKED", "DIRTY_UNKNOWN", "UNTRACKED_FILES", "SKIPPED_FOLDER", "NOT_ANALYZED",
                          "GIT_DIR_EXTERNAL")
NVD_NOTICE = "This product uses the NVD API but is not endorsed or certified by the NVD."
SPDX_CONTEXT = "SBOM Generation Context: Source"
# Said in every output (SPDX creation comment, report.md, summary): this is a plain skill install, so nothing but the script
# itself stops a repository from being written (the hardened variant had hooks; references/limitations.md lists the loss).
ENFORCEMENT_NOTE = "harness enforcement: none (plain skill install without hooks; see references/limitations.md)"

# Editable columns of review/cpe-lookup-names.csv (contract sections 4.13 and 5.3).
EDITABLE_COLUMNS = ("include", "include_in", "action", "search_name", "vendor_hint", "product_hint", "part_hint",
                    "cpe_override", "cpe_version_override", "cpe_update_override", "extra_vendor_products")

# Directory names whose children are treated as vendored third-party trees (contract section 3.9, inventory.py).
VENDORED_PARENT_DIRS = ("3rdparty", "dep", "deps", "thirdparty", "third-party", "third_party", "libs", "external",
                        "externals", "vendor", "vendored", "extern", "contrib")

ANALYSIS_MODE_REASON = "compiler and sandbox evidence are not implemented in this version"


@dataclass
class PhaseResult:
    done: bool = True                                         # False only for the checkpointing units of section 5.5
    outputs: Dict[str, str] = field(default_factory=dict)     # sbom-out-relative path -> sha256
    incomplete: List[str] = field(default_factory=list)       # reasons that make the repo INCOMPLETE
    warnings: List[Dict[str, Any]] = field(default_factory=list)
    repo_status: Optional[str] = None                         # per-repo units only: "NOT ANALYZED" (describe_repo) or None
    repo_reason: Optional[str] = None
    info: Dict[str, Any] = field(default_factory=dict)
    # Defined info keys (the driver persists them; no other key is read):
    #   "repos": [str]                  enumerate:scan, enumerated repo names in queue order -> run.json.repos entries
    #   "head": str                     enumerate:<repo> -> run.json.repos[r].head
    #   "adjudicate": {...}             adjudicate:* units and names:build: the block of section 5.7
    #   "review": {...}                 names:write: the write_review() dict -> run.json.review
    #   "nvd": {"source", "status"}     cpe:resolve -> run.json.nvd
    #   "errors": [str]                 emit:<repo> -> run.json.repos[r].emit_errors
    #   "audit": {...}                  audit:finalize: {"verdict", "validation", "report"}


@dataclass
class ApplyResult:
    ok: bool
    messages: List[str]
    applied: int = 0
    inconclusive: List[str] = field(default_factory=list)    # item ids forced to INCONCLUSIVE (attempt 2)
    notes: List[Dict[str, Any]] = field(default_factory=list)  # what the reply reader tolerated (replyread.note_records)


def warning(tier: str, code: str, message: str, repo: Optional[str] = None) -> Dict[str, Any]:
    """Build a warning dict; rejects a tier or code outside the enums."""
    if tier not in WARNING_TIERS:
        raise ValueError("unknown warning tier: %r" % (tier,))
    if code not in WARNING_CODES:
        raise ValueError("unknown warning code: %r" % (code,))
    return {"tier": tier, "code": code, "message": str(message), "repo": repo}


def _check_enum(name: str, value: Any, allowed: Any, *, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if value not in allowed:
        raise ValueError("%s: %r is not one of %s" % (name, value, ", ".join(str(a) for a in allowed)))


_EVIDENCE_KEYS = ("id", "repo", "type", "candidate", "strength", "path", "line", "symbol", "detail", "quote_sha256",
                  "object_store", "object", "value", "ref_kind", "condition", "guards", "scope", "target", "technique",
                  "weight", "check", "coverage")
_EVIDENCE_REQUIRED = ("id", "repo", "type")
DETAIL_MAX = 200


def new_evidence(**fields: Any) -> Dict[str, Any]:
    """Evidence record with the defaults of contract section 4.9; ValueError on an unknown key or enum value."""
    unknown = sorted(set(fields) - set(_EVIDENCE_KEYS))
    if unknown:
        raise ValueError("unknown evidence key(s): %s" % ", ".join(unknown))
    for key in _EVIDENCE_REQUIRED:
        if not fields.get(key):
            raise ValueError("evidence key %r is required" % key)
    etype = fields["type"]
    _check_enum("type", etype, EVIDENCE_TYPES)
    default_strength, default_technique = EVIDENCE_DEFAULTS[etype]
    weight = fields.get("weight")
    if etype == "API_HIT":
        if weight is None:
            raise ValueError("API_HIT evidence requires weight")
        default_strength = "strong" if weight == "strong" else "weak"
    if etype == "ABSENCE":
        if not fields.get("check") or not fields.get("coverage"):
            raise ValueError("ABSENCE evidence requires check and coverage")
    rec = {
        "id": fields["id"], "repo": fields["repo"], "type": etype,
        "candidate": fields.get("candidate"),
        "strength": fields.get("strength", default_strength),
        "path": fields.get("path"), "line": fields.get("line"),
        "symbol": fields.get("symbol"), "detail": fields.get("detail"),
        "quote_sha256": fields.get("quote_sha256"),
        "object_store": fields.get("object_store"), "object": fields.get("object"),
        "value": copy.deepcopy(fields.get("value")),
        "ref_kind": fields.get("ref_kind"),
        "condition": copy.deepcopy(fields.get("condition")),
        "guards": list(fields.get("guards") or []),
        "scope": fields.get("scope", "product"),
        "target": fields.get("target"),
        "technique": fields.get("technique", default_technique),
        "weight": weight, "check": fields.get("check"), "coverage": fields.get("coverage"),
    }
    _check_enum("strength", rec["strength"], STRENGTHS)
    _check_enum("scope", rec["scope"], SCOPES)
    _check_enum("technique", rec["technique"], TECHNIQUES)
    _check_enum("ref_kind", rec["ref_kind"], REF_KINDS, nullable=True)
    _check_enum("weight", rec["weight"], EVIDENCE_WEIGHTS, nullable=True)
    if rec["line"] is not None and not isinstance(rec["line"], int):
        raise ValueError("line must be an int or None")
    if isinstance(rec["detail"], str) and len(rec["detail"]) > DETAIL_MAX:
        rec["detail"] = rec["detail"][:DETAIL_MAX]
    return rec


def default_version() -> Dict[str, Any]:
    """The default ``version`` object of a candidate (contract section 4.8)."""
    return {"version": "NOASSERTION", "version_raw": None, "version_kind": "none", "version_source": "none",
            "cpe_version": None, "cpe_update": None, "evidence_ids": [], "conflict": False, "notes": [], "options": []}


_CANDIDATE_KEYS = ("id", "name", "norm_name", "map_entry", "detected_as", "location", "locations", "version",
                   "identity_options", "identity_confidence", "version_confidence", "upstream", "submodule", "fork_of",
                   "within", "first_party", "sha256", "license", "supplier", "declared_ids", "evidence_ids", "notes")
_CANDIDATE_REQUIRED = ("id", "name", "norm_name", "detected_as", "location")


def new_candidate(**fields: Any) -> Dict[str, Any]:
    """Candidate record with the defaults of contract section 4.8; ValueError on an unknown key or enum value."""
    unknown = sorted(set(fields) - set(_CANDIDATE_KEYS))
    if unknown:
        raise ValueError("unknown candidate key(s): %s" % ", ".join(unknown))
    for key in _CANDIDATE_REQUIRED:
        if not fields.get(key):
            raise ValueError("candidate key %r is required" % key)
    _check_enum("detected_as", fields["detected_as"], DETECTED_AS)
    loc = fields["location"]
    if not isinstance(loc, dict) or "kind" not in loc or "path" not in loc:
        raise ValueError("location must be an object with kind and path")
    _check_enum("location.kind", loc["kind"], LOCATION_KINDS)
    location = {"kind": loc["kind"], "path": loc["path"], "line": loc.get("line")}
    version = default_version()
    given = fields.get("version")
    if given is not None:
        if not isinstance(given, dict):
            raise ValueError("version must be an object")
        extra = sorted(set(given) - set(version))
        if extra:
            raise ValueError("unknown version key(s): %s" % ", ".join(extra))
        version.update(copy.deepcopy(given))
    _check_enum("version.version_kind", version["version_kind"], VERSION_KINDS)
    _check_enum("version.version_source", version["version_source"], VERSION_SOURCES)
    identity_options = fields.get("identity_options")
    if identity_options is None:
        identity_options = [{"name": fields["name"], "evidence_ids": []}]
    cand = {
        "id": fields["id"], "name": fields["name"], "norm_name": fields["norm_name"],
        "map_entry": fields.get("map_entry"), "detected_as": fields["detected_as"], "location": location,
        "locations": list(fields.get("locations") or []),
        "version": version,
        "identity_options": copy.deepcopy(identity_options),
        "identity_confidence": fields.get("identity_confidence", "low"),
        "version_confidence": fields.get("version_confidence", "none"),
        "upstream": dict({"url": None, "commit": None, "nearest_tag": None, "commits_since_tag": None},
                         **(fields.get("upstream") or {})),
        "submodule": copy.deepcopy(fields.get("submodule")),
        "fork_of": fields.get("fork_of"), "within": fields.get("within"),
        "first_party": bool(fields.get("first_party", False)),
        "sha256": fields.get("sha256"),
        "license": dict({"id": "NOASSERTION", "loc": None}, **(fields.get("license") or {})),
        "supplier": fields.get("supplier"),
        "declared_ids": list(fields.get("declared_ids") or []),
        "evidence_ids": list(fields.get("evidence_ids") or []),
        "notes": list(fields.get("notes") or []),
    }
    _check_enum("identity_confidence", cand["identity_confidence"], CONFIDENCE)
    _check_enum("version_confidence", cand["version_confidence"], CONFIDENCE)
    return cand
