"""Shipping configurations and condition evaluation (contract sections 6.10 and D20).

Pure functions, no I/O:

* ``shipping_set(buildmodel)``      the configurations that decide usage;
* ``variables_for(buildmodel, c)``  the CMake variable table of one configuration;
* ``evaluate(condition, vars)``     a buildmodel condition (section 4.7) -> one of ``model.CONDITION_VALUES``;
* ``guard_value(guards, c, ctx)``   a preprocessor guard stack -> (value, platform terms);
* ``macro_context(...)``            the ``ctx_macros`` argument of ``guard_value`` for one source file.

A value is one of ``enabled`` (certainly active), ``disabled`` (certainly inactive in this configuration),
``unknown`` (cannot be told statically) and ``platform`` (active on some platform; counts as enabled, D20).
Conjunction order: disabled > unknown > platform > enabled.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from sbomlib import model

ENABLED, DISABLED, UNKNOWN, PLATFORM = "enabled", "disabled", "unknown", "platform"

_PLATFORM_MACROS = frozenset(model.PLATFORM_MACROS)
_PLATFORM_VARS = frozenset(model.CMAKE_PLATFORM_VARS)
_GENERATED_NAME_RE = re.compile(model.GENERATED_NAME_RE)

# Variables a user normally supplies at configure time: when nothing in the parsed build files, presets or cache
# assigns one of them its value is unknown, not CMake's "undefined is false" (stricter reading of section 6.10).
USER_SUPPLIED_VARS = frozenset(("CMAKE_BUILD_TYPE", "CMAKE_CONFIGURATION_TYPES", "CMAKE_TOOLCHAIN_FILE",
                                "CMAKE_PREFIX_PATH", "CMAKE_MODULE_PATH", "CMAKE_INSTALL_PREFIX"))

_NON_SHIPPING_WORDS = frozenset(("debug", "test", "ci", "asan", "ubsan", "tsan", "msan", "coverage", "cov", "fuzz"))
_NAME_TOKEN_RE = re.compile(r"[-_.]+")
_RELEASE_TYPES = frozenset(("release", "relwithdebinfo", "minsizerel"))

_FALSE_CONSTANTS = frozenset(("0", "OFF", "NO", "FALSE", "N", "IGNORE", "NOTFOUND", ""))


def combine(values: Iterable[str]) -> str:
    """Conjunction of condition values: disabled > unknown > platform > enabled (empty -> enabled)."""
    seen = set(values)
    if DISABLED in seen:
        return DISABLED
    if UNKNOWN in seen:
        return UNKNOWN
    if PLATFORM in seen:
        return PLATFORM
    return ENABLED


def any_of(values: Iterable[str]) -> str:
    """Disjunction over alternatives: enabled > platform > unknown > disabled (empty -> disabled)."""
    seen = set(values)
    if ENABLED in seen:
        return ENABLED
    if PLATFORM in seen:
        return PLATFORM
    if UNKNOWN in seen:
        return UNKNOWN
    return DISABLED


def is_enabled(value: str) -> bool:
    """``platform`` counts as enabled in every shipping configuration (D20)."""
    return value in (ENABLED, PLATFORM)


# ------------------------------------------------------------------------------------------------ shipping set

def _name_tokens(name: str) -> List[str]:
    return [t for t in _NAME_TOKEN_RE.split(name.lower()) if t]


def _name_is_non_shipping(name: str) -> bool:
    for token in _name_tokens(name):
        if token in _NON_SHIPPING_WORDS or token.startswith("sanitiz"):
            return True
        if token.endswith("s") and token[:-1] in _NON_SHIPPING_WORDS:      # "tests", "debugs"
            return True
    return False


def _build_type_of(config: Mapping[str, Any]) -> Optional[str]:
    cache = config.get("cache") or {}
    value = cache.get("CMAKE_BUILD_TYPE")
    if isinstance(value, dict):
        value = value.get("value")
    return str(value) if value is not None else None


def shipping_set(buildmodel: Dict[str, Any]) -> Dict[str, Any]:
    """``{"configs": [...], "all": [...], "assumed": bool, "reason": str}`` (section 6.10 "Configurations").

    Hidden presets never appear. Configurations named by release scripts win; otherwise debug, test, ci, sanitizer,
    coverage and fuzz configurations (by name token or ``CMAKE_BUILD_TYPE=Debug``) are dropped; an emptied set keeps every
    non-hidden configuration and sets ``assumed``. No declared configuration -> one implicit ``default``.
    """
    declared = [c for c in (buildmodel.get("configurations") or []) if not c.get("hidden")]
    if not declared:
        return {"configs": ["default"], "all": ["default"], "assumed": False,
                "reason": "no configurations declared; build-system defaults"}
    everything = [str(c["name"]) for c in declared]
    named = [str(c["name"]) for c in declared if c.get("named_by")]
    if named:
        return {"configs": named, "all": everything, "assumed": False,
                "reason": "configurations named by release scripts: " + ", ".join(named)}
    kept = []
    for config in declared:
        build_type = (_build_type_of(config) or "").lower()
        if build_type == "debug" or _name_is_non_shipping(str(config["name"])):
            continue
        kept.append(str(config["name"]))
    if kept:
        dropped = [n for n in everything if n not in kept]
        reason = "debug, test, ci, sanitizer, coverage and fuzz configurations dropped"
        if dropped:
            reason += " (" + ", ".join(dropped) + ")"
        else:
            reason = "no configuration needed dropping"
        return {"configs": kept, "all": everything, "assumed": False, "reason": reason}
    return {"configs": list(everything), "all": everything, "assumed": True,
            "reason": "every declared configuration looks like a debug, test or ci configuration; all are kept"}


# ------------------------------------------------------------------------------------------------ variables

def cmake_truthy(value: str) -> bool:
    """CMake ``if(<variable>)`` truthiness of an assigned value."""
    text = str(value).strip()
    upper = text.upper()
    if upper in _FALSE_CONSTANTS or upper.endswith("-NOTFOUND"):
        return False
    try:
        return float(text) != 0
    except ValueError:
        return True


def _as_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bool):
        return "ON" if value else "OFF"
    if isinstance(value, dict):
        value = value.get("value")
        return None if value is None else _as_text(value)
    return str(value)


def variables_for(buildmodel: Dict[str, Any], config: str,
                  inventory: Optional[Dict[str, Any]] = None) -> Dict[str, Optional[str]]:
    """Variable table of one configuration: a name maps to its value, or to ``None`` when the value is unknown.

    Precedence (low to high): option defaults and ``set(... CACHE ...)`` defaults; normal ``set()`` of the build files
    (``None`` for a conditional or non-literal assignment); the preset's resolved ``cacheVariables`` (an explicit user
    choice wins over a conditional default, so ``if(NOT CMAKE_BUILD_TYPE) set(...)`` cannot hide the preset value).
    ``<Pkg>_FOUND`` is true after a REQUIRED ``find_package`` and unknown otherwise. ``inventory`` adds the result
    variables of configure-time checks (``generated_macros.checks``) as unknown.
    """
    out: Dict[str, Optional[str]] = {}
    for option in buildmodel.get("options") or []:
        name = option.get("name")
        if name:
            default = _as_text(option.get("default"))
            out[name] = default if default is not None else "OFF"
    for name, value in (buildmodel.get("cache_defaults") or {}).items():
        out[name] = _as_text(value)
    for name, value in ((buildmodel.get("globals") or {}).get("variables") or {}).items():
        out[name] = _as_text(value)
    for package in buildmodel.get("packages") or []:
        pname = package.get("name")
        if not pname or package.get("kind") not in ("find_package", "pkg_check_modules", "pkg_check_ac",
                                                    "meson_dependency", "ac_check_lib"):
            continue
        for key in {pname + "_FOUND", str(pname).upper() + "_FOUND"}:
            if key not in out:
                out[key] = "TRUE" if package.get("required") and package.get("kind") == "find_package" else None
    if inventory:
        for check in (inventory.get("generated_macros") or {}).get("checks") or []:
            macro = check.get("macro") if isinstance(check, dict) else None
            if macro and "*" not in macro and macro not in out:
                out[macro] = None
    for entry in buildmodel.get("configurations") or []:
        if entry.get("name") == config:
            for name, value in (entry.get("cache") or {}).items():
                out[name] = _as_text(value)
            break
    return out


def _is_generator_capable(name: str) -> bool:
    return bool(_GENERATED_NAME_RE.fullmatch(name))


# ------------------------------------------------------------------------------------------------ conditions

def _clause_value(clause: Dict[str, Any], variables: Mapping[str, Optional[str]]) -> str:
    op = clause.get("op")
    if op == "unknown":
        return UNKNOWN
    name = clause.get("var")
    if not isinstance(name, str) or not name:
        return UNKNOWN
    if name in _PLATFORM_VARS:
        return PLATFORM
    if name in variables:
        value = variables[name]
        if value is None:
            return UNKNOWN
        if op == "truthy":
            return ENABLED if cmake_truthy(value) else DISABLED
        if op == "falsy":
            return DISABLED if cmake_truthy(value) else ENABLED
        if op == "eq":
            return ENABLED if value == str(clause.get("value")) else DISABLED
        if op == "ne":
            return DISABLED if value == str(clause.get("value")) else ENABLED
        return UNKNOWN
    # not assigned anywhere
    if _is_generator_capable(name) or name in USER_SUPPLIED_VARS:
        return UNKNOWN
    if op == "truthy":
        return DISABLED
    if op == "falsy":
        return ENABLED
    if op == "eq":
        return ENABLED if str(clause.get("value")) == "" else DISABLED
    if op == "ne":
        return DISABLED if str(clause.get("value")) == "" else ENABLED
    return UNKNOWN


def evaluate(condition: Optional[Dict[str, Any]], variables: Mapping[str, Optional[str]]) -> str:
    """Value of a buildmodel condition under ``variables`` (``None`` condition = unconditional = enabled)."""
    if not condition:
        return ENABLED
    clauses = condition.get("all") if isinstance(condition, dict) else None
    if not clauses:
        return ENABLED
    return combine(_clause_value(c, variables) for c in clauses if isinstance(c, dict))


def conjoin(*conditions: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Conjunction of buildmodel conditions (``None`` entries are unconditional)."""
    clauses: List[Dict[str, Any]] = []
    for cond in conditions:
        if cond and cond.get("all"):
            clauses.extend(cond["all"])
    return {"all": clauses} if clauses else None


def _clause_text(clause: Dict[str, Any]) -> str:
    op = clause.get("op")
    if op == "unknown":
        return "?"
    name = str(clause.get("var"))
    if op == "truthy":
        return name
    if op == "falsy":
        return "NOT " + name
    if op == "eq":
        return "%s==%s" % (name, clause.get("value"))
    if op == "ne":
        return "%s!=%s" % (name, clause.get("value"))
    return "?"


def condition_terms(condition: Optional[Dict[str, Any]]) -> List[str]:
    """Bare platform terms of a condition (``WIN32``, ``NOT WIN32``, ``CMAKE_SYSTEM_NAME==Linux``), in clause order."""
    terms: List[str] = []
    for clause in (condition or {}).get("all") or []:
        if isinstance(clause, dict) and clause.get("op") != "unknown" and clause.get("var") in _PLATFORM_VARS:
            text = _clause_text(clause)
            if text not in terms:
                terms.append(text)
    return terms


def render_condition(condition: Optional[Dict[str, Any]]) -> str:
    """Compact rendering of section 4.22: ``WITH_LZ4`` / ``NOT WITH_LZ4`` / ``CMAKE_BUILD_TYPE==Release`` /
    ``platform:WIN32``, ``&&``-joined, ``?`` for an unknown clause. Empty for an unconditional record."""
    parts: List[str] = []
    for clause in (condition or {}).get("all") or []:
        if not isinstance(clause, dict):
            continue
        text = _clause_text(clause)
        if clause.get("op") != "unknown" and clause.get("var") in _PLATFORM_VARS:
            text = "platform:" + text
        parts.append(text)
    return " && ".join(parts)


def render_terms(terms: Iterable[str]) -> Optional[str]:
    """``platform:A && platform:B`` for sorted unique bare terms, ``None`` when there are none (the verdict condition)."""
    unique = sorted(set(terms))
    if not unique:
        return None
    return " && ".join("platform:" + t for t in unique)


# ------------------------------------------------------------------------------------------------ preprocessor guards

_DEFINED_RE = re.compile(r"^defined\(\s*([A-Za-z_]\w*)\s*\)$")
_NOT_DEFINED_RE = re.compile(r"^!\s*defined\(\s*([A-Za-z_]\w*)\s*\)$")
_TOKEN_RE = re.compile(r"\s*(?:(0[xX][0-9a-fA-F]+[uUlL]*|\d+[uUlL]*)|([A-Za-z_]\w*)|(&&|\|\||==|!=|<=|>=|<<|>>|[-+*/%<>!~&|^?:(),]))")


def macro_context(buildmodel: Dict[str, Any], inventory: Dict[str, Any], variables: Mapping[str, Optional[str]],
                  *, definitions: Sequence[Dict[str, Any]] = (), closure_files: Iterable[str] = ()
                  ) -> Dict[str, Any]:
    """The ``ctx_macros`` argument of ``guard_value`` for one source file and one configuration.

    ``definitions`` are the build definitions that apply to the file (``{"name", "condition"}`` with the target condition
    already conjoined); ``closure_files`` are the file itself and the first-party files in its include closure, whose
    ``#define`` lines (``inventory["macro_defs"]``) decide steps 3 and 4 of section 6.10.
    """
    macro_defs = inventory.get("macro_defs") or {}
    defined: Set[str] = set()
    guarded: Set[str] = set()
    for path in closure_files:
        for entry in macro_defs.get(path) or []:
            macro = entry.get("macro")
            if not macro:
                continue
            (guarded if entry.get("guards") else defined).add(macro)
    generated = inventory.get("generated_macros") or {}
    names: Set[str] = set()
    have_pattern = False
    for template in generated.get("templates") or []:
        names.update(template.get("macros") or [])
    for check in generated.get("checks") or []:
        macro = check.get("macro") if isinstance(check, dict) else None
        if not macro:
            continue
        if "*" in macro:
            if macro.startswith("HAVE_"):
                have_pattern = True
        else:
            names.add(macro)
    return {"variables": variables, "definitions": list(definitions), "defined": defined, "guarded_defined": guarded,
            "generated": {"names": names, "have_pattern": have_pattern}}


def _variables_of(ctx_macros: Mapping[str, Any], config: str) -> Mapping[str, Optional[str]]:
    by_config = ctx_macros.get("variables_by_config") or {}
    if config in by_config:
        return by_config[config]
    return ctx_macros.get("variables") or {}


def macro_state(name: str, config: str, ctx_macros: Mapping[str, Any]) -> str:
    """Classification of ``defined(name)``: ``platform``, ``enabled``, ``disabled``, ``unknown`` or ``undefined``.

    ``undefined`` means no definition exists anywhere and the macro is not generator-capable: ``defined(X)`` is then
    ``unknown`` (never ``disabled``) while ``!defined(X)`` is ``enabled`` (section 6.10, steps 1 to 6).
    """
    if name in _PLATFORM_MACROS:
        return PLATFORM
    variables = _variables_of(ctx_macros, config)
    if name in ("NDEBUG", "_DEBUG"):
        build_type = variables.get("CMAKE_BUILD_TYPE")
        if build_type is None:
            return UNKNOWN
        release = build_type.lower() in _RELEASE_TYPES
        debug = build_type.lower() == "debug"
        if name == "NDEBUG":
            return ENABLED if release else (DISABLED if debug else UNKNOWN)
        return ENABLED if debug else (DISABLED if release else UNKNOWN)
    definitions = [d for d in ctx_macros.get("definitions") or [] if d.get("name") == name]
    unguarded_define = name in (ctx_macros.get("defined") or ())
    guarded_define = name in (ctx_macros.get("guarded_defined") or ())
    gen = ctx_macros.get("generated") or {}
    generated = name in (gen.get("names") or ()) or (bool(gen.get("have_pattern")) and name.startswith("HAVE_"))
    if unguarded_define or any(not (d.get("condition") or {}).get("all") for d in definitions):
        return ENABLED
    state: Optional[str] = None
    if definitions:
        values = [evaluate(d.get("condition"), variables) for d in definitions]
        if any(is_enabled(v) for v in values):
            return ENABLED
        state = UNKNOWN if UNKNOWN in values else DISABLED
        if state == DISABLED and guarded_define:
            state = UNKNOWN
    if generated:
        return UNKNOWN
    if state is not None:
        return state
    if guarded_define:
        return UNKNOWN
    return "undefined"


def _defined_value(state: str) -> str:
    return UNKNOWN if state == "undefined" else state


def _not_defined_value(state: str) -> str:
    if state == PLATFORM:
        return PLATFORM
    if state == ENABLED:
        return DISABLED
    if state in (DISABLED, "undefined"):
        return ENABLED
    return UNKNOWN


def _tokenize(raw: str) -> Optional[List[Tuple[str, str]]]:
    tokens: List[Tuple[str, str]] = []
    pos = 0
    text = raw.strip()
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match or match.end() == pos:
            return None
        if match.group(1) is not None:
            tokens.append(("int", match.group(1)))
        elif match.group(2) is not None:
            tokens.append(("id", match.group(2)))
        else:
            tokens.append(("op", match.group(3)))
        pos = match.end()
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return tokens


def _k_not(value: str) -> str:
    if value == ENABLED:
        return DISABLED
    if value == DISABLED:
        return ENABLED
    return value


def _k_and(values: Sequence[str]) -> str:
    return combine(values)


def _k_or(values: Sequence[str]) -> str:
    return any_of(values)


class _ExprParser:
    """Recursive descent over ``defined()`` forms joined by ``!``, ``&&``, ``||`` and parentheses (None on anything else)."""

    def __init__(self, tokens: List[Tuple[str, str]], config: str, ctx: Mapping[str, Any]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.config = config
        self.ctx = ctx
        self.terms: List[str] = []

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> Optional[Tuple[str, str]]:
        tok = self.peek()
        if tok is not None:
            self.pos += 1
        return tok

    def parse(self) -> Optional[str]:
        value = self.parse_or()
        if value is None or self.peek() is not None:
            return None
        return value

    def parse_or(self) -> Optional[str]:
        values = []
        first = self.parse_and()
        if first is None:
            return None
        values.append(first)
        while self.peek() == ("op", "||"):
            self.take()
            nxt = self.parse_and()
            if nxt is None:
                return None
            values.append(nxt)
        return _k_or(values)

    def parse_and(self) -> Optional[str]:
        values = []
        first = self.parse_not()
        if first is None:
            return None
        values.append(first)
        while self.peek() == ("op", "&&"):
            self.take()
            nxt = self.parse_not()
            if nxt is None:
                return None
            values.append(nxt)
        return _k_and(values)

    def parse_not(self) -> Optional[str]:
        tok = self.peek()
        if tok == ("op", "!"):
            self.take()
            nxt = self.peek()
            if nxt == ("id", "defined"):
                state = self.parse_defined_state()
                return None if state is None else _not_defined_value(state)
            inner = self.parse_not()
            return None if inner is None else _k_not(inner)
        if tok == ("op", "("):
            self.take()
            value = self.parse_or()
            if value is None or self.take() != ("op", ")"):
                return None
            return value
        if tok == ("id", "defined"):
            state = self.parse_defined_state()
            return None if state is None else _defined_value(state)
        return None

    def parse_defined_state(self) -> Optional[str]:
        self.take()                                   # 'defined'
        paren = self.peek() == ("op", "(")
        if paren:
            self.take()
        ident = self.take()
        if ident is None or ident[0] != "id":
            return None
        if paren and self.take() != ("op", ")"):
            return None
        state = macro_state(ident[1], self.config, self.ctx)
        if state == PLATFORM:
            self.terms.append(ident[1])
        return state


def _expr_guard(raw: str, config: str, ctx: Mapping[str, Any]) -> Tuple[str, List[str]]:
    tokens = _tokenize(raw)
    if tokens is None or not tokens:
        return UNKNOWN, []
    # a bare integer literal (possibly negated or parenthesised): #if 0 / #if 1
    stripped = [t for t in tokens if t not in (("op", "("), ("op", ")"))]
    if len(stripped) == 1 and stripped[0][0] == "int":
        try:
            number = int(stripped[0][1].rstrip("uUlL"), 0)
        except ValueError:
            return UNKNOWN, []
        return (ENABLED if number != 0 else DISABLED), []
    if len(stripped) == 2 and stripped[0] == ("op", "!") and stripped[1][0] == "int":
        try:
            number = int(stripped[1][1].rstrip("uUlL"), 0)
        except ValueError:
            return UNKNOWN, []
        return (DISABLED if number != 0 else ENABLED), []
    # contract rule: every identifier is a platform macro (defined(), !, &&, ||, comparisons, integer literals) -> platform
    idents = [text for kind, text in tokens if kind == "id" and text != "defined"]
    if idents and all(i in _PLATFORM_MACROS for i in idents):
        return PLATFORM, sorted(set(idents))
    if not idents:
        return UNKNOWN, []
    # defined() forms joined by ! && || and parentheses are evaluated three-valued; anything else is unknown
    parser = _ExprParser(tokens, config, ctx)
    value = parser.parse()
    if value is not None:
        return value, (sorted(set(parser.terms)) if value == PLATFORM else [])
    return UNKNOWN, []


def guard_value(guards: Sequence[str], config: str, ctx_macros: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Preprocessor guard stack -> ``(value, platform terms)`` for one configuration (section 6.10, D20).

    The stack is a conjunction. Guards are ``defined(X)``, ``!defined(X)`` and ``expr:<raw>``. Platform terms are bare
    (``_WIN32``, ``NOT __linux__``). ``ctx_macros`` comes from ``macro_context`` (it may carry ``variables_by_config``).
    """
    values: List[str] = []
    terms: List[str] = []
    for guard in guards or ():
        guard = guard.strip()
        match = _DEFINED_RE.match(guard)
        negated = False
        if match is None:
            match = _NOT_DEFINED_RE.match(guard)
            negated = match is not None
        if match is not None:
            name = match.group(1)
            state = macro_state(name, config, ctx_macros)
            if negated:
                values.append(_not_defined_value(state))
                if state == PLATFORM:
                    terms.append("NOT " + name)
            else:
                values.append(_defined_value(state))
                if state == PLATFORM:
                    terms.append(name)
            continue
        if guard.startswith("expr:"):
            value, found = _expr_guard(guard[5:], config, ctx_macros)
            values.append(value)
            terms.extend(found)
            continue
        values.append(UNKNOWN)
    unique: List[str] = []
    for term in terms:
        if term not in unique:
            unique.append(term)
    return combine(values), unique
