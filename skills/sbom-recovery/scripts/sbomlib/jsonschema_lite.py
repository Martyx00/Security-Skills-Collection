"""A small JSON Schema interpreter for the vendored SPDX schemas (contract section 3.12).

Supported validation keywords: ``type``, ``properties``, ``required``, ``additionalProperties``, ``enum``, ``items``,
``minItems`` and ``pattern``. The annotation keywords ``$schema``, ``$id``, ``$comment``, ``title``, ``description`` and
``deprecated`` are ignored. Any other keyword is reported as an error: a schema this module cannot interpret must never
validate a document silently.

``validate(instance, schema)`` returns the list of problems, each prefixed with the JSON pointer (RFC 6901) of the
offending value; an empty list means the instance is valid. The traversal order is deterministic.

Notes on the interpretation:

* ``type`` accepts a name or a list of names (``object``, ``array``, ``string``, ``integer``, ``number``, ``boolean``,
  ``null``). A Python ``bool`` is never an ``integer`` or a ``number``; an ``integer`` is a ``float`` with no fraction.
* ``enum`` compares by value and type (``1`` does not equal ``True``).
* ``pattern`` is an unanchored search (as in JSON Schema); a trailing ``$`` means the end of the string, not "before a
  final newline" (Python's meaning), so it is translated to ``\\Z``.
* ``items`` is a schema applied to every element; the list form is not supported (reported as an error).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

ANNOTATION_KEYWORDS = ("$schema", "$id", "$comment", "title", "description", "deprecated")
VALIDATION_KEYWORDS = ("type", "properties", "required", "additionalProperties", "enum", "items", "minItems", "pattern")
TYPE_NAMES = ("object", "array", "string", "integer", "number", "boolean", "null")

_PATTERN_CACHE: Dict[str, "re.Pattern[str]"] = {}


def _escape_pointer(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _join(pointer: str, token: Any) -> str:
    return pointer + "/" + _escape_pointer(str(token))


def _show(pointer: str) -> str:
    return pointer if pointer else "/"


def _type_ok(value: Any, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "integer":
        if isinstance(value, bool):
            return False
        return isinstance(value, int) or (isinstance(value, float) and value.is_integer())
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _json_equal(a: Any, b: Any) -> bool:
    """Equality by JSON value: ``True`` is not ``1``, ``1`` equals ``1.0``."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    return type(a) == type(b) and a == b


def _compile(pattern: str) -> "re.Pattern[str]":
    compiled = _PATTERN_CACHE.get(pattern)
    if compiled is None:
        text = pattern
        if text.endswith("$") and not text.endswith("\\$"):
            text = text[:-1] + "\\Z"
        compiled = re.compile(text)
        _PATTERN_CACHE[pattern] = compiled
    return compiled


def _describe(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if value is None:
        return "null"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return type(value).__name__


def check_schema(schema: Any, pointer: str = "") -> List[str]:
    """Problems of the schema itself: unsupported keywords, malformed keyword values. Empty for a usable schema."""
    problems: List[str] = []
    if not isinstance(schema, dict):
        return ["%s: a schema must be an object" % _show(pointer)]
    for keyword in schema:
        if keyword in ANNOTATION_KEYWORDS:
            continue
        if keyword not in VALIDATION_KEYWORDS:
            problems.append("%s: unsupported schema keyword %r" % (_show(pointer), keyword))
    if "type" in schema:
        wanted = schema["type"]
        names = wanted if isinstance(wanted, list) else [wanted]
        if not names or any(n not in TYPE_NAMES for n in names):
            problems.append("%s: unsupported type %r" % (_show(pointer), wanted))
    if "properties" in schema:
        props = schema["properties"]
        if not isinstance(props, dict):
            problems.append("%s: properties must be an object" % _show(pointer))
        else:
            for name, sub in props.items():
                problems.extend(check_schema(sub, _join(_join(pointer, "properties"), name)))
    if "required" in schema and not (isinstance(schema["required"], list)
                                     and all(isinstance(n, str) for n in schema["required"])):
        problems.append("%s: required must be a list of names" % _show(pointer))
    if "additionalProperties" in schema:
        extra = schema["additionalProperties"]
        if isinstance(extra, dict):
            problems.extend(check_schema(extra, _join(pointer, "additionalProperties")))
        elif not isinstance(extra, bool):
            problems.append("%s: additionalProperties must be a boolean or a schema" % _show(pointer))
    if "enum" in schema and not isinstance(schema["enum"], list):
        problems.append("%s: enum must be a list" % _show(pointer))
    if "items" in schema:
        if isinstance(schema["items"], dict):
            problems.extend(check_schema(schema["items"], _join(pointer, "items")))
        else:
            problems.append("%s: only a single items schema is supported" % _show(pointer))
    if "minItems" in schema and (not isinstance(schema["minItems"], int) or isinstance(schema["minItems"], bool)
                                 or schema["minItems"] < 0):
        problems.append("%s: minItems must be a non-negative integer" % _show(pointer))
    if "pattern" in schema:
        if not isinstance(schema["pattern"], str):
            problems.append("%s: pattern must be a string" % _show(pointer))
        else:
            try:
                _compile(schema["pattern"])
            except re.error as exc:
                problems.append("%s: pattern %r does not compile: %s" % (_show(pointer), schema["pattern"], exc))
    return problems


def _validate(instance: Any, schema: Dict[str, Any], pointer: str, out: List[str]) -> None:
    for keyword in schema:
        if keyword not in ANNOTATION_KEYWORDS and keyword not in VALIDATION_KEYWORDS:
            out.append("%s: unsupported schema keyword %r" % (_show(pointer), keyword))
    if "type" in schema:
        wanted = schema["type"]
        names = wanted if isinstance(wanted, list) else [wanted]
        if not any(_type_ok(instance, n) for n in names if isinstance(n, str)):
            out.append("%s: expected %s, found %s" % (_show(pointer), " or ".join(str(n) for n in names), _describe(instance)))
            return                                           # the other keywords would only add noise
    if "enum" in schema and isinstance(schema["enum"], list):
        if not any(_json_equal(instance, option) for option in schema["enum"]):
            shown = ", ".join(repr(o) for o in schema["enum"][:8]) + (", ..." if len(schema["enum"]) > 8 else "")
            out.append("%s: %r is not one of %s" % (_show(pointer), instance, shown))
    if "pattern" in schema and isinstance(instance, str) and isinstance(schema["pattern"], str):
        try:
            matched = _compile(schema["pattern"]).search(instance) is not None
        except re.error as exc:
            out.append("%s: pattern %r does not compile: %s" % (_show(pointer), schema["pattern"], exc))
            matched = True
        if not matched:
            out.append("%s: %r does not match pattern %s" % (_show(pointer), instance, schema["pattern"]))
    if isinstance(instance, dict):
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else []
        for name in required:
            if name not in instance:
                out.append("%s: missing required property %r" % (_show(pointer), name))
        for name in props:
            if name in instance and isinstance(props[name], dict):
                _validate(instance[name], props[name], _join(pointer, name), out)
        if "additionalProperties" in schema:
            extra = schema["additionalProperties"]
            for name in sorted(k for k in instance if k not in props):
                if extra is False:
                    out.append("%s: additional property %r is not allowed" % (_show(pointer), name))
                elif isinstance(extra, dict):
                    _validate(instance[name], extra, _join(pointer, name), out)
    if isinstance(instance, list):
        if "minItems" in schema and isinstance(schema["minItems"], int) and len(instance) < schema["minItems"]:
            out.append("%s: has %d item(s), at least %d required" % (_show(pointer), len(instance), schema["minItems"]))
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(instance):
                _validate(item, schema["items"], _join(pointer, index), out)
        elif "items" in schema:
            out.append("%s: only a single items schema is supported" % _show(pointer))


def validate(instance: Any, schema: Dict[str, Any]) -> List[str]:
    """Problems of ``instance`` against ``schema`` (see the module docstring); ``[]`` when valid."""
    out: List[str] = []
    if not isinstance(schema, dict):
        return ["/: the schema must be an object"]
    _validate(instance, schema, "", out)
    return out


def first_error(instance: Any, schema: Dict[str, Any]) -> Optional[str]:
    """The first problem or ``None``."""
    problems = validate(instance, schema)
    return problems[0] if problems else None
