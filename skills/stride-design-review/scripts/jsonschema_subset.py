#!/usr/bin/env python3
"""Dependency-free validator for the JSON Schema subset used by this package."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any


def _resolve(root: dict[str, Any], ref: str) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise ValueError(f"unsupported external $ref: {ref}")
    node: Any = root
    for part in ref[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def _type_ok(value: Any, expected: str) -> bool:
    checks = {
        "object": lambda: isinstance(value, dict),
        "array": lambda: isinstance(value, list),
        "string": lambda: isinstance(value, str),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "number": lambda: isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": lambda: isinstance(value, bool),
        "null": lambda: value is None,
    }
    return checks[expected]()


def validate(instance: Any, schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def walk(value: Any, rule: dict[str, Any], path: str, out: list[str]) -> None:
        if "$ref" in rule:
            walk(value, _resolve(schema, rule["$ref"]), path, out)
            return
        if "anyOf" in rule:
            candidates: list[list[str]] = []
            for candidate in rule["anyOf"]:
                candidate_errors: list[str] = []
                walk(value, candidate, path, candidate_errors)
                candidates.append(candidate_errors)
            if all(candidates):
                out.append(f"{path}: does not match any allowed shape")
            return
        if "not" in rule:
            forbidden_errors: list[str] = []
            walk(value, rule["not"], path, forbidden_errors)
            if not forbidden_errors:
                out.append(f"{path}: matches forbidden shape")
        if "const" in rule and value != rule["const"]:
            out.append(f"{path}: expected constant {rule['const']!r}")
        if "enum" in rule and value not in rule["enum"]:
            out.append(f"{path}: value {value!r} is outside closed enum")
        expected = rule.get("type")
        if expected:
            choices = expected if isinstance(expected, list) else [expected]
            if not any(_type_ok(value, item) for item in choices):
                out.append(f"{path}: expected type {'|'.join(choices)}")
                return
        if isinstance(value, dict):
            for key in rule.get("required", []):
                if key not in value:
                    out.append(f"{path}: missing required key {key!r}")
            properties = rule.get("properties", {})
            if rule.get("additionalProperties") is False:
                for key in value:
                    if key not in properties:
                        out.append(f"{path}: unexpected key {key!r}")
            for key, child in properties.items():
                if key in value:
                    walk(value[key], child, f"{path}.{key}", out)
        if isinstance(value, list):
            if len(value) < rule.get("minItems", 0):
                out.append(f"{path}: needs at least {rule['minItems']} items")
            if "maxItems" in rule and len(value) > rule["maxItems"]:
                out.append(f"{path}: allows at most {rule['maxItems']} items")
            if rule.get("uniqueItems"):
                seen: set[str] = set()
                for item in value:
                    marker = repr(item)
                    if marker in seen:
                        out.append(f"{path}: duplicate array item {item!r}")
                    seen.add(marker)
            if "items" in rule:
                for index, item in enumerate(value):
                    walk(item, rule["items"], f"{path}[{index}]", out)
        if isinstance(value, str):
            if len(value) < rule.get("minLength", 0):
                out.append(f"{path}: string is too short")
            if "pattern" in rule and re.search(rule["pattern"], value) is None:
                out.append(f"{path}: does not match {rule['pattern']!r}")
            if rule.get("format") == "date-time":
                try:
                    datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    out.append(f"{path}: invalid RFC3339 date-time")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in rule and value < rule["minimum"]:
                out.append(f"{path}: below minimum {rule['minimum']}")
            if "maximum" in rule and value > rule["maximum"]:
                out.append(f"{path}: above maximum {rule['maximum']}")
        for conditional in rule.get("allOf", []):
            condition_errors: list[str] = []
            walk(value, conditional.get("if", {}), path, condition_errors)
            branch = conditional.get("else" if condition_errors else "then")
            if branch:
                walk(value, branch, path, out)

    walk(instance, schema, "$", errors)
    return errors
