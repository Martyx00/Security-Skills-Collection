#!/usr/bin/env python3
"""cvss31.py - CVSS v3.1 base score, with the arithmetic written out for a finding file.

    python3 -I -B <skill folder>/scripts/cvss31.py CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    python3 -I -B <skill folder>/scripts/cvss31.py --json <vector>

Prints the weight of every metric, the Impact Sub-Score, Impact, Exploitability and
Base Score, each as the expression that produced it, so the finding can carry the
arithmetic and anyone can re-run this command on the vector to check it. The
constants, the scope-dependent Privileges Required weights and Roundup are those of
the FIRST CVSS v3.1 specification, section 7.1 and Appendix A. Only the base metrics
are accepted: a temporal or environmental metric, a v3.0 prefix or a repeated metric
is refused rather than ignored, so a score can never silently differ from its vector.

Exit status: 0 scored, 2 the vector is not a CVSS v3.1 base vector. Standard library
only; Python 3.9 and newer. It reads nothing and writes nothing but its output.
"""

import argparse
import json
import math
import sys

PREFIX = "CVSS:3.1"
ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": None,  # depends on Scope, see pr_weight
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": None, "C": None},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_VALUES = ("N", "L", "H")
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
BANDS = ((0.0, 0.0, "None"), (0.1, 3.9, "Low"), (4.0, 6.9, "Medium"), (7.0, 8.9, "High"), (9.0, 10.0, "Critical"))


class VectorError(ValueError):
    pass


def roundup(value):
    """Roundup of the v3.1 specification, Appendix A: the smallest number with one
    decimal place that is equal to or higher than its input, computed on integers so
    that floating-point noise (4.000000000000001) does not round up a whole step."""
    whole = int(math.floor(value * 100000 + 0.5))
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def parse(vector):
    """Return {metric: value} for a CVSS v3.1 base vector, or raise VectorError."""
    text = vector.strip()
    parts = text.split("/")
    if not parts or parts[0] != PREFIX:
        head = parts[0] if parts else ""
        if head.upper().startswith("CVSS:3.0"):
            raise VectorError("a CVSS v3.0 vector: v3.0 rounds differently; rescore it as CVSS:3.1 from the metric definitions")
        if head.upper().startswith("CVSS:4"):
            raise VectorError("a CVSS v4.0 vector: this calculator is v3.1 only; use FIRST's v4.0 calculator and name it")
        raise VectorError("the vector must start with %s/" % PREFIX)
    metrics = {}
    for part in parts[1:]:
        if ":" not in part:
            raise VectorError("%r is not METRIC:VALUE" % part)
        name, value = part.split(":", 1)
        if name not in VALUES:
            raise VectorError("%s is not a base metric; only the base score is computed (no temporal or environmental metric)" % name)
        if name in metrics:
            raise VectorError("%s appears twice" % name)
        allowed = PR_VALUES if name == "PR" else tuple(VALUES[name])
        if value not in allowed:
            raise VectorError("%s:%s is not a value of %s (allowed: %s)" % (name, value, name, ", ".join(allowed)))
        metrics[name] = value
    missing = [name for name in ORDER if name not in metrics]
    if missing:
        raise VectorError("missing base metric(s): %s" % ", ".join(missing))
    return metrics


def pr_weight(pr, scope):
    return (PR_CHANGED if scope == "C" else PR_UNCHANGED)[pr]


def severity(score):
    for low, high, name in BANDS:
        if low <= score <= high:
            return name, low, high
    raise ValueError("score %r outside 0.0-10.0" % score)


def score(vector):
    """Score a vector. Returns a dict with every intermediate value and the lines of
    arithmetic; raises VectorError for anything that is not a v3.1 base vector."""
    m = parse(vector)
    changed = m["S"] == "C"
    w = {
        "AV": VALUES["AV"][m["AV"]],
        "AC": VALUES["AC"][m["AC"]],
        "PR": pr_weight(m["PR"], m["S"]),
        "UI": VALUES["UI"][m["UI"]],
        "C": VALUES["C"][m["C"]],
        "I": VALUES["I"][m["I"]],
        "A": VALUES["A"][m["A"]],
    }
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * w["AV"] * w["AC"] * w["PR"] * w["UI"]
    if impact <= 0:
        inner, base = 0.0, 0.0
    elif changed:
        inner = min(1.08 * (impact + exploitability), 10)
        base = roundup(inner)
    else:
        inner = min(impact + exploitability, 10)
        base = roundup(inner)
    band, low, high = severity(base)
    canonical = PREFIX + "/" + "/".join("%s:%s" % (k, m[k]) for k in ORDER)

    def f(x):
        return "%.6f" % x

    lines = [
        canonical,
        "Weights: AV:%s=%s AC:%s=%s PR:%s=%s (scope %s) UI:%s=%s C:%s=%s I:%s=%s A:%s=%s" % (
            m["AV"], w["AV"], m["AC"], w["AC"], m["PR"], w["PR"], "changed" if changed else "unchanged",
            m["UI"], w["UI"], m["C"], w["C"], m["I"], w["I"], m["A"], w["A"]),
        "ISS = 1 - (1-%s)*(1-%s)*(1-%s) = %s" % (w["C"], w["I"], w["A"], f(iss)),
    ]
    if changed:
        lines.append("Impact = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15 = %s" % f(impact))
    else:
        lines.append("Impact = 6.42*ISS = %s" % f(impact))
    lines.append("Exploitability = 8.22*%s*%s*%s*%s = %s" % (w["AV"], w["AC"], w["PR"], w["UI"], f(exploitability)))
    if impact <= 0:
        lines.append("Base = 0.0 (Impact <= 0)")
    elif changed:
        lines.append("Base = Roundup(min(1.08*(Impact+Exploitability), 10)) = Roundup(%s) = %.1f" % (f(inner), base))
    else:
        lines.append("Base = Roundup(min(Impact+Exploitability, 10)) = Roundup(%s) = %.1f" % (f(inner), base))
    lines.append("Severity: %s (%.1f-%.1f)" % (band, low, high))
    lines.append("Computed with scripts/cvss31.py (FIRST CVSS v3.1 specification, section 7.1 and Appendix A)")
    return {
        "vector": canonical,
        "metrics": m,
        "weights": w,
        "iss": iss,
        "impact": impact,
        "exploitability": exploitability,
        "base": base,
        "severity": band,
        "arithmetic": lines,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="CVSS v3.1 base score with its arithmetic.")
    parser.add_argument("vector", help="a CVSS v3.1 base vector, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)
    try:
        result = score(args.vector)
    except VectorError as exc:
        print("cvss31: refused: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("\n".join(result["arithmetic"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
