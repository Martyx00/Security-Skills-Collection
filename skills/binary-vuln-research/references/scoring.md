# Scoring (Phase 4)

## Which version

Score each RAISE in the version the programme's rules mandate, as the person named it at Gate A:
CVSS v3.1, CVSS v4.0, or the programme's own rating. If none was named, use v3.1 and say so. Never convert a score
from one version to another: rescore from the metric definitions of the version you report.

- **v3.1**: run `python3 -I -B <skill folder>/scripts/cvss31.py <vector>` and copy its output
  into the finding. It prints every weight, the Impact Sub-Score, Impact, Exploitability and
  the Base Score as the expressions that produced them, so the arithmetic is shown and anyone
  can re-run the command on the vector to check it. It accepts base vectors only and refuses
  anything else (a v3.0 or v4.0 prefix, a temporal or environmental metric, a repeated or
  missing metric) instead of ignoring it.
- **v4.0**: its score comes from a lookup of macro-vectors this skill does not ship, not from arithmetic you can show. Give the vector and ask the person for its score, or for their OK, in their own message, to open FIRST's v4.0 calculator for it; record which. Without that OK, never paste a vector into a web tool, and never fetch or run a reference implementation (offline by default; untrusted content never runs).
- **The programme's own rating**: quote the rule you applied, and the inputs you gave it.

## The lower bound

- The score is a conservative lower bound. Score impact from what the cited instructions do on the shipped build (what is written or read, how far, and with whose bytes), not from what a higher rung would show. Where the evidence supports more than one value of a metric, take the one that gives the lower score and name that metric as argued. A score goes down on measurement and never up on impression.
- The stated severity band is exactly what the vector computes, never above.
- Count each precondition once: either inside a metric (AV, AC, PR, UI, or AT in v4.0) or
  printed beside the score as an unscored precondition, never both. Say which, per
  precondition.
- Print every precondition next to the score, in the finding and in the summary.

## CVSS v3.1 base score, as `scripts/cvss31.py` computes it

From the FIRST CVSS v3.1 specification, section 7.1 and Appendix A.

| Metric | Values and weights |
|---|---|
| Attack Vector (AV) | N 0.85, A 0.62, L 0.55, P 0.2 |
| Attack Complexity (AC) | L 0.77, H 0.44 |
| Privileges Required (PR), Scope Unchanged | N 0.85, L 0.62, H 0.27 |
| Privileges Required (PR), Scope Changed | N 0.85, L 0.68, H 0.5 |
| User Interaction (UI) | N 0.85, R 0.62 |
| Confidentiality, Integrity, Availability (C, I, A) | H 0.56, L 0.22, N 0 |

```text
ISS            = 1 - (1 - C) * (1 - I) * (1 - A)
Impact         = 6.42 * ISS                                          Scope Unchanged
               = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02)^15      Scope Changed
Exploitability = 8.22 * AV * AC * PR * UI
Base           = 0                                                   if Impact <= 0
               = Roundup(min(Impact + Exploitability, 10))           Scope Unchanged
               = Roundup(min(1.08 * (Impact + Exploitability), 10))  Scope Changed
```

Roundup returns the smallest number with one decimal place that is equal to or higher than its
input, computed on integers so that floating-point noise does not add a step: take
`round(x * 100000)`; if it divides by 10000 the result is that over 100000, otherwise
`(floor(it / 10000) + 1) / 10`.

Bands: 0.0 None; 0.1 to 3.9 Low; 4.0 to 6.9 Medium; 7.0 to 8.9 High; 9.0 to 10.0 Critical.

Two mistakes this table exists to prevent:

- **Privileges Required depends on Scope.** Using the Scope Changed weights 0.68 and 0.5 on a
  Scope Unchanged vector raises the score: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` is 8.8
  (High), but computes 9.0 (Critical) with the wrong weight.
- **The base formula is not the environmental one.** v3.1 changed the *environmental* Modified
  Impact for a changed scope to `7.52 * (MISS - 0.029) - 3.25 * (MISS * 0.9731 - 0.02)^13`. The
  *base* Impact kept `(ISS - 0.02)^15`. Mixing them moves scores near a band edge:
  `CVSS:3.1/AV:P/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:L` is 7.0 (High) by the base formula.

The script's tests pin these vectors and a set of published scores.
