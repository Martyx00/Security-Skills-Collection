#!/usr/bin/env python3
r"""
sweep_secrets.py - the deterministic half of the secret sweep, and the thing that
keeps the other half honest.

Four rules in this skill decide whether a value is secret BY ITS NAME - LOG-008
and HW-009 match `\w*(secret|token|hash|mac|hmac|signature|...)\w*` and treat a
hit as sensitive. That is a guess about what a secret is *called*, and references/tuning.md
records it failing in both directions on a real run: it missed a key held in
`buf`, and "the light tier called public key names and certificate digests secret
and the arbiter overturned every one." Those are values the attacker already
holds. No amount of arbitration fixes a rule whose premise is wrong, so contract
§4a replaces the guess with an inventory of what is actually secret in this
repository, and the four rules read that instead.

Building the inventory needs judgement - is `expected` a MAC or a length? - so an
agent (the secret-sweeper role) writes it. Everything around that judgement is
mechanical and lives here:

  candidates  what a regex can find, handed to the agent to judge
  check       what the agent wrote back, held to §4a, mechanically
  status      the result, grouped by §4a's rule - not by what the file claims

THE RULE THIS FILE EXISTS TO MAKE MECHANICAL
--------------------------------------------

    A HARDCODED SECRET IS A FINDING. HOLDING A SECRET IS NOT.

A program that does cryptography holds keys, tags and nonces in variables - that
is what it is for. An inventory that reported each one as an issue would produce
two hundred findings and no signal, which is worse than no inventory. So
`is_finding` is true IF AND ONLY IF `kind == "secret"` and `origin == "literal"`.
Every other origin - env, file, kdf, key-store, fuse-otp, wire, derived, unknown
- is inventory, never a finding on its own. A secret-holding value becomes a
finding only when something is done wrong with it, and that finding belongs to
the rule governing the wrongdoing, not to the sweeper.

`check` refuses any other combination, in BOTH directions, under its own problem
code (`is_finding_discipline`). An inventory that quietly promoted its env reads
to findings would reproduce exactly the noise §4a was written to end, and a
contract clause nothing enforces is a comment.

AND THE RULE THAT STOPS THIS TOOL BECOMING THE LEAK
---------------------------------------------------

`.security-review/` lands on disk, is read by a model, and on some trees is
archived by CI. Copying a live credential into it makes the scanner a second
place the secret leaks from - a scanner that reports a leaked AWS key by leaking
it again has not helped. So redaction is this tool's job and not the agent's:

  * `redact()` keeps at most the first four and last four characters;
  * every literal is emitted redacted, INCLUDING inside the matched line text -
    the line goes out with EVERY literal found on it replaced by its
    redaction, never whole, whichever candidate the line was emitted for;
  * `scrub()` makes a second pass over every emitted line with the same
    predicate `check` uses to refuse a leak, so this tool's own output passes
    this tool's own check - which is selftested;
  * `check` refuses an inventory entry whose `redacted` or `evidence.code`
    carries more than eight consecutive characters of raw key material, or a
    whole literal this tool's own families find on the cited line, and a
    literal entry whose `redacted` is not visibly a redaction at all.

WHERE IT SITS
-------------

`extract_functions.py` owns `function_key`; `touched_by` entries are checked
against `extract/functions.jsonl` when it exists, so an inventory cannot name a
function nobody extracted. Citations are checked with `verify_findings.py`'s own
`norm`, `quote_at` and `DRIFT_WINDOW` - imported, not reimplemented, because a
second copy of a tolerance drifts from the first and the checker built to catch a
disagreement becomes the disagreement. The one thing added on top is redaction
awareness: the agent quotes a redacted line, the file holds the real one, and
`citation_verdict()` reconciles the two without letting a fabricated line through.

Stdlib only. Python 3.8+.

Exit codes
  0  the command completed and nothing was refused
  1  usage, or the run could not be completed: an unreadable root, an output path
     outside .security-review/ or reached through a symlink at or under it
     (contract §1, §9 rule 2), a --sarif file that will not parse, or --selftest
     failed
  2  `check` found at least one problem in inventory.json, or `status` was asked
     to print a file that contradicts §4a. `status` groups by the RULE, never by
     the file's own `is_finding`, and exits 2 where the two disagree: nothing in
     this pipeline forces `check` to run, and `status` is the command a person
     reads. An `origin: "env"` entry claiming `is_finding: true` used to print
     under the heading "FINDINGS - secrets HARDCODED into the source", and an
     `origin: "literal"` entry claiming false printed under "INVENTORY - NOT
     findings" while the findings block said "none". Both exited 0.
  3  there is no inventory.json to read, it does not parse, or it declares a
     schema_version this tool does not know (contract §0: refuse, never guess)
  7  refused before reading or writing anything: the scanned repository commits
     files under .security-review/ other than .gitignore and regular files
     under ledger/, git cannot say whether it does, or --root is this installed
     skill or an old copy of the scanner rather than a repository
     (rules_lib.run_dir_gate). Checked first, so it outranks every other code

Usage
  python3 sweep_secrets.py candidates --root .
  python3 sweep_secrets.py candidates --root . --sarif gitleaks.sarif --exclude fixtures
  python3 sweep_secrets.py check --root .
  python3 sweep_secrets.py check --root . --json
  python3 sweep_secrets.py status --root .
  python3 sweep_secrets.py --selftest
"""

import argparse
import bisect
import fnmatch
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import time

sys.dont_write_bytecode = True      # the skill folder is read-only: no __pycache__ in it
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rules_lib                                       # noqa: E402
import extract_functions as ef                         # noqa: E402
import verify_findings as vf                           # noqa: E402
# Already loaded by extract_functions, so naming it adds no import. It holds the
# one definition of how the run directory is written to: `linked_write_path`,
# `write_text` and `ensure_gitignore`.
import snapshot                                        # noqa: E402

TOOL = "sweep_secrets.py"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = 1

RUN_DIR = ".security-review"
SECRETS_DIR = "secrets"
CANDIDATES_NAME = "candidates.json"
INVENTORY_NAME = "inventory.json"
FUNCTIONS_JSONL = os.path.join("extract", "functions.jsonl")

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_REFUSED = 2
EXIT_NO_INPUT = 3

# Written if absent, for the same reason extract_functions.py writes it: this
# command's output names credentials by file and line, and an unignored
# candidates.json is a map of the repository's secrets committed to the
# repository. Its rules match extract_functions.GITIGNORE, including the
# `!ledger/` carve-out contract §1 requires, so whichever stage 1 tool runs first
# leaves the same ignores behind - and an existing file that ignores everything
# without that carve-out has it appended (snapshot.ensure_gitignore).
GITIGNORE = """\
# Written by security-review stage 1. Run artifacts are not committed; the ledger is.
*
!.gitignore
!ledger/
!ledger/**
"""


# --------------------------------------------------------------------------- #
# redaction - the tool's job, not the agent's
# --------------------------------------------------------------------------- #

# U+2026, one character, and not in SECRET_CHARS - which is what lets
# citation_verdict() split a redacted quote on it without splitting the quote.
ELISION = "\u2026"

# The markers `check` will accept from an agent as "something was elided here".
# Wider than what redact() writes, because the agent quotes lines by hand and
# `***`, `...` and `[REDACTED]` are what hands reach for.
ELISION_MARK = re.compile(r"\u2026|\.\.\.|\*{3,}|\[REDACTED\]|<redacted>|<elided>",
                          re.IGNORECASE)

# The other form a `redacted` value may take: the shape alone, which the
# sweeper prompt asks for on anything twelve characters or shorter -
# `<6 digits>`, `<32 bytes, hex>`.
SHAPE_TOKEN = re.compile(r"^\s*<[^<>]{1,40}>\s*$")


def not_a_redaction(text):
    """A non-empty `redacted` with neither an elision nor a `<shape>` in it."""
    return bool(isinstance(text, str) and text.strip()
                and not ELISION_MARK.search(text) and not SHAPE_TOKEN.match(text))


def redact(value):
    """At most the first four and last four characters, middle elided.

    Contract §4a: `redacted` never carries the secret. Four either side is the
    ceiling, not the rule - a short value gives up proportionally less, because
    first-four-and-last-four of an eight-character password is the password:

        len >= 16  ->  4 either side     AKIAIOSFODNN7EXAMPLE -> AKIA...MPLE
        len 12-15  ->  3 either side
        len 8-11   ->  2 either side
        len 4-7    ->  1 either side
        len < 4    ->  nothing but the elision

    The elision is always written, so a redaction is always visibly a redaction
    and never mistaken for a short literal that happened to be printed whole.

    This is stricter than the illustrative record in §4a, which keeps a whole
    `sk-live-` family prefix. Keeping the prefix is defensible - it is a public
    marker, not entropy - but it is a judgement, and a redactor that makes
    judgements is a redactor that eventually makes the wrong one.
    """
    if value is None:
        return None
    text = str(value)
    n = len(text)
    if n == 0:
        return ""
    if n >= 16:
        keep = 4
    else:
        keep = n // 4
    if keep <= 0:
        return ELISION
    return text[:keep] + ELISION + text[-keep:]


def redact_span(line, start, end):
    """The line with exactly [start:end) replaced by its redaction."""
    if start is None or end is None or start < 0 or end > len(line) or start >= end:
        return line
    return line[:start] + redact(line[start:end]) + line[end:]


def overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def redact_spans(line, spans):
    """The line with every span in `spans` replaced by its redaction.

    Overlapping spans are one secret described twice - an assignment's value
    and the key-family match inside it - and are redacted once, as their union.
    Applied right to left, so an earlier span's offsets survive the later ones.
    """
    merged = []
    for start, end in sorted(s for s in spans
                             if s and 0 <= s[0] < s[1] <= len(line)):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    for start, end in reversed(merged):
        line = redact_span(line, start, end)
    return line


def spans_within(spans, start, end):
    """`spans` clipped to [start, end) and shifted to be relative to `start`."""
    return [(max(s, start) - start, min(e, end) - start)
            for s, e in spans if s < end and start < e]


# --------------------------------------------------------------------------- #
# entropy, and what a run of key material looks like
# --------------------------------------------------------------------------- #

# The alphabet key material is written in: base64 and base64url, which covers
# hex, base32, and every token family below. What is NOT in it is doing the real
# work - a space, a quote, a `:`, a `%` and a `.` all end a run, which is how
# high_entropy_runs() excludes prose, URLs and format strings without a
# blocklist. `/`, `+` and `=` stay in, because base64 uses all three; that is
# what SEGMENT_SPLIT below then has to undo for path-like text.
SECRET_CHARS = re.compile(r"[A-Za-z0-9+/=_\-]+")

# Default for --entropy-threshold, in bits per character.
#
# WHY 3.6, and not truffleHog's familiar 4.5: a string of n characters cannot
# exceed log2(n) bits per character, so a 20-character literal - the shortest
# this family looks at - tops out at log2(20) = 4.32. A threshold of 4.5 is
# unreachable there; it would silently switch the family off for everything
# shorter than about 28 characters, which includes a 20-hex-digit key and most
# session tokens. 4.5 is a number borrowed from a tool that measures whole
# 40-character runs, and borrowing it here would produce a family that looks
# configured and finds nothing.
#
# 3.6 is 83% of that 20-character ceiling, and it sits in the gap that the two
# populations actually leave:
#
#   random hex, 20-40 chars          3.55 - 3.95   (ceiling 4.0)
#   random base64, 20-40 chars       4.10 - 4.70   (ceiling 6.0)
#   identifiers, MIME types, paths   2.90 - 3.50   after identifier_shaped()
#                                                   has removed the long ones
#
# It is deliberately recall-biased. A false candidate costs the agent one line to
# dismiss; a hardcoded key nobody surfaced costs the review its point. The
# threshold is not a verdict - nothing this pass emits is a finding until the
# agent classifies it and `check` holds that classification to §4a.
DEFAULT_ENTROPY_THRESHOLD = 3.6

# Shortest run the high-entropy family will look at. Below 20 characters the
# entropy of a random string and the entropy of a word are not separable: at
# n = 12 the ceiling is 3.58, under the threshold itself.
DEFAULT_ENTROPY_MIN_LENGTH = 20

# `check`'s leak test looks at runs as short as 9 - "more than 8 consecutive
# characters of a high-entropy literal" - where the entropy ceiling is
# log2(9) = 3.17 and a fixed 3.6 could never fire, so the test would pass
# everything and refuse nothing. Below DEFAULT_ENTROPY_MIN_LENGTH, therefore, the
# floor drops to this fraction of the run's OWN ceiling.
#
# The adjustment only ever lowers the floor, and only for short runs. It must not
# apply above twenty characters, or raising --entropy-threshold would stop
# raising the bar: a 32-character run's ceiling is 5.0, and capping a threshold of
# 5.9 at 4.5 would silently keep matching what the operator just said to stop
# matching.
LEAK_MIN_RUN = 9
ENTROPY_CEILING_FRACTION = 0.9

HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")

# Where an identifier breaks. `_`, `-`, `.` and camelCase are the obvious ones;
# `/`, `=` and `+` are here because they are in the secret alphabet and so do NOT
# end a run - `arbitration/ARB-CAND-001` and `max_bytes=MAX_FILE_BYTES` arrive at
# identifier_shaped() as single 24-character runs, and without these they read as
# key material.
#
# The camelCase split is the one that cuts the other way. `/` and `+` each turn
# up once in 64 characters of random base64, but a lowercase-then-uppercase pair
# turns up every few characters, so random mixed case falls apart into short
# `[A-Za-z]*[0-9]*` pieces that each look like a word: the AWS documentation's
# example secret key splits into w/Jalr/XUtn/FEMI/K7/MDENG/b/Px/Rfi/CYEXAMPLEKEY
# and averaged over three characters a piece. Measured over random base64, this
# alone threw away 15% of 20-character tokens and 4% of 40-character ones - an
# AWS secret access key among them - while entropy dropped under 0.4%.
# ACRONYM_THEN_LOWER is what separates the two populations; see
# identifier_shaped().
SEGMENT_SPLIT = re.compile(r"[_\-./=+]+|(?<=[a-z0-9])(?=[A-Z])")
WORDLIKE_SEGMENT = re.compile(r"^[A-Za-z]*[0-9]*$")

# Longest segment still readable as a word. `Configuration` is thirteen.
WORDLIKE_MAX = 16

# A named elliptic curve is a word in a crypto tree, though its letters and
# digits alternate: `secp256r1`, `sect163k1`, `prime256v1`, and brainpool's
# `P256r1` once camelCase has split it off. `testkey_ec_secp192r1`, a fixture's
# name in a scope reason, refused the report that quoted it.
CURVE_SEGMENT = re.compile(r"^(?:sec[pt]\d{3}[kr]\d|prime\d{3}v\d|P\d{3}[rt]\d)$")

# A piece that starts with two or more capitals and then goes lowercase: `XUtn`,
# `ZQQYb`. Random case produces them constantly; a name seldom has more than
# one - `AESKey`, `HTTPServer` - because it spells one acronym and then a word.
# Refusing two in one run brought the random-token loss to 0.2% at 40
# characters and reclassified none of 3277 identifier-shaped runs in the Python
# stdlib. `HTTPServerXMLParser` is the price: a candidate for the agent to
# dismiss, which is the cheap direction to be wrong in.
ACRONYM_THEN_LOWER = re.compile(r"^[A-Z]{2,}[a-z]")


def shannon(text):
    """Shannon entropy of `text` in bits per character."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(text))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def identifier_shaped(token):
    """Does this run read as an identifier rather than as key material?

    The single largest source of false key material is a long snake_case or
    CamelCase name: `mbedtls_pkcs5_pbkdf2_hmac_ext` is 29 characters of the
    secret alphabet, mixes letters and digits, and measures 3.96 bits per
    character - comfortably over the threshold, and not a secret.

    Entropy cannot separate it, because entropy does not see structure. This
    does: an identifier splits on SEGMENT_SPLIT - `_`, `-`, `.`, `/`, `=`, `+`
    and camelCase boundaries - into segments that are each a word followed by
    digits, and the segments are words rather than fragments.

        mbedtls_pkcs5_pbkdf2_hmac_ext  -> mbedtls/pkcs5/pbkdf2/hmac/ext   yes
        aes_256_gcm_encrypt_ctx        -> aes/256/gcm/encrypt/ctx         yes
        AESKeyWrapUnwrapTest256        -> AES/Key/Wrap/Unwrap/Test/256    yes
        arbitration/ARB-CAND-001       -> arbitration/ARB/CAND/001        yes
        sk-live-9f2c1ab4e0d73516aaaa   -> sk/live/9f2c1ab4e0d73516aaaa    no
        AKIAIOSFODNN7EXAMPLE           -> one segment                     no
        aBcDeFgHiJkLmNoPqRsTuV12       -> 12 segments, mean length 2.0    no
        xskbknCsBqzfcDAXBMnXjYKz       -> xskbkn/Cs/Bqzfc/DAXBMn/Xj/YKz,
                                          mean 4.0, but DAXBMn and YKz    no

    The mean-length floor is what stops a mixed-case token from splitting itself
    into an identifier: a real name averages three characters or more a segment,
    alternating case every other character does not. It is not enough on its
    own - random base64 averages three too, often enough to matter - so a run
    with two ACRONYM_THEN_LOWER pieces is not an identifier either.
    """
    segments = [s for s in SEGMENT_SPLIT.split(token) if s]
    if len(segments) < 2:
        return False
    for seg in segments:
        if len(seg) > WORDLIKE_MAX or not (WORDLIKE_SEGMENT.match(seg)
                                           or CURVE_SEGMENT.match(seg)):
            return False
    if sum(1 for seg in segments if ACRONYM_THEN_LOWER.match(seg)) >= 2:
        return False
    return (sum(len(s) for s in segments) / float(len(segments))) >= 3.0


def magic_constant(token):
    """`0xDEADBEEF12345678` and friends: a machine word, written as one."""
    if token[:2].lower() != "0x":
        return False
    body = token[2:]
    return bool(body) and bool(HEX_ONLY.match(body)) and len(body) <= 16


# Assets whose base64 begins with a known magic number. A PNG pasted into a
# source file is 40 kilobytes of high-entropy base64 and no secret at all; left
# in, one favicon buries the candidate list.
ASSET_B64_PREFIXES = (
    "iVBORw0KGgo",      # PNG
    "/9j/",             # JPEG
    "R0lGOD",           # GIF
    "JVBERi0",          # PDF
    "UEsDB",            # ZIP / docx / jar
    "PHN2Zw",           # SVG "<svg"
    "AAABAA",           # ICO
    "GkXfo",            # WebM
    "AAAAIGZ0eX",       # MP4 ftyp
    "T2dnUw",           # Ogg
    "d09GR",            # WOFF
    "AAEAAA",           # TrueType
    "H4sI",             # gzip
    "data:",            # a data: URI reached the run somehow
)


def asset_base64(token):
    return any(token.startswith(p) for p in ASSET_B64_PREFIXES)


def covered_by_known_family(token):
    """Does a known token family account for at least half of this run?"""
    match = KNOWN_TOKEN_ANY.search(token)
    return bool(match) and (match.end() - match.start()) * 2 >= len(token)


def structurally_random(token):
    """Is this run shaped like key material at all?

    Entropy alone says yes to too much, so a run must also look like something a
    generator produced rather than something a person typed:

      * pure hexadecimal of eight characters or more - every hex key, digest and
        raw AES key in the tree;
      * lower AND upper AND digit together - base64 and base64url tokens;
      * two of those three over twenty characters - base32 and the
        uppercase-and-digits families, of which `AKIA…` is the one everybody
        knows;
      * anything a known token family accounts for half of, whatever its shape.
        A family prefix is not a heuristic: `ghp_` followed by thirty-six
        characters is a GitHub token and nothing else.
    """
    if not token:
        return False
    if covered_by_known_family(token):
        return True
    body = token[2:] if token[:2].lower() == "0x" else token
    if HEX_ONLY.match(body) and len(body) >= 8:
        return True
    classes = 0
    for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]"):
        if re.search(pattern, token):
            classes += 1
    if classes >= 3:
        return True
    return classes == 2 and len(token) >= 20


def looks_like_key_material(token, threshold, min_length):
    """The one predicate both passes use, at two different lengths.

    `candidates` calls it at min_length = 20 to decide what to show the agent.
    `check` calls it at min_length = 9 to decide whether an inventory entry is
    carrying a secret it should have redacted. Same test, so an entry that quotes
    a line this tool emitted can never be refused for carrying what this tool
    wrote - which is selftested, because the alternative is a checker that
    rejects its own sibling's output.
    """
    n = len(token)
    if n < min_length:
        return False
    # A family prefix settles it before any heuristic gets a vote: `ghp_` and
    # thirty-six characters would otherwise have to survive identifier_shaped(),
    # and a token that happens to split into word-shaped pieces is still a token.
    # It must be most of the run, though - a short family match buried in a long
    # blob says something about three of its characters, not about the blob.
    if covered_by_known_family(token):
        return True
    if magic_constant(token) or identifier_shaped(token) or asset_base64(token):
        return False
    if not structurally_random(token):
        return False
    floor = threshold
    if n < DEFAULT_ENTROPY_MIN_LENGTH:
        floor = min(floor, ENTROPY_CEILING_FRACTION * math.log(n, 2))
    return shannon(token) >= floor


def high_entropy_runs(text, threshold, min_length):
    """Runs of key material in `text`, as (start, end, run).

    The run, rather than the whole quoted string, is what the entropy is measured
    over. Measuring the string dilutes a 24-character key sitting inside a
    200-character JSON blob below any threshold that is not also matching prose.
    And requiring a RUN of the secret alphabet is what excludes URLs, paths,
    format strings and English without a blocklist that has to be maintained: a
    space, a `.`, a `:` or a `%` ends the run, so `https://api.example.com/v1/get`
    breaks into `https`, `//api`, `example`, `com/v1/get` and contains no run of
    twenty, while `?token=9f2c1ab4e0d73516aaaa` contains one - and that is the
    right answer for both.
    """
    for match in SECRET_CHARS.finditer(text or ""):
        run = match.group(0)
        if looks_like_key_material(run, threshold, min_length):
            yield match.start(), match.end(), run


def leaked_runs(text, threshold=DEFAULT_ENTROPY_THRESHOLD):
    """Runs of more than eight consecutive characters of raw key material."""
    return high_entropy_runs(text, threshold, LEAK_MIN_RUN)


def scrub(text, threshold=DEFAULT_ENTROPY_THRESHOLD):
    """Every leaked run in `text`, replaced by its redaction.

    The second pass. The first redacts the literal this tool matched, by span,
    because it knows exactly where that literal is. This one catches whatever
    else is on the line - a second key, a SARIF snippet whose extent nobody told
    us - using the same predicate `check` refuses on. The invariant it buys is
    worth stating: nothing this tool writes can fail this tool's leak test.
    """
    if not text:
        return text
    out, last = [], 0
    for start, end, run in leaked_runs(text, threshold):
        out.append(text[last:start])
        out.append(redact(run))
        last = end
    out.append(text[last:])
    return "".join(out)


# --------------------------------------------------------------------------- #
# literal families - possible hardcoded secrets
# --------------------------------------------------------------------------- #

# PEM. The block is multi-line; the BEGIN marker is not itself secret, so the
# candidate is recorded at the marker's line and the BODY is what gets redacted.
PEM_BEGIN = re.compile(
    r"-----BEGIN (?:(RSA|DSA|EC|OPENSSH|PGP|SSH2 ENCRYPTED|ENCRYPTED) )?PRIVATE KEY(?: BLOCK)?-----")
PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
PEM_MAX_BODY_LINES = 400

# What may follow a BEGIN marker and still be the key: base64, and the RFC 1421
# headers openssl writes above an encrypted body. The walk STOPS at the first
# line that is neither, which matters more than it looks: a `-----BEGIN RSA
# PRIVATE KEY-----` written inside a comment, a test fixture or a regex - this
# file contains three - would otherwise swallow the next four hundred lines into
# a "key body" and suppress every other family over all of them. A marker with
# nothing key-shaped under it is emitted with `pem_body_lines: 0`, which tells
# the agent in one field that it is a mention and not a key.
#
# Which made the most common way TLS and embedded code carry a key read as a
# mention. Compiled into C, Go or JS the body is `"MIIE...\n"` a line, quotes and
# an escaped newline around the base64; in a service-account JSON it is all on
# the BEGIN line, joined by literal `\n`. Both stopped the walk at zero lines: a
# real 2048-bit key came out as `pem_body_lines: 0` with no fingerprint, and in
# C as 26 unrelated high-entropy candidates besides. So the body is also read
# (a) from the rest of the BEGIN line, split on escaped newlines, and (b) from
# string literals on the lines below - but only when the marker itself is
# written inside one (PEM_WRAPPED_BEGIN), so a marker mentioned in code cannot
# swallow the ordinary quoted strings after it.
PEM_BODY_LINE = re.compile(r"^[A-Za-z0-9+/=\s]*$")
PEM_HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z-]*:\s")
ESCAPED_NEWLINE = re.compile(r"(?:\\r)?\\n")
PEM_WRAPPED_BEGIN = re.compile(r"^(?:\\r)?\\n")
PEM_STRING_LINE = re.compile(
    r"""^\s*(?:[+,]\s*)?(?P<q>["'])(?P<b>[^"'\\]*)(?:\\r)?(?:\\n)?(?P=q)"""
    r"""\s*(?:[+,;)\\]\s*)*$""")

# Known token families. (subkind, pattern). Each pattern matches the WHOLE
# literal, because the whole literal is what gets redacted out of the line.
KNOWN_TOKEN_FAMILIES = (
    ("aws-access-key-id",     r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA)[0-9A-Z]{16}"),
    ("openai-key",            r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}"),
    ("github-token",          r"gh[pousr]_[A-Za-z0-9]{20,}"),
    ("github-fine-grained",   r"github_pat_[A-Za-z0-9_]{30,}"),
    ("slack-token",           r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("slack-webhook",         r"https://hooks\.slack\.com/services/[A-Za-z0-9/+_-]{20,}"),
    ("google-api-key",        r"AIza[0-9A-Za-z_-]{35}"),
    ("gitlab-pat",            r"glpat-[A-Za-z0-9_-]{16,}"),
    ("npm-token",             r"npm_[A-Za-z0-9]{30,}"),
    ("stripe-key",            r"[sr]k_(?:live|test)_[A-Za-z0-9]{10,}"),
    ("sendgrid-key",          r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    ("twilio-sid-or-key",     r"(?:AC|SK)[0-9a-fA-F]{32}"),
    ("azure-storage-key",     r"AccountKey=[A-Za-z0-9+/=]{40,}"),
    ("jwt",                   r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # `secret` names the part to redact where the match is wider than the secret.
    # Redacting the whole URL would hide the host, which is the context that
    # tells an agent whether this is production or a docker-compose fixture.
    # The user may be empty: `redis://:password@host` is how Redis, Valkey and
    # many AMQP URLs spell a password with no user, and `+` there made the
    # family skip every one of them. The scheme and `://` are what keep an
    # empty user from matching `host:port@`.
    #
    # The scheme is capped at 32 characters. Unbounded, `[a-zA-Z0-9+.-]*` ran
    # to the end of every run of scheme characters looking for the `://` after
    # it and gave them back one at a time, from every start position finditer()
    # and search() try: quadratic in the run. A test vector is one long run.
    # MbedTLS's hash_file_5 is a single line of a million `a`, which this
    # pattern alone took twenty minutes or more over, and KNOWN_TOKEN_ANY
    # carries the same scheme into the search() made for every entropy run -
    # the hex vectors of an ML-DSA .data file, thousands of digits each.
    # RFC 3986 sets no maximum for a scheme, and the cap costs a longer one
    # little: the pattern is not anchored, so a 40-character scheme still
    # matches from its last 32 characters, with the same `secret` span and
    # host. What moves is where the match starts, and with it the name
    # literal_hits() reads to the left of it, which is then the head of the
    # scheme rather than the name assigned. The one match lost is a scheme
    # whose last 32 characters are all digits, `+`, `.` and `-`. No scheme in
    # this skill's tree or in MbedTLS's is longer than eight characters.
    ("basic-auth-in-url",
     r"[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s:/@]*:(?P<secret>[^\s:/@]{3,})@[^\s/]+"),
)

KNOWN_TOKEN_RE = [(sub, re.compile(pat)) for sub, pat in KNOWN_TOKEN_FAMILIES]

# One alternation of all of them, for structurally_random(). A family prefix
# settles the question of whether a run is key material without asking entropy.
KNOWN_TOKEN_ANY = re.compile("|".join("(?:%s)" % pat for _, pat in KNOWN_TOKEN_FAMILIES))

# A long literal assigned to a secret-ish name. The name half is deliberately the
# same guess LOG-008 makes - the difference is that here it produces a CANDIDATE
# for an agent to judge rather than a finding, which is the whole of §4a.
# The optional quote after the name is not decoration: `{"password": "hunter2"}`
# and `password: "hunter2"` are how JSON, YAML and every config file in the tree
# spell this, and without it the pattern only ever matched source code. Nor is
# the choice of glue: Go declares with `apiKey := "..."` and PHP and Ruby key a
# hash with `'password' => '...'`, and `[:=]` alone matched neither - the `:`
# of `:=` and the `=` of `=>` each left the other character between the glue
# and the quote. LOG-005's line_pattern already spells all three, and the
# sweeper found none of the Go or PHP lines that rule flags.
#
# `auth` is spelled out into its compounds rather than left bare. Bare `auth`
# plus `\w*` matches `author`, and on this skill's own tree that was twelve of
# twenty hits - every `"author": "you@example.com"` in a fixture. A name list
# that fires on the wrong names is the failure 4a was written about; it does not
# become acceptable because this end of it only produces candidates.
SECRET_NAME_STEM = (
    r"(?:pass|pwd|secret|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|authorization|auth[_-]?(?:token|key|secret|code|header)|"
    r"bearer|credential|passphrase)")


def secret_assign_pattern(floor):
    """SECRET_ASSIGN with the value's length floor at `floor` characters.

    One spelling of the name list and the glue, so the outbound detector's
    six-character copy (EXPORT_ASSIGN) cannot drift from the sweeper's own.
    """
    return re.compile(
        (r"(?i)(?P<name>" + SECRET_NAME_STEM + r"\w*)[\"']?\s*(?::=|=>|[:=])\s*"
         r"(?P<q>[\"'])(?P<val>[^\"']{%d,})(?P=q)") % floor)


SECRET_ASSIGN = secret_assign_pattern(8)

# The same thing unquoted, which is how a .env, a Dockerfile ENV and a CI
# variable file spell it. Without this the single most common place a credential
# is committed reads as an empty file.
#
# The line shape and the name test are separate because they answer separate
# questions, and folding the name into the line pattern made both unreadable and
# one of them wrong: `[A-Za-z_][A-Za-z0-9_]*(?:...|TOKEN|...)` cannot match a
# variable simply called `TOKEN`, since it demands a character before the stem.
# `.`, `-` and `:` are in here because .properties, .ini and YAML all spell the
# same thing slightly differently - `db.password=`, `db-password=`,
# `password: value` - and a k8s manifest or a CI config is exactly where an
# unquoted credential ends up.
ENV_ASSIGN = re.compile(
    r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*"
    r"(?P<val>[^\s#]{8,})\s*(?:#.*)?$")

# The stem must start the name or follow a separator. Without that anchor, `key`
# matches `monkey` and `pass` matches `bypass`; with it, `TOKEN`, `API_TOKEN`,
# `db-password` and `db.password` all match and `MONKEY_COUNT` does not.
ENV_SECRET_NAME = re.compile(
    r"(?i)(?:^|[_.\-])(?:pass|pwd|secret|token|key|cred|auth|passphrase)")

# An unquoted value is a literal in a config file and an EXPRESSION in source.
# Run ENV_ASSIGN over Python and `key = record.get("key")` is a hardcoded secret
# twenty-six times over on this skill's own tree - none of them a secret, all of
# them ordinary assignments. So the unquoted family runs over configuration only;
# source keeps the quoted family, the prefix families and entropy, and an
# unquoted credential in source is not a thing that can exist.
CONFIG_SUFFIXES = (".env", ".ini", ".cfg", ".conf", ".config", ".properties",
                   ".yaml", ".yml", ".toml", ".tf", ".tfvars", ".sh", ".bash",
                   ".zsh", ".service", ".cnf", ".netrc", ".npmrc", ".pgpass",
                   ".htpasswd", ".env.local", ".env.production")
# The credential files are here by name because they have no suffix to go by,
# and they are where the value is unquoted: `aws_secret_access_key = wJalr...`
# in a committed `.aws/credentials` produced no candidate at all while the
# non-secret key id beside it did, because only the entropy family ran there.
CONFIG_BASENAMES = ("dockerfile", "docker-compose.yml", "docker-compose.yaml",
                    ".env", ".netrc", ".npmrc", ".pgpass", "credentials",
                    ".git-credentials", ".pypirc", ".s3cfg", ".boto")

# What an unquoted config value never is. Parentheses, brackets and `$` are the
# punctuation of an expression or an interpolation, not of a credential.
EXPRESSION_VALUE = re.compile(r"[()\[\]{}<>$,;]")


def config_file(rel):
    base = os.path.basename(rel).lower()
    if base in CONFIG_BASENAMES or base.startswith(".env"):
        return True
    if base.startswith("dockerfile"):
        return True
    return any(base.endswith(suffix) for suffix in CONFIG_SUFFIXES)

# A value that is an interpolation is not a literal at all: `password =
# "${DB_PASS}"` is an env read wearing a literal's clothes, and emitting it as a
# possible hardcoded secret trains the agent to skim.
TEMPLATED_VALUE = re.compile(r"\$\{|\$\(|\{\{|%\(|<%|%s\b|\{[0-9]*\}|^\$[A-Za-z_]|^<[^>]+>$")


# --------------------------------------------------------------------------- #
# outbound text - one judgement of what may not leave the machine
# --------------------------------------------------------------------------- #
#
# Four readers hold text that leaves this machine or outlives the run. The
# first three meet the line a credential is on, because a LOG-005 or HW-010
# finding's evidence IS that line, quoted verbatim (Validator Contract §7):
#
#   export_sarif.scrub()            the SARIF a consumer uploads to a dashboard
#   verify_findings.secret_spans()  the REPORT.md gate, and the source text the
#                                   gate quotes back into arbitration/
#   ledger.key_material()           committed reasons, and the training samples
#                                   cut from them
#   upstream_check._withheld()      the function names, repository identity
#                                   and scanned commit an operator-approved
#                                   query sends to a code host or an advisory
#                                   database; a flagged term is withheld, never
#                                   redacted and sent
#
# Each used to carry its own detector, and the first two disagreed about the
# very strings they exist for: `password = "Pr0dPassw0rd…"` - a truncation, not
# a redaction - went into the SARIF whole while the report gate refused it; a
# key array's continuation line was redacted in the SARIF and passed by the
# gate; and a fix-commit URL, which `/` joins into one entropy run, was mangled
# in the SARIF and refused in the report. So there is one detector, here beside
# the families it is built from, and each reader applies only what is its own:
# the report gate and the ledger excuse a digest that is provenance, which the
# SARIF scrub redacts anyway because a redacted commit costs a dashboard
# nothing. And the two readers that REFUSE on a hit - the gate a whole report,
# the ledger a reason or an export - leave the REDACT_ONLY_KINDS, which the
# readers that redact in place take: a passphrase or a dictionary word under a
# password name is the value a LOG-005 finding quotes, and redacting it from a
# snippet costs nothing, while refusing a report over `token_type = "Bearer"`
# or `dev_desc[18] = {0x12, ...}` costs the report. One detector does not mean
# one verdict on every line; it means no line a refusing reader refuses leaves
# a redacting reader whole. The upstream check excuses one term from one kind:
# the scanned commit id in the OSV body - the one thing OSV can be asked, a git
# object id held to hex - is sent past `entropy`, which flags every real
# commit, so that screening it does not withhold every OSV request; any other
# kind on it still withholds it. Function names and the repository identity
# are withheld on any hit, digests and REDACT_ONLY_KINDS included: a term it
# withholds costs one search, and a term it sends has left for good.

# LOG-005's own floor. The sweeper's candidate family keeps eight; what a
# finding may quote, LOG-005 flags from six.
EXPORT_ASSIGN = secret_assign_pattern(6)

# The entropy test outbound text is held to: 3.0 over runs of twenty, what all
# three readers used before they shared one. It is below the sweeper's 3.6,
# which is set to hand an agent candidates to dismiss; nobody reviews what
# these readers let out, and the digest and URL exemptions are what keep this
# one off provenance.
EXPORT_ENTROPY_THRESHOLD = 3.0
EXPORT_ENTROPY_MIN_LENGTH = 20

# A byte-array initialiser under a key-shaped name - HW-010's shape - on the one
# line a finding quotes. The body is the span; the declaration is kept. At least
# four elements, and not all zero: `uint8_t key[32] = {0};` is a buffer. An
# element is a byte written as a number or as a C character literal: HW-010
# flags `char key[`, and `{'h','u','n','t','e','r','2','!'}` is the same eight
# bytes as their hex, each too short for any other detector to see.
#
# The name is the whole word - it starts at `\b` and `\s*\[` cannot follow a
# word character - so the stem is a lookahead rather than `\w*(?:key|secret)\w*`.
# Spelled that way, a word that was not followed by `[` was tried once per
# `key` in it, each try reading to the end of the word: quadratic in the word.
KEY_ARRAY_INIT = re.compile(
    r"(?i)\b(?P<name>(?=\w*?(?:key|secret))\w+)\s*\[[^\]\n]*\]\s*=\s*\{(?P<body>[^}\n]*)")
ARRAY_ELEMENT = re.compile(
    r"\b(?:0x[0-9a-fA-F]{1,2}|\d{1,3})\b"
    r"|'(?:\\x[0-9a-fA-F]{1,2}|\\[0-7]{1,3}|\\.|[^'\\\n])'")
CHAR_OCTAL_ESCAPE = re.compile(r"\\[0-7]{1,3}\Z")
KEY_ARRAY_MIN_ELEMENTS = 4

# The words that carry `key` or `secret` without meaning one. HW-010 matches
# the stem anywhere in the name, and it has to: `aeskey`, `privkey`, `keydata`
# and `masterKey` are keys with no separator to split on. But so it also
# matched `keypad_map`, `hotkeys` and `monkey_table`, and the refusing readers
# refused a report or a ledger reason over a scan-code table. These words are
# taken out of the name before the stem is looked for, so `keypad_aes_key` is
# still a key.
NON_KEY_WORDS = re.compile(
    r"(?i)keypad|keyboard|keycode|keymap|keypress|keystroke|keyword|keyframe|keysym"
    r"|hotkey|monkey|donkey|turkey|hockey|jockey|whiskey|secretar")


def names_a_key(name):
    """Does this array's name say it holds a key or a secret?"""
    return bool(re.search(r"(?i)key|secret", NON_KEY_WORDS.sub("", name or "")))


# LOG-005's name stem, the one secret_assign_pattern spells, for the byte
# tables below: `wifi_password[8] = {0x68, 0x75, ...}` is not a key by HW-010's
# name test, and it is still the bytes of a password.
SECRET_NAME = re.compile(r"(?i)" + SECRET_NAME_STEM)


def names_a_secret(name):
    """Does this initialiser's name say it holds a key (HW-010) or a secret (LOG-005)?"""
    return names_a_key(name) or bool(SECRET_NAME.search(NON_KEY_WORDS.sub("", name or "")))


# The continuation lines of the same array, quoted as evidence items of their
# own: eight or more hex bytes in a row. That also takes an S-box or a test
# vector out of a snippet, which costs a redacting reader nothing the file does
# not still say. A refusing reader is another matter: the evidence of a MEM or
# HW finding and the reason for an FP-CONST dismissal quote a USB descriptor or
# an ELF magic as readily as a key, and refusing them refused a correct report
# and a committed ledger. So a run inside the body of an initialiser whose name
# is neither a key's nor a secret's (NAMED_INIT, names_a_secret: HW-010's name
# test and LOG-005's stem, so `wifi_password[8]` and `api_token[]` are still
# refused) is a `hex-table`, which only the redacting readers take. A run with
# no name on its line is still `hex-bytes`, because a key array's continuation
# line has none either: that is the price of keeping it out of REPORT.md, paid
# by a quoted CRC table's second line.
# The body stops at ANY brace, so only a flat initialiser is a table: in
# `cfg = { .aes_key = {0x2b, ...} }` the bytes belong to `aes_key`, not to
# `cfg`, and a body running to the first `}` gave them to `cfg`.
HEX_BYTE_RUN = re.compile(r"(?i)\b0x[0-9a-f]{2}(?:\s*,\s*0x[0-9a-f]{2}){7,}\b")
NAMED_INIT = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\[\]\n]*\]\s*)*=\s*\{(?P<body>[^{}\n]*)")

# A URL, for url_path_run(). Up to the first character that cannot be in one.
# The scheme is capped at 32 characters for the reason basic-auth-in-url's is:
# unbounded, a long run of scheme characters with no `://` after it was read
# to its end from every start, and a REPORT.md quoting a long hex vector beside
# one permalink took minutes. A longer scheme is found from its last 32, which
# moves where the URL starts and nothing url_path_run() reads: the authority is
# found from the `://`, and an entropy run cannot start in a scheme and reach
# its `/`, since the `:` ends it.
URL_IN_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s\"'<>`]+")

# A git object name or a content hash, standing alone as one segment of a URL's
# path: `/commit/<sha>`, `/blob/<sha>/`. Lower-case hex of exactly the lengths
# git, sha256 and this pipeline's content_hash write.
URL_DIGEST_SEGMENT = re.compile(r"(?:[0-9a-f]{16}|[0-9a-f]{40}|[0-9a-f]{64})\Z")

# The path segments after which such a digest is a citation: what GitHub and
# its REST API (`/git/commits/`, `/git/trees/`, `/git/blobs/`), GitLab
# (`/-/commit/`), Bitbucket (`/commits/`, `/src/`) and Gitiles (`/+/`) put in
# front of an object name, and the source archive of a pinned commit that a
# Bazel `http_archive` fetches. The shape alone says nothing, because
# 40 and 64 lowercase hex is also how `secrets.token_hex(20)` and
# `token_hex(32)` are written (see verify_findings.LONG_DIGEST): excused on
# shape, a webhook or capability URL - `https://hooks.example.com/deliver/<64
# hex>` - went into the SARIF and REPORT.md whole while the sweeper flagged
# the same line as a secret. A digest after any other segment is judged like
# any other run.
URL_CITATION_SEGMENTS = frozenset((
    "commit", "commits", "blob", "blobs", "tree", "trees", "raw", "blame", "src",
    "compare", "rev", "+", "archive", "tarball", "zipball"))
# A host that puts the object name at a fixed place in the path rather than
# after a word: raw.githubusercontent.com/<owner>/<repo>/<sha>/<file>. The
# number is how many `/` come before it.
URL_CITATION_HOSTS = {"raw.githubusercontent.com": 3}

# Where a URL's authority ends and where its path ends, for url_path_run():
# the first `/`, `?` or `#` after `scheme://`, and the first `?` after that.
URL_AUTHORITY_END = re.compile(r"[/?#]")
URL_QUERY_START = re.compile(r"\?")

# A redaction keeps a few characters either side of the elision: redact() keeps
# at most four, and §4a's own example keeps the `sk-live-` family prefix. A
# fragment as long as the leak test (LEAK_MIN_RUN, nine) is more of the value
# than any redaction keeps, so `Pr0dPassw0rd…` is a password with an ellipsis
# after it, not a redacted one.
REDACTED_FRAGMENT_MAX = 8

# The longest all-letter value read as a word rather than a password:
# `"Bearer"`, `"Basic"`, `"password"` itself on the default-credential line.
BARE_WORD_MAX = 8

# A value that is an identifier, of any length: letter-only words joined the
# way code and config join them - `same-origin`, `client_secret_basic`,
# `in-inventory:mac-or-tag`, `ACCESS_TOKEN` - or one camelCase word,
# `localStorage`. Under a secret-shaped name these are a fetch() credentials
# mode, an OAuth auth method, a storage key, and this pipeline's own
# `secret_status` vocabulary, which the validator prompts tell a dismissal to
# cite - and the report gate refused every report that did. No digits: a
# password policy asks for one, so `hunter2-not` is still a password.
IDENTIFIER_WORDS = re.compile(
    r"(?:[a-z]+(?:[-_:.][a-z]+)+|[A-Z]+(?:[-_][A-Z]+)+|[a-z]+(?:[A-Z][a-z]+)+)\Z")

# The kinds only a reader that redacts in place acts on. The report gate and
# the ledger refuse the whole text on a hit, and leave these; the SARIF scrub
# and the arbitration records' scrub take them. See the block above.
REDACT_ONLY_KINDS = frozenset(("assign-word", "hex-table"))

# The last word of a secret-shaped name, when it says the value is something
# ABOUT the secret rather than the secret: `TOKEN_URL`, `PASSWORD_HASH_ALGO`,
# `AUTH_HEADER`, `passwd_file`, `API_KEY_ENV`, `tokenEndpoint`. Findings and
# remediations quote exactly these lines - a token endpoint over plain HTTP, a
# password hasher to move off - and none of their values is key material. The
# secret under a name like this is still found by the family and entropy
# detectors, which do not read the name at all. `secret_status`,
# `token_storage`, `token_endpoint_auth_method`, `passport_strategy`,
# `token_issuer` and the rest of the second half are the same thing: where a
# secret is kept, how it is sent, whose it is - `"google-oauth20"` has a digit
# and an issuer is a URL, so only the name says neither is a password.
SECRET_NAME_DESCRIPTORS = frozenset((
    "url", "uri", "endpoint", "host", "header", "name", "file", "filename", "path", "dir",
    "algo", "algorithm", "alg", "hasher", "hash", "type", "kind", "mode", "field", "param",
    "prompt", "label", "format", "env", "var", "len", "length", "prefix",
    "status", "storage", "method", "hint", "policy", "backend", "strategy",
    "issuer", "audience"))
NAME_PART_RE = re.compile(r"[_.\-]+|(?<=[a-z0-9])(?=[A-Z])")


def names_a_descriptor(name):
    """Is the last word of this secret-shaped name one saying what kind of thing it holds?"""
    parts = [p for p in NAME_PART_RE.split(name or "") if p]
    return len(parts) > 1 and parts[-1].lower() in SECRET_NAME_DESCRIPTORS


def quoted_value_kind(name, value):
    """The kind of `value`, quoted and assigned to the secret-shaped `name`.

    None when it is no secret at all: an interpolation, punctuation, or a
    value under a name that describes the secret rather than holding it
    (`TOKEN_URL = "http://..."`). "assign-word" when it reads as words - prose
    (`"Enter your password"`, the `"Bearer "` of an Authorization header), a
    short bare word (`token_type = "Bearer"`) or an identifier
    (`credentials: "same-origin"`, `secret_status: "in-inventory:public"`,
    IDENTIFIER_WORDS) - which is also how a passphrase and a dictionary
    password (`"changeme"`, `"correct-horse-battery"`) read: a reader that
    refuses a whole report on a hit leaves it, erring away from refusing a
    correct report, and a reader that redacts takes it, because LOG-005 flags
    exactly those values and a redaction costs nothing. "assign" otherwise.
    """
    if (TEMPLATED_VALUE.search(value) or not re.search(r"[A-Za-z0-9]", value)
            or names_a_descriptor(name)):
        return None
    if (re.search(r"\s", value) or (value.isalpha() and len(value) <= BARE_WORD_MAX)
            or IDENTIFIER_WORDS.match(value)):
        return "assign-word"
    return "assign"


def already_redacted(text):
    """An elision mark, and no fragment longer than a redaction keeps."""
    if not ELISION_MARK.search(text):
        return False
    return all(len(part) <= REDACTED_FRAGMENT_MAX for part in ELISION_MARK.split(text))


def _array_value(element):
    # int(e, 0) refuses a decimal with a leading zero, and `{08, 09}` is C.
    if element.startswith("'"):
        inner = element[1:-1]
        if inner[:2].lower() == "\\x":
            return int(inner[2:], 16)
        if CHAR_OCTAL_ESCAPE.match(inner):
            return int(inner[1:], 8)
        return ord(inner[-1])                          # a character, or `\n`
    return int(element, 16) if element[:2].lower() == "0x" else int(element, 10)


class UrlIndex:
    """The URLs in one text, found once, for url_path_run().

    export_spans asks which URL encloses each entropy run that carries a `/`,
    and asking URL_IN_TEXT from the start of the text every time made the
    report gate - which passes the whole of REPORT.md in one call - quadratic
    in the links it carries: 4000 permalinks took nineteen seconds. The
    matches are found on the first question and bisected after that. URL
    matches never overlap and come back in order, and a run is at least
    twenty characters, so the last URL starting at or before a run is the
    only one that can hold it. One index per text, never shared across
    calls: the SARIF scrub alone asks about thousands of different strings.
    """

    def __init__(self, text):
        self._text = text
        self._matches = None
        self._starts = None

    def enclosing(self, start, end):
        """The URL match holding text[start:end] whole, or None."""
        if self._matches is None:
            self._matches = list(URL_IN_TEXT.finditer(self._text))
            self._starts = [m.start() for m in self._matches]
        i = bisect.bisect_right(self._starts, start) - 1
        if i >= 0 and end <= self._matches[i].end():
            return self._matches[i]
        return None


def url_path_run(text, start, end, urls=None):
    """True when an entropy run is a URL's path and no segment of it is a key.

    `/` is in the secret alphabet, so `github.com/o/r/commit/<sha>` is ONE run
    from `com` to the end of the hash, and a path of words around a hash reads
    as random - a fix-commit URL, the most ordinary citation a report or a
    reason carries, was refused as key material. Inside a URL's PATH a `/`
    separates, so each segment is held to the test it would face on its own,
    with a digest excused where the segment before it says it is an object
    name: `/commit/<sha>`, `/blob/<sha>/`, `/-/commit/<sha>`, `/+/<sha>`
    (URL_CITATION_SEGMENTS), or where its host puts one (URL_CITATION_HOSTS).
    A digest anywhere else - the `/deliver/<64 hex>` of a webhook - is judged
    like any other segment, and a 40- or 64-hex one is long and random enough
    to fail it.

    Only inside the path. In the query a `/` is data - a base64 signature
    carries it - and splitting there cut `?sig=<base64 with slashes>` into
    pieces too short for the entropy test, so the whole signature was excused.
    And a digest-shaped value in the authority is not a git object: the user
    in `https://<40 hex>@github.com/` or `https://<40 hex>:x-oauth-basic@...`
    is a classic GitHub token, and excusing it as a commit let the token out.
    A run that reaches the query, or a digest segment before the path begins,
    is judged as one run, as it was before this existed. What is left is the
    price of reading `/commit/<sha>` and `/advisories/GHSA-...` as citations:
    a key that carries `/` itself - base64 - placed in a PATH is split like
    any path, and caught only where one piece is long enough to test; and a
    hex token placed right after a `commit` or `blob` segment reads as the
    object name it is dressed as.

    `urls` is export_spans' UrlIndex over the same text; without one, this
    builds its own.
    """
    run = text[start:end]
    if "/" not in run:
        return False
    url = (urls if urls is not None else UrlIndex(text)).enclosing(start, end)
    if url is None:
        return False
    authority = url.start() + url.group(0).index("://") + 3
    boundary = URL_AUTHORITY_END.search(text, authority, url.end())
    path_start = boundary.start() if boundary else url.end()
    query = URL_QUERY_START.search(text, path_start, url.end())
    if query and end > query.start():
        return False                                   # `/` is data in a query
    offset = start
    for segment in run.split("/"):
        segment_start, offset = offset, offset + len(segment) + 1
        if URL_DIGEST_SEGMENT.match(segment):
            if segment_start < path_start:
                return False                           # a token in the authority
            # Only the one segment right before it names the object - `commit`
            # in `/-/commit/<sha>`, `+` in `/+/<sha>` - and it is read from the
            # text between the path's start and this segment, not from the
            # run, so where the run happened to begin does not decide it.
            if segment_start > path_start and text[segment_start - 1] == "/":
                previous = text.rfind("/", path_start, segment_start - 1)
                if ((previous >= 0 and text[previous + 1:segment_start - 1].lower()
                     in URL_CITATION_SEGMENTS)
                        or URL_CITATION_HOSTS.get(text[authority:path_start].lower())
                        == text.count("/", path_start, segment_start)):
                    continue
        if any(True for _ in high_entropy_runs(segment, EXPORT_ENTROPY_THRESHOLD,
                                               EXPORT_ENTROPY_MIN_LENGTH)):
            return False
    return True


def export_spans(text):
    """[(start, end, kind)] of everything in `text` that may be key material.

    The one detector for text that leaves the machine; see the block above for
    who calls it. `kind` says which detector found the span - family, assign,
    assign-word, array, hex-bytes, hex-table or entropy - because only an
    entropy run can be a digest: a value assigned to `secret` is not excused
    for happening to be sixteen hex digits, and a reader that exempts digests
    exempts entropy spans only. A reader that refuses on a hit also leaves
    REDACT_ONLY_KINDS.

      family       a known token family (an AWS id, an `sk-` key, a `ghp_`
                   token, a URL password with or without a user), recognisable
                   by shape whatever its entropy. Where the family names its
                   `secret` part, that part is the span: the host after a URL
                   password is the context that says whether this is
                   production. Not when that part is an interpolation:
                   `redis://:${REDIS_PASSWORD}@redis` is how compose and k8s
                   say that no password is hardcoded;
      assign       a quoted value of six characters or more under a
                   secret-shaped name (LOG-005), whatever its entropy -
                   `password = "Winter2026Payroll"` has no family and no
                   high-entropy run;
      assign-word  the same, when the value reads as words - a phrase, one
                   short all-letter word, or an identifier (`same-origin`,
                   `in-inventory:public`) - which is also how a passphrase and
                   `"changeme"` read (quoted_value_kind);
      array        the body of a key or secret byte-array initialiser (HW-010),
                   where every byte is its own four-character run - a name
                   holding `key` only inside `keypad` or `hotkey` is none
                   (names_a_key);
      hex-bytes    eight or more `0xNN` bytes in a row, that array's
                   continuation lines quoted on their own;
      hex-table    the same run inside the initialiser of a name that is
                   neither a key's nor a secret's (names_a_secret) -
                   `dev_desc[18] = {0x12, 0x01, ...}`, `ELF_MAGIC[]`;
      entropy      a high-entropy run, unless it is a URL path whose every
                   segment is a word, or a digest right after a `commit`,
                   `blob`, `tree` or other citation segment (url_path_run).

    A span that is already redacted is not returned, from any detector: an
    elision mark with nothing either side of it longer than a redaction keeps.
    Overlapping spans are returned as found; a reader redacting them merges
    them (redact_spans).
    """
    if not isinstance(text, str) or not text:
        return []
    spans = []
    for _subkind, pattern in KNOWN_TOKEN_RE:
        group = "secret" if "secret" in pattern.groupindex else 0
        for m in pattern.finditer(text):
            if group and TEMPLATED_VALUE.search(m.group(group)):
                continue            # `redis://:${REDIS_PASSWORD}@host` reads an env var
            spans.append((m.start(group), m.end(group), "family"))
    for m in EXPORT_ASSIGN.finditer(text):
        kind = quoted_value_kind(m.group("name"), m.group("val"))
        if kind:
            spans.append((m.start("val"), m.end("val"), kind))
    for m in KEY_ARRAY_INIT.finditer(text):
        if not names_a_key(m.group("name")):
            continue                                   # `keypad_map`, `hotkeys`
        elements = ARRAY_ELEMENT.findall(m.group("body"))
        if (len(elements) >= KEY_ARRAY_MIN_ELEMENTS
                and any(_array_value(e) for e in elements)):
            spans.append((m.start("body"), m.end("body"), "array"))
    tables = [m.span("body") for m in NAMED_INIT.finditer(text)
              if not names_a_secret(m.group("name"))]
    table_starts = [start for start, _end in tables]
    for m in HEX_BYTE_RUN.finditer(text):
        i = bisect.bisect_right(table_starts, m.start()) - 1
        in_table = i >= 0 and m.end() <= tables[i][1]
        spans.append((m.start(), m.end(), "hex-table" if in_table else "hex-bytes"))
    urls = UrlIndex(text)
    for start, end, _run in high_entropy_runs(text, EXPORT_ENTROPY_THRESHOLD,
                                              EXPORT_ENTROPY_MIN_LENGTH):
        if not url_path_run(text, start, end, urls):
            spans.append((start, end, "entropy"))
    return [(start, end, kind) for start, end, kind in spans
            if end > start and not already_redacted(text[start:end])]


# --------------------------------------------------------------------------- #
# source families - where a secret ENTERS. Inventory, never findings.
# --------------------------------------------------------------------------- #

# (subkind, origin_hint, pattern). `origin_hint` is the contract §4a `origin`
# value this family suggests; it is a HINT and the agent may overrule it, because
# a `getenv` whose result is immediately run through HKDF is a `kdf` by the time
# it matters. The tool does not get a vote on that.
SOURCE_FAMILIES = (
    ("env-read", "env",
     r"\b(?:getenv|secure_getenv|os\.environ|environ\[|std::env::var|process\.env|"
     r"System\.getenv|ENV\[|Environment\.GetEnvironmentVariable|dotenv|"
     r"load_dotenv|viper\.GetString|os\.Getenv)\b"),

    ("key-store", "key-store",
     r"(?i)\b(?:secretsmanager|get_secret_value|SecretClient|KeyVault|azure\.keyvault|"
     r"hvac\.|vault(?:\.read|_client|\.kv)|keychain|SecItemCopyMatching|KeyStore|"
     r"keystore|gnome_keyring|libsecret|CryptUnprotectData|kms\.(?:decrypt|Decrypt)|"
     r"KmsClient|CloudKMS|parameter_store|ssm\.get_parameter|CredentialsProvider|"
     r"DefaultAzureCredential)\b"),

    ("kdf", "kdf",
     r"(?i)\b(?:PBKDF2[A-Za-z0-9_]*|pbkdf2_hmac|Rfc2898DeriveBytes|scrypt[A-Za-z0-9_]*|"
     r"argon2[a-z0-9_]*|bcrypt[A-Za-z0-9_]*|HKDF[A-Za-z0-9_]*|hkdf_(?:extract|expand)|"
     r"EVP_PKEY_derive|EVP_KDF_derive|mbedtls_hkdf[a-z_]*|mbedtls_pkcs5_pbkdf2[a-z_]*|"
     r"psa_key_derivation_[a-z_]+|crypto_pwhash[a-z_]*|derive_key|DeriveKey|"
     r"deriveBits|deriveKey|X963KDF|ConcatKDF)\b"),

    ("fuse-otp", "fuse-otp",
     r"(?i)\b(?:e_?fuse[a-z0-9_]*|esp_efuse_[a-z_]+|otp_(?:read|write|get|program)[a-z_]*|"
     r"read_otp|nvm_otp[a-z_]*|flash_read_unique_id|HAL_GetUIDw?[0-9]*|"
     r"chip_?id|device_?id|unique_?id|serial_?number|UID_BASE|DEVICE_UNIQUE[A-Z_]*|"
     r"hw_?unique_?key|OTP_[A-Z0-9_]+)\b"),

    ("key-file", "file",
     r"(?i)(?:PEM_read[A-Za-z_]*|d2i_[A-Za-z0-9_]*PrivateKey|load_pem_private_key|"
     r"X509_load[a-z_]*|SSL_CTX_use_PrivateKey_file|mbedtls_pk_parse_keyfile|"
     r"\b(?:open|fopen|read_file|readFileSync|File\.ReadAll(?:Bytes|Text))\s*\("
     r"[^)\n]{0,80}\.(?:pem|key|p12|pfx|jks|keystore|crt|der)\b)"),
)

SOURCE_RE = [(sub, hint, re.compile(pat)) for sub, hint, pat in SOURCE_FAMILIES]

# `wire` and `derived` have no family here on purpose. A value that arrived from
# the network or fell out of an AEAD has no distinctive spelling - `buf`, `tmp`
# and `expected` are exactly the names §4a says the name-matching rules miss. A
# regex family for them would be a regex for every buffer in the tree. The agent
# assigns those origins from context, and `check` holds them to the same
# discipline as every other non-literal origin: inventory, never a finding.


# --------------------------------------------------------------------------- #
# the file walk - the tree is attacker-supplied
# --------------------------------------------------------------------------- #

DEFAULT_MAX_FILE_BYTES = 2_000_000

# Directories skipped by default. `vendor/` and `third_party/` are NOT here: a
# vendored `.pem` committed by mistake is a real finding, and the habit of
# excluding your way to a quiet report is the habit this skill is written
# against.
DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".gradle",
    ".security-review", ".golden-cache",
)

# The high-entropy family, and only it, is switched off for these. A lockfile is
# a wall of base64 integrity hashes: `package-lock.json` alone contributes
# thousands of runs over the threshold, none of them secret, and a candidate list
# nobody can read is a candidate list nobody reads. The literal families with
# real prefixes still run over them, because an `ghp_` token pasted into a
# lockfile is still a token.
ENTROPY_SKIP_GLOBS = (
    "*.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock",
    "composer.lock", "Gemfile.lock", "poetry.lock", "go.sum", "*.sum",
    "*.min.js", "*.min.css", "*.map", "*.snap", "*.pot", "*.po",
)

MAX_LINE_CHARS = 400


def is_excluded(rel, patterns):
    parts = rel.replace("\\", "/").split("/")
    for pat in patterns:
        clean = pat.rstrip("/")
        if not clean:
            continue
        if clean in parts:
            return True
        if rel == clean or rel.startswith(clean + "/"):
            return True
        if any(fnmatch.fnmatch(part, clean) for part in parts):
            return True
    return False


def entropy_skipped(rel):
    base = os.path.basename(rel)
    return any(fnmatch.fnmatch(base, g) for g in ENTROPY_SKIP_GLOBS)


def read_text(path, max_bytes):
    """(lines, truncated) or (None, False) for binary and unreadable files.

    Reading max_bytes + 1 is how we learn the file was over the cap rather than
    exactly at it, and the tail is dropped at the last newline so the last line
    handed to a pattern is a whole line. A half line is a match that cannot be
    cited.
    """
    # A cap on how much is read is not a cap on how long the read takes. `open()`
    # on a FIFO blocks until somebody writes, and a named pipe committed to the
    # tree under review - the tree is attacker-supplied - stops the sweep dead
    # before a single byte counts against max_bytes. A device node is the same
    # argument with a different ending. Only regular files are opened.
    try:
        if not os.path.isfile(path):
            return None, False
    except OSError:
        return None, False
    try:
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes + 1)
    except OSError:
        return None, False
    if b"\x00" in raw[:8192]:
        return None, False
    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]
        cut = raw.rfind(b"\n")
        if cut > 0:
            raw = raw[:cut]
    return source_lines(raw), truncated


def source_lines(raw):
    """The decoded lines of a scanned file, numbered the way stage 1 numbers them.

    Stage 1 splits on "\\n" and nothing else (extract_functions: `text.split
    ("\\n")`, phantom last element dropped), and so do grep, rg, gitleaks and
    trufflehog. `str.splitlines()`, which this used, ALSO breaks on \\f, \\v,
    \\x1c-\\x1e, \\x85, U+2028, U+2029 and a lone \\r - so one page break above a
    secret moved every number below it. A password inside login() at line 13
    was cited at line 18 of a 15-line file with function_key null, a gitleaks
    hit at the true line corroborated nothing and became a second candidate
    quoting the wrong line, and `check` refused an entry citing line 13.

    A trailing "\\r" is still taken off each line, so a CRLF file reads exactly
    as it did: only the numbering moved, and only where the two disagree.
    A copy rather than an import, because stage 1 keeps its split inline; the
    selftest pins a candidate's line to the "\\n" count on a file full of the
    characters the two used to disagree about.
    """
    lines = raw.decode("utf-8", errors="replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def escapes_tree(root, path):
    """Does this path on disk resolve outside the tree under review?

    `os.walk` does not descend into a symlinked directory, but it does hand back
    a symlinked FILE, and `open()` follows it. A `notes.txt -> /root/.ssh/id_rsa`  # check-skills: allow-path
    committed to the repository made this tool read that key and publish a line
    of it into `candidates.json` under the name `notes.txt` - a file outside the
    scanned root, read and quoted, with nothing in the record saying so. The
    scanned tree is attacker-supplied; a name in it is not permission to open
    whatever it points at.
    """
    real_base = os.path.realpath(root)
    real_target = os.path.realpath(path)
    return real_target != real_base and \
        not real_target.startswith(real_base + os.sep)


def iter_files(root, excludes, max_bytes, tooling=None):
    """Every readable text file under `root`, as (rel, lines, truncated).

    Symlinks out of the tree are skipped, not read: see `escapes_tree`. The
    scanner's own folders are skipped by identity (rules_lib.is_tooling_dir): this
    installed skill carries a fixture with credentials planted for LOG-005, the
    validator corpus and the rule tables, and a project install puts all of that
    inside the tree being swept. `tooling`, when given, is a list that receives a
    (path, reason) pair for each folder skipped on those grounds, so the caller can
    record it: a folder that is left out of the sweep is never left out silently.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        rules_lib.prune_tooling(root, dirpath, dirnames, tooling)
        dirnames[:] = sorted(
            d for d in dirnames
            if not is_excluded((rel_dir + "/" + d).lstrip("/"), excludes))
        for name in sorted(filenames):
            rel = (rel_dir + "/" + name).lstrip("/")
            if is_excluded(rel, excludes):
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full) and escapes_tree(root, full):
                continue
            lines, truncated = read_text(full, max_bytes)
            if lines is None:
                continue
            yield rel, lines, truncated


# --------------------------------------------------------------------------- #
# the candidates pass
# --------------------------------------------------------------------------- #

# What stands between a name and the value assigned to it, and the name itself.
# The quote characters belong in the FIRST of these: without them `AWS = "AKIA…"`
# leaves `AWS = "` for the name pattern to match, which it cannot reach the end
# of, and every candidate came back with no identifier at all.
#
# Both are anchored at the end and are only ever asked for the tail of the
# text, through tail_search() - never search() or sub() on the whole of it.
ASSIGN_GLUE_CHARS = r"\s\"'=:<>|,(\[{+"
ASSIGN_GLUE = re.compile(r"[%s]+$" % ASSIGN_GLUE_CHARS)
ASSIGN_GLUE_RUN = re.compile(r"[%s]*" % ASSIGN_GLUE_CHARS)
IDENT_CHARS = r"A-Za-z0-9_.$\[\]"
IDENT_LEFT = re.compile(r"[A-Za-z_][%s]*$" % IDENT_CHARS)
IDENT_RUN = re.compile(r"[%s]*" % IDENT_CHARS)


def tail_search(pattern, run, text):
    """pattern.search(text), in time linear in the text.

    `pattern` is anchored at the end with `$` and every character it matches
    is one `run` matches, so any match lies inside the run of those characters
    that ends the text. search() does not know that. It tries every start, and
    from a start inside an EARLIER run the loop reads to the end of that run
    and gives it back one character at a time before failing: quadratic in the
    run. The ML-DSA vectors in MbedTLS's .data files put two 9,000-digit hex
    runs on one line, and naming the hit after the second read the first that
    way - 5 of the file's 6 seconds, and hours on a million-character line.

    So the search starts where the final run does, found by matching `run`
    over the reversed text. `$` also matches just before a final newline, so
    the run ending there is a candidate too, and the earlier of the two starts
    is where the leftmost match can be.
    """
    start = len(text) - run.match(text[::-1]).end()
    if text.endswith("\n"):
        start = min(start, len(text) - 1 - run.match(text[-2::-1]).end())
    return pattern.search(text, start)

# Most specific family wins when several match the same literal on the same line,
# so the agent sees one candidate carrying every family that fired rather than
# four candidates that are the same secret.
FAMILY_PRIORITY = {
    "pem-private-key": 0,
    "known-token": 1,
    "secret-assignment": 2,
    "env-assignment": 2,
    "sarif": 3,
    "high-entropy": 4,
}


def identifier_left_of(line, pos, threshold=DEFAULT_ENTROPY_THRESHOLD, spans=(),
                       same=()):
    """The name being assigned to, read leftwards from a match.

    Returns None when what is to the left is itself key material. On

        PAIR = ("AKIAIOSFODNN7EXAMPLE", "glpat-x7Kq2mB9nR4tL1vW8pZ0")

    the name to the left of the second secret is the FIRST one, and `identifier`
    is not a field redaction would otherwise reach - so a line with two secrets
    on it would have published one of them in full, in the field nobody thinks
    to check.

    Or when it overlaps one of `spans`, the literals the families found on the
    line: entropy does not recognise `hunter2hunter2`, so on
    `password="hunter2hunter2" + os.environ["X"]` the env read's identifier
    was the password, whole, beside a line_text that had it redacted.

    Except a span in `same`: an entropy run over the literal this match IS.
    `=` and `_` are in the secret alphabet, so `GH=ghp_…` and `k=AKIA…` are one
    run each, name included, and refusing on that run dropped the name - or,
    once the entropy candidate's own identifier was merged in, named the
    `const` in `const k=AKIA…` instead. The name still counts only when glue
    separates it from the match; glued straight on, it is the head of the same
    blob (`…EFD48B2ASK…`, a twilio match inside a hex vector).
    """
    head = line[:pos]
    glue = tail_search(ASSIGN_GLUE, ASSIGN_GLUE_RUN, head)
    if glue:
        head = head[:glue.start()] + head[glue.end():]
    match = tail_search(IDENT_LEFT, IDENT_RUN, head)
    if not match:
        return None
    name = match.group(0)
    if looks_like_key_material(name, threshold, LEAK_MIN_RUN):
        return None
    separated = match.end() < pos
    if any(overlaps(match.span(), span)
           and not (separated and span in same) for span in spans):
        return None
    return name


# What may precede a matched name stem and still be part of the same identifier.
# `.` and `-` are in it because `db.password` and `db-password` are one name in
# a .properties file and in a k8s manifest respectively.
# End-anchored like IDENT_LEFT, and asked through tail_search() for the same
# reason.
NAME_PREFIX_CHARS = r"A-Za-z0-9_.\-$"
NAME_PREFIX = re.compile(r"[A-Za-z_][%s]*$" % NAME_PREFIX_CHARS)
NAME_PREFIX_RUN = re.compile(r"[%s]*" % NAME_PREFIX_CHARS)

# An identifier longer than this is not an identifier. `identifier` is one of the
# few fields redaction does not reach, so it is bounded on the way out.
MAX_IDENT_CHARS = 128


def whole_identifier(line, name_start, name, threshold=DEFAULT_ENTROPY_THRESHOLD):
    """The identifier SECRET_ASSIGN's `name` group is the TAIL of.

    That pattern is anchored on a stem - `secret`, `token`, `key` - plus `\\w*`,
    so it matches from the stem rightwards and the words to its LEFT are not in
    the group. On

        PEER_CERT_DIGEST_SECRET = "3b1f…eff0"

    `name` is `SECRET`, and `SECRET` is what the candidate carried to the agent
    judging it. The dropped words are `PEER`, `CERT` and `DIGEST` - which is to
    say, the whole of the evidence that this value is one the attacker already
    holds. §4a exists because `references/tuning.md` measured this rule calling certificate
    digests secret; handing the sweeper the one word that makes it look like a
    key, with the three that say otherwise removed, is that failure built into
    the candidate list.

    Bounded, and dropped if what it picks up is itself key material: this field
    is not redacted.
    """
    match = tail_search(NAME_PREFIX, NAME_PREFIX_RUN, line[:name_start])
    if not match:
        return name
    prefix = match.group(0)
    if len(prefix) + len(name) > MAX_IDENT_CHARS:
        return name
    if looks_like_key_material(prefix, threshold, LEAK_MIN_RUN):
        return name
    return prefix + name


def clip(text):
    if len(text) <= MAX_LINE_CHARS:
        return text, False
    return text[:MAX_LINE_CHARS], True


def make_literal_candidate(rel, lineno, line, subkind, literal, span, salt,
                           threshold, identifier=None, extra=None, others=()):
    """One literal candidate, redacted on the way out.

    Redaction happens twice and the order matters. The spans are redacted
    first, on the full line, because we know exactly which characters are
    secret: this candidate's own, and `others` - every other literal the
    families found on the same line. The line is then clipped to MAX_LINE_CHARS
    and scrubbed, which catches whatever no family spelled.

    `others` exists because scrub() is an ENTROPY test. It used to be the only
    thing standing between a candidate's line_text and the second secret on
    that line, and a low-entropy password is not key material by that test:
    on `connect(password="hunter2hunter2", backup_password="letmein12345")`
    each of the two candidates carried the other password whole. An `other`
    that overlaps this candidate's own span is the same secret described twice
    and is left to the own span, which is what keeps a basic-auth URL's host
    visible inside the assignment that holds it.
    """
    spans = ([span] if span else []) + [
        o for o in others if not (span and overlaps(o, span))]
    shown, truncated = clip(redact_spans(line, spans))
    shown = scrub(shown, threshold)
    record = {
        "candidate_id": None,
        "kind": "literal",
        "subkind": subkind,
        "file": rel,
        "line": lineno,
        "column": (span[0] + 1) if span else None,
        "line_text": shown.rstrip(),
        "line_text_truncated": truncated,
        "redacted": redact(literal),
        "literal_length": len(literal),
        "fingerprint": fingerprint(literal, salt),
        "identifier": identifier,
        "also_matched": [],
        "corroborated_by": [],
    }
    if extra:
        record.update(extra)
    return record


def fingerprint(literal, salt):
    """A correlation id for one secret, good only inside this one file.

    Ten copies of the same key in ten files should be one inventory entry, and
    the agent needs to see that they are the same without being shown the value.
    The salt is generated per run and is NEVER written to disk, so the digest
    correlates entries inside this candidates.json and confirms nothing to
    anybody who reads it later - which an unsalted digest of a weak password
    would, since a dictionary can be hashed as easily as it can be tried.
    """
    return hashlib.sha256((salt + "\x00" + literal).encode("utf-8")).hexdigest()[:12]


def literal_hits(rel, line, threshold, min_length, skip_entropy, is_config=None,
                 quiet=None):
    """Every literal the families find on one line, before anything is emitted.

    Each is (subkind, literal, span, identifier, extra). Gathered first because
    every candidate on the line needs every OTHER literal's span to redact its
    own line_text by (make_literal_candidate), and so does a source candidate
    on the same line. One definition, also, for `check`, which reads the
    literals back off the line an entry cites (line_literals): the two halves
    cannot disagree about what a literal on a line is.

    `quiet` is a span whose high-entropy runs are not reported: the body of a
    PEM written on its own BEGIN line, which the PEM candidate already stands
    for - a 2048-bit key was otherwise also 26 unrelated entropy candidates.
    """
    if is_config is None:
        is_config = config_file(rel)
    hits = []
    # Hits whose identifier is read leftwards, and from where. Read once every
    # span is known, so no hit is named after another hit's literal.
    left_of = {}

    # ---- known token families
    for subkind, pattern in KNOWN_TOKEN_RE:
        for match in pattern.finditer(line):
            group = "secret" if "secret" in pattern.groupindex else 0
            # The password of `redis://:${REDIS_PASSWORD}@redis` is an env
            # read, as `password = "${DB_PASS}"` is below. Only the named part
            # is tested: a templated host or user excuses nothing.
            if group and TEMPLATED_VALUE.search(match.group(group)):
                continue
            left_of[len(hits)] = match.start()
            hits.append((subkind, match.group(group), match.span(group), None,
                         {"family": "known-token"}))

    # ---- a long literal assigned to a secret-ish name
    for match in SECRET_ASSIGN.finditer(line):
        value = match.group("val")
        if TEMPLATED_VALUE.search(value):
            continue
        hits.append(("secret-assignment", value, match.span("val"),
                     whole_identifier(line, match.start("name"),
                                      match.group("name"), threshold),
                     {"family": "secret-assignment"}))

    env = ENV_ASSIGN.match(line) if is_config else None
    if env and ENV_SECRET_NAME.search(env.group("name")) \
            and not EXPRESSION_VALUE.search(env.group("val")):
        start, end = env.span("val")
        # The span and the value have to be the same characters, or the line
        # gets redacted somewhere other than where the secret is. A quoted
        # value gives up its quotes from BOTH, together.
        if line[start] in "\"'" and end - start >= 2 and line[end - 1] == line[start]:
            start, end = start + 1, end - 1
        value = line[start:end]
        if value and not TEMPLATED_VALUE.search(value):
            hits.append(("env-assignment", value, (start, end), env.group("name"),
                         {"family": "secret-assignment"}))

    # ---- high entropy
    if not skip_entropy:
        for start, end, run in high_entropy_runs(line, threshold, min_length):
            if quiet and overlaps((start, end), quiet):
                continue
            left_of[len(hits)] = start
            hits.append(("high-entropy", run, (start, end), None,
                         {"family": "high-entropy",
                          "entropy": round(shannon(run), 3),
                          "entropy_threshold": threshold}))

    spans = [hit[2] for hit in hits]
    for index, pos in left_of.items():
        subkind, literal, span, _none, extra = hits[index]
        same = [hit[2] for hit in hits
                if hit[0] == "high-entropy" and overlaps(hit[2], span)]
        hits[index] = (subkind, literal, span,
                       identifier_left_of(line, pos, threshold, spans, same), extra)
    return hits


def line_literals(rel, line):
    """The literal VALUES this tool's own families find on one line.

    What `check` holds an entry's `redacted` and `evidence.code` against,
    beside the entropy test. Entropy says nothing about `hunter2hunter2`, and
    that - the most common hardcoded secret there is - went through `check`
    whole in both fields and was printed by `status`. The families spell it,
    so the literal is known exactly, and containing it whole is the leak.
    High entropy is left to leaked_runs(), which already covers it; values
    under four characters are too short to be anything but noise here.

    Returned as (literal, allowance) pairs, compared after vf.norm(). The
    allowance is how often the literal is on the line with every literal
    redacted: on `password = "password"` the NAME is the value, and a quote
    cannot show the line without it. Plain containment refused every quote of
    that line, `password = "pa…rd"` and `password = "` included, so the one
    shape of hardcoded password a checker most needs to pass was the one no
    sweeper could get through it. The leak is holding it more often than that.
    """
    hits = [hit for hit in literal_hits(rel, line, DEFAULT_ENTROPY_THRESHOLD,
                                        DEFAULT_ENTROPY_MIN_LENGTH, True)
            if len(vf.norm(hit[1])) >= 4]
    safe = vf.norm(redact_spans(line, [hit[2] for hit in hits]))
    return [(vf.norm(hit[1]), safe.count(vf.norm(hit[1]))) for hit in hits]


def pem_same_line_body(line, begin):
    """A body written on the BEGIN line itself, split on escaped newlines.

    Returns (body pieces, span of the body on the line or None, terminated).
    A service-account JSON, or `var k = "-----BEGIN...\\nMII...\\n-----END..."`,
    carries the whole key on one line; walking the lines BELOW found nothing
    and reported a real key as a mention.
    """
    tail_start = begin.end()
    tail = line[tail_start:]
    seps = list(ESCAPED_NEWLINE.finditer(tail))
    body, body_end = [], None
    for index, sep in enumerate(seps):
        start = sep.end()
        end = seps[index + 1].start() if index + 1 < len(seps) else len(tail)
        piece = tail[start:end]
        if PEM_END.search(piece):
            span = (tail_start, tail_start + sep.start())
            return body, (span if span[0] < span[1] else None), True
        if not (PEM_BODY_LINE.match(piece) or PEM_HEADER_LINE.match(piece)):
            break
        body.append(piece.strip())
        body_end = end
    if not any(body):
        return [], None, False
    return body, (tail_start, tail_start + body_end), False


def scan_file(rel, lines, threshold, min_length, salt, skip_entropy):
    """Every candidate in one file."""
    out = []
    pem_body = set()
    pem_quiet = {}
    is_config = config_file(rel)
    cache = {}

    def hits_on(idx):
        if idx not in cache:
            cache[idx] = literal_hits(rel, lines[idx], threshold, min_length,
                                      skip_entropy, is_config, pem_quiet.get(idx))
        return cache[idx]

    # ---- PEM blocks, first, so their base64 body is not re-found as entropy.
    for idx, line in enumerate(lines):
        begin = PEM_BEGIN.search(line)
        if not begin:
            continue
        kind = (begin.group(1) or "").strip().lower() or "generic"
        body, own, terminated = pem_same_line_body(line, begin)
        end_idx = idx if terminated else None
        if own:
            pem_quiet[idx] = own
        # The lines below: plain base64, or - when the marker is itself inside
        # a string literal - base64 inside a string literal on each line.
        wrapped = bool(PEM_WRAPPED_BEGIN.match(line[begin.end():]))
        if not terminated and (wrapped or not body):
            for probe in range(idx + 1,
                               min(len(lines), idx + 1 + PEM_MAX_BODY_LINES)):
                text = lines[probe]
                if PEM_END.search(text):
                    pem_body.add(probe)
                    end_idx = probe
                    break
                if wrapped:
                    literal = PEM_STRING_LINE.match(text)
                    if not literal:
                        break
                    text = literal.group("b")
                if not (PEM_BODY_LINE.match(text) or PEM_HEADER_LINE.match(text)):
                    break
                pem_body.add(probe)
                body.append(text.strip())
        joined = "".join(body)
        # The body written on this line is redacted, and so is every other
        # literal on it - except one that overlaps the marker, which is the
        # key's own string described again: the marker is what this record is
        # cited by, and it is not secret.
        marker = begin.span()
        spans = ([own] if own else []) + [
            hit[2] for hit in hits_on(idx)
            if not overlaps(hit[2], marker) and not (own and overlaps(hit[2], own))]
        shown, truncated = clip(redact_spans(line, spans).strip())
        out.append({
            "candidate_id": None,
            "kind": "literal",
            "subkind": "pem-private-key",
            "family": "pem-private-key",
            "file": rel,
            "line": idx + 1,
            "column": None,
            "line_text": scrub(shown, threshold),
            "line_text_truncated": truncated,
            "redacted": redact(joined),
            "literal_length": len(joined),
            "fingerprint": fingerprint(joined, salt) if joined else None,
            "identifier": None,
            "pem_kind": kind,
            "pem_body_lines": len(body),
            "pem_terminated": end_idx is not None,
            "also_matched": [],
            "corroborated_by": [],
        })

    for idx, raw in enumerate(lines):
        lineno = idx + 1
        if idx in pem_body:
            continue
        line = raw

        # ---- the literal families, gathered before any is emitted: each
        # candidate's line_text is redacted by every OTHER literal's span too.
        hits = hits_on(idx)
        spans = [hit[2] for hit in hits]
        for subkind, literal, span, identifier, extra in hits:
            out.append(make_literal_candidate(
                rel, lineno, line, subkind, literal, span, salt, threshold,
                identifier=identifier, extra=extra, others=spans))

        # ---- source families: where a secret ENTERS. Inventory, not findings.
        for subkind, hint, pattern in SOURCE_RE:
            match = pattern.search(line)
            if not match:
                continue
            # Redacted BEFORE strip(), which would shift every offset. A literal
            # on the line an env read is on used to go out whole here: this
            # record is not about the literal, and scrub() alone does not
            # recognise a low-entropy one.
            shown, truncated = clip(redact_spans(line, spans).strip())
            matched = redact_spans(match.group(0),
                                   spans_within(spans, match.start(), match.end()))
            out.append({
                "candidate_id": None,
                "kind": "source",
                "subkind": subkind,
                "origin_hint": hint,
                "file": rel,
                "line": lineno,
                "line_text": scrub(shown, threshold),
                "line_text_truncated": truncated,
                "matched": scrub(matched[:80], threshold),
                "identifier": identifier_left_of(line, match.start(), threshold,
                                                 spans),
                "corroborated_by": [],
                "note": "a source, not a finding: contract 4a makes is_finding "
                        "true only for kind=secret with origin=literal",
            })

    return out


def family_rank(cand):
    """How specific a candidate's family is. Lower wins.

    Ranked on `family`, never on `subkind`: the table is keyed by family, and
    `.get("aws-access-key-id", 9)` on a table that says `known-token` returns the
    default, which made the generic entropy match outrank the AWS pattern and
    hid every prefixed token behind "high-entropy".
    """
    return FAMILY_PRIORITY.get(cand.get("family") or cand.get("subkind"), 9)


def literal_span(cand):
    """(start, end) of the matched literal on its line, or None.

    Derived rather than stored: `column` and `literal_length` are both emitted
    for the agent anyway, and a third field that has to agree with them is a
    third field that can stop agreeing with them.
    """
    column = cand.get("column")
    length = cand.get("literal_length")
    if not isinstance(column, int) or not isinstance(length, int):
        return None
    return column - 1, column - 1 + length


def absorb(winner, loser):
    for name in [loser["subkind"]] + list(loser.get("also_matched") or []):
        if name != winner["subkind"] and name not in winner["also_matched"]:
            winner["also_matched"].append(name)
    for corr in loser.get("corroborated_by") or []:
        if corr not in winner["corroborated_by"]:
            winner["corroborated_by"].append(corr)
    if not winner.get("identifier"):
        winner["identifier"] = loser.get("identifier")
    # The loser may hold a measurement the winner's family does not take.
    for field in ("entropy", "entropy_threshold", "pem_kind", "pem_body_lines",
                  "pem_terminated"):
        if field in loser and field not in winner:
            winner[field] = loser[field]


def merge_literals(candidates):
    """One candidate per secret, carrying every family that fired on it.

    A hardcoded AWS key matches the AWS pattern AND the entropy family AND, if it
    is assigned to something called `key`, the assignment family; in a `.env`
    file the entropy family additionally matches the whole `NAME=value` line,
    because `=` and `_` are both in the secret alphabet. Four candidates for one
    secret is four times the reading for none of the signal.

    Overlap on the line is what identifies "one secret", not equality of the
    matched text: the assignment family matches the value and the entropy family
    matches the line around it, and those are the same secret described twice.
    The most specific family wins, and on a tie the narrower span does - the
    value is the secret, the line merely contains it.
    """
    by_line = {}
    for position, cand in enumerate(candidates):
        if cand["kind"] == "literal":
            by_line.setdefault((cand["file"], cand["line"]), []).append(position)

    dropped = set()
    for positions in by_line.values():
        ranked = sorted(positions,
                        key=lambda i: (family_rank(candidates[i]),
                                       candidates[i].get("literal_length") or 0,
                                       candidates[i].get("column") or 0))
        kept = []
        for index in ranked:
            cand = candidates[index]
            span = literal_span(cand)
            if span is None:
                kept.append((None, cand))
                continue
            overlapping = next(
                (other for other_span, other in kept
                 if other_span and span[0] < other_span[1] and other_span[0] < span[1]),
                None)
            if overlapping is None:
                kept.append((span, cand))
            else:
                absorb(overlapping, cand)
                dropped.add(index)

    return [cand for position, cand in enumerate(candidates)
            if position not in dropped]


# --------------------------------------------------------------------------- #
# SARIF ingest - gitleaks and trufflehog, folded in as corroboration
# --------------------------------------------------------------------------- #

class SweepError(Exception):
    def __init__(self, message, code=EXIT_USAGE):
        Exception.__init__(self, message)
        self.code = code


SECRET_SCANNERS = ("gitleaks", "trufflehog", "detect-secrets", "ggshield",
                   "noseyparker", "secretscanner")


def driver_analyzer(name):
    """Contract §7 identifies an analyzer from tool.driver.name, and so do we.

    An unrecognised driver keeps its own name rather than becoming "other": the
    record's whole job is to say WHOSE second opinion this is, and a
    `corroborated_by` that says "other" corroborates nothing.

    Both sides lose their separators before they are compared. Only the
    driver's used to, so `detect-secrets` - the one known name with a hyphen in
    it - was looked for in `detectsecrets` and never found: a driver named
    `detect-secrets` or `Detect Secrets` came out as an unrecognised label.
    enrich_candidates.py compares the same way, over the same six names.
    """
    key = re.sub(r"[\s_-]+", "", (name or "").strip().lower())
    for known in SECRET_SCANNERS:
        if known.replace("-", "") in key:
            return known
    return clean_label(name, 60) or "unknown"


def sarif_uri(location, root):
    physical = (location.get("physicalLocation") or {}) if location else {}
    uri = ((physical.get("artifactLocation") or {}).get("uri") or "")
    uri = uri.replace("\\", "/")
    if uri.startswith("file://"):
        uri = uri[len("file://"):]
    if os.path.isabs(uri):
        try:
            uri = os.path.relpath(uri, root).replace(os.sep, "/")
        except ValueError:
            pass
    # `lstrip("./")` here would eat the leading dot of `.env` and `.npmrc`, which
    # are two of the files a secrets scanner most often has something to say
    # about, and the candidate would then cite a path that is not in the tree.
    while uri.startswith("./"):
        uri = uri[2:]
    return uri


def clean_label(text, limit):
    """A short, printable label out of an analyzer's own output.

    Every string in a SARIF file was written by a tool that read the repository
    under audit, so control characters and a megabyte of "rule id" are both
    things that can arrive here.
    """
    text = "".join(ch for ch in str(text or "") if ch.isprintable())
    return text.strip()[:limit]


def name_on_line(line):
    """The name assigned to on this line, from the assignment patterns.

    Reading leftwards from the end of the line - which is all there is to go on
    when the match came from somebody else's tool - returns the LAST word on it,
    and a candidate whose `identifier` is the last word of an unrelated sentence
    is worse than one with no identifier at all.
    """
    match = SECRET_ASSIGN.search(line or "")
    if match:
        return match.group("name")
    match = ENV_ASSIGN.match(line or "")
    return match.group("name") if match else None


def parse_sarif(path, root):
    """Normalised secret findings from one SARIF 2.1.0 file.

    A file that will not parse is a refusal, not a warning - the same call
    `enrich_candidates.py` makes, for the same reason: an analyzer somebody ran,
    whose output this tool silently read as zero findings, produces a candidate
    list with no corroboration in it and nothing that says why.
    """
    try:
        if os.path.getsize(path) > MAX_JSON_BYTES:
            raise SweepError("%s: SARIF file is over the %d-byte cap"
                             % (path, MAX_JSON_BYTES))
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        raise SweepError("%s: not readable as SARIF (%s)" % (path, exc))
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise SweepError(
            "%s: not SARIF - no `runs` array. Point --sarif at the file the "
            "scanner wrote with its SARIF formatter, not at its console output."
            % path)

    findings = []
    for run in doc["runs"]:
        if not isinstance(run, dict):
            continue
        driver = ((run.get("tool") or {}).get("driver") or {})
        analyzer = driver_analyzer(driver.get("name"))
        version = driver.get("version") or driver.get("semanticVersion")
        for result in (run.get("results") or []):
            if not isinstance(result, dict):
                continue
            rule = clean_label(result.get("ruleId")
                               or (result.get("rule") or {}).get("id") or "", 200)
            locations = result.get("locations") or []
            location = locations[0] if locations else {}
            region = ((location.get("physicalLocation") or {}).get("region")) or {}
            line = region.get("startLine")
            snippet = ((region.get("snippet") or {}).get("text") or "").strip()
            findings.append({
                "analyzer": analyzer,
                "analyzer_version": version,
                "rule": rule,
                "file": sarif_uri(location, root),
                "line": line if isinstance(line, int) else None,
                "snippet": snippet,
                "message": ((result.get("message") or {}).get("text") or "")[:200],
                "sarif_file": os.path.basename(path),
            })
    return findings


def fold_sarif(candidates, findings, root, threshold, min_length, salt,
               max_bytes):
    """Fold each SARIF finding in: corroboration where we already looked, a new
    literal candidate where we did not.

    Both directions matter. Corroboration is the cheap half - gitleaks agreeing
    with our own `known-token` hit is a strong prior for the agent. The other
    half is why §7 calls these analyzers INDEPENDENT: a credential in a YAML file
    that no pattern here spells is a finding a function-scoped ruleset
    structurally cannot reach, and dropping it because we did not find it first
    would hold an independent signal to a restriction written about a different
    one.
    """
    by_place = {}
    for cand in candidates:
        if cand["kind"] == "literal":
            by_place.setdefault((cand["file"], cand["line"]), []).append(cand)

    added = 0
    for found in findings:
        corr = {"analyzer": found["analyzer"], "rule": found["rule"]}
        if found.get("analyzer_version"):
            corr["analyzer_version"] = found["analyzer_version"]
        existing = by_place.get((found["file"], found["line"])) or []
        if existing:
            for cand in existing:
                if corr not in cand["corroborated_by"]:
                    cand["corroborated_by"].append(corr)
            continue

        # Nothing of ours at that line. Build the candidate from the file when we
        # can read it, so the agent gets real context, and from the scanner's own
        # snippet when we cannot.
        #
        # `found["file"]` came out of a SARIF file written by a tool that read
        # the repository under audit: it is input, not a path this tool may
        # open. A run with `"uri": "/etc/shadow"` made this read line 2 of a
        # file outside the scanned tree and publish its text into
        # candidates.json. The analyzer's own snippet is still folded in - §7's
        # independent signal survives - but the path is not followed.
        line_text = ""
        outside = bool(found["file"]) and escapes_root(root, found["file"])
        if found["file"] and found["line"] and not outside:
            lines, _ = read_text(os.path.join(root, found["file"]), max_bytes)
            if lines and 1 <= found["line"] <= len(lines):
                line_text = lines[found["line"] - 1]
        if not line_text:
            line_text = found["snippet"]
        shown, truncated = clip(line_text.strip())
        literal = ""
        for _, _, run in high_entropy_runs(line_text, threshold, LEAK_MIN_RUN):
            if len(run) > len(literal):
                literal = run
        candidates.append({
            "candidate_id": None,
            "kind": "literal",
            "subkind": "sarif",
            "family": "sarif",
            "file": found["file"],
            "line": found["line"],
            "column": None,
            "line_text": scrub(shown, threshold),
            "line_text_truncated": truncated,
            "redacted": redact(literal) if literal else None,
            "literal_length": len(literal) or None,
            "fingerprint": fingerprint(literal, salt) if literal else None,
            "identifier": name_on_line(line_text),
            "also_matched": [],
            "corroborated_by": [corr],
            "analyzer_message": scrub(found["message"], threshold),
            "cited_path_outside_root": outside,
            "note": ("found by %s at a path OUTSIDE the scanned root; the path "
                     "was not followed and this line is the analyzer's own "
                     "snippet, not text read from disk" % found["analyzer"])
                    if outside else
                    ("found by %s, not by this tool's patterns"
                     % found["analyzer"]),
        })
        added += 1
    return added


def collect_sarif_paths(args):
    paths = list(args.sarif or [])
    for directory in (args.sarif_dir or []):
        if not os.path.isdir(directory):
            raise SweepError("--sarif-dir %s is not a directory" % directory)
        for name in sorted(os.listdir(directory)):
            if name.endswith(".sarif") or name.endswith(".sarif.json"):
                paths.append(os.path.join(directory, name))
    return paths


# --------------------------------------------------------------------------- #
# run-directory plumbing
# --------------------------------------------------------------------------- #

def run_dir(root):
    return os.path.join(root, RUN_DIR)


def secrets_dir(root):
    return os.path.join(run_dir(root), SECRETS_DIR)


def run_dir_problem(root, targets=()):
    """Why the run directory cannot be written to as spelled, or None.

    An abspath comparison said `.security-review/secrets/` was inside
    `.security-review/` and let it go at that - true of the spelling, and
    nothing to do with where the bytes land. The tree is attacker-supplied and
    may commit `.security-review/`, so a `.security-review -> ../elsewhere` or a
    `secrets -> ../../src` wrote candidates.json - a map of the repository's
    credentials - wherever it pointed, and exited 0. snapshot.linked_write_path
    is the one definition of what is refused; `targets` are the files written.
    """
    out = os.path.abspath(secrets_dir(root))
    base = os.path.abspath(run_dir(root))
    if out != base and not out.startswith(base + os.sep):
        return "refusing to write outside %s (contract 9 rule 2)" % base
    return snapshot.linked_write_path(
        root, base, [out, os.path.join(base, ".gitignore")] + list(targets))


def ensure_run_dir(root, targets=()):
    """Create `.security-review/secrets/`, refusing anything outside it.

    Contract §9 rule 2: no tool in this skill writes into the scanned tree -
    including through a link the tree committed at or under the run directory.
    """
    problem = run_dir_problem(root, targets)
    if problem:
        raise SweepError(problem)
    out = os.path.abspath(secrets_dir(root))
    os.makedirs(out, exist_ok=True)
    # `lexists` inside: a dangling .gitignore link read as absent to `exists`,
    # and the plain open() that followed created the file it pointed at. The
    # link itself is refused above; an existing `*` that ignores the ledger is
    # repaired rather than kept (contract §1 commits ledger/).
    snapshot.ensure_gitignore(os.path.join(os.path.abspath(run_dir(root)),
                                           ".gitignore"), GITIGNORE)
    return out


def write_json(path, doc):
    # rules_lib.json_dumps, not json.dump: `evidence.file` is a path off
    # os.walk, and a name that is not valid UTF-8 would kill the write.
    # snapshot.write_text, not `path + ".tmp"`: a predictable name in a
    # directory the scanned tree can commit to is a name it can plant a link
    # at, and a planted `candidates.json.tmp -> ~/.bashrc` had its target
    # overwritten with this file.
    snapshot.write_text(path, rules_lib.json_dumps(doc, indent=2, sort_keys=False)
                        + "\n")


# Every JSON this tool reads - inventory.json, a SARIF file - was written by
# something that read the repository under audit. `json.load` on a file handle
# reads whatever is there, so the cap is applied before the parse and not after.
MAX_JSON_BYTES = 64_000_000


def load_json(path, what):
    if not os.path.isfile(path):
        raise SweepError("%s: no %s to read. The secret-sweeper role writes "
                         "it; run the sweep first." % (path, what),
                         code=EXIT_NO_INPUT)
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise SweepError("%s: %s could not be read (%s)" % (path, what, exc),
                         code=EXIT_NO_INPUT)
    if size > MAX_JSON_BYTES:
        raise SweepError(
            "%s: %s is %d bytes, over the %d-byte cap. A run directory this "
            "tool reads is written by an agent reading attacker-supplied "
            "source; it is not read without a bound."
            % (path, what, size, MAX_JSON_BYTES), code=EXIT_NO_INPUT)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except ValueError as exc:
        raise SweepError("%s: %s does not parse as JSON (%s)" % (path, what, exc),
                         code=EXIT_NO_INPUT)
    except OSError as exc:
        raise SweepError("%s: %s could not be read (%s)" % (path, what, exc),
                         code=EXIT_NO_INPUT)


def load_function_keys(root):
    """The corpus's function keys, or None when stage 1 has not run.

    None and empty are different answers and the caller must not confuse them: no
    corpus means `touched_by` is unverifiable, which is reported and not refused.
    An EMPTY corpus means every `touched_by` names a function that is not there.
    """
    path = os.path.join(run_dir(root), FUNCTIONS_JSONL)
    if not os.path.isfile(path):
        return None
    keys = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                key = record.get("function_key")
                if isinstance(key, str):
                    keys.add(key)
    except OSError:
        return None
    return keys


# --------------------------------------------------------------------------- #
# `candidates`
# --------------------------------------------------------------------------- #

THE_RULE = ("A hardcoded secret is a finding. Holding a secret is not. "
            "In inventory.json, is_finding is true if and only if "
            "kind == 'secret' and origin == 'literal'. Every other origin - env, "
            "file, kdf, key-store, fuse-otp, wire, derived, unknown - is "
            "inventory, never a finding on its own.")


def declared_test_globs(root):
    """The manifest's `test_tree_globs`, or () when stage 1's recon has not run.

    Stage 1's recon agent writes which trees are tests, and every other tool in
    this skill reads it - `extract_functions` stamps `in_test_tree` on each
    function record, and it rides through scoring onto every candidate. This
    tool was the one that did not, and on libxml2 that meant handing the sweeper
    agent 1953 candidates of which 1803 were in `test/` and `result/`, with
    nothing on the record to say so.

    Marking is not dismissing, and the distinction is the whole point here. The
    sweeper's own prompt forbids writing a file off because its path says test -
    a real credential in a test directory is a real credential, and §4 of that
    prompt is built around exactly that case. So nothing is dropped, filtered or
    reordered. The candidate carries one more fact about where it lives, which
    is what lets an agent sequence 1953 of them on evidence instead of on
    whatever order they happened to come out in.
    """
    path = os.path.join(root, RUN_DIR, "manifest.json")
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            globs = (json.load(fh) or {}).get("test_tree_globs")
    except (OSError, ValueError, AttributeError):
        return ()
    return tuple(g for g in (globs or []) if isinstance(g, str) and g)


def cmd_candidates(args):
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        raise SweepError("--root %s is not a directory" % args.root)

    excludes = list(DEFAULT_EXCLUDES) + list(args.exclude or [])
    salt = os.urandom(16).hex()
    started = time.time()
    out_path = os.path.join(secrets_dir(root), CANDIDATES_NAME)

    # Before the walk, for the reason the SARIF files are read first: a run
    # directory that will be refused should be refused before the scan, not
    # after it. ensure_run_dir asks again right before the write.
    problem = run_dir_problem(root, [out_path])
    if problem:
        raise SweepError(problem)

    # The analyzer output is read FIRST, before the walk. A --sarif that will not
    # parse is a refusal, and refusing it after four seconds of scanning wastes
    # the scan; worse, on a large tree it looks like the scan is what failed.
    sarif_paths = collect_sarif_paths(args)
    sarif_findings = []
    for path in sarif_paths:
        sarif_findings.extend(parse_sarif(path, root))

    candidates = []
    scanned = oversize = entropy_off = 0
    tooling_skipped = []
    for rel, lines, truncated in iter_files(root, excludes, args.max_file_bytes,
                                            tooling_skipped):
        scanned += 1
        if truncated:
            oversize += 1
        skip_entropy = entropy_skipped(rel)
        if skip_entropy:
            entropy_off += 1
        candidates.extend(scan_file(rel, lines, args.entropy_threshold,
                                    args.entropy_min_length, salt, skip_entropy))

    candidates = merge_literals(candidates)

    from_sarif = fold_sarif(candidates, sarif_findings, root,
                            args.entropy_threshold, args.entropy_min_length,
                            salt, args.max_file_bytes)

    by_file = index_functions(root)
    # One definition of "is this a test tree", shared with stage 1's extractor,
    # for the same reason the language table lives in rules_lib: two tools that
    # answer this differently are two tools that disagree about the corpus.
    test_globs = declared_test_globs(root)
    for idx, cand in enumerate(candidates, 1):
        cand["candidate_id"] = "SC-%04d" % idx
        cand["function_key"] = locate_function(by_file, cand["file"], cand["line"])
        cand["in_test_tree"] = ef.in_test_tree(cand["file"], test_globs)

    literal = sum(1 for c in candidates if c["kind"] == "literal")
    doc = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)),
        "root": root,
        "the_rule": THE_RULE,
        "config": {
            "entropy_threshold": args.entropy_threshold,
            "entropy_min_length": args.entropy_min_length,
            "max_file_bytes": args.max_file_bytes,
            "excludes": excludes,
            "entropy_skip_globs": list(ENTROPY_SKIP_GLOBS),
            "sarif": [os.path.basename(p) for p in sarif_paths],
        },
        # Folders left out of the sweep as the scanner's own tooling, by identity
        # (rules_lib.is_tooling_dir), each with the reason: the same list
        # extract-report.json carries as `tooling_skipped`. A hostile tree can
        # hide a folder by carrying the files that identity rests on, so the
        # skip is a record a reader can check.
        "tooling_skipped": [{"path": path, "reason": why}
                            for path, why in sorted(set(tooling_skipped))],
        "counts": {
            "files_scanned": scanned,
            "files_truncated_at_cap": oversize,
            "files_entropy_family_off": entropy_off,
            "literal": literal,
            "source": len(candidates) - literal,
            "from_sarif": from_sarif,
            "sarif_findings_read": len(sarif_findings),
        },
        "redaction": ("Every literal in this file is redacted to at most its "
                      "first four and last four characters, including inside "
                      "line_text. `fingerprint` is a per-run salted digest: it "
                      "correlates entries inside this file and discloses nothing "
                      "outside it. The salt is not written."),
        "candidates": candidates,
    }

    ensure_run_dir(root, [out_path])
    write_json(out_path, doc)

    if args.as_json:
        json.dump(doc["counts"], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("wrote %s" % out_path)
        print("  %d literal candidate(s) - possible hardcoded secrets, for the "
              "agent to judge" % literal)
        print("  %d source candidate(s)  - where a secret enters. INVENTORY, "
              "never findings." % (len(candidates) - literal))
        print("  %d file(s) scanned, %d truncated at --max-file-bytes, "
              "%d with the entropy family off" % (scanned, oversize, entropy_off))
        if tooling_skipped:
            print("  left out as this scanner's own tooling or another skill's run folder "
                  "(not swept): %s"
                  % ", ".join("%s (%s)" % (rules_lib._printable(p, 120), w)
                              for p, w in sorted(set(tooling_skipped))))
        in_tests = sum(1 for c in candidates if c.get("in_test_tree"))
        declared = ""
        if test_globs:
            declared = (", and the manifest's test_tree_globs (%s)"
                        % (", ".join(test_globs[:4])
                           + (", ..." if len(test_globs) > 4 else "")))
        print("  %d of them are in a test tree - stage 1's own test directory "
              "and file names%s. They are MARKED, not dropped: a real "
              "credential in a test directory is a real credential, and this "
              "is the count that lets an agent sequence the rest first."
              % (in_tests, declared))
        if sarif_paths:
            print("  %d SARIF finding(s) from %d file(s); %d became new candidates"
                  % (len(sarif_findings), len(sarif_paths), from_sarif))
    return EXIT_OK


def index_functions(root):
    """file -> [(line_start, line_end, function_key)], for locating a candidate."""
    path = os.path.join(run_dir(root), FUNCTIONS_JSONL)
    index = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                rel = record.get("file")
                key = record.get("function_key")
                start = record.get("line_start")
                end = record.get("line_end")
                if not (rel and key and isinstance(start, int) and isinstance(end, int)):
                    continue
                index.setdefault(rel, []).append((start, end, key))
    except OSError:
        return {}
    for rel in index:
        index[rel].sort()
    return index


def locate_function(index, rel, lineno):
    """The narrowest extracted function containing this line, or None.

    Narrowest, because a `<module>` record spans the whole file and would
    otherwise swallow every hit inside a real function. §4a's own example carries
    both, and the module record is what a file-level secret joins to.
    """
    best = None
    for start, end, key in index.get(rel, ()):
        if isinstance(lineno, int) and start <= lineno <= end:
            if best is None or (end - start) < (best[1] - best[0]):
                best = (start, end, key)
    return best[2] if best else None


# --------------------------------------------------------------------------- #
# `check` - §4a, made mechanical
# --------------------------------------------------------------------------- #

KINDS = ("secret", "public")
CLASSES = ("long-term-key", "session-token", "password-or-pin", "mac-or-tag",
           "nonce-or-iv", "device-unique", "other-secret")
ORIGINS = ("literal", "env", "file", "kdf", "key-store", "fuse-otp", "wire",
           "derived", "unknown")

REQUIRED_FIELDS = ("entry_id", "kind", "class", "origin", "is_finding",
                   "identifiers", "evidence", "touched_by")

ENTRY_ID = re.compile(r"^SEC-\d{4,}$")
FUNCTION_KEY = re.compile(r"^(?P<file>[^\s]+)::(?P<name>[^:\s]+)::(?P<ordinal>\d+)$")

# How much of a redacted quote must survive redaction before it can be matched
# back to the source. The same floor verify_findings.matches() applies to a
# containment match, for the same reason: without it, `"` and `;` verify
# everything.
MIN_QUOTE_CHARS = 8

# The widest gap a single elision may stand for, inside one line. A PEM body is
# longer than this, and a PEM should be cited by its BEGIN marker - a line that
# is itself quotable - rather than by 1700 characters of base64 with the middle
# taken out.
MAX_ELIDED_CHARS = 512

# How many elisions one quoted line may carry. A redacted line has one, or two
# when there are two secrets on it; a dozen is not a quote any more but a pattern
# with a dozen bounded wildcards in it, which is both permissive and slow to
# match. Refusing is the right answer to both.
MAX_ELISIONS = 4


def redaction_pattern(want):
    """A redacted quote, compiled as a pattern over the real line.

    The subtle part of `check`. The agent writes

        API_KEY = "sk-l...aaaa"

    and the file holds

        API_KEY = "sk-live-9f2c1ab4e0d73516aaaa"

    so neither contains the other and verify_findings.matches() says no, which
    is the right answer to the question it is asking. The question here is
    different: does the real line AGREE with what survived redaction?

    So the quote is split on its elision marks and the surviving fragments are
    required to appear in the real line, in order, separated by at most
    MAX_ELIDED_CHARS. The alternative - redact the source line too and compare
    redactions - was rejected because it needs to know where the secret starts
    and ends in the source, which is precisely what `check` does not know.

    Three floors keep this from being a wildcard, and all three are
    load-bearing:

      * the surviving fragments must total MIN_QUOTE_CHARS, so `"..."` cannot
        verify against any line with a quote in it;
      * at least one fragment must be four characters, so
        `a...b...c...d...e...f...g...h` cannot reach the total by accumulating
        single characters that occur everywhere;
      * there may be at most MAX_ELISIONS of them, because beyond that the quote
        is not a quote with a secret taken out of it but a pattern with bounded
        wildcards in it - permissive to match, and slow.

    Returns None when there is no elision mark - in which case there is nothing
    to reconcile and the ordinary comparison is the whole test.
    """
    if not ELISION_MARK.search(want):
        return None
    fragments = [f for f in ELISION_MARK.split(want) if f]
    if not fragments:
        return None
    if sum(len(f.strip()) for f in fragments) < MIN_QUOTE_CHARS:
        return None
    if max(len(f.strip()) for f in fragments) < 4:
        return None
    if len(fragments) > MAX_ELISIONS + 1:
        return None
    gap = ".{0,%d}" % MAX_ELIDED_CHARS
    return re.compile(gap.join(re.escape(f) for f in fragments), re.DOTALL)


def citation_verdict(cited_code, cited_line, lines):
    """How a cited line relates to the file. One of:

        exact           the text is at the line cited
        drift           within verify_findings.DRIFT_WINDOW of it
        redacted        the redacted quote reconciles with the line cited
        redacted-drift  ... within the same window
        far             the text is in the file, but nowhere near
        not-found       the text is not in the file
        no-line         the citation names no usable line number

    The window is verify_findings.DRIFT_WINDOW and the comparison is
    verify_findings.quote_at(), imported rather than copied: a second tolerance
    drifts from the first, and then the two tools disagree about whether a
    correct run is correct. It was matches(), and when that stopped accepting a
    quote that merely CONTAINS its line, this kept calling it on one line at a
    time: an assignment broken over two lines and quoted joined - the way the
    contract's own examples quote a statement - was refused here while the gate
    verified the same quote. quote_at() reads the quote against the line and
    its real neighbours, and strips a copied line-number prefix, exactly as the
    gate does. `far` is refused here exactly as that tool refuses it under
    `citation_far_drift` - text four thousand lines from the line cited is a
    grep hit, not the line the entry says it read.
    """
    want = vf.norm(cited_code or "")
    if not want:
        return "not-found", None
    try:
        ln = int(cited_line)
    except (TypeError, ValueError):
        return "no-line", None
    if not (1 <= ln <= len(lines)):
        return "no-line", None

    window = list(range(max(1, ln - vf.DRIFT_WINDOW),
                        min(len(lines), ln + vf.DRIFT_WINDOW) + 1))

    for probe in [ln] + [p for p in window if p != ln]:
        if vf.quote_at(want, lines, probe):
            return ("exact" if probe == ln else "drift"), probe

    pattern = redaction_pattern(want)
    if pattern is not None:
        for probe in [ln] + [p for p in window if p != ln]:
            if pattern.search(vf.norm(lines[probe - 1])):
                return ("redacted" if probe == ln else "redacted-drift"), probe

    for probe in range(1, len(lines) + 1):
        if vf.quote_at(want, lines, probe):
            return "far", probe
        if pattern is not None and pattern.search(vf.norm(lines[probe - 1])):
            return "far", probe

    return "not-found", None


# The four verdicts that verify a citation. Everything else is a problem, and the
# branch is written as "in this tuple, else refuse" so that a verdict added later
# is refused until somebody decides it should not be.
ACCEPTED_VERDICTS = ("exact", "drift", "redacted", "redacted-drift")


def problem(code, entry_id, detail):
    return {"code": code, "entry_id": entry_id, "detail": detail}


def cited_line_text(lines, lineno, threshold):
    """What is actually at the cited line, scrubbed, for the refusal message.

    Scrubbed because a refusal is written into the run directory too, and a
    checker that quotes the secret back while refusing an entry for quoting the
    secret has not understood its own rule.
    """
    try:
        index = int(lineno)
    except (TypeError, ValueError):
        return "<no line number>"
    if not (1 <= index <= len(lines)):
        return "<line out of range>"
    return scrub(vf.norm(lines[index - 1]), threshold)[:160]


def escapes_root(root, rel):
    """Does this cited path leave the tree under review?

    The inventory is written by an agent reading attacker-supplied source, so the
    path in a citation is not automatically a path inside the repository. A
    checker that followed `../../.ssh/id_rsa` would quote it into the run
    directory while refusing an entry for quoting a secret.

    `abspath` alone is not enough: it normalises `..` but does not resolve a
    symlink, so `notes.txt -> /root/.ssh/id_rsa` sitting in the tree walks  # check-skills: allow-path
    straight past a lexical check and the checker reads the target and quotes a
    line of it back in its own refusal message. Both are tested: the lexical
    check catches `../../etc/passwd` before any filesystem call, and `realpath`
    catches the link.
    """
    if os.path.isabs(rel):
        return True
    base = os.path.abspath(root)
    target = os.path.abspath(os.path.join(base, rel))
    if target != base and not target.startswith(base + os.sep):
        return True
    real_base = os.path.realpath(base)
    real_target = os.path.realpath(target)
    return real_target != real_base and \
        not real_target.startswith(real_base + os.sep)


def check_entry(entry, index, root, keys, threshold, max_bytes, seen_ids):
    """Every problem in one inventory entry."""
    problems = []
    entry_id = entry.get("entry_id") if isinstance(entry, dict) else None
    label = entry_id if isinstance(entry_id, str) else "entry[%d]" % index

    if not isinstance(entry, dict):
        return [problem("schema_not_an_object", label,
                        "entry %d is %s, not an object" % (index, type(entry).__name__))]

    # ---- (a) schema
    for field in REQUIRED_FIELDS:
        if field not in entry:
            problems.append(problem("schema_missing_field", label,
                                    "required field `%s` is absent (contract 4a)" % field))

    if not isinstance(entry_id, str) or not ENTRY_ID.match(entry_id or ""):
        problems.append(problem("schema_bad_entry_id", label,
                                "entry_id must look like SEC-0001, got %r" % (entry_id,)))
    elif entry_id in seen_ids:
        problems.append(problem("duplicate_entry_id", label,
                                "entry_id %s is used more than once; the four "
                                "side-channel rules join on it" % entry_id))
    if isinstance(entry_id, str):
        seen_ids.add(entry_id)

    kind = entry.get("kind")
    klass = entry.get("class")
    origin = entry.get("origin")
    is_finding = entry.get("is_finding")

    if kind not in KINDS:
        problems.append(problem("schema_bad_enum", label,
                                "kind %r is not one of %s" % (kind, ", ".join(KINDS))))
    if origin not in ORIGINS:
        problems.append(problem("schema_bad_enum", label,
                                "origin %r is not one of %s" % (origin, ", ".join(ORIGINS))))
    if "class" in entry:
        if kind == "public":
            if klass is not None:
                problems.append(problem("class_kind_mismatch", label,
                                        "class must be null when kind == \"public\"; "
                                        "got %r. A value the attacker already holds "
                                        "has no secret class." % (klass,)))
        elif kind == "secret":
            if klass is None:
                problems.append(problem("class_kind_mismatch", label,
                                        "class must not be null when kind == "
                                        "\"secret\"; the side-channel rules read it "
                                        "as in-inventory:<class>"))
            elif klass not in CLASSES:
                problems.append(problem("schema_bad_enum", label,
                                        "class %r is not one of %s"
                                        % (klass, ", ".join(CLASSES))))

    if not isinstance(is_finding, bool):
        problems.append(problem("schema_bad_type", label,
                                "is_finding must be a boolean, got %r" % (is_finding,)))
    if not isinstance(entry.get("identifiers"), list) or \
            any(not isinstance(i, str) for i in entry.get("identifiers") or []):
        problems.append(problem("schema_bad_type", label,
                                "identifiers must be a list of strings"))
    if not isinstance(entry.get("touched_by"), list):
        problems.append(problem("schema_bad_type", label,
                                "touched_by must be a list (empty is fine: a "
                                "credential in a YAML file touches no function)"))

    # ---- (b) THE DISCIPLINE
    if isinstance(is_finding, bool) and kind in KINDS and origin in ORIGINS:
        should = (kind == "secret" and origin == "literal")
        if is_finding and not should:
            problems.append(problem(
                "is_finding_discipline", label,
                "is_finding is true but kind=%s origin=%s. Contract 4a: a "
                "hardcoded secret is a finding, HOLDING a secret is not. Only "
                "origin=\"literal\" on kind=\"secret\" is a finding; a value read "
                "from %s becomes one when something is done wrong with it, and "
                "that finding belongs to the rule governing the wrongdoing."
                % (kind, origin, origin)))
        if should and not is_finding:
            problems.append(problem(
                "is_finding_discipline", label,
                "is_finding is false but kind=secret origin=literal. Contract 4a "
                "makes that combination a finding, and the report gate fails a "
                "secrets section naming an entry with is_finding false - so this "
                "hardcoded secret would be reportable nowhere."))

    # ---- (c) citations
    evidence = entry.get("evidence")
    cited_code = None
    real_literals = []
    if not isinstance(evidence, dict):
        if "evidence" in entry:
            problems.append(problem("schema_bad_type", label,
                                    "evidence must be an object with file, line and code"))
    else:
        rel = evidence.get("file")
        cited_code = evidence.get("code")
        if not isinstance(rel, str) or not rel:
            problems.append(problem("schema_missing_field", label,
                                    "evidence.file is required"))
        elif not isinstance(cited_code, str) or not cited_code.strip():
            problems.append(problem("schema_missing_field", label,
                                    "evidence.code is required"))
        elif escapes_root(root, rel):
            problems.append(problem(
                "citation_outside_root", label,
                "evidence.file %s resolves outside the scanned repository. A "
                "citation names a file in the tree under review; anything else "
                "is a path this tool will not follow." % rel))
        else:
            lines, _ = read_text(os.path.join(root, rel), max_bytes)
            if lines is None:
                problems.append(problem("citation_file_not_found", label,
                                        "evidence.file %s is not a readable text "
                                        "file under the root" % rel))
            else:
                verdict, at = citation_verdict(cited_code, evidence.get("line"), lines)
                if verdict in ACCEPTED_VERDICTS:
                    # The line actually matched, which may be a drift line
                    # rather than the one cited: its literals are what (d)
                    # holds both fields against.
                    real_literals = line_literals(rel, lines[at - 1])
                elif verdict == "no-line":
                    problems.append(problem(
                        "citation_not_found", label,
                        "evidence.line %r is not a line of %s. A citation is a "
                        "path AND a line number; an entry nobody can look up is "
                        "an assertion." % (evidence.get("line"), rel)))
                elif verdict == "far":
                    problems.append(problem(
                        "citation_far_drift", label,
                        "evidence.code is in %s at line %s but %s was cited - "
                        "beyond verify_findings.DRIFT_WINDOW (%d), a match is a "
                        "grep hit and not the line the entry says it read"
                        % (rel, at, evidence.get("line"), vf.DRIFT_WINDOW)))
                else:
                    problems.append(problem(
                        "citation_not_found", label,
                        "evidence.code is nowhere in %s, redacted or whole. "
                        "Cited line %s holds: %s"
                        % (rel, evidence.get("line"),
                           cited_line_text(lines, evidence.get("line"), threshold))))

    # ---- (d) redaction
    #
    # Three tests, one problem per field. The entropy test alone let the
    # commonest hardcoded secret through: `hunter2hunter2` is lower+digit and
    # under twenty characters, so it is not key material, and an entry carrying
    # it whole in both fields passed with zero problems and was printed by
    # `status`. So a field also leaks when it holds, whole, a literal this
    # tool's own families find on the line the citation resolved to - exact
    # containment, because a type prefix (`sk-live-`) may legitimately survive
    # and "no more than eight characters of it" would refuse the contract's own
    # example - and more often than that line shows it with every literal
    # redacted, because on `password = "password"` the name is the value too
    # (see line_literals). A PUBLIC entry is exempt from that one: quoting a
    # value the attacker already holds is not a leak, and entropy still guards it.
    #
    # And `redacted` on a literal entry must visibly BE a redaction - an
    # elision mark, or the `<6 digits>` shape the prompt asks for on a short
    # value - since a bare value is what a sweeper writes when it forgot to.
    shown = {}
    for field, text in (("redacted", entry.get("redacted")),
                        ("evidence.code", cited_code)):
        if not isinstance(text, str):
            continue
        runs = [run for _, _, run in leaked_runs(text, threshold)]
        whole = [] if kind == "public" else [
            lit for lit, allowed in real_literals
            if vf.norm(text).count(lit) > allowed]
        bare = (field == "redacted" and origin == "literal" and kind != "public"
                and not_a_redaction(text))
        if runs:
            shown[field] = (
                "%s carries %d consecutive characters of key material (%s)"
                % (field, max(len(r) for r in runs), redact(max(runs, key=len))))
        elif whole:
            longest = max(whole, key=len)
            shown[field] = (
                "%s carries a whole %d-character literal that is on the cited "
                "line (%s) - entropy does not flag it, the families do"
                % (field, len(longest), redact(longest)))
        elif bare:
            shown[field] = (
                "%s is %d character(s) with no elision and no `<shape>`, so it "
                "is not visibly a redaction of anything"
                % (field, len(text.strip())))
    for field in ("redacted", "evidence.code"):
        if field in shown:
            problems.append(problem(
                "redaction_leak", label,
                "%s. Contract 4a: redacted never carries the secret - at most the "
                "first four and last four characters, and the shape alone "
                "(`<6 digits>`) for a short one. The run directory is written to "
                "disk and read by a model; copying a live credential into it "
                "makes the scanner a second place the secret leaks from."
                % shown[field]))

    if entry.get("is_finding") is True and not entry.get("redacted"):
        problems.append(problem(
            "redaction_missing", label,
            "a finding must carry `redacted`: the report names the secret, and "
            "with nothing to name it either says nothing or says everything"))

    # ---- (e) touched_by
    for key in (entry.get("touched_by") if isinstance(entry.get("touched_by"), list)
                else []):
        if not isinstance(key, str) or not FUNCTION_KEY.match(key):
            problems.append(problem(
                "touched_by_malformed", label,
                "touched_by entry %r is not a function_key (<file>::<name>::<n>, "
                "contract 2)" % (key,)))
            continue
        if keys is not None and key not in keys:
            problems.append(problem(
                "touched_by_unknown_function", label,
                "touched_by names %s, which is not in extract/functions.jsonl. "
                "enrich_candidates.py stamps secret_status by joining on this "
                "key, so a name nothing matches stamps nothing." % key))

    return problems


def unjudged_literals(root, entries):
    """Literal candidates from the last `candidates` run that no entry cites.

    This is a COUNT and never a problem, and the distinction is the whole of the
    design. Most of what a name-and-shape matcher returns in a crypto tree is not
    a secret - refusing an inventory for every candidate it declined would make
    the checker demand an entry for each of four hundred base64 asset blobs, and
    a checker nobody can satisfy is a checker somebody turns off.

    But the other direction is the one §4a cares about: the ONLY thing on the
    secrets track that is a finding is a hardcoded secret, and a sweeper that
    quietly skipped half the list produces an inventory that `check` passes
    clean, because `check` only ever looked at the entries that are there. A
    literal nobody judged is a literal nobody decided about, and this skill
    counts what it did not look at everywhere else it does that.

    Matched on file and line within DRIFT_WINDOW, the same tolerance a citation
    gets, because an entry may cite a neighbouring line of the same secret.
    Returns None when there is no candidates.json to compare against - absence
    of the file is not evidence of a complete sweep either.
    """
    path = os.path.join(secrets_dir(root), CANDIDATES_NAME)
    if not os.path.isfile(path):
        return None
    try:
        doc = load_json(path, CANDIDATES_NAME)
    except SweepError:
        return None
    candidates = doc.get("candidates") if isinstance(doc, dict) else None
    if not isinstance(candidates, list):
        return None

    cited = set()
    for entry in entries:
        ev = entry.get("evidence")
        if not isinstance(ev, dict):
            continue
        rel = ev.get("file")
        try:
            line = int(ev.get("line"))
        except (TypeError, ValueError):
            continue
        if isinstance(rel, str):
            for near in range(line - vf.DRIFT_WINDOW, line + vf.DRIFT_WINDOW + 1):
                cited.add((rel, near))

    missed = [c for c in candidates
              if isinstance(c, dict) and c.get("kind") == "literal"
              and (c.get("file"), c.get("line")) not in cited]
    return {
        "literal_candidates": sum(1 for c in candidates
                                  if isinstance(c, dict) and c.get("kind") == "literal"),
        "uncited": len(missed),
        # Ids and locations only. `candidates.json` is redacted, and this is a
        # count of what was skipped, not a second place to quote it.
        "sample": [{"candidate_id": c.get("candidate_id"), "file": c.get("file"),
                    "line": c.get("line"), "subkind": c.get("subkind")}
                   for c in missed[:12]],
    }


def run_check(root, threshold, max_bytes):
    """Every problem in inventory.json, plus what was checked."""
    path = os.path.join(secrets_dir(root), INVENTORY_NAME)
    doc = load_json(path, "inventory.json")

    if isinstance(doc, list):
        entries = doc
        declared = SCHEMA_VERSION
    elif isinstance(doc, dict):
        entries = doc.get("entries")
        declared = doc.get("schema_version", SCHEMA_VERSION)
        if entries is None:
            raise SweepError("%s: no `entries` array" % path, code=EXIT_NO_INPUT)
    else:
        raise SweepError("%s: inventory.json must be an object with `entries`, "
                         "or a bare array of entries" % path, code=EXIT_NO_INPUT)
    if not isinstance(entries, list):
        raise SweepError("%s: `entries` is not an array" % path, code=EXIT_NO_INPUT)
    try:
        declared = int(declared)
    except (TypeError, ValueError):
        declared = -1
    if declared > SCHEMA_VERSION:
        raise SweepError(
            "%s declares schema_version %s; this tool knows %d. Contract 0: a "
            "tool reading a higher schema_version than it knows must refuse, not "
            "guess." % (path, declared, SCHEMA_VERSION), code=EXIT_NO_INPUT)

    keys = load_function_keys(root)
    problems, seen = [], set()
    for index, entry in enumerate(entries):
        problems.extend(check_entry(entry, index, root, keys, threshold,
                                    max_bytes, seen))

    rows = [e for e in entries if isinstance(e, dict)]
    findings = [e for e in rows if e.get("is_finding") is True]
    public = [e for e in rows if e.get("kind") == "public"]
    return {
        "unjudged": unjudged_literals(root, rows),
        "path": path,
        "entries": len(entries),
        # Counted the way `status` prints them, and the way 4a splits them: a
        # public entry is not "inventory the rules read", and rolling the two
        # together here would put a different number next to the same file.
        "findings": len(findings),
        "inventory": len(rows) - len(findings) - len(public),
        "public": len(public),
        "corpus_available": keys is not None,
        "corpus_functions": len(keys) if keys is not None else None,
        "problems": problems,
    }


def cmd_check(args):
    root = os.path.abspath(args.root)
    result = run_check(root, args.entropy_threshold, args.max_file_bytes)
    problems = result["problems"]

    if args.as_json:
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("checked %s" % result["path"])
        print("  %d entr(ies): %d finding(s), %d inventory, %d public"
              % (result["entries"], result["findings"], result["inventory"],
                 result["public"]))
        if not result["corpus_available"]:
            print("  NOTE: no extract/functions.jsonl, so touched_by keys were "
                  "checked for SHAPE only, not for existence")
        missed = result.get("unjudged")
        if missed and missed["uncited"]:
            # A count, not a refusal: most literal candidates in a crypto tree
            # are correctly declined. But `check` reads only the entries that
            # are there, so a sweeper that skipped half the list passes it
            # clean, and the one thing on this track that IS a finding is a
            # hardcoded secret.
            print("  NOTE: %d of %d literal candidate(s) are cited by no entry. "
                  "That is not a problem - most are not secrets - but `check` "
                  "reads only what is in the file, so a skipped candidate is "
                  "invisible to it:" % (missed["uncited"], missed["literal_candidates"]))
            for row in missed["sample"]:
                print("        %-9s %-18s %s:%s"
                      % (row["candidate_id"], row["subkind"], row["file"], row["line"]))
            if missed["uncited"] > len(missed["sample"]):
                print("        ... and %d more"
                      % (missed["uncited"] - len(missed["sample"])))
        for prob in problems:
            print("  %-28s %-10s %s" % (prob["code"], prob["entry_id"], prob["detail"]))
        print()
        print("check: %d problem(s)" % len(problems))
        if not problems:
            # Said as what was checked, not as "nothing carries a whole
            # secret": a low-entropy value on a line no family spells -
            # `DB_PIN = "12345678"` - is still invisible to both tests.
            print("  is_finding is true for exactly the kind=secret origin=literal "
                  "entries, every citation resolves, and no `redacted` or "
                  "evidence.code carries key material or a whole literal this "
                  "tool's patterns find on the cited line.")
    return EXIT_REFUSED if problems else EXIT_OK


# --------------------------------------------------------------------------- #
# `status`
# --------------------------------------------------------------------------- #

BAR = "=" * 74
RULE = "-" * 74


def scrubbed(value, threshold, depth=0):
    """`value` with every string in it scrubbed.

    `status` prints a file this tool did not write. If that inventory carries a
    whole secret - which is exactly what `check` refuses it for - then printing
    it verbatim puts the secret on a terminal and into whatever captured that
    terminal. A reader is not a reason to relax the rule the writer is held to.
    """
    if depth > 12:
        return value
    if isinstance(value, str):
        return scrub_literals(scrub(value, threshold))
    if isinstance(value, list):
        return [scrubbed(v, threshold, depth + 1) for v in value]
    if isinstance(value, dict):
        return dict((k, scrubbed(v, threshold, depth + 1)) for k, v in value.items())
    return value


def scrub_literals(text):
    """`text` with every literal the source-code families spell in it redacted.

    scrub() is the entropy half; this is the other one, for the text `status`
    prints. `ADMIN_PASSWORD = "hunter2hunter2"` quoted whole in evidence.code
    is not key material to scrub(), and went out on the terminal as written.
    A value that already carries an elision is a redaction, and is left as
    one rather than redacted a second time.
    """
    if not text:
        return text
    return redact_spans(text, [
        span for _s, literal, span, _i, _e in literal_hits(
            "", text, DEFAULT_ENTROPY_THRESHOLD, DEFAULT_ENTROPY_MIN_LENGTH, True,
            is_config=False)
        if not ELISION_MARK.search(literal)])


# What `status` prints in place of a literal entry's `redacted` when that is not
# visibly a redaction - `check` refuses the entry for it.
NOT_A_REDACTION = "<not a redaction - `sweep_secrets.py check` refuses this entry>"


def masked_redacted(entry):
    """`entry` with a bare `redacted` replaced, when it is a literal's."""
    if entry.get("origin") == "literal" and entry.get("kind") != "public" \
            and not_a_redaction(entry.get("redacted")):
        entry = dict(entry, redacted=NOT_A_REDACTION)
    return entry


def is_a_finding(entry):
    """Contract 4a's rule, COMPUTED - never the entry's own claim.

    `status` used to split on `entry["is_finding"]`, which is the one field in
    the file that an inventory can get wrong. An entry with `origin: "env"` and
    `is_finding: true` was printed under the heading "FINDINGS - secrets
    HARDCODED into the source (origin: literal)", and an `origin: "literal"`
    entry with `is_finding: false` was filed under "INVENTORY - NOT findings"
    while the findings block said "none. No secret in this repository is written
    into the source." Both exited 0.

    `check` refuses both, but nothing makes `check` run, and `status` is the
    command a person reads. A reader is not a reason to relax the rule the
    writer is held to - the same argument `scrubbed()` above makes about
    printing a leaked secret. So `status` computes the rule itself, routes every
    entry by the answer, and says out loud where the file disagrees.
    """
    return entry.get("kind") == "secret" and entry.get("origin") == "literal"


def discipline_violations(entries):
    """(entry, claimed, actual) for every entry whose `is_finding` is wrong."""
    out = []
    for entry in entries:
        claimed = entry.get("is_finding") is True
        actual = is_a_finding(entry)
        if claimed != actual:
            out.append((entry, claimed, actual))
    return out


def cmd_status(args):
    root = os.path.abspath(args.root)
    threshold = args.entropy_threshold
    path = os.path.join(secrets_dir(root), INVENTORY_NAME)
    doc = load_json(path, "inventory.json")
    if isinstance(doc, list):
        entries = doc
    elif isinstance(doc, dict):
        entries = doc.get("entries") or []
    else:
        raise SweepError("%s: inventory.json must be an object with `entries`, "
                         "or a bare array of entries" % path, code=EXIT_NO_INPUT)
    entries = [masked_redacted(scrubbed(e, threshold))
               for e in entries if isinstance(e, dict)]

    # Routed by contract 4a's rule, not by what the file claims. See
    # `is_a_finding` for what went through here before.
    findings = [e for e in entries if is_a_finding(e)]
    secrets = [e for e in entries
               if e.get("kind") == "secret" and not is_a_finding(e)]
    public = [e for e in entries if e.get("kind") == "public"]
    # Nothing may vanish, and 4a's rule cannot be computed on a value outside
    # its own enums. An entry with `kind` outside KINDS belongs to neither list.
    # An entry with `origin` outside ORIGINS is worse than that: `origin:
    # "Literal"` makes `is_a_finding` false, so a HARDCODED secret claiming
    # `is_finding: false` matched its claim, raised no violation, and was filed
    # under "INVENTORY - NOT findings" while the findings block said "none". A
    # typo is not a classification.
    unclassifiable = [e for e in entries
                      if e.get("kind") not in KINDS
                      or e.get("origin") not in ORIGINS]
    violations = discipline_violations(entries)
    exit_code = EXIT_REFUSED if (violations or unclassifiable) else EXIT_OK

    if args.as_json:
        json.dump({
            "path": path,
            "the_rule": THE_RULE,
            "findings": findings,
            "inventory": secrets,
            "public": public,
            "unclassifiable": unclassifiable,
            "discipline_violations": [
                {"entry_id": e.get("entry_id"), "kind": e.get("kind"),
                 "origin": e.get("origin"), "is_finding_claimed": claimed,
                 "is_finding_by_rule": actual}
                for e, claimed, actual in violations],
            "by_class": tally(secrets, "class"),
            "by_origin": tally(secrets, "origin"),
        }, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return exit_code

    def where(entry):
        ev = entry.get("evidence") or {}
        return "%s:%s" % (ev.get("file", "?"), ev.get("line", "?"))

    def names(entry):
        return ", ".join(entry.get("identifiers") or []) or "-"

    if violations or unclassifiable:
        print(BAR)
        print("DISCIPLINE VIOLATION - this inventory contradicts contract 4a")
        print(BAR)
        print("  is_finding is true if and only if kind == \"secret\" and")
        print("  origin == \"literal\". Where the file says otherwise, the blocks")
        print("  below are grouped by THE RULE, not by what the file claims.")
        print()
        for entry, claimed, actual in violations:
            print("  %-9s kind=%-8s origin=%-10s is_finding=%-5s -> should be %s"
                  % (entry.get("entry_id", "?"), entry.get("kind"),
                     entry.get("origin"), str(claimed).lower(),
                     str(actual).lower()))
            if actual:
                print("            a HARDCODED secret marked as not a finding: "
                      "reportable nowhere.")
            else:
                print("            HOLDING a secret is not a finding; this "
                      "belongs to the rule governing the wrongdoing.")
        for entry in unclassifiable:
            if entry.get("kind") not in KINDS:
                print("  %-9s kind=%r is not one of %s - 4a's rule cannot be "
                      "computed on it, so it is classified nowhere"
                      % (entry.get("entry_id", "?"), entry.get("kind"),
                         ", ".join(KINDS)))
            else:
                print("  %-9s origin=%r is not one of the 4a origins - if this "
                      "means \"literal\", it is a FINDING and is filed here as "
                      "neither" % (entry.get("entry_id", "?"),
                                   entry.get("origin")))
        print("  --> %d violation(s). Run `sweep_secrets.py check` and fix the "
              "inventory." % (len(violations) + len(unclassifiable)))
        print()

    print(BAR)
    print("FINDINGS - secrets HARDCODED into the source (origin: literal)")
    print(BAR)
    if not findings:
        print("  none. No secret in this repository is written into the source.")
    for entry in findings:
        print("  %-9s %-16s %-28s %s"
              % (entry.get("entry_id", "?"), entry.get("class", "?"),
                 where(entry), names(entry)))
        if entry.get("redacted"):
            print("            %s" % entry["redacted"])
        if entry.get("why"):
            print("            %s" % str(entry["why"])[:200])
    print("  --> %d finding(s). These are reported on the secrets track."
          % len(findings))

    print()
    print(RULE)
    print("INVENTORY - NOT findings. Holding a secret is not a finding.")
    print(RULE)
    print("  These are evidence the four side-channel rules read. A value here")
    print("  becomes a finding only when something is done wrong with it, and")
    print("  that finding belongs to the rule governing the wrongdoing.")
    print()
    print("  by class:  %s" % fmt_tally(tally(secrets, "class")))
    print("  by origin: %s" % fmt_tally(tally(secrets, "origin")))
    print()
    for entry in secrets:
        print("  %-9s %-16s %-11s %-28s %s"
              % (entry.get("entry_id", "?"), entry.get("class", "?"),
                 entry.get("origin", "?"), where(entry), names(entry)))
    if not secrets:
        print("  (none)")
    print("  --> %d inventory entr(ies). Not findings." % len(secrets))

    print()
    print(RULE)
    print("PUBLIC - values the attacker already holds")
    print(RULE)
    print("  Recording these is the point of the file, not an afterthought: it is")
    print("  what stops the light tier calling a public key or a certificate")
    print("  digest secret and the arbiter overturning every one.")
    print()
    for entry in public:
        print("  %-9s %-11s %-28s %s"
              % (entry.get("entry_id", "?"), entry.get("origin", "?"),
                 where(entry), names(entry)))
    if not public:
        print("  (none) - a sweeper that lists only secrets has not done the job.")
    print("  --> %d public entr(ies)." % len(public))
    print()
    print("`sweep_secrets.py check` is what holds this file to contract 4a. "
          "This command reads it,")
    print("and groups it by 4a's rule rather than by the file's own "
          "`is_finding`, so a wrong")
    print("claim cannot put a non-literal secret under the FINDINGS heading.")
    return exit_code


def tally(entries, field):
    counts = {}
    for entry in entries:
        value = entry.get(field)
        key = "null" if value is None else str(value)
        counts[key] = counts.get(key, 0) + 1
    return counts


def fmt_tally(counts):
    if not counts:
        return "(none)"
    return "   ".join("%s %d" % (k, counts[k]) for k in sorted(counts))


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class _Args(object):
    def __init__(self, **kw):
        self.root = "."
        self.sarif = []
        self.sarif_dir = []
        self.entropy_threshold = DEFAULT_ENTROPY_THRESHOLD
        self.entropy_min_length = DEFAULT_ENTROPY_MIN_LENGTH
        self.max_file_bytes = DEFAULT_MAX_FILE_BYTES
        self.exclude = []
        self.as_json = True
        for key, value in kw.items():
            setattr(self, key, value)


# Fixture secrets. Shaped like the real families, and not live.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
GH_TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6"
OPENAI_KEY = "sk-" + "Zq7Xw2Nv9Rt4Bs1Yh6Lk3Pm8Jd5Fg0Cc"
GOOGLE_KEY = "AIza" + "Sy" + "B7nQ2mX9vL4kR1tW8pZ0aH6dJ3cF5gE2y"
GITLAB_PAT = "glpat-" + "x7Kq2mB9nR4tL1vW8pZ0"
NPM_TOKEN = "npm_" + "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4"
SLACK_TOKEN = "xoxb-" + "123456789012-1234567890123-" + "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0"
STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
       "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
       "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
HIGH_ENTROPY = "9fK2xQ7pR4tL1vW8zB3nM6cJ5dH0sA2e"
PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
       "MIIEowIBAAKCAQEA3Zq7Xw2Nv9Rt4Bs1Yh6Lk3Pm8Jd5Fg0CcVb2Nm4Qp7Rs9Tu1\n"
       "Wx3Yz5Ab7Cd9Ef1Gh3Ij5Kl7Mn9Op1Qr3St5Uv7Wx9Yz1Ab3Cd5Ef7Gh9Ij1Kl3M\n"
       "-----END RSA PRIVATE KEY-----\n")


def selftest():
    failures = 0

    def ok(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s:\n         got  %r\n         want %r" % (label, got, want))

    def truthy(label, got):
        ok(label, bool(got), True)

    def quietly(fn, *a, **kw):
        """Run a command for its effect, not its chatter."""
        result = {}
        _capture(lambda: result.setdefault("rc", fn(*a, **kw)))
        return result["rc"]

    print("redaction")
    ok("a long literal keeps four either side",
       redact(AWS_KEY), "AKIA" + ELISION + "MPLE")
    ok("a twelve-character literal gives up three",
       redact("abcdefghijkl"), "abc" + ELISION + "jkl")
    ok("an eight-character password gives up two, not four - four either side "
       "of eight IS the password",
       redact("hunter22"), "hu" + ELISION + "22")
    ok("three characters give up nothing", redact("abc"), ELISION)
    ok("the empty string stays empty", redact(""), "")
    ok("a span is redacted in place",
       redact_span('KEY = "%s"' % AWS_KEY, 7, 7 + len(AWS_KEY)),
       'KEY = "AKIA' + ELISION + 'MPLE"')

    print("entropy and what counts as key material")
    ok("a random base64 run is key material",
       looks_like_key_material(HIGH_ENTROPY, 3.6, 20), True)
    ok("and stops being one when the threshold is raised above it",
       looks_like_key_material(HIGH_ENTROPY, 5.9, 20), False)
    ok("a long snake_case identifier is not, whatever its entropy",
       (round(shannon("mbedtls_pkcs5_pbkdf2_hmac_ext"), 2) > 3.6,
        looks_like_key_material("mbedtls_pkcs5_pbkdf2_hmac_ext", 3.6, 20)),
       (True, False))
    ok("nor is a CamelCase one",
       looks_like_key_material("AESKeyWrapUnwrapTest256", 3.6, 20), False)
    ok("nor is a base64 asset",
       looks_like_key_material("iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB", 3.6, 20), False)
    ok("nor a machine word written as hex",
       looks_like_key_material("0xDEADBEEFCAFEBABE", 3.6, 9), False)
    ok("a nineteen-character run is below the entropy family's floor",
       looks_like_key_material(HIGH_ENTROPY[:19], 3.6, 20), False)
    ok("but the leak test looks at runs as short as nine",
       looks_like_key_material(HIGH_ENTROPY[:12], 3.6, LEAK_MIN_RUN), True)
    ok("a URL contributes no run of twenty",
       list(high_entropy_runs("https://api.example.com/v1/users/list", 3.6, 20)), [])
    ok("but a token in its query string does",
       [r for _, _, r in high_entropy_runs(
           "https://api.example.com/v1?token=%s" % HIGH_ENTROPY, 3.6, 20)],
       ["token=" + HIGH_ENTROPY])
    ok("prose contributes none",
       list(high_entropy_runs(
           "the quick brown fox jumps over the lazy dog again and again",
           3.6, 20)), [])

    print("the tool's own output survives its own leak test")
    ok("scrub redacts a whole secret on a line",
       scrub('API_KEY = "%s"' % HIGH_ENTROPY),
       'API_KEY = "%s"' % redact(HIGH_ENTROPY))
    ok("and leaves an identifier alone",
       scrub("mbedtls_pkcs5_pbkdf2_hmac_ext(ctx, salt, len);"),
       "mbedtls_pkcs5_pbkdf2_hmac_ext(ctx, salt, len);")
    ok("a scrubbed line reports no leaked run",
       list(leaked_runs(scrub('key = "%s"' % HIGH_ENTROPY))), [])

    with tempfile.TemporaryDirectory() as tmp:
        print("candidates: the literal families")
        _write(os.path.join(tmp, "src", "app.py"), "\n".join([
            "import os",
            'AWS = "%s"' % AWS_KEY,
            'GH  = "%s"' % GH_TOKEN,
            'OPENAI_API_KEY = "%s"' % OPENAI_KEY,
            'GOOGLE = "%s"' % GOOGLE_KEY,
            'GITLAB = "%s"' % GITLAB_PAT,
            'NPM = "%s"' % NPM_TOKEN,
            'SLACK = "%s"' % SLACK_TOKEN,
            'STRIPE = "%s"' % STRIPE_KEY,
            'JWT = "%s"' % JWT,
            'DSN = "postgres://admin:s3cretpassword@db.internal:5432/app"',
            'password = "correct-horse-battery"',
            'blob = "%s"' % HIGH_ENTROPY,
            'templated = {"password": "${DB_PASS}"}',
            'DB = os.environ["DB_PASSWORD"]',
            "key = hkdf_expand(prk, info, 32)",
            "uid = esp_efuse_read_field_blob(ESP_EFUSE_MAC, mac, 48);",
            'cert = open("/etc/ssl/server.pem").read()',
            "",
        ]) + "\n")
        _write(os.path.join(tmp, "keys", "id_rsa"), PEM)
        _write(os.path.join(tmp, ".env"),
               "DATABASE_PASSWORD=hunter2hunter2\n"
               'API_TOKEN="%s"\n'
               "DEBUG=1\n" % GH_TOKEN)
        _write(os.path.join(tmp, "package-lock.json"),
               '{"integrity": "sha512-%s"}\n' % HIGH_ENTROPY)

        rc = quietly(cmd_candidates, _Args(root=tmp))
        ok("the command succeeds", rc, EXIT_OK)
        doc = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                          CANDIDATES_NAME), encoding="utf-8"))
        cands = doc["candidates"]
        subkinds = sorted({c["subkind"] for c in cands if c["kind"] == "literal"})
        for want in ("aws-access-key-id", "github-token", "openai-key",
                     "google-api-key", "gitlab-pat", "npm-token", "slack-token",
                     "stripe-key", "jwt", "basic-auth-in-url", "pem-private-key",
                     "secret-assignment", "env-assignment", "high-entropy"):
            ok("family %s matched" % want, want in subkinds, True)

        sources = sorted({c["subkind"] for c in cands if c["kind"] == "source"})
        ok("the source families matched, all four kinds",
           sources, ["env-read", "fuse-otp", "kdf", "key-file"])
        ok("and every source candidate is marked as inventory, not a finding",
           all("is_finding" not in c and "not a finding" in c["note"]
               for c in cands if c["kind"] == "source"), True)
        ok("source candidates carry the origin the agent should start from",
           sorted({c["origin_hint"] for c in cands if c["kind"] == "source"}),
           ["env", "file", "fuse-otp", "kdf"])

        print("candidates: redaction is applied everywhere")
        blob = json.dumps(doc)  # the whole artifact, searched for whole secrets
        for name, secret in (("AWS key", AWS_KEY), ("GitHub token", GH_TOKEN),
                             ("OpenAI key", OPENAI_KEY), ("JWT", JWT),
                             ("high-entropy literal", HIGH_ENTROPY),
                             ("env password", "hunter2hunter2")):
            ok("the whole %s is nowhere in candidates.json" % name,
               secret in blob, False)
        aws = next(c for c in cands if c["subkind"] == "aws-access-key-id")
        ok("the literal is redacted", aws["redacted"], redact(AWS_KEY))
        ok("and the emitted LINE carries the redaction, not the literal",
           aws["line_text"], 'AWS = "%s"' % redact(AWS_KEY))
        ok("its true length is still recorded, because the agent needs it",
           aws["literal_length"], len(AWS_KEY))
        ok("a BEGIN marker with nothing key-shaped under it is a mention, and "
           "does not swallow the next four hundred lines",
           [(c["pem_body_lines"], c["pem_terminated"]) for c in
            merge_literals(scan_file("doc.md", [
                "the file starts `-----BEGIN RSA PRIVATE KEY-----`, and then",
                'ok("something else entirely", value, want)',
            ], 3.6, 20, "s", False)) if c["subkind"] == "pem-private-key"],
           [(0, False)])
        pem = next(c for c in cands if c["subkind"] == "pem-private-key")
        ok("a PEM is recorded at its BEGIN marker",
           (pem["file"], pem["line"], pem["line_text"]),
           ("keys/id_rsa", 1, "-----BEGIN RSA PRIVATE KEY-----"))
        ok("with the body redacted and counted, never quoted",
           (pem["pem_body_lines"], pem["pem_terminated"],
            "MIIEowIBAAKCAQEA" in blob),
           (2, True, False))
        _write(os.path.join(tmp, "src", "pair.py"),
               'PAIR = ("%s", "%s")\n' % (AWS_KEY, GITLAB_PAT))
        quietly(cmd_candidates, _Args(root=tmp))
        pair = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                           CANDIDATES_NAME), encoding="utf-8"))
        ok("two secrets on one line stay two candidates",
           sorted(c["subkind"] for c in pair["candidates"]
                  if c["file"] == "src/pair.py"),
           ["aws-access-key-id", "gitlab-pat"])
        ok("and the first is not published as the second's identifier - "
           "`identifier` is a field redaction would not otherwise reach",
           [c["identifier"] for c in pair["candidates"]
            if c["file"] == "src/pair.py"], ["PAIR", None])
        ok("a JSON-style name is read from the pattern, not from its left",
           _identifier_of('cfg = {"password": "correct-horse-battery-x"}'),
           "password")
        # SECRET_ASSIGN matches from the stem rightwards, so the words to the
        # LEFT of it are not in the `name` group - and on a public value those
        # words are the whole of the evidence that it is public. §4a exists
        # because references/tuning.md measured this rule calling certificate digests
        # secret; `SECRET` alone, with `PEER_CERT_DIGEST_` dropped, is that
        # failure handed to the sweeper as a candidate.
        ok("the identifier is the WHOLE name, not the stem the pattern matched",
           _identifier_of('PEER_CERT_DIGEST_SECRET = "3b1f9a2c4d5e6f708192a3b4"'),
           "PEER_CERT_DIGEST_SECRET")
        ok("a dotted config name survives too",
           _identifier_of('db.password = "correct-horse-battery-x"'),
           "db.password")
        ok("and a hyphenated one",
           _identifier_of('my-api-token = "correct-horse-battery-x"'),
           "my-api-token")
        ok("but punctuation that is not part of a name is not swept in",
           _identifier_of('cfg={}; password = "correct-horse-battery-x"'),
           "password")
        ok("nothing this tool wrote fails this tool's leak test",
           [c["candidate_id"] for c in cands
            if list(leaked_runs(c["line_text"]))
            or list(leaked_runs(c.get("redacted") or ""))], [])

        print("candidates: precision")
        ok("a templated value is not a hardcoded secret",
           any(c["line"] == 14 and c["kind"] == "literal" for c in cands), False)
        ok("an unquoted assignment is a literal in a config file",
           [c["subkind"] for c in
            merge_literals(scan_file("app.ini", ["api_key = hunter2hunter2"],
                                     3.6, 20, "s", False))],
           ["env-assignment"])
        ok("and an expression in source, where it is not a candidate at all",
           merge_literals(scan_file("app.py", ["api_key = hunter2hunter2"],
                                    3.6, 20, "s", False)),
           [])
        ok("nor is an unquoted value that is plainly an expression",
           merge_literals(scan_file("app.ini", ["api_key = compute_it(arg)"],
                                    3.6, 20, "s", False)),
           [])
        ok("a lockfile's integrity hash is not an entropy candidate",
           any(c["file"] == "package-lock.json" for c in cands), False)
        ok("the same secret twice shares a fingerprint",
           len({c["fingerprint"] for c in cands
                if c["subkind"] == "aws-access-key-id"}), 1)
        ok("and the salt is not written to the file",
           "fingerprint_salt" in blob, False)
        quoted = [c for c in cands
                  if c["file"] == ".env" and c["identifier"] == "API_TOKEN"]
        ok("a quoted .env value is redacted inside its quotes, not around them",
           (len(quoted), quoted[0]["line_text"] if quoted else None),
           (1, 'API_TOKEN="%s"' % redact(GH_TOKEN)))
        ok("the entropy threshold and its length floor are recorded",
           (doc["config"]["entropy_threshold"],
            doc["config"]["entropy_min_length"]), (3.6, 20))

        print("candidates: the entropy threshold, both sides")
        high = _Args(root=tmp, entropy_threshold=5.9)
        quietly(cmd_candidates, high)
        doc2 = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                           CANDIDATES_NAME), encoding="utf-8"))
        ok("raising the threshold past the literal drops the entropy family",
           any(c["subkind"] == "high-entropy" for c in doc2["candidates"]), False)
        ok("but the prefix families do not depend on entropy and still fire",
           any(c["subkind"] == "aws-access-key-id" for c in doc2["candidates"]),
           True)

        print("candidates: --exclude and --max-file-bytes")
        quietly(cmd_candidates, _Args(root=tmp, exclude=["keys"]))
        doc3 = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                           CANDIDATES_NAME), encoding="utf-8"))
        ok("--exclude removes a directory",
           any(c["file"].startswith("keys/") for c in doc3["candidates"]), False)
        quietly(cmd_candidates, _Args(root=tmp, max_file_bytes=20))
        doc4 = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                           CANDIDATES_NAME), encoding="utf-8"))
        truthy("--max-file-bytes caps what is read",
               doc4["counts"]["files_truncated_at_cap"] > 0)

        print("candidates: SARIF ingestion")
        # A line no pattern here spells, so the SARIF hit on it has to create its
        # own candidate rather than corroborate one - which is the half of 7's
        # "independent analyzer" that matters.
        _write(os.path.join(tmp, "yaml", "values.yaml"),
               "replicas: 2\nopaqueRef: zz--not--a--token\n")
        sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "gitleaks", "version": "8.18.2"}},
                "results": [
                    {"ruleId": "aws-access-token",
                     "message": {"text": "aws access token"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "src/app.py"},
                         "region": {"startLine": 2}}}]},
                    {"ruleId": "generic-api-key",
                     "message": {"text": "generic api key"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "yaml/values.yaml"},
                         "region": {"startLine": 2}}}]},
                ],
            }],
        }
        sarif_path = os.path.join(tmp, "gitleaks.sarif")
        _write(sarif_path, json.dumps(sarif))
        quietly(cmd_candidates, _Args(root=tmp, sarif=[sarif_path]))
        doc5 = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                           CANDIDATES_NAME), encoding="utf-8"))
        aws5 = next(c for c in doc5["candidates"]
                    if c["subkind"] == "aws-access-key-id")
        ok("a SARIF hit on a line we already found corroborates it",
           aws5["corroborated_by"],
           [{"analyzer": "gitleaks", "rule": "aws-access-token",
             "analyzer_version": "8.18.2"}])
        yaml_cand = [c for c in doc5["candidates"] if c["file"] == "yaml/values.yaml"]
        ok("a SARIF hit on a line we did not becomes its own candidate",
           (len(yaml_cand), yaml_cand[0]["subkind"] if yaml_cand else None,
            doc5["counts"]["from_sarif"]),
           (1, "sarif", 1))
        ok("and the analyzer is identified from tool.driver.name",
           yaml_cand[0]["corroborated_by"][0]["analyzer"], "gitleaks")
        # Nothing that reads a repository file may follow a path out of it.
        print("candidates: paths that leave the scanned root are NOT followed")
        outside = os.path.join(tmp, "..", "sweep_outside_root.txt")
        _write(outside, 'OUTSIDE = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"\n'
                        "second line of a file outside the tree\n")
        evil = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "gitleaks"}},
                "results": [
                    {"ruleId": "abs", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {
                             "uri": os.path.abspath(outside)},
                         "region": {"startLine": 2}}}]},
                    {"ruleId": "rel", "message": {"text": "m"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {
                             "uri": "../sweep_outside_root.txt"},
                         "region": {"startLine": 2}}}]},
                ],
            }],
        }
        evil_path = os.path.join(tmp, "evil.sarif")
        _write(evil_path, json.dumps(evil))
        quietly(cmd_candidates, _Args(root=tmp, sarif=[evil_path]))
        doc6 = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                           CANDIDATES_NAME), encoding="utf-8"))
        away = [c for c in doc6["candidates"] if c.get("cited_path_outside_root")]
        ok("a SARIF uri pointing out of the tree is marked, both spellings",
           len(away), 2)
        ok("and NOT read: the line outside the tree is nowhere in the output",
           "second line of a file outside the tree"
           in json.dumps(doc6), False)

        link = os.path.join(tmp, "notes.txt")
        try:
            os.symlink(os.path.abspath(outside), link)
            have_symlink = True
        except (OSError, NotImplementedError, AttributeError):
            have_symlink = False
            rules_lib.skip_case("a symlink out of the tree is skipped by the walk (two checks)",
                                n=2)
        if have_symlink:
            quietly(cmd_candidates, _Args(root=tmp))
            doc7 = json.load(open(os.path.join(tmp, RUN_DIR, SECRETS_DIR,
                                               CANDIDATES_NAME), encoding="utf-8"))
            ok("a symlink out of the tree is skipped by the walk, not read",
               any(c["file"] == "notes.txt" for c in doc7["candidates"]), False)
            ok("and `check` does not follow one either - abspath would have, "
               "realpath does not",
               escapes_root(tmp, "notes.txt"), True)
            os.remove(link)
        # A cap on bytes is not a cap on time. `open()` on a FIFO blocks until
        # somebody writes, so a named pipe committed to the tree under review
        # stops the sweep dead before one byte counts against --max-file-bytes.
        # The test has to be the non-blocking half of that: if read_text opened
        # it, this call would never return to fail.
        if not rules_lib.can_mkfifo():
            rules_lib.skip_case("a FIFO in the tree is not opened", "a named pipe")
        else:
            fifo = os.path.join(tmp, "src", "pipe.sock")
            try:
                os.mkfifo(fifo)
            except OSError:
                fifo = None
            if fifo:
                ok("a FIFO in the tree is not opened - the byte cap does not "
                   "bound a read that blocks",
                   read_text(fifo, DEFAULT_MAX_FILE_BYTES), (None, False))
                os.remove(fifo)
        ok("a lexically escaping citation is refused before any file is opened",
           (escapes_root(tmp, "../sweep_outside_root.txt"),
            escapes_root(tmp, "/etc/passwd"),
            escapes_root(tmp, "src/app.py")),
           (True, True, False))
        os.remove(outside)
        os.remove(evil_path)

        ok("a SARIF uri keeps the leading dot of a dotfile, which is where a "
           "secrets scanner most often has something to say",
           sarif_uri({"physicalLocation": {
               "artifactLocation": {"uri": "./.env"}}}, tmp), ".env")
        ok("and an unknown driver keeps its own name, bounded and printable - "
           "a corroboration that says \"other\" corroborates nothing",
           driver_analyzer("Acme\x07Scanner " + "x" * 200),
           "AcmeScanner " + "x" * 48)
        ok("--sarif-dir finds the same file",
           quietly(cmd_candidates, _Args(root=tmp, sarif_dir=[tmp])), EXIT_OK)

        try:
            _write(os.path.join(tmp, "bad.sarif"), "{}")
            parse_sarif(os.path.join(tmp, "bad.sarif"), tmp)
            ok("a SARIF file with no runs is refused", "accepted", "refused")
        except SweepError:
            ok("a SARIF file with no runs is refused", "refused", "refused")

    # ---------------------------------------------------------------------- #
    with tempfile.TemporaryDirectory() as tmp:
        print("check: the fixture")
        _write(os.path.join(tmp, "src", "app.py"), "\n".join([
            "import os",
            "",
            "",
            'API_KEY = "%s"' % HIGH_ENTROPY,
            "",
            "",
            "def authenticate(given):",
            "    return given == API_KEY",
            "",
            "",
            "def derive(password, salt):",
            "    return hashlib.pbkdf2_hmac('sha256', password, salt, 200000)",
            "",
        ]) + "\n")
        _write(os.path.join(tmp, RUN_DIR, FUNCTIONS_JSONL), "\n".join(json.dumps(r) for r in [
            {"function_key": "src/app.py::<module>::0", "file": "src/app.py",
             "line_start": 1, "line_end": 13},
            {"function_key": "src/app.py::authenticate::0", "file": "src/app.py",
             "line_start": 7, "line_end": 8},
            {"function_key": "src/app.py::derive::0", "file": "src/app.py",
             "line_start": 11, "line_end": 12},
        ]) + "\n")

        redacted_line = 'API_KEY = "%s"' % redact(HIGH_ENTROPY)

        def entry(**kw):
            base = {
                "entry_id": "SEC-0001",
                "kind": "secret",
                "class": "long-term-key",
                "origin": "literal",
                "is_finding": True,
                "identifiers": ["API_KEY"],
                "evidence": {"file": "src/app.py", "line": 4,
                             "code": redacted_line},
                "redacted": redact(HIGH_ENTROPY),
                "touched_by": ["src/app.py::<module>::0",
                               "src/app.py::authenticate::0"],
                "why": "A key written into the source and compared in authenticate().",
            }
            base.update(kw)
            return base

        def codes(entries):
            _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
                   json.dumps({"schema_version": 1, "entries": entries}))
            return sorted(p["code"] for p in
                          run_check(tmp, DEFAULT_ENTROPY_THRESHOLD,
                                    DEFAULT_MAX_FILE_BYTES)["problems"])

        ok("a well-formed finding passes", codes([entry()]), [])

        print("check: a REDACTED quote verifies against the REAL line")
        # Through read_text, the reader `check` uses, not a second one.
        app_lines = read_text(os.path.join(tmp, "src", "app.py"),
                              DEFAULT_MAX_FILE_BYTES)[0]
        ok("the redacted citation resolves at the line cited",
           citation_verdict(redacted_line, 4, app_lines)[0],
           "redacted")
        ok("and within the drift window verify_findings accepts",
           citation_verdict(redacted_line, 6, app_lines)[0],
           "redacted-drift")
        ok("other elision marks are accepted too, because hands write those",
           citation_verdict('API_KEY = "9fK2***B3nM6cJ5dH0sA2e"', 4, app_lines)[0],
           "redacted")
        ok("an unredacted quote still verifies the ordinary way",
           citation_verdict('API_KEY = "%s"' % HIGH_ENTROPY, 4, app_lines)[0],
           "exact")

        print("check: a FABRICATED line still fails")
        ok("a line that is not in the file at all",
           codes([entry(evidence={"file": "src/app.py", "line": 4,
                                  "code": 'API_KEY = os.environ["%s"]'
                                          % redact(HIGH_ENTROPY)})]),
           ["citation_not_found"])
        ok("an elision that elides the whole quote cannot stand in for it",
           codes([entry(evidence={"file": "src/app.py", "line": 4,
                                  "code": 'SECRET_KEY = "' + ELISION + '"'})]),
           ["citation_not_found"])
        ok("nor can single characters accumulated around elisions",
           redaction_pattern("a" + ELISION + "b" + ELISION + "c" + ELISION +
                             "d" + ELISION + "e" + ELISION + "f" + ELISION +
                             "g" + ELISION + "h"),
           None)
        ok("and a quote that is more pattern than quote is refused outright",
           redaction_pattern("API_KEY" + ELISION + "9fK2" + ELISION + "xQ7p" +
                             ELISION + "R4tL" + ELISION + "vW8z" + ELISION +
                             "sA2e"),
           None)
        ok("text that IS in the file but far from the line cited is not rescued",
           codes([entry(evidence={"file": "src/app.py", "line": 12,
                                  "code": redacted_line})]),
           ["citation_far_drift"])
        ok("a line number outside the file is refused",
           codes([entry(evidence={"file": "src/app.py", "line": 900,
                                  "code": redacted_line})]),
           ["citation_not_found"])

        print("check: THE DISCIPLINE, in both directions")
        ok("kind=secret origin=env may NOT be a finding",
           codes([entry(origin="env")]), ["is_finding_discipline"])
        ok("kind=secret origin=kdf may NOT be a finding",
           codes([entry(origin="kdf")]), ["is_finding_discipline"])
        ok("kind=secret origin=fuse-otp may NOT be a finding",
           codes([entry(origin="fuse-otp")]), ["is_finding_discipline"])
        ok("kind=public may NOT be a finding, whatever its origin",
           codes([entry(kind="public", origin="literal", **{"class": None})]),
           ["is_finding_discipline"])
        ok("and kind=secret origin=literal MUST be one",
           codes([entry(is_finding=False)]), ["is_finding_discipline"])
        ok("an env read that is correctly NOT a finding passes",
           codes([entry(origin="env", is_finding=False,
                        **{"class": "session-token"})]), [])

        print("check: class against kind")
        ok("a public entry may not carry a class",
           codes([entry(kind="public", is_finding=False,
                        **{"class": "long-term-key"})]),
           ["class_kind_mismatch"])
        ok("a secret entry must carry one",
           codes([entry(origin="env", is_finding=False, **{"class": None})]),
           ["class_kind_mismatch"])
        ok("and it must be in the enum",
           codes([entry(origin="env", is_finding=False,
                        **{"class": "very-secret"})]),
           ["schema_bad_enum"])

        print("check: schema")
        broken = entry()
        del broken["identifiers"]
        del broken["touched_by"]
        ok("missing required fields are named",
           codes([broken]),
           ["schema_bad_type", "schema_bad_type", "schema_missing_field",
            "schema_missing_field"])
        ok("an unknown origin is refused",
           codes([entry(origin="telepathy", is_finding=False)]),
           ["schema_bad_enum"])
        ok("a duplicate entry_id is refused",
           codes([entry(), entry()]), ["duplicate_entry_id"])
        ok("a schema_version from the future is refused, not guessed at",
           _future_version_refused(tmp), True)

        print("check: redaction - the sweeper must not be a leak")
        ok("an entry quoting the whole secret is refused",
           codes([entry(evidence={"file": "src/app.py", "line": 4,
                                  "code": 'API_KEY = "%s"' % HIGH_ENTROPY},
                        redacted=HIGH_ENTROPY)]),
           ["redaction_leak", "redaction_leak"])
        ok("a whole secret in `redacted` alone is refused",
           codes([entry(redacted=HIGH_ENTROPY)]), ["redaction_leak"])
        ok("but a legitimate identifier on the cited line is not a leak",
           codes([entry(origin="kdf", is_finding=False,
                        **{"class": "long-term-key",
                           "identifiers": ["password"],
                           "redacted": None,
                           "evidence": {
                               "file": "src/app.py", "line": 12,
                               "code": "return hashlib.pbkdf2_hmac('sha256', "
                                       "password, salt, 200000)"},
                           "touched_by": ["src/app.py::derive::0"]})]),
           [])
        ok("a finding with nothing to name is refused",
           codes([entry(redacted=None)]), ["redaction_missing"])

        ok("a citation that leaves the tree is refused, not followed",
           codes([entry(evidence={"file": "../../../etc/passwd", "line": 1,
                                  "code": "root:x:0:0:root:/root:/bin/bash"})]),
           ["citation_outside_root"])
        ok("and so is an absolute one",
           codes([entry(evidence={"file": "/etc/passwd", "line": 1,
                                  "code": "root:x:0:0:root:/root:/bin/bash"})]),
           ["citation_outside_root"])

        print("check: touched_by")
        ok("a key that is not shaped like one is refused",
           codes([entry(touched_by=["src/app.py:authenticate"])]),
           ["touched_by_malformed"])
        ok("a key naming a function not in the corpus is refused",
           codes([entry(touched_by=["src/app.py::ghost::0"])]),
           ["touched_by_unknown_function"])
        ok("an empty touched_by is fine - a credential in a YAML file touches "
           "no function", codes([entry(touched_by=[])]), [])
        ok("and one that is not a list is a type problem, not 44 malformed keys",
           codes([entry(touched_by="src/app.py::authenticate::0")]),
           ["schema_bad_type"])

        print("check: a bare array is accepted, because an agent may write one")
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps([entry()]))
        ok("a bare array of entries checks clean",
           run_check(tmp, DEFAULT_ENTROPY_THRESHOLD,
                     DEFAULT_MAX_FILE_BYTES)["problems"], [])

        print("check: what the sweeper did NOT judge")
        # `check` reads only the entries that are there, so a sweeper that
        # skipped half its candidate list passes it clean - and the one thing on
        # this track that IS a finding is a hardcoded secret. Counted, never
        # refused: most literal candidates in a crypto tree are correctly
        # declined, and a checker nobody can satisfy is one somebody turns off.
        # A private key in the tree that the inventory below never mentions -
        # the drop that matters, since it is the one shape on this track that
        # contract 4a makes a finding.
        _write(os.path.join(tmp, "keys", "id_rsa"), PEM)
        quietly(cmd_candidates, _Args(root=tmp))
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [entry()]}))
        result = run_check(tmp, DEFAULT_ENTROPY_THRESHOLD, DEFAULT_MAX_FILE_BYTES)
        ok("a hardcoded key no entry cites is counted, by id and location",
           [(r["candidate_id"] is not None, r["file"], r["subkind"])
            for r in (result["unjudged"] or {"sample": []})["sample"]],
           [(True, "keys/id_rsa", "pem-private-key")])
        ok("and counting it is not refusing it - the exit code is unchanged",
           quietly(cmd_check, _Args(root=tmp)), EXIT_OK)
        ok("and with no candidates.json to compare against it says None, "
           "because an absent file is not evidence of a complete sweep",
           (lambda p: (os.rename(p, p + ".moved"),
                       run_check(tmp, DEFAULT_ENTROPY_THRESHOLD,
                                 DEFAULT_MAX_FILE_BYTES)["unjudged"],
                       os.rename(p + ".moved", p))[1])(
               os.path.join(tmp, RUN_DIR, SECRETS_DIR, CANDIDATES_NAME)),
           None)

        print("check and status: exit codes")
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [entry()]}))
        ok("check exits 0 on a clean inventory",
           quietly(cmd_check, _Args(root=tmp)), EXIT_OK)
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [entry(origin="env")]}))
        ok("and 2 on a discipline violation",
           quietly(cmd_check, _Args(root=tmp)), EXIT_REFUSED)

        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [
                   entry(),
                   entry(entry_id="SEC-0002", origin="env", is_finding=False,
                         **{"class": "session-token"}),
                   entry(entry_id="SEC-0003", kind="public", is_finding=False,
                         origin="wire", **{"class": None, "redacted": None}),
               ]}))
        status = _capture(lambda: cmd_status(_Args(root=tmp, as_json=False)))
        ok("status separates findings from inventory from public",
           ("FINDINGS - secrets HARDCODED" in status,
            "INVENTORY - NOT findings" in status,
            "PUBLIC - values the attacker already holds" in status),
           (True, True, True))
        ok("status counts each section",
           ("--> 1 finding(s)" in status,
            "--> 1 inventory entr(ies). Not findings." in status,
            "--> 1 public entr(ies)." in status),
           (True, True, True))
        ok("and status does not print a whole secret either",
           HIGH_ENTROPY in status, False)

        # THE DISCIPLINE, in the command a PERSON reads. `check` refuses a wrong
        # `is_finding`, but nothing makes `check` run, and `status` used to
        # believe the field.
        print("status: THE DISCIPLINE, in the command a person reads")
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [
                   entry(entry_id="SEC-0001", origin="env", is_finding=True)]}))
        held = _capture(lambda: cmd_status(_Args(root=tmp, as_json=False)))
        ok("a HELD secret claiming to be a finding is not printed as one",
           ("DISCIPLINE VIOLATION" in held,
            "--> 0 finding(s)" in held,
            "--> 1 inventory entr(ies). Not findings." in held),
           (True, True, True))
        ok("and status exits 2 on it, so a clean exit still means a clean file",
           quietly(cmd_status, _Args(root=tmp, as_json=False)), EXIT_REFUSED)

        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [
                   entry(entry_id="SEC-0001", origin="literal",
                         is_finding=False)]}))
        hidden = _capture(lambda: cmd_status(_Args(root=tmp, as_json=False)))
        ok("a HARDCODED secret claiming not to be a finding still is one",
           ("DISCIPLINE VIOLATION" in hidden,
            "--> 1 finding(s)" in hidden,
            "none. No secret in this repository" in hidden),
           (True, True, False))
        ok("the json format routes by the rule too, and names the violation",
           _discipline_json(tmp),
           (0, 1, 1))

        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [
                   entry(entry_id="SEC-0001", kind="banana")]}))
        odd = _capture(lambda: cmd_status(_Args(root=tmp, as_json=False)))
        ok("an entry with a kind outside the enum is named, not dropped",
           ("classified nowhere" in odd, "--> 0 finding(s)" in odd),
           (True, True))

        # The narrowest way out: a typo in `origin` makes the rule compute
        # `false`, which MATCHES an `is_finding: false` claim - so no violation
        # fires and a hardcoded secret is filed as inventory.
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [
                   entry(entry_id="SEC-0001", origin="Literal",
                         is_finding=False)]}))
        typo = _capture(lambda: cmd_status(_Args(root=tmp, as_json=False)))
        ok("a typo in `origin` cannot file a hardcoded secret as inventory",
           ("DISCIPLINE VIOLATION" in typo,
            "is not one of the 4a origins" in typo,
            quietly(cmd_status, _Args(root=tmp, as_json=False))),
           (True, True, EXIT_REFUSED))

        # `status` reads a file this tool did not write, so it must not trust it.
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
               json.dumps({"schema_version": 1, "entries": [
                   entry(redacted=HIGH_ENTROPY,
                         why="the key is %s, in full" % HIGH_ENTROPY)]}))
        leaky = _capture(lambda: cmd_status(_Args(root=tmp, as_json=False)))
        leaky_json = _capture(lambda: cmd_status(_Args(root=tmp, as_json=True)))
        ok("a leaky inventory is still not printed whole - by either format",
           (HIGH_ENTROPY in leaky, HIGH_ENTROPY in leaky_json), (False, False))

        missing = os.path.join(tmp, "elsewhere")
        os.makedirs(missing, exist_ok=True)
        try:
            run_check(missing, DEFAULT_ENTROPY_THRESHOLD, DEFAULT_MAX_FILE_BYTES)
            ok("a missing inventory exits 3", "found", "no-input")
        except SweepError as exc:
            ok("a missing inventory exits 3", exc.code, EXIT_NO_INPUT)

    # ---- in_test_tree: marked, never dropped ---- #
    # On libxml2 this tool handed the sweeper agent 1953 candidates of which
    # 1803 were in test/ and result/, with nothing on the record to say so. The
    # prompt forbids dismissing a file because its path says test - its §4 is
    # built around a real credential in a test directory - so the fix is a fact
    # on the record, not a filter.
    with tempfile.TemporaryDirectory() as tmp:
        run = os.path.join(tmp, RUN_DIR)
        os.makedirs(run)
        ok("with no manifest at all, no globs are claimed",
           declared_test_globs(tmp), ())
        with open(os.path.join(run, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"test_tree_globs": ["test/**", "result/**"]}, fh)
        ok("the manifest's globs are read",
           declared_test_globs(tmp), ("test/**", "result/**"))
        with open(os.path.join(run, "manifest.json"), "w", encoding="utf-8") as fh:
            fh.write("{ not json")
        ok("an unreadable manifest claims nothing rather than guessing",
           declared_test_globs(tmp), ())
        with open(os.path.join(run, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"test_tree_globs": ["ok/**", 7, "", None]}, fh)
        ok("and non-string entries are dropped, not passed to fnmatch",
           declared_test_globs(tmp), ("ok/**",))

    # The marking itself is the extractor's function, shared so the two stages
    # cannot disagree about what a test tree is.
    ok("a file under a declared test tree is marked",
       ef.in_test_tree("test/threads/abc.xml", ("test/**", "result/**")), True)
    ok("and one beside it is not",
       ef.in_test_tree("parser.c", ("test/**", "result/**")), False)

    def load_candidates(root):
        with open(os.path.join(root, RUN_DIR, SECRETS_DIR, CANDIDATES_NAME),
                  encoding="utf-8") as fh:
            return json.load(fh)

    # The extractor marks tests/ by name with no globs at all, so the sweep
    # must too: on pyjwt, with an empty test_tree_globs, all 352 candidates
    # under tests/ came out unmarked while stage 1 marked the same files.
    with tempfile.TemporaryDirectory() as tmp:
        _write(os.path.join(tmp, "tests", "keys", "conf.py"),
               'password = "hunter2hunter2"\n')
        _write(os.path.join(tmp, "src", "conf.py"),
               'password = "hunter2hunter2"\n')
        quietly(cmd_candidates, _Args(root=tmp))
        marked = {c["file"]: c["in_test_tree"]
                  for c in load_candidates(tmp)["candidates"]}
        ok("with no manifest test_tree_globs, a candidate under tests/ is still "
           "marked, by the extractor's own test names, and one in src/ is not",
           (marked.get(os.path.join("tests", "keys", "conf.py")),
            marked.get(os.path.join("src", "conf.py"))), (True, False))

    # ---- random mixed case is not an identifier ---- #
    # The camelCase split broke random base64 into word-shaped pieces, and
    # identifier_shaped() threw away 15% of 20-character tokens and 4% of
    # 40-character ones - an AWS secret access key among them. Seeded, so the
    # floor is a fact about this code and not about a lucky draw.
    import base64
    import random
    print("entropy: random mixed case is key material, identifiers are not")
    draw = random.Random(4242)
    for length, floor in ((32, 0.98), (40, 0.99)):
        tokens = [base64.b64encode(draw.getrandbits(384).to_bytes(48, "big"))
                  .decode("ascii")[:length] for _ in range(1000)]
        kept = sum(1 for t in tokens if looks_like_key_material(
            t, DEFAULT_ENTROPY_THRESHOLD, DEFAULT_ENTROPY_MIN_LENGTH)) / 1000.0
        ok("at least %d%% of random %d-character base64 tokens are key material"
           % (int(floor * 100), length), kept >= floor, True)
    ok("and every identifier the docstring names is still one",
       [identifier_shaped(t) for t in (
           "mbedtls_pkcs5_pbkdf2_hmac_ext", "aes_256_gcm_encrypt_ctx",
           "AESKeyWrapUnwrapTest256", "arbitration/ARB-CAND-001",
           "max_bytes=MAX_FILE_BYTES")], [True] * 5)
    ok("and so is a name carrying a named curve",
       [identifier_shaped(t) for t in (
           "tests/keys/testkey_ec_secp192r1", "ecdsa_secp256k1_verify",
           "load_prime256v1_key", "brainpoolP384r1_params")], [True] * 4)
    ok("while a curve-shaped piece inside a token does not launder it",
       looks_like_key_material("sk-live-secp256r1-9f2c1ab4e0d73516aaaa",
                               DEFAULT_ENTROPY_THRESHOLD, DEFAULT_ENTROPY_MIN_LENGTH),
       True)
    ok("the credential files are config files, so their values are read",
       (config_file(".aws/credentials"), config_file("home/.pypirc"),
        config_file(".s3cfg"), config_file("src/credentials.py")),
       (True, True, True, False))

    # ---- a private key written as a string literal is a key ---- #
    # Compiled into C, Go or JS the body is `"MIIE...\n"` a line; in a
    # service-account JSON it is all on the BEGIN line. Both came out as
    # `pem_body_lines: 0` - the one field that says "a mention, not a key".
    print("candidates: a private key inside string literals is a key, not a mention")
    pem_lines = PEM.strip().split("\n")
    plain = [c for c in merge_literals(scan_file("k.pem", pem_lines, 3.6, 20,
                                                 "s", False))
             if c["subkind"] == "pem-private-key"]
    forms = (
        ("a C string per line",
         ["static const char k[] ="] + ['    "%s\\n"' % l for l in pem_lines] + [";"]),
        ("a JS string per line, joined by +",
         ["const k ="] + ["  '%s\\n' +" % l for l in pem_lines[:-1]]
         + ["  '%s\\n';" % pem_lines[-1]]),
        ("one JSON line with \\n escapes", [json.dumps({"private_key": PEM})]),
    )
    for label, form in forms:
        found = merge_literals(scan_file("k.c", form, 3.6, 20, "s", False))
        pem = [c for c in found if c["subkind"] == "pem-private-key"]
        ok("%s: read as a body, and terminated" % label,
           [(c["pem_body_lines"], c["pem_terminated"]) for c in pem], [(2, True)])
        ok("%s: the same fingerprint as the plain PEM" % label,
           pem[0]["fingerprint"] if pem else None, plain[0]["fingerprint"])
        ok("%s: its body is not re-found as entropy" % label,
           [c["line"] for c in found if c["subkind"] == "high-entropy"], [])
        ok("%s: and the body is nowhere in the output" % label,
           "MIIEowIBAAKCAQEA" in json.dumps(found), False)
    ok("a marker quoted in code is still a mention: nothing below it is unwrapped",
       [(c["pem_body_lines"], c["pem_terminated"]) for c in merge_literals(
           scan_file("m.py", ['MARK = "-----BEGIN RSA PRIVATE KEY-----"',
                              'x = "ok"', 'y = "fine"'], 3.6, 20, "s", False))
        if c["subkind"] == "pem-private-key"],
       [(0, False)])

    with tempfile.TemporaryDirectory() as tmp:
        # ---- every literal on a line is redacted in every record of it ---- #
        # scrub() is an entropy test, and it was the only thing between a
        # candidate's line_text and the SECOND secret on its line.
        print("candidates: every literal on a line is redacted in every record of it")
        _write(os.path.join(tmp, "src", "creds.py"), "\n".join([
            'db = connect(user="admin", password="hunter2hunter2", '
            'backup_password="letmein12345")',
            'x = os.environ.get("X"); password = "correcthorse99"',
            'client = Client(api_key="%s", password="qwerty123456")' % STRIPE_KEY,
            'CACHE = "redis://:s3cr3tcachepw@cache.internal:6379/0"',
            'LOCAL = "http://[::1]:8080/x"',
            'password="opensesame2024" + os.environ["SUFFIX"]',
            "",
        ]))
        _write(os.path.join(tmp, "c.json"),
               '{"db_password": "hunter2hunter2", "redis_password": '
               '"letmein12345", "smtp_pass": "qwerty123456"}\n')
        _write(os.path.join(tmp, ".aws", "credentials"),
               "[default]\n"
               "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
               "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
        _write(os.path.join(tmp, "docker-compose.yml"),
               "services:\n  worker:\n    environment:\n"
               "      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0\n"
               "      DATABASE_URL: postgres://app:${POSTGRES_PASSWORD}@db:5432/app\n")
        ok("the command succeeds", quietly(cmd_candidates, _Args(root=tmp)), EXIT_OK)
        doc = load_candidates(tmp)
        cands = doc["candidates"]
        blob = json.dumps(doc)
        for secret in ("hunter2hunter2", "letmein12345", "correcthorse99",
                       "qwerty123456", "s3cr3tcachepw", STRIPE_KEY,
                       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                       "opensesame2024"):
            ok("%s is nowhere in candidates.json" % redact(secret),
               secret in blob, False)
        ok("and a literal is never read back as the NEXT match's identifier",
           [c["identifier"] for c in cands if c["kind"] == "source"
            and c["file"] == "src/creds.py" and c["line"] == 6], [None])
        # The entropy run over `GH=ghp_…` holds the name too, and is the same
        # secret as the token, so it is no reason to drop the name - dropping it
        # let the merge name `const` in `const k=AKIA…` instead.
        named = merge_literals(scan_file(
            "src/n.js", ["GH=" + GH_TOKEN, "const k=%s;" % AWS_KEY],
            DEFAULT_ENTROPY_THRESHOLD, DEFAULT_ENTROPY_MIN_LENGTH, "s", False))
        ok("a name `=` glues to its token is still that token's name",
           [(c["subkind"], c["identifier"]) for c in named],
           [("github-token", "GH"), ("aws-access-key-id", "k")])
        env_read = [c for c in cands if c["kind"] == "source"
                    and c["file"] == "src/creds.py" and c["line"] == 2]
        ok("an env read on a password's line carries the password redacted",
           [redact("correcthorse99") in c["line_text"] for c in env_read], [True])
        stripe = [c for c in cands if c["subkind"] == "stripe-key"]
        ok("a key's line_text carries the password beside it redacted too",
           [redact("qwerty123456") in c["line_text"] for c in stripe], [True])
        ok("each password on a two-password line is its own candidate",
           len([c for c in cands if c["file"] == "src/creds.py" and c["line"] == 1
                and c["kind"] == "literal"]), 2)

        # ---- an empty user is still basic auth ---- #
        print("candidates: `redis://:password@host` is basic auth")
        redis = [c for c in cands if c["file"] == "src/creds.py" and c["line"] == 4]
        ok("a URL with an empty user is found",
           [c["subkind"] for c in redis], ["basic-auth-in-url"])
        ok("with the password redacted and the host kept for context",
           [("cache.internal" in c["line_text"], redact("s3cr3tcachepw")
             in c["line_text"]) for c in redis], [(True, True)])
        ok("and `[::1]:8080` is not mistaken for one",
           [c["subkind"] for c in cands if c["file"] == "src/creds.py"
            and c["line"] == 5], [])
        # Allowing the empty user made compose's own spelling of "the password
        # comes from the environment" a hardcoded one.
        ok("nor is a URL whose password is an interpolation, with or without a user",
           [(c["line"], c["subkind"]) for c in cands
            if c["file"] == "docker-compose.yml" and c["kind"] == "literal"], [])
        ok("and `check` does not hold one as a literal a quote may not carry",
           line_literals("docker-compose.yml",
                         "REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0"), [])

        # Unbounded, the scheme made a million-`a` line cost this family twenty
        # minutes (see the family). Timing it here would be a flaky test; where
        # a long scheme's match starts is what the cap changes, so that is what
        # is held, in both of the regexes built from the family table.
        print("candidates: a URL's scheme is capped at 32 characters")
        basic = dict(KNOWN_TOKEN_RE)["basic-auth-in-url"]
        tail = "://admin:s3cretpassword@db.internal:5432/app"
        ok("a 32-character scheme is matched whole",
           basic.search("s" * 32 + tail).start(), 0)
        ok("a longer one from its last 32, with the same password and host",
           [(m.start(), m.group("secret"), m.group(0).split("@")[1])
            for m in basic.finditer("s" * 40 + tail)],
           [(8, "s3cretpassword", "db.internal:5432")])
        ok("and the alternation covered_by_known_family() searches is capped too",
           KNOWN_TOKEN_ANY.search("s" * 40 + tail).start(), 8)
        ok("a password past column %d is still found: lines are not clipped "
           "before the families run" % MAX_LINE_CHARS,
           [(hit[0], hit[1], hit[2][0] > MAX_LINE_CHARS) for hit in literal_hits(
               "notes.txt", "-" * 500 + " postgres" + tail, 3.6, 20, True)],
           [("basic-auth-in-url", "s3cretpassword", True)])

        print("candidates: a committed .aws/credentials")
        ok("the secret access key is a candidate, not only the key id beside it",
           sorted((c["line"], c["subkind"]) for c in cands
                  if c["file"] == ".aws/credentials"),
           [(2, "aws-access-key-id"), (3, "env-assignment")])

    with tempfile.TemporaryDirectory() as tmp:
        # ---- lines are numbered the way stage 1 numbers them ---- #
        # splitlines() also breaks on \f, \v, U+2028 and friends, so four page
        # breaks moved a password inside login() past the end of its file.
        print("candidates and check: lines are numbered by \\n, as stage 1 numbers them")
        text = ("/* page one */\n\f\n\f\n\v\n\f\n/* \u2028 in a comment */\n"
                "int login(void)\n{\n"
                '  const char *password = "%s";\n'
                "  return 0;\n}\n" % HIGH_ENTROPY)
        _write(os.path.join(tmp, "src", "a.c"), text)
        at = text.count("\n", 0, text.index(HIGH_ENTROPY)) + 1
        _write(os.path.join(tmp, RUN_DIR, FUNCTIONS_JSONL), json.dumps(
            {"function_key": "src/a.c::login::0", "file": "src/a.c",
             "line_start": 7, "line_end": 11}) + "\n")
        leaks = os.path.join(tmp, "gitleaks.sarif")
        _write(leaks, json.dumps({"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{"ruleId": "generic-api-key", "message": {"text": "m"},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "src/a.c"},
                             "region": {"startLine": at}}}]}]}]}))
        quietly(cmd_candidates, _Args(root=tmp, sarif=[leaks]))
        doc = load_candidates(tmp)
        mine = [c for c in doc["candidates"] if c["file"] == "src/a.c"]
        ok("the candidate is at the line grep and stage 1 say, in its function",
           [(c["line"], c["function_key"]) for c in mine],
           [(at, "src/a.c::login::0")])
        ok("so a gitleaks hit at that line corroborates it, and adds nothing",
           ([c["corroborated_by"][0]["analyzer"] for c in mine if c["corroborated_by"]],
            doc["counts"]["from_sarif"]), (["gitleaks"], 0))
        _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME), json.dumps(
            {"schema_version": 1, "entries": [{
                "entry_id": "SEC-0001", "kind": "secret", "class": "password-or-pin",
                "origin": "literal", "is_finding": True, "identifiers": ["password"],
                "evidence": {"file": "src/a.c", "line": at,
                             "code": 'const char *password = "%s";'
                                     % redact(HIGH_ENTROPY)},
                "redacted": redact(HIGH_ENTROPY),
                "touched_by": ["src/a.c::login::0"]}]}))
        ok("and `check` accepts an entry citing that line",
           [p["code"] for p in run_check(tmp, DEFAULT_ENTROPY_THRESHOLD,
                                         DEFAULT_MAX_FILE_BYTES)["problems"]], [])
        ok("a CRLF file still reads as it did: no \\r on the end of a line",
           source_lines(b"a\r\nb\fc\r\n\n"), ["a", "b\fc", ""])

    with tempfile.TemporaryDirectory() as tmp:
        # ---- a whole LOW-entropy secret is refused by check ---- #
        print("check: a whole low-entropy secret is refused, and status does not print it")
        _write(os.path.join(tmp, "src", "pins.py"),
               'import os\nADMIN_PASSWORD = "hunter2hunter2"\n'
               'password = "password"\n')
        whole_line = 'ADMIN_PASSWORD = "hunter2hunter2"'

        def pin(**kw):
            base = {"entry_id": "SEC-0001", "kind": "secret",
                    "class": "password-or-pin", "origin": "literal",
                    "is_finding": True, "identifiers": ["ADMIN_PASSWORD"],
                    "evidence": {"file": "src/pins.py", "line": 2,
                                 "code": 'ADMIN_PASSWORD = "hunt'},
                    "redacted": "<14 chars>", "touched_by": []}
            base.update(kw)
            return base

        def pin_codes(entries):
            _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
                   json.dumps({"schema_version": 1, "entries": entries}))
            return sorted(p["code"] for p in run_check(
                tmp, DEFAULT_ENTROPY_THRESHOLD, DEFAULT_MAX_FILE_BYTES)["problems"])

        ok("a `<shape>` redaction and a truncated quote pass", pin_codes([pin()]), [])
        ok("so does an elided one", pin_codes([pin(redacted=redact("hunter2hunter2"))]),
           [])
        ok("the whole password in `redacted` is refused",
           pin_codes([pin(redacted="hunter2hunter2")]), ["redaction_leak"])
        ok("the whole line quoted in evidence.code is refused",
           pin_codes([pin(evidence={"file": "src/pins.py", "line": 2,
                                    "code": whole_line})]), ["redaction_leak"])
        ok("a bare value in a literal's `redacted` is refused, family or not",
           pin_codes([pin(redacted="12345678")]), ["redaction_leak"])
        # The name IS the value here, so no quote of the line can leave the
        # literal out: only holding it more often than the line does is a leak.
        named = {"file": "src/pins.py", "line": 3}
        ok("a password spelled like its own name can still be quoted, elided",
           pin_codes([pin(identifiers=["password"], redacted="<8 chars>",
                          evidence=dict(named, code='password = "pa…rd"'))]), [])
        ok("or truncated before the value",
           pin_codes([pin(identifiers=["password"], redacted="<8 chars>",
                          evidence=dict(named, code='password = "'))]), [])
        ok("but not with the value beside the name whole",
           pin_codes([pin(identifiers=["password"], redacted="<8 chars>",
                          evidence=dict(named, code='password = "password"'))]),
           ["redaction_leak"])
        ok("but a PUBLIC entry may quote a value the attacker already holds",
           pin_codes([pin(kind="public", is_finding=False,
                          evidence={"file": "src/pins.py", "line": 2,
                                    "code": whole_line},
                          **{"class": None, "redacted": None})]), [])
        pin_codes([pin(redacted="hunter2hunter2",
                       evidence={"file": "src/pins.py", "line": 2,
                                 "code": whole_line})])
        said = _capture(lambda: cmd_status(_Args(root=tmp, as_json=False)))
        said_json = _capture(lambda: cmd_status(_Args(root=tmp, as_json=True)))
        ok("status prints it in neither format",
           ("hunter2hunter2" in said, "hunter2hunter2" in said_json), (False, False))

    if not rules_lib.can_symlink():
        rules_lib.skip_case("the run directory is never reached through a link (seven checks)",
                            n=7)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            # ---- the run directory is never reached through a link ---- #
            # The tree may commit `.security-review/` - the ledger lives there -
            # and every one of these used to exit 0 with candidates.json, a map
            # of the repository's credentials, written wherever the link went.
            print("candidates: the run directory is never reached through a link")
            outside = os.path.join(tmp, "outside")
            victim = os.path.join(outside, "victim.txt")
            _write(victim, "VICTIM\n")

            def attempt(root):
                try:
                    quietly(cmd_candidates, _Args(root=root))
                except SweepError as exc:
                    return exc.code, str(exc)
                return EXIT_OK, ""

            def repo(name):
                root = os.path.join(tmp, name)
                _write(os.path.join(root, "src", "app.py"),
                       'password = "correct-horse-battery"\n')
                return root

            root = repo("into-src")
            os.symlink("src", os.path.join(root, RUN_DIR))
            code, said = attempt(root)
            ok("a committed `.security-review -> src` is refused, naming the link",
               (code, "symlink" in said, "§9 rule 2" in said),
               (EXIT_USAGE, True, True))
            ok("and nothing was written into src/",
               sorted(os.listdir(os.path.join(root, "src"))), ["app.py"])

            root = repo("secrets-away")
            away = os.path.join(outside, "away")
            os.makedirs(away)
            os.makedirs(os.path.join(root, RUN_DIR))
            os.symlink(away, os.path.join(root, RUN_DIR, SECRETS_DIR))
            ok("a real run directory holding `secrets -> elsewhere` is refused",
               (attempt(root)[0], os.listdir(away)), (EXIT_USAGE, []))

            root = repo("planted-tmp")
            os.makedirs(os.path.join(root, RUN_DIR, SECRETS_DIR))
            os.symlink(victim, os.path.join(root, RUN_DIR, SECRETS_DIR,
                                            CANDIDATES_NAME + ".tmp"))
            with open(victim, encoding="utf-8") as fh:
                before = fh.read()
            code, _said = attempt(root)
            with open(victim, encoding="utf-8") as fh:
                after = fh.read()
            ok("a planted `candidates.json.tmp` link is never written through",
               (code, after == before,
                os.path.islink(os.path.join(root, RUN_DIR, SECRETS_DIR,
                                            CANDIDATES_NAME))),
               (EXIT_OK, True, False))

            root = repo("linked-candidates")
            os.makedirs(os.path.join(root, RUN_DIR, SECRETS_DIR))
            os.symlink(victim, os.path.join(root, RUN_DIR, SECRETS_DIR,
                                            CANDIDATES_NAME))
            ok("a link AT candidates.json is refused",
               attempt(root)[0], EXIT_USAGE)

            root = repo("dangling-gitignore")
            os.makedirs(os.path.join(root, RUN_DIR))
            created = os.path.join(outside, "created-by-gitignore")
            os.symlink(created, os.path.join(root, RUN_DIR, ".gitignore"))
            ok("a dangling .gitignore link is refused, and creates nothing",
               (attempt(root)[0], os.path.lexists(created)), (EXIT_USAGE, False))

            clean = repo("clean")
            os.symlink(clean, os.path.join(tmp, "via-link"))
            ok("--root may itself be a link: only what is below it is checked",
               attempt(os.path.join(tmp, "via-link"))[0], EXIT_OK)

    with tempfile.TemporaryDirectory() as tmp:
        # ---- a `*` that swallowed the ledger is given it back ---- #
        print("candidates: a .gitignore of `*` gets the ledger carved back out")
        _write(os.path.join(tmp, "src", "app.py"), "x = 1\n")
        ignore = os.path.join(tmp, RUN_DIR, ".gitignore")
        _write(ignore, "*\n")
        quietly(cmd_candidates, _Args(root=tmp))
        with open(ignore, encoding="utf-8") as fh:
            body = fh.read()
        ok("appended after the `*`, not overwritten",
           (body.startswith("*\n"), "!ledger/" in body.split("\n"),
            "!ledger/**" in body.split("\n")), (True, True, True))

    # ---- `:=` and `=>` are assignment glue too ---- #
    # LOG-005 flags Go's `apiKey := "..."` and PHP's `'password' => '...'`, and
    # `[:=]` left the other half of each glue between the name and the quote.
    print("candidates: Go and PHP spell an assignment the rule already flags")
    for rel, lines, value, lineno in (
            ("svc/conn.go", ["func connect() error {",
                             '\tapiKey := "abcd1234efgh5678"',
                             "\treturn dial(apiKey)", "}"],
             "abcd1234efgh5678", 2),
            ("web/config.php", ["<?php", "$db = ['password' => 'hunter2-not'];"],
             "hunter2-not", 2)):
        found = [c for c in merge_literals(scan_file(rel, lines, 3.6, 20, "s", False))
                 if c["kind"] == "literal"]
        ok("%s gives a secret-assignment candidate at the line" % rel,
           [(c["subkind"], c["line"], c["literal_length"]) for c in found],
           [("secret-assignment", lineno, len(value))])
        ok("...with the value redacted out of the line it records",
           value in json.dumps(found), False)

    # ---- driver names are compared without their separators ---- #
    print("SARIF: a secrets scanner is known by its name however it is spelled")
    ok("detect-secrets, however it is spelled, is one known scanner",
       [driver_analyzer(n) for n in ("detect-secrets", "Detect Secrets",
                                     "detect_secrets", "DetectSecrets")],
       ["detect-secrets"] * 4)
    ok("and the others still resolve",
       [driver_analyzer(n) for n in ("Gitleaks", "Nosey Parker", "TruffleHog v3")],
       ["gitleaks", "noseyparker", "trufflehog"])

    # ---- citations are compared the way the gate compares them ---- #
    print("check: a quote is held to verify_findings.quote_at, not to one line")
    split = ["def connect():",
             "    password = (",
             '        "hunter2hunter2")',
             "    return db(password)"]
    ok("an assignment broken over two lines and quoted joined verifies",
       citation_verdict('password = ( "hunter2hunter2")', 2, split), ("exact", 2))
    ok("and so does a quote copied with its listing's line number",
       citation_verdict("2:     password = (", 2, split), ("exact", 2))
    ok("while a guard wrapped round a real line is not in the file",
       citation_verdict("if (n > MAX) return db(password)", 4, split),
       ("not-found", None))

    # ---- the one detector for text that leaves the machine ---- #
    # Canaries built at run time, so a secret sweep over this skill does not
    # read the source as leaking.
    print("outbound: export_spans")
    password = "Winter" + "2026Payroll"
    url_pw = "S3cr3t" + "Passw0rd"
    key_bytes = ("0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, "
                 "0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c")
    sha = "a83fcd7b2e9c4f1a0d5e6b7c8d9e0f1a2b3c4d5e"

    def found(text):
        return [(kind, text[start:end]) for start, end, kind in export_spans(text)]

    for label, text, want in (
            ("a quoted password of no particular entropy (LOG-005)",
             'password = "%s"' % password, [("assign", password)]),
            ("one at LOG-005's six-character floor",
             'pwd = "hun' + 't3r";', [("assign", "hun" + "t3r")]),
            ("a Go declaration", 'apiKey := "abcd1234efgh5678"',
             [("assign", "abcd1234efgh5678")]),
            ("a PHP array key", "'password' => 'hunter2-not'",
             [("assign", "hunter2-not")]),
            ("a URL password with no user: the password, not the host",
             'REDIS_URL = "redis://:%s@cache:6379/0"' % url_pw,
             [("family", url_pw)]),
            ("a known family inside prose, and the entropy run it also is",
             "The key %s is committed." % AWS_KEY,
             [("family", AWS_KEY), ("entropy", AWS_KEY)]),
            ("a truncation is not a redaction",
             'password = "Pr0dPassw0rd' + ELISION + '"',
             [("assign", "Pr0dPassw0rd" + ELISION)])):
        ok("export_spans finds %s" % label, found(text), want)
    ok("a key byte array's body, and its continuation line",
       ([k for k, _ in found("static const uint8_t aes_key[16] = {%s};" % key_bytes)],
        [k for k, _ in found("    %s," % key_bytes)]),
       (["array", "hex-bytes"], ["hex-bytes"]))
    ok("a decimal array with leading zeros is read, not a ValueError",
       [k for k, _ in found("uint8_t key[4] = {08, 09, 10, 11};")], ["array"])
    for label, text in (
            ("the endpoint a token is fetched from",
             'TOKEN_URL = "http://auth.internal/oauth/token"'),
            ("the algorithm a password is hashed with",
             'PASSWORD_HASH_ALGO = "pbkdf2_sha1"'),
            ("the header a token travels in", 'authHeader: "X-Auth-Token"'),
            ("prose under a descriptor", 'password_prompt = "Enter your password"'),
            ("an interpolation", 'password = "${DB_PASSWORD}"'),
            ("a redacted value", 'password = "Wint' + ELISION + 'roll"'),
            ("a zeroed buffer", "uint8_t key[32] = {0};"),
            ("a fix-commit URL", "fixed in https://github.com/acme/widget/commit/" + sha),
            ("a blob URL at a line",
             "see https://github.com/acme/widget/blob/%s/src/parse.c#L42" % sha)):
        ok("and not %s" % label, found(text), [])
    ok("while a token that is a URL path segment is still caught",
       [k for k, _ in found("https://chat.example.com/api/webhooks/1234/"
                            "Xq7vK2pL9mN4rT8wZ1yB" + "3cD5fG6hJ0kQeRsUaVbWcYdE")],
       ["entropy"])
    # A `/` separates only in a URL's path. The user of a clone URL is a token
    # however much it looks like a commit, and a base64 signature in a query is
    # one value, not segments too short to test.
    hex_token = "0f3a9c7e1b2d4f6a" + "8c0e2b4d6f8a1c3e5b7d9f0a"
    b64_sig = "Zk3pQm9pR2x/T7vW1aB4cD8/" + "eF2gH6jK0lM9/nP5qR3sTuVw"
    ok("a digest-shaped token as a clone URL's user is caught, not excused "
       "as a commit",
       ([k for k, _ in found("git clone https://%s@github.com/acme/p.git"
                             % hex_token)],
        [k for k, _ in found("https://%s:x-oauth-basic@github.com/acme/p.git"
                             % hex_token)]),
       (["entropy"], ["family", "entropy"]))
    ok("and so is a base64 signature whose `/`s sit in the query",
       [k for k, _ in found("https://files.example.com/dl?sig=" + b64_sig)],
       ["entropy"])
    ok("while an advisory URL, whose path reads as random, is still a citation",
       found("https://github.com/curl/curl/security/advisories/GHSA-x9gq-8rhj-3w8v"),
       [])
    # Words a refusing reader leaves and a redacting one takes: LOG-005 flags
    # them, and a dictionary password is still a password in a SARIF snippet.
    for label, text, value in (
            ("a passphrase", 'password = "correct horse battery"',
             "correct horse battery"),
            ("a dictionary password", 'password = "change' + 'me"', "change" + "me"),
            ("an Authorization scheme", 'authorization: "Bearer "', "Bearer ")):
        ok("%s is an assign-word span, which only a redacting reader takes" % label,
           (found(text), "assign-word" in REDACT_ONLY_KINDS),
           ([("assign-word", value)], True))
    ok("a key written as character literals is a key array",
       [k for k, _ in found("static const char key[] = "
                            "{'h','u','n','t','e','r','2','!'};")], ["array"])
    ok("but a buffer of NULs written that way is not, nor are escapes a ValueError",
       ([k for k, _ in found(r"char key[4] = {'\0', '\x00', '\000', 0};")],
        [k for k, _ in found(r"char key[4] = {'\8', '\n', '\x7f', 'A'};")]),
       ([], ["array"]))

    def refused(text):
        """The kinds a reader that refuses on a hit - the gate, the ledger - acts on."""
        return [kind for kind, _ in found(text) if kind not in REDACT_ONLY_KINDS]

    # ---- a digest in a URL path is a citation only where the path says so ---- #
    # 40 and 64 lowercase hex is how git names an object and how
    # `secrets.token_hex` writes a key. Excused on shape, a webhook or trigger
    # URL built from one went into the SARIF and REPORT.md whole, while the
    # sweeper flagged the very same line as a secret.
    print("outbound: a digest in a URL's path is a citation only after commit, blob, ...")
    hex64 = "5d41402abc4b2a76b9719d911017c592" + "e0f1a5d6c8b1f3a2e9d4c7b6a5f40312"
    hex40 = "a94a8fe5ccb19ba61c4c" + "0873d391e987982fbbd3"
    for label, text in (
            ("a capability token as a webhook's last segment",
             'WEBHOOK = "https://hooks.example.com/deliver/%s"' % hex64),
            ("one in the middle of a trigger URL",
             "curl -X POST https://ci.example.com/api/v1/trigger/%s/build" % hex40),
            ("one before a query", "https://api.example.com/v1/keys/%s?x=1" % hex64),
            ("one as the path's first segment", "https://h.example.com/" + hex64),
            ("one where raw.githubusercontent.com keeps a commit, on another host",
             "https://hooks.example.com/o/r/%s/x" % hex64),
            ("one elsewhere in a raw.githubusercontent.com path",
             "https://raw.githubusercontent.com/acme/widget/main/k/" + hex64)):
        ok("%s is caught" % label, [k for k, _ in found(text)], ["entropy"])
    for label, text in (
            ("a tree", "https://github.com/acme/widget/tree/%s/src" % sha),
            ("a pull request's commit",
             "https://github.com/acme/widget/pull/12/commits/" + sha),
            ("a GitLab commit", "https://gitlab.com/g/p/-/commit/" + sha),
            ("a GitLab blob at a line",
             "https://gitlab.com/g/p/-/blob/%s/src/a.c#L4" % sha),
            ("a Bitbucket commit", "https://bitbucket.org/o/r/commits/" + sha),
            ("a Bitbucket source link", "https://bitbucket.org/o/r/src/%s/a.c" % sha),
            ("a Gitiles commit",
             "https://chromium.googlesource.com/chromium/src/+/" + sha),
            ("a sha256 repository's commit", "https://git.example.org/r/commit/" + hex64),
            ("a tree through the REST API",
             "https://api.github.com/repos/acme/widget/git/trees/" + sha),
            ("a blob through the REST API",
             "https://api.github.com/repos/acme/widget/git/blobs/" + sha),
            ("a pinned source archive",
             'urls = ["https://github.com/acme/widget/archive/%s.tar.gz"]' % sha),
            ("a raw file at a commit",
             "https://raw.githubusercontent.com/acme/widget/%s/src/parse.c" % sha),
            ("a content hash, too short to judge as a key on its own",
             "https://ci.example.com/runs/0f3a9c7e" + "1b2d4f6a/report")):
        ok("while %s is still a citation" % label, found(text), [])

    # ---- one URL scan per text ---- #
    # url_path_run looked for the enclosing URL from the start of the text for
    # every run, and the report gate passes the whole of REPORT.md at once:
    # 4000 permalinks took nineteen seconds.
    print("outbound: the URLs in a text are found once, not once per run")
    held, scans = URL_IN_TEXT, []

    class _CountingUrls:
        def finditer(self, text):
            scans.append(len(text))
            return held.finditer(text)

    links = "\n".join("- [CAND-%d](https://github.com/acme/fw/blob/%s/src/p%d.c#L%d)"
                      % (i, sha, i, i) for i in range(50))
    globals()["URL_IN_TEXT"] = _CountingUrls()
    try:
        spans = export_spans(links)
    finally:
        globals()["URL_IN_TEXT"] = held
    ok("fifty permalinks are no key material, and cost one scan for URLs",
       (spans, len(scans)), ([], 1))
    webhook = "https://hooks.example.com/deliver/" + hex64
    pieces = ["fixed in https://github.com/acme/widget/commit/" + sha, webhook,
              "see https://github.com/acme/widget/blob/%s/src/parse.c#L42" % sha,
              "and " + b64_sig + " in the log"]
    for order, text in (("in order", "\n".join(pieces)),
                        ("reversed", "\n".join(reversed(pieces)))):
        got = found(text)
        ok("each run is judged by its own URL, with several before it (%s)" % order,
           ([k for k, _ in got], [hex64 in v for _, v in got],
            [b64_sig in v for _, v in got].count(True)),
           (["entropy", "entropy"], [True, False] if order == "in order"
            else [False, True], 1))
    ok("and url_path_run still finds the URL itself when given no index",
       url_path_run(pieces[0], pieces[0].index("com/"), len(pieces[0])), True)
    ok("a URL's scheme is capped at 32 characters, like basic-auth-in-url's",
       URL_IN_TEXT.search("s" * 40 + "://h.example.com/x").start(), 8)

    # ---- the end-anchored names are read from the tail ---- #
    # identifier_left_of and whole_identifier searched `...*$` over the whole
    # text left of a hit, and an earlier long run was read to its end from
    # every start inside it: 40,000 `a` before one AWS key took 17 seconds.
    # No timing here; where each search starts is what tail_search() changes.
    print("candidates: the name left of a hit is searched for from the tail only")
    held = {name: globals()[name] for name in ("ASSIGN_GLUE", "IDENT_LEFT", "NAME_PREFIX")}

    class _RecordingStart:
        def __init__(self, pattern):
            self.pattern, self.starts = pattern, []

        def search(self, text, pos=0):
            self.starts.append(pos)
            return self.pattern.search(text, pos)

    recorders = {name: _RecordingStart(p) for name, p in held.items()}
    globals().update(recorders)
    try:
        named = [hit[3] for hit in literal_hits(
            "x.py", "a" * 1000 + ') k = "AKIAIOSFODNN7EXAMPLE"', 3.6, 20, True)]
        assigned = [hit[3] for hit in literal_hits(
            "x.py", "a" * 1000 + ' db.password = "hunter2hunter2"', 3.6, 20, True)]
    finally:
        globals().update(held)
    ok("the key is still named after `k`, and the password after its whole name",
       (named, assigned), (["k"], ["db.password"]))
    ok("and no search began inside the thousand characters before them",
       {name: bool(r.starts) and min(r.starts) > 1000
        for name, r in recorders.items()},
       {"ASSIGN_GLUE": True, "IDENT_LEFT": True, "NAME_PREFIX": True})
    tails = ("x = abc\n", "abc", "a) b\n", "a1 \n", "\n", "")
    ok("tail_search agrees with search(), `$` before a final newline included",
       [m and m.span() for m in (tail_search(IDENT_LEFT, IDENT_RUN, t) for t in tails)],
       [m and m.span() for m in (IDENT_LEFT.search(t) for t in tails)])

    # ---- an identifier under a secret-shaped name is not a password ---- #
    # The name stem is unanchored, and has to be: `dbpassword` and
    # `clientSecret` hold passwords. So `tokenizer`, `passport` and `bypass`
    # match it too, and the value's shape is what says it is a word.
    print("outbound: an identifier under a secret-shaped name is read as words")
    for label, text in (
            ("this pipeline's own secret_status vocabulary",
             'Dismissed CAND-012 FP-NOT-SECURITY: the value is public '
             '(`secret_status: "in-inventory:public"`, SEC-0004).'),
            ("the same, as contract 4a prints it",
             '"secret_status": "in-inventory:mac-or-tag"'),
            ("a ledger reason quoting it",
             'compared value is public: secret_status: "in-inventory:public" (SEC-0004)'),
            ("an OAuth client's auth method",
             '`token_endpoint_auth_method: "client_secret_basic"`'),
            ("a token type hint", '`token_type_hint: "access_token"`'),
            ("where a token is kept", '`token_storage: "localStorage"`'),
            ("a passport strategy, digits and all",
             'passport_strategy = "google-oauth20"'),
            ("a token's issuer", 'TOKEN_ISSUER = "https://auth.example.com/"'),
            ("a fetch credentials mode",
             'fetch("/api/transfer", {method: "POST", credentials: "same-origin"})'),
            ("a tokenizer's model", '`tokenizer = "bert-base-uncased"`'),
            ("a word under `bypass`", 'bypass_cache = "true-always"'),
            ("a word under `compass`", 'compass_heading = "north-east"')):
        ok("a refusing reader passes %s" % label, refused(text), [])
    for label, text, value in (
            ("a fetch credentials mode",
             'fetch(u, {credentials: "same-origin"})', "same-origin"),
            ("a model name", 'tokenizer = "bert-base-uncased"', "bert-base-uncased"),
            ("a storage key", 'const TOKEN_KEY = "ACCESS_TOKEN";', "ACCESS_TOKEN"),
            ("one camelCase word", 'token: "sessionStorage"', "sessionStorage"),
            ("a hyphenated passphrase", 'password = "correct-horse-battery"',
             "correct-horse-battery")):
        ok("%s is an assign-word span, which a redacting reader still takes" % label,
           found(text), [("assign-word", value)])
    ok("while a password under a name the stem sits inside is still one",
       (found('dbpassword = "%s"' % password), found('clientSecret: "%s"' % password)),
       ([("assign", password)], [("assign", password)]))

    # ---- a constant byte table is not a key ---- #
    # A MEM or HW finding's evidence and an FP-CONST reason quote a USB
    # descriptor or a magic number as readily as a key, and both refusing
    # readers refused them: the report, and a committed ledger's `check`.
    print("outbound: a byte table under a name that is not a key's")
    for label, text in (
            ("a USB device descriptor",
             "The parser trusts `bLength` from `static const uint8_t dev_desc[18] = "
             "{0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x83, 0x04};`"),
            ("an ELF magic",
             "It compares the header against `ELF_MAGIC[] = {0x7f, 0x45, 0x4c, 0x46, "
             "0x02, 0x01, 0x01, 0x00}` only by its first byte."),
            ("an FP-CONST reason quoting a table",
             "copies from dev_desc = {0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40}, "
             "a constant")):
        ok("%s is a hex-table span, which only a redacting reader takes" % label,
           ([k for k, _ in found(text)], refused(text)), (["hex-table"], []))
    for label, text in (
            ("a keypad map",
             "`static const uint8_t keypad_map[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, "
             "10, 11};` is indexed by an unchecked scan code."),
            ("a hotkey table", "hotkeys[4] = {1,2,3,4};"),
            ("a keyboard layout", "uint8_t keyboard_layout[4] = {1,2,3,4};"),
            ("a monkey's table", "uint8_t monkey_table[4] = {1,2,3,4};")):
        ok("and %s is no key array" % label, found(text), [])
    for label, text in (
            ("`aeskey`", "uint8_t aeskey[4] = {1,2,3,4};"),
            ("`masterKey`", "uint8_t masterKey[4] = {1,2,3,4};"),
            ("`keydata`", "uint8_t keydata[4] = {1,2,3,4};"),
            ("`keypad_aes_key`", "uint8_t keypad_aes_key[4] = {1,2,3,4};")):
        ok("while %s is still a key array" % label,
           [k for k, _ in found(text)], ["array"])
    ok("and a key's bytes in a struct initialiser are the field's, not the struct's",
       [k for k, _ in found("static const struct cfg c = { .aes_key = {%s} };"
                            % key_bytes)], ["hex-bytes"])
    # HW-010's name test is not the only one that says a table holds a secret:
    # LOG-005 reads one under `password` or `token`, and these bytes are
    # "hunter2!" as surely as `{'h','u','n','t','e','r','2','!'}` is.
    for label, name in (("`wifi_password`", "wifi_password"), ("`api_token`", "api_token"),
                        ("`credentials`", "credentials"), ("`admin_pwd`", "admin_pwd")):
        ok("and a byte table under %s, a name LOG-005 reads, is still refused" % label,
           refused("static const uint8_t %s[16] = {%s};" % (name, key_bytes)),
           ["hex-bytes"])

    # ---- an interpolated URL password is an env read ---- #
    # Allowing the empty user made compose's spelling of "the password comes
    # from the environment" read as a hardcoded one.
    print("outbound: a URL password that is an interpolation")
    for label, text in (
            ("an interpolated URL password with no user",
             "REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0"),
            ("the same in prose",
             "The worker reads `REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0` "
             "from the compose file, so no password is hardcoded."),
            ("a shell variable", "redis://:$REDIS_PASSWORD@redis:6379/0"),
            ("a Python format", "redis://:%(redis_password)s@redis:6379/0"),
            ("an interpolated URL password under a user",
             "DATABASE_URL=postgres://app:${POSTGRES_PASSWORD}@db:5432/app")):
        ok("and not %s" % label, found(text), [])
    ok("while a templated host or user excuses no hardcoded password",
       (found("DATABASE_URL=postgres://app:%s@{{ db_host }}/app" % url_pw),
        found("DATABASE_URL=postgres://${DB_USER}:%s@db/app" % url_pw)),
       ([("family", url_pw)], [("family", url_pw)]))

    print()
    print("selftest: %d failure(s)%s" % (failures, rules_lib.skipped_note()))
    return EXIT_USAGE if failures else EXIT_OK


def _discipline_json(tmp):
    """(findings, violations, was-routed-to-findings) from `status --json`."""
    raw = _capture(lambda: cmd_status(_Args(root=tmp, as_json=True)))
    doc = json.loads(raw)
    return (len(doc["findings"]) - 1, len(doc["discipline_violations"]),
            len(doc["findings"]))


def _identifier_of(line):
    """The identifier scan_file() would record for the one literal on `line`."""
    found = scan_file("x.py", [line], DEFAULT_ENTROPY_THRESHOLD,
                      DEFAULT_ENTROPY_MIN_LENGTH, "salt", False)
    literals = merge_literals([c for c in found if c["kind"] == "literal"])
    return literals[0]["identifier"] if literals else None


def _future_version_refused(tmp):
    _write(os.path.join(tmp, RUN_DIR, SECRETS_DIR, INVENTORY_NAME),
           json.dumps({"schema_version": SCHEMA_VERSION + 1, "entries": []}))
    try:
        run_check(tmp, DEFAULT_ENTROPY_THRESHOLD, DEFAULT_MAX_FILE_BYTES)
        return False
    except SweepError as exc:
        return exc.code == EXIT_NO_INPUT


def _capture(fn):
    import io
    held, sys.stdout = sys.stdout, io.StringIO()
    try:
        fn()
        return sys.stdout.getvalue()
    finally:
        sys.stdout = held


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    ap = argparse.ArgumentParser(
        description="Stage 1: the deterministic half of the secret sweep. "
                    "A hardcoded secret is a finding; holding a secret is not.")
    ap.add_argument("--selftest", action="store_true",
                    help="build the fixtures, assert on the values, and exit")
    subparsers = ap.add_subparsers(dest="command")

    def common(parser):
        parser.add_argument("--root", default=".",
                            help="scanned repository root, holding "
                                 ".security-review/ (default: .)")
        parser.add_argument("--entropy-threshold", type=float,
                            default=DEFAULT_ENTROPY_THRESHOLD,
                            help="bits per character above which a run of the "
                                 "secret alphabet is key material (default: "
                                 "%.1f; see the constant for why that number)"
                                 % DEFAULT_ENTROPY_THRESHOLD)
        parser.add_argument("--max-file-bytes", type=int,
                            default=DEFAULT_MAX_FILE_BYTES,
                            help="never read more than this from one file; the "
                                 "tree is attacker-supplied (default: %d)"
                                 % DEFAULT_MAX_FILE_BYTES)
        parser.add_argument("--exclude", action="append", default=[],
                            metavar="PATH_OR_GLOB",
                            help="skip this directory or name; repeatable. "
                                 "Added to the defaults, which do NOT include "
                                 "vendor/ or third_party/ - a vendored .pem "
                                 "committed by mistake is a real finding")
        parser.add_argument("--json", dest="as_json", action="store_true",
                            help="machine-readable output")
        return parser

    cand = common(subparsers.add_parser(
        "candidates", help="write secrets/candidates.json for the agent to judge"))
    cand.add_argument("--sarif", action="append", default=[], metavar="FILE",
                      help="gitleaks/trufflehog SARIF to fold in; repeatable")
    cand.add_argument("--sarif-dir", action="append", default=[], metavar="DIR",
                      help="a directory of *.sarif to fold in; repeatable")
    cand.add_argument("--entropy-min-length", type=int,
                      default=DEFAULT_ENTROPY_MIN_LENGTH,
                      help="shortest run the entropy family looks at (default: "
                           "%d; below 20 a random string and a word are not "
                           "separable)" % DEFAULT_ENTROPY_MIN_LENGTH)

    common(subparsers.add_parser(
        "check", help="hold secrets/inventory.json to contract 4a"))
    common(subparsers.add_parser(
        "status", help="the inventory, with findings and inventory kept apart"))
    return ap


def main():
    args = build_parser().parse_args()
    if args.selftest:
        return selftest()
    if not args.command:
        build_parser().print_help()
        return EXIT_USAGE
    # Before anything under the run directory is read: the scanned repository
    # never answers for the run (rules_lib.run_dir_gate).
    shipped, _gate = rules_lib.enforce_run_dir_gate(os.path.abspath(args.root))
    if shipped:
        return shipped
    handlers = {"candidates": cmd_candidates, "check": cmd_check,
                "status": cmd_status}
    try:
        return handlers[args.command](args)
    except SweepError as exc:
        prefix = "ERROR" if exc.code == EXIT_USAGE else "REFUSED"
        print("%s: %s" % (prefix, exc), file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    sys.exit(main())
