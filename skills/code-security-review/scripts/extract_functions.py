#!/usr/bin/env python3
r"""
extract_functions.py - stage 1: one record per function, and every rule hit joined to one.

Build a record only for a function that already contains a matched sink and the
corpus is whatever a grep opened. Measured on a tree of roughly nine thousand
functions that is 18 of them, and a report closing with - no further issues
found - is then a claim about the two percent of the tree the grep reached. A
bounds check that is off by one, a status code compared the wrong way round, a
length clamped after the arithmetic rather than before: none of those has a sink
to match, so nothing would ever construct the record, and nothing downstream
could tell the difference between a function that was read and cleared and a
function that was never named.

So the corpus is the whole tree. Every function gets a record; a rule hit is an
ATTRIBUTE of a function rather than the reason one exists. That is the coverage
claim §4 of the pipeline contract makes, and it is the claim a sink-first corpus
cannot make.

Two failures follow from that decision and are answered here.

**A boundary that is off by one function is worse than no boundary.** A record
whose line_end runs into the next function hands a validator a different body,
whose guards then look sufficient, and the dismissal is written against code the
candidate was never about. So boundaries are tiered and the tier is recorded on
every record: `exact` from tree-sitter, `heuristic` from a language-aware walk
that masks strings, comments and preprocessor lines before it counts a brace, and
`window` - a fixed range around a hit - only where neither could resolve anything
at all. `extract-report.json` counts the three per language and stage 2 refuses a
calibrated score over a corpus more than ten percent of which is windows (§6).
Never claim a line_end you did not measure.

**A tool nobody can install is a tool nobody runs.** tree-sitter is an OPTIONAL
import here and its absence is silent: the skill installs and runs with nothing
but python3. It is genuinely better with one - that is the difference between
`exact` and `heuristic` on most trees - but an ImportError must degrade a number
in a report, never fail a run.

The context window every function is scored in is a NAMED PROFILE recorded on the
record, described as file and line ranges rather than embedded text, and pinned by
`context.text_sha256` over the materialised bytes. `--emit-context` prints exactly
those bytes so the hash is checkable. This is the seam the fine-tuned model drops
into: its training extractor's windowing rules become another profile, and a score
carrying a profile the model was not trained on is refusable rather than merely
regrettable.

Skipping is the other thing this stage does not get to decide. A hit is skipped
when and only when the rule's own `skip_pattern` matches it - the hit's own
stretch of its line, from its match to the rule's next match there, never the
whole line - via `rules_lib.compile_skip`, which returns None for 48 of the 50
rules. There is no flag here that adds a skip path, because the failure this
pipeline was built around was 2652 of 2750 hits leaving through one.

**`--snapshot` reads frozen bytes and records live paths.** Without it this stage
scans the working tree, which is a directory somebody is still editing: one real
run reported *19 candidate(s) quote a line that changed since stage 1 read it*,
and every one of those citations was about code that no longer said what the
finding said it said. With it, `snapshot.py` has already copied the tree to
`.security-review/snapshot/` and the extractor reads there instead - but every
`file` field it writes stays relative to the ORIGINAL root, so a report's
`src/proto/parse.c:214` still resolves for a person who opens the repository. The
two roots are kept apart deliberately: `repo_root`, the git state and the churn
history come from the real tree (the snapshot has no `.git`, by design), while
every byte that is read, hashed and quoted comes from the snapshot. Behaviour
without the flag is exactly what it was - the pipeline must keep working for
somebody who never runs the snapshotter.

`run.json` also states what produced the run: `rules_hash` over the whole rule
directory, the `snapshot` it read (or null), and the `environment` it ran in. A
pinned tool with an unpinned ruleset is not a reproducible scan.

Stdlib only, except tree-sitter, which is optional. Python 3.8+.

Exit codes
  0  the corpus was written
  1  the run could not be completed: rules would not load, the root is unreadable,
     the output directory is not writable, or --selftest failed
  2  usage: an unknown --context-profile, a --budget-tokens that is not
     positive, a manifest that will not parse, an --out that would write into
     the scanned tree (§1, §9.2) - including a run directory that is, or holds
     on the way to a file this stage writes, a symlink - a --snapshot that is
     not a snapshot of --root, or an --emit-context function_id that is not in
     the corpus
  3  --emit-context re-materialised the window and its sha256 disagreed with the
     record: the corpus and the tree have diverged, which is a fact about the run
  7  refused before reading or writing anything: the scanned repository commits
     files under .security-review/ other than .gitignore and regular files
     under ledger/, git cannot say whether it does, or --root is this installed
     skill or an old copy of the scanner rather than a repository
     (rules_lib.run_dir_gate). Checked first, so it outranks every other code

Usage
  python3 extract_functions.py --root . --manifest .security-review/manifest.json
  python3 extract_functions.py --root . --exclude external --language c --jobs 8
  python3 snapshot.py --root . && python3 extract_functions.py --root . --snapshot
  python3 extract_functions.py --emit-context 'src/proto/parse.c::parse_tlv_record::0@9f2c1ab4e0d7'
  python3 extract_functions.py --selftest
"""

import argparse
import bisect
import codecs
import fnmatch
import hashlib
import json
import math
import multiprocessing
import os
import platform
import re
import shutil
import stat
import subprocess
import importlib.util
import sys
import tempfile
import time

sys.dont_write_bytecode = True      # the skill folder is read-only: no __pycache__ in it
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rules_lib                                       # noqa: E402
import snapshot                                        # noqa: E402

TOOL = "extract_functions.py"
TOOL_VERSION = "1.1.0"
BUNDLE_VERSION = rules_lib.skill_version()
SCHEMA_VERSION = 1

DEFAULT_EXCLUDES = ("third_party", "vendor", "node_modules", "build", "dist",
                    ".git", "target", "__pycache__")
# Pruned whatever the caller says, because they hold this pipeline's own text: a
# candidate file that quotes the line it flagged would otherwise be scanned as if
# it were the code under review - and .golden-cache, golden_set.py's old
# cwd-relative cache of third-party checkouts (sweep_secrets.DEFAULT_EXCLUDES
# already skips it). It is here and not in DEFAULT_EXCLUDES because those are
# counted into excluded_dirs, and run_status would then advise
# `--include .golden-cache`. The scanner's OWN installed folder, and an old copy of
# it, are pruned by identity instead (rules_lib.is_tooling_dir), because their
# folder names are a host's choice and a name list cannot know them.
ALWAYS_PRUNE = (".git", ".hg", ".svn", ".security-review", ".golden-cache")

MAX_FILE_BYTES = 2_000_000

# The synthetic scope a file-level hit is joined to. Bracketed so it cannot
# collide with a real identifier in any language this skill reads.
MODULE_SCOPE_NAME = "<module>"

# What the brace walk calls a function it found and could not name: a Go or PHP
# closure, a JS function expression or arrow bound to nothing. Bracketed for the
# same reason `<module>` is, and named here rather than spelled at each use so
# that SYNTHETIC_FUNCTION_NAMES below cannot drift from what is really emitted.
ANONYMOUS_NAME = "<anonymous>"
ARROW_NAME = "<arrow>"
CLOSURE_NAME = "<closure>"

# ---- languages ---------------------------------------------------------- #

# The table lives in rules_lib because stage 4 re-runs these rules and has to
# agree with this stage about which files each one ran over. See the note there.
LANGUAGE_BY_EXT = rules_lib.LANGUAGE_BY_EXT
LANGUAGES = rules_lib.LANGUAGES

BRACE_LANGUAGES = ("c", "cpp", "rust", "go", "java", "csharp",
                   "javascript", "typescript", "php")
INDENT_LANGUAGES = ("python", "ruby")

# Name separator used to build qualified_name from the enclosing container stack.
QUALIFIER_SEP = {"c": "::", "cpp": "::", "rust": "::", "php": "\\",
                 "go": ".", "java": ".", "csharp": ".", "javascript": ".",
                 "typescript": ".", "python": ".", "ruby": "#"}

WINDOW_LINES = 40                                  # tier 3, each side of a hit
WINDOW_NAME = "<window>"

# Every name this stage invents rather than reads off the source. Stage 4's
# candidate gate refuses a candidate whose function name does not occur in the
# file it cites, and none of these ever can - which is the point of the brackets
# - so the gate has to know every one of them. It used to know `<module>` only,
# and a single hit inside an Express callback or a Go handler closure made it
# refuse the whole run. verify_findings.py carries its own copy (the tools do not
# import each other); this one is a one-line literal so a check can read both
# copies off the source text and pin them together.
SYNTHETIC_FUNCTION_NAMES = ("<module>", "<window>", "<arrow>", "<anonymous>", "<closure>")

# Tier 3 fires only when a file that produced no boundaries LOOKS like it holds
# definitions. Without this test, `pydoc_data/topics.py` - fifteen thousand lines
# of documentation strings and not one `def` outside them - came back as eighteen
# `window` records, and a file with genuinely no functions in it is not a file
# the parser failed on.
#
# Which text the marker is read from differs by language, and the difference is
# the point. In Python a `def` inside a docstring is not a definition, and the
# MASK is what knows that. In C the definition may be produced entirely by a
# macro, which the mask blanks - so there the mask cannot be the witness and the
# raw text is.
#
# The optional U+FEFF is a UTF-8 byte-order mark, which survives the decode as a
# character at the start of line 1 and is not whitespace to `^[ \t]*`.
DEF_MARKER = {
    "c": (re.compile(r"\)[\s\\]*\{"), "raw"),
    "cpp": (re.compile(r"\)[\s\\]*\{"), "raw"),
    "java": (re.compile(r"\)[\s\\]*\{"), "raw"),
    "csharp": (re.compile(r"\)[\s\\]*\{"), "raw"),
    "python": (re.compile(r"^\ufeff?[ \t]*(?:async[ \t]+)?def[ \t]", re.M), "masked"),
    "ruby": (re.compile(r"^\ufeff?[ \t]*def[ \t]", re.M), "masked"),
    "go": (re.compile(r"\bfunc\b"), "masked"),
    "rust": (re.compile(r"\bfn\b"), "masked"),
    "javascript": (re.compile(r"\bfunction\b|=>"), "masked"),
    "typescript": (re.compile(r"\bfunction\b|=>"), "masked"),
    "php": (re.compile(r"\bfunction\b"), "masked"),
}

# ---- context profiles ---------------------------------------------------- #

# One token per 3.6 characters. It is an ESTIMATE and it is named so that it can
# be replaced: when the fine-tuned model arrives its real tokeniser becomes
# another entry here, the profile names which one produced a record's
# estimated_tokens, and a budget measured with one estimator is never silently
# compared against a budget measured with another.
def _chars_v1_from_length(n):
    return int(math.ceil(n / 3.6))


def estimate_tokens_chars_v1(text):
    """Characters / 3.6, rounded up. Swappable by name; see TOKEN_ESTIMATORS."""
    return _chars_v1_from_length(len(text))


TOKEN_ESTIMATORS = {"chars-3.6-v1": estimate_tokens_chars_v1}
# The same estimators as functions of the text's LENGTH, for those that are one.
# The context builder then prices a candidate window without joining it; an
# estimator missing here (a real tokeniser) is simply given the joined text.
LENGTH_ESTIMATORS = {"chars-3.6-v1": _chars_v1_from_length}

CONTEXT_PROFILES = {
    # Priority order is the order the parts are tried in, and the order they are
    # dropped from the back when the budget runs out. The function itself is
    # never dropped: a record whose context does not contain its own function is
    # not a smaller context, it is a different one.
    "default-v1": {
        "budget_tokens": 4096,
        "estimator": "chars-3.6-v1",
        "order": ["function", "type_decl", "caller", "file_preamble", "callee"],
        "max_parts": {"type_decl": 4, "caller": 3, "file_preamble": 1, "callee": 3},
        "caller_context_lines": 5,
        "callee_signature_lines": 3,
        "preamble_max_lines": 40,
    },
}

CONTEXT_ROLES = ("function", "caller", "callee", "type_decl", "header", "macro",
                 "file_preamble")

# ---- coverage ------------------------------------------------------------ #

# Mirrors verify_findings.py's SKIP_SAMPLE_* constants. The sample is every Nth
# skipped hit; stage 4 re-reads the sampled lines and re-runs the rule's pattern
# over them, so a sample that is too small or unreadable fails the run there.
SKIP_SAMPLE_PERCENT = 2
SKIP_SAMPLE_MIN = 5
SKIP_SAMPLE_MAX = 25

ZERO_HIT_CAUSES = ("absent-from-tree", "pattern-unmatchable")


class ExtractError(Exception):
    """A run that cannot be completed. Carries the file and, where there is one,
    the line that caused it."""


def fail(path, line, msg):
    raise ExtractError("%s:%s: %s" % (path, line if line else "?", msg))


def root_prefixed(root, value):
    """`value` with the root's own name stripped from its front when it was
    written relative to the folder that holds the repository rather than to
    `root` - say `payments-api/lib/vendor` for `lib/vendor` - else None.

    Every path this tool takes besides --root and --out is relative to --root,
    and one typed from the folder beside the repository matches nothing:
    an --include that waives nothing, an --exclude that leaves the directory
    in, a scanned root with no files under it, all with exit 0. Only a first
    component equal to the root's name, where the root holds no such
    directory, is read as that mistake.
    """
    name = os.path.basename(os.path.normpath(os.path.abspath(root)))
    text = str(value or "").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    head, _, rest = text.partition("/")
    if not name or head != name or os.path.isdir(os.path.join(root, name)):
        return None
    return rest or "."


# --------------------------------------------------------------------------- #
# masking: strings, comments and preprocessor lines, blanked in place
# --------------------------------------------------------------------------- #

_NON_NEWLINE = re.compile(r"[^\n]")


def _blank(chunk):
    """The same text with every character but the newlines replaced by a space.

    Length and line numbering are preserved, which is the whole point: the mask
    is indexed with the same offsets as the source it came from.
    """
    return _NON_NEWLINE.sub(" ", chunk)


def _cfamily_tokens(language):
    parts = []
    if language in ("java", "csharp"):
        # A Java text block or a C# raw string. First, because an alternation is
        # tried left to right and a lone `"` would otherwise win at the same
        # offset - which blanked `""` as an empty string and left every line of
        # the block, code-shaped text and all, for the brace walk to count.
        parts.append(r'"""')
    parts += [r'"', r"'"]
    parts.append(r"/\*")
    parts.append(r"//")
    if language in ("go", "javascript", "typescript"):
        parts.append(r"`")
    if language in ("javascript", "typescript"):
        # A regex literal's opening slash - or a division; `_js_regex_end`
        # decides which. After `/*` and `//`, so a comment still wins.
        parts.append(r"/")
    if language == "php":
        parts.append(r"#")
    if language in ("c", "cpp"):
        parts.append(r"^[ \t]*#")
    return re.compile("|".join(parts), re.M)


_CFAMILY_TOKEN_RE = {lang: _cfamily_tokens(lang) for lang in BRACE_LANGUAGES}
_RUST_CHAR = re.compile(r"'(?:\\.|[^\\'])'")
_RAW_PREFIX = re.compile(r"(r|R)(#*)$")
_PP_DIRECTIVE = re.compile(r"[ \t]*([A-Za-z_]\w*)")
_JS_WHITESPACE = " \t\r\n\f\v"

# Where a `/` in JavaScript opens a regex rather than dividing: after one of
# these, or after one of the keywords below, an operand is expected, and an
# operand that starts with `/` is a regex literal. `<` is deliberately absent:
# .jsx and .tsx are read as javascript and typescript, and a closing tag `</p>`
# would otherwise open a "regex" that runs to the next slash on the line. `)`
# and `]` are absent because `(a + b) / 2` is far commoner than `if (x) /re/`.
# `}` and a bare `>` are absent for JSX's sake too: text between tags is not
# code, and `{p.done}/{p.all} {p.x && <Icon/>}` or `<td>/{p.a} {p.b && <br/>}`
# opened a "regex" running to the `/` of the next tag, blanked a `{` whose `}`
# was left standing, and closed the function a line early. The one `>` that
# does expect an operand is an arrow's, `x => /re/.test(x)`, and _js_regex_end
# takes `=>` on its own; a regex straight after a block's `}` is rare enough
# to read as the division it would be after an object literal's. The rest of
# the set is JSX text punctuation as well - `Path: /{dir} {x && <Icon/>}`,
# `Home | /{s} ...`, `See (/{p}) or ...` - and dropping it would lose `f(/re/)`
# and `{k: /re/}`, so that JSX is caught by the span itself: see _js_regex_end.
_JS_REGEX_AFTER = frozenset("(,=:[!&|?{;+-*%~^")
_JS_REGEX_KEYWORD = re.compile(
    r"(?:^|[^\w$.])(?:return|typeof|case|in|of|delete|void|throw|new|yield|"
    r"await|instanceof|else|do)$")
# A regex literal longer than this is taken for a division instead. The scan
# for its closing slash is the one part of the mask that could otherwise rescan
# the rest of a minified line once per slash - and 2000 characters per slash
# is still 2000 x n on a line of `(/[` that never closes its class, so a file
# also has a budget for the scans that fail (JS_REGEX_BUDGET_PER_CHAR).
JS_REGEX_MAX_CHARS = 2000
# What failed regex scans may spend in one file, per character of it, before
# every later slash in that file is read as a division. Real code spends a
# fraction of its length: the most seen, over 7,300 installed JS and TS files,
# was 0.27 x (esutils' code.js). A crafted 2 MB line of `x=(/[` cost a minute.
JS_REGEX_BUDGET_PER_CHAR = 4


def _eol(text, i):
    """End of the logical line at `i`, following backslash continuations."""
    n = len(text)
    while True:
        j = text.find("\n", i)
        if j < 0:
            return n
        k = j - 1
        while k >= i and text[k] in " \t\r":
            k -= 1
        if k >= i and text[k] == "\\":
            i = j + 1
            continue
        return j


def _mask_cfamily(text, language, directives=None):
    r"""Blank comment and string content for a brace language.

    A naive brace counter is wrong on any real file - `"}"` in a format string,
    `/* } */` in a disabled block, and in C the `#define` whose braces do not
    balance at all - and that is the difference between this tool being usable
    and not. Everything below is masked so that the brace walk sees only code.

    An unterminated quote stops at the newline rather than running to the end of
    the file: a single stray apostrophe must not blank a whole translation unit.

    JavaScript's regex literal is masked too. `/^https?:\/\//` read as code puts
    a `//` comment in the middle of the line and blanks the `{` after it, so the
    if-block's `}` closed the FUNCTION; `/^\s*[{[]/` opened a block that never
    closed, the function vanished and the next header became a phantom called
    `test`. Whether a slash opens a regex is decided the way a JS tokenizer does
    it, from what came before - the last significant code, comments ignored.

    `directives`, when a list, receives `(start, end, name)` for every C/C++
    preprocessor line - found here, outside comments and strings, which is the
    only place a directive can be told from text that merely looks like one.

    Linear in the text. The newline that bounds a quote is found once per line,
    not once per quote: on a 1 MB minified line the per-quote search to the end
    of the line was a rescan of the rest of the file for every string in it.
    The regex scans that fail draw on a budget of JS_REGEX_BUDGET_PER_CHAR per
    character of the file, and once it is spent every slash divides: without
    it a line of `x=(/[` rescanned 2000 characters per slash, and a 400 KB
    file took twelve seconds to mask where it had taken none.
    """
    out, i, n = [], 0, len(text)
    tok = _CFAMILY_TOKEN_RE[language]
    js = language in ("javascript", "typescript")
    # The tail of the last significant code before the scan position, for the
    # regex-or-division question: "" at the start of the file, `"` after a
    # string or a regex (an operand, so a slash after it divides).
    lead = ""
    nl = -1                                            # next newline at or after s
    # Per call, never global: a file's mask must not depend on the files the
    # same worker masked before it.
    regex_budget = [JS_REGEX_BUDGET_PER_CHAR * n + 4 * JS_REGEX_MAX_CHARS]
    while i < n:
        m = tok.search(text, i)
        if m is None:
            out.append(text[i:])
            break
        s, kind = m.start(), m.group(0)
        code = text[i:s]
        out.append(code)
        if js:
            k = len(code) - 1
            while k >= 0 and code[k] in _JS_WHITESPACE:
                k -= 1
            if k >= 0:
                lead = code[max(0, k - 11):k + 1]
        if nl < s:
            nl = text.find("\n", s)
            nl = n if nl < 0 else nl
        if kind == "//":
            e = _eol(text, s)
            out.append(_blank(text[s:e]))
            i = e
        elif kind == "/*":
            depth, j = 1, s + 2
            while j < n and depth:
                if language == "rust" and text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            out.append(_blank(text[s:j]))
            i = j
        elif kind == "/":                              # js/ts: regex or division
            j = _js_regex_end(text, s, nl, lead, regex_budget)
            if j is None:
                out.append("/")
                lead = "/"
                i = s + 1
            else:
                out.append(_blank(text[s:j]))
                lead = '"'
                i = j
        elif kind == "#" and language == "php":        # php line comment
            e = _eol(text, s)
            out.append(_blank(text[s:e]))
            i = e
        elif kind.lstrip(" \t") == "#":                # c/cpp preprocessor line
            e = _eol(text, m.end() - 1)
            out.append(_blank(text[s:e]))
            if directives is not None:
                d = _PP_DIRECTIVE.match(text, m.end())
                directives.append((s, e, d.group(1) if d else ""))
            i = e
        elif kind == "`":
            j = text.find("`", s + 1)
            j = n if j < 0 else j + 1
            out.append(_blank(text[s:j]))
            lead = '"'
            i = j
        elif kind == '"""' and not (language == "csharp"
                                    and "@" in text[max(0, s - 2):s]):
            # (`@"""` in C# is a VERBATIM string opening on an escaped `""`, and
            # takes the verbatim path in _mask_quote below.)
            j = _raw_string_end(text, s, language)
            out.append(_blank(text[s:j]))
            i = j
        else:
            j = _mask_quote(text, s, language, out, nl)
            lead = '"'
            i = j
    return "".join(out)


def _js_regex_end(text, s, limit, lead, budget=None):
    """The offset after the regex literal whose opening slash is at `s`, or None
    when that slash is a division.

    It is a regex when the code before it expects an operand - see
    _JS_REGEX_AFTER - and a closing slash is found on the same line: a regex
    literal cannot span lines, so a newline first means the guess was wrong and
    the slash divides after all. A `/` inside a `[...]` class does not close
    it, which is what `/[{(/]/` needs, and `\\/` never does. After a postfix
    `++` or `--` the slash always divides: `n++ / 2` is not `++/re/`.

    A span that opens a JSX tag - `<Icon`, `</p`, `<>`, outside a class and not
    the `(?<` of a named group - and does not balance its braces is JSX text,
    not a regex: `Path: /{p.dir} {p.isNew && <Badge/>}` ran from the text's
    slash to the tag's, blanked a `{` whose `}` stayed standing, and closed the
    component a line early with its hits in `<module>`. A regex with a brace
    and a tag both, `/<b>{/`, is rarer than that JSX; a regex with an unbalanced
    brace and no tag, `/^\\s*[{[]/` or `/^(?<key>\\w+)\\s*\\{/`, stays a regex.

    `budget`, a one-item list, is what failed scans may still spend in this
    file (see _mask_cfamily). Each scan that runs and fails is charged its
    length; a scan that succeeds consumes its text and costs nothing more, and
    a slash the lead already settles costs nothing at all, so an ordinary
    minified bundle keeps its budget for the regexes late in its line.
    """
    if lead and lead[-1] not in _JS_REGEX_AFTER and not lead.endswith("=>") \
            and not _JS_REGEX_KEYWORD.search(lead):
        return None
    if lead.endswith(("++", "--")) or (budget is not None and budget[0] <= 0):
        return None
    n = len(text)
    stop = min(limit, s + JS_REGEX_MAX_CHARS)
    j, in_class, tag = s + 1, False, False
    while j < stop:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "<" and not in_class and text[j - 1] != "?" and j + 1 < n \
                and (text[j + 1].isalpha() or text[j + 1] in "_$/>"):
            tag = True
        elif c == "/" and not in_class:
            if tag and text.count("{", s, j) != text.count("}", s, j):
                break                                  # JSX text, not a regex
            j += 1
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1                                 # the flags
            return j
        j += 1
    if budget is not None:
        budget[0] -= j - s
    return None


def _raw_string_end(text, s, language):
    """The offset after a Java text block or C# raw string opening at `s`.

    Java's `\"""` is an escaped quote inside the block. C# has no escapes; its
    delimiter is a run of three or more quotes and the literal closes on a run
    of the same length. Either one unterminated runs to the end of the file,
    which is what the compiler would make of it too.
    """
    n = len(text)
    if language == "csharp":
        k = s
        while k < n and text[k] == '"':
            k += 1
        close = text.find('"' * (k - s), k)
        return n if close < 0 else close + (k - s)
    j = s + 3
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text.startswith('"""', j):
            return j + 3
        j += 1
    return n


def _digit_separator(text, s):
    """True when the `'` at `s` separates digits (`10'000`, `0x1'FF`) in C++14
    and C23, rather than opening a character literal.

    Read as a quote it masked the rest of the line, braces included: `clamp`
    with a `10'000` in its first line came back two lines long. The token before
    it has to START with a digit, which `u8'a'`, `L'a'` and `f(1,'a')` do not.
    """
    if s + 1 >= len(text) or not text[s + 1].isalnum():
        return False
    k, floor = s, max(0, s - 64)
    while k > floor and (text[k - 1].isalnum() or text[k - 1] in "_'."):
        k -= 1
    return text[k:k + 1].isdigit()


def _mask_quote(text, s, language, out, limit=None):
    """Blank one quoted run starting at `s`; returns the offset after it.

    `limit` is the first newline at or after `s`, when the caller has it."""
    n = len(text)
    quote = text[s]
    prefix = text[max(0, s - 8):s]

    if language == "rust" and quote == "'":
        m = _RUST_CHAR.match(text, s)
        if m is None:                                  # a lifetime, not a literal
            out.append(text[s])
            return s + 1
        out.append(_blank(m.group(0)))
        return m.end()

    if quote == "'" and language in ("c", "cpp") and _digit_separator(text, s):
        out.append(text[s])
        return s + 1

    if quote == '"':
        raw = _RAW_PREFIX.search(prefix)
        if language == "csharp" and (prefix.endswith("@") or prefix.endswith("@$")):
            j = s + 1                                  # @"..." doubles its quotes
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            out.append(_blank(text[s:j]))
            return j
        if raw and language == "rust":
            close = '"' + raw.group(2)
            j = text.find(close, s + 1)
            j = n if j < 0 else j + len(close)
            out.append(_blank(text[s:j]))
            return j
        if language in ("c", "cpp") and prefix.endswith("R"):
            # Bounded, like the check after it: an unbounded find ran to the
            # next `(` anywhere in the file for every `R"` that had none.
            open_paren = text.find("(", s + 1, s + 20)
            if 0 < open_paren < s + 20:
                close = ")" + text[s + 1:open_paren] + '"'
                j = text.find(close, open_paren)
                j = n if j < 0 else j + len(close)
                out.append(_blank(text[s:j]))
                return j

    if limit is None or limit < s:
        limit = text.find("\n", s)
        limit = n if limit < 0 else limit
    j = s + 1
    while j < limit:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == quote:
            j += 1
            break
        j += 1
    # Only an escape at the very end of the line can carry `j` past the newline,
    # and only then does it matter whether the line holds a second quote - so
    # the line is counted in that one case rather than for every quote in it.
    if j > limit and text.count(quote, s, limit) < 2:
        j = limit
    out.append(_blank(text[s:j]))
    return j


_PY_TOKEN_RE = re.compile(r"#|'''|\"\"\"|'|\"")
_PY_PREFIX = re.compile(r"(?:^|[^A-Za-z0-9_])([rRbBuUfF]{1,3})$")


def _mask_python(text):
    out, i, n = [], 0, len(text)
    nl = -1                     # next newline at or after s; see _mask_cfamily
    while i < n:
        m = _PY_TOKEN_RE.search(text, i)
        if m is None:
            out.append(text[i:])
            break
        s, kind = m.start(), m.group(0)
        out.append(text[i:s])
        if nl < s:
            nl = text.find("\n", s)
            nl = n if nl < 0 else nl
        if kind == "#":
            e = text.find("\n", s)
            e = n if e < 0 else e
            out.append(_blank(text[s:e]))
            i = e
            continue
        pref = _PY_PREFIX.search(text[max(0, s - 4):s])
        raw = bool(pref) and "r" in pref.group(1).lower()
        if kind in ("'''", '"""'):
            j = s + 3
            while j < n:
                if not raw and text[j] == "\\":
                    j += 2
                    continue
                if text.startswith(kind, j):
                    j += 3
                    break
                j += 1
            out.append(_blank(text[s:j]))
            i = j
            continue
        limit = nl
        j = s + 1
        while j < limit:
            if not raw and text[j] == "\\":
                j += 2
                continue
            if text[j] == kind:
                j += 1
                break
            j += 1
        j = min(j, limit)
        out.append(_blank(text[s:j]))
        i = j
    return "".join(out)


_RB_TOKEN_RE = re.compile(r"#|^=begin|'|\"|<<[-~]?['\"]?([A-Za-z_]\w*)['\"]?", re.M)


def _mask_ruby(text):
    out, i, n = [], 0, len(text)
    while i < n:
        m = _RB_TOKEN_RE.search(text, i)
        if m is None:
            out.append(text[i:])
            break
        s, kind = m.start(), m.group(0)
        out.append(text[i:s])
        if kind == "#":
            e = text.find("\n", s)
            e = n if e < 0 else e
            out.append(_blank(text[s:e]))
            i = e
        elif kind == "=begin":
            e = text.find("\n=end", s)
            e = n if e < 0 else text.find("\n", e + 1)
            e = n if e < 0 else e
            out.append(_blank(text[s:e]))
            i = e
        elif kind.startswith("<<"):
            ident = m.group(1)
            j = m.end()
            end = re.compile(r"^[ \t]*%s[ \t]*$" % re.escape(ident), re.M)
            me = end.search(text, j)
            j2 = me.end() if me else n
            out.append(text[s:m.end()])
            out.append(_blank(text[m.end():j2]))
            i = j2
        else:
            j, quote = s + 1, kind
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            out.append(_blank(text[s:j]))
            i = j
    return "".join(out)


def mask_source(text, language, directives=None):
    """`text` with comments and literals blanked; see _mask_cfamily for
    `directives`, which only a C-family language fills."""
    if language in INDENT_LANGUAGES:
        return _mask_python(text) if language == "python" else _mask_ruby(text)
    if language in _CFAMILY_TOKEN_RE:
        return _mask_cfamily(text, language, directives)
    return text


_BRACE = re.compile(r"[{}]")


def _brace_balanced(masked):
    """True when every `}` closes an earlier `{` and nothing is left open."""
    depth = 0
    for m in _BRACE.finditer(masked):
        depth += 1 if m.group(0) == "{" else -1
        if depth < 0:
            return False
    return depth == 0


def _first_branch_only(masked, directives):
    """`masked` with every `#else`/`#elif` branch after the first blanked.

    The mask keeps the code in EVERY branch of a conditional, which is right
    when each branch is balanced for its own build - `#ifdef _WIN32` over one
    whole definition and `#else` over another - and wrong when each branch
    opens a brace of its own:

        #ifdef HAVE_FAST_PATH
            if (n > 16 && fast_ok(src)) {
        #else
            if (n > 16) {
        #endif

    One `{` too many, so the function's own `}` closed the inner block, the
    function was never emitted, every function after it was qualified under it,
    and its hits went to an `exact` `<module>` record that reported nothing
    wrong. That is ctags' problem too, and this is ctags' answer: count the
    first branch only. The caller applies it only when the all-branches mask
    does not balance and this one does, so a file that parsed right keeps both
    of its alternative definitions.

    Newlines and length are preserved; nested conditionals inside a skipped
    branch are skipped with it.
    """
    stack, start, regions = [], None, []
    for s, e, name in directives:
        if name in ("if", "ifdef", "ifndef"):
            stack.append(False)
        elif name in ("else", "elif", "elifdef", "elifndef"):
            if stack and not stack[-1]:
                stack[-1] = True
                if start is None:
                    start = (len(stack), e)
        elif name == "endif" and stack:
            stack.pop()
            if start is not None and len(stack) < start[0]:
                regions.append((start[1], s))
                start = None
    if start is not None:
        regions.append((start[1], len(masked)))
    if not regions:
        return masked
    parts, at = [], 0
    for lo, hi in regions:
        parts.append(masked[at:lo])
        parts.append(_blank(masked[lo:hi]))
        at = hi
    parts.append(masked[at:])
    return "".join(parts)


# --------------------------------------------------------------------------- #
# tier 2: language-aware brace and indentation walks
# --------------------------------------------------------------------------- #

_C_STOPWORDS = {
    "if", "for", "while", "switch", "return", "else", "do", "case", "default",
    "sizeof", "typedef", "struct", "union", "enum", "class", "namespace",
    "template", "new", "delete", "throw", "catch", "try", "using", "extern",
    "static_assert", "decltype", "noexcept", "alignof", "defined", "asm",
    "__asm__", "__attribute__", "operator", "and", "or", "not", "goto",
    "synchronized", "lock", "foreach", "fixed", "unchecked", "checked", "await",
    "match", "unsafe", "in", "of", "with", "select", "go", "defer", "assert",
}
_CALL_IN_HEADER = re.compile(r"([A-Za-z_~][A-Za-z0-9_]*)\s*\(")
_QUALIFIED_TAIL = re.compile(r"([A-Za-z_][\w]*(?:\s*(?:::|\.)\s*[A-Za-z_][\w]*)*"
                             r"\s*(?:::|\.)\s*)$")
_HEADER_TAIL_OK = re.compile(r"^[\sA-Za-z0-9_:,&*<>()\[\]~.+\-?]*$")
_CONTAINER_RE = re.compile(
    r"\b(?:class|struct|namespace|interface|enum|impl|trait|mod|module|object)\s+"
    r"([A-Za-z_][\w]*)")


def _match_paren(masked_header, open_pos):
    depth, i, n = 0, open_pos, len(masked_header)
    while i < n:
        c = masked_header[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


# Parenthesised groups that come BEFORE a declarator's name and are not it: a
# GCC or MSVC attribute, an alignment, `decltype(auto)`. The first `ident(` in
# `static void __attribute__((noreturn)) die(const char *msg)` is the attribute,
# and taking it lost `die` altogether; `__declspec(dllexport) int api_parse(...)`
# came out as a function called `__declspec`.
_DECORATOR_CALLS = frozenset((
    "__attribute__", "__attribute", "__declspec", "alignas", "_Alignas",
    "decltype", "__pragma", "_Pragma"))
_OPERATOR_NAME = re.compile(
    r"\boperator\s*(\(\s*\)|\[\s*\]|(?:new|delete)\b(?:\s*\[\s*\])?"
    r"|[^\w\s()\[\]{};]{1,3})\s*\(")
_POINTER_GROUP = re.compile(r"\s*\*")
_NAMESPACE = re.compile(r"\bnamespace\b")
_TAG_KEYWORD_TAIL = re.compile(r"\b(?:class|struct|union|enum)\s*$")


def _header_name_call(masked):
    """(start, paren, name, skipped) for the call that names a C-family
    declarator, or None: `start` is where the name begins, `paren` the offset of
    its `(`, and `skipped` the (lo, hi) spans of the groups passed over first.

    Passed over: a _DECORATOR_CALLS group; a Java annotation, `@GetMapping("/x")`;
    a call inside an unclosed `[` - a C# attribute, `[HttpGet("{id}")]`, or a
    C++ `[[deprecated("x")]]` - or inside an unclosed `<`, a template argument
    such as `class function<_Res(_ArgTypes...)>`; a macro straight after a tag
    keyword, `class DLL_API(x) Foo`; and the `int (` of a function that returns
    a function pointer, `int (*pick(int))(int)`, whose name is inside the group.
    Each of those used to be taken for the name, and the class ones turned a
    whole class body into one phantom function. The pointer group is never
    looked into after a keyword: `if (*p && f(x)) {` is a condition, not a
    declarator, and reading it as one named a phantom `f` nested in the
    function - which took the memcpy in the block and the MEM-WFS pass away
    from the function holding the guard. Returned as `if`, it is refused.

    An operator is named as the source spells it, the way tree-sitter's
    `operator_name` slices it - `operator==`, `operator []`, `operator new[]`,
    and `operator =` with its space - so the two tiers key it alike and stage
    4 finds that exact spelling in the file. Squashed to `operator=`, a copy
    assignment written `operator = (` was a name the candidate gate could not
    find, and it refused the run. Before either, an operator never matched at
    all and its body went to `<module>`.
    """
    pos, skipped = 0, []
    while True:
        m = _CALL_IN_HEADER.search(masked, pos)
        op = _OPERATOR_NAME.search(masked, pos)
        if op is not None and (m is None or op.start() <= m.start()):
            # Masking never moves an offset, and an operator's symbol is code,
            # so the masked slice is the source's spelling.
            return op.start(), op.end() - 1, masked[op.start():op.end(1)], skipped
        if m is None:
            return None
        paren = m.end() - 1
        before = masked[:m.start()]
        angles = before.replace("->", "  ") if "<" in before else ""
        if (m.group(1) in _DECORATOR_CALLS or before.rstrip().endswith("@")
                or before.count("[") > before.count("]")
                or angles.count("<") > angles.count(">")
                or _TAG_KEYWORD_TAIL.search(before)):
            close = _match_paren(masked, paren)
            if close < 0:
                return None
            skipped.append((m.start(), close + 1))
            pos = close + 1
            continue
        if m.group(1) not in _C_STOPWORDS \
                and _POINTER_GROUP.match(masked, paren + 1):
            pos = paren + 1                            # the name is inside
            continue
        return m.start(), paren, m.group(1), skipped


def _hdr_c(header, masked):
    """(name, kind) for a C-family declarator header, or None.

    The header is everything between the previous `;`, `{` or `}` and this `{`,
    so `if (x) ` and `} else {` arrive here too and are rejected by the keyword
    test. `static const t tbl[] = ` is rejected because nothing in it is a call.
    """
    found = _header_name_call(masked)
    if found is None:
        return None
    start, paren, name, skipped = found
    if name in _C_STOPWORDS:
        return None
    before = masked[:start]
    for lo, hi in skipped:                             # `@RequestMapping(value = "/x")`
        before = before[:lo] + " " * (hi - lo) + before[hi:]
    if "=" in before or ";" in before or "{" in before:
        return None                                    # an assignment, not a definition
    if _NAMESPACE.search(before):
        # `namespace std _GLIBCXX_VISIBILITY(default) {` is a namespace with an
        # attribute macro, and a function never follows that keyword. Read as a
        # function it swallowed the whole namespace, and every definition in it
        # was then "nested" in a function.
        return None
    close = _match_paren(masked, paren)
    if close < 0:
        return None
    tail = masked[close + 1:]
    if not _HEADER_TAIL_OK.match(tail) or "=" in tail or ";" in tail:
        return None
    qual = _QUALIFIED_TAIL.search(header[:start])
    prefix = re.sub(r"\s+", "", qual.group(1)) if qual else ""
    return name, prefix + name


# A constructor's member initialiser list whose last item is still waiting for
# its brace: `Buffer::Buffer(size_t n) : size_{n}, data_{new char[n]} {`. The
# walk took `size_{` for the body, so the constructor was one line long and its
# real body belonged to nothing.
_CTOR_INIT_TAIL = re.compile(
    r"^\s*(?:noexcept\s*(?:\([^()]*\))?\s*)?:(?!:)(?:[^;{}]*,)?"
    r"\s*[A-Za-z_][\w:]*\s*(?:<[^;{}()]*>)?\s*$")


def _ctor_brace_init(masked_header):
    """True when the `{` after this C++ header opens a member's brace
    initialiser rather than the constructor's body."""
    found = _header_name_call(masked_header)
    if found is None:
        return False
    start, paren, name, _skipped = found
    if name in _C_STOPWORDS or "=" in masked_header[:start] \
            or ";" in masked_header[:start]:
        return False
    close = _match_paren(masked_header, paren)
    return close >= 0 and bool(_CTOR_INIT_TAIL.match(masked_header[close + 1:]))


def _match_brace(masked, open_pos):
    depth = 0
    for m in _BRACE.finditer(masked, open_pos):
        depth += 1 if m.group(0) == "{" else -1
        if depth == 0:
            return m.start()
    return -1


# What may stand before the name of a call-shaped statement: a keyword that
# takes a statement, or a label.
_NOT_A_TYPE = re.compile(r"\b(?:else|do|return|case|default)\b"
                         r"|^\s*[A-Za-z_]\w*\s*:(?!:)")
_TYPE_WORD = re.compile(r"[A-Za-z_]|::")


def _statement_macro(language, stack, masked_header):
    """True for a call-shaped C/C++ header, nested in a function body, with
    nothing before its name that could be a declaration specifier.

    That is an iteration macro - `list_for_each_entry(pos, head, node) {`,
    `TAILQ_FOREACH(e, h, link) {`, `} else json_object_foreach(o, k, v) {` -
    and not a definition: C does not nest functions (see _ts_call_shaped), and
    recording one made a phantom that captured the loop's hits and took the
    MEM-WFS pass away from the function that holds the guards before the loop.

    A REAL definition that is only nested because a `#ifdef` unbalanced the
    braces still has its return type in front of it, so it is kept - which is
    why this does not simply refuse every header below a function. The methods
    of a class declared inside a function are kept too: their nearest owner is
    the class, not the function. And a macro is followed by its block and
    nothing else, so a header with anything after its closing paren - the
    `noexcept` or `: base()` of a constructor, which has no type either - is
    not one.
    """
    if language not in ("c", "cpp"):
        return False
    owner = next((e for e in reversed(stack) if e), None)
    if owner is None or "name" not in owner:
        return False                   # file scope, or a class/namespace body
    found = _header_name_call(masked_header)
    if found is None:
        return False
    close = _match_paren(masked_header, found[1])
    if close < 0 or masked_header[close + 1:].strip():
        return False
    before = _NOT_A_TYPE.sub(" ", masked_header[:found[0]])
    return not _TYPE_WORD.search(before)


def _hdr_go(header, masked):
    m = re.search(r"\bfunc\b", masked)
    if m is None:
        return None
    rest = masked[m.end():]
    recv = re.match(r"\s*\(\s*(?:[A-Za-z_]\w*\s+)?\*?([A-Za-z_]\w*)\s*\)", rest)
    if recv:
        rest = rest[recv.end():]
    nm = re.match(r"\s*([A-Za-z_]\w*)", rest)
    if nm:
        name = nm.group(1)
        return name, ("%s.%s" % (recv.group(1), name)) if recv else name
    lhs = re.search(r"([A-Za-z_]\w*)\s*:?=\s*$", masked[:m.start()])
    name = lhs.group(1) if lhs else CLOSURE_NAME
    return name, name


def _hdr_rust(header, masked):
    m = re.search(r"\bfn\s+([A-Za-z_]\w*)", masked)
    if m is None:
        return None
    return m.group(1), m.group(1)


def _hdr_php(header, masked):
    m = re.search(r"\bfunction\b\s*&?\s*([A-Za-z_]\w*)?", masked)
    if m is None:
        return None
    name = m.group(1) or CLOSURE_NAME
    return name, name


_JS_ARROW_NAME = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]*)?=\s*$"
    r"|([A-Za-z_$][\w$]*)\s*:\s*$"
    r"|([A-Za-z_$][\w$]*)\s*=\s*$")
_JS_ASYNC_TAIL = re.compile(r"\basync\s*$")
_JS_GENERIC_TAIL = re.compile(r"<[^<>()=]*>\s*$")
_JS_BARE_PARAM = re.compile(r"(?<![\w$.])[A-Za-z_$][\w$]*\s*$")
_TS_RETURN_TYPE = re.compile(r"\)\s*:")
_TS_RETURN_TYPE_TRIES = 8
# A JSX tag's `<`: a TypeScript generic's always has a name against it,
# `Map<string>`, and a comparison a space after it.
_JSX_TAG = re.compile(r"(?<![\w$)\].])<[A-Za-z/>]")


def _js_binding(before):
    """The name `before` binds its function to - `const f =`, `f:`, `x.f =` -
    once an `async` keyword and a TypeScript type-parameter list are taken off
    the end, or None.

    The async form is the common modern Express handler, `const run = async
    (req, res) => {`, and the lookup used to see `... = async` and give up: the
    record was called `<arrow>`, and stage 4 could find no `<arrow>` in the file.
    """
    pre = _JS_GENERIC_TAIL.sub("", before.rstrip()).rstrip()
    pre = _JS_ASYNC_TAIL.sub("", pre).rstrip()
    nm = _JS_ARROW_NAME.search(pre)
    return next((g for g in (nm.groups() if nm else ()) if g), None)


def _js_arrow_params(head):
    """Where an arrow function's parameters start in `head` (the header up to
    its `=>`), for each reading of it that is plausible, most likely first."""
    stripped = head.rstrip()
    bare = _JS_BARE_PARAM.search(stripped)
    if bare is not None:
        yield bare.start()                             # `async req =>`
    if stripped.endswith(")"):
        depth = 0
        for k in range(len(stripped) - 1, -1, -1):
            if stripped[k] == ")":
                depth += 1
            elif stripped[k] == "(":
                depth -= 1
                if depth == 0:
                    yield k                            # `(req, res) =>`
                    break
    # A TypeScript return type after the parameters, `(a: T): Promise<X> =>`:
    # the parameter list is a `(...)` whose close is followed by a colon. The
    # last few only: a real header has one or two, and a crafted one with
    # hundreds cost hundreds of binding lookups per `{`, quadratic in a header
    # the walk now reads twice when a parameter is destructured.
    closes = [t.start() for t in _TS_RETURN_TYPE.finditer(stripped)]
    for close in reversed(closes[-_TS_RETURN_TYPE_TRIES:]):
        opened = _match_paren_back(stripped, close)
        if opened >= 0:
            yield opened
    cut = head.rfind("(")
    if cut >= 0:
        yield cut


def _match_paren_back(text, close):
    depth = 0
    for k in range(close, -1, -1):
        if text[k] == ")":
            depth += 1
        elif text[k] == "(":
            depth -= 1
            if depth == 0:
                return k
    return -1


def _hdr_js(header, masked):
    m = re.search(r"\bfunction\b\s*\*?\s*([A-Za-z_$][\w$]*)?", masked)
    if m is not None:
        if m.group(1):
            return m.group(1), m.group(1)
        name = _js_binding(masked[:m.start()]) or ANONYMOUS_NAME
        return name, name
    if masked.rstrip().endswith("=>"):
        head = masked.rstrip()[:-2]
        name = None
        for cut in _js_arrow_params(head):
            name = _js_binding(head[:cut])
            if name:
                break
        if name is None:
            name = _js_binding(head) or ARROW_NAME
        return name, name
    # A method's body follows its `)` or its return type, never a `:`, `,`,
    # `?`, `|` or `&`: after one of those the `{` is a value or a type -
    # `get(o: { id: T }): { data: T };` in an interface, `{ a: f(x), b: {` -
    # and naming it made a phantom method out of an object or a type literal.
    # A return type that is a string, `get kind(): 'circle' {`, is blank in
    # the mask and leaves its `:` last there; the header itself ends with the
    # quote, which no value or type literal before a `{` does.
    if masked.rstrip()[-1:] in (":", ",", "?", "|", "&") \
            and header.rstrip()[-1:] not in ("'", '"', "`"):
        return None
    # A header with a brace in it is one extract_brace read back past a
    # pattern (see there). A JSX tag in it means the `(` left open may be
    # text - `<p>Note (see: {p.x}) {p.y}</p>` - and `Note (...) {` is not a
    # method: the read-back named that phantom where the plain cut named
    # nothing, so it does not name a method there at all.
    if "{" in masked and _JSX_TAG.search(masked):
        return None
    return _hdr_c(header, masked)                      # class/object method shorthand


# What stands before a JS `{` that opens a pattern rather than a body, when a
# `(` before it is still open: a destructured parameter `({ a }`, a default
# object `(a = {`, a TypeScript type literal `(x: {`, an object argument
# `f(a, {`. Inside parentheses a `{` is always an expression or a type, never
# a block; a body's `{` follows `)`, `=>` or a name.
_JS_PATTERN_LEAD = frozenset("(,=:[")


def _js_pattern_brace(masked, ext, pos, opened):
    """True when the JS `{` at `pos` opens a pattern, a default object or a type
    literal inside a parameter list: `opened`, the net `(` count since `ext`, is
    positive, and the last code before it is one of _JS_PATTERN_LEAD.

    The scan back crosses only whitespace, and the `{` it starts from is not
    whitespace, so no two scans cross the same character: linear in the file.
    """
    if opened <= 0:
        return False
    k = pos - 1
    while k >= ext and masked[k] in _JS_WHITESPACE:
        k -= 1
    return k >= ext and masked[k] in _JS_PATTERN_LEAD


# What may stand between a parameter list's `)` and its body's `{`: an arrow,
# a TypeScript return type, or nothing.
_JS_PARAMS_END = re.compile(r"\)\s*(?::[^(){};]*?)?(?:=>)?\s*$")


def _js_params_hold_pattern(masked, ext, boundary, pos):
    """True when the header extract_brace would read back from `ext` for the
    `{` at `pos` ends in the parameter list that holds the pattern which moved
    `boundary`: its last `(...)` opened before `boundary`, and nothing but an
    arrow or a return type follows it.

    Otherwise the pattern was an argument to a call in an earlier statement,
    and the read-back names that call. With no `;` after it - the style a
    formatter with `semi: false` writes - `res.json({ ok: true })` followed
    by `if (x) {` became a phantom `res.json` nested in the function, holding
    the block and every hit in it, and `foo({ a })` before a class named the
    class `foo` and every method in it `foo.m`.
    """
    end = _JS_PARAMS_END.search(masked, boundary, pos)
    if end is None:
        return False
    close = end.start() - ext
    opened = _match_paren_back(masked[ext:end.start() + 1], close)
    return 0 <= opened and ext + opened < boundary


HEADER_MATCHERS = {
    "c": _hdr_c, "cpp": _hdr_c, "java": _hdr_c, "csharp": _hdr_c,
    "go": _hdr_go, "rust": _hdr_rust, "php": _hdr_php,
    "javascript": _hdr_js, "typescript": _hdr_js,
}

MAX_NESTING = 8
MAX_HEADER_CHARS = 2000


def extract_brace(text, masked, language, line_at, stats=None):
    """Functions in a brace language, from the masked source.

    Nested definitions are kept - a JS closure, a C++ lambda's enclosing method,
    a local function in C# - because the innermost enclosing function is the one
    a rule hit belongs to, and a corpus that only has outer functions joins the
    hit to the wrong body. C and C++ are the exception, because C does not nest
    functions: a call-shaped header inside a function body with no type before
    its name is an iteration macro, not a definition (_statement_macro).

    `stats`, when a dict, receives `unclosed`: the named functions still open
    when the file ran out, which is a walk that lost count of its braces and
    dropped those functions. It used to drop them without a word.
    """
    matcher = HEADER_MATCHERS[language]
    out, stack, boundary = [], [], 0
    # C++ brace initialisers in a constructor's member list, skipped whole and
    # read by later headers as `(...)`, which is what they would have been
    # before C++11. Offsets are kept, so nothing else moves.
    blanked, skip_to = [], -1
    # A header is the text between the last statement boundary and the `{`, and
    # in a language whose file preamble carries no `;` and no `}` that text runs
    # back to byte 0. Go is the case that exposed it: `package svc` followed by
    # an `import ( ... )` group means the first `{` in the file is the first
    # function's, its header is the whole preamble, and `lead` cannot trim it
    # because a package clause is code rather than a comment - so the function
    # was reported as starting at line 1 and swallowing the imports. A blank
    # line is an additional boundary because a declaration does not contain one,
    # in any of these languages, while a preamble is almost always separated by
    # one. It does not disturb a multi-line C declaration (`static int\nf(void)`),
    # which has no blank line in it.
    #
    # In JavaScript a `{` inside a parameter list opens a pattern, not a body -
    # `const getAgent = (url, { agent } = {}) => {`, `function POST({ request })
    # {` - and cutting the header there left `) =>` or `) ` for the matcher: the
    # arrow was `<arrow>` to this tier and `getAgent` to tree-sitter, and the
    # handler's body was one line long, with its SQL-injection hit in
    # `<module>`. `ext` is the boundary such a brace does not move (nor a `;`
    # or blank line inside one: a type literal's `{ a: T; b: U }`), `opened`
    # the net `(` count between it and `seen`, kept as the walk goes so the
    # file is read once. A header the narrow cut cannot name, or names only
    # `<arrow>`/`<anonymous>`, is read again from `ext`, and a real name found
    # there is taken with its start - only a real one, or the object argument
    # in `defineComponent({ data() {` would move `data` up to the call line -
    # and only when the pattern sits in the parameter list the header ends
    # with (_js_params_hold_pattern). A pattern that was an argument in the
    # statement before, `res.json({ ok })` with no `;` after it, would name
    # the `if (x) {` that follows.
    js = language in ("javascript", "typescript")
    ext, opened, seen = 0, 0, 0
    for m in re.finditer(r"[{};]|\n[ \t]*\n", masked):
        ch, pos = m.group(0), m.start()
        if pos < skip_to:
            continue
        if js:
            gap = masked[seen:pos]
            opened += gap.count("(") - gap.count(")")
            seen = m.end()
        in_pattern = js and stack and stack[-1].get("pattern")
        if ch == ";" or ch[0] == "\n":
            boundary = m.end()
            blanked = []
            if not in_pattern:
                ext, opened = boundary, 0
            continue
        if ch == "{" and js and _js_pattern_brace(masked, ext, pos, opened):
            stack.append({"pattern": True})
            boundary = pos + 1
            continue
        if ch == "{":
            header_raw = text[boundary:pos]
            header_masked = masked[boundary:pos]
            for lo, hi in blanked:
                lo, hi = lo - boundary, hi - boundary
                header_masked = (header_masked[:lo] + "(" + " " * (hi - lo - 2)
                                 + ")" + header_masked[hi:])
            if language == "cpp" and len(header_raw) <= MAX_HEADER_CHARS \
                    and _ctor_brace_init(header_masked):
                close = _match_brace(masked, pos)
                if close > pos:
                    blanked.append((pos, close + 1))
                    skip_to = close + 1
                    continue
            entry = None
            if len(header_raw) <= MAX_HEADER_CHARS and header_raw.strip():
                if len(stack) <= MAX_NESTING:
                    hit = matcher(header_raw, header_masked)
                    if js and ext < boundary and pos - ext <= MAX_HEADER_CHARS \
                            and (hit is None or hit[0] in SYNTHETIC_FUNCTION_NAMES) \
                            and _js_params_hold_pattern(masked, ext, boundary, pos):
                        wide = matcher(text[ext:pos], masked[ext:pos])
                        if wide is not None and (
                                hit is None or wide[0] not in SYNTHETIC_FUNCTION_NAMES):
                            hit, boundary = wide, ext
                            header_raw = text[ext:pos]
                            header_masked = masked[ext:pos]
                    if hit is not None and _statement_macro(language, stack,
                                                            header_masked):
                        hit = None
                    if hit is not None:
                        # The lead is measured on the MASKED header: a comment or
                        # a #define ahead of the declaration is blank there, so
                        # line_start lands on the declaration rather than on the
                        # block comment three lines above it.
                        lead = len(header_masked) - len(header_masked.lstrip())
                        start = boundary + lead
                        entry = {
                            "name": hit[0],
                            "local": hit[1],
                            "start": start,
                            "line_start": line_at(start),
                            "signature": _one_line(header_raw),
                        }
            if entry is None:
                con = _CONTAINER_RE.search(header_masked)
                entry = {"container": con.group(1)} if con else {}
            stack.append(entry)
            boundary = ext = pos + 1
            opened = 0
            blanked = []
            continue
        boundary = pos + 1
        blanked = []
        entry = stack.pop() if stack else {}
        if not entry.get("pattern"):
            ext, opened = boundary, 0
        if "name" not in entry:
            continue
        containers = [e["container"] for e in stack if "container" in e]
        containers += [e["local"] for e in stack if "local" in e]
        sep = QUALIFIER_SEP[language]
        out.append({
            "name": entry["name"],
            "qualified_name": sep.join(containers + [entry["local"]]),
            "line_start": entry["line_start"],
            "line_end": line_at(pos),
            "byte_from": entry["start"],
            "byte_to": pos + 1,
            "signature": entry["signature"],
        })
    if stats is not None:
        stats["unclosed"] = sum(1 for e in stack if "name" in e)
    return out


def _one_line(header):
    # A UTF-8 byte-order mark is not whitespace to str.strip().
    return re.sub(r"\s+", " ", header).strip().lstrip("\ufeff")[:300]


_PY_DEF = re.compile(r"^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)[ \t]*\(")
_PY_CLASS = re.compile(r"^([ \t]*)class[ \t]+([A-Za-z_]\w*)")


def _without_bom(lines):
    """The masked lines with a leading UTF-8 byte-order mark taken off line 1.

    Windows editors write one, it decodes to U+FEFF, and `^[ \t]*def` does not
    match past it: a file whose first line was a `def` lost that function to
    `<module>`, and one whose first line was a `class` lost the qualification of
    every method in it. Only this line list changes. The mark stays in the text
    and in the mask, because both are indexed by the same offsets as the bytes
    on disk, and dropping a character from either would move every one of them.
    """
    if lines and lines[0].startswith("\ufeff"):
        lines[0] = lines[0][1:]
    return lines


def extract_python(text, masked, line_offsets):
    """Python functions by indentation, over the masked source.

    The masked copy is what makes a `def` inside a docstring invisible, which is
    the one thing an indentation walk over raw text gets wrong every time.
    """
    lines = _without_bom(masked.split("\n"))
    raw_lines = text.split("\n")
    blocks, out = [], []
    for i, line in enumerate(lines):
        m = _PY_DEF.match(line)
        if m:
            blocks.append(["def", i, len(m.group(1).expandtabs(8)), m.group(2), None])
            continue
        c = _PY_CLASS.match(line)
        if c:
            blocks.append(["class", i, len(c.group(1).expandtabs(8)), c.group(2), None])

    def indent_of(idx):
        """Indentation of a line of CODE, or None for anything that is not one.

        Masked-blank is two different things and neither is a dedent: a comment
        (handled by the caller) and the inside of a triple-quoted string, whose
        raw indentation is not indentation at all - reading it would end a
        function at the first line of a docstring that starts at column 0.
        """
        line = lines[idx]
        if not line.strip():
            return None
        lead = len(line) - len(line.lstrip())
        if raw_lines[idx][:lead].strip():
            # The leading blanks are masked source, not indentation: this line
            # begins inside a string that opened above it. `""" % funcname)`
            # closing a here-doc at column 0 read as a dedent to indent 4 and cut
            # distutils' has_function off fifteen lines early.
            return None
        return len(line[:lead].expandtabs(8))

    def next_code(idx):
        for j in range(idx + 1, len(lines)):
            if lines[j].strip():
                return indent_of(j)
        return None

    def signature_end(idx):
        """Last line of a `def` header, which is not always the `def` line.

        `async def staggered_race(\n ... \n) -> typing.Tuple[\n ...\n]:` puts a
        `)` at column 0 four lines down. Scanning for the body from the `def`
        line treats that as a dedent and ends the function before it starts -
        which is how `staggered_race` came back five lines long instead of 135.
        """
        depth = 0
        for j in range(idx, min(idx + 80, len(lines))):
            line = lines[j]
            depth += (line.count("(") + line.count("[")
                      - line.count(")") - line.count("]"))
            if depth <= 0 and ":" in line:
                return j
        return idx

    for block in blocks:
        _kind, idx, indent, _name, _end = block
        head = signature_end(idx)
        end = len(lines) - 1
        for j in range(head + 1, len(lines)):
            ind = indent_of(j)
            if ind is not None:
                if ind <= indent:
                    end = j - 1
                    break
                continue
            if not raw_lines[j].lstrip().startswith("#"):
                continue                               # blank, or inside a string
            # A comment at or above the `def`'s own indentation. It ends the
            # function only when the code AFTER it dedents too. The two cases
            # this separates are both real: the `## ----` banner between two
            # methods in random.py, which is not part of the method above it,
            # and the `##          if sourcematch(":"):` commented-out code at
            # column 0 inside re/_parser.py's `_parse`, which is - and ending
            # there cut 343 lines of that function out of its own record.
            raw = raw_lines[j]
            if len(raw[:len(raw) - len(raw.lstrip())].expandtabs(8)) > indent:
                continue
            after = next_code(j)
            if after is None or after <= indent:
                end = j - 1
                break
        while end > idx and not raw_lines[end].strip():
            end -= 1
        block[4] = end

    for kind, idx, indent, name, end in blocks:
        if kind != "def":
            continue
        # Enclosing blocks are the ones that CONTAIN this line, not merely the
        # ones above it: a module-level `def outer` earlier in the file is not
        # what qualifies `Parser.parse`, and treating it as one produced
        # `Parser.outer.parse` on the first run of this fixture.
        owners = [nm for (_k, bi, bind, nm, bend) in blocks
                  if bi < idx <= bend and bind < indent]
        sig = _one_line(" ".join(raw_lines[idx:min(idx + 4, len(raw_lines))])
                        .split(":")[0])
        out.append({
            "name": name,
            "qualified_name": ".".join(owners + [name]),
            "line_start": idx + 1,
            "line_end": end + 1,
            "byte_from": line_offsets[idx],
            "byte_to": line_offsets[min(end + 1, len(line_offsets) - 1)],
            "signature": sig,
        })
    return out


_RB_DEF = re.compile(r"^([ \t]*)def[ \t]+(?:self[ \t]*\.[ \t]*)?"
                     r"([A-Za-z_][\w]*[?!=]?|\[\]=?|[<>=+\-*/%]+)")
_RB_CLASS = re.compile(r"^([ \t]*)(?:class|module)[ \t]+([A-Za-z_][\w:]*)")
_RB_OPEN = re.compile(r"\b(?:def|class|module|begin|case|do)\b")
_RB_COND = re.compile(r"(?:^|[=(;]|\b(?:and|or|not|then)\b)\s*"
                      r"\b(?:if|unless|while|until|for)\b")
_RB_END = re.compile(r"\bend\b")


def extract_ruby(text, masked, line_offsets):
    """Ruby methods, `def` to its matching `end`.

    Depth is counted over keywords rather than indentation because a `do` block
    or a trailing `if` modifier moves the `end` that closes a method without
    moving anything's indentation. When the count never returns to zero - which
    happens on the constructs this does not model, `%w[]` and a regex literal
    holding a keyword - the walk falls back to the first `end` at the `def`'s own
    column, which is what an indentation walk would have said anyway.
    """
    lines = _without_bom(masked.split("\n"))
    raw_lines = text.split("\n")
    out = []
    classes = [(i, len(m.group(1).expandtabs(8)), m.group(2))
               for i, line in enumerate(lines)
               for m in [_RB_CLASS.match(line)] if m]
    for i, line in enumerate(lines):
        m = _RB_DEF.match(line)
        if not m:
            continue
        indent = len(m.group(1).expandtabs(8))
        depth, end = 0, None
        for j in range(i, len(lines)):
            body = lines[j]
            opens = len(_RB_OPEN.findall(body)) + len(_RB_COND.findall(body))
            closes = len(_RB_END.findall(body))
            depth += opens - closes
            if j > i and depth <= 0:
                end = j
                break
        if end is None:
            for j in range(i + 1, len(lines)):
                stripped = lines[j].strip()
                if stripped == "end" and \
                        len(lines[j][:len(lines[j]) - len(lines[j].lstrip())]
                            .expandtabs(8)) == indent:
                    end = j
                    break
        if end is None:
            end = len(lines) - 1
        # The innermost enclosing class only. Ruby class bodies are not tracked
        # to their `end` here, so an earlier sibling class must not be allowed to
        # qualify a method it never contained.
        enclosing = [nm for (ci, cind, nm) in classes if ci < i and cind < indent]
        owners = enclosing[-1:]
        out.append({
            "name": m.group(2),
            "qualified_name": "#".join(owners + [m.group(2)]),
            "line_start": i + 1,
            "line_end": end + 1,
            "byte_from": line_offsets[i],
            "byte_to": line_offsets[min(end + 1, len(line_offsets) - 1)],
            "signature": _one_line(raw_lines[i]),
        })
    return out


# --------------------------------------------------------------------------- #
# tier 1: tree-sitter, optional
# --------------------------------------------------------------------------- #

TS_NODES = {
    "c": {"function_definition"},
    "cpp": {"function_definition", "lambda_expression"},
    "rust": {"function_item", "closure_expression"},
    "go": {"function_declaration", "method_declaration", "func_literal"},
    "python": {"function_definition"},
    "java": {"method_declaration", "constructor_declaration", "lambda_expression"},
    "javascript": {"function_declaration", "function_expression", "arrow_function",
                   "method_definition", "generator_function_declaration"},
    "typescript": {"function_declaration", "function_expression", "arrow_function",
                   "method_definition", "generator_function_declaration"},
    "csharp": {"method_declaration", "constructor_declaration",
               "local_function_statement", "lambda_expression"},
    # `anonymous_function` is what current PHP grammars call a closure; the
    # older name is kept for the grammars that still use it. With only the old
    # one here, tree-sitter dropped every PHP closure the brace walk extracts.
    "php": {"function_definition", "method_declaration", "anonymous_function",
            "anonymous_function_creation_expression", "arrow_function"},
    "ruby": {"method", "singleton_method"},
}

_TS = {"probed": False, "provider": None, "errors": [], "parsers": {}}


def _ts_probe():
    """Find a tree-sitter provider, or record why there is none and move on.

    Three shapes are tried because three are in the wild, and NONE of them is a
    dependency: an install of this skill must work with nothing but python3, so
    every failure here is a number in extract-report.json rather than a traceback.
    """
    _TS["probed"] = True
    try:
        import tree_sitter_language_pack as pack       # noqa: F401
        _TS["provider"] = ("language_pack", pack)
        return
    except Exception as exc:                           # noqa: BLE001
        _TS["errors"].append("tree_sitter_language_pack: %s" % exc)
    try:
        import tree_sitter_languages as langs         # noqa: F401
        _TS["provider"] = ("languages", langs)
        return
    except Exception as exc:                           # noqa: BLE001
        _TS["errors"].append("tree_sitter_languages: %s" % exc)
    try:
        import tree_sitter                             # noqa: F401
        _TS["provider"] = ("per_language", tree_sitter)
    except Exception as exc:                           # noqa: BLE001
        _TS["errors"].append("tree_sitter: %s" % exc)


_TS_MODULE_NAME = {"cpp": "cpp", "csharp": "c_sharp", "javascript": "javascript",
                   "typescript": "typescript"}


def ts_parser(language):
    """A parser for `language`, or None. Every failure is silent by design."""
    if not _TS["probed"]:
        _ts_probe()
    if _TS["provider"] is None:
        return None
    if language in _TS["parsers"]:
        return _TS["parsers"][language]
    parser = None
    kind, mod = _TS["provider"]
    try:
        if kind == "language_pack":
            parser = mod.get_parser(language)
        elif kind == "languages":
            parser = mod.get_parser(language)
        else:
            name = _TS_MODULE_NAME.get(language, language)
            grammar = __import__("tree_sitter_" + name)
            lang_fn = getattr(grammar, "language_" + name, None) or grammar.language
            lang = mod.Language(lang_fn())
            try:
                parser = mod.Parser(lang)
            except TypeError:                          # tree-sitter < 0.22
                parser = mod.Parser()
                parser.set_language(lang)
    except Exception as exc:                           # noqa: BLE001
        _TS["errors"].append("%s: %s" % (language, exc))
        parser = None
    _TS["parsers"][language] = parser
    return parser


def _ts_receiver(node, language, src):
    """`Rec` for a Go method declared on `(r *Rec)`, else None.

    Go's receiver is a field of the declaration rather than part of the name, so
    without this every method on every type collapses into one name per method:
    twelve `Read` records in one package, told apart only by their ordinals.
    """
    if language != "go":
        return None
    field = node.child_by_field_name("receiver")
    if field is None:
        return None
    text = src[field.start_byte:field.end_byte].decode("utf-8", "replace")
    m = re.search(r"\*?\s*([A-Za-z_]\w*)\s*\)", text)
    return m.group(1) if m else None


def _ts_name(node, language, src):
    field = node.child_by_field_name("name")
    if field is None and language in ("c", "cpp"):
        field = node.child_by_field_name("declarator")
        while field is not None and field.type not in (
                "identifier", "field_identifier", "qualified_identifier",
                "operator_name", "destructor_name"):
            nxt = field.child_by_field_name("declarator")
            if nxt is None:
                for child in field.children:
                    if child.type in ("identifier", "field_identifier",
                                      "qualified_identifier", "function_declarator",
                                      "parenthesized_declarator", "pointer_declarator"):
                        nxt = child
                        break
            if nxt is None or nxt is field:
                break
            field = nxt
    if field is None:
        return None
    return src[field.start_byte:field.end_byte].decode("utf-8", "replace")


# Where a nameless function expression's binding is, per parent node type:
# (the field holding the function, the field holding the name it is bound to).
_TS_JS_BINDINGS = {
    "variable_declarator": ("value", "name"),          # const f = () => {}
    "assignment_expression": ("right", "left"),        # x.f = function () {}
    "pair": ("value", "key"),                          # { f: () => {} }
    "field_definition": ("value", "property"),         # class C { f = () => {} }
    "public_field_definition": ("value", "name"),      # the TypeScript spelling
}
_TS_JS_NAME_NODES = ("identifier", "property_identifier",
                     "private_property_identifier")


def _ts_same(a, b):
    return a is not None and b is not None and (
        a.type, a.start_byte, a.end_byte) == (b.type, b.start_byte, b.end_byte)


def _ts_binding(node, language, src):
    """The name a nameless function expression is bound to - `const f = () =>`,
    `x.f = function`, `{ f: () => }`, `f := func(`, `x.F = func(` - or None.

    The brace walk reads that name off the text before the function (_js_binding,
    _hdr_go), and tree-sitter has to give the same answer: the commonest modern
    Express handler, `const run = async (req, res) => {`, was `run` to one tier
    and `<anonymous>` to the other, so a tree extracted two ways named its
    handlers differently, and the fixture's EXPECT-FUNC failed only where
    tree-sitter was installed.
    """
    parent = node.parent
    if parent is None:
        return None
    target = None
    if language in ("javascript", "typescript"):
        slot = _TS_JS_BINDINGS.get(parent.type)
        if slot is None or not _ts_same(parent.child_by_field_name(slot[0]), node):
            return None
        target = parent.child_by_field_name(slot[1])
        if target is not None and target.type == "member_expression":
            target = target.child_by_field_name("property")
        if target is None or target.type not in _TS_JS_NAME_NODES:
            return None
    elif language == "go":
        # `f := func`, `f = func`, `var f = func`: one name, one value.
        if parent.type != "expression_list" or parent.named_child_count != 1:
            return None
        holder = parent.parent
        if holder is None:
            return None
        if holder.type in ("short_var_declaration", "assignment_statement"):
            if not _ts_same(holder.child_by_field_name("right"), parent):
                return None
            left = holder.child_by_field_name("left")
            names = list(left.named_children) if left is not None else []
        elif holder.type == "var_spec":
            names = list(holder.children_by_field_name("name"))
        else:
            return None
        if len(names) == 1 and names[0].type == "selector_expression":
            # `srv.Handler = func(`: the field, which is what _hdr_go reads off
            # the text, as the JS branch takes a member_expression's property.
            # It was `<closure>` here and `Handler` there.
            names = [names[0].child_by_field_name("field")]
        if (len(names) != 1 or names[0] is None
                or names[0].type not in ("identifier", "field_identifier")):
            return None
        target = names[0]
    else:
        return None
    return src[target.start_byte:target.end_byte].decode("utf-8", "replace")


def _ts_unnamed(node, language):
    """The synthetic name for a function with neither a name nor a binding - the
    same one the brace walk gives that shape (_hdr_js, _hdr_go, _hdr_php)."""
    if language in ("javascript", "typescript") and node.type == "arrow_function":
        return ARROW_NAME
    if language == "go" or language == "php" and node.type != "function_definition":
        return CLOSURE_NAME
    return ANONYMOUS_NAME


# A control-flow keyword is never a function name, in any language here. Both
# extractors produce records named this way when they lose the thread: the
# tree-sitter walk descends into an ERROR node and calls an `else if` block a
# function, and the brace walk reads `int` off a line it mis-split. Measured on
# curl: 22 such records, including two inside the function holding
# CVE-2023-38545. They are parse debris, and a corpus that carries them is a
# corpus whose count nobody can trust.
KEYWORD_DEBRIS = {
    "c": {"if", "else", "for", "while", "do", "switch", "case", "default",
          "return", "goto", "break", "continue", "sizeof", "typedef", "struct",
          "union", "enum", "static", "const", "int", "char", "void", "unsigned",
          "signed", "long", "short", "float", "double", "defined"},
    "cpp": {"if", "else", "for", "while", "do", "switch", "case", "default",
            "return", "goto", "break", "continue", "sizeof", "typedef",
            "struct", "union", "enum", "static", "const", "int", "char", "void",
            "template", "typename", "catch", "try", "new", "delete"},
    "java": {"if", "else", "for", "while", "do", "switch", "case", "return",
             "try", "catch", "finally", "synchronized", "new"},
    "csharp": {"if", "else", "for", "foreach", "while", "do", "switch", "case",
               "return", "try", "catch", "finally", "lock", "using", "new"},
    "javascript": {"if", "else", "for", "while", "do", "switch", "case",
                   "return", "try", "catch", "finally", "typeof", "new"},
    "typescript": {"if", "else", "for", "while", "do", "switch", "case",
                   "return", "try", "catch", "finally", "typeof", "new"},
    "go": {"if", "else", "for", "switch", "case", "return", "select", "defer",
           "go", "range"},
    "rust": {"if", "else", "for", "while", "loop", "match", "return", "unsafe"},
    "php": {"if", "else", "elseif", "for", "foreach", "while", "do", "switch",
            "case", "return", "try", "catch", "finally"},
    "python": set(),
    "ruby": set(),
}


def drop_debris(functions, language):
    """(kept, dropped) - records whose name is a keyword are not functions."""
    bad = KEYWORD_DEBRIS.get(language) or set()
    if not bad:
        return list(functions), []
    kept, dropped = [], []
    for f in functions:
        (dropped if f.get("name") in bad else kept).append(f)
    return kept, dropped


def fill_gaps(kept, candidates):
    """Fallback boundaries for the regions the grammar did NOT parse.

    A union by "does it overlap anything" is wrong in both directions. The
    grammar's own records are the trustworthy part of a damaged parse, so a
    candidate starting inside one is a duplicate and goes. But a candidate that
    starts in a GAP may still run long - the brace walk loses its end when a
    preprocessor conditional unbalances the braces, and curl's
    `Curl_http_bodysend` came back as 2497-2842, swallowing five functions the
    grammar had parsed correctly. Rejecting it on overlap lost the function;
    accepting it whole would have double-covered the others.

    So a candidate is clipped to end before the next record the grammar parsed.
    The grammar owns what it parsed, the fallback owns the gaps between, and
    nothing is covered twice or not at all.
    """
    starts = sorted((k["line_start"], k["line_end"]) for k in kept)
    out = []
    for f in candidates:
        lo = f["line_start"]
        if any(a <= lo <= b for a, b in starts):
            continue                                   # the grammar owns this
        nxt = None
        for a, _b in starts:
            if a > lo:
                nxt = a
                break
        hi = f["line_end"] if nxt is None else min(f["line_end"], nxt - 1)
        if hi < lo:
            continue
        g = dict(f)
        g["line_end"] = hi
        g["clipped"] = hi != f["line_end"]
        out.append(g)
    return out


def _ts_call_shaped(node, language):
    """True when a `function_definition` is really a CALL the grammar mis-read.

    In curl's http.c, inside an ERROR region, the grammar reported
    `Curl_setup_transfer(data, FIRSTSOCKET, -1, TRUE, -1);` - a call statement -
    as an 80-line function definition, and that phantom sat on top of the real
    `Curl_http_cookies` below it and kept it out of the corpus.

    The test is a language rule rather than a heuristic: **a C function
    definition can only appear at file scope.** One whose parent chain passes
    through a `compound_statement` is inside another function's body, which C
    does not allow, so the grammar has mis-read something.

    The first version of this tested the parameter list instead - no
    `parameter_declaration`, therefore a call - and that was wrong in a way
    worth recording, because it passed every test I had. A K&R definition,

        int ZEXPORT deflateInit2_(strm, level, method, windowBits, ...)
            z_streamp strm;
            int level;
        {

    has a parameter list of bare identifiers too, because its types come AFTER
    the closing paren. So the filter deleted every K&R function in zlib,
    deflate.c fell all the way to window tier, and the golden set's oldest case
    went from reached to missed. The parameter list cannot tell a 1989
    definition from a 2023 call; the scope can.

    The known cost: GCC's nested-function extension is legal C where this says
    it is not. It is rare, this only runs on a file the grammar already failed
    on, and the fallback walk recovers such a function anyway - so the trade is
    a rare boundary demoted to `heuristic`, against whole functions vanishing.
    """
    if language not in ("c", "cpp"):
        return False
    parent = node.parent
    seen = 0
    while parent is not None and seen < 64:
        if parent.type == "compound_statement":
            return True
        if parent.type == "translation_unit":
            return False
        parent = parent.parent
        seen += 1
    return False


def extract_treesitter(raw, language):
    """{"functions": [...], "parse_error": bool}, or None with no grammar.

    `parse_error` is not advisory. A C parse that hits `#if` inside an if/else
    chain emits ERROR nodes, the walk descends into one and reports the `else
    if` block as a function, and the REAL enclosing function is never emitted at
    all. On curl that silently cost 20 functions - `do_SOCKS5`, which holds
    CVE-2023-38545, `Curl_readwrite`, `Curl_http_header`, `parse_proxy` - out of
    a corpus the report called 100% exact. The caller uses this flag to run the
    fallback as well and union in what was lost.
    """
    parser = ts_parser(language)
    if parser is None:
        return None
    try:
        tree = parser.parse(raw)
    except Exception as exc:                           # noqa: BLE001
        _TS["errors"].append("%s: parse failed: %s" % (language, exc))
        return None
    wanted = TS_NODES.get(language, set())
    sep = QUALIFIER_SEP[language]
    out = []
    errors = []

    def walk(node, owners):
        kind = node.type
        if kind == "ERROR" or node.is_missing:
            # Where the grammar lost the thread, to the line. Everything the
            # walk reports from inside one of these is suspect: in curl's
            # http.c it read the CALL `Curl_setup_transfer(data, ...)` as a
            # function definition spanning 80 lines, and that phantom then sat
            # on top of the real `Curl_http_cookies` below it.
            errors.append((node.start_point[0] + 1, node.end_point[0] + 1))
        here = owners
        if kind in wanted:
            name = _ts_name(node, language, raw)
            if name is None:
                name = (_ts_binding(node, language, raw)
                        or _ts_unnamed(node, language))
            receiver = _ts_receiver(node, language, raw)
            if receiver:
                here = owners + [receiver]
                owners = here
            body = node.child_by_field_name("body")
            sig_end = body.start_byte if body is not None else node.end_byte
            out.append({
                "suspect": _ts_call_shaped(node, language),
                "name": name.split("::")[-1].split(".")[-1],
                "qualified_name": sep.join(owners + [name]),
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "byte_from": node.start_byte,
                "byte_to": node.end_byte,
                "signature": _one_line(
                    raw[node.start_byte:sig_end].decode("utf-8", "replace")),
            })
            here = owners + [name]
        elif kind in ("class_declaration", "class_definition", "class_specifier",
                      "struct_specifier", "namespace_definition", "impl_item",
                      "module", "class", "interface_declaration", "trait_item"):
            # Rust's `impl Rec` carries the name in a `type` field, not a `name`
            # one, so asking only for `name` qualified every method in every impl
            # block as though it were free-standing.
            field = (node.child_by_field_name("name")
                     or node.child_by_field_name("type"))
            if field is not None:
                here = owners + [raw[field.start_byte:field.end_byte]
                                 .decode("utf-8", "replace")]
        for child in node.children:
            walk(child, here)

    try:
        walk(tree.root_node, [])
    except RecursionError:
        return None
    # `has_error` is the grammar telling you it lost the thread - overwhelmingly,
    # in C, a preprocessor conditional spliced into an if/else chain, which the
    # grammar cannot represent. 178 of curl's 605 C files parse this way. The
    # boundaries OUTSIDE the damaged region are still right, so this is not a
    # reason to throw the parse away; it is a reason to stop calling the file
    # `exact` and to go looking for what fell through.
    out.sort(key=lambda f: (f["line_start"], f["line_end"]))
    errors.sort()
    return {"functions": out, "error_spans": errors,
            "parse_error": bool(tree.root_node.has_error) or bool(errors)}


# --------------------------------------------------------------------------- #
# identity: §2's three keys
# --------------------------------------------------------------------------- #

def normalised_body(body):
    """§2: trailing whitespace stripped, blank runs collapsed, newline enforced.

    Comments are NOT stripped. A `/* safe: bounded by caller */` that stops being
    true is exactly the edit a stale suppression must not survive, so a comment
    change is a content change and the hash says so.
    """
    lines = [ln.rstrip() for ln in body.split("\n")]
    out, blank = [], False
    for ln in lines:
        if not ln:
            if blank:
                continue
            blank = True
        else:
            blank = False
        out.append(ln)
    while out and not out[-1]:
        out.pop()
    return "\n".join(out) + "\n"


def text_digest(text):
    r"""The sha256 of `text`, for text that may carry a filename in it.

    `os.walk` hands back a name that is not valid UTF-8 as a string holding
    lone surrogates, and `str.encode("utf-8")` raises UnicodeEncodeError on
    those. That is not hypothetical here: `materialise` puts `part["file"]`
    into the header line it hashes, so one latin-1 `src/caf\xe9.c` anywhere in
    a tree used to take stage 1 down with an unhandled traceback - after the
    snapshot had been copied, which is the worst possible moment.

    `surrogateescape` round-trips those bytes exactly, and is byte-identical
    to plain UTF-8 for every string that has no surrogates in it. So no
    `text_sha256` on any corpus that works today moves; the only behaviour
    that changes is the one that used to be a crash.
    """
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def content_hash(body):
    return hashlib.sha256(normalised_body(body).encode("utf-8")).hexdigest()[:16]


def function_key(rel, name, ordinal):
    return "%s::%s::%d" % (rel, name, ordinal)


# --------------------------------------------------------------------------- #
# the file walk
# --------------------------------------------------------------------------- #

# The scanner's own signature. A skill that installs INSIDE the repository it
# reviews is skipped by identity wherever the walk meets it (rules_lib.is_tooling_dir),
# and a repository's own host configuration is scanned like any other directory.
# What no prune can help with is the scanner being the root: the walk then happily
# extracts the scanner's own source, and its rule patterns - which quote memcpy,
# strcpy, MD5 and the rest - become rule HITS. One run measured 907 functions and
# 1,457 hits that way, with a confident summary and no warning anywhere in it.
#
# That is reachable by accident. A harness that fails to load a skill and falls
# back to the skill folder as its working root produces exactly this, and the
# operator sees a clean-looking review of the wrong repository. The folder this
# skill replaced is recognised too (the first marker pair: its `security-review`
# folder held the tools and the shared contracts), as a root, because an old
# bundle checked out as the root is still a wrong root.
BUNDLE_MARKERS = (
    os.path.join("security-review", "tools", "extract_functions.py"),
    os.path.join("security-review", "shared", "pipeline-contract.md"),
)


def looks_like_the_bundle(root):
    """True when `root` is the scanner's own tree rather than a repo to review:
    this skill or an old copy of it (rules_lib.inside_the_bundle), or the folder
    that held the old layout."""
    if rules_lib.inside_the_bundle(root):
        return True
    return all(os.path.isfile(os.path.join(root, m)) for m in BUNDLE_MARKERS)


def is_excluded(rel, patterns):
    # Patterns are written with "/" and `rel` comes off os.path.relpath, which has
    # backslashes on Windows: a multi-segment directory pattern (`src/legacy`,
    # `src/legacy/`) matched nothing there. Both sides are compared with "/".
    # snapshot.is_excluded is a copy of this; the selftest holds the two equal.
    rel = rel.replace(os.sep, "/")
    parts = rel.split("/")
    for pat in patterns:
        pat = pat.replace(os.sep, "/")
        clean = pat.rstrip("/")
        if clean in parts:
            return True
        if rel == clean or rel.startswith(clean + "/"):
            return True
        if fnmatch.fnmatch(rel, pat):
            return True
    return False


def _first_match(rel, patterns):
    """The first of `patterns` that excludes `rel`, or None.

    is_excluded one pattern at a time, so the coverage account can say WHICH
    pattern removed something. is_excluded itself is left alone: snapshot.py
    keeps a copy of it that is meant to stay identical."""
    for pat in patterns:
        if is_excluded(rel, (pat,)):
            return pat
    return None


def _under(rel, path):
    return rel == path or rel.startswith(path + os.sep)


def walk_files(root, scanned_roots, excludes, languages, max_bytes, includes=(),
               tooling=None):
    """(files, unsupported, oversize, unstattable, pruned, extensionless).

    `pruned` is the half this used to drop on the floor. DEFAULT_EXCLUDES holds
    `vendor` and `third_party`, the walk removes any directory matching them,
    and nothing counted what went with it - so a tree with a vulnerable function
    in `vendor/` produced a report that did not mention `vendor` at all, and a
    reader had no way to tell an empty directory from a skipped one.

    That is the exact claim §4's coverage account exists to refuse. Vendored
    code is in scope for a security review - a vulnerable dependency is your
    vulnerability - so the default stays, and what it costs is now counted and
    reported. `--include` un-excludes a directory the default caught wrongly.

    A file an exclude pattern removes by itself - `src/legacy/*`, `*.gen.c`, a
    manifest exclusion naming one file - is counted too, under its directory.
    Only pruned DIRECTORIES used to be, so a glob could take source out of the
    tree with no row in the account. Each row also names the patterns that
    removed its files, and a file is counted once however many scanned roots
    reach it.

    `includes` are the `--include` paths, normalised, and they are PATH-scoped:
    under an included directory, every pattern that excluded the directory
    itself is waived - so `--include lib/vendor` recovers `lib/vendor` from the
    component pattern `vendor`, which it was never equal to, while `vendor/`
    elsewhere stays excluded and so does a `build/` inside `lib/vendor`. A
    directory above an include is walked rather than pruned so the include can
    be reached; its other contents are still excluded, and still counted.

    `extensionless` counts the files `unsupported` cannot key: a name with no
    extension - `Makefile`, `LICENSE`, `.envrc`, `bin/tool`. They used to leave
    no trace at all, so a Python CLI shipped as `bin/tool` with `shell=True` in
    it was not scanned, not unsupported, not anything. See _count_extensionless.

    `tooling`, when given, is a list that receives a (path, reason) pair for each
    directory the walk skipped as the scanner's own tooling (rules_lib.is_tooling_dir:
    this installed skill, a skill (a folder with a SKILL.md) in a dot folder's
    `skills` folder, an old copy of the scanner). It is skipped whatever the excludes say and is not counted into
    `pruned`: it is not part of the product, and `--include` cannot waive it.
    """
    files, unsupported, oversize, seen = [], {}, [], set()
    unstattable, pruned, counted = [], {}, set()
    extensionless = {"files": 0, "scripts": {}, "script_files": []}
    includes = tuple(includes)
    waived = {inc: {p for p in excludes if is_excluded(inc, (p,))}
              for inc in includes}

    def active(rel):
        """The patterns that apply at `rel`, once the includes above it waived
        theirs."""
        pats = excludes
        for inc in includes:
            if _under(rel, inc) and waived[inc]:
                pats = [p for p in pats if p not in waived[inc]]
        return pats

    def selected(name):
        language = LANGUAGE_BY_EXT.get(os.path.splitext(name)[1].lower())
        if language and (not languages or language in languages):
            return language
        return None

    def count(rel_dir, rel_file, language, pattern):
        if rel_file in counted:
            return
        counted.add(rel_file)
        row = pruned.setdefault(rel_dir, {"files": 0, "languages": [],
                                          "patterns": []})
        row["files"] += 1
        row["languages"] = sorted(set(row["languages"]) | {language})
        if pattern is not None:
            row["patterns"] = sorted(set(row["patterns"]) | {pattern})

    def count_pruned(abs_dir, rel_dir, pattern):
        """Scannable source under a directory the excludes removed."""
        for dp, dn, fn in os.walk(abs_dir):
            dn[:] = [d for d in dn if d not in ALWAYS_PRUNE]
            rules_lib.prune_tooling(root, dp, dn)
            for name in fn:
                language = selected(name)
                if language:
                    count(rel_dir, os.path.relpath(os.path.join(dp, name), root),
                          language, pattern)
    for entry in scanned_roots:
        base = entry if os.path.isabs(entry) else os.path.join(root, entry)
        base = os.path.normpath(base)
        if os.path.isfile(base):
            walk_pairs = [(os.path.dirname(base), [os.path.basename(base)])]
        elif os.path.isdir(base):
            walk_pairs = None
        else:
            continue
        if walk_pairs is None:
            walk_pairs = []
            for dirpath, dirnames, filenames in os.walk(base):
                keep = []
                for d in sorted(dirnames):
                    rel_d = os.path.relpath(os.path.join(dirpath, d), root)
                    if d in ALWAYS_PRUNE:
                        continue            # pipeline's own text; reported already
                    why = rules_lib.tooling_reason(root, dirpath, d)
                    if why:
                        if tooling is not None:
                            tooling.append((rel_d.replace(os.sep, "/"), why))
                        continue            # the scanner's own folder, by identity
                    pats = active(rel_d)
                    if is_excluded(rel_d, pats) and not any(
                            inc.startswith(rel_d + os.sep) for inc in includes):
                        count_pruned(os.path.join(dirpath, d), rel_d,
                                     _first_match(rel_d, pats))
                        continue
                    keep.append(d)
                dirnames[:] = keep
                walk_pairs.append((dirpath, sorted(filenames)))
        for dirpath, filenames in walk_pairs:
            for name in filenames:
                path = os.path.join(dirpath, name)
                rel = os.path.relpath(path, root)
                if rel in seen:
                    continue
                pats = active(rel)
                if is_excluded(rel, pats):
                    language = selected(name)
                    if language:
                        count(os.path.dirname(rel) or os.curdir, rel, language,
                              _first_match(rel, pats))
                    continue
                ext = os.path.splitext(name)[1].lower()
                language = LANGUAGE_BY_EXT.get(ext)
                if language is None:
                    if ext:
                        unsupported[ext] = unsupported.get(ext, 0) + 1
                    else:
                        # Once, however many scanned roots reach it.
                        seen.add(rel)
                        _count_extensionless(extensionless, path, rel)
                    continue
                if languages and language not in languages:
                    continue
                try:
                    size = os.path.getsize(path)
                except OSError as exc:
                    # A dangling symlink, a file the walk cannot stat, a race
                    # with a checkout. It is a file in a language this tool
                    # reads that produced no record, which is a hole in the
                    # coverage claim §4 makes - so it is COUNTED, never just
                    # skipped over.
                    unstattable.append({"file": rel, "error": str(exc)})
                    continue
                if size > max_bytes:
                    oversize.append({"file": rel, "bytes": size})
                    continue
                seen.add(rel)
                files.append((rel, language))
    files.sort()
    extensionless["script_files"].sort(key=lambda row: row["file"])
    return files, unsupported, oversize, unstattable, pruned, extensionless


# As much of a `#!` line as Linux itself reads when it runs the script.
SHEBANG_READ = 256


def _count_extensionless(acc, path, rel):
    """Count one extensionless file, and name it by its `#!` line if it has one.

    The `#!` line and not the execute bit, because snapshot.py copies files
    without their execute bits: a mode test would find every script in the
    live tree and none in the snapshot of it. The script is COUNTED, never
    extracted - rules_lib.language_of says why - so `extracted` is written as
    the fact it is on every row rather than left for a reader to infer.

    Opened non-blocking and read only if it is a regular file once open: the
    walk lists whatever the directory holds, and reading a FIFO blocks until
    something writes to it. A file that cannot be opened is still counted in
    `files`; it just names no script.
    """
    acc["files"] += 1
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return
        head = os.read(fd, SHEBANG_READ)
    except OSError:
        return
    finally:
        os.close(fd)
    label = rules_lib.shebang_language(head)
    if label:
        acc["scripts"][label] = acc["scripts"].get(label, 0) + 1
        acc["script_files"].append({"file": rel, "language": label,
                                    "extracted": False})


def scripts_note(bare):
    """The stderr line for the scripts a `#!` line names, or None if none do.

    The ones in a language this run reads come first: that is source the run
    could have read, and before this line nothing anywhere said it was there.
    `bare` is extract-report.json's `extensionless_files`.
    """
    if not bare["scripts"]:
        return None
    order = sorted(bare["scripts"],
                   key=lambda k: (k not in bare["readable_languages"], k))
    return ("scripts: %d extensionless script(s), named by their `#!` line, "
            "were not extracted - %s (extensionless_files in "
            "extract-report.json)"
            % (sum(bare["scripts"].values()),
               ", ".join("%s %d" % (k, bare["scripts"][k]) for k in order)))


TEST_DIR_NAMES = {"test", "tests", "testing", "spec", "specs", "__tests__",
                  "fuzz", "fuzzing", "testdata"}
TEST_FILE_RE = re.compile(r"(^test_|_test\.|\.test\.|_spec\.|Test\.java$|Tests?\.cs$)")
GENERATED_RE = re.compile(
    r"(?i)(do not edit|@generated|code generated by|autogenerated|"
    r"automatically generated|generated by the protocol buffer)")
GENERATED_NAME_RE = re.compile(
    r"(\.pb\.go$|_pb2\.py$|\.generated\.|^lex\.yy\.c$|\.tab\.[ch]$|\.min\.js$)")


def in_test_tree(rel, globs):
    parts = rel.split(os.sep)
    if any(p.lower() in TEST_DIR_NAMES for p in parts[:-1]):
        return True
    if TEST_FILE_RE.search(parts[-1]):
        return True
    return any(fnmatch.fnmatch(rel, g) for g in globs or ())


def is_generated(rel, head):
    return bool(GENERATED_NAME_RE.search(os.path.basename(rel))
                or GENERATED_RE.search(head))


# --------------------------------------------------------------------------- #
# rules
# --------------------------------------------------------------------------- #

class CompiledRules:
    """Every pattern compiled once, grouped by the language it runs over.

    There is no union of a language's patterns to screen lines with. There was
    one, on the theory that a line it missed could skip the per-rule scans, and
    measured it was slower than the scans it saved: on a C tree, 85-89% of
    stage 1 was that screen, and when the rule table widened (the INJ and CRY
    alternations) stage 1 went 1.5x slower with it. A rule compiled on its own
    keeps `re`'s literal-prefix and charset fast paths, and a union of 700
    branches loses them, on Python 3.11 to 3.13 and with the old table and the
    new. run_rules asks each rule's own `search` whether the line is worth a
    `finditer`, which is a gate that cannot drop a hit: it is the rule itself.
    """

    def __init__(self, rules, wrappers):
        self.rules = []
        self.line_halves = {}
        self.by_language = {}
        # A rule stage 3 derives (LOG-TRI, `derived_at: "enrich"`) is not stage 1's: it
        # has no pattern to run and no derivation from the hits emitted here, so it gets
        # no hit in rules.jsonl and no row in coverage.json. Dropped here because every
        # path that compiles rules - stage 1, the selftests and the single-function
        # check - builds them through this class.
        for rule in rules_lib.stage1_rules(rules):
            if rule.get("derived"):
                self.rules.append({"rule": rule, "target": None, "rx": None,
                                   "skip": None, "pattern": None,
                                   "source": "as-written"})
                continue
            text, source = rules_lib.resolve_pattern(rule, wrappers)
            # A name rule is run segment-aware (rules_lib, "name targets"): its
            # `\b` reads `_` and camelCase humps as boundaries, so `do_verify`
            # and `isAuthenticated` are selected, not only names that open with
            # the keyword. `pattern` stays the text the rule file holds.
            name_rule = rule["match_target"] == "function_or_path"
            entry = {
                "rule": rule,
                "target": rule["match_target"],
                "rx": (rules_lib.compile_name_pattern(text) if name_rule
                       else re.compile(text)),
                "skip": rules_lib.compile_skip(rule),
                "pattern": text,
                "source": source,
            }
            self.rules.append(entry)
            for language in rule["languages"]:
                self.by_language.setdefault(language, []).append(entry)

            # The sink half of a name-matched rule. A separate entry rather than
            # an alternation, because merging them is what made LOG-004's
            # `verify\w*` run over source lines and return 201 hits across 243
            # functions on a codebase with no cryptography in it.
            line_text, line_source = rules_lib.resolve_line_pattern(rule, wrappers)
            if line_text is None:
                continue
            half = {
                "rule": rule,
                "target": "line",
                "rx": re.compile(line_text),
                "skip": rules_lib.compile_skip(rule),
                "pattern": line_text,
                "source": line_source,
                "is_line_half": True,
            }
            self.line_halves[rule["rule_id"]] = half
            for language in rule["languages"]:
                self.by_language.setdefault(language, []).append(half)

    def for_language(self, language):
        return self.by_language.get(language, [])


def classify_skip(line, match, language=None):
    """The skipped_sample class, decided from the line rather than asserted.

    `match` is the rule's skip_pattern matching this hit, which is the only
    thing that can skip a hit at all - so every hit this is asked about already
    has a class stage 4 can check: `skip-pattern`, which stage 4 re-derives by
    running the rule's own skip_pattern over the hit's own span again. The
    three narrower mechanical classes say more about WHY the pattern matched
    and are preferred when the line shows one. It used to fall through to
    `other`, which stage 4 cannot check and caps at a fifth of a sample, so
    every OTH-004 skip was `other`, and any C or Python tree that ignores
    SIGPIPE with `signal(SIGPIPE, SIG_IGN)` failed the candidate gate with
    coverage_skip_unverifiable on a skip that was correct. Inventing
    `declaration` to slide under that ceiling would have been the same widening
    this skill exists to stop; `skip-pattern` is not a word the scout writes,
    it is a regex stage 4 runs.
    """
    stripped = line.lstrip()
    openers = ("//", "*", "/*")
    if language in rules_lib.HASH_COMMENT_LANGUAGES:
        openers += ("#",)
    if stripped.startswith(openers):
        return "comment"
    slash = line.find("//")
    if 0 <= slash < match.start():
        return "comment"
    if re.search(r"\bsizeof\s*\(", line[match.start():]):
        return "sizeof-bounded"
    quote = line.count('"', 0, match.start())
    if quote % 2 == 1:
        return "string-literal"
    return "skip-pattern"


def run_rules(rel, language, text, lines, compiled, advisory):
    """Every rule hit in one file, with its disposition already decided."""
    entries = compiled.for_language(language)
    if not entries:
        return []
    hits = []
    # One stripped copy per LINE, not per hit: a minified line with a thousand
    # hits on it used to be stripped a thousand times.
    sinks = {}

    def record(entry, line_no, column, target_line, matched_text, span=None):
        rule = entry["rule"]
        skip_rx = entry["skip"]
        disposition, skip_reason, skip_class = "emitted", None, None
        if skip_rx is not None:
            # The skip is decided for THIS hit: over the text from its own
            # match to the next match of the same rule on the line, never over
            # the whole line. Over the whole line, `memcpy(dst, src, n);
            # memcpy(hdr, src, sizeof(hdr));` skipped the unbounded copy
            # because the other one was bounded, and the reason recorded for it
            # - "third argument is literally sizeof(<dest>)" - was false.
            m = (skip_rx.search(matched_text, span[0], span[1]) if span
                 else skip_rx.search(matched_text))
            if m is not None:
                # THE CRITICAL RULE: this is the only path to `skipped`, and the
                # reason is the rule's own written clause, verbatim.
                disposition = "skipped"
                skip_reason = rule["skip_clause"]
                skip_class = classify_skip(target_line, m, language)
        sink = sinks.get(line_no)
        if sink is None:
            sink = sinks[line_no] = target_line.strip()[:400]
        hit = {
            "rule_id": rule["rule_id"],
            "category": rule["category"],
            "cwe": rule["cwe"],
            "file": rel,
            "line": line_no,
            "column": column,
            "sink_text": sink,
            "why_flagged": rule["why_flagged"],
            "disposition": disposition,
            "skip_reason": skip_reason,
            "skip_class": skip_class,
            # §5: which of the rule's patterns produced this hit. Stage 4 re-runs
            # the two halves over different things - source lines and
            # `<file>::<function>` targets - and a hit that does not say which
            # half it came from is a hit stage 4 has to guess about. `line` here
            # covers the line pass and the sink half of a name-matched rule,
            # both of which ran over source lines.
            "match_target": "line",
            "pattern_source": entry["source"],
            "language": language,
        }
        if rule.get("threat_model") == "physical_attacker" and advisory:
            # The manifest says no physical attacker. The candidate is still
            # extracted and still dispatched; only its severity ceiling moves.
            hit["advisory_only"] = True
        hits.append(hit)

    line_entries = [e for e in entries
                    if e["target"] == "line" and not e["rule"]["multiline"]]
    if line_entries:
        # Line outer, rule inner, so rules.jsonl keeps its order. The `search`
        # gate is the rule's own pattern (see CompiledRules): 98% of lines match
        # nothing, and a list built for every rule on every one of them costs
        # more than the search does.
        for idx, line in enumerate(lines):
            for entry in line_entries:
                rx = entry["rx"]
                if rx.search(line) is None:
                    continue
                found = list(rx.finditer(line))
                for k, m in enumerate(found):
                    end = found[k + 1].start() if k + 1 < len(found) else len(line)
                    record(entry, idx + 1, m.start() + 1, line, line,
                           (m.start(), end))

    for entry in entries:
        if not entry["rule"]["multiline"]:
            continue
        if entry["target"] != "line":
            # A name pattern matches `<file>::<function>`; running it over source
            # text recounts something nobody ran. §5 keeps the two halves apart
            # for exactly this reason, and `multiline` is a property of the line
            # half only.
            continue
        starts = _line_start_offsets(text)
        for m in entry["rx"].finditer(text):
            line_no = bisect.bisect_right(starts, m.start())
            column = m.start() - starts[line_no - 1] + 1
            target = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            record(entry, line_no, column, target, m.group(0).split("\n")[0])
    return hits


def run_name_rules(rel, language, lines, functions, compiled):
    """`match_target: function_or_path` rules, whose hit is a whole function.

    Logical flaws are not reliably grep-able, so their candidate set is built by
    function selection: running LOG-003's name pattern over source lines instead
    would flag every line in the tree that contains the word `key`. The pattern
    runs over rules_lib.name_target(file, name), compiled segment-aware in
    CompiledRules, so `pam_authenticate` and `isAuthenticated` are selected by
    LOG-001 and `monkey` is not by LOG-003.
    """
    entries = [e for e in compiled.for_language(language)
               if e["target"] == "function_or_path"]
    if not entries:
        return []
    hits, sinks = [], {}
    for func in functions:
        target = rules_lib.name_target(func["file"], func["name"])
        line_no = func["line_start"]
        for entry in entries:
            if entry["rx"].search(target) is None:
                continue
            sink = sinks.get(line_no)
            if sink is None:                           # once per line; see run_rules
                sink = sinks[line_no] = (lines[line_no - 1].strip()[:400]
                                         if line_no - 1 < len(lines) else "")
            rule = entry["rule"]
            hits.append({
                "rule_id": rule["rule_id"],
                "category": rule["category"],
                "cwe": rule["cwe"],
                "file": rel,
                "line": line_no,
                "column": 1,
                "sink_text": sink,
                "why_flagged": rule["why_flagged"],
                "disposition": "emitted",
                "skip_reason": None,
                "skip_class": None,
                "pattern_source": entry["source"],
                "language": language,
                "match_target": "function_or_path",
            })
    return hits


def _line_start_offsets(text):
    offs = [0]
    start = text.find("\n")
    while start >= 0:
        offs.append(start + 1)
        start = text.find("\n", start + 1)
    return offs


def loosen(pattern):
    r"""The same pattern with its word-boundary anchors dropped.

    This is BOTH halves of the loosening §5 asks for. `\b` is exactly what
    forbids a name prefix: `\bcalloc` cannot open a match inside
    `mbedtls_calloc`, because `_` is a word character. Dropping the anchors
    therefore strips the prefix requirement too, and it is byte-for-byte the
    transform `verify_findings.unanchored` applies when it re-derives
    zero_hit_cause at stage 4 - so the two cannot disagree about whether a rule
    was blind or the tree was clean.
    """
    return pattern.replace(r"\b", "").replace(r"\B", "")


# --------------------------------------------------------------------------- #
# per-file work (the worker)
# --------------------------------------------------------------------------- #

_WORK = {}


def worker_init(payload):
    _WORK["root"] = payload["root"]
    _WORK["compiled"] = CompiledRules(payload["rules"], payload["wrappers"])
    _WORK["test_globs"] = payload["test_globs"]
    _WORK["advisory"] = payload["advisory"]
    _WORK["prefer_ts"] = payload["prefer_ts"]


def _module_record(rel, language, lines, line_offsets, records, hits, line_count):
    """A `<module>` scope for a file whose hits land outside every function.

    The corpus is function-scoped, and the join is what gives a hit somewhere to
    be scored, ranked and adjudicated. A hit that lands in no function has none
    of that: it is counted in coverage and then dropped, which is defensible for
    an `import random` line and is not defensible at all for
    `API_KEY = "sk-live-..."` at module scope, which is the entire purpose of
    LOG-005. On the shipped fixture both of LOG-005's hits were module-level and
    both were silently unreportable.

    So a file with an unjoined hit gets one synthetic record covering it. The
    boundaries are the file's, which is why the tier stays `exact` - they are
    not estimated - and `module_scope` marks it for anything that needs to know
    it is not a function. It is created only when something actually landed
    outside a function, because a `<module>` record per file would double a
    corpus mostly to say nothing.
    """
    if not hits:
        return None
    # The lines some record covers, merged into runs: a hit is outside when no
    # run holds its line. One bisect per hit rather than one pass over every
    # record, which on a minified file is hits x functions.
    runs = []
    for lo, hi in sorted((r["line_start"], r["line_end"]) for r in records):
        if runs and lo <= runs[-1][1] + 1:
            runs[-1][1] = max(runs[-1][1], hi)
        else:
            runs.append([lo, hi])
    firsts = [lo for lo, _hi in runs]

    def covered(line):
        k = bisect.bisect_right(firsts, line) - 1
        return k >= 0 and runs[k][1] >= line

    if all(covered(h["line"]) for h in hits):
        return None
    body = "\n".join(lines[:line_count])
    digest = content_hash(body)
    key = function_key(rel, MODULE_SCOPE_NAME, 0)
    return {
        "schema_version": SCHEMA_VERSION,
        "function_id": "%s@%s" % (key, digest),
        "function_key": key,
        "content_hash": digest,
        "file": rel,
        "language": language,
        "name": MODULE_SCOPE_NAME,
        "qualified_name": MODULE_SCOPE_NAME,
        "line_start": 1,
        "line_end": max(1, line_count),
        "byte_start": 0,
        "byte_end": line_offsets[min(line_count, len(line_offsets) - 1)],
        "loc": max(1, line_count),
        "signature": "<file scope of %s>" % rel,
        "module_scope": True,
        "extractor": {"parser": "module-scope", "grammar": None,
                      "confidence": "exact"},
    }


def _dedup_hits(hits):
    """One hit per (rule_id, line). Earlier wins, so the line pass beats the
    name pass - it points at the sink rather than at the definition line.

    Except that an emitted hit replaces a skipped one from the same pass, in
    the skipped one's place: `memcpy(hdr, p, sizeof(hdr)); memcpy(body, p, n);`
    is one (rule_id, line) with a skipped first match and an emitted second,
    and first-wins kept the skip and dropped the candidate. A line is now
    `skipped` only when every match of the rule on it was. The pass has to
    match because stage 4 recounts the line half and the name half apart, and
    a name hit standing in for a line hit would leave the line recount short.
    """
    out, at = [], {}
    for hit in hits:
        key = (hit["rule_id"], hit["line"])
        k = at.get(key)
        if k is None:
            at[key] = len(out)
            out.append(hit)
        elif (out[k]["disposition"] == "skipped"
              and hit["disposition"] == "emitted"
              and out[k].get("match_target") == hit.get("match_target")):
            out[k] = hit
    return out


_WIDE_BOMS = ((codecs.BOM_UTF32_LE, "UTF-32LE"), (codecs.BOM_UTF32_BE, "UTF-32BE"),
              (codecs.BOM_UTF16_LE, "UTF-16LE"), (codecs.BOM_UTF16_BE, "UTF-16BE"))


def _wide_encoding(raw):
    """`UTF-16LE` and the like for bytes that open with a UTF-16 or UTF-32
    byte-order mark, else None. UTF-32 is tried first because its
    little-endian mark begins with UTF-16's."""
    for bom, name in _WIDE_BOMS:
        if raw.startswith(bom):
            return name
    return None


def scan_file(job):
    rel, language = job
    root = _WORK["root"]
    path = os.path.join(root, rel)
    result = {"file": rel, "language": language, "error": None, "functions": [],
              "hits": [], "types": [], "calls": {}, "preamble": 0,
              "tier": None, "bytes": 0, "lines": 0, "line_text": {}, "line_text_at": {},
              "name_hit_counts": {},
              # §4's coverage claim is only checkable if a damaged parse says so.
              "parse_error": False, "debris_dropped": 0, "recovered": 0,
              "unclosed": 0}
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        result["error"] = "%s: %s" % (rel, exc)
        return result
    wide = _wide_encoding(raw)
    if wide:
        # Not decoded - every stage after this one reads bytes as UTF-8, and a
        # corpus whose offsets only this stage could reproduce is worse than a
        # file that is honestly missing. But it is not BINARY, and saying so
        # hid a Visual Studio "Unicode" source file behind the same words as a
        # .png: the reason has to tell the operator what to do about it.
        result["error"] = ("%s:1: %s text (byte-order mark), not scanned: "
                           "re-encode it as UTF-8 to scan it" % (rel, wide))
        return result
    if b"\0" in raw[:8192]:
        result["error"] = "%s:1: binary content, not scanned" % rel
        return result
    text = raw.decode("utf-8", "replace")
    result["bytes"] = len(raw)
    lines = text.split("\n")
    # A file ending in a newline splits to a phantom empty last element. Counting
    # it as a line lets a window claim a line_end one past the end of the file,
    # which is a range nothing can read back.
    line_count = len(lines) - 1 if lines and lines[-1] == "" else len(lines)
    result["lines"] = line_count
    line_offsets = _byte_offsets(lines, text)
    starts = _line_start_offsets(text)

    def line_at(pos):
        return bisect.bisect_right(starts, pos)

    # C/C++ preprocessor lines, as the mask found them; see _first_branch_only.
    directives = [] if language in ("c", "cpp") else None
    brace_stats = {}

    def fallback_functions(masked):
        if language == "python":
            return extract_python(text, masked, line_offsets)
        if language == "ruby":
            return extract_ruby(text, masked, line_offsets)
        # Only this walk gets the first-branch mask, and only when the whole
        # mask does not balance and the first-branch one does. Types, call
        # sites and the preamble keep reading every branch: a call made only
        # under `#else` is still a call.
        if directives and not _brace_balanced(masked):
            alt = _first_branch_only(masked, directives)
            if _brace_balanced(alt):
                masked = alt
        return extract_brace(text, masked, language, line_at, brace_stats)

    functions, tier, grammar = [], None, None
    parse_error = False
    if _WORK["prefer_ts"]:
        try:
            found = extract_treesitter(raw, language)
        except Exception:                              # noqa: BLE001
            found = None
        if found is not None:
            functions, tier, grammar = found["functions"], "exact", language
            parse_error = found["parse_error"]

    masked = mask_source(text, language, directives)
    if tier is None:
        functions = fallback_functions(masked)
        tier, grammar = "heuristic", None
        result["unclosed"] = brace_stats.get("unclosed", 0)
    elif parse_error:
        # THE RECOVERY. The grammar said it lost the thread somewhere in this
        # file, so `exact` is no longer a claim this run can make about it. The
        # parts it did parse are still right, so they are kept and stay `exact`;
        # the fallback is run as well and every function it found that the
        # damaged parse has no record of is unioned in, tagged `heuristic` so
        # the record says which walk produced it.
        #
        # Without this, curl lost 20 functions with no error, no note and no
        # tier change - among them `do_SOCKS5` (CVE-2023-38545),
        # `Curl_readwrite` and `Curl_http_header`. §4's claim is ONE RECORD PER
        # FUNCTION IN THE REPOSITORY, and it was quietly false.
        functions, debris = drop_debris(functions, language)
        # Anything the walk reported from inside an ERROR region is dropped
        # too, whatever it is named. Keyword debris is only the visible half;
        # the dangerous half is a phantom with a plausible name sitting on top
        # of a real function, which is how `Curl_http_cookies` stayed lost
        # after the keyword filter was already in place.
        spans = found.get("error_spans") or []
        # Positional filters were tried first and both were wrong. Dropping
        # everything that OVERLAPS an ERROR node cost `Curl_setup_transfer` and
        # pushed 567 sound boundaries down to `heuristic`, because an ERROR node
        # can span hundreds of lines with good code either side. Dropping
        # everything that STARTS inside one still cost it, because the real
        # definition in transfer.c starts inside an error span too. What
        # actually separates the phantom from the function is the shape of its
        # parameter list, which `_ts_call_shaped` reads off the grammar.
        trusted = [f for f in functions if not f.get("suspect")]
        phantoms = len(functions) - len(trusted)
        functions = trusted
        candidates, _ = drop_debris(fallback_functions(masked), language)

        # The SECOND shape of the same damage. Losing a function outright leaves
        # a gap the fallback can fill, and that is the curl socks.c case. But a
        # grammar that loses the thread can instead run a function's END past
        # the next one, swallowing it with no gap left to find - which is what a
        # `#ifdef` inside an if/else chain does to the function AFTER it.
        #
        # Where both walks name the same function at the same line and disagree
        # only about where it ends, the shorter end is the safe one: an over-run
        # silently absorbs whole functions, an under-run costs a few lines of
        # one. The record then says `heuristic`, because that end is the
        # fallback's and no longer the grammar's.
        by_start = {}
        for f in candidates:
            by_start.setdefault((f["line_start"], f["name"]), f)
        for k in functions:
            other = by_start.get((k["line_start"], k["name"]))
            if other is not None and other["line_end"] < k["line_end"]:
                k["line_end"] = other["line_end"]
                k["tier"] = "heuristic"

        recovered = fill_gaps(functions, candidates)
        for f in recovered:
            f["tier"] = "heuristic"
        functions = sorted(functions + recovered,
                           key=lambda f: (f["line_start"], f["line_end"]))
        result["parse_error"] = True
        result["debris_dropped"] = len(debris) + phantoms
        result["recovered"] = len(recovered)

    # Debris is not a tree-sitter problem alone: the brace walk reads `int` off
    # a line it mis-splits. Filter whatever tier produced the list.
    if tier == "heuristic" or not parse_error:
        functions, debris = drop_debris(functions, language)
        if debris:
            result["debris_dropped"] = result.get("debris_dropped", 0) + len(debris)

    result["types"] = _type_declarations(masked, language, line_at)
    result["calls"] = _call_sites(masked, starts)
    result["preamble"] = _preamble_end(masked, language)

    result["tier"] = tier
    compiled = _WORK["compiled"]
    hits = run_rules(rel, language, text, lines, compiled, _WORK["advisory"])

    records = _function_records(rel, language, lines, line_offsets, functions,
                                tier, grammar, line_count)
    if not records and hits:
        # Tier 3. Only reached when neither parser resolved a single boundary in
        # a file that has hits AND looks like it holds definitions: a record with
        # a measured window is worth more than a hit with no function at all, and
        # `window` says which it is on every record that carries it. A file that
        # simply has no functions gets no window - its hits stay `file-only`, and
        # the report counts them.
        marker, basis = DEF_MARKER.get(language, (None, "raw"))
        source = text if basis == "raw" else masked
        if marker is not None and marker.search(source):
            records = _window_records(rel, language, lines, line_offsets, hits,
                                      line_count)
            result["tier"] = "window"
        else:
            result["tier"] = "no-functions"

    module = _module_record(rel, language, lines, line_offsets, records,
                            hits, line_count)
    if module is not None:
        records = list(records) + [module]
    result["functions"] = records
    # §5: `sink_text` is read from the file at `line`, never reconstructed. The
    # derived MEM-WFS record is built in the parent, which no longer has the
    # file open, so the one line each record could ever quote travels with it.
    # Reconstructing it from `signature` is what made stage 3 report "the tree
    # moved under the run" on a tree that had not moved: a `<module>` record's
    # signature is `<file scope of ...>`, which appears in no file at any line.
    # Stripped once per line: every record in a minified file opens on line 1.
    quoted, anchored = {}, {}
    for r in records:
        n = r["line_start"]
        if n not in quoted:
            quoted[n] = lines[n - 1].strip()[:400] if 0 < n <= len(lines) else ""
        if quoted[n]:
            continue
        # A record that opens on a blank line - a `<module>` scope in a file
        # that starts with one, a `<window>` cut at one - would hand its MEM-WFS
        # candidate an empty sink_text, which the candidate gate refuses as
        # incomplete: two of them failed a run over /usr/include. The candidate
        # is anchored at the record's first line that has text instead; the
        # range the validator reads is the record's, unchanged.
        for m in range(n + 1, min(r.get("line_end") or n, len(lines)) + 1):
            text = lines[m - 1].strip()[:400]
            if text:
                anchored[r["function_id"]] = (m, text)
                break
    result["line_text"] = {
        r["function_id"]: anchored.get(r["function_id"], (0, quoted[r["line_start"]]))[1]
        for r in records}
    result["line_text_at"] = {fid: m for fid, (m, _t) in anchored.items()}
    # A `both` rule runs in both passes, so the same rule can land twice on one
    # line - a function whose NAME matches and whose opening line also carries a
    # sink. One candidate per (rule_id, line) is the contract's dedup rule, and
    # the line pass wins because it points at the sink rather than at the
    # definition.
    name_hits = run_name_rules(rel, language, lines, records, compiled)
    # Counted BEFORE the dedup, because this is the number stage 4 re-derives.
    # It recounts a name-matched rule by running its pattern over every
    # `<file>::<function>` target in the corpus, and that count knows nothing
    # about the line pass. Two definitions that open on the same line - a JS
    # function returning a named function, a one-line nested def - are two
    # targets and one `(rule_id, line)`, so the deduped list is one short and
    # the gate fails a run that did everything right.
    result["name_hit_counts"] = {}
    for hit in name_hits:
        result["name_hit_counts"][hit["rule_id"]] = \
            result["name_hit_counts"].get(hit["rule_id"], 0) + 1
    result["hits"] = _dedup_hits(hits + name_hits)
    result["in_test_tree"] = in_test_tree(rel, _WORK["test_globs"])
    result["generated"] = is_generated(rel, text[:4000])
    return result


def _byte_offsets(lines, text):
    """Byte offset of the start of each line, plus the end of the file."""
    offs = [0]
    if text.isascii():
        total = 0
        for ln in lines:
            total += len(ln) + 1
            offs.append(total)
        return offs
    total = 0
    for ln in lines:
        total += len(ln.encode("utf-8", "replace")) + 1
        offs.append(total)
    return offs


def _function_records(rel, language, lines, line_offsets, functions, tier,
                      grammar, line_count=None):
    """Raw boundaries -> §4 records, with the ordinal assigned per (file, name).

    The body hash is taken once per distinct line range. Records are
    line-granular, so every function in a minified file has the same body - the
    whole file - and hashing it once per function was one of the costs that
    made a 1 MB bundle quadratic.
    """
    out, ordinals, digests = [], {}, {}
    line_count = len(lines) if line_count is None else line_count
    for func in sorted(functions, key=lambda f: (f["line_start"], f["line_end"],
                                                 f["name"])):
        ls = max(1, int(func["line_start"]))
        le = max(ls, min(int(func["line_end"]), line_count))
        ordinal = ordinals.get(func["name"], 0)
        ordinals[func["name"]] = ordinal + 1
        digest = digests.get((ls, le))
        if digest is None:
            digest = digests[(ls, le)] = content_hash("\n".join(lines[ls - 1:le]))
        key = function_key(rel, func["name"], ordinal)
        out.append({
            "schema_version": SCHEMA_VERSION,
            "function_id": "%s@%s" % (key, digest),
            "function_key": key,
            "content_hash": digest,
            "file": rel,
            "language": language,
            "name": func["name"],
            "qualified_name": func.get("qualified_name") or func["name"],
            "line_start": ls,
            "line_end": le,
            "byte_start": line_offsets[ls - 1],
            "byte_end": line_offsets[min(le, len(line_offsets) - 1)],
            "loc": le - ls + 1,
            "signature": func.get("signature") or "",
            # A function can carry its own tier: in a file whose grammar parse
            # was damaged, what the fallback recovered is `heuristic` while
            # what the grammar did parse stays `exact`. The confidence is a
            # claim about THIS boundary, so it is recorded per boundary.
            "extractor": {"parser": "tree-sitter"
                                   if (func.get("tier") or tier) == "exact"
                                   else "stdlib",
                          "grammar": grammar if (func.get("tier") or tier) == "exact"
                                     else None,
                          "confidence": func.get("tier") or tier},
        })
    return out


def _window_records(rel, language, lines, line_offsets, hits, line_count):
    """±WINDOW_LINES around each hit, merged where the windows overlap."""
    spans = []
    for hit in sorted(hits, key=lambda h: h["line"]):
        lo = max(1, hit["line"] - WINDOW_LINES)
        hi = min(line_count, hit["line"] + WINDOW_LINES)
        if spans and lo <= spans[-1][1] + 1:
            spans[-1][1] = max(spans[-1][1], hi)
        else:
            spans.append([lo, hi])
    windows = [{"name": WINDOW_NAME, "qualified_name": WINDOW_NAME,
                "line_start": lo, "line_end": hi,
                "signature": "window around a rule hit; no boundary was resolved"}
               for lo, hi in spans]
    return _function_records(rel, language, lines, line_offsets, windows,
                             "window", None, line_count)


_TYPE_DECL_RE = {
    "c": re.compile(r"^[ \t]*(?:typedef[ \t]+)?(?:struct|union|enum)[ \t]+"
                    r"([A-Za-z_]\w*)[ \t]*\{", re.M),
    "go": re.compile(r"^[ \t]*type[ \t]+([A-Za-z_]\w*)[ \t]+(?:struct|interface)"
                     r"[ \t]*\{", re.M),
    "rust": re.compile(r"^[ \t]*(?:pub[ \t]+)?(?:struct|enum|trait|union)[ \t]+"
                       r"([A-Za-z_]\w*)", re.M),
    "python": re.compile(r"^[ \t]*class[ \t]+([A-Za-z_]\w*)", re.M),
    "generic": re.compile(r"^[ \t]*(?:[A-Za-z_]\w*[ \t]+)*"
                          r"(?:class|interface|struct|enum|record)[ \t]+"
                          r"([A-Za-z_]\w*)", re.M),
}
_TYPE_DECL_RE["cpp"] = re.compile(
    r"^[ \t]*(?:typedef[ \t]+)?(?:struct|union|enum|class)[ \t]+([A-Za-z_]\w*)",
    re.M)
_CALL_RE = re.compile(r"\b([A-Za-z_]\w{2,})\s*\(")
_CALL_KEYWORDS = _C_STOPWORDS | {"function", "def", "print", "len", "range",
                                 "self", "this", "super", "elif", "except",
                                 "raise", "yield", "lambda", "end"}
MAX_CALL_NAMES = 200
MAX_CALL_LINES = 3


def _type_declarations(masked, language, line_at):
    rx = _TYPE_DECL_RE.get(language, _TYPE_DECL_RE["generic"])
    out = []
    for m in rx.finditer(masked):
        line = line_at(m.start())
        out.append({"name": m.group(1), "line_start": line})
    return out[:400]


def _call_sites(masked, starts):
    """name -> the first few lines that call it.

    Capped hard. The profile needs at most three callers; recording every call
    site of `printf` in a hundred-thousand-function tree costs memory for context
    nothing will ever include.
    """
    out = {}
    for m in _CALL_RE.finditer(masked):
        name = m.group(1)
        if name in _CALL_KEYWORDS:
            continue
        seen = out.get(name)
        if seen is None:
            if len(out) >= MAX_CALL_NAMES:
                continue
            seen = out[name] = []
        if len(seen) >= MAX_CALL_LINES:
            continue
        line = bisect.bisect_right(starts, m.start())
        if line not in seen:
            seen.append(line)
    return out


_PREAMBLE_RE = re.compile(
    r"^[ \t]*(?:#\s*(?:include|import)|import\b|from\b|using\b|use\b|require\b|"
    r"package\b|extern\s+\"C\"|namespace\b)")


def _preamble_end(masked, language):
    """Last line of the leading include/import block, or 0."""
    last = 0
    for idx, line in enumerate(masked.split("\n")[:200], 1):
        if _PREAMBLE_RE.match(line):
            last = idx
        elif line.strip() and last and idx > last + 8:
            break
    return last


# --------------------------------------------------------------------------- #
# context windows
# --------------------------------------------------------------------------- #

def materialise(parts, read_lines):
    """The exact bytes `context.text_sha256` is taken over.

    The per-part header line is part of the hashed text. It has to be: two parts
    that are adjacent ranges of one file would otherwise materialise to the same
    bytes as one part spanning both, and the hash would stop distinguishing two
    different windows.
    """
    chunks = []
    for part in parts:
        lines = read_lines(part["file"])
        if lines is None:
            continue
        lo = max(1, part["line_start"])
        hi = min(len(lines), part["line_end"])
        chunks.append("# %s %s:%d-%d\n" % (part["role"], part["file"], lo, hi))
        chunks.append("\n".join(lines[lo - 1:hi]))
        chunks.append("\n")
    return "".join(chunks)


class ContextBuilder:
    """default-v1, and whatever profile replaces it when a model is trained."""

    def __init__(self, root, profile_name, profile, index, budget=None):
        self.root = root
        self.profile_name = profile_name
        self.profile = profile
        self.index = index
        self.budget = budget or profile["budget_tokens"]
        self.estimate = TOKEN_ESTIMATORS[profile["estimator"]]
        self.estimate_length = LENGTH_ESTIMATORS.get(profile["estimator"])
        self.cache = {}
        self.forget()

    def forget(self):
        """Drop the per-file memos below; context_for_file calls it per file.

        They exist because records are line-granular. Every function in a
        minified file opens and closes on line 1, so each one's window starts
        with the same megabyte, and scanning, rendering and hashing that once
        per FUNCTION made one 360 KB bundle take 77 seconds and a 1.36 MB one
        not finish at all. Each memo is keyed by exactly what its value is a
        function of, so what comes out is byte-identical either way.
        """
        self.spans = {}                     # (file, start, end) -> type/callee parts
        self.rendered = {}                  # part -> materialise([part])
        self.hashed = {}                    # first part -> sha256 state after it

    def read_lines(self, rel):
        if rel in self.cache:
            return self.cache[rel]
        if len(self.cache) > 64:
            self.cache.clear()
        try:
            with open(os.path.join(self.root, rel), "rb") as fh:
                lines = fh.read().decode("utf-8", "replace").split("\n")
        except OSError:
            lines = None
        self.cache[rel] = lines
        return lines

    def span_parts(self, rel, ls, le, body):
        """(type_decl parts, callee candidates) for a record spanning `ls`-`le`
        of `rel`: everything the identifier scan decides, which depends on the
        span and not on which record occupies it.

        The callee list is the candidates in name order, each paired with its
        name, and one longer than the limit: the only per-record filter left is
        that a record is not its own callee, and that removes at most one."""
        key = (rel, ls, le)
        got = self.spans.get(key)
        if got is not None:
            return got
        prof = self.profile
        limits = prof["max_parts"]
        names = sorted(set(re.findall(r"[A-Za-z_]\w{2,}", body)))
        types = []
        for name in names:
            if len(types) >= limits["type_decl"]:
                break
            found = self.index["types"].get(name)
            if found and not (found[0] == rel and ls <= found[1] <= le):
                types.append({"role": "type_decl", "file": found[0],
                              "line_start": found[1], "line_end": found[2]})
        sig = prof["callee_signature_lines"]
        callees = []
        for name in names:
            if len(callees) > limits["callee"]:
                break
            found = self.index["functions"].get(name)
            if not found:
                continue
            if found[0] == rel and found[1] == ls:
                continue
            callees.append((name, {"role": "callee", "file": found[0],
                                   "line_start": found[1],
                                   "line_end": min(found[2], found[1] + sig - 1)}))
        got = self.spans[key] = (types, callees)
        return got

    def candidate_parts(self, record, body):
        prof = self.profile
        limits = prof["max_parts"]
        rel, ls, le = record["file"], record["line_start"], record["line_end"]
        own = {"role": "function", "file": rel, "line_start": ls, "line_end": le}
        types, callees = self.span_parts(rel, ls, le, body)
        buckets = {"function": [own], "type_decl": [dict(p) for p in types],
                   "caller": [], "file_preamble": [], "callee": []}

        span = prof["caller_context_lines"]
        for site_file, site_line in self.index["calls"].get(record["name"], ())[:12]:
            if len(buckets["caller"]) >= limits["caller"]:
                break
            if site_file == rel and ls <= site_line <= le:
                continue                               # recursion is not a caller
            buckets["caller"].append(
                {"role": "caller", "file": site_file,
                 "line_start": max(1, site_line - span), "line_end": site_line + span})

        end = self.index["preamble"].get(rel, 0)
        if end and ls > end:
            buckets["file_preamble"].append(
                {"role": "file_preamble", "file": rel, "line_start": 1,
                 "line_end": min(end, prof["preamble_max_lines"])})

        for name, part in callees:
            if len(buckets["callee"]) >= limits["callee"]:
                break
            if name == record["name"]:
                continue
            buckets["callee"].append(dict(part))
        return buckets

    def render(self, part):
        """materialise([part]). A window is its parts' renderings end to end -
        materialise is a concatenation - so each part is rendered once."""
        key = (part["role"], part["file"], part["line_start"], part["line_end"])
        chunk = self.rendered.get(key)
        if chunk is None:
            chunk = self.rendered[key] = materialise([part], self.read_lines)
        return chunk

    def digest(self, kept, chunks):
        """text_digest("".join(chunks)), without joining them, and with the
        hash of the first part - the function itself - taken once per range."""
        if not chunks:
            return text_digest("")
        first = kept[0]
        key = (first["role"], first["file"], first["line_start"], first["line_end"])
        state = self.hashed.get(key)
        if state is None:
            state = self.hashed[key] = hashlib.sha256(
                chunks[0].encode("utf-8", "surrogateescape"))
        state = state.copy()
        for chunk in chunks[1:]:
            state.update(chunk.encode("utf-8", "surrogateescape"))
        return state.hexdigest()

    def build(self, record, body):
        buckets = self.candidate_parts(record, body)
        kept, chunks, size, tokens, truncated = [], [], 0, 0, False
        for role in self.profile["order"]:
            for part in buckets.get(role, ()):
                chunk = self.render(part)
                if self.estimate_length is not None:
                    cost = self.estimate_length(size + len(chunk))
                else:
                    cost = self.estimate("".join(chunks) + chunk)
                if kept and cost > self.budget:
                    # Stop at the first part that does not fit rather than
                    # cherry-picking a smaller one further down the order: a
                    # window whose contents depend on the sizes of what came
                    # before is not reproducible from the profile alone.
                    truncated = True
                    break
                kept.append(part)
                chunks.append(chunk)
                size += len(chunk)
                tokens = cost
            if truncated:
                break
        return {
            "profile": self.profile_name,
            "budget_tokens": self.budget,
            "estimated_tokens": tokens,
            "estimator": self.profile["estimator"],
            "truncated": truncated,
            "parts": [{"role": p["role"], "file": p["file"],
                       "line_start": p["line_start"], "line_end": p["line_end"]}
                      for p in kept],
            "text_sha256": self.digest(kept, chunks),
        }


_CTX = {}


def context_init(payload):
    _CTX["builder"] = ContextBuilder(payload["root"], payload["profile_name"],
                                     payload["profile"], payload["index"],
                                     payload["budget"])
    _CTX["records"] = payload["records"]


def context_for_file(rel):
    builder = _CTX["builder"]
    builder.forget()
    lines = builder.read_lines(rel) or []
    out, bodies = [], {}
    for record in _CTX["records"].get(rel, ()):
        span = (record["line_start"], record["line_end"])
        body = bodies.get(span)
        if body is None:
            body = bodies[span] = "\n".join(lines[span[0] - 1:span[1]])
        out.append((record["function_id"], builder.build(record, body)))
    return out


# --------------------------------------------------------------------------- #
# git
# --------------------------------------------------------------------------- #

# Every git process stage 1 starts runs in the scanned repository, whose own
# config is the attacker's whenever the tree arrived with its .git/. The
# settings every call carries, and why, are in rules_lib.py beside
# GIT_OVERRIDES: they moved there so the run-directory gate - which every
# reader runs, some as a `python3 -I` process that imports only the standard
# library - carries them too. These names are kept so nothing here changes.
_GIT_OVERRIDES = rules_lib.GIT_OVERRIDES
_git_env = rules_lib.git_env
run_git = rules_lib.run_git
_git_trusted_config = rules_lib.git_trusted_config
_GIT_FILTER_KEYS = ("clean", "smudge", "process")
# Repositories _git_filter_overrides will ask about - the scanned one and its
# submodules, nested ones included - before it refuses. Four git processes
# each; a tree past this is one whose status nobody should wait for.
GIT_MAX_REPOSITORIES = 1000


def _config_pairs(raw):
    """(key, value) pairs out of `git config -z --get-regexp` output."""
    pairs = []
    for entry in (raw or b"").split(b"\0"):
        if entry:
            key, _nl, value = entry.partition(b"\n")
            pairs.append((os.fsdecode(key), os.fsdecode(value)))
    return pairs


def _git_filter_overrides(root, config):
    """`-c` items that disarm every filter driver the scanned repository defines
    itself, or None when one of them cannot be disarmed.

    A driver is disarmed by giving its programs the values the operator's
    GLOBAL config gives them, or none. git-lfs, which `git lfs install` puts in
    the global config, keeps working - disarming it would make every LFS file
    whose stat data is stale read as modified - while a repository that defines
    or redefines a driver gets the operator's program or nothing. The other
    candidate, `--attr-source=<empty tree>`, is not enough: it replaces the
    tree's .gitattributes but still reads `$GIT_DIR/info/attributes`, which
    ships inside the same untrusted .git/, and it disarms git-lfs as well.

    The repository's drivers are read from its local and worktree config and
    from every submodule's, because `git status` recurses into submodules and
    these settings go with it. Reading config runs nothing.

    The submodules are found the way `git status` finds them - each gitlink
    in a repository's index whose work tree has a `.git`, asked about with
    `--git-dir=.git` from there, as git's own recursion does - and never by
    walking the filesystem. The walk this replaces went through
    `.git/modules`, which arrives with the untrusted tree: linked to `/`, it
    read every file called `config` on the machine and started a git process
    for each, and it never looked at a nested submodule that keeps a real
    `.git` directory in its work tree, whose filter `git status` then ran.
    More than GIT_MAX_REPOSITORIES of them is refused, like a driver that
    cannot be disarmed, and so is one whose git directory will not open:
    `dirty` is null rather than a status nobody vouched for.
    """
    names, seen, todo, asked = set(), set(), [(root, [])], 0
    while todo:
        where, pre = todo.pop()
        asked += 1
        if asked > GIT_MAX_REPOSITORIES:
            return None
        gitdir = run_git(where, pre + ["rev-parse", "--git-dir"], config=config)
        if not gitdir:
            # A submodule with a .git that git cannot open, which fails
            # `git status` too - and whose config nobody has read.
            return None
        key = os.path.realpath(os.path.join(where, os.fsdecode(gitdir.strip())))
        if key in seen:
            continue
        seen.add(key)
        for scope in ("--local", "--worktree"):
            raw = run_git(where, pre + ["config", scope, "--includes", "-z",
                                        "--get-regexp", r"^filter\."], config=config)
            for item, _value in _config_pairs(raw):
                name = item[len("filter."):].rpartition(".")[0]
                if name:
                    names.add(name)
        listed = run_git(where, pre + ["ls-files", "-s", "-z"], config=config) or b""
        for entry in listed.split(b"\0"):
            if not entry.startswith(b"160000 ") or b"\t" not in entry:
                continue                               # not a submodule
            sub = os.path.join(where, os.fsdecode(entry.split(b"\t", 1)[1]))
            if os.path.lexists(os.path.join(sub, ".git")):
                todo.append((sub, ["--git-dir=.git"]))
    if any("=" in name for name in names):
        return None                    # `-c` cannot name it, so it cannot be disarmed
    own = dict(_config_pairs(run_git(
        root, ["config", "--global", "-z", "--get-regexp", r"^filter\."],
        config=config)))
    items = []
    for name in sorted(names):
        for sub in _GIT_FILTER_KEYS:
            key = "filter.%s.%s" % (name, sub)
            items.append("%s=%s" % (key, own.get(key, "")))
        key = "filter.%s.required" % name
        items.append("%s=%s" % (key, own.get(key, "false")))
    return items


def _tooling_paths(root):
    """The scanner's own folders inside `root`, as pathspecs relative to it: this
    installed skill, when it sits inside the tree. They are never scanned, so a
    checkout whose only change is the skill's own install folder is not dirty."""
    out = []
    real_root = os.path.realpath(root)
    skill = rules_lib.SKILL_ROOT
    if skill.startswith(real_root.rstrip(os.sep) + os.sep):
        out.append(os.path.relpath(skill, real_root).replace(os.sep, "/"))
    return tuple(out)


def git_state(root):
    """{commit, branch, dirty, available} for the tree at `root`.

    `dirty` is null when `git status` could not answer. A failed status used to
    read as a clean one - a corrupt index, a submodule whose git directory was
    gone, a status past its timeout - and `dirty: false` is a claim that the
    scanned bytes are the recorded commit. The pipeline's own directories are
    left out of the question, because they are never scanned: a clean
    checkout's first run used to record itself dirty because of the
    `.security-review/` it had just written.
    """
    config = _git_trusted_config()
    head = run_git(root, ["rev-parse", "HEAD"], config=config)
    if head is None:
        return {"commit": None, "branch": None, "dirty": False, "available": False}
    branch = run_git(root, ["rev-parse", "--abbrev-ref", "HEAD"], config=config) or b""
    filters = _git_filter_overrides(root, config)
    status = None
    if filters is not None:
        # The explicit "." is what git before 2.13 needs beside an exclusion.
        status = run_git(root, ["status", "--porcelain", "--", "."]
                         + [":(exclude)" + p for p in
                            (RUN_DIR_NAME,) + _tooling_paths(root)],
                         config=config + filters)
    return {"commit": head.decode("utf-8", "replace").strip(),
            "branch": branch.decode("utf-8", "replace").strip(),
            "dirty": None if status is None else bool(status.strip()),
            "available": True}


_C_ESCAPES = {ord("a"): 7, ord("b"): 8, ord("t"): 9, ord("n"): 10, ord("v"): 11,
              ord("f"): 12, ord("r"): 13, ord('"'): 34, ord("\\"): 92}


def _c_unquote(raw):
    """A path as git prints it, unquoted: `"src/tab\\tx.c"` is `src/tab<TAB>x.c`.

    Even with core.quotePath off, git C-quotes a path holding a quote, a
    backslash or a control character. Anything not in quotes comes back as it
    is."""
    if len(raw) < 2 or raw[:1] != b'"' or raw[-1:] != b'"':
        return raw
    body, out, i = raw[1:-1], bytearray(), 0
    while i < len(body):
        c = body[i]
        if c != 0x5C or i + 1 >= len(body):
            out.append(c)
            i += 1
            continue
        octal = body[i + 1:i + 4]
        if len(octal) == 3 and all(0x30 <= d <= 0x37 for d in octal):
            out.append(int(octal, 8) & 0xFF)
            i += 4
            continue
        out.append(_C_ESCAPES.get(body[i + 1], body[i + 1]))
        i += 2
    return bytes(out)


def git_file_history(root, now):
    """(last-modified days, commits in 90 days) per repo-relative path.

    One `git log` pass bounded to two years, not one `git log` per file: on a
    tree with ten thousand files the per-file form costs ten thousand processes.
    The figures are per FILE, and every function in a file carries its file's -
    per-function churn needs a blame per function, which costs more than the
    signal is worth to a ranking that only sorts.

    Each commit's header line is a NUL and the timestamp, because a path can
    never hold a NUL. The header used to be told from a path by `isdigit()`, so
    a file called `404` was read as a commit made 404 seconds after 1970, and
    stamped every path after it in its commit. `core.quotePath=false` and
    _c_unquote give paths back as the walk spells them - a quoted
    `"src/h\\303\\251llo.c"` matched no record, and its churn was always zero -
    and `--relative` makes them relative to `root` when `root` is a
    subdirectory of the repository, as every record's `file` is.
    """
    raw = run_git(root, ["-c", "core.quotePath=false", "log", "--since=2.years",
                         "--relative", "--name-only", "--no-merges",
                         "--no-show-signature", "--no-textconv", "--no-ext-diff",
                         "--pretty=format:%x00%ct"],
                  timeout=120, config=_git_trusted_config())
    if raw is None:
        return {}
    last, recent, stamp = {}, {}, None
    cutoff = now - 90 * 86400
    for line in raw.split(b"\n"):
        if line.startswith(b"\0"):
            try:
                stamp = int(line[1:])
            except ValueError:
                stamp = None
            continue
        if not line or stamp is None:
            continue
        path = os.fsdecode(_c_unquote(line))
        if path not in last:
            last[path] = stamp
        if stamp >= cutoff:
            recent[path] = recent.get(path, 0) + 1
    return {path: {"last_modified_days": int((now - ts) // 86400),
                   "commits_90d": recent.get(path, 0)}
            for path, ts in last.items()}


# --------------------------------------------------------------------------- #
# coverage
# --------------------------------------------------------------------------- #

def expected_sample_size(skipped):
    want = -(-int(skipped) * SKIP_SAMPLE_PERCENT // 100)
    return min(int(skipped), max(SKIP_SAMPLE_MIN, min(SKIP_SAMPLE_MAX, want)))


def skip_sample(skipped_hits):
    """Every Nth skipped hit, sized the way stage 4 recomputes it."""
    want = expected_sample_size(len(skipped_hits))
    if want <= 0:
        return []
    step = max(1, len(skipped_hits) // want)
    picked = skipped_hits[::step][:want]
    return [{"file": h["file"], "line": h["line"],
             "class": h.get("skip_class") or "other"} for h in picked]


def build_coverage(compiled, counts, skipped_by_rule, scanned_roots, wrappers,
                   loose_hits, languages_seen, wrapper_blind=None):
    rules = []
    for entry in compiled.rules:
        rule = entry["rule"]
        rid = rule["rule_id"]
        tally = counts.get(rid, {"hits": 0, "emitted": 0, "skipped": 0,
                                 "deferred": 0,
                                 "by_target": {"line": 0, "function_or_path": 0}})
        half = compiled.line_halves.get(rid)
        hits = tally["hits"]
        cause = None
        if hits == 0:
            cause = "pattern-unmatchable" if loose_hits.get(rid) else "absent-from-tree"
        blind = (wrapper_blind or {}).get(rid) or {"blind": False, "extra": 0,
                                                    "examples": []}
        rules.append({
            "rule_id": rid,
            "category": rule["category"],
            "cwe": rule["cwe"],
            "languages": list(rule["languages"]),
            "match_target": rule["match_target"],
            "multiline": bool(rule["multiline"]),
            "pattern": entry["pattern"],
            "canonical_pattern": rule["pattern"],
            "pattern_source": entry["source"],
            # How a name pattern was run over "<file>::<function>": `segment`
            # reads `_` and camelCase humps as `\b` (rules_lib, "name
            # targets"). Stage 4 recounts the name half the way this says, so a
            # run from before segment matching - which has no such field - is
            # recounted the way it counted. Null on a line rule.
            "name_match": (rules_lib.NAME_MATCH
                           if rule["match_target"] == "function_or_path" else None),
            # The sink half of a name-matched rule, and the only pattern in this
            # row stage 4 can re-run against source lines. Null for every rule
            # that has just the one pattern.
            "line_pattern": half["pattern"] if half else None,
            "canonical_line_pattern": rule.get("line_pattern"),
            "line_pattern_source": half["source"] if half else None,
            "hits": hits,
            "hits_by_target": dict(tally.get(
                "by_target", {"line": 0, "function_or_path": 0})),
            "emitted": tally["emitted"],
            "skipped": tally["skipped"],
            "deferred": tally["deferred"],
            "skip_reason": rule["skip_clause"] if tally["skipped"] else None,
            "skipped_sample": skip_sample(skipped_by_rule.get(rid, [])),
            "zero_hit_cause": cause,
            # Not part of §5, and it is here because §5's two causes cannot say
            # which of them applies to a C rule in a tree that holds no C. The
            # cause stays what the loosened pattern measured - stage 4 recomputes
            # it and the two must agree - and this field carries the fact that
            # separates a blind rule from a language nobody wrote here.
            "languages_present": sorted(set(rule["languages"]) & languages_seen),
            "zero_hit_evidence": loose_hits.get(rid) if hits == 0 else None,
            # The blindness `zero_hit_cause` cannot speak for: a rule that
            # matched, and is blind to more sites than it caught because the
            # tree wraps the call under a prefixed name its leading `\b`
            # cannot open a match inside. The same test stage 4 refuses on
            # (rules_lib.is_wrapper_blind), over the same bytes. `extra` is the
            # sites the anchored form missed; `examples` (up to three, an
            # identifier each) are only listed when `wrapper_blind`; `remedy`
            # says whether a wrapper_resolution entry can close it - only a
            # rule with a wrapper_class has one - and the gate refuses a blind
            # rule with a remedy and merely reports one without.
            "wrapper_blind": blind["blind"],
            "wrapper_blind_extra": blind["extra"],
            "wrapper_blind_examples": list(blind["examples"]),
            "wrapper_blind_remedy": bool(rule.get("wrapper_class")),
            "high_signal": bool(rule["high_signal"]),
            "weight": rule["weight"],
        })
    return {
        "schema_version": SCHEMA_VERSION,
        "scanned_roots": list(scanned_roots),
        "wrapper_resolution": {k: list(wrappers.get(k, []))
                               for k in rules_lib.WRAPPER_CLASSES},
        "rules": rules,
    }


# --------------------------------------------------------------------------- #
# the run
# --------------------------------------------------------------------------- #

def _pool_map(func, items, jobs, initializer, payload):
    if jobs <= 1 or len(items) < 32:
        initializer(payload)
        return [func(item) for item in items]
    ctx = multiprocessing.get_context("fork") \
        if "fork" in multiprocessing.get_all_start_methods() \
        else multiprocessing.get_context()
    with ctx.Pool(jobs, initializer=initializer, initargs=(payload,)) as pool:
        return pool.map(func, items, chunksize=8)


def load_manifest(path):
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        fail(path, None, "cannot be read: %s" % exc)
    except ValueError as exc:
        fail(path, getattr(exc, "lineno", None), "not valid JSON: %s" % exc)
    if not isinstance(doc, dict):
        fail(path, 1, "top level is %s, expected an object" % type(doc).__name__)
    version = doc.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        fail(path, 1, "schema_version is %r, this tool knows %d"
             % (version, SCHEMA_VERSION))
    return doc


RUN_DIR_NAME = ".security-review"

# Everything this stage writes under the run directory, relative to it.
# check_out_dir looks at each one before a byte is read, so a run that is going
# to be refused is refused before it has done the extraction.
STAGE1_WRITES = (
    ".gitignore", "manifest.json", "run.json",
    os.path.join("extract", "functions.jsonl"),
    os.path.join("extract", "rules.jsonl"),
    os.path.join("extract", "coverage.json"),
    os.path.join("extract", "extract-report.json"),
)


def _run_dir_link(root, path):
    """The first symlink on the way from `<root>/.security-review` down to
    `path`, `path` included, or None - and None for a path outside that
    directory, which is not this check's business.

    `root` itself and everything above it are never examined: `--root` may
    legitimately be a symlink, and on macOS /var is one. Every tool in this
    bundle that writes under the run directory makes this check (pipeline
    contract §1, §9 rule 2); the tools do not import each other for it, so
    this is extract_functions.py's own copy.
    """
    base = os.path.join(os.path.normpath(root), RUN_DIR_NAME)
    rel = os.path.relpath(os.path.normpath(path), base)
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return None
    probe = base
    for step in [None] + ([] if rel == os.curdir else rel.split(os.sep)):
        if step is not None:
            probe = os.path.join(probe, step)
        if os.path.islink(probe):
            return probe
        if not os.path.lexists(probe):
            return None
    return None


def _refuse_linked(root, path):
    """Stop, as a usage error, when a write to `path` would go through a link."""
    link = _run_dir_link(root, path)
    if link is None:
        return
    try:
        target = os.readlink(link)
    except OSError as exc:
        target = "(unreadable: %s)" % exc
    fail("--out", None,
         "%s is a symlink to %s. The run directory sits inside the scanned tree, "
         "and a repository can legitimately ship one - its ledger is committed "
         "there - so a link in it is the tree under review choosing where this "
         "tool writes: into its own source, or anywhere else the operator can "
         "write. Stage 1 does not write through one. Pipeline contract §1 fixes "
         "the run directory at <root>/%s and §9 rule 2 forbids writing to the "
         "tree under review; remove the link, or pass --out a directory outside "
         "the tree." % (link, target, RUN_DIR_NAME))


def check_out_dir(root, out):
    """The run directory, refused when it would write into the scanned tree.

    §1 puts every run artifact at `.security-review/` in the scanned repository,
    and §9.2 is that no tool in this skill writes to the scanned tree at all.
    `--out src` satisfies neither: it drops run.json, a .gitignore and two JSONL
    files into the code under review. A directory outside the scanned root is
    another matter - it contaminates nothing - so only the in-tree case is
    refused, and it is refused rather than silently redirected, because a run
    that quietly wrote somewhere other than where it was told is worse than one
    that stopped.

    The test is on the RESOLVED path as well as the spelled one. It used to be
    normpath alone, and a repository that committed `.security-review -> src`,
    or `.security-review/extract -> ../src`, had every artifact of the run
    written into its source tree - or through a link planted at one of the
    files, over anything the operator could write. So an in-tree run directory
    must be exactly `<real root>/.security-review` once resolved, with no link
    on the way to it or to anything this stage writes there; and an out-of-tree
    one must not resolve back into the tree.
    """
    out_dir = os.path.normpath(
        out if os.path.isabs(out) else os.path.join(root, out))
    root = os.path.normpath(root)
    inside = out_dir == root or out_dir.startswith(root + os.sep)
    if inside and os.path.basename(out_dir) != RUN_DIR_NAME:
        fail("--out", None,
             "%r is inside the scanned tree at %s and is not named %s. Stage 1 "
             "writes run artifacts, never source: §1 fixes the run directory and "
             "§9.2 forbids writing to the tree under review"
             % (out, root, RUN_DIR_NAME))
    real_root = os.path.realpath(root)
    run_dir = os.path.join(real_root, RUN_DIR_NAME)
    real_out = os.path.realpath(out_dir)
    if inside:
        for rel in ("",) + STAGE1_WRITES:
            _refuse_linked(root, os.path.join(out_dir, rel) if rel else out_dir)
        if real_out != run_dir:
            fail("--out", None,
                 "%s resolves to %s, not to %s. Pipeline contract §1 fixes the "
                 "run directory at <root>/%s and §9 rule 2 forbids writing "
                 "anywhere else in the tree under review"
                 % (out_dir, real_out, run_dir, RUN_DIR_NAME))
    elif real_out == real_root or real_out.startswith(real_root + os.sep):
        if real_out != run_dir:
            fail("--out", None,
                 "%s is outside the scanned tree as spelled, but resolves to %s, "
                 "inside it. §9 rule 2 forbids writing to the tree under review"
                 % (out_dir, real_out))
        for rel in STAGE1_WRITES:
            _refuse_linked(real_root, os.path.join(run_dir, rel))
    return out_dir


# The `--snapshot` value meaning "the one this run directory holds". Not a real
# path: argparse hands it back when the flag is given without an argument, and
# resolve_snapshot turns it into <out>/snapshot once --out is known.
SNAPSHOT_HERE = "<out>/snapshot"


def resolve_snapshot(root, out_dir, value):
    """(the tree to READ, the run.json snapshot block) for a --snapshot value.

    Two roots, and the whole subtlety of the flag is keeping them apart.

      READ root     the snapshot. Every byte hashed, scored or quoted comes from
                    here, and nothing can edit it mid-run.
      RECORD root   the original tree. `repo_root`, the git state and per-file
                    churn come from here, and every `file` field stays relative
                    to it.

    The two agree on relative paths because the snapshot mirrors the tree's
    layout exactly - `snapshot/src/proto/parse.c` is `src/proto/parse.c`. That is
    what makes the mapping the identity rather than a translation table, and it
    is also what makes it easy to get wrong in the other direction: point the
    extractor at the snapshot with `--root` and every downstream file:line reads
    `.security-review/snapshot/src/proto/parse.c`, which resolves to nothing once
    the run directory is cleaned up, and `git` on every record goes empty because
    a snapshot deliberately has no `.git`.

    The manifest's `source_root` must be this run's `--root`. A snapshot of some
    other tree would hand back paths that resolve against a repository it was
    never taken from - the citations would look fine and point at unrelated
    lines - so it is refused as a usage error rather than scanned.
    """
    if value is None:
        return root, None
    path = os.path.join(out_dir, snapshot.SNAPSHOT_DIR_NAME) \
        if value == SNAPSHOT_HERE else os.path.abspath(value)
    if not os.path.isdir(path):
        fail("--snapshot", None,
             "%s is not a directory; run snapshot.py --root %s first"
             % (path, root))
    # The run directory's own snapshot is read only as snapshot.py leaves it: a
    # real directory beside a real manifest. A link there is a snapshot some
    # other tree - or the scanned repository - chose.
    if value == SNAPSHOT_HERE:
        for linked in (path, os.path.join(out_dir, snapshot.MANIFEST_NAME)):
            if os.path.islink(linked):
                fail("--snapshot", None,
                     "%s is a symbolic link. The run directory's snapshot is "
                     "read only as snapshot.py writes it; re-run snapshot.py" % linked)
    try:
        manifest = snapshot.load_manifest(os.path.dirname(path))
    except snapshot.SnapshotError as exc:
        fail("--snapshot", None, str(exc))
    # snapshot.py records both roots as absolute real paths. A relative one is
    # not a manifest it wrote, and realpath() would resolve it against the
    # working directory - where `"source_root": "."` and `"snapshot_root":
    # ".security-review/snapshot"` pass both checks below from the repository
    # root without knowing where the checkout is, and a committed decoy
    # snapshot/ becomes the corpus.
    if manifest.get("tool") != snapshot.TOOL or not all(
            isinstance(manifest.get(key), str) and os.path.isabs(manifest[key])
            for key in ("snapshot_root", "source_root")):
        fail("--snapshot", None,
             "%s was not written by %s: it %s. Re-run snapshot.py"
             % (os.path.join(os.path.dirname(path), snapshot.MANIFEST_NAME),
                snapshot.TOOL, "names another tool" if manifest.get("tool")
                != snapshot.TOOL else "records a relative root"))
    if os.path.realpath(manifest["snapshot_root"]) != os.path.realpath(path):
        fail("--snapshot", None,
             "%s names %s, not %s" % (snapshot.MANIFEST_NAME,
                                      manifest["snapshot_root"], path))
    # Spelled exactly as snapshot.py records it, os.path.realpath(root). Resolved
    # first, an absolute `/proc/self/cwd` passed from the repository root just as
    # "." did.
    if manifest["source_root"] != os.path.realpath(root):
        fail("--snapshot", None,
             "this snapshot was taken of %s, not of --root %s. Its paths would "
             "resolve against a tree it was never taken from"
             % (manifest["source_root"], root))
    block = {
        "id": manifest["snapshot_id"],
        "files": manifest.get("counts", {}).get("files"),
        "bytes": manifest.get("counts", {}).get("bytes"),
        "created_at": manifest["created_at"],
        # Carried because a run whose snapshot was incomplete, or taken while the
        # tree moved, must say so where the provenance is read - not only in a
        # manifest beside it that nobody opens.
        "cap_hit": manifest.get("caps", {}).get("hit"),
        "changed_during_snapshot":
            manifest.get("counts", {}).get("changed_during_snapshot", 0),
        # Two more narrowings that used to live only in the manifest, which
        # nothing downstream opens. `snapshot.py --exclude src` produces a
        # snapshot with no source in it, and a run over that snapshot used to
        # report a clean scan of a tree it had never seen: the files were simply
        # absent, which reads as "not present" rather than "excluded, reason".
        # `copy_failed` is the same shape - a file this machine could not write.
        "excludes": list(manifest.get("policy", {}).get("excludes") or []),
        "copy_failed": manifest.get("counts", {}).get("copy_failed", 0),
        # The folders the snapshot left out as the scanner's own tooling (reason
        # `scanner-tooling`) or as the run folder of another skill (reason
        # `sibling-run-directory`), each with the words that justified it. The walk
        # over the snapshot never meets them, so without this `tooling_skipped`
        # was empty on exactly the path every run takes (snapshot first), and
        # the report, the summary and the coverage limitations said nothing about
        # a folder that was never read. They are copied into `tooling_skipped`.
        "scanner_tooling": [
            {"path": e["path"],
             "reason": str(e.get("detail") or "scanner tooling").split(" (rules_lib", 1)[0]}
            for e in (manifest.get("exclusions") or [])
            if isinstance(e, dict)
            and e.get("reason") in ("scanner-tooling", rules_lib.SIBLING_RUN_REASON)
            and isinstance(e.get("path"), str)],
        "root": path,
        "tool_version": manifest.get("tool_version"),
    }
    return path, block


def tree_sitter_importable():
    """Whether ANY tree-sitter provider imports in this process. True/False.

    Distinct from `parser.tree_sitter_available` in extract-report.json, which
    says a grammar actually parsed something. Both are worth having: the first
    is a fact about the machine the run happened on, the second is a fact about
    the corpus, and a run where the import works but no grammar loads is a real
    state that used to read as "tree-sitter is not installed".
    """
    if not _TS["probed"]:
        _ts_probe()
    return _TS["provider"] is not None


def extract(args):
    """The whole of stage 1. Returns the report dict."""
    started = time.time()
    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        fail(root, None, "not a directory")
    if looks_like_the_bundle(root) and not args.scan_self:
        fail(root, None,
             "this is the security-review skill itself (or an old copy of it), not "
             "a repository to review. Extracting here reads the scanner's own "
             "source and counts its rule patterns as rule hits, which looks like "
             "a clean run and is not one. --root should be the repository under "
             "review: run from its top directory and pass --root . . Pass "
             "--scan-self only if you really mean to review the scanner.")
    out_dir = check_out_dir(root, args.out)
    scan_root, snapshot_block = resolve_snapshot(root, out_dir, args.snapshot)
    profile_name = args.context_profile
    if profile_name not in CONTEXT_PROFILES:
        fail("--context-profile", None,
             "%r is not a profile; this build ships %s"
             % (profile_name, ", ".join(sorted(CONTEXT_PROFILES))))
    profile = CONTEXT_PROFILES[profile_name]
    # `args.budget_tokens or profile[...]` reads 0 as "not given", so
    # `--budget-tokens 0` ran at the profile's budget while the operator believed
    # they had asked for none, and a negative one reached the window builder.
    # Neither is a budget.
    if args.budget_tokens is not None and args.budget_tokens <= 0:
        fail("--budget-tokens", None,
             "%d is not a context budget; pass a positive token count, or leave "
             "the flag off for the profile's own %d"
             % (args.budget_tokens, profile["budget_tokens"]))

    # `--manifest` used to default to None, so a run that omitted the flag
    # discarded stage 1's ENTIRE recon in silence: no wrappers, no entry points,
    # no threat model, and nothing in the output saying so. Measured on libxml2:
    # the recon agent declared 137 wrappers across four classes and 84 entry
    # points, the flag was left off, and all 49 rules ran `as-written` - a run
    # that looked exactly like one where recon had found nothing.
    #
    # The manifest lives at a path §1 fixes, inside the run directory this tool
    # writes to itself, so there is no ambiguity about whose it is. It is read
    # by default and `--manifest` stays as the override.
    manifest_path, manifest_basis = args.manifest, "--manifest"
    if not manifest_path:
        here = os.path.join(out_dir, "manifest.json")
        if os.path.isfile(here):
            manifest_path, manifest_basis = here, "found in the run directory"
    manifest = load_manifest(manifest_path)
    wrappers = {k: list(v or []) for k, v in
                (manifest.get("wrapper_resolution") or {}).items()
                if k in rules_lib.WRAPPER_CLASSES}
    # Three states, and only two of them are answers. `physical_attacker` gates
    # whether HW-* hits carry `advisory_only`, which caps their severity at low
    # - they are dispatched and reported either way, so this moves a ceiling,
    # never a candidate.
    #
    # `None is False` is False, so an ABSENT value used to read exactly like
    # `true`: physical attacker in scope, HW severities uncapped, on a tree
    # where nobody had determined the threat model. Found on libxml2, where an
    # emptied manifest silently uncapped every HW finding in a library that
    # cannot be physically attacked.
    #
    # Unknown still resolves the way it did - uncapped - because under-reporting
    # a real physical-attack bug is worse than over-reporting one, and the
    # ceiling is the only thing at stake. What changes is that it says so.
    physical = manifest.get("physical_attacker")
    advisory = physical is False
    threat_basis = ("declared: physical attacker in scope" if physical is True
                    else "declared: no physical attacker, HW-* capped at low"
                    if physical is False
                    else "UNDETERMINED")
    test_globs = list(manifest.get("test_tree_globs") or [])
    scanned_roots = [r for r in (manifest.get("scanned_roots") or []) if r] or ["."]

    rules_dir = os.path.abspath(args.rules_dir or rules_lib.default_rules_dir())
    rules = rules_lib.load_rules(rules_dir)
    compiled = CompiledRules(rules, wrappers)

    for flag, values in (("--include", args.include), ("--exclude", args.exclude),
                         ("the manifest's scanned_roots", scanned_roots),
                         ("the manifest's exclusions",
                          [i.get("path") if isinstance(i, dict) else i
                           for i in manifest.get("exclusions") or []])):
        for value in values or []:
            fixed = root_prefixed(root, value)
            if fixed is not None:
                fail(flag, None,
                     "%r starts with the repository's own name. Paths here are "
                     "relative to --root %s, not to the folder holding it: "
                     "write %r" % (value, os.path.basename(root), fixed))
    keep = {os.path.normpath(d.rstrip("/")) for d in (args.include or [])
            if d.rstrip("/")}
    excludes = list(DEFAULT_EXCLUDES) + list(args.exclude or [])
    # A pattern the SNAPSHOT was narrowed by. Those files are not on disk under
    # scan_root at all, so without this they would be missing rather than
    # excluded - and coverage.json would account for a tree that was never
    # there. Carried as a real exclusion so the reason travels with it.
    snapshot_excludes = list((snapshot_block or {}).get("excludes") or [])
    excludes.extend(snapshot_excludes)
    # `waived_exclusions` is where the last run set aside what its --include
    # waived (see below), and it is an exclusion again unless this run waives
    # it too.
    for key in ("exclusions", "waived_exclusions"):
        for item in manifest.get(key) or []:
            if isinstance(item, dict) and item.get("path"):
                excludes.append(item["path"])
            elif isinstance(item, str):
                excludes.append(item)
    # `--include` is applied to the MERGED list, not to the defaults alone.
    # write_outputs persists every exclusion into manifest.json and the next run
    # reads that manifest back, so after any first run the manifest's own copy
    # of `vendor` undid `--include vendor` - the one recovery the coverage
    # account tells an operator to use, re-run in the same run directory, did
    # nothing. A snapshot's narrowing is the exception: those files are not in
    # the snapshot at all, and dropping the pattern would lose the reason why.
    #
    # What the include drops is not thrown away. Dropped from `exclusions` and
    # nothing else, an approved stage-0 scope - `src/gen`, with its reason and
    # risk_if_skipped - was gone from the manifest for good after one
    # `--include src/gen`, which run_status itself advises: every later run
    # scanned it without the flag, and the Not scanned row was lost, where the
    # README says an include is a flag and a re-run without it excludes the
    # directory again. So it is written to `waived_exclusions` as it was given,
    # and read back above.
    narrowed = set(snapshot_excludes)
    waived_excludes = [e for e in excludes if e not in narrowed
                       and os.path.normpath(e.rstrip("/")) in keep]
    excludes = [e for e in excludes
                if e in narrowed or os.path.normpath(e.rstrip("/")) not in keep]
    languages = set(args.language or ())
    tooling_skipped = []
    files, unsupported, oversize, unstattable, pruned, extensionless = walk_files(
        scan_root, scanned_roots, excludes, languages, args.max_file_bytes,
        includes=sorted(keep), tooling=tooling_skipped)
    # A snapshot walk never meets the folders the snapshot left out, so they are
    # taken from its manifest: the skip is reported on this path as on a live walk.
    for item in (snapshot_block or {}).get("scanner_tooling") or []:
        tooling_skipped.append((item["path"].replace(os.sep, "/"), item["reason"]))

    jobs = max(1, args.jobs or (os.cpu_count() or 1))
    # Every worker below reads bytes, so every one of them gets scan_root. The
    # only things that get `root` are the two that ask the ORIGINAL tree a
    # question: git_file_history (a snapshot has no .git) and the record of what
    # this run was about.
    payload = {"root": scan_root, "rules": rules, "wrappers": wrappers,
               "test_globs": test_globs, "advisory": advisory,
               "prefer_ts": not args.no_tree_sitter}
    results = _pool_map(scan_file, files, jobs, worker_init, payload)

    # ---- aggregate ---- #
    functions, hits, errors = [], [], []
    by_language, tiers = {}, {"exact": 0, "heuristic": 0, "window": 0}
    # Records a tree-sitter grammar actually produced. Counted from the records,
    # not from _TS, because in a pooled run the parsing happens in the workers
    # and the parent never builds a parser of its own.
    tree_sitter_records = 0
    type_index, call_index, func_index, preamble_index = {}, {}, {}, {}
    records_by_file, window_files, no_function_files = {}, [], []
    line_text, line_text_at, name_hit_counts, unclosed_files = {}, {}, {}, []
    for res in results:
        if res["error"]:
            errors.append(res["error"])
            continue
        rel, language = res["file"], res["language"]
        stats = by_language.setdefault(language, {
            "files": 0, "functions": 0, "exact": 0, "heuristic": 0, "window": 0})
        stats["files"] += 1
        preamble_index[rel] = res["preamble"]
        line_text.update(res.get("line_text") or {})
        line_text_at.update(res.get("line_text_at") or {})
        for rid, n in (res.get("name_hit_counts") or {}).items():
            name_hit_counts[rid] = name_hit_counts.get(rid, 0) + n
        for name, lines_ in res["calls"].items():
            slot = call_index.setdefault(name, [])
            if len(slot) < 8:
                slot.extend((rel, ln) for ln in lines_[:MAX_CALL_LINES])
        for decl in res["types"]:
            type_index.setdefault(decl["name"],
                                  (rel, decl["line_start"], decl["line_start"] + 15))
        for record in res["functions"]:
            record["in_test_tree"] = res["in_test_tree"]
            record["generated_file"] = res["generated"]
            functions.append(record)
            stats["functions"] += 1
            confidence = record["extractor"]["confidence"]
            stats[confidence] += 1
            tiers[confidence] += 1
            if record["extractor"].get("parser") == "tree-sitter":
                tree_sitter_records += 1
            func_index.setdefault(record["name"],
                                  (rel, record["line_start"], record["line_end"]))
            records_by_file.setdefault(rel, []).append(record)
        if res["tier"] == "window":
            window_files.append(rel)
        elif res["tier"] == "no-functions" :
            no_function_files.append(rel)
        if res.get("unclosed"):
            unclosed_files.append({"file": rel, "functions": res["unclosed"]})
        hits.extend(res["hits"])

    # ---- join hits to functions, innermost first ---- #
    ranges = {}
    for record in functions:
        ranges.setdefault(record["file"], []).append(record)
    for values in ranges.values():
        values.sort(key=lambda r: (r["line_start"], -(r["line_end"])))
    unjoined, owners = 0, {}
    for hit in hits:
        # Once per (file, line): every hit in a minified file is on line 1, and
        # each walk of the file's records is as long as the file.
        where = (hit["file"], hit["line"])
        if where not in owners:
            owners[where] = _innermost(ranges.get(hit["file"], ()), hit["line"])
        owner = owners[where]
        if owner is None:
            unjoined += 1
            hit["function_id"] = None
            hit["function_key"] = None
            hit["join"] = "file-only"
        else:
            hit["function_id"] = owner["function_id"]
            hit["function_key"] = owner["function_key"]
            hit["join"] = "line-in-range"

    hits.sort(key=lambda h: (h["file"], h["line"], h["column"], h["rule_id"]))
    hits.extend(derive_wfs(compiled, hits, ranges, line_text, line_text_at))
    for index, hit in enumerate(hits, 1):
        hit["schema_version"] = SCHEMA_VERSION
        hit["rule_hit_id"] = "RH-%06d" % index

    counts, skipped_by_rule = {}, {}
    for hit in hits:
        tally = counts.setdefault(
            hit["rule_id"],
            {"hits": 0, "emitted": 0, "skipped": 0, "deferred": 0,
             "by_target": {"line": 0, "function_or_path": 0}})
        tally["hits"] += 1
        tally[hit["disposition"]] += 1
        # A rule with a line_pattern produces hits from two different patterns,
        # and stage 4 re-runs only the line-level one against the tree. Without
        # this split it would compare a line-pattern recount against a total
        # that includes name matches and fail every such rule.
        target = hit.get("match_target") or "line"
        if target == "line":
            tally["by_target"]["line"] += 1
        if hit["disposition"] == "skipped":
            skipped_by_rule.setdefault(hit["rule_id"], []).append(hit)
    for rid, n in name_hit_counts.items():
        counts.setdefault(rid, {"hits": 0, "emitted": 0, "skipped": 0,
                                "deferred": 0,
                                "by_target": {"line": 0,
                                              "function_or_path": 0}})
        counts[rid]["by_target"]["function_or_path"] = n

    # ---- zero_hit_cause, mechanically ---- #
    zero = [e for e in compiled.rules
            if not e["rule"].get("derived")
            and counts.get(e["rule"]["rule_id"], {}).get("hits", 0) == 0]
    targets = [rules_lib.name_target(r["file"], r["name"]) for r in functions]
    loose_hits, loose_skipped = (loose_scan(scan_root, files, zero, jobs, targets,
                                            compiled.line_halves)
                                 if zero else ({}, 0))
    # ---- wrapper blindness, for every rule with a call-shaped branch ---- #
    wrapper_blind, wrapper_blind_skipped = wrapper_blind_scan(scan_root, files,
                                                              compiled, jobs)

    # ---- context ---- #
    index = {"types": type_index, "calls": call_index, "functions": func_index,
             "preamble": preamble_index}
    ctx_payload = {"root": scan_root, "profile_name": profile_name, "profile": profile,
                   "index": index, "budget": args.budget_tokens,
                   "records": records_by_file}
    contexts = {}
    for chunk in _pool_map(context_for_file, sorted(records_by_file), jobs,
                           context_init, ctx_payload):
        for function_id, context in chunk:
            contexts[function_id] = context
    truncated = 0
    for record in functions:
        context = contexts.get(record["function_id"])
        if context is None:
            continue
        record["context"] = context
        truncated += 1 if context["truncated"] else 0

    history = git_file_history(root, time.time())
    for record in functions:
        record["git"] = history.get(record["file"],
                                    {"last_modified_days": None, "commits_90d": 0})

    coverage = build_coverage(compiled, counts, skipped_by_rule, scanned_roots,
                              wrappers, loose_hits, set(by_language), wrapper_blind)
    environment = {
        "python": platform.python_version(),
        # The interpreter's PATH, not only its version. When tree-sitter is
        # installed in a venv but the corpus comes back heuristic, the version
        # cannot tell a venv interpreter from /usr/bin/python3 - they are often
        # the same version - and this can, in one look. A field test hit exactly
        # that: `(.venv)` active in the operator's shell, 92% heuristic in the run.
        "executable": sys.executable,
        # Set when the run re-launched itself into the activated venv because
        # tree-sitter was missing from the interpreter it started under.
        "reexec_from": os.environ.get(REEXEC_FROM),
        "platform": platform.platform(),
        "machine": platform.machine(),
        # null, not false, under --no-tree-sitter: the run declined to ask, and
        # "we did not look" is a different fact from "it is not there". §6 reads
        # this to decide whether a `heuristic` corpus is a property of the
        # machine or of the invocation.
        "tree_sitter": None if args.no_tree_sitter else tree_sitter_importable(),
    }
    total_functions = len(functions)
    unjoined_files = sorted({h["file"] for h in hits
                             if h.get("join") == "file-only"})
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "root": root,
        # Where the bytes came from, which is root itself unless --snapshot was
        # given. Recorded separately so a reader never has to infer it from the
        # presence of a snapshot block somewhere else.
        "scan_root": scan_root,
        "snapshot": snapshot_block,
        "out": out_dir,
        "jobs": jobs,
        "started_at": _iso(started),
        "elapsed_seconds": round(time.time() - started, 2),
        # Two questions, and they were collapsed into one field that got the
        # answer wrong on every default run. `tree_sitter_available` used to
        # require `any(_TS["parsers"])` - the PARENT process's parser cache -
        # but extraction happens in a worker pool, so the parent never parses a
        # file and that cache is always empty. Measured on curl at
        # fb4415d8: 5294 of 5301 boundaries exact, and the report said
        # `tree_sitter_available: false` and told the operator to install a
        # package they already had. `--jobs 1` said true over the same bytes.
        #
        # A field that reports "we could not" about work that was done is the
        # failure this skill exists to refuse, so the two questions are now two
        # fields: a grammar IMPORTED, and a grammar actually PARSED something.
        # The second is read from the tiers, which come back from the workers.
        # Which recon this corpus was built on. Absent used to be
        # indistinguishable from present-and-empty, and the two are opposite
        # facts about how much a reader should trust the rule coverage below.
        "recon": {
            "manifest": (os.path.relpath(manifest_path, root)
                         if manifest_path else None),
            "basis": manifest_basis if manifest_path else "none found",
            "entry_points": len(manifest.get("entry_points") or []),
            "wrapper_classes_resolved": sorted(k for k, v in wrappers.items() if v),
            "wrappers": sum(len(v) for v in wrappers.values()),
            "physical_attacker": physical,
            "threat_basis": threat_basis,
        },
        "parser": {
            "tree_sitter_available": _TS["provider"] is not None,
            # NOT tiers["exact"] > 0. A file's module-scope record is "exact"
            # because its boundary is trivially the whole file, so any C tree
            # with top-level code had exact > 0 with no grammar loaded at all.
            # A field-test run with every tree-sitter import failing reported
            # tree_sitter_parsed: true, and that silenced the one warning the
            # run most needed to print - the corpus was 92% heuristic.
            "tree_sitter_parsed": tree_sitter_records > 0
                                  or any(v for v in _TS["parsers"].values()),
            "provider": _TS["provider"][0] if _TS["provider"] else None,
            "import_errors": _TS["errors"][:10],
        },
        "counts": {
            "files_scanned": sum(1 for r in results if not r["error"]),
            "files_unreadable": len(errors),
            "files_too_large": len(oversize),
            "files_unstattable": len(unstattable),
            "functions": total_functions,
            "rule_hits": len(hits),
            "emitted": sum(1 for h in hits if h["disposition"] == "emitted"),
            "skipped": sum(1 for h in hits if h["disposition"] == "skipped"),
            # Counted, not asserted. A literal 0 here is a number that cannot
            # disagree with the records it summarises because it never looked at
            # them, which is the whole class of defect this contract is about.
            "deferred": sum(1 for h in hits if h["disposition"] == "deferred"),
            "hits_unjoined": unjoined,
            # Named functions the brace walk still had open when a file ran
            # out: it lost count of the braces, and those functions are not in
            # the corpus. Dropped without a word until this was counted.
            "functions_unclosed": sum(f["functions"] for f in unclosed_files),
        },
        "confidence": dict(tiers, window_share=round(
            tiers["window"] / total_functions, 4) if total_functions else 0.0),
        "by_language": {
            lang: dict(stats, window_share=round(
                stats["window"] / stats["functions"], 4) if stats["functions"] else 0.0)
            for lang, stats in sorted(by_language.items())},
        "window_files": sorted(window_files)[:25],
        "window_files_total": len(window_files),
        # Files that hold rule hits and in which no boundary could be resolved
        # at all. Most of them still carry a `<module>` record, so their hits ARE
        # joined and ARE scored; this counts the parse outcome, not a coverage
        # gap, and it used to be reported as the second while carrying the first.
        "files_no_boundaries_resolved": len(no_function_files),
        "no_boundary_files": sorted(no_function_files)[:25],
        # The real coverage gap: hits that reached no record of any kind. Taken
        # from the join that was actually performed rather than from the tier a
        # file parsed at, because `<module>` rescues most of the second set and
        # the two numbers were being reported as one.
        "files_with_hits_no_functions": len(unjoined_files),
        "hits_outside_functions_files": unjoined_files[:25],
        "unreadable_files": errors[:25],
        "too_large_files": oversize[:25],
        "unstattable_files": unstattable[:25],
        "unclosed_files": sorted(unclosed_files, key=lambda f: f["file"])[:25],
        "unsupported_extensions": dict(sorted(unsupported.items())),
        # Files with no extension, which unsupported_extensions has no key for.
        # `scripts` counts the ones a `#!` line names, by language, and
        # `readable_languages` says which of those labels THIS run extracts
        # when the file has their extension - source it could have read and
        # did not. This run's, not the skill's: on a `--language c` run a
        # Python script is not one extension away from the corpus, and saying
        # it is would send the operator to rename a file for nothing. Kept out
        # of manifest.json's unsupported_languages: a LICENSE is not a language.
        "extensionless_files": {
            "files": extensionless["files"],
            "scripts": dict(sorted(extensionless["scripts"].items())),
            "readable_languages": sorted(set(extensionless["scripts"])
                                         & (languages or set(LANGUAGES))),
            "script_files": extensionless["script_files"][:25]},
        # Directories the exclude patterns removed that held scannable source,
        # and the directories of files a pattern removed one by one - each row
        # with the patterns that did it. A reader cannot otherwise tell an
        # absent directory from a skipped one.
        "excluded_dirs": [dict(dir=d, **v) for d, v in sorted(pruned.items())],
        # Folders the walk left out as the scanner's own tooling, by identity
        # (rules_lib.is_tooling_dir), each with the reason. Not an exclusion the
        # analyst chose and not in the manifest: listed here so a reader can see
        # that nothing else was left out of the walk, and so the report can say it.
        "tooling_skipped": [{"path": path, "reason": why}
                            for path, why in sorted(set(tooling_skipped))],
        # What the blindness re-check could not examine, so that a bound on it
        # is a number in the report rather than a silence in the cause column.
        "blindness_scan": {
            "max_line_chars": LOOSE_SCAN_MAX_LINE,
            "max_text_chars": LOOSE_SCAN_MAX_TEXT,
            # (rule, line) examinations the caps above declined, summed over the
            # run. Non-zero means some zero-hit rule's `absent-from-tree` was
            # decided without reading every byte, and says how much.
            "unit_checks_skipped": loose_skipped,
            # The same, for the wrapper-blindness pass: lines over the cap that
            # neither the anchored nor the unanchored form read.
            "wrapper_blind_units_skipped": wrapper_blind_skipped,
        },
        "context": {"profile": profile_name, "budget_tokens":
                    args.budget_tokens or profile["budget_tokens"],
                    "estimator": profile["estimator"], "truncated": truncated},
        "zero_hit_rules": sorted(
            r["rule_id"] for r in coverage["rules"] if r["zero_hit_cause"]),
        # Split, because these are two different problems wearing one cause. A
        # rule whose languages are in the tree and that still matched nothing is
        # a rule that did not run - usually an unresolved wrapper. A rule whose
        # languages are absent said nothing because there was nothing to say.
        "pattern_unmatchable": sorted(
            r["rule_id"] for r in coverage["rules"]
            if r["zero_hit_cause"] == "pattern-unmatchable" and r["languages_present"]),
        "rules_language_absent": sorted(
            r["rule_id"] for r in coverage["rules"]
            if r["zero_hit_cause"] and not r["languages_present"]),
        # Rules that matched and are blind to more than they caught. Split by
        # whether a wrapper_class gives the agent a remedy, because the gate
        # refuses the first kind and only reports the second.
        "wrapper_blind": sorted(
            r["rule_id"] for r in coverage["rules"]
            if r["wrapper_blind"] and r["wrapper_blind_remedy"]),
        "wrapper_blind_advisory": sorted(
            r["rule_id"] for r in coverage["rules"]
            if r["wrapper_blind"] and not r["wrapper_blind_remedy"]),
    }
    return {"report": report, "functions": functions, "hits": hits,
            "coverage": coverage, "manifest": manifest, "out_dir": out_dir,
            "root": root, "scan_root": scan_root, "snapshot": snapshot_block,
            "rules_dir": rules_dir, "environment": environment,
            "files": files, "unsupported": unsupported,
            "by_language": by_language, "started": started,
            "scanned_roots": scanned_roots, "excludes": excludes,
            "includes": sorted(keep), "waived_excludes": waived_excludes,
            "manifest_path": manifest_path,
            "manifest_basis": manifest_basis,
            "snapshot_excludes": snapshot_excludes,
            "cli_excludes": list(args.exclude or []),
            "test_globs": test_globs}


def _innermost(records, line):
    """The smallest function whose range holds `line`.

    Innermost, because a hit inside a closure belongs to the closure: joining it
    to the enclosing function points a validator at a body the sink is not in.
    """
    best = None
    for record in records:
        if record["line_start"] > line:
            break
        if record["line_end"] >= line:
            if best is None or (record["line_end"] - record["line_start"]
                                < best["line_end"] - best["line_start"]):
                best = record
    return best


def derive_wfs(compiled, hits, ranges, line_text=None, line_text_at=None):
    """MEM-WFS: one record per distinct function that produced a candidate, in
    one of the rule's own languages (C, C++ and Rust as shipped). A function in
    any other language gets none, and verify_findings' I5 owes it none: it reads
    the languages off the coverage row this run writes for the rule.

    Not grepped - derived, exactly as the rule file says. Its `emitted` is the
    distinct-pair count that stage 4 recomputes from the candidate files rather
    than reading (invariant I5), so it is computed here as a set and never as a
    running total.
    """
    rule = next((e["rule"] for e in compiled.rules
                 if e["rule"]["rule_id"] == "MEM-WFS"), None)
    if rule is None:
        return []
    by_id = {}
    for records in ranges.values():
        for record in records:
            by_id[record["function_id"]] = record
    produced = []
    seen = set()
    for hit in hits:
        if hit["disposition"] != "emitted" or hit["rule_id"] == "MEM-WFS":
            continue
        fid = hit.get("function_id")
        if not fid or fid in seen:
            continue
        record = by_id.get(fid)
        if record is None or record["language"] not in rule["languages"]:
            continue
        seen.add(fid)
        produced.append({
            "schema_version": SCHEMA_VERSION,
            "rule_id": "MEM-WFS",
            "category": rule["category"],
            "cwe": rule["cwe"],
            "file": record["file"],
            # The record's first line, or its first line with text when it
            # opens on a blank one: sink_text quotes whichever this is.
            "line": (line_text_at or {}).get(record["function_id"],
                                             record["line_start"]),
            "column": 1,
            # The line off disk, as §5 requires. Empty only when the record's
            # own line could not be read back, which is a fact and not a guess.
            "sink_text": (line_text or {}).get(record["function_id"], ""),
            "why_flagged": rule["why_flagged"],
            "disposition": "emitted",
            "skip_reason": None,
            "skip_class": None,
            # Derived, so neither of §5's two patterns produced it. The field is
            # present and null rather than absent: "no pattern ran" and "nobody
            # recorded which pattern ran" are different facts.
            "match_target": None,
            "pattern_source": "as-written",
            "language": record["language"],
            "function_id": record["function_id"],
            "function_key": record["function_key"],
            "join": "line-in-range",
            "derived": True,
        })
    return produced


_LOOSE = {}

# The blindness pass runs a pattern with its word-boundary anchors removed, and
# that is the one transform that can turn a linear pattern into a quadratic one:
# `\b\w*(secret|token|...)\w*\b` is bounded by its anchors, and the same
# pattern without them backtracks over every prefix of every run of word
# characters. On one 300 KB single-line file - a minified bundle, a generated
# table, a base64 blob - two of the 50 shipped rules did not finish, and stage 1
# hung with no output and no timeout. The anchored patterns are written with
# bounded gaps so they stay linear on any line, and rules_lib --selftest times
# every one, anchored and loosened, against planted lines; this cap bounds the
# loosened re-check as well. What it could not examine is COUNTED and reported
# rather than dropped, because a bound nobody can see is the silent truncation
# this skill exists to stop.
LOOSE_SCAN_MAX_LINE = 2000
LOOSE_SCAN_MAX_TEXT = 200_000


def loose_init(payload):
    _LOOSE["root"] = payload["root"]
    _LOOSE["rx"] = {rid: (re.compile(pat, re.S if multiline else 0), bool(multiline))
                    for rid, (pat, multiline, _langs) in payload["patterns"].items()}
    _LOOSE["languages"] = {rid: set(langs)
                           for rid, (_p, _m, langs) in payload["patterns"].items()}


def loose_scan_file(job):
    """(first hit per loosened rule, units too long to examine) for one file.

    Line by line for a line rule and over the whole text for a multiline one,
    which is exactly what `verify_findings.scan_tree` does when stage 4
    re-derives `zero_hit_cause`. Searching the whole text for a line rule - what
    this did - reports `pattern-unmatchable` for a rule whose loosened form only
    matches across a newline, and stage 4's line-by-line recount then finds
    nothing and fails a correct run.
    """
    rel = job[0]
    out, skipped = {}, 0
    try:
        with open(os.path.join(_LOOSE["root"], rel), "rb") as fh:
            text = fh.read().decode("utf-8", "replace")
    except OSError:
        return {"found": out, "skipped_units": 0}
    lines = None
    language = rules_lib.language_of(rel)
    for rid, (rx, multiline) in _LOOSE["rx"].items():
        want = _LOOSE["languages"].get(rid)
        if want and language not in want:
            continue
        if multiline:
            if len(text) > LOOSE_SCAN_MAX_TEXT:
                skipped += 1
                continue
            m = rx.search(text)
            if m is not None:
                out[rid] = "%s:%d" % (rel, text.count("\n", 0, m.start()) + 1)
            continue
        if lines is None:
            lines = text.split("\n")
        for number, line in enumerate(lines, 1):
            if len(line) > LOOSE_SCAN_MAX_LINE:
                skipped += 1
                continue
            if rx.search(line) is not None:
                out[rid] = "%s:%d" % (rel, number)
                break
    return {"found": out, "skipped_units": skipped}


def loose_scan(root, files, zero_entries, jobs, name_targets, line_halves=None):
    """Which zero-hit rules the LOOSENED pattern still finds something for.

    A second read of the corpus, and the only one: it runs solely for rules that
    matched nothing, which is a handful on any tree, and it is what turns
    zero_hit_cause from a judgement call into a measurement. §5 requires the
    cause and stage 4 recomputes it, so guessing here is a run that fails there.

    A `function_or_path` rule is loosened over the FUNCTION TARGETS it actually
    ran against, not over source lines. Loosening LOG-003 over lines asks whether
    the word `key` appears anywhere in the tree, which it does in every tree, and
    the answer would have been `pattern-unmatchable` for every logic rule in
    every run - a blindness report that is never wrong and never says anything.
    The anchored run already reads `_` and camelCase humps as boundaries, and
    a name rule is loosened by dropping only its leading anchors, so it is
    blind here only when its keyword closes a lowercase segment (`reauth`,
    `hotkey`) - the family is in the tree, spelled in a way the rule does not
    select.

    A name rule's sink half (`line_halves`, CompiledRules.line_halves) is a
    line pattern, and it is loosened over source lines the same way: leading
    anchors only. Stage 4's I4 asks it of every zero-hit name rule, and this
    pass used to ask only the name half, so the two disagreed whenever the sink
    half's loosened form met a line: LOG-008's `sig ==` inside `cursig ==`, or
    LOG-006's `\\bunserialize` inside `php_unserialize(`, recorded
    `absent-from-tree` here and refused there, with no cause stage 1 could
    write to pass.

    Returns `(first hit per rule, units the caps above left unexamined)`. The
    second number is reported; it is not allowed to vanish.
    """
    patterns, name_patterns = {}, {}
    for entry in zero_entries:
        # A name rule drops only the anchors its fragments open with
        # (rules_lib.loosen_name): its narrowed tails - `sign(?:|s|ed)`, not
        # `signal` - must stay narrowed, or a tree with a signal handler reads
        # as LOG-004 gone blind. Stage 4 loosens it the same way.
        name_rule = entry["target"] == "function_or_path"
        half = (line_halves or {}).get(entry["rule"]["rule_id"]) if name_rule else None
        if half is not None:
            # Its sink half, too, keeps its trailing anchors: LOG-004's
            # `X509_verify(?:|_cert)\b` leaves out X509_verify_cert_error_string,
            # and with every anchor dropped a tree whose only such line was that
            # lookup read as LOG-004 gone blind. Line by line, under the caps
            # and over the rule's own languages, as stage 4's scan_tree runs it.
            sink_loose = rules_lib.loosen_name(half["pattern"])
            if sink_loose != half["pattern"]:
                try:
                    re.compile(sink_loose)
                except re.error:
                    pass
                else:
                    patterns[entry["rule"]["rule_id"]] = (
                        sink_loose, bool(entry["rule"]["multiline"]),
                        tuple(entry["rule"].get("languages") or ()))
        loose = (rules_lib.loosen_name(entry["pattern"]) if name_rule
                 else loosen(entry["pattern"]))
        if loose == entry["pattern"]:
            continue                                   # nothing to loosen: absent
        multiline = bool(entry["rule"]["multiline"])
        try:
            rx = re.compile(loose, re.S if multiline else 0)
        except re.error:
            continue
        if entry["target"] == "function_or_path":
            # Through the one name matcher, as the anchored run was; with every
            # `\b` dropped the segment rewrite has nothing left to change.
            try:
                rx = rules_lib.compile_name_pattern(loose)
            except re.error:
                continue
            name_patterns[entry["rule"]["rule_id"]] = (
                rx, set(entry["rule"].get("languages") or ()))
        else:
            # The rule's OWN languages ride with the pattern. A rule runs
            # only over the languages it declares, so its loosened form
            # matching in a file it would never open is not evidence that the
            # rule is blind - and `zero_hit_cause` is what that evidence
            # decides. Stage 4 re-derives the same cause with the same filter;
            # without it here the two disagree and the gate fails a correct run.
            patterns[entry["rule"]["rule_id"]] = (
                loose, multiline, tuple(entry["rule"].get("languages") or ()))
    found, skipped = {}, 0
    for rid, (rx, want) in name_patterns.items():
        for target in name_targets:
            # Same filter as the line path, for the same reason: a C rule whose
            # loosened NAME pattern matches a Python function has not shown that
            # the C rule is blind. LOG-004 was recorded `pattern-unmatchable`
            # on that evidence and stage 4, which does filter, then reported the
            # cause should have been `absent-from-tree` - the two stages
            # disagreeing about one rule because only one of them asked the
            # question the rule's own languages define.
            if want and rules_lib.language_of(target.split("::")[0]) not in want:
                continue
            if rx.search(target):
                found[rid] = target
                break
    if not patterns:
        return found, skipped
    for chunk in _pool_map(loose_scan_file, files, jobs, loose_init,
                           {"root": root, "patterns": patterns}):
        skipped += chunk["skipped_units"]
        for rid, where in chunk["found"].items():
            found.setdefault(rid, where)
    return found, skipped


# What the wrapper-blindness pass keeps of a site it found: an identifier, not a
# source line. An example is written into coverage.json, which is copied beside
# the records and tarred up for references/field-test.md, and a line this pass cites can be
# the line that holds a credential. The identifier is also all the reader needs -
# `tfm_crypto_operation_release` is the diagnosis - and it is what they look up.
# It is still passed through the gate's scrub (_scrub_identifier), because the
# run of identifier characters around a match can hold text glued to the name.
WRAPPER_BLIND_EXAMPLES = 3
WRAPPER_BLIND_IDENT_MAX = 80
_WB = {}
_WB_SCRUB = {}


def wb_init(payload):
    _WB["root"] = payload["root"]
    _WB["rx"] = {rid: (re.compile(tight), re.compile(loose), set(langs))
                 for rid, (tight, loose, langs) in payload["patterns"].items()}


def _scrub_identifier(ident):
    """`ident` as it may be written into coverage.json, or None when it cannot be
    scrubbed.

    The identifier is an alnum/underscore run extended left from the match, so
    whatever is glued to the call name rides along: `"AKIA...EXAMPLEfree(x)` gives
    `AKIA...EXAMPLEfree`. It goes through the scrub the gate puts on every line it
    quotes (verify_findings.scrubbed_text): sweep_secrets.export_spans' spans
    redacted, then sweep_secrets.scrub. Imported here, lazily and once, because
    sweep_secrets imports this file at its top. A run too plain for either
    detector (a bare word glued to the name) is not a thing they can see; the
    80-character cap bounds how much of it there is.
    """
    if "sweep_secrets" not in _WB_SCRUB:
        try:
            import sweep_secrets                       # noqa: PLC0415
            _WB_SCRUB["sweep_secrets"] = sweep_secrets
        except Exception:                              # noqa: BLE001
            _WB_SCRUB["sweep_secrets"] = None
    module = _WB_SCRUB["sweep_secrets"]
    if module is None:
        return None
    merged = []
    for start, end, _kind in sorted(module.export_spans(ident)):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        ident = module.redact_span(ident, start, end)
    return module.scrub(ident)[:WRAPPER_BLIND_IDENT_MAX]


def _blind_sites(tx, lx, line):
    """The identifier holding each match of `lx` that no match of `tx` overlaps."""
    spans = [m.span() for m in tx.finditer(line)]
    out = []
    for m in lx.finditer(line):
        if any(a < m.end() and m.start() < b for a, b in spans):
            continue
        left = right = m.start()
        while left > 0 and (line[left - 1].isalnum() or line[left - 1] == "_"):
            left -= 1
        while right < len(line) and (line[right].isalnum() or line[right] == "_"):
            right += 1
        ident = (line[left:right] or line[m.start():m.end()].strip())[:WRAPPER_BLIND_IDENT_MAX]
        if ident:
            out.append(ident)
    return out


def wb_scan_file(job):
    """One file's share of the wrapper-blindness counts.

    `{"file", "found": {rule: (anchored matches, unanchored matches, sites)},
    "skipped_units"}`, `sites` being `{identifier: [count, first line]}` for the
    matches the anchored form missed: exactly the counts `verify_findings.verify_coverage`
    takes for its wrapper test. Line by line (never the whole text, whatever the
    rule's `multiline`), the rule's own languages only, and a line longer than
    LOOSE_SCAN_MAX_LINE passed over under BOTH patterns, as scan_tree(loose=True)
    does. Lines are split on "\\n" alone and a trailing empty element dropped, as
    its source_lines() does. The unanchored form contains every anchored match,
    so a line it does not match is a line the anchored form does not either, and
    only the lines it matches pay for the second findall.
    """
    rel = job[0]
    out, skipped = {}, 0
    try:
        with open(os.path.join(_WB["root"], rel), "rb") as fh:
            raw = fh.read()
    except OSError:
        return {"file": rel, "found": out, "skipped_units": 0}
    if b"\0" in raw[:8192]:
        # Not text, as the gate reads a file.
        return {"file": rel, "found": out, "skipped_units": 0}
    text = raw.decode("utf-8", "replace")
    language = rules_lib.language_of(rel)
    lines = None
    for rid, (tx, lx, want) in _WB["rx"].items():
        if want and language not in want:
            continue
        if lines is None:
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
        found = loose = 0
        sites = {}
        for number, line in enumerate(lines, 1):
            if len(line) > LOOSE_SCAN_MAX_LINE:
                skipped += 1
                continue
            wide = len(lx.findall(line))
            if not wide:
                continue
            narrow = len(tx.findall(line))
            found += narrow
            loose += wide
            if wide > narrow:
                for ident in _blind_sites(tx, lx, line):
                    seen = sites.setdefault(ident, [0, number])
                    seen[0] += 1
        if loose:
            out[rid] = (found, loose, sites)
    return {"file": rel, "found": out, "skipped_units": skipped}


def wrapper_blind_scan(root, files, compiled, jobs):
    """`({rule_id: {"blind", "extra", "examples"}}, units the line cap passed over)`.

    The gate's partial-blindness test (rules_lib.wrapper_blind_forms and
    is_wrapper_blind), asked of EVERY rule with a call-shaped branch rather than
    only the rules that matched nothing. `zero_hit_cause` is the one blindness
    signal stage 1 used to emit and it speaks only for hits == 0; MEM-008 matched
    74 sites and was blind to 171 more, and nothing said so until stage 4 refused
    the run. One pass over the files for all the rules at once.

    A rule the test does not apply to has no row (build_coverage writes False /
    0 / [] for it); `examples` is empty unless the rule is blind. A name-matched rule is asked of its `line_pattern`, the half
    that runs over lines, as the gate asks it.
    """
    patterns = {}
    for entry in compiled.rules:
        if entry["rule"].get("derived"):
            continue
        rid = entry["rule"]["rule_id"]
        if entry["target"] == "function_or_path":
            half = compiled.line_halves.get(rid)
            scan_pattern = half["pattern"] if half else None
        else:
            scan_pattern = entry["pattern"]
        if not scan_pattern:
            continue
        tight, loose = rules_lib.wrapper_blind_forms(scan_pattern)
        if not tight:
            continue
        try:
            re.compile(tight)
            re.compile(loose)
        except re.error:
            continue
        patterns[rid] = (tight, loose, tuple(entry["rule"].get("languages") or ()))
    if not patterns:
        return {}, 0
    totals = {rid: [0, 0, {}] for rid in patterns}
    skipped = 0
    # `files` is in walk order and pool.map keeps it, so "first" below is the
    # first site in that order and the result does not depend on --jobs.
    for chunk in _pool_map(wb_scan_file, files, jobs, wb_init,
                           {"root": root, "patterns": patterns}):
        skipped += chunk["skipped_units"]
        for rid, (found, loose, sites) in chunk["found"].items():
            row = totals[rid]
            row[0] += found
            row[1] += loose
            for ident, (count, number) in sites.items():
                seen = row[2].setdefault(ident, [0, "%s:%d" % (chunk["file"], number)])
                seen[0] += count
    # Examples only for a rule that IS blind: they are what the agent reads the
    # definitions of, and on a rule that is not they are noise in the file. One
    # per distinct identifier, the most frequent first: three sites of the same
    # wrapper would name one wrapper and leave the rest to a search, while the
    # agent's search is the part that is capped.
    def examples(sites):
        ranked = sorted(sites.items(), key=lambda kv: -kv[1][0])   # stable: first seen wins a tie
        out = []
        for ident, (_count, where) in ranked[:WRAPPER_BLIND_EXAMPLES]:
            clean = _scrub_identifier(ident)
            out.append("%s: %s" % (where, clean if clean is not None
                                   else "<withheld: sweep_secrets.py is not importable>"))
        return out
    return ({rid: {"blind": blind, "extra": loose - found,
                   "examples": examples(sites) if blind else []}
             for rid, (found, loose, sites) in totals.items()
             for blind in (rules_lib.is_wrapper_blind(found, loose),)},
            skipped)


def blind_reasons(coverage_rows):
    """`rule (evidence): why` for each pattern-unmatchable rule in a language
    this tree holds, read off what its loosened pattern met.

    A name rule has two ways to be blind, and the summary once gave it only
    the first. Its keyword can close a lowercase segment of a NAME (`reauth`),
    which the name matcher cannot see because it reads `_` and humps as
    boundaries. Or its sink half's keyword can sit behind a prefix or inside a
    longer identifier on a LINE, where `_` is part of the word: a tree whose
    only deserialiser call was `php_unserialize(buf)` recorded LOG-006 with
    evidence src/net.c:5, and the summary said the keyword closed a lowercase
    segment of a name no function had."""
    out = []
    for row in coverage_rows:
        if row.get("zero_hit_cause") != "pattern-unmatchable" or not row.get(
                "languages_present"):
            continue
        evidence = row.get("zero_hit_evidence") or "?"
        if row.get("match_target") != "function_or_path":
            why = "a wrapper is unresolved or the rule does not fit here"
        elif "::" in evidence:
            why = "its keyword only closes a lowercase segment of a name"
        else:
            why = ("its line_pattern's keyword only follows a prefix or sits inside a "
                   "longer identifier on a line")
        out.append("%s (%s): %s" % (row["rule_id"], evidence, why))
    return out


def _iso(stamp):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(stamp))


def _run_id(stamp):
    return time.strftime("%Y-%m-%dT%H-%M-%SZ", time.gmtime(stamp))


GITIGNORE = """\
# Written by the security-review pipeline. Run artifacts are not committed; the ledger is.
*
!.gitignore
!ledger/
!ledger/**
"""
# What an ignore-everything file needs appended so the ledger is not lost, and
# the lines that already say so. git keeps the ledger only when, after the LAST
# `*` or `**` line, one line re-includes the directory (`!ledger/`, `!ledger`)
# AND one re-includes what is in it (`!ledger/**`): the directory alone leaves
# every file in it matched by `*`, the contents alone cannot come back out of
# an excluded directory, `!ledger/*` misses ledger/training/, and a `*` after
# the lot ignores it all again - each one checked with `git check-ignore`.
# Any single one of these lines used to pass, and `*`, `!.gitignore`,
# `!ledger/` was left alone while git ignored every decision in it. snapshot.py
# and ledger.py keep their own copies of this test; move together.
GITIGNORE_CARVE_OUT = "!.gitignore\n!ledger/\n!ledger/**\n"
GITIGNORE_EVERYTHING = ("*", "**")
GITIGNORE_LEDGER_DIR = ("!ledger/", "!ledger")
GITIGNORE_LEDGER_CONTENTS = ("!ledger/**",)
GITIGNORE_MAX_BYTES = 1 << 20


def ledger_carved_out(lines):
    """True when a .gitignore's `lines` (each stripped) leave the ledger to be
    committed: no line ignores everything, or the last one that does is
    followed by both halves of the carve-out."""
    last = max((i for i, line in enumerate(lines) if line in GITIGNORE_EVERYTHING),
               default=None)
    if last is None:
        return True
    after = lines[last + 1:]
    return (any(line in GITIGNORE_LEDGER_DIR for line in after)
            and any(line in GITIGNORE_LEDGER_CONTENTS for line in after))


def ensure_gitignore(path):
    """Write the run directory's .gitignore, or mend the one that is there.

    Written when absent - tested with lexists, so a dangling link counts as
    present and is refused by the caller rather than written through. When a
    file is there and ignores everything (a `*` or `**` line) without carving
    out the ledger, the carve-out is APPENDED: stage 0 writes a bare `*` as its
    first act, the check here used to be "exists, so leave it", and so every
    run that began at stage 0 ignored the one directory contract §1 says is
    committed - `ledger.py check` failed, and every recorded decision was lost
    on the next clone. Anything else in the file is the operator's, and stays:
    a partial carve-out is mended by appending the whole one after it, which
    may repeat a line of theirs, and never by rewriting or reordering it.
    """
    if not os.path.lexists(path):
        _write(path, GITIGNORE)
        return
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as fh:
            text = fh.read(GITIGNORE_MAX_BYTES + 1)
    except OSError:
        return                                         # not a file we can mend
    if len(text) > GITIGNORE_MAX_BYTES:
        return
    if ledger_carved_out([line.strip() for line in text.splitlines()]):
        return
    sep = "\n" if text and not text.endswith("\n") else ""
    _write(path, text + sep + GITIGNORE_CARVE_OUT, errors="surrogateescape")


def write_outputs(state, args):
    out_dir = state["out_dir"]
    root = state["root"]
    extract_dir = os.path.join(out_dir, "extract")
    # Checked again at the moment of writing, not only by check_out_dir: the
    # run directory is in the scanned tree, and nothing about it is ours until
    # it has been looked at. Each write below goes through put(), which looks.
    _refuse_linked(root, extract_dir)
    os.makedirs(extract_dir, exist_ok=True)
    _refuse_linked(root, extract_dir)

    def put(path, text):
        _refuse_linked(root, path)
        _write(path, text)

    def put_jsonl(path, records):
        _refuse_linked(root, path)
        _write_jsonl(path, records)

    gitignore = os.path.join(out_dir, ".gitignore")
    _refuse_linked(root, gitignore)
    ensure_gitignore(gitignore)

    started = state["started"]
    tools = {TOOL: TOOL_VERSION}
    block = state.get("snapshot")
    if block:
        tools[snapshot.TOOL] = block.get("tool_version")
    run = {
        "schema_version": SCHEMA_VERSION,
        "run_id": _run_id(started),
        "started_at": _iso(started),
        # The ORIGINAL tree, never the snapshot. Every `file` in the corpus is
        # relative to this, which is what makes a report's file:line resolve for
        # somebody who opens the repository months later.
        "repo_root": state["root"],
        "git": git_state(state["root"]),
        "bundle_version": BUNDLE_VERSION,
        "tools": tools,
        # Contract §3. Three facts a run used to leave unstated, each of which
        # decides whether the run can be reproduced or only re-executed.
        #
        # rules_hash   coverage.json records each rule's resolved pattern, which
        #              looks like provenance and is not: it carries nothing about
        #              skip clauses, weights, or a rule that fired zero times. Two
        #              runs with the same rules_hash read byte-identical rules.
        # snapshot     which frozen bytes produced this corpus, or null for a run
        #              against the live tree - which is a weaker claim, and says so
        #              by being null rather than by being absent.
        # environment  a corpus whose boundaries are `heuristic` because
        #              tree-sitter was not importable on that machine is a
        #              different artifact from one where it was, and §6 branches
        #              on the difference.
        "rules_hash": rules_lib.rules_hash(state["rules_dir"]),
        "snapshot": block,
        "environment": state["environment"],
        # What git said the scanned repository commits under the run directory
        # (rules_lib.run_dir_gate): "git" when it was asked and listed nothing
        # but .gitignore and ledger/, "no-git" or "untracked-tree" when it could
        # not be asked - an unverified run directory, which run_status reports.
        "run_dir": getattr(args, "run_dir_check", None),
        "stages_completed": ["extract"],
    }
    # run.json is written LAST, at the bottom of this function. §3: a stage
    # appends its name to `stages_completed` when it FINISHES cleanly, and a
    # stage whose predecessor is absent from that list must refuse to run. Write
    # it first and a full disk halfway through functions.jsonl leaves a run
    # directory that tells stage 2 the corpus is complete.

    languages = {lang: stats["files"]
                 for lang, stats in sorted(state["by_language"].items())}
    manifest = dict(state["manifest"])               # never drop a key the agent set
    manifest.update({
        "schema_version": SCHEMA_VERSION,
        "run_id": run["run_id"],
        "scanned_roots": state["scanned_roots"],
        "languages": languages,
        "unsupported_languages": state["unsupported"],
        "exclusions": _exclusions(state),
        # The --include paths this run honoured, normalised. `exclusions` still
        # lists `vendor` after `--include lib/vendor` - the pattern is waived
        # only under lib/vendor, and still excludes every other vendor/ - so a
        # later stage that prunes by `exclusions` alone walked straight past
        # the code this run scanned. Written each run, never read back: an
        # include is a flag, and a re-run without it excludes lib/vendor again.
        "included_paths": state["includes"],
        # And an exclusion the include matched exactly - `--include src/gen`
        # against a scope's `src/gen` - which this run did not apply, so it is
        # not in `exclusions` (the Not scanned table would list a directory
        # this run scanned), but kept here as the manifest had it, reason and
        # risk_if_skipped, for the next run to apply again. Written on every
        # run, empty included, so a stale list does not outlive its include.
        "waived_exclusions": _waived(state),
        # The size above which this run skipped a file (too_large_files, a
        # list the report truncates). The candidate gate's recount reads the
        # tree again and has to skip the same files, or one amalgamation with
        # a rule hit in it fails a correct run. Written each run, like the
        # include, and never read back.
        "max_file_bytes": args.max_file_bytes,
        "test_tree_globs": state["test_globs"],
        "extracted_by": {"tool": TOOL, "version": TOOL_VERSION},
    })
    manifest.setdefault("entry_points", [])
    manifest.setdefault("wrapper_resolution",
                        {k: [] for k in rules_lib.WRAPPER_CLASSES})
    manifest.setdefault("physical_attacker", None)
    manifest.setdefault("threat_model", None)
    put(os.path.join(out_dir, "manifest.json"), json.dumps(manifest, indent=1) + "\n")

    put_jsonl(os.path.join(extract_dir, "functions.jsonl"), state["functions"])
    put_jsonl(os.path.join(extract_dir, "rules.jsonl"), state["hits"])
    put(os.path.join(extract_dir, "coverage.json"),
        json.dumps(state["coverage"], indent=1) + "\n")
    report = dict(state["report"], run_id=run["run_id"])
    put(os.path.join(extract_dir, "extract-report.json"),
        json.dumps(report, indent=1) + "\n")
    put(os.path.join(out_dir, "run.json"), json.dumps(run, indent=1) + "\n")
    return report


def _exclusions(state):
    """Every exclusion this run applied, as manifest.json records it.

    Each one says why, and the why has to be true: the report's coverage
    section is built from it. A manifest entry keeps its own reason, and its
    `risk_if_skipped` when it has one - an approved stage-0 scope arrives that
    way, and the Not scanned table is its whole point. A path given only as
    `--exclude` says so; it used to be filed under the defaults' reason, which
    told the report that `src/util` was build output or third-party code.
    """
    out, seen = [], set()
    supplied = _supplied(state)
    narrowed = set(state.get("snapshot_excludes") or ())
    cli = set(state.get("cli_excludes") or ()) - set(DEFAULT_EXCLUDES)
    for path in state["excludes"]:
        if path in seen:
            continue
        seen.add(path)
        entry = supplied.get(path)
        if entry is not None:
            reason = entry.get("reason")
        elif path in narrowed:
            reason = ("not in the snapshot: snapshot.py was run with --exclude "
                      "%s, so these files were never available to this run" % path)
        elif path in cli:
            reason = "--exclude on the command line"
        else:
            reason = "default exclusion: build output or third-party code"
        row = {"path": path, "reason": reason}
        if entry is not None and entry.get("risk_if_skipped") is not None:
            row["risk_if_skipped"] = entry["risk_if_skipped"]
        out.append(row)
    return out


def _manifest_entries(state):
    """The manifest's exclusion entries, a waived one first so that the same
    path in `exclusions` - which the agent may have rewritten since - wins."""
    manifest = state["manifest"]
    return [e for key in ("waived_exclusions", "exclusions")
            for e in (manifest.get(key) or [])]


def _supplied(state):
    """{path: entry} for every manifest exclusion given as an object, waived or
    not: an exclusion restored after an include has to come back with its own
    reason and risk_if_skipped, not with the defaults' reason and no risk."""
    return {e["path"]: e for e in _manifest_entries(state)
            if isinstance(e, dict) and e.get("path")}


def _waived(state):
    """The manifest exclusions this run's --include waived, as the manifest gave
    them - an object copied, a bare pattern as its string - once each. A
    pattern only this run's own --exclude supplied has nothing to keep."""
    supplied = _supplied(state)
    bare = {e for e in _manifest_entries(state) if isinstance(e, str)}
    out, seen = [], set()
    for path in state.get("waived_excludes") or ():
        if path in seen:
            continue
        seen.add(path)
        if path in supplied:
            out.append(dict(supplied[path]))
        elif path in bare:
            out.append(path)
    return out


def _current_umask():
    """The process umask. Reading it means setting it, so it is put straight
    back; the writes below run in the main process after the pool is done."""
    mask = os.umask(0o022)
    os.umask(mask)
    return mask


def _atomic_write(path, emit, errors="strict"):
    """Write `path` whole or not at all, and never through a link.

    The temporary file is made by mkstemp, which creates it with O_EXCL and so
    never follows a link. It used to be `path + ".tmp"`, a name the scanned tree
    can plant a symlink at - and open() followed it, overwriting whatever the
    link pointed to, anywhere the operator could write. os.replace then swaps a
    link that sits AT `path` for the new file; it does not write through it.
    """
    directory = os.path.dirname(path) or os.curdir
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp",
                               prefix="." + os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors=errors) as fh:
            emit(fh)
        # mkstemp makes 0600, and other stages read these: give the file the
        # mode open() would have, which is what it had before - 0644 under the
        # usual umask, and still 0600 for an operator whose umask asks for it.
        os.chmod(tmp, 0o666 & ~_current_umask())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _write(path, text, errors="strict"):
    _atomic_write(path, lambda fh: fh.write(text), errors)


def _write_jsonl(path, records):
    def emit(fh):
        for record in records:
            fh.write(rules_lib.json_dumps(record) + "\n")
    _atomic_write(path, emit)


def contained_reader(root, max_bytes=MAX_FILE_BYTES):
    """`materialise`'s line reader, confined to the scanned root.

    The paths it is handed come off disk, out of a corpus another stage - or
    another agent - may have written, and they are the only paths this tool ever
    opens that it did not walk itself. A part whose file resolves outside the
    root, or that is larger than the walk would have admitted, is not read. The
    window then fails its own hash and `--emit-context` exits 3, which is the
    honest outcome: the corpus and the tree have diverged.
    """
    base = os.path.realpath(root)
    cache = {}

    def read_lines(rel):
        if rel in cache:
            return cache[rel]
        cache[rel] = None
        try:
            path = os.path.realpath(os.path.join(root, rel))
            if path != base and not path.startswith(base + os.sep):
                return None
            if os.path.getsize(path) > max_bytes:
                return None
            with open(path, "rb") as fh:
                cache[rel] = fh.read().decode("utf-8", "replace").split("\n")
        except OSError:
            cache[rel] = None
        return cache[rel]
    return read_lines


def context_read_root(root, out_dir, override=None):
    """Where `--emit-context` re-materialises from: the snapshot, if there was one.

    The corpus says which tree it was taken from, so the caller does not have to
    remember. A run that used a snapshot re-materialises from the snapshot and
    the window's `text_sha256` still verifies weeks later; the same run against
    the live tree exits 3 the moment somebody saves the file - which was the
    honest outcome when there was no alternative, and is now avoidable.

    A snapshot that has since been deleted falls back to the live tree rather
    than refusing. The window then either verifies or it does not, and exit 3
    already says exactly that.
    """
    if override:
        return override
    run = os.path.join(out_dir, "run.json")
    try:
        with open(run, encoding="utf-8") as fh:
            block = (json.load(fh) or {}).get("snapshot") or {}
    except (OSError, ValueError, AttributeError):
        return root
    frozen = block.get("root")
    # Only the one snapshot this run directory can own. run.json names it, and
    # a run.json the tool did not write - or that points anywhere else - would
    # make --emit-context print files from wherever it said.
    own = os.path.join(out_dir, snapshot.SNAPSHOT_DIR_NAME)
    if (isinstance(frozen, str) and os.path.isdir(frozen) and not os.path.islink(own)
            and os.path.realpath(frozen) == os.path.realpath(own)):
        return frozen
    return root


def emit_context(root, out_dir, function_id):
    """Print the exact text `context.text_sha256` was taken over."""
    path = os.path.join(out_dir, "extract", "functions.jsonl")
    if not os.path.isfile(path):
        fail(path, None, "no corpus here; run the extractor before --emit-context")
    record = None
    with open(path, encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            try:
                candidate = json.loads(line)
            except ValueError as exc:
                fail(path, number, "not valid JSON: %s" % exc)
            if candidate.get("function_id") == function_id:
                record = candidate
                break
    if record is None:
        return None, "%s: no function_id %s in the corpus" % (path, function_id)
    read_lines = contained_reader(root)

    text = materialise(record.get("context", {}).get("parts", []), read_lines)
    digest = text_digest(text)
    recorded = record.get("context", {}).get("text_sha256")
    return (text, None) if digest == recorded else (
        text, "%s: text_sha256 is %s, the tree now materialises %s"
              % (function_id, recorded, digest))


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

FIXTURE_C = r'''#include <string.h>
#include <stdio.h>

struct rec { char payload[256]; };

/* A comment with an unbalanced brace: { and here is another {
 * If the walker counted these, every boundary below would be wrong.
 */
static int parse_tlv_record(struct rec *rec, const unsigned char *cur, int len)
{
    const char *fmt = "}{ a brace in a string literal }";
    if (len > 0) {
        memcpy(rec->payload, cur, len);
    }
    printf("%s", fmt);
    return 0;
}

#define WRAP_BRACE(x) do { if (x) { } } while (0)

static int helper(int a)
{
    char dst[8];
    memcpy(dst, &a, sizeof(dst));
    return a;
}

static int parse_tlv_record(struct rec *rec, int n)
{
    /* Same name, same file: the ordinal is what tells them apart. */
    return n;
}

int main(int argc, char **argv)
{
    struct rec r;
    (void)argv;
    return parse_tlv_record(&r, argc);
}
'''

FIXTURE_PY = '''"""A docstring holding a def that is not a function:

def not_a_function(x):
    return x
"""


def outer(value):
    # A brace in a comment: {
    text = "} not code {"

    def inner(x):
        return x + 1

    return inner(value) + len(text)


class Parser:
    def parse(self, blob):
        return blob[1:]

    def check(self, blob):
        return len(blob) > 0
'''

FIXTURE_GO = '''package main

import "fmt"

type Rec struct {
\tPayload []byte
}

func (r *Rec) Parse(b []byte) error {
\tmsg := `a raw string with } and {`
\tfmt.Println(msg)
\tcopy(r.Payload, b)
\treturn nil
}

func main() {
\tr := &Rec{}
\t_ = r.Parse([]byte("x"))
}
'''

FIXTURE_GO_PREAMBLE = '''package svc

import (
	"crypto/md5"
	"os/exec"
)

func Digest(d []byte) [16]byte {
	return md5.Sum(d)
}
'''

FIXTURE_RS = '''use std::ptr;

pub struct Rec {
    pub payload: Vec<u8>,
}

impl Rec {
    pub fn parse(&mut self, src: &[u8]) -> usize {
        let s = "a brace } in a string {";
        // a brace { in a comment
        unsafe {
            ptr::copy(src.as_ptr(), self.payload.as_mut_ptr(), src.len());
        }
        s.len()
    }
}

fn main() {
    let mut r = Rec { payload: vec![0; 8] };
    r.parse(b"x");
}
'''

# A `#ifdef` spliced into an if/else chain - the single most common thing that
# defeats a C grammar in portable code, and the shape that cost curl twelve
# functions with no error, no note and no tier change. Reduced from curl's
# lib/socks.c, where it hid `do_SOCKS5` and therefore CVE-2023-38545. The
# grammar parses `sender` but runs its END past `target`, so `target` vanishes
# from a corpus whose §4 claim is ONE RECORD PER FUNCTION IN THE REPOSITORY.
FIXTURE_C_PREPROCESSOR = """\
static int lead(int n)
{
  return n + 1;
}

static int sender(struct ctx *cx, const char *host)
{
  int result = 0;
  if(cx->head) {
    if(cx->want)
      result = push(cx, host, -1);
#ifdef HAVE_TRAILER
    else if(cx->trailer)
      result = push_trailer(cx, host);
#endif
    else
      setup_stream(cx, FIRSTSOCKET, -1, TRUE, -1);
  }

  return result;
}

static int target(struct ctx *cx, const char *host, char *out)
{
  memcpy(out, host, strlen(host));
  return 0;
}
"""


# K&R parameter declarations, with an export macro between the return type and
# the name - zlib's deflate.c, which is what the golden set's oldest case is
# about. Both halves matter: the macro is what makes the grammar emit an ERROR
# node, and the K&R parameter list is what a parameter-shape filter mistakes for
# a call. Without the macro this parses cleanly and tests nothing.
FIXTURE_C_KANDR = """\
int lead(int n)
{
  return n + 1;
}

int ZEXPORT deflateInit2_(strm, level, method, windowBits, memLevel, strategy)
    z_streamp strm;
    int  level;
    int  method;
    int  windowBits;
    int  memLevel;
    int  strategy;
{
    char overlay[16];
    memcpy(overlay, strm, level);
    return 0;
}

int tail(int n)
{
  return n - 1;
}
"""


# A regex literal is the JS construct the mask did not know, and every shape
# here broke the walk in its own way: `//` inside `/^https?:\/\//` read as a
# comment and blanked the `{` after it; `[{[]` and `[{(]` opened blocks that
# never closed; `/\/*$/` opened a block COMMENT that ran to the next `*/` in
# the file; a quote inside a regex blanked the rest of its line. The division
# and the JSX lines are the things the fix must not take for a regex - a slash
# in JSX text after `}` or a tag's `>` is text - and an arrow's `=>` is the one
# `>` that still opens one. crumb, help and nav are JSX text after `:`, `(` and
# `|`, which do expect an operand in code, so the span decides; key is the
# regex with a `(?<` group and a lone brace that must stay one; avg divides
# after a postfix `++`. Each of those five closed a line early.
FIXTURE_JS_MASKING = r'''function fetchIt(u) {
  if (!/^https?:\/\//.test(u)) {
    u = "http://" + u;
  }
  return child_process.exec("curl " + u);
}
function parseBody(body) {
  if (/^\s*[{[]/.test(body)) {
    return JSON.parse(body);
  }
  return eval("(" + body + ")");
}
function tokens(s) {
  return s.split(/[{(]/).map(t => t.replace(/\/*$/, ""));
}
function quoted(s) {
  if (/'/.test(s)) {
    return 1;
  }
  const x = s.length / 2 / 1;
  return x;
}
function view(p) {
  return <div><p>{p.a}</p><p>{p.b}</p></div>;
}
function pager(p) {
  return <span>{p.page}/{p.total} {p.open && <Icon/>}</span>;
}
function cell(p) {
  return <td>/{p.a} {p.b && <br/>}</td>;
}
function card(p) {
  return <div><Avatar src={p.img} /> {p.admin && <Badge/>}</div>;
}
function braces(xs) {
  return xs.filter(x => /\{/.test(x));
}
function after() {
  return 1;
}
function crumb(p) {
  return <li>Path: /{p.dir} {p.isNew && <Badge/>}</li>;
}
function help(p) {
  return <p>See (/{p.page}) or {p.alt && <Link/>}</p>;
}
function nav(p) {
  return <nav>Home | /{p.s} {p.sub && <Sub/>}</nav>;
}
function key(s) {
  return s.match(/^(?<key>\w+)\s*\{/) || s.split(/[<>{]/);
}
function avg(n) {
  let i = n++ / 2; if (i) { i = i / 3; }
  return i;
}
function tail2() {
  return 2;
}
'''

# Headers whose first `ident(` is not the name, and C++ shapes the brace walk
# cut short: an initialiser list that brace-initialises, an operator, a
# digit separator. The last three definitions are the ones that must NOT move.
FIXTURE_CPP_HEADERS = '''Buffer::Buffer(size_t n) : size_{n}, data_{new char[n]} {
    memset(data_, 0, n);
}

bool operator==(const Buf &a, const Buf &b) {
    return memcmp(a.p, b.p, a.n) == 0;
}

char &Buf::operator[](size_t i) {
    return p[i];
}

Foo::Foo() : Base(1), m_(2) {
    int k = 0;
}

int clamp(int v) {
    if (v > 10'000) {
        v = 10'000;
    }
    return v;
}

template <int N = sizeof(int)> struct Holder : Base {
    int get() { return N; }
};

int run(int c) {
    auto x = c ? make() : Thing{1, 2};
    for (auto v : items(c)) {
        use(v);
    }
    return 0;
}
'''

FIXTURE_C_HEADERS = '''static void __attribute__((noreturn)) die(const char *msg)
{
    fprintf(stderr, msg);
    exit(1);
}

__declspec(dllexport) int api_parse(const char *s)
{
    return 0;
}

int (*pick(int k))(int)
{
    return 0;
}
'''

# Iteration macros, which C code opens a block after exactly like a function
# header. Each one used to become a function nested in flush_all, and the
# memcpy - with the `cap` guard that makes it safe - belonged to the phantom.
# The conditions after them start with a dereference, `if (*dst && ...`, which
# the skip for `int (*pick(int))(int)` took for a declarator: is_valid, check,
# isspace and kind_of each became a phantom with the block's hits in it.
FIXTURE_C_LOOP_MACROS = '''#include <string.h>
static int flush_all(struct list_head *head, char *dst, size_t cap)
{
    size_t used = 0;
    if (cap < 64)
        return -1;
    list_for_each_entry(pos, head, node) {
        memcpy(dst + used, pos->data, pos->len);
    }
    TAILQ_FOREACH(e, h, link) {
        used++;
    }
    if (used) {
        used--;
    } else json_object_foreach(o, k, v) {
        used++;
    }
    if (*dst && is_valid(dst)) {
        memcpy(dst, head, cap);
    } else if (*dst || check(dst)) {
        used--;
    }
    while (*dst && isspace((unsigned char)*dst)) {
        dst++;
    }
    switch (*kind_of(dst)) {
    default:
        break;
    }
    return 0;
}
'''

# Each branch of the first conditional opens a brace of its own. The function
# vanished, parse_header was qualified `copy_in::parse_header`, and the memcpy
# went to an `exact` <module> record. The second conditional has no braces;
# the call only its #else makes must still reach the call-site index.
FIXTURE_C_IFDEF_BRACES = '''int copy_in(char *dst, const char *src, size_t n)
{
#ifdef HAVE_FAST_PATH
    if (n > 16 && fast_ok(src)) {
#elif defined(OTHER)
    if (n > 32) {
#else
    if (n > 16) {
#endif
        n = 16;
    }
#if WANT_LOG
    log_it(n);
#else
#  if VERBOSE
    shout(n);
#  endif
    whisper_only_here(n);
#endif
    memcpy(dst, src, n);
    return 0;
}

int parse_header(char *out, const char *buf)
{
    strcpy(out, buf);
    return 0;
}
'''

# Whole alternative definitions: each branch balanced for its own build. The
# all-branches mask gets this right, and the first-branch retry must not be
# used on it - that would lose the POSIX definition and its memcpy.
FIXTURE_C_IFDEF_ALTERNATIVES = '''#ifdef _WIN32
static int plat_read(SOCKET s, char *buf, int n)
{
    return recv(s, buf, n, 0);
}
#else
static int plat_read(int fd, char *buf, int n)
{
    memcpy(buf, "x", n);
    return (int)read(fd, buf, n);
}
#endif
'''

# A block that never closes, and a definition after it. Nothing can balance
# this one, so the definition is nested; it has a return type, so it is kept -
# and the function left open is counted rather than dropped in silence.
FIXTURE_C_UNCLOSED = '''static int over(int a)
{
    if (a) {
        a++;

static int target(char *out, const char *host)
{
    memcpy(out, host, strlen(host));
    return 0;
}
'''


SELFTEST_RULES = {
    "schema_version": 1,
    "category": "memory-safety",
    "validator": "sec-val-memory-safety",
    "rules": [
        {
            "rule_id": "MEM-002", "title": "memcpy with untrusted size",
            "cwe": "CWE-787", "languages": ["c", "cpp"],
            "pattern": r"\b(memcpy|memmove)\s*\(",
            "multiline": False, "match_target": "line",
            "why_flagged": "third argument is a variable, not sizeof(dest)",
            "flag_condition": "flag when the size argument is not sizeof(<dest>)",
            "skip_clause": "third argument is literally sizeof(<dest>)",
            "skip_pattern": r"\b(?:memcpy|memmove)\s*\(\s*([A-Za-z_]\w*)\s*,"
                            r"[^,()]*,\s*sizeof\s*\(\s*\1\s*\)",
            "wrapper_class": "copy", "threat_model": None, "derived": False,
            "high_signal": True, "weight": 3,
        },
        {
            "rule_id": "MEM-010", "title": "allocation",
            "cwe": "CWE-190", "languages": ["c", "cpp"],
            "pattern": r"\b(?:malloc|calloc)\s*\(",
            "multiline": False, "match_target": "line",
            "why_flagged": "allocation size may overflow",
            "flag_condition": "every hit is a candidate",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": "alloc", "threat_model": None, "derived": False,
            "high_signal": False, "weight": 2,
        },
        {
            "rule_id": "MEM-006", "title": "scanf family",
            "cwe": "CWE-120", "languages": ["c", "cpp"],
            "pattern": r"\b(scanf|fscanf|sscanf)\s*\(",
            "multiline": False, "match_target": "line",
            "why_flagged": "unbounded conversion",
            "flag_condition": "every hit is a candidate",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": False,
            "high_signal": False, "weight": 2,
        },
        {
            "rule_id": "MEM-011", "title": "rust unsafe",
            "cwe": "CWE-119", "languages": ["rust"],
            "pattern": r"\bunsafe\s*\{|ptr::(copy|write|read)",
            "multiline": False, "match_target": "line",
            "why_flagged": "unsafe block",
            "flag_condition": "every hit is a candidate",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": False,
            "high_signal": False, "weight": 2,
        },
        {
            "rule_id": "MEM-WFS", "title": "whole-function scan",
            "cwe": "CWE-119",
            # As shipped: the whole-function pass is a memory-safety pass, and
            # the fixture's Python and Go functions produce candidates too.
            "languages": ["c", "cpp", "rust"],
            "pattern": None, "multiline": False, "match_target": None,
            "why_flagged": "whole-function memory-safety pass, not a matched sink",
            "flag_condition": "the four questions a whole-function pass answers",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": True,
            "derivation": "one per distinct (file, function) pair across the "
                          "emitted candidate files",
            "high_signal": False, "weight": 2,
        },
    ],
}

# A synthetic LOG-010, not the shipped one: `parse\w*|validate\w*` is broad on
# purpose, so the fixtures below reach a name hit in every language and exercise
# the join, line_start, match_target and dedup machinery. It selects a bare
# `parse`, which the shipped rule does not, and passes however the shipped
# patterns change. Those are held by rules_lib.py's name and line-half probes,
# by the name_cases run over the shipped rules further down, and by the fixture.
SELFTEST_LOG_RULES = {
    "schema_version": 1,
    "category": "logic-flaws",
    "validator": "sec-val-logic-flaws",
    "rules": [{
        "rule_id": "LOG-010", "title": "input validation",
        "cwe": "CWE-20",
        "languages": ["c", "cpp", "rust", "go", "python"],
        "pattern": r"(?i:\b(parse\w*|validate\w*)\b)",
        "multiline": False, "match_target": "function_or_path",
        "why_flagged": "function name or path is in the parsing surface",
        "flag_condition": "selected by function, not by line",
        "skip_clause": None, "skip_pattern": None,
        "wrapper_class": None, "threat_model": None, "derived": False,
        "high_signal": False, "weight": 1,
    }],
}


BLINDNESS_RULES = {
    "schema_version": 1,
    "category": "memory-safety",
    "validator": "sec-val-memory-safety",
    "rules": [
        {
            "rule_id": "MEM-010", "title": "allocation",
            "cwe": "CWE-190", "languages": ["c", "cpp"],
            "pattern": r"\b(?:malloc|calloc)\s*\(",
            "multiline": False, "match_target": "line",
            "why_flagged": "allocation size may overflow",
            "flag_condition": "every hit is a candidate",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": "alloc", "threat_model": None, "derived": False,
            "high_signal": False, "weight": 2,
        },
        {
            # Loosened, this spans a newline. A multiline rule is scanned over
            # the whole text, so it must be found.
            "rule_id": "MEM-901", "title": "multiline",
            "cwe": "CWE-119", "languages": ["c", "cpp"],
            "pattern": r"\bAAA\s[\s\S]*?BBB",
            "multiline": True, "match_target": "line",
            "why_flagged": "spans lines",
            "flag_condition": "every hit is a candidate",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": False,
            "high_signal": False, "weight": 1,
        },
        {
            # The same shape declared as a LINE rule. Stage 4 recounts a line
            # rule line by line, so this one must NOT be found across a newline
            # - or stage 1 and stage 4 disagree about whether the rule is blind.
            "rule_id": "MEM-902", "title": "line only",
            "cwe": "CWE-119", "languages": ["c", "cpp"],
            "pattern": r"\bCCC\s[\s\S]*?DDD",
            "multiline": False, "match_target": "line",
            "why_flagged": "does not span lines",
            "flag_condition": "every hit is a candidate",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": False,
            "high_signal": False, "weight": 1,
        },
        {
            # Anchored it is linear; loosened it backtracks over every prefix of
            # every run of word characters, which is what hung stage 1 on a
            # minified file.
            "rule_id": "MEM-903", "title": "quadratic when loosened",
            "cwe": "CWE-798", "languages": ["javascript", "c", "cpp"],
            "pattern": r"(?i:\b\w*(secret|token)\w*\b)",
            "multiline": False, "match_target": "line",
            "why_flagged": "a secret-shaped identifier",
            "flag_condition": "every hit is a candidate",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": False,
            "high_signal": False, "weight": 1,
        },
    ],
}


def selftest():                                        # noqa: C901
    failures = []
    checks = [0]

    def check(label, got, want):
        checks[0] += 1
        if got != want:
            failures.append("  FAIL %s: got %r, want %r" % (label, got, want))

    # A path typed from the folder holding the repository instead of relative to --root.
    with tempfile.TemporaryDirectory() as ws:
        repo = os.path.join(ws, "payments-api")
        os.makedirs(os.path.join(repo, "lib", "vendor"))
        check("a workspace-relative path is caught, and the fix named",
              (root_prefixed(repo, "payments-api/lib/vendor"),
               root_prefixed(repo, "./payments-api"), root_prefixed(repo, "lib/vendor"),
               root_prefixed(repo, "vendor")),
              ("lib/vendor", ".", None, None))
        os.makedirs(os.path.join(repo, "payments-api"))
        check("unless the repository really holds a directory of its own name",
              root_prefixed(repo, "payments-api/x"), None)

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        for name, doc in (("memory-safety.json", SELFTEST_RULES),
                          ("logic-flaws.json", SELFTEST_LOG_RULES)):
            with open(os.path.join(rules_dir, name), "w", encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
        for name, body in (("parse.c", FIXTURE_C), ("app.py", FIXTURE_PY),
                           ("rec.go", FIXTURE_GO), ("pre.go", FIXTURE_GO_PREAMBLE),
                           ("lib.rs", FIXTURE_RS)):
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        # The one allocation in the tree is a wrapper, so MEM-010's anchored
        # pattern finds nothing and its loosened form finds this. That is the
        # difference between a blind rule and a clean tree, and coverage has to
        # say which.
        with open(os.path.join(src, "alloc.c"), "w", encoding="utf-8") as fh:
            fh.write("#include <stdlib.h>\nvoid *mk(unsigned n)\n{\n"
                     "    return mbedtls_calloc(1, n);\n}\n")

        # The stdlib walk is what every install has, so it is what the fixtures
        # below are asserted against - with tree-sitter installed these same
        # assertions would be testing a library instead. Tier 1 gets its own
        # block at the end, and only when a grammar is importable.
        args = build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"])
        state = extract(args)
        report = write_outputs(state, args)
        check("with no grammar every boundary is heuristic",
              {r["extractor"]["confidence"] for r in state["functions"]},
              {"heuristic"})

        by_key = {}
        for record in state["functions"]:
            by_key.setdefault(record["file"], {})[record["function_key"]] = record
        cfuncs = by_key["src/parse.c"]

        # ---- boundaries, against braces the walk must not count ---- #
        first = cfuncs["src/parse.c::parse_tlv_record::0"]
        check("a brace inside a string literal does not end the function",
              (first["line_start"], first["line_end"]), (9, 17))
        helper = cfuncs["src/parse.c::helper::0"]
        check("the function after a brace-bearing comment starts where it starts",
              (helper["line_start"], helper["line_end"]), (21, 26))
        check("a #define whose braces do not balance is not a function",
              any(r["name"] == "WRAP_BRACE" for r in cfuncs.values()), False)
        check("main is extracted too", "src/parse.c::main::0" in cfuncs, True)
        check("every C function in the fixture is found", len(cfuncs), 4)

        # ---- ordinals ---- #
        second = cfuncs["src/parse.c::parse_tlv_record::1"]
        check("two same-named statics get ordinals 0 and 1, by line order",
              second["line_start"] > first["line_start"], True)
        check("the ordinal is the only thing separating their keys",
              (first["function_key"], second["function_key"]),
              ("src/parse.c::parse_tlv_record::0",
               "src/parse.c::parse_tlv_record::1"))
        check("a function_id carries the content hash",
              first["function_id"], "%s@%s" % (first["function_key"],
                                               first["content_hash"]))

        # ---- content_hash: a comment change is a change ---- #
        body = "int f(void)\n{\n    /* safe: bounded by caller */\n    return 0;\n}"
        edited = body.replace("safe: bounded by caller", "bounded by nothing")
        check("a comment edit changes content_hash",
              content_hash(body) == content_hash(edited), False)
        check("trailing whitespace does not change it",
              content_hash(body), content_hash(body.replace("\n", "   \n")))
        check("a run of blank lines collapses to one",
              content_hash(body.replace("{\n", "{\n\n")),
              content_hash(body.replace("{\n", "{\n\n\n\n")))

        # ---- python, go, rust ---- #
        py = by_key["src/app.py"]
        check("a def inside a docstring is not a function",
              "src/app.py::not_a_function::0" in py, False)
        check("a nested def is its own record", "src/app.py::inner::0" in py, True)
        check("the outer def ends before the class",
              py["src/app.py::outer::0"]["line_end"], 15)
        check("a method is qualified by its class",
              py["src/app.py::parse::0"]["qualified_name"], "Parser.parse")
        go = by_key["src/rec.go"]
        check("a go method with a receiver is found",
              go["src/rec.go::Parse::0"]["qualified_name"], "Rec.Parse")
        check("a go raw string holding braces does not move the boundary",
              (go["src/rec.go::Parse::0"]["line_start"],
               go["src/rec.go::Parse::0"]["line_end"]), (9, 14))
        check("a go struct type is not a function",
              "src/rec.go::Rec::0" in go, False)
        # A grouped `import ( ... )` carries no `;` and no `}`, so the first `{`
        # in the file is the function's and its header ran back to byte 0: the
        # function was reported as lines 1-10, swallowing the package clause and
        # the imports. `lead` could not trim it, because a package clause is
        # code and not a comment. The fix is a blank line counting as a
        # statement boundary; this pins it.
        pre = by_key["src/pre.go"]
        check("a go preamble with a grouped import is not part of the function",
              (pre["src/pre.go::Digest::0"]["line_start"],
               pre["src/pre.go::Digest::0"]["line_end"]), (8, 10))
        check("and the package clause did not become a function",
              sorted(r["name"] for r in pre.values()), ["Digest"])
        rs = by_key["src/lib.rs"]
        check("a rust method inside impl is found",
              "src/lib.rs::parse::0" in rs, True)
        check("the rust impl block is not itself a function",
              sorted(r["name"] for r in rs.values()), ["main", "parse"])
        check("a rust method is qualified by its impl",
              rs["src/lib.rs::parse::0"]["qualified_name"], "Rec::parse")

        # ---- skipping ---- #
        hits = state["hits"]
        mem002 = [h for h in hits if h["rule_id"] == "MEM-002"]
        skipped = [h for h in mem002 if h["disposition"] == "skipped"]
        emitted = [h for h in mem002 if h["disposition"] == "emitted"]
        check("the sizeof(dest) copy is skipped", len(skipped), 1)
        check("the skip reason is the rule's clause, verbatim",
              skipped[0]["skip_reason"], "third argument is literally sizeof(<dest>)")
        check("the variable-length copy is NOT skipped", len(emitted), 1)
        check("and it is the one whose size is a variable",
              "cur, len" in emitted[0]["sink_text"], True)
        check("an emitted hit carries no skip_reason",
              emitted[0]["skip_reason"], None)
        check("a rule with no skip_pattern has no skip path",
              rules_lib.compile_skip(
                  next(r for r in rules_lib.load_rules(rules_dir)
                       if r["rule_id"] == "MEM-006")), None)

        # ---- hits joined to the right function ---- #
        check("the hit lands in the function that holds its line",
              emitted[0]["function_key"], "src/parse.c::parse_tlv_record::0")
        check("sink_text is the line off disk",
              emitted[0]["sink_text"], "memcpy(rec->payload, cur, len);")

        # ---- function_or_path rules select whole functions ---- #
        log = [h for h in hits if h["rule_id"] == "LOG-010"]
        check("a function_or_path rule hits functions, not lines",
              {h["function_key"] for h in log} >= {
                  "src/parse.c::parse_tlv_record::0",
                  "src/app.py::parse::0", "src/rec.go::Parse::0"}, True)
        check("its line is the function's opening line",
              all(h["line"] == by_key[h["file"]][h["function_key"]]["line_start"]
                  for h in log), True)

        # ---- zero_hit_cause, both ways ---- #
        cov = {r["rule_id"]: r for r in state["coverage"]["rules"]}
        check("a rule whose only call site is a wrapper is pattern-unmatchable",
              cov["MEM-010"]["zero_hit_cause"], "pattern-unmatchable")
        check("a rule whose family is simply not here is absent-from-tree",
              cov["MEM-006"]["zero_hit_cause"], "absent-from-tree")
        check("a rule that matched something records no cause",
              cov["MEM-002"]["zero_hit_cause"], None)
        check("both zero-hit rules are named in the report",
              sorted(report["zero_hit_rules"]), ["MEM-006", "MEM-010"])

        # ---- coverage arithmetic, which stage 4 recomputes ---- #
        check("emitted + skipped + deferred == hits, per rule",
              [r["rule_id"] for r in state["coverage"]["rules"]
               if r["emitted"] + r["skipped"] + r["deferred"] != r["hits"]], [])
        check("the skipped sample is sized the way stage 4 expects",
              len(cov["MEM-002"]["skipped_sample"]),
              expected_sample_size(cov["MEM-002"]["skipped"]))
        check("the sample classes the sizeof skip mechanically",
              cov["MEM-002"]["skipped_sample"][0]["class"], "sizeof-bounded")
        check("a rule that skipped nothing carries no skip_reason",
              cov["MEM-006"]["skip_reason"], None)
        check("every rule in the directory has exactly one coverage entry",
              len(cov), 6)

        # ---- MEM-WFS ---- #
        wfs = [h for h in hits if h["rule_id"] == "MEM-WFS"]
        wfs_languages = next(r["languages"] for r in SELFTEST_RULES["rules"]
                             if r["rule_id"] == "MEM-WFS")
        language = {r["function_id"]: r["language"] for r in state["functions"]}
        emitting = {h["function_id"] for h in hits
                    if h["rule_id"] != "MEM-WFS" and h["disposition"] == "emitted"
                    and h["function_id"]}
        producing = {f for f in emitting if language.get(f) in wfs_languages}
        check("MEM-WFS is one record per distinct candidate-producing function "
              "in its own languages", len(wfs), len(producing))
        check("and it names exactly those functions",
              {h["function_id"] for h in wfs}, producing)
        check("a Python or Go function with a candidate gets none: the pass is "
              "C, C++ and Rust's", sorted({language[f] for f in emitting - producing}),
              ["go", "python"])
        check("its coverage count equals the derivation",
              cov["MEM-WFS"]["emitted"], len(producing))
        check("and coverage records the languages it was derived over",
              cov["MEM-WFS"]["languages"], wfs_languages)
        # derive_wfs reads the rule's own `languages`, not a fixed C/C++/Rust
        # test: the gate trusts the recorded list for old runs, so the two must
        # be the same list. A table that listed Python would derive Python's.
        wfs_rule = dict(next(r for r in SELFTEST_RULES["rules"]
                             if r["rule_id"] == "MEM-WFS"),
                        languages=["c", "python"], category="memory-safety")
        stub = type("Compiled", (), {"rules": [{"rule": wfs_rule}]})()
        by_file = {}
        for record in state["functions"]:
            by_file.setdefault(record["file"], []).append(record)
        derived = derive_wfs(stub, [h for h in hits if h["rule_id"] != "MEM-WFS"], by_file)
        check("derive_wfs follows the rule's own languages, not a fixed list",
              sorted({language[h["function_id"]] for h in derived}),
              sorted({"c", "python"} & {language[f] for f in emitting}))
        check("no MEM-WFS record was derived from a skipped hit",
              all(h["function_id"] in producing for h in wfs), True)
        check("MEM-WFS carries no pattern", cov["MEM-WFS"]["pattern"], None)

        # ---- identity of the rule-hit records ---- #
        check("every hit has a unique rule_hit_id",
              len({h["rule_hit_id"] for h in hits}), len(hits))
        check("rule_hit_ids are the contract's shape",
              bool(re.match(r"^RH-\d{6}$", hits[0]["rule_hit_id"])), True)

        # ---- context ---- #
        ctx = first["context"]
        check("the context profile is recorded on the record",
              ctx["profile"], "default-v1")
        check("the function itself is always the first part",
              ctx["parts"][0], {"role": "function", "file": "src/parse.c",
                                "line_start": 9, "line_end": 17})
        check("a caller is included", any(p["role"] == "caller"
                                          for p in ctx["parts"]), True)
        text, problem = emit_context(tmp, state["out_dir"], first["function_id"])
        check("--emit-context re-materialises the recorded hash", problem, None)
        check("and the text really holds the function",
              "parse_tlv_record" in text, True)
        check("the estimate is the named estimator over that text",
              ctx["estimated_tokens"], estimate_tokens_chars_v1(text))
        _, missing = emit_context(tmp, state["out_dir"], "nope::nope::0@dead")
        check("an unknown function_id is an error, not an empty window",
              missing is not None, True)

        # ---- the files on disk ---- #
        for name in ("run.json", "manifest.json", "extract/functions.jsonl",
                     "extract/rules.jsonl", "extract/coverage.json",
                     "extract/extract-report.json", ".gitignore"):
            check("%s was written" % name,
                  os.path.isfile(os.path.join(state["out_dir"], name)), True)
        with open(os.path.join(state["out_dir"], "run.json"), encoding="utf-8") as fh:
            run = json.load(fh)
        check("run.json records the stage", run["stages_completed"], ["extract"])
        check("run.json names this tool's version",
              run["tools"][TOOL], TOOL_VERSION)
        with open(os.path.join(state["out_dir"], ".gitignore"),
                  encoding="utf-8") as fh:
            ignore = fh.read()
        check("the run directory ignores itself", "*" in ignore.split("\n"), True)
        check("but not the ledger, which is meant to be committed",
              "!ledger/" in ignore, True)
        with open(os.path.join(state["out_dir"], "extract", "functions.jsonl"),
                  encoding="utf-8") as fh:
            written = [json.loads(line) for line in fh]
        check("one record per function was written",
              len(written), len(state["functions"]))
        check("every record carries the schema version",
              {r["schema_version"] for r in written}, {SCHEMA_VERSION})
        check("every record carries a measured line range",
              all(r["line_end"] >= r["line_start"] for r in written), True)
        check("no record claims a confidence it did not measure",
              {r["extractor"]["confidence"] for r in written} <=
              {"exact", "heuristic", "window"}, True)

        # ---- the report stage 2 reads ---- #
        check("the report counts the three tiers",
              sorted(k for k in report["confidence"]
                     if k != "window_share"), ["exact", "heuristic", "window"]),
        check("and breaks them down per language",
              sorted(report["by_language"]), ["c", "go", "python", "rust"])
        check("the window share is a fraction, not a count",
              0.0 <= report["confidence"]["window_share"] <= 1.0, True)
        check("nothing needed a window in a tree the walk could parse",
              report["confidence"]["window"], 0)

    # ---- tier 3: a file no walk can resolve still gets a record ---- #
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        # A translation unit with a hit and no resolvable definition: every brace
        # is inside a macro the walker blanks.
        with open(os.path.join(src, "macro.c"), "w", encoding="utf-8") as fh:
            fh.write("#define DEFINE_COPY(name) \\\n"
                     "    static void name(char *d, const char *s, int n) \\\n"
                     "    { memcpy(d, s, n); }\n"
                     "DEFINE_COPY(copy_one)\n")
        args = build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"])
        state = extract(args)
        windows = [r for r in state["functions"]
                   if r["extractor"]["confidence"] == "window"]
        check("a file no walk could resolve still produces a record",
              len(windows), 1)
        check("and it is honest about what it is",
              windows[0]["name"], WINDOW_NAME)
        check("its range is measured, not claimed",
              windows[0]["line_end"] <= 4, True)
        check("the hit inside it is joined to it",
              [h["function_key"] for h in state["hits"]
               if h["rule_id"] == "MEM-002"], [windows[0]["function_key"]])
        check("the report says the corpus holds a window",
              state["report"]["confidence"]["window"], 1)

    # ---- <module>: the scope a file-level hit is joined to (§4) ---- #
    # Untested until now, and the fixture above never reached it because every
    # one of its hits happened to land inside a function. §4 exists because on
    # the shipped tree both of LOG-005's hits were module-level and both were
    # silently unreportable, so "it works" has to be an assertion.
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        for name, doc in (("memory-safety.json", SELFTEST_RULES),
                          ("logic-flaws.json", SELFTEST_LOG_RULES)):
            with open(os.path.join(rules_dir, name), "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
        with open(os.path.join(src, "mod.c"), "w", encoding="utf-8") as fh:
            fh.write("#include <string.h>\n"
                     "static char g[8];\n"
                     "static char *gp = memcpy(g, \"ab\", 2);\n"
                     "\n"
                     "static void parse_seed(void)\n"
                     "{\n"
                     "    memcpy(g, \"cd\", 2);\n"
                     "}\n")
        # Every hit inside a function: this file must get NO synthetic scope.
        with open(os.path.join(src, "inside.c"), "w", encoding="utf-8") as fh:
            fh.write("#include <string.h>\n"
                     "static void copy_one(char *d, const char *s, int n)\n"
                     "{\n"
                     "    memcpy(d, s, n);\n"
                     "}\n")
        args = build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"])
        state = extract(args)
        report = write_outputs(state, args)
        mods = [r for r in state["functions"] if r.get("module_scope")]
        check("a file with a hit outside every function gets one <module> record",
              [r["function_key"] for r in mods], ["src/mod.c::<module>::0"])
        scope = mods[0] if mods else {}
        check("and its name is the bracketed literal nothing can collide with",
              scope.get("name"), MODULE_SCOPE_NAME)
        check("its boundaries are the file's, so the tier is exact",
              (scope.get("line_start"), scope.get("line_end")), (1, 8))
        check("and it says which parser measured them",
              scope.get("extractor"),
              {"parser": "module-scope", "grammar": None, "confidence": "exact"})
        check("the qualified name is the same literal",
              scope.get("qualified_name"), MODULE_SCOPE_NAME)
        check("a file whose hits are all inside functions gets no <module>",
              any(r["file"] == "src/inside.c" for r in mods), False)
        # The pair, not the flag alone: `exact > 0` is the precondition that
        # makes this fixture the bug, so it cannot pass by drifting away from it.
        # A module scope is exact by construction, and tree_sitter_parsed was
        # once `exact > 0` - true here with no grammar loaded, which silenced the
        # "install tree-sitter" note on a field run that was 92% heuristic.
        check("a module scope's exact tier does not make tree_sitter_parsed true",
              (report["confidence"]["exact"] > 0,
               report["parser"]["tree_sitter_parsed"]), (True, False))
        outside = [h for h in state["hits"]
                   if h["file"] == "src/mod.c" and h["line"] == 3
                   and h["rule_id"] == "MEM-002"]
        check("the module-level hit is joined to it, not dropped",
              [(h["join"], h["function_key"]) for h in outside],
              [("line-in-range", "src/mod.c::<module>::0")])
        inner = [h for h in state["hits"]
                 if h["file"] == "src/mod.c" and h["line"] == 7
                 and h["rule_id"] == "MEM-002"]
        check("a hit inside a function still joins to the function, not the file",
              [h["function_key"] for h in inner], ["src/mod.c::parse_seed::0"])
        check("so nothing is left unjoined", report["counts"]["hits_unjoined"], 0)
        check("and the report does not claim a coverage gap it does not have",
              report["files_with_hits_no_functions"], 0)

        # ---- §5: match_target is on the hit, not only on the coverage row ---- #
        check("every hit records which pattern produced it",
              all("match_target" in h for h in state["hits"]), True)
        check("a line-pattern hit says line",
              {h.get("match_target") for h in state["hits"]
               if h["rule_id"] == "MEM-002"}, {"line"})
        check("a name-pattern hit says function_or_path",
              {h.get("match_target") for h in state["hits"]
               if h["rule_id"] == "LOG-010"}, {"function_or_path"})
        check("a derived hit says neither, explicitly",
              {h.get("match_target") for h in state["hits"]
               if h["rule_id"] == "MEM-WFS"}, {None})
        check("and nothing invents a third value",
              {h.get("match_target") for h in state["hits"]} <=
              {"line", "function_or_path", None}, True)

        # ---- the name count stage 4 re-derives survives the dedup (§5) ---- #
        # Two definitions opening on one line are two `<file>::<function>`
        # targets and one `(rule_id, line)`. §5's dedup drops one of them from
        # the record stream, and stage 4 recounts the rule by running its
        # pattern over every target in the corpus - so a `hits_by_target` taken
        # after the dedup is one short and the gate fails a correct run.
        with open(os.path.join(src, "pair.c"), "w", encoding="utf-8") as fh:
            fh.write("static int parse_a(void) { return 0; } "
                     "static int parse_b(void) { return 1; }\n")
        collide = build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"])
        collided = extract(collide)
        pair = sorted(r["name"] for r in collided["functions"]
                      if r["file"] == "src/pair.c")
        check("both definitions on the one line are extracted",
              pair, ["parse_a", "parse_b"])
        names = [r for r in collided["coverage"]["rules"]
                 if r["rule_id"] == "LOG-010"][0]
        targets = [rules_lib.name_target(r["file"], r["name"])
                   for r in collided["functions"]
                   if r["language"] in SELFTEST_LOG_RULES["rules"][0]["languages"]]
        # Through the one name matcher, as stage 4 recounts it - a plain
        # re.search here would expect a different number than the run records.
        name_rx = rules_lib.compile_name_pattern(r"(?i:\b(parse\w*|validate\w*)\b)")
        matching = sum(1 for t in targets if name_rx.search(t))
        check("the name half counts targets, not surviving records",
              names["hits_by_target"]["function_or_path"], matching)
        check("and the dedup really did drop one of them",
              sum(1 for h in collided["hits"]
                  if h["rule_id"] == "LOG-010"
                  and h.get("match_target") == "function_or_path"
                  and h["file"] == "src/pair.c"), 1)

        # ---- §5: sink_text is read from the file, never reconstructed ---- #
        # MEM-WFS used to copy the record's `signature`, and a <module> record's
        # signature is `<file scope of ...>` - a string that appears in no file
        # at any line. Stage 3 read that back off disk and reported "the tree
        # moved under the run" on a tree that had not moved.
        disk = {}
        for rel in ("src/mod.c", "src/inside.c"):
            with open(os.path.join(tmp, rel), encoding="utf-8") as fh:
                disk[rel] = fh.read().split("\n")
        check("every hit quotes the line that is really at its line number",
              [h["rule_hit_id"] for h in state["hits"]
               if h["sink_text"] != disk[h["file"]][h["line"] - 1].strip()[:400]],
              [])

        # ---- run.json vouches for a corpus that is already on disk ---- #
        out_dir = state["out_dir"]
        os.remove(os.path.join(out_dir, "run.json"))
        real_jsonl = _write_jsonl

        def explode(path, records):
            if path.endswith("functions.jsonl"):
                raise OSError("no space left on device")
            real_jsonl(path, records)

        globals()["_write_jsonl"] = explode
        try:
            write_outputs(state, args)
        except OSError:
            pass
        finally:
            globals()["_write_jsonl"] = real_jsonl
        check("a run that died writing the corpus leaves no run.json claiming "
              "the stage completed",
              os.path.exists(os.path.join(out_dir, "run.json")), False)

    # ---- refusals, and the exit code each one is ---- #
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        with open(os.path.join(src, "a.c"), "w", encoding="utf-8") as fh:
            fh.write("void f(char *d, const char *s, int n)\n{\n"
                     "    memcpy(d, s, n);\n}\n")
        base = ["--root", tmp, "--rules-dir", rules_dir, "--jobs", "1",
                "--no-tree-sitter"]

        def refusal(argv):
            args = build_parser().parse_args(argv)
            try:
                extract(args)
            except ExtractError as exc:
                return str(exc), _usage_error(exc, args)
            return None, None

        why, usage = refusal(base + ["--out", os.path.join(tmp, ".security-review"),
                                     "--context-profile", "finetune-v1"])
        check("a profile this build does not ship is refused",
              why is not None and "is not a profile" in why, True)
        check("and it is a usage error, not a run failure", usage, True)

        bad = os.path.join(tmp, "manifest.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION + 1}, fh)
        why, usage = refusal(base + ["--out", os.path.join(tmp, ".security-review"),
                                     "--manifest", bad])
        check("a manifest from a newer schema is refused, never guessed at",
              why is not None and "schema_version" in why, True)
        check("and that is a usage error too", usage, True)

        why, usage = refusal(base + ["--out", "src"])
        check("an --out inside the scanned tree is refused (§9.2)",
              why is not None and "inside the scanned tree" in why, True)
        check("and it is reported as usage", usage, True)
        check("nothing was written into the tree under review",
              sorted(os.listdir(src)), ["a.c"])
        why, _ = refusal(base + ["--out", ".security-review"])
        check("the run directory itself is of course allowed", why, None)

        args = build_parser().parse_args(
            base + ["--out", os.path.join(tmp, ".security-review")])
        state = extract(args)
        write_outputs(state, args)
        fid = state["functions"][0]["function_id"]
        _, problem = emit_context(tmp, state["out_dir"], fid)
        check("--emit-context agrees with the corpus it was written from",
              problem, None)
        with open(os.path.join(src, "a.c"), "w", encoding="utf-8") as fh:
            fh.write("/* edited under the run */\n"
                     "void f(char *d, const char *s, int n)\n{\n"
                     "    memcpy(d, s, n);\n}\n")
        _, problem = emit_context(tmp, state["out_dir"], fid)
        check("and says so when the tree has moved under it",
              problem is not None and "text_sha256" in problem, True)
        parts = [{"role": "function", "file": "../../etc/passwd",
                  "line_start": 1, "line_end": 1}]
        escaped = materialise(parts, contained_reader(tmp))
        check("a corpus that names a file outside the root materialises nothing",
              escaped, "")

    # ---- MEM-WFS over a tree that holds none of its languages ---- #
    # A Python-only tree with candidates derives no whole-function pass at all.
    # The row says so the way any rule with nothing to look at does - zero hits,
    # absent-from-tree, no language present - and the report lists it with
    # those rules, never as blind: a derived rule has no pattern to loosen.
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "src"))
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        for name, doc in (("memory-safety.json", SELFTEST_RULES),
                          ("logic-flaws.json", SELFTEST_LOG_RULES)):
            with open(os.path.join(rules_dir, name), "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
        with open(os.path.join(tmp, "src", "app.py"), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_PY)
        state = extract(build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"]))
        row = next(r for r in state["coverage"]["rules"] if r["rule_id"] == "MEM-WFS")
        check("a Python-only tree with candidates derives no MEM-WFS, and says why",
              (any(h["disposition"] == "emitted" for h in state["hits"]),
               row["hits"], row["zero_hit_cause"], row["languages_present"]),
              (True, 0, "absent-from-tree", []))
        check("and reports it with the rules whose languages are absent, not as blind",
              ("MEM-WFS" in state["report"]["rules_language_absent"],
               "MEM-WFS" in state["report"]["pattern_unmatchable"]), (True, False))

    # ---- the blindness scan: bounded, line by line, and honest about it ---- #
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(BLINDNESS_RULES, fh)
        with open(os.path.join(src, "a.c"), "w", encoding="utf-8") as fh:
            fh.write("void f(void)\n{\n"
                     "    void *p = mbedtls_calloc(1, 8);\n"
                     "    /* xAAA\n"
                     "       BBB */\n"
                     "    /* xCCC\n"
                     "       DDD */\n"
                     "}\n")
        # One line longer than the cap, holding the only thing the quadratic
        # rule could ever match. Without the cap the loosened form of QUAD does
        # not finish on it; with the cap the run completes and SAYS what it
        # declined to read.
        long_line = "z" * 120_000                  # a minified bundle, in one line
        with open(os.path.join(src, "min.js"), "w", encoding="utf-8") as fh:
            fh.write("var a=" + long_line + ";\n")
        check("the long-line fixture is longer than the cap it tests",
              len(long_line) > LOOSE_SCAN_MAX_LINE, True)
        # A file in a language this tool reads that produced no record. Silently
        # dropping it is a hole in the coverage claim §4 makes.
        dangling = rules_lib.can_symlink()
        if dangling:
            os.symlink(os.path.join(tmp, "gone.c"), os.path.join(src, "dangling.c"))
        args = build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"])
        began = time.time()
        state = extract(args)
        report = write_outputs(state, args)
        elapsed = time.time() - began
        cov = {r["rule_id"]: r for r in state["coverage"]["rules"]}
        check("a multiline rule is loosened over the text, as stage 4 does",
              cov["MEM-901"]["zero_hit_cause"], "pattern-unmatchable")
        # The regression: a LINE rule loosened over the whole file text matches
        # across a newline, records pattern-unmatchable, and stage 4's
        # line-by-line recount then finds nothing and fails a correct run.
        check("a line rule is loosened line by line, as stage 4 does",
              cov["MEM-902"]["zero_hit_cause"], "absent-from-tree")
        check("a real blindness is still caught",
              cov["MEM-010"]["zero_hit_cause"], "pattern-unmatchable")
        check("a line too long to re-examine is counted, not passed over",
              report["blindness_scan"]["unit_checks_skipped"] > 0, True)
        check("and the cap it was measured against is in the report",
              report["blindness_scan"]["max_line_chars"], LOOSE_SCAN_MAX_LINE)
        # MEM-903 anchored is linear and runs over every byte of that line in
        # milliseconds; loosened and unbounded it does not finish. This is the
        # regression, and it is timed because nothing else about the run says
        # the difference between "fast" and "never".
        check("a minified line does not stall the run",
              elapsed < 60, True)
        if dangling:
            check("a file the walk cannot stat is counted, not silently dropped",
                  report["counts"]["files_unstattable"], 1)
            check("and the report names it",
                  [e["file"] for e in report["unstattable_files"]],
                  ["src/dangling.c"])
        else:
            rules_lib.skip_case("a file the walk cannot stat is counted and named (a dangling link)")

    # ---- tier 1, when a grammar happens to be importable ---- #
    if ts_parser("c") is not None:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            os.makedirs(src)
            rules_dir = os.path.join(tmp, "rules")
            os.makedirs(rules_dir)
            with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(SELFTEST_RULES, fh)
            for name, body in (("parse.c", FIXTURE_C), ("app.py", FIXTURE_PY),
                               ("rec.go", FIXTURE_GO), ("pre.go", FIXTURE_GO_PREAMBLE),
                           ("lib.rs", FIXTURE_RS)):
                with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                    fh.write(body)
            args = build_parser().parse_args(
                ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
                 "--rules-dir", rules_dir, "--jobs", "1"])
            state = extract(args)
            keyed = {r["function_key"]: r for r in state["functions"]}
            check("a resolved grammar is recorded as exact",
                  keyed["src/parse.c::parse_tlv_record::0"]
                  ["extractor"]["confidence"], "exact")
            check("and names the parser it used",
                  keyed["src/parse.c::parse_tlv_record::0"]
                  ["extractor"]["parser"], "tree-sitter")
            # The point of the whole tier scheme: the fallback has to agree with
            # the parser on a file both can read, or the two tiers are two
            # different corpora and `confidence` is the only thing that says so.
            check("tree-sitter agrees with the stdlib walk on the C boundaries",
                  (keyed["src/parse.c::parse_tlv_record::0"]["line_start"],
                   keyed["src/parse.c::parse_tlv_record::0"]["line_end"]), (9, 17))
            check("and on the ordinals of the two same-named statics",
                  sorted(k for k in keyed if "parse_tlv_record" in k),
                  ["src/parse.c::parse_tlv_record::0",
                   "src/parse.c::parse_tlv_record::1"])
            check("a go receiver qualifies the method",
                  keyed["src/rec.go::Parse::0"]["qualified_name"], "Rec.Parse")
            check("a rust impl qualifies the method",
                  keyed["src/lib.rs::parse::0"]["qualified_name"], "Rec::parse")
            check("a python method is qualified by its class",
                  keyed["src/app.py::parse::0"]["qualified_name"], "Parser.parse")
            check("nothing fell back to a window",
                  state["report"]["confidence"]["window"], 0)

            # ---- the same bytes under a worker pool ---- #
            # The default is a pool, and the parser block used to be read off
            # the PARENT's parser cache - which a pool never populates, because
            # the parent parses nothing. On curl that reported "no tree-sitter
            # grammar was importable" over a corpus whose boundaries were 5294
            # of 5301 exact, and told the operator to install a package they
            # already had. The invariant is environment-independent: whatever
            # the machine has, --jobs 1 and --jobs 4 must say the same thing
            # about it over the same tree.
            # ---- the same bytes under a real worker pool ---- #
            # Two things conspired to hide a live bug here. `_pool_map` runs
            # in-process below 32 files, so no selftest in this file had ever
            # crossed into the forked path at all; and the parser block was read
            # off the PARENT's parser cache, which a fork never populates
            # because the parent parses nothing. On curl that reported "no
            # tree-sitter grammar was importable" over a corpus whose boundaries
            # were 5294 of 5301 exact, and told the operator to install a package
            # they already had. `--jobs 1` said the opposite over the same bytes.
            #
            # So this case needs >= 32 files to engage the pool, and it clears
            # the parent cache the serial run above warmed - together those are
            # what reproduce a fresh pooled process. The invariant is
            # environment-independent: whatever the machine has, --jobs 1 and
            # --jobs 4 must say the same thing about it over the same tree.
            with tempfile.TemporaryDirectory() as pooled_tmp:
                psrc = os.path.join(pooled_tmp, "src")
                os.makedirs(psrc)
                for n in range(40):
                    with open(os.path.join(psrc, "f%02d.c" % n), "w",
                              encoding="utf-8") as fh:
                        fh.write(FIXTURE_C)
                pool_argv = ["--root", pooled_tmp, "--rules-dir", rules_dir,
                             "--out", os.path.join(pooled_tmp, ".security-review")]

                serial = extract(build_parser().parse_args(
                    pool_argv + ["--jobs", "1"]))
                warm = dict(_TS["parsers"])
                _TS["parsers"].clear()
                try:
                    pooled = extract(build_parser().parse_args(
                        pool_argv + ["--jobs", "4"]))
                finally:
                    _TS["parsers"].update(warm)

                check("40 files really engage the pool, not the in-process path",
                      len(serial["files"]) >= 32, True)
                check("a pooled run reports the same parser block as a serial one",
                      pooled["report"]["parser"], serial["report"]["parser"])
                check("and the same tier counts",
                      pooled["report"]["confidence"], serial["report"]["confidence"])
                check("tree_sitter_parsed is true when the boundaries are exact",
                      (pooled["report"]["parser"]["tree_sitter_parsed"],
                       pooled["report"]["confidence"]["exact"] > 0), (True, True))
                check("and `available` stays the narrower question - a module imported",
                      pooled["report"]["parser"]["tree_sitter_available"], True)
    # ---- a record that opens on a blank line still quotes a line ---- #
    # `<module>` starts at line 1, and a header whose first line is blank gave
    # its MEM-WFS candidate an empty sink_text, which the candidate gate
    # refuses as incomplete: /usr/include/pngconf.h did exactly that.
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "src"))
        os.makedirs(os.path.join(tmp, "rules"))
        with open(os.path.join(tmp, "rules", "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        with open(os.path.join(tmp, "src", "copy.h"), "w", encoding="utf-8") as fh:
            fh.write("\n\n#define COPY(d, s, n) memcpy(d, s, n)\n")
        got = extract(build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", os.path.join(tmp, "rules"), "--jobs", "1",
             "--no-tree-sitter"]))
        wfs = [(h["line"], h["sink_text"]) for h in got["hits"]
               if h["rule_id"] == "MEM-WFS"]
        check("a MEM-WFS on a record opening on blank lines quotes its first line "
              "with text", wfs, [(3, "#define COPY(d, s, n) memcpy(d, s, n)")])

    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        rule_file = os.path.join(rules_dir, "memory-safety.json")
        with open(rule_file, "w", encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh, indent=2)
        with open(os.path.join(src, "parse.c"), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_C)
        out_dir = os.path.join(tmp, ".security-review")
        argv = ["--root", tmp, "--out", out_dir, "--rules-dir", rules_dir,
                "--jobs", "1", "--no-tree-sitter"]
        write_outputs(extract(build_parser().parse_args(argv)),
                      build_parser().parse_args(argv))
        with open(os.path.join(out_dir, "run.json"), encoding="utf-8") as fh:
            run = json.load(fh)

        check("run.json pins the ruleset that produced it",
              run["rules_hash"], rules_lib.rules_hash(rules_dir))
        check("a run against the live tree records no snapshot, explicitly",
              ("snapshot" in run, run["snapshot"]), (True, None))
        check("the environment names the interpreter",
              run["environment"]["python"], platform.python_version())
        check("--no-tree-sitter records null, not false: the run did not ask",
              run["environment"]["tree_sitter"], None)

        # The ruleset moves, the tool does not, and the hash is the only thing
        # that says the two runs are not comparable.
        before = run["rules_hash"]
        edited = json.loads(json.dumps(SELFTEST_RULES))
        edited["rules"][0]["weight"] = 1
        with open(rule_file, "w", encoding="utf-8") as fh:
            json.dump(edited, fh, indent=2)
        write_outputs(extract(build_parser().parse_args(argv)),
                      build_parser().parse_args(argv))
        with open(os.path.join(out_dir, "run.json"), encoding="utf-8") as fh:
            check("editing a rule file moves rules_hash",
                  json.load(fh)["rules_hash"] == before, False)

    # ---- tier 1 names what tier 2 names ---- #
    # The brace walk reads a function expression's name off its binding; the
    # grammar has to agree, or one tree extracted two ways names its handlers
    # differently. Found by CI, the one place tree-sitter was installed: the
    # fixture's `const runCode = async (req, res) => {` came out `<anonymous>`.
    for language, text, want in (
            ("javascript",
             "const runCode = async (req, res) => { eval(q); };\n"
             "let g = function (a) { return a; };\n"
             "obj.h = (a) => a + 1;\n"
             "const o = { m: (x) => x };\n"
             "class C { f = () => 1; }\n"
             "app.get('/x', function (req, res) { eval(y); });\n"
             "arr.map(x => x * 2);\n"
             "const getAgent = (url, { agent, proxy } = {}) => { return agent; };\n"
             "const run = async ({\n  a,\n}) => { return a; };\n"
             "function getError ({ Type = TypeError, message }) { return 1; }\n",
             ["runCode", "g", "h", "m", "f", ANONYMOUS_NAME, ARROW_NAME,
              "getAgent", "run", "getError"]),
            ("typescript",
             "export const h = async (a: T): Promise<X> => { return a; };\n"
             "const typed = (req: R, { id }: { id: string }): P => { return id; };\n",
             ["h", "typed"]),
            ("go",
             "package p\nfunc main() { f := func() {}; var g = func() {}; "
             "go func() {}(); srv.Handler = func() {}; a.b.C = func() {} }\n",
             ["main", "f", "g", CLOSURE_NAME, "Handler", "C"]),
            ("cpp",
             "Buf &Buf::operator = (const Buf &o) {\n    return *this;\n}\n"
             "void *P::operator new [] (size_t n) {\n    return 0;\n}\n",
             ["operator =", "operator new []"]),
            ("php",
             "<?php $f = function ($a) { return $a; }; "
             "$g = fn($x) => $x + 1;\n",
             [CLOSURE_NAME, CLOSURE_NAME])):
        if ts_parser(language) is None:
            continue
        got = [f["name"] for f in
               extract_treesitter(text.encode("utf-8"), language)["functions"]]
        check("tree-sitter names %s function expressions as the brace walk does"
              % language, got, want)

    # ---- a C grammar that loses the thread on the preprocessor ---- #
    # Found by running this pipeline on curl, which is the first tree here with
    # enough portable C in it to break a grammar. 178 of curl's 605 C files
    # parse with ERROR nodes, and the damage cost TWELVE functions - do_SOCKS5
    # (CVE-2023-38545), Curl_readwrite, Curl_http_header, parse_proxy,
    # Curl_strerror among them - out of a corpus the report called 100% exact.
    # No error, no note, no tier change: §4's coverage claim was quietly false.
    if ts_parser("c") is not None:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            os.makedirs(src)
            rules_dir = os.path.join(tmp, "rules")
            os.makedirs(rules_dir)
            with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(SELFTEST_RULES, fh)
            with open(os.path.join(src, "pp.c"), "w", encoding="utf-8") as fh:
                fh.write(FIXTURE_C_PREPROCESSOR)

            raw = FIXTURE_C_PREPROCESSOR.encode("utf-8")
            direct = extract_treesitter(raw, "c")
            check("the grammar really does fail on this shape",
                  direct["parse_error"], True)
            # The precise damage, so a future grammar release that fixes it
            # shows up as a changed expectation rather than as silence.
            bare = {f["name"]: (f["line_start"], f["line_end"])
                    for f in direct["functions"]}
            check("and the grammar alone loses the function after the #ifdef",
                  "target" in bare, False)
            check("because the one before it runs past the end",
                  bare.get("sender"), (6, 27))

            args = build_parser().parse_args(
                ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
                 "--rules-dir", rules_dir, "--jobs", "1"])
            state = extract(args)
            got = {r["name"]: (r["line_start"], r["line_end"],
                               r["extractor"]["confidence"])
                   for r in state["functions"] if r["name"] != MODULE_SCOPE_NAME}

            check("the lost function is recovered",
                  got.get("target", (None,))[0:2], (23, 27))
            check("the over-running one is clipped back off the next",
                  got.get("sender", (None,))[0:2], (6, 21))
            check("both say `heuristic`, because that boundary is not the grammar's",
                  (got.get("target", (0, 0, None))[2],
                   got.get("sender", (0, 0, None))[2]),
                  ("heuristic", "heuristic"))
            check("a function the grammar parsed cleanly keeps `exact`",
                  got.get("lead"), (1, 4, "exact"))
            check("and no control-flow keyword is reported as a function",
                  sorted(n for n in got if n in KEYWORD_DEBRIS["c"]), [])
            check("the memcpy in the recovered function is joined to it",
                  [h["rule_id"] for h in state["hits"]
                   if h.get("function_id", "").startswith("src/pp.c::target::")]
                  != [], True)

    # ---- the recon manifest survives a run that does not name it ---- #
    # Found by running the pipeline end to end. Stage 1's recon agent spent ten
    # minutes deriving libxml2's 137 wrappers, 84 entry points and threat model
    # into .security-review/manifest.json. The extract run omitted --manifest,
    # which defaulted to None - so stage 1 scanned with no wrappers AND THEN
    # WROTE ITS OWN manifest.json over the agent's. The recon was not ignored,
    # it was destroyed, and re-running with the flag then read the empty file.
    #
    # The writer was never at fault: it says `never drop a key the agent set`
    # and it is right. The default was what defeated it.
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        with open(os.path.join(src, "parse.c"), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_C)

        out_dir = os.path.join(tmp, ".security-review")
        os.makedirs(out_dir)
        recon = {
            "schema_version": SCHEMA_VERSION,
            "entry_points": ["src/parse.c:parse_tlv_record"],
            "entry_point_confidence": "high",
            "wrapper_resolution": {"copy": ["proj_memcpy"], "alloc": ["proj_malloc"]},
            "physical_attacker": False,
            "physical_attacker_basis": "no linker script, no ISR vector",
            "threat_model": "unauthenticated remote peer",
            "claims_found": [{"file": "a.md", "line": 4, "text": "audited"}],
        }
        with open(os.path.join(out_dir, "manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(recon, fh)

        # The run the operator actually typed: no --manifest.
        argv = ["--root", tmp, "--out", out_dir, "--rules-dir", rules_dir,
                "--jobs", "1", "--no-tree-sitter"]
        state = extract(build_parser().parse_args(argv))
        write_outputs(state, build_parser().parse_args(argv))

        check("the run-directory manifest is read without being named",
              state["manifest_basis"], "found in the run directory")
        check("and the report records which recon the corpus was built on",
              (state["report"]["recon"]["entry_points"],
               state["report"]["recon"]["wrappers"],
               state["report"]["recon"]["wrapper_classes_resolved"]),
              (1, 2, ["alloc", "copy"]))

        with open(os.path.join(out_dir, "manifest.json"), encoding="utf-8") as fh:
            after = json.load(fh)
        check("the agent's wrappers survive the write",
              after["wrapper_resolution"],
              {"copy": ["proj_memcpy"], "alloc": ["proj_malloc"]})
        check("so do its entry points",
              after["entry_points"], ["src/parse.c:parse_tlv_record"])
        check("and every field stage 1 does not itself produce",
              (after.get("threat_model"), after.get("entry_point_confidence"),
               after.get("physical_attacker_basis"),
               len(after.get("claims_found") or [])),
              ("unauthenticated remote peer", "high",
               "no linker script, no ISR vector", 1))
        check("while stage 1's own measurements are still written",
              (after["extracted_by"]["tool"], "languages" in after,
               "unsupported_languages" in after),
              (TOOL, True, True))

        # physical_attacker has three states and only two are answers.
        for value, want_advisory, want_basis in (
                (True,  False, "declared: physical attacker in scope"),
                (False, True,  "declared: no physical attacker"),
                (None,  False, "UNDETERMINED")):
            recon2 = dict(recon)
            if value is None:
                recon2.pop("physical_attacker", None)
            else:
                recon2["physical_attacker"] = value
            with open(os.path.join(out_dir, "manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(recon2, fh)
            st = extract(build_parser().parse_args(argv))
            hw = [h for h in st["hits"] if h["rule_id"].startswith("HW-")]
            capped = any(h.get("advisory_only") for h in hw)
            check("physical_attacker %r caps HW-* severity: %s"
                  % (value, want_advisory),
                  capped if hw else want_advisory, want_advisory)
            check("...and the report names which state it was in",
                  st["report"]["recon"]["threat_basis"].startswith(want_basis),
                  True)
        # ABSENT resolves the same way TRUE does, which is why it has to say so
        # rather than resolve quietly.
        check("an undetermined threat model is not silently 'no attacker'",
              st["report"]["recon"]["physical_attacker"], None)
        with open(os.path.join(out_dir, "manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(recon, fh)

        # An explicit --manifest still wins, so the override is not lost.
        other = os.path.join(tmp, "other.json")
        with open(other, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION,
                       "wrapper_resolution": {"compare": ["proj_ct_memcmp"]}}, fh)
        argv2 = argv + ["--manifest", other]
        state2 = extract(build_parser().parse_args(argv2))
        check("an explicit --manifest still overrides the run directory's",
              (state2["manifest_basis"],
               state2["report"]["recon"]["wrapper_classes_resolved"]),
              ("--manifest", ["compare"]))

    # ---- K&R, which a parameter-shape filter reads as a call ---- #
    # The regression this is here for was mine. The phantom filter first tested
    # the PARAMETER LIST - no `parameter_declaration`, therefore a call - and a
    # K&R definition has a parameter list of bare identifiers because its types
    # come after the closing paren. So it deleted every K&R function in zlib,
    # deflate.c fell to window tier, and the golden set's oldest case went from
    # reached to missed. Caught by running the whole golden set, not by any
    # test here, which is why this one exists.
    if ts_parser("c") is not None:
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "src")
            os.makedirs(src)
            rules_dir = os.path.join(tmp, "rules")
            os.makedirs(rules_dir)
            with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(SELFTEST_RULES, fh)
            with open(os.path.join(src, "knr.c"), "w", encoding="utf-8") as fh:
                fh.write(FIXTURE_C_KANDR)

            direct = extract_treesitter(FIXTURE_C_KANDR.encode("utf-8"), "c")
            check("the export macro really does damage the parse - without it "
                  "this fixture proves nothing",
                  direct["parse_error"], True)
            check("and no K&R definition is taken for a mis-read call",
                  [f["name"] for f in direct["functions"] if f["suspect"]], [])

            args = build_parser().parse_args(
                ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
                 "--rules-dir", rules_dir, "--jobs", "1"])
            state = extract(args)
            got = {r["name"]: (r["line_start"], r["line_end"])
                   for r in state["functions"] if r["name"] != MODULE_SCOPE_NAME}
            check("the K&R function is in the corpus, by name",
                  got.get("deflateInit2_"), (6, 17))
            check("and the file did not fall back to windows",
                  [n for n in got if n.startswith("<window")], [])
            check("its neighbours on both sides survive too",
                  (got.get("lead"), got.get("tail")), ((1, 4), (19, 22)))
            check("the memcpy inside it is joined to it, not to the file scope",
                  [h["rule_id"] for h in state["hits"]
                   if h.get("function_id", "").startswith("src/knr.c::deflateInit2_::")]
                  != [], True)

    # ---- a snapshot narrowed by --exclude ---- #
    # `snapshot.py --exclude src` produces a snapshot with no source in it, and
    # a run over that snapshot used to report a clean scan of a tree it had
    # never seen: the files were simply ABSENT, which reads as "not present"
    # rather than "excluded, reason", and the narrowing lived only in a manifest
    # nothing downstream opens.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        os.makedirs(os.path.join(root, "src"))
        os.makedirs(os.path.join(root, "docs"))
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh, indent=2)
        with open(os.path.join(root, "src", "parse.c"), "w",
                  encoding="utf-8") as fh:
            fh.write(FIXTURE_C)
        with open(os.path.join(root, "docs", "a.c"), "w", encoding="utf-8") as fh:
            fh.write("int doc(void) { return 0; }\n")

        out_dir = os.path.join(root, ".security-review")
        snapshot.build(root, ".security-review", excludes=["src"])
        argv = ["--root", root, "--out", out_dir, "--rules-dir", rules_dir,
                "--jobs", "1", "--no-tree-sitter", "--snapshot"]
        state = extract(build_parser().parse_args(argv))
        write_outputs(state, build_parser().parse_args(argv))

        check("the narrowing is carried onto the run, not left in the manifest",
              state["snapshot"]["excludes"], ["src"])
        with open(os.path.join(out_dir, "manifest.json"), encoding="utf-8") as fh:
            reasons = {e["path"]: e["reason"]
                       for e in json.load(fh)["exclusions"]}
        check("and `src` is an EXCLUSION with a reason, not a silent absence",
              "not in the snapshot" in reasons.get("src", ""), True)
        check("the reason names the flag that caused it",
              "--exclude src" in reasons.get("src", ""), True)
        check("the rest of the tree is still scanned",
              sorted({r["file"] for r in state["functions"]}),
              [os.path.join("docs", "a.c")])
        # The default exclusions must keep their own reason - a narrowing that
        # relabelled `vendor` would be its own kind of lie.
        check("a default exclusion is not relabelled as a snapshot narrowing",
              "not in the snapshot" in reasons.get("vendor", ""), False)
        check("and copy_failed rides along too",
              state["snapshot"]["copy_failed"], 0)

    # ---- --snapshot: the scanner's own folders are named, not just absent ---- #
    #
    # The snapshot leaves them out, so the walk over it never meets them. Taken
    # from a live walk `tooling_skipped` listed them; taken from a snapshot - the
    # path every run uses - it was empty, and neither the report nor the summary
    # said that a folder had not been read. A skill (a folder with a SKILL.md) in a
    # dot folder's `skills` folder is tooling; a folder there without one is code.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh, indent=2)
        for rel, text in (("src/parse.c", FIXTURE_C),
                          (".hostdir/skills/other/SKILL.md", "---\nname: other\n---\n"),
                          (".hostdir/skills/other/tool.c", FIXTURE_C),
                          (".hostdir/skills/build-helpers/pay.c", FIXTURE_C),
                          (".oldhost/security-review/tools/rules_lib.py",
                           rules_lib.TOOL_SIGNATURE + "\n"),
                          (".oldhost/security-review/tools/old.c", FIXTURE_C)):
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        out_dir = os.path.join(root, ".security-review")
        snapshot.build(root, ".security-review")
        argv = ["--root", root, "--out", out_dir, "--rules-dir", rules_dir,
                "--jobs", "1", "--no-tree-sitter", "--snapshot"]
        state = extract(build_parser().parse_args(argv))
        listed = {i["path"]: i["reason"] for i in state["report"]["tooling_skipped"]}
        check("a snapshot run names the skill and the old copy the snapshot left out",
              (sorted(listed),
               listed.get(".hostdir/skills/other", "").startswith("an installed skill"),
               listed.get(".oldhost/security-review", "")),
              ([".hostdir/skills/other", ".oldhost/security-review"], True,
               "a copy of this scanner"))
        check("and reads a folder in that skills folder that is no skill",
              sorted({r["file"] for r in state["functions"]}),
              [os.path.join(".hostdir", "skills", "build-helpers", "pay.c"),
               os.path.join("src", "parse.c")])

    # ---- a filename that is not valid UTF-8 ---- #
    # os.walk hands one of these back as a string of lone surrogates, and it
    # used to kill stage 1 twice over: text_sha256 raised on the window header
    # that embeds the path, and functions.jsonl raised on the write - AFTER the
    # whole corpus had been built. A name like this is ordinary in an old test
    # corpus, and the tool has no business deciding a file is unscannable
    # because of how it is spelled.
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        src_dir = os.path.join(root, "src")
        os.makedirs(src_dir)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh, indent=2)

        # Written through the filesystem encoding, so what comes back off
        # os.walk is the real thing rather than a string that merely looks odd.
        odd_name = os.fsdecode(b"caf\xe9.c")
        check("the fixture name really is undecodable",
              any(0xD800 <= ord(c) <= 0xDFFF for c in odd_name), True)
        with open(os.path.join(src_dir, odd_name), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_C)
        with open(os.path.join(src_dir, "plain.c"), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_C)

        out_dir = os.path.join(root, ".security-review")
        argv = ["--root", root, "--out", out_dir, "--rules-dir", rules_dir,
                "--jobs", "1", "--no-tree-sitter"]
        state = extract(build_parser().parse_args(argv))
        write_outputs(state, build_parser().parse_args(argv))

        files = sorted({r["file"] for r in state["functions"]})
        check("the odd file is scanned, not skipped",
              files, sorted(["src/" + odd_name, "src/plain.c"]))

        # The write is the half that used to fail, so read it back off disk.
        corpus = os.path.join(out_dir, "extract", "functions.jsonl")
        with open(corpus, encoding="utf-8") as fh:
            back = [json.loads(line) for line in fh]
        check("functions.jsonl is written and is valid UTF-8",
              len(back), len(state["functions"]))
        check("and the name round-trips through it unchanged",
              sorted({r["file"] for r in back}), files)

        # text_sha256 over a window whose header carries that name. The two
        # files hold identical bytes, so the ONLY difference between their
        # windows is the path in the header - which makes this both a
        # "it does not crash" case and a "it still distinguishes" one.
        by_file = {}
        for record in back:
            by_file.setdefault(record["file"], []).append(record)
        odd = by_file["src/" + odd_name][0]
        plain = by_file["src/plain.c"][0]
        check("the odd file's window hashed at all",
              len(odd["context"]["text_sha256"]), 64)
        check("identical bodies in differently-named files hash apart",
              odd["context"]["text_sha256"] != plain["context"]["text_sha256"],
              True)
        check("content_hash, which is over the body alone, matches",
              odd["content_hash"], plain["content_hash"])

        text, problem = emit_context(root, out_dir, odd["function_id"])
        check("--emit-context re-materialises the odd file's recorded hash",
              problem, None)
        check("and the window really holds the function",
              "parse_tlv_record" in text, True)

        # surrogateescape is only reached by a string that needs it, so no
        # hash on an ordinary corpus moved.
        check("text_digest is plain UTF-8 for text without surrogates",
              text_digest("int main(void);"),
              hashlib.sha256(b"int main(void);").hexdigest())

    # ---- --snapshot: frozen bytes, live paths ---- #
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "repo")
        src = os.path.join(root, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh, indent=2)
        target = os.path.join(src, "parse.c")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_C)
        out_dir = os.path.join(root, ".security-review")

        def run_extract(extra):
            argv = ["--root", root, "--out", out_dir, "--rules-dir", rules_dir,
                    "--jobs", "1", "--no-tree-sitter"] + extra
            state = extract(build_parser().parse_args(argv))
            write_outputs(state, build_parser().parse_args(argv))
            with open(os.path.join(out_dir, "run.json"), encoding="utf-8") as fh:
                return state, json.load(fh)

        live_state, _ = run_extract([])
        live = {r["function_key"]: r["content_hash"] for r in live_state["functions"]}

        manifest = snapshot.build(root, ".security-review")
        snap_state, snap_run = run_extract(["--snapshot"])
        snapped = {r["function_key"]: r["content_hash"]
                   for r in snap_state["functions"]}

        # The mapping, both halves. Same keys and same hashes as the live run -
        # so the snapshot is not a different corpus - and every path still
        # relative to the repository, not to the snapshot directory.
        check("a snapshot run produces the same corpus as a live one",
              snapped, live)
        check("every recorded path is relative to the ORIGINAL tree",
              sorted({r["file"] for r in snap_state["functions"]}),
              ["src/parse.c"])
        check("no recorded path leaks the snapshot directory",
              [r["file"] for r in snap_state["functions"]
               if ".security-review" in r["file"] or "snapshot" in r["file"]], [])
        check("and every one of them resolves in the repository",
              sorted({os.path.isfile(os.path.join(root, r["file"]))
                      for r in snap_state["functions"]}), [True])
        check("repo_root is the repository, not the snapshot",
              snap_run["repo_root"], os.path.abspath(root))
        check("run.json names the snapshot it read",
              (snap_run["snapshot"]["id"], snap_run["snapshot"]["files"]),
              (manifest["snapshot_id"], manifest["counts"]["files"]))
        check("and records snapshot.py in tools",
              snap_run["tools"].get("snapshot.py"), snapshot.TOOL_VERSION)
        check("the report says where the bytes came from",
              snap_state["report"]["scan_root"],
              os.path.join(out_dir, "snapshot"))

        # The whole point, in one assertion: the tree moves, the snapshot run
        # still reports the function it froze, the live run reports the edit.
        function_id = [r["function_id"] for r in snap_state["functions"]
                       if r["function_key"] == "src/parse.c::parse_tlv_record::0"][0]
        # An edit INSIDE the body, because that is what a stale citation is: the
        # line the finding quoted now says something else. A line added above
        # the function would move line_start and leave content_hash alone.
        edit = FIXTURE_C.replace('printf("%s", fmt);',
                                 'printf("%s", fmt);  /* edited under the run */')
        check("the fixture edit is the one the assertions below need",
              edit == FIXTURE_C, False)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(edit)
        moved_state, _ = run_extract([])
        moved = {r["function_key"]: r["content_hash"] for r in moved_state["functions"]}
        check("a live re-run after the edit reports a different body",
              moved["src/parse.c::parse_tlv_record::0"]
              == live["src/parse.c::parse_tlv_record::0"], False)
        frozen_state, _ = run_extract(["--snapshot"])
        frozen = {r["function_key"]: r["content_hash"] for r in frozen_state["functions"]}
        check("a snapshot re-run after the same edit reports the frozen body",
              frozen["src/parse.c::parse_tlv_record::0"],
              live["src/parse.c::parse_tlv_record::0"])

        # ...and the citation that quotes it still verifies, which is the thing
        # the 19-candidate run could not do.
        text, problem = emit_context(context_read_root(root, out_dir), out_dir,
                                     function_id)
        check("--emit-context verifies against the snapshot after the tree moved",
              (problem, FIXTURE_C.splitlines()[8] in text), (None, True))
        _, live_problem = emit_context(root, out_dir, function_id)
        check("and would have failed against the live tree",
              live_problem is not None, True)

        # A snapshot of somebody else's tree hands back paths that resolve
        # against a repository it was never taken from.
        other = os.path.join(tmp, "other")
        os.makedirs(os.path.join(other, "src"))
        with open(os.path.join(other, "src", "parse.c"), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE_C)
        snapshot.build(other, ".security-review")

        # Asserting on the exception's TEXT is what let the exit code be wrong
        # for every one of these: the message started with "--snapshot:" and
        # _usage_error did not know the prefix, so main() returned 1 where the
        # docstring promises 2. Each case now asks what a wrapper would see.
        def snapshot_refusal(path):
            args = build_parser().parse_args(
                ["--root", root, "--out", out_dir, "--rules-dir", rules_dir,
                 "--jobs", "1", "--no-tree-sitter", "--snapshot", path])
            try:
                extract(args)
            except ExtractError as exc:
                return str(exc), (2 if _usage_error(exc, args) else 1)
            return None, 0

        why, code = snapshot_refusal(
            os.path.join(other, ".security-review", "snapshot"))
        check("a snapshot of another tree is refused",
              why is not None and "never taken from" in why, True)
        check("and it exits 2, the usage code the docstring promises", code, 2)

        why, code = snapshot_refusal(os.path.join(tmp, "nothing-here"))
        check("a --snapshot that is not there is refused",
              why is not None and why.startswith("--snapshot:"), True)
        check("and that is usage too, not a run failure", code, 2)

        # A committed decoy: snapshot/ plus a manifest whose roots are RELATIVE.
        # realpath() resolves them against the working directory, so from the
        # repository root `"."` and `".security-review/snapshot"` used to pass
        # both root checks without knowing where the checkout is - and the
        # decoy became the corpus.
        manifest_path = os.path.join(out_dir, snapshot.MANIFEST_NAME)
        with open(manifest_path, encoding="utf-8") as fh:
            genuine = json.load(fh)
        planted = dict(genuine, source_root=".",
                       snapshot_root=os.path.join(".security-review", "snapshot"))
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(planted, fh)
        here = os.getcwd()
        try:
            os.chdir(root)
            why, code = snapshot_refusal(SNAPSHOT_HERE)
        finally:
            os.chdir(here)
        check("a snapshot manifest with relative roots is refused, even run "
              "from the root they resolve against",
              (why is not None and "relative root" in why, code), (True, 2))
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(dict(genuine, tool="not-snapshot.py"), fh)
        why, _code = snapshot_refusal(SNAPSHOT_HERE)
        check("and so is one another tool wrote",
              why is not None and "names another tool" in why, True)
        if os.path.isdir("/proc/self/cwd"):
            with open(manifest_path, "w", encoding="utf-8") as fh:
                json.dump(dict(genuine, source_root="/proc/self/cwd",
                               snapshot_root="/proc/self/cwd/.security-review/snapshot"),
                          fh)
            try:
                os.chdir(root)
                why, _code = snapshot_refusal(SNAPSHOT_HERE)
            finally:
                os.chdir(here)
            check("and one whose absolute roots only resolve to the tree from its "
                  "own working directory", why is not None and "never taken from" in why,
                  True)
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(genuine, fh)
        real_snap = os.path.join(out_dir, "snapshot")
        if rules_lib.can_symlink():
            os.rename(real_snap, real_snap + ".real")
            os.symlink(real_snap + ".real", real_snap)
            why, _code = snapshot_refusal(SNAPSHOT_HERE)
            check("a snapshot/ that is a link is refused before it is read",
                  why is not None and "symbolic link" in why, True)
            os.unlink(real_snap)
            os.rename(real_snap + ".real", real_snap)
            os.rename(manifest_path, manifest_path + ".real")
            os.symlink(manifest_path + ".real", manifest_path)
            why, _code = snapshot_refusal(SNAPSHOT_HERE)
            check("and so is a snapshot-manifest.json that is a link",
                  why is not None and "symbolic link" in why, True)
            os.unlink(manifest_path)
            os.rename(manifest_path + ".real", manifest_path)
        else:
            rules_lib.skip_case("a snapshot/ or a snapshot-manifest.json that is a link is refused (two cases)",
                                n=2)

        # --emit-context follows run.json's snapshot.root - but only to the one
        # snapshot this run directory owns. A run.json naming anywhere else
        # printed files from there.
        elsewhere = os.path.join(tmp, "elsewhere")
        os.makedirs(elsewhere, exist_ok=True)
        with open(os.path.join(out_dir, "run.json"), encoding="utf-8") as fh:
            run_doc = json.load(fh)
        run_doc["snapshot"] = dict(run_doc.get("snapshot") or {}, root=elsewhere)
        with open(os.path.join(out_dir, "run.json"), "w", encoding="utf-8") as fh:
            json.dump(run_doc, fh)
        check("--emit-context ignores a run.json snapshot.root outside the run "
              "directory", context_read_root(root, out_dir), root)
        run_doc["snapshot"]["root"] = real_snap
        with open(os.path.join(out_dir, "run.json"), "w", encoding="utf-8") as fh:
            json.dump(run_doc, fh)
        check("and still follows it to the run directory's own snapshot",
              context_read_root(root, out_dir), real_snap)
        if rules_lib.can_symlink():
            os.rename(real_snap, real_snap + ".real")
            os.symlink(real_snap + ".real", real_snap)
            check("but not when that snapshot/ is itself a link",
                  context_read_root(root, out_dir), root)
            os.unlink(real_snap)
            os.rename(real_snap + ".real", real_snap)
        else:
            rules_lib.skip_case("--emit-context does not follow a snapshot/ that is itself a link")

        # `args.budget_tokens or profile[...]` read 0 as the flag left off.
        for budget in ("0", "-64"):
            args = build_parser().parse_args(
                ["--root", root, "--out", out_dir, "--rules-dir", rules_dir,
                 "--jobs", "1", "--no-tree-sitter", "--budget-tokens", budget])
            try:
                extract(args)
                code = 0
            except ExtractError as exc:
                code = 2 if _usage_error(exc, args) else 1
            check("--budget-tokens %s is refused as usage, not run at the "
                  "profile's budget" % budget, code, 2)

    # ---- the names this stage invents, and the JS shapes it now names ---- #
    # Stage 4 refuses a candidate whose function name is absent from its file,
    # and exempts only the synthetic names; one it does not know about refuses
    # the whole run. The async arrow is the common Express handler, and it came
    # out as `<arrow>` because the lookup saw `... = async` and gave up.
    check("every name stage 1 invents is in SYNTHETIC_FUNCTION_NAMES",
          SYNTHETIC_FUNCTION_NAMES,
          (MODULE_SCOPE_NAME, WINDOW_NAME, ARROW_NAME, ANONYMOUS_NAME, CLOSURE_NAME))
    check("and every one of them is bracketed, so none can be a real name",
          [n for n in SYNTHETIC_FUNCTION_NAMES
           if not (n.startswith("<") and n.endswith(">"))], [])
    for header, want in (
            ("const runCode = async (req, res) =>", "runCode"),
            ("const f = async req =>", "f"),
            ("const f = req =>", "f"),
            ("const f = async function (a)", "f"),
            ("export const h = async (a: T): Promise<X> =>", "h"),
            ("handler: async (e) =>", "handler"),
            ("x.onload = async () =>", "onload"),
            ("const f = (a = g()) =>", "f"),
            ("const g = async <T>(x: T): Promise<{ f(): void }> =>", "g"),
            ("app.get(    , (req, res) =>", ARROW_NAME),
            ("app.get(    , function (req, res)", ANONYMOUS_NAME)):
        check("the JS header %r is named %r" % (header, want),
              _hdr_js(header, header)[0], want)
    check("an unbound Go closure is <closure>",
          _hdr_go("go func() ", "go func() ")[0], CLOSURE_NAME)

    check("a Go func assigned to a field is named for the field",
          _hdr_go("srv.Handler = func() ", "srv.Handler = func() ")[0], "Handler")

    def walk(text, language, stats=None):
        starts = _line_start_offsets(text)
        masked = mask_source(text, language)
        found = extract_brace(text, masked, language,
                              lambda p: bisect.bisect_right(starts, p), stats)
        return [(f["line_start"], f["line_end"], f["qualified_name"]) for f in found]

    # Through the walk, not _hdr_js: the checks above hand it a header whole,
    # and the walk cut this one at the first `{` of a destructured parameter,
    # so the matcher saw `) =>`. The arrow was `<arrow>` here and named under
    # tree-sitter, a SvelteKit handler's body was one line long with its
    # SQL-injection hit in `<module>`, and a method whose parameter was
    # destructured was not a function at all. From the interface on, the
    # braces open a type, a value, an argument or a catch binding, or sit in
    # JSX text, and must not name anything new or move the line a real
    # function starts on. The last two are arguments in a statement no `;`
    # ends, which the read-back named: `reply.res.json` held the eval, and
    # the class was `configure`, its method `configure.m`.
    for language, text, want in (
            ("javascript", "const validateToken = (req, { token, secret } = {}) => {\n"
             "  return 1\n}\n", [(1, 3, "validateToken")]),
            ("javascript", "const run = async ({\n  a,\n  b,\n}) => {\n  return a\n}\n",
             [(1, 6, "run")]),
            ("javascript", "function getError ({ Type = TypeError, message }) {\n"
             "  return 1\n}\n", [(1, 3, "getError")]),
            ("javascript", "export async function POST({ request, cookies }) {\n"
             "  const q = 1\n  return db.query('x' + q)\n}\n", [(1, 4, "POST")]),
            ("javascript", "function f(a = {}) {\n  return a\n}\n", [(1, 3, "f")]),
            ("javascript", "class A {\n  run({ a }) {\n    return a\n  }\n}\n",
             [(2, 4, "A.run")]),
            ("javascript", "app.get('/x', ({ query }, res) => {\n  res.send(query)\n})\n",
             [(1, 3, ARROW_NAME)]),
            ("typescript", "const typed = (req: Request, { id }: { id: string; n: T }):"
             " Promise<void> => {\n  return id\n}\n", [(1, 3, "typed")]),
            ("typescript", "interface Api {\n  get(o: { id: string }): { data: T };\n"
             "  put(x: string): { ok: boolean };\n}\n", []),
            # ...while a method whose return type is a string still is one.
            ("typescript", "class Circle {\n  get kind(): 'circle' {\n    return 'circle'\n"
             "  }\n  mode(): \"r\" {\n    return \"r\"\n  }\n}\n",
             [(2, 4, "Circle.kind"), (5, 7, "Circle.mode")]),
            ("javascript", "export default defineComponent({\n  data() {\n"
             "    return { a: 1 }\n  },\n  methods: {\n    submit({ a }) {\n"
             "      return a\n    },\n  },\n})\n", [(2, 4, "data"), (6, 8, "submit")]),
            ("javascript", "$.ajax({ url: u, success: function (d) {\n  eval(d)\n} })\n",
             [(1, 3, "success")]),
            ("javascript", "const o = {\n  a: f(x), b: {\n    c: 1\n  }\n}\n", []),
            ("javascript", "function A(p) {\n"
             "  return <p>Note (see: {p.x}) {p.ys.map(y => {\n"
             "    return y\n  })}</p>\n}\n", [(2, 4, "A.<arrow>"), (1, 5, "A")]),
            ("javascript", "if (check({ a })) {\n  go()\n}\n", []),
            ("javascript", "try {\n  x()\n} catch ({ message }) {\n  log(message)\n}\n",
             []),
            ("javascript", "function reply(res, x) {\n  res.json({ ok: true })\n"
             "  if (x) {\n    eval(x)\n  }\n}\n", [(1, 6, "reply")]),
            ("javascript", "configure({ strict: true })\nclass B {\n  m() {\n"
             "    return 1\n  }\n}\n", [(3, 5, "B.m")])):
        check("the JS function in %r" % text.split("\n")[0][:48],
              walk(text, language), want)
    # A header is read twice when a parameter is destructured, and a crafted
    # one of hundreds of `):` cost a binding lookup per `):` per read: sixty
    # times a same-sized header without them. Timed against that header, so
    # a slow machine is slow on both.
    walked = {}
    for shape, sep in (("crafted", "):(a"), ("plain", "),(a")):
        text = ("f(({a}" + sep * 480 + ") =>{}\n") * 30
        best = None
        for _attempt in range(2):
            began = time.perf_counter()
            walk(text, "javascript")
            took = time.perf_counter() - began
            best = took if best is None else min(best, took)
        walked[shape] = best
    check("a JS header of hundreds of `):` costs what any header that long does",
          walked["crafted"] < 10 * walked["plain"], True)

    # ---- the mask: regex literals, text blocks, raw strings, separators ---- #
    check("masking never moves an offset",
          [lang for lang, text in (("javascript", FIXTURE_JS_MASKING),
                                   ("cpp", FIXTURE_CPP_HEADERS))
           if len(mask_source(text, lang)) != len(text)], [])
    check("a JS regex literal is masked, and a division and JSX are not",
          walk(FIXTURE_JS_MASKING, "javascript"),
          [(1, 6, "fetchIt"), (7, 12, "parseBody"), (13, 15, "tokens"),
           (16, 22, "quoted"), (23, 25, "view"), (26, 28, "pager"),
           (29, 31, "cell"), (32, 34, "card"), (35, 37, "braces"),
           (38, 40, "after"), (41, 43, "crumb"), (44, 46, "help"),
           (47, 49, "nav"), (50, 52, "key"), (53, 56, "avg"), (57, 59, "tail2")])
    # A line of `(/[` never closes its class, so every slash scanned 2000
    # characters and failed: 400 KB took twelve seconds, 2 MB a minute. On one
    # line or on many, the budget makes it linear, and the regex before the
    # hostile text is masked as ever; the one after it is past the budget and
    # divides, which leaves its `{` standing and is all it costs.
    head = "var a = /^https?:\\/\\//;\n"
    for shape, body in (("one line", "x=(/[" * 80000 + "\n"),
                        ("many lines", ("x=(/[" * 399 + "\n") * 200)):
        text = head + body + "var b = /[{]/;\n"
        began = time.time()
        masked = mask_source(text, "javascript")
        spent = time.time() - began
        check("a JS regex scan that never closes is linear, on %s" % shape,
              (spent < 5, len(masked) == len(text), "//" in masked[:len(head)],
               "{" in masked[len(head) + len(body):]), (True, True, False, True))
    java = ('public class Tb {\n    String tpl() {\n        return """\n'
            '            function x() {\n              if (a) {\n'
            '            """;\n    }\n    void run() {\n'
            '        System.out.println("x");\n    }\n    void last() { }\n}\n')
    check("a Java text block holding code-shaped text is masked",
          walk(java, "java"),
          [(2, 7, "Tb.tpl"), (8, 10, "Tb.run"), (11, 11, "Tb.last")])
    csharp = ('class Raw {\n    string Tpl() {\n        return """\n'
              '            { "a": {\n            """;\n    }\n    void Run() { }\n'
              '    string V() { return @"""quoted"" {"; }\n    void W() { }\n}\n')
    check("a C# raw string is masked, and a verbatim @\"\"\" is still verbatim",
          walk(csharp, "csharp"),
          [(2, 6, "Raw.Tpl"), (7, 7, "Raw.Run"), (8, 8, "Raw.V"), (9, 9, "Raw.W")])

    # ---- C-family headers whose first `ident(` is not the name ---- #
    check("attributes, export macros and pointer returns do not hide the name",
          walk(FIXTURE_C_HEADERS, "c"),
          [(1, 5, "die"), (7, 10, "api_parse"), (12, 15, "pick")])
    check("C++ brace initialisers, operators and digit separators",
          walk(FIXTURE_CPP_HEADERS, "cpp"),
          [(1, 3, "Buffer::Buffer"), (5, 7, "operator=="), (9, 11, "Buf::operator[]"),
           (13, 15, "Foo::Foo"), (17, 22, "clamp"), (25, 25, "Holder::get"),
           (28, 34, "run")])
    # Stage 4 looks for the candidate's function name in the file, spelled as
    # stage 1 gave it. `operator=` is not in `operator = (`, and a copy
    # assignment holding a memcpy refused the run with no tree-sitter.
    spaced = ("Buf &Buf::operator = (const Buf &o) {\n    return *this;\n}\n"
              "void *P::operator new [] (size_t n) {\n    return 0;\n}\n")
    check("a C++ operator is named as the source spells it, spaces and all",
          walk(spaced, "cpp"),
          [(1, 3, "Buf::operator ="), (4, 6, "P::operator new []")])
    # C# has no _statement_macro to fall back on, and `unsafe` code
    # dereferences in conditions as C does.
    check("a condition that starts with a dereference names no C# method",
          walk("class A {\n    unsafe void Run(byte* p) {\n"
               "        if (*p > 0 && Check(p)) {\n            Copy(p);\n"
               "        }\n    }\n}\n", "csharp"), [(2, 6, "A.Run")])
    annotated = ('public class Ctl {\n    @GetMapping("/users/{id}")\n'
                 '    public String show(@PathVariable("id") String id) {\n'
                 '        return id;\n    }\n'
                 '    @RequestMapping(value = "/x", method = GET)\n'
                 '    public String other() {\n        return "";\n    }\n}\n')
    check("a Java annotation is not the method's name",
          [q for _a, _b, q in walk(annotated, "java")], ["Ctl.show", "Ctl.other"])
    attributed = ('public class Ctl {\n    [HttpGet("{id}")]\n'
                  '    public IActionResult Show(string id) {\n'
                  '        return Ok();\n    }\n}\n')
    check("nor is a C# attribute",
          [q for _a, _b, q in walk(attributed, "csharp")], ["Ctl.Show"])
    check("a namespace with an attribute macro is not a function",
          walk("namespace std _GLIBCXX_VISIBILITY(default)\n{\n"
               "  int f(int a)\n  {\n    return a;\n  }\n}\n", "cpp"),
          [(3, 6, "std::f")])

    # ---- iteration macros, and a nested definition that is real ---- #
    stats = {}
    check("an unclosed block is counted, and the definition after it is kept",
          (walk(FIXTURE_C_UNCLOSED, "c", stats), stats),
          ([(6, 10, "over::target")], {"unclosed": 1}))
    local = ("int outer(int k)\n{\n    struct Local {\n"
             "        Local(int x) : v(x) { }\n        int get() const { return v; }\n"
             "        int v;\n    };\n    Q_FOREACH(auto x, list) {\n        k++;\n"
             "    }\n    return k;\n}\n")
    check("a class declared in a function keeps its methods; a macro is dropped",
          sorted(q.split("::")[-1] for _a, _b, q in walk(local, "cpp")),
          ["Local", "get", "outer"])
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        for name, body in (("loop.c", FIXTURE_C_LOOP_MACROS),
                           ("ifdef.c", FIXTURE_C_IFDEF_BRACES),
                           ("alt.c", FIXTURE_C_IFDEF_ALTERNATIVES)):
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        argv = ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
                "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"]
        state = extract(build_parser().parse_args(argv))
        per_file = {}
        for record in state["functions"]:
            per_file.setdefault(record["file"], []).append(
                (record["line_start"], record["line_end"], record["qualified_name"]))
        hits = state["hits"]

        def owners(rel, rule_id):
            return sorted(h["function_key"] for h in hits
                          if h["file"] == rel and h["rule_id"] == rule_id)
        check("loop macros and `if (*p && f(x))` are not functions: flush_all "
              "is the only record", per_file.get("src/loop.c"), [(2, 31, "flush_all")])
        check("so the memcpys in the loop and the if join to the function with "
              "its guard", owners("src/loop.c", "MEM-002"),
              ["src/loop.c::flush_all::0", "src/loop.c::flush_all::0"])
        check("and the whole-function pass is flush_all's",
              owners("src/loop.c", "MEM-WFS"), ["src/loop.c::flush_all::0"])

        # ---- #ifdef branches that each open a brace ---- #
        check("a function whose #ifdef branches each open a brace is recovered",
              per_file.get("src/ifdef.c"),
              [(1, 22, "copy_in"), (24, 28, "parse_header")])
        check("its memcpy joins to it, not to an `exact` <module> record",
              owners("src/ifdef.c", "MEM-002"), ["src/ifdef.c::copy_in::0"])
        check("balanced alternative definitions keep both",
              per_file.get("src/alt.c"),
              [(2, 5, "plat_read"), (7, 11, "plat_read")])
        check("and the memcpy in the #else one joins to the #else one",
              owners("src/alt.c", "MEM-002"), ["src/alt.c::plat_read::1"])
        check("nothing was left open in a file the retry balanced",
              state["report"]["counts"]["functions_unclosed"], 0)
        # The first-branch mask is the brace walk's alone: a call made only
        # under #else is still a call, for the caller context.
        worker_init({"root": tmp, "rules": rules_lib.load_rules(rules_dir),
                     "wrappers": {}, "test_globs": [], "advisory": False,
                     "prefer_ts": False})
        check("a call made only under #else still reaches the call-site index",
              "whisper_only_here" in scan_file(("src/ifdef.c", "c"))["calls"], True)

        # ---- a skip is decided for the hit, not for its line ---- #
        compiled = CompiledRules(rules_lib.load_rules(rules_dir), {})
        text = ("void f(char *hdr, char *body, const char *p, int len)\n{\n"
                "    memcpy(hdr, p, sizeof(hdr)); memcpy(body, p + 4, len);\n"
                "    memcpy(body, p + 4, len); memcpy(hdr, p, sizeof(hdr));\n"
                "    memcpy(hdr, p, sizeof(hdr));\n}\n")
        found = _dedup_hits(run_rules("x.c", "c", text, text.split("\n"),
                                      compiled, False))
        check("an unbounded copy is not skipped for sharing a line with a bounded one",
              [(h["line"], h["disposition"], h["skip_reason"]) for h in found
               if h["rule_id"] == "MEM-002"],
              [(3, "emitted", None), (4, "emitted", None),
               (5, "skipped", "third argument is literally sizeof(<dest>)")])

        # ---- every skip carries a class stage 4 can check ---- #
        # A skip that fell through to `other` counted against stage 4's ceiling
        # on unverifiable classes, and every OTH-004 skip did: one
        # `signal(SIGPIPE, SIG_IGN)` in a tree failed the candidate gate. And
        # `#` opens a comment only where the language says so.
        shipped = CompiledRules(rules_lib.load_rules(rules_lib.default_rules_dir()), {})

        def skip_classes(rel, language, text):
            return sorted((h["rule_id"], h["line"], h["skip_class"])
                          for h in run_rules(rel, language, text, text.split("\n"),
                                             shipped, False)
                          if h["disposition"] == "skipped")
        check("an OTH-004 skip is classed skip-pattern, not other",
              skip_classes("x.c", "c",
                           "void install(void)\n{\n"
                           "    signal(SIGPIPE, SIG_IGN);\n"
                           "    // signal(SIGHUP, SIG_IGN);\n"
                           "#define NOPIPE() signal(SIGPIPE, SIG_IGN)\n"
                           "    memcpy(hdr, p, sizeof(hdr));\n}\n"),
              [("MEM-002", 6, "sizeof-bounded"), ("OTH-004", 3, "skip-pattern"),
               ("OTH-004", 4, "comment"), ("OTH-004", 5, "skip-pattern")])
        check("and a # line is a comment in Python, where it is one",
              skip_classes("x.py", "python",
                           "import signal\n"
                           "# signal.signal(signal.SIGPIPE, signal.SIG_IGN)\n"
                           "signal.signal(signal.SIGPIPE, signal.SIG_IGN)\n"),
              [("OTH-004", 2, "comment"), ("OTH-004", 3, "skip-pattern")])

    # ---- a minified file is linear, and the memos change no byte ---- #
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        units = 2500
        unit = ('function f%d(a,b){var s="k%d",t=\'q\';if(a>b){return s+a}'
                'return b/2}var o%d={x:1,y:"z%d",g:function(c){return c*2}};')
        with open(os.path.join(src, "app.min.js"), "w", encoding="utf-8") as fh:
            fh.write("".join(unit % (i, i, i, i) for i in range(units)) + "\n")
        with open(os.path.join(src, "pair.js"), "w", encoding="utf-8") as fh:
            fh.write("function alpha(a){return beta(a)} function beta(b){return b}\n"
                     "function gamma(c){return alpha(c)+beta(c)}\n")
        args = build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"])
        began = time.time()
        state = extract(args)
        elapsed = time.time() - began
        minified = [r for r in state["functions"] if r["file"] == "src/app.min.js"]
        check("every function on the minified line has a record",
              len(minified), 2 * units)
        # Quadratic, this was about a minute on this fixture; linear, about a
        # second. The bound is loose so a slow machine does not fail it.
        check("a 300 KB minified line does not stall the run", elapsed < 20, True)
        read_lines = contained_reader(tmp)
        profile = CONTEXT_PROFILES["default-v1"]
        estimate = TOKEN_ESTIMATORS[profile["estimator"]]
        wrong = []
        for record in state["functions"][:50] + state["functions"][-50:]:
            text = materialise(record["context"]["parts"], read_lines)
            if (text_digest(text) != record["context"]["text_sha256"]
                    or estimate(text) != record["context"]["estimated_tokens"]):
                wrong.append(record["function_id"])
        check("every window's hash and estimate are over the text it materialises",
              wrong, [])
        # The callee memo is per span, and a record is not its own callee: two
        # records on one span must get different lists from one memo entry.
        builder = ContextBuilder(tmp, "default-v1", profile, {
            "types": {}, "calls": {}, "preamble": {},
            "functions": {n: ("src/other.js", 10 * k + 1, 10 * k + 5)
                          for k, n in enumerate(("aaa", "bbb", "ccc", "ddd"))}})
        body = "aaa(); bbb(); ccc(); ddd();"
        callees = {}
        for name in ("bbb", "zzz"):
            record = {"file": "src/x.js", "name": name, "line_start": 1, "line_end": 1}
            callees[name] = [p["line_start"]
                             for p in builder.candidate_parts(record, body)["callee"]]
        check("one span, two records, each with its own callees",
              callees, {"bbb": [1, 21, 31], "zzz": [1, 11, 21]})

    # ---- a UTF-8 byte-order mark, and UTF-16 and UTF-32 sources ---- #
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        for name, body in (
                ("a.py", "\ufeffdef run(cmd):\n    import os\n    os.system(cmd)\n"),
                ("b.py", "\ufeffclass Handler:\n    def run(self, cmd):\n"
                         "        return 1\n"),
                ("d.rb", "\ufeffclass Handler\n  def run(cmd)\n    system(cmd)\n"
                         "  end\nend\n")):
            with open(os.path.join(src, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        with open(os.path.join(src, "w16.c"), "wb") as fh:
            fh.write("void f(char *d) { strcpy(d, s); }\n".encode("utf-16"))
        with open(os.path.join(src, "w32.c"), "wb") as fh:
            fh.write("void f(char *d) { strcpy(d, s); }\n".encode("utf-32"))
        with open(os.path.join(src, "bin.c"), "wb") as fh:
            fh.write(b"\x7fELF\x00\x00\x01")
        args = build_parser().parse_args(
            ["--root", tmp, "--out", os.path.join(tmp, ".security-review"),
             "--rules-dir", rules_dir, "--jobs", "1", "--no-tree-sitter"])
        state = extract(args)
        named = {(r["file"], r["qualified_name"]): (r["line_start"], r["line_end"])
                 for r in state["functions"]}
        check("a def on a BOM's line is a function, not <module>",
              named.get(("src/a.py", "run")), (1, 3))
        check("a class on a BOM's line still qualifies its methods",
              ("src/b.py", "Handler.run") in named, True)
        check("in Ruby too", ("src/d.rb", "Handler#run") in named, True)
        reasons = sorted(e.split(": ", 1)[1] for e in state["report"]["unreadable_files"])
        check("a UTF-16 or UTF-32 source says so, not 'binary content'",
              reasons,
              ["UTF-16LE text (byte-order mark), not scanned: re-encode it as UTF-8 "
               "to scan it",
               "UTF-32LE text (byte-order mark), not scanned: re-encode it as UTF-8 "
               "to scan it",
               "binary content, not scanned"]
              if sys.byteorder == "little" else reasons)

    # ---- exclusions: --include recovers, every exclusion is counted ---- #
    with tempfile.TemporaryDirectory() as tmp:
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        root = os.path.join(tmp, "repo")
        for rel in ("src/a.c", "vendor/v.c", "lib/vendor/w.c", "lib/vendor/build/b.c",
                    "src/legacy/old.c", "gen/g.c", "src/vendor/x.c"):
            os.makedirs(os.path.dirname(os.path.join(root, rel)), exist_ok=True)
            with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
                fh.write("int f(void)\n{\n    return 0;\n}\n")
        # golden_set.py's old cache, left in a checkout by running it from the
        # repository root: third-party code, holding sinks, that is not ours.
        os.makedirs(os.path.join(root, ".golden-cache", "X"))
        with open(os.path.join(root, ".golden-cache", "X", "b.c"), "w",
                  encoding="utf-8") as fh:
            fh.write("#include <string.h>\nvoid g(char *d, const char *s, "
                     "unsigned n)\n{\n    memcpy(d, s, n);\n}\n")
        out_dir = os.path.join(root, ".security-review")

        def run_walk(extra, out=out_dir, write=False):
            argv = ["--root", root, "--out", out, "--rules-dir", rules_dir,
                    "--jobs", "1", "--no-tree-sitter"] + extra
            state = extract(build_parser().parse_args(argv))
            if write:
                write_outputs(state, build_parser().parse_args(argv))
            rows = {row["dir"]: row for row in state["report"]["excluded_dirs"]}
            return sorted({r["file"] for r in state["functions"]}), rows

        files, rows = run_walk([], write=True)
        check("a plain run excludes and counts every default-caught directory",
              sorted(rows), ["lib/vendor", "src/vendor", "vendor"])
        check(".golden-cache is pruned like the pipeline's own directories",
              [f for f in files if f.startswith(".golden-cache")], [])
        check("and is not counted, so nothing advises --include .golden-cache",
              [d for d in rows if ".golden-cache" in d], [])
        files, rows = run_walk(["--include", "vendor"], write=True)
        check("--include works on a re-run, when the manifest lists the default",
              "vendor/v.c" in files and "vendor" not in rows, True)
        with open(os.path.join(out_dir, "manifest.json"), encoding="utf-8") as fh:
            persisted = [e["path"] for e in json.load(fh)["exclusions"]]
        check("and the rewritten manifest no longer excludes it",
              "vendor" in persisted, False)
        fresh = os.path.join(tmp, "elsewhere")
        files, rows = run_walk(["--include", "lib/vendor/"], out=fresh)
        check("--include of a nested directory recovers that directory",
              "lib/vendor/w.c" in files, True)
        check("and only that one, and not a build/ inside it",
              ("vendor/v.c" in files, "lib/vendor/build/b.c" in files,
               sorted(rows)),
              (False, False, ["lib/vendor/build", "src/vendor", "vendor"]))
        # Stage 3's declaration walk prunes by the manifest's exclusions, which
        # still say `vendor`; the include has to travel with them.
        incl = os.path.join(tmp, "incl")
        run_walk(["--include", "lib/vendor/"], out=incl, write=True)
        with open(os.path.join(incl, "manifest.json"), encoding="utf-8") as fh:
            written = json.load(fh)
        check("the manifest records the include beside the exclusion it waives",
              (written.get("included_paths"),
               "vendor" in [e["path"] for e in written["exclusions"]]),
              (["lib/vendor"], True))
        check("and the size limit, which the gate's recount passes over files by",
              written.get("max_file_bytes"), MAX_FILE_BYTES)
        manifest = os.path.join(tmp, "m.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION,
                       "exclusions": [{"path": "gen", "reason": "generated"}]}, fh)
        files, _ = run_walk(["--manifest", manifest, "--include", "gen"], out=fresh)
        check("--include undoes a manifest's own exclusion", "gen/g.c" in files, True)
        files, rows = run_walk(["--exclude", "src/legacy/*"], out=fresh)
        check("a file-glob exclusion is counted, with the pattern that did it",
              rows.get("src/legacy"),
              {"dir": "src/legacy", "files": 1, "languages": ["c"],
               "patterns": ["src/legacy/*"]})
        # The recorded reason is what the report's coverage section prints. A
        # scope stage 0 approved arrives as a manifest exclusion, and its
        # risk_if_skipped used to be dropped on the rewrite; a path given only
        # as --exclude used to be filed as build output or third-party code.
        risk = "A heap overflow in the generated parser would not be found."
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION,
                       "exclusions": [{"path": "gen",
                                       "reason": "scope profile p0: " + risk,
                                       "risk_if_skipped": risk}]}, fh)
        told = os.path.join(tmp, "told")
        run_walk(["--manifest", manifest, "--exclude", "src/legacy/*"],
                 out=told, write=True)
        with open(os.path.join(told, "manifest.json"), encoding="utf-8") as fh:
            recorded = {e["path"]: e for e in json.load(fh)["exclusions"]}
        check("a manifest exclusion keeps its reason and its risk_if_skipped",
              recorded["gen"],
              {"path": "gen", "reason": "scope profile p0: " + risk,
               "risk_if_skipped": risk})
        check("a path given only as --exclude says it came from the command line",
              recorded["src/legacy/*"],
              {"path": "src/legacy/*", "reason": "--exclude on the command line"})
        check("and a default keeps the defaults' reason",
              recorded["vendor"]["reason"],
              "default exclusion: build output or third-party code")
        # An include is a flag. The run directory's own manifest carries an
        # approved scope; one run waives it, and the next, without the flag,
        # excludes it again with its reason and risk - where it used to scan
        # gen/ for good and lose the Not scanned row.
        scoped = os.path.join(tmp, "scoped")
        os.makedirs(scoped)
        scope = {"path": "gen", "reason": "scope profile p0: " + risk,
                 "risk_if_skipped": risk}
        with open(os.path.join(scoped, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION, "exclusions": [scope],
                       "entry_points": ["src/a.c"]}, fh)

        def recorded_manifest():
            with open(os.path.join(scoped, "manifest.json"), encoding="utf-8") as fh:
                return json.load(fh)
        files, _ = run_walk(["--include", "gen"], out=scoped, write=True)
        written = recorded_manifest()
        check("--include scans a scope's directory, and does not list it as excluded",
              ("gen/g.c" in files, "gen" in [e["path"] for e in written["exclusions"]]),
              (True, False))
        check("but keeps the scope, reason and risk, aside for the next run",
              written["waived_exclusions"], [scope])
        files, _ = run_walk([], out=scoped, write=True)
        written = recorded_manifest()
        check("a re-run without the flag excludes the scope's directory again",
              "gen/g.c" in files, False)
        check("with the scope's own reason and risk_if_skipped",
              ([e for e in written["exclusions"] if e["path"] == "gen"],
               written["waived_exclusions"], written["entry_points"]),
              ([scope], [], ["src/a.c"]))
        with open(os.path.join(scoped, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION, "exclusions": ["gen/"]}, fh)
        run_walk(["--include", "gen", "--exclude", "src/legacy",
                  "--include", "src/legacy"], out=scoped, write=True)
        check("a bare pattern is kept as it was written, and a pattern only this "
              "run's --exclude gave is not kept at all",
              recorded_manifest()["waived_exclusions"], ["gen/"])
        files, _ = run_walk([], out=scoped, write=True)
        check("and it excludes again too",
              ("gen/g.c" in files,
               "gen/" in [e["path"] for e in recorded_manifest()["exclusions"]]),
              (False, True))
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION,
                       "scanned_roots": [".", "src"]}, fh)
        _, rows = run_walk(["--manifest", manifest], out=fresh)
        check("overlapping scanned roots count a pruned file once",
              rows.get("src/vendor", {}).get("files"), 1)

    # ---- extensionless files are counted, and a `#!` names a script ---- #
    # They used to leave no trace: a Python CLI shipped as bin/tool was not in
    # files_scanned, not in unsupported_extensions, not anywhere.
    with tempfile.TemporaryDirectory() as tmp:
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        root = os.path.join(tmp, "repo")
        for rel, body in (
                ("src/app.py", "def run():\n    return 0\n"),
                ("bin/tool", "#!/usr/bin/env python3\nimport subprocess\n"
                             "subprocess.call(cmd, shell=True)\n"),
                ("bin/deploy", "#!/usr/bin/env -S bash -e\neval \"$1\"\n"),
                ("Makefile", "all:\n\tcc -o app app.c\n"),
                ("LICENSE", "MIT License\n"),
                ("bin/empty", ""),
                ("vendor/hook", "#!/bin/sh\nexit 0\n"),
                ("README.md", "# app\n")):
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        fifo = rules_lib.can_mkfifo()
        if fifo:
            # Reading one blocks until something writes to it, and nothing will.
            os.mkfifo(os.path.join(root, "bin", "pipe"))
        else:
            rules_lib.skip_case("an extensionless FIFO is counted", "a named pipe")
        out = os.path.join(root, ".security-review")
        argv = ["--root", root, "--out", out, "--rules-dir", rules_dir,
                "--jobs", "1", "--no-tree-sitter"]
        state = extract(build_parser().parse_args(argv))
        write_outputs(state, build_parser().parse_args(argv))
        bare = state["report"]["extensionless_files"]
        check("every extensionless file outside an exclusion is counted, a "
              "Makefile, a LICENSE, an empty file and a FIFO included",
              bare["files"], 6 if fifo else 5)
        check("the ones a `#!` line names are counted by language",
              (bare["scripts"], bare["readable_languages"]),
              ({"python": 1, "shell": 1}, ["python"]))
        check("each named, and written as not extracted",
              bare["script_files"],
              [{"file": os.path.join("bin", "deploy"), "language": "shell",
                "extracted": False},
               {"file": os.path.join("bin", "tool"), "language": "python",
                "extracted": False}])
        check("counted is not extracted: the script produced no record",
              sorted({r["file"] for r in state["functions"]}),
              [os.path.join("src", "app.py")])
        check("an excluded extensionless script is not counted, like every "
              "other file no language selects",
              [r["file"] for r in bare["script_files"] if "vendor" in r["file"]], [])
        check("unsupported_extensions gains no nameless key",
              state["report"]["unsupported_extensions"], {".md": 1})
        with open(os.path.join(out, "manifest.json"), encoding="utf-8") as fh:
            check("and neither does the manifest's unsupported_languages",
                  json.load(fh)["unsupported_languages"], {".md": 1})
        manifest = os.path.join(tmp, "m.json")
        with open(manifest, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": SCHEMA_VERSION,
                       "scanned_roots": [".", "bin"]}, fh)
        state = extract(build_parser().parse_args(
            argv[:2] + ["--out", os.path.join(tmp, "o2")] + argv[4:]
            + ["--manifest", manifest]))
        check("overlapping scanned roots count an extensionless file once",
              (state["report"]["extensionless_files"]["files"],
               state["report"]["extensionless_files"]["scripts"]),
              (6 if fifo else 5, {"python": 1, "shell": 1}))
        # Readable by THIS run: `--language c` extracts no .py file either, so
        # renaming bin/tool would not bring it in, and the report must not say
        # it would.
        state = extract(build_parser().parse_args(
            argv[:2] + ["--out", os.path.join(tmp, "o3")] + argv[4:]
            + ["--language", "c"]))
        bare = state["report"]["extensionless_files"]
        check("a --language run counts the scripts, and reads none it excluded",
              (bare["scripts"], bare["readable_languages"]),
              ({"python": 1, "shell": 1}, []))
    # The stderr line puts what this run reads first, whatever the alphabet
    # says: awk sorts before python, and python is the one that matters.
    check("the scripts: line names the readable language first",
          scripts_note({"scripts": {"awk": 1, "python": 2, "shell": 1},
                        "readable_languages": ["python"]}),
          "scripts: 4 extensionless script(s), named by their `#!` line, were "
          "not extracted - python 2, awk 1, shell 1 (extensionless_files in "
          "extract-report.json)")
    check("and there is no line when no `#!` names a script",
          scripts_note({"scripts": {}, "readable_languages": []}), None)

    # ---- the run directory is not redirected by the tree it sits in ---- #
    # §1 and §9.2. A repository can ship `.security-review/` - its ledger is
    # committed there - so it can ship links in it, and every write this stage
    # makes used to follow them: into the source under review, or anywhere the
    # operator could write, through a planted `run.json.tmp` too.
    with tempfile.TemporaryDirectory() as tmp:
        rules_dir = os.path.join(tmp, "rules")
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, "memory-safety.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(SELFTEST_RULES, fh)
        victim = os.path.join(tmp, "victim.txt")

        def fresh_repo(name):
            root = os.path.join(tmp, name)
            os.makedirs(os.path.join(root, "src"))
            with open(os.path.join(root, "src", "a.c"), "w", encoding="utf-8") as fh:
                fh.write("void f(char *d, const char *s, int n)\n{\n"
                         "    memcpy(d, s, n);\n}\n")
            with open(victim, "w", encoding="utf-8") as fh:
                fh.write("precious\n")
            return root

        def attempt(root, out=None):
            argv = ["--root", root, "--rules-dir", rules_dir, "--jobs", "1",
                    "--no-tree-sitter", "--out",
                    out or os.path.join(root, RUN_DIR_NAME)]
            args = build_parser().parse_args(argv)
            try:
                write_outputs(extract(args), args)
            except ExtractError as exc:
                return str(exc), (2 if _usage_error(exc, args) else 1)
            return None, 0

        def untouched():
            with open(victim, encoding="utf-8") as fh:
                return fh.read() == "precious\n"
        if not rules_lib.can_symlink():
            rules_lib.skip_case("the run-directory symlink cases (ten checks)", n=10)
        else:
            root = fresh_repo("dirlink")
            os.symlink("src", os.path.join(root, RUN_DIR_NAME))
            why, code = attempt(root)
            check("a run directory that is a symlink is refused, as usage",
                  (code, why is not None and "symlink" in why and "§1" in why), (2, True))
            check("and nothing was written into the source it pointed at",
                  sorted(os.listdir(os.path.join(root, "src"))), ["a.c"])

            root = fresh_repo("sublink")
            os.makedirs(os.path.join(root, RUN_DIR_NAME))
            os.symlink(os.path.join("..", "src"),
                       os.path.join(root, RUN_DIR_NAME, "extract"))
            why, code = attempt(root)
            check("so is a symlinked directory beneath it", code, 2)
            check("and the corpus did not land in the source tree",
                  sorted(os.listdir(os.path.join(root, "src"))), ["a.c"])

            root = fresh_repo("filelink")
            os.makedirs(os.path.join(root, RUN_DIR_NAME))
            os.symlink(victim, os.path.join(root, RUN_DIR_NAME, "run.json"))
            why, code = attempt(root)
            check("so is a symlink at a file this stage writes", code, 2)
            check("and the file it pointed at is untouched", untouched(), True)

            root = fresh_repo("dangling")
            os.makedirs(os.path.join(root, RUN_DIR_NAME))
            os.symlink(os.path.join(tmp, "created-by-the-scan"),
                       os.path.join(root, RUN_DIR_NAME, ".gitignore"))
            why, code = attempt(root)
            check("a dangling .gitignore link is refused, not written through",
                  (code, os.path.lexists(os.path.join(tmp, "created-by-the-scan"))),
                  (2, False))

            root = fresh_repo("tmplink")
            os.makedirs(os.path.join(root, RUN_DIR_NAME, "extract"))
            for rel in ("run.json.tmp", os.path.join("extract", "functions.jsonl.tmp")):
                os.symlink(victim, os.path.join(root, RUN_DIR_NAME, rel))
            why, code = attempt(root)
            check("a planted `.tmp` link is never written through",
                  (code, untouched(),
                   os.path.islink(os.path.join(root, RUN_DIR_NAME, "run.json"))),
                  (0, True, False))

            root = fresh_repo("real")
            alias = os.path.join(tmp, "alias")
            os.symlink(root, alias)
            why, code = attempt(alias)
            check("--root may itself be a symlink", (why, code), (None, 0))

            root = fresh_repo("outlink")
            outside = os.path.join(tmp, "looks-outside")
            os.symlink(os.path.join(root, "src"), outside)
            why, code = attempt(root, out=outside)
            check("an --out outside the tree that resolves into it is refused",
                  (code, sorted(os.listdir(os.path.join(root, "src")))), (2, ["a.c"]))

        root = fresh_repo("nested")
        why, code = attempt(root, out=os.path.join(root, "src", RUN_DIR_NAME))
        check("a run directory anywhere in the tree but <root>/%s is refused"
              % RUN_DIR_NAME,
              (code, os.path.isdir(os.path.join(root, "src", RUN_DIR_NAME))), (2, False))

        # .gitignore: written when absent, mended when it ignores the ledger.
        root = fresh_repo("ignore")
        run_dir = os.path.join(root, RUN_DIR_NAME)
        os.makedirs(run_dir)
        with open(os.path.join(run_dir, ".gitignore"), "w", encoding="utf-8") as fh:
            fh.write("*")
        attempt(root)
        with open(os.path.join(run_dir, ".gitignore"), encoding="utf-8") as fh:
            check("a stage-0 `*` gets the ledger carve-out appended",
                  fh.read(), "*\n" + GITIGNORE_CARVE_OUT)
        mine = "# mine\n*\n!.gitignore\n!ledger/\n!ledger/**\nnotes/\n"
        with open(os.path.join(run_dir, ".gitignore"), "w", encoding="utf-8") as fh:
            fh.write(mine)
        attempt(root)
        with open(os.path.join(run_dir, ".gitignore"), encoding="utf-8") as fh:
            check("one that already carves out the ledger is left alone",
                  fh.read(), mine)
        # Each of these passed the old any-one-line test, and git ignores the
        # ledger under every one: a directory line alone, the contents alone,
        # `ledger/*` (one level, not ledger/training/), and a carve-out that a
        # later `*` overrides. Mended, and mended once.
        for partial in ("# mine\n*\n!.gitignore\n!ledger/\nnotes/\n",
                        "*\n!.gitignore\n!ledger\n", "*\n!.gitignore\n!ledger/**\n",
                        "*\n!ledger/\n!ledger/*\n", "**\n!ledger/\n",
                        "!ledger/\n!ledger/**\n*"):
            ignore = os.path.join(run_dir, ".gitignore")
            with open(ignore, "w", encoding="utf-8") as fh:
                fh.write(partial)
            attempt(root)
            attempt(root)
            with open(ignore, encoding="utf-8") as fh:
                check("a partial carve-out %r gets the whole one appended, once"
                      % partial, fh.read(),
                      partial + ("" if partial.endswith("\n") else "\n")
                      + GITIGNORE_CARVE_OUT)
        check("a carve-out read the way git reads it",
              [ledger_carved_out(text.split("\n")) for text in (
                  "*\n!ledger\n!ledger/**", "**\n!ledger/\n!ledger/**",
                  "*\n!ledger/\n!ledger/**\n*", "*.log\nnotes/", "/*\n!ledger")],
              [True, True, False, True, True])
        with open(os.path.join(run_dir, ".gitignore"), "w", encoding="utf-8") as fh:
            fh.write(GITIGNORE)
        check("run artifacts stay readable by the stages after this one",
              oct(os.stat(os.path.join(run_dir, "run.json")).st_mode & 0o777),
              oct(0o666 & ~_current_umask()))
        check("and no temporary file is left behind",
              sorted(n for n in os.listdir(run_dir) if n.endswith(".tmp")), [])
        # Before mkstemp the artifacts had open()'s mode, so an operator's
        # umask still decides it: 0077 keeps a run's source excerpts private.
        if os.name == "posix":
            saved = os.umask(0o077)
            try:
                attempt(root)
            finally:
                os.umask(saved)
            check("and a restrictive umask is honoured, not widened to 0644",
                  oct(os.stat(os.path.join(run_dir, "run.json")).st_mode & 0o777),
                  "0o600")

    # ---- git: the scanned repository's config runs nothing ---- #
    # A tree that arrives with its .git/ carries its config, and git runs the
    # programs that config names: core.fsmonitor and the hooks under `git
    # status`, a clean filter under `git status` on a file with stale stat data
    # (selected here from .git/info/attributes, which --attr-source would not
    # have covered), and gpg.program under `git log` with log.showSignature.
    if shutil.which("git") and os.name == "posix":
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.makedirs(os.path.join(repo, "src"))
            ident = ["-c", "user.name=t", "-c", "user.email=t@t",
                     "-c", "commit.gpgsign=false"]

            def git(*argv, **kw):
                return subprocess.run(["git"] + list(argv), cwd=kw.get("cwd", repo),
                                      input=kw.get("input"), stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, env=_git_env(),
                                      check=False).stdout

            markers = {k: os.path.join(tmp, "PWNED-" + k)
                       for k in ("fsmonitor", "hook", "filter", "gpg")}

            def script(name, body):
                path = os.path.join(tmp, name)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("#!/bin/sh\n" + body)
                os.chmod(path, 0o755)
                return path

            def stale(rel):
                path = os.path.join(repo, rel)
                st = os.stat(path)
                os.utime(path, (st.st_atime + 5, st.st_mtime + 5))

            git("init", "-q")
            names = ["404", os.path.join("src", "plain.c"),
                     os.path.join("src", "h\u00e9llo.c")]
            try:
                with open(os.path.join(repo, "src", "tab\tx.c"), "w",
                          encoding="utf-8") as fh:
                    fh.write("int t;\n")
                names.append(os.path.join("src", "tab\tx.c"))
            except OSError:
                pass
            for rel in names[:3]:
                with open(os.path.join(repo, rel), "w", encoding="utf-8") as fh:
                    fh.write("int a;\n")
            git("add", "-A")
            git(*ident, "commit", "-q", "-m", "one")
            for rel in names[:2]:
                with open(os.path.join(repo, rel), "a", encoding="utf-8") as fh:
                    fh.write("int b;\n")
            git("add", "-A")
            git(*ident, "commit", "-q", "-m", "two")
            head = git("rev-parse", "HEAD").strip()
            # A signed-looking commit on top, for log.showSignature to verify.
            tree = git("rev-parse", "HEAD^{tree}").strip()
            stamp = int(time.time())
            body = ("tree %s\nparent %s\nauthor t <t@t> %d +0000\n"
                    "committer t <t@t> %d +0000\ngpgsig -----BEGIN PGP SIGNATURE-----\n"
                    " \n iQEzBAABCAAdFiEE\n -----END PGP SIGNATURE-----\n\nsigned\n"
                    % (tree.decode(), head.decode(), stamp, stamp))
            signed = git("hash-object", "-t", "commit", "-w", "--stdin",
                         input=body.encode()).strip()
            git("update-ref", "HEAD", signed)
            os.makedirs(os.path.join(repo, ".git", "info"), exist_ok=True)
            with open(os.path.join(repo, ".git", "info", "attributes"), "w",
                      encoding="utf-8") as fh:
                fh.write("*.c filter=fx\n")
            hooks = os.path.join(tmp, "hooks")
            os.makedirs(hooks)
            script(os.path.join("hooks", "post-index-change"),
                   "touch %s\n" % markers["hook"])
            git("config", "core.fsmonitor", "touch %s; false" % markers["fsmonitor"])
            git("config", "core.hooksPath", hooks)
            git("config", "filter.fx.clean",
                script("clean.sh", "touch %s\ncat\n" % markers["filter"]))
            git("config", "log.showSignature", "true")
            git("config", "gpg.program", script("gpg.sh", "touch %s\n" % markers["gpg"]))
            stale(os.path.join("src", "plain.c"))

            state = git_state(repo)
            history = git_file_history(repo, time.time())
            check("no program the scanned repository's config names was run",
                  sorted(k for k, path in markers.items() if os.path.exists(path)), [])
            check("and the answers are still the repository's",
                  (state["commit"], state["available"], state["dirty"]),
                  (signed.decode(), True, False))
            os.makedirs(os.path.join(repo, RUN_DIR_NAME))
            for rel in (os.path.join(RUN_DIR_NAME, ".gitignore"),):
                with open(os.path.join(repo, rel), "w", encoding="utf-8") as fh:
                    fh.write("*\n")
            check("the pipeline's own directory does not make a checkout dirty",
                  git_state(repo)["dirty"], False)
            with open(os.path.join(repo, "src", "plain.c"), "a", encoding="utf-8") as fh:
                fh.write("int c;\n")
            check("an edit to the source does", git_state(repo)["dirty"], True)
            with open(os.path.join(repo, ".git", "index"), "w", encoding="utf-8") as fh:
                fh.write("garbage")
            broken = git_state(repo)
            check("a status git cannot answer is unknown, not clean",
                  (broken["dirty"], broken["available"]), (None, True))

            check("a file named 404 is a path, not a commit timestamp",
                  history.get("404", {}).get("commits_90d"), 2)
            check("and does not stamp the paths after it",
                  (history.get(os.path.join("src", "plain.c"), {}).get("commits_90d"),
                   history.get(os.path.join("src", "plain.c"),
                               {}).get("last_modified_days")), (2, 0))
            check("a non-ASCII path keeps its churn",
                  history.get(os.path.join("src", "h\u00e9llo.c"), {}).get("commits_90d"),
                  1)
            check("so does a path git has to quote",
                  [n for n in names if n not in history], [])
            check("a root below the repository top gets paths relative to itself",
                  "plain.c" in git_file_history(os.path.join(repo, "src"), time.time()),
                  True)

        # ---- submodules: found as git status finds them, not by a walk ---- #
        # A nested submodule's filter, run by `git status` as it recurses, in
        # the layouts a tarball can ship: submodule git dirs linked in from
        # elsewhere in the tree, and a nested submodule that keeps a real .git
        # directory. The walk of .git/modules missed the last two, and followed
        # a `.git/modules` linked to `/` over the whole machine.
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "PWNED-nested")

            def sgit(cwd, *argv):
                return subprocess.run(
                    ["git", "-c", "protocol.file.allow=always", "-c", "user.name=t",
                     "-c", "user.email=t@t", "-c", "commit.gpgsign=false"] + list(argv),
                    cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=_git_env(), check=False)
            base = os.path.join(tmp, "base")
            for name in ("inner", "mid", "outer"):
                os.makedirs(os.path.join(base, name))
                sgit(os.path.join(base, name), "init", "-q")
                with open(os.path.join(base, name, name + ".c"), "w",
                          encoding="utf-8") as fh:
                    fh.write("int %s;\n" % name)
                sgit(os.path.join(base, name), "add", "-A")
                sgit(os.path.join(base, name), "commit", "-q", "-m", "one")
            for sup, sub in (("mid", "inner"), ("outer", "mid")):
                sgit(os.path.join(base, sup), "submodule", "add", "-q",
                     os.path.join(base, sub), sub)
                sgit(os.path.join(base, sup), "commit", "-q", "-m", "sub")
            outer = os.path.join(base, "outer")
            sgit(outer, "submodule", "update", "-q", "--init", "--recursive")
            modules = os.path.join(outer, ".git", "modules")
            inner_dir = os.path.join(modules, "mid", "modules", "inner")
            # Relative git-dir links only, so the layouts below can move them.
            for cfg in (os.path.join(modules, "mid", "config"),
                        os.path.join(inner_dir, "config")):
                sgit(outer, "config", "--file", cfg, "--unset", "core.worktree")
            os.makedirs(os.path.join(inner_dir, "info"), exist_ok=True)
            with open(os.path.join(inner_dir, "info", "attributes"), "w",
                      encoding="utf-8") as fh:
                fh.write("*.c filter=fx\n")
            clean = os.path.join(tmp, "nested-clean.sh")
            with open(clean, "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\ntouch %s\ncat\n" % marker)
            os.chmod(clean, 0o755)
            sgit(outer, "config", "--file", os.path.join(inner_dir, "config"),
                 "filter.fx.clean", clean)

            def layout(name):
                where = os.path.join(tmp, name)
                shutil.copytree(base, where, symlinks=True)
                top = os.path.join(where, "outer")
                mods = os.path.join(top, ".git", "modules")
                if name == "inner-linked":
                    os.rename(os.path.join(mods, "mid", "modules"),
                              os.path.join(top, "kept"))
                    os.symlink(os.path.join(top, "kept"),
                               os.path.join(mods, "mid", "modules"))
                elif name == "all-linked":
                    os.rename(mods, os.path.join(top, "kept"))
                    os.symlink(os.path.join(top, "kept"), mods)
                elif name == "embedded":
                    dotgit = os.path.join(top, "mid", "inner", ".git")
                    os.remove(dotgit)
                    os.rename(os.path.join(mods, "mid", "modules", "inner"), dotgit)
                path = os.path.join(top, "mid", "inner", "inner.c")
                st = os.stat(path)
                os.utime(path, (st.st_atime + 5, st.st_mtime + 5))
                return top
            ran = []
            for name in ("plain", "inner-linked", "all-linked", "embedded"):
                try:
                    top = layout(name)
                except (OSError, NotImplementedError) as exc:
                    rules_lib.skip_case("submodule layout %s (%s)" % (name, exc))
                    continue
                git_state(top)
                if os.path.exists(marker):
                    ran.append(name)
                    os.remove(marker)
            check("no nested submodule's filter runs, whatever its layout", ran, [])
            subprocess.run(["git", "status", "--porcelain"],
                           cwd=os.path.join(tmp, "plain", "outer"), env=_git_env(),
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not os.path.exists(marker):
                print("  (this git's own status did not run the nested filter, so "
                      "the check above tested nothing)")

            plainrepo = os.path.join(tmp, "plainrepo")
            os.makedirs(plainrepo)
            sgit(plainrepo, "init", "-q")
            with open(os.path.join(plainrepo, "a.c"), "w", encoding="utf-8") as fh:
                fh.write("int a;\n")
            sgit(plainrepo, "add", "-A")
            sgit(plainrepo, "commit", "-q", "-m", "one")
            if rules_lib.can_symlink():
                os.symlink(os.path.abspath(os.sep), os.path.join(plainrepo, ".git", "modules"))
                started = [0]
                real_run_git = run_git

                def counting(*argv, **kw):
                    started[0] += 1
                    return real_run_git(*argv, **kw)
                globals()["run_git"] = counting
                try:
                    state = git_state(plainrepo)
                finally:
                    globals()["run_git"] = real_run_git
                check("a .git/modules linked to / is not walked: a handful of git "
                      "processes, not one per `config` file on the machine",
                      (started[0] < 20, state["dirty"]), (True, False))
            else:
                rules_lib.skip_case("a .git/modules linked to / is not walked")

            # The ledger carve-out, asked of git itself rather than of the rule
            # written down above.
            ask = os.path.join(tmp, "ask")
            os.makedirs(os.path.join(ask, RUN_DIR_NAME, "ledger", "training"))
            sgit(ask, "init", "-q")
            for rel in ("decisions.jsonl", os.path.join("training", "samples.jsonl")):
                with open(os.path.join(ask, RUN_DIR_NAME, "ledger", rel), "w",
                          encoding="utf-8") as fh:
                    fh.write("{}\n")
            disagree = []
            for text in ("*\n!.gitignore\n!ledger/\n!ledger/**\n", "*\n!ledger\n",
                         "*\n!ledger/\n", "*\n!ledger/**\n", "*\n!ledger/\n!ledger/*\n",
                         "!ledger/\n!ledger/**\n*\n", "**\n!ledger/\n!ledger/**\n",
                         "*\n!ledger\n!ledger/**\n", "*.log\n"):
                with open(os.path.join(ask, RUN_DIR_NAME, ".gitignore"), "w",
                          encoding="utf-8") as fh:
                    fh.write(text)
                kept = all(subprocess.run(
                    ["git", "check-ignore", "-q", "--no-index",
                     os.path.join(RUN_DIR_NAME, "ledger", rel)], cwd=ask,
                    env=_git_env(), stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL).returncode == 1
                    for rel in ("decisions.jsonl", "training/samples.jsonl"))
                if kept != ledger_carved_out([ln.strip() for ln in text.splitlines()]):
                    disagree.append(text)
            check("git keeps the ledger exactly when ledger_carved_out says so",
                  disagree, [])

    # ---- the shipped rules, which are what this tool actually runs ---- #
    shipped = rules_lib.default_rules_dir()
    if os.path.isdir(shipped):
        try:
            compiled = CompiledRules(rules_lib.load_rules(shipped), {})
            check("every language a shipped rule names has line rules to run",
                  sorted(lang for lang, entries in compiled.by_language.items()
                         if any(e["target"] == "line" and not e["rule"]["multiline"]
                                for e in entries)),
                  sorted(set(LANGUAGES) & {lang for e in compiled.rules
                                           for lang in e["rule"]["languages"]}))
            check("the loosened form of every shipped pattern still compiles",
                  [e["rule"]["rule_id"] for e in compiled.rules
                   if e["pattern"] and not _compiles(loosen(e["pattern"]))], [])
            # LOG-TRI is stage 3's, derived from a triage verdict that does not exist
            # yet: stage 1 compiles no entry for it, so it has no coverage row and no hit.
            check("stage 1 holds no LOG-TRI entry and still holds MEM-WFS",
                  ["LOG-TRI" in {e["rule"]["rule_id"] for e in compiled.rules},
                   "MEM-WFS" in {e["rule"]["rule_id"] for e in compiled.rules}],
                  [False, True])

            # ---- name rules match at identifier-segment boundaries ---- #
            # `\b` inside an identifier used to mean "the name starts here": `_`
            # is a word character and a camelCase hump no boundary, so LOG-001
            # never saw `pam_authenticate` and HW-007 never saw
            # `mbedtls_ecdsa_verify`. Each case is (rule, file, name, selected).
            name_cases = [
                ("LOG-001", "src/pam.c", "pam_authenticate", True),      # snake_case
                ("LOG-001", "src/a.java", "isAuthenticated", True),      # camelCase
                ("LOG-001", "src/a.c", "HTTPAuthCheck", True),           # acronym run
                ("LOG-001", "src/a.c", "login_handler", True),           # trailing \b
                ("LOG-001", "src/user_auth.c", "init", True),            # path segment
                ("LOG-001", "src/a.c", "unauthorized", False),           # mid-segment
                ("LOG-003", "src/a.c", "monkey", False),                 # mid-segment
                ("LOG-003", "src/a.c", "hotkey", False),
                ("LOG-003", "src/a.c", "get_key", True),
                ("LOG-004", "src/a.cc", "Verifier::verify", True),       # Namespace::
                ("LOG-005", "src/a.c", "load_private_key_file", True),
                ("LOG-007", "library/b.c", "mbedtls_mpi_exp_mod", True),
                ("HW-007", "src/e.c", "mbedtls_ecdsa_verify", True),
                ("HW-007", "src/e.c", "reverify", False),
                # SELFTEST_LOG_RULES's LOG-010 selects a bare `parse`; the
                # shipped one does not.
                ("LOG-010", "src/app.py", "parse", False),
                # The LOG pattern fixes, through run_name_rules: a keyword that
                # could not open inside `privkey`, spellings the patterns lacked
                # (`ecp_mul`, `ticket`), a tail that swallowed another word
                # (`authority`), and case (MPI is not `mpi_`).
                ("LOG-001", "library/x509_crt.c", "x509_get_authority_key_id", False),
                ("LOG-003", "library/ecp.c", "mbedtls_ecp_gen_privkey", True),
                ("LOG-007", "library/ecp.c", "ecp_mul_comb_after_precomp", True),
                ("LOG-007", "src/solver.c", "MPI_Allreduce", False),
                ("LOG-009", "library/ssl_ticket.c", "mbedtls_ssl_ticket_parse", True),
            ]
            got_names = {}
            for rid, path, name, _want in name_cases:
                language = rules_lib.language_of(path)
                hits = run_name_rules(path, language, ["x"],
                                      [{"file": path, "name": name, "line_start": 1}],
                                      compiled)
                got_names[(rid, path, name)] = any(h["rule_id"] == rid for h in hits)
            check("name rules are selected at identifier-segment boundaries",
                  [c for c in name_cases if got_names[c[:3]] != c[3]], [])
            check("a name rule's compiled pattern is the one rules_lib hands out",
                  [e["rule"]["rule_id"] for e in compiled.rules
                   if e["target"] == "function_or_path"
                   and e["rx"] is not rules_lib.compile_name_pattern(e["pattern"])], [])
            # rules_lib's selftest probes each sink half by compiling
            # resolve_line_pattern, so that has to be what stage 1 runs. Which
            # rules have one is pinned as well: LOG-003's and LOG-007's
            # flag_condition name call sites (ECB, a modular exponentiation) that
            # no pattern of theirs selects, and the validator settles them.
            check("a sink half's compiled pattern is resolve_line_pattern's",
                  sorted(rid for rid, half in compiled.line_halves.items()
                         if half["rx"].pattern
                         != rules_lib.resolve_line_pattern(half["rule"])[0]), [])
            check("the name rules that carry a sink half",
                  sorted(compiled.line_halves),
                  ["LOG-004", "LOG-005", "LOG-006", "LOG-008"])
            # The zero-hit diagnosis runs the loosened pattern through the same
            # matcher: a keyword only ever inside one lowercase segment is
            # `pattern-unmatchable` (the rule is blind here), one at a segment
            # start would have been a hit and is not a zero at all.
            log001 = [e for e in compiled.rules if e["rule"]["rule_id"] == "LOG-001"]
            blind, _ = loose_scan(tempfile.gettempdir(), [], log001, 1,
                                  ["src/a.c::reauthorize", "src/a.c::helper"])
            check("a keyword only inside a lowercase segment is found loosened",
                  blind.get("LOG-001"), "src/a.c::reauthorize")
            hw007 = [e for e in compiled.rules if e["rule"]["rule_id"] == "HW-007"]
            clean, _ = loose_scan(tempfile.gettempdir(), [], hw007, 1,
                                  ["src/a.c::helper", "src/a.py::reverify"])
            check("and not in a language the rule does not declare",
                  clean.get("HW-007"), None)
            # A tail a rule was narrowed to leave out is not blindness: LOG-004
            # does not select `signal`, and a tree whose only `sign` is a signal
            # handler has no signature code the rule missed.
            log004 = [e for e in compiled.rules if e["rule"]["rule_id"] == "LOG-004"]
            narrowed, _ = loose_scan(tempfile.gettempdir(), [], log004, 1,
                                     ["src/a.c::install_signal_handlers"])
            check("a narrowed-out tail is not reported as a blind rule",
                  narrowed.get("LOG-004"), None)
            # A sink half is loosened over lines the same way, leading anchors
            # only, which is what the candidate gate's I4 asks of it. LOG-004's
            # `X509_verify(?:|_cert)\b` stays narrowed, so the error string a
            # failed verify logs is no verify; LOG-008's `sig ==` inside
            # `cursig ==` is a keyword closing a lowercase segment, found. This
            # pass used to loosen only the name half: the first was recorded
            # right and refused at stage 4 (unanchored, the tail came back), the
            # second recorded `absent-from-tree` and refused the same way.
            sink_tmp = tempfile.mkdtemp()
            try:
                os.makedirs(os.path.join(sink_tmp, "src"))
                with open(os.path.join(sink_tmp, "src", "net.c"), "w") as fh:
                    fh.write("void report_peer(long r)\n{\n"
                             '    fprintf(stderr, "%s\\n", '
                             "X509_verify_cert_error_string(r));\n}\n")
                with open(os.path.join(sink_tmp, "src", "loop.c"), "w") as fh:
                    fh.write("void on_sig(int cursig)\n{\n    if (cursig == SIGINT)\n"
                             "        stop();\n}\n")
                pair = [e for e in compiled.rules
                        if e["rule"]["rule_id"] in ("LOG-004", "LOG-008")]
                sink, _ = loose_scan(sink_tmp, [("src/net.c", "c"), ("src/loop.c", "c")],
                                     pair, 1, ["src/net.c::report_peer", "src/loop.c::on_sig"],
                                     compiled.line_halves)
            finally:
                shutil.rmtree(sink_tmp, ignore_errors=True)
            check("a sink half's narrowed-out tail is not reported as a blind rule",
                  sink.get("LOG-004"), None)
            check("while a sink keyword closing a lowercase segment is found loosened",
                  sink.get("LOG-008"), "src/loop.c:3")
            # The summary says which of a name rule's two blindnesses it was,
            # from the evidence: a line is the sink half's keyword behind a
            # prefix (`php_unserialize(`), a function the name half's keyword
            # closing a segment. It once said the second of both.
            reasons = blind_reasons([
                {"rule_id": "LOG-006", "match_target": "function_or_path",
                 "zero_hit_cause": "pattern-unmatchable", "languages_present": ["c"],
                 "zero_hit_evidence": "src/net.c:5"},
                {"rule_id": "LOG-001", "match_target": "function_or_path",
                 "zero_hit_cause": "pattern-unmatchable", "languages_present": ["c"],
                 "zero_hit_evidence": "src/a.c::reauth"},
                {"rule_id": "INJ-001", "match_target": "line",
                 "zero_hit_cause": "pattern-unmatchable", "languages_present": ["c"],
                 "zero_hit_evidence": "src/q.c:9"},
                {"rule_id": "LOG-002", "match_target": "function_or_path",
                 "zero_hit_cause": "pattern-unmatchable", "languages_present": [],
                 "zero_hit_evidence": "x.py::reperm"}])
            check("the blind summary names a sink line as the line_pattern's keyword "
                  "behind a prefix, not a name's lowercase segment",
                  reasons,
                  ["LOG-006 (src/net.c:5): its line_pattern's keyword only follows a "
                   "prefix or sits inside a longer identifier on a line",
                   "LOG-001 (src/a.c::reauth): its keyword only closes a lowercase "
                   "segment of a name",
                   "INJ-001 (src/q.c:9): a wrapper is unresolved or the rule does not "
                   "fit here"])

            # ---- the line gate drops nothing, and costs nothing extra ---- #
            # The first line of each language is matched only by a branch its
            # rule gained when the table was widened (INJ-004, INJ-003, INJ-002
            # match none of them at a83fcd7); the second by no rule. Every line
            # rule is run over every line with no gate at all, and run_rules
            # must find exactly that.
            gate_lines = {
                "javascript": ["const s = fs.readFileSync(p);",
                               "let total = items.length + 1;"],
                "php": ['mysqli_query($db, "SELECT * FROM t WHERE id=" . $id);',
                        "$total = count($items) + 1;"],
                "c": ["    pid = spawn(path, argv);", "    total = count + 1;"],
            }
            for language, glines in sorted(gate_lines.items()):
                brute = []
                for idx, line in enumerate(glines):
                    for entry in compiled.for_language(language):
                        if entry["target"] == "line" and not entry["rule"]["multiline"]:
                            brute += [(entry["rule"]["rule_id"], idx + 1, m.start() + 1)
                                      for m in entry["rx"].finditer(line)]
                text = "\n".join(glines) + "\n"
                got = [(h["rule_id"], h["line"], h["column"])
                       for h in run_rules("x", language, text, text.split("\n"),
                                          compiled, False)]
                check("the %s line gate drops no hit an ungated scan finds"
                      % language, (got, bool(brute)), (brute, True))
            # A union of every pattern, put back in front of the rules as a
            # prefilter, costs 1.7x or more here (2.5x in front of the gate);
            # the gate is the rule's own search and costs about what that
            # search does. Re-timed before failing, the way rules_lib times a
            # slow pattern.
            planted = ["    size_t n%d = strlen(name) + %d; /* nothing */" % (k, k)
                       for k in range(500)]
            text = "\n".join(planted) + "\n"
            entries = [e for e in compiled.for_language("c")
                       if e["target"] == "line" and not e["rule"]["multiline"]]

            def plain():
                for line in planted:
                    for entry in entries:
                        entry["rx"].search(line)

            def gated():
                run_rules("x.c", "c", text, planted, compiled, False)
            ratio = None
            for _attempt in range(2):
                spent = {}
                for name, func in (("plain", plain), ("gated", gated)):
                    best = None
                    for _k in range(3):
                        began = time.perf_counter()
                        func()
                        took = time.perf_counter() - began
                        best = took if best is None else min(best, took)
                    spent[name] = best
                ratio = spent["gated"] / max(spent["plain"], 1e-9)
                if ratio <= 1.35:
                    break
            check("the line gate costs no more than the rules' own searches "
                  "(%.2fx)" % ratio, ratio <= 1.35, True)
        except rules_lib.RulesError as exc:
            failures.append("  FAIL the shipped rules do not load: %s" % exc)

    # ---- re-launching into the activated venv ------------------------------
    # The decision only; nothing here execs. find_spec is stubbed to "missing"
    # so the answer does not depend on whether this machine has tree-sitter.
    real_find_spec = importlib.util.find_spec
    saved = {k: os.environ.get(k) for k in ("VIRTUAL_ENV", REEXEC_FROM)}

    def environ(**values):
        for key, value in values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    with tempfile.TemporaryDirectory() as tmp:
        outside = os.path.join(tmp, "venv")
        tree = os.path.join(tmp, "repo")
        inside = os.path.join(tree, ".venv")
        for venv in (outside, inside):
            os.makedirs(os.path.join(venv, "bin"))
            py = os.path.join(venv, "bin", "python3")
            with open(py, "w") as fh:
                fh.write("#!/bin/sh\n")
            os.chmod(py, 0o755)
        try:
            importlib.util.find_spec = lambda name, *a, **k: None
            environ(VIRTUAL_ENV=outside, **{REEXEC_FROM: None})
            check("an active venv outside the tree is where a missing tree-sitter is sought",
                  active_venv_interpreter(tree),
                  os.path.join(os.path.realpath(outside), "bin", "python3"))
            environ(VIRTUAL_ENV=inside)
            check("but never a venv inside the tree under review - that interpreter "
                  "is the reviewed repository's to write", active_venv_interpreter(tree), None)
            environ(VIRTUAL_ENV=None)
            check("no venv active, nothing to re-launch into",
                  active_venv_interpreter(tree), None)
            environ(VIRTUAL_ENV=outside, **{REEXEC_FROM: "/usr/bin/python3"})
            check("a process that already re-launched does not do it again",
                  active_venv_interpreter(tree), None)
            environ(**{REEXEC_FROM: None})
            importlib.util.find_spec = lambda name, *a, **k: object()
            check("and an interpreter that already has tree-sitter keeps the run",
                  active_venv_interpreter(tree), None)
        finally:
            importlib.util.find_spec = real_find_spec
            environ(**saved)

    for line in failures:
        print(line)
    if failures:
        print("selftest: %d failure(s) of %d checks%s"
              % (len(failures), checks[0], rules_lib.skipped_note()))
        return 1
    print("selftest: OK - %d checks over c, c++, python, go, rust, javascript, "
          "java, c# and ruby fixtures, all three extractor tiers%s"
          % (checks[0], rules_lib.skipped_note()))
    return 0


def _compiles(pattern):
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def build_parser():
    ap = argparse.ArgumentParser(
        description="Stage 1: extract every function in a repository, run the "
                    "rules, and write the corpus stages 2-5 read.")
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--out", default=".security-review",
                    help="run directory (default: .security-review under --root)")
    ap.add_argument("--manifest", default=None,
                    help="recon manifest to merge: entry_points, wrapper_resolution, "
                         "physical_attacker, threat_model")
    ap.add_argument("--exclude", action="append", default=[], metavar="PATH",
                    help="exclude a path or glob (repeatable); the defaults are %s"
                         % ", ".join(DEFAULT_EXCLUDES))
    ap.add_argument("--scan-self", action="store_true",
                    help="allow --root to be the bundle's own tree; off by "
                         "default because reaching it by accident produces a "
                         "confident review of the wrong repository")
    ap.add_argument("--include", action="append", default=[], metavar="DIR",
                    help="un-exclude a directory an exclude pattern caught - a "
                         "default, --exclude, or the manifest's exclusions - "
                         "scoped to that path (lib/vendor, not every vendor/): "
                         "a project that keeps first-party code in vendor/ or "
                         "target/ is ordinary, and without this the code is "
                         "unreachable. Recorded in manifest.json as "
                         "included_paths, which stage 3's declaration walk and "
                         "the candidate gate's recount honour too")
    ap.add_argument("--language", action="append", default=[], metavar="LANG",
                    choices=list(LANGUAGES),
                    help="restrict to a language (repeatable)")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1,
                    help="worker processes (default: os.cpu_count())")
    ap.add_argument("--max-file-bytes", type=int, default=MAX_FILE_BYTES,
                    help="skip files larger than this (default: %d). Recorded "
                         "in manifest.json as max_file_bytes, so the candidate "
                         "gate's recount skips them too" % MAX_FILE_BYTES)
    ap.add_argument("--context-profile", default="default-v1",
                    help="context profile (default: default-v1)")
    ap.add_argument("--budget-tokens", type=int, default=None,
                    help="override the profile's context budget. The profile "
                         "name is unchanged, but stage 2 compares the budget "
                         "with the profile's own: a calibrated backend "
                         "downgrades to an ordering (context_profile_mismatch), "
                         "and a corpus mixing budgets is refused")
    ap.add_argument("--snapshot", nargs="?", const=SNAPSHOT_HERE, default=None,
                    metavar="DIR",
                    help="read the frozen tree snapshot.py wrote (default: "
                         "<out>/snapshot) instead of the live working tree, "
                         "while still recording every path relative to --root")
    ap.add_argument("--rules-dir", default=None,
                    help="rules directory (default: ../rules beside this tool)")
    ap.add_argument("--emit-context", default=None, metavar="FUNCTION_ID",
                    help="print the exact text context.text_sha256 was taken over")
    ap.add_argument("--no-tree-sitter", action="store_true",
                    help="do not try the optional tree-sitter import")
    ap.add_argument("--selftest", action="store_true",
                    help="run the fixtures and exit")
    return ap


def _usage_error(exc, args):
    """Exit 2 is reserved for the caller getting the invocation wrong.

    Decided on what the message is ABOUT, not on whether a substring happens to
    appear in it: the old test asked whether "manifest" was anywhere in the
    text, so a repository at /srv/manifest-tools that could not be read exited 2
    - usage - instead of 1.
    """
    text = str(exc)
    # `--snapshot:` belongs here for the same reason `--out:` does: "that
    # directory is not a snapshot of this root" is the caller getting the
    # invocation wrong, not the run failing. It was documented as exit 2 in the
    # docstring above and left out of this tuple, so every --snapshot refusal
    # exited 1 - and the selftest missed it by asserting on the exception's text
    # rather than on what main() returns, which is the only thing a wrapper sees.
    if text.startswith(("--context-profile:", "--budget-tokens:", "--out:",
                        "--snapshot:")):
        return True
    return bool(args.manifest) and text.startswith(args.manifest + ":")


# Set on the re-executed process, holding the interpreter it came from. It is
# both the loop guard and what run.json records, so a re-run is never silent.
REEXEC_FROM = "SECREVIEW_EXTRACT_REEXEC_FROM"
TREE_SITTER_MODULES = ("tree_sitter_language_pack", "tree_sitter_languages", "tree_sitter")


def active_venv_interpreter(root):
    """The activated venv's interpreter, when tree-sitter is missing here.

    An operator installs tree-sitter into a venv, activates it, starts the agent - and
    the agent's `python3` can still resolve to another interpreter. A shell that
    re-reads a login profile rebuilds PATH (macOS's path_helper puts /usr/bin
    first), and a field test saw one session find the venv and the next, set up
    the same way, not find it. The run then came back 92% heuristic and 26
    functions short.

    PATH is what gets rebuilt; VIRTUAL_ENV, which activation also sets, is not.
    So when it names a venv we are not running in, and tree-sitter cannot be
    imported here, the venv's own interpreter is the one the operator chose.

    Never into a venv inside the tree under review: the repository being audited
    could have put that interpreter there, and running it would hand the review
    to the code it is reviewing.
    """
    venv = os.environ.get("VIRTUAL_ENV")
    if not venv or os.environ.get(REEXEC_FROM):
        return None
    if any(importlib.util.find_spec(m) is not None for m in TREE_SITTER_MODULES):
        return None
    venv = os.path.realpath(venv)
    if os.path.realpath(sys.prefix) == venv:
        return None
    tree = os.path.realpath(root)
    if venv == tree or venv.startswith(tree + os.sep):
        return None
    for parts in (("bin", "python3"), ("bin", "python"), ("Scripts", "python.exe")):
        candidate = os.path.join(venv, *parts)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def main():
    args = build_parser().parse_args()
    if args.selftest:
        return selftest()
    if not args.no_tree_sitter:
        target = active_venv_interpreter(os.path.abspath(args.root))
        if target:
            print("note:   tree-sitter is not importable by %s, but VIRTUAL_ENV names "
                  "%s; re-running under that venv's interpreter, %s. Your shell "
                  "put another python3 first on PATH."
                  % (sys.executable, os.environ.get("VIRTUAL_ENV"), target),
                  file=sys.stderr)
            sys.stderr.flush()
            sys.stdout.flush()
            env = dict(os.environ)
            env[REEXEC_FROM] = sys.executable
            os.execve(target, [target, os.path.abspath(__file__)] + sys.argv[1:], env)

    root = os.path.abspath(args.root)
    # Before anything under the run directory is read - the manifest stage 1
    # merges, the snapshot it scans, the run.json --emit-context follows: the
    # scanned repository never answers for the run (rules_lib.run_dir_gate).
    shipped, gate = rules_lib.enforce_run_dir_gate(root)
    if shipped:
        return shipped
    for note in rules_lib.run_dir_notes(gate):
        print(note, file=sys.stderr)
    args.run_dir_check = rules_lib.run_dir_summary(gate)
    try:
        out_dir = check_out_dir(root, args.out)
    except ExtractError as exc:
        print("%s" % exc, file=sys.stderr)
        return 2

    if args.emit_context:
        try:
            read_root = context_read_root(
                root, out_dir,
                None if args.snapshot in (None, SNAPSHOT_HERE)
                else os.path.abspath(args.snapshot))
            text, problem = emit_context(read_root, out_dir, args.emit_context)
        except ExtractError as exc:
            print("%s" % exc, file=sys.stderr)
            return 2
        if text is None:
            print("%s" % problem, file=sys.stderr)
            return 2
        sys.stdout.write(text)
        if problem:
            print("%s" % problem, file=sys.stderr)
            return 3
        return 0

    try:
        state = extract(args)
        report = write_outputs(state, args)
    except (ExtractError, rules_lib.RulesError) as exc:
        print("%s" % exc, file=sys.stderr)
        return 2 if _usage_error(exc, args) else 1
    except OSError as exc:
        print("%s: %s" % (out_dir, exc), file=sys.stderr)
        return 1

    counts, conf = report["counts"], report["confidence"]
    print("%d function(s) across %d file(s), %d language(s) -> %s"
          % (counts["functions"], counts["files_scanned"],
             len(report["by_language"]), os.path.join(out_dir, "extract")))
    print("parse:  exact %d - heuristic %d - window %d (%.1f%% window)"
          % (conf["exact"], conf["heuristic"], conf["window"],
             100.0 * conf["window_share"]))
    print("rules:  %d hit(s) - %d emitted - %d skipped - %d deferred - "
          "%d joined to no function"
          % (counts["rule_hits"], counts["emitted"], counts["skipped"],
             counts["deferred"], counts["hits_unjoined"]))
    # Files in a language this tool reads that never reached the corpus. They
    # were counted in extract-report.json and said nowhere else, so a run whose
    # only C file was saved as UTF-16 printed a clean summary over one file
    # fewer than the tree has.
    dropped = ([str(e) for e in report.get("unreadable_files") or []]
               + ["%s: %d bytes, over the %d-byte limit"
                  % (e["file"], e["bytes"], args.max_file_bytes)
                  for e in report.get("too_large_files") or []])
    total = counts["files_unreadable"] + counts["files_too_large"]
    if total:
        print("unread: %d file(s) in a supported language were not scanned: %s%s"
              % (total, "; ".join(dropped[:3]), "; ..." if total > 3 else ""),
              file=sys.stderr)
    note = scripts_note(report["extensionless_files"])
    if note:
        print(note, file=sys.stderr)
    if counts.get("functions_unclosed"):
        print("lost:   %d function(s) were still open when their file ended - the "
              "brace walk lost count, and they are not in the corpus (see "
              "unclosed_files in extract-report.json)"
              % counts["functions_unclosed"], file=sys.stderr)
    if report["pattern_unmatchable"]:
        print("blind:  %s matched nothing while the loosened pattern matched a "
              "language that IS in this tree - %s"
              % (", ".join(report["pattern_unmatchable"]),
                 "; ".join(blind_reasons(state["coverage"]["rules"]))))
    if report["wrapper_blind"]:
        rows = {r["rule_id"]: r for r in state["coverage"]["rules"]}
        print("wrapper-blind: %s matched, and the tree holds more sites inside "
              "prefixed identifiers than the rule caught - %s. Read each "
              "example's definition and add the genuine wrappers to "
              "wrapper_resolution, then re-run stage 1; stage 4's candidate "
              "gate refuses the run otherwise (coverage_pattern_blind)"
              % (", ".join(report["wrapper_blind"]),
                 "; ".join("%s +%d (%s)" % (rid, rows[rid]["wrapper_blind_extra"],
                                            ", ".join(e.split(": ", 1)[-1] for e in
                                                      rows[rid]["wrapper_blind_examples"]))
                           for rid in report["wrapper_blind"])))
    if report["wrapper_blind_advisory"]:
        rows = {r["rule_id"]: r for r in state["coverage"]["rules"]}
        print("wrapper-blind (no wrapper_class, advisory): %s"
              % "; ".join("%s +%d" % (rid, rows[rid]["wrapper_blind_extra"])
                          for rid in report["wrapper_blind_advisory"]))
    if report["rules_language_absent"]:
        print("unused: %d rule(s) matched nothing and none of their languages is "
              "in this tree (%s)"
              % (len(report["rules_language_absent"]),
                 ", ".join(report["rules_language_absent"][:6])
                 + (", ..." if len(report["rules_language_absent"]) > 6 else "")))
    recon = report.get("recon") or {}
    if recon.get("manifest"):
        print("recon:  %s (%s) - %d entry point(s), %d wrapper(s) in %s"
              % (recon["manifest"], recon["basis"], recon["entry_points"],
                 recon["wrappers"],
                 ", ".join(recon["wrapper_classes_resolved"]) or "no class"))
    else:
        # The silence this replaces: 137 declared wrappers and 84 entry points
        # discarded because a flag was omitted, with nothing in the output to
        # say a corpus had been built on no recon at all.
        print("recon:  NO MANIFEST. No wrapper resolution, no entry points, no "
              "threat model - every rule ran as-written, so a rule naming a "
              "wrapper_class was blind to this project's own memcpy, malloc "
              "and memcmp. Stage 1's recon writes .security-review/"
              "manifest.json; this run had none.", file=sys.stderr)
    if (recon.get("threat_basis") or "").startswith("UNDETERMINED"):
        print("threat: physical_attacker is UNDETERMINED. HW-* findings are "
              "NOT capped at low, which asserts a physical attacker is in "
              "scope - an assertion nobody in this run made. Set it true or "
              "false in the manifest; until then, discount every HW-* "
              "severity in the report.", file=sys.stderr)
    parser = report["parser"]
    if not parser["tree_sitter_parsed"] and report["counts"]["functions"]:
        # Keyed on what the sentence actually claims - that no boundary in THIS
        # RUN is exact - rather than on whether a module imported. The two come
        # apart when a grammar imports and then fails on the languages present.
        if parser["tree_sitter_available"]:
            print("note:   a tree-sitter provider (%s) imported but parsed nothing, "
                  "so every boundary above is heuristic or window. %s"
                  % (parser["provider"],
                     "; ".join(parser["import_errors"][:3])
                     or "no per-language import error was recorded."))
        else:
            # Say what the "exact" count above is when no grammar ran, because
            # that number is what hid this note: module-scope records are
            # exact by construction and say nothing about a function boundary.
            print("note:   no tree-sitter grammar was importable, so every "
                  "FUNCTION boundary above is heuristic or window - the %d "
                  "`exact` record(s) are module scopes, a file's top-level code, "
                  "exact by construction. On one measured C tree the heuristic "
                  "walk found 752 functions where tree-sitter found 778; the "
                  "missing ones are absent, not degraded. `pip install "
                  "tree_sitter_language_pack` into the interpreter that runs "
                  "this tool is what makes them exact." % report["confidence"]["exact"])
    if conf["window_share"] > 0.10:
        print("note:   %.1f%% of the corpus is windows rather than functions; "
              "stage 2 cannot report a calibrated score over it (contract §6)."
              % (100.0 * conf["window_share"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
