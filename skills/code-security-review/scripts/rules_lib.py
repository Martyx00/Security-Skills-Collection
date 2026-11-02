#!/usr/bin/env python3
r"""
rules_lib.py - the one way to read the rule tables (assets/rules/*.json).

The rules are data now because a model used to decide what to skip. In one
audited run 2652 of 2750 matched hits - 96.4% - left through `skipped`, on a
clause the rule never granted, into a free-text field whose only constraint was
being non-empty. The fix is structural: a hit may be skipped only when the
rule's own `skip_pattern` matches it, and a rule with `skip_pattern: null` has no
skip path at all. That property lives in code, here, once. `compile_skip` returns
None for such a rule, so a caller that wants to skip a hit has nothing to call.

The second failure this file prevents is quieter. Stage 1's extractor runs the
patterns and `verify_findings.py` re-runs them to check the count; if each grew
its own loader, the two would eventually disagree about what a rule says, and the
checker built to catch a disagreement would be the disagreement. So both read
rules through this module, and the wrapper rewrite - extending a `\b`-anchored
libc alternation with the wrapper names stage 1 recon resolved, so that a tree
routing everything through `mbedtls_calloc` stops reading as a tree with no
allocations - happens in one function that can only ever APPEND an alternation
branch. §3's `coverage_pattern_narrowed` fails a run whose recorded pattern lost a
canonical branch, because both sides of a recount use the narrowed pattern and
agree perfectly about a tree neither looked at. Appending is the only rewrite
that cannot do that.

Wrapper names arrive from a grep over the scanned repository, which is content
under audit and therefore attacker-influenced: they are `re.escape`d and
name-shaped names are the only ones accepted. A repository that defines
`void a|.*_free(void)` does not get to widen a rule to `.*`.

Stdlib only. Python 3.8+.

It also holds the one check every reader of the run directory makes first,
`--check-run-dir`: that the scanned repository commits nothing under
.security-review/ but .gitignore and ledger/ (see run_dir_gate).

Exit codes
  0  every rule file loaded and every pattern compiled; with --check-run-dir,
     the run directory may be read
  1  a rule file is malformed, a pattern does not compile, or --selftest failed
  2  the rules directory does not exist, --show named a rule that is not there,
     or --check-run-dir was given another mode's flag
  7  --check-run-dir, or --wrappers naming a file under a run directory: the
     scanned repository commits run-directory content, git cannot say
     whether it does, or --root is not a repository under review (it is not a
     directory, or it is this installed skill or an old copy of the scanner)

Usage
  python3 rules_lib.py                       # check the shipped rules
  python3 rules_lib.py --rules-dir ../assets/rules --show MEM-002
  python3 rules_lib.py --show MEM-008 --wrappers .security-review/candidates/coverage.json
  python3 rules_lib.py --check-run-dir --root .
  python3 rules_lib.py --selftest
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys

SCHEMA_VERSION = 1

# The wrapper families stage 1 recon resolves, and the key names it records them
# under in coverage.json's `wrapper_resolution`. A rule names at most one.
#
# `read` was added after MEM-005 failed the blindness gate on libxml2: the tree
# takes its untrusted input through `xmlReadFile`/`xmlCtxtReadFile`, which a
# `\b(read|fread|...)\s*\(` alternation cannot open a match inside, so 60 real
# input sites went unexamined while the rule reported 37 and looked healthy.
# Nothing mechanical can separate those from `CreateThread` - "Thread" ends in
# "read" too - which is why the family is RESOLVED BY RECON and written down,
# not inferred.
WRAPPER_CLASSES = ("alloc", "printf", "copy", "compare", "read")

# Rule-id prefix -> the validator that owns it. Mirrors RULE_OWNER in
# verify_findings.py: a rule pasted into the wrong category file would route its
# candidates to a playbook that has no gates for them, and the finding would come
# back dismissed rather than wrong-looking.
VALIDATOR_BY_PREFIX = {
    "MEM": "sec-val-memory-safety",
    "INJ": "sec-val-injection-input",
    "CRY": "sec-val-crypto-auth",
    "OTH": "sec-val-other-hygiene",
    "LOG": "sec-val-logic-flaws",
    "HW": "sec-val-hw-hardening",
}

RULE_ID = re.compile(r"^(MEM|INJ|CRY|OTH|LOG|HW)-(\d{3}|WFS|TRI)$")

# What a wrapper name may look like. C identifiers, and nothing else.
WRAPPER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# The stage that synthesises a derived rule. `extract` (the default) is stage 1: MEM-WFS is
# written into rules.jsonl from the hits stage 1 emitted. `enrich` is stage 3: LOG-TRI is
# built from a triage verdict in scores.jsonl, which does not exist until stage 2, so stage
# 1 neither runs it nor gives it a row in coverage.json (stage1_rules).
DERIVED_AT = ("extract", "enrich")

# Where a rule's pattern is applied.
#
# The logical-flaw rules are not reliably grep-able, so their candidate set is
# built by function selection, and HW-007 anchors a multi-step sequence the same
# way. Running a name pattern over source lines instead would flag every line
# that says `key`.
#
#   line              against each source line. The default, and right for a
#                     rule whose pattern is a set of sink call names.
#   function_or_path  against "<file>::<function>". Right for the logical-flaw
#                     rules, whose patterns are name fragments - running LOG-003's
#                     `key\w*` over source lines flags every line in the tree
#                     containing the word "key".
#
# A `function_or_path` rule may ALSO carry an optional `line_pattern`, run over
# source lines as a second, separate pattern. Four rules need it, because their
# sinks and their name fragments are different regexes doing different jobs:
# LOG-005's hardcoded-secret regex (`password = "..."`) and `-----BEGIN` marker
# never appear in a function name, so the rule whose entire value is that regex
# matched nothing on any tree; LOG-004 (RSA_verify, X509_verify*), LOG-006
# (pickle.loads, ObjectInputStream) and LOG-008 (memcmp, strcmp) had the same
# half of themselves switched off.
#
# It is a second FIELD rather than a third match_target because the two halves
# must not be merged: LOG-004's name half is `verify\w*|sign\w*|cert\w*`, and
# running that over source lines produced 201 hits across 243 functions on a
# codebase with no cryptography in it - every line containing the word "verify".
# The sinks are specific and belong on lines; the fragments are vague and belong
# on names. A rule carrying both is deduplicated on (rule_id, line).
# ---- languages ----------------------------------------------------------- #
#
# One table, here, for the same reason the patterns are loaded here: stage 1
# decides which files a rule runs over, and stage 4 re-runs that rule to check
# the count. Two copies of this map drift, and the drift is invisible - the
# checker recounts a C-only rule over a Python file, finds matches stage 1 never
# looked for, and fails a correct run. That happened: HW-007 recorded 0 hits
# and a language-blind recount found 2, in app.py and web.js.
#
# `.h` is recorded as `c` and not as `cpp`. Every memory rule runs over both, so
# the choice costs nothing there; it costs a C++-only rule its headers, and that
# is cheaper than calling every C header C++ and running the C++ walk over it.
LANGUAGE_BY_EXT = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".c++": "cpp",
    ".hpp": "cpp", ".hh": "cpp", ".hxx": "cpp", ".inl": "cpp", ".ipp": "cpp",
    ".rs": "rust",
    ".go": "go",
    ".py": "python", ".pyi": "python",
    ".java": "java",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".cts": "typescript",
    ".cs": "csharp",
    ".php": "php", ".phtml": "php", ".php5": "php",
    ".rb": "ruby", ".rake": "ruby",
}
LANGUAGES = tuple(sorted(set(LANGUAGE_BY_EXT.values())))


def language_of(path):
    """The language this skill assigns a path, or None if it scans none.

    The extension decides, and nothing else. A script with no extension -
    `bin/tool` starting `#!/usr/bin/env python3` - is None here even though
    its language is one the skill reads: stage 1 COUNTS such files by their
    `#!` line (shebang_language, below) and does not extract them. Extracting
    them would take every caller of this function on both sides of the
    candidate gate's recount to agree on the content-aware answer, or a correct
    run fails `coverage_hits_mismatch`.
    """
    return LANGUAGE_BY_EXT.get(os.path.splitext(str(path))[1].lower())


# What a `#!` line's interpreter names, as a language label. The ones this
# bundle reads are its own language ids, so a reader can tell "a file in a
# language the extractor parses, that produced no record" from "a language it
# has no parser for"; the rest are display names, spelled as run_status.py's
# UNSUPPORTED_SOURCE spells the language where it lists it. An interpreter the
# map does not know is labelled by its bare name rather than dropped: an awk or
# make script is still executable text in the tree.
INTERPRETER_LANGUAGE = {
    "python": "python", "pypy": "python",
    "ruby": "ruby",
    "node": "javascript", "nodejs": "javascript", "bun": "javascript",
    "ts-node": "typescript", "tsx": "typescript", "deno": "typescript",
    "php": "php",
    "sh": "shell", "bash": "shell", "dash": "shell", "zsh": "shell",
    "ksh": "shell", "mksh": "shell", "ash": "shell",
    "perl": "Perl", "lua": "Lua", "luajit": "Lua",
    "pwsh": "PowerShell", "elixir": "Elixir", "escript": "Erlang",
    "Rscript": "R", "julia": "Julia", "groovy": "Groovy",
}

# `env` options that consume the word after them. `env -u HOME python3` runs
# python3, and reading HOME as the interpreter would name a language nobody
# wrote.
_ENV_OPTIONS_WITH_ARGUMENT = ("-u", "--unset", "-C", "--chdir", "-P")

# Launchers that run a script through a program they name, looked through to
# it: `env -S npx tsx` runs TypeScript, and a label of `npx` would call source
# this skill reads a language it has no parser for. The value is the label
# when no later word names an interpreter the map knows. `uv run --script`
# (inline script metadata, PEP 723) runs the file as Python whatever options
# come between, and so do pipx, poetry and pipenv; npx and its kin run any
# package's program, so they have no default and are labelled by their name.
_LAUNCHERS = {"uv": "python", "pipx": "python", "poetry": "python",
              "pipenv": "python", "npx": None, "pnpx": None, "bunx": None}

# A version on the end of an interpreter's name: `python3.11`, `ruby-2.7`.
_VERSION_SUFFIX = re.compile(r"[-_]?[0-9][0-9.]*\Z")

# The bare-name fallback is copied from the scanned tree into extract-report.json
# and into run_status's sentences, so it is held to the shape of a program name.
# The tree is content under audit; a `#!` line is not a channel into the report.
_INTERPRETER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_+-]{0,23}\Z")


def _interpreter_label(word):
    """INTERPRETER_LANGUAGE's label for one `#!` word, or None.

    The version comes off (`python3.11`, `ruby-2.7`), and so does a build
    variant after one (`python3-dbg`, `python3.11-config`). The variant only
    after a version, so that `node-red` is not read as node.
    """
    name = os.path.basename(word)
    head = name.split("-", 1)[0]
    for candidate in (name, head if head[-1:].isdigit() else name):
        base = _VERSION_SUFFIX.sub("", candidate) or candidate
        if base in INTERPRETER_LANGUAGE:
            return INTERPRETER_LANGUAGE[base]
    return None


def shebang_language(head):
    """The language label a file's first bytes declare with `#!`, or None.

    `head` is bytes. The `#!` must open the file. `/usr/bin/env` is looked
    through, past its options and `NAME=value` words, with `-S`,
    `-Sword` and `--split-string=word` read as the start of the command and
    the quotes `env -S` would remove removed. A launcher in _LAUNCHERS is
    looked through in turn. A version suffix is dropped (`python3.11` is
    `python`). An interpreter INTERPRETER_LANGUAGE does not know is returned by
    its bare name, or as "unknown" when that is not shaped like a program name.
    A `#!` naming no interpreter at all is None.
    """
    if not head.startswith(b"#!"):
        return None
    line = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace")
    argv = line.split()
    if not argv:
        return None
    if os.path.basename(argv[0]) == "env":
        rest, skip = [], False
        for word in argv[1:]:
            if skip:
                skip = False
            elif word in _ENV_OPTIONS_WITH_ARGUMENT:
                skip = True
            elif word.startswith("--split-string="):
                rest.append(word[len("--split-string="):])
            elif word.startswith("-S") and len(word) > 2:
                rest.append(word[2:])       # `env -Spython3 -u`: the rest is argv
            elif not word.startswith("-") and "=" not in word:
                rest.append(word)
        # `env -S "python3 -u"` splits the quoted string itself; the kernel
        # hands it over whole, so the quotes are still on the words here.
        argv = [w for w in (w.strip("\"'") for w in rest) if w]
        if not argv:
            return None
    name = os.path.basename(argv[0])
    if name in _LAUNCHERS:
        for word in argv[1:]:
            label = None if word.startswith("-") else _interpreter_label(word)
            if label:
                return label
        if _LAUNCHERS[name]:
            return _LAUNCHERS[name]
    label = _interpreter_label(name)
    if label:
        return label
    base = _VERSION_SUFFIX.sub("", name) or name
    return base if _INTERPRETER_NAME.match(base) else "unknown"


# The languages in which a `#` opens a comment. In the others it opens a
# preprocessor line (C, C++, C#), an attribute (`#[...]` in Rust) or a private
# name (`#x` in JavaScript), and a skip on `#define NOPIPE() signal(SIGPIPE,
# SIG_IGN)` is not a skip inside a comment. Stage 1 reads this when it classes a
# skipped hit `comment`, and stage 4 when it re-reads that class off the line:
# stage 1 used to call every `#` line a comment and stage 4 none, so a commented
# out `# signal.signal(signal.SIGPIPE, signal.SIG_IGN)` in a Python file failed
# the candidate gate.
HASH_COMMENT_LANGUAGES = ("php", "python", "ruby")


MATCH_TARGETS = ("line", "function_or_path")

REQUIRED_FIELDS = ("rule_id", "title", "cwe", "languages", "pattern", "multiline",
                   "why_flagged", "flag_condition", "skip_clause", "skip_pattern",
                   "wrapper_class", "high_signal", "weight")


class RulesError(Exception):
    """A rules file that cannot be trusted. Carries the file and the line."""


def _fail(path, line, msg):
    raise RulesError("%s:%s: %s" % (path, line if line else "?", msg))


def _line_of(text, needle):
    """1-based line of `needle` in `text`, or None.

    json.load throws the offsets away, so the line a bad rule sits on has to be
    recovered from the raw text. An error naming only the file sends a reader
    hunting through 50 rules for the one that is wrong.
    """
    idx = text.find(needle)
    if idx < 0:
        return None
    return text.count("\n", 0, idx) + 1


# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #

def load_category(path):
    """One <category>.json -> its rules, each with category and validator folded in."""
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise RulesError("%s: %s" % (path, exc))
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        line = getattr(exc, "lineno", None)
        _fail(path, line, "not valid JSON: %s" % exc)

    if not isinstance(doc, dict):
        _fail(path, 1, "top level is %s, expected an object" % type(doc).__name__)

    version = doc.get("schema_version")
    if version != SCHEMA_VERSION:
        # Pipeline Contract §0: a tool reading a higher schema_version than it
        # knows must refuse, not guess.
        _fail(path, _line_of(raw, '"schema_version"'),
              "schema_version is %r, this tool knows %d" % (version, SCHEMA_VERSION))

    category = doc.get("category")
    validator = doc.get("validator")
    if not category:
        _fail(path, 1, "no `category`")
    if not validator:
        _fail(path, 1, "no `validator`")
    if os.path.basename(path) != category + ".json":
        _fail(path, _line_of(raw, '"category"'),
              "category %r does not match the file name" % category)

    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        _fail(path, _line_of(raw, '"rules"'), "`rules` is missing or empty")

    out = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            _fail(path, None, "rules[%d] is not an object" % index)
        rule_id = rule.get("rule_id")
        line = _line_of(raw, '"rule_id": "%s"' % rule_id) if rule_id else None
        if not rule_id or not RULE_ID.match(str(rule_id)):
            _fail(path, line, "rules[%d] has rule_id %r" % (index, rule_id))
        for field in REQUIRED_FIELDS:
            if field not in rule:
                _fail(path, line, "%s is missing `%s`" % (rule_id, field))

        prefix = rule_id.split("-", 1)[0]
        if VALIDATOR_BY_PREFIX[prefix] != validator:
            _fail(path, line, "%s belongs to %s, but this file dispatches to %s"
                  % (rule_id, VALIDATOR_BY_PREFIX[prefix], validator))

        # A flag read by truthiness is a flag a typo inverts: "high_signal":
        # "false" is a non-empty string, so the rule joined the arbiter's
        # always-review set, and "multiline": "false" ran a line rule over the
        # whole file text. JSON has a boolean; nothing else is one.
        for field in ("multiline", "high_signal", "derived"):
            if field in rule and not isinstance(rule[field], bool):
                _fail(path, line, "%s has %s %r, expected true or false"
                      % (rule_id, field, rule[field]))

        # `languages` decides which files a rule is ever run over, and every way
        # of getting it wrong is silent. The extractor iterates the value, so a
        # bare "python" became the six languages p, y, t, h, o, n; a typo such
        # as "javascipt" named a language no file is assigned; an empty list ran
        # the rule over nothing. Each one passed this loader, and coverage.json
        # then recorded `absent-from-tree` for a rule that never looked - the
        # blind-rule-reported-as-clean outcome this skill exists to stop.
        langs = rule["languages"]
        if (not isinstance(langs, list) or not langs
                or not all(isinstance(x, str) for x in langs)):
            _fail(path, line, "%s has languages %r, expected a non-empty list of "
                  "language names" % (rule_id, langs))
        unknown = sorted(set(langs) - set(LANGUAGES))
        if unknown:
            _fail(path, line, "%s names language(s) %s that no file is assigned; "
                  "expected any of %s"
                  % (rule_id, ", ".join(unknown), " ".join(LANGUAGES)))
        if len(set(langs)) != len(langs):
            # The extractor registers the rule once per entry, so a duplicate
            # runs it twice over every file in that language.
            _fail(path, line, "%s lists a language twice: %r" % (rule_id, langs))

        if rule.get("derived"):
            if rule["pattern"] is not None:
                _fail(path, line, "%s is derived and still carries a pattern" % rule_id)
            if not rule.get("derivation"):
                _fail(path, line, "%s is derived with no `derivation` to derive it from"
                      % rule_id)
        elif not rule["pattern"]:
            _fail(path, line, "%s has no pattern and is not marked derived" % rule_id)

        # Which stage derives the rule. MEM-WFS is derived by stage 1 from the hits it
        # emitted; LOG-TRI is derived by stage 3 from a triage verdict stage 1 has never
        # seen, so stage 1 must neither run it nor write a coverage row for it. The
        # field is optional and only means something on a derived rule: a pattern rule
        # naming one would be a rule that claims to be grepped and is not.
        if "derived_at" in rule:
            if not rule.get("derived"):
                _fail(path, line, "%s carries derived_at but is not derived; the field "
                      "says which stage synthesises a derived rule" % rule_id)
            if rule["derived_at"] not in DERIVED_AT:
                _fail(path, line, "%s has derived_at %r, expected one of %s"
                      % (rule_id, rule["derived_at"], ", ".join(DERIVED_AT)))

        # `null` is a match target only for a derived rule, which is synthesised
        # rather than run. On a pattern rule it used to load - `setdefault`
        # does not replace an explicit None - and the extractor then put the
        # rule in neither the line pass nor the name pass, so coverage.json
        # called a pattern that matches the line `pattern-unmatchable`.
        target = rule.get("match_target", "line")
        if target is None and not rule.get("derived"):
            _fail(path, line, "%s has match_target null, which only a derived rule "
                  "may carry; a pattern rule runs over one of %s"
                  % (rule_id, ", ".join(MATCH_TARGETS)))
        if target is not None and target not in MATCH_TARGETS:
            _fail(path, line, "%s has match_target %r, expected one of %s"
                  % (rule_id, target, ", ".join(MATCH_TARGETS)))

        lp = rule.get("line_pattern")
        if lp is not None:
            if target != "function_or_path":
                _fail(path, line, "%s has a line_pattern but match_target %r. The "
                      "field exists to give a name-matched rule a second, "
                      "line-level pattern; on a rule already matched against "
                      "lines it would just be a second pattern nobody reads."
                      % (rule_id, target))
            try:
                re.compile(lp)
            except re.error as exc:
                _fail(path, line, "%s line_pattern does not compile: %s"
                      % (rule_id, exc))

        wclass = rule["wrapper_class"]
        if wclass is not None and wclass not in WRAPPER_CLASSES:
            _fail(path, line, "%s has wrapper_class %r, expected one of %s or null"
                  % (rule_id, wclass, ", ".join(WRAPPER_CLASSES)))

        if rule["weight"] not in (1, 2, 3):
            _fail(path, line, "%s has weight %r, expected 1-3" % (rule_id, rule["weight"]))

        # THE CRITICAL RULE, checked where it can still be fixed: a skip_pattern
        # with no written clause beside it is a skip nothing can be held against,
        # which is the 2652/2750 shape exactly.
        if rule["skip_pattern"] is not None and not rule["skip_clause"]:
            _fail(path, line, "%s has a skip_pattern and no skip_clause; "
                  "skip_reason must be the rule's own written clause" % rule_id)

        for field in ("pattern", "skip_pattern"):
            if rule[field] is None:
                continue
            try:
                re.compile(rule[field])
            except re.error as exc:
                _fail(path, line, "%s %s does not compile: %s" % (rule_id, field, exc))

        folded = dict(rule)
        folded["category"] = category
        folded["validator"] = validator
        folded["source_file"] = path
        folded["source_line"] = line
        folded.setdefault("match_target", "line")
        folded.setdefault("line_pattern", None)
        folded.setdefault("derived", False)
        folded.setdefault("threat_model", None)
        folded["derived_at"] = (rule.get("derived_at") or "extract") if rule.get("derived") \
            else None
        out.append(folded)
    return out


def load_rules(rules_dir):
    """Every rule in every <category>.json under `rules_dir`, category folded in.

    Ordered by file name then by position in the file, so two tools reading the
    same directory iterate in the same order and a diff of their output is about
    the rules rather than about the walk.
    """
    if not os.path.isdir(rules_dir):
        raise RulesError("%s: not a directory" % rules_dir)
    names = sorted(n for n in os.listdir(rules_dir) if n.endswith(".json"))
    if not names:
        raise RulesError("%s: no <category>.json files" % rules_dir)
    rules, seen = [], {}
    for name in names:
        path = os.path.join(rules_dir, name)
        for rule in load_category(path):
            rid = rule["rule_id"]
            if rid in seen:
                # Silent loss: the second definition would win, or the first, and
                # coverage invariant I1 wants exactly one entry per rule either way.
                _fail(path, rule["source_line"],
                      "%s is already defined at %s:%s"
                      % (rid, seen[rid]["source_file"], seen[rid]["source_line"]))
            seen[rid] = rule
            rules.append(rule)
    return rules


# --------------------------------------------------------------------------- #
# patterns
# --------------------------------------------------------------------------- #

def wrapper_branch(names):
    r"""`\b(?:a|b)\s*\(` for the resolved wrapper names, or None for none of them.

    The names come from a grep over the repository being audited. They are
    escaped, and anything that is not an identifier is dropped rather than
    compiled - a rule widened to `.*` by a name in the scanned tree would match
    every line in it and report that as coverage.
    """
    clean = sorted({n for n in (names or []) if WRAPPER_NAME.match(str(n))})
    if not clean:
        return None
    return r"\b(?:%s)\s*\(" % "|".join(re.escape(n) for n in clean)


def resolve_pattern(rule, wrappers=None):
    """(pattern text to run, pattern_source) for this rule and this run's wrappers.

    `pattern_source` is the value coverage.json wants: `as-written` when nothing
    was added, `wrapper-resolved` when a branch was. The rewrite APPENDS a branch
    and never edits the canonical one, which is what keeps §3's
    `coverage_pattern_narrowed` unreachable - alternation binds loosest, so
    `<canonical>|<branch>` is exactly "the canonical pattern, or this wrapper".
    """
    if rule.get("derived") or rule["pattern"] is None:
        raise RulesError("%s:%s: %s is derived - it is synthesised from the emitted "
                         "candidate files, not matched against the tree"
                         % (rule.get("source_file"), rule.get("source_line"),
                            rule["rule_id"]))
    canonical = rule["pattern"]
    wclass = rule.get("wrapper_class")
    if not wclass or not wrappers:
        return canonical, "as-written"
    branch = wrapper_branch(wrappers.get(wclass))
    if branch is None:
        return canonical, "as-written"
    return "%s|%s" % (canonical, branch), "wrapper-resolved"


def resolve_line_pattern(rule, wrappers=None):
    """(line pattern, source) for a name-matched rule's sink half, or (None, None).

    The wrapper rewrite applies here too and for the same reason: a tree that
    routes its comparisons through `mbedtls_ct_memcmp` has no bare `memcmp` for
    LOG-008's sink half to find, and the rule would record a true zero.
    """
    lp = rule.get("line_pattern")
    if lp is None:
        return None, None
    wclass = rule.get("wrapper_class")
    if not wclass or not wrappers:
        return lp, "as-written"
    branch = wrapper_branch(wrappers.get(wclass))
    if branch is None:
        return lp, "as-written"
    return "%s|%s" % (lp, branch), "wrapper-resolved"


def compile_pattern(rule, wrappers=None):
    """The rule's pattern, wrapper-extended for this run, compiled."""
    text, _ = resolve_pattern(rule, wrappers)
    try:
        return re.compile(text)
    except re.error as exc:
        raise RulesError("%s:%s: %s pattern does not compile: %s"
                         % (rule.get("source_file"), rule.get("source_line"),
                            rule["rule_id"], exc))


# ---- wrapper blindness ----------------------------------------------------- #
#
# Moved here from verify_findings.py so that stage 1 (extract_functions.py) and
# stage 4 (the candidate gate) compute one predicate from one definition. Both
# tools keep thin aliases of these names.

# The blindness test used to run only for a rule that matched nothing, which is
# the one case where it is not needed to notice anything: three rules of the
# audited run matched 0 of 36 real free sites while reporting a healthy hit count
# from the branches they could see, and a rule with hits > 0 never reached the
# test at all. A rule is blind when dropping its own \b anchors finds at least
# COVERAGE_BLIND_MIN more matches AND at least as many again as the anchored form
# found - i.e. the anchored pattern missed more than it caught.
COVERAGE_BLIND_MIN = 5
COVERAGE_BLIND_RATIO = 1.0

# A `\b(one|two|three)\b` group: a list of bare words, anchored on both sides.
# `\b(memcpy|memmove)\s*\(` is NOT one - it closes on `\s*\(`, not on `\b`.
WORD_LIST_GROUP = re.compile(r"\\b\([^)]*\|[^)]*\)\\b")


def word_list_shaped(pattern):
    r"""True when the pattern contains a bare `(a|b|c)` word list.

    The blindness scan drops `` and asks what the tree holds that the anchored
    pattern missed. On a call pattern that is a real question - `calloc\s*\(`
    cannot open a match inside `mbedtls_calloc`, and naming the wrapper is the
    remedy. On a word list it is a substring search that always wins and has no
    remedy: CRY-001 looks for `(iv|IV|nonce|salt|counter|ctr)`, and
    unanchored it matches "iv" inside a host's dot folder (where this was
    measured), inside "received", inside "derive". On one real tree that turned 6 honest matches into 214 and failed
    the run.

    `call_shaped` alone could not see this, because five of the shipped rules are
    MIXED - a word list OR a call pattern in one alternation - and it answered
    for the call half while the word half did the damage.
    """
    return bool(WORD_LIST_GROUP.search(str(pattern)))


def call_shaped(pattern):
    r"""True when a pattern looks for a call rather than a word.

    The wrapper-blindness test below is only meaningful for the first kind: `\b`
    in front of a bare libc name is exactly what a prefixed wrapper defeats. A
    pattern matching vocabulary has no wrapper to be blind to.
    """
    if not isinstance(pattern, str):
        return False
    return bool(re.search(r"\\s\*\\\(|\\\(", pattern)) and "\\b" in pattern


def top_level_branches(pattern):
    r"""The pattern's top-level `|` branches, respecting nesting and classes.

    The blindness question is asked of a whole pattern, but the shipped rules
    are MIXED: `\b(memcmp|strcmp)\s*\(|(?i:\b\w*(secret|token)\w*\b)` is a
    call pattern OR a word list in one alternation. Asking the question of the
    whole thing lets the word half set off a test only the call half has a
    remedy for, which is how five correct rules blocked a run at once.
    """
    out, depth, cls, esc, cur = [], 0, False, False, []
    for ch in pattern:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            cur.append(ch)
            esc = True
            continue
        if cls:
            cur.append(ch)
            if ch == "]":
                cls = False
            continue
        if ch == "[":
            cur.append(ch)
            cls = True
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    out.append("".join(cur))
    return [b for b in out if b]


# A branch's LEADING `\b`, the one in front of the call name, optionally behind
# an inline-flag group like `(?i:`.
LEADING_ANCHOR = re.compile(r"^(\(\?[a-zA-Z]*:)?\\b")


def drop_call_anchor(branch):
    r"""Drop only the anchor in front of the call name.

    `unanchored()` strips EVERY `\b`, which is right for asking whether a tree
    is really clean and wrong for asking about wrappers. Two ways it misfires:
    `\b(DES|TripleDES)(_|\b)` becomes `(DES|TripleDES)(_|)`, where the empty
    alternative turns the whole thing into a substring search that matches
    `XPATH_NO` + `DES` + `ET`; and `\b(printf)\s*\([^)]*\bkey\b` loses the
    anchors around `key`, an ARGUMENT word that no wrapper name can defeat, so
    `n_key` counts as a site the rule was blind to.

    Only the leading anchor is what a prefixed wrapper defeats, so only the
    leading anchor comes off.
    """
    return LEADING_ANCHOR.sub(lambda m: m.group(1) or "", branch, count=1)


def wrapper_blind_forms(pattern):
    r"""(tight, loose) for the wrapper question, or (None, None) if it does not apply.

    Keeps only the branches a wrapper could actually hide from - call-shaped and
    not a word list - and unanchors just their call names.
    """
    keep = [b for b in top_level_branches(pattern)
            if call_shaped(b) and not word_list_shaped(b)]
    if not keep:
        return None, None
    tight = "|".join(keep)
    loose = "|".join(drop_call_anchor(b) for b in keep)
    return (tight, loose) if loose != tight else (None, None)


def is_wrapper_blind(found, loose_found):
    """Is a rule blind to wrappers, given its two counts?

    `found` is what the call-shaped branches matched (wrapper_blind_forms'
    tight form), `loose_found` what they match with the call name's leading
    anchor dropped. Blind when the anchor hid at least COVERAGE_BLIND_MIN more
    sites AND at least COVERAGE_BLIND_RATIO times as many as the rule caught.
    A rule that caught nothing is not asked: zero_hit_cause speaks for it.

    The one predicate stage 1 records as `wrapper_blind` and stage 4's candidate
    gate refuses on (`coverage_pattern_blind`), so the two cannot disagree.
    """
    extra = loose_found - found
    return bool(found and extra >= COVERAGE_BLIND_MIN
                and extra >= found * COVERAGE_BLIND_RATIO)


# ---- name targets ---------------------------------------------------------- #
#
# A `function_or_path` rule runs over "<file>::<function>", and its fragments are
# anchored with `\b`. Inside an identifier `_` is a word character and a
# camelCase hump is no boundary at all, so `\bauth\w*\b` found `authenticate`
# and never `pam_authenticate`, `Curl_http_auth_act` or `isAuthenticated`: a name
# rule selected a function only when its name STARTED with the keyword. Measured
# over real corpora, LOG-001 selected 15 of curl's functions where 140 carry an
# auth segment, and HW-007 missed `mbedtls_ecdsa_verify`; two zlib field runs
# called LOG-001 and HW-007 blind for this reason alone.
#
# So a name pattern is run with every `\b` read as an identifier-SEGMENT
# boundary: an ordinary word boundary, either side of an underscore, any word
# character but `_` or a capital before an ASCII capital (`isAuth`), and the
# last capital of an acronym before a lower (`HTTPAuth`). `\B` becomes its
# negation. The rewrite happens here, once, for the extractor, its zero-hit
# diagnosis and stage 4's recount alike - the rule files keep the plain `\b` a
# person reads. A keyword inside one lowercase segment still does not match
# (`monkey`, `unauthorized`, `hotkey`), which is what keeps `key\w*` from
# selecting every function that says "monkey".
#
# The boundary's letter classes are case-sensitive on purpose, inside the rules'
# own `(?i:...)`: case-insensitively every letter pair would be a hump and the
# rule would be a substring search. It is one pass over the target with
# constant-width lookarounds, so it is as linear as the pattern it rewrites.
NAME_MATCH = "segment"
NAME_MATCH_MODES = ("plain", "segment")
# A hump is any word character that is not `_` or an ASCII capital before an
# ASCII capital, so `caféKey` splits like `cafeKey`; the capital side is ASCII
# because a camelCase convention outside ASCII is not one this skill has met.
SEGMENT_BOUNDARY = (r"(?-i:(?:\b|(?<=_)(?=[^\W_])|(?<=[^\W_])(?=_)"
                    r"|(?<=[^\W_A-Z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])))")
NOT_SEGMENT_BOUNDARY = "(?!%s)" % SEGMENT_BOUNDARY


def name_target(path, name):
    """The string a name rule runs over: `<file>::<function>`."""
    return "%s::%s" % (path, name)


def segment_pattern(text):
    r"""`text` with every `\b` a segment boundary and every `\B` its negation.

    Escapes inside a character class are copied as they are: `[\b]` is a
    backspace there, not an anchor.
    """
    out, i, n, in_class = [], 0, len(text), False
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            pair = text[i:i + 2]
            if not in_class and pair == r"\b":
                out.append(SEGMENT_BOUNDARY)
            elif not in_class and pair == r"\B":
                out.append(NOT_SEGMENT_BOUNDARY)
            else:
                out.append(pair)
            i += 2
            continue
        out.append(c)
        i += 1
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            # A `^` and then a `]` straight after the bracket are literal.
            if i < n and text[i] == "^":
                out.append("^")
                i += 1
            if i < n and text[i] == "]":
                out.append("]")
                i += 1
    return "".join(out)


_GROUP_OPEN = re.compile(r"(?:^|\||\((?:\?[aiLmsux-]*:)?)$")


def loosen_name(text):
    r"""A name pattern with its LEADING anchors dropped and its trailing ones kept.

    This is the zero-hit test for a name rule run segment-aware: was the
    family in the tree, spelled in a way the rule does not select? Dropping
    the anchor a fragment opens with answers exactly that - `auth\w*` finds
    `reauth`, `key\w*` finds `hotkey`, a keyword that CLOSES a lowercase
    segment. Dropping the trailing anchor too, as a line rule's loosening
    does, would also make a narrowed tail optional again: `sign(?:|s|ed)`
    exists so that `signal` is not a signature, and fully unanchored it
    reported every tree with a signal handler as LOG-004 gone blind. An anchor
    is leading when it opens the pattern, a group or an alternative.
    """
    out, i, n, in_class = [], 0, len(text), False
    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            pair = text[i:i + 2]
            if (not in_class and pair in (r"\b", r"\B")
                    and _GROUP_OPEN.search("".join(out))):
                i += 2
                continue
            out.append(pair)
            i += 2
            continue
        out.append(c)
        i += 1
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
            if i < n and text[i] == "^":
                out.append("^")
                i += 1
            if i < n and text[i] == "]":
                out.append("]")
                i += 1
    return "".join(out)


_NAME_RX = {}


def compile_name_pattern(text, mode=NAME_MATCH):
    """A name rule's pattern compiled the way `mode` runs it.

    `plain` is how a run before segment matching ran it; stage 4 is handed the
    mode coverage.json recorded, so it recounts a run the way that run counted.
    Raises re.error for a pattern that does not compile, like re.compile.
    """
    if mode not in NAME_MATCH_MODES:
        raise ValueError("unknown name_match %r; this skill knows %s"
                         % (mode, ", ".join(NAME_MATCH_MODES)))
    key = (text, mode)
    rx = _NAME_RX.get(key)
    if rx is None:
        rx = re.compile(segment_pattern(text) if mode == "segment" else text)
        if len(_NAME_RX) < 1024:
            _NAME_RX[key] = rx
    return rx


def hits_signature(items):
    """A digest of a function's rule hits as a scorer is shown them.

    `items` is one JSON-serialisable value per hit - score_functions.py passes
    what a backend renders of it - and the digest is order-free with
    multiplicity kept. A stage-2 score cached against a function's content
    said nothing about the hits it was scored with, and llm-triage's and
    finetuned's inputs both list them, so a matcher or rule-file change that
    gave a function a new hit served the old verdict back.
    """
    rows = sorted(json.dumps(item, sort_keys=True, default=str) for item in items)
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def compile_skip(rule):
    """The rule's skip_pattern compiled, or None when it has none.

    None is the answer for all but two of the 50 rules, and it is the point of
    the file. A hit is skipped when and only when this regex matches the hit:
    it is searched from the hit's own match to the next match of the same rule
    on that line (to the end of the line when there is none), never over the
    whole line and so never over some other call beside it - which is why a
    skip_pattern begins with the call it describes. `skip_reason` is then the
    rule's `skip_clause` verbatim, never a paraphrase and never a judgement
    about whether the hit looked interesting. Stage 4 runs the same search
    again over a sampled skip classed `skip-pattern`.
    A condition that cannot be written as a regex produces an EMITTED candidate
    carrying `flag_condition` for the validator to settle: a false candidate
    costs one cheap call, a missed sink costs the review.
    """
    pattern = rule.get("skip_pattern")
    if pattern is None:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RulesError("%s:%s: %s skip_pattern does not compile: %s"
                         % (rule.get("source_file"), rule.get("source_line"),
                            rule["rule_id"], exc))


def load_wrappers(path):
    """`wrapper_resolution` out of a coverage.json, or out of a bare mapping."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    resolution = doc.get("wrapper_resolution", doc)
    if not isinstance(resolution, dict):
        raise RulesError("%s: no `wrapper_resolution` object" % path)
    return {k: list(v or []) for k, v in resolution.items() if k in WRAPPER_CLASSES}


# --------------------------------------------------------------------------- #
# LOG-TRI: the logic pass a triage verdict derives
# --------------------------------------------------------------------------- #
#
# One predicate, here, because three tools must agree on it: stage 2 counts the
# validator calls it owes into every CORPUS SHAPE row before the person chooses a
# cut, stage 3 builds the candidates, and the candidate gate (verify_findings I8)
# recomputes the whole set from stage 1 and 2's own artefacts. Three copies would
# drift, and the drift would be invisible: a row that prices a candidate stage 3
# never writes, or a candidate the gate has no reason to refuse.
#
# The verdict is a model's reading of a function's own text, so it decides only
# WHERE a validator looks. It is never evidence, it is not copied into the
# candidate record, and the gate refuses a LOG-TRI that no recorded `high` verdict
# owes.

TRIAGE_RULE = "LOG-TRI"
TRIAGE_VERDICT = "high"
TRIAGE_VERDICTS = ("high", "medium", "low", "none")
# The four absent-control checklists a LOG-TRI validator answers, fixed here and
# never chosen from the verdict: a sentence a model wrote after reading the
# function's own comments must not be able to narrow which questions are asked.
TRIAGE_CHECKLISTS = ("LOG-001", "LOG-002", "LOG-004", "LOG-009")
# Stage 1's scope records that are not a function body. `<anonymous>`, `<arrow>` and
# `<closure>` are real bodies (an inline Express handler is exactly the case) and stay in.
TRIAGE_NOT_FUNCTIONS = ("<module>", "<window>")
# The vendored directory names in extract_functions.DEFAULT_EXCLUDES; the parity test
# holds this a subset of it. A directory the person re-included with --include still
# gets its rule-hit candidates, and no LOG-TRI.
VENDORED_DIR_NAMES = ("third_party", "vendor", "node_modules")

# code -> the sentence a queue row, run-status.json and the summary say. The first nine
# are the predicate's own, in the order it tests them; the last three are decided outside
# it (the person's opt-out, an unreadable anchor, a run scored before 0.1.3).
TRIAGE_REASONS = {
    "no-verdict": "the scoring backend records no triage verdict",
    "verdict-medium": "the triage model rated it medium, and only high derives a LOG-TRI",
    "verdict-low": "the triage model rated it low, and only high derives a LOG-TRI",
    "verdict-none": "the triage model rated it none, and only high derives a LOG-TRI",
    "has-rule-hit": "a rule matched in it, so that rule's validator reads it and no "
                    "LOG-TRI is added",
    "not-a-function": "it is a module or window scope, not a function body",
    "test-tree": "it is in the test tree",
    "generated": "it is in a generated file",
    "vendored": "it is under a vendored directory (%s)" % ", ".join(VENDORED_DIR_NAMES),
    "opted-out": "LOG-TRI was switched off (--no-triage-candidates)",
    "over-cap": "it is beyond --triage-candidates-max, which keeps the first N owed "
                "functions by rank",
    "anchor-unreadable": "no line of it could be read back to anchor a candidate on",
    "scored-before-0.1.3": "it was scored before 0.1.3, so its score record carries no "
                           "triage verdict; re-run score_functions.py --resume to derive "
                           "LOG-TRI (every verdict is cached); if the row chosen then holds "
                           "LOG-TRI validator calls, the cut is asked again",
}


def stage1_rules(rules):
    """The rules stage 1 runs or derives itself: everything but a rule stage 3 derives.

    A rule with `derived_at: "enrich"` has no pattern and no stage-1 derivation, so
    it gets no hit in rules.jsonl and no row in coverage.json (verify_findings I1
    would otherwise ask for a row that nothing can fill).
    """
    return [r for r in rules if r.get("derived_at") != "enrich"]


def _index_hits(rule_hits, keep):
    index = {}
    for hit in rule_hits or ():
        if not keep(hit):
            continue
        for key in (hit.get("function_id"), hit.get("function_key")):
            if key:
                index.setdefault(key, []).append(hit)
    return index


def index_emitted_hits(rule_hits):
    """`function_id` / `function_key` -> the EMITTED hits carrying it.

    The same index scorers/base.index_hits builds, restated for the two readers that
    cannot import the scorer package (stage 3 and the candidate gate import nothing
    from it); tests/test_triage_derived.py holds the two equal. A skipped or deferred
    hit is not evidence and joins nothing.
    """
    return _index_hits(rule_hits, lambda hit: hit.get("disposition") == "emitted")


def index_all_hits(rule_hits):
    """The same index over hits of every disposition: what a packet shows a validator of a
    function's other rule hits (a skipped or deferred one is context there, never a candidate)."""
    return _index_hits(rule_hits, lambda hit: True)


def hits_joining(fn, index):
    """The hits of `index` that join to `fn` under either of its keys, de-duplicated by
    rule_hit_id and in the order they were found (the function_id's, then the function_key's).

    One join for every reader: the emitted index gives stage 2's rows, stage 3's candidates
    and the gate's recount; the all-disposition index gives a packet's hit list, so the two
    cannot disagree about which hits belong to a function.
    """
    out, seen = [], set()
    for key in (fn.get("function_id"), fn.get("function_key")):
        if not key:
            continue
        for hit in index.get(key) or ():
            mark = hit.get("rule_hit_id") or id(hit)
            if mark in seen:
                continue
            seen.add(mark)
            out.append(hit)
    return out


def emitted_hits_joining(fn, index):
    """The emitted hits that join to `fn` under either of its keys, de-duplicated.

    scorers/base.hits_for, restated; ONE definition of "has an emitted rule hit" for
    stage 2's rows, stage 3's candidates and the gate's recount. `index` is
    index_emitted_hits.
    """
    return hits_joining(fn, index)


def selection_tier(score, point):
    """strict | loose | None, from the operating point's own cutoffs.

    enrich_candidates.tier_of, moved here so the candidate gate recomputes the
    selection with the same function stage 3 used, falling back to the cutoff score
    exactly where it does.
    """
    rank = score.get("rank")
    value = score.get("score")
    for name in ("strict", "loose"):
        band = point.get(name) or {}
        cutoff_rank = band.get("cutoff_rank")
        cutoff_score = band.get("cutoff_score")
        if isinstance(cutoff_rank, int) and isinstance(rank, int):
            if rank <= cutoff_rank:
                return name
        elif cutoff_score is not None and value is not None:
            if value >= cutoff_score:
                return name
    return None


def triage_derivation(fn, hits, verdict):
    """(owed, reason): does function `fn` owe a LOG-TRI candidate?

    `hits` are the rule hits that join to `fn` (emitted_hits_joining; anything not
    emitted is ignored), `verdict` is the score record's `triage_verdict` (None for a
    backend that records none). `reason` is None when owed, else a TRIAGE_REASONS code.
    Tested in a fixed order so the same function always gets the same reason.

    The cut and the person's opt-out are not tested here: a function is owed on the
    corpus before the cut is chosen (stage 2 prices it), and stage 3 / the gate add
    "selected" and "enabled" on top.
    """
    if verdict not in TRIAGE_VERDICTS:
        return False, "no-verdict"
    if verdict != TRIAGE_VERDICT:
        return False, "verdict-%s" % verdict
    if any(h.get("disposition") == "emitted" for h in hits or ()):
        return False, "has-rule-hit"
    if fn.get("name") in TRIAGE_NOT_FUNCTIONS or fn.get("module_scope"):
        return False, "not-a-function"
    if fn.get("in_test_tree"):
        return False, "test-tree"
    if fn.get("generated_file"):
        return False, "generated"
    directories = str(fn.get("file") or "").replace("\\", "/").split("/")[:-1]
    if any(d.lower() in VENDORED_DIR_NAMES for d in directories):
        return False, "vendored"
    return True, None


# The exclusions a high-rated function with no rule hit can still meet, in the order
# triage_derivation tests them: the tally stage 2 prints and the queue repeats.
TRIAGE_EXCLUSIONS = ("not-a-function", "test-tree", "generated", "vendored")


def triage_owed(pairs, hits_index, cap=None):
    """Who owes a LOG-TRI, over the WHOLE corpus and before any cut: a dict with

      owed             function_ids that are owed one and within `cap`, best rank first
      over_cap         function_ids owed one that `cap` leaves out, best rank first
      excluded         {code: count} for a high-rated function no rule matched that
                       triage_derivation still excludes (TRIAGE_EXCLUSIONS)
      high_without_hit owed + over_cap + every exclusion: the functions the model
                       rated high that no rule matched

    `pairs` is (function record, score record) per function, scores already ranked;
    `hits_index` is index_emitted_hits over rules.jsonl; `cap` is the person's
    --triage-candidates-max, None for no cap. The cap keeps the first N owed
    functions in rank order (rank, then function_id), a deterministic order and
    nothing more: within the no-hit functions of the high band the rank is the rules
    backend's tie-break over no hits, which says little. Stage 2 prices this set into
    every row, stage 3 builds from it, and the candidate gate recomputes it, so all
    three call here.
    """
    ranked = []
    excluded = dict.fromkeys(TRIAGE_EXCLUSIONS, 0)
    for fn, score in pairs:
        owed, reason = triage_derivation(
            fn, emitted_hits_joining(fn, hits_index), score.get("triage_verdict"))
        if owed:
            rank = score.get("rank")
            ranked.append((rank if isinstance(rank, int) and not isinstance(rank, bool)
                           else 10 ** 9, str(fn.get("function_id")), fn.get("function_id")))
        elif reason in excluded:
            excluded[reason] += 1
    ranked.sort(key=lambda item: item[:2])
    ids = [item[2] for item in ranked]
    limit = len(ids) if cap is None else max(0, int(cap))
    return {"owed": ids[:limit], "over_cap": ids[limit:], "excluded": excluded,
            "high_without_hit": len(ids) + sum(excluded.values())}


# The two flags, once. The cut stop's command line, the table's sentences and the
# handshake all name them.
TRIAGE_OFF_FLAG = "--no-triage-candidates"
TRIAGE_MAX_FLAG = "--triage-candidates-max"


def triage_cap(block):
    """The --triage-candidates-max an operating point records: a whole number of at least
    0, or None for no ceiling. Anything else (a doctored point) reads as no ceiling, in
    every tool, so the set stage 3 builds and the set the gate recomputes cannot differ
    over a malformed value."""
    value = block.get("max") if isinstance(block, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 \
        else None


def triage_applies(block):
    """Does the LOG-TRI setting mean anything for this run?

    True only for an operating-point `triage_candidates` block whose backend records
    triage verdicts. A run scored by 0.1.2 has no block at all and a `rules` or
    `finetuned` run has one that says it records none; for both, the person's
    --no-triage-candidates is accepted and changes nothing, and nothing compares it
    with what the run recorded.
    """
    return isinstance(block, dict) and block.get("records_verdicts") is True


def triage_say(block, where):
    """What the person is told about LOG-TRI before choosing a cut: a list of sentences.

    `block` is scorer-report.json's `distribution.triage_candidates`; `where` is
    "table" (the CORPUS SHAPE block under the rows) or "cut" (the cut stop's say-block).
    One function so the table and the cut say the same thing, and so a test can hold the
    words: the cost is added to every row, the rating is the model's and nothing checks
    it, and the way out is named. No recommendation either way.
    """
    if not isinstance(block, dict):
        return []
    lead = "LOG-TRI: " if where == "table" else "LOG-TRI calls: "
    if not block.get("records_verdicts"):
        basis = str(block.get("basis") or "the backend records no triage verdict")
        return [lead + "none. " + basis[:1].upper() + basis[1:]
                + ", so a selected function no rule matches gets no candidate and is "
                  "listed as selected without one, unexamined."]
    owed, over = int(block.get("owed") or 0), int(block.get("over_cap") or 0)
    if not block.get("enabled"):
        would = owed + over
        if not would:
            return ["LOG-TRI is off (%s); no function rated high is without a rule hit "
                    "anyway." % TRIAGE_OFF_FLAG]
        return ["LOG-TRI is off (%s): %d function(s) rated high that match no rule get "
                "no candidate; they are listed as selected without a candidate, "
                "unexamined." % (TRIAGE_OFF_FLAG, would)]
    if not owed and not over:
        return [lead + "no function rated high is without a rule hit, so none is added."]
    out = []
    # The count that match no rule is every function the model rated high without a hit, the
    # ones a ceiling leaves out included; how many of them become candidates is said in the
    # ceiling's own sentence below.
    total = owed + over
    each = "each" if not over else "each one the ceiling keeps"
    if where == "table":
        out.append("%s%d function(s) the triage model rated high match no rule; %s "
                   "becomes one logic-flaws candidate (a validator reads the whole "
                   "function for a missing check), and their calls are in every row "
                   "above. The rating is the model's and nothing checks it. `%s` takes "
                   "them out of every row."
                   % (lead, total, each, TRIAGE_OFF_FLAG))
    else:
        out.append("%s%d function(s) the triage model rated high match no rule, so %s "
                   "goes to a logic-flaws validator that reads the whole function for a "
                   "missing check. The rating is the model's and nothing checks it. They "
                   "are in every row; if you want a row without them, say so."
                   % (lead, total, each))
    if block.get("max") is not None or over:
        out.append("%s %d keeps the first %d of %d owed by rank, so %s "
                   "(a fixed order, not a judgement of which matter); the rest (%d) are "
                   "listed as selected without a candidate, unexamined."
                   % (TRIAGE_MAX_FLAG, int(block.get("max") or 0), owed, owed + over,
                      "1 becomes a candidate" if owed == 1 else "%d become candidates" % owed,
                      over))
    if block.get("note"):
        out.append(str(block["note"]))
    return out


def no_verdict_reason(score):
    """`no-verdict`, or `scored-before-0.1.3` for a record that predates the field.

    An llm-triage score record written by 0.1.2 has no `triage_verdict` key at all
    (a backend that records none writes the key as null), and the remedy for it is a
    free `--resume`, not a different backend. Only llm-triage records verdicts, so
    only its records can be told apart this way.
    """
    if isinstance(score, dict) and "triage_verdict" not in score \
            and score.get("backend") == "llm-triage":
        return "scored-before-0.1.3"
    return "no-verdict"


def first_text_line(lines, start, end):
    """(number, text) of the first line in [start, end] whose text is not blank, or
    (None, None). `lines` is the file as a list (line 1 is lines[0]).

    The anchor of a LOG-TRI candidate: the same "first line with text" rule stage 1
    uses for MEM-WFS. Nothing from a triage verdict (its localized_line is model
    output) chooses it.
    """
    if not lines or not isinstance(start, int) or not isinstance(end, int):
        return None, None
    for number in range(max(1, start), min(end, len(lines)) + 1):
        text = lines[number - 1]
        if text.strip():
            return number, text
    return None, None


# --------------------------------------------------------------------------- #
# the run directory, declared once
# --------------------------------------------------------------------------- #

# Contract §1 draws this as a tree, and the tree had gone stale for NINE
# artifacts: two stage-0 files, the secret inventory, the triage directory, the
# scanner run record, the dependency track, the selection reconciliation, the
# SARIF export and the two precheck files - every one of them written by a tool
# in this directory, none of them in the contract's picture of the run. Two
# separate reviews landed on the same recommendation independently, which is
# what a structural problem looks like from the outside: the tree is prose, and
# prose does not get checked.
#
# So it is data here, and tests/test_contract_parity.py reconciles §1's tree against
# it in both directions. Adding an artifact now means editing this list AND the
# contract, and forgetting either one fails that test. `<angle>` segments
# are placeholders for a name the run chooses, and a trailing `/` marks a
# directory whose contents are not enumerated.
RUN_DIR_NAME = ".security-review"

# A derived MEM-WFS finding. The memory-safety validator's whole-function pass may find a
# defect the candidate's own rule did not; the Validator Contract (section 7) has it emit an
# additional verdict with rule_id MEM-WFS and `derived_from` naming that candidate. It has
# no candidate record of its own (stage 3 emits one MEM-WFS candidate per function, and
# this one was found while validating another), so `review_run.py ingest` files it as
# findings/<candidate id>_WFS.json (`_WFS2` for a second) with that id as its
# candidate_id, and every reader that joins a finding to its candidate reads it against
# `derived_record`: the source candidate's function, hash, path and exposure, as MEM-WFS.
# ledger.py keeps a copy of both functions (it imports nothing from here); the parity test
# pins them equal.
DERIVED_RULE = "MEM-WFS"
DERIVED_SUFFIX = "_WFS"
_LOCATION = re.compile(r"^(.*):(\d+)\s*$")


def derived_record(finding, source):
    """The candidate-shaped record a derived MEM-WFS `finding` is read against, or
    None when it is not a derived finding of `source` (a candidate record).

    The record is the source's, relabelled: it keeps the function identity
    (function_key, content_hash, exposure, language), takes the finding's own id and
    rule, and takes the file, line and sink from the finding's `primary_location`
    and sink evidence, because the source's are another rule's.
    """
    if not isinstance(finding, dict) or not isinstance(source, dict):
        return None
    if finding.get("rule_id") != DERIVED_RULE or not finding.get("candidate_id"):
        return None
    if not source.get("candidate_id") or str(finding.get("derived_from")) != str(
            source["candidate_id"]):
        return None
    record = dict(source)
    for key in ("sink_text", "line", "sink_offset", "line_offset"):
        record.pop(key, None)
    record.update(candidate_id=finding["candidate_id"], rule_id=DERIVED_RULE,
                  derived_from=source["candidate_id"])
    where = finding.get("primary_location")
    hit = _LOCATION.match(where) if isinstance(where, str) else None
    if hit:
        record["file"] = hit.group(1)
        record["line"] = int(hit.group(2))
    for item in finding.get("evidence") or []:
        if isinstance(item, dict) and item.get("role") == "sink" and item.get("code"):
            record["sink_text"] = item["code"]
            break
    return record

RUN_LAYOUT = (
    (".gitignore", "stage 1", "self-ignoring, written on first write"),
    ("snapshot/", "stage 1", "the frozen working tree the run reads"),
    ("snapshot-manifest.json", "stage 1",
     "what was taken, what was refused, and why"),
    ("run.json", "stage 1",
     "run identity, tool versions, git state, provenance"),
    ("manifest.json", "stage 1",
     "roots, languages, exclusions, included paths, entry points, threat model"),
    ("scope/scope.json", "stage 0",
     "the scoping pass, if it ran; stage 1 applies an approved profile"),
    ("scope/attack-surface.md", "stage 0",
     "the analyst's briefing: the map, the open questions, the profiles"),
    ("scope/graph.json", "stage 0", "entry points and reachability, if it ran"),
    ("secrets/candidates.json", "stage 1",
     "every literal a regex can find, redacted, and where a secret enters - §4a"),
    ("secrets/inventory.json", "stage 1",
     "the sweeper's verdict per secret - §4a"),
    ("extract/functions.jsonl", "stage 1",
     "ONE RECORD PER FUNCTION IN THE REPOSITORY"),
    ("extract/rules.jsonl", "stage 1",
     "deterministic rule hits, joined to functions"),
    ("extract/coverage.json", "stage 1", "per-rule accounting"),
    ("extract/extract-report.json", "stage 1",
     "parser used, fallbacks, unparsed files"),
    ("scores/scores.jsonl", "stage 2", "one score per function"),
    ("scores/operating-point.json", "stage 2",
     "the thresholds applied, and their provenance"),
    ("scores/scorer-report.json", "stage 2", "backend, calibration, timing"),
    ("scores/partial.jsonl", "stage 2",
     "what a stopped run had already paid for; --resume reads it"),
    ("scores/triage/", "stage 2",
     "the llm-triage backend's prompts and verdicts, if that backend ran"),
    ("enrich/analyzers/<analyzer>.sarif", "stage 3",
     "raw analyzer output, copied in"),
    ("enrich/analyzer-findings.jsonl", "stage 3",
     "normalised, joined to functions"),
    ("enrich/analyzer-runs.json", "stage 3",
     "per-run completeness, never inferred from exit status"),
    ("enrich/dependencies.jsonl", "stage 3",
     "the dependency track - §7a, never adjudicated"),
    ("enrich/packets/<candidate_id>.json", "stage 3",
     "the adjudication packet"),
    ("enrich/queue.json", "stage 3", "the ranked dispatch queue"),
    ("candidates/<category>.json", "stage 3",
     "Validator Contract candidate records"),
    ("candidates/<category>-deferred.json", "stage 3",
     "what the budget cut"),
    ("candidates/coverage.json", "stage 3",
     "copied from extract/coverage.json"),
    ("candidates/coverage-selection.json", "stage 3",
     "the same rules, reconciled against what was dispatched"),
    ("findings/<candidate_id>.json", "stage 4",
     "validator verdicts; a derived MEM-WFS one is <candidate_id>_WFS.json"),
    ("arbitration/precheck.json", "stage 4",
     "mechanical results for every finding"),
    ("arbitration/queue.json", "stage 4",
     "what the arbiter must review, and why"),
    ("arbitration/ARB-<candidate_id>.json", "stage 4",
     "one adjudication per queued finding"),
    ("arbitration/summary.json", "stage 4",
     "the arbiter's summary and calibration_flag"),
    ("arbitration/cross-findings.md", "stage 4", "root-cause clusters"),
    ("arbitration/coverage-precheck.json", "gate",
     "verify_findings.py --candidates, written where it is told to"),
    ("arbitration/arbitration-precheck.json", "gate",
     "verify_findings.py --arbitration, likewise"),
    ("arbitration/report-precheck.json", "gate",
     "verify_findings.py --report, likewise"),
    ("previous/", "stage 3", "the last numbering's stage-4 artifacts, moved aside"),
    ("upstream/plan.json", "stage 5",
     "optional: the upstream check's exact requests and local-history hints, "
     "shown before anything is sent"),
    ("upstream/matches.json", "stage 5",
     "optional: possible upstream reports - hints, never verdicts"),
    ("ledger/decisions.jsonl", "stage 5", "confirm / reject / needs-info"),
    ("ledger/suppressions.jsonl", "stage 5", "author, reason, expiry"),
    ("ledger/training/samples.jsonl", "stage 5",
     "export, training-sample shaped"),
    ("dispatch/", "every stage",
     "review_run.py: the validator batch plan, each unit's reply file and "
     "dispatch record (subagent or inline)"),
    ("tmp/", "every stage",
     "scratch: the one place a unit or the orchestrator may write anything the "
     "pipeline does not (a helper script, a dump of a long file); never read as "
     "the run's own, never committed, and listed by `review_run.py hygiene`"),
    ("run-status.json", "every stage",
     "how the run went, and the exit code for it"),
    ("findings.sarif", "export",
     "SARIF 2.1.0 for a code-scanning dashboard"),
    ("REPORT.md", "stage 4",
     "the scout's report, and the artifact that leaves the building"),
)

RUN_ARTIFACTS = tuple(path for path, _stage, _why in RUN_LAYOUT)


# --------------------------------------------------------------------------- #
# the scanned repository never answers for the run
# --------------------------------------------------------------------------- #
#
# The run directory lives in the scanned tree, so the scanned repository can
# commit files into it - and every stage reads files there as this run's own.
# A committed scores/triage/answers/*.jsonl with the right digests ranks the
# repository's own functions `none` without a model being asked; a committed
# secrets/inventory.json calls its hardcoded key public; a committed
# scope/scope.json "approved" by nobody drops src/ from the scan; a committed
# snapshot/ becomes the corpus; and a `git pull` between two stages silently
# replaces local artifacts with committed ones, because the stage-1 .gitignore
# makes them expendable to git. Patching each reader would miss the next one.
#
# So there is one rule, asked of git before anything under the run directory is
# read: git may list nothing there but `.gitignore` and regular files under
# `ledger/`, the two the stage-1 .gitignore un-ignores on purpose. Anything
# else - in the index or in HEAD, in any letter case, a file, a link or a
# submodule, on disk or not - stops every reader with EXIT_SHIPPED before it
# reads or writes anything.
#
# The rule never looks at content. "Tracked but modified, so ours" was the
# obvious refinement and it is steerable: a committed .gitattributes makes a
# freshly cloned file show as modified. It is existence-blind for the same
# reason in reverse: a tracked file the operator deleted is still one a pull
# puts back. And HEAD is asked as well as the index, because `git rm --cached`
# empties the index while leaving the committed bytes on disk, untracked, where
# nothing could tell them from the run's own.
#
# A tree git does not track - a tarball, a drop with its .git/ removed, a copy
# under another repository's ignored directory - cannot be asked. The gate
# passes it with a note that says so, stage 1 records it in run.json, and the
# run's status carries it as a coverage limitation. That is a limit of the
# check, and references/guide.md "Limits" states it.

EXIT_SHIPPED = 7

# What the scanned repository MAY commit under the run directory: exactly what
# the stage-1 .gitignore un-ignores (`!.gitignore`, `!ledger/`, `!ledger/**`).
# tests/test_contract_parity.py holds the two together. Regular files only: a committed
# link or submodule is refused even here.
RUN_COMMITTED = (".gitignore", "ledger/")
_REGULAR_MODES = ("100644", "100755")

# Every tool that reads the run directory calls the gate before it does, and
# every other tool is named as exempt: tests/test_contract_parity.py fails a tool in
# neither list, so a new reader cannot be added without being classified.
RUN_DIR_READERS = (
    "extract_functions.py", "snapshot.py", "score_functions.py",
    "sweep_secrets.py", "enrich_candidates.py", "verify_findings.py",
    "ledger.py", "run_status.py", "export_sarif.py", "upstream_check.py",
    "review_run.py",
)
RUN_DIR_EXEMPT = (
    "rules_lib.py",         # the gate itself; --wrappers, the one mode that reads
                            # a run-directory file, runs the gate on it first
    "build_graph.py",       # writes scope/graph.json, opens nothing there
    "golden_set.py", "smoke_test.py",   # harnesses over their own fixtures
    "validator_twins.py",               # the same, over the twin corpus's halves
)

# Step 0, and the command SKILL.md and the stage procedures carry. The text
# writes it with `<skill folder>` for the skill's absolute path; a unit role's
# step 0 is `review_run.py unit-task`, which runs this gate before it prints
# anything, so a unit never types a path by hand.
RUN_DIR_CHECK_ARGS = ("--check-run-dir", "--root", ".")


def run_dir_check_command(python="python3 -I -B"):
    """The step-0 command line with this skill's absolute path in it."""
    return "%s %s %s" % (python, os.path.join(SKILL_ROOT, "scripts", "rules_lib.py"),
                         " ".join(RUN_DIR_CHECK_ARGS))


# Every git process this module starts runs in the scanned repository, and
# that repository's own config is the attacker's whenever the tree arrived
# with its .git/ - a vendor tarball, a CI artifact, a bug-bounty drop - or sits
# under a parent repository that did. Several keys there name a program for git
# to run: `core.fsmonitor` and the hooks are run by `git status` (and a raw
# `git ls-files` runs the fsmonitor too), a `filter.<x>.clean` that an
# attributes file selects is run by `git status` on a file whose stat data is
# stale, and `gpg.program` is run by `git log` under `log.showSignature`. Each
# of those was measured running an attacker's command during a stage-1 run,
# with the operator's privileges, before any analysis had happened - and
# `--snapshot` did not help, because these calls ask the LIVE tree by design.
# So every call carries settings of its own, which outrank the repository's
# (see extract_functions._git_filter_overrides for the filters), and runs with
# the system config off and no inherited GIT_* variable that names a
# repository - an inherited GIT_DIR would also have described some other one.
# The operator's own GIT_CONFIG_* variables are kept (see git_env), and the
# `-c` settings on the command line still outrank them. The answers on a
# benign repository do not change.
#
# This hardens the skill's tools only. The agents' own `git log` and `git
# status` in the same tree are not covered by it: a .git/ from an untrusted
# source should not be scanned in place at all.
#
# Moved here from extract_functions.py, which keeps its old names as aliases,
# so the gate - which every reader runs, some as a separate `python3 -I`
# process that can import nothing but the standard library - has it too.
GIT_OVERRIDES = (
    "core.fsmonitor=",                         # no fsmonitor hook or daemon
    "core.hooksPath=" + os.devnull,            # no hooks, post-index-change included
    "core.pager=cat",
    "diff.external=",                          # never the repository's diff program
    "log.showSignature=false",                 # never gpg.program
)


# The GIT_* variables that carry the OPERATOR's configuration rather than
# point at a repository: a CI job that sets safe.directory through
# GIT_CONFIG_COUNT/KEY/VALUE, or names its own global file. Everything else in
# GIT_* - GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE, GIT_OBJECT_DIRECTORY and the
# rest - describes some other repository and is dropped. The command line's own
# `-c` settings still come after these and win.
_GIT_ENV_KEEP = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS")
_GIT_ENV_KEEP_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")


def git_env(system=False):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") or k in _GIT_ENV_KEEP
           or k.startswith(_GIT_ENV_KEEP_PREFIXES)
           or (system and k == "GIT_CONFIG_SYSTEM")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    # `git status` would otherwise rewrite the scanned repository's index,
    # which is a write to the tree under review and is what fires the
    # post-index-change hook.
    env["GIT_OPTIONAL_LOCKS"] = "0"
    if not system:
        env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def run_git(root, args, timeout=30, config=(), system=False):
    """git's stdout as bytes, or None when git is missing, fails or times out.
    See the comment above for what every call carries."""
    argv = ["git", "--no-pager"]
    for item in GIT_OVERRIDES + tuple(config):
        argv += ["-c", item]
    try:
        out = subprocess.run(argv + list(args), cwd=root, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             env=git_env(system), timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


def git_trusted_config():
    """`-c` items carried over from config the OPERATOR controls.

    GIT_CONFIG_NOSYSTEM drops the system file along with the repository's, and
    with it any `safe.directory` an administrator put there - which is how a CI
    image commonly lets root read a checkout owned by another user. Those
    entries are read on their own, from outside the scanned tree, and handed
    back on the command line, where git honours them."""
    raw = run_git(os.path.abspath(os.sep),
                  ["config", "--system", "-z", "--get-all", "safe.directory"],
                  system=True)
    return ["safe.directory=" + os.fsdecode(entry)
            for entry in (raw or b"").split(b"\0") if entry]


def _git_complaint(root, args, config):
    """The first line git wrote to stderr for `args`, for a refusal to quote."""
    argv = ["git", "--no-pager"]
    for item in GIT_OVERRIDES + tuple(config):
        argv += ["-c", item]
    try:
        out = subprocess.run(argv + list(args), cwd=root, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                             env=git_env(), timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return str(exc)
    lines = [line for line in os.fsdecode(out.stderr).splitlines() if line.strip()]
    return _printable(lines[0]) if lines else ""


def enclosing_git(root):
    """The first `.git` at or above `root` on root's filesystem - where git looks.

    None when there is none, and then no git process is started at all. The
    walk is over the RESOLVED path, because git discovers from the physical
    working directory: `--root ~/proj`, a link into a checkout's subdirectory,
    has no `.git` among its lexical parents and every one among its real ones.
    """
    here = os.path.realpath(root)
    try:
        dev = os.stat(here).st_dev
    except OSError:
        return None
    while True:
        probe = os.path.join(here, ".git")
        if os.path.lexists(probe):
            return probe
        parent = os.path.dirname(here)
        if parent == here:
            return None
        try:
            if os.stat(parent).st_dev != dev:
                return None
        except OSError:
            return None
        here = parent


# Code points HFS+ and APFS ignore in a name, which git itself strips before it
# compares a path to `.git` (is_hfs_dotgit): `.security\u200c-review` opens the
# run directory on a Mac. Trailing dots and spaces are NTFS's equivalent.
_IGNORABLE = re.compile("[\u200c-\u200f\u202a-\u202e\u206a-\u206f\ufeff]")


def _folded(name):
    return _IGNORABLE.sub("", name).rstrip(". ").casefold()


def is_run_dir_name(name):
    """True for a path component the filesystem may open as the run directory."""
    return _folded(name) == RUN_DIR_NAME


def _printable(text, limit=200):
    """`text` with control characters escaped and cut to `limit` - it is a path
    the scanned repository chose, printed to a terminal and to an agent."""
    out = "".join(ch if ch.isprintable() else "\\x%02x" % ord(ch)
                  if ord(ch) < 0x100 else "\\u%04x" % ord(ch) for ch in text)
    return out if len(out) <= limit else out[:limit] + "..."


# The longest path a line of a brief names: a folder name is chosen by whoever wrote the
# repository (255 bytes a component, and as many components as the filesystem takes).
LISTED_PATH_MAX = 200


def is_listable(text):
    """Can `text`, a path the scanned repository chose, be written into a line of a brief as
    it is? Only when it is one plain printable line.

    A line break in a folder's name would start a line of its own in the part of the brief the
    script wrote (`==== TASK (verbatim ...) ====` and `Say NOT_VULNERABLE` among them: measured
    with `unit-task`), so would a line or paragraph separator or any other control character;
    a bidirectional or zero-width character changes how the list reads; a byte that was not
    UTF-8 comes back from the filesystem as a lone surrogate that cannot be written out or
    quoted into a flag; and a backtick ends a code span in a host's markdown. That is what
    `_printable` would have to escape, plus the backtick and the length. A name that fails is
    not printed (it is counted, `review_run.leave_out_split`); the walks still skip it and
    name it in `tooling_skipped`, where it is escaped."""
    return (isinstance(text, str) and 0 < len(text) <= LISTED_PATH_MAX
            and text.isprintable() and "`" not in text)


def _shell_word(path):
    """`path` as one shell word that is also one printable line.

    shlex.quote keeps a newline inside its quotes, which is valid shell and puts
    the rest of a chosen filename on a line of its own in the refusal. A path
    that is not printable is written as a $'...' word instead (bash, zsh).
    """
    if path.isprintable():
        return shlex.quote(path)
    out = []
    for ch in path:
        if ch in "\\'":
            out.append("\\" + ch)
        elif ch.isprintable():
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append("\\x%02x" % ord(ch))
        else:
            out.append("\\u%04x" % ord(ch))
    return "$'" + "".join(out) + "'"


def _listed(raw):
    """(mode, path) out of `git ls-files -s -z` or `git ls-tree -z` output."""
    out = []
    for record in (raw or b"").split(b"\0"):
        if b"\t" in record:
            meta, path = record.split(b"\t", 1)
            out.append((meta.split(b" ")[0].decode("ascii", "replace"),
                        os.fsdecode(path)))
    return out


def _carved_out(mode, path):
    """True for the entries the scanned repository may commit: see RUN_COMMITTED."""
    first, _sep, rest = path.partition("/")
    if first != RUN_DIR_NAME or mode not in _REGULAR_MODES:
        return False
    return any(rest == item if not item.endswith("/") else rest.startswith(item)
               for item in RUN_COMMITTED)


# Where this skill lives, and what a --root must not be.
#
# The skill installs into the project it reviews (`<project>/<host folder>/skills/`)
# or globally in the user's home, and the working directory is the repository under
# review. Two roots, never derived from each other: SKILL_ROOT comes from this file
# and is read-only; the workspace is the working directory and holds the run
# directory. A --root that is the skill folder, or inside it, would review the
# scanner instead of a repository, and so would one that is an old copy of the
# scanner (the skill this skill replaces, which sat in a dot folder of the
# project): the gate refuses both the way it refuses a run directory it cannot
# trust. Identity, not marker files: a scanned repository that commits a folder
# shaped like the scanner cannot opt itself out of review, because the old-copy
# test only looks inside dot folders, and every path it skips is listed in the
# extractor's report.
SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
BUNDLE_DIR = SKILL_ROOT                       # the name older callers know it by

# What this very file says about itself on its first line. A copy of the tool that
# is not the running one - the skill this skill replaces, or the same skill
# installed for another host in the same project - is recognised by it rather
# than by a host's folder name. The phrase is in both generations of this file.
# `--selftest` pins that this file still carries it.
TOOL_SIGNATURE = "rules_lib.py - the one way to read"
_SIGNATURE_HEAD_BYTES = 4096
# A dot folder is looked into for a copy of the tool only this far: a cache folder
# with thousands of entries must not turn every walk into a crawl.
_BUNDLE_SCAN_LIMIT = 256


def carries_tool_signature(folder):
    """Does `folder` hold a copy of this tool (`scripts/` or `tools/rules_lib.py`)?"""
    for sub in ("scripts", "tools"):
        path = os.path.join(folder, sub, "rules_lib.py")
        try:
            if not os.path.isfile(path):
                continue
            with open(path, "rb") as fh:
                head = fh.read(_SIGNATURE_HEAD_BYTES)
        except OSError:
            continue
        if TOOL_SIGNATURE.encode("ascii") in head:
            return True
    return False


def _dot_ancestor(root, path):
    """True when a component of `path` below `root` (its own name included) is a dot
    folder: where an installed tool is dropped (`<host folder>/skills/<name>`)."""
    rel = os.path.relpath(os.path.abspath(path), os.path.abspath(root))
    parts = [p for p in rel.replace("\\", "/").split("/") if p]
    return any(p.startswith(".") and p not in (".", "..") for p in parts)


def _is_installed_skill(parent, name):
    """Is `parent/name` a skill installed for a host: `<dot folder>/skills/<name>/`
    holding a SKILL.md?

    That is what an Agent Skill is, and where every host that loads them keeps
    them. The `skills` folder itself is not tooling: a repository's own code can
    sit in `.github/skills/` or `.tools/skills/`, and only a child that is a skill
    is recognised. The other installed skills carry rule-shaped text and planted
    fixtures of their own, which is why they are left out of a walk.
    """
    if os.path.basename(os.path.abspath(parent)) != "skills":
        return False
    holder = os.path.basename(os.path.dirname(os.path.abspath(parent)))
    if not holder.startswith(".") or holder in (".", ".."):
        return False
    try:
        return os.path.isfile(os.path.join(parent, name, "SKILL.md"))
    except OSError:
        return False


# The run folders of the other skills of this portfolio. They are installed beside this
# one in a project and leave their output in the workspace: report-triage keeps the report
# it is judging (a quarantined, possibly embargoed copy) in `.report-triage/`,
# sbom-recovery writes `sbom-out/` (a full run) and `sbom-out-pilot/` (a pilot), and
# binary-vuln-research keeps `.binary-vuln-research/` (findings that quote decompiled code and
# redacted secrets, and vendor archives it extracted under `work/`). A file in
# one of them is a copy of the product or a text about it, never the product: a walk that
# entered them doubled every function with a twin, reported the quarantined report's tokens
# as hardcoded secrets, and gave a validator's caller search a copy to find. A
# stride-design-review run folder has no fixed name (the person picks `--run-root`), so it
# is recognised the way that skill finds it: a `run-manifest.json` whose `envelope` names a
# `runRoot` and a `docsRoot`. This skill's own run folder is not here (`RUN_DIR_NAME`,
# pruned by every walk on its own). report-triage keeps the equivalent list
# (`SIBLING_RUN_DIRS` in its scripts), with this skill's run folder in place of its own.
SIBLING_RUN_DIRS = (".report-triage", "sbom-out", "sbom-out-pilot", ".binary-vuln-research")
# The reason the snapshot's manifest gives for leaving one out (snapshot.REASONS).
SIBLING_RUN_REASON = "sibling-run-directory"
SIBLING_RUN_WORDS = "the run folder of another skill"
# A manifest is a few KB; a file past this is not read.
_MANIFEST_MAX_BYTES = 4 * 1024 * 1024
# How many folders `sibling_run_dirs_present` looks into: the workspace root's own
# entries, then the children of the non-dot ones.
_SIBLING_SCAN_LIMIT = 256
_DESIGN_RUN_SCAN_SKIP = frozenset((
    "node_modules", "dist", "build", "out", "target", "vendor", "__pycache__"))


def holds_design_run(folder):
    """Is `folder` the run folder of a stride-design-review run?"""
    path = os.path.join(folder, "run-manifest.json")
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > _MANIFEST_MAX_BYTES:
            return False
        with open(path, "rb") as fh:
            data = json.loads(fh.read().decode("utf-8-sig", "replace"))
    except (OSError, ValueError):
        return False
    envelope = data.get("envelope") if isinstance(data, dict) else None
    return (isinstance(envelope, dict) and "runRoot" in envelope
            and "docsRoot" in envelope)


def is_sibling_run_dir(folder):
    """Is `folder` the run folder of another skill (`SIBLING_RUN_DIRS`, a design run)?"""
    return (os.path.basename(os.path.normpath(folder)) in SIBLING_RUN_DIRS
            or holds_design_run(folder))


def sibling_run_dirs_present(root):
    """The run folders of other skills that exist under `root`, as paths relative to it.

    Looked for where those skills put them (the workspace root, and a design run one level
    further down), not by walking the tree: it is the list a validator is told to leave out
    of its searches (`review_run.tooling_paths`), to which `review_run.leave_out_split` adds what
    the walks recorded at any depth. The names are the repository's to choose and come back as
    they are; whatever prints them goes through `is_listable` first."""
    found = []
    try:
        with os.scandir(root) as entries:
            top = sorted(e.name for e in entries
                         if e.is_dir(follow_symlinks=False))[:_SIBLING_SCAN_LIMIT]
    except OSError:
        return found
    for name in top:
        if name in SIBLING_RUN_DIRS or (not name.startswith(".")
                                        and holds_design_run(os.path.join(root, name))):
            found.append(name)
            continue
        if name.startswith(".") or name in _DESIGN_RUN_SCAN_SKIP:
            continue
        try:
            with os.scandir(os.path.join(root, name)) as entries:
                children = sorted(e.name for e in entries
                                  if e.is_dir(follow_symlinks=False)
                                  and not e.name.startswith("."))[:_SIBLING_SCAN_LIMIT]
        except OSError:
            continue
        for child in children:
            if holds_design_run(os.path.join(root, name, child)):
                found.append("%s/%s" % (name, child))
    return found


def tooling_reason(root, parent, name, skill_root=None):
    """Why `parent/name` is this scanner's own tooling, or another skill's run folder,
    not the product, in a few words; "" when it is not.

    Four cases, none of which names a host:

    * this very skill, wherever it is installed under the scanned tree (compared
      by real path, so a link to it is the same folder);
    * a skill installed for a host: a directory holding a SKILL.md directly inside
      `<dot folder>/skills/`. Not the `skills` folder around it, and not a
      folder in it without a SKILL.md: a product's own code there is scanned; and
    * a directory inside a dot directory that holds a copy of this tool
      (`scripts/rules_lib.py` or `tools/rules_lib.py`, recognised by
      TOOL_SIGNATURE): the skill this skill replaces, or this skill installed a
      second time for another host. Not the dot directory around it - a
      repository's own host configuration next to it is still scanned; and
    * the run folder of another skill of this portfolio (`SIBLING_RUN_DIRS`, or a
      folder holding a stride-design-review `run-manifest.json`): a quarantined
      report, a verdict file or a copy of the product that is not the product.

    The last three are recognised by a name or a file anyone can write: a SKILL.md, a
    line of this file's own source, a folder called `sbom-out`. A tree that planted
    one would hide that folder from stage 1. So every walk lists each folder it
    skipped on these grounds (`tooling_skipped` in extract-report.json, and the
    snapshot's `scanner-tooling` and `sibling-run-directory` exclusions, which the
    extractor copies there), and the summary says so.
    """
    full = os.path.join(parent, name)
    real_skill = os.path.realpath(skill_root or SKILL_ROOT)
    if (os.path.islink(full) or name == os.path.basename(real_skill)) \
            and os.path.realpath(full) == real_skill:
        return "the running skill"
    if _is_installed_skill(parent, name):
        return "an installed skill (it holds a SKILL.md)"
    if _dot_ancestor(root, full) and carries_tool_signature(full):
        return "a copy of this scanner"
    if name in SIBLING_RUN_DIRS or holds_design_run(full):
        return SIBLING_RUN_WORDS
    return ""


def tooling_exclusion_reason(why):
    """The snapshot manifest's `reason` for a `tooling_reason` answer: `sibling-run-directory`
    for another skill's run folder, `scanner-tooling` for the scanner's own."""
    return SIBLING_RUN_REASON if why == SIBLING_RUN_WORDS else "scanner-tooling"


def is_tooling_dir(root, parent, name, skill_root=None):
    """Is the directory `parent/name` this scanner's own tooling? See `tooling_reason`."""
    return bool(tooling_reason(root, parent, name, skill_root))


def prune_tooling(root, dirpath, dirnames, found=None, skill_root=None):
    """Remove the tooling directories from `dirnames` in place (an os.walk step).

    `found`, when given, is a list that receives (relative path, reason) for each
    directory removed, so the caller can report what it left out.
    """
    keep = []
    for d in dirnames:
        why = tooling_reason(root, dirpath, d, skill_root)
        if why:
            if found is not None:
                found.append((os.path.relpath(os.path.join(dirpath, d), root)
                              .replace(os.sep, "/"), why))
        else:
            keep.append(d)
    dirnames[:] = keep
    return dirnames


def _same(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def inside_the_bundle(root, bundle=None):
    """True when `root` is this skill's own tree, a directory inside it, or an old
    copy of the scanner (or a directory inside one)."""
    real = os.path.realpath(root)
    home = os.path.realpath(bundle or SKILL_ROOT)
    if real == home or real.startswith(home.rstrip(os.sep) + os.sep):
        return True
    # An old copy: the root, or one of the few folders above it, holds the tool.
    here = real
    for _ in range(4):
        if carries_tool_signature(here):
            return True
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return False


def run_dir_gate(root, bundle=None):
    """Ask git what the scanned repository ships under the run directory.

    Returns {state, shipped, committed, why, git}:
      state      "bundle"          the root is this skill, an old copy of the
                                   scanner, or inside one: not a repository
                 "run-dir"         the root is a run directory (named
                                   .security-review) or inside one: the caller
                                   changed into it
                 "missing"         the root is not a directory
                 "git"             git tracks this tree and was asked
                 "untracked-tree"  a repository encloses the tree but HEAD
                                   lists none of it (an unborn HEAD, or a
                                   directory not yet committed or under an
                                   ignored one): only the index is asked
                 "no-git"          no .git at or above the tree: nothing to ask
                 "unanswerable"    a .git is there and git cannot answer
      shipped    [{path, mode, in: ["HEAD", "index"], on_disk}] - refused
      committed  the same shape, for the carve-out (.gitignore, ledger/)
      root       the scanned root, absolute: where the remedy's paths start
    Refuse iff state is "unanswerable", "bundle", "run-dir" or "missing", or `shipped` is
    non-empty. `bundle` overrides the skill folder (the tests use it).
    """
    root = os.path.abspath(root)
    result = {"state": None, "shipped": [], "committed": [], "why": None, "git": None,
              "root": root}
    if not os.path.isdir(root):
        result.update(state="missing",
                      why="%s is not a directory - --root names the repository under "
                          "review, a directory as it is spelled on disk (`.` from "
                          "inside it)" % root)
        return result
    if inside_the_bundle(root, bundle):
        result.update(state="bundle",
                      why="%s is this security-review skill, an old copy of it, or "
                          "inside one, not a repository under review" % root)
        return result
    if any(is_run_dir_name(part) for part in root.split(os.sep) if part):
        result.update(state="run-dir",
                      why="%s is, or is inside, a run directory (%s), not the repository "
                          "under review: a tool given it as --root would write a second "
                          "run directory inside the first" % (root, RUN_DIR_NAME))
        return result
    dotgit = enclosing_git(root)
    if dotgit is None:
        result["state"] = "no-git"
        return result
    result["git"] = dotgit
    if shutil.which("git") is None:
        result.update(state="unanswerable",
                      why="%s is here, but git is not installed, so nothing can say "
                          "what this repository commits" % dotgit)
        return result
    config = git_trusted_config()
    inside = run_git(root, ["rev-parse", "--is-inside-work-tree"], config=config)
    if inside is None or inside.strip() != b"true":
        complaint = _git_complaint(root, ["rev-parse", "--is-inside-work-tree"], config)
        result.update(state="unanswerable",
                      why="git will not open the repository at %s%s" % (
                          dotgit, ": " + complaint if complaint else
                          " (not a work tree, a bare or corrupt repository, or "
                          "one owned by another user)"))
        return result

    found = {}
    # The index, folded the way the filesystem folds: `.Security-Review/`, and
    # `.security-review` with a zero-width joiner in it, ARE the run directory
    # on a Mac. git's own `icase` pathspec folds ASCII only, so the whole index
    # under root is listed and each entry's first component folded here - an
    # entry AT the run directory, a link or a submodule, included. Run in root,
    # ls-files lists only root's subtree, relative to it.
    index = run_git(root, ["ls-files", "-s", "-z"], config=config, timeout=120)
    if index is None:
        result.update(state="unanswerable", why="`git ls-files` failed in %s" % root)
        return result
    for mode, path in _listed(index):
        if is_run_dir_name(path.partition("/")[0]):
            found.setdefault(path, [mode, set()])[1].add("index")

    # HEAD, because `git rm --cached` empties the index and leaves the bytes.
    # ls-tree takes no icase magic, so root's own entries are listed and folded
    # the way the filesystem folds them; paths come back relative to root.
    top = run_git(root, ["ls-tree", "-z", "HEAD"], config=config)
    if top is None:
        born = run_git(root, ["rev-parse", "-q", "--verify", "HEAD"], config=config)
        unborn = born is None and run_git(root, ["symbolic-ref", "-q", "HEAD"],
                                          config=config) is not None
        if not unborn:
            result.update(state="unanswerable",
                          why="HEAD in %s names no commit git can read" % dotgit)
            return result
        top = b""
    entries = _listed(top)
    for mode, name in entries:
        if not is_run_dir_name(name):
            continue
        if mode != "040000":
            found.setdefault(name, [mode, set()])[1].add("HEAD")
            continue
        below = run_git(root, ["ls-tree", "-r", "-z", "HEAD", "--",
                               ":(literal)" + name], config=config)
        if below is None:
            result.update(state="unanswerable", why="`git ls-tree` failed in %s" % root)
            return result
        for sub_mode, path in _listed(below):
            found.setdefault(path, [sub_mode, set()])[1].add("HEAD")

    result["state"] = "git" if entries else "untracked-tree"
    for path in sorted(found):
        mode, sources = found[path]
        entry = {"path": path, "mode": mode, "in": sorted(sources),
                 "on_disk": os.path.lexists(os.path.join(root, path))}
        result["committed" if _carved_out(mode, path) else "shipped"].append(entry)
    return result


def run_dir_refused(result):
    return (result["state"] in ("unanswerable", "bundle", "missing", "run-dir")
            or bool(result["shipped"]))


def _remedy_target(path):
    """What `git rm -r` should name for a shipped path: its top-level child
    under the run directory, or the exact path inside the carve-out."""
    parts = path.split("/")
    if len(parts) < 2:
        return path
    if parts[0] == RUN_DIR_NAME and (parts[1] == ".gitignore" or parts[1] == "ledger"):
        return path
    return "/".join(parts[:2])


def run_dir_refusal(result, limit=20):
    """The message a reader prints before it exits EXIT_SHIPPED, or None."""
    if not run_dir_refused(result):
        return None
    if result["state"] == "missing":
        return ("REFUSED: %s. Nothing was read or written. (exit %d)"
                % (result["why"], EXIT_SHIPPED))
    if result["state"] == "run-dir":
        return ("REFUSED: %s. Run every command from the repository root, with `--root .`; "
                "never change into %s/ first. Nothing was read or written. (exit %d)"
                % (result["why"], RUN_DIR_NAME, EXIT_SHIPPED))
    if result["state"] == "bundle":
        return ("REFUSED: %s. Run from the repository you want reviewed (the working "
                "directory is the workspace) and pass `--root .`; the skill folder is "
                "read-only and is never the target. Nothing was read or written. "
                "(exit %d)" % (result["why"], EXIT_SHIPPED))
    if result["state"] == "unanswerable":
        return ("REFUSED: %s. The run directory is read only once git has said the "
                "scanned repository commits nothing there but .gitignore and ledger/, "
                "and here it cannot say. If git refused a repository owned by another "
                "user, `git config --global --add safe.directory %s` is the fix; if git "
                "is missing, install it; if the .git/ is damaged, scan a fresh `git "
                "clone --no-local` instead. (exit %d)"
                % (result["why"], shlex.quote(os.path.dirname(result["git"] or "")),
                   EXIT_SHIPPED))
    shipped = result["shipped"]
    lines = ["REFUSED: the scanned repository commits %d path(s) under %s/, where the "
             "pipeline keeps its own state. A stage reading them would take them for "
             "this run's own - a triage verdict, a cached score, an approved scope, a "
             "secrets inventory, a snapshot - so nothing under %s/ is read while git "
             "lists anything there but .gitignore and regular files under ledger/."
             % (len(shipped), RUN_DIR_NAME, RUN_DIR_NAME)]
    for entry in shipped[:limit]:
        kind = {"120000": " (a symbolic link)", "160000": " (a submodule)",
                "040000": " (a directory)"}.get(entry["mode"], "")
        lines.append("  %s%s  - in %s%s" % (
            _printable(entry["path"]), kind, " and ".join(entry["in"]),
            "" if entry["on_disk"] else ", not on disk"))
    if len(shipped) > limit:
        lines.append("  ... and %d more" % (len(shipped) - limit))
    in_index = sorted(set(_remedy_target(e["path"]) for e in shipped
                          if "index" in e["in"]))
    head_only = sorted(e["path"] for e in shipped
                       if e["in"] == ["HEAD"] and e["on_disk"])
    # The paths are git's, relative to the scanned root; every command names the
    # root, so it runs from anywhere.
    top = _shell_word(result.get("root") or ".")
    lines.append("To scan this repository, remove them and commit the removal:")
    if in_index:
        lines.append("  git -C %s rm -r -f -q -- %s"
                     % (top, " ".join(_shell_word(p) for p in in_index)))
    if head_only:
        lines.append("  rm -rf -- " + " ".join(
            _shell_word(os.path.join(result.get("root") or ".", p)) for p in head_only))
    if any("HEAD" in e["in"] for e in shipped):
        lines.append("  git -C %s commit -q -m 'Remove run artifacts committed under %s/'"
                     % (top, RUN_DIR_NAME))
    lines.append("then re-run from stage 1. Not `git rm --cached`: it keeps the "
                 "committed bytes on disk, where every tool would read them as this "
                 "run's, and this check goes on refusing while HEAD lists them. If you "
                 "did not expect these files, that is worth reporting: the repository "
                 "is supplying the review's own state. (exit %d)" % EXIT_SHIPPED)
    return "\n".join(lines)


def run_dir_notes(result):
    """What a passing check still has to say. A list of lines, maybe empty."""
    notes = []
    if result["state"] in ("no-git", "untracked-tree"):
        notes.append(
            "note: run-directory provenance unverified - %s, so nothing can say "
            "whether the files under %s/ were written by this pipeline. If this "
            "tree came from someone else, empty %s/ before stage 1 (keep ledger/ "
            "only if you trust whoever wrote it)."
            % ("no git repository encloses this tree" if result["state"] == "no-git"
               else "HEAD lists none of this tree (an unborn HEAD, or a directory "
                    "not yet committed or under an ignored one), so only the index "
                    "could be asked",
               RUN_DIR_NAME, RUN_DIR_NAME))
    ledger = [e["path"] for e in result["committed"]
              if e["path"].startswith(RUN_DIR_NAME + "/ledger/")]
    if ledger:
        notes.append(
            "note: the scanned repository commits %s. The ledger is meant to be "
            "committed, so it is read: its suppressions hide findings and its "
            "decisions are counted as a person's. If you did not write it, read it "
            "before stage 3." % ", ".join(_printable(p) for p in ledger[:5]))
    return notes


def run_dir_summary(result):
    """The JSON-safe record stage 1 writes into run.json and run_status reports."""
    return {"check": result["state"],
            "committed": [e["path"] for e in result["committed"]],
            "shipped": [e["path"] for e in result["shipped"]]}


def enforce_run_dir_gate(root, err=None):
    """For a reader's main(), before it reads anything: (exit code, result).

    The code is EXIT_SHIPPED after the refusal has been printed, or None when
    the run directory may be read.
    """
    result = run_dir_gate(root)
    refusal = run_dir_refusal(result)
    if refusal:
        print(refusal, file=err or sys.stderr)
        return EXIT_SHIPPED, result
    return None, result


def check_run_dir_main(root, as_json=False, out=sys.stdout, err=sys.stderr):
    """The CLI: `rules_lib.py --check-run-dir [--root DIR] [--json]`. 0 or 7."""
    result = run_dir_gate(root)
    refusal = run_dir_refusal(result)
    if as_json:
        print(json.dumps(result, sort_keys=True), file=out)
    if refusal:
        print(refusal, file=err)
        return EXIT_SHIPPED
    if not as_json:
        print("run directory: %s - %s" % (
            result["state"], "git lists nothing under %s/ but the carve-out"
            % RUN_DIR_NAME if result["state"] == "git" else "not verifiable"), file=out)
        for note in run_dir_notes(result):
            print(note, file=out)
    return 0


# The only characters `str.encode("utf-8")` refuses. `os.walk` hands back a
# filename that is not valid UTF-8 as a string holding these, so any artifact
# recording a path can be handed one.
_SURROGATE = re.compile("[\ud800-\udfff]")


def json_dumps(obj, **kw):
    r"""`json.dumps` whose result is always writable to a UTF-8 file.

    Every artifact in this skill records paths, and a path comes off `os.walk`,
    which returns a name that is not valid UTF-8 as a string of lone surrogates.
    `json.dumps` is happy to put one in its output - it returns a `str` and never
    encodes - and the write then dies with UnicodeEncodeError, half a file in.
    That is not hypothetical: one latin-1 `src/caf\xe9.c` used to take stage 1
    down at `functions.jsonl`, after the whole corpus had been built.

    `ensure_ascii=False` is the default here because artifacts are read by people
    and by models, and `使用` is worth keeping legible. So the escape is
    taken only for the records that need it: if the rendered text carries a
    surrogate, it is re-rendered with `ensure_ascii=True`, which escapes it to
    six ASCII characters that `json.loads` reads back as the same string. The
    file stays valid UTF-8 and valid JSON either way, and the undecodable name
    survives in it rather than taking the run down or being silently dropped.
    """
    kw.pop("ensure_ascii", None)
    text = json.dumps(obj, ensure_ascii=False, **kw)
    if _SURROGATE.search(text):
        return json.dumps(obj, ensure_ascii=True, **kw)
    return text


# --------------------------------------------------------------------------- #
# a role's JSON reply, as `review_run.py ingest` and `validator_twins.py` read it
# --------------------------------------------------------------------------- #

_FENCE_LINE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
# A closing fence written on the last line of the object (`}```), which models do: a line
# that ends in `}` or `]` and then a run of the fence character. Only after a closing
# bracket, so a line of prose or code that happens to end in backticks is not a close.
_CLOSE_ON_LINE = re.compile(r"^(.*[}\]])[ \t]*(`{3,}|~{3,})[ \t]*$")


def split_fences(text):
    """([(info, body, closed)], prose) for `text`: its fenced blocks in order, and everything
    outside them.

    A fence is a line that starts (after blanks) with three or more backticks or tildes; the
    rest of that line is the info string, and the block runs to a line of the same character,
    at least as long, with nothing else on it (or a closing bracket and then that run: `}```),
    or to the end of the text, and then `closed` is False: the reply ended inside it, which is
    what a cut-off reply looks like."""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    blocks, prose, i = [], [], 0
    while i < len(lines):
        opener = _FENCE_LINE.match(lines[i])
        if not opener or (opener.group(1)[0] == "`" and "`" in opener.group(2)):
            prose.append(lines[i])
            i += 1
            continue
        mark, info = opener.group(1), opener.group(2).strip()
        body, j, closed = [], i + 1, False
        while j < len(lines):
            line = lines[j].strip()
            if len(line) >= len(mark) and line == mark[0] * len(line):
                closed = True
                break
            tail = _CLOSE_ON_LINE.match(lines[j])
            if tail and tail.group(2)[0] == mark[0] and len(tail.group(2)) >= len(mark):
                body.append(tail.group(1))
                closed = True
                break
            body.append(lines[j])
            j += 1
        blocks.append((info, "\n".join(body), closed))
        i = j + 1
    return blocks, "\n".join(prose)


def _objects_of(doc):
    """The list of objects a parsed reply is, or None when it is something else."""
    if isinstance(doc, dict):
        return [doc]
    if isinstance(doc, list) and all(isinstance(x, dict) for x in doc):
        return doc
    return None


_VERDICT_KEYS = re.compile(r'"(?:candidate_id|verdict)"\s*:')


def _may_be_a_verdict(info, body, closed):
    """Is a fenced block a verdict, or may it be? Only a block that shows no sign of it is prose.

    The signs: its info string mentions json (any case or spacing); it is unmarked and starts
    with `{` or `[`; its body holds a `"verdict":` or `"candidate_id":` key; or it is not closed,
    because a reply that ends inside a fence is a reply that ran out of room, and the block it
    ran out in could be anything, whatever it is marked. What is left is a closed block with
    none of those signs - a `bash` command, a quoted `c` function, a fenced note."""
    if not closed or "json" in info.lower() or _VERDICT_KEYS.search(body):
        return True
    return not info and body.lstrip()[:1] in ("{", "[")


def parse_json_reply_noted(text):
    """(list of JSON objects, list of what could not be read, list of cautions).

    A reply is one bare JSON document (an object or an array of objects), or fenced blocks
    each holding one - a validator that cannot write a file replies with a block per
    candidate. Blocks are taken one by one, so one malformed block costs its own candidate
    and not the batch. `unread` has one sentence per block (or for the reply as a whole)
    that could not be read, numbered by its place among the reply's fenced blocks and naming
    its info string when that is not json; what it holds is the caller's to account for.

    The rule that keeps a verdict from vanishing is one: a fenced block is an attempt at a
    verdict unless it shows no sign of being one (`_may_be_a_verdict`), and an attempt that
    does not parse is `unread`. The signs are an info string that mentions json, an unmarked
    body that starts with `{` or `[`, a `"verdict":` or `"candidate_id":` key anywhere in the
    body - whatever the block is marked and however it starts, so `` ```text `` after a heading
    and `` ``` `` after a `// derived` comment are read, and fail loudly - and a block the reply
    never closes. A closed block with none of those (a `bash` command, a quoted `c` function)
    is prose and is ignored, and so is the prose between blocks - unless it holds one of the
    keys, which is an object somebody forgot to fence, and is `unread` too. A fence the reply
    never closes is read as far as it goes: cut off or empty, it is `unread`, and the sentence
    says the reply may have been cut off - which is what loses the last block, and the last
    block is where the contract puts the derived MEM-WFS verdict. Whole, it is used, and it is
    a caution (`cautions`): the reply ended right after it, so whatever should have followed
    is missing and nothing in the reply says so. A closing fence written on the object's own
    last line (`}```) closes it; a leading byte-order mark (a PowerShell redirect writes one)
    is not part of the reply.

    `cautions` is for what was read and used but leaves a doubt the caller must say; `unread`
    is for what was not."""
    text = (text or "").lstrip("\ufeff").strip()
    if not text:
        return [], ["the reply is empty"], []
    attempts = []                       # (name, body, closed): the blocks that are, or may be, a verdict
    blocks, prose = split_fences(text)
    for n, (info, body, closed) in enumerate(blocks, 1):
        if _may_be_a_verdict(info, body, closed):
            name = "block %d" % n
            if info and "json" not in info.lower():
                name += " (marked %s)" % info[:30]
            attempts.append((name, body, closed))
    whole = not attempts                # no fenced attempt: the whole reply is the document
    if whole:
        attempts = [("the reply", text, True)]
    objects, bad, cautions = [], [], []
    for name, body, closed in attempts:
        try:
            doc = json.loads(body)
        except ValueError as exc:
            bad.append("%s is %snot valid JSON (%s)"
                       % (name, "" if closed else "not closed (the reply ends inside it, so it "
                          "may have been cut off) and is ", exc if body.strip() else "it is empty"))
            continue
        found = _objects_of(doc)
        if found is None:
            bad.append("%s is not a JSON object or an array of objects" % name)
            continue
        objects.extend(found)
        if not closed:
            cautions.append("%s was never closed: the reply ends inside it, so it may have been "
                            "cut off after it and whatever should follow (a derived MEM-WFS "
                            "verdict, the contract's last block) may be missing" % name)
    if not whole and _VERDICT_KEYS.search(prose):
        bad.append("text outside the fenced blocks has a \"verdict\" or \"candidate_id\" key, "
                   "so it may be an object that was not fenced; it was not read")
    return objects, bad, cautions


def parse_json_reply(text):
    """(list of JSON objects, list of what could not be read): `parse_json_reply_noted`
    without its cautions, for a caller that has nowhere to say them (the twin scorer, which
    scores a recording and files nothing)."""
    objects, bad, _cautions = parse_json_reply_noted(text)
    return objects, bad


def rules_hash(rules_dir):
    r"""One 16-hex digest over every `<category>.json` in `rules_dir`.

    A run pins its tools by version and its scored bytes by `content_hash`, and
    until now it pinned nothing at all about the rules that produced the hits.
    `coverage.json` records each rule's resolved `pattern`, which is close enough
    to look like provenance and is not: it carries no `skip_pattern`, no
    `weight`, no `high_signal`, no `languages`, and nothing whatsoever about a
    rule that fired zero times - so a ruleset edit that switched a rule off, or
    widened a skip clause, leaves two runs looking identically provenanced. A
    pinned tool with an unpinned ruleset is not a reproducible scan, and this is
    the field that makes the claim checkable: two runs carrying the same
    `rules_hash` were produced by byte-identical rule files.

    The file NAME is hashed alongside its content, so adding an empty
    `seventh.json` - or renaming `logic-flaws.json` to something the loader
    still accepts - moves the digest. The directory listing is part of the
    ruleset, not a detail of how it is stored.

    16 hex characters, matching `content_hash` in contract §2: this value is
    compared, never searched for, and a second hash width in one run record
    teaches a reader that the width carries meaning.
    """
    if not os.path.isdir(rules_dir):
        raise RulesError("%s: not a directory" % rules_dir)
    names = sorted(n for n in os.listdir(rules_dir) if n.endswith(".json"))
    if not names:
        raise RulesError("%s: no <category>.json files" % rules_dir)
    digest = hashlib.sha256()
    for name in names:
        with open(os.path.join(rules_dir, name), "rb") as fh:
            body = fh.read()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(body).hexdigest().encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()[:16]


def default_rules_dir():
    """assets/rules in the skill folder."""
    return os.path.join(SKILL_ROOT, "assets", "rules")


def default_fixture_dir(rules_dir=None):
    """tests/fixture in the skill folder (`rules_dir`, when given, is only used to
    find the skill folder it belongs to: <skill>/assets/rules)."""
    if rules_dir:
        base = os.path.dirname(os.path.dirname(os.path.abspath(rules_dir)))
        if os.path.basename(os.path.dirname(os.path.abspath(rules_dir))) == "assets":
            return os.path.join(base, "tests", "fixture")
    return os.path.join(SKILL_ROOT, "tests", "fixture")


def default_evalsets_dir():
    """assets/evalsets in the skill folder: the shipped, read-only registry."""
    return os.path.join(SKILL_ROOT, "assets", "evalsets")


def skill_version():
    """The skill's own version: the VERSION file beside SKILL.md, else "0.0.0".

    run.json's `bundle_version`, the SARIF tool version and the upstream check's
    user agent all say it, so a result can be traced to the skill that wrote it.
    """
    try:
        with open(os.path.join(SKILL_ROOT, "VERSION"), encoding="utf-8") as fh:
            text = fh.read().strip()
    except OSError:
        return "0.0.0"
    return text if re.match(r"^[0-9][0-9A-Za-z.+-]{0,31}$", text) else "0.0.0"


def default_references_dir():
    """references/ in the skill folder (the contracts the checkers compare against)."""
    return os.path.join(SKILL_ROOT, "references")


# --------------------------------------------------------------------------- #
# ripgrep
# --------------------------------------------------------------------------- #

# A rule's `pattern` has to mean the same thing to ripgrep as to Python `re`,
# because a person or an agent checking a hit greps the tree with rg, and the
# rules README promises the two engines agree. Most of what differs is refused
# outright by one engine and so shows up the first time anyone runs it. These do
# not: each one compiles in Python and then means something else, or nothing, to
# ripgrep's default engine, and the difference is a set of lines one engine
# reports and the other silently does not.
_RG_GROUP_HAZARDS = (
    (("=", "!", "<=", "<!"), "lookaround, which ripgrep's default engine refuses"),
    ((">",), "an atomic group, which ripgrep refuses"),
    (("#",), "a Python comment group, which ripgrep refuses"),
    (("P=",), "a named backreference, which ripgrep refuses"),
    (("(",), "a conditional group, which ripgrep refuses"),
)


def ripgrep_hazards(pattern):
    r"""The constructs in `pattern` that ripgrep reads differently from Python, as prose.

    Empty for a pattern whose every construct means the same to both. Read off
    the pattern text rather than off Python's parse, because the point is what
    the OTHER engine will make of the same characters: `\<` is a literal to
    Python and a word boundary to ripgrep 14, `[a&&b]` is four characters to
    Python and an intersection to ripgrep, `a{ 1}` is five literal characters
    to Python and one `a` to ripgrep. A `skip_pattern` runs only in Python and
    is not asked.
    """
    found = []
    i, n, in_class, quantified = 0, len(pattern), False, False
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            nxt = pattern[i + 1:i + 2]
            if nxt in ("<", ">"):
                found.append("\\%s is a word-boundary assertion to ripgrep and a "
                             "literal %s to Python" % (nxt, nxt))
            elif nxt == "b" and not in_class and pattern[i + 2:i + 3] == "{":
                found.append("\\b{ opens one of ripgrep's special word boundaries")
            elif nxt.isdigit():
                found.append("\\%s is a backreference or an octal escape, which "
                             "ripgrep refuses" % nxt)
            elif nxt == "g" and pattern[i + 2:i + 3] == "<":
                found.append("\\g< is a backreference, which ripgrep refuses")
            elif nxt in ("Z", "z", "N"):
                found.append("\\%s is Python's alone; ripgrep refuses or reads it "
                             "differently" % nxt)
            i += 2
            quantified = False
            continue
        if in_class:
            if ch == "]":
                in_class = False
            elif ch == "[":
                found.append("[ inside a character class opens a nested or [:posix:] "
                             "class to ripgrep and is a literal to Python")
            elif pattern[i:i + 2] in ("&&", "--", "~~", "||"):
                found.append("%s inside a character class is a set operation to "
                             "ripgrep and two literals to Python" % pattern[i:i + 2])
                i += 2
                continue
            i += 1
            continue
        if ch == "[":
            in_class = True
            i += 1
            if pattern[i:i + 1] == "^":
                i += 1
            if pattern[i:i + 1] == "]":
                i += 1
            quantified = False
            continue
        if ch == "(" and pattern[i + 1:i + 2] == "?":
            rest = pattern[i + 2:]
            for openers, why in _RG_GROUP_HAZARDS:
                opener = next((o for o in openers if rest.startswith(o)), None)
                if opener is not None:
                    found.append("(?%s is %s" % (opener, why))
                    break
            else:
                if not rest.startswith(("P<", ":")):
                    flags = re.match(r"[A-Za-z-]*", rest).group(0)
                    if set(flags) - {"i"}:
                        found.append("(?%s: only the i flag means the same to both "
                                     "engines" % flags)
            i += 2
            quantified = False
            continue
        if ch == "{":
            counted = re.match(r"\{(\d*)(?:,(\d*))?\}", pattern[i:])
            if counted is None or not counted.group(1):
                found.append("%s is not a repetition Python and ripgrep both read "
                             "(a literal brace is written \\{, and {,n} is written "
                             "{0,n})" % (counted.group(0) if counted else "{"))
                i += counted.end() if counted else 1
                quantified = False
                continue
            i += counted.end()
            quantified = True
            continue
        if ch in "*+?":
            if quantified and ch == "+":
                found.append("a possessive quantifier, which ripgrep reads as a "
                             "second repetition")
                quantified = False
            else:
                # `*?` is lazy to both; anything else starts a fresh quantifier.
                quantified = not quantified
            i += 1
            continue
        quantified = False
        i += 1
    return found


def ripgrep_disagreements(rules, corpus, rg="rg", timeout=120):
    r"""Every line of `corpus` one engine matches a rule's pattern on and the other does not.

    `ripgrep_hazards` catches what can be read off a pattern; this catches what
    cannot. ripgrep 14.1.0 - the version `apt install ripgrep` gives on Ubuntu
    24.04 - silently matched nothing on every line of INJ-002's backtick branch,
    `` `ls $d` `` included, because of an engine bug with an optional group
    inside an alternation: `(X)?` failed where the equivalent `(?:|X)` does not.
    Nothing about the pattern was wrong, so only running both engines over the
    same lines shows it. Stage 1 and stage 4 run Python, so candidates were
    right; what broke was every check of an INJ-002 hit done by hand with rg.

    Each file is decoded as UTF-8 and split on "\n" only, which is ripgrep's
    line model and stage 1's. A file that does not decode is left out: ripgrep
    searches its bytes and Python a decoded string, and the two are then not
    reading the same text. A multiline rule is left out too - ripgrep runs line
    by line without -U, which is the difference its README entry is about.
    """
    import subprocess
    files = []
    for root, dirs, names in os.walk(corpus):
        dirs.sort()
        for name in sorted(names):
            path = os.path.join(root, name)
            try:
                with open(path, "rb") as fh:
                    text = fh.read().decode("utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            lines = text.split("\n")
            if text.endswith("\n"):
                lines.pop()
            files.append((path, lines))
    if not files:
        return ["%s holds no readable file to compare over" % corpus]
    out = []
    for rule in rules:
        if rule.get("derived") or rule.get("multiline"):
            continue
        for field in ("pattern", "line_pattern"):
            text = rule.get(field)
            if not text:
                continue
            rx = re.compile(text)
            python = {(path, k + 1) for path, lines in files
                      for k, line in enumerate(lines) if rx.search(line)}
            # --no-config so an RIPGREP_CONFIG_PATH cannot add flags, --text so a
            # NUL byte cannot turn a file binary, -e so a pattern opening with a
            # dash is not read as an option.
            argv = [rg, "--no-config", "--no-ignore", "--hidden", "--text",
                    "--line-number", "--with-filename", "--no-heading", "--null",
                    "--color", "never", "-e", text, "--"] + [p for p, _ in files]
            try:
                proc = subprocess.run(argv, capture_output=True, timeout=timeout)
            except (OSError, subprocess.SubprocessError) as exc:
                out.append("%s %s: ripgrep did not run: %s" % (rule["rule_id"], field, exc))
                continue
            if proc.returncode not in (0, 1):
                why = proc.stderr.decode("utf-8", "replace").strip().splitlines()
                out.append("%s %s: ripgrep refused it: %s"
                           % (rule["rule_id"], field, why[-1] if why else proc.returncode))
                continue
            ripgrep = set()
            for raw in proc.stdout.split(b"\n"):
                path, sep, rest = raw.partition(b"\0")
                if sep:
                    ripgrep.add((os.fsdecode(path), int(rest.split(b":", 1)[0])))
            for path, line in sorted(python ^ ripgrep):
                out.append("%s %s: %s:%d is matched by %s only"
                           % (rule["rule_id"], field, os.path.relpath(path, corpus), line,
                              "Python" if (path, line) in python else "ripgrep"))
    return out


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

GOOD = {
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
            "skip_pattern": r"\b(?:memcpy|memmove)\s*\(\s*([A-Za-z_]\w*)\s*,[^,()]*,"
                            r"\s*sizeof\s*\(\s*\1\s*\)",
            "wrapper_class": "copy", "threat_model": None, "derived": False,
            "high_signal": True, "weight": 3,
        },
        {
            "rule_id": "MEM-005", "title": "untrusted read into fixed buffer",
            "cwe": "CWE-120", "languages": ["c"],
            "pattern": r"\b(read|recv)\s*\(",
            "multiline": False, "match_target": "line",
            "why_flagged": "read length is not sizeof(dest)",
            "flag_condition": "flag when the length argument is not sizeof(<dest>)",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": False,
            "high_signal": False, "weight": 2,
        },
        {
            "rule_id": "MEM-WFS", "title": "whole-function scan",
            "cwe": "CWE-119", "languages": ["c"],
            "pattern": None, "multiline": False, "match_target": None,
            "why_flagged": "whole-function memory-safety pass",
            "flag_condition": "the four questions a whole-function pass answers",
            "skip_clause": None, "skip_pattern": None,
            "wrapper_class": None, "threat_model": None, "derived": True,
            "derivation": "one per distinct (file, function) pair across the emitted "
                          "candidate files",
            "high_signal": False, "weight": 2,
        },
    ],
}


# Lines a scanned repository can plant, one per way a shipped pattern used to go
# quadratic. Each is a literal that can repeat, followed by nothing the pattern
# needs: a regex that opens a match at every copy of `EC` and then runs `.*` to
# the end of the line looking for `secp112` does N/2 scans of up to N
# characters. One such line of 200 KB - a tenth of the per-file cap - kept stage
# 1 running past two minutes, and at the 2 MB cap it was hours per rule. The
# repository under review is attacker-influenced, so it could stop its own
# review with one file; stage 4's recount runs the same patterns and hung the
# same way. The units are the literals those patterns were anchored on.
#
# A plant reaches a branch only when its head is what the branch opens on:
# LOG-004's `(?:mbedtls|psa)_\w*verify\w*\s*\(` shipped with every plant above
# passing, and took 2.8 s on 48 KB of `= psa_verifyverify...` (4x per doubling,
# about an hour and a half on one line at the 2 MB cap), because no plant put a
# call context and a prefix in front of the repeating `verify`. So a branch that
# opens on a fixed prefix gets a plant that starts with it.
PATHOLOGICAL = (
    ("", "EC"), ("", "AES"), ("", "tag"), ("", "key"), ("", "hmac_"),
    ("", "secret"), ("", "log_"), ("", "parse_"), ("", "EVP_"), ("", "a"),
    ("", "0123456789abcdef"), ("", "for("), ("", "printf("), ("", "strcat"),
    ("", "Runtime.exec"), ("", "mbedtls_rsa_rsassa"), ("", "RSA_generate_key"),
    ("", "SSL_CTX_set_verify("), ("char ", "key"), ("int ", "_ok"),
    ("if (", "auth"), ("return ", "buf"), ("memset(", "key"),
    ('"SELECT ', "from "), ("= `", "$a"), ("", "subprocess.a("),
    ("= psa_", "verify"), ("gnutls_", "verify"), ("wc_", "Verify"),
    # LOG-004's prefix before crypto_sign_open, behind `=` and behind `.`;
    # LOG-008's indexed and qualified compares.
    ("= ", "a_"), ("", ".a_"), ("if (hmac[i] != ", "a"), ("", "hmac_out  "),
)

# Identifiers a scanned repository can plant for the segment-aware name matcher:
# a boundary at every other character, humps, acronym runs and a keyword that
# opens a segment again and again. A function name is as unbounded as a line.
PATHOLOGICAL_NAMES = (
    ("src/x.c::", "a_"), ("src/x.c::", "aB"), ("src/x.c::", "ABc"),
    ("src/x.c::", "auth_"), ("src/x.c::", "Key"), ("src/", "d_x/"),
)

# How long one pattern may take over one planted line. Generous on purpose: the
# linear patterns finish these in milliseconds and the quadratic ones they
# replaced took seconds to minutes, so the bound is there to catch a regression
# of that kind and not to benchmark a slow machine.
PATHOLOGICAL_BUDGET = 1.0
PATHOLOGICAL_CHARS = 32000
# Stage 1's blindness pass runs each pattern with its `\b` anchors dropped, and
# caps the lines it runs them over at LOOSE_SCAN_MAX_LINE in extract_functions
# for exactly this reason. That loosened form is timed at that length.
PATHOLOGICAL_LOOSE_CHARS = 2000
# A pattern that grows with the square of the line can still sit well inside
# the budget at PATHOLOGICAL_CHARS when its constant is small. INJ-002's
# `subprocess\.\w+\([^)]*shell` spent 0.09 s on 32 KB of `subprocess.a(` and
# passed, and would have spent six minutes on one line at the 2 MB file cap. So
# an anchored pattern that takes measurable time on a planted line is timed
# again on a line PATHOLOGICAL_GROWTH times as long, and fails when its time
# grew by more than PATHOLOGICAL_GROWTH_MAX: linear work grows by about the
# factor itself, quadratic work by its square.
PATHOLOGICAL_GROWTH_FLOOR = 0.03
PATHOLOGICAL_GROWTH = 4
PATHOLOGICAL_GROWTH_MAX = 10.0


def _planted(head, unit, size):
    return head + unit * ((size - len(head)) // len(unit))


def _pathological_lines(size):
    for head, unit in PATHOLOGICAL:
        yield _planted(head, unit, size)


def _header(count):
    return "".join("char f_%d[32];\n" % i for i in range(count))


def _timed(rx, text):
    import time
    started = time.perf_counter()
    for _ in rx.finditer(text):
        pass
    return time.perf_counter() - started


def slow_patterns(rules, budget=PATHOLOGICAL_BUDGET, size=PATHOLOGICAL_CHARS,
                  loose_size=PATHOLOGICAL_LOOSE_CHARS,
                  growth_floor=PATHOLOGICAL_GROWTH_FLOOR):
    r"""Every (rule, field, form, line) that took longer than `budget` seconds,
    or whose time grew with the square of the line.

    Timed rather than reasoned about, because the property that matters - that
    a pattern's work grows with the line and not with its square - is exactly
    the one a reader of a 400-character alternation cannot see. A `multiline`
    rule runs over a whole file, so it is also run over a header of 4000
    fixed-size buffers with no `return` after them, which is where MEM-009's
    `[\s\S]*?return` used to spend 45 seconds on 400 KB.
    """
    slow = []
    for rule in rules:
        for field in ("pattern", "line_pattern", "skip_pattern"):
            text = rule.get(field)
            if not text:
                continue
            forms = [("anchored", text, size)]
            if field == "pattern" and rule.get("match_target") == "function_or_path":
                # How stage 1 and stage 4 actually run a name pattern: every
                # `\b` a segment boundary. Its lookarounds are constant-width,
                # and this is where a rewrite that made it quadratic shows.
                forms.append(("segment", segment_pattern(text), size))
            if field != "skip_pattern":
                # The transform extract_functions.loosen and
                # verify_findings.unanchored both apply.
                forms.append(("loosened", text.replace(r"\b", "").replace(r"\B", ""),
                              loose_size))
            if field == "line_pattern":
                # A sink half's zero-hit test keeps its trailing anchors
                # (loose_scan and the candidate gate's I4, both through
                # loosen_name), which is a pattern of its own to time.
                forms.append(("loosened-leading", loosen_name(text), loose_size))
            for form, pattern, length in forms:
                rx = re.compile(pattern)
                # Each input as a function of a scale, so the growth check
                # below can ask for the same shape PATHOLOGICAL_GROWTH times
                # as long.
                makers = [(lambda k, h=head, u=unit, n=length: _planted(h, u, n * k))
                          for head, unit in PATHOLOGICAL
                          + (PATHOLOGICAL_NAMES if form == "segment" else ())]
                if rule.get("multiline") and field == "pattern":
                    makers.append(lambda k: _header(4000 * k))
                for make in makers:
                    line = make(1)
                    took = _timed(rx, line)
                    if took > budget:
                        slow.append("%s %s (%s) %.1fs on %r..."
                                    % (rule["rule_id"], field, form, took, line[:24]))
                        continue
                    # Only the anchored form runs over lines of any length; the
                    # loosened ones are capped at LOOSE_SCAN_MAX_LINE, so their
                    # growth past that length is never paid.
                    if form.startswith("loosened") or took < growth_floor:
                        continue
                    grown = _timed(rx, make(PATHOLOGICAL_GROWTH))
                    if grown > took * PATHOLOGICAL_GROWTH_MAX:
                        # Once more before calling it, taking the kinder of
                        # each timing, so a scheduler hiccup is not a failure.
                        took = max(took, _timed(rx, line))
                        grown = min(grown, _timed(rx, make(PATHOLOGICAL_GROWTH)))
                    if grown > took * PATHOLOGICAL_GROWTH_MAX:
                        slow.append("%s %s (%s) grew %.0fx on a %dx longer %r..."
                                    % (rule["rule_id"], field, form, grown / took,
                                       PATHOLOGICAL_GROWTH, line[:24]))
    return slow


# What the selftests may ask of the platform. `hasattr(os, "symlink")` is true on Windows, where
# the call raises OSError 1314 (no privilege) unless Developer Mode is on or the shell is
# elevated, and `os.mkfifo` is absent there: a selftest that made either without asking died
# with a traceback before most of its checks ran. So the platform is asked by doing it once, in a
# scratch folder, and a case that needs a link or a fifo is skipped, named and counted
# (`skip_case`, `skipped_note`) where it cannot be made. The unittest suite does the same
# (tests/fixtures.py `can_symlink`).
_PLATFORM_CAN = {}
_SKIPPED_CASES = []


def _platform_can(what):
    if what not in _PLATFORM_CAN:
        import tempfile
        made = False
        try:
            with tempfile.TemporaryDirectory() as scratch:
                target = os.path.join(scratch, "target")
                with open(target, "w", encoding="utf-8") as fh:
                    fh.write("x\n")
                if what == "symlink":
                    os.symlink(target, os.path.join(scratch, "probe"))
                else:
                    os.mkfifo(os.path.join(scratch, "probe"))
                made = True
        except (OSError, NotImplementedError, AttributeError):
            made = False
        _PLATFORM_CAN[what] = made
    return _PLATFORM_CAN[what]


def can_symlink():
    """Can this process make a symbolic link? Asked by making one (see above)."""
    return _platform_can("symlink")


def can_mkfifo():
    """Can this process make a named pipe? False where `os.mkfifo` does not exist (Windows)."""
    return _platform_can("fifo")


def skip_case(label, what="a symbolic link", n=1):
    """Say that a selftest case was left out because the platform cannot make `what`, and count
    it (`n` checks, for a group named once). Never a pass: the final line of the selftest
    carries the count (`skipped_note`)."""
    _SKIPPED_CASES.extend([label] * n)
    print("  skip %s: this platform cannot make %s" % (label, what))


def skipped_note():
    """The tail of a selftest's last line: how many cases were skipped, or ''."""
    if not _SKIPPED_CASES:
        return ""
    return ", %d case(s) skipped, the platform cannot make links or pipes" % len(_SKIPPED_CASES)


def _write(tmp, name, doc):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    return path


def _mutate(base, index=None, **changes):
    import copy
    doc = copy.deepcopy(base)
    if index is None:
        doc.update(changes)
    else:
        doc["rules"][index].update(changes)
    return doc


def selftest():
    import tempfile
    if os.environ.get("RULES_LIB_SELFTEST_NESTED"):
        # Only reached when --check-run-dir let --selftest through: fail fast.
        print("selftest refused: started from inside the --check-run-dir guard's own "
              "test", file=sys.stderr)
        return 3
    failures = 0

    def check(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    def refuses(label, doc, name="memory-safety.json", fragment=None):
        nonlocal failures
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, name, doc)
            try:
                load_category(path)
            except RulesError as exc:
                text = str(exc)
                ok = text.startswith(path) and (fragment is None or fragment in text)
                if ok:
                    print("  ok   %s" % label)
                else:
                    failures += 1
                    print("  FAIL %s: error did not name the file%s: %s"
                          % (label, "" if fragment is None
                             else " and %r" % fragment, text))
                return
        failures += 1
        print("  FAIL %s: loaded without complaint" % label)

    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "memory-safety.json", GOOD)
        rules = load_rules(tmp)
        by_id = {r["rule_id"]: r for r in rules}
        check("every rule in the file is loaded", len(rules), 3)
        check("the category is folded into the rule",
              by_id["MEM-002"]["category"], "memory-safety")
        check("the validator is folded in too",
              by_id["MEM-002"]["validator"], "sec-val-memory-safety")
        check("the rule carries the file it came from",
              os.path.basename(by_id["MEM-002"]["source_file"]), "memory-safety.json")
        check("match_target defaults to line",
              by_id["MEM-005"]["match_target"], "line")
        check("a derived rule may still carry match_target null",
              by_id["MEM-WFS"]["match_target"], None)

        # ---- the wrapper rewrite widens and never narrows ---- #
        m2 = by_id["MEM-002"]
        plain = compile_pattern(m2)
        check("with no wrappers the canonical pattern is what runs",
              plain.pattern, m2["pattern"])
        check("and pattern_source says so", resolve_pattern(m2)[1], "as-written")
        wrapped = compile_pattern(m2, {"copy": ["mbedtls_memcpy"], "alloc": ["x_calloc"]})
        check("a resolved wrapper now matches",
              bool(wrapped.search("mbedtls_memcpy(d, s, n);")), True)
        check("the canonical branch still matches after the rewrite",
              bool(wrapped.search("memcpy(d, s, n);")), True)
        check("pattern_source becomes wrapper-resolved",
              resolve_pattern(m2, {"copy": ["mbedtls_memcpy"]})[1], "wrapper-resolved")
        check("a wrapper of another class is not spliced in",
              bool(wrapped.search("x_calloc(1, n);")), False)
        check("a rule with wrapper_class null ignores the resolution",
              resolve_pattern(by_id["MEM-005"], {"copy": ["mbedtls_memcpy"]})[1],
              "as-written")

        # ---- wrapper blindness: one definition, for stage 1 and the gate ---- #
        # Stage 1 records what stage 4's candidate gate refuses on, so both call
        # these. tests/test_wrapper_blind.py runs the two tools against each other.
        check("a bare word list is word-list shaped",
              word_list_shaped(r"\b(iv|IV|nonce|salt)\b"), True)
        check("a call pattern is not, even with a \\b group",
              word_list_shaped(r"\b(memcpy|memmove)\s*\("), False)
        check("a MIXED pattern is word-list shaped, and call_shaped alone cannot tell",
              (word_list_shaped(r"\b(iv|nonce)\b|memset\s*\(\s*\w*(iv|nonce)"),
               call_shaped(r"\b(iv|nonce)\b|memset\s*\(\s*\w*(iv|nonce)")), (True, True))
        check("only the leading anchor of a call branch comes off",
              wrapper_blind_forms(r"\b(?:printf)\s*\([^)]*\bkey\b|\b(?:iv|nonce)\b"),
              (r"\b(?:printf)\s*\([^)]*\bkey\b", r"(?:printf)\s*\([^)]*\bkey\b"))
        check("a pattern with no call-shaped branch has no form",
              wrapper_blind_forms(r"\b(?:iv|nonce)\b"), (None, None))
        check("blind: at least MIN more AND at least as many again as were caught",
              [is_wrapper_blind(f, n) for f, n in ((3, 12), (3, 7), (0, 50), (10, 25))],
              [True, False, False, True])
        check("an empty list for the class is not a rewrite",
              resolve_pattern(m2, {"copy": []})[1], "as-written")
        # verify_findings.py splits both patterns into alternation branches and
        # fails the run when a canonical branch is missing from the one that ran.
        text, _ = resolve_pattern(m2, {"copy": ["mbedtls_memcpy"]})
        check("no canonical branch is lost by the rewrite",
              all(n in text for n in ("memcpy", "memmove")), True)
        # A name from the scanned tree is data, not regex. Before escaping, a
        # tree could name a function `.*` and widen a rule to everything.
        hostile = compile_pattern(m2, {"copy": [".*", "a|b", "ok_wrapper"]})
        check("a non-identifier wrapper name is dropped rather than compiled",
              bool(hostile.search("this line has no copy call at all")), False)
        check("the identifier beside it still resolves",
              bool(hostile.search("ok_wrapper(d, s, n);")), True)

        # ---- THE CRITICAL RULE ---- #
        check("a rule with no skip_pattern offers no skip path",
              compile_skip(by_id["MEM-005"]), None)
        skip = compile_skip(m2)
        check("a rule with one offers exactly that one", skip is None, False)
        check("sizeof(dest) is skipped",
              bool(skip.search("memcpy(buf, src, sizeof(buf));")), True)
        # The widening the audited run took: its clause said sizeof(<dest>) and
        # its skips included a plain variable and a sizeof of the SOURCE.
        check("sizeof(source) is NOT sizeof(dest) and is not skipped",
              bool(skip.search("memcpy(dst, src, sizeof(src));")), False)
        check("a variable size is not skipped",
              bool(skip.search("memcpy(rec->payload, cur, len);")), False)
        check("a constant size is not skipped either",
              bool(skip.search("memcpy(dst, src, 16);")), False)
        check("the skip_reason is the rule's written clause, not a paraphrase",
              m2["skip_clause"], "third argument is literally sizeof(<dest>)")
        # Both skip classers read this table; a name in it that is not a
        # language the skill assigns would be a `#` rule nothing ever applies.
        check("every # comment language is a language the skill scans",
              sorted(set(HASH_COMMENT_LANGUAGES) - set(LANGUAGES)), [])

        # ---- a `#!` line names an extensionless script's language ---- #
        for head, want in (
                (b"#!/usr/bin/python3.11 -u\nimport os\n", "python"),
                (b"#! /bin/sh\n", "shell"),
                (b"#!/usr/bin/env FOO=1 ruby\n", "ruby"),
                (b"#!/usr/bin/env -S node --x\n", "javascript"),
                (b"#!/usr/bin/env -u HOME python3\n", "python"),
                (b"#!/usr/bin/env -S bash -e\r\nset -u\r\n", "shell"),
                (b"#!/bin/bash\r\n", "shell"),
                (b"#!/usr/bin/awk -f\n", "awk"),
                (b"#!/usr/bin/env --split-string=python3 -u\n", "python"),
                (b"#!/usr/bin/env -S \"python3 -u\"\n", "python"),
                (b"#!/usr/local/bin/ruby-2.7\n", "ruby"),
                (b"#!/usr/local/bin/python3-dbg\n", "python"),
                (b"#!/usr/bin/env node-red\n", "node-red"),
                (b"#!/opt/tool-1.2\n", "tool"),
                (b"#!/usr/bin/env -S uv run --script\n", "python"),
                (b"#!/usr/bin/env -S uv run --with requests --script\n",
                 "python"),
                (b"#!/usr/bin/env -S poetry run node\n", "javascript"),
                (b"#!/usr/bin/env -S npx tsx\n", "typescript"),
                (b"#!/usr/bin/env -S npx -p typescript ts-node\n", "typescript"),
                (b"#!/usr/bin/env -S npx cowsay\n", "npx"),
                (b"#!/opt/" + b"k" * 40 + b"\n", "unknown"),
                (b"#!\n", None),
                (b"#!/usr/bin/env\n", None),
                (b"# not a shebang\n", None),
                (b" #!/bin/sh\n", None),
                (b"", None)):
            check("shebang_language(%r)" % head[:32], shebang_language(head), want)
        # A label that is a bundle language is a file the extractor could read
        # and did not, and stage 1 says so in so many words; these are those.
        check("the script labels that are bundle languages",
              sorted(set(INTERPRETER_LANGUAGE.values()) & set(LANGUAGES)),
              ["javascript", "php", "python", "ruby", "typescript"])
        check("and language_of still reads the extension alone",
              language_of("bin/tool"), None)

        # ---- derived rules are synthesised, never matched ---- #
        try:
            compile_pattern(by_id["MEM-WFS"])
            check("a derived rule refuses to be compiled into a pattern", True, False)
        except RulesError as exc:
            check("a derived rule refuses to be compiled into a pattern",
                  "MEM-WFS" in str(exc) and "derived" in str(exc), True)

    # ---- LOG-TRI: the one predicate three tools share ---- #
    check("RULE_ID accepts LOG-TRI", bool(RULE_ID.match("LOG-TRI")), True)
    check("and refuses LOG-TR1, LOG-TRIX and tri", [bool(RULE_ID.match(x)) for x in
                                                    ("LOG-TR1", "LOG-TRIX", "LOG-tri")],
          [False, False, False])
    check("the verdicts are the four the triage worker answers with",
          TRIAGE_VERDICTS, ("high", "medium", "low", "none"))
    check("LOG-TRI's four checklists are LOG-001, 002, 004 and 009",
          TRIAGE_CHECKLISTS, ("LOG-001", "LOG-002", "LOG-004", "LOG-009"))
    plain = {"function_id": "a.py::f::0@1", "function_key": "a.py::f::0", "name": "f",
             "file": "src/shop/views.py", "in_test_tree": False, "generated_file": False}
    emitted = {"rule_hit_id": "RH-1", "disposition": "emitted", "function_id": "a.py::f::0@1"}
    skipped_hit = dict(emitted, disposition="skipped")
    for label, fn, hits, verdict, want in (
            ("high with no hit is owed", plain, [], "high", (True, None)),
            ("medium is not", plain, [], "medium", (False, "verdict-medium")),
            ("low is not", plain, [], "low", (False, "verdict-low")),
            ("none is not", plain, [], "none", (False, "verdict-none")),
            ("no verdict (the rules backend) is not", plain, [], None,
             (False, "no-verdict")),
            ("an unknown verdict word is not", plain, [], "critical", (False, "no-verdict")),
            ("an emitted hit makes a high function that rule's, not LOG-TRI's", plain,
             [emitted], "high", (False, "has-rule-hit")),
            ("a skipped hit is not evidence and joins nothing", plain, [skipped_hit], "high",
             (True, None)),
            ("a module scope is not a function", dict(plain, name="<module>"), [], "high",
             (False, "not-a-function")),
            ("nor is a window", dict(plain, name="<window>"), [], "high",
             (False, "not-a-function")),
            ("an anonymous handler is a real body", dict(plain, name="<anonymous>"), [],
             "high", (True, None)),
            ("so is an arrow", dict(plain, name="<arrow>"), [], "high", (True, None)),
            ("a function in the test tree is not", dict(plain, in_test_tree=True), [], "high",
             (False, "test-tree")),
            ("a generated file is not", dict(plain, generated_file=True), [], "high",
             (False, "generated")),
            ("a vendored directory is not", dict(plain, file="src/vendor/x.py"), [], "high",
             (False, "vendored")),
            ("nor third_party, any case", dict(plain, file="a/Third_Party/x.py"), [], "high",
             (False, "vendored")),
            ("nor node_modules", dict(plain, file="node_modules/a/b.js"), [], "high",
             (False, "vendored")),
            ("a file NAMED vendor.py is not a vendored directory",
             dict(plain, file="src/vendor.py"), [], "high", (True, None)),
            ("examples/ and docs/ are not left out", dict(plain, file="examples/x.py"), [],
             "high", (True, None))):
        check(label, triage_derivation(fn, hits, verdict), want)
    check("a verdict-less test-tree function says no-verdict first (the order is fixed)",
          triage_derivation(dict(plain, in_test_tree=True), [], None), (False, "no-verdict"))
    check("a medium function in the test tree says medium (the order is fixed)",
          triage_derivation(dict(plain, in_test_tree=True), [], "medium"),
          (False, "verdict-medium"))
    check("a hit beats the test tree", triage_derivation(
        dict(plain, in_test_tree=True), [emitted], "high"), (False, "has-rule-hit"))
    check("every code the predicate returns has a sentence",
          sorted(c for c in ("no-verdict", "verdict-medium", "verdict-low", "verdict-none",
                             "has-rule-hit", "not-a-function", "test-tree", "generated",
                             "vendored", "opted-out", "anchor-unreadable",
                             "scored-before-0.1.3") if c not in TRIAGE_REASONS), [])
    check("an llm-triage record from before 0.1.3 says so",
          no_verdict_reason({"backend": "llm-triage"}), "scored-before-0.1.3")
    check("a rules-backend record with the field null does not",
          no_verdict_reason({"backend": "rules", "triage_verdict": None}), "no-verdict")
    check("nor does an llm-triage record that carries the field",
          no_verdict_reason({"backend": "llm-triage", "triage_verdict": None}), "no-verdict")

    index = index_emitted_hits([
        dict(emitted, function_key="a.py::f::0"),
        {"rule_hit_id": "RH-2", "disposition": "emitted", "function_key": "b.py::g::0"},
        {"rule_hit_id": "RH-3", "disposition": "skipped", "function_id": "c.py::h::0@3"},
        {"rule_hit_id": "RH-4", "disposition": "emitted"}])
    check("the hit index is emitted hits under either key and nothing else",
          sorted(index), ["a.py::f::0", "a.py::f::0@1", "b.py::g::0"])
    check("a hit under both keys joins once",
          [h["rule_hit_id"] for h in emitted_hits_joining(plain, index)], ["RH-1"])
    check("a hit under the key alone joins",
          [h["rule_hit_id"] for h in emitted_hits_joining(
              {"function_id": "gone@9", "function_key": "b.py::g::0"}, index)], ["RH-2"])
    check("a function no hit names joins nothing",
          emitted_hits_joining({"function_id": "x@1", "function_key": "x::y::0"}, index), [])

    pairs = []
    for number, (verdict, extra) in enumerate((
            ("high", {}), ("high", {}), ("medium", {}), ("high", {"in_test_tree": True}),
            ("high", {}), (None, {}))):
        fid = "src/f%d.py::f%d::0@%d" % (number, number, number)
        pairs.append((dict(plain, function_id=fid, function_key=fid.split("@")[0],
                           file="src/f%d.py" % number, **extra),
                      {"function_id": fid, "rank": 6 - number if number != 4 else 1,
                       "triage_verdict": verdict}))
    owed = triage_owed(pairs, {})
    check("triage_owed orders by rank, then function_id",
          owed["owed"], ["src/f4.py::f4::0@4", "src/f1.py::f1::0@1", "src/f0.py::f0::0@0"])
    check("and tallies the exclusions a high function no rule matched meets",
          (owed["excluded"]["test-tree"], owed["high_without_hit"]), (1, 4))
    capped = triage_owed(pairs, {}, cap=2)
    check("a cap keeps the first N and names the rest",
          (capped["owed"], capped["over_cap"]),
          (["src/f4.py::f4::0@4", "src/f1.py::f1::0@1"], ["src/f0.py::f0::0@0"]))
    check("a cap of zero keeps none", triage_owed(pairs, {}, cap=0)["owed"], [])
    check("selection_tier reads the cutoff rank, and the cutoff score where there is none",
          (selection_tier({"rank": 3, "score": 0.9}, {"strict": {"cutoff_rank": 3}}),
           selection_tier({"rank": 4, "score": 0.9}, {"strict": {"cutoff_rank": 3},
                                                      "loose": {"cutoff_rank": 5}}),
           selection_tier({"rank": 9, "score": 0.9}, {"strict": {"cutoff_rank": 3}}),
           selection_tier({"rank": None, "score": 0.9},
                          {"strict": {"cutoff_rank": None, "cutoff_score": 0.8}})),
          ("strict", "loose", None, "strict"))
    check("first_text_line skips blank lines and stops at the end of the range",
          (first_text_line(["", "  ", "def f():", "    pass"], 1, 4),
           first_text_line(["", "  ", "def f():"], 1, 2),
           first_text_line(["def f():"], 5, 9)),
          ((3, "def f():"), (None, None), (None, None)))

    # ---- malformed files are refused, and the error names the file ---- #
    refuses("a future schema_version is refused rather than guessed",
            _mutate(GOOD, schema_version=2), fragment="schema_version")
    refuses("a rule in the wrong category file is refused",
            _mutate(GOOD, index=1, rule_id="INJ-002"), fragment="sec-val-injection-input")
    refuses("a pattern that does not compile is refused",
            _mutate(GOOD, index=1, pattern=r"\b(unclosed"), fragment="does not compile")
    refuses("a skip_pattern that does not compile is refused",
            _mutate(GOOD, index=0, skip_pattern=r"(?P<"), fragment="skip_pattern")
    refuses("a skip_pattern with no written clause is refused",
            _mutate(GOOD, index=0, skip_clause=None), fragment="skip_clause")
    refuses("a non-derived rule with no pattern is refused",
            _mutate(GOOD, index=1, pattern=None), fragment="not marked derived")
    refuses("a derived rule with no derivation is refused",
            _mutate(GOOD, index=2, derivation=None), fragment="derivation")
    refuses("an unknown wrapper_class is refused",
            _mutate(GOOD, index=1, wrapper_class="memcpy"), fragment="wrapper_class")
    refuses("a weight outside 1-3 is refused",
            _mutate(GOOD, index=1, weight=7), fragment="weight")
    refuses("a missing required field is refused",
            {"schema_version": 1, "category": "memory-safety",
             "validator": "sec-val-memory-safety",
             "rules": [{"rule_id": "MEM-001"}]}, fragment="missing")
    refuses("a category that disagrees with the file name is refused",
            _mutate(GOOD, category="crypto-auth"), fragment="file name")

    # Rules that load and can never run. Each of these used to pass this loader
    # and print "every pattern compiled", and each one reached coverage.json as
    # a rule that looked at the tree and found it clean.
    refuses("a bare-string languages is refused, not iterated into letters",
            _mutate(GOOD, index=1, languages="python"), fragment="languages")
    refuses("an empty languages list is refused",
            _mutate(GOOD, index=1, languages=[]), fragment="languages")
    refuses("a language no file is assigned is refused, and named",
            _mutate(GOOD, index=1, languages=["c", "javascipt"]), fragment="javascipt")
    refuses("a language listed twice is refused",
            _mutate(GOOD, index=1, languages=["c", "c"]), fragment="twice")
    refuses("match_target null on a pattern rule is refused",
            _mutate(GOOD, index=1, match_target=None), fragment="match_target null")
    refuses("a string where multiline wants a boolean is refused",
            _mutate(GOOD, index=1, multiline="false"), fragment="multiline")
    refuses("a string where high_signal wants a boolean is refused",
            _mutate(GOOD, index=1, high_signal="false"), fragment="high_signal")
    refuses("a string where derived wants a boolean is refused",
            _mutate(GOOD, index=1, derived="no"), fragment="derived")
    refuses("derived_at on a pattern rule is refused: it would claim to be grepped and not be",
            _mutate(GOOD, index=1, derived_at="enrich"), fragment="not derived")
    refuses("a derived_at that names no stage is refused",
            _mutate(GOOD, index=2, derived_at="score"), fragment="derived_at")

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "memory-safety.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{\n  \"schema_version\": 1,\n  oops\n}\n")
        try:
            load_category(path)
            failures += 1
            print("  FAIL truncated JSON loaded without complaint")
        except RulesError as exc:
            # json.JSONDecodeError carries the line; an error naming only the
            # file sends a reader hunting through 50 rules.
            check("a syntax error carries the line it is on",
                  str(exc).startswith(path + ":3"), True)

    with tempfile.TemporaryDirectory() as tmp:
        # The same rule twice. Whichever definition won, coverage invariant I1
        # wants exactly one entry per rule, and the loser vanishes silently.
        doubled = _mutate(GOOD)
        doubled["rules"].append(dict(GOOD["rules"][1]))
        _write(tmp, "memory-safety.json", doubled)
        try:
            load_rules(tmp)
            failures += 1
            print("  FAIL a duplicate rule_id across files loaded without complaint")
        except RulesError as exc:
            check("a rule_id defined twice names both definitions",
                  "already defined" in str(exc), True)

    with tempfile.TemporaryDirectory() as tmp:
        try:
            load_rules(tmp)
            failures += 1
            print("  FAIL an empty rules directory loaded without complaint")
        except RulesError as exc:
            check("an empty rules directory is an error, not zero rules",
                  "no <category>.json" in str(exc), True)

    # ---- rules_hash: what pins the ruleset a run was produced by ---- #
    with tempfile.TemporaryDirectory() as tmp:
        one = os.path.join(tmp, "one")
        two = os.path.join(tmp, "two")
        os.makedirs(one)
        os.makedirs(two)
        _write(one, "memory-safety.json", GOOD)
        _write(two, "memory-safety.json", GOOD)
        base = rules_hash(one)
        check("the same rule bytes hash the same in two directories",
              rules_hash(two), base)
        check("the hash is 16 hex characters",
              (len(base), all(c in "0123456789abcdef" for c in base)), (16, True))

        # The four edits that used to leave two runs looking identically
        # provenanced. Each one changes what the scan actually did.
        _write(one, "memory-safety.json", _mutate(GOOD, 0, weight=9))
        check("a weight change moves the hash", rules_hash(one) == base, False)
        _write(one, "memory-safety.json", _mutate(GOOD, 0, skip_pattern=None))
        check("dropping a skip_pattern moves the hash",
              rules_hash(one) == base, False)
        _write(one, "memory-safety.json", _mutate(GOOD, 1, pattern=r"\brecv\s*\("))
        check("editing the pattern of a rule moves the hash",
              rules_hash(one) == base, False)
        _write(one, "memory-safety.json", GOOD)
        check("and reverting the edit restores it", rules_hash(one), base)

        _write(one, "logic-flaws.json", {"schema_version": 1,
                                         "category": "logic-flaws",
                                         "validator": "sec-val-logic-flaws",
                                         "rules": []})
        check("adding a rule file moves the hash - the listing is the ruleset",
              rules_hash(one) == base, False)
        os.rename(os.path.join(one, "logic-flaws.json"),
                  os.path.join(one, "other-hygiene.json"))
        check("renaming it moves the hash again",
              rules_hash(one) == rules_hash(two), False)

        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        try:
            rules_hash(empty)
            check("a directory with no rule files is refused", False, True)
        except RulesError as exc:
            check("a directory with no rule files is refused",
                  "no <category>.json" in str(exc), True)

    # ---- json_dumps: an artifact a filename cannot kill ---- #
    # The surrogate is what os.walk returns for a latin-1 `src/caf\xe9.c`. It
    # used to take stage 1 down at functions.jsonl, after the whole corpus had
    # been built - so these cases are about a write that completes, not a
    # string that looks right.
    surrogate = "src/caf\udce9.c"
    plain = {"file": "src/parse.c", "name": "handle"}
    check("ordinary records are not escaped - artifacts stay legible",
          json_dumps(plain), json.dumps(plain, ensure_ascii=False))
    legible = {"name": "使用"}
    check("and neither is non-ASCII that encodes fine",
          json_dumps(legible), '{"name": "使用"}')

    rendered = json_dumps({"file": surrogate})
    try:
        rendered.encode("utf-8")
        writable = True
    except UnicodeEncodeError:
        writable = False
    check("a surrogate filename renders to something a UTF-8 file accepts",
          writable, True)
    check("and it round-trips to the same string, not a replacement character",
          json.loads(rendered)["file"], surrogate)
    check("the escape is taken only for the record that needs it",
          json_dumps({"file": surrogate}) != json.dumps({"file": surrogate},
                                                        ensure_ascii=False),
          True)
    try:
        json.dumps({"file": surrogate}, ensure_ascii=False).encode("utf-8")
        check("...and the plain call really is the one that fails", False, True)
    except UnicodeEncodeError:
        check("...and the plain call really is the one that fails", True, True)

    # ensure_ascii is this function's to decide: a caller passing it would get
    # back exactly the crash the function exists to prevent.
    check("an ensure_ascii=False from a caller is overridden, not honoured",
          json.loads(json_dumps({"file": surrogate},
                                ensure_ascii=False))["file"], surrogate)
    check("indent and sort_keys are passed through",
          json_dumps({"b": 1, "a": 2}, indent=2, sort_keys=True),
          '{\n  "a": 2,\n  "b": 1\n}')

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "functions.jsonl")
        with open(path, "w", encoding="utf-8") as fh:
            for record in (plain, {"file": surrogate}, legible):
                fh.write(json_dumps(record) + "\n")
        with open(path, encoding="utf-8") as fh:
            back = [json.loads(line) for line in fh]
        check("three records go out and three come back",
              [r.get("file") or r.get("name") for r in back],
              ["src/parse.c", surrogate, "使用"])

    # ---- ripgrep_hazards: compiles in both engines, means two things ---- #
    for text, fragment in ((r"\<main\b", "word-boundary"), (r"[\w&&\d]", "set operation"),
                           (r"[[:alpha:]]", "nested"), (r"a{,3}", "{0,n}"),
                           (r"a{ 1}", "not a repetition"), (r"x++", "possessive"),
                           (r"(?=a)b", "lookaround"), (r"(\w)\1", "backreference"),
                           (r"(?x) a", "only the i flag"), (r"a\Z", "Python's alone")):
        check("ripgrep reads %s differently, and the hazard is named" % text,
              any(fragment in h for h in ripgrep_hazards(text)), True)
    for text in (r"\b(?:memcpy|memmove)\s*\(", r'(?i:select\s[^"]{0,200}?\bfrom\b)',
                 r"a*?b", r"[({\[|!]", r"#\{", r"(?:|[^`{$][^`$]{0,300}?)"):
        check("...and %s means the same to both" % text, ripgrep_hazards(text), [])

    # ---- the shipped rules, which are the reason this file exists ---- #
    shipped = default_rules_dir()
    if os.path.isdir(shipped):
        try:
            rules = load_rules(shipped)
        except RulesError as exc:
            failures += 1
            print("  FAIL the shipped rules do not load: %s" % exc)
            rules = []
        if rules:
            ids = [r["rule_id"] for r in rules]
            check("the shipped rules load", len(ids), len(set(ids)))
            derived_rules = [r["rule_id"] for r in rules if r["derived"]]
            compiled = sum(1 for r in rules
                           if not r["derived"] and compile_pattern(r) is not None)
            check("every shipped pattern compiles", compiled, len(ids) - len(derived_rules))
            check("MEM-WFS and LOG-TRI are the only derived rules",
                  derived_rules, ["LOG-TRI", "MEM-WFS"])
            by_derived = {r["rule_id"]: r for r in rules}
            check("MEM-WFS is stage 1's and LOG-TRI is stage 3's",
                  (by_derived["MEM-WFS"]["derived_at"], by_derived["LOG-TRI"]["derived_at"]),
                  ("extract", "enrich"))
            check("a pattern rule has no derived_at",
                  by_derived["MEM-002"]["derived_at"], None)
            check("stage 1 runs every rule but LOG-TRI",
                  sorted(set(ids) - {r["rule_id"] for r in stage1_rules(rules)}),
                  ["LOG-TRI"])
            check("LOG-TRI is the logic-flaws validator's, CWE-693, on every language",
                  (by_derived["LOG-TRI"]["validator"], by_derived["LOG-TRI"]["cwe"],
                   sorted(by_derived["LOG-TRI"]["languages"]),
                   by_derived["LOG-TRI"]["high_signal"]),
                  ("sec-val-logic-flaws", "CWE-693", sorted(LANGUAGES), False))
            # Its playbook is a memory-safety pass. Over Python and Go every one of
            # an e2e run's 21 closed FP-WFS-CLEAN, so widening it again is a
            # decision, not an edit.
            check("MEM-WFS runs on C, C++ and Rust and on nothing else",
                  sorted(next(r["languages"] for r in rules
                              if r["rule_id"] == "MEM-WFS")), ["c", "cpp", "rust"])
            check("every HW rule carries the physical-attacker threat model",
                  {r["threat_model"] for r in rules if r["rule_id"].startswith("HW-")},
                  {"physical_attacker"})
            # If this ever grows, something decided a condition was mechanizable.
            # It is the one number in this repository worth re-reading a diff for.
            check("only MEM-002 and OTH-004 carry a skip_pattern",
                  sorted(r["rule_id"] for r in rules if r["skip_pattern"]),
                  ["MEM-002", "OTH-004"])

            by_id = {r["rule_id"]: r for r in rules}

            def skipped(rid, line):
                # One call per line, so the answer must not depend on whether
                # the skip is searched over the whole line or from the hit
                # onward; both are asked, and a disagreement is its own failure.
                hit = compile_pattern(by_id[rid]).search(line)
                if hit is None:
                    return "the rule does not match"
                skip = compile_skip(by_id[rid])
                whole = skip.search(line) is not None
                at_hit = skip.search(line, hit.start()) is not None
                return whole if whole == at_hit else "line and hit disagree"

            # OTH-004's clause is about the HANDLER argument. The skip used to be
            # any SIG_IGN/SIG_DFL/SIG_ERR on the line, and SIG_ERR is never a
            # handler: it is what signal() returns on failure, so the textbook
            # error-checked registration was skipped as "not a handler" while
            # registering one.
            check("OTH-004: a checked registration of a real handler is not skipped",
                  skipped("OTH-004", "if (signal(SIGTERM, on_term) == SIG_ERR)"), False)
            check("OTH-004: nor is a sigaction handler assignment",
                  skipped("OTH-004", "sa.sa_handler = on_term;"), False)
            check("OTH-004: SIG_IGN as the handler is skipped",
                  skipped("OTH-004", "signal(SIGPIPE, SIG_IGN);"), True)
            check("OTH-004: ...and so is its own error check",
                  skipped("OTH-004", "if (signal(SIGINT, SIG_IGN) == SIG_ERR)"), True)
            check("OTH-004: SIG_DFL assigned to sa_handler is skipped",
                  skipped("OTH-004", "sa.sa_handler = SIG_DFL;"), True)
            check("OTH-004: the Python spelling of SIG_IGN is skipped",
                  skipped("OTH-004", "signal.signal(signal.SIGPIPE, signal.SIG_IGN)"),
                  True)

            # MEM-002's back-reference assumes the first argument is the
            # destination and the third a byte count. bcopy takes the source
            # first, so sizeof(first) is sizeof(<source>); wmemcpy/wmemmove count
            # wchar_t, so sizeof(dest) overstates the bound by sizeof(wchar_t).
            # Each is the overflow itself, so none of them may skip.
            check("MEM-002: sizeof(dest) still skips memcpy",
                  skipped("MEM-002", "memcpy(r->payload, local, sizeof(r->payload));"),
                  True)
            check("MEM-002: bcopy's sizeof(first) is sizeof(source) and is not skipped",
                  skipped("MEM-002", "bcopy(big, dst, sizeof(big));"), False)
            check("MEM-002: wmemcpy counts elements, so sizeof(dest) is not skipped",
                  skipped("MEM-002", "wmemcpy(wdst, wsrc, sizeof(wdst));"), False)
            check("MEM-002: nor is wmemmove's",
                  skipped("MEM-002", "wmemmove(wdst, wsrc, sizeof wdst);"), False)

            # MEM-007 used to match only realpath(p, NULL) - the one form the
            # validator is told is fine - and nothing matched realpath(p, buf).
            m7 = compile_pattern(by_id["MEM-007"])
            check("MEM-007: realpath into a caller buffer is a candidate",
                  bool(m7.search("char out[64]; realpath(user_path, out);")), True)
            # ...and the branch opens on a non-word character rather than on `\b`.
            # The candidate gate drops the `\b` in front of a call name to ask
            # whether a wrapper hid sites from the rule, and refuses the run when
            # it finds more than the rule caught. MEM-007 has no wrapper_class,
            # so there is no wrapper to name: under `\brealpath\s*\(` any tree
            # with one realpath() and a `safe_realpath` helper used five times -
            # or Ruby's `rb_iseq_realpath` - was refused with nothing an
            # operator could change. Written this way it matches the same calls
            # and holds no anchor for the gate to drop.
            loose7 = re.compile(m7.pattern.replace(r"\b", ""))
            for line in ("static char *safe_realpath(const char *p, char *out)",
                         "VALUE rb_iseq_realpath(const rb_iseq_t *iseq);"):
                check("MEM-007: a *_realpath helper matches with or without the anchors: "
                      "%s" % line, (bool(m7.search(line)), bool(loose7.search(line))),
                      (False, False))
            for line in ("x = realpath(p, NULL);", "if (!p->realpath(a))", "realpath(a, b);"):
                check("MEM-007: realpath itself still does: %s" % line,
                      bool(m7.search(line)), True)

            # The per-language spellings, and the shapes they must not take for
            # a sink. The negatives live here because the fixture cannot hold
            # one: smoke_test counts an unexpected hit and never fails on it.
            # INJ-002's bare exec/spawn branch matched every method DEFINED with
            # that name - 64 `async exec (args) {` command classes on the npm
            # tree, each on a high-signal rule whose dismissal the arbiter must
            # review - so the name now needs a call context: punctuation, `=>`,
            # `: ` or a statement keyword before it, an argument after it, and
            # an argument list that does not close onto `{`.
            probes = (
                ("INJ-002", True, (
                    "exec(userCmd)", "  const child = spawn(bin, args)", "  return exec(cmd)",
                    "  await execFile(bin, args)", "  p.then(() => exec(cmd))",
                    "  ok ? exec(a) : exec(b)", "  exec(cmd, function (err) {",
                    '  exec("ls #{dir}")', "  $o = exec($cmd);", "  return spawn([",
                    '  const out = execFileSync("git", ["log", ref])',
                    "x = `ls $d`", "  `ls #{dir}`")),
                ("INJ-002", False, (
                    "  async exec (args) {", "  exec (args) {", "  static async exec(args) {",
                    "  async #exec (cmd, args) {", "    await this.#exec(cmd, args)",
                    "  def exec(self, sock, ver, path):", "function spawn(command, args, options) {",
                    "(function exec() {", "func exec(cmd string) error {", "re.exec(s)",
                    "  /* the child calls exec() when it is ready */",
                    "  throw new Error(`Add ${dir} to your $PATH`)")),
                # Qt's modal loop is `dialog->exec()`, with no SQL to inject.
                ("INJ-003", True, ("$this->db->query($sql);", "$r = $this->db->query(",
                                   "pqxx::result r = txn->exec(sql);")),
                ("INJ-003", False, ("if (dialog->exec() == QDialog::Accepted)",)),
                ("INJ-004", True, (
                    'return readFile("/srv/docs/" + name, "utf8");',
                    "await writeFile(path.join(root, name), data)", "  return fsp.readFile(p)",
                    "  await rm(dir, { force: true })", "  const names = readdirSync(dir)",
                    'include("pages/" . $p . ".php");', "include $page;",
                    "require_once __DIR__ . '/lang/' . $lang . '.php';")),
                ("INJ-004", False, (
                    "  async readFile(path) {", "promises.push(fetchOne(id))",
                    "require(['jquery'], function($) {", '#include "config.h"',
                    'require_once __DIR__ . "/vendor/autoload.php";',
                    'self.WriteLn("include $(CLEAR_VARS)")')),
                # `new URL(u)` parses; `Net::HTTPSuccess` is a response class; an
                # import names a library and makes no request.
                ("INJ-005", True, (
                    "InputStream in = url.openStream();", "new java.net.URL(u).openConnection()",
                    "Net::HTTP.get(URI(u))", "klass = Net::HTTP::Proxy(h, p)",
                    "s = requests.Session()", "async with aiohttp.ClientSession() as session:",
                    "let c = reqwest::Client::new();", "use reqwest::blocking::Client;")),
                ("INJ-005", False, (
                    "const u = new URL(args[0])", "when Net::HTTPSuccess, Net::HTTPNotModified",
                    "@requests.each(&block)", "requests.push(fetchOne(id))", "import aiohttp",
                    "fn f() -> Result<(), reqwest::Error> {")),
                ("CRY-004", True, ('new https.Agent({ "rejectUnauthorized": false })',
                                   "{ rejectUnauthorized: false }")),
            )
            for rid, want, lines in probes:
                rx = compile_pattern(by_id[rid])
                for line in lines:
                    check("%s %s %s" % (rid, "matches" if want else "does not match", line),
                          bool(rx.search(line)), want)

            # A name rule's probes are `<file>::<function>` targets through the
            # one name matcher (see "name targets"): a keyword opening any
            # identifier segment selects the function, one inside a lowercase
            # segment does not.
            name_probes = (
                ("LOG-001", True, ("src/pam.c::pam_authenticate", "a.java::isAuthenticated",
                                   "a.c::HTTPAuthCheck", "a.c::login_handler",
                                   "a.c::userLogin", "src/user_auth.c::init",
                                   "u.c::unzOpenCurrentFilePassword")),
                ("LOG-001", False, ("a.c::unauthorized", "a.c::reauth", "a.c::helper")),
                ("LOG-003", True, ("a.c::get_key", "a.c::check_mac", "a.c::HmacSha256")),
                ("LOG-003", False, ("a.c::monkey", "a.c::hotkey", "a.c::stomach")),
                ("LOG-004", True, ("lib/x509_crt.c::foo", "a.cc::verify",
                                   "e.c::mbedtls_ecdsa_verify")),
                ("LOG-005", True, ("a.c::load_private_key_file", "a.js::getApiKey")),
                ("LOG-007", True, ("b.c::mbedtls_mpi_exp_mod",)),
                ("HW-007", True, ("e.c::mbedtls_ecdsa_verify", "d.c::unlock_device",
                                  "Flash.cpp::Unlock", "unlock/seq.c::step")),
                # `compare` and a prefixed `unlock` were 48 and 19 lock/sort
                # functions against 2 security sequences across six corpora.
                ("HW-007", False, ("d.c::reverify", "d.c::reboot_count", "d.c::log_unlock",
                                   "x.c::mutex_unlock", "x.c::xmlSchemaCompareValues")),
                # The tails narrowed when segment matching multiplied them: each
                # pair is a real selection kept and the noise it no longer takes.
                ("LOG-002", True, ("a.c::drop_privileges", "a.c::priv_check_cred",
                                   "a.c::isPrivileged")),
                ("LOG-002", False, ("rsa.c::mbedtls_rsa_private", "u.c::xmlUCSIsPrivateUseArea")),
                ("LOG-003", True, ("k.c::derive_key", "k.c::deriveBits")),
                ("LOG-003", False, ("s.c::xmlSchemaCheckCOSDerivedOK",)),
                ("LOG-004", True, ("pk.c::mbedtls_pk_sign", "a.js::signData",
                                   "p.c::pkcs7_signed_data", "e.c::EVP_DigestSignctx")),
                ("LOG-004", False, ("t.c::install_signal_handlers",
                                    "x.c::xmlSchemaValDecimalGetSignificantDigitCount")),
                ("LOG-006", True, ("a.py::deserialize_obj", "A.java::readSerializable")),
                ("LOG-006", False, ("x509.c::mbedtls_x509_get_serial", "t.py::transfer_serial")),
                ("LOG-010", True, ("t.c::xmlValidateQName", "u.c::hostname_check",
                                   "a.js::isValid", "c.c::checkSum")),
                ("LOG-010", False, ("s.c::ssl_update_checksum_sha256",
                                    "e.c::xmlParserValidityError")),
            )
            for rid, want, targets in name_probes:
                rx = compile_name_pattern(by_id[rid]["pattern"])
                for target in targets:
                    check("%s %s name %s" % (rid, "selects" if want else "does not select",
                                             target), bool(rx.search(target)), want)

            # `probes` compiles each rule's `pattern`, and a name rule's pattern
            # is its NAME half. A LOG row added there would search a function-
            # name regex over a source line and pass for the wrong reason:
            # LOG-005's name half matches `SECRET_KEY = '...'` as text, where its
            # line half did not. So that table holds line rules only, and a name
            # rule's sink half is probed in `line_probes` below.
            check("the line probes hold only line rules",
                  sorted({rid for rid, _, _ in probes if by_id[rid]["match_target"] != "line"}),
                  [])
            check("the name probes hold only name rules",
                  sorted({rid for rid, _, _ in name_probes
                          if by_id[rid]["match_target"] != "function_or_path"}), [])

            # Every LOG rule's name half, both ways, in names real code uses:
            # Mbed TLS, OpenSSL, OpenSSH, WordPress. A row that selects is a
            # selection a reviewer would keep; a row that does not is a keyword
            # inside a word, or a name the rule is not about. Noise only a
            # reader can tell apart - `hash` a table, `token` a lexer's,
            # `sign_in` a login to LOG-004 - is not pinned either way
            # (rules/README.md). LOG-008's and LOG-009's name halves had no row
            # before this table.
            # The rows under a comment are pattern fixes, measured over Mbed
            # TLS's library/, tf-psa-crypto/core/ and
            # tf-psa-crypto/drivers/builtin/src/ (2,133 functions), and each
            # failed before its fix.
            log_name_probes = (
                ("LOG-001", True, ("modules/pam_unix/support.c::pam_sm_authenticate",
                                   "sshd.c::mm_answer_authpassword", "a.go::Authorizer",
                                   "a.cs::OnAuthorization", "a.c::authorise_user",
                                   "a.c::authn_check",
                                   "Controllers/AccountController.cs::PasswordSignInAsync")),
                ("LOG-001", False, ("a.c::signing_key", "a.c::sign_input", "a.c::design_info")),
                # `auth\w*` took `author` and `authority`: 2 of LOG-001's 21
                # selections there were X.509 authority-key-id code. The SSH
                # `userauth` family, `sign_in`, `signon` and `logged_in` were not
                # selected; `sign_in` reached only LOG-004, as a signature.
                ("LOG-001", True, ("sshconnect2.c::userauth_pubkey",
                                   "src/client.c::ssh_userauth_publickey",
                                   "middleware/index.js::isLoggedIn",
                                   "app/helpers/sessions_helper.rb::logged_in?",
                                   "app/controllers/users_controller.rb::sign_in",
                                   "wp-includes/user.php::wp_signon",
                                   "wp-includes/pluggable.php::is_user_logged_in")),
                ("LOG-001", False, ("library/x509_crt.c::x509_get_authority_key_id",
                                    "library/x509write_crt.c::"
                                    "mbedtls_x509write_crt_set_authority_key_identifier",
                                    "git/objects/commit.py::get_author",
                                    "x/CertUtil.java::getAuthorityInfoAccess",
                                    "plumbing/object/commit.go::Author")),
                ("LOG-002", True, ("fs/namei.c::inode_permission",
                                   "auth2-pubkey.c::user_key_allowed", "a.c::permissions",
                                   "a.c::perms", "x.c::permit_root", "a.js::hasPermission")),
                ("LOG-002", False, ("a.c::disallowed_chars",)),
                # `perm\w*` took the Keccak-f permutation: Mbed TLS's own vendored
                # mldsa-native has `mld_keccakf1600_permute`.
                ("LOG-002", False, ("tf-psa-crypto/drivers/pqcp/mldsa-native/mldsa/src/"
                                    "fips202/keccakf1600.c::mld_keccakf1600_permute",
                                    "keccak.c::KeccakP1600_Permute_24rounds",
                                    "itertools_ext.py::next_permutation")),
                # A path selects every function in its file, by design:
                # cipher_wrap.c's 47 of 47 in Mbed TLS. `crypt` is CRY-001/002's;
                # `crypt\w*` would take every crypto_* path in tf-psa-crypto.
                ("LOG-003", True, ("crypto/evp/evp_enc.c::EVP_EncryptInit_ex",
                                   "a.cs::CreateEncryptor", "a.cs::Rfc2898DeriveBytes",
                                   "a.js::createCipheriv", "a.py::salted_hmac",
                                   "a.java::SecretKeySpec",
                                   "tf-psa-crypto/drivers/builtin/src/cipher_wrap.c::"
                                   "aes_crypt_cbc_wrap")),
                ("LOG-003", False, ("a.c::macro_expand", "a.py::derived_class",
                                    "tf-psa-crypto/drivers/builtin/src/aes.c::"
                                    "mbedtls_aes_crypt_ecb")),
                # `key\w*` cannot open inside `privkey` or `pubkey`, nor `kdf\w*`
                # inside `hkdf` or `pbkdf2`: 18 functions there, 12 private- or
                # public-key ones and 6 HKDF/PBKDF2 ones, and
                # `mbedtls_ecp_gen_privkey` had no rule of any category.
                ("LOG-003", True, ("tf-psa-crypto/drivers/builtin/src/ecp.c::"
                                   "mbedtls_ecp_gen_privkey",
                                   "e.c::mbedtls_ecp_check_pubkey",
                                   "r.c::mbedtls_rsa_check_privkey",
                                   "p.c::EVP_PKEY_derive", "library/hkdf.c::mbedtls_hkdf_expand",
                                   "tf-psa-crypto/core/psa_crypto.c::psa_pbkdf2_set_salt",
                                   "django/utils/crypto.py::pbkdf2",
                                   "golang.org/x/crypto/hkdf/hkdf.go::New")),
                # `lib/x509/verify.c::check_if_ca` (GnuTLS CVE-2014-0092) is
                # selected by its path alone.
                ("LOG-004", True, ("sslKeyExchange.c::SSLVerifySignedServerKeyExchange",
                                   "lib/x509/verify.c::check_if_ca",
                                   "crypto/x509/x509_vfy.c::X509_verify_cert",
                                   "a.cs::ValidateServerCertificate", "a.cs::VerifyHash",
                                   "a.cs::CheckSignature", "a.rb::valid_signature?",
                                   "src/pki.c::ssh_pki_signature_verify",
                                   "jwt/claims.go::VerifyAudience", "a.c::cert_authority_check",
                                   "a.go::CertPool")),
                ("LOG-004", False, ("library/x509write_crt.c::mbedtls_x509write_crt_der",)),
                # `cert\w*` took `certain`, in Mbed TLS's own framework scripts.
                # The Java trust manager, whose empty body is the whole bug, was
                # selected by LOG-010 as a check and never as a certificate.
                ("LOG-004", True, ("src/main/java/a/TrustAll.java::checkServerTrusted",
                                   "src/main/java/a/TrustAll.java::checkClientTrusted")),
                # `verify\w*` never opened on `verification` or `verified`, so
                # CVE-2025-27809's site, Mbed TLS's get_hostname_for_verification,
                # was selected by no rule at its pre-patch commit.
                ("LOG-004", True, ("library/ssl_tls.c::get_hostname_for_verification",
                                   "a.c::verified_boot", "k.c::VerifierInit")),
                ("LOG-004", False, ("x.c::reverify", "x.c::unverified_input")),
                ("LOG-004", False, ("framework/scripts/mbedtls_framework/min_requirements.py::"
                                    "pylint_doesn_t_notice_that_certain_types_"
                                    "are_used_in_annotations",
                                    "src/ml/eval.py::is_certain")),
                # What stores a password or makes a token is LOG-001's and
                # LOG-009's, not LOG-005's.
                ("LOG-005", True, ("ssl/ssl_rsa.c::SSL_CTX_use_PrivateKey_file",
                                   "django/core/management/utils.py::get_random_secret_key",
                                   "Vault.cs::GetClientSecret")),
                ("LOG-005", False, ("kbd.c::private_keyboard_map",
                                    "pkg/auth/store.go::StorePassword",
                                    "auth/tokens.py::generate_token", "a.c::pskip_frames")),
                # `privkey`, plural keys and a pre-shared key were not selected:
                # +46 there, 5 private-key and 41 PSK functions.
                ("LOG-005", True, ("library/ecp.c::mbedtls_ecp_gen_privkey",
                                   "src/pki.c::ssh_pki_import_privkey_file",
                                   "app/keys.py::load_api_keys",
                                   "src/Crypto.java::readPrivateKeys",
                                   "library/ssl_tls.c::mbedtls_ssl_conf_psk")),
                ("LOG-006", True, ("pkg/api/types.go::UnmarshalJSON",
                                   "com/fasterxml/Bean.java::deserialize")),
                ("LOG-006", False, ("a.py::download_session",)),
                # LOG-006 selected none of the 2,133 functions, in a tree whose
                # ssl.h documents `mbedtls_ssl_session_load` and
                # `mbedtls_ssl_context_load` as loading serialized data. Now 7,
                # those and their internal halves in ssl_tls.c.
                ("LOG-006", True, ("library/ssl_tls.c::mbedtls_ssl_session_load",
                                   "library/ssl_tls.c::ssl_context_load",
                                   "app/cache.py::unpickle_session")),
                ("LOG-006", False, ("a.c::session_loadavg_stats",)),
                ("LOG-007", True, ("crypto/bn/bn_exp.c::BN_mod_exp_mont_consttime",
                                   "crypto/bn/bn_exp2.c::mod_exp2_mont",
                                   "cipher/mpi-pow.c::_gcry_mpi_powm",
                                   "crypto_scalarmult/curve25519/ref10/x25519_ref10.c::"
                                   "crypto_scalarmult_curve25519_ref10",
                                   "crypto/elliptic/elliptic.go::ScalarMult",
                                   "a.c::montgomery_ladder",
                                   "tf-psa-crypto/drivers/builtin/src/bignum.c::"
                                   "mbedtls_asn1_get_mpi")),
                ("LOG-007", False, ("src/net.c::exponential_backoff",)),
                # `scalar_?mult` needs the t, so it missed OpenSSL's `scalar_mul`,
                # and nothing spelled an `ecp_mul`: LOG-007 selected none of the
                # ten in Mbed TLS, and `mbedtls_ecp_mul` and the CVE-2020-10932
                # site `ecp_mul_comb_after_precomp` had no rule of any category.
                # The open `\w*` tails took `mod_export`, `mod_expr`, `exp_model`
                # and `scalar_multiply`, and `mpi_` under `(?i:)` took the Message
                # Passing Interface; it is case-sensitive now.
                ("LOG-007", True, ("tf-psa-crypto/drivers/builtin/src/ecp.c::mbedtls_ecp_mul",
                                   "library/ecp.c::ecp_mul_comb_after_precomp",
                                   "library/ecp.c::ecp_mul_mxz",
                                   "crypto/ec/ec_mult.c::ossl_ec_scalar_mul_ladder",
                                   "crypto/ec/ec_lib.c::EC_POINT_mul",
                                   "crypto/elliptic/elliptic.go::ScalarBaseMult",
                                   "src/ecmult_const_impl.h::secp256k1_ecmult_const",
                                   "java/math/BigInteger.java::modPow", "mpz/powm.c::mpz_powm_sec",
                                   "rsa/core.py::powmod")),
                ("LOG-007", False, ("src/solver.c::MPI_Allreduce",
                                    "kernel/module.c::mod_export_symbol",
                                    "src/parser.py::mod_expr", "train/run.py::load_exp_model",
                                    "src/linalg.c::scalar_multiply",
                                    "drivers/net/wifi.c::set_powmode",
                                    "drivers/pm.c::powmgmt_enable")),
                # LOG-008's `\w{0,64}?` prefix is the one deliberate substring
                # search among the name rules.
                ("LOG-008", True, ("src/auth.c::verify_password",
                                   "webhook/github.go::ValidateSignature", "fw.c::verify_pin",
                                   "api.ts::checkToken", "a.c::getpassword")),
                ("LOG-008", False, ("django/utils/crypto.py::constant_time_compare",)),
                ("LOG-009", True, ("src/api.ts::checkToken",
                                   "library/ssl_cookie.c::local_err_translation",
                                   "ssl/statem/statem_srvr.c::tls_construct_new_session_ticket",
                                   "handlers.go::RefreshToken",
                                   "Startup.cs::ConfigureApplicationCookie",
                                   "a.py::token_type", "a.java::getTokenId", "a.go::TokenExpiry")),
                ("LOG-009", False, ("libio/iofopncook.c::fopencookie", "a.c::detokenize",
                                    "a.c::log_output")),
                # LOG-009 did not select the session-ticket code, which is where
                # TLS expires a session (`mbedtls_ssl_ticket_parse` compares the
                # ticket's age with its lifetime, ssl_ticket.c:418), nor logout or
                # remember-me: +16 there, the whole of ssl_ticket.c and the TLS
                # 1.3 ticket functions. `token\w*` took every tokenizer.
                ("LOG-009", True, ("library/ssl_ticket.c::mbedtls_ssl_ticket_parse",
                                   "ssl/t1_lib.c::tls_decrypt_ticket",
                                   "flask_login/utils.py::logout_user",
                                   "routes/auth.js::handleLogout",
                                   "wp-includes/pluggable.php::wp_logout",
                                   "app/controllers/application_controller.rb::sign_out",
                                   "x/SecurityConfig.java::rememberMeServices")),
                ("LOG-009", False, ("json_tokener.c::json_tokener_parse_ex",
                                    "nlp/tokenizer.py::split_words", "a.py::tokenise")),
                # A path selects every function in its file (check_files.py), and
                # a camelCase hump ends `check` as `_` does.
                ("LOG-010", True, ("library/ssl_msg.c::ssl_parse_record_header",
                                   "library/ecp.c::mbedtls_ecp_check_pubkey",
                                   "net/crc.c::verify_check_sum",
                                   "scripts/check_files.py::normalize_path",
                                   "a.c::checkbounds", "a.c::checkpolicy", "a.js::checkOut",
                                   "a.c::checkorigin")),
                # The shipped rule does not select a bare `parse`; the synthetic
                # LOG-010 in extract_functions.py's selftest does, on purpose.
                ("LOG-010", False, ("src/a.c::invalidate_cache", "src/app.py::parse")),
                # `parse_` needed its underscore and knew four nouns: LOG-010
                # selected 2 of the 100 functions there with parse in the name,
                # and none of the TLS hello and extension parsers (+42). `ext`
                # takes the underscore before it, so `parse_text` and
                # `parse_context` stay out; a `\b` there would be a leading
                # anchor to loosen_name, and the zero-hit test would count
                # `parse_text` as a parser the rule missed. `check` stopped
                # taking checkout, checkpoint and checkbox the way it already did
                # checksum, and keeps checkbounds and checkpolicy above.
                ("LOG-010", True, ("net/proto.py::parse_message", "src/net.js::parsePacket",
                                   "proto/wire.go::ParseMessage", "src/net.c::parse_pkt",
                                   "library/ssl_tls12_server.c::ssl_parse_client_hello",
                                   "library/ssl_tls.c::mbedtls_ssl_parse_server_name_ext",
                                   "app/forms.py::sanitise_filename")),
                ("LOG-010", False, ("ml/train.py::save_checkpoint", "shop/cart.js::checkout",
                                    "vcs/git.py::git_checkout_branch",
                                    "ui/form.js::renderCheckbox", "a.c::parse_text",
                                    "a.c::parse_context")),
            )
            for rid, want, targets in log_name_probes:
                rx = compile_name_pattern(by_id[rid]["pattern"])
                for target in targets:
                    check("%s %s name %s" % (rid, "selects" if want else "does not select",
                                             target), bool(rx.search(target)), want)
            check("every LOG rule's name half is probed both ways",
                  sorted({(rid, want) for rid, want, _ in log_name_probes}),
                  sorted((r["rule_id"], want) for r in rules
                         if r["rule_id"].startswith("LOG-") and not r["derived"]
                         for want in (False, True)))

            # A name rule's SINK half, compiled the way stage 1 compiles it:
            # resolve_line_pattern, then re.compile (CompiledRules.line_halves in
            # extract_functions.py). Nothing ran a shipped one on a sample line
            # before this table, and the fixture held no LOG-004 sink at all.
            ghp = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"   # built, not a literal token
            line_probes = (
                ("LOG-004", True, ("if (EVP_DigestVerifyFinal(ctx, sig, siglen) == 1)",
                                   "ret = RSA_verify(NID_sha256, m, mlen, sig, siglen, rsa);",
                                   "X509_verify_cert(ctx);",
                                   "    crypto_sign_open(m, &mlen, sm, smlen, pk);",
                                   "boolean ok = sig.verify(sigBytes);",
                                   "const decoded = jwt.verify(token, process.env.SECRET);",
                                   "pub.verify(OpenSSL::Digest::SHA256.new, sig, data)",
                                   "verifying_key.verify(&msg, &signature).is_ok()")),
                ("LOG-004", False, ("if (ssl->conf->verify_mode == MBEDTLS_SSL_VERIFY_NONE)",
                                    "x = cfg.verify;")),
                # The half knew OpenSSL's digest verify and a lowercase `.verify(`.
                # EVP_VerifyFinal, DSA_verify and EVP_PKEY_verify return -1 on
                # error, which `if (i)` takes for a good signature (CVE-2008-5077);
                # Mbed TLS verifies through mbedtls_pk_verify*, mbedtls_x509_crt_
                # verify* and psa_*verify*, and 9 functions there call one that
                # LOG-004 did not select (mbedtls_ssl_decrypt_buf's record MAC
                # check among them); Go and C# capitalise Verify. The Mbed TLS and
                # PSA calls, like crypto_sign_open, need a call context before
                # them, so a prototype or a doc comment naming one is not a call:
                # 31 of the 53 crypto_sign_open lines in the tree were those.
                ("LOG-004", True, ("i = EVP_VerifyFinal(&md_ctx, p, (int)n, pkey);",
                                   "if (EVP_PKEY_verify(pctx, sig, siglen, md, mdlen))",
                                   "if (DSA_verify(0, dgst, len, sig, siglen, dsa))",
                                   "if (ECDSA_do_verify(dgst, dlen, s, eckey) != 1)",
                                   "if (ED25519_verify(msg, len, sig, pub))",
                                   "if (crypto_sign_verify_detached(sig, m, mlen, pk) != 0)",
                                   "ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, "
                                   "sig, sig_len);",
                                   "    ret = mbedtls_pk_verify_ext((mbedtls_pk_sigalg_t) pk_alg, "
                                   "peer_pk,",
                                   "    mbedtls_x509_crt_verify(&chain, &ca, NULL, NULL, &flags, "
                                   "NULL, NULL);",
                                   "status = psa_verify_hash(key, alg, hash, hlen, sig, slen);",
                                   "    return mbedtls_ecdsa_verify(grp, buf, blen, Q, r, s);",
                                   "gnutls_certificate_verify_peers2(session, &status);",
                                   "wc_ecc_verify_hash(sig, siglen, hash, hashlen, &res, &key);",
                                   "return ctx->pk_info->verify_func(ctx->pk_ctx, md_alg, hash, "
                                   "hlen, sig, slen);",
                                   "if (!ed25519.Verify(pub, msg, sig) {",
                                   "err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)",
                                   "if _, err := cert.Verify(opts); err != nil {",
                                   "bool ok = rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, "
                                   "RSASignaturePadding.Pkcs1);",
                                   "if (signedXml.CheckSignature()) {",
                                   "$ok = openssl_verify($data, $sig, $pub, OPENSSL_ALGO_SHA256);",
                                   "return sodium_crypto_sign_verify_detached($sig, $msg, $pk);",
                                   "ring::signature::verify(&signature::ED25519, pk, msg, "
                                   "sig)?;")),
                # A discarded return value is the LOG-004 defect itself, and the
                # call context above had no `)`: `(void) crypto_sign_open(...)`,
                # which the bare branch used to match, and every cast,
                # brace-less `if`, brace, `;`, `else` or closing comment in
                # front of an Mbed TLS or PSA call read as no call at all.
                ("LOG-004", True, ("    (void) mbedtls_pk_verify(&pk, md, h, 0, s, sl);",
                                   "    (void) crypto_sign_open(m, &mlen, sm, smlen, pk);",
                                   "    (void)crypto_sign_open(m, &mlen, sm, smlen, pk);",
                                   "    if (x) psa_verify_hash(k, a, h, hl, s, sl);",
                                   "    ret = (int) psa_verify_hash(k, a, h, hl, s, sl);",
                                   "    if (x) { psa_verify_hash(k, a, h, hl, s, sl); }",
                                   "    ret = 0; mbedtls_pk_verify(&pk, md, h, 0, s, sl);",
                                   "    } else mbedtls_pk_verify(&pk, md, h, 0, s, sl);",
                                   "    /* checked by caller */ mbedtls_pk_verify(&pk, md, h, "
                                   "0, s, sl);")),
                # crypto_sign_open is also called through a binding - PHP's
                # sodium_ prefix, libsodium.js's and PyNaCl's `.` - and compared
                # or negated, and the context above took none of them: a tree
                # whose only open was one of these had no LOG-004 hit at all.
                # PHP's returns false on a bad signature, which an unchecked
                # result reads as the message.
                ("LOG-004", True, ("    $msg = sodium_crypto_sign_open($signed, $pk);",
                                   "  const msg = sodium.crypto_sign_open(signed, publicKey);",
                                   "    msg = nacl.bindings.crypto_sign_open(sm, pk)",
                                   "    if (0 > crypto_sign_open(m, &mlen, sm, smlen, pk))",
                                   "    ret = -crypto_sign_open(m, &mlen, sm, smlen, pk);",
                                   "    if (PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(m, &mlen, sm, "
                                   "smlen, pk) != 0)")),
                ("LOG-004", False, ("int PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(uint8_t *m, "
                                    "size_t *mlen,",
                                    "PHP_FUNCTION(sodium_crypto_sign_open)",
                                    " * - crypto_sign_open() verifies and opens")),
                # X509_verify\w* took the error-string lookup a failed verify logs.
                ("LOG-004", False, ('fprintf(stderr, "%s\\n", '
                                    'X509_verify_cert_error_string(err));',
                                    " * Name:        crypto_sign_open",
                                    "#define crypto_sign_open MLD_API_NAMESPACE(open)",
                                    "int mbedtls_pk_verify(mbedtls_pk_context *ctx, "
                                    "mbedtls_md_type_t md_alg,",
                                    " * \\brief  This function verifies a signature, as "
                                    "mbedtls_pk_verify_ext does",
                                    "int crypto_sign_open(uint8_t *m, size_t *mlen, "
                                    "const uint8_t *sm, size_t smlen,",
                                    "/** Verify. */ int mbedtls_pk_verify(mbedtls_pk_context "
                                    "*ctx,")),
                ("LOG-005", True, ('static const char *password = "hunter2hunter2";',
                                   "const id = 'AKIAIOSFODNN7EXAMPLE';",
                                   '"-----BEGIN EC PRIVATE KEY-----\\n"',
                                   'apiKey := "abcd1234efgh5678-not-real"',
                                   "'password' => 'hunter2hunter2',", 'token = "%s"' % ghp)),
                ("LOG-005", False, ("password = request.form['password']", "token_type = 'Bearer'",
                                    '"-----BEGIN PUBLIC KEY-----\\n"',
                                    "api_key = os.environ['API_KEY']")),
                # The keyword had to sit right before the `=`, so Django's and
                # Flask's SECRET_KEY and Rails' secret_key_base were never matched.
                ("LOG-005", True, ("SECRET_KEY = 'django-insecure-0123456789abcdefghij'",
                                   "app.config['SECRET_KEY'] = 'super-secret-dev-key'",
                                   "config.secret_key_base = 'a1b2c3d4e5f6a1b2c3d4e5f6'",
                                   "privkey = '4f3c2b1a0987654321fedcba'")),
                # A `]` counts only after a quote, as in config['SECRET_KEY']; a
                # bare one takes Mbed TLS's extension-name table, ssl_tls.c:638.
                ("LOG-005", False, ('    [MBEDTLS_SSL_EXT_ID_EXTENDED_MASTER_SECRET] = '
                                    '"extended_master_secret",',)),
                ("LOG-006", True, ("obj = pickle.loads(blob)",
                                   "cfg = yaml.load(text, Loader=yaml.FullLoader)",
                                   "len = *(struct hdr *)p;",
                                   "auto *h = reinterpret_cast<const Header *>(data);",
                                   "Object o = new ObjectInputStream(in).readObject();",
                                   "var o = new BinaryFormatter().Deserialize(s);",
                                   "Marshal.load(blob)", "$o = unserialize($data);")),
                ("LOG-006", False, ("cfg = yaml.safe_load(text)", "data = json.loads(body)",
                                    "pickle.dump(obj, fh)", "yaml.dump(cfg, fh)")),
                # pickle.load reads a file where pickle.loads reads bytes, and
                # yaml.unsafe_load and full_load (CVE-2020-14343) say what they do.
                ("LOG-006", True, ("obj = pickle.load(open(path, 'rb'))",
                                   "obj = cPickle.loads(data)", "cfg = yaml.unsafe_load(text)",
                                   "docs = yaml.load_all(stream)", "cfg = yaml.full_load(text)",
                                   "code = marshal.loads(data)",
                                   "data = YAML.load(params[:doc])")),
                ("LOG-008", True, ("if (given == stored_pin)", "return given == API_KEY",
                                   "if (sig === expected) {",
                                   "if (memcmp(tag, expected_tag, 16) != 0)",
                                   "return token === apiKey;",
                                   'if (strcmp(argv[i], "--help") == 0)',
                                   "if (user.password == input)", "if (secret_key == provided)",
                                   "if (apiKey !== expected) {",
                                   "if hmac.new(k, m, sha256).hexdigest() == sig:",
                                   "if (expectedSignature.equals(sig)) {")),
                ("LOG-008", False, ("if not hmac.compare_digest(sig, expected):",
                                    "if subtle.ConstantTimeCompare(mac, expected) == 1 {",
                                    "if (mbedtls_ct_memcmp(tag, check_tag, tag_len) != 0)",
                                    "if (!MessageDigest.isEqual(a, b)) {",
                                    "if (!CryptographicOperations.FixedTimeEquals(a, b))")),
                # A keyword was any substring followed by any 64 word characters,
                # and any ALL-CAPS constant holding one counted on the right: 330
                # of the 2,133 functions were selected, 58 for `tag` inside
                # MBEDTLS_SSL_TRANSPORT_DATAGRAM (76 lines), and not one of a
                # seeded 10 compared a secret. It is now the identifier's last
                # segment, and in capitals only a secret's name: 169, every one
                # of them selected before. The PHP and Ruby request lookups and
                # Go's and Java's byte compares were not matched.
                ("LOG-008", False, ("if (transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM) {",
                                    "if (operation->stage != PSA_PAKE_OPERATION_STAGE_SETUP) {",
                                    "if (ret == MBEDTLS_ERR_SSL_INVALID_MAC) {",
                                    "if (signal(SIGTERM, on_term) == SIG_ERR)",
                                    "if (mapping == NULL)", "if (rootpath == NULL)",
                                    "if (ctx->cmac_ctx == NULL)", "if (hash_len == 0)",
                                    "if (tok->type == TOKEN_EOF)",
                                    "if (md_info->sig_alg != MBEDTLS_PK_RSA)",
                                    "if token_type == 'Bearer':")),
                ("LOG-008", True, ("if ($_GET['token'] == $token) {",
                                   "if params[:token] == user.token",
                                   "if bytes.Equal(mac, expectedMAC) {",
                                   "if (Arrays.equals(expected, computedMac)) {")),
                # The last-segment rule also took the OTP and the PIN whose name
                # goes on with `code`: `otp_code`, `pinCode` and `PIN_CODE` are
                # the secret itself, and none of them matched. Only otp and pin
                # take the qualifier, so `hashCode()`, a `hash_value` bucket and
                # a `tag_buf` NULL check stay out, as `opcode` and `spin_code` do.
                ("LOG-008", True, ("if (otp_code == expected_otp_code)",
                                   "if (user_pin_code != entered)",
                                   "if (pinCode != storedPinCode)",
                                   "if user.otp_code != code:",
                                   "if (req.body.pinCode !== user.pinCode) {",
                                   "if (PIN_CODE == entered)")),
                ("LOG-008", False, ("if (a.hashCode() == b.hashCode())",
                                    "if (hash_value == e->hash_value)",
                                    "if (tag_buf == NULL)", "if (opcode == OP_X)",
                                    "if (spin_code == 1)", "if (pin_code_len == 4)")),
                # A MAC compared byte by byte, the early-exit loop itself, and
                # a secret named for what was done to it (`hmac_out`,
                # `macCalc`) were out with the last-segment rule. The byte
                # form wants an indexed element on the right, so a tag or a
                # file signature checked against a character stays out, and
                # takes `secretBytes[i]` too; the named form wants a lowercase
                # name there, so the NULL, nil, null and nullptr checks of an
                # out-parameter stay out, and takes no `_bytes` (a count) or
                # `_value` (a lexer's token_value). Poco's SCRAM client
                # compares serverSignatureComputed with serverSignatureReceived.
                ("LOG-008", True, ("        if (hmac[i] != hmac_calc[i])",
                                   "    if (hmac_out[i] != expected[i]) return 0;",
                                   "    if (secretBytes[i] != other[i]) return false;",
                                   "    if hmac_out != sent:",
                                   "    if (mac_calc != expected) {",
                                   "  if (hmacOut !== req.headers['x-sig']) {",
                                   "    return serverSignatureComputed == "
                                   "serverSignatureReceived;")),
                ("LOG-008", False, ("    if (mac_out == NULL)",
                                    "    return (*token_out != NULL) ? 0 : -1;",
                                    "    if (hmacOut != null) {", "    if macOut != nil {",
                                    "    if (tag_check == 0 && name_check == 0) {",
                                    "        if (tag[i] != ':' || tag[i+1] != '\"') {",
                                    "    if ((sig[0] == 'B') && (sig[1] == 'M'))",
                                    "    if (hash[i] == NULL)",
                                    "            if (sig_algs[i] != sig_algs[j]) {",
                                    "    if (sig_bytes != sig_len)",
                                    "    if token_value == expected:")),
            )
            check("the line-half probes hold only rules that carry a line_pattern",
                  sorted({rid for rid, _, _ in line_probes
                          if not by_id[rid].get("line_pattern")}), [])
            check("every line half is probed both ways",
                  sorted({(rid, want) for rid, want, _ in line_probes}),
                  sorted((r["rule_id"], want) for r in rules if r.get("line_pattern")
                         for want in (False, True)))
            for rid, want, lines in line_probes:
                text, _ = resolve_line_pattern(by_id[rid])
                if text is None:
                    continue                 # reported just above
                rx = re.compile(text)
                for line in lines:
                    check("%s line half %s %s" % (rid, "matches" if want else "does not match",
                                                  line), bool(rx.search(line)), want)

            # Groups in a pattern are for alternation and never for capture:
            # nothing reads a group of a rule's match. Stage 1 joins every line
            # pattern for a language into one prefilter regex, and there each
            # capturing group costs work in proportion to its number every time
            # the engine enters it. The per-language branches took the C
            # prefilter from 73 groups to 117 and stage 1 over a pure C tree from
            # about 11.5 s to 16 s; non-capturing, with every branch kept, 12 s.
            check("no shipped pattern captures a group",
                  [r["rule_id"] for r in rules for f in ("pattern", "line_pattern")
                   if r.get(f) and re.compile(r[f]).groups], [])

            # A pattern has to mean to ripgrep what it means to Python: that is
            # what a person or an agent checking a hit greps the tree with.
            check("no shipped pattern holds a construct ripgrep reads differently",
                  ["%s %s: %s" % (r["rule_id"], f, h) for r in rules
                   for f in ("pattern", "line_pattern") if r.get(f)
                   for h in ripgrep_hazards(r[f])], [])
            import shutil
            rg = shutil.which("rg")
            fixture = default_fixture_dir(shipped)
            # A missing fixture is a failure, never a skip: the comparison below is the
            # invariant this file exists for (the rules mean the same to `re` and to
            # ripgrep), and a check that silently tests nothing is the failure it
            # exists to refuse. Only a missing ripgrep, which the skill declares as a
            # requirement, is reported as a skip.
            check("the fixture the ripgrep comparison reads is there",
                  os.path.isdir(fixture), True)
            if rg and os.path.isdir(fixture):
                disagreements = ripgrep_disagreements(rules, fixture, rg)
                check("ripgrep and Python agree on every shipped pattern over the fixture",
                      disagreements, [])
                if disagreements:
                    print("       ripgrep 14.1.0 drops matches of an optional group inside "
                          "an alternation, which 14.1.1 fixed; a pattern it disagrees "
                          "on is rewritten, as INJ-002's `(X)?` became `(?:|X)`")
            elif not rg:
                print("  skip ripgrep agreement: rg is not on PATH")
            # The fixture holds a sink or two per rule; the probes hold a line
            # for each branch, so both engines read those as well.
            if rg:
                with tempfile.TemporaryDirectory() as tmp:
                    with open(os.path.join(tmp, "probes.txt"), "w", encoding="utf-8") as fh:
                        for _rid, _want, lines in probes + line_probes:
                            fh.write("".join(line + "\n" for line in lines))
                    check("ripgrep and Python agree on every shipped pattern over the "
                          "probe lines", ripgrep_disagreements(rules, tmp, rg), [])

            # The patterns run over every line of an attacker-influenced tree, so
            # their cost has to grow with the line and not with its square.
            check("every shipped pattern stays linear on a planted pathological line",
                  slow_patterns(rules), [])

    else:
        # Not a skip: 460 of this file's checks read the shipped rules, and a
        # selftest that passes without them has tested nothing.
        failures += 1
        print("  FAIL the shipped rules are not there: %s is not a directory" % shipped)

    # ---- the name matcher's rewrite (see "name targets") ---- #
    check("`\\b` becomes a segment boundary and `\\B` its negation",
          segment_pattern(r"\bx\B"), SEGMENT_BOUNDARY + "x" + NOT_SEGMENT_BOUNDARY)
    check("an escape inside a character class is left alone",
          segment_pattern(r"[\b]x[^]\b]y[]\b]"), r"[\b]x[^]\b]y[]\b]")
    check("an escaped backslash before b is not an anchor",
          segment_pattern(r"a\\b"), r"a\\b")
    check("plain mode compiles the pattern as written",
          compile_name_pattern(r"(?i:\bkey\w*\b)", "plain").search("a.c::get_key"), None)
    check("and segment mode reads the underscore as the boundary",
          bool(compile_name_pattern(r"(?i:\bkey\w*\b)").search("a.c::get_key")), True)
    check("the camelCase test stays case-sensitive inside (?i:...)",
          compile_name_pattern(r"(?i:\bkey\w*\b)").search("a.c::monkey"), None)
    try:
        compile_name_pattern(r"\bx", "fuzzy")
        unknown = False
    except ValueError:
        unknown = True
    check("a name_match mode this skill does not know is refused", unknown, True)
    check("hits_signature counts multiplicity and ignores order",
          (hits_signature(["LOG-001", "MEM-002"]) == hits_signature(["MEM-002", "LOG-001"]),
           hits_signature(["LOG-001"]) == hits_signature(["LOG-001", "LOG-001"])),
          (True, False))
    # loosen_name drops only the anchors a fragment OPENS with.
    check("loosen_name keeps the trailing anchor and drops the leading ones",
          [loosen_name(p) for p in (r"(?i:\b(?:a|b)\b)", r"\bx\w*\b|(?:^|/)y",
                                    r"[\b]\bz", r"(?:\bq)\b")],
          [r"(?i:(?:a|b)\b)", r"x\w*\b|(?:^|/)y", r"[\b]\bz", r"(?:q)\b"])
    check("so a narrowed tail stays narrowed in the zero-hit test",
          [bool(compile_name_pattern(loosen_name(r"(?i:\b(?:sign(?:|s|ed))\b)"))
                .search(t)) for t in ("a.c::install_signal", "a.c::cosign")],
          [False, True])
    check("a camelCase hump after a non-ASCII lowercase letter is a boundary",
          bool(compile_name_pattern(r"(?i:\bkey\w*\b)").search("a.java::caféKey")), True)

    # A statement, not `failures +=`: `check` already counts, and an augmented
    # assignment would read `failures` before the call and write it back after.
    _gate_selftest(check)

    print("\nselftest: %d failure(s)%s" % (failures, skipped_note()))
    return 1 if failures else 0


def _gate_selftest(check):
    """The run-directory gate, over real repositories. Returns 0: `check` counts."""
    import tempfile
    if shutil.which("git") is None or os.name != "posix":
        print("  skip run-directory gate: %s" % ("git is not on PATH"
              if shutil.which("git") is None else "not a POSIX system"))
        return 0

    # One private, empty HOME for every fixture git call, and no global config
    # file at all: the machine's ~/.gitconfig is not the fixture's business, and
    # a HOME derived from a fixture's path was /tmp itself for a clone, where
    # anyone's .gitconfig would have run.
    home = tempfile.mkdtemp(prefix="gate-home-")
    try:
        return _gate_selftest_cases(check, home)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _gate_selftest_cases(check, home):
    import tempfile

    def git(cwd, *args):
        # Identity, no signing and no hooks on the command line.
        env = git_env()
        env["HOME"] = env["XDG_CONFIG_HOME"] = home
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        argv = ["git", "-c", "user.name=selftest", "-c", "user.email=s@t.invalid",
                "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                "-c", "init.defaultBranch=main", "-c", "core.hooksPath=" + os.devnull,
                "-c", "pull.rebase=false"]
        return subprocess.run(argv + list(args), cwd=cwd, env=env, check=True,
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

    def put(root, rel, text="{}\n"):
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def repo(tmp, name="r"):
        root = os.path.join(tmp, name)
        os.makedirs(root)
        git(root, "init", "-q")
        put(root, "src/main.c", "int main(void) { return 0; }\n")
        git(root, "add", "src/main.c")
        git(root, "commit", "-q", "-m", "source")
        return root

    def verdict(root):
        result = run_dir_gate(root)
        return (result["state"], run_dir_refused(result),
                sorted(e["path"] for e in result["shipped"]))

    verdicts = RUN_DIR_NAME + "/scores/triage/verdicts/T-000001.json"
    answers = RUN_DIR_NAME + "/scores/triage/answers/A.jsonl"

    def folding_filesystem(tmp):
        """True where the filesystem opens differently spelled names as one -
        macOS's default - and a fixture's variants may collapse into one entry."""
        probe = os.path.join(tmp, "Fold-Probe")
        open(probe, "w").close()
        try:
            return os.path.exists(os.path.join(tmp, "fold-probe"))
        finally:
            os.unlink(probe)

    def variants_refused(root, variants):
        """(refused, what to compare): every variant listed where the filesystem
        keeps them apart; at least one, and nothing else, where it folds them."""
        result = run_dir_gate(root)
        paths = sorted(e["path"] for e in result["shipped"])
        if folding_filesystem(os.path.dirname(root)):
            return run_dir_refused(result), bool(paths) and set(paths) <= set(variants)
        return run_dir_refused(result), paths == sorted(variants)

    with tempfile.TemporaryDirectory() as tmp:
        plain = os.path.join(tmp, "plain")
        put(plain, verdicts)
        check("gate: a tree no repository encloses passes, unverified, with a note",
              (verdict(plain), bool(run_dir_notes(run_dir_gate(plain)))),
              (("no-git", False, []), True))

        root = os.path.join(tmp, "fresh")
        os.makedirs(root)
        git(root, "init", "-q")
        put(root, verdicts)
        check("gate: an unborn HEAD with nothing staged passes as untracked-tree "
              "(the smoke test's state)", verdict(root), ("untracked-tree", False, []))
        git(root, "add", "-f", verdicts)
        check("gate: the same file staged is refused",
              verdict(root), ("untracked-tree", True, [verdicts]))

        # The skill folder, and an old copy of the scanner, are never a --root; a
        # repository that holds the skill inside it is checked as usual. The skill
        # is recognised by identity, an old copy by the line this file opens with,
        # and only inside a dot folder.
        project = os.path.join(tmp, "project")
        put(project, "src/main.c", "int main(void) { return 0; }\n")
        skill = os.path.join(project, "skills-home", "security-review-copy")
        put(skill, "scripts/rules_lib.py", TOOL_SIGNATURE + "\n")

        def gate(path, bundle=None):
            result = run_dir_gate(path, bundle)
            return result["state"], run_dir_refused(result), run_dir_refusal(result) or ""

        state, refused, refusal = gate(SKILL_ROOT)
        check("gate: the running skill folder is refused, naming the fix",
              (state, refused, "--root ." in refusal,
               "(exit %d)" % EXIT_SHIPPED in refusal), ("bundle", True, True, True))
        check("gate: so is a folder inside it",
              gate(os.path.join(SKILL_ROOT, "scripts"))[:2], ("bundle", True))
        check("gate: a project that holds the skill is a repository like any other",
              gate(project, skill)[:2], ("no-git", False))
        check("gate: a target that is not there is refused, not passed unverified",
              gate(os.path.join(tmp, "payments-apu"))[:2], ("missing", True))
        inner = os.path.join(project, RUN_DIR_NAME)
        os.makedirs(os.path.join(inner, "arbitration"), exist_ok=True)
        state, refused, refusal = gate(os.path.join(inner, "arbitration"))
        check("gate: nor is a folder inside the run directory (an arbiter that changed "
              "into arbitration/ and said --root .)", (state, refused, "--root ." in refusal,
                                                       "(exit %d)" % EXIT_SHIPPED in refusal),
              ("run-dir", True, True, True))
        state, refused, refusal = gate(inner)
        check("gate: the run directory itself is refused as a root, naming the fix",
              (state, refused, "--root ." in refusal, "(exit %d)" % EXIT_SHIPPED in refusal),
              ("run-dir", True, True, True))
        old = os.path.join(tmp, "old")
        put(old, "tools/rules_lib.py", TOOL_SIGNATURE + "\n")
        check("gate: an old copy of the scanner is refused as a root, and so is a "
              "folder inside it", (gate(old)[:2], gate(os.path.join(old, "tools"))[:2]),
              (("bundle", True), ("bundle", True)))
        decoy = os.path.join(tmp, "decoy")
        put(decoy, "scripts/rules_lib.py", "not this tool\n")
        check("gate: a folder with another rules_lib.py is no old copy",
              gate(decoy)[:2], ("no-git", False))
        check("gate: this file still opens with the signature old copies are found by",
              TOOL_SIGNATURE in open(os.path.abspath(__file__), encoding="utf-8").read(
                  _SIGNATURE_HEAD_BYTES), True)

        # The walks: what is tooling, by identity.
        def tooling(rel_parent, name, base=None):
            return is_tooling_dir(base or project, os.path.join(base or project, rel_parent),
                                  name)
        put(project, ".claude/skills/other/SKILL.md", "---\n---\n")
        put(project, ".hostdir/security-review/tools/rules_lib.py", TOOL_SIGNATURE + " x\n")
        put(project, ".agents/skills/security-review-copy/scripts/rules_lib.py",
            TOOL_SIGNATURE + "\n")
        put(project, "vendor/lib/scripts/rules_lib.py", TOOL_SIGNATURE + "\n")
        put(project, "docs/skills/readme.md", "x\n")
        put(project, ".github/skills/build-helpers/payments.c", "int pay(void) { return 0; }\n")
        check("tooling: a skill installed for a host (a SKILL.md in a skills folder "
              "directly inside a dot folder) is tooling",
              tooling(os.path.join(".claude", "skills"), "other"), True)
        check("tooling: ... but the skills folder around it is not",
              tooling(".claude", "skills"), False)
        check("tooling: a folder in a dot folder's skills folder with no SKILL.md is "
              "the product's own code",
              tooling(os.path.join(".github", "skills"), "build-helpers"), False)
        check("tooling: a skills folder anywhere else is the product",
              tooling("docs", "skills"), False)
        check("tooling: an old copy of the scanner inside a dot folder is tooling",
              tooling(".hostdir", "security-review"), True)
        check("tooling: ... but the dot folder around it is not",
              tooling("", ".hostdir"), False)
        check("tooling: a second copy of this skill under another host is tooling",
              tooling(os.path.join(".agents", "skills"), "security-review-copy"), True)
        check("tooling: a folder outside any dot folder is never recognised by the "
              "signature (a repository cannot hide a folder by planting the line)",
              tooling("vendor", "lib"), False)
        check("tooling: the running skill is tooling wherever it is, by real path",
              is_tooling_dir(project, os.path.dirname(SKILL_ROOT),
                             os.path.basename(SKILL_ROOT)), True)
        found = []
        dirs = ["other", "plugins"]
        prune_tooling(project, os.path.join(project, ".claude", "skills"), dirs, found)
        check("tooling: prune_tooling removes it in place and says what it removed",
              (dirs, found), (["plugins"],
                              [(".claude/skills/other",
                                "an installed skill (it holds a SKILL.md)")]))
        dirs = ["skills", "plugins"]
        found = []
        prune_tooling(project, os.path.join(project, ".github"), dirs, found)
        check("tooling: and removes nothing from a folder that only holds skills-shaped code",
              (dirs, found), (["skills", "plugins"], []))

    with tempfile.TemporaryDirectory() as tmp:
        root = repo(tmp)
        put(root, RUN_DIR_NAME + "/.gitignore", "*\n!.gitignore\n!ledger/\n!ledger/**\n")
        put(root, RUN_DIR_NAME + "/ledger/suppressions.jsonl", "")
        git(root, "add", "-f", RUN_DIR_NAME + "/.gitignore",
            RUN_DIR_NAME + "/ledger/suppressions.jsonl")
        git(root, "commit", "-q", "-m", "ledger")
        put(root, RUN_DIR_NAME + "/run.json")          # the run's own, untracked
        result = run_dir_gate(root)
        check("gate: a committed .gitignore and ledger, plus the run's own files, pass",
              (verdict(root), sorted(e["path"] for e in result["committed"])),
              (("git", False, []), [RUN_DIR_NAME + "/.gitignore",
                                    RUN_DIR_NAME + "/ledger/suppressions.jsonl"]))
        check("gate: and the committed ledger is named in a note, since it is read",
              any("ledger/suppressions.jsonl" in n for n in run_dir_notes(result)), True)

        # The user's case: a verdict and an answers file the repository ships.
        put(root, verdicts)
        put(root, answers)
        git(root, "add", "-f", verdicts, answers)
        git(root, "commit", "-q", "-m", "ship a verdict")
        result = run_dir_gate(root)
        check("gate: a committed verdict and answers file are refused",
              verdict(root), ("git", True, [answers, verdicts]))
        check("gate: each listed as in HEAD and the index",
              [e["in"] for e in result["shipped"]], [["HEAD", "index"]] * 2)
        refusal = run_dir_refusal(result)
        check("gate: the refusal names the paths and the remedy, and says exit 7",
              (verdicts in refusal,
               "git -C %s rm -r -f -q -- .security-review/scores" % _shell_word(root)
               in refusal,
               "git -C %s commit" % _shell_word(root) in refusal, "(exit 7)" in refusal),
              (True, True, True, True))

        with open(os.path.join(root, verdicts), "w", encoding="utf-8") as fh:
            fh.write('{"verdict": "high"}\n')
        check("gate: the check never reads content - a shipped file rewritten "
              "locally is still refused", verdict(root)[1], True)

        git(root, "rm", "-r", "-q", "--cached", RUN_DIR_NAME + "/scores")
        result = run_dir_gate(root)
        check("gate: `git rm --cached` leaves the bytes, and HEAD still lists them",
              (verdict(root), [e["in"] for e in result["shipped"]],
               [e["on_disk"] for e in result["shipped"]]),
              (("git", True, [answers, verdicts]), [["HEAD"]] * 2, [True, True]))
        check("gate: so the remedy says to delete them, and why not --cached",
              ("rm -rf -- " in run_dir_refusal(result),
               "Not `git rm --cached`" in run_dir_refusal(result)), (True, True))
        git(root, "reset", "-q")
        git(root, "rm", "-r", "-q", "-f", RUN_DIR_NAME + "/scores")
        result = run_dir_gate(root)
        check("gate: `git rm -f` without a commit is still refused, not on disk",
              (verdict(root)[1], [e["on_disk"] for e in result["shipped"]]),
              (True, [False, False]))
        git(root, "commit", "-q", "-m", "remove")
        put(root, verdicts)                             # the run writes its own
        check("gate: after the removal is committed, the run's own files pass",
              verdict(root), ("git", False, []))

    with tempfile.TemporaryDirectory() as tmp:
        root = repo(tmp)
        put(root, RUN_DIR_NAME + "/run.json")
        git(root, "add", "-f", RUN_DIR_NAME + "/run.json")
        git(root, "commit", "-q", "-m", "ship")
        os.unlink(os.path.join(root, RUN_DIR_NAME + "/run.json"))
        check("gate: a tracked file deleted from disk is still refused - a pull "
              "puts it back", verdict(root), ("git", True, [RUN_DIR_NAME + "/run.json"]))

    if can_symlink():
        with tempfile.TemporaryDirectory() as tmp:
            root = repo(tmp)
            os.makedirs(os.path.join(root, "elsewhere"))
            os.symlink("elsewhere", os.path.join(root, RUN_DIR_NAME))
            git(root, "add", RUN_DIR_NAME)
            git(root, "commit", "-q", "-m", "link")
            result = run_dir_gate(root)
            check("gate: a committed link AT the run directory is refused",
                  (verdict(root), [e["mode"] for e in result["shipped"]]),
                  (("git", True, [RUN_DIR_NAME]), ["120000"]))
    else:
        skip_case("gate: a committed link AT the run directory is refused")

    if can_symlink():
        with tempfile.TemporaryDirectory() as tmp:
            root = repo(tmp)
            os.makedirs(os.path.join(root, RUN_DIR_NAME, "ledger"))
            os.symlink("../../src/main.c",
                       os.path.join(root, RUN_DIR_NAME, "ledger", "suppressions.jsonl"))
            git(root, "add", "-f", RUN_DIR_NAME + "/ledger/suppressions.jsonl")
            git(root, "commit", "-q", "-m", "link in the ledger")
            check("gate: a link inside the ledger is refused despite the carve-out",
                  verdict(root)[1:], (True, [RUN_DIR_NAME + "/ledger/suppressions.jsonl"]))
    else:
        skip_case("gate: a link inside the ledger is refused despite the carve-out")

    with tempfile.TemporaryDirectory() as tmp:
        root = repo(tmp)
        head = git(root, "rev-parse", "HEAD").stdout.decode().strip()
        git(root, "update-index", "--add", "--cacheinfo",
            "160000,%s,%s/scores" % (head, RUN_DIR_NAME))
        git(root, "commit", "-q", "-m", "submodule")
        result = run_dir_gate(root)
        check("gate: a submodule under the run directory is refused",
              [e["mode"] for e in result["shipped"]], ["160000"])

    with tempfile.TemporaryDirectory() as tmp:
        root = repo(tmp)
        variants = [".Security-Review/run.json", ".security-review\u200c/run.json"]
        for variant in variants:
            put(root, variant)
            git(root, "add", "-f", variant)
        git(root, "commit", "-q", "-m", "case")
        check("gate: a letter-case or ignorable-code-point variant is the run "
              "directory on a Mac, and is refused",
              variants_refused(root, variants), (True, True))
        check("gate: and the refusal escapes what it prints",
              "\\u200c" in run_dir_refusal(run_dir_gate(root)), True)

    with tempfile.TemporaryDirectory() as tmp:
        outer = repo(tmp, "outer")
        put(outer, "sub/" + RUN_DIR_NAME + "/run.json")
        git(outer, "add", "-f", "sub/" + RUN_DIR_NAME + "/run.json")
        git(outer, "commit", "-q", "-m", "nested")
        check("gate: a tree inside a larger repository is asked about itself",
              (verdict(os.path.join(outer, "sub")), verdict(outer)),
              (("git", True, [RUN_DIR_NAME + "/run.json"]), ("git", False, [])))
        put(outer, ".gitignore", "vendor/\n")
        git(outer, "add", ".gitignore")
        git(outer, "commit", "-q", "-m", "ignore vendor")
        drop = os.path.join(outer, "vendor", "drop")
        put(drop, verdicts)
        put(drop, "main.c", "int x;\n")
        check("gate: a drop under an ignored directory is untracked-tree: passed, "
              "and said to be unverified", verdict(drop), ("untracked-tree", False, []))

    with tempfile.TemporaryDirectory() as tmp:
        upstream = repo(tmp, "upstream")
        clone = os.path.join(tmp, "clone")
        git(tmp, "clone", "-q", upstream, clone)
        put(clone, RUN_DIR_NAME + "/.gitignore", "*\n!.gitignore\n!ledger/\n!ledger/**\n")
        put(clone, RUN_DIR_NAME + "/secrets/inventory.json", '{"local": true}\n')
        check("gate: a clone with the run's own files passes", verdict(clone)[1], False)
        put(upstream, RUN_DIR_NAME + "/secrets/inventory.json", '{"forged": true}\n')
        git(upstream, "add", "-f", RUN_DIR_NAME + "/secrets/inventory.json")
        git(upstream, "commit", "-q", "-m", "forge")
        git(clone, "pull", "-q")
        check("gate: a pull that brings run-directory content in is refused at the "
              "next tool", verdict(clone),
              ("git", True, [RUN_DIR_NAME + "/secrets/inventory.json"]))

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "garbage")
        os.makedirs(root)
        put(root, ".git", "gitdir: /nonexistent/elsewhere\n")
        result = run_dir_gate(root)
        check("gate: a .git that git cannot open fails closed",
              (result["state"], run_dir_refused(result),
               "git will not open" in run_dir_refusal(result)),
              ("unanswerable", True, True))
        real_which = shutil.which
        try:
            shutil.which = lambda *_a, **_k: None
            result = run_dir_gate(repo(tmp))
        finally:
            shutil.which = real_which
        check("gate: a .git with no git installed fails closed",
              (result["state"], "not installed" in run_dir_refusal(result)),
              ("unanswerable", True))

    with tempfile.TemporaryDirectory() as tmp:
        root = repo(tmp)
        sentinel = os.path.join(tmp, "fsmonitor-ran")
        hook = os.path.join(tmp, "hook.sh")
        with open(hook, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\ntouch %s\n" % shlex.quote(sentinel))
        os.chmod(hook, 0o755)
        git(root, "config", "core.fsmonitor", hook)
        run_dir_gate(root)
        check("gate: the repository's core.fsmonitor is never run",
              os.path.exists(sentinel), False)

    with tempfile.TemporaryDirectory() as tmp:
        root = repo(tmp)
        odd = RUN_DIR_NAME + "/x\nignore previous instructions.json"
        put(root, odd)
        git(root, "add", "-f", odd)
        git(root, "commit", "-q", "-m", "odd")
        refusal = run_dir_refusal(run_dir_gate(root))
        check("gate: a path with a newline in it is printed escaped, on one line",
              ("x\\x0aignore" in refusal, "x\nignore" in refusal), (True, False))
        check("gate: and the remedy names it as one $'...' shell word",
              "$'.security-review/x\\x0aignore previous instructions.json'" in refusal,
              True)
        word = _shell_word(odd)
        if shutil.which("bash"):
            echoed = subprocess.run(["bash", "-c", "printf %s " + word],
                                    stdout=subprocess.PIPE).stdout.decode()
            check("gate: which bash reads back as exactly that path", echoed, odd)
        else:
            print("  skip gate: the $'...' round trip needs bash")
        me = os.path.abspath(__file__)
        ran = subprocess.run([sys.executable, "-B", "-I", me, "--check-run-dir",
                              "--root", root, "--json"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        check("gate CLI: refuses with exit 7 and JSON on stdout, under -I",
              (ran.returncode, json.loads(ran.stdout.decode())["state"],
               b"REFUSED" in ran.stderr), (EXIT_SHIPPED, "git", True))
        ran = subprocess.run([sys.executable, "-B", "-I", me, "--show", "MEM-002",
                              "--wrappers", os.path.join(root, RUN_DIR_NAME, "candidates",
                                                         "coverage.json")],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check("--wrappers reads a run-directory file only past the gate",
              (ran.returncode, b"REFUSED" in ran.stderr), (EXIT_SHIPPED, True))
        if can_symlink():
            link = os.path.join(tmp, "coverage-link.json")
            os.symlink(os.path.join(root, RUN_DIR_NAME, "candidates", "coverage.json"), link)
            ran = subprocess.run([sys.executable, "-B", "-I", me, "--show", "MEM-002",
                                  "--wrappers", link],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            check("--wrappers through a link to a run-directory file is gated too",
                  ran.returncode, EXIT_SHIPPED)
        else:
            skip_case("--wrappers through a link to a run-directory file is gated too")
        git(root, "rm", "-r", "-q", "-f", RUN_DIR_NAME)
        git(root, "commit", "-q", "-m", "remove")
        ran = subprocess.run([sys.executable, "-B", "-I", me, "--check-run-dir",
                              "--root", root], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        check("gate CLI: passes with exit 0 once the removal is committed",
              (ran.returncode, ran.stdout.decode().startswith("run directory: git")),
              (0, True))
        ran = subprocess.run([sys.executable, "-B", "-I", me, "--check-run-dir",
                              "--root", root, "--show", "MEM-002"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        check("gate CLI: takes no other mode with it", ran.returncode, 2)
        # With a marker in the environment, so that if the guard ever regresses
        # the child's selftest stops at once instead of recursing into this.
        try:
            ran = subprocess.run([sys.executable, "-B", "-I", me, "--check-run-dir",
                                  "--root", root, "--self"],
                                 env=dict(os.environ, RULES_LIB_SELFTEST_NESTED="1"),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=60)
        except subprocess.TimeoutExpired:
            ran = subprocess.CompletedProcess([], -1)
        check("gate CLI: nor the selftest, even abbreviated - its allowlist entry "
              "approves whatever follows it", ran.returncode, 2)

    # A root reached through a link: git discovers from the resolved directory,
    # and so must the walk that decides whether to ask it at all.
    if can_symlink():
        with tempfile.TemporaryDirectory() as tmp:
            mono = repo(tmp, "mono")
            put(mono, "svc/" + RUN_DIR_NAME + "/secrets/inventory.json")
            git(mono, "add", "-f", "svc/" + RUN_DIR_NAME + "/secrets/inventory.json")
            git(mono, "commit", "-q", "-m", "ship")
            os.makedirs(os.path.join(tmp, "links"))
            os.symlink(os.path.join(mono, "svc"), os.path.join(tmp, "links", "svc"))
            check("gate: a root that is a link into a checkout's subdirectory is asked "
                  "of git, and refused", verdict(os.path.join(tmp, "links", "svc")),
                  ("git", True, [RUN_DIR_NAME + "/secrets/inventory.json"]))
            plain = os.path.join(tmp, "plain")
            put(plain, "main.c", "int x;\n")
            os.symlink(plain, os.path.join(mono, "outside"))
            check("gate: and a link inside a checkout to a tree outside any repository "
                  "is no-git, not unanswerable", verdict(os.path.join(mono, "outside")),
                  ("no-git", False, []))
    else:
        skip_case("gate: a root that is a link into a checkout is asked of git, and refused")
        skip_case("gate: a link inside a checkout to a tree outside any repository is no-git")

    # Staged only, never committed: the index is folded the way HEAD is.
    for born in (False, True):
        with tempfile.TemporaryDirectory() as tmp:
            if born:
                root = repo(tmp)
            else:
                root = os.path.join(tmp, "r")
                os.makedirs(root)
                git(root, "init", "-q")
            variants = [".security-review\u200c/run.json", ".security-review./run.json",
                        ".\u017fecurity-review/run.json"]
            for variant in variants:
                put(root, variant)
                git(root, "add", "-f", variant)
            result = run_dir_gate(root)
            check("gate: staged-only spelling variants are refused from the index "
                  "(%s HEAD)" % ("a born" if born else "an unborn"),
                  (variants_refused(root, variants),
                   sorted(set(i for e in result["shipped"] for i in e["in"]))),
                  ((True, True), ["index"]))

    # Every git failure after the .git is found fails closed. Each case keeps
    # the run directory out of the index, so only the branch under test can
    # refuse it.
    with tempfile.TemporaryDirectory() as tmp:
        def drop(root, rev):
            sha = git(root, "rev-parse", rev).stdout.decode().strip()
            os.unlink(os.path.join(root, ".git", "objects", sha[:2], sha[2:]))

        for name, rev, says in (("nocommit", "HEAD", "names no commit"),
                                ("notree", "HEAD^{tree}", "names no commit"),
                                ("nosubtree", "HEAD:" + RUN_DIR_NAME,
                                 "`git ls-tree` failed")):
            root = repo(tmp, name)
            put(root, RUN_DIR_NAME + "/run.json")
            git(root, "add", "-f", RUN_DIR_NAME + "/run.json")
            git(root, "commit", "-q", "-m", "ship")
            git(root, "rm", "-q", "--cached", RUN_DIR_NAME + "/run.json")
            drop(root, rev)
            result = run_dir_gate(root)
            check("gate: an unreadable %s fails closed" % rev,
                  (result["state"], says in (result["why"] or "")), ("unanswerable", True))
        root = repo(tmp, "noindex")
        with open(os.path.join(root, ".git", "index"), "wb") as fh:
            fh.write(b"DIRC garbage")
        result = run_dir_gate(root)
        check("gate: an index git cannot read fails closed",
              result["state"], "unanswerable")

    # An inherited GIT_DIR describes some other repository. The gate must ask
    # about THIS one - a shipped verdict here, a clean repository there.
    with tempfile.TemporaryDirectory() as tmp:
        root = repo(tmp)
        put(root, verdicts)
        git(root, "add", "-f", verdicts)
        git(root, "commit", "-q", "-m", "ship a verdict")
        clean = repo(tmp, "clean")
        inherited = {"GIT_DIR": os.path.join(clean, ".git"),
                     "GIT_INDEX_FILE": os.path.join(clean, ".git", "index")}
        saved = dict((k, os.environ.get(k)) for k in inherited)
        os.environ.update(inherited)
        try:
            got = verdict(root)
            kept = git_env()
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        check("gate: an inherited GIT_DIR and GIT_INDEX_FILE are not what it asks",
              got, ("git", True, [verdicts]))
        check("gate: git_env drops them", [k for k in inherited if k in kept], [])
        saved = os.environ.get("GIT_CONFIG_COUNT")
        os.environ["GIT_CONFIG_COUNT"] = "1"
        try:
            kept = git_env()
        finally:
            if saved is None:
                os.environ.pop("GIT_CONFIG_COUNT", None)
            else:
                os.environ["GIT_CONFIG_COUNT"] = saved
        check("gate: and keeps the operator's own config, a CI job's safe.directory "
              "among it", kept.get("GIT_CONFIG_COUNT"), "1")
    return 0


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def build_parser():
    ap = argparse.ArgumentParser(
        description="Load and check the rule tables (assets/rules/*.json).")
    ap.add_argument("--rules-dir", default=None,
                    help="rules directory (default: assets/rules in the skill folder)")
    ap.add_argument("--wrappers", default=None,
                    help="coverage.json whose wrapper_resolution extends the patterns")
    ap.add_argument("--show", default=None, metavar="RULE_ID",
                    help="print one rule, with its pattern resolved for this run")
    ap.add_argument("--check-run-dir", action="store_true",
                    help="refuse (exit 7) unless the scanned repository commits nothing "
                         "under .security-review/ but .gitignore and ledger/; the first "
                         "thing every stage runs")
    ap.add_argument("--root", default=".",
                    help="with --check-run-dir: the scanned repository (default: .)")
    ap.add_argument("--json", action="store_true",
                    help="with --check-run-dir: print the check's result as JSON")
    ap.add_argument("--selftest", action="store_true", help="run the fixtures and exit")
    return ap


def main():
    args = build_parser().parse_args()
    if args.check_run_dir:
        # First, and alone: this mode is what every stage agent runs, and its
        # allowlist entry approves whatever follows it, so it must not be a way
        # into the others - --selftest included, which writes and runs git and
        # bash. Parsed values, so an abbreviation (`--self`) is caught too.
        if (args.selftest or args.show is not None or args.wrappers is not None
                or args.rules_dir is not None):
            print("--check-run-dir takes only --root and --json", file=sys.stderr)
            return 2
        return check_run_dir_main(args.root, args.json)
    if args.selftest:
        return selftest()
    # #10: --wrappers names a coverage.json, which lives in a run directory. It
    # is read only once that run directory's repository has passed the gate.
    # Both as spelled and as resolved: a link to a run-directory file is one.
    if args.wrappers is not None:
        roots = set()
        for path in (os.path.abspath(args.wrappers), os.path.realpath(args.wrappers)):
            parts = path.split(os.sep)
            at = [i for i, part in enumerate(parts) if is_run_dir_name(part)]
            if at:
                roots.add(os.sep.join(parts[:at[-1]]) or os.sep)
        for repo_root in sorted(roots):
            shipped, _gate = enforce_run_dir_gate(repo_root)
            if shipped:
                return shipped

    rules_dir = os.path.abspath(args.rules_dir or default_rules_dir())
    if not os.path.isdir(rules_dir):
        print("%s: not a directory" % rules_dir, file=sys.stderr)
        return 2
    try:
        wrappers = load_wrappers(args.wrappers) if args.wrappers else None
        rules = load_rules(rules_dir)
    except (RulesError, OSError, ValueError) as exc:
        print("%s" % exc, file=sys.stderr)
        return 1

    if args.show:
        for rule in rules:
            if rule["rule_id"] == args.show:
                text, source = resolve_pattern(rule, wrappers) \
                    if not rule["derived"] else (None, "derived")
                out = dict(rule)
                out["resolved_pattern"] = text
                out["pattern_source"] = source
                print(json.dumps(out, indent=2, ensure_ascii=False))
                return 0
        print("%s: no rule %s" % (rules_dir, args.show), file=sys.stderr)
        return 2

    by_category = {}
    for rule in rules:
        by_category.setdefault(rule["category"], []).append(rule)
    skips = 0
    for category in sorted(by_category):
        group = by_category[category]
        for rule in group:
            if not rule["derived"]:
                compile_pattern(rule, wrappers)
            if compile_skip(rule) is not None:
                skips += 1
        print("%-16s %-24s %2d rules  %d high-signal  %d derived"
              % (category, group[0]["validator"], len(group),
                 sum(1 for r in group if r["high_signal"]),
                 sum(1 for r in group if r["derived"])))
    print("%d rules, every pattern compiled; %d carry a skip_pattern, "
          "so %d of them have no skip path at all and can only emit"
          % (len(rules), skips, len(rules) - skips))
    return 0


if __name__ == "__main__":
    sys.exit(main())
