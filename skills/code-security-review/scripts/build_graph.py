#!/usr/bin/env python3
"""
build_graph.py - measure call distance from the entry points, for stage 0.

The scope stage scores a zone's Trust-boundary dimension - 10 of the 47 points - from
how far it sits from an entry point. Without this tool that distance is an
import-graph approximation, and §2.2 says so outright. An import edge means "this
file can see those declarations", which in a library with a flat public-header
directory is nearly every file: on libxml2 v2.9.4, 40 of 75 root .c files include
libxml/parser.h directly. The estimate is not wrong so much as flat, and a
dimension that cannot separate zones hands its 10 points to whatever else varies -
file size, churn, and how the file is named.

This walks calls instead. It indexes every function definition in the tree, joins
call sites to those definitions, and breadth-firsts from the entry points the
PARENT supplies. The parent supplies the roots because the root set defines every
answer downstream and cannot be checked after the fact; this tool only measures.

Deliberately an over-approximation. Textual call sites are not resolved through
the preprocessor, so an edge inside `#if 0` counts. Error runs toward more
scanning, which is the safe direction for a scoping tool - and toward a *floor*
under a zone's score, never a ceiling, so a missed edge costs a bonus rather than
demoting anything. C and C++ only: other languages report as unindexed rather
than as unreachable, because "I could not read it" and "nothing reaches it" must
not produce the same score.

Stdlib only. Python 3.8+.

It skips the scanner's own folders by identity (rules_lib.is_tooling_dir): this
installed skill, a skill installed in a host's `<dot folder>/skills/` (a folder
with a SKILL.md), and an old copy of the scanner. They carry C fixtures and Python tools that are not the product.

Usage
  python3 build_graph.py --root . --entry parser.c:xmlParseDocument \
      --entry HTMLparser.c:htmlParseDocument --out .security-review/scope/graph.json
  python3 build_graph.py --selftest

--out must name a file under <root>/.security-review/ (contract §9 rule 2: no
tool writes to the scanned tree); anything else, or a symbolic link on the way
there, is refused with exit 2 and nothing is written. With no --out the JSON goes
to stdout.
"""

import argparse
import collections
import contextlib
import io
import json
import os
import re
import sys
import tempfile

sys.dont_write_bytecode = True      # the skill folder is read-only: no __pycache__ in it
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rules_lib                                       # noqa: E402

RUN_DIR = ".security-review"

# A definition at column 0, in either style C actually uses:
#   xmlStrndup(const xmlChar *cur, int len) {     name first, type on the line above
#   int mbedtls_ssl_handshake(mbedtls_ssl_context *ssl)   type and name on one line
# and the out-of-class C++ member, which the docstring's "C and C++" promised and
# the C-only pattern never matched - so parser.cpp and tlv.cpp read not_reached:
#   int Parser::parse(const char *buf)      std::vector<int> Parser::split(...)
#   Parser::Parser() : n(0) {               Parser::~Parser()
# The name is the last identifier before the '(', with any `Class::` qualifiers
# before it dropped, because a call site says `p.parse(`. Control keywords are
# excluded so an unindented `if (` never reads as a definition. Whether a match
# is a definition or a prototype is decided by is_prototype(), across lines.
#
# A qualifier's template arguments may not contain a '<' or '>' of their own
# beyond one nested level. `<[^()]*>` could span `<b>::a<b>` - every `::` on the
# line was a place a qualifier might end - so a column-0 line of forty
# `a<b>::` with no '(' after them took hours to fail to match, and the scanned
# tree decides what is on column 0.
TEMPLATE_ARGS = r"<[^()<>]*(?:<[^()<>]*>[^()<>]*)*>"
DEF = re.compile(
    r"^(?!(?:if|for|while|switch|return|else|do|typedef|struct|union|enum|sizeof)\b)"
    r"(?:[A-Za-z_][\w:<>,]*[\s*&]+)*"   # type tokens: 'static', 'int', '*', 'std::vector<int>'
    r"(?:[A-Za-z_]\w*(?:" + TEMPLATE_ARGS + r")?::)*"  # C++ qualifiers: 'Parser::', 'Box<T>::'
    r"~?([A-Za-z_]\w*)\s*\("            # the name, immediately before the '('
)
# How far past the '(' a declaration may run before this stops looking for its
# end and calls it a definition - the over-approximating answer.
PROTOTYPE_SCAN = 40
IDENT = re.compile(r"[A-Za-z_]\w*")
# What may follow a prototype's parameter list before its ';' - attributes and
# the macros that wrap them (`__THROW`, `__nonnull ((1))`, `ZEXPORT`, `WUR`) and
# C++ qualifiers. Anything else there is an old-style K&R parameter declaration
# (`int a;` between the ')' and the '{'), which makes the match a DEFINITION.
TAIL_QUALIFIERS = ("const", "noexcept", "throw", "override", "final")
HEADER_EXT = (".h", ".hh", ".hpp", ".hxx")
CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
# A function name bound into a dispatch table or struct field:
#   hdlr->startElement = xmlSAX2StartElement;   .opencallback = xmlIOHTTPOpen,
# Whoever later calls through that pointer reaches the bound function, and no
# call-site regex can see it. Binding it here is what keeps a callback-dispatched
# subsystem from scoring as unreachable.
BIND = re.compile(r"([A-Za-z_][\w.\[\]>-]*)\s*=\s*([A-Za-z_]\w*)\s*[;,]")

C_EXT = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
# The rest of the scout's language list (roles/scout.md, "Languages present").
# This tool does not index them and is not going to: a regex call graph for Rust
# or Go would be flat over-approximation on a dimension that is only ever applied
# as a floor. They are listed as `unindexed` rather than left out, because a file
# that is simply ABSENT from `files` is indistinguishable from one nothing
# reaches - and that is the collapse the docstring above forbids. Before this,
# a mixed tree's .rs files vanished from the output with `counts.unindexed: 0`.
OTHER_EXT = (".rs", ".go", ".py", ".java", ".js", ".ts", ".cs", ".php", ".rb")

# Distance -> Trust-boundary points. Suggested only: the scope stage decides, and §2.3
# applies this as a floor under the structural score, never as a replacement.
def trust_boundary_points(hops):
    if hops is None:
        return None
    if hops <= 1:
        return 10
    if hops == 2:
        return 6
    return 3


def source_files(root):
    """(C/C++ files to index, other-language files to report as unindexed)."""
    indexed, other = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", ".hg", ".svn", ".security-review",
                                    ".golden-cache", "node_modules")]
        rules_lib.prune_tooling(root, dirpath, dirnames)
        for fn in filenames:
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            if fn.endswith(C_EXT):
                indexed.append(rel)
            elif fn.endswith(OTHER_EXT):
                other.append(rel)
    return sorted(indexed), sorted(other)


def read(path):
    """A file's lines, split on "\\n" only - stage 1's line model.

    str.splitlines() also breaks on a form feed, a vertical tab, a lone "\\r"
    and U+2028, so a U+2028 inside a string literal could start a "line" at
    column 0 that DEF then read as a definition.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except Exception:                              # noqa: BLE001
        return None
    lines = raw.decode("utf-8", "replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def _code_lines(lines, start, limit):
    """(index, text) from lines[start:], with /* */ and // comments blanked."""
    in_comment = False
    for j in range(start, min(start + limit, len(lines))):
        text, out, k = lines[j], [], 0
        while k < len(text):
            if in_comment:
                end = text.find("*/", k)
                if end < 0:
                    break
                in_comment, k = False, end + 2
                out.append(" ")
            elif text.startswith("/*", k):
                in_comment, k = True, k + 2
            elif text.startswith("//", k):
                break
            else:
                out.append(text[k])
                k += 1
        yield j, "".join(out)


def is_prototype(lines, i, paren):
    """True when the '(' at lines[i][paren] opens a declaration, not a definition.

    This used to be "the matched LINE ends in ';'", and a prototype split over
    two lines does not - `int mbedtls_ssl_read_record(mbedtls_ssl_context *ssl,`
    is how public headers are written. The header was indexed as the symbol's
    definition, include/ sorts before library/ and src/, every call edge went to
    the header, and the file that implements the function read `not_reached`:
    the under-approximation the caveats promise never happens.

    So the parameter list is followed to its closing ')', across lines and past
    comments, and what comes next decides. A ';' - with nothing between or only
    attributes and qualifiers - is a prototype. A '{' is a definition, and so is
    anything else before the ';' (a K&R parameter declaration), and so is a list
    that never closes within PROTOTYPE_SCAN lines: when in doubt this indexes,
    because an extra edge costs a floor and a missing one costs a file.
    """
    depth, closed, tail_words = 0, False, []
    for j, code in _code_lines(lines, i, PROTOTYPE_SCAN):
        k = paren if j == i else 0
        while k < len(code):
            ch = code[k]
            if not closed:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    closed = depth == 0
                k += 1
                continue
            if ch == "(":                       # attribute arguments: skipped whole
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth > 0:
                pass
            elif ch == "{":
                return False
            elif ch == ";":
                return all(w.startswith("__") or w.isupper() or w in TAIL_QUALIFIERS
                           for w in tail_words)
            else:
                word = IDENT.match(code, k)
                if word:
                    tail_words.append(word.group(0))
                    k = word.end()
                    continue
            k += 1
    return False


def index(root, files):
    """symbol -> every file defining it (non-headers first), and file -> lines.

    Every definition, not the first one found. First-wins made the index depend
    on sort order - a header with a stray inline definition, or one of fifty
    same-named statics, took every edge for the name - and this tool is an
    over-approximation by contract: an edge to each definition is the answer
    that never costs a file its reachability.
    """
    found, src, unreadable = collections.defaultdict(list), {}, []
    for rel in files:
        lines = read(os.path.join(root, rel))
        if lines is None:
            unreadable.append(rel)
            continue
        src[rel] = lines
        for i, line in enumerate(lines):
            m = DEF.match(line)
            if m and not is_prototype(lines, i, m.end() - 1):
                if rel not in found[m.group(1)]:
                    found[m.group(1)].append(rel)
    defs = dict((sym, sorted(where, key=lambda f: (f.endswith(HEADER_EXT), f)))
                for sym, where in found.items())
    return defs, src, unreadable


def edges_from(defs, src):
    """Direct call edges plus function-pointer bindings.

    A binding only counts when the field it assigns is *demonstrably* a
    function-pointer field - that is, somewhere in the tree the same field is
    bound to a name this tool can resolve to a real function. Without that test
    the pattern matches every ordinary assignment in the codebase and the
    residual-indirection count becomes noise that argues for work nobody needs.

    `unresolved` is then the honest residual: assignments to a known
    function-pointer field whose target this tool cannot name - macro-generated,
    computed, or defined outside the indexed set. That is the only reachability a
    language model could add here.
    """
    raw = []                                       # (file, field, rhs)
    for rel, lines in src.items():
        for line in lines:
            for lhs, rhs in BIND.findall(line):
                if "->" in lhs or "." in lhs:      # dispatch tables live in fields
                    raw.append((rel, re.split(r"[.>]", lhs)[-1], rhs))
    fp_fields = {field for _rel, field, rhs in raw if rhs in defs}

    edges = collections.defaultdict(set)
    resolved = unresolved = cleared = 0
    unnamed = collections.Counter()
    for rel, lines in src.items():
        for line in lines:
            if DEF.match(line):
                continue
            for sym in CALL.findall(line):
                for tgt in defs.get(sym, ()):
                    if tgt != rel:
                        edges[rel].add(tgt)
    for rel, field, rhs in raw:
        if field not in fp_fields:
            continue
        targets = defs.get(rhs)
        if not targets:
            # `= NULL` clears a handler; it is not an unresolved target, and
            # counting it as one is how this metric ends up arguing for a
            # model pass that has nothing to resolve.
            if rhs == "NULL":
                cleared += 1
            else:
                unresolved += 1
                unnamed[rhs] += 1
        else:
            resolved += 1
            for tgt in targets:
                if tgt != rel:
                    edges[rel].add(tgt)
    return edges, resolved, unresolved, cleared, unnamed


def health_warning(n_defs, n_files):
    """Why the index below should not be believed, or None.

    The zero-file case is tested FIRST because the ratio test silently passes it:
    on a pure-Rust or pure-Go tree `n_defs >= 2 * n_files` is `0 >= 0`, so the
    tool reported itself healthy while having measured nothing at all.
    """
    if n_files == 0:
        return ("No C/C++ source files were indexed; this tool measured nothing. "
                "Every Trust-boundary score must come from the structural estimate "
                "(§2.3), and no file below may be read as dead code.")
    if n_defs < 2 * n_files:
        return ("Very few function definitions were indexed for the number "
                "of files read. The definition style in this tree is probably "
                "one this tool does not recognise, in which case reachability "
                "here is not measured and its Trust-boundary points must be "
                "discarded rather than applied as a floor. Check a known "
                "function before trusting any distance below.")
    return None


def resolve_entries(entries, defs, src):
    """An entry is 'file.c', 'file.c:symbol', or a bare symbol.

    A file holding an entry point is distance 0 even when nothing calls into it -
    a main() is reached from the command line, not from another function, and
    scoring it unreachable is how a CLI gets tiered as if it were dead code.
    """
    roots, unresolved = set(), []
    for e in entries:
        name = e.split(":", 1)
        # A symbol defined in several files resolves to the first of them, which
        # index() orders non-headers first: deterministic, and never a header's
        # stray copy when a .c file defines it.
        if name[0] in src:
            roots.add(name[0])
        elif len(name) == 2 and name[1] in defs:
            roots.add(defs[name[1]][0])
        elif e in defs:
            roots.add(defs[e][0])
        else:
            unresolved.append(e)
    return roots, unresolved


def bfs(roots, edges):
    dist = {r: 0 for r in roots}
    queue = collections.deque(sorted(roots))
    while queue:
        node = queue.popleft()
        for nxt in sorted(edges.get(node, ())):
            if nxt not in dist:
                dist[nxt] = dist[node] + 1
                queue.append(nxt)
    return dist


def build(root, entries):
    files, other_files = source_files(root)
    defs, src, unreadable = index(root, files)
    edges, binds_resolved, binds_unresolved, binds_cleared, unnamed = edges_from(defs, src)
    roots, unresolved = resolve_entries(entries, defs, src)
    dist = bfs(roots, edges)

    per_file = {}
    for rel in sorted(src):
        hops = dist.get(rel)
        per_file[rel] = {"hops": hops,
                         "trust_boundary": trust_boundary_points(hops),
                         "reachability": "measured" if hops is not None else "not_reached"}
    for rel in unreadable:
        # Never let "I could not read it" score the same as "nothing reaches it".
        per_file[rel] = {"hops": None, "trust_boundary": None,
                         "reachability": "unindexed"}
    for rel in other_files:
        # Same rule for a language this tool does not index at all. §2.2 reads
        # `unindexed` as "says nothing about what reaches it"; omitting these
        # files instead let a Rust or Go zone read as dead code by default.
        per_file[rel] = {"hops": None, "trust_boundary": None,
                         "reachability": "unindexed"}
    return {
        "schema": "build_graph/1",
        "roots": sorted(roots),
        "unresolved_entries": unresolved,
        "counts": {
            "files_indexed": len(src),
            "symbols_defined": len(defs),
            "file_edges": sum(len(v) for v in edges.values()),
            "reached": len(dist),
            "unindexed": len(unreadable) + len(other_files),
        },
        "indirection": {
            "bindings_resolved": binds_resolved,
            "bindings_cleared_to_null": binds_cleared,
            "bindings_unresolved": binds_unresolved,
            "unresolved_targets": [n for n, _c in unnamed.most_common(15)],
            "unreached_files": sorted(f for f in src
                                      if f not in dist and f.endswith((".c", ".cc", ".cpp"))),
            "note": "bindings_unresolved counts function-pointer assignments whose "
                    "target this tool could not name - macro-generated, computed, or "
                    "defined outside the indexed set. That is the ONLY reachability "
                    "a model could add here. When it is 0, or when no unreached file "
                    "would be touched by resolving it, a model-based call-graph pass "
                    "has nothing left to contribute and should not be run. Read "
                    "unresolved_targets before believing the count: names that are "
                    "plainly enum constants or local variables are not functions, "
                    "and nothing can resolve them into new reachability.",
        },
        "files": per_file,
        "health": {
            "symbols_per_file": round(len(defs) / max(1, len(src)), 1),
            "warning": health_warning(len(defs), len(src)),
        },
        "caveats": [
            "Textual call resolution, not preprocessed: an edge inside #if 0 counts.",
            "Over-approximates. Apply as a FLOOR under the structural score (§2.3), "
            "never as a replacement, so a missed edge costs a bonus and never a demotion.",
            "reachability 'unindexed' means the file was not read and says nothing "
            "about whether anything reaches it.",
            "Indexes C and C++ only. Files in every other language are listed as "
            "'unindexed' and score nothing here; that is not a finding of dead code, "
            "and their Trust-boundary points must come from the structural estimate.",
        ],
    }


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #

FIXTURE = {
    "entry.c": "#include <x.h>\nxmlParseDocument(int a) {\n    helper(a);\n    return 0;\n}\n",
    "mid.c":   "helper(int a) {\n    deep(a);\n    return a;\n}\n",
    "deep.c":  "deep(int a) {\n    return a + 1;\n}\n",
    # the other definition style: return type and name on one line
    "modern.c": "int mbedtls_do_thing(ctx_t *c)\n{\n    deep(1);\n    return 0;\n}\n",
    "lonely.c": "nobodyCallsThis(void) {\n    return 0;\n}\n",
    "cli.c":   "main(int argc, char **argv) {\n    return 0;\n}\n",
    # callback.c is reachable ONLY by having its function bound into a table.
    # No call site names it, so a call-only graph scores it unreachable.
    "table.c": "setup(void) {\n    h->onData = handleData;\n}\n",
    "callback.c": "handleData(int a) {\n    return a;\n}\n",
    # a binding whose target this tool cannot name: residual indirection
    # same field as table.c binds to a real function, but this target cannot be
    # named - the residual a model could resolve and this tool cannot
    "opaque.c": "wire(void) {\n    h->onData = GENERATED_HANDLER;\n}\n",
    # a language this tool does not index. It must still appear in `files`:
    # absent and `not_reached` both read as dead code one stage downstream.
    "lib.rs": "pub fn handle_data(a: i32) -> i32 {\n    a + 1\n}\n",
}


def selftest():
    import tempfile
    failures = 0

    def check(label, got, want):
        nonlocal failures
        if got == want:
            print("  ok   %s" % label)
        else:
            failures += 1
            print("  FAIL %s: got %r, want %r" % (label, got, want))

    with tempfile.TemporaryDirectory() as tmp:
        for name, body in FIXTURE.items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        g = build(tmp, ["entry.c:xmlParseDocument", "cli.c:main"])
        f = g["files"]
        check("entry file is distance 0", f["entry.c"]["hops"], 0)
        check("one call away is distance 1", f["mid.c"]["hops"], 1)
        check("two calls away is distance 2", f["deep.c"]["hops"], 2)
        check("uncalled file is not reached", f["lonely.c"]["hops"], None)
        check("a main() nobody calls is still distance 0",
              f["cli.c"]["hops"], 0)
        check("distance 0-1 scores the full 10", f["mid.c"]["trust_boundary"], 10)
        check("distance 2 scores 6", f["deep.c"]["trust_boundary"], 6)
        check("unreached scores nothing rather than 3",
              f["lonely.c"]["trust_boundary"], None)
        check("an unresolvable entry is reported, not silently dropped",
              build(tmp, ["nosuch.c:nope"])["unresolved_entries"], ["nosuch.c:nope"])
        check("edges were actually found", g["counts"]["file_edges"] >= 2, True)
        check("type-and-name-on-one-line definitions are indexed too",
              build(tmp, ["modern.c:mbedtls_do_thing"])["files"]["deep.c"]["hops"], 1)
        with open(os.path.join(tmp, "keyword.c"), "w", encoding="utf-8") as fh:
            fh.write("while (running) {\n    tick();\n}\n")
        # if `while` were indexed as a function, this entry would resolve
        check("an unindented control keyword is not indexed as a function",
              build(tmp, ["while"])["unresolved_entries"], ["while"])
        check("the real name is captured, not the name minus its first letter",
              build(tmp, ["callback.c:handleData"])["files"]["callback.c"]["hops"], 0)
        g2 = build(tmp, ["entry.c:xmlParseDocument", "cli.c:main", "table.c:setup"])
        check("a file reachable only via a function-pointer binding is reached",
              g2["files"]["callback.c"]["hops"], 1)
        check("a binding whose target cannot be named is counted as residual",
              g2["indirection"]["bindings_unresolved"] >= 1, True)
        check("resolvable bindings are counted separately",
              g2["indirection"]["bindings_resolved"] >= 1, True)
        check("a file in an unindexed language is listed, never absent",
              "lib.rs" in f, True)
        check("a file in an unindexed language reads unindexed, not not_reached",
              f["lib.rs"]["reachability"], "unindexed")
        check("an unindexed file scores nothing rather than a distance",
              (f["lib.rs"]["hops"], f["lib.rs"]["trust_boundary"]), (None, None))
        check("unindexed files are counted", g["counts"]["unindexed"] >= 1, True)
        # the .rs body is never read, so nothing inside it can resolve as a root
        check("a symbol in an unindexed language does not resolve as an entry",
              build(tmp, ["handle_data"])["unresolved_entries"], ["handle_data"])
        check("the caveats state the C/C++-only scope",
              any("C and C++ only" in c for c in g["caveats"]), True)

    with tempfile.TemporaryDirectory() as tmp2:
        for name, body in (("main.rs", "fn main() {}\n"),
                           ("app.py", "def main():\n    pass\n")):
            with open(os.path.join(tmp2, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        g3 = build(tmp2, ["main.rs:main"])
        # `len(defs) >= 2 * len(src)` is `0 >= 0` here: before the zero-file test
        # a pure-Rust tree came back with no warning at all - healthy-looking
        # JSON over nothing measured.
        check("a tree with no C files warns instead of looking healthy",
              "measured nothing" in (g3["health"]["warning"] or ""), True)
        check("nothing was indexed in a tree with no C files",
              g3["counts"]["files_indexed"], 0)
        check("its files are still listed, as unindexed",
              sorted(k for k, v in g3["files"].items()
                     if v["reachability"] == "unindexed"), ["app.py", "main.rs"])

    # ---- prototypes are not definitions, however they are laid out ---- #
    # include/ sorts before src/, which is the layout that let a header's split
    # prototype own the symbol and leave the implementing file not_reached.
    layout = {
        "include/api.h": "int api_read(ctx_t *c,\n             unsigned flag);\n"
                         "int api_close(ctx_t *c); /* see impl.c */\n"
                         "extern void *xcopy (void *d, const void *s,\n"
                         "                    size_t n) __THROW __nonnull ((1, 2));\n",
        "src/impl.c": "int api_read(ctx_t *c,\n             unsigned flag)\n{\n"
                      "    return 0;\n}\n"
                      "int api_close(ctx_t *c) {\n    return 0;\n}\n"
                      "void *xcopy(void *d, const void *s, size_t n) {\n"
                      "    return d;\n}\n",
        "src/main.c": "int main(void) {\n    api_read(0, 1);\n    api_close(0);\n"
                      "    old(1, 2);\n    return 0;\n}\n",
        # An old-style definition: its parameter declarations sit between the
        # ')' and the '{', and it is still a definition.
        "src/knr.c": "int old(a, b)\n    int a;\n    int b;\n{\n    return a + b;\n}\n",
        "src/parser.cpp": "int Parser::parse(const char *b)\n{\n    return 0;\n}\n"
                          "std::vector<int> Parser::split(const char *s) {\n"
                          "    return {};\n}\n"
                          "Parser::Parser() : n(0) {\n}\n",
        "src/use.cpp": "int run(Parser &p, const char *buf) {\n    p.parse(buf);\n"
                       "    return 0;\n}\n",
    }
    with tempfile.TemporaryDirectory() as tmp:
        for name, body in layout.items():
            os.makedirs(os.path.dirname(os.path.join(tmp, name)), exist_ok=True)
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(body)
        g4 = build(tmp, ["src/main.c:main", "src/use.cpp:run"])
        f4 = g4["files"]
        check("a prototype split over two lines is not the definition",
              (f4["src/impl.c"]["hops"], f4["include/api.h"]["reachability"]),
              (1, "not_reached"))
        defs, src, _unreadable = index(tmp, sorted(layout))
        check("nor is one with a trailing comment, or one ending in attributes",
              sorted(sym for sym, where in defs.items() if "include/api.h" in where), [])
        check("an old-style K&R definition is still a definition",
              (defs.get("old"), f4["src/knr.c"]["hops"]), (["src/knr.c"], 1))
        check("out-of-class C++ members are indexed under their own names",
              sorted(sym for sym, where in defs.items() if "src/parser.cpp" in where),
              ["Parser", "parse", "split"])
        check("so a method call reaches the file that defines it",
              f4["src/parser.cpp"]["hops"], 1)
        check("is_prototype reads past a comment to the ';'",
              is_prototype(["int f(int a) /* x */ ;"], 0, 5), True)

    # A line the scanned tree writes must not be able to stall the index. With
    # qualifier template arguments free to span '>' and '::', this one line took
    # seconds at 26 repeats and doubled with each one more.
    import time
    started = time.time()
    DEF.match("a<b>::" * 26 + "c")
    DEF.match("Foo<Bar>:: " * 4000)
    check("a column-0 run of `a<b>::` is rejected in linear time",
          time.time() - started < 2.0, True)
    check("and one nested template level still qualifies a member",
          (DEF.match("Box<std::pair<int,int>>::get(void) {") or [None, None])[1], "get")

    # ---- --out is confined to the run directory ---- #
    with tempfile.TemporaryDirectory() as parent:
        tmp = os.path.join(parent, "repo")
        os.makedirs(tmp)
        with open(os.path.join(tmp, "entry.c"), "w", encoding="utf-8") as fh:
            fh.write(FIXTURE["entry.c"])
        os.makedirs(os.path.join(tmp, "src"))
        with open(os.path.join(tmp, "src", "app.py"), "w", encoding="utf-8") as fh:
            fh.write("print('hi')\n")

        def _text(path):
            with open(path, encoding="utf-8") as fh:
                return fh.read()

        def _main(out, root=tmp):
            sink = io.StringIO()
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                code = main(["--root", root, "--entry", "entry.c", "--out", out])
            return code, sink.getvalue()

        app = os.path.join(tmp, "src", "app.py")
        code, said = _main(app)
        check("--out onto a source file is refused, and nothing is written",
              (code, "§9 rule 2" in said, _text(app)),
              (2, True, "print('hi')\n"))
        outside = os.path.join(parent, "outside.json")
        check("so is --out outside the tree altogether",
              (_main(outside)[0], os.path.exists(outside)), (2, False))
        check("and --out naming the run directory itself",
              _main(os.path.join(tmp, RUN_DIR))[0], 2)
        graph = os.path.join(tmp, RUN_DIR, "scope", "graph.json")
        check("the documented path is written",
              (_main(graph)[0], json.loads(_text(graph))["schema"]), (0, "build_graph/1"))
        previous_mask = os.umask(0o077)
        try:
            _main(graph)
        finally:
            os.umask(previous_mask)
        check("with the mode the operator's umask gives it, not a fixed 0644",
              oct(os.stat(graph).st_mode & 0o777), oct(0o600))
        if rules_lib.can_symlink():
            alias = os.path.join(parent, "alias")
            os.symlink(tmp, alias)
            check("a --root that is itself a link is not refused",
                  _main(os.path.join(alias, RUN_DIR, "scope", "graph.json"), alias)[0], 0)
            os.remove(graph)
            os.symlink(app, graph)
            code, said = _main(graph)
            check("a link planted at the output file is refused, not written through",
                  (code, "symbolic link" in said, _text(app)),
                  (2, True, "print('hi')\n"))
            os.remove(graph)
            os.rmdir(os.path.join(tmp, RUN_DIR, "scope"))
            os.symlink(os.path.join(tmp, "src"), os.path.join(tmp, RUN_DIR, "scope"))
            code, said = _main(os.path.join(tmp, RUN_DIR, "scope", "app.py"))
            check("so is a link on the way there",
                  (code, "symbolic link" in said, _text(app)),
                  (2, True, "print('hi')\n"))
            os.remove(os.path.join(tmp, RUN_DIR, "scope"))
            os.rename(os.path.join(tmp, RUN_DIR), os.path.join(tmp, "elsewhere"))
            os.symlink(os.path.join(tmp, "elsewhere"), os.path.join(tmp, RUN_DIR))
            code, said = _main(os.path.join(tmp, RUN_DIR, "scope", "graph.json"))
            check("and so is a .security-review that is a link",
                  (code, "symbolic link" in said,
                   os.path.exists(os.path.join(tmp, "elsewhere", "scope", "graph.json"))),
                  (2, True, False))
        else:
            rules_lib.skip_case("a link at --root, at the output file, on the way there, or as the run directory (four cases)",
                            n=4)

    print("\nselftest: %d failure(s)%s" % (failures, rules_lib.skipped_note()))
    return 1 if failures else 0


# --------------------------------------------------------------------------- #
# where --out may write
# --------------------------------------------------------------------------- #
#
# The run directory lives in the scanned tree (contract §1), and an agent types
# the --out, so nothing but this check stands between a typo and the tree. It
# used to be written wherever it pointed: `--out src/app.py` replaced a source file under review with graph
# JSON. So --out is confined the way ledger.py confines its own - it must
# resolve strictly under <realpath(root)>/.security-review - and, as in every
# writer under the run directory (snapshot.py, extract_functions.py,
# sweep_secrets.py, enrich_candidates.py and the rest each carry their own
# copy of this rule; this file takes only the tooling-folder test from rules_lib), a symbolic
# link at `.security-review`, at any directory beneath it on the way, or at the
# file itself is refused rather than followed. --root itself is never checked:
# it may legitimately be a link, and on macOS every temporary directory is one.

def _link_refusal(link):
    try:
        target = os.readlink(link)
    except OSError:
        target = os.path.realpath(link)
    return ("%s is a symbolic link to %s. The run directory lives inside the "
            "scanned tree, and a link in it sends this tool's write wherever the "
            "tree says - contract §1 (the run directory) and §9 rule 2 (no tool "
            "writes to the scanned tree)." % (link, target))


def confined_out(root, out):
    """(path to write, None) for --out, or (None, why it is refused).

    The path returned is the one that was checked, every link resolved, and it
    is the one written: writing `out` as typed would let `a/../b` mean one thing
    to this check and another to the kernel.
    """
    base = os.path.join(os.path.realpath(root), RUN_DIR)
    run_dir = os.path.join(os.path.abspath(root), RUN_DIR)
    if os.path.islink(run_dir):
        return None, _link_refusal(run_dir)
    if os.path.lexists(run_dir) and os.path.realpath(run_dir) != base:
        return None, ("%s resolves to %s, not %s - contract §1, §9 rule 2"
                      % (run_dir, os.path.realpath(run_dir), base))
    head, parts = os.path.abspath(out), []
    while True:
        head, tail = os.path.split(head)
        if not tail:
            break
        parts.append(tail)
    current = head
    for part in reversed(parts):
        step = os.path.join(current, part)
        if step == base or step.startswith(base + os.sep):
            # Inside the run directory nothing is followed: a link there is one
            # the scanned tree planted.
            if os.path.islink(step):
                return None, _link_refusal(step)
            current = step
        else:
            current = os.path.realpath(step)
    if not current.startswith(base + os.sep):
        return None, ("--out %s resolves to %s, which is not under %s. Contract §9 "
                      "rule 2 confines every write this skill makes to "
                      ".security-review/; write the graph to %s."
                      % (out, current, base, os.path.join(base, "scope", "graph.json")))
    return current, None


def _umask_mode():
    """0o666 less the process umask: the mode `open(path, "w")` would have given.

    mkstemp creates its file 0600, and a fixed 0644 after it would hand every
    user on the machine a file an operator's `umask 077` meant to keep private.
    """
    mask = os.umask(0)
    os.umask(mask)
    return 0o666 & ~mask


def write_out(path, text):
    """Write `path` whole through a temp file nobody could have planted."""
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix="." + os.path.basename(path) + ".",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, _umask_mode())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def build_parser():
    ap = argparse.ArgumentParser(description="Measure call distance from entry points.")
    ap.add_argument("--root", default=".", help="repository root (default: .)")
    ap.add_argument("--entry", action="append", default=[],
                    help="entry point: 'file.c', 'file.c:symbol', or 'symbol' (repeatable)")
    ap.add_argument("--out", default=None,
                    help="write JSON here, under <root>/.security-review/ "
                         "(default: stdout)")
    ap.add_argument("--selftest", action="store_true", help="run the fixtures and exit")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.selftest:
        return selftest()
    if not args.entry:
        print("no --entry given: the parent supplies the root set, this tool only "
              "measures. Nothing to do.", file=sys.stderr)
        return 2
    target = None
    if args.out:
        # Checked before the tree is read: a refused --out costs nothing.
        target, why = confined_out(args.root, args.out)
        if target is None:
            print("REFUSED: %s" % why, file=sys.stderr)
            return 2
    graph = build(os.path.abspath(args.root), args.entry)
    text = json.dumps(graph, indent=1, sort_keys=False)
    if target:
        try:
            write_out(target, text + "\n")
        except OSError as exc:
            print("%s could not be written (%s)" % (target, exc), file=sys.stderr)
            return 1
        c = graph["counts"]
        # `reached` counts FILES, and the line used to print it straight after the
        # symbol total - "504 symbols, 306 edges; 49 reached" - which reads as 49
        # of 504 symbols. It was read that way twice: once by a stage 1 agent that
        # reported "51 of 529 symbols reached" in its summary, and once by the
        # person reviewing the skill, who flagged a healthy 56% of files as a
        # thin graph. Name the unit next to the number it counts.
        files_total = len(graph.get("files") or {}) or (c["files_indexed"] + c["unindexed"])
        print("indexed %d files (%d symbols, %d file edges); %d of %d FILES reached "
              "from the entry points, %d unindexed -> %s"
              % (c["files_indexed"], c["symbols_defined"], c["file_edges"],
                 c["reached"], files_total, c["unindexed"], args.out))
    else:
        print(text)
    if graph["unresolved_entries"]:
        print("WARNING: unresolved entry points: %s"
              % ", ".join(graph["unresolved_entries"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
