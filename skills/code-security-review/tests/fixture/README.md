# Smoke-test fixture

Deliberately vulnerable code, in every language the extractor assigns a file to
(`rules_lib.LANGUAGES`: C, C++, C#, Go, Java, JavaScript, PHP, Python, Ruby,
Rust and TypeScript), used by `scripts/smoke_test.py` to run the
deterministic stages end to end and measure which rules actually fire.

**Nothing here is reachable, buildable or imported by anything.** It exists to be
matched by a regex. Every walk skips the installed skill by identity, so
it is not read as part of a scanned tree, and every script refuses a `--root`
that is the skill itself or a directory inside it.

## What it covers

Every pattern rule carries at least one `EXPECT` somewhere in `src/`, including
the paths that are easy to leave untested: the multiline pass (`MEM-009`, whose
third branch spans lines), the name-matched rules whose hit is a whole function
(`LOG-*` and `HW-007`, tagged on the definition line), and every `HW-*` rule
(`fw.c`). The rules that list every language carry an expectation in the
languages they are most often wrong about, in the spelling that language
actually uses - `exec("ls " . $dir)` and backticks in PHP, `exec(...)` after
`const { exec } = require('child_process')` in Node, `readFile` imported from
`node:fs/promises`, `include("pages/" . $name . ".php")`, `find_by_sql` with
`#{}` in Ruby, `os.ReadFile` in Go, `rejectUnauthorized: false` with its key
quoted and not, `ssl.CERT_NONE`, `"DESede"`. Each of those once recorded zero
hits and `zero_hit_cause: absent-from-tree` on a tree full of them. The shapes
those rules must NOT match - a method defined as `async exec (args) {`, an
`import`, `new URL(u)`, `Net::HTTPSuccess` - are probes in `rules_lib.py`'s
selftest, since a line here cannot assert an absence.

The name-matched rules that also carry a `line_pattern` (`LOG-004`, `LOG-005`,
`LOG-006`, `LOG-008`) have each half asserted on a line the other cannot meet:
a sink inside a function the name half does not select (`load_peer` in `fw.c`,
`requireSession` in `web.js`), and a name on a definition line no sink shares
(`get_api_key`, `deserialize_session` and `check_otp` in `app.py`).
`smoke_test.py` compares `(file, line, rule)` and not which half fired, and
stage 1 keeps one hit per `(rule, line)`, so an expectation either half can
meet tests neither: removing `LOG-004`'s sink half, or the name half of
`LOG-005`, `LOG-006` or `LOG-008`, once left every expectation met. `LOG-001`
to `LOG-003`, asserted only in Python until then, carry expectations in five to
nine languages each. The spellings the logic-flaw patterns learned after the
Mbed TLS run each have a line too, `accept_update`'s CVE-2008-5077 call among
them, and `LOG-007`, `LOG-009` and `LOG-010`, asserted in one or two languages
until then, carry expectations in four to six. Five sink lines sit in
functions no name half selects, in shapes a narrowed sink half once dropped:
`open_message` in `fw.c` discards a `crypto_sign_open` result through a
`(void)` cast, `load_message` in `app.php` calls libsodium's
`sodium_crypto_sign_open`, `confirm_device` in `app.py` compares a
`pin_code` and `receive_update` an `hmac_out`, and `macs_equal` in `fw.c`
compares a MAC byte by byte (`hmac[i] != hmac_calc[i]`).

It also carries the shapes the candidate gate once refused a correct run over:
an async arrow bound to a name, an unbound Express callback that stage 1 calls
`<anonymous>` (an `EXPECT-FUNC` cannot spell that name, so only its sink is
tagged), and a Ruby method defined without parentheses (`web.js`, `tasks.rb`).
`web.js` also holds a regex literal containing `//`, which a comment mask would
read to the end of the line, taking the `}` there with it: `fetchChecked` would
then stay open to the end of the file and be dropped, and its `EXPECT-FUNC`
reported missing. `render.cpp` ends with two structs that each define `load`:
two functions with one name in one file, each with its own MEM-WFS (`load::0`
and `load::1`). The gate's I5 check once counted them as one `(file, function)`
pair recorded twice and refused the run. The case was first written as the two
Python classes in `app.py` that still define `load`; MEM-WFS runs over C, C++
and Rust only, so those two carry none and I5 takes no pair from them, and
`smoke_test.py` fails when no file holds a same-named pair with a MEM-WFS
each. For the same reason, the function `smoke_test.py` suppresses (`shell` in
`parse.c`), whose MEM-WFS it expects to be held with it, has to stay C, C++ or
Rust. `parse.c` ends with a `safe_realpath` helper named more often
than `realpath` itself: while `MEM-007` opened its realpath branch on `\b`, the
gate's wrapper-blindness check dropped that anchor, counted the helper's five
lines as sites the rule missed, and refused a run for a rule that has no wrapper
to name.

`rules_lib.py --selftest` also runs every shipped pattern through ripgrep and
Python over this directory, when `rg` is on PATH, and fails on a line the two
disagree about - `app.php:6` and `tasks.rb:10` are the lines ripgrep 14.1.0 once
missed.

Lines are appended at the end of an existing file rather than inserted above
older ones: prompts and docs cite fixture lines by number
(`src/app.py:39` among them), and an inserted line moves every citation below it.

## The expectation format

A line carrying a comment of the form

```
EXPECT: RULE-ID
```

asserts that the rule fires **on that line**. Several ids may be listed, comma
separated. `EXPECT-FUNC: name` on a definition line asserts that the extractor
resolved a function by that name starting there. Two tags on one line need a
character between them that an id cannot contain - `*/ /*`, `//` or `#` - or
the second tag's keyword is read as part of the first tag's name.

A line carrying `EXPECT-SKIP: RULE-ID` asserts that the rule matches and is then
skipped by its own `skip_pattern` — the one sanctioned skip path. That is the
distinction the whole ruleset is built around, so it is tested directly rather
than assumed.

`MEM-002` has one, and `OTH-004` carries both halves. The checked
registration `if (signal(SIGTERM, on_term) == SIG_ERR)` is expected to be
**emitted**, because the skip is about the handler argument and `on_term` is a
handler; `signal(SIGPIPE, SIG_IGN)` in `ignore_pipe` is expected to be
**skipped**. That skip is sampled with class `skip-pattern`, which the candidate
gate checks by running the rule's own `skip_pattern` over the hit again. It used
to be sampled as `other`, which the gate caps at 20% of a sample, so this line
failed the gate on a skip that was correct.

`smoke_test.py` fails on a missing expectation. It reports unexpected hits as a
count and a sample without failing, because rules firing more widely than the
fixture anticipated is the recall bias working, not a defect.

Lines are numbered the way stage 1 numbers them: the file's bytes, decoded, split
on `\n` and nothing else. A carriage return, form feed or U+2028 inside a line
does not start a new one. `src/pagebreaks.c` puts a form feed between its
functions, GNU style, so a later stage that splits on more than `\n` quotes the
wrong line for both of its hits and fails the smoke test's line-model check.

## What is walked, and what is not

`smoke_test.py` runs stage 1 with `--include src/vendor`. `src/vendor/` stands
for first-party code kept under a directory a default exclusion catches: its
hits are expected like any other, and the `vendor` exclusion stays in
`manifest.json` because it still excludes every other `vendor/`. So every later
stage that walks the tree has to honour the include the way stage 1 did.
`target/` is build output, excluded by default, and carries no expectation; the
candidate gate's recount has to leave it out too. The two hold different rules
on purpose, so a recount that got both wrong cannot balance to the right count.
