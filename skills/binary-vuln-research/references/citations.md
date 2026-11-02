# Citations: quoting a location so a script can re-read it

Read this before writing the first packet (Phase 3), and again before any finding, brief, summary
or addendum. Version 0.1.0 of this skill was reported to quote wrong addresses and file
locations: an address in one base read as another, objdump's words copied as if they were bytes in
file order, a line number off by one, a member path that did not exist. Since 0.2.0 everything a
file quotes goes in a block that `scripts/verify_citations.py` re-reads against the artifact.

## The rule

- Every address, offset, symbol, file:line, hash and secret that a finding, brief, summary,
  addendum, refuter packet, refuter reply or candidate's `notes.md` quotes is in a `citations` or
  `excerpt` block of that same file. The prose may repeat it; it may not quote anything the blocks
  lack. A KILL's evidence, from Phase 2 or from a refuter, is quoted in blocks in
  `candidates/<ID>/notes.md`: a KILL in `candidates.md` whose notes hold no checked line fails.
- An excerpt is pasted from the tool's output, never retyped or "tidied": keep objdump's columns.
- Run the checker from the working directory (the folder holding `.binary-vuln-research/`):

  ```text
  python3 -I -B <skill folder>/scripts/verify_citations.py
  ```

  before recording a KILL, before applying a refuter's reply, before posting Gate B or Gate C,
  and before the summary is final. Exit 0: every check holds. Exit 1: something fails; fix it before
  going on. Exit 2: the run folder or a named file is missing. Name files (relative to the run
  folder) to check only those; `--json` prints every result.
- A FAIL is fixed at its source: re-read the artifact at the cited place, correct the claim and
  everything built on it (tier, verdict, score, headline), never only the expected bytes to make
  the check pass. A correction to something the person saw is logged and gets an addendum.
- A refuter's reply is never edited: one that fails is sent back once, as a reply naming no
  location is, with the checker's FAIL lines added to the prompt ("An earlier reply named no
  location: name it or answer NONE_FOUND" and then "Its citations failed: <the FAIL lines>"); if
  it fails again it counts as NONE_FOUND, and the failure goes in the correction log.
- The summary prints the checker's last line, for example:

  ```text
  verify_citations: 41 check(s) in 6 file(s) and artifacts.md: 41 ok, 0 failed (0 uncited); 0 warning(s); 1 value(s) declared, not checked
  ```

## References: which file

`<ref>` is the path of a file registered in `artifacts.md`, as its Path column spells it: relative
to the working directory, or absolute. A member of an archive is `<archive>!<member>`, the member
path as the archive lists it (`fw.tar.gz!usr/sbin/httpd`, `libwifi.a!wpa_parse.o`). ar (GNU and
BSD long names), zip and tar (also compressed) are read directly; for any other container
(squashfs, UBI, a vendor format) the checker reads the extraction at
`.binary-vuln-research/work/extract/<first 12 hex of the archive's SHA-256>/<member>`, so extract
there and nowhere else. A cited file without a row in `artifacts.md` fails; a member is covered by
its archive's row (registered, as Phase 0 says, by the archive's hash). `sha256 <archive>!<member>`
cites the member's own hash; the archive's is cited as `sha256 <archive>`. A text file inside the run folder (a brief, a log) needs no row; a binary there (a patched copy, a
dump) is an artifact and does. A path with a `..` segment is refused, and so is a link in the
extraction, or an extraction folder, that leads out of the run folder. An archive holding two
members of the same name fails: which one is meant is ambiguous.

`artifacts.md` holds one row per file, however its path is spelled (`artifacts/fw.bin`,
`./artifacts/fw.bin` and its absolute path are one file: a second row fails), under a table header:
the row directly above a `|---|` row, with a Path and a SHA-256 column. Every row is checked (the
file exists and has that hash). A source tree is registered file by file, only the files cited;
its coverage goes in the intake record.

## Bases: which address

Every address names its base. Mixing bases is the most common wrong citation.

| Base | What the number is | Where it comes from |
|---|---|---|
| `image` | the address as loaded | ELF: the program headers' `p_vaddr` (`readelf -lW`), what `objdump -d` prints; a PIE starts near 0, before relocation. PE: image base + RVA, what objdump and most disassemblers print (an RVA alone is refused). Raw image: the load base recorded in `artifacts.md` plus the file offset, as `objdump -b binary -m <arch> --adjust-vma=<load base> -D` prints it |
| `object` | an offset into a section | a relocatable object or archive member (`.o`, `.a`), where `objdump -d -j .text` prints offsets from the section start; written `.text+0x1c` in a citation and `object .text` in an excerpt header. Also valid for a section of an ELF or PE executable |
| `file` | an offset into the file | `xxd -s`, `dd skip=`, a hex editor |
| `runtime` | an address in a running process or target | a debugger, a log or a crash; cited as `runtime <address> <log>`, checked only for appearing in that log (with `0x`, or as eight or more bare hex digits) |

The load base of a raw image is the first `0x` number in its `artifacts.md` row's Load base cell,
outside parentheses; its evidence goes in parentheses after it. The Memory map cell lists ranges as
`0x<first>-0x<last> <name>`, separated by `;`, with their evidence in parentheses.

A decompiler may rebase: Ghidra loads a PIE at `0x100000` by default and IDA may pick its own base.
Set the project's image base to the ELF's (or the load base in `artifacts.md`) before quoting from
it, or convert. A decompiler's auto-name carries its address (`FUN_00101149`, `sub_8001234`,
`LAB_`, `DAT_`, `loc_`, `off_`): the checker treats it as that address, so a name taken from a
rebased project fails until the base matches.

## The citations block

One claim per line; `#` starts a comment line. The grammar (the block itself is fenced as
`citations`):

Write every address and offset as `0x` and hex (or `0`): objdump's `0000000000401136` is `0x401136`,
and a bare `401136` or `.text+12` is refused, since it could be read as decimal. `len`, line numbers
and `value` may be decimal, with no leading zero.

```text
sha256  <ref> <64 hex>
bytes   <ref> @ <address> <base> = <hex>[/le16|/le32|/be16|/be32]
symbol  <ref> <name>[+<offset>|-<offset>] @ <address> <base>
secret  <ref> @ <address> <base> len <n> sha256 <64 hex>
line    <path>:<n> = <quoted text>
runtime <address> <log, relative to the run folder>
region  <address> <ref> <region name>
value   <number> <why it is not an address>
```

- `bytes`: the hex is in file order, spaces optional. objdump prints instruction words as values:
  ARM `e3a00000` and AArch64 `d503201f` are 32-bit words, Thumb `f04f 0000` is two 16-bit
  halfwords, MIPS words follow the target's byte order. Copy such words with the suffix that says
  so (`/le32`, `/le16`, `/be32`, `/be16`), or write the bytes in file order. A mismatch shows at
  most 8 bytes of what is there, says when the bytes match in another order, and gives up to three
  places where the quoted bytes do occur.
- `symbol`: the symbol starts exactly at the address, or at the address minus the offset
  (`parse+0x1c`, and objdump's `parse-0x10` before a symbol). Symbols come from `.symtab` and
  `.dynsym`; an ARM Thumb function (its symbol value odd) matches with bit 0 clear or set, every
  other symbol exactly; a version suffix (`memcpy@GLIBC_2.14`) is dropped. objdump's section labels
  for code with no symbol (`<.plt>`, `<.text>` in a stripped file, `<.data>` for a raw image read
with `-b binary`) are checked against the section's start. The offset must keep the address inside
the file: in a loaded segment, or within the section. `<name@plt>` is checked on x86-64: the
address must be the stub's start (a multiple of 8 into the section, its jump through the GOT slot
first, or after `endbr64`, or after `endbr64` and `bnd`), and that slot's relocation names the
function, as objdump does, `*ABS*+0x...` for an ifunc. On other architectures a `@plt` name fails,
so cite the call's bytes instead. A stripped binary gives no symbols here, nor does a PE file:
cite the instruction bytes.
- `secret`: compared by the SHA-256 of `len` bytes at the address; the bytes are never printed,
  and wherever the same bytes would be shown after a failing `bytes` or excerpt check (through
  any spelling of the file, its archive, its extraction or a copy) they show as `**`.
- `line`: lines are counted at line feeds, as `grep -n` and editors count them; whitespace is
  normalised; the quote is the whole line, or at least 8 characters of it. A wrong number is
  answered with the line that does hold the quote; the file's text is never printed.
- `value`: a constant written as `0x` and four or more hex digits that is not an address (a mask,
  a length, a magic number). Declared, counted in the result line, never checked: never use it for
an address. Only the number is declared: an address in the reason text is not cited by it, and a
`value` line is not a checked line.
- `region`: an address the image holds no bytes for (a peripheral register, RAM, the initial
  stack), checked to lie inside a range of that artifact's Memory map in `artifacts.md` and outside
  the bytes of the file; an address the file does hold is cited with `bytes`.

## The excerpt block

The header names the file and the base; the body is `objdump -d` (or `-D`) output with the raw bytes
shown, unchanged:

```excerpt artifacts/libwifi.a!wpa_parse.o object .text
0000000000000000 <wpa_parse_ie>:
   0:	f3 0f 1e fa          	endbr64
   4:	0f b6 47 01          	movzbl 0x1(%rdi),%eax
   8:	3c 20                	cmp    $0x20,%al
   a:	77 2c                	ja     38 <wpa_parse_ie+0x38>
```

Each `<address>: <bytes>` line is checked against the file at that address in that base (pairs
are bytes in file order; 4- and 8-digit groups are words, tried in both byte orders), and each
`<address> <name>:` label against the symbol table. Lines without an address column are skipped:
`...`, comments, objdump's `file format` and `In archive` headers, its relocation lines
(`8: R_X86_64_PLT32 memcpy-0x4`), and the source, function and file lines of `-S` and `-l`. A
line that starts with an address column, after any marker, but is not in objdump's form fails: a
marker such as `=>` or `*` on the key line (say which line matters in the prose instead), gdb's
`x/i`, `--prefix-addresses`, `--no-show-raw-insn`, `--visualize-jumps`, and an IDA or Ghidra
listing; so does an excerpt with no line in objdump's form. Paste `objdump -d` without `-C`:
demangled names are not in the symbol table. A PE file's function labels are not checked (its
symbols are not read) and show as warnings; its bytes lines are checked. Only the
address, the bytes and the labels are checked; the mnemonic and operands after the bytes,
including objdump's `<symbol>` annotations of a branch target, are not. The excerpt header is
`excerpt <ref> image`, `excerpt <ref> file` or `excerpt <ref> object <section>`.

## The text around the blocks

The checker reads the text outside the blocks for what looks like a location:

- an address: `0x` and four or more hex digits, or a decompiler auto-name, also inside a longer
  name (`FUN_00401136`, `PTR_FUN_00401136`, `sub_8001234`); `0x` with fewer digits is taken for a
  constant and not read;
- an object offset: `.text+0x1c`, matched against the object-base lines of that section;
- a `file.ext:N` (also `<archive>!<member>:N`) whose extension is one of source, header, assembly,
  linker script, device tree, build, text, log or map files (the list is `SOURCE_EXT` in the
  checker), and `Makefile:N`, `Kconfig:N`;
- a 64-hex hash.

Not read as addresses: `name+0x1c` (an offset from a symbol), and the value after
`--stop-address=` (objdump never prints that address). Each location read must appear in a block
of the same file; the load base and the Memory map range bounds in the `artifacts.md` row of a
cited artifact count as quoted (their evidence text does not), and an address inside a range is
cited with `region`. In a finding, the notes of a KILLed candidate, and a KILLED or
REACHABILITY_DOUBT reply (its `fact` and `paths`, and anything before its first field), one that
does not appear is a FAIL; in the reply's other fields and in every other file it is a warning. A
reply counts as KILLED or REACHABILITY_DOUBT however its outcome line is written, and when it has
no outcome line. In these strict files the text of other fenced blocks is read too (except
pseudo-C, fenced as `c` or `pseudo-c`), and so are comment lines in citations blocks. A branch
target or a pointer quoted from an excerpt's instruction text is cited by a `bytes` or `symbol`
line at that address; a constant, by `value`. A path in backticks that names no cited, registered,
extracted or existing file is a warning. A strict file with no checked citation or excerpt line
fails (an empty block, or only `value` lines, counts as none). `candidates.md` and `run-log.md`
are indexes and are not read: the location a candidate row gives is quoted, in blocks, in its
packet, and for a KILL in its notes (a KILL verdict is found however it is capitalised, and in a
table with or without outer pipes).

## What it does not check

That the bytes mean what the finding says (that the compare guards this length, that the branch
is taken); the instruction text printed after the bytes; reachability; counts; an address written
without `0x`, with fewer than four hex digits, or in words; `function+0x1c` in the text; a
`file:N` with an extension outside its list; anything else outside a block that the text does not
quote in a form it recognises; the symbols of a PE file; a `@plt` name outside x86-64; a runtime
address beyond its appearing in the log; a `region` address beyond its lying in a recorded range. It proves that the quoted locations exist and
hold what is quoted, nothing more, and only when it is run.

## A finding's blocks, worked

```citations
sha256 artifacts/libwifi.a 5f1c2b9e0d7a4c3b8e6f1a2d9c0b7e4f3a6d5c8b1e0f9a2d7c4b3e6f5a8d1c0b
symbol artifacts/libwifi.a!wpa_parse.o wpa_parse_ie @ .text+0 object
bytes artifacts/libwifi.a!wpa_parse.o @ .text+0x8 object = 3c 20
line src/driver/wpa_ie.c:214 = memcpy(ie->data, buf + 2, len);
value 0x7fff mask the driver applies to the length
```

The prose may then say "the length check at `.text+0x8` (`cmp $0x20,%al`) is unsigned" and quote
`wpa_ie.c:214`; quoting `.text+0x9`, `wpa_ie.c:215`, or an address such as `0x0801a4c2` that no
block holds, fails.
