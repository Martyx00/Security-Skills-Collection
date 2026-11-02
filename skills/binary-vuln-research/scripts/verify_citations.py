#!/usr/bin/env python3
"""verify_citations.py - re-check what a binary-vuln-research run cites, against the artifacts.

    python3 -I -B <skill folder>/scripts/verify_citations.py                     # ./.binary-vuln-research
    python3 -I -B <skill folder>/scripts/verify_citations.py --run-folder <path>
    python3 -I -B <skill folder>/scripts/verify_citations.py findings/BVR-0001.md # only these (run folder relative)
    python3 -I -B <skill folder>/scripts/verify_citations.py --json

A finding, brief, summary, addendum, refuter packet or reply, or a candidate's notes.md carries what it
quotes in fenced blocks; references/citations.md has the grammar and worked examples:

  ```citations                                  one checkable claim per line
  sha256  <ref> <64 hex>
  bytes   <ref> @ <address> <base> = <hex>[/le16|/le32|/be16|/be32]
  symbol  <ref> <name>[+<offset>|-<offset>] @ <address> <base>
  secret  <ref> @ <address> <base> len <n> sha256 <64 hex>
  line    <path>:<n> = <quoted text>
  runtime <address> <log>                       the address appears in that log (run folder relative)
  region  <address> <ref> <region name>         in the artifact's recorded memory map, not in its bytes
  value   <number> <why it is not an address>   declared, not checked
  ```

  ```excerpt <ref> <base>                       disassembly as objdump prints it: each "<address>: <bytes>"
      1154:   3c 1f     cmp $0x1f,%al           line is checked against the file, each "<address> <name>:"
  ```                                           line against the symbol table

<ref> is a path as registered in artifacts.md (relative to the folder that holds the run folder, or
absolute), or <archive>!<member>. <base> is `file` (an offset into the file), `image` (an address as
loaded: from the ELF program headers, the PE image base, or the load base artifacts.md records for a raw
image), or `object`: `<section>+<offset>` in a citation, `object <section>` in an excerpt header (an ELF
relocatable object, or a section of any ELF or PE file).

Also checked: every row of artifacts.md (the file exists and has that SHA-256; one row per artifact);
every cited file outside the run folder has a row there; each KILL in candidates.md has a notes.md. A
finding, a reply whose outcome is KILLED or REACHABILITY_DOUBT, and the notes of a KILLed candidate hold
at least one checked line, and every address (0x and four or more hex digits, or a decompiler name such
as FUN_0801a4c2), object offset (.text+0x1c), file:line and 64-hex hash in their text appears in their
blocks (the load base and memory map of a cited artifact's row count as quoted). Elsewhere an uncited
reference is a warning, as is a path in backticks that names no cited, registered, extracted or existing
file. Addresses are written 0x and hex.

Exit status: 0 every check holds; 1 a check fails; 2 the run folder or a named file cannot be read.
Reads only and writes nothing. Prints no line of an artifact's text, never a byte that a `secret`
citation in any file of the run covers (they are compared by hash and shown as **), and at most 8 bytes
of what is actually there when a `bytes` or excerpt check fails. A malformed or hostile artifact fails
the checks it cannot read; it never crashes the checker. Standard library only; Python 3.9 and newer.
"""

import argparse
import difflib
import hashlib
import json
import mmap
import os
import re
import shlex
import struct
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

RUN_DIR = ".binary-vuln-research"
SKILL_ROOT = Path(__file__).resolve().parent.parent
MAX_IN_MEMORY = 512 * 1024 * 1024     # an archive member or a text file read whole
MAX_TABLE = 64 * 1024 * 1024          # a string or symbol table
SHOW_BYTES = 8                        # bytes of a mismatch shown, never more
SHORT_QUOTE = 8                       # a partial line quote shorter than this identifies nothing
BASES = ("file", "image", "object")
EM_ARM = 40
EM_X86_64 = 62
STT_FUNC = 2
RUNTIME_HINT = ("; a runtime address (from a debugger, log or crash) is not an image address: cite it as "
                "`runtime`, or subtract the load bias")


class CheckError(Exception):
    """A citation that does not hold, or cannot be checked; the message says why."""


class Unchecked(CheckError):
    """A line this checker cannot verify and does not fail on its own: reported as a warning."""


def attempt(fn, *args):
    """Run one check. A malformed or hostile artifact can make a parser or decompressor raise anything
    (struct.error, zlib.error, EOFError, ...): that fails the check, it never passes it."""
    try:
        return fn(*args)
    except CheckError:
        raise
    except Exception as exc:
        raise CheckError("cannot read what this cites (%s: %s)" % (exc.__class__.__name__, exc))


# --------------------------------------------------------------------------- bytes of an artifact

class Blob:
    """The bytes of an artifact or of an archive member, read on demand."""

    def __init__(self, label, path=None, data=None):
        self.label, self.path, self.data = label, path, data
        self.size = len(data) if data is not None else path.stat().st_size
        self._sha = None

    def read(self, offset, n):
        if offset < 0 or n < 0 or offset + n > self.size:
            raise CheckError("file 0x%x+%d is outside %s (%d bytes)" % (offset, n, self.label, self.size))
        if self.data is not None:
            return self.data[offset:offset + n]
        with open(str(self.path), "rb") as fh:
            fh.seek(offset)
            return fh.read(n)

    def whole(self):
        if self.size > MAX_IN_MEMORY:
            raise CheckError("%s is too large to read whole (%d bytes)" % (self.label, self.size))
        return self.read(0, self.size)

    def sha256(self):
        if self._sha is None:
            h = hashlib.sha256()
            if self.data is not None:
                h.update(self.data)
            else:
                with open(str(self.path), "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
            self._sha = h.hexdigest()
        return self._sha

    def find(self, needle, limit=3):
        """File offsets where needle occurs (at most limit), for a hint after a mismatch."""
        hits = []
        if len(needle) < 2 or self.size == 0:
            return hits

        def scan(hay):
            pos = hay.find(needle)
            while pos != -1 and len(hits) < limit:
                hits.append(pos)
                pos = hay.find(needle, pos + 1)
        if self.data is not None:
            scan(self.data)
        else:
            with open(str(self.path), "rb") as fh:
                with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    scan(mm)
        return hits


def split_ref(ref):
    if "!" in ref:
        path, member = ref.split("!", 1)
        return path, member
    return ref, None


def clean_parts(rel, what, absolute_ok):
    text = rel.replace("\\", "/")
    p = PurePosixPath(text)
    if not text or ".." in p.parts or (p.is_absolute() and not absolute_ok) or re.match(r"^[A-Za-z]:", text):
        raise CheckError("%s %r must be a normalised path, with no `..` segment%s"
                         % (what, rel, "" if absolute_ok else ", relative"))
    return p


def norm_member(name):
    name = name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def only(found, archive, member):
    """The one member of that name; two or more are ambiguous (extraction keeps the last, a reader the first)."""
    if len(found) > 1:
        raise CheckError("%s has %d members named %s: which one is meant is ambiguous" % (archive, len(found), member))
    return found[0] if found else None


def ar_member(path, member):
    if path.stat().st_size > MAX_IN_MEMORY:
        raise CheckError("archive %s is too large to read (%d bytes)" % (path.name, path.stat().st_size))
    data = path.read_bytes()
    pos, longnames, found = 8, b"", []
    while pos + 60 <= len(data):
        header = data[pos:pos + 60]
        raw_name = header[0:16].decode("ascii", "replace").rstrip()
        try:
            size = int(header[48:58].decode("ascii").strip())
        except ValueError:
            size = -1
        if size < 0:
            raise CheckError("archive %s has a malformed member header at offset %d" % (path.name, pos))
        start = pos + 60
        body = data[start:start + size]
        if len(body) < size:
            raise CheckError("archive %s is truncated at offset %d" % (path.name, pos))
        name = None
        if raw_name == "//":
            longnames = body
        elif raw_name in ("/", "/SYM64/", "__.SYMDEF", "__.SYMDEF SORTED"):
            pass
        elif raw_name.startswith("#1/") and raw_name[3:].isdigit():         # BSD long name
            n = int(raw_name[3:])
            name, body = body[:n].rstrip(b"\0").decode("utf-8", "replace"), body[n:]
        elif raw_name.startswith("/") and raw_name[1:].isdigit():          # GNU long name
            off = int(raw_name[1:])
            end = longnames.find(b"/\n", off)
            name = longnames[off:end if end != -1 else len(longnames)].decode("utf-8", "replace")
        else:
            name = raw_name[:-1] if raw_name.endswith("/") else raw_name
        if name is not None and norm_member(name) == member:
            found.append(body)
        pos = start + size + (size & 1)
    return only(found, path.name, member)


def zip_member(path, member):
    with zipfile.ZipFile(str(path)) as z:
        info = only([i for i in z.infolist() if norm_member(i.filename) == member and not i.is_dir()],
                    path.name, member)
        if info is None:
            return None
        if info.file_size > MAX_IN_MEMORY:
            raise CheckError("member %s is too large to read" % member)
        return z.read(info)


def tar_member(path, member):
    with tarfile.open(str(path)) as t:
        m = only([m for m in t.getmembers() if norm_member(m.name) == member and m.isfile()], path.name, member)
        if m is None:
            return None
        if m.size > MAX_IN_MEMORY:
            raise CheckError("member %s is too large to read" % member)
        return t.extractfile(m).read()


# --------------------------------------------------------------------------- file formats

def signed(off):
    return "" if not off else ("+0x%x" % off if off > 0 else "-0x%x" % -off)


def cstr(table, offset):
    if offset >= len(table):
        return ""
    end = table.find(b"\0", offset)
    return table[offset:end if end != -1 else len(table)].decode("utf-8", "replace")


def split_name(name):
    """'parse+0x1c' -> ('parse', 0x1c), and objdump's 'parse-0x10' before a symbol -> ('parse', -0x10); a
    version suffix (memcpy@GLIBC_2.14, f@@Base) is dropped, @plt is kept."""
    off = 0
    m = re.match(r"^(.*?)([+-])(0x[0-9a-fA-F]{1,16}|[0-9]{1,18})$", name)
    if m:
        name, off = m.group(1), int(m.group(3), 0) * (-1 if m.group(2) == "-" else 1)
    if "@" in name and not name.endswith("@plt"):
        name = name.split("@", 1)[0]
    return name, off


class Elf:
    kind = "ELF"

    def __init__(self, blob):
        self.blob = blob
        ident = blob.read(0, 16)
        if ident[4] not in (1, 2) or ident[5] not in (1, 2):
            raise CheckError("%s: not a valid ELF header (class %d, data %d)" % (blob.label, ident[4], ident[5]))
        self.bits = 32 if ident[4] == 1 else 64
        e = self.end = "<" if ident[5] == 1 else ">"
        if self.bits == 32:
            (self.type, self.machine, _v, _entry, phoff, shoff, _fl, _eh, phentsize, phnum, shentsize, shnum,
             shstrndx) = struct.unpack(e + "HHIIIIIHHHHHH", blob.read(16, 36))
            ph_min, sh_min = 32, 40
        else:
            (self.type, self.machine, _v, _entry, phoff, shoff, _fl, _eh, phentsize, phnum, shentsize, shnum,
             shstrndx) = struct.unpack(e + "HHIQQQIHHHHHH", blob.read(16, 48))
            ph_min, sh_min = 56, 64
        self.segments, self.sections = [], []
        if phoff and phnum:
            if phentsize < ph_min:
                raise CheckError("%s: implausible ELF program header size %d" % (blob.label, phentsize))
            for i in range(phnum):
                raw = blob.read(phoff + i * phentsize, ph_min)
                if self.bits == 32:
                    p_type, p_off, p_vaddr, _pa, p_filesz, p_memsz, _f, _al = struct.unpack(e + "IIIIIIII", raw)
                else:
                    p_type, _f, p_off, p_vaddr, _pa, p_filesz, p_memsz, _al = struct.unpack(e + "IIQQQQQQ", raw)
                self.segments.append((p_type, p_off, p_vaddr, p_filesz, p_memsz))
        if shoff:
            if shentsize < sh_min:
                raise CheckError("%s: implausible ELF section header size %d" % (blob.label, shentsize))
            first = self._section(shoff, sh_min)
            if shnum == 0:
                shnum = first["size"]
            if shstrndx == 0xFFFF:
                shstrndx = first["link"]
            if shnum * shentsize > blob.size:
                raise CheckError("%s: ELF section table runs past the end of the file" % blob.label)
            self.sections = [self._section(shoff + i * shentsize, sh_min) for i in range(shnum)]
            names = b""
            if 0 < shstrndx < len(self.sections):
                s = self.sections[shstrndx]
                if s["size"] <= MAX_TABLE:
                    names = blob.read(s["offset"], s["size"])
            for s in self.sections:
                s["name"] = cstr(names, s["name_off"])
        self._symbols = None

    def _section(self, at, size):
        raw = self.blob.read(at, size)
        if self.bits == 32:
            name, stype, _fl, addr, off, sz, link, _info, _al, entsize = struct.unpack(self.end + "IIIIIIIIII", raw)
        else:
            name, stype, _fl, addr, off, sz, link, _info, _al, entsize = struct.unpack(self.end + "IIQQQQIIQQ", raw)
        return {"name_off": name, "type": stype, "addr": addr, "offset": off, "size": sz, "link": link,
                "entsize": entsize, "name": ""}

    def loads(self):
        return [s for s in self.segments if s[0] == 1]

    def image_offset(self, addr, n):
        loads = self.loads()
        if not loads:
            raise CheckError("%s is an ELF file with no loadable segment (a relocatable object): cite base "
                             "`object` (<section>+<offset>) or `file`" % self.blob.label)
        holding = [(off, vaddr, filesz) for _t, off, vaddr, filesz, memsz in loads
                   if vaddr <= addr < vaddr + max(memsz, filesz)]
        for off, vaddr, filesz in holding:      # segments may overlap: any that maps file bytes for the range
            if addr - vaddr + n <= filesz:
                return off + addr - vaddr
        if holding:
            raise CheckError("image 0x%x is in the zero-filled part of a segment (.bss): the file holds no bytes "
                             "there" % addr)
        spans = ", ".join("0x%x-0x%x" % (v, v + max(m, f)) for _t, _o, v, f, m in loads[:6])
        raise CheckError("image 0x%x is in no loadable segment of %s (they span %s)%s"
                         % (addr, self.blob.label, spans, RUNTIME_HINT))

    def file_to_image(self, off):
        for _t, s_off, vaddr, filesz, _m in self.loads():
            if s_off <= off < s_off + filesz:
                return vaddr + (off - s_off)
        return None

    def section_index(self, name):
        hits = [i for i, s in enumerate(self.sections) if s["name"] == name]
        if not hits:
            known = ", ".join(s["name"] for s in self.sections if s["name"])[:200]
            raise CheckError("%s has no section %s (it has: %s)" % (self.blob.label, name, known))
        if len(hits) > 1:
            raise CheckError("%s has %d sections named %s: cite base `file`" % (self.blob.label, len(hits), name))
        return hits[0]

    def object_offset(self, section, off, n):
        s = self.sections[self.section_index(section)]
        if s["type"] == 8:
            raise CheckError("section %s of %s holds no bytes in the file (NOBITS)" % (section, self.blob.label))
        if off + n > s["size"]:
            raise CheckError("%s+0x%x+%d is outside the section (0x%x bytes)" % (section, off, n, s["size"]))
        return s["offset"] + off

    def symbols(self):
        if self._symbols is not None:
            return self._symbols
        syms, e = [], self.end
        ent_min = 16 if self.bits == 32 else 24
        for s in self.sections:
            if s["type"] not in (2, 11) or not (0 <= s["link"] < len(self.sections)):
                continue
            entsize = s["entsize"] or ent_min
            strtab = self.sections[s["link"]]
            if entsize < ent_min or s["size"] > MAX_TABLE or strtab["size"] > MAX_TABLE:
                continue
            strings = self.blob.read(strtab["offset"], strtab["size"])
            count = s["size"] // entsize
            table = self.blob.read(s["offset"], count * entsize)
            for i in range(count):
                raw = table[i * entsize:i * entsize + ent_min]
                if self.bits == 32:
                    name, value, size, info, _o, shndx = struct.unpack(e + "IIIBBH", raw)
                else:
                    name, info, _o, shndx, value, size = struct.unpack(e + "IBBHQQ", raw)
                stype = info & 0xF
                if not name or stype in (3, 4) or shndx == 0:     # section, file and undefined symbols
                    continue
                thumb = self.machine == EM_ARM and stype == STT_FUNC and value & 1
                syms.append((cstr(strings, name), value & ~1 if thumb else value, size, shndx, bool(thumb)))
        self._symbols = syms
        return syms

    def relocations(self):
        """{GOT slot address: symbol name} from the dynamic relocation sections."""
        if getattr(self, "_relocs", None) is not None:
            return self._relocs
        out, e = {}, self.end
        for s in self.sections:
            if s["type"] not in (4, 9) or s["size"] > MAX_TABLE or not (0 < s["link"] < len(self.sections)):
                continue
            rela = s["type"] == 4
            ent = (24 if rela else 16) if self.bits == 64 else (12 if rela else 8)
            symtab = self.sections[s["link"]]
            if not (0 < symtab["link"] < len(self.sections)) or symtab["size"] > MAX_TABLE:
                continue
            strtab = self.sections[symtab["link"]]
            if strtab["size"] > MAX_TABLE:
                continue
            strings = self.blob.read(strtab["offset"], strtab["size"])
            table = self.blob.read(s["offset"], (s["size"] // ent) * ent)
            sym_ent = 24 if self.bits == 64 else 16
            for i in range(0, len(table), ent):
                if self.bits == 64:
                    r_offset, r_info = struct.unpack(e + "QQ", table[i:i + 16])
                    index = r_info >> 32
                    addend = struct.unpack(e + "q", table[i + 16:i + 24])[0] if rela else 0
                else:
                    r_offset, r_info = struct.unpack(e + "II", table[i:i + 8])
                    index = r_info >> 8
                    addend = struct.unpack(e + "i", table[i + 8:i + 12])[0] if rela else 0
                if not index and rela:           # IRELATIVE (an ifunc): objdump names it *ABS*+<addend>
                    out.setdefault(r_offset, "*ABS*%s" % signed(addend) if addend else "*ABS*")
                    continue
                if not index or (index + 1) * sym_ent > symtab["size"]:
                    continue
                raw = self.blob.read(symtab["offset"] + index * sym_ent, sym_ent)
                name_off = struct.unpack(e + "I", raw[:4])[0]
                out.setdefault(r_offset, cstr(strings, name_off))
        self._relocs = out
        return out

    def plt_target(self, stub):
        """The function an x86-64 PLT stub jumps to: decode its `jmp *slot(%rip)` and name the relocation of
        that GOT slot, as objdump does when it names stubs `<name>@plt`."""
        if self.machine != EM_X86_64:
            raise CheckError("PLT stub names are mapped only for x86-64 here: cite the call's bytes, and the "
                             "imported function by its relocation")
        plt = [s for s in self.sections if s["name"].startswith(".plt") and s["addr"] <= stub < s["addr"] + s["size"]]
        if not plt:
            raise CheckError("image 0x%x is in no .plt section of %s" % (stub, self.blob.label))
        if (stub - plt[0]["addr"]) % 8:
            raise CheckError("image 0x%x is not at the start of a PLT entry of %s" % (stub, plt[0]["name"]))
        code = self.blob.read(self.image_offset(stub, 16), 16)
        # the stub's own jump, at a fixed place: first, or after endbr64, or after endbr64 and bnd
        at = next((i for i, lead in ((0, b""), (4, b"\xf3\x0f\x1e\xfa"), (5, b"\xf3\x0f\x1e\xfa\xf2"))
                   if code[:i] == lead and code[i:i + 2] == b"\xff\x25"), None)
        if at is None:
            raise CheckError("image 0x%x is not the start of a PLT stub that jumps through a GOT slot" % stub)
        slot = stub + at + 6 + struct.unpack("<i", code[at + 2:at + 6])[0]
        target = self.relocations().get(slot)
        if target is None:
            raise CheckError("the stub at 0x%x jumps through GOT slot 0x%x, which no relocation names" % (stub, slot))
        return target

    def section_label(self, name, plus, addr, base, section):
        """objdump labels code with no symbol by its section (`<.plt>:`, `<.text>:` in a stripped file)."""
        hits = [s for s in self.sections if s["name"] == name]
        if len(hits) != 1:
            return None
        start = hits[0]["addr"] if base == "image" else 0
        if base == "object" and section != name:
            raise CheckError("the label names section %s, the excerpt section %s" % (name, section))
        if start + plus == addr:
            if not 0 <= plus < max(hits[0]["size"], 1):
                raise CheckError("%s%s is outside section %s (0x%x bytes)" % (name, signed(plus), name, hits[0]["size"]))
            return "the start of section %s%s" % (name, signed(plus))
        raise CheckError("section %s starts at 0x%x, so %s%s is not 0x%x" % (name, start, name, signed(plus), addr))

    def within(self, addr, base, section):
        """A symbol plus an offset still names a place in the file: a loaded segment, or its section."""
        if base == "object":
            size = self.sections[self.section_index(section)]["size"]
            if not 0 <= addr <= size:
                raise CheckError("%s+0x%x is outside section %s (0x%x bytes)" % (section, addr, section, size))
        elif not any(v <= addr <= v + max(m, f) for _t, _o, v, f, m in self.loads()):
            raise CheckError("image 0x%x is in no loadable segment of %s%s" % (addr, self.blob.label, RUNTIME_HINT))

    def check_symbol(self, label, addr, base, section):
        name, plus = split_name(label)
        if base not in ("image", "object"):
            raise CheckError("a symbol is cited with base `image` or `object`, not `file`")
        if name.endswith("@plt"):
            if base != "image":
                raise CheckError("a PLT stub is cited with base `image`")
            target = self.plt_target(addr - plus)
            if target == name[:-4]:
                return "the stub at 0x%x jumps to %s" % (addr - plus, target)
            raise CheckError("the stub at 0x%x jumps to %s, not %s" % (addr - plus, target, name[:-4]))
        if name.startswith("."):
            found = self.section_label(name, plus, addr, base, section)
            if found:
                return found
        syms = self.symbols()
        if not syms:
            raise CheckError("%s has no symbol table (stripped): cite the instruction bytes instead" % self.blob.label)
        if base == "object":
            idx = self.section_index(section)
            origin = self.sections[idx]["addr"]
            pool = [(n, v - origin, sz, th) for n, v, sz, ndx, th in syms if ndx == idx]
        else:
            if not self.loads():
                raise CheckError("%s is a relocatable object: cite its symbols with base `object`" % self.blob.label)
            pool = [(n, v, sz, th) for n, v, sz, ndx, th in syms]
        named = [(v, th) for n, v, sz, th in pool if n == name]
        starts = sorted({v for v, th in named})
        # a Thumb function's address may be quoted with bit 0 set, as code pointers carry it
        if any(v + plus == addr or (th and v + plus == addr & ~1) for v, th in named):
            self.within(addr, base, section)
            return "%s%s is at that address" % (name, signed(plus))
        below = sorted(((v, n) for n, v, sz, th in pool if v <= addr), reverse=True)
        here = ""
        if below:
            v, n = below[0]
            here = "; 0x%x is %s%s" % (addr, n, signed(addr - v))
        if starts:
            raise CheckError("%s is at %s, so %s%s is not 0x%x%s"
                             % (name, ", ".join("0x%x" % v for v in starts[:3]), name, signed(plus), addr, here))
        hint = ("; objdump -C prints demangled names and the symbol table holds mangled ones: paste objdump's "
                "output without -C" if "::" in name or "(" in name else "")
        raise CheckError("%s has no symbol %s%s%s" % (self.blob.label, name, here, hint))


class Pe:
    kind = "PE"

    def __init__(self, blob, lfanew):
        self.blob = blob
        _m, nsec, _t, _p, _n, optsize, _c = struct.unpack("<HHIIIHH", blob.read(lfanew + 4, 20))
        opt = lfanew + 24
        magic = struct.unpack("<H", blob.read(opt, 2))[0]
        if magic == 0x10B:
            self.image_base = struct.unpack("<I", blob.read(opt + 28, 4))[0]
        elif magic == 0x20B:
            self.image_base = struct.unpack("<Q", blob.read(opt + 24, 8))[0]
        else:
            raise CheckError("%s: unknown PE optional header (magic 0x%x)" % (blob.label, magic))
        self.headers = struct.unpack("<I", blob.read(opt + 60, 4))[0]
        if nsec > 96:
            raise CheckError("%s: implausible PE section count %d" % (blob.label, nsec))
        self.sections = []
        for i in range(nsec):
            raw = blob.read(opt + optsize + 40 * i, 40)
            vsize, vaddr, rawsize, rawptr = struct.unpack("<IIII", raw[8:24])
            self.sections.append({"name": raw[:8].rstrip(b"\0").decode("ascii", "replace"), "vaddr": vaddr,
                                  "vsize": vsize, "rawsize": rawsize, "rawptr": rawptr})

    def image_offset(self, addr, n):
        if addr < self.image_base:
            raise CheckError("0x%x is below the image base 0x%x of %s: an `image` address is image base + RVA"
                             % (addr, self.image_base, self.blob.label))
        rva = addr - self.image_base
        if rva + n <= self.headers:
            return rva
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"], 1):
                rel = rva - s["vaddr"]
                if rel + n > s["rawsize"]:
                    raise CheckError("image 0x%x is in the uninitialised part of section %s" % (addr, s["name"]))
                return s["rawptr"] + rel
        raise CheckError("image 0x%x (RVA 0x%x) is in no section of %s%s"
                         % (addr, rva, self.blob.label, RUNTIME_HINT))

    def file_to_image(self, off):
        if off < self.headers:
            return self.image_base + off
        for s in self.sections:
            if s["rawptr"] <= off < s["rawptr"] + s["rawsize"]:
                return self.image_base + s["vaddr"] + (off - s["rawptr"])
        return None

    def object_offset(self, section, off, n):
        hits = [s for s in self.sections if s["name"] == section]
        if len(hits) != 1:
            raise CheckError("%s has %d sections named %s" % (self.blob.label, len(hits), section))
        if off + n > hits[0]["rawsize"]:
            raise CheckError("%s+0x%x+%d is outside the section's bytes in the file" % (section, off, n))
        return hits[0]["rawptr"] + off

    def check_symbol(self, label, addr, base, section):
        name, plus = split_name(label)
        hits = [s for s in self.sections if s["name"] == name]
        if len(hits) == 1 and base in ("image", "object"):     # objdump's `<.text>:` with no symbol
            start = self.image_base + hits[0]["vaddr"] if base == "image" else 0
            if start + plus == addr and (base == "image" or section == name):
                return "the start of section %s%s" % (name, signed(plus))
            raise CheckError("section %s starts at 0x%x, so %s%s is not 0x%x" % (name, start, name, signed(plus), addr))
        raise Unchecked("symbols of a PE file are not read, so a PE symbol is not checked: cite the instruction bytes")


class Raw:
    kind = "raw"

    def __init__(self, blob, load_base):
        self.blob, self.load_base = blob, load_base

    def image_offset(self, addr, n):
        if self.load_base is None:
            raise CheckError("%s is a raw image and artifacts.md records no load base for it: record it "
                             "(Phase 0) or cite base `file`" % self.blob.label)
        if addr < self.load_base:
            raise CheckError("image 0x%x is below the load base 0x%x of %s" % (addr, self.load_base, self.blob.label))
        return addr - self.load_base

    def file_to_image(self, off):
        return None if self.load_base is None else self.load_base + off

    def object_offset(self, section, off, n):
        raise CheckError("%s is not an ELF or PE file and has no sections: cite base `image` or `file`"
                         % self.blob.label)

    def check_symbol(self, label, addr, base, section):
        name, plus = split_name(label)
        if name == ".data" and base in ("image", "file"):     # `objdump -b binary` names the whole file .data
            start = 0 if base == "file" else self.load_base
            if start is None:
                raise CheckError("%s is a raw image and artifacts.md records no load base for it" % self.blob.label)
            if start + plus == addr:
                return "the start of the raw image%s" % signed(plus)
            raise CheckError("the raw image starts at 0x%x, so .data%s is not 0x%x" % (start, signed(plus), addr))
        raise CheckError("%s has no symbol table (not ELF): cite the instruction bytes instead" % self.blob.label)


# --------------------------------------------------------------------------- the workspace

def first_hex(cell):
    m = re.search(r"0[xX][0-9a-fA-F]{1,16}", evidence_free(cell))
    return int(m.group(0), 16) if m else None


def table_cells(line):
    """The cells of a Markdown table row, with or without its outer pipes; None for any other line."""
    text = line.strip()
    return [c.strip() for c in text.strip("|").split("|")] if "|" in text else None


def evidence_free(cell):
    """A Load base or Memory map cell without its evidence: parenthesised text is evidence."""
    return re.sub(r"\([^)]*\)", " ", cell or "")


def is_separator(cells):
    return cells is not None and all(c and set(c) <= set("-: ") for c in cells)


def parse_register(path):
    """artifacts.md as ({ref: {"sha", "base", "line"}}, [(ref, line) of a second row for a ref]), from every
    table with a Path and a SHA-256 column. A table's header is the row above its |---| row; every later
    table row, across blank lines, belongs to it until the next header. None when the file does not exist."""
    if not path.is_file():
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    rows, duplicates, header = {}, [], None
    for n, line in enumerate(lines, 1):
        cells = table_cells(line)
        if cells is None or is_separator(cells):
            continue
        if n < len(lines) and is_separator(table_cells(lines[n])):
            header = [c.lower() for c in cells]
            continue
        if header is None:
            continue
        pi = next((i for i, h in enumerate(header) if h.startswith("path")), None)
        si = next((i for i, h in enumerate(header) if h.startswith("sha-256") or h.startswith("sha256")), None)
        bi = next((i for i, h in enumerate(header) if h.startswith("load base")), None)
        mi = next((i for i, h in enumerate(header) if h.startswith("memory map")), None)
        if pi is None or si is None or pi >= len(cells):
            continue
        ref = cells[pi].strip("`").strip()
        if ref in rows:
            duplicates.append((ref, n))
        elif ref:
            base = first_hex(cells[bi]) if bi is not None and bi < len(cells) else None
            layout = evidence_free(cells[mi]) if mi is not None and mi < len(cells) else ""
            ranges = [(int(a, 16), int(b, 16)) for a, b in
                      re.findall(r"0[xX]([0-9a-fA-F]{1,16})\s*(?:-|\.\.|to)\s*0[xX]([0-9a-fA-F]{1,16})", layout)]
            rows[ref] = {"sha": cells[si].strip("`").strip() if si < len(cells) else "", "base": base, "line": n,
                         "ranges": ranges,
                         "addresses": ({base} if base is not None else set()) | {x for r in ranges for x in r}}
    return rows, duplicates


class Workspace:
    def __init__(self, run_folder):
        self.run = run_folder
        self.root = run_folder.parent
        parsed = parse_register(run_folder / "artifacts.md")
        self.register, self.duplicates = parsed if parsed is not None else (None, [])
        self._blobs, self._formats, self.secrets, self.secret_values = {}, {}, {}, []
        self.rows = {}                       # one row per file, however its path is spelled
        for ref, row in sorted((self.register or {}).items(), key=lambda kv: kv[1]["line"]):
            if self.canon(ref) in self.rows:
                self.duplicates.append((ref, row["line"]))
            else:
                self.rows[self.canon(ref)] = row

    def canon(self, ref):
        """(the real path, the member as an archive lists it) of a ref: one file, however spelled."""
        path, member = split_ref(ref)
        try:
            real = os.path.realpath(str(self.resolve(path)))
        except Exception:
            real = path
        try:
            member = "/".join(clean_parts(member, "member", absolute_ok=False).parts) if member else None
        except CheckError:
            pass
        return real, member

    def resolve(self, rel):
        p = clean_parts(rel, "path", absolute_ok=True)
        return Path(str(p)) if p.is_absolute() else self.root.joinpath(*p.parts)

    def blob(self, ref):
        if ref not in self._blobs:
            self._blobs[ref] = attempt(self._open, ref)
        return self._blobs[ref]

    def _open(self, ref):
        path, member = split_ref(ref)
        full = self.resolve(path)
        if not full.is_file():
            raise CheckError("%s does not exist" % path)
        return Blob(path, path=full) if member is None else Blob(ref, data=self._member(path, full, member))

    def _member(self, path, full, member):
        parts = clean_parts(member, "member", absolute_ok=False).parts
        member = "/".join(parts)
        with open(str(full), "rb") as fh:
            head = fh.read(8)
        data, kind = None, None
        try:
            if head == b"!<arch>\n":
                data, kind = ar_member(full, member), "an ar archive"
            elif zipfile.is_zipfile(str(full)):
                data, kind = zip_member(full, member), "a zip archive"
            elif tarfile.is_tarfile(str(full)):
                data, kind = tar_member(full, member), "a tar archive"
        except Exception as exc:                  # a damaged archive: its extraction may still be there
            kind = "an archive it cannot read (%s)" % (exc if isinstance(exc, CheckError) else exc.__class__.__name__)
        if data is not None:
            return data
        sha12 = Blob(path, path=full).sha256()[:12]
        root = self.run.joinpath("work", "extract", sha12)
        extracted = root.joinpath(*parts)
        if extracted.is_file():
            try:
                extracted.resolve().relative_to(root.resolve())
                root.resolve().relative_to(self.run.joinpath("work", "extract").resolve())
            except ValueError:
                raise CheckError("work/extract/%s/%s is a link that leads out of the extraction" % (sha12, member))
            if extracted.stat().st_size > MAX_IN_MEMORY:
                raise CheckError("member %s is too large to read" % member)
            return extracted.read_bytes()
        found = "%s with no member %s" % (kind, member) if kind else "not an ar, zip or tar archive"
        raise CheckError("%s is %s, and work/extract/%s/%s does not exist" % (path, found, sha12, member))

    def fmt(self, ref):
        if ref not in self._formats:
            self._formats[ref] = attempt(self._detect, ref)
        return self._formats[ref]

    def _detect(self, ref):
        blob = self.blob(ref)
        head = blob.read(0, min(64, blob.size))
        fmt = None
        if head[:4] == b"\x7fELF" and blob.size >= 52:
            fmt = Elf(blob)
        elif head[:2] == b"MZ" and blob.size >= 0x40:
            lfanew = struct.unpack("<I", blob.read(0x3C, 4))[0]
            if lfanew + 24 <= blob.size and blob.read(lfanew, 4) == b"PE\0\0":
                fmt = Pe(blob, lfanew)
        if fmt is None:
            row = self.row(ref)
            fmt = Raw(blob, row["base"] if row else None)
        return fmt

    def offset(self, ref, base, addr, section, n):
        if base == "file":
            self.blob(ref).read(addr, n)
            return addr
        if base == "image":
            return self.fmt(ref).image_offset(addr, n)
        return self.fmt(ref).object_offset(section, addr, n)

    def add_secret(self, ref, base, addr, section, n):
        """Record a `secret` citation's range, and its bytes: the same bytes are masked wherever they are
        shown, through any spelling of the file, its archive or its extraction."""
        try:
            blob = self.blob(ref)
            off = self.offset(ref, base, addr, section, 1)
            n = max(0, min(n, blob.size - off))
            self.secrets.setdefault(self.canon(ref), []).append((off, off + n))
            if n:
                self.secret_values.append(blob.read(off, n))
        except Exception:                  # a secret that cannot be located fails its own check
            pass

    def show(self, ref, off, data):
        """At most SHOW_BYTES of what is there; every byte of a declared secret is shown as **."""
        window = data[:SHOW_BYTES]
        hidden = set()
        try:
            for a, b in self.secrets.get(self.canon(ref), []):
                hidden.update(i for i in range(len(window)) if a <= off + i < b)
            blob = self.blob(ref)
            for value in self.secret_values:
                lo = max(0, off - len(value) + 1)
                hay = blob.read(lo, min(blob.size, off + len(window) + len(value) - 1) - lo)
                at = hay.find(value)
                while at != -1:
                    hidden.update(i for i in range(len(window)) if lo + at <= off + i < lo + at + len(value))
                    at = hay.find(value, at + 1)
        except Exception:
            hidden = set(range(len(window)))     # unsure: show nothing
        shown = ["**" if i in hidden else "%02x" % c for i, c in enumerate(window)]
        return " ".join(shown) + (" ..." if len(data) > SHOW_BYTES else "")

    def registered(self, ref):
        if self.row(ref) is not None:
            return True
        try:                                 # the run's own text files (a brief, a log) are not artifacts
            path = split_ref(ref)[0]
            Path(os.path.realpath(str(self.resolve(path)))).relative_to(os.path.realpath(str(self.run)))
            with open(str(self.resolve(path)), "rb") as fh:
                head = fh.read(8192)
            return not split_ref(ref)[1] and b"\0" not in head
        except Exception:                    # outside the run folder, unreadable, or a link loop
            return False

    def row(self, ref):
        if self.register is None:
            return None
        return self.rows.get(self.canon(ref)) or self.rows.get(self.canon(split_ref(ref)[0]))

    def killed(self):
        """IDs whose verdict in candidates.md is a KILL: their evidence is quoted in their notes.md."""
        path, out, header = self.run / "candidates.md", set(), None
        if not path.is_file():
            return out
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        for n, line in enumerate(lines, 1):
            cells = table_cells(line)
            if cells is None or is_separator(cells):
                continue
            if n < len(lines) and is_separator(table_cells(lines[n])):
                header = [c.lower() for c in cells]
                continue
            vi = next((i for i, h in enumerate(header or []) if h.startswith("verdict")), None)
            ii = next((i for i, h in enumerate(header or []) if h.strip("* ") == "id"), 0)
            if vi is not None and vi < len(cells) and re.match(r"^\W*KILL(ED)?\b", cells[vi], re.I):
                ident = re.search(r"BVR-[0-9]+", cells[ii] if ii < len(cells) else "")
                if ident:
                    out.add(ident.group(0))
        return out


# --------------------------------------------------------------------------- citations

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
HEX_NUMBER = r"0[xX][0-9a-fA-F]{1,16}"
NUMBER = re.compile(r"^(%s|0|[1-9][0-9]{0,17})$" % HEX_NUMBER)
ADDRESS = re.compile(r"^(%s|0)$" % HEX_NUMBER)
LINE_CITATION = re.compile(r"^line\s+(?P<path>\S(?:.*?\S)?):(?P<n>[0-9]{1,9})\s+=(?:\s(?P<text>.*))?$")
WORDS = {"le16": (2, "little"), "le32": (4, "little"), "be16": (2, "big"), "be32": (4, "big")}


class Claim:
    """What one citation line or excerpt line vouches for, so the text around it may quote it."""

    def __init__(self):
        self.refs, self.addresses, self.file_lines, self.hashes = [], set(), set(), set()
        self.objects = set()                 # (section, offset) of every object-base address

    def note(self, section, addr):
        self.addresses.add(addr)
        if section is not None:
            self.objects.add((section, addr))

    def update(self, other):
        self.refs += other.refs
        self.addresses |= other.addresses
        self.file_lines |= other.file_lines
        self.hashes |= other.hashes
        self.objects |= other.objects


def number(tok):
    if not NUMBER.match(tok):
        raise CheckError("%r is not a number: 0x<hex>, or decimal with no leading zero" % tok)
    return int(tok, 16) if tok[:2] in ("0x", "0X") else int(tok)


def hex_address(tok):
    if not ADDRESS.match(tok):
        raise CheckError("%r is not an address: write it as 0x<hex> (objdump's 0000000000401136 is 0x401136)" % tok)
    return int(tok, 16) if tok != "0" else 0


def address(tok, base):
    if base == "object":
        m = re.match(r"^([^+\s]+)(?:\+(\S+))?$", tok)
        if not m:
            raise CheckError("an `object` address is <section>+<offset>, not %r" % tok)
        return m.group(1), hex_address(m.group(2)) if m.group(2) else 0
    if base not in BASES:
        raise CheckError("base %r is not one of file, image, object" % base)
    return None, hex_address(tok)


def parse_bytes(spec, suffix):
    tokens = spec.replace(":", " ").split()
    if not tokens:
        raise CheckError("no bytes after '='")
    if suffix is None:
        joined = "".join(tokens)
        if len(joined) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", joined):
            raise CheckError("bytes are hex digits in pairs, in file order (or add /le32, /le16, /be32, /be16)")
        return bytes.fromhex(joined)
    width, order = WORDS[suffix]
    out = b""
    for t in tokens:
        if not re.fullmatch(r"[0-9a-fA-F]+", t) or len(t) % (2 * width):
            raise CheckError("%r is not a run of %d-hex-digit words" % (t, 2 * width))
        for i in range(0, len(t), 2 * width):
            out += int(t[i:i + 2 * width], 16).to_bytes(width, order)
    return out


def normalise(text):
    return re.sub(r"\s+", " ", text).strip()


def where_else(ws, ref, needle):
    """Where the expected bytes do occur, as a hint: offsets only."""
    try:
        hits = ws.blob(ref).find(needle)
    except (OSError, ValueError, CheckError):
        return ""
    if not hits:
        return "; those bytes occur nowhere in %s" % ws.blob(ref).label
    try:
        fmt = ws.fmt(ref)
    except CheckError:
        fmt = None
    out = []
    for off in hits:
        img = fmt.file_to_image(off) if fmt is not None else None
        out.append("file 0x%x%s" % (off, " (image 0x%x)" % img if img is not None else ""))
    return "; those bytes are at %s%s" % (", ".join(out), " and more" if len(hits) == 3 else "")


def check_bytes(ws, ref, base, addr, section, spec):
    m = re.search(r"/(le16|le32|be16|be32)$", spec.strip())
    suffix = m.group(1) if m else None
    body = spec.strip()[:m.start()] if m else spec
    want = parse_bytes(body, suffix)
    off = ws.offset(ref, base, addr, section, len(want))
    have = ws.blob(ref).read(off, len(want))
    if have == want:
        return "%d byte(s) match at file 0x%x" % (len(want), off)
    hint = ""
    for alt in (None, "le32", "le16", "be32", "be16"):
        if alt == suffix:
            continue
        try:
            if parse_bytes(body, alt) == have:
                hint = ("; they match read as %s: %s" % (alt, "add /%s" % alt) if alt
                        else "; they match in file order: drop the /%s" % suffix)
                break
        except CheckError:
            continue
    raise CheckError("the file holds %s at file 0x%x%s" % (ws.show(ref, off, have), off,
                                                           hint or where_else(ws, ref, want)))


def check_line(ws, ref, n, text):
    lines = ws.blob(ref).whole().decode("utf-8", "replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    want = normalise(text or "")
    if not want:
        raise CheckError("nothing is quoted after '='")
    if n < 1 or n > len(lines):
        raise CheckError("%s has %d line(s); line %d does not exist" % (ref, len(lines), n))
    have = normalise(lines[n - 1])
    if want == have:
        return "matches line %d" % n
    if want in have:
        if len(want) < SHORT_QUOTE:
            raise CheckError("a quote of %d character(s) identifies nothing: quote at least %d, or the whole line"
                             % (len(want), SHORT_QUOTE))
        return "matches part of line %d" % n
    elsewhere = [i for i, l in enumerate(lines, 1) if want in normalise(l)][:5]
    if elsewhere:
        raise CheckError("line %d does not hold the quote; line %s does" % (n, ", ".join(map(str, elsewhere))))
    best = max(range(len(lines)), key=lambda i: difflib.SequenceMatcher(None, want, normalise(lines[i])).ratio())
    raise CheckError("the quote is nowhere in %s (the closest line is %d; the file's text is not shown)"
                     % (ref, best + 1))


def check_runtime(ws, addr, log):
    full = ws.run.joinpath(*clean_parts(log, "log file", absolute_ok=False).parts)
    if not full.is_file():
        raise CheckError("%s does not exist in the run folder" % log)
    blob = Blob(log, path=full)
    text = blob.whole().decode("utf-8", "replace")
    # 0x-prefixed, or eight or more hex digits bare (a UART "PC: 0801a4c2"): a short bare number is
    # as likely decimal
    for m in re.finditer(r"(?<![0-9A-Za-z_])(?:0[xX]([0-9a-fA-F]+)|([0-9a-fA-F]{8,}))(?![0-9A-Za-z_])", text):
        if int(m.group(1) or m.group(2), 16) == addr:
            return "0x%x appears in %s" % (addr, log)
    raise CheckError("0x%x does not appear in %s" % (addr, log))


def check_region(ws, addr, ref):
    """A memory-mapped address (a peripheral register, RAM) that the image holds no bytes for: it must lie
    in a range of the Memory map recorded for that artifact in artifacts.md."""
    row = ws.row(ref)
    ranges = row["ranges"] if row else []
    if not any(lo <= addr <= hi for lo, hi in ranges):
        raise CheckError("0x%x is in no range of the Memory map artifacts.md records for %s%s" % (
            addr, ref, " (%s)" % ", ".join("0x%x-0x%x" % r for r in ranges[:6]) if ranges else ""))
    try:
        off = ws.fmt(ref).image_offset(addr, 1)
        ws.blob(ref).read(off, 1)
    except CheckError:
        return "0x%x lies in a recorded memory-map range, outside the image's bytes" % addr
    raise CheckError("the image holds bytes at 0x%x (file 0x%x): cite them with `bytes`" % (addr, off))


def check_citation(ws, text):
    """One line of a citations block: (kind, Claim, message, status)."""
    claim = Claim()
    m = LINE_CITATION.match(text)
    if m:
        path, n = m.group("path"), int(m.group("n"))
        claim.refs.append(path)
        claim.file_lines.add((path, n))
        return "line", claim, lambda: check_line(ws, path, n, m.group("text"))
    try:
        toks = shlex.split(text)
    except ValueError as exc:
        raise CheckError("cannot read this citation: %s" % exc)
    kind = toks[0] if toks else ""
    if kind == "sha256":
        if len(toks) != 3 or not HEX64.match(toks[2]):
            raise CheckError("expected: sha256 <ref> <64 hex digits>")
        claim.refs.append(toks[1])
        claim.hashes.add(toks[2].lower())

        def run():
            have = ws.blob(toks[1]).sha256()
            if have != toks[2].lower():
                path, member = split_ref(toks[1])
                if member and ws.blob(path).sha256() == toks[2].lower():
                    raise CheckError("that is the SHA-256 of the archive %s: cite it as `sha256 %s <hash>`; the "
                                     "member's own is %s" % (path, path, have))
                raise CheckError("the SHA-256 of %s is %s" % (toks[1], have))
            return "SHA-256 matches"
        return kind, claim, run
    if kind == "bytes":
        if len(toks) < 6 or toks[2] != "@" or toks[5] != "=":
            raise CheckError("expected: bytes <ref> @ <address> <base> = <hex>")
        claim.refs.append(toks[1])
        section, addr = address(toks[3], toks[4])
        claim.note(section, addr)
        return kind, claim, lambda: check_bytes(ws, toks[1], toks[4], addr, section, " ".join(toks[6:]))
    if kind == "symbol":
        if len(toks) != 6 or toks[3] != "@":
            raise CheckError("expected: symbol <ref> <name>[+<offset>|-<offset>] @ <address> <base>")
        claim.refs.append(toks[1])
        section, addr = address(toks[4], toks[5])
        claim.note(section, addr)
        return kind, claim, lambda: ws.fmt(toks[1]).check_symbol(toks[2], addr, toks[5], section)
    if kind == "secret":
        if len(toks) != 9 or toks[2] != "@" or toks[5] != "len" or toks[7] != "sha256" or not HEX64.match(toks[8]):
            raise CheckError("expected: secret <ref> @ <address> <base> len <n> sha256 <64 hex digits>")
        claim.refs.append(toks[1])
        section, addr = address(toks[3], toks[4])
        claim.note(section, addr)
        claim.hashes.add(toks[8].lower())
        n = number(toks[6])

        def run():
            off = ws.offset(toks[1], toks[4], addr, section, n)
            if hashlib.sha256(ws.blob(toks[1]).read(off, n)).hexdigest() != toks[8].lower():
                raise CheckError("the SHA-256 of the %d byte(s) at file 0x%x differs (the bytes are not shown)"
                                 % (n, off))
            return "hash of %d byte(s) at file 0x%x matches" % (n, off)
        return kind, claim, run
    if kind == "runtime":
        if len(toks) != 3:
            raise CheckError("expected: runtime <address> <log file, relative to the run folder>")
        addr = hex_address(toks[1])
        claim.addresses.add(addr)
        return kind, claim, lambda: check_runtime(ws, addr, toks[2])
    if kind == "region":
        if len(toks) < 4:
            raise CheckError("expected: region <address> <ref> <the region's name>")
        addr = hex_address(toks[1])
        claim.addresses.add(addr)
        claim.refs.append(toks[2])
        return kind, claim, lambda: check_region(ws, addr, toks[2])
    if kind == "value":
        if len(toks) < 3:
            raise CheckError("expected: value <number> <why it is not an address>")
        claim.addresses.add(number(toks[1]))           # only the number: the reason text vouches for nothing
        return kind, claim, None
    if kind == "line":
        raise CheckError("expected: line <path>:<n> = <quoted text>")
    raise CheckError("unknown citation %r: use sha256, bytes, symbol, secret, line, runtime, region or value" % kind)


EXCERPT_LINE = re.compile(r"^\s*(?:0x)?(?P<addr>[0-9a-fA-F]+):\s+"
                          r"(?P<bytes>[0-9a-fA-F]{2,8}(?: [0-9a-fA-F]{2,8})*)(?:\t|\s{2,}|\s*$)")
EXCERPT_LABEL = re.compile(r"^\s*(?:0x)?(?P<addr>[0-9a-fA-F]+)\s+<(?P<name>.+)>:\s*$")
# a line that starts with an address, after any marker (=>, *, >), in any tool's form: checked or failed
# a line that starts with an address column in any tool's form, after any marker (=>, *, >): checked or
# failed, never skipped. Source lines of objdump -S and -l (`bad:`, `1:`, `D:/src/a.c:7`) are not this.
ADDRESS_START = re.compile(r"^\W*(?:0[xX])?[0-9a-fA-F]+:[ \t]"
                           r"|^\W*(?:0[xX])?[0-9a-fA-F]{4,}\s+<[^>]*>"
                           r"|^\W*0[xX][0-9a-fA-F]{4,}\s+[0-9a-fA-F]{2}")
OBJDUMP_HEADER = re.compile(r"^\S.*:\s+file format \S|^In archive \S")
RELOCATION = re.compile(r"^\s*[0-9a-fA-F]+:\s+R_[A-Z0-9_]+")       # objdump -r: annotation, no bytes


def excerpt_bytes(tokens):
    """The byte strings an objdump line can stand for: pairs are bytes in file order; 4- and 8-digit
    tokens are words, printed as values, so both byte orders are tried (ARM BE8 code is little-endian
    in a big-endian file)."""
    if all(len(t) == 2 for t in tokens):
        return [bytes.fromhex("".join(tokens))]
    if any(len(t) not in (2, 4, 8) for t in tokens):
        return []
    return [b"".join(int(t, 16).to_bytes(len(t) // 2, order) for t in tokens) for order in ("little", "big")]


def check_excerpt(ws, header, body, start):
    """(line number, text, Claim, outcome) for each checkable line of an excerpt block."""
    try:
        toks = shlex.split(header)
    except ValueError as exc:
        yield start, header, Claim(), CheckError("cannot read the excerpt header: %s" % exc)
        return
    if len(toks) < 3 or toks[2] not in BASES or len(toks) != (4 if toks[2] == "object" else 3):
        yield start, header, Claim(), CheckError("expected: excerpt <ref> image | file | object <section>")
        return
    ref, base = toks[1], toks[2]
    section = toks[3] if base == "object" else None
    head = Claim()
    head.refs.append(ref)
    try:
        fmt = ws.fmt(ref)
    except CheckError as exc:
        yield start, header, head, exc
        return
    yield start, header, head, None
    read = 0
    for i, line in enumerate(body, start + 1):
        label, m = EXCERPT_LABEL.match(line), EXCERPT_LINE.match(line)
        if RELOCATION.match(line) or OBJDUMP_HEADER.match(line) or not (label or m or ADDRESS_START.match(line)):
            continue
        read += 1
        claim = Claim()
        try:
            outcome = attempt(excerpt_line, ws, fmt, ref, base, section, label, m, claim)
        except CheckError as exc:
            outcome = exc
        yield i, line.strip(), claim, outcome
    if not read:
        yield start, header, Claim(), CheckError("no line of this excerpt is in objdump's form ('<address>: <hex bytes>' "
                                                 "or '<address> <name>:'), so nothing in it is checked")


def excerpt_line(ws, fmt, ref, base, section, label, m, claim):
    if label:
        addr = int(label.group("addr"), 16)
        found = fmt.check_symbol(label.group("name"), addr, base, section)
        claim.note(section, addr)
        return found
    if not m:
        raise CheckError("an address line this checker cannot read: an excerpt is `objdump -d` (or -D) output "
                         "with the raw bytes shown, '<address>: <hex bytes>' then a tab or two spaces, without "
                         "--no-show-raw-insn, --visualize-jumps or --prefix-addresses, and with no marker")
    addr = int(m.group("addr"), 16)
    claim.note(section, addr)
    options = excerpt_bytes(m.group("bytes").split())
    if not options:
        raise CheckError("bytes are pairs, or 4- or 8-digit words")
    off = ws.offset(ref, base, addr, section, len(options[0]))
    have = ws.blob(ref).read(off, len(options[0]))
    if have not in options:
        raise CheckError("the file holds %s at file 0x%x%s" % (ws.show(ref, off, have), off,
                                                               where_else(ws, ref, options[0])))
    return "%d byte(s) match at file 0x%x" % (len(have), off)


# --------------------------------------------------------------------------- documents

FENCE = re.compile(r"^\s*(`{3,}|~{3,})\s*(.*)$")
ADDRESS_TOKEN = re.compile(r"(?<![0-9A-Za-z_])0[xX]([0-9a-fA-F]{4,})(?![0-9A-Za-z_])(?!\s*-?\s*bytes?\b)")
# a decompiler's auto-name carries an address, also inside a longer name (PTR_FUN_..., thunk_FUN_...)
DECOMPILER_NAME = re.compile(r"(?<![0-9A-Za-z])(?:FUN|LAB|DAT|PTR|SUB|sub|loc|locret|off|unk|byte|word|dword|"
                             r"qword|xmmword|ymmword|zmmword|tbyte|oword|flt|dbl|stru|asc|jpt|def|j_sub)_(?:0[xX])?"
                             r"([0-9a-fA-F]{4,})(?![0-9A-Za-z_])")
SOURCE_EXT = ("c|h|cc|cpp|cxx|c\\+\\+|hpp|hh|hxx|inl|ipp|tcc|tpp|cu|cuh|inc|def|s|S|sx|asm|ld|lds|x|dts|dtsi|y|l|"
              "py|pyx|js|ts|go|rs|java|kt|swift|m|mm|cs|php|rb|pl|lua|sh|mk|cmake|txt|md|json|xml|yml|yaml|ini|"
              "conf|cfg|html|htm|sql|map|lst|log|v|sv|vh|vhd|vhdl")
FILE_LINE_TOKEN = re.compile(r"(?<![\w./!-])((?:[\w.+-]+[/!])*(?:Makefile|GNUmakefile|Kconfig|[\w+-][\w.+-]*\.(?:"
                             + SOURCE_EXT + r"))):([0-9]{1,9})(?![\w])")
OBJECT_TOKEN = re.compile(r"(?<![\w.])(\.[A-Za-z_][\w.]*)\+0[xX]([0-9a-fA-F]+)(?![0-9A-Za-z_])")
HASH_TOKEN = re.compile(r"(?<![0-9A-Za-z])([0-9a-fA-F]{64})(?![0-9A-Za-z])")
CODE_PATH = re.compile(r"`(/?(?:[\w.+-]+/)+[\w.+-]+)`")


def blocks(lines):
    """[(word, info, line number of the fence, body)] and the prose lines [(number, text)]."""
    found, prose, i = [], [], 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            prose.append((i + 1, lines[i]))
            i += 1
            continue
        fence, info, start = m.group(1), m.group(2).strip(), i
        i += 1
        body = []
        while i < len(lines) and not lines[i].strip().startswith(fence):
            body.append(lines[i])
            i += 1
        i += 1
        found.append((info.split()[0] if info else "", info, start + 1, body))
    return found, prose


def path_cited(path, claim, ws):
    try:
        return path_found(path, claim, ws)
    except (OSError, ValueError):           # a name the file system refuses names no file
        return False


def path_found(path, claim, ws):
    if path.startswith("/") and ".." not in path and Path(path).exists():
        return True
    path = path.lstrip("/")
    names = set()
    for ref in claim.refs + list(ws.register or {}):
        whole, member = split_ref(ref)
        names.update(n for n in (whole, member) if n)
    if any(n == path or n.endswith("/" + path) for n in names):
        return True
    for root in (ws.root, ws.run, SKILL_ROOT):
        if root.joinpath(*PurePosixPath(path).parts).exists():
            return True
    return any(p.exists() for p in ws.run.glob("work/extract/*/" + path)) if ".." not in path else False


def needs_blocks(label, text, killed=()):
    """A finding always quotes something; so does a refuter reply that kills or doubts (its `fact` and
    `paths`), and the notes of a candidate KILLed in candidates.md (its kill evidence). In these the text
    may quote nothing the blocks lack; elsewhere that is a warning."""
    if label.startswith("findings/"):
        return "a finding"
    if label.endswith("/reply.md"):
        outcomes = re.findall(r"(?im)^\W*(?:\d+[.)]\s*)?(?:refuter\W+)?outcome\b(.*)$", text)
        if any(re.search(r"(?i)\bkill|reachability[\W_]*doubt", o) for o in outcomes) or not outcomes:
            return "a KILLED or REACHABILITY_DOUBT reply"
    m = re.match(r"^candidates/(BVR-[0-9]+)/notes\.md$", label)
    if m and m.group(1) in killed:
        return "the notes of a KILLed candidate"
    return None


PSEUDO_C = ("c", "cpp", "c++", "pseudo-c", "pseudoc", "pseudocode", "decompiler", "decompiled")
REPLY_FIELD = re.compile(r"^\W*(outcome|fact|paths|searched|suspicious|would_have_changed_my_mind)\W*:", re.I)
STRICT_FIELDS = ("fact", "paths")


def check_document(ws, path, label, killed=()):
    results, claim, notes = [], Claim(), 0
    text = path.read_text(encoding="utf-8", errors="replace")
    found, prose = blocks(text.splitlines())

    def add(line, kind, item, status, message):
        results.append({"file": label, "line": line, "kind": kind, "item": item, "status": status,
                        "message": message})

    def record(line, kind, item, outcome):
        if isinstance(outcome, CheckError):
            add(line, kind, item, "fail", str(outcome))
        else:
            add(line, kind, item, "ok", outcome)

    checked = 0                              # lines checked, not blocks: an empty block quotes nothing
    for word, info, start, body in found:
        if word == "citations":
            for i, raw in enumerate(body, start + 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                kind = line.split()[0]
                try:
                    kind, one, run = attempt(check_citation, ws, line)
                except CheckError as exc:
                    checked += 1
                    record(i, kind, line, exc)
                    continue
                if run is not None:          # a `value` line is declared, not checked: it does not count
                    checked += 1
                claim.update(one)
                if run is None:
                    notes += 1
                    add(i, kind, line, "note", "declared, not checked")
                    continue
                try:
                    record(i, kind, line, attempt(run))
                except CheckError as exc:
                    record(i, kind, line, exc)
        elif word == "excerpt":
            for i, item, one, outcome in check_excerpt(ws, info, body, start):
                claim.update(one)
                if isinstance(outcome, Unchecked):
                    add(i, "excerpt", item, "warn", str(outcome))
                elif outcome is not None:
                    checked += 1
                    record(i, "excerpt", item, outcome)
    required = needs_blocks(label, text, killed)
    if required and not checked:
        add(1, "document", label, "fail", "%s with no citation or excerpt line that is checked (a `value` line "
            "is not): nothing it quotes is checked" % required)
    for ref in sorted(set(claim.refs)):
        if ws.register is not None and not ws.registered(ref):
            add(0, "register", ref, "fail", "cited, but artifacts.md has no row for %s" % split_ref(ref)[0])

    for ref in set(claim.refs):              # the register's load base and memory map are its own claims
        row = ws.row(ref)
        if row:
            claim.addresses |= row["addresses"]
    # In a strict file the text inside other fences (but pseudo-C, a lead) and the comment lines of
    # citations blocks are read too: a reply's fields are often fenced, as refuter.md shows them.
    lines = list(prose)
    if required:
        for word, info, start, body in found:
            if word == "citations":
                lines += [(i, l) for i, l in enumerate(body, start + 1) if l.strip().startswith("#")]
            elif word != "excerpt" and word.lower() not in PSEUDO_C:
                lines += list(enumerate(body, start + 1))
        lines.sort()
    reply, field = label.endswith("/reply.md"), None
    for n, line in lines:
        f = REPLY_FIELD.match(line)
        if f:
            field = f.group(1).lower()
        # in a reply only `fact` and `paths` carry the kill (and text before any field); other fields warn
        uncited = "fail" if required and (not reply or field in (None,) + STRICT_FIELDS) else "warn"
        for m in list(ADDRESS_TOKEN.finditer(line)) + list(DECOMPILER_NAME.finditer(line)):
            before = line[:m.start()]
            if m.re is ADDRESS_TOKEN and (re.search(r"(?<![0-9A-Za-z_])[A-Za-z_][\w.@]*[+-]$", before)
                                          or before.endswith("--stop-address=")):
                continue                     # name+0x1c, and the end objdump never prints, are not addresses
            if int(m.group(1), 16) not in claim.addresses:
                add(n, "uncited", m.group(0), uncited, "address in the text but in no citation or excerpt line here "
                    "(cite a branch target or pointer with a `bytes` or `symbol` line at it; a constant with `value`)")
        for m in OBJECT_TOKEN.finditer(line):
            if (m.group(1), int(m.group(2), 16)) not in claim.objects:
                add(n, "uncited", m.group(0), uncited, "object offset in the text but in no citation or excerpt line "
                    "of that section here")
        for m in FILE_LINE_TOKEN.finditer(line):
            quoted, num = m.group(1), int(m.group(2))
            if not any(num == cn and (cp == quoted or cp.endswith("/" + quoted) or cp.endswith("!" + quoted))
                       for cp, cn in claim.file_lines):
                add(n, "uncited", m.group(0), uncited, "file:line in the text but in no `line` citation here")
        for m in HASH_TOKEN.finditer(line):
            if m.group(1).lower() not in claim.hashes:
                add(n, "uncited", m.group(1), uncited, "hash in the text but in no citation here")
        for m in CODE_PATH.finditer(line):
            if not m.group(1).startswith(("http:", "https:")) and not path_cited(m.group(1), claim, ws):
                add(n, "path", m.group(1), "warn", "names no cited, registered, extracted or existing file")
    return results, notes


def check_register(ws):
    if ws.register is None:
        return [{"file": "artifacts.md", "line": 0, "kind": "register", "item": "artifacts.md", "status": "fail",
                 "message": "the run folder has no artifacts.md: every cited file is registered there"}]
    if not ws.register and not ws.duplicates:
        return [{"file": "artifacts.md", "line": 0, "kind": "register", "item": "artifacts.md", "status": "fail",
                 "message": "artifacts.md has no row under a table header with a Path and a SHA-256 column "
                            "(a header is the row above a |---| row)"}]
    results = []
    for ref, line in ws.duplicates:
        results.append({"file": "artifacts.md", "line": line, "kind": "register", "item": ref, "status": "fail",
                        "message": "a second row for %s: one row per artifact" % ref})
    for ref, row in sorted(ws.register.items(), key=lambda kv: kv[1]["line"]):
        result = {"file": "artifacts.md", "line": row["line"], "kind": "register", "item": "%s %s" % (ref, row["sha"]),
                  "status": "ok", "message": "the file exists and its SHA-256 matches"}
        try:
            if not HEX64.match(row["sha"]):
                raise CheckError("the SHA-256 column holds no 64-hex-digit hash")
            have = attempt(ws.blob(ref).sha256)
            path, member = split_ref(ref)
            if member and have != row["sha"].lower() and attempt(ws.blob(path).sha256) == row["sha"].lower():
                result["message"] = "the member exists and its archive's SHA-256 matches"
            elif have != row["sha"].lower():
                raise CheckError("the SHA-256 of %s is %s" % (ref, have))
        except CheckError as exc:
            result.update(status="fail", message=str(exc))
        results.append(result)
    return results


def collect_secrets(ws, paths):
    """Every range a `secret` citation covers, in any file of the run, before anything is shown."""
    for path in paths:
        try:
            found, _ = blocks(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            continue
        for word, info, start, body in found:
            if word != "citations":
                continue
            for raw in body:
                try:
                    toks = shlex.split(raw.strip())
                    if len(toks) >= 7 and toks[0] == "secret" and toks[2] == "@" and toks[5] == "len":
                        section, addr = address(toks[3], toks[4])
                        ws.add_secret(toks[1], toks[4], addr, section, number(toks[6]))
                except Exception:
                    continue


def documents(run, named):
    if named:
        parts = [clean_parts(n, "file", absolute_ok=False).parts for n in named]
        return [(run.joinpath(*p), "/".join(p)) for p in parts]
    out = []
    for pattern in ("findings/*.md", "briefs/*.md", "summary-*.md", "addendum-*.md", "candidates/*/packet.md",
                    "candidates/*/reply.md", "candidates/*/notes.md"):
        out.extend((p, p.relative_to(run).as_posix()) for p in sorted(run.glob(pattern)))
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description="Re-check every citation of a binary-vuln-research run.")
    parser.add_argument("files", nargs="*", help="files to check, relative to the run folder (default: all)")
    parser.add_argument("--run-folder", default=RUN_DIR, help="the run folder (default: ./%s)" % RUN_DIR)
    parser.add_argument("--json", action="store_true", help="print the results as JSON")
    args = parser.parse_args(argv)

    run = Path(args.run_folder).resolve()
    if not run.is_dir():
        print("verify_citations: no run folder at %s" % run, file=sys.stderr)
        return 2
    try:
        docs = documents(run, args.files)
    except CheckError as exc:
        print("verify_citations: %s" % exc, file=sys.stderr)
        return 2
    missing = [label for path, label in docs if not path.is_file()]
    if missing:
        print("verify_citations: not in the run folder: %s" % ", ".join(missing), file=sys.stderr)
        return 2

    ws = Workspace(run)
    collect_secrets(ws, sorted({p for p, _ in documents(run, [])} | {p for p, _ in docs}))
    results, notes = check_register(ws), 0
    killed = ws.killed()
    for ident in sorted(killed):
        if not (run / "candidates" / ident / "notes.md").is_file():
            results.append({"file": "candidates.md", "line": 0, "kind": "kill", "item": ident, "status": "fail",
                            "message": "KILLed in candidates.md, but candidates/%s/notes.md, which quotes the kill's "
                                       "evidence, does not exist" % ident})
    for path, label in docs:
        found, n = check_document(ws, path, label, killed)
        results.extend(found)
        notes += n

    checks = [r for r in results if r["status"] in ("ok", "fail") and r["kind"] not in ("uncited", "path")]
    failed = [r for r in results if r["status"] == "fail"]
    summary = {"files": len(docs), "checks": len(checks), "ok": sum(r["status"] == "ok" for r in checks),
               "failed": len(failed), "uncited": sum(r["kind"] == "uncited" for r in failed),
               "warnings": sum(r["status"] == "warn" for r in results), "declared_values": notes}
    line = ("verify_citations: %(checks)d check(s) in %(files)d file(s) and artifacts.md: %(ok)d ok, "
            "%(failed)d failed (%(uncited)d uncited); %(warnings)d warning(s); %(declared_values)d value(s) "
            "declared, not checked" % summary)
    if args.json:
        print(json.dumps({"summary": summary, "summary_line": line, "results": results}, indent=2))
    else:
        for r in results:
            where = "%s:%d" % (r["file"], r["line"]) if r["line"] else r["file"]
            print("%-4s %s  %s  -- %s" % (r["status"].upper(), where, r["item"][:120], r["message"]))
        print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
