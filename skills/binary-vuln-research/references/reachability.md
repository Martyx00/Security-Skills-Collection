# Reachability and kills (Phase 2, and the refuter's standard)

The standard behind every tier and every kill. The detector reads it before tiering; the
refuter reads it before replying. Nothing here depends on who raised a candidate or why.

For each candidate: (a) **present?** A function in a shipped artifact beats an object in a
shipped archive, which beats a reference in a shipped Makefile; a `.map` is one proof, not
the only one; never require building an example. (b) **Reachable?** Record the route; one
is enough: (1) an in-tree caller passes attacker input; (2) a registration (IRQ, callback,
H2C or IPC command ID, ops table, address taken); (3) a protocol entry point a peer, AP,
STA, host or other core can trigger, whether or not the sender's code ships; (4) a
pointer, length or index supplied across a boundary unvalidated. Route 4 from a side the
attacker model controls (user to kernel, untrusted host to device, peer to local) is
tiered like any input. Between cores the model trusts equally it needs an influence path
for T2 (the peer parses external data, is separately updatable, sits on a named attack
surface, or its compromise is in the model), and that path is the T2 precondition. If the peer has none of these four influence paths, each shown absent with its reason, the verdict is `FOLD-hardening`; if any is only unknown, the candidate is T-U. A candidate with no route found is never folded for that reason: it is T3 if exported or registered, T-U if a caller is indicated or an artifact able to call in was not searched, and T4 only by the dead-code standard.

Tiers, from most to least reachable:

- **T1**: default build, reachable from an entry point the attacker model controls.
- **T2**: reachable only under a stated precondition (a non-default setting with an
  enabler, a peer with an influence path, an attacker position beyond the model's
  default), which goes in the headline.
- **T-U**: a caller or registration is indicated (header, IPC ID, import, document) but
  its code is outside the inspected set; the headline names what is missing.
- **T3**: present and exported or registered, no caller anywhere inspected; reachable by
  integrator code following a cited SDK flow or example ("undocumented" if none).
- **T4**: proven unreachable by the dead-code standard.

**Dead-code standard.** T4 needs the function unregistered, unexported and unreferenced in
every artifact that could transfer control into it, each one searched: the symbol, export
and relocation tables (`readelf -r` on `.o`, `.a` and `.ko` members); code
cross-references after full analysis at the established load base and ISA mode; a raw scan
for the address in every encoding the ISA uses (both byte orders, bit 0 set for Thumb,
literal pools, `movw`/`movt`, `adrp`/`add`, `lui`/`addi`, `l32r`); and every registration
table (vectors, IPC and H2C command tables with the host's use of each ID, ops and
callback structures, init arrays). Mask ROM, bootloader, the other cores' images and the
host driver count whether or not they ship or are in scope; if one cannot be obtained or
was not searched, the candidate is T-U, naming it. Every search goes in the coverage
statement.

**Kill list**, each on cited positive evidence:

- **T4** by the dead-code standard.
- **Flaw refuted**: a named guard or caller check, cited at its offset with its compare
  and branch instructions, bounds the value on every attacker-reachable path into the
  sink. A guard on some paths refutes nothing.
- **No enabler** for a non-default configuration in any shipped artifact. An enabler is
  default-on, a runtime setting, a Kconfig option with a user-visible prompt, or a
  documented build flag; a `#if` or a promptless symbol that nothing shipped sets is not.
  With an enabler the candidate is T2, the setting its precondition.
- **Vendor-documented limitation** (cite the document), only if no shipped caller breaks
  the documented contract with attacker-influenced data; if one does, RAISE against that
  caller. Never report a documented limitation as a vulnerability.
- **Externally reported duplicate** in the same version, citing an advisory, CVE or vendor
  bulletin the person supplied or approved fetching. Without a check the summary says
  "external duplicate check: not done" and nothing dies on that ground.

In-round duplicates are `FOLD-dup(<primary ID>)`, never KILL; the primary lists their
entry points.
