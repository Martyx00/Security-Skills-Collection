# Detector patterns (Phase 1A)

Read this file in full before the sweep. Run every pattern on every artifact confirmed at
Gate A, by the method agreed there (read in full, or scanned by query or script), and log
each pattern's query or script and its hit count per artifact in the sweep log of
`run-log.md`.

A hit is a location that matches a pattern's shape, or a suspected defect the boundary
read-through finds (pattern `B`), before any judgement of guards: no verdicts in Phase 1. Every hit becomes a candidate with an ID `BVR-NNNN`, cited as artifact
plus function@offset, or file:line. Findings and the summary cite patterns by number, so
the numbers below are stable: add a new shape as a new number, never renumber.

Pseudo-C is where most hits are first seen, and it gets signedness, widths and inlined
copies wrong. A hit found in pseudo-C is still a hit; the guard or sink a later verdict
rests on is quoted as instructions (SKILL.md, Hard rules).

## Patterns

1. Length or count reused as a copy size or index, unbounded at the destination.
2. Length arithmetic truncated, wrapped or subtracted (`len-HDR`) before the check and used
   untruncated after; a signed compare or a sign-extended field (`MOVSX`, `LDRSB`,
   `LDRSH`) guarding an unsigned size; an allocation size (`n*sz`, `len+HDR`) that wraps.
3. Copy bound re-read after the check from attacker-influenced memory or flash (double
   fetch; verify, then load).
4. Guard after the store, off by one (`<=`, no room for the terminator), or only breaking
   an inner loop.
5. Unclamped count driving a loop.
6. Fatal assert reachable from a short payload.
7. Pointer plus length crossing a trust boundary (core and core, host and device, user and
   kernel, peer and local) unvalidated.
8. Parsing, installing or executing before signature, MIC or authentication is verified;
   an update accepted without a signature or anti-rollback check.
9. Lock bit or debug port (JTAG/SWD, UART console) never set, set late, settable twice, or
   re-enabled by a command.
10. Authentication or certificate validation disabled, stubbed or defaulted off (verify
    none, no-op setters, accept-all callbacks).
11. Secrets stored, logged or sent unprotected, or hard-coded (keys, passphrases, default or
    backdoor accounts); a predictable RNG, seed, IV or nonce; a MAC or password compared in
    non-constant time.
12. State-machine bypass: an out-of-state unauthenticated message, or success honoured
    without the negotiated state.
13. A privileged operation (ioctl, procfs, vendor, debug or manufacturing command) with no
    capability check.
14. Attacker data reaching a format string, a shell or exec (`system`, `popen`, `exec*`,
    `sh -c`) or a file path (a `..` segment, an absolute path, a symlink, an archive member
    name) in a web, CGI, CLI, update or file handler.
15. Lifetime: an object freed on an error, disconnect or timeout path but still reachable
    from a callback, timer or queue, or freed twice; uninitialised stack, heap or padding
    bytes copied to a peer, host or log.
16. A type, opcode or TLV tag selecting a layout or handler without checking that the
    length fits that type.

## B: the boundary read-through

What no pattern shape matches is found by reading. At each boundary, read in full the
trust-deciding functions: the IPC and H2C dispatchers and their callees; frame, EAPOL, WPS,
BLE, USB and other protocol parsers; handshake handlers; fast-connect and credential storage;
web, CGI and CLI handlers; update and bootloader image loaders; the shipped-source feeders.
Follow guards across call edges, objects, trees and binary boundaries (stubs, function
pointers, callbacks, IPC): the guard is often in the caller, the copy in the callee. A
suspected defect found this way is a hit like any other, recorded with pattern `B`.
