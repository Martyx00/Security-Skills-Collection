# Verification (Phase 5): briefs, probe connection, evidence

Read this in full before writing the first brief. Phase 5 runs only on RAISEs the person
picked at Gate B, and every contact with a live target only on a brief the person approved at
Gate C (SKILL.md, STOP rules). The hard rules of SKILL.md apply throughout; nothing here
relaxes them.

## The brief

`briefs/BVR-NNNN-E<k>.md`, written before Gate C, one per experiment, never edited after
approval (an edited brief needs a new approval). It carries:

- the candidate, its tier, and the rung this experiment aims at;
- the target identifier as named at Gate A (device serial, probe serial, MAC, IP or hostname),
  and the build ID of what runs on it, both from the person, never read from the target before
  this brief is approved;
- the exact stimulus: bytes or command, channel, and for radio the frequency and power;
- who else can receive the stimulus, and why no one outside the named targets can (isolated
  network, shielded or cabled RF);
- the maximum number of sends;
- what can change on the target, and "irreversible effects: none" (if confirming the
  candidate needs an irreversible action, there is no brief: the candidate stays at R1);
- every debugger write, and every reset, voltage or clock action beyond the probe's normal
  connect, each named;
- the predicted observable, the falsifiers (what would show the prediction wrong), and the
  expected non-outcomes;
- the stop criterion, and the abort conditions: the target stops responding or reset-loops, a
  lock, unlock or recover prompt appears, a write you did not plan happens;
- how the target is recovered if it stops responding, without writing to its persistent
  storage (if only a write would recover it, the person does that);
- an hour estimate;
- hardware: probe, interface, speed, target voltage, reset strategy, and the checklist below;
- software: build ID, debugger and connection, emulator or VM and its isolation.

Post its path and SHA-256 at Gate C, and record the person's answer with that SHA-256 in
`run-log.md`.

## Probe connection checklist (inside an approved brief)

1. Turn off every automatic erase or unlock before connecting (pyOCD `-O auto_unlock=false`,
   for example). Refuse any unsecure, unlock or recover prompt the tool or probe software shows.
2. Connect without reset where the tool allows (attach, not connect-under-reset), and assume
   the attach may reset the target as well as halt the core until a connect under an approved
   brief has shown otherwise: take PRE captures after the attach, list the possible reset under
   what can change on the target, and remember that a halted radio or co-processor can trip a
   host watchdog.
3. Use hardware breakpoints and watchpoints only. Never a software or flash breakpoint: on many
   probes a breakpoint in flash reprograms the flash sector.
4. If the tool reports the device locked, secured or read-protected, stop and tell the person.
   Never try to lift the protection.
5. Log the tool, its version, the interface, the speed and the reset strategy actually used in
   `run-log.md`.

Untrusted vendor scripts (`.gdbinit`, OpenOCD or J-Link scripts, flash or build scripts) are
never sourced: GDB starts with `-nx -iex 'set auto-load off'`, and you type only the connect
commands you reviewed.

## Rungs R2 to R5

Rungs are cumulative, and R2 to R5 come from one run. R0 and R1 are static (SKILL.md, Phase 5).

- **R2**: a stimulus through an attacker channel observed reaching the sink.
- **R3**: the violation observed. Memory classes: a fault, a watchpoint hit or a corrupted
  value. Logic classes: the forbidden outcome itself (an unauthenticated operation executed, a
  forged credential accepted, a secret disclosed, an out-of-state message honoured).
- **R4**: the attacker's chosen value determines the violation.
- **R5**: memory classes, controlled code execution by the R5 test below; logic classes, the
  end-to-end impact the CVSS vector claims, demonstrated.

Report the rung reached and what each higher rung needs.

## Evidence rules

- A run is one delivery of the stimulus, with its own folder `work/runs/BVR-NNNN-E<k>-<m>/`
  holding the exact input, the delivery evidence, and the PRE and POST captures from the same
  boot. Rungs never combine evidence from two runs, and never splice across a reboot.
- A post-mortem record written by the faulting boot (a core dump, a crash log, preserved fault
  registers) belongs to that run, even though it is read after the reset.
- Proportionate repeats: `n>=3` for timing-, hardware- or watchdog-sensitive results, reported
  as k/n with delivery evidence for every attempt; `n=1` suffices for a deterministic captured
  fault, and the finding says so.
- A discarded run is renamed `<run>_VOID_<reason>` and nothing is quoted from it.

## Labels

Labels travel with every quote and cap the claim:

- `R<n>-emu`: emulator evidence. It never stands for the device.
- `DEBUG-WRITE`: a run that used a debugger write. It supports no rung above R1.
- `[debugger]`: evidence observed with a debugger attached (a halt, a breakpoint, a watchpoint,
  a memory read). Name what the attach changed (halted cores, stopped watchdogs, timing); the
  finding's "What this does not show" says the result was not seen without a debugger, unless a
  run without one also shows it.
- `[rebuilt]`: a build of shipped source made under the Gate A agreement, isolated and with the
  shipped configuration. It counts like emulator evidence and never stands for a binary the
  vendor shipped.
- `[instrumented]`: any modified build (sanitizers, debug options, changed flags or code). It
  counts like emulator evidence.

## The R5 test (memory classes)

R5, controlled code execution, needs all three:

1. **A marker the injected code computes at run time**, for example a per-run nonce
   transformed by an operation only the injected code performs. Search for it, and record each
   command and its zero result in the run folder, in: the payload, any input, every artifact in
   `artifacts.md` (the binary under research included), any dumped image or partition
   (application, bootloader, partition table, NVS, filesystem, OTA slots, ROM where a ROM image
   is obtainable), and RAM before the stimulus. It must occur literally in none of them. A
   victim that echoes or logs the payload therefore cannot fake it.
2. **The marker observed on a channel or in a state the unmodified code cannot produce**: a GPIO
   or UART write the firmware never makes, or register state at a breakpoint outside the
   victim's code.
3. **A negative control** on the same build and setup: the same delivery with only the
   hijacking field made in-bounds, and no marker.

Without a ROM image, write "ROM not searched" next to R5.
