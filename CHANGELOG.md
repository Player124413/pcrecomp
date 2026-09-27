# Changelog

All notable changes to pcrecomp. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- `tools/ne/ne_link.py`: lift a Win16 program made of several NE modules
  into one segment numbering, image and glue, with cross-module imports as
  direct calls (Catz 2 modules, Dogz 4, Oddballz 8). With it:
  `gen_dispatch.py`, `seed_misses.py`, `bpguard.py`, `patch_borland_eh.py`
  (from catz), and multi-module `gen_image.py` / `gen_win16_stubs.py`.
- `runtime/win16/host/`: the Win16-on-Win32 host runtime, upstreamed from
  catz and generalised (per-game `RecompGame`, module table, host thunks,
  GetProcAddress/LoadLibrary by path, RT_NAMETABLE, FindFirst/FindNext,
  AccessResource/_hread, template-font dialog units, and the USER/GDI/KERNEL
  surface Dogz and Oddballz reach).
- `gen_win16_stubs.py --dll-dir`: an unknown purge is read from the
  exporting DLL's own `retf N`.

### Fixed
- `ne_decode`: catz's decoder fixes ported (catch handlers from OFFSET16
  relocations, jump tables in code, block after jmp/ret, recover at forced
  entries without doubling FWAIT x87 ops, a code map from another module
  ignored), plus: segment lookups survive renumbering, and recover() no
  longer decodes across another entry point.
- `ne_lift` imported disasm/lift from `../../tools/tools`, a path that only
  resolved from a checkout named `tools` beside catz.
- `lift16`: a tail jump's real-mode paragraph was masked to 16 bits, breaking
  NE modules past 1 MB (`0x-E8121` in the output).
- `win16`: `SOSLIB03.SOSDIGIDETECTINIT` purge is 6, not 4.

From #4. Found running Gunman Chronicles (MSVC 6 CRT, Quake-lineage software renderer)
fully recompiled; each is generic x86 semantics or code generation. Each fix
has a difftest case against Unicorn: 175/187 match, 12 known divergences,
0 failures.

### Fixed
- `sahf` loads SF ZF AF PF CF from `ah` (it was a comment), and `fprem` reports
  C2 clear: the CRT `fmod` loop `fprem; fnstsw ax; sahf; jp` spun forever.
- `fxam` and `xlatb` lifted; the CRT math functions classify with them.
- `frndint` rounds by the control word (it truncated, so `floor`/`ceil` did).
- `fld`/`fstp` of 80-bit operands convert for real (they pushed 0.0 / dropped
  the value); `fsin`/`fcos`/`fsincos`/`fptan` clear C2.
- Flags survive `ret`: every `ret` publishes the lazy flag state and every call
  reloads it (`RECOMP_FLAGS_OUT/IN`), so a caller's `je` after a helper that
  returns ZF reads the helper's flags. Weak globals in `recomp_types.h`, so no
  project runtime needs a change.
- `inc`/`dec` keep CF; `bt; jae` no longer inverted; memory `bt*` address the
  bit string; `lock`-prefixed forms lift; `fist`/`fistp` round by the control
  word; patched immediates/displacements apply on every read.
- x87 compares report unordered (NaN) as C3=C2=C0; `repe cmps; sbb` reads the
  real CF; PF of narrow results is taken from the low byte.
- `generate.py`: a body can hold code below its entry (a `goto` to the entry
  comes first); `push label; jmp func` lifts as a call returning to `label`;
  a body that runs off its end falls through as a tail call.

### Added
- `Lifter(precise_carry=True)`: `adc`/`sbb` take CF from the `add`/`sub`/`cmp`
  before them instead of the `_cf` variable. Opt-in: Fury3 depends on the old
  behaviour.
- `Lifter(reloc=fn)`: rewrite every absolute displacement and immediate that
  points into a moved block of static data (growing fixed-size tables).
- `RECOMP_LOCAL_REGS` (opt-in): lifted bodies keep the eight registers in
  locals, written back around calls and returns, so the optimiser can hold
  them in host registers. `RECOMP_FLAT_MEMORY` (opt-in): no base added per
  guest access. Together about 2x on Gunman's renderer.
- `lift_function_linear(indirect_targets=...)`: when the caller knows every
  local target of a body's indirect jumps, only those get labels and switch
  cases, so a function with a `switch` optimises (default unchanged).
