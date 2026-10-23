# Shrek 2 (PC, 2004) — hybrid static recompilation

The application body of Shrek 2, lifted from `System/game.exe` (274,432 bytes,
MSVC 7.00, built 2004-04-14) to C, built as a **32-bit Windows executable that
replaces `game.exe` in the shipping install**. The UE2 engine stays real
machine code — this is the hybrid model from [docs/HYBRID.md](../../docs/HYBRID.md),
not an all-or-nothing lift.

```
        original game.exe            this project
        ┌────────────────┐           ┌──────────────────────────────┐
        │ 1,644 functions│  lift →   │ recomp_*.c (14.5 MB of C)    │
        │ CRT startup    │           │ CRT startup, static ctors,   │
        │ native classes │           │ classes — all lifted         │
        └───────┬────────┘           └──────────────┬───────────────┘
                │ imports                           │ native32 bind
                ▼                                   ▼
        ┌───────────────────────────────────────────────────────────┐
        │ Core.dll · Engine.dll · KWGame.dll · Window.dll ·         │  stays
        │ WinDrv.dll · D3DDrv.dll · msvcr70.dll · d3d8 · DDRAW      │  native
        └───────────────────────────────────────────────────────────┘
```

Why the exe and not the engine: `Core.dll` (954 KB) `Engine.dll` (4.98 MB) and
`KWGame.dll` (139 KB) are the shipped UE2 runtime and Shrek 2's native game
classes. They are optimised, heavily inlined, C++-heavy, and they are exactly
the part that already works. `game.exe` is the part that is *this game* — its
WinMain, its launch path, the `Window.dll` UI layer glue, its own native
classes, its CRT startup and static initialisers. That is what is lifted here,
and it is enough for the exe to stop being opaque: every function the engine
calls back into is now C you can read, instrument and change.

## What this binary is (from the import table, not from memory)

`game.exe` is not "the game" — it is the application exe on top of the engine,
and the import table says exactly which part:

| evidence | reading |
|---|---|
| 9 imports from `Engine.dll`: `StaticClass` for `AActor`, `UEngine`, `UGameEngine`, `URenderDevice`, `AActor::GetLevel`, `FStats::UpdateString`/`Clear` + `GStats`/`GEngineStats` | the UE2 application startup (`Launch.cpp`): the four class lookups and the stats hooks are exactly what an app exe uses |
| 175 imports from `Core.dll` — `FArchive`/`FArray`/`FName`/`FFileManager`/`FMalloc` constructors, `appStrchr`, … | the exe does real work with the engine's core objects, not just call `InitEngine` |
| 146 imports from `Window.dll` — `WDialog`, `WButton`, `WWizardPage`, `FDelegate` | the exe carries Shrek 2's own window/UI code (the launcher and settings dialogs) |
| `Direct3DCreate8` (`d3d8`) and `DirectDrawCreate` (`DDRAW`) imported **by the exe** | it enumerates/creates display devices itself — a launcher/video-setup path, not something `Launch.cpp` does |
| 25 `MSVCR70.dll` imports: `_initterm`, `__getmainargs`, `_acmdlm`… | a static-CRT-shaped startup against the DLL CRT, so the guest's `_WinMainCRTStartup` drives static initialisation and then `WinMain` |
| exports: one, `GPackage` (data) | nothing in the engine imports code from the exe by name; the engine reaches the exe only through function pointers |

That last line is the whole reason this hybrid works: the engine never needs to
`GetProcAddress` anything from the exe. Every real → lifted crossing is a
function pointer the exe itself put into engine data (a class constructor, a
`UFunction` body, a vtable slot), which is precisely what `native32`'s callback
trampoline catches.

Two consequences worth knowing before the first run:

* **No SEH in the lifted set.** The exe imports `__CxxFrameHandler` and
  `_except_handler3`, but no instruction in the image references either IAT
  slot (byte-scanned), so no lifted function installs an EH frame. Guest C++
  exceptions therefore never cross the lift; `runtime/native32/eh32.c` is
  linked but unused by this target.
* **`.data` is mostly zero-filled pages.** Its virtual size is 203,212 bytes
  against 40,960 on disk; `recomp_load_image` zeroes the whole span, so the
  exe's uninitialised globals exist exactly where it expects them. That is why
  the mapping must be at `0x10900000` — the code addresses them absolutely.

## What the lift is

| | |
|---|---|
| Target | `System/game.exe`, 274,432 bytes |
| SHA-256 | `4900aa131cf35d4951943f2d6ee831841745af8e5d657ffdcfd7fb012cbaa2ef` |
| Image base / entry | `0x10900000` / `0x1091AACB` (`_WinMainCRTStartup`) |
| Sections | `.text` `0x21000`, `.rdata`, `.data`, `.idata`, `.rsrc` |
| Exports | `GPackage` (a `UPackage*`, data) |
| Imports | 438 from 10 DLLs: `Core.dll` 175, `Window.dll` 146, `KERNEL32` 52, `USER32` 26, `MSVCR70` 25, `Engine.dll` 9, `SHELL32` 2, `comdlg32` 1, `d3d8` 1, `DDRAW` 1 |
| **Functions lifted** | **1,644** |
| Generated C | **14.5 MB** in 5 `recomp_*.c`, plus `recomp_funcs.h`, `recomp_dispatch.c`, `recomp_target.h` |
| Executable bytes catalogued | 87,476 / 135,168 (**64.72 %**) |
| … of the rest | 43,692 bytes are `int3`/`nop` alignment fill, **4,000 bytes are real** (import thunks and bodies reached only through a computed jump) |
| Gate failures | 0 |

The 4 KB that no lifted body covers are listed in
[`analysis/report.md`](analysis/report.md) with their address ranges. They are
mostly `jmp [IAT]` thunks that no instruction in the image references, i.e.
reserved for calls that never happen in this build; they are not silently
assumed to be data.

Function recovery is the recursive-descent path (`disasm32.find_functions`),
seeded with more than the entry point:

* the entry point and every export,
* **218 vtable slots** found structurally (`cpp/vtable_scan.py`) — a method
  reached only through a vtable is called by no `CALL` in the image,
* **35 alternate entry points** from `lift/recover.py` — direct calls that land
  inside an already-listed body,
* plus the disassembler's own data-pointer scan (385 functions reachable only
  from data: static initialiser tables, class registration, vtables).

The first pass yields **1,604** functions; the 35 recovered entry points (and 5
more reached from them) take it to **1,644**, and that second catalog is what
the lift is generated from.

## Building

### Locally (Windows, Visual Studio 2022 + CMake)

```bat
:: 1. install the Python side (Capstone)
python -m pip install -r projects\shrek2\requirements.txt

:: 2. lift the original binary (once; ~20 s)
python projects\shrek2\tools\build_lift.py ^
    --game "C:\Games\Shrek 2\System\game.exe"

:: 3. build the x86 executable
cmake -S projects\shrek2 -B build -G "Visual Studio 17 2022" -A Win32
cmake --build build --config Release --parallel
```

`build\Release\shrek2.exe` is the result. x86 is mandatory: the engine DLLs are
32-bit and `runtime/native32` bridges to them with inline asm; CMake refuses a
64-bit configure rather than failing later.

Quick path: [`build.bat`](build.bat) runs the same three steps with
`SHREK2_GAME` pointing at the install.

Without the game (contributing to `main.c`, or a toolchain check) configure with
`-DSHREK2_SYNTHETIC=ON`: the host is built against [`ci/stub`](ci/stub), a
one-function stand-in catalog, and the resulting exe answers `SHREK2_HELP` and
the missing-install diagnostic exactly like the real one. It is what CI falls
back to when it cannot fetch `game.exe`.

### CI

`.github/workflows/shrek2-windows.yml` runs on every push that touches the
project:

1. **lift** (ubuntu) — fetches the one file the lift is made from
   (`System/game.exe`, 274 KB), runs the driver, **runs it twice and diffs the
   output** (the lift is reproducible), compiles every generated translation
   unit *and* the host for `x86-windows` with clang/mingw, and uploads the lift
   as a 14-day artifact together with `analysis/report.md`.
2. **windows** (windows-latest) — downloads that artifact, builds
   `shrek2.exe` with MSVC (`cmake -A Win32`, default generator: whatever
   Visual Studio the image has), **runs it twice** (`SHREK2_HELP=1` must
   exit 0, an empty game folder must exit 2), and uploads `shrek2.exe` and
   `shrek2-win32.zip`.
3. On a GitHub release, the zip is attached to it.

The game is never committed and never redistributed — the workflow fetches the
binary, and the generated C is a build artifact (the repo's
[`tools/audit_repo.py`](../../tools/audit_repo.py) classifies lifted output as a
derivative of the binary, so no public project here tracks it).

### Running it with your own link

**Actions → Shrek 2 (Windows x86) → Run workflow** has a `game_url` box. Paste
a link to a **zip** holding `System/game.exe` — or to `game.exe` itself — and
run. That is the whole setup; nothing has to be made public and no secret is
required.

| what you paste | what happens |
|---|---|
| `https://huggingface.co/<user>/<repo>/blob/main/Shrek2.zip` | `blob/` is rewritten to `resolve/`; works for model and dataset repos; `HF_TOKEN` is used if the repo is private or gated |
| `https://huggingface.co/datasets/<user>/<repo>/resolve/main/files/game.zip` | used as is |
| `https://drive.google.com/file/d/<id>/view?usp=sharing` | rewritten to the `uc?export=download` request, and the *"file is too large to scan for viruses"* page is followed (its form, with cookies) to the real download. The file must be shared as *anyone with the link* |
| any `https://…/file.zip` | downloaded; `Content-Length` is not trusted, the bytes are |
| any `https://…/game.exe` | used directly |

The archive is **not** unpacked wholesale: `tools/fetch_game.py` reads the zip
index, prefers `*/System/game.exe` over a bare `game.exe` (an install archive
also holds `game.ini`, `game.log`, …), and extracts only that member. A 785 MB
upload therefore costs a 785 MB download and a 274 KB write.

The script prints the size and SHA-256 and compares them with
[`config/game.json`](config/game.json) — if you uploaded a different
release/patch of the game it says so before the driver refuses it. It also runs
`--selftest` (URL rewriting, Google Drive's interstitial, archive ranking) on
every CI run, offline.

To avoid retyping the link on every push, put it in a repository
**variable** `SHREK2_GAME_URL` (Settings → Secrets and variables → Actions →
Variables); the box overrides it when filled.

If the `game_url` box is empty, the workflow falls back to the files repository:
`FILES_TOKEN` secret first, then anonymous. If all of that fails, the lift job
prints exactly what to add and the Windows job builds against
[`ci/stub`](ci/stub) instead — one hand-written function, no game — so the host,
the runtime, CMake and the MSVC path are still verified on every push, and the
uploaded artifact is named `shrek2-win32-host-smoke` rather than
`shrek2-win32`. A build from the real lift is never silently substituted.

Locally the same two steps are:

```bat
python -m pip install -r projects\shrek2\requirements.txt
python projects\shrek2\tools\build_lift.py --game "C:\Games\Shrek 2\System\game.exe"
cmake -S projects\shrek2 -B build -G "Visual Studio 17 2022" -A Win32
cmake --build build --config Release --parallel
```

## Running

Drop `shrek2.exe` into `Shrek 2/System/`, next to the untouched `game.exe`, the
engine DLLs and `msvcr70.dll`, and run **`shrek2.exe` instead of `game.exe`**.
The original files stay where they are — the host maps `game.exe`'s data
sections at `0x10900000` and binds its imports against the shipping DLLs.

Command-line switches are passed to the game unchanged (`-log`, `-windowed`,
`-nosound`, …), because the guest's CRT parses the same command line the
original did.

The host's own knobs are environment variables, so they cannot leak into the
game's `argv`:

| variable | effect |
|---|---|
| `SHREK2_DIR=<path>` | game folder, if not the exe's own |
| `SHREK2_TRACE=1` | log every lifted → real call |
| `SHREK2_TRACE_CALLBACKS=1` | log every real → lifted call |
| `SHREK2_NO_HOLD=1` | do not reserve the image range by relaunching (debugger use) |
| `SHREK2_LOG=1` | write the log to `shrek2.log` |
| `SHREK2_HELP=1` | print the switches and exit |

Exit codes: `0` WinMain returned, `2` incomplete install or wrong image, `3`
the image could not be mapped (or the entry point is not in the catalog), `4`
binding left imports unresolved.

## What is verified, and what is not

Verified here (Linux, no Windows, no GPU):

* the driver runs against the real binary and is **deterministic** (two runs,
  byte-identical C);
* all 1,644 functions lift with **zero errors**; every direct `call` in the
  generated C resolves to a definition in the same catalog (this is a gate in
  the driver, not a hope);
* the whole 14.5 MB of generated C **parses** (gcc, `-fsyntax-only`, against
  `runtime/recomp32/recomp_types.h`); no GCC-only constructs are used, so MSVC
  gets the same source;
* the whole program **links as a 32-bit Windows PE**: host + `native32` +
  `image_loader` + `recomp_trace` + 1,644 lifted functions, cross-built with
  clang/mingw (Zig) — `zig cc -target x86-windows-gnu -mwindows`, 22 MB of
  image, no unresolved symbols. That is a second compiler's opinion, not a
  substitute for the MSVC build below; the two disagreeing is what the CI
  workflow is for;
* the coverage arithmetic above, and the explicit list of uncovered ranges.

Not verified: the game running. That needs Windows, the real install and a GPU,
none of which this environment has. What the first run on Windows will exercise
and where it may stop first:

1. **binding** — `native32_bind` prints `N native, M guest, K shimmed,
   U unresolved`. `U` must be 0; a non-zero count names the missing DLL.
2. **CRT startup** — the lifted `_WinMainCRTStartup` calls `_initterm` in the
   real `msvcr70.dll`, which calls the exe's static initialisers. Those are
   guest addresses in a non-executable `.text`: each one faults into the
   callback trampoline and enters its lifted body. If a static initialiser was
   missed by recovery, the run says so by name (see below).
3. **`appInit` and the engine handshake** — the first lifted → real calls into
   `Core.dll`/`Engine.dll`. `SHREK2_TRACE=1` prints each one.
4. **the first real → lifted callback** — the engine constructing a class or
   calling a virtual that lives in the exe. `SHREK2_TRACE_CALLBACKS=1`.

### Closing the loop when a body is missing

When native code calls a guest address that has no lifted body, the host does
not just die: it names the address, writes it to `System/shrek2_missing.txt`
and dumps the guest registers and the last indirect calls. Feed that file back:

```bat
python projects\shrek2\tools\build_lift.py --game ...\System\game.exe ^
       --seed-file ...\System\shrek2_missing.txt
```

The address is then a seed of the next recovery pass — the same mechanism the
vtable and `recover.py` seeds use. This is the intended workflow for bring-up:
play until something is missing, rebuild, repeat.

For a crash inside a lifted body, the report names the guest function
(`g_cur_func`), the faulting access, all the guest registers and the last 16
indirect calls with their callers — the caller is usually the interesting one
(it built the bad `this` or the bad argument).

## Layout

```
projects/shrek2/
  config/game.json          target identity: size, SHA-256, base, entry, exports
  tools/build_lift.py       the driver: verify → analyse → recover → lift → gate → report
  tools/fetch_game.py       get game.exe from a zip link (HF / Google Drive / any URL)
  src/main.c                the host: native32, image mapping, binding, crash report
  src/game/recomp/gen/      generated C (not committed; built by the driver/CI)
  analysis/                 pe.json, imports.json, functions.json, report.md, manifest.json
  CMakeLists.txt            x86 MSVC build, `lift` custom target
  requirements.txt          capstone
  build.bat                 one-shot local build
```

## Credits and licensing

The lifted code is a derivative work of Shrek 2 (© DreamWorks / Activision,
2004) and is not distributed here — the driver regenerates it locally from your
copy, exactly as the engine DLLs stay your copy. Do not redistribute the game,
the generated C, or a binary built from both.

Tooling: [`pcrecomp`](../../README.md) — `disasm32`, `lift32`,
`cpp/vtable_scan`, `lift/recover`, `runtime/native32`, `runtime/recomp32`.
