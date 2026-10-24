# Android (and any non-Windows, non-x86 host)

Short answer: **the part of this project that is C moves to Android for free;
the part that is a Windows x86 binary does not move at all.** That is not a
detail, it decides which of three routes you are on and what each costs.

| route | what it means | effort | who it is for |
|---|---|---|---|
| **A. Emulation** | Winlator / Box64 + Wine + DXVK, i.e. an x86-Windows container on the phone, running the *original* `game.exe` — or this `shrek2.exe`, which is just another x86 Windows program to that stack | none from us | you want to **play**, on a phone, this week |
| **B. Native ARM64 port** | lift the whole engine, host it on `runtime/win32hle` + SDL2, answer D3D8 with GLES/Vulkan | months; the ladder below | you want a **port**: an ARM64 binary, no Wine, no x86 |
| **C. x86 Android** | the same host as Windows, built for Android x86 with `win32hle` instead of `native32` | weeks | nobody — no shipping phone is x86, and Google Play has required 64-bit for years |

Route A is not a joke answer: a static recompilation does not make a game run on
a phone by itself, and pretending otherwise wastes the effort. Route B is the
interesting one, and the rest of this file is about it.

---

## What already moves (verified in this repo, not hoped for)

| piece | why it survives | evidence |
|---|---|---|
| **The lifted C** | it is plain C: `MEM32(va)`, `esp += 4`, `goto L_x`. Nothing x86-specific is emitted. | the 14.5 MB in `src/game/recomp/gen/` compiles with gcc, clang and MSVC |
| **x87, MMX, SSE** | modelled in software — a global `_st[8]`/`_fp_top`, `_mm[8]`, `xmm_t` copied with `memcpy`. No intrinsics, no inline asm. | `runtime/recomp32/recomp_types.h` (`xmm_ld`/`xmm_st` are `memcpy`) |
| **Memory model on a 64-bit host** | `win32hle` maps the guest's 4 GB at `g_mem_base` and `ADDR(va)` adds it; `HLE_FLAT` only for 32-bit hosts. | `runtime/win32hle/win32hle.h` |
| **The Win32 surface** | `win32hle` answers ~all of it on POSIX/SDL2: windowing, GDI+SDL2_ttf, software DirectDraw, DirectSound mixer, Bink via ffmpeg, COM, storage, registry, Winsock. Proven on Tiberian Sun, Red Alert 2, SimCity 2000. | `runtime/win32hle/README.md`, root `README.md` |
| **No assembly to re-target** | `win32hle` has zero inline asm — that is the whole point of its shim ABI. | `grep asm runtime/win32hle/*.c` → nothing |
| **Endianness** | Android is little-endian on both ARM64 and x86_64, so no byte-swapping layer. | — |

So the CPU half of an Android port is *already written*: it is the lift.

## What blocks it (each one is a work item, not a footnote)

**1. The engine is real x86 machine code.** The hybrid design deliberately
leaves `Core.dll` (954 KB), `Engine.dll` (4.98 MB), `KWGame.dll`, `Window.dll`,
`WinDrv.dll`, `D3DDrv.dll` as the shipped binaries and calls into them through
`native32` on Windows. There is no equivalent of that call on ARM — you cannot
call an x86 DLL from an ARM process. Everything must be lifted. (This is why
`runtime/native32` is MSVC-x86-only and `win32hle` exists at all.)

**2. No D3D8.** Shrek 2 renders through `D3DDrv.dll`, UE2's Direct3D 8 render
device, which loads `d3d8.dll`. `win32hle` implements DirectDraw and
DirectSound and, in its own words, *"DirectX past DirectDraw 2 / DirectSound 1"*
is out of scope. There is no `d3d8.c` anywhere in the tree. On Android that is
the whole renderer: device creation, vertex/index buffers, textures, render
states, `DrawIndexedPrimitive`, and creating **shader 1.1** vertex/pixel
shaders from precompiled bytecode — i.e. a vs_1_1/ps_1_1 → GLSL ES 3 translator
(or a D3D8 → Vulkan path; DXVK/d8vk solves this problem for the Wine route,
which is exactly why route A works and route B is work).

**3. Guest C++ exceptions.** The exe has no EH frames (byte-scanned, see README),
so the current lift links `eh32.c` and never uses it. The engine is the opposite:
UE2's `guard`/`appTry` and its error recovery are everywhere. Lifting it needs
two things that do not exist yet: the driver must wire `lift/eh32.py`'s
`resume_points` into `RECOMP_EH_ENTER` landing pads (it does not today —
`build_lift.py` calls `Lifter.lift_function` directly, so no lifted body carries
a landing pad), and `win32hle` needs the guest-EH runtime that
`native32` has (`eh32.c`, setjmp/longjmp based). `win32hle`'s README lists
"guest SEH / C++ exceptions" as out of scope too.

**4. Audio driver.** `ALAudio.dll` + `DefOpenAL32.dll` (OpenAL 1.1). There is no
OpenAL HLE in the tree. The cheap version: build OpenAL Soft for Android and
answer the `al*`/`alc*` imports by forwarding to it — that is a shim, not a
rewrite.

**5. Speed.** `win32hle` keeps the guest registers in **globals**, not in CPU
registers (`native32` does the same; the register file is memory). On x86 that
costs L1 traffic; on ARM64 with a 32-register file and no global-register
variables it costs more. The mitigations are ordinary (LTO, `-O3`, keeping hot
functions in one TU), but expect the lift to be a *different* mix than the x86
build, and measure before optimising.

## The work, sized

Measured on this lift, from the exe: 87,476 bytes of code → 1,644 functions →
14.5 MB of C. The engine's code is ~6 MB, so:

| | exe (done) | engine (to lift) |
|---|---|---|
| code | 87 KB | ~6 MB (**≈70×**) |
| functions | 1,644 | **~115,000** |
| generated C | 14.5 MB | **~1 GB** (in ~290 files at the current split of 400) |
| lift time | 18 s | ~20–30 min |
| compile | ~20 s/file | hours; needs `/bigobj`, `-O1`, and patience |

That is mechanical — the same driver, more input. The non-mechanical part is the
D3D8 layer, and that is where the months are.

## The ladder (each stage has a yes/no check)

**Stage 0 — prove the model on a 64-bit host, still on Linux x86.**
Lift `game.exe` as today, but host it on `win32hle` instead of `native32`, with
the renderer stubbed. Check: the lifted CRT startup runs, `_initterm` fires the
static initialisers, `appInit` is reached, the log stops at "no render device"
instead of crashing. This validates the 64-bit memory model, the shim ABI and
the missing-EH question **without touching ARM**. Cheap, and everything after it
depends on it.

**Stage 1 — ARM64, headless.** Cross-compile the same host with the Android NDK
for `arm64-v8a`; SDL2 for Android provides the window and input. Check: it boots
to the same place on a device. If it does, the CPU side of the port is done —
the lift does not care what ISA runs it.

**Stage 2 — lift the engine.** `build_lift.py` pointed at `Core.dll`,
`Engine.dll`, `KWGame.dll`, `Window.dll`, `WinDrv.dll`, in that order (each with
its own `--out`), then `D3DDrv.dll` last because it cannot do anything until
`d3d8` exists. Check: the game constructs its engine objects and reaches
`UGameEngine::Init` — the same VA the Windows build reaches, now in ARM64.

**Stage 3 — D3D8.** Start with the subset UE2's RHI actually calls, fill the
rest with logged stubs (the pattern `win32hle` uses everywhere else:
`recomp_host_boot_permissive` binds unresolved imports to a self-naming stub).
Check: a frame is presented — black is fine, wrong is fine, *something* is fine.

**Stage 4 — playable.** Shaders, textures, audio, touch input (UE2 wants a
keyboard and mouse: SDL2 maps touch to a virtual mouse, which is enough to reach
a menu).

## Do not start from Stage 2

The tempting order — "lift the big DLLs first, the renderer will come" — fails
in a way that is hard to attribute: with no D3D8 the engine dies inside device
creation, and every bug above it looks like an engine bug. Stage 0 first, and
its output is a log line, not a picture.

## What it costs, in one line each

* **Route A**: install Winlator, copy the game folder in, pick a D3D wrapper.
  Works with the *original* `game.exe`; this project adds nothing to it.
* **Route B**: weeks for stages 0–2 (mostly waiting for compilers), months for
  stage 3, and the result is a genuinely ARM64-native Shrek 2 with no Wine and
  no x86 anywhere — which is the thing worth wanting.
