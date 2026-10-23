# From "it builds" to "it plays"

The lift in this project is **built and gated but has never been run**. That is
not a hedge, it is the state of the evidence: the driver, the C, the linker and
the host are verified on Linux; the game needs Windows, the install and a GPU,
and none of those exist in the environment the lift was produced in. This file
is the ladder between those two points — what to run, what each result means,
and what to change when it goes wrong.

It is written to be followed in order. Do not skip to step 5 because step 2
"probably works"; every hybrid bring-up failure so far looked like a later
problem than it was (see `docs/HYBRID.md`).

---

## Step 0 — the machine

* Windows 10/11 x64 (the exe is 32-bit; that is fine and intended).
* The retail install, unmodified: `System/game.exe`, the DLLs, the `.u`
  packages, `Maps/`, `Textures/` …
* Visual Studio 2022 with **Desktop development with C++** and the **x86**
  toolset, plus CMake and Python 3.
* Keep `game.exe` where it is. This build runs *next to* it and reads its data.

## Step 1 — build

```bat
set SHREK2_GAME=C:\Games\Shrek 2\System\game.exe
set SHREK2_TRACE=ON
projects\shrek2\build.bat
```

`SHREK2_TRACE=ON` before `build.bat` is the environmental form of
`-DSHREK2_TRACE=ON`; it compiles the lift with `RECOMP_TRACE`, which costs a
call per lifted function and buys you everything in step 4. Build it in from the
first run — adding it later invalidates your observations.

Result: `projects\shrek2\build\Release\shrek2.exe`. Copy it into
`Shrek 2\System\`.

## Step 2 — does it get control at all?

```bat
cd "C:\Games\Shrek 2\System"
set SHREK2_LOG=1
shrek2.exe -log
```

Read `System\shrek2.log` in this order:

| line | meaning | if wrong |
|---|---|---|
| `[host] log: …` | the host started | never appears: the exe did not load — check it is x86, and that the CRT DLLs are next to it |
| `[host] Shrek 2 recompiled build` + `game dir` | past the relaunch for the image range | the process exits and the log stops before this line: the image-range hold failed (step 3) |
| `lift : 1644 functions, source sha256 …` | it mapped the correct `game.exe` and knows the catalog | a different sha256: wrong copy of the game; a different count: the lift was not rebuilt |
| `[host] calling lifted entry 0x1091AACB` | the lifted `_WinMainCRTStartup` is running | missing: exit 3, the entry VA is not in the catalog |

Exit codes are the summary: **2** install incomplete / wrong image, **3** the
image could not be mapped, **4** imports unresolved (the message lists the
DLLs), **5** no lifted body at the entry.

## Step 3 — the image range (`0x10900000`)

The guest's globals are addressed absolutely, so the original image must be
mapped at `0x10900000`. `native32_hold_image()` reserves that range in a child
process started suspended, before its loader places the first stack, then
execs the real work. **This path has never been exercised on Windows.**

If it does not work, the failure is loud and immediate: `cannot map the image at
0x10900000: the range is in use`, exit 3. In that order:

1. `set SHREK2_NO_HOLD=1` — skip the relaunch and map into whatever is free.
   If it works now, the reservation is the bug, and the fallback below is the
   fix rather than a workaround.
2. If a DLL inside the process sits at `0x10900000`, `SetDllDirectoryA` +
   `LoadLibraryA` ordering is the suspect: the engine DLLs are all based in
   `0x10000000`–`0x10300000`, so the likely occupant is a system DLL loaded by
   the CRT before `WinMain`. Relaunching is exactly what avoids that, which is
   why (1) is a diagnosis, not a fix.
3. Confirm with a debugger: attach, `!address 0x10900000`, see what owns it.

## Step 4 — does the game code run?

Three questions, in this order, each with one knob:

**4a. Did the CRT startup reach the static initialisers?** The lifted
`_WinMainCRTStartup` imports `_initterm` from `msvcr70.dll` and hands it a table
of pointers into guest `.data`. Each of those is a real → lifted callback.

```bat
set SHREK2_TRACE_CALLBACKS=1
shrek2.exe -log
```

You want a stream of `[callback] Windows called guest 0x…` lines. If execution
stops with `no lifted body`, the missing VA is written to `shrek2_missing.txt`:

```bat
python projects\shrek2\tools\build_lift.py ^
    --game "C:\Games\Shrek 2\System\game.exe" ^
    --seed-file "C:\Games\Shrek 2\System\shrek2_missing.txt"
```

then rebuild. That loop is ~20 s per iteration and it is the normal way this
work goes; it is also why coverage is a metric and not a gate (README, "Why not
100 %").

**4b. What ran, in order?** For the first minutes of a run, an unbounded trace
is the cheapest description of "where did it stop":

```bat
set SHREK2_CALLTRACE=%CD%\trace.txt
set SHREK2_TRACE=1
shrek2.exe -log
```

`trace.txt` is one line per lifted entry, thread-tagged (buffered — it is
flushed on a fault, so a crash still leaves the tail). The last line before the
end is the function it died in; look it up in
[`analysis/functions.json`](analysis/functions.json) (`address`, `size`,
`calls_to`) and in the report's "Largest functions".

**4c. Did it reach the subsystem I care about?** `--firsthit` is the narrow
question answered cheaply — "did the render path ever run, and in what order":

```bat
set SHREK2_FIRSTHIT=0x10901000-0x10914000
shrek2.exe -log
```

Bisect the range if the answer is "no": the boundary between "ran" and "never
ran" is the call you are missing.

## Step 5 — the crash report is the map

Any fault inside lifted code prints, via the host's VEH:

```
================ recompiled game crashed ================
  exception   : 0xC0000005 at 0x1091B2C4
  read        : 0x0000002C
  in lifted   : 0x1091B2A0 (sub_1091B2A0)
  EAX=… ECX=… EDX=… EBX=…
  ESP=… EBP=… ESI=… EDI=…
  last indirect calls (newest first):
    0x10914F0B  from 0x1091A2C0
```

Read it as: **`in lifted` is your function**, the faulting access says which
field of which object was bad, `ECX` is almost always the `this` of the failing
call, and the indirect-call list names the engine call that handed it the bad
pointer. Then:

* `SHREK2_WATCH=0x1091B2A0` — registers, arguments and the object at `ecx` on
  every entry to that function;
* `SHREK2_ARGTRACE=0x1091B2A0` — one line per entry with three arguments (use
  this on a dispatcher: it turns into a script trace);
* `SHREK2_POISON=0x109F1234` — report every write to one dword. This is how you
  find *who* set a flag to a wrong value, which is usually the real bug and not
  the one that crashed.

## Step 6 — what is likely to actually be broken

In rough order of probability, from how this kind of lift fails:

1. **Wrong `this` or wrong argument order** at a real → lifted vtable call.
   UE2 calls class constructors through pointers the exe registered at startup;
   if the lift's callback trampoline mis-computes the purge, the object is
   right but every argument after it is shifted. Symptom: a plausible-looking
   object with garbage fields.
2. **x87 state across the boundary.** The exe is MSVC 7.00 code that returns
   floats in `st(0)`; `native32` moves that onto the lifted FPU stack. A wrong
   `_fp_top` shows up as `NaN` in physics or camera code, not as a crash.
3. **Threads.** UE2 starts render/audio threads. Each guest thread needs its own
   guest stack and TIB; `MAX_GTHREADS` is 64. A missing thread shows as the game
   running but never presenting a frame.
4. **The DirectX 8 device path.** The exe imports `Direct3DCreate8` and
   `DirectDrawCreate` itself, so the launcher's device enumeration is lifted C.
   A wrong `D3DPRESENT_PARAMETERS` (a 32-bit struct passed by pointer) is a
   black screen, not a crash.
5. **SEH.** The lift does not install any EH frame (README, byte-scanned), so a
   guest exception should not cross it. If you see the process die inside
   `_except_handler3`, that assumption is now false and worth re-checking.

## Step 7 — when it runs, make it playable

Correctness first, then:

* **Speed.** `-O2 /Oi` is already on. The cost is the bridge: every lifted →
  real call copies argument slots and measures `esp`. Measure before optimising
  — `SHREK2_TRACE=1` prints one line per native call, and a frame in
  `Shrek 2\System\shrek2.log` tells you if you are spending the frame there.
  The first lever is lifting *more*: every function with a lifted body stops
  paying the bridge for that call.
* **`/GL` + `/LTCG`** for the generated translation units is worth a try; it is
  what the toolkit's template does for exactly this reason.
* **Shipping.** A playable build should be Release, without `SHREK2_TRACE`
  (the trace build is measurably slower), and with the 64 MB guest thread kept —
  UE2's renderer recurses.

## What "done" looks like

The original `game.exe` is still on disk and untouched; `shrek2.exe` sits next
to it; the intro movie plays, the menu accepts input, a level loads, and the
game's own logic — its `WinMain`, its classes, its UI glue — is the C in
`src/game/recomp/gen/`, which you can read and change. That is the deliverable:
not a from-scratch engine, but *this game's application body*, running.

Send back the first `shrek2.log` that fails and the trace tail; the addresses in
it are enough to say which of step 6's five it is.
