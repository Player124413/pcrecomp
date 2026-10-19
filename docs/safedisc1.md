# SafeDisc 1.x: unwrapping by emulating the loader

This is the mechanism of SafeDisc 1.x copy protection as measured on Microsoft
Flight Simulator 2000 (`FS2000.EXE` + `FS2000.ICD`, SafeDisc `BoG_ *90.0`,
secdrv.sys dated 1999), and how `tools/drm/safedisc1.py` unwraps it without a
disc, a driver, or launching anything. It is the reference for finishing that
tool, and it applies to every SafeDisc 1 title (Crimson Skies, X-Wing Alliance,
the many others on the usual-suspects list), because the pieces are shared.

The goal is a decrypted, importable PE for the lifter — not a working disc
check. We measure the game; we do not help anyone skip buying it.

## The two files

A SafeDisc 1 title ships as:

- **`GAME.EXE`** — a normal MSVC program. Its `.text` is cleartext (a standard
  CRT start-up and `WinMain`), but it carries extra `.txt`/`.txt2` sections at
  ~8 bits/byte: the obfuscated SafeDisc shell, reached from `WinMain` as a
  `jmp`-maze (overlapping instructions, jumps into mid-instruction — junk that
  defeats a linear or recursive disassembler but runs fine under emulation).
- **`GAME.ICD`** — the real program. A valid PE whose `.text` is encrypted
  (~7.98 bits/byte) and whose `kernel32`/`user32` imports are stripped; its
  entry point sits *inside* the encrypted `.text`, so it cannot self-decrypt.
  The loader decrypts it.

Both are linked at `0x400000`, which is the first hint that the ICD runs in a
*separate* process, not inside the loader.

## What the loader does (measured, in order)

Driven from `GAME.EXE`'s clean entry point under Unicorn, the loader:

1. Runs the MSVC CRT start-up (heap, TLS, `_setenvp`, `_cinit`).
2. Creates a 0x30-byte named section, `ladybird` / `SAFEDISC_ERROR_%08x` (the
   pid) — the shell↔child IPC control block.
3. `GetProfileIntA("C-DILLA", "INTERACTIVE"/"TESTMESSAGES")` — C-DILLA config.
4. Opens `CLCD32.DLL`, `CLCD16.DLL`, `SECDRV.SYS` from the CD drive and calls
   `drvmgt.dll!Setup`, which installs the `secdrv` kernel driver.
5. Opens `GAME.ICD`.
6. **Anti-debug gauntlet.** All of these must answer "no debugger":
   - `CreateFileA("\\.\SICE")`, `"\\.\NTICE")`, … → must fail (`INVALID_HANDLE_VALUE`).
     Succeeding tells SafeDisc SoftICE is loaded.
   - `NtQueryInformationProcess(ProcessDebugPort)` → port 0, `STATUS_SUCCESS`.
   - `IsDebuggerPresent` → 0; reads `KUSER_SHARED_DATA` at `0x7FFE0000`.
7. **Driver authentication.** `DeviceIoControl(\\.\Secdrv, 0xEF002407,
   in=1300, out=1552)` — a challenge/response with secdrv. The loader retries
   256 times and then traps if the 1552-byte response is wrong.
8. Only once authentication passes: it decrypts the ICD and **process-hollows**
   it into a child — `CreateProcess` (suspended), `WriteProcessMemory` the
   decrypted sections, `SetThreadContext` with `Eip` = the ICD's real OEP,
   `ResumeThread`.

The decryption is **gated on step 7**: with the secdrv response stubbed, step 8
never happens (no `CreateProcess`, no `WriteProcessMemory`). So the decryption
key is derived from the secdrv response, and there is no shortcut around it.

## The emulator

`tools/drm/safedisc1.py` maps the loader and answers its imports in Python, the
same shape as `drm/emu_unpack.py`: a GDT/TEB/PEB, a thunk per IAT entry, a
`UC_HOOK_CODE` over the thunk page that dispatches to `api_*` handlers, and
`ArgcResolver` (tools/pe/stdcall_argc.py) for the stdcall purge of any import
without a hand-written handler, so the stack never silently desynchronises.

### Done so far

- **Steps 1–6** (CRT, C-DILLA set-up, the full anti-debug gauntlet).
- **Step 7, the secdrv authentication — `tools/drm/secdrv.py`.** This was the
  documented crux and it is solved. `SECDRV.SYS` (14 KB, imports only `Io*`/`Rtl*`
  from `ntoskrnl`, no disk I/O) runs headless under its own Unicorn instance with
  a fake `DRIVER_OBJECT` and stubbed ntoskrnl imports. `DriverEntry` (`0x12466`)
  is emulated once to capture `MajorFunction[IRP_MJ_DEVICE_CONTROL]` (`0x10676`);
  each call builds an IRP + `IO_STACK_LOCATION` and runs the dispatch, stopping at
  `IofCompleteRequest` (fastcall) to read `IoStatus` + the response. Two things
  mattered: `0xEF002407 & 3 == 3` is **METHOD_NEITHER** (input is
  `Type3InputBuffer`, output is `Irp->UserBuffer` — *not* `SystemBuffer`); and
  `KeTickCount` is a 3-dword `KSYSTEM_TIME` the driver reads with a stable-read
  spin (`High1Time==High2Time`), so its variable needs its own zeroed region
  clear of `NtBuildNumber`. The crypto worker (`0x10cbc` → `0x10da6`) reads `DR1`
  as an anti-debug check; `0` is the correct clean-machine value. The loader now
  **accepts the response and proceeds** (verification: before, it trapped at the
  gate after ~10M insns; after, it runs ~132M insns deep into the shell). secdrv
  is byte-identical across SafeDisc 1 titles, so this is reusable as-is.
- **Software interrupts (`safedisc1.py` `_intr`/`_seh`).** The shell sprinkles
  `int 1`/`int 3`/`icebp`; on a clean machine the fault reaches SafeDisc's own
  SEH handler, which resumes after the trap (a debugger would consume it — that
  is the check). We dispatch as the no-debugger case: resume past the trap.
- **A real file model (`safedisc1.py`).** `GetModuleFileNameA(NULL)` returns the
  loader; `CreateFileA`/`SetFilePointer`/`ReadFile`/`GetFileSize` are backed by
  the real loader and ICD bytes, so the shell's self-reopen (it `SetFilePointer`s
  to `EXE+0x44200`, the appended `"custom data"` block, and reads it) and the ICD
  reads deliver true bytes instead of zeros.

### The frontier: `.txt` reconstruction

With all of the above, the loader reaches the shell's **code-reconstruction
engine** and stops cleanly at `0x0040AAE2` (a `.txt` byte that reconstructed to
junk). The engine is now fully mapped:

- A command interpreter walks records keyed off the `"custom data"` payload and
  calls a dispatcher (`0x415d10`): command `0x64` = nop, `0x65` → `0x415960`,
  `0x66`/`0x67` → the patch engine `0x415a80`.
- `0x415a80` wraps a `rep movsd` copy in `VirtualProtect` (`[0x435958]`, for
  `0x67` = patch self) or routes through `WriteProcessMemory` (`[0x43595c]`, for
  `0x66` = write the hollowed child). On this title it issues 13 `0x67` calls
  rebuilding `.txt` page-by-page (`0x401000`…`0x40d800`).
- Each page's plaintext is produced by a **per-page decrypt routine** (in the
  interpreter above `0x415d10`) into a stack buffer, which `0x67` then copies in.
  That decryptor is the one remaining gap: it currently yields junk, so the
  rebuilt `.txt` is wrong and a later `call` into it faults. Finding its key
  derivation from the `"custom data"` block is the next concrete step.

### A reference oracle, from the VM (2026-10-19)

The headless `.txt` decryptor was "unverifiable without a reference dump." We now
have one, and it needed no disc check: the SafeDisc shell (`FS2000.EXE`)
self-decrypts its own `.txt` **before** any ICD hollow or CD check, so running the
game on the Win2000 box (see the `win2kdev` memory) and grabbing `FS2000.EXE`'s
memory yields the correct plaintext. `tools/drm/safedisc1_dump.c grab FS2000.EXE
shell.bin` does exactly that; the capture is in `work/safedisc1/`.

Measured against that oracle (`work/safedisc1/cmp_pages.py`):

- Every `.txt` page is encrypted in the file (entropy ~7.95) and real code in the
  shell dump (~6.3–7.0). The emulator's final `.txt` is still ~7.97 — it
  reconstructs only the first page (0x401000, already-cleartext bootstrap) and then
  the per-page decryptor emits **garbage** for the rest.
- The cipher is **not** a simple keystream: `file_txt XOR shell_txt` is ~7.95
  (high) per page, so it is a real stream/block cipher, not a repeating XOR.
- The key comes from the **"custom data"** block at file offset `0x44200`, which
  begins with the ASCII `"custom data"` stored **reversed** (`61 74 61 64 20 6d 6f
  74 73 75 63`), then a small header (`…01 00 00 00 09 04 00 00 68 00 …`).
- The decryptor *code* runs correctly in the emulator (it is the same shell code);
  it produces garbage because its **key input is wrong**. So the fix is not to
  re-implement the cipher but to find what input the real decryptor consumes that
  the emulator feeds wrong — the `"custom data"` bytes delivered by the file model,
  the secdrv response, or a runtime value — by tracing the decryptor's reads in the
  emulator and matching them to the state that yields `shell.bin`.

Next concrete step: hook the emulator around the per-page decrypt routine (reached
just before the dispatcher `0x415d10` / patch engine `0x415a80`; the copy-in is the
`rep movsd` at `0x415AC8`), log its inputs for the first page that diverges from the
oracle, and correct the emulator's delivery of that input. Then the shell runs to
completion, and — with secdrv already answered headless — it decrypts the ICD.

### Then

1. **Finish the page decryptor** so `.txt` reconstructs to real code; the shell
   then runs its own reconstruction to completion.
2. **Model the child.** `CreateProcess(ICD)` initialises a second memory image
   from the ICD's file layout; `WriteProcessMemory`/`ReadProcessMemory`/
   `VirtualProtect` act on it (the `0x66` path already targets it);
   `GetThreadContext`/`SetThreadContext` carry the OEP. After `ResumeThread` the
   child image holds the decrypted program.
3. **Rebuild the PE.** Reuse `emu_unpack.py`'s `find_iat`/`layout`/`write`: the
   stripped imports come back as the runs of thunk addresses the decrypted code
   calls through, and a fresh import directory is appended. Output is an ordinary
   PE that `pe_analyze` and the lifters read like any other.

## Verifying

A decrypted ICD is correct when `pe/pe_analyze.py` reads a clean import table,
`disasm/disasm32.py` recovers a sane function count (not a sea of invented
functions from decoding data as code), and the lifted program runs. Until then,
`drm/safedisc_dump.py` (run the game on a Windows VM with the disc, dump `.text`
from memory) is the fallback that unblocks lifting — slower and not headless,
but it produces the same decrypted bytes to check the emulator against.
