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

It currently clears steps 1–6 and reaches step 7 (~1M+ instructions, every
anti-debug check handled). What is left:

1. **Emulate `SECDRV.SYS`'s IOCTL `0xEF002407`.** The driver is 8 KB, imports
   only `Io*`/`Rtl*` from `ntoskrnl` (no disk I/O — it is pure computation), and
   its `DriverEntry` (`0x12466`) is `jmp`-maze obfuscated like the shell. Run it
   under Unicorn too: a fake `DRIVER_OBJECT`, stub the `ntoskrnl` imports
   (`IoCreateDevice`, `IoCreateSymbolicLink`, `RtlInitUnicodeString`,
   `RtlQueryRegistryValues`, `IofCompleteRequest`), call `DriverEntry` to capture
   `MajorFunction[IRP_MJ_DEVICE_CONTROL]`, then build an IRP + `IO_STACK_LOCATION`
   for the IOCTL (METHOD_BUFFERED: challenge in `AssociatedIrp.SystemBuffer`) and
   read the response back out. Wire it into `api_DeviceIoControl`.
2. **Let the loader decrypt.** With a valid response it will fall into step 8.
3. **Model the child.** `CreateProcess(ICD)` initialises a second memory image
   from the ICD's file layout; `WriteProcessMemory`/`ReadProcessMemory`/
   `VirtualProtect` act on it; `GetThreadContext` returns `Eax` = entry and a PEB
   pointer in `Ebx`; `SetThreadContext` records the OEP. After `ResumeThread`
   the child image holds the decrypted program.
4. **Rebuild the PE.** Reuse `emu_unpack.py`'s `find_iat`/`layout`/`write`: the
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
