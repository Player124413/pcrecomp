/*
 * shrek2.exe -- the recompiled Shrek 2 (PC, 2004) application body.
 *
 * This process replaces the original `System/game.exe` with lifted C.  It is a
 * *hybrid* recompilation (docs/HYBRID.md): the application body -- the exe's
 * 1,644 functions, its CRT startup, its C++ static initialisers and its native
 * classes -- is generated C, while the UE2 engine (Core.dll, Engine.dll,
 * KWGame.dll and the drivers) stays real machine code
 * (Core.dll, Engine.dll, KWGame.dll, the drivers).  native32 runs the boundary:
 *
 *   lifted -> real   an import call lands on the DLL that shipped with the game
 *   real   -> lifted the engine calls a virtual method or a class constructor
 *                    that lives in the exe; the fetch faults on the mapped
 *                    image's non-executable .text and the callback trampoline
 *                    enters the lifted body
 *
 * So the exe's `.rdata`/`.data`/`.idata` must be mapped at their original VAs
 * (0x10900000, its preferred base -- the image is /FIXED, there are no
 * relocations to apply), and the original game.exe must still be on disk: it
 * is the source of that data, exactly as the engine DLLs are the source of the
 * engine.
 *
 * Layout it expects -- the shipping install, with one file added:
 *
 *     Shrek 2/
 *       System/
 *         game.exe        <- the original, untouched (mapped for its data)
 *         shrek2.exe      <- this (the lift; run this instead of game.exe)
 *         Core.dll Engine.dll KWGame.dll msvcr70.dll ...
 *       Textures/ Sounds/ ...
 *
 * Command line: everything is passed through to the game untouched, so the
 * host accepts exactly the switches game.exe accepted (`-log`, `-windowed`,
 * ...).  The host's own knobs are environment variables, because taking them
 * from argv would change the command line the guest's CRT parses:
 *
 *     SHREK2_DIR=<path>       use a game folder other than the exe's own
 *     SHREK2_TRACE=1          log every lifted -> real call
 *     SHREK2_TRACE_CALLBACKS=1 log every real -> lifted call
 *     SHREK2_NO_HOLD=1        do not reserve the image range by relaunching
 *                             (useful under a debugger; see native32_hold_image)
 *     SHREK2_LOG=1            write the [host] log to shrek2.log next to the exe
 *
 * The host is a GUI subsystem binary like the original.  Started from a
 * console it attaches to it, so `shrek2.exe -log` prints as you would expect
 * from `game.exe -log`; started from Explorer it is silent until something
 * goes wrong.
 *
 * Exit codes: 0 the game's WinMain returned, 2 the install is incomplete,
 * 3 the image could not be mapped, 4 binding left imports unresolved,
 * 5 the entry point is not in the catalog.
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>
#include <stdint.h>

#include "recomp_types.h"
#include "native32.h"
#include "recomp_target.h"

#ifndef RECOMP_IMAGE_BASE
#error "build with the generated headers on the include path (src/game/recomp/gen)"
#endif

#define GAME_EXE      "game.exe"
#define MISSING_FILE  "shrek2_missing.txt"

/* native32 owes the runtime this one symbol: the hook RECOMP_ICALL and
 * RECOMP_ITAIL consult before the generated dispatch table, for a hand-written
 * override of a function the lift got wrong.  Empty here on purpose -- the
 * generated table answers everything; override one by returning its lifted
 * body from this function instead. */
recomp_func_t recomp_lookup_manual(uint32_t va)
{
    (void)va;
    return NULL;
}

static char g_game_dir[MAX_PATH];
static char g_game_exe[MAX_PATH];

/* ------------------------------------------------------------------ */

static int file_exists(const char *path)
{
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void join(char *out, size_t n, const char *dir, const char *file)
{
    snprintf(out, n, "%s%s%s", dir,
             (dir[0] && dir[strlen(dir) - 1] != '\\' && dir[strlen(dir) - 1] != '/') ? "\\" : "",
             file);
}

/* Read just enough of the PE to prove it is the image the lift was made from. */
static int read_pe_identity(const char *path, uint32_t *base, uint32_t *entry,
                            uint32_t *span)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS32 nt;
    int ok = fread(&dos, sizeof dos, 1, f) == 1 && dos.e_magic == IMAGE_DOS_SIGNATURE &&
             fseek(f, dos.e_lfanew, SEEK_SET) == 0 &&
             fread(&nt, sizeof nt, 1, f) == 1 && nt.Signature == IMAGE_NT_SIGNATURE;
    fclose(f);
    if (!ok) return 0;
    if (base)  *base  = nt.OptionalHeader.ImageBase;
    if (entry) *entry = nt.OptionalHeader.ImageBase + nt.OptionalHeader.AddressOfEntryPoint;
    if (span)  *span  = nt.OptionalHeader.SizeOfImage;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Diagnostics                                                         */
/* ------------------------------------------------------------------ */

static FILE *g_missing;

/* Guest addresses native code called that have no lifted body.  The static
 * scan cannot see every method (a computed jump, a pointer built at runtime);
 * this is the list that closes the loop -- feed it back to the driver:
 *
 *     python3 projects/shrek2/tools/build_lift.py --game ... \
 *             --seed-file System/shrek2_missing.txt
 */
static void note_missing(uint32_t va)
{
    if (!g_missing) {
        char path[MAX_PATH];
        join(path, sizeof path, g_game_dir, MISSING_FILE);
        g_missing = fopen(path, "a");
    }
    if (g_missing) {
        fprintf(g_missing, "0x%08X\n", va);
        fflush(g_missing);
    }
}

/* Registered after native32's handler (first=0), so it runs only when
 * native32 has already declined the fault: either a fetch of a guest address
 * with no lifted body, or a genuine crash inside the lift. */
static LONG WINAPI host_veh(EXCEPTION_POINTERS *ep)
{
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    uint32_t pc = (uint32_t)(uintptr_t)er->ExceptionAddress;
    int fetch = er->NumberParameters >= 2 &&
                (er->ExceptionInformation[0] == 8 ||
                 (uint32_t)er->ExceptionInformation[1] == pc);

    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && fetch &&
        native32_in_guest(pc) && !recomp_lookup(pc)) {
        fprintf(stderr, "\n[host] native code called guest 0x%08X -- no lifted body\n", pc);
        fprintf(stderr, "[host] wrote it to %s; re-run the driver with --seed-file to add it\n",
                MISSING_FILE);
        note_missing(pc);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        er->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION ||
        er->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION ||
        er->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        const char *fn = native32_name(g_cur_func);
        fprintf(stderr, "\n================ recompiled game crashed ================\n");
        fprintf(stderr, "  exception   : 0x%08lX at %p\n",
                (unsigned long)er->ExceptionCode, (void *)(uintptr_t)pc);
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
            fprintf(stderr, "  %s        : 0x%08X\n",
                    er->ExceptionInformation[0] ? "write" : "read",
                    (unsigned int)er->ExceptionInformation[1]);
        if (fn)
            fprintf(stderr, "  in lifted   : 0x%08X (%s)\n", g_cur_func, fn);
        else
            fprintf(stderr, "  in lifted   : 0x%08X\n", g_cur_func);
        fprintf(stderr, "  EAX=%08X ECX=%08X EDX=%08X EBX=%08X\n",
                g_eax, g_ecx, g_edx, g_ebx);
        fprintf(stderr, "  ESP=%08X EBP=%08X ESI=%08X EDI=%08X\n",
                g_esp, g_ebp, g_esi, g_edi);
        fprintf(stderr, "  guest stack : 0x%08X\n", g_esp);
        fprintf(stderr, "  last indirect calls (newest first):\n");
        native32_dump_icalls(16);
        fprintf(stderr, "  If the top one is an engine function, the lift passed it a\n"
                        "  bad `this` or a bad argument; run with SHREK2_TRACE=1 to see\n"
                        "  the call sequence that led here.\n");
        fprintf(stderr, "==========================================================\n");
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ------------------------------------------------------------------ */

static DWORD WINAPI guest_main(LPVOID unused)
{
    (void)unused;
    fprintf(stderr, "[host] calling lifted entry 0x%08X\n", (unsigned)RECOMP_ENTRY_VA);
    native32_call_guest(RECOMP_ENTRY_VA, 0, NULL);
    /* The CRT's exit() normally ends the process inside the call above.  If the
     * guest's WinMain returns instead, so do we. */
    fprintf(stderr, "[host] WinMain returned\n");
    return 0;
}

static void usage(void)
{
    fprintf(stderr,
        "shrek2.exe -- recompiled Shrek 2 (2004) application body\n"
        "\n"
        "Run it from the game's System folder, next to the original game.exe and\n"
        "the engine DLLs.  Command-line switches are passed to the game unchanged.\n"
        "\n"
        "Environment:\n"
        "  SHREK2_DIR=<path>          game folder (default: this exe's folder)\n"
        "  SHREK2_TRACE=1             log lifted -> real calls\n"
        "  SHREK2_TRACE_CALLBACKS=1   log real -> lifted calls\n"
        "  SHREK2_NO_HOLD=1           do not reserve the image range by relaunching\n"
        "  SHREK2_LOG=1               write the log to shrek2.log\n"
        "  SHREK2_HELP=1              print this and exit\n"
        "\n"
        "Build: cmake -S projects/shrek2 -B build -A Win32 && cmake --build build --config Release\n");
}

/* ------------------------------------------------------------------ */

static int shrek2_run(void)
{
    if (getenv("SHREK2_HELP")) { usage(); return 0; }

    /* ---- where is the game? ------------------------------------------- */

    const char *env_dir = getenv("SHREK2_DIR");
    if (env_dir && *env_dir) {
        snprintf(g_game_dir, sizeof g_game_dir, "%s", env_dir);
    } else {
        char self[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, self, MAX_PATH);
        char *slash = strrchr(self, '\\');
        if (slash) *slash = 0;
        snprintf(g_game_dir, sizeof g_game_dir, "%s", self[0] ? self : ".");
    }

    join(g_game_exe, sizeof g_game_exe, g_game_dir, GAME_EXE);
    if (!file_exists(g_game_exe)) {
        fprintf(stderr,
            "[host] no original game.exe in %s\n"
            "[host] this build maps the original image for its data sections:\n"
            "[host] the game's own game.exe, Core.dll and Engine.dll must stay in place.\n"
            "[host] set SHREK2_DIR if the game is installed somewhere else.\n",
            g_game_dir);
        return 2;
    }

    uint32_t base = 0, entry = 0, span = 0;
    if (!read_pe_identity(g_game_exe, &base, &entry, &span)) {
        fprintf(stderr, "[host] %s is not a PE image\n", g_game_exe);
        return 2;
    }
    if (base != RECOMP_IMAGE_BASE) {
        fprintf(stderr,
            "[host] the game.exe on disk has image base 0x%08X, the lift was built for\n"
            "[host] 0x%08X.  Re-run the driver against this copy of the game.\n",
            base, (unsigned)RECOMP_IMAGE_BASE);
        return 2;
    }

    /* ---- the machine ------------------------------------------------ */
    native32_init();
    AddVectoredExceptionHandler(0, host_veh);

    /* Reserve [base, base+span) in a child launched suspended, before its
     * loader has placed the first stack and any DLL: that is the only moment
     * the range is guaranteed free.  In the parent this never returns; in the
     * child it returns 1 with the reservation made. */
    if (!getenv("SHREK2_NO_HOLD"))
        native32_hold_image(g_game_exe, RECOMP_IMAGE_BASE);

    /* Printed after the relaunch, so the banner appears once. */
    fprintf(stderr, "[host] Shrek 2 recompiled build\n");
    fprintf(stderr, "[host]   game dir : %s\n", g_game_dir);
    fprintf(stderr, "[host]   game.exe : image base 0x%08X, span 0x%X, entry 0x%08X\n",
            base, span, entry);
    fprintf(stderr, "[host]   lift     : %u functions, source sha256 %.16s\n",
            (unsigned)RECOMP_FUNCTION_COUNT, RECOMP_SOURCE_SHA256);

    if (!native32_map(g_game_exe, RECOMP_IMAGE_BASE)) {
        fprintf(stderr, "[host] cannot map the image at 0x%08X: the range is in use.\n"
                        "[host] rerun without SHREK2_NO_HOLD so the image range is held\n"
                        "[host] before the loader places anything.\n",
                (unsigned)RECOMP_IMAGE_BASE);
        return 3;
    }

    /* The DLLs come from the game folder, not from system32: the shipping
     * msvcr70 and the UE2 builds are what the exe was linked against. */
    SetDllDirectoryA(g_game_dir);
    _chdir(g_game_dir);

    if (getenv("SHREK2_TRACE"))           native32_trace_native = 1;
    if (getenv("SHREK2_TRACE_CALLBACKS")) native32_trace_callbacks = 1;

    int missing = native32_bind(RECOMP_IMAGE_BASE, NULL, 0);
    if (missing) {
        fprintf(stderr,
            "[host] %d imports unresolved.  The DLLs the exe links against are:\n"
            "[host]   Core.dll Engine.dll Window.dll WinDrv.dll D3DDrv.dll KWGame.dll\n"
            "[host]   msvcr70.dll IFC23.DLL and the Windows system DLLs.\n"
            "[host] They must be the ones from this install, in %s.\n",
            missing, g_game_dir);
        return 4;
    }

    /* ---- run --------------------------------------------------------- */
    /* The lifted body gets its own big-stack thread: a lifted frame is several
     * times the original's (register locals, flag state, spills), and UE2's
     * renderer and audio threads recurse through the bridge.  64 MB reserve,
     * committed on demand; the /STACK of the exe itself stays small so the
     * image range at 0x10900000 cannot collide with the first thread's stack. */
    HANDLE th = CreateThread(NULL, 64u << 20, guest_main, NULL, 0, NULL);
    if (!th) {
        fprintf(stderr, "[host] cannot start the guest thread (%lu)\n", GetLastError());
        return 3;
    }
    WaitForSingleObject(th, INFINITE);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    return (int)code;
}

/* A GUI subsystem binary, like the original game.exe.  Started from a console
 * (`shrek2.exe -log`) it attaches to that console so the log is visible;
 * started from Explorer it stays silent. */
int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show)
{
    (void)inst; (void)prev; (void)cmd; (void)show;

    if (getenv("SHREK2_LOG")) {
        char log[MAX_PATH];
        GetModuleFileNameA(NULL, log, MAX_PATH);
        char *slash = strrchr(log, '\\');
        if (slash) slash[1] = 0; else log[0] = 0;
        strncat(log, "shrek2.log", MAX_PATH - strlen(log) - 1);
        if (freopen(log, "w", stderr)) {
            fprintf(stderr, "[host] log: %s\n", log);
        }
    } else if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
    }
    return shrek2_run();
}
