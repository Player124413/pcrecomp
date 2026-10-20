/* safedisc1_dump.c -- native Win2k/XP port of drm/safedisc1_dump.py.
 *
 * The run-and-dump fallback for the SafeDisc 1 loader/ICD model (FS2000 and
 * friends): a cleartext loader EXE decrypts a separate .ICD and process-hollows
 * it into a child at the ICD's image base, so the decrypted program lives in the
 * *child's* memory. This launches the loader, finds the child, reads the ICD's
 * section ranges out of it, and writes a decrypted copy of the .ICD.
 *
 * It exists in C as well as Python because the box that can actually pass the
 * disc + secdrv check is often ancient (our FS2000 box is Windows 2000, where no
 * modern Python runs). This builds to a single static exe with i686 mingw:
 *
 *   i686-w64-mingw32-gcc -O2 -s -static -o safedisc1_dump.exe safedisc1_dump.c
 *
 *   safedisc1_dump.exe FS2000.EXE FS2000.ICD [FS2000.decrypted.icd]
 *
 * Finding the right process: the loader EXE is *also* linked at 0x400000, so its
 * own cleartext .text sits at the ICD's base with low entropy too -- picking by
 * entropy alone can grab the loader by mistake (the Python version's latent bug).
 * We instead match the in-memory PE headers at the image base against the ICD's
 * own (SizeOfImage + entry point): only the hollowed child carries the ICD image.
 * We scan *all* processes, not just children of the loader: the loader runs a long
 * anti-debug + secdrv-retry + CD-verify gauntlet and may exit (orphaning the child)
 * before the child is even up, so a parent-PID filter misses it. And we only accept
 * the child once its .text has actually decrypted (entropy below ~7), so we don't
 * grab a freshly-mapped-but-still-ciphertext image. If a decrypted child is already
 * running we attach to it instead of launching a second copy.
 */
#define WINVER 0x0500
#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <io.h>

static double entropy(const unsigned char *b, size_t n) {
    size_t f[256] = {0};
    double e = 0.0, p;
    size_t i;
    if (!n) return 0.0;
    for (i = 0; i < n; i++) f[b[i]]++;
    for (i = 0; i < 256; i++)
        if (f[i]) { p = (double)f[i] / n; e -= p * (log(p) / log(2.0)); }
    return e;
}

static unsigned char *read_file(const char *path, size_t *out_n) {
    FILE *fp = fopen(path, "rb");
    long sz;
    unsigned char *buf;
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END); sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    buf = (unsigned char *)malloc(sz);
    if (!buf || fread(buf, 1, sz, fp) != (size_t)sz) { free(buf); fclose(fp); return NULL; }
    fclose(fp);
    *out_n = (size_t)sz;
    return buf;
}

/* Parse the 32-bit PE headers already in a buffer. Returns the NT headers, or
 * NULL if the buffer is not a PE32. */
static IMAGE_NT_HEADERS32 *pe32(unsigned char *base, size_t n) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS32 *nt;
    if (n < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if ((size_t)dos->e_lfanew + sizeof(*nt) > n) return NULL;
    nt = (IMAGE_NT_HEADERS32 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return NULL;
    return nt;
}

/* Scan every process for the one carrying the ICD image at `base`: its in-memory
 * PE headers match the ICD's (SizeOfImage + entry point) and its .text has already
 * decrypted (entropy below `max_ent`). Returns the pid, or 0 if none yet. */
static DWORD scan_for_image(DWORD base, DWORD want_sizeofimage, DWORD want_entry,
                            DWORD text_va, double max_ent) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    DWORD found = 0;
    if (snap == INVALID_HANDLE_VALUE) return 0;
    pe.dwSize = sizeof pe;
    if (Process32First(snap, &pe)) do {
        unsigned char hdr[0x400], probe[4096];
        IMAGE_NT_HEADERS32 *cnt;
        SIZE_T got = 0;
        HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                               pe.th32ProcessID);
        if (!h) continue;
        if (ReadProcessMemory(h, (LPCVOID)(DWORD_PTR)base, hdr, sizeof hdr, &got) && got) {
            cnt = pe32(hdr, got);
            if (cnt)
                fprintf(stderr, "    [dbg] PID %lu %-16s PE@400k SizeOfImage 0x%lX\n",
                        (unsigned long)pe.th32ProcessID, pe.szExeFile,
                        (unsigned long)cnt->OptionalHeader.SizeOfImage);
            /* SizeOfImage alone identifies the ICD image (the loader's differs); the
             * entry point is NOT matched -- SafeDisc restores the real OEP only in
             * memory, so the file header's entry differs from the running child's. */
            (void)want_entry;
            if (cnt && cnt->OptionalHeader.SizeOfImage == want_sizeofimage) {
                double e;
                got = 0;
                ReadProcessMemory(h, (LPCVOID)(DWORD_PTR)text_va, probe, sizeof probe, &got);
                e = entropy(probe, got);
                fprintf(stderr, "    [dbg] PID %lu %s SizeOfImage match, .text read %lu bytes entropy %.2f\n",
                        (unsigned long)pe.th32ProcessID, pe.szExeFile,
                        (unsigned long)got, e);
                if (got && e < max_ent) {
                    printf("[*] ICD image in PID %lu (.text entropy %.2f)\n",
                           (unsigned long)pe.th32ProcessID, e);
                    found = pe.th32ProcessID;
                } /* else: mapped but still ciphertext -- wait for it to decrypt */
            }
        }
        CloseHandle(h);
    } while (!found && Process32Next(snap, &pe));
    CloseHandle(snap);
    return found;
}

/* Diagnostic: list every process and what sits at 0x400000 in it, so we can see
 * which process actually carries the decrypted ICD and what its headers look like. */
static void list_processes(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    if (snap == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof pe;
    printf("%-6s %-20s %-8s %-10s %-10s %-7s\n",
           "PID", "EXE", "PE@400k", "SizeOfImg", "EntryPt", "txtEnt");
    if (Process32First(snap, &pe)) do {
        unsigned char hdr[0x400], probe[4096];
        IMAGE_NT_HEADERS32 *cnt;
        SIZE_T got = 0;
        char soi[11] = "-", ep[11] = "-", te[8] = "-", pep[9] = "no";
        HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,
                               pe.th32ProcessID);
        if (h) {
            if (ReadProcessMemory(h, (LPCVOID)0x400000, hdr, sizeof hdr, &got) && got) {
                cnt = pe32(hdr, got);
                if (cnt) {
                    strcpy(pep, "yes");
                    _snprintf(soi, sizeof soi, "0x%lX",
                              (unsigned long)cnt->OptionalHeader.SizeOfImage);
                    _snprintf(ep, sizeof ep, "0x%lX",
                              (unsigned long)cnt->OptionalHeader.AddressOfEntryPoint);
                }
                got = 0;
                if (ReadProcessMemory(h, (LPCVOID)0x401000, probe, sizeof probe, &got) && got)
                    _snprintf(te, sizeof te, "%.2f", entropy(probe, got));
            }
            CloseHandle(h);
        }
        printf("%-6lu %-20s %-8s %-10s %-10s %-7s\n",
               (unsigned long)pe.th32ProcessID, pe.szExeFile, pep, soi, ep, te);
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
}

int main(int argc, char **argv) {
    const char *loader, *icd, *out;
    char out_auto[MAX_PATH], cmd[MAX_PATH], dir[MAX_PATH], *slash;
    size_t icd_n;
    unsigned char *icd_data;
    IMAGE_NT_HEADERS32 *nt;
    IMAGE_SECTION_HEADER *sh;
    DWORD base, text_va, want_sizeofimage, want_entry;
    WORD nsec, i;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    DWORD target = 0, loader_pid = 0;
    int t, attach_only = 0;
    HANDLE h;

    setvbuf(stdout, NULL, _IONBF, 0);   /* unbuffered: output survives a mid-run VM stop */

    if (argc >= 2 && strcmp(argv[1], "list") == 0) { list_processes(); return 0; }
    /* grab EXENAME OUT.bin -- dump a running process's whole image at 0x400000 to a
     * file (its in-memory SizeOfImage). Used to capture the decrypted SafeDisc shell
     * (FS2000.EXE), which self-decrypts its .txt with no disc, as a reference oracle. */
    if (argc >= 4 && strcmp(argv[1], "grab") == 0) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe; DWORD pid = 0; unsigned char hdr[0x400]; SIZE_T got = 0;
        IMAGE_NT_HEADERS32 *cnt; DWORD soi; unsigned char *buf; FILE *fp;
        pe.dwSize = sizeof pe;
        if (Process32First(snap, &pe)) do {
            if (_stricmp(pe.szExeFile, argv[2]) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
        CloseHandle(snap);
        if (!pid) { fprintf(stderr, "grab: no process named %s\n", argv[2]); return 1; }
        h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!h) { fprintf(stderr, "grab: OpenProcess %lu failed %lu\n",
                          (unsigned long)pid, GetLastError()); return 1; }
        if (!ReadProcessMemory(h, (LPCVOID)0x400000, hdr, sizeof hdr, &got) || !got) {
            fprintf(stderr, "grab: read header failed\n"); return 1; }
        cnt = pe32(hdr, got);
        soi = cnt ? cnt->OptionalHeader.SizeOfImage : 0x4B000;
        buf = (unsigned char *)malloc(soi); got = 0;
        ReadProcessMemory(h, (LPCVOID)0x400000, buf, soi, &got);
        CloseHandle(h);
        fp = fopen(argv[3], "wb");
        if (!fp || fwrite(buf, 1, got, fp) != got) { fprintf(stderr, "grab: write failed\n"); return 1; }
        fflush(fp); _commit(_fileno(fp)); fclose(fp);
        printf("grab: PID %lu %s -> %s (%lu bytes, SizeOfImage 0x%lX)\n",
               (unsigned long)pid, argv[2], argv[3], (unsigned long)got, (unsigned long)soi);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "launch") == 0) {
        memset(&si, 0, sizeof si); si.cb = sizeof si; memset(&pi, 0, sizeof pi);
        _snprintf(dir, sizeof dir, "%s", argv[2]);
        slash = strrchr(dir, '\\'); if (slash) *slash = 0; else strcpy(dir, ".");
        _snprintf(cmd, sizeof cmd, "%s", argv[2]);
        if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) {
            fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError()); return 1;
        }
        printf("launched %s as PID %lu\n", argv[2], (unsigned long)pi.dwProcessId);
        return 0;
    }
    /* attach mode: the game is ALREADY running (launched cleanly, undisturbed, so
     * SafeDisc decrypted + hollowed without our memory-reads tripping its anti-debug).
     * We only scan and dump -- never launch, so no second instance, no anti-debug. */
    if (argc >= 3 && strcmp(argv[1], "attach") == 0) {
        attach_only = 1; loader = NULL; icd = argv[2];
        out = (argc > 3) ? argv[3] : NULL;
    } else if (argc >= 3) {
        loader = argv[1]; icd = argv[2];
        out = (argc > 3) ? argv[3] : NULL;
    } else {
        fprintf(stderr, "usage: safedisc1_dump LOADER.EXE GAME.ICD [out.icd]  (launch+dump)\n"
                        "       safedisc1_dump attach GAME.ICD [out.icd]   (dump a running game)\n"
                        "       safedisc1_dump launch LOADER.EXE           (start it, don't poll)\n"
                        "       safedisc1_dump grab EXENAME out.bin        (dump a process image at 0x400000)\n"
                        "       safedisc1_dump list                        (diagnostic table)\n");
        return 2;
    }
    if (!out) {
        _snprintf(out_auto, sizeof out_auto, "%s", icd);
        slash = strrchr(out_auto, '.'); if (slash) *slash = 0;
        strncat(out_auto, ".decrypted.icd", sizeof out_auto - strlen(out_auto) - 1);
        out = out_auto;
    }

    icd_data = read_file(icd, &icd_n);
    if (!icd_data) { fprintf(stderr, "cannot read %s\n", icd); return 1; }
    nt = pe32(icd_data, icd_n);
    if (!nt) { fprintf(stderr, "%s is not a PE32\n", icd); return 1; }
    base = nt->OptionalHeader.ImageBase;
    want_sizeofimage = nt->OptionalHeader.SizeOfImage;
    want_entry = nt->OptionalHeader.AddressOfEntryPoint;
    nsec = nt->FileHeader.NumberOfSections;
    sh = (IMAGE_SECTION_HEADER *)((unsigned char *)&nt->OptionalHeader +
                                  nt->FileHeader.SizeOfOptionalHeader);
    text_va = base + 0x1000;
    for (i = 0; i < nsec; i++)
        if (memcmp(sh[i].Name, ".text", 5) == 0) text_va = base + sh[i].VirtualAddress;
    printf("[*] ICD base 0x%08lX, .text VA 0x%08lX, SizeOfImage 0x%lX, %u sections\n",
           (unsigned long)base, (unsigned long)text_va,
           (unsigned long)want_sizeofimage, nsec);

    /* already running from a previous launch? attach, don't start a second copy */
    target = scan_for_image(base, want_sizeofimage, want_entry, text_va, 7.0);
    if (!target && attach_only) {
        printf("[*] attach: scanning for the running decrypted ICD image (30s)...\n");
        for (t = 0; t < 30 && !target; t++) {
            Sleep(1000);
            target = scan_for_image(base, want_sizeofimage, want_entry, text_va, 7.0);
        }
    }
    if (!target && !attach_only) {
        _snprintf(cmd, sizeof cmd, "%s", loader);
        _snprintf(dir, sizeof dir, "%s", loader);
        slash = strrchr(dir, '\\'); if (slash) *slash = 0; else strcpy(dir, ".");
        memset(&si, 0, sizeof si); si.cb = sizeof si;
        memset(&pi, 0, sizeof pi);
        if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, dir, &si, &pi)) {
            fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
            return 1;
        }
        loader_pid = pi.dwProcessId;
        printf("[*] launched loader PID %lu; waiting (up to 120s) for it to decrypt "
               "+ hollow the child...\n", (unsigned long)loader_pid);
        for (t = 0; t < 120 && !target; t++) {
            Sleep(1000);
            fprintf(stderr, "[poll %d]\n", t);
            target = scan_for_image(base, want_sizeofimage, want_entry, text_va, 7.0);
        }
    }

    if (!target) {
        fprintf(stderr, "[!] no process showed the decrypted ICD image in time -- the "
                        "child may need the disc/secdrv, or it hollows differently.\n");
        return 3;   /* leave everything running so it can be inspected / re-attached */
    }

    h = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, target);
    for (i = 0; i < nsec; i++) {
        DWORD want = sh[i].Misc.VirtualSize;
        DWORD raw = sh[i].SizeOfRawData;
        DWORD n = (want && want < raw) ? want : (raw ? raw : want);
        unsigned char *mem;
        SIZE_T got = 0;
        char nm[9]; memcpy(nm, sh[i].Name, 8); nm[8] = 0;
        if (!n) continue;
        mem = (unsigned char *)malloc(n);
        if (!mem) continue;
        if (ReadProcessMemory(h, (LPCVOID)(DWORD_PTR)(base + sh[i].VirtualAddress),
                              mem, n, &got) && got) {
            if (sh[i].PointerToRawData + got <= icd_n)
                memcpy(icd_data + sh[i].PointerToRawData, mem, got);
            printf("    %-8s: %6lu bytes  entropy %.2f\n",
                   nm, (unsigned long)got, entropy(mem, got < 4096 ? got : 4096));
        } else {
            printf("    %-8s: read failed (%lu)\n", nm, GetLastError());
        }
        free(mem);
    }
    CloseHandle(h);

    {
        FILE *fp = fopen(out, "wb");
        if (!fp || fwrite(icd_data, 1, icd_n, fp) != icd_n) {
            fprintf(stderr, "cannot write %s\n", out); return 1;
        }
        fflush(fp);
        _commit(_fileno(fp));   /* flush to disk now: the host reads this file after a poweroff */
        fclose(fp);
    }
    if (loader_pid) {           /* only if we started it; an attached game is left alone */
        HANDLE lh = OpenProcess(PROCESS_TERMINATE, FALSE, loader_pid);
        if (lh) { TerminateProcess(lh, 0); CloseHandle(lh); }
    }
    printf("[*] wrote %s (%lu bytes). verify: pe_analyze; .text entropy ~6 not ~8\n",
           out, (unsigned long)icd_n);
    return 0;
}
