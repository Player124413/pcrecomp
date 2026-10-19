r"""Dump a SafeDisc 1 process-hollowed child to recover the decrypted .ICD.

This is the run-and-dump fallback for the loader/ICD model (FS2000, Crimson Skies,
and the like), where a cleartext loader EXE decrypts a separate .ICD and
process-hollows it into a child at the ICD's image base. The decrypted program
therefore lives in the *child's* memory, not the loader's -- so, unlike the
in-place XWA dumper (drm/safedisc_dump.py), this one launches the loader, finds
the hollowed child, and reads the ICD's section ranges out of it.

Run this ON A WINDOWS VM that can actually play the title (the disc in the drive,
secdrv installed). It is not headless and it launches the game -- that is the
point of the fallback; the headless, nothing-launched path is drm/safedisc1.py.

    python tools/drm/safedisc1_dump.py FS2000.EXE FS2000.ICD [FS2000.decrypted.icd]

Output is a copy of the .ICD with its sections overwritten by the decrypted bytes
from the child, ready for pe/pe_analyze.py and the lifters. Verify by the entropy
line (decrypted .text is ~6 bits/byte, encrypted ~8) and that pe_analyze reads a
sane function count. Imports are stripped in the ICD and the child's IAT holds
this machine's absolute addresses, so import *names* still need reconstruction
(drm/emu_unpack.py's find_iat over the decrypted code) -- the decrypted bytes are
what this produces.
"""
import ctypes
import math
import os
import sys
import time
from ctypes import wintypes

import pefile

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TH32CS_SNAPPROCESS = 0x00000002

k32 = ctypes.WinDLL('kernel32', use_last_error=True)


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_void_p),
                ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', ctypes.c_long),
                ('dwFlags', wintypes.DWORD), ('szExeFile', ctypes.c_char * 260)]


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [('cb', wintypes.DWORD)] + [
        (n, t) for n, t in (
            ('lpReserved', ctypes.c_char_p), ('lpDesktop', ctypes.c_char_p),
            ('lpTitle', ctypes.c_char_p), ('dwX', wintypes.DWORD), ('dwY', wintypes.DWORD),
            ('dwXSize', wintypes.DWORD), ('dwYSize', wintypes.DWORD),
            ('dwXCountChars', wintypes.DWORD), ('dwYCountChars', wintypes.DWORD),
            ('dwFillAttribute', wintypes.DWORD), ('dwFlags', wintypes.DWORD),
            ('wShowWindow', wintypes.WORD), ('cbReserved2', wintypes.WORD),
            ('lpReserved2', ctypes.c_void_p), ('hStdInput', wintypes.HANDLE),
            ('hStdOutput', wintypes.HANDLE), ('hStdError', wintypes.HANDLE))]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [('hProcess', wintypes.HANDLE), ('hThread', wintypes.HANDLE),
                ('dwProcessId', wintypes.DWORD), ('dwThreadId', wintypes.DWORD)]


def _entropy(b):
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    return -sum((f / len(b)) * math.log2(f / len(b)) for f in freq if f)


def _read(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value] if ok else b''


def _snapshot():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    out = []
    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if k32.Process32First(snap, ctypes.byref(pe)):
        while True:
            out.append((pe.th32ProcessID, pe.th32ParentProcessID,
                        pe.szExeFile.decode('latin-1').lower()))
            if not k32.Process32Next(snap, ctypes.byref(pe)):
                break
    k32.CloseHandle(snap)
    return out


def _sections(icd_path):
    pe = pefile.PE(icd_path)
    base = pe.OPTIONAL_HEADER.ImageBase
    secs = [{'name': s.Name.rstrip(b'\0').decode('latin-1'),
             'va': base + s.VirtualAddress, 'vsize': s.Misc_VirtualSize,
             'raw': s.PointerToRawData, 'rawsize': s.SizeOfRawData}
            for s in pe.sections]
    text_va = next((s['va'] for s in secs if s['name'] == '.text'), base + 0x1000)
    pe.close()
    return base, secs, text_va


def dump(loader, icd, out=None):
    out = out or (os.path.splitext(icd)[0] + '.decrypted.icd')
    base, secs, text_va = _sections(icd)
    print('[*] ICD base 0x%08X, .text VA 0x%08X; %d sections' % (base, text_va, len(secs)))

    before = {p for p, _, _ in _snapshot()}
    si = STARTUPINFOA()
    si.cb = ctypes.sizeof(STARTUPINFOA)
    pi = PROCESS_INFORMATION()
    exe = os.path.abspath(loader)
    ok = k32.CreateProcessA(exe.encode('latin-1'), None, None, None, False, 0, None,
                            os.path.dirname(exe).encode('latin-1'),
                            ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        sys.exit('CreateProcess failed: %d' % ctypes.get_last_error())
    print('[*] launched loader PID %d; letting it decrypt + hollow the child...' % pi.dwProcessId)

    # The decrypted image is whichever process (the child, or the loader itself if
    # it hollows in place) has a low-entropy .text at the ICD base. Poll a while.
    target = None
    for _ in range(20):
        time.sleep(1)
        cands = [pi.dwProcessId] + [p for p, pp, _ in _snapshot()
                                    if pp == pi.dwProcessId or p not in before]
        for p in dict.fromkeys(cands):
            h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, p)
            if not h:
                continue
            probe = _read(h, text_va, 4096)
            k32.CloseHandle(h)
            if probe and _entropy(probe) < 6.5:        # decrypted, not ciphertext
                target = p
                print('[*] decrypted image in PID %d (.text entropy %.2f)' % (p, _entropy(probe)))
                break
        if target:
            break
    if not target:
        k32.TerminateProcess(pi.hProcess, 0)
        sys.exit('[!] no process showed a decrypted .text; the child may need the '
                 'disc/secdrv, or it hollows differently -- raise the poll or inspect manually')

    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, target)
    data = bytearray(open(icd, 'rb').read())
    for s in secs:
        n = min(s['vsize'], s['rawsize']) or s['vsize']
        mem = _read(h, s['va'], n)
        if not mem:
            print('    %-8s: read failed' % s['name'])
            continue
        if s['raw'] + len(mem) <= len(data):
            data[s['raw']:s['raw'] + len(mem)] = mem
        print('    %-8s: %6d bytes  entropy %.2f  %s' % (
            s['name'], len(mem), _entropy(mem[:4096]), mem[:8].hex()))
    k32.CloseHandle(h)
    k32.TerminateProcess(pi.hProcess, 0)

    open(out, 'wb').write(data)
    print('[*] wrote %s (%d bytes)' % (out, len(data)))
    print('[*] verify: pe/pe_analyze.py %s ; .text entropy should be ~6, not ~8' % out)


if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit('usage: safedisc1_dump.py LOADER.EXE GAME.ICD [out.icd]   (run on a Windows VM)')
    dump(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
