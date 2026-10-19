r"""Emulate SafeDisc's SECDRV.SYS headless, to answer the loader's IOCTL challenge.

SafeDisc 1.x gates ICD decryption on a challenge/response with its kernel driver
secdrv.sys (`DeviceIoControl(\\.\Secdrv, 0xEF002407, in=1300, out=1552)`). The
driver is tiny (14 KB), imports only Io*/Rtl* from ntoskrnl, touches no disk and
no hardware for this IOCTL -- it is pure computation. So it runs under Unicorn
with a fake DRIVER_OBJECT and a handful of ntoskrnl stubs: no driver is loaded,
nothing touches the real kernel. drm/safedisc1.py calls this from its
api_DeviceIoControl with the loader's real challenge bytes.

    s = Secdrv('SECDRV.SYS')
    status, info, out = s.ioctl(0xEF002407, challenge_bytes, 1552)

secdrv is the same binary across SafeDisc 1 titles, so this serves all of them.
"""
import struct

import pefile
from unicorn import *
from unicorn.x86_const import *

# Private address space for the driver image (its own, separate from the loader's).
THUNK = 0x90000000          # one slot per ntoskrnl import; hooked for dispatch
DATA = 0x91000000           # KeTickCount / NtBuildNumber variables
STACK, SSZ = 0x92000000, 0x100000
POOL = 0x93000000           # fake pool: DRIVER_OBJECT, DEVICE_OBJECT, IRPs, buffers
POOL_SIZE = 0x400000
SCRATCH = POOL + 0x100000   # per-ioctl buffers start here (reset each call)

# _DRIVER_OBJECT.MajorFunction[] is at +0x38 (x86); IRP_MJ_DEVICE_CONTROL = 0x0E.
MJ_DEVICE_CONTROL = 0x0E
# _IRP offsets (x86): AssociatedIrp.SystemBuffer, IoStatus.{Status,Information},
# Tail.Overlay.CurrentStackLocation.
IRP_SYSTEMBUFFER = 0x0C
IRP_IOSTATUS = 0x18
IRP_USERBUFFER = 0x3C       # output buffer for METHOD_NEITHER / METHOD_OUT_DIRECT
IRP_CURRENT_STACK = 0x60
# _IO_STACK_LOCATION offsets (x86) for a device-control request.
IOSL_MAJOR = 0x00
IOSL_OUTLEN = 0x04
IOSL_INLEN = 0x08
IOSL_IOCTL = 0x0C
IOSL_TYPE3INPUT = 0x10      # input buffer for METHOD_NEITHER


def _align(v, a=0x1000):
    return (v + a - 1) & ~(a - 1)


class Secdrv:
    def __init__(self, sys_path):
        self.pe = pefile.PE(sys_path)
        oh = self.pe.OPTIONAL_HEADER
        self.base = oh.ImageBase
        self.entry = self.base + oh.AddressOfEntryPoint
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.names = {}
        self.pool = POOL + 0x1000
        self.completed = None
        self._map()
        self._driver_entry()

    # ---- helpers
    def _w32(self, a, v):
        self.uc.mem_write(a, struct.pack('<I', v & 0xFFFFFFFF))

    def _r32(self, a):
        return struct.unpack('<I', self.uc.mem_read(a, 4))[0]

    def _alloc(self, n):
        a = self.pool
        self.pool = _align(self.pool + n, 16)
        return a

    def _thunk(self, name):
        a = THUNK + 4 * len(self.names)
        self.names[a] = name
        return a

    # ---- setup
    def _map(self):
        uc = self.uc
        size = max(_align(self.pe.OPTIONAL_HEADER.SizeOfImage), 0x4000)
        uc.mem_map(self.base, size, UC_PROT_ALL)
        uc.mem_write(self.base, self.pe.get_memory_mapped_image()[:size])
        for a, s in ((THUNK, 0x1000), (DATA, 0x1000), (STACK, SSZ), (POOL, POOL_SIZE)):
            uc.mem_map(a, s, UC_PROT_ALL)
        for imp in self.pe.DIRECTORY_ENTRY_IMPORT:
            for i in imp.imports:
                name = i.name.decode()
                if name in ('KeTickCount', 'NtBuildNumber'):
                    # Data exports: the IAT slot holds the address of the variable.
                    # KeTickCount is a 3-dword KSYSTEM_TIME; the driver spins until
                    # High1Time(+4)==High2Time(+8), so it needs its own zeroed region
                    # well clear of NtBuildNumber (one dword) -- else the two overlap
                    # and the stable-read spin never terminates.
                    var = DATA + (0x00 if name == 'KeTickCount' else 0x40)
                    if name == 'NtBuildNumber':
                        self._w32(var, 2195)
                    self._w32(i.address, var)
                else:
                    self._w32(i.address, self._thunk(name))
        uc.hook_add(UC_HOOK_CODE, self._ntos, begin=THUNK, end=THUNK + 0x1000)

    def _ntos(self, uc, addr, size, _):
        name = self.names.get(addr)
        if not name:
            return
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret = self._r32(esp)
        arg = lambda n: self._r32(esp + 4 + 4 * n)  # noqa: E731
        if name == 'IofCompleteRequest':
            # fastcall: Irp in ECX, no stack args. The IRP is finished here, so
            # record its result and stop -- no need to unwind the dispatch.
            irp = uc.reg_read(UC_X86_REG_ECX)
            self.completed = (self._r32(irp + IRP_IOSTATUS),
                              self._r32(irp + IRP_IOSTATUS + 4))
            uc.emu_stop()
            return
        argc, val = 0, 0
        if name == 'IoCreateDevice':                 # (...,[6]=*DeviceObject)
            dev = self._alloc(0x100)
            if arg(6):
                self._w32(arg(6), dev)
            argc = 7
        elif name == 'RtlEqualUnicodeString':
            argc, val = 3, 1                          # names match -> take driver's path
        elif name == 'RtlQueryRegistryValues':
            argc = 5                                  # STATUS_SUCCESS, no values touched
        else:
            argc = {'RtlInitUnicodeString': 2, 'IoCreateSymbolicLink': 2,
                    'IoDeleteSymbolicLink': 1, 'IoDeleteDevice': 1}.get(name, 0)
        uc.reg_write(UC_X86_REG_EAX, val)
        uc.reg_write(UC_X86_REG_EIP, ret)
        uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4 * argc)

    def _driver_entry(self):
        uc = self.uc
        self.drvobj = self._alloc(0x200)
        uc.mem_write(self.drvobj, b'\0' * 0x200)
        regpath = self._alloc(0x20)
        uc.mem_write(regpath, b'\0' * 0x20)
        sp = STACK + SSZ - 0x100
        uc.mem_write(sp, struct.pack('<III', 0xDEADBEEF, self.drvobj, regpath))
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.emu_start(self.entry, 0xDEADBEEF, count=2_000_000)
        mj = struct.unpack('<28I', uc.mem_read(self.drvobj + 0x38, 28 * 4))
        self.dispatch = mj[MJ_DEVICE_CONTROL]
        if not self.dispatch:
            raise RuntimeError('secdrv DriverEntry set no DEVICE_CONTROL handler')

    # ---- the one call the loader needs
    def ioctl(self, code, indata, outlen):
        """Run one device-control IRP (the buffering method is taken from the low
        two bits of `code`). Returns (status, info, out)."""
        uc = self.uc
        self.pool = SCRATCH                           # reuse scratch (loader retries ~256x)
        method = code & 3                             # 0 BUFFERED, 1/2 DIRECT, 3 NEITHER
        inbuf = self._alloc(len(indata) + 0x10)
        uc.mem_write(inbuf, bytes(indata) + b'\0' * 0x10)
        outds = self._alloc(outlen + 0x10)
        uc.mem_write(outds, b'\0' * (outlen + 0x10))
        irp = self._alloc(0x200)
        uc.mem_write(irp, b'\0' * 0x200)
        iosl = self._alloc(0x40)
        uc.mem_write(iosl, b'\0' * 0x40)
        if method == 3:                               # METHOD_NEITHER (0xEF002407)
            self._w32(iosl + IOSL_TYPE3INPUT, inbuf)
            self._w32(irp + IRP_USERBUFFER, outds)
        else:                                         # BUFFERED: one shared SystemBuffer
            outds = inbuf
            self._w32(irp + IRP_SYSTEMBUFFER, inbuf)
        self._w32(irp + IRP_CURRENT_STACK, iosl)
        uc.mem_write(iosl + IOSL_MAJOR, bytes([MJ_DEVICE_CONTROL]))
        self._w32(iosl + IOSL_OUTLEN, outlen)
        self._w32(iosl + IOSL_INLEN, len(indata))
        self._w32(iosl + IOSL_IOCTL, code)
        self.completed = None
        sp = STACK + SSZ - 0x400
        uc.mem_write(sp, struct.pack('<III', 0xDEADBEEF, self.drvobj, irp))
        uc.reg_write(UC_X86_REG_ESP, sp)
        try:
            uc.emu_start(self.dispatch, 0xDEADBEEF, count=20_000_000)
        except UcError:
            pass                                      # completion stops us; a later fault is harmless
        status, info = self.completed or (0xC0000001, 0)
        out = bytes(uc.mem_read(outds, outlen))
        return status, info, out


def _selftest():
    import os
    p = None
    for c in (r'G:\recomp\pc\fs2000\game\SECDRV.SYS',):
        if os.path.exists(c):
            p = c
            break
    assert p, 'no SECDRV.SYS to self-test against'
    s = Secdrv(p)
    assert s.dispatch, 'no dispatch captured'
    # Dummy input must be *rejected* cleanly (STATUS_UNSUCCESSFUL), not crash the host.
    status, info, out = s.ioctl(0xEF002407, bytes(range(256)) * 6, 1552)
    assert status == 0xC0000001, 'expected dummy input rejected, got 0x%08x' % status
    assert len(out) == 1552
    print('secdrv self-test ok: dispatch=0x%08x, dummy rejected (0x%08x)' % (s.dispatch, status))


if __name__ == '__main__':
    _selftest()
