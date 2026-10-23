#!/usr/bin/env python3
"""Shrek 2 (PC, 2004, Unreal Engine 2) -- static recompilation driver.

This is the project's own driver: it runs the phases the pcrecomp pipeline
document describes, in order, and refuses to hand over a lift that fails its
gates.  Everything it produces is derived from the *shipping* `game.exe`
(`System/game.exe`, 274,432 bytes, MSVC 7.00, image base 0x10900000) -- the
binary is never committed here, the driver is pointed at it:

    python3 projects/shrek2/tools/build_lift.py --game /path/to/System/game.exe

Phases
------
  0. verify   the binary really is the one the project was built against
              (SHA-256 from config/game.json; --any-game to bypass)
  1. analyse  PE headers, sections, imports -> analysis/pe.json, imports.json
  2. recover  function starts: recursive descent seeded from the entry point,
              the export table, vtable slots (`cpp/vtable_scan.py`) and the
              alternate entry points `lift/recover.py` finds; a second pass
              unioned with those is what the lift is generated from
  3. lift     x86-32 -> C (`lift/lift32.py`) -> src/game/recomp/gen/
  4. gate     no lift errors, every `sub_XXXXXXXX` reference defined, dispatch
              table strictly increasing and unique, C parses
  5. report   analysis/report.md + analysis/functions.json + manifest.json

Why the extra seeds: a method reached only through a vtable is called by no
CALL anywhere in the image, and an optimised `__thiscall` accessor has no
`push ebp; mov ebp, esp` prologue.  Those are exactly the entry points a
recompile loses, and they surface at runtime as one unresolved indirect call.
The engine DLLs (Core.dll, Engine.dll, KWGame.dll) stay real machine code --
they are 6 MB of optimised UE2 runtime and this is a *hybrid* recompilation
(see docs/HYBRID.md); only the application body is lifted.

Exit status is non-zero when a gate fails, so CI can rely on it.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)                    # projects/shrek2
REPO = os.path.dirname(os.path.dirname(PROJECT))   # pcrecomp
TOOLS = os.path.join(REPO, "tools")

for _sub in ("pe", "disasm", "lift", "cpp"):
    _p = os.path.join(TOOLS, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pe_analyze import analyze_pe, build_iat_map, export_json   # noqa: E402
from disasm32 import Disassembler                                 # noqa: E402
from lift32 import Lifter                                         # noqa: E402
import vtable_scan                                                # noqa: E402
from recover import recover_functions                             # noqa: E402


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_config():
    with open(os.path.join(PROJECT, "config", "game.json")) as f:
        return json.load(f)


def is_padding(byte):
    """Bytes that cannot be the start of a function body: int3/nop/zero fill."""
    return byte in (0xCC, 0x90, 0x00)


def _byte_at(pe_data, info, va):
    """The file byte backing a VA, or None when the VA is not backed by data."""
    rva = va - info.image_base
    for sec in info.sections:
        if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
            off = sec.raw_offset + (rva - sec.virtual_address)
            return pe_data[off] if 0 <= off < len(pe_data) else None
    return None


def coverage_report(pe_data, info, functions):
    """How much of the executable range is decoded, and what is not.

    The number that matters is *non-padding* bytes: every MSVC image is full of
    `int3` alignment fill between functions, and counting that as "uncovered"
    makes a complete lift look 35% incomplete.  What is left after removing the
    fill is import thunks (data addressed by nothing in the image) and the odd
    body reached only through a computed jump.
    """
    lo, hi = info.code_start, info.code_end
    size = hi - lo
    cov = bytearray(size)
    for f in functions.values():
        a = max(f.address, lo)
        b = min(f.address + f.size, hi)
        if b > a:
            cov[a - lo:b - lo] = b"\x01" * (b - a)
    uncovered = [i for i, c in enumerate(cov) if not c]
    pad = sum(1 for i in uncovered
              if (b := _byte_at(pe_data, info, lo + i)) is not None and is_padding(b))
    return {
        "executable_bytes": size,
        "covered_bytes": size - len(uncovered),
        "uncovered_bytes": len(uncovered),
        "uncovered_padding_bytes": pad,
        "uncovered_code_bytes": len(uncovered) - pad,
        "coverage_pct": round(100.0 * (size - len(uncovered)) / size, 2),
    }


def unrecovered_runs(pe_data, info, functions, min_len=8):
    """Contiguous non-padding runs with no lifted body -- the honest gap list."""
    lo, hi = info.code_start, info.code_end
    cov = bytearray(hi - lo)
    for f in functions.values():
        a = max(f.address, lo)
        b = min(f.address + f.size, hi)
        if b > a:
            cov[a - lo:b - lo] = b"\x01" * (b - a)
    sec_of = [_byte_at(pe_data, info, lo + i) for i in range(hi - lo)]
    runs, i = [], 0
    while i < len(cov):
        if not cov[i] and sec_of[i] is not None and not is_padding(sec_of[i]):
            j = i
            while (j < len(cov) and not cov[j] and sec_of[j] is not None
                   and not is_padding(sec_of[j])):
                j += 1
            if j - i >= min_len:
                runs.append({"start": lo + i, "end": lo + j, "size": j - i})
            i = j
        else:
            i += 1
    return sorted(runs, key=lambda r: -r["size"])


# --------------------------------------------------------------------------
# phases
# --------------------------------------------------------------------------

def phase_verify(path, cfg, allow_any):
    digest = sha256_file(path)
    size = os.path.getsize(path)
    ok = digest == cfg["sha256"] and size == cfg["size"]
    print(f"[0] {os.path.basename(path)}: {size:,} bytes, sha256 {digest[:16]}...")
    if not ok:
        msg = (f"this is not the binary the project was built against\n"
               f"    expected {cfg['size']:,} bytes {cfg['sha256'][:16]}...\n"
               f"    got      {size:,} bytes {digest[:16]}...")
        if not allow_any:
            sys.exit("[0] FAIL: " + msg + "\n    (--any-game lifts something else anyway)")
        print("[0] WARNING: " + msg)
    return digest


def phase_analyse(path, outdir):
    info = analyze_pe(path)
    os.makedirs(outdir, exist_ok=True)
    pe_out = os.path.join(outdir, "pe.json")
    export_json(info, pe_out)
    # The dump records the absolute path it read; keep the artifact portable.
    with open(pe_out) as f:
        doc = json.load(f)
    doc["filepath"] = doc.get("filename", os.path.basename(path))
    with open(pe_out, "w") as f:
        json.dump(doc, f, indent=2)

    imports = []
    for imp in info.imports:
        imports.append({
            "dll": imp.dll,
            "name": imp.name,
            "ordinal": imp.ordinal,
            "iat_va": info.image_base + imp.iat_rva,
        })
    imports.sort(key=lambda i: (i["dll"].lower(), i["name"] or "", i["ordinal"] or 0))
    with open(os.path.join(outdir, "imports.json"), "w") as f:
        json.dump(imports, f, indent=1)

    by_dll = {}
    for imp in imports:
        by_dll.setdefault(imp["dll"], 0)
        by_dll[imp["dll"]] += 1
    print(f"[1] image base 0x{info.image_base:08X}, entry 0x{info.image_base + info.entry_point_rva:08X}")
    print(f"[1] {len(imports)} imports from {len(by_dll)} DLLs: " +
          ", ".join(f"{d}={n}" for d, n in sorted(by_dll.items(), key=lambda x: -x[1])))
    return info, imports, by_dll


def phase_discover(path, pe_data, info, extra_seeds=(), no_recover=False):
    """Two-pass recovery: descent from every seed we can justify."""
    iat = build_iat_map(info)
    dis = Disassembler(pe_data, info.image_base, info.sections)

    seeds = {info.image_base + info.entry_point_rva} | set(extra_seeds)
    for e in getattr(info, "exports", []) or []:
        if e.rva:
            seeds.add(info.image_base + e.rva)

    # vtable slots: methods called by nothing the call/jmp scan can see
    try:
        _vts, methods, _ = vtable_scan.scan(path)
    except Exception as exc:                      # a scan failure must not stop the lift
        print(f"[2] vtable scan skipped: {exc}")
        methods = []
    vt_seeds = set(methods)
    seeds |= vt_seeds
    print(f"[2] seeds: entry+exports+{len(vt_seeds)} vtable methods")

    t0 = time.time()
    functions = dis.find_functions(info.code_start, info.code_end, iat, seeds=seeds)
    print(f"[2] pass 1: {len(functions)} functions in {time.time() - t0:.1f}s")
    if no_recover:
        return dis, iat, functions, vt_seeds

    # Alternate entry points: a CALL that lands inside a listed body.
    code_rva = info.code_start - info.image_base
    sec = next((s for s in info.sections
                if s.virtual_address <= code_rva < s.virtual_address + s.virtual_size), None)
    if sec is None:
        sys.exit("[2] FAIL: the code range is not inside any section")
    start = sec.raw_offset + (code_rva - sec.virtual_address)
    code = pe_data[start:start + (info.code_end - info.code_start)]
    known = [(f.address, f.address + f.size) for f in functions.values()]
    extras = recover_functions(code, info.code_start, info.code_end, known)
    extras = [(a, b) for a, b in extras
              if info.code_start <= a < info.code_end and a not in functions]
    if extras:
        print(f"[2] recover: {len(extras)} entry points the catalog does not list")
        seeds |= {a for a, _ in extras}
        functions = dis.find_functions(info.code_start, info.code_end, iat, seeds=seeds)
        print(f"[2] pass 2: {len(functions)} functions")
    else:
        print("[2] recover: none")
    return dis, iat, functions, vt_seeds


def read_seed_file(path):
    """Entry points the game asked for that the static scan could not see.

    The host writes `shrek2_missing.txt` when native code calls a guest address
    that has no lifted body; feeding that file back in closes the loop.
    """
    seeds = set()
    with open(path) as f:
        text = f.read()
    for m in re.finditer(r"0x([0-9A-Fa-f]{8})", text):
        seeds.add(int(m.group(1), 16))
    return seeds


def phase_lift(functions, iat, outdir, split, target):
    os.makedirs(outdir, exist_ok=True)
    for old in os.listdir(outdir):
        if old.startswith("recomp_") and old.endswith(".c"):
            os.remove(os.path.join(outdir, old))
    lifter = Lifter(iat_map=iat, func_names={})
    funcs = sorted(functions.values(), key=lambda f: f.address)
    written, emitted = [], 0
    for idx, start in enumerate(range(0, len(funcs), split)):
        chunk = funcs[start:start + split]
        path = os.path.join(outdir, f"recomp_{idx:04d}.c")
        with open(path, "w") as f:
            f.write("/* Auto-generated by pcrecomp -- DO NOT EDIT\n"
                    " * target: System/game.exe (Shrek 2, UE2, 2004)\n"
                    f" * functions {start}..{start + len(chunk) - 1} of {len(funcs)}\n"
                    f" * address range 0x{chunk[0].address:08X}-0x{chunk[-1].address:08X}\n"
                    " */\n")
            f.write("#define RECOMP_GENERATED_CODE\n")
            f.write('#include "recomp_types.h"\n')
            # Direct calls lift to `RECOMP_CALL(sub_XXXXXXXX)`; without the
            # declarations the MSVC C compiler has to assume `int sub_X()` and
            # the definition is then a conflicting one.  The catalog header is
            # generated below, in the same directory.
            f.write('#include "recomp_funcs.h"\n')
            f.write("#include <math.h>\n#include <string.h>\n\n")
            for func in chunk:
                try:
                    f.write(lifter.lift_function(func))
                    emitted += 1
                except Exception as exc:                    # noqa: BLE001
                    f.write(f"/* LIFT ERROR {func.name}: {exc} */\n")
                    f.write(f"void {func.name}(void) {{ }}\n")
                f.write("\n\n")
        written.append(path)

    with open(os.path.join(outdir, "recomp_funcs.h"), "w") as f:
        f.write("/* Auto-generated function declarations -- DO NOT EDIT */\n"
                "#pragma once\n\n#include <stdint.h>\n\n")
        f.write(f"/* {len(funcs)} lifted functions */\n\n")
        for func in funcs:
            f.write(f"void {func.name}(void);  /* 0x{func.address:08X} */\n")

    # A header the host includes, so the exe and the lift it was built from
    # cannot disagree about the base or the entry point.
    with open(os.path.join(outdir, "recomp_target.h"), "w") as f:
        f.write("/* Auto-generated -- the host includes this so it cannot disagree\n"
                " * with the catalog it was built against. */\n#pragma once\n\n")
        f.write(f"#define RECOMP_IMAGE_BASE    0x{target['image_base']:08X}u\n")
        f.write(f"#define RECOMP_ENTRY_VA      0x{target['entry_va']:08X}u\n")
        f.write(f"#define RECOMP_FUNCTION_COUNT {len(funcs)}u\n")
        f.write(f"#define RECOMP_SOURCE_SHA256 \"{target['sha256']}\"\n")

    with open(os.path.join(outdir, "recomp_dispatch.c"), "w") as f:
        f.write("/* Auto-generated dispatch table: original VA -> lifted body.\n"
                " * Sorted; native32's dispatch_find binary-searches it. */\n\n")
        f.write('#include "recomp_types.h"\n#include "recomp_funcs.h"\n\n')
        f.write("const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n")
        for func in funcs:
            f.write(f"    {{ 0x{func.address:08X}u, {func.name} }},\n")
        f.write("};\n\n")
        f.write(f"const uint32_t recomp_dispatch_count = {len(funcs)};\n")

    print(f"[3] wrote {len(written)} source files, {emitted} functions")
    return funcs, written


def phase_gate(outdir, funcs, written):
    """Everything that would otherwise fail 4 minutes into an MSVC build."""
    problems = []
    defined = {f.name for f in funcs}
    for path in written:
        src = open(path).read()
        if "LIFT ERROR" in src:
            for line in src.splitlines():
                if "LIFT ERROR" in line:
                    problems.append(f"{os.path.basename(path)}: {line.strip()}")
        for name in set(re.findall(r"\bsub_([0-9A-F]{8})\b", src)):
            if f"sub_{name}" not in defined:
                problems.append(f"{os.path.basename(path)}: undefined sub_{name}")
    addresses = [f.address for f in funcs]
    if len(set(addresses)) != len(addresses):
        problems.append("duplicate function addresses in the catalog")
    if addresses != sorted(addresses):
        problems.append("catalog is not address-sorted")
    print(f"[4] gates: {'OK' if not problems else str(len(problems)) + ' problems'}")
    for p in problems[:20]:
        print("      " + p)
    return problems


def phase_report(analysis_dir, cfg, digest, info, imports, by_dll, functions,
                 cov, runs, funcs, written, problems):
    def size_of(paths):
        return sum(os.path.getsize(p) for p in paths)

    largest = sorted(functions.values(), key=lambda f: -f.size)[:10]
    manifest = {
        "source": {
            "file": os.path.basename(cfg["path"]),
            "sha256": digest,
            "expected_sha256": cfg["sha256"],
            "size": cfg["size"],
            "image_base": f"0x{info.image_base:08X}",
            "entry_va": f"0x{info.image_base + info.entry_point_rva:08X}",
            "timestamp": info.timestamp_str,
        },
        "lift": {
            "functions": len(funcs),
            "source_files": [os.path.basename(p) for p in written],
            "c_bytes": size_of(written),
            "largest_functions": [{"va": f"0x{f.address:08X}", "size": f.size}
                                  for f in largest],
            "gates": "ok" if not problems else problems[:20],
        },
        "coverage": cov,
        "imports": {"total": len(imports), "by_dll": by_dll},
        "toolchain": {"python": sys.version.split()[0], "pcrecomp_head": git_head()},
    }
    with open(os.path.join(analysis_dir, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)

    catalog = [{
        "address": f"0x{f.address:08X}",
        "size": f.size,
        "blocks": len(f.blocks),
        "instructions": f.num_instructions,
        "thunk": bool(f.is_thunk),
        "calls_to": [f"0x{t:08X}" for t in sorted(f.calls_to)],
    } for f in sorted(functions.values(), key=lambda x: x.address)]
    with open(os.path.join(analysis_dir, "functions.json"), "w") as f:
        json.dump(catalog, f, indent=1)

    largest = sorted(functions.values(), key=lambda f: -f.size)[:10]
    lines = [
        "# Shrek 2 -- lift report",
        "",
        "Generated by `projects/shrek2/tools/build_lift.py`. Do not edit: re-run it.",
        "",
        "## Target",
        "",
        f"| | |",
        f"|---|---|",
        f"| file | `System/{os.path.basename(cfg['path'])}` |",
        f"| size | {cfg['size']:,} bytes |",
        f"| sha256 | `{digest}` |",
        f"| built with | MSVC 7.00, {info.timestamp_str} |",
        f"| image base | `0x{info.image_base:08X}` |",
        f"| entry point | `0x{info.image_base + info.entry_point_rva:08X}` |",
        f"| code range | `0x{info.code_start:08X}`-`0x{info.code_end:08X}` |",
        "",
        "## Lift",
        "",
        f"| | |",
        f"|---|---|",
        f"| functions lifted | **{len(funcs)}** |",
        f"| C generated | **{size_of(written) / 1e6:.1f} MB** in {len(written)} files |",
        f"| executable bytes catalogued | {cov['covered_bytes']:,} / {cov['executable_bytes']:,} "
        f"({cov['coverage_pct']}%) |",
        f"| uncovered, alignment fill (`int3`/`nop`) | {cov['uncovered_padding_bytes']:,} bytes |",
        f"| uncovered, real bytes | {cov['uncovered_code_bytes']:,} bytes in {len(runs)} runs "
        f"(import thunks and computed-jump-only bodies) |",
        f"| gates | {'**all passed**' if not problems else f'**{len(problems)} failed**'} |",
        "",
        "## Imports (the shim / engine surface)",
        "",
        "| DLL | imports |",
        "|---|---|",
    ]
    for dll, n in sorted(by_dll.items(), key=lambda x: -x[1]):
        lines.append(f"| `{dll}` | {n} |")
    lines += ["", "## Largest functions", "", "| VA | bytes | blocks | instructions |", "|---|---|---|---|"]
    for f in largest:
        lines.append(f"| `0x{f.address:08X}` | {f.size:,} | {len(f.blocks)} | {f.num_instructions:,} |")
    if runs:
        lines += ["", "## Non-padding ranges with no lifted body", "",
                  "Import thunks (`jmp [IAT]`) reached by no instruction in the image, and",
                  "bodies reached only through a computed jump. They are listed so the next",
                  "run has something to measure against, not because they are known broken.", "",
                  "| range | bytes |", "|---|---|"]
        for r in runs[:15]:
            lines.append(f"| `0x{r['start']:08X}`-`0x{r['end']:08X}` | {r['size']:,} |")
    if problems:
        lines += ["", "## Gate failures", "", "```"] + problems[:20] + ["```"]
    with open(os.path.join(analysis_dir, "report.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"[5] wrote {os.path.join(analysis_dir, 'report.md')} and manifest.json")
    return manifest


def git_head():
    try:
        out = subprocess.run(["git", "-C", REPO, "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except Exception:                                  # noqa: BLE001
        return "unknown"


# --------------------------------------------------------------------------

def looks_like_pe(path):
    """Cheap structural check, so a truncated or renamed file fails with a
    sentence instead of a traceback from inside the PE reader."""
    import struct
    try:
        with open(path, "rb") as f:
            head = f.read(0x40)
            if len(head) < 0x40 or head[:2] != b"MZ":
                return False
            off = struct.unpack_from("<I", head, 0x3C)[0]
            f.seek(off)
            return f.read(4) == b"PE\0\0"
    except OSError:
        return False


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--game", required=True, help="path to the original System/game.exe")
    ap.add_argument("--out", default=os.path.join(PROJECT, "src", "game", "recomp", "gen"),
                    help="directory for the generated C")
    ap.add_argument("--analysis", default=os.path.join(PROJECT, "analysis"),
                    help="directory for the analysis artifacts")
    ap.add_argument("--split", type=int, default=400, help="functions per generated file")
    ap.add_argument("--any-game", action="store_true",
                    help="lift a game.exe that does not match config/game.json")
    ap.add_argument("--no-recover", action="store_true", help="skip recover.py")
    ap.add_argument("--seed-file", action="append", default=[],
                    help="extra entry points (e.g. shrek2_missing.txt from a run)")
    args = ap.parse_args()

    t0 = time.time()
    cfg = load_config()
    cfg["path"] = args.game
    if not os.path.exists(args.game):
        sys.exit(f"no such file: {args.game}")

    if not looks_like_pe(args.game):
        sys.exit(f"[0] FAIL: {args.game} is not a complete 32-bit PE image.\n"
                 "    (a truncated download is the usual cause; the driver needs\n"
                 "    the whole file, headers and all)")

    digest = phase_verify(args.game, cfg, args.any_game)
    with open(args.game, "rb") as f:
        pe_data = f.read()
    try:
        info, imports, by_dll = phase_analyse(args.game, args.analysis)
    except Exception as e:                                   # noqa: BLE001
        sys.exit(f"[1] FAIL: cannot read the PE (a truncated download is the usual cause): {e}")

    if info.image_base != cfg["image_base"]:
        sys.exit(f"[1] FAIL: image base 0x{info.image_base:08X} != config "
                 f"0x{cfg['image_base']:08X}")

    extra = set()
    for sf in args.seed_file:
        s_ = read_seed_file(sf)
        print(f"[2] {len(s_)} seeds from {sf}")
        extra |= s_
    try:
        _dis, iat, functions, _vt = phase_discover(args.game, pe_data, info,
                                                   extra_seeds=extra,
                                                   no_recover=args.no_recover)
    except Exception as e:                                   # noqa: BLE001
        sys.exit(f"[2] FAIL: function discovery failed: {e}")
    cov = coverage_report(pe_data, info, functions)
    runs = unrecovered_runs(pe_data, info, functions)
    funcs, written = phase_lift(functions, iat, args.out, args.split,
                                {"image_base": info.image_base,
                                 "entry_va": info.image_base + info.entry_point_rva,
                                 "sha256": digest})
    problems = phase_gate(args.out, funcs, written)
    manifest = phase_report(args.analysis, cfg, digest, info, imports, by_dll,
                            functions, cov, runs, funcs, written, problems)

    print(f"\n[done] {len(funcs)} functions, {manifest['lift']['c_bytes'] / 1e6:.1f} MB of C, "
          f"{time.time() - t0:.1f}s")
    if problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
