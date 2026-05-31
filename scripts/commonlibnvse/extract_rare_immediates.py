#!/usr/bin/env python3
"""Extract rare 32-bit immediate constants from PC FalloutNV.exe.

A "rare" immediate is one that appears in only a few functions in
.text.  These are useful as cross-binary fingerprints (game IDs, hash
seeds, format-version magic, etc.) -- a function using a unique 32-bit
magic in Xbox + the same magic in PC FNV is very likely the same
function across builds.

We intentionally do NOT scan Xbox here -- PowerPC immediate encoding
spans multiple instruction forms (li/addi/addis/ori/lis) and would
need a real PPC parser.  Instead we emit PC-side rare immediates with
their xref-er function RVAs, ready for manual pairing or future
Xbox-side extraction.

Detected x86 patterns (single-instruction):
  0x68 imm32          push imm32
  0xB8-0xBF imm32     mov r32, imm32      (8 register variants)
  0x3D imm32          cmp eax, imm32
  0xA1 imm32          mov eax, [imm32]

Output: ``<imm>|<count>|<comma-separated fn_va list>`` per line, sorted
by count ascending (rarest first).

Run:
    python extract_rare_immediates.py <FalloutNV.exe> <out.txt> [max_count]
"""
from __future__ import annotations

import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_pc_fnv_string_xrefs import (
    parse_pe_x86, find_function_start_for_offset,
)

# Opcodes that take a 32-bit immediate at the NEXT byte
# (i.e. opcode_byte at i, imm32 at i+1)
_OPCODE_IMM32 = {
    0x68,                     # push imm32
    0xB8, 0xB9, 0xBA, 0xBB,   # mov eax/ecx/edx/ebx, imm32
    0xBC, 0xBD, 0xBE, 0xBF,   # mov esp/ebp/esi/edi, imm32
    0x3D,                     # cmp eax, imm32
    0xA1, 0xA3,               # mov eax,[imm32] / mov [imm32],eax
    0xA0, 0xA2,               # mov al,[imm32] / mov [imm32],al (actually 32-bit addr)
}

# Common immediates we don't care about
_BORING = set(range(0, 256)) | {
    0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFC, 0xFFFFFFF8,
    0x00010000, 0xFFFF0000, 0x0000FFFF, 0x80000000,
    0x7FFFFFFF, 0x40000000, 0x20000000, 0x10000000,
    0x00010000, 0x00020000, 0x00040000, 0x00080000,
    0x00100000, 0x00200000, 0x00400000, 0x00800000,
}


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    exe_path  = Path(sys.argv[1])
    out_path  = Path(sys.argv[2])
    max_count = int(sys.argv[3]) if len(sys.argv) > 3 else 3

    print(f'Parsing PE: {exe_path}')
    data, image_base, sects = parse_pe_x86(exe_path)
    text_sect = next(s for s in sects if s['chars'] & 0x20000000)
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    n = len(text_bytes)
    print(f'.text: 0x{text_vaddr:08X} ({n:,} bytes)')

    print('Scanning for 32-bit immediates...')
    imm_to_fns: dict = defaultdict(lambda: defaultdict(int))
    n_total = 0
    n_filtered = 0
    for i in range(n - 5):
        op = text_bytes[i]
        if op not in _OPCODE_IMM32:
            continue
        imm = (text_bytes[i+1] | (text_bytes[i+2] << 8) |
               (text_bytes[i+3] << 16) | (text_bytes[i+4] << 24))
        n_total += 1
        if imm in _BORING:
            n_filtered += 1
            continue
        # Filter out values that look like in-image addresses (covered
        # by string/data xref tooling already).  Image is 0x400000..0x14089E4.
        if 0x00400000 <= imm < 0x01500000:
            continue
        fn_va = find_function_start_for_offset(text_bytes, text_vaddr, i)
        if fn_va == 0:
            continue
        imm_to_fns[imm][fn_va] += 1
    print(f'  total imm32s observed: {n_total:,}')
    print(f'  boring/skipped: {n_filtered:,}')
    print(f'  distinct rare imm32 values: {len(imm_to_fns):,}')

    # Filter to "rare" (small fn set)
    rare = [(imm, fns) for imm, fns in imm_to_fns.items()
            if len(fns) <= max_count]
    print(f'  rare (used in <={max_count} fns): {len(rare):,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write(f'# rare PC FNV imm32s (used in <={max_count} fns)\n')
        f.write(f'# format: 0x<imm>|<fn_count>|<fn_va,fn_va,...>\n')
        for imm, fns in sorted(rare, key=lambda kv: (len(kv[1]), kv[0])):
            fn_list = ','.join(f'0x{v:08X}' for v in sorted(fns))
            f.write(f'0x{imm:08X}|{len(fns)}|{fn_list}\n')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
