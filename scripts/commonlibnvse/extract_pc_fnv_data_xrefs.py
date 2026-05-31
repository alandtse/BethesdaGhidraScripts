#!/usr/bin/env python3
"""Build a {data_va -> set(pc_fn_va)} xref table for PC FalloutNV.exe.

For every 4-byte LE window in .text that points into a R/W data section
(.rdata/.data/.bss/.tls -- anything non-executable, NOT the string VAs
we've already covered separately), record the byte position as a data
xref.  Walk back to the enclosing function start via INT3-padding
heuristic.

Output: ``0x<data_va>|0x<fn_va>|<count>`` per line.

Run:
    python extract_pc_fnv_data_xrefs.py <FalloutNV.exe> <strings.txt> <out.txt>
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import Dict, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_pc_fnv_string_xrefs import (
    parse_pe_x86, load_strings, find_function_start_for_offset,
)


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    exe_path     = Path(sys.argv[1])
    strings_path = Path(sys.argv[2])
    out_path     = Path(sys.argv[3])

    print(f'Loading strings to exclude (already handled): {strings_path}')
    string_vas = set(load_strings(strings_path).keys())
    print(f'  {len(string_vas):,} string VAs to exclude')

    print(f'Parsing PE: {exe_path}')
    data, image_base, sects = parse_pe_x86(exe_path)

    # Collect non-executable data section VA ranges
    data_ranges = []  # [(start_va, end_va)]
    text_sect = None
    for s in sects:
        is_exec = bool(s['chars'] & 0x20000000)
        is_read = bool(s['chars'] & 0x40000000)
        if is_exec:
            text_sect = s
            continue
        if not is_read or s['vsize'] == 0:
            continue
        start_va = image_base + s['vaddr']
        end_va = start_va + s['vsize']
        data_ranges.append((start_va, end_va, s['name']))
        print(f'  data range: {s["name"]:8s} 0x{start_va:08X}..0x{end_va:08X}')
    assert text_sect is not None
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']

    def in_data(va):
        for start, end, _ in data_ranges:
            if start <= va < end:
                return True
        return False

    print(f'Scanning .text ({len(text_bytes):,} bytes) for data xrefs...')
    data_to_funcs: Dict[int, Dict[int, int]] = {}
    n_xrefs = 0
    n_resolved = 0
    n_skipped_string = 0
    for i in range(0, len(text_bytes) - 4):
        va = (text_bytes[i] | (text_bytes[i+1] << 8) |
              (text_bytes[i+2] << 16) | (text_bytes[i+3] << 24))
        if not in_data(va):
            continue
        # Filter for 4-byte-aligned targets only -- globals/statics in MSVC
        # are at least DWORD-aligned, so an unaligned ``target'' is almost
        # always a coincidental 4-byte window inside a larger string/struct.
        if va & 0x3:
            continue
        if va in string_vas:
            n_skipped_string += 1
            continue
        n_xrefs += 1
        fn_va = find_function_start_for_offset(text_bytes, text_vaddr, i)
        if fn_va == 0:
            continue
        n_resolved += 1
        d = data_to_funcs.setdefault(va, {})
        d[fn_va] = d.get(fn_va, 0) + 1

    print(f'  data xrefs (excl. strings): {n_xrefs:,}  resolved: {n_resolved:,}')
    print(f'  excluded as strings: {n_skipped_string:,}')
    print(f'  unique data VAs xref\'d: {len(data_to_funcs):,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# PC FNV data xrefs: 0x<data_va>|0x<fn_va>|<count>\n')
        for data_va, fn_counts in sorted(data_to_funcs.items()):
            for fn_va, count in sorted(fn_counts.items(), key=lambda kv: -kv[1]):
                f.write(f'0x{data_va:08X}|0x{fn_va:08X}|{count}\n')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
