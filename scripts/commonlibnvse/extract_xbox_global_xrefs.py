#!/usr/bin/env python3
"""Find Xbox xrefs to each PDB global/static data symbol.

PDB publics with the ``@@3`` infix (e.g. ``?gFoo@@3HA``) are data
symbols, not functions.  For each such symbol's RVA, run the same PPC
lis+addi/ori pair-recovery scanner used by ``extract_xbox_string_xrefs.py``
to find every code instruction that materializes its address.

Output: ``<mangled_name>|0x<global_rva>|<xbox_fn_name>|<count>`` per line.

Run:
    python extract_xbox_global_xrefs.py <Xbox.exe> <publics_dump> <out.txt>
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Reuse PPC scanner + PE parsing from the string xref module
sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_xbox_string_xrefs import (
    parse_xbox_pe, is_text,
    scan_ppc_string_xrefs,
    load_publics, build_function_ranges, function_at_rva,
)


_GLOBAL_RE = re.compile(r'\s*public\s+\[0x([0-9A-Fa-f]+)\]\s+(\?\w[\w@]*@@3\S*)\s*$')


def load_globals(path: Path) -> List[Tuple[int, str]]:
    """Pull every ``?Name@@3<type>`` public symbol (these are data, not code)."""
    out = []
    with path.open('r', encoding='utf-8', errors='replace') as f:
        for line in f:
            m = _GLOBAL_RE.match(line)
            if m:
                out.append((int(m.group(1), 16), m.group(2)))
    return out


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    exe_path = Path(sys.argv[1])
    pub_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3])

    print(f'Parsing PE: {exe_path}')
    data, image_base, sects = parse_xbox_pe(exe_path)

    print(f'Loading globals from {pub_path}')
    globals_list = load_globals(pub_path)
    print(f'  {len(globals_list):,} global/static data symbols')

    global_va_to_name = {image_base + rva: name for rva, name in globals_list}
    print(f'  {len(global_va_to_name):,} unique global VAs')

    print(f'Loading publics (for function-range mapping)...')
    publics = load_publics(pub_path)
    print(f'  {len(publics):,} unique publics')

    # Largest text section
    text_sects = [s for s in sects if is_text(s)]
    text_sect = max(text_sects, key=lambda s: s['rsize'])
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    text_end = text_vaddr + text_sect['vsize']
    print(f'  .text: 0x{text_vaddr:08X}..0x{text_end:08X}')

    ranges = build_function_ranges(publics, text_sect['vaddr'],
                                    text_sect['vaddr'] + text_sect['vsize'])
    print(f'  function ranges: {len(ranges):,}')

    print('Scanning PPC code for global xrefs...')
    target_set = set(global_va_to_name.keys())
    pairs = scan_ppc_string_xrefs(text_bytes, text_vaddr, target_set)
    print(f'  {len(pairs):,} xref pairs found')

    # Map each xref to its enclosing function name; aggregate by global VA
    global_to_funcs: Dict[int, Dict[str, int]] = {}
    for insn_va, target_va in pairs:
        fn_rva = insn_va - image_base
        fn_name = function_at_rva(ranges, fn_rva)
        if not fn_name:
            continue
        d = global_to_funcs.setdefault(target_va, {})
        d[fn_name] = d.get(fn_name, 0) + 1

    n_globals_referenced = len(global_to_funcs)
    total_edges = sum(len(v) for v in global_to_funcs.values())
    print(f'  globals with xrefs: {n_globals_referenced:,}')
    print(f'  total (global, function) edges: {total_edges:,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# Xbox global xrefs: <mangled_name>|0x<global_rva>|<xbox_fn>|<count>\n')
        for target_va, fn_counts in sorted(global_to_funcs.items()):
            rva = target_va - image_base
            name = global_va_to_name.get(target_va, '?')
            for fn, count in sorted(fn_counts.items(), key=lambda kv: -kv[1]):
                f.write(f'{name}|0x{rva:08X}|{fn}|{count}\n')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
