#!/usr/bin/env python3
"""Parse PPC ``bl`` (branch-link / call) instructions from Xbox
Fallout.exe and build a per-function callee list.

PowerPC ``bl`` encoding (I-form):
    [opcode:6=18][LI:24 disp][AA:1][LK:1=1]
    Target VA = pc + sign_ext(LI << 2)     when AA == 0

We scan each function's byte range (derived from PDB publics) and record
every ``bl`` target, in instruction order.  The output is:

    {qualified_function_name: [callee_target_va, ...]}

Used by ``match_callgraph.py`` to align PC FNV call sites with Xbox
PDB-named call targets and propagate names through the call graph.

Run:
    python extract_xbox_callgraph.py <Xbox.exe> <publics.txt> <out.json>
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_xbox_string_xrefs import (
    parse_xbox_pe, is_text, load_publics,
    build_function_ranges, function_at_rva,
)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'core'))
from pdb_symbols import undecorate  # noqa: E402


def scan_function_calls(text_bytes: bytes, text_vaddr: int,
                          fn_start_va: int, fn_end_va: int) -> List[int]:
    """Return list of ``bl`` target VAs from this function, in instruction
    order.  Skips conditional and indirect calls (bctrl, blrl) -- only
    direct ``bl`` is useful for name alignment."""
    targets = []
    start_off = fn_start_va - text_vaddr
    end_off   = fn_end_va - text_vaddr
    if start_off < 0 or end_off > len(text_bytes):
        return targets
    i = start_off & ~3   # align to 4
    while i + 4 <= end_off:
        insn = struct.unpack_from('>I', text_bytes, i)[0]
        opcode = (insn >> 26) & 0x3F
        if opcode == 18:  # b/bl
            li_raw = (insn >> 2) & 0x00FFFFFF   # 24-bit LI field
            # Sign-extend
            if li_raw & 0x00800000:
                li_raw -= 0x01000000
            disp = li_raw << 2
            aa   = (insn >> 1) & 1
            lk   = insn & 1
            if lk == 1 and aa == 0:
                # Relative bl
                pc = text_vaddr + i
                target = (pc + disp) & 0xFFFFFFFF
                targets.append(target)
        i += 4
    return targets


def to_qname(d: str) -> str:
    """``return_type Class::method`` -> ``Class::method``, template-aware."""
    # Strip args
    depth = 0
    last_paren = -1
    for k in range(len(d) - 1, -1, -1):
        c = d[k]
        if c == ')': depth += 1
        elif c == '(':
            depth -= 1
            if depth == 0:
                last_paren = k; break
    if last_paren > 0:
        d = d[:last_paren].rstrip()
    # Walk back, depth-aware
    tdepth = 0
    start = 0
    for k in range(len(d) - 1, -1, -1):
        c = d[k]
        if c == '>': tdepth += 1
        elif c == '<': tdepth -= 1
        elif c.isspace() and tdepth == 0:
            start = k + 1; break
    return d[start:].strip()


def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    exe_path = Path(sys.argv[1])
    pub_path = Path(sys.argv[2])
    out_path = Path(sys.argv[3])

    print(f'Parsing PE: {exe_path}')
    data, image_base, sects = parse_xbox_pe(exe_path)
    text_sects = [s for s in sects if is_text(s)]
    text_sect = max(text_sects, key=lambda s: s['rsize'])
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    text_end = text_vaddr + text_sect['vsize']
    print(f'  .text: 0x{text_vaddr:08X}..0x{text_end:08X}')

    print(f'Loading publics: {pub_path}')
    publics = load_publics(pub_path)
    print(f'  {len(publics):,} publics')
    ranges = build_function_ranges(
        publics, text_sect['vaddr'],
        text_sect['vaddr'] + text_sect['vsize'])
    print(f'  function ranges: {len(ranges):,}')

    # Build VA -> public name (so we can name call targets too)
    va_to_mangled = {}
    for rva, mangled in publics.items():
        if mangled.startswith('??_'):  # skip vtable symbols
            continue
        va_to_mangled[image_base + rva] = mangled

    print('Scanning + building call graph...')
    fn_to_calls: Dict[str, List[str]] = {}
    n_fns_with_calls = 0
    n_total_calls = 0
    for i, (rva, end_rva, mangled) in enumerate(ranges):
        if i % 10000 == 0 and i:
            print(f'  {i:,}/{len(ranges):,}...')
        if mangled.startswith('??_'):  # vtables
            continue
        fn_start_va = image_base + rva
        fn_end_va   = image_base + end_rva
        targets = scan_function_calls(text_bytes, text_vaddr,
                                       fn_start_va, fn_end_va)
        if not targets:
            continue
        # Demangle current function name
        try:
            d = undecorate(mangled)
        except Exception:
            d = mangled
        q = to_qname(d)
        if not q or q.startswith('?'):
            continue
        # Resolve each call target to a function name
        call_names = []
        for t_va in targets:
            target_mangled = va_to_mangled.get(t_va)
            if not target_mangled:
                # Function-internal jump or non-public callee
                call_names.append('?')
                continue
            try:
                td = undecorate(target_mangled)
            except Exception:
                td = target_mangled
            tq = to_qname(td)
            call_names.append(tq if tq else '?')
        # Only keep functions with at least 2 RESOLVABLE calls
        resolvable = [n for n in call_names if n != '?']
        if len(resolvable) < 2:
            continue
        fn_to_calls[q] = call_names
        n_fns_with_calls += 1
        n_total_calls += len(call_names)

    print(f'  functions with bl calls:   {n_fns_with_calls:,}')
    print(f'  total bl call sites:       {n_total_calls:,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(fn_to_calls), encoding='utf-8')
    print(f'Wrote {out_path}: {out_path.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
