#!/usr/bin/env python3
"""Find constructors in PC FalloutNV.exe by byte-scanning .text for
references to known vtable VAs.

x86 constructors initialize the vtable pointer with patterns like:
    C7 06 LL HH HH HH        mov dword ptr [esi], offset vtable
    C7 07 LL HH HH HH        mov dword ptr [edi], offset vtable
    C7 45 ?? LL HH HH HH     mov dword ptr [ebp+X], offset vtable
    8B/89 forms with esp     stack-allocated cases

We don't decode instructions fully -- the constructor signature is
simply ``a 4-byte LE encoding of a vtable VA somewhere in .text``.
The function containing that byte sequence is the constructor (or one
of several constructors / inlined sites).  Most classes have at least
one constructor whose ONLY job is to set the vtable + a couple fields.

For each vtable VA:
  1. Find every byte position in .text matching its 4-byte LE encoding
  2. Walk back to function start (INT3-padding heuristic)
  3. Emit ``<Class>::<Class>`` at each unique fn start

Output: ``fnv_constructor_names.csv`` with ``RVA|Class::Class|<vtable>`` rows.

Run:
    python find_fnv_constructors.py
"""
from __future__ import annotations

import re
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
PC_EXE     = Path(r'D:\FNV Project\FalloutNewVegas\FalloutNV.exe')

sys.path.insert(0, str(SCRIPT_DIR))
from extract_pc_fnv_string_xrefs import (
    parse_pe_x86, find_function_start_for_offset,
)


def load_vtables() -> Dict[int, str]:
    """{vtable_va: class_name} from fnv_pc_vtables.txt + RTTI extras."""
    out = {}
    rx = re.compile(r'^VTABLE\|0x([0-9A-Fa-f]+)\|([^|]+)\|')
    for fname in ('fnv_pc_vtables.txt', 'fnv_pc_vtables_rtti_extra.txt'):
        p = REFS_DIR / fname
        if not p.is_file():
            continue
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            m = rx.match(ln)
            if m:
                va = int(m.group(1), 16)
                cls = m.group(2).strip()
                if va not in out:
                    out[va] = cls
    return out


def load_existing_names() -> Dict[int, str]:
    """RVAs already named via fallback symbols.  We skip ctor candidates
    landing on these (they have better names already)."""
    sys.path.insert(0, str(SCRIPT_DIR))
    from pdb_naming import build_fallback_symbols
    return {s['a']: s['n'] for s in build_fallback_symbols() if s.get('a')}


def _sanitize_class_for_ctor(cls: str) -> str:
    """``BSSimpleArray<X,1024>`` -> ``BSSimpleArray`` (bare class).
    Constructors use the bare class name as the method name in MSVC.
    For nested classes like ``Class::Inner``, use the last segment."""
    last = cls.rsplit('::', 1)[-1]
    return last.split('<', 1)[0]


def main():
    print('Loading vtables (incl. RTTI extras)...')
    vtables = load_vtables()
    print(f'  vtables: {len(vtables):,}')

    print('Loading existing fallback names...')
    existing = load_existing_names()
    print(f'  named RVAs: {len(existing):,}')

    print(f'Parsing PE: {PC_EXE}')
    data, image_base, sects = parse_pe_x86(PC_EXE)
    text_sect = next(s for s in sects if s['chars'] & 0x20000000)
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    print(f'  .text: 0x{text_vaddr:08X} ({len(text_bytes):,} bytes)')

    # Reverse map: vtable VA -> class for fast lookup
    vt_va_set = set(vtables.keys())

    print('Scanning .text for vtable VA references...')
    # For each xref position, record (fn_start_va, vtable_va)
    # A function might init MULTIPLE vtables -- common for multi-inheritance
    # ctors -- so we collect all matches per function.
    fn_to_vts: Dict[int, Set[int]] = defaultdict(set)
    n_xrefs = 0
    n_resolved = 0
    for i in range(0, len(text_bytes) - 4):
        v = (text_bytes[i] | (text_bytes[i+1] << 8) |
             (text_bytes[i+2] << 16) | (text_bytes[i+3] << 24))
        if v not in vt_va_set:
            continue
        n_xrefs += 1
        fn_va = find_function_start_for_offset(text_bytes, text_vaddr, i)
        if fn_va == 0:
            continue
        n_resolved += 1
        fn_to_vts[fn_va].add(v)
    print(f'  xrefs found: {n_xrefs:,}')
    print(f'  resolved to a function: {n_resolved:,}')
    print(f'  unique constructor-candidate fns: {len(fn_to_vts):,}')

    # Emit: for each fn that's NOT already named, pick the PRIMARY vtable
    # (the one whose class has the most fns associated -- typically the
    # primary base of a multi-inherit ctor) and name as Class::Class.
    matches: List = []
    skipped_named = 0
    skipped_multi = 0
    for fn_va, vts in fn_to_vts.items():
        rva = fn_va - image_base
        if rva in existing:
            skipped_named += 1
            continue
        # Single-vtable -> unambiguous primary ctor
        if len(vts) == 1:
            vt = next(iter(vts))
            cls = vtables.get(vt, '')
            if not cls:
                continue
            bare = _sanitize_class_for_ctor(cls)
            if bare:
                matches.append((rva, f'{cls}::{bare}', vt))
            continue
        # Multi-vtable: try to pick the EARLIEST emitted (lowest VA) --
        # MSVC initializes the primary vtable last (overwrites bases), so
        # the LAST init wins.  Without instruction order we can't tell;
        # pick the alphabetically-first class name as a tiebreaker.
        # For now, skip multi-vt cases to avoid noise.
        skipped_multi += 1

    print(f'  named candidates: {len(matches):,}')
    print(f'  skipped (already named): {skipped_named:,}')
    print(f'  skipped (multi-vtable initialization): {skipped_multi:,}')

    out_path = REFS_DIR / 'fnv_constructor_names.csv'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# constructor-candidate names: 0x<rva>|<Class::Class>|0x<vtable_va>\n')
        for rva, name, vt in sorted(matches):
            f.write(f'0x{rva:08X}|{name}|0x{vt:08X}\n')
    print(f'Wrote {out_path}: {len(matches):,} new constructor candidates')


if __name__ == '__main__':
    main()
