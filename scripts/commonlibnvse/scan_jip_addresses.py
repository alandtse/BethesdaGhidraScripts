#!/usr/bin/env python3
"""Scan JIP-LN-NVSE source for name->VA mappings.

JIP-LN-NVSE is a community NVSE plugin with extensive engine
annotation -- it's the LARGEST FNV mod for engine internals.  Most
of its address annotations live in two forms:

  1. ``kVtbl_<Class> = 0xVA,`` in class_vtbls.h enums (~1000 vtables)
  2. ``#define <NAME> 0xVA`` in internal/*.h (singletons, critical
     sections, globals)
  3. ``addr<Name> = 0xVA,`` and similar enums in utility/etc.

Run:
    python scan_jip_addresses.py <jip_root> [out.csv]
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple


# Match enum-style ``kName = 0xVA,`` -- works for class_vtbls / patches enums
_ENUM_NAME_VA = re.compile(
    r'^\s*'
    r'(?P<name>k[A-Z][\w]*|[A-Z][A-Z0-9_]+(?:[A-Z][\w]*)?)\s*=\s*'
    r'0x(?P<va>[0-9A-Fa-f]+)\s*,?'
)

# Match ``#define NAME 0xVA``
_DEFINE_NAME_VA = re.compile(
    r'^\s*#\s*define\s+(?P<name>[A-Z][A-Z0-9_]+)\s+'
    r'0x(?P<va>[0-9A-Fa-f]+)\s*$'
)

# Match ``DEFINE_MEMBER_FN(Method, ret, 0xVA, ...)`` -- xNVSE-style
_DEFINE_MEMBER_FN = re.compile(
    r'DEFINE_MEMBER_FN(?:_LONG)?\s*\(\s*'
    r'(?P<name>[A-Za-z_]\w*)\s*,\s*[\w\s:*&<>,]+\s*,\s*'
    r'0x(?P<va>[0-9A-Fa-f]+)'
)


# Filter: a "real" FNV address is in .text [0x401000..0xFDF000] or
# .rdata/.data [0xBDF000..0x14089E4].  Below 0x401000 = code constants
# not actual addresses.
def _is_fnv_va(va: int) -> bool:
    return 0x00401000 <= va <= 0x01410000


def scan(root: Path, verbose: bool = False) -> List[Tuple[int, str, str]]:
    """Return (va, name, source) tuples for every name->VA mapping found
    under ``root``.  Names overlap with xNVSE / our existing pipeline
    sources; downstream dedup handles collisions."""
    out: List[Tuple[int, str, str]] = []
    n_files = 0
    for dirpath, _, files in os.walk(root):
        for fname in files:
            if not fname.endswith(('.h', '.cpp', '.hpp', '.inl')):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                    src = f.read()
            except OSError:
                continue
            n_files += 1
            rel = os.path.relpath(fpath, root)
            for line in src.splitlines():
                for rx in (_ENUM_NAME_VA, _DEFINE_NAME_VA, _DEFINE_MEMBER_FN):
                    m = rx.match(line)
                    if not m:
                        continue
                    try:
                        va = int(m.group('va'), 16)
                    except ValueError:
                        continue
                    if not _is_fnv_va(va):
                        continue
                    name = m.group('name')
                    # Drop ``kVtbl_`` prefix -> let downstream emit as
                    # VTABLE_<Class> via the label heuristic
                    if name.startswith('kVtbl_'):
                        name = 'VTABLE_' + name[6:]
                    out.append((va, name, f'JIP-LN/{rel}'))
                    break  # first match wins per line
    if verbose:
        print(f'  scanned {n_files} files, found {len(out)} name->VA entries')
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    root = Path(sys.argv[1])
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else \
        Path(__file__).parent / 'refs' / 'fnv_jip_addresses.txt'

    print(f'Scanning {root}...')
    rows = scan(root, verbose=True)

    # Dedup by VA (first source wins)
    seen = set()
    deduped = []
    for va, name, src in rows:
        key = (va, name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((va, name, src))
    print(f'  unique (va, name) pairs: {len(deduped):,}')

    # Also count vtable vs non-vtable
    n_vt = sum(1 for _, n, _ in deduped if n.startswith('VTABLE_'))
    n_fn = len(deduped) - n_vt
    print(f'  vtable labels: {n_vt:,}')
    print(f'  function/data names: {n_fn:,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# JIP-LN-NVSE Address Mappings\n')
        f.write('# Format: 0xVA|name|source\n')
        for va, name, src in sorted(deduped):
            f.write(f'0x{va:08X}|{name}|{src}\n')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
