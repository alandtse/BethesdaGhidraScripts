"""Load demangled publics from the Fallout4 1.11.221 debug PDB.

Source: ``Fallout4_1_11_221_for_debug.pdb`` (Bethesda-released debug
PDB) dumped via ``llvm-pdbutil pretty --externals``.  The dump is
checked into ``refs/f4_221_pdb_publics.txt``; the format is one symbol
per line:

    public [0xRVA] DemangledQualifiedName(args)

RVAs are image-relative (Fallout4.exe has image base 0x140000000;
0x02215dc0 above is the offset within the image).  Direct match for
the import script's ``base_addr.add(off)`` symbol-application path.

Filter out compiler-internal mangled forms (``?``-prefixed leftovers
from llvm-pdbutil's partial demangle), template-machinery instances,
and zero-RVA placeholders.
"""
from __future__ import annotations

import os
import re
from typing import Iterator, List, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REFS_DIR   = os.path.join(SCRIPT_DIR, 'refs')
PUBLICS_TXT = os.path.join(REFS_DIR, 'f4_221_pdb_publics.txt')


_LINE_RE = re.compile(
    r'^\s*public\s+'
    r'\[0x(?P<rva>[0-9A-Fa-f]+)\]\s+'
    r'(?P<name>\S.*?)\s*$'
)


def _iter_lines(path: str) -> Iterator[Tuple[int, str]]:
    if not os.path.isfile(path):
        return
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for ln in fh:
            m = _LINE_RE.match(ln)
            if not m:
                continue
            try:
                rva = int(m.group('rva'), 16)
            except ValueError:
                continue
            if rva == 0:
                continue
            name = m.group('name').strip()
            if not name:
                continue
            yield rva, name


def _looks_like_label(name: str) -> bool:
    """vftable / RTTI / typeinfo / strings are data, not code."""
    return any(h in name for h in (
        'RTTI_', "::`vftable'", "::`RTTI",
        '`vector-deleting-destructor-init',
        'type_info::', '`typeinfo for',
    ))


def load_publics() -> List[dict]:
    """Return symbols shaped for ``fallback_symbols_json`` (F4 1.11.221).

    Schema mirrors the FNV pdb_naming output: ``{n, t, sig, 221, src}``
    where ``221`` is the per-version RVA key the generated F4_221 import
    script's ``version_key`` lookup expects.
    """
    seen: set = set()
    out: List[dict] = []
    for rva, name in _iter_lines(PUBLICS_TXT):
        key = (rva, name)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            'n':   name,
            't':   'label' if _looks_like_label(name) else 'func',
            'sig': '',
            '221': rva,
            'src': 'f4_221_pdb',
        })
    return out


if __name__ == '__main__':
    syms = load_publics()
    n_func  = sum(1 for s in syms if s['t'] == 'func')
    n_label = sum(1 for s in syms if s['t'] == 'label')
    print(f'F4 1.11.221 PDB publics: {len(syms):,} '
          f'({n_func:,} funcs, {n_label:,} labels)')
