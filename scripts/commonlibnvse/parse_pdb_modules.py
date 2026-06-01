#!/usr/bin/env python3
"""Parse ``llvm-pdbutil pretty --module-syms`` output to extract
function VA -> compiland (.obj file) and function VA -> source-file
prefix mappings.

Used to attach navigation comments to symbol entries in the FNV
import script (so each PC FNV function gets a ``// from foo.obj``
plate comment when applied to a project that lacks PDB info).

Run:
    python parse_pdb_modules.py <module_syms.txt> <out.json>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


# 2-space-indented compiland header: ``  obj\xbox\foo.obj``
_COMPILAND = re.compile(r'^  ([\w\\:.\-/]+\.obj)\s*$')

# 4-space-indented func line: ``    func [0xVA+N - 0xEND- M | sizeof=K] sig``
_FUNC = re.compile(
    r'^\s+func\s+\[0x(?P<va>[0-9A-Fa-f]+)\+\d+\s+-\s+0x[0-9A-Fa-f]+-\s*\d+\s*'
    r'\|\s*sizeof=\d+\]\s+(?P<sig>.+)$'
)


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    in_path  = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    print(f'Parsing {in_path}...')
    va_to_compiland = {}
    cur_obj = None
    n_funcs = 0
    n_uniq  = 0

    with in_path.open('r', encoding='utf-8', errors='replace') as f:
        for ln in f:
            m = _COMPILAND.match(ln)
            if m:
                cur_obj = m.group(1)
                continue
            if cur_obj is None:
                continue
            mf = _FUNC.match(ln)
            if mf:
                va = int(mf.group('va'), 16)
                n_funcs += 1
                if va in va_to_compiland:
                    continue
                # Normalize compiland to its basename (drop ``obj\xbox\`` etc.)
                basename = cur_obj.replace('\\', '/').rsplit('/', 1)[-1]
                # Drop .obj extension; that's the source-file stem
                if basename.endswith('.obj'):
                    basename = basename[:-4]
                va_to_compiland[va] = basename
                n_uniq += 1

    print(f'  functions seen:    {n_funcs:,}')
    print(f'  unique fn VAs:     {n_uniq:,}')
    print(f'  distinct compilands: '
          f'{len(set(va_to_compiland.values())):,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(va_to_compiland), encoding='utf-8')
    print(f'Wrote {out_path}: {out_path.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
