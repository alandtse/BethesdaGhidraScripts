#!/usr/bin/env python3
"""Parse ``llvm-pdbutil pretty --enums`` output and convert into the
enums dict shape that ghidra_import_gen.generate_script consumes.

Pretty format:
    enum _D3DRENDERSTATETYPE {
      D3DRS_ZENABLE = 40
      D3DRS_ZFUNC = 44
      ...
    }

Some enum names are nested (``Class::EnumName``) -- we normalize ``::``
to ``_`` for Ghidra DTM keying (same convention as
pdb_types_to_pipeline.py).

Run:
    python parse_pdb_enums.py <enums.txt> <out.json>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


# enum NAME { ... }
_ENUM_HDR = re.compile(r'^\s+enum\s+(?P<name>[\w:<>\?\$\@,\s\*&\-\+\.]+?)\s*\{?\s*$')
# MEMBER = NUMBER  (number can be signed; some are listed as hex)
_MEMBER   = re.compile(r'^\s+(?P<name>[A-Za-z_][\w]*)\s*=\s*(?P<val>-?\d+|0x[0-9A-Fa-f]+)\s*$')
# bare brace open / close
_OPEN  = re.compile(r'^\s*\{\s*$')
_CLOSE = re.compile(r'^\s*\}\s*$')


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    in_path  = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    print(f'Parsing {in_path}...')
    enums = {}                # full_name -> {name, size, category, values, full_name}
    cur_name = None
    cur_values = []
    in_body = False

    with in_path.open('r', encoding='utf-8', errors='replace') as f:
        for ln in f:
            # Header (may be followed by ``{`` on same line or next line)
            m = _ENUM_HDR.match(ln)
            if m:
                if cur_name is not None and cur_values:
                    norm = cur_name.replace('::', '_')
                    enums[cur_name] = {
                        'name':      norm,
                        'full_name': cur_name,
                        'size':      4,
                        'category':  '/xNVSE/PDB',
                        'values':    cur_values,
                    }
                cur_name = m.group('name').strip()
                cur_values = []
                in_body = ln.rstrip().endswith('{')
                continue

            if _OPEN.match(ln):
                in_body = True
                continue
            if _CLOSE.match(ln):
                if cur_name is not None and cur_values:
                    norm = cur_name.replace('::', '_')
                    enums[cur_name] = {
                        'name':      norm,
                        'full_name': cur_name,
                        'size':      4,
                        'category':  '/xNVSE/PDB',
                        'values':    cur_values,
                    }
                cur_name = None
                cur_values = []
                in_body = False
                continue

            if in_body and cur_name is not None:
                mm = _MEMBER.match(ln)
                if mm:
                    v = mm.group('val')
                    val = int(v, 16) if v.lower().startswith('0x') else int(v)
                    cur_values.append([mm.group('name'), val])

    # Flush trailing
    if cur_name is not None and cur_values:
        enums[cur_name] = {
            'name':      cur_name.replace('::', '_'),
            'full_name': cur_name,
            'size':      4,
            'category':  '/xNVSE/PDB',
            'values':    cur_values,
        }

    n_members = sum(len(e['values']) for e in enums.values())
    print(f'  enums:   {len(enums):,}')
    print(f'  members: {n_members:,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(enums), encoding='utf-8')
    print(f'Wrote {out_path}: {out_path.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
