#!/usr/bin/env python3
"""End-to-end coverage report for the FNV pipeline.

Aggregates every naming + type + signature source feeding
CommonLibImport_FNV.py and prints a per-source breakdown plus an
overall script-quality scorecard.

Run:
    python fnv_coverage_report.py
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR   = SCRIPT_DIR.parent.parent
SCRIPT     = REPO_DIR / 'ghidrascripts' / 'CommonLibImport_FNV.py'


def main():
    if not SCRIPT.is_file():
        print(f'ERROR: {SCRIPT} not found.  Run parse_commonlib_types.py first.')
        sys.exit(1)

    print(f'Analyzing {SCRIPT} ...')
    src = SCRIPT.read_text(encoding='utf-8')
    tree = ast.parse(src)

    def _find(name):
        for n in tree.body:
            if isinstance(n, ast.Assign) and \
               isinstance(n.targets[0], ast.Name) and \
               n.targets[0].id == name:
                return n.value
        return None

    enums_node   = _find('ENUMS')
    structs_node = _find('STRUCTS')
    sym_match    = re.search(r'FALLBACK_SYMBOLS\s*=\s*(\[.*?\])\s*\n', src, re.S)
    fb_syms = json.loads(sym_match.group(1)) if sym_match else []
    sym_match    = re.search(r'^SYMBOLS\s*=\s*(\[.*?\])\s*\n', src, re.S | re.M)
    primary = json.loads(sym_match.group(1)) if sym_match else []

    n_enums = len(enums_node.elts) if enums_node else 0
    n_enum_members = 0
    if enums_node:
        for elt in enums_node.elts:
            if isinstance(elt, ast.Tuple) and len(elt.elts) >= 4 \
               and isinstance(elt.elts[3], ast.List):
                n_enum_members += len(elt.elts[3].elts)

    n_structs = len(structs_node.elts) if structs_node else 0
    n_fields = n_struct = n_enum_t = n_arr = n_prim = n_bytes = 0
    defined = set()
    refs = set()
    if structs_node:
        for elt in structs_node.elts:
            if not isinstance(elt, ast.Tuple) or len(elt.elts) < 4: continue
            defined.add(elt.elts[0].value)
            fnode = elt.elts[3]
            if not isinstance(fnode, ast.List): continue
            for f in fnode.elts:
                if isinstance(f, ast.Tuple) and len(f.elts) >= 2 \
                   and isinstance(f.elts[1], ast.Constant):
                    t = f.elts[1].value
                    n_fields += 1
                    if t.startswith('struct:'):  n_struct += 1; refs.add(t[7:])
                    elif t.startswith('enum:'):  n_enum_t += 1
                    elif t.startswith('arr:'):   n_arr += 1
                    elif t.startswith('bytes:'): n_bytes += 1
                    else:                         n_prim += 1

    # Symbols
    n_primary = len(primary)
    n_fb = len(fb_syms)
    n_total = n_primary + n_fb
    sig_count = sum(1 for s in fb_syms if s.get('sig'))
    sd_count  = sum(1 for s in fb_syms if s.get('sd'))
    cmp_count = sum(1 for s in fb_syms if '/' in s.get('src', ''))
    anno_count = sum(1 for s in fb_syms if '|' in s.get('src', ''))
    by_src = Counter(s['src'].split(' / ')[0].split(' | ')[0] for s in fb_syms)

    # Report
    print()
    print('=== FNV CommonLibImport script — coverage report ===')
    print(f'Script size:           {len(src)/1024/1024:.2f} MB')
    print()
    print('--- Types ---')
    print(f'enums:                 {n_enums:,} ({n_enum_members:,} members)')
    print(f'structs:               {n_structs:,}')
    print(f'fields total:          {n_fields:,}')
    print(f'  -> struct refs       {n_struct:,}')
    print(f'  -> enum refs         {n_enum_t:,}')
    print(f'  -> array refs        {n_arr:,}')
    print(f'  -> primitives        {n_prim:,}')
    print(f'  -> raw bytes:N       {n_bytes:,} '
          f'({n_bytes/max(1,n_fields)*100:.1f}%)')
    missing = refs - defined
    resolution = (1 - len(missing) / max(1, len(refs))) * 100
    print(f'struct ref resolution: {resolution:.1f}% '
          f'({len(missing)} of {len(refs)} missing)')
    print()
    print('--- Symbols ---')
    print(f'primary (xNVSE):       {n_primary:,}')
    print(f'fallback:              {n_fb:,}')
    print(f'TOTAL:                 {n_total:,}')
    print(f'  with C signature:    {sig_count:,} '
          f'({sig_count/max(1,n_fb)*100:.1f}%)')
    print(f'  with structured sig: {sd_count:,} '
          f'({sd_count/max(1,n_fb)*100:.1f}%)')
    print(f'  with compiland tag:  {cmp_count:,}')
    print(f'  with DIA annotation: {anno_count:,}')
    print()
    print('--- Fallback symbol provenance ---')
    for src_name, count in by_src.most_common():
        print(f'  {src_name:25s} {count:,}')


if __name__ == '__main__':
    main()
