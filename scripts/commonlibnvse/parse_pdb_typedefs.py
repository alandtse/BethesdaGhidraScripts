#!/usr/bin/env python3
"""Parse ``llvm-pdbutil pretty --typedefs`` output into a
{alias_name: target_type} dict.

Used in pdb_types_to_pipeline._convert_one as a fallback resolver:
when a field's type isn't a known struct/enum/primitive but IS a
known typedef alias, we follow the alias and try again.

Format:
    typedef class _STFC_STATS STFC_STATS
    typedef int (__cdecl *)() PFNXAMISUIACTIVE
    typedef class HDC__* HDC

The LAST whitespace-separated token (at depth 0) is the alias name;
everything before is the target.

Run:
    python parse_pdb_typedefs.py <typedefs.txt> <out.json>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


_TYPEDEF = re.compile(r'^\s+typedef\s+(?P<body>.+)$')


def split_target_alias(body: str):
    """Split typedef body into (target_type, alias_name).  Walks
    backwards through the body counting ``<>`` AND ``()`` depth so
    function-pointer typedefs split correctly:
        ``int (__cdecl *)() PFNXAMISUIACTIVE``
        -> target = ``int (__cdecl *)()``, alias = ``PFNXAMISUIACTIVE``
    """
    depth_angle = 0
    depth_paren = 0
    for i in range(len(body) - 1, -1, -1):
        ch = body[i]
        if ch == '>': depth_angle += 1
        elif ch == '<': depth_angle -= 1
        elif ch == ')': depth_paren += 1
        elif ch == '(': depth_paren -= 1
        elif ch.isspace() and depth_angle == 0 and depth_paren == 0:
            return body[:i].rstrip(), body[i+1:].strip()
    return '', body.strip()


def clean_target(t: str) -> str:
    """Strip ``class`` / ``struct`` / ``union`` / ``enum`` prefixes."""
    for kw in ('class ', 'struct ', 'union ', 'enum '):
        while t.startswith(kw):
            t = t[len(kw):]
    return t.strip()


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    in_path  = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    print(f'Parsing {in_path}...')
    out = {}
    n_total = 0
    for ln in in_path.read_text(encoding='utf-8', errors='replace').splitlines():
        m = _TYPEDEF.match(ln)
        if not m:
            continue
        n_total += 1
        target, alias = split_target_alias(m.group('body'))
        if not alias:
            continue
        out[alias] = clean_target(target)

    print(f'  total typedefs:       {n_total:,}')
    print(f'  parsed (alias -> tgt): {len(out):,}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out), encoding='utf-8')
    print(f'Wrote {out_path}: {out_path.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
