#!/usr/bin/env python3
"""Print one struct's layout from a generated CommonLibImport_CLVR_<VER>[_only].py.

Read-only and clang-free: it scans the STRUCTS (and STRUCT_FULL_NAMES, when
present) tables of an already generated import script, so it answers in about a
second. Regenerate the script first if CommonLib headers changed; for a small
script that holds just the structs you need, use
``parse_commonlib_types.py <ver> --only A,B``.

Usage:
    python dump_struct.py BSShaderManager::State --version se
    python dump_struct.py State --size 328 --version vr --json
    python dump_struct.py BSShaderManager::State --version ae --range 0xA0:0xC4
    python dump_struct.py BSShaderManager::State --version se --reng

``--reng`` prints a ``reng.define_struct`` call for the Ghidra eval bridge. That
call takes only (offset, size, comment), so field types are carried in the
comment; run the ``_only`` import script when typed fields are needed.
"""
import argparse
import ast
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPTS_DIR = os.path.join(REPO, 'ghidrascripts')


def _block(lines, start_marker):
    """Yield the literal entries of the top-level list that starts at start_marker."""
    inside = False
    for line in lines:
        if not inside:
            inside = line.startswith(start_marker)
            continue
        if line.startswith(']'):
            return
        text = line.strip()
        if text:
            yield ast.literal_eval(text.rstrip(','))


def load_structs(path):
    """Return [(full_name, name, size, category, fields)]; full_name falls back to
    the bare name for scripts generated before STRUCT_FULL_NAMES existed."""
    with open(path, encoding='utf-8') as f:
        lines = f.read().split('\n')
    structs = list(_block(lines, 'STRUCTS = ['))
    full = list(_block(lines, 'STRUCT_FULL_NAMES = ['))
    if full and len(full) != len(structs):
        sys.exit('{}: STRUCT_FULL_NAMES ({}) and STRUCTS ({}) differ in length'.format(
            path, len(full), len(structs)))
    return [((full[i] if full else s[0]), s[0], s[1], s[2], s[3])
            for i, s in enumerate(structs)]


def pick(structs, want, size=None):
    hits = [s for s in structs
            if s[0] == want or s[0].endswith('::' + want) or ('::' not in want and s[1] == want)]
    exact = [s for s in hits if s[0] == want]
    hits = exact or hits
    if size is not None:
        hits = [s for s in hits if s[2] == size]
    if len(hits) != 1:
        cand = '\n'.join('  {} ({} bytes, {})'.format(s[0], s[2], s[3]) for s in hits)
        sys.exit('{!r} matched {} structs{}'.format(
            want, len(hits), ':\n' + cand if hits else ''))
    return hits[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('name', help="full name or trailing ::-suffix, e.g. BSShaderManager::State")
    ap.add_argument('--version', default='svr', choices=('se', 'ae', 'svr', 'vr'))
    ap.add_argument('--script', help="import script to read (default: _only if present, else full)")
    ap.add_argument('--size', type=lambda v: int(v, 0), help="disambiguate by struct size")
    ap.add_argument('--range', help="only fields overlapping LO:HI (byte offsets)")
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--reng', action='store_true')
    a = ap.parse_args()

    ver = 'VR' if a.version in ('svr', 'vr') else a.version.upper()
    path = a.script
    if not path:
        base = os.path.join(SCRIPTS_DIR, 'CommonLibImport_CLVR_' + ver)
        path = base + '_only.py' if os.path.isfile(base + '_only.py') else base + '.py'
    full_name, name, size, category, fields = pick(load_structs(path), a.name, a.size)

    if a.range:
        lo, hi = (int(x, 0) for x in a.range.split(':'))
        fields = [f for f in fields if f[2] < hi and f[2] + f[3] > lo]

    if a.json:
        print(json.dumps({'name': full_name, 'size': size, 'category': category,
                          'fields': [dict(zip(('name', 'type', 'offset', 'size'), f))
                                     for f in fields]}, indent=2))
    elif a.reng:
        body = ',\n'.join('    {!r}: ({:#x}, {}, {!r})'.format(f[0], f[2], f[3], f[1])
                          for f in fields)
        print('reng.define_struct({!r}, fields={{\n{}\n}})'.format(name, body))
    else:
        print('{}  size={:#x} ({})  category={}  [{}]'.format(
            full_name, size, size, category, os.path.basename(path)))
        for f in fields:
            print('  {:#06x}  {:#4x}  {:<32} {}'.format(f[2], f[3], f[0], f[1]))


if __name__ == '__main__':
    main()
