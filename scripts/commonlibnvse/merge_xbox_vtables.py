#!/usr/bin/env python3
"""Merge per-PDB vtable extracts into one master, picking the richest source.

For each class, pick the PDB extract that has the most slots AND the
greatest naming diversity (fewest ICF-folded duplicates).  Debug build
typically wins -- less ICF folding because identical-body virtuals stay
distinct (separate debug symbols).

Run:
    python merge_xbox_vtables.py <out.json> <in1.json> <in2.json> ...
"""
import json
import sys
from collections import Counter
from pathlib import Path


def _score(slots):
    """Higher is better: more named slots + more distinct names = richer."""
    named = [s for s in slots if not s.get('m', '').startswith('__unnamed_')]
    distinct = len({s.get('d') or s.get('m') for s in named})
    return (distinct, len(named), len(slots))


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    out_path = Path(sys.argv[1])
    inputs = [Path(p) for p in sys.argv[2:]]

    pick_count = Counter()
    best = {}
    for p in inputs:
        data = json.loads(p.read_text(encoding='utf-8'))
        for cls, slots in data.items():
            prev = best.get(cls)
            if prev is None or _score(slots) > _score(prev['slots']):
                best[cls] = {'slots': slots, 'src': p.stem}
    for cls, entry in best.items():
        pick_count[entry['src']] += 1

    merged = {cls: e['slots'] for cls, e in best.items()}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(merged), encoding='utf-8')

    total_slots = sum(len(v) for v in merged.values())
    distinct = len({s.get('d') or s.get('m')
                    for slots in merged.values() for s in slots})
    print(f'Merged: {len(merged)} classes, {total_slots} slots, '
          f'{distinct} distinct method names')
    print('Class source breakdown:')
    for src, n in pick_count.most_common():
        print(f'  {src:35s} {n}')
    print(f'Wrote {out_path}')


if __name__ == '__main__':
    main()
