#!/usr/bin/env python3
"""Pair PC FNV data addresses with Xbox PDB globals via shared
function-xref-ers.

We don't have a content-based join key for data (unlike strings, where
the literal text matches across binaries).  Instead we use the existing
PC<->Xbox function-name mapping (the 19k symbols already in our fallback
set) as a translation table:

For each known (pc_fn_va, xbox_fn_name) pair:
  for each xbox_global xref'd by xbox_fn_name:
    for each pc_data xref'd by pc_fn_va:
      edge_score[(pc_data, xbox_global)] += 1

This essentially asks: ``which PC data address has its xref-er set
correspond (via the fn mapping) to which Xbox global's xref-er set?''

Run greedy bipartite matching on the edges -- one PC data ↔ one Xbox
global per pair.

Output: ``0x<pc_data_va>|<demangled global>|<votes>|<mangled>`` per line.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'
IMAGE_BASE = 0x00400000

sys.path.insert(0, str(SCRIPT_DIR.parent / 'core'))
from pdb_symbols import undecorate  # noqa: E402

XBOX_GLOBAL_XREFS = Path(r'C:\GhidraProjects\scripts\fnv_xbox_global_xrefs.txt')
PC_DATA_XREFS     = Path(r'C:\GhidraProjects\scripts\fnv_pc_data_xrefs.txt')


def load_xbox_global_xrefs(path: Path):
    """<mangled>|0x<rva>|<xbox_fn>|<count> -> two indexes:
       global_va_to_name (str), xbox_fn_to_globals: {fn_name: set(global_va)}
    """
    name_by_va = {}
    fn_to_globals = defaultdict(set)
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|')
        if len(p) != 4:
            continue
        try:
            rva = int(p[1], 16)
        except ValueError:
            continue
        name_by_va[rva] = p[0]
        fn_to_globals[p[2]].add(rva)
    return name_by_va, dict(fn_to_globals)


def load_pc_data_xrefs(path: Path):
    """0x<data_va>|0x<fn_va>|<count> -> {pc_fn_va: set(pc_data_va)}"""
    fn_to_data = defaultdict(set)
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|')
        if len(p) != 3:
            continue
        try:
            data_va = int(p[0], 16)
            fn_va   = int(p[1], 16)
        except ValueError:
            continue
        fn_to_data[fn_va].add(data_va)
    return dict(fn_to_data)


_CSV_RE = re.compile(r'^0x([0-9A-Fa-f]+)\|.*?\|.*?\|.*?\|(\?\S+)\s*$')


def load_pc_to_xbox_mapping():
    """Load every known (pc_va, xbox_mangled) pair from fallback sources.

    Primary source: fnv_string_xref_names.csv has both sides directly.
    Secondary: vtable slot pairing -- but we need the mangled name (the
    JSON has demangled or mangled per slot).
    """
    out: Dict[int, str] = {}  # pc_va -> xbox_mangled

    # 1. String-xref CSV
    p = REFS_DIR / 'fnv_string_xref_names.csv'
    if p.is_file():
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            if not ln or ln.startswith('#'):
                continue
            m = _CSV_RE.match(ln)
            if m:
                rva = int(m.group(1), 16)
                out[IMAGE_BASE + rva] = m.group(2)

    # 2. Vtable slot pairing (xbox JSON + pc vtables)
    xbox_p = REFS_DIR / 'fnv_xbox_vtables.json'
    pc_p   = REFS_DIR / 'fnv_pc_vtables.txt'
    if xbox_p.is_file() and pc_p.is_file():
        xbox = json.loads(xbox_p.read_text(encoding='utf-8'))
        pc_slots: Dict[str, List[Tuple[int, int]]] = {}
        cur_cls = None
        hdr_re = re.compile(r'^VTABLE\|0x([0-9A-Fa-f]+)\|([^|]+)\|')
        row_re = re.compile(r'^\s+VFUNC\|0x([0-9A-Fa-f]+)\|[\w:]+::vf(?:unc_)?(\d+)\s*$')
        for line in pc_p.read_text(encoding='utf-8', errors='replace').splitlines():
            m = hdr_re.match(line)
            if m:
                cur_cls = m.group(2).strip()
                pc_slots.setdefault(cur_cls, [])
                continue
            m = row_re.match(line)
            if m and cur_cls is not None:
                pc_slots[cur_cls].append((int(m.group(2)), int(m.group(1), 16)))
        for cls, xb_slots in xbox.items():
            pc = pc_slots.get(cls)
            if not pc:
                continue
            pc.sort()
            n = min(len(xb_slots), len(pc))
            for i in range(n):
                m_name = xb_slots[i].get('m', '')
                if not m_name or m_name.startswith('__unnamed_') or not m_name.startswith('?'):
                    continue
                pc_va = IMAGE_BASE + pc[i][1]
                out.setdefault(pc_va, m_name)
    return out


def main():
    print(f'Loading Xbox global xrefs: {XBOX_GLOBAL_XREFS}')
    g_name_by_va, xbox_fn_to_globals = load_xbox_global_xrefs(XBOX_GLOBAL_XREFS)
    print(f'  globals: {len(g_name_by_va):,}')
    print(f'  Xbox fns referencing globals: {len(xbox_fn_to_globals):,}')

    print(f'Loading PC data xrefs: {PC_DATA_XREFS}')
    pc_fn_to_data = load_pc_data_xrefs(PC_DATA_XREFS)
    print(f'  PC fns referencing data: {len(pc_fn_to_data):,}')

    print('Loading PC<->Xbox function mapping...')
    pc_to_xbox = load_pc_to_xbox_mapping()
    print(f'  mappings: {len(pc_to_xbox):,}')

    # Compute edges via mapping
    print('Building edge weights (pc_data, xbox_global) ...')
    edges: Dict[Tuple[int, int], int] = defaultdict(int)
    for pc_va, xbox_mangled in pc_to_xbox.items():
        pc_datas = pc_fn_to_data.get(pc_va)
        if not pc_datas:
            continue
        xb_globals = xbox_fn_to_globals.get(xbox_mangled)
        if not xb_globals:
            continue
        for d in pc_datas:
            for g in xb_globals:
                edges[(d, g)] += 1
    print(f'  edges: {len(edges):,}')

    # Sort edges by weight, greedy match
    edge_list = sorted(edges.items(), key=lambda kv: -kv[1])
    pc_claimed: Set[int] = set()
    g_claimed: Set[int] = set()
    matches = []
    # Two passes: first claim all votes >= 2 (high confidence), then any
    # remaining votes >= 1 (low-confidence but better than nothing).
    for (pc_d, g), w in edge_list:
        if pc_d in pc_claimed or g in g_claimed or w < 2:
            continue
        pc_claimed.add(pc_d)
        g_claimed.add(g)
        matches.append((pc_d, g, w))
    high = len(matches)
    for (pc_d, g), w in edge_list:
        if pc_d in pc_claimed or g in g_claimed or w < 1:
            continue
        pc_claimed.add(pc_d)
        g_claimed.add(g)
        matches.append((pc_d, g, w))
    low = len(matches) - high
    print(f'Greedy matches (votes>=2 high-conf): {high:,}')
    print(f'Greedy matches (votes==1 low-conf):  {low:,}')

    # Demangle global names
    print('Demangling...')
    demangled = {}
    for _, g, _ in matches:
        mangled = g_name_by_va.get(g, '?')
        if mangled not in demangled:
            try:
                demangled[mangled] = undecorate(mangled)
            except Exception:
                demangled[mangled] = mangled

    def qualify(d):
        # Strip ``<type> ClassName::var`` -> ``ClassName::var``
        toks = d.split()
        return toks[-1] if toks else d

    out_path = REFS_DIR / 'fnv_global_label_names.csv'
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# global labels: 0x<pc_data_rva>|<qualified name>|votes|<mangled>\n')
        for pc_d, g, w in sorted(matches):
            mangled = g_name_by_va.get(g, '?')
            qname = qualify(demangled.get(mangled, mangled))
            if qname.startswith('?'):
                continue
            rva = pc_d - IMAGE_BASE
            f.write(f'0x{rva:08X}|{qname}|{w}|{mangled}\n')
            written += 1
    print(f'Wrote {out_path}: {written:,} global labels')


if __name__ == '__main__':
    main()
