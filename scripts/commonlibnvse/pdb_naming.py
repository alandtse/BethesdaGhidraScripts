#!/usr/bin/env python3
"""PDB-derived fallback symbols for FalloutNV.

Sources, in priority order (lower index wins on address collision):

  1. ``refs/fnv_pc_symbols.txt``  -- 7.6k labels from xNVSE / JIP LN NVSE
     headers in ``0xVA|name|src`` form.  Already PC FNV image-base coords.
  2. ``refs/fnv_xbox_vtables.json`` + ``refs/fnv_pc_vtables.txt``
     -- per-class Xbox vtable slot order paired with PC FNV vtable
     addresses.  For each class present in both, emit
     ``Class::method`` for every PC vfunc slot whose Xbox counterpart
     has a name.  This is the rich source: ~1800 classes, ~45k slots.
  3. ``refs/fnv_pdb_matched_classes.txt`` -- legacy pre-matched cross-ref
     (predates the direct vtable extraction).  Only consumes classes
     with exact PDB-method-count == PC-vfunc-count (~112 classes).

Returns a list of symbol entries shaped for the FNV pipeline's
``fallback_symbols_json`` slot:
    {'n': qualified_name, 't': 'func'|'label', 'sig': '', 'a': rva, 'src': label}
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / "refs"
FNV_IMAGE_BASE = 0x00400000

_VTABLE_HINTS = ('_vtbl', '_vtable', 'vtable_', 'VTABLE_', '::vftable',
                 '_RTTI', 'RTTI_', '_RTTIType', 'kVtbl_', 'g_vftable_',
                 's_vtbl_')


def _looks_like_label(name: str) -> bool:
    return any(h in name for h in _VTABLE_HINTS)


def _load_nvse_known(path: Path) -> List[Tuple[int, str]]:
    """Parse fnv_pc_symbols.txt (`0xVA|name|source` form), discard noise."""
    out: List[Tuple[int, str]] = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        parts = ln.split('|', 2)
        if len(parts) < 2:
            continue
        addr_s, name = parts[0].strip(), parts[1].strip()
        if not addr_s.startswith('0x'):
            continue
        # Image-base bogus entries the extractor included for flag enums.
        if int(addr_s, 16) == FNV_IMAGE_BASE:
            continue
        if name.startswith(('aka:', 'GAME -', 'GAME-', 'GECK -', 'GECK-',
                            'see 0x', 'see address', 'unknown ', '0x')):
            continue
        # Drop parenthetical noise the extractor appended to flag-enum names.
        name = re.sub(r'\s*\([^)]*\)\s*$', '', name).strip()
        if not name:
            continue
        # Skip names that are basically a hex literal or comma-list of them.
        if re.fullmatch(r'(?:0x[0-9A-Fa-f]+[,\s]*)+', name):
            continue
        # Skip names that contain spaces and look like prose ("locale fix" etc.).
        # Real identifiers don't have spaces.
        if ' ' in name and not name.startswith(('kVtbl_', 'k_', 'g_', 's_', 'kFlag', 'kEvent')):
            continue
        try:
            va = int(addr_s, 16)
        except ValueError:
            continue
        out.append((va - FNV_IMAGE_BASE, name))
    return out


_CLASS_HDR = re.compile(r'^#\s+(\w+)\s*$', re.M)
_PDB_METHOD = re.compile(
    r'#\s+PDB seg\d+:0x[0-9A-Fa-f]+\s+\w[\w:]*::(?P<m>[~`]?[\w<>\s]+?)\s*$', re.M)
_PC_VFUNC = re.compile(
    r'^\s+PC\s+0x(?P<addr>[0-9A-Fa-f]+)\s*=\s*\w+::vfunc_(?P<slot>\d+)\s*$', re.M)


def _load_matched_vtable_methods(path: Path) -> List[Tuple[int, str]]:
    """For each class block where PDB method count == PC vfunc count,
    positional-map PDB names to PC vtable slot RVAs.  Returns (rva, "Class::method").
    """
    out: List[Tuple[int, str]] = []
    if not path.is_file():
        return out
    text = path.read_text(encoding='utf-8', errors='replace')
    # Class blocks separated by blank-line-then-class-header.
    blocks = re.split(r'\n(?=# \w+\s*\n)', text)
    for blk in blocks:
        m = re.match(r'^#\s+(\w+)\s*\n', blk)
        if not m:
            continue
        cls = m.group(1)
        methods = [m.group('m').strip() for m in _PDB_METHOD.finditer(blk)]
        slots = [(int(m.group('addr'), 16), int(m.group('slot')))
                 for m in _PC_VFUNC.finditer(blk)]
        if not methods or not slots or len(methods) != len(slots):
            continue
        # Slots aren't guaranteed sequential in the file; sort by slot index.
        slots.sort(key=lambda x: x[1])
        for (addr, _slot), method in zip(slots, methods):
            # Strip the trailing parenthesis form some destructors carry.
            clean = method.split('(')[0].strip()
            qname = f'{cls}::{clean}'
            out.append((addr - FNV_IMAGE_BASE, qname))
    return out


_PC_VT_HDR = re.compile(r'^VTABLE\|0x([0-9A-Fa-f]+)\|([^|]+)\|(\d+)\s+vfuncs\s*$')
_PC_VT_ROW = re.compile(r'^\s+VFUNC\|0x([0-9A-Fa-f]+)\|[\w:]+::vf(?:unc_)?(\d+)\s*$')


def _strip_args(demangled: str) -> str:
    """``ClassName::method(args)`` -> ``ClassName::method`` (drop signature)."""
    # Cut at the first unparenthesized '(' from the right -- demangled names
    # may have ``operator()`` etc. inside, so simple split('(') is unsafe.
    depth = 0
    last_paren = -1
    for i in range(len(demangled) - 1, -1, -1):
        ch = demangled[i]
        if ch == ')':
            depth += 1
        elif ch == '(':
            depth -= 1
            if depth == 0:
                last_paren = i
                break
    if last_paren > 0:
        return demangled[:last_paren].rstrip()
    return demangled


def _load_xbox_vtable_methods() -> List[Tuple[int, str]]:
    """Pair the Xbox per-class vtable slot order with PC FNV vtable slot RVAs.

    For each class present in both fnv_xbox_vtables.json (Xbox slot ->
    demangled name) and fnv_pc_vtables.txt (PC slot RVA -> generic vfN),
    pair them positionally: PC slot N's RVA gets named after Xbox slot N's
    method.  Returns [(rva, "Class::method"), ...].
    """
    xbox_path = REFS_DIR / 'fnv_xbox_vtables.json'
    pc_path   = REFS_DIR / 'fnv_pc_vtables.txt'
    if not xbox_path.is_file() or not pc_path.is_file():
        return []

    xbox = json.loads(xbox_path.read_text(encoding='utf-8'))

    # Parse PC vtables: per class, ordered list of (slot_index, slot_rva).
    pc_slots: Dict[str, List[Tuple[int, int]]] = {}
    cur_cls = None
    for line in pc_path.read_text(encoding='utf-8', errors='replace').splitlines():
        m = _PC_VT_HDR.match(line)
        if m:
            cur_cls = m.group(2).strip()
            pc_slots.setdefault(cur_cls, [])
            continue
        m = _PC_VT_ROW.match(line)
        if m and cur_cls is not None:
            va = int(m.group(1), 16)
            slot = int(m.group(2))
            pc_slots[cur_cls].append((slot, va))

    out: List[Tuple[int, str]] = []
    for cls, xb_slots in xbox.items():
        pc = pc_slots.get(cls)
        if not pc:
            continue
        pc.sort(key=lambda x: x[0])
        # Pair up to the shorter of the two; cap=PC was already applied
        # at extraction time, so counts usually match.
        n = min(len(xb_slots), len(pc))
        for i in range(n):
            entry = xb_slots[i]
            method_full = entry.get('d') or entry.get('m', '')
            if not method_full or method_full.startswith('__unnamed_'):
                continue
            # Demangled looks like ``return_type Class::method(args) qual``
            # or ``Class::method``.  Strip args + return type.
            method_full = _strip_args(method_full)
            # Drop leading return-type words; keep last ``::``-segment with prefix
            # so we end up with ``Class::method`` (or ``A::B::method``).
            tokens = method_full.split()
            qname = tokens[-1] if tokens else method_full
            if not qname or '::' not in qname:
                # Fallback: prefix with class explicitly
                qname = f'{cls}::vf{i:03d}'
            slot_rva = pc[i][1] - FNV_IMAGE_BASE
            out.append((slot_rva, qname))
    return out


def build_fallback_symbols() -> List[dict]:
    """Return the merged fallback symbol list for the FNV pipeline."""
    nvse_syms = _load_nvse_known(REFS_DIR / 'fnv_pc_symbols.txt')
    pdb_syms  = _load_matched_vtable_methods(REFS_DIR / 'fnv_pdb_matched_classes.txt')
    xbox_vt   = _load_xbox_vtable_methods()
    # Address -> (name, source).  Earlier source wins on collision.
    by_addr: Dict[int, Tuple[str, str]] = {}
    for rva, name in nvse_syms:
        by_addr.setdefault(rva, (name, 'nvse_known'))
    for rva, name in xbox_vt:
        by_addr.setdefault(rva, (name, 'xbox_vtable'))
    for rva, name in pdb_syms:
        by_addr.setdefault(rva, (name, 'xbox_pdb_matched'))
    out = []
    for rva, (name, src) in by_addr.items():
        out.append({
            'n': name,
            't': 'label' if _looks_like_label(name) else 'func',
            'sig': '',
            'a': rva,
            'src': src,
        })
    return out


if __name__ == '__main__':
    syms = build_fallback_symbols()
    n_func  = sum(1 for s in syms if s['t'] == 'func')
    n_label = sum(1 for s in syms if s['t'] == 'label')
    by_src: Dict[str, int] = {}
    for s in syms:
        by_src[s['src']] = by_src.get(s['src'], 0) + 1
    print(f'Total fallback symbols: {len(syms)}  (funcs {n_func}, labels {n_label})')
    for src, n in sorted(by_src.items(), key=lambda kv: -kv[1]):
        print(f'  {src:14s} {n:6d}')
