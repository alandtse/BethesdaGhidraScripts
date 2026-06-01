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
# Class name in slot rows can include templated chars (?$@<>) and digits,
# so match anything up to the literal ``::vf`` / ``::vfunc_`` suffix.
_PC_VT_ROW = re.compile(r'^\s+VFUNC\|0x([0-9A-Fa-f]+)\|.+?::vf(?:unc_)?(\d+)\s*$')


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

    Also consumes fnv_pc_vtables_rtti_extra.txt when present -- those
    are RTTI-discovered vtables that Ghidra missed (templated types,
    etc.).
    """
    xbox_path = REFS_DIR / 'fnv_xbox_vtables.json'
    pc_path   = REFS_DIR / 'fnv_pc_vtables.txt'
    pc_extra  = REFS_DIR / 'fnv_pc_vtables_rtti_extra.txt'
    if not xbox_path.is_file() or not pc_path.is_file():
        return []

    xbox = json.loads(xbox_path.read_text(encoding='utf-8'))

    # Parse PC vtables: per class, ordered list of (slot_index, slot_rva).
    pc_slots: Dict[str, List[Tuple[int, int]]] = {}
    cur_cls = None
    def _parse_pc(text: str):
        nonlocal cur_cls
        for line in text.splitlines():
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

    _parse_pc(pc_path.read_text(encoding='utf-8', errors='replace'))
    if pc_extra.is_file():
        _parse_pc(pc_extra.read_text(encoding='utf-8', errors='replace'))

    # Demangle on-the-fly via dbghelp -- when extract_xbox_vtables.py was
    # built llvm-undname.exe wasn't on this box so the JSON's ``d`` field
    # was just the mangled string.  Re-undecorate here so we get real
    # method names (and they'll match the PDB sig index downstream).
    import sys as _sys
    _sys.path.insert(0, str((SCRIPT_DIR.parent / 'core').resolve()))
    from pdb_symbols import undecorate

    def _qname_template_aware(s: str) -> str:
        """Template-aware ``return_type Class::method`` -> ``Class::method``.
        Walks backwards from end counting ``<>`` depth so template commas
        don't fool the split."""
        tdepth = 0
        start = 0
        for i in range(len(s) - 1, -1, -1):
            ch = s[i]
            if ch == '>':
                tdepth += 1
            elif ch == '<':
                tdepth -= 1
            elif ch.isspace() and tdepth == 0:
                start = i + 1
                break
        return s[start:].strip()

    def _qname_from_demangled(d: str, cls_fallback: str, slot_i: int) -> str:
        """Extract ``Class::method`` from a demangled MSVC name, handling
        backticked special methods, ``_purecall``, templated class names
        with commas, etc."""
        if d in ('_purecall', '__purecall', '__abi_winrt_thunk') or '__cdecl' in d and '::' not in d:
            return f'{cls_fallback}::vf{slot_i:03d}_{d.lstrip("_")}'
        m_bt = re.search(r"`([^']+)'", d)
        if m_bt:
            spec = m_bt.group(1).replace(' ', '_')
            head = d[:m_bt.start()].rstrip(':').rstrip()
            head = head.split('(')[0].rstrip()
            head = _qname_template_aware(head)
            if head.endswith('::'):
                head = head[:-2]
            if head:
                return f'{head}::{spec}'
            return f'{cls_fallback}::vf{slot_i:03d}_{spec}'
        s = _strip_args(d)
        qname = _qname_template_aware(s)
        if qname and '::' in qname:
            return qname
        return f'{cls_fallback}::vf{slot_i:03d}'

    out: List[Tuple[int, str]] = []
    for cls, xb_slots in xbox.items():
        pc = pc_slots.get(cls)
        if not pc:
            continue
        pc.sort(key=lambda x: x[0])
        n = min(len(xb_slots), len(pc))
        for i in range(n):
            entry = xb_slots[i]
            method_full = entry.get('d') or entry.get('m', '')
            mangled     = entry.get('m', '')
            if not method_full or method_full.startswith('__unnamed_'):
                continue
            # If the "demangled" form is actually still mangled (i.e.
            # extraction time didn't have llvm-undname), demangle now.
            if method_full == mangled and mangled.startswith('?'):
                try:
                    method_full = undecorate(mangled)
                except Exception:
                    pass
            qname = _qname_from_demangled(method_full, cls, i)
            slot_rva = pc[i][1] - FNV_IMAGE_BASE
            out.append((slot_rva, qname))
    return out


def _load_string_anchored(path: Path) -> List[Tuple[int, str]]:
    """Parse string_anchored.csv (``0xRVA|qualified name|<src>``).

    Sources: self-naming string anchors (string_anchor_lift.py).
    """
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 2)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        out.append((rva, p[1].strip()))
    return out


def _load_string_xref_names(path: Path) -> List[Tuple[int, str]]:
    """Parse string_xref_names.csv (``0xRVA|qname|tier|votes|mangled``).

    Sources: string-xref greedy bipartite matching (match_string_xrefs.py).
    """
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 4)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        out.append((rva, p[1].strip()))
    return out


def _load_source_file_names(path: Path) -> List[Tuple[int, str]]:
    """Parse source_file_names.csv (``0xRVA|qname|cpp_basename|mangled``).

    Sources: per-compiland positional matching (source_file_cluster_lift.py).
    """
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 3)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        out.append((rva, p[1].strip()))
    return out


def _load_imm_paired_names(path: Path) -> List[Tuple[int, str]]:
    """Parse imm_paired_names.csv (``0xRVA|qname|0xIMM|mangled``).

    Sources: rare-immediate fingerprint pairing
    (extract_xbox_rare_immediates.py).
    """
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 3)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        out.append((rva, p[1].strip()))
    return out


def _load_global_labels(path: Path) -> List[Tuple[int, str]]:
    """Parse global_label_names.csv (``0xRVA|qname|votes|mangled``).

    Sources: xref-set-similarity pairing (match_globals_via_xrefs.py).
    These are DATA addresses, named as ``label`` symbols.
    """
    out = []
    if not path.is_file():
        return out
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        p = ln.split('|', 3)
        if len(p) < 2:
            continue
        try:
            rva = int(p[0], 16)
        except ValueError:
            continue
        out.append((rva, p[1].strip()))
    return out


def _load_pdb_sig_index():
    """Lazy import + load the qualified-name -> C signature index.

    Merges sigs from all 4 PDBs (Debug + Retail + Release-Beta +
    Release-MemDebug).  Debug wins on collisions; the other builds fill
    gaps where Debug didn't surface a sig (different inlining/ICF).
    """
    try:
        from pdb_signatures import load_sigs
        base = Path(r'C:\GhidraProjects\scripts')
        paths = [base / f'{n}_funcs.json' for n in (
                 'Fallout_Debug', 'Fallout',
                 'Fallout_Release_Beta', 'Fallout_Release_MemDebug')]
        return load_sigs(paths)
    except Exception:
        return {}


def _build_rva_to_sig_index(sig_by_qname: Dict[str, str]) -> Dict[int, str]:
    """Build PC-RVA -> sig index using sources that surface BOTH a name
    AND an address.  Used as a fallback when the symbol's final name
    differs from the PDB qualified form (e.g. xNVSE wrappers like
    ``FormHeap_Allocate`` are PDB's ``Bethesda::FormHeap::Allocate``).
    """
    out: Dict[int, str] = {}

    # 1. xbox_vtable pairs (PC RVA -> qualified PDB name)
    for rva, name in _load_xbox_vtable_methods():
        if name in sig_by_qname:
            out.setdefault(rva, sig_by_qname[name])

    # 2. string_xref CSV (PC RVA -> qualified name)
    p = REFS_DIR / 'fnv_string_xref_names.csv'
    if p.is_file():
        for ln in p.read_text(encoding='utf-8', errors='replace').splitlines():
            if not ln or ln.startswith('#'):
                continue
            parts = ln.split('|', 4)
            if len(parts) < 2:
                continue
            try:
                rva = int(parts[0], 16)
            except ValueError:
                continue
            name = parts[1].strip()
            if name in sig_by_qname:
                out.setdefault(rva, sig_by_qname[name])
    return out


def build_fallback_symbols() -> List[dict]:
    """Return the merged fallback symbol list for the FNV pipeline."""
    nvse_syms     = _load_nvse_known(REFS_DIR / 'fnv_pc_symbols.txt')
    pdb_syms      = _load_matched_vtable_methods(REFS_DIR / 'fnv_pdb_matched_classes.txt')
    xbox_vt       = _load_xbox_vtable_methods()
    string_anch   = _load_string_anchored(REFS_DIR / 'fnv_string_anchored.csv')
    string_xref   = _load_string_xref_names(REFS_DIR / 'fnv_string_xref_names.csv')
    src_file      = _load_source_file_names(REFS_DIR / 'fnv_source_file_names.csv')
    imm_pairs     = _load_imm_paired_names(REFS_DIR / 'fnv_imm_paired_names.csv')
    globals_      = _load_global_labels(REFS_DIR / 'fnv_global_label_names.csv')

    # Address -> (name, source).  Earlier source wins on collision.
    by_addr: Dict[int, Tuple[str, str]] = {}
    label_addrs: Dict[int, Tuple[str, str]] = {}  # data symbols (forced label)
    for rva, name in nvse_syms:
        by_addr.setdefault(rva, (name, 'nvse_known'))
    for rva, name in xbox_vt:
        by_addr.setdefault(rva, (name, 'xbox_vtable'))
    for rva, name in string_anch:
        by_addr.setdefault(rva, (name, 'string_anchor'))
    for rva, name in string_xref:
        by_addr.setdefault(rva, (name, 'string_xref'))
    for rva, name in src_file:
        by_addr.setdefault(rva, (name, 'source_file'))
    for rva, name in imm_pairs:
        by_addr.setdefault(rva, (name, 'imm_paired'))
    for rva, name in pdb_syms:
        by_addr.setdefault(rva, (name, 'xbox_pdb_matched'))
    # Globals are DATA addresses -- never collide with function RVAs from
    # the sources above.  Tracked separately so they're always emitted as
    # labels, regardless of the looks-like-label heuristic.
    for rva, name in globals_:
        label_addrs.setdefault(rva, (name, 'global_label'))
    sig_index = _load_pdb_sig_index()
    rva_sig_index = _build_rva_to_sig_index(sig_index)

    out = []
    n_sigs_by_name = 0
    n_sigs_by_rva  = 0
    for rva, (name, src) in by_addr.items():
        is_label = _looks_like_label(name)
        sig = ''
        if not is_label:
            sig = sig_index.get(name, '')
            if sig:
                n_sigs_by_name += 1
            else:
                # Fallback: try by RVA (catches nvse_known whose name
                # form doesn't match the PDB qualified form)
                sig = rva_sig_index.get(rva, '')
                if sig:
                    n_sigs_by_rva += 1
        out.append({
            'n': name,
            't': 'label' if is_label else 'func',
            'sig': sig,
            'a': rva,
            'src': src,
        })
    for rva, (name, src) in label_addrs.items():
        out.append({
            'n': name,
            't': 'label',
            'sig': '',
            'a': rva,
            'src': src,
        })
    if sig_index:
        print(f'  Attached PDB signatures: {n_sigs_by_name:,} by name + '
              f'{n_sigs_by_rva:,} by RVA fallback '
              f'(of {len(by_addr):,} candidates)')
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
