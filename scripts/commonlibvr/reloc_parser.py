"""CommonLibVR (alandtse) relocation/symbol scanner.

Additive sibling to ``commonlibsse/reloc_parser.py``. CommonLibVR differs from
powerof3/CommonLibSSE in exactly two ways that matter to the address layer:

  1. Functions use ``RELOCATION_ID(se, ae)`` (2-arg) and there is no ``Offset::``
     namespace header. VR offsets are resolved by looking the SE id up in
     ``addr_lib.vr_db`` (sourced from vr_address_tools ``version-1-4-15-0.csv``,
     generated from the canonical ``database.csv``). The base header/src function
     scanners already do exactly this, so we reuse them verbatim.

  2. RTTI / VTABLE / NiRTTI offsets are written as ``REL::VariantID(se, ae, vr)``
     in a SINGLE section (CommonLibVR has no ``#ifdef SKYRIM_SUPPORT_AE`` split),
     where the third argument is the literal VR RVA. The base scanner expects the
     powerof3 ``REL::ID`` + ``#ifdef`` layout, so we replace just that scanner.

Public API mirrors the base so ``commonlibsse/parse_commonlib_types.py``'s
``main()``-style wiring can drive it:
  collect_relocations()     - RTTI/VTABLE (VariantID) + RE/ header functions
  collect_src_relocations() - src/**/*.cpp functions (delegates to base)
"""
from __future__ import annotations

import glob
import importlib.util
import os
import re
from typing import Dict, List, Set, Tuple

# Reuse the powerof3 base parser's helpers (import-safe: regex/context only).
# Load it by explicit path under a distinct module name: both this file and the
# base share the basename ``reloc_parser.py``, so a plain ``import`` would alias
# one to the other in sys.modules. importlib avoids that collision.
_BASE_RP_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'commonlibsse', 'reloc_parser.py')
_spec = importlib.util.spec_from_file_location('commonlibsse_reloc_parser', _BASE_RP_PATH)
base_rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base_rp)

# REL::VariantID(se, ae, vr) — single declaration form used by RTTI / NiRTTI:
#   constexpr REL::VariantID RTTI_AlchemyItem(513850, 392218, 0x1ed6d60);
_VARIANT_DECL_RE = re.compile(
    r'REL::VariantID\s+(\w+)\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)')

# std::array<REL::VariantID, N> VTABLE_Name{ REL::VariantID(se,ae,vr), ... };
_VTABLE_ARR_RE = re.compile(
    r'std::array<REL::VariantID,\s*\d+>\s+(VTABLE_\w+)\s*\{([^}]*)\}')

# inner element of a VTABLE array (no name between VariantID and '(')
_VARIANT_ELEM_RE = re.compile(
    r'REL::VariantID\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)')


def _scan_variant_rtti_vtable_file(file_path: str, addr_lib) -> List[dict]:
    """Parse a CommonLibVR Offsets_{RTTI,NiRTTI,VTABLE}.h file.

    Single-section ``REL::VariantID(se, ae, vr)`` form. ``se``/``ae`` are ids
    resolved against the SE/AE address DBs; ``vr`` is the literal VR RVA.
    Returns label dicts {name, se_off, ae_off, vr_off}.
    """
    try:
        with open(file_path, encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError:
        return []

    labels: Dict[str, dict] = {}

    # VTABLE arrays first (multi-slot). idx 0 = base name; later slots get _N+1.
    consumed_spans: List[Tuple[int, int]] = []
    for m in _VTABLE_ARR_RE.finditer(content):
        consumed_spans.append(m.span())
        base_name = m.group(1)
        for idx, em in enumerate(_VARIANT_ELEM_RE.finditer(m.group(2))):
            se_id, ae_id, vr_lit = int(em.group(1)), int(em.group(2)), int(em.group(3), 0)
            se_off = addr_lib.se_db.get(se_id)
            ae_off = addr_lib.ae_db.get(ae_id)
            if not se_off and not ae_off and not vr_lit:
                continue
            lname = base_name if idx == 0 else '{}_{}'.format(base_name, idx + 1)
            labels.setdefault(lname, {'name': lname, 'se_off': None,
                                      'ae_off': None, 'vr_off': None})
            if se_off: labels[lname]['se_off'] = se_off
            if ae_off: labels[lname]['ae_off'] = ae_off
            if vr_lit: labels[lname]['vr_off'] = vr_lit

    # Single RTTI/NiRTTI declarations (skip any that fell inside a VTABLE array).
    for m in _VARIANT_DECL_RE.finditer(content):
        if any(s <= m.start() < e for s, e in consumed_spans):
            continue
        name = m.group(1)
        se_off = addr_lib.se_db.get(int(m.group(2)))
        ae_off = addr_lib.ae_db.get(int(m.group(3)))
        vr_lit = int(m.group(4), 0)
        if not se_off and not ae_off and not vr_lit:
            continue
        labels.setdefault(name, {'name': name, 'se_off': None,
                                 'ae_off': None, 'vr_off': None})
        if se_off: labels[name]['se_off'] = se_off
        if ae_off: labels[name]['ae_off'] = ae_off
        if vr_lit: labels[name]['vr_off'] = vr_lit

    return list(labels.values())


def collect_relocations(
    re_include: str,
    addr_lib,
    verbose: bool = False,
    root_namespace: str = 'RE',
) -> Tuple[List[dict], List[dict], Dict[str, int], Set[Tuple[str, str]], Dict[str, int], Dict[str, int]]:
    """Scan CommonLibVR RE/ headers for relocation symbols.

    Returns the same 6-tuple as the base parser so the existing symbol-build
    wiring works unchanged. CommonLibVR has no Offsets.h, so the offset maps are
    empty and the function scanners fall back to RELOCATION_ID only.
    """
    all_func_syms: List[dict] = []
    all_label_syms: List[dict] = []
    all_static_methods: Set[Tuple[str, str]] = set()
    offset_id_map: Dict[str, int] = {}
    se_offset_map: Dict[str, int] = {}
    ae_offset_map: Dict[str, int] = {}

    # 1. RTTI / NiRTTI / VTABLE labels (VariantID form).
    for fname in ('Offsets_RTTI.h', 'Offsets_NiRTTI.h', 'Offsets_VTABLE.h'):
        fpath = os.path.join(re_include, fname)
        if os.path.isfile(fpath):
            labels = _scan_variant_rtti_vtable_file(fpath, addr_lib)
            all_label_syms.extend(labels)
            if verbose:
                print('  Parsed {} labels from {}'.format(len(labels), fname))

    # 2. RE/ header functions (RELOCATION_ID) — reuse base scanner verbatim.
    h_files = sorted(glob.glob(os.path.join(re_include, '**', '*.h'), recursive=True))
    for h_path in h_files:
        if os.path.basename(h_path) in (
                'Offsets.h', 'Offsets_RTTI.h', 'Offsets_NiRTTI.h', 'Offsets_VTABLE.h'):
            continue
        funcs, _labels, statics = base_rp._scan_header_relocations(
            h_path, addr_lib, offset_id_map,
            se_offset_map=se_offset_map, ae_offset_map=ae_offset_map,
            root_namespace=root_namespace)
        all_func_syms.extend(funcs)
        all_static_methods |= statics

    if verbose:
        print('  Header scan: {} func symbols, {} labels, {} static methods'.format(
            len(all_func_syms), len(all_label_syms), len(all_static_methods)))

    # Dedup (mirror base behaviour).
    seen = set()
    deduped_funcs = []
    for f in all_func_syms:
        key = (f.get('se_off'), f.get('ae_off'), f.get('vr_off'))
        if key not in seen:
            seen.add(key)
            deduped_funcs.append(f)

    seen_labels = set()
    deduped_labels = []
    for lbl in all_label_syms:
        key = (lbl['name'], lbl.get('se_off'), lbl.get('ae_off'), lbl.get('vr_off'))
        if key not in seen_labels:
            seen_labels.add(key)
            deduped_labels.append(lbl)

    _attach_ae1799(deduped_funcs, addr_lib)
    _attach_ae1799(deduped_labels, addr_lib)

    return (deduped_funcs, deduped_labels, offset_id_map,
            all_static_methods, se_offset_map, ae_offset_map)


def _attach_ae1799(syms: List[dict], addr_lib) -> None:
    """Attach an ``ae1799_off`` to each symbol that has an ``ae_off``.

    AE 1.7.99 reuses the same AE id as 1.6.353-1.6.1179 (single
    ``RELOCATION_ID(se, ae)``/``VariantID(se, ae, vr)`` declaration, no
    separate macro arg -- see CommonLibVR-ng PR #298/#299), so the 1.7.99 RVA
    for a given symbol is found by reverse-mapping its known ``ae_off`` back
    to the shared id via ``addr_lib.ae_db``, then looking that id up in
    ``addr_lib.ae1799_db`` (format-5 address library, a separate physical
    binary's RVA space).
    """
    ae_off_to_id = {off: aid for aid, off in addr_lib.ae_db.items()}
    for s in syms:
        ae_off = s.get('ae_off')
        if not ae_off:
            continue
        aid = ae_off_to_id.get(ae_off)
        if aid is None:
            continue
        ae1799_off = addr_lib.ae1799_db.get(aid)
        if ae1799_off:
            s['ae1799_off'] = ae1799_off


def collect_src_relocations(src_dir, addr_lib, offset_id_map,
                            se_offset_map=None, ae_offset_map=None,
                            verbose=False, root_namespace='RE'):
    """src/**/*.cpp RELOCATION_ID functions, with VR offsets attached.

    The base src scanner only records se_off/ae_off (powerof3 has no VR). Most
    CommonLibVR functions are defined in src/, so we reverse-map each se_off back
    to its SE id and look the VR offset up in vr_db — otherwise every src-defined
    function would lose its VR binding.
    """
    func_syms = base_rp.collect_src_relocations(
        src_dir, addr_lib, offset_id_map,
        se_offset_map=se_offset_map, ae_offset_map=ae_offset_map,
        verbose=verbose, root_namespace=root_namespace)

    se_off_to_id = {off: sid for sid, off in addr_lib.se_db.items()}
    vr_attached = 0
    for fs in func_syms:
        se_off = fs.get('se_off')
        if not se_off:
            continue
        sid = se_off_to_id.get(se_off)
        if sid is None:
            continue
        vr_off = addr_lib.vr_db.get(sid)
        if vr_off:
            fs['vr_off'] = vr_off
            vr_attached += 1
    if verbose:
        print('  Attached VR offsets to {} of {} src functions'.format(
            vr_attached, len(func_syms)))

    _attach_ae1799(func_syms, addr_lib)
    return func_syms
