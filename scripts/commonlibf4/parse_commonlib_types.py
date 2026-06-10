#!/usr/bin/env python3
"""
Parse libxse/commonlibf4 headers and generate Ghidra import scripts for
Fallout 4 OG / NG / AE / VR.

Pipeline:
  Types:        core/clang_types.py  (clang AST dump + record layouts)
  Relocations:  reloc_parser.py      (IDs.h map + ID::Class::Method references)
  Address lib:  address_library.py   (OG / NG / AE / VR)
  Fallback:     ida_names.py         (extras/IDAImportNames_1.11.191.0.py)
  Script gen:   core/ghidra_import_gen.py

Generates:
  ghidrascripts/CommonLibImport_F4_OG.py   (types/labels only)
  ghidrascripts/CommonLibImport_F4_NG.py   (types + NG-resolved symbols)
  ghidrascripts/CommonLibImport_F4_AE.py   (types + AE-resolved symbols)
  ghidrascripts/CommonLibImport_F4_VR.py   (types/labels only)

Symbol resolution
-----------------
CommonLibF4's IDs are managed by meh321 with a single ID space across all
F4 patch revisions — the OG / NG / AE / VR address libraries differ only
in per-version offsets, not in which IDs exist.  ~83% of
CommonLibF4-referenced IDs resolve in OG and VR; the rest were dropped in
the older patches or added later.  Each symbol carries up to four offset
fields (`og`, `ng`, `a`, `v`) and the per-version script picks the one
matching its build.

Function-name coverage for IDs that exist only in AE (the remaining 17%)
is recovered post-generation via masked byte-signature porting — see
`run_bytesig_port.py`.
"""

import os
import sys
import re

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
CORE_DIR    = os.path.join(os.path.dirname(SCRIPT_DIR), 'core')

sys.path.insert(0, CORE_DIR)
sys.path.insert(0, SCRIPT_DIR)

COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'include')
FALLOUT_H         = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Fallout.h')
RE_INCLUDE        = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR        = os.path.join(PROJECT_DIR, 'ghidrascripts')
ADDRLIB_DIR       = os.path.join(PROJECT_DIR, 'addresslibrary', 'f4')


# A descriptor that ends in a single-letter uppercase qualified path is an
# uninstantiated template parameter (``T``, ``K``, ``V``...).  Signatures
# containing such tokens can't point at the exact correct type and are
# dropped instead of being applied with a stale ``RE::T`` placeholder.
_UNRESOLVED_TPARAM_RE = re.compile(r'(?:^|[:>])([A-Z])(?=$|\W)')


def _has_unresolved_tparam(desc):
    if not desc:
        return False
    if 'struct:' not in desc and 'enum:' not in desc:
        return False
    return bool(_UNRESOLVED_TPARAM_RE.search(desc))


def _enrich_symbols(symbols_list, structs):
    structs_by_suffix = {}
    for key, val in structs.items():
        parts = key.split('::')
        for i in range(len(parts)):
            suffix = '::'.join(parts[i:])
            if suffix not in structs_by_suffix:
                structs_by_suffix[suffix] = val
    enriched = 0
    skipped = 0
    for sym in symbols_list:
        if sym['t'] != 'func' or sym.get('sd'):
            continue
        name = sym['n']
        if '::' not in name:
            continue
        idx = name.rfind('::')
        class_name  = name[:idx]
        method_name = name[idx + 2:]
        st = structs.get(class_name) or structs_by_suffix.get(class_name)
        if not st:
            continue
        info = st.get('methods', {}).get(method_name)
        if info:
            ret, params, is_static = info
            # Reject signatures containing uninstantiated template parameters
            # (e.g. ``T*`` from a class template's method) — they would resolve
            # to ``void*`` in Ghidra and mask the real types in the binary.
            if _has_unresolved_tparam(ret) or any(_has_unresolved_tparam(p[1]) for p in params):
                skipped += 1
                continue
            sym['sd'] = [ret, params, 1 if is_static else 0]
            enriched += 1
    if enriched:
        print(f'Enriched {enriched} symbols with AST method signatures')
    if skipped:
        print(f'Skipped {skipped} symbols with uninstantiated template params in signature')


# Per-version output config.  OG/VR have no fallback symbol pool — their
# IDs are in disjoint namespaces, so an AE-namespace fallback would
# poison the import with mislabeled functions.
#
# Each entry is (version_key, output_filename, fallback_symbols_json_or_None,
# anchors_basename, parse_defines).
#
# `parse_defines` lets each runtime parse the CommonLib headers with its own
# preprocessor flags.  All four are currently empty because the powerof3
# CommonLibF4 fork has no per-version vfunc-insertion #ifdefs — but the seam
# exists so a VR-aware overlay can add (e.g.) `-DBGS_FALLOUT4_VR=1` and emit
# a correctly-shifted vtable layout for F4VR without affecting OG/NG/AE.
F4_TARGETS = (
    # OG/NG inherit the IDA fallback pool: meh321's ID namespace is shared
    # across OG/NG/AE/221, so IDA entries cross-resolve via their 'ai' ID
    # (see the n_ng_resolved/n_og_resolved loop in main).  VR keeps '[]'
    # -- its community ID namespace is disjoint, nothing would resolve.
    ('f4_og', 'CommonLibImport_F4_OG.py', None,  'og.csv', []),
    ('f4_ng', 'CommonLibImport_F4_NG.py', None,  'ng.csv', []),
    ('f4_ae', 'CommonLibImport_F4_AE.py', None,  'ae.csv', []),
    ('f4_vr', 'CommonLibImport_F4_VR.py', '[]',  'vr.csv', []),
    # 1.11.221 uses meh321's version-1-11-221-0.bin (same ID namespace as
    # AE/NG).  Direct address-library resolution covers every CommonLibF4
    # symbol; AE->221 byte-sig porting (run_bytesig_port.py) still fills
    # in IDA-name extras whose source pool is AE-only.
    ('f4_221', 'CommonLibImport_F4_221.py', '[]',  '221.csv', []),
)


def main():
    import json as _json

    from address_library import F4AddressLibrary, get_pe_version
    from ghidra_import_gen import (
        build_vtable_structs as _build_vtable_structs,
        inject_vtable_fields as _inject_vtable_fields,
        flatten_structs       as _flatten_structs,
        apply_secondary_vtable_typing as _apply_secondary_vtable_typing,
        generate_script,
    )

    # --- Address library (OG / NG / AE / VR) ---
    addr_lib = F4AddressLibrary()
    addr_lib.load_all(ADDRLIB_DIR)
    print(f'Address libraries — OG: {len(addr_lib.og_db):,}, '
          f'NG: {len(addr_lib.ng_db):,}, AE: {len(addr_lib.ae_db):,}, '
          f'VR: {len(addr_lib.vr_db):,}, 221: {len(addr_lib.db_221):,}')

    # --- Relocation scan ---
    print('\n=== Collecting symbols via relocation parser ===')
    import reloc_parser as _rp

    func_syms, label_syms, static_methods = _rp.collect_relocations(
        RE_INCLUDE, addr_lib, verbose=True)

    # Mark statics
    for fs in func_syms:
        if fs.get('class_') and fs.get('name'):
            if (fs['class_'], fs['name']) in static_methods:
                fs['is_static'] = True

    # CommonLibF4's IDs are managed by meh321 with a single ID space across
    # all F4 patch revisions — the OG / NG / AE / VR address libraries differ
    # only in their per-version offsets, not in which IDs exist.  In
    # practice ~83% of CommonLibF4-referenced IDs resolve in OG and VR
    # (the older patches dropped some helpers and gained others), so we
    # look up every symbol's ID against all four DBs.  The 'a' key stays
    # as AE for backward compatibility with the prior generator.
    def _resolve(sym, id_val):
        if not id_val:
            return
        og = addr_lib.og_db.get(id_val)
        ng = addr_lib.ng_db.get(id_val)
        ae = addr_lib.ae_db.get(id_val)
        vr = addr_lib.vr_db.get(id_val)
        v221 = addr_lib.db_221.get(id_val)
        if og: sym['og'] = og
        if ng: sym['ng'] = ng
        if ae: sym['a']  = ae
        if vr: sym['v']  = vr
        if v221: sym['221'] = v221

    symbols = []
    for fs in func_syms:
        full_name = '{}::{}'.format(fs['class_'], fs['name']) if fs['class_'] else fs['name']
        sym = {'n': full_name, 't': 'func', 'sig': '', 'src': 'CommonLibF4'}
        if fs.get('id'):
            sym['id'] = fs['id']
        _resolve(sym, fs.get('id'))
        symbols.append(sym)

    for lbl in label_syms:
        sym = {'n': lbl['name'], 't': 'label', 'sig': '', 'src': 'CommonLibF4'}
        if lbl.get('id'):
            sym['id'] = lbl['id']
        _resolve(sym, lbl.get('id'))
        symbols.append(sym)

    # Normalise __ -> ::
    for s in symbols:
        if '__' in s['n']:
            s['n'] = re.sub(r':{3,}', '::', s['n'].replace('__', '::'))

    n_og = sum(1 for s in symbols if 'og' in s)
    n_ng = sum(1 for s in symbols if 'ng' in s)
    n_ae = sum(1 for s in symbols if 'a'  in s)
    n_vr = sum(1 for s in symbols if 'v'  in s)
    n_221 = sum(1 for s in symbols if '221' in s)
    print(f'\nTotal symbols: {len(symbols)} '
          f'(OG: {n_og}, NG: {n_ng}, AE: {n_ae}, VR: {n_vr}, 221: {n_221})')

    # --- Type parsing setup (per-version below) ---
    print('\n=== Parsing types (clang AST) — per version ===')
    from clang_types import collect_types, _setup_include_paths
    from anchor_verifier import verify_or_exit as _verify_anchors_or_exit
    from vtable_matcher import load_json as _load_shift_map_json
    from vtable_patcher import patch_vtable_structs as _patch_vtable_structs

    if not os.path.isfile(FALLOUT_H):
        print('ERROR: Could not find Fallout.h at', FALLOUT_H)
        sys.exit(1)

    stub_dir = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
    base_parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir)
    # commonlib-shared provides REL/ and REX/ headers
    shared_include = os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4', 'lib', 'commonlib-shared', 'include')
    if os.path.isdir(shared_include):
        base_parse_args = ['-I' + shared_include] + base_parse_args

    # Capture types from REL/, REX/, F4SE/ as well as RE/ — they're sibling
    # namespaces under CommonLibF4 whose AST methods would otherwise be skipped.
    extra_scopes = [
        COMMONLIB_INCLUDE,                                   # F4SE/ + RE/
        os.path.join(PROJECT_DIR, 'extern', 'CommonLibF4',
                     'lib', 'commonlib-shared', 'include'),  # REL/ + REX/
    ]

    # --- IDAImportNames_1.11.191.0.py fallback symbols (AE only) ---
    print('\n=== Loading IDAImportNames_1.11.191.0.py fallback symbols ===')
    from ida_names import load_ida_import_names as _load_ida
    f4_ida_path = os.path.join(PROJECT_DIR, 'extras', 'IDAImportNames_1.11.191.0.py')
    ida_names = _load_ida(f4_ida_path)
    print(f'IDA names: {len(ida_names):,} entries')

    primary_rvas = {s['a'] for s in symbols if s.get('a')}
    # Inverse AE address-library map (RVA -> ID) for back-referencing IDA-named
    # functions to a stable CommonLibF4 ID where one exists.  Built from
    # addr_lib.ae_db ({id: rva}) so a CommonLib upgrade that renumbers IDs
    # invalidates the cache automatically.
    ae_rva_to_id = {rva: id_val for id_val, rva in addr_lib.ae_db.items()}
    ida_fallback = []
    n_ng_resolved = n_og_resolved = n_221_resolved = 0
    for rva, name in ida_names.items():
        entry = {'n': name, 't': 'func', 'sig': '', 'a': rva, 'src': 'IDAImportNames'}
        ae_id = ae_rva_to_id.get(rva)
        if ae_id is not None:
            entry['ai'] = ae_id
            # The meh321 ID namespace is shared across OG/NG/AE/221, so an
            # AE-derived ID resolves directly in the sibling DBs.  This is
            # what lets NG and OG (previously fallback='[]') inherit the
            # IDA name pool.  VR stays out: its community IDs are disjoint.
            ng = addr_lib.ng_db.get(ae_id)
            og = addr_lib.og_db.get(ae_id)
            v221 = addr_lib.db_221.get(ae_id)
            if ng:
                entry['ng'] = ng
                n_ng_resolved += 1
            if og:
                entry['og'] = og
                n_og_resolved += 1
            if v221 and '221' not in entry:
                entry['221'] = v221
                n_221_resolved += 1
        ida_fallback.append(entry)
    not_in_primary = sum(1 for s in ida_fallback if s['a'] not in primary_rvas)
    print(f'IDA fallback symbols: {len(ida_fallback):,} loaded '
          f'({not_in_primary:,} not in primary; cross-resolved: '
          f'NG {n_ng_resolved:,}, OG {n_og_resolved:,}, 221 {n_221_resolved:,})')

    fallback_json_ae = _json.dumps(ida_fallback, separators=(',', ':'))

    # --- F4 1.11.221 PDB publics (Bethesda debug PDB) ---
    print('\n=== Loading Fallout4 1.11.221 debug PDB publics ===')
    from pdb_publics_f4_221 import load_publics as _load_f4_221_publics
    f4_221_publics = _load_f4_221_publics()
    primary_221_rvas = {s['221'] for s in symbols if s.get('221')}
    f4_221_fallback = [s for s in f4_221_publics
                       if s['221'] not in primary_221_rvas]
    n_221_func  = sum(1 for s in f4_221_fallback if s['t'] == 'func')
    n_221_label = sum(1 for s in f4_221_fallback if s['t'] == 'label')
    print(f'F4 1.11.221 PDB publics: {len(f4_221_publics):,} loaded, '
          f'{len(f4_221_fallback):,} new ({n_221_func:,} funcs, '
          f'{n_221_label:,} labels)')
    # Merge IDA names that cross-resolved to a 221 RVA (PDB publics win on
    # collision -- they're authoritative for this build).
    used_221 = {s['221'] for s in f4_221_fallback}
    ida_into_221 = [e for e in ida_fallback
                    if e.get('221') and e['221'] not in used_221]
    print(f'  + IDA names cross-resolved into 221 pool: {len(ida_into_221):,}')
    fallback_json_221 = _json.dumps(f4_221_fallback + ida_into_221,
                                    separators=(',', ':'))
    fallback_json_by_ver = {'f4_221': fallback_json_221}

    # --- Per-version: parse → build vtable structs → verify anchors → generate ---
    # One AST parse per target so a VR-aware overlay can change the layout for
    # F4VR without affecting OG/NG/AE.  Today all four use empty defines so
    # the parses produce identical results; the seam is here to make adding
    # version-specific layout fixes a one-line change in F4_TARGETS.
    anchors_dir = os.path.join(SCRIPT_DIR, 'anchors')
    print('\nGenerating Ghidra scripts...')
    # Per-version RVA key used both by the generated script's version_key
    # map and by the persisted-bytesig merge below.
    _ver_rva_key = {'f4_og': 'og', 'f4_ng': 'ng', 'f4_ae': 'a',
                    'f4_vr': 'v', 'f4_221': '221'}

    def _merge_bytesig_csv(fb_json, ver):
        """Merge refs/bytesig_ported_<short>.csv into a fallback pool.

        Written by bytesig_port_combined.py / run_bytesig_port.py; makes
        ported names survive regeneration instead of living only inside
        the previously-generated script.
        """
        short = ver.replace('f4_', '')
        csv_path = os.path.join(SCRIPT_DIR, 'refs',
                                'bytesig_ported_{}.csv'.format(short))
        if not os.path.isfile(csv_path):
            return fb_json
        rva_key = _ver_rva_key[ver]
        existing = _json.loads(fb_json)
        used = {s.get(rva_key) for s in existing if s.get(rva_key)}
        n_added = 0
        with open(csv_path, encoding='utf-8') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                parts = ln.split(',', 2)
                if len(parts) < 2:
                    continue
                try:
                    rva = int(parts[0], 16)
                except ValueError:
                    continue
                if rva in used:
                    continue
                used.add(rva)
                existing.append({'n': parts[1], 't': 'func', 'sig': '',
                                 rva_key: rva,
                                 'src': parts[2] if len(parts) > 2 else 'bytesig-port'})
                n_added += 1
        if n_added:
            print('  merged {} persisted bytesig names from {}'.format(
                n_added, os.path.basename(csv_path)))
        return _json.dumps(existing, separators=(',', ':'))

    for ver, fname, fb_json, anchors_name, parse_defines in F4_TARGETS:
        print(f'\n--- {ver} ---')
        if ver in fallback_json_by_ver:
            fb_json = fallback_json_by_ver[ver]
        elif fb_json is None:
            fb_json = fallback_json_ae
        fb_json = _merge_bytesig_csv(fb_json, ver)
        parse_args = list(base_parse_args) + list(parse_defines)
        enums, structs, template_source = collect_types(
            FALLOUT_H, RE_INCLUDE, parse_args,
            verbose=True, category_prefix='/CommonLibF4',
            extra_scope_paths=extra_scopes)
        print(f'  found {len(enums)} enums, {len(structs)} structs/classes')

        _enrich_symbols(symbols, structs)
        # Serialize AFTER enrichment: _enrich_symbols mutates 'sd'
        # (structured signature) fields onto the symbol dicts.  A
        # pre-loop dump silently dropped every signature from the
        # generated scripts ("Signatures applied: 0" at apply time).
        symbols_json = _json.dumps(symbols, separators=(',', ':'))

        vtable_structs = _build_vtable_structs(structs)
        _inject_vtable_fields(structs, vtable_structs)
        _flatten_structs(structs)
        _apply_secondary_vtable_typing(structs)

        # Apply per-version shift map (if one exists) to remap vtable struct
        # slot offsets onto this binary's actual layout.  Missing shift map ->
        # fall back to header-shaped layout; anchor verifier below catches drift.
        shift_map_path = os.path.join(SCRIPT_DIR, 'refs', 'shift_{}.json'.format(ver))
        shift_map = _load_shift_map_json(shift_map_path)
        if shift_map:
            print(f'  applying shift map: {shift_map_path}')
            _patch_vtable_structs(vtable_structs, shift_map, ver)

        # Verify hand-checked vtable slot anchors before emitting the script.
        # Fatal on mismatch — see core/anchor_verifier.py.
        _verify_anchors_or_exit(ver, vtable_structs,
                                os.path.join(anchors_dir, anchors_name))

        output_path = os.path.join(OUTPUT_DIR, fname)
        n_enums, n_structs = generate_script(
            enums, structs, vtable_structs, output_path,
            version=ver,
            symbols_json=symbols_json,
            fallback_symbols_json=fb_json,
            template_source=template_source,
            project_name='CommonLibF4',
        )
        print(f'  {fname}: {n_enums} enums, {n_structs} structs')


if __name__ == '__main__':
    main()
