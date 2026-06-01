#!/usr/bin/env python3
"""Parse xNVSE headers and generate a Ghidra import script for Fallout NV.

FNV is the odd one out: x86 (32-bit), no formal versionlib, no
CommonLib-style ``REL::ID`` macros.  Symbol sources, in priority order:

  1. ``addresses.scan_xnvse(...)``  hardcoded VAs scraped from xNVSE
     headers + .cpp (DEFINE_MEMBER_FN, typed-constant addresses, casted
     fn-pointer constants).
  2. ``refs/fnv_names.csv`` (optional)  per-name overrides / additions.
  3. clang AST + record-layouts on a small set of xNVSE entry headers
     for struct/enum types (best-effort: xNVSE uses pre-modern C++ and
     relies on Windows headers, so parse failures are expected and we
     fall back to labels-only).

Output: ``ghidrascripts/CommonLibImport_FNV.py``.
"""

import json as _json
import os
import sys

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
XNVSE_ROOT  = os.path.join(PROJECT_DIR, 'extern', 'xNVSE')
XNVSE_INCLUDE = os.path.join(XNVSE_ROOT, 'nvse')
XNVSE_NVSE_DIR = os.path.join(XNVSE_INCLUDE, 'nvse')
REFS_DIR    = os.path.join(SCRIPT_DIR, 'refs')
OUTPUT_DIR  = os.path.join(PROJECT_DIR, 'ghidrascripts')

# Entry header for type extraction.  We pick a "umbrella" header that
# pulls in the bulk of the game types; xNVSE doesn't have a single
# Starfield.h-style aggregate, so GameForms.h works as the closest
# equivalent (TESForm + all its subclasses).
ENTRY_HEADER = os.path.join(XNVSE_NVSE_DIR, 'GameForms.h')

sys.path.insert(0, SCRIPT_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))

from addresses import collect_all as collect_xnvse_symbols


def _make_symbols(funcs, labels):
    """Convert addresses output into the SYMBOLS array.

    The script-side ``version_key`` map looks symbols up by the ``'fnv'``
    key (see scripts/core/ghidra_import_gen.py).
    """
    symbols = []
    seen = set()

    for f in funcs:
        full_name = ('{}::{}'.format(f['class_'], f['name'])
                     if f.get('class_') else f['name'])
        key = (full_name, 'func', f['rva'])
        if key in seen:
            continue
        seen.add(key)
        symbols.append({
            'n':   full_name,
            't':   'func',
            'sig': '',
            'fnv': f['rva'],
            'src': f.get('src', 'xNVSE'),
        })

    for l in labels:
        key = (l['name'], 'label', l['rva'])
        if key in seen:
            continue
        seen.add(key)
        symbols.append({
            'n':   l['name'],
            't':   'label',
            'sig': '',
            'fnv': l['rva'],
            'src': l.get('src', 'xNVSE'),
        })

    return symbols


def _try_clang_types(verbose=True):
    """Best-effort clang AST parse of xNVSE headers.

    xNVSE was written for a much older C++ standard and relies on
    Windows.h, FNV-specific macros (DEFINE_MEMBER_FN, NiTPointerMap,
    etc.), and an idiosyncratic include layout (everything is rooted at
    ``nvse/nvse/``).  We try ``-std=c++17`` first which matches xNVSE's
    actual buildable standard.

    Returns empty containers on any parse failure so the rest of the
    pipeline still produces a usable labels-only script.
    """
    if not os.path.isfile(ENTRY_HEADER):
        if verbose:
            print('  xNVSE entry header not found: {}'.format(ENTRY_HEADER))
            print('  Falling back to labels-only output.')
        return {}, {}, {}, ''

    try:
        from clang_types import collect_types, _setup_include_paths
        from ghidra_import_gen import (
            build_vtable_structs,
            inject_vtable_fields,
            flatten_structs,
            apply_secondary_vtable_typing,
        )

        stub_dir   = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
        # xNVSE includes things as `nvse/Foo.h`, so the include base is
        # the directory containing the `nvse/` folder (XNVSE_INCLUDE).
        parse_args = _setup_include_paths(XNVSE_INCLUDE, stub_dir)
        # xNVSE targets pre-C++20 with MSVC-isms.  C++17 + permissive
        # parsing is the closest we can do with clang.
        parse_args = ['-std=c++17', '-fms-compatibility',
                      '-fms-extensions', '-Wno-everything',
                      '-DBUILD_NVSE',
                      '-D_WIN32', '-D_M_IX86'] + parse_args

        if verbose:
            print('Parsing xNVSE headers via clang AST...')
        enums, structs, template_source = collect_types(
            ENTRY_HEADER, XNVSE_NVSE_DIR, parse_args,
            verbose=verbose,
            root_namespace=None,           # xNVSE doesn't namespace its game types
            category_prefix='/xNVSE',
        )

        if verbose:
            print('Building vtable structs...')
        vtable_structs = build_vtable_structs(structs)
        inject_vtable_fields(structs, vtable_structs)
        flatten_structs(structs)
        apply_secondary_vtable_typing(structs)

        if verbose:
            print('  enums:    {}'.format(len(enums)))
            print('  structs:  {}'.format(len(structs)))
            print('  vtables:  {}'.format(len(vtable_structs)))
        return enums, structs, vtable_structs, template_source
    except (Exception, SystemExit) as e:
        # clang_types.collect_types() calls sys.exit() when clang.exe
        # isn't on PATH, so catch SystemExit too.
        print('WARNING: xNVSE AST parse failed ({}: {})'.format(
            type(e).__name__, e))
        if os.environ.get('BGS_DEBUG_FNV'):
            import traceback
            traceback.print_exc()
        print('         Falling back to labels-only output '
              '(no struct/enum types).')
        return {}, {}, {}, ''


def main():
    print('=== xNVSE -> Ghidra import script (Fallout NV) ===')
    print('PROJECT_DIR     =', PROJECT_DIR)
    print('XNVSE_ROOT      =', XNVSE_ROOT)
    print('ENTRY_HEADER    =', ENTRY_HEADER)
    print('OUTPUT_DIR      =', OUTPUT_DIR)
    print()

    if not os.path.isdir(XNVSE_ROOT):
        print('ERROR: {} not found.  Run `git submodule update --init` first.'.format(
            XNVSE_ROOT))
        sys.exit(1)

    # 1. Symbol scan: xNVSE headers + optional CSV overlay
    func_syms, label_syms = collect_xnvse_symbols(
        XNVSE_ROOT, REFS_DIR, verbose=True)

    if not func_syms and not label_syms:
        print('ERROR: no symbols extracted from xNVSE.  Check that '
              '`extern/xNVSE/nvse/nvse/` is populated.')
        sys.exit(1)

    # 2. Type extraction via libclang (best-effort)
    enums, structs, vtable_structs, template_source = _try_clang_types(verbose=True)

    # 2a. PDB-derived enums (3.4k of them; clang produces ~40).  Merge
    # WITHOUT clobbering xNVSE enums.
    pdb_enums_json = r'C:\GhidraProjects\scripts\Fallout_Debug_enums.json'
    if os.path.isfile(pdb_enums_json):
        try:
            import json as _j
            pdb_enums = _j.loads(open(pdb_enums_json, encoding='utf-8').read())
            n_added = 0
            for cls, en in pdb_enums.items():
                if cls in enums:
                    continue
                # Convert ``values`` lists back to tuples (json normalizes)
                en['values'] = [tuple(v) for v in en.get('values', [])]
                enums[cls] = en
                n_added += 1
            print('PDB enums merged: {} added ({} members)'.format(
                  n_added, sum(len(e['values']) for e in pdb_enums.values())))
        except Exception as e:
            print('WARNING: PDB enum merge failed: {}: {}'.format(
                type(e).__name__, e))

    # 2b. PDB-derived type layouts -- merge into structs.  When clang
    # provides a REAL layout (size>0 with non-vftable fields), it wins
    # (xNVSE knows methods + RE-style namespacing).  When clang is empty
    # (xNVSE never documented that type), PDB fills it in.
    pdb_types_json = r'C:\GhidraProjects\scripts\Fallout_Debug_types.json'
    if os.path.isfile(pdb_types_json):
        try:
            from pdb_types_to_pipeline import convert_pdb_types
            from pathlib import Path
            pdb_structs, n_skip, n_field = convert_pdb_types(
                Path(pdb_types_json),
                Path(pdb_enums_json) if os.path.isfile(pdb_enums_json) else None)
            n_added = 0
            n_upgraded = 0
            for cls, st in pdb_structs.items():
                existing = structs.get(cls)
                if existing is None:
                    structs[cls] = st
                    n_added += 1
                    continue
                # Existing clang entry -- check if it has REAL field data
                ex_fields = existing.get('fields', [])
                non_vft = [f for f in ex_fields
                           if not f.get('name', '').startswith('__vftable')]
                if existing.get('size', 0) == 0 or not non_vft:
                    # Empty clang stub -- upgrade with PDB layout, but keep
                    # clang's class methods + vtable info if any
                    upgraded = dict(st)
                    upgraded['vmethods']         = existing.get('vmethods', {})
                    upgraded['methods']          = existing.get('methods', {})
                    upgraded['has_vtable']       = existing.get('has_vtable', False)
                    upgraded['bases']            = existing.get('bases', [])
                    upgraded['_overload_aliases'] = existing.get('_overload_aliases', {})
                    structs[cls] = upgraded
                    n_upgraded += 1
            print('PDB types merged: {} new + {} upgraded (skipped: {} '
                  'empty/anon, {} fields total in source)'.format(
                  n_added, n_upgraded, n_skip, n_field))
        except Exception as e:
            print('WARNING: PDB type merge failed: {}: {}'.format(
                type(e).__name__, e))

    # 3. Assemble SYMBOLS array
    symbols      = _make_symbols(func_syms, label_syms)
    symbols_json = _json.dumps(symbols, separators=(',', ':'))

    n_func  = sum(1 for s in symbols if s['t'] == 'func')
    n_label = sum(1 for s in symbols if s['t'] == 'label')
    print('\nSymbols: {} total ({} funcs, {} labels)'.format(
        len(symbols), n_func, n_label))

    # 3b. PDB-derived fallback symbols (NVSE-known + Xbox dev-kit PDB).
    # Primary xNVSE wins on address collision; fallbacks only fill gaps.
    primary_addrs = {s['a'] for s in symbols if s.get('a')}
    from pdb_naming import build_fallback_symbols
    fb_all = build_fallback_symbols()
    fallback_symbols = [s for s in fb_all if s['a'] not in primary_addrs]
    n_fb_func  = sum(1 for s in fallback_symbols if s['t'] == 'func')
    n_fb_label = sum(1 for s in fallback_symbols if s['t'] == 'label')
    print('Fallback symbols (PDB / NVSE-known, new only): {} total ({} funcs, {} labels)'.format(
        len(fallback_symbols), n_fb_func, n_fb_label))
    fallback_symbols_json = _json.dumps(fallback_symbols, separators=(',', ':'))

    # 4. Vtable anchor verification (only if we successfully parsed
    # vtables -- labels-only run skips this).
    if vtable_structs:
        try:
            from anchor_verifier import verify_or_exit as _verify
            _verify('fnv', vtable_structs,
                    os.path.join(SCRIPT_DIR, 'anchors', 'fnv.csv'))
        except Exception as e:
            print('  anchor verification skipped: {}'.format(e))
    else:
        print('Skipping vtable anchor verification: no vtable_structs '
              '(labels-only run).')

    # 5. Generate the Ghidra Jython import script
    from ghidra_import_gen import generate_script
    output_path = os.path.join(OUTPUT_DIR, 'CommonLibImport_FNV.py')
    n_enums, n_structs = generate_script(
        enums, structs, vtable_structs,
        output_path,
        version='fnv',
        symbols_json=symbols_json,
        fallback_symbols_json=fallback_symbols_json,
        template_source=template_source,
        project_name='xNVSE',
    )
    print('\nWrote {}'.format(output_path))
    print('  {} enums, {} structs, {} vtable structs, {} symbols'.format(
        n_enums, n_structs, len(vtable_structs), len(symbols)))


if __name__ == '__main__':
    main()
