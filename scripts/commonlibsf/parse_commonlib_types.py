#!/usr/bin/env python3
"""
Parse CommonLibSF headers and generate a Ghidra import script for Starfield.

Single-version pipeline (no SE/AE-style branching).  Symbol sources, in
priority order:

  1. ``RE/IDs.h``         function IDs grouped by ``namespace RE::ID::<Class>``
  2. ``RE/IDs_RTTI.h``    flat ``RTTI_*`` labels
  3. ``RE/IDs_NiRTTI.h``  flat ``NiRTTI_*`` labels
  4. ``RE/IDs_VTABLE.h``  ``std::array<REL::ID, N> VTABLE_*`` slots
  5. clang AST + record-layouts on ``RE/Starfield.h`` for type definitions
     (best-effort -- if the libclang parse fails, fall through to a
     label/symbol-only script)

Output: ``ghidrascripts/CommonLibImport_SF.py``.
"""

import json as _json
import os
import re
import sys

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(os.path.dirname(SCRIPT_DIR))
COMMONLIB_INCLUDE = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSF', 'include')
STARFIELD_H = os.path.join(COMMONLIB_INCLUDE, 'RE', 'Starfield.h')
RE_INCLUDE  = os.path.join(COMMONLIB_INCLUDE, 'RE')
OUTPUT_DIR  = os.path.join(PROJECT_DIR, 'ghidrascripts')
EXES_DIR    = os.path.join(PROJECT_DIR, 'exes', 'starfield', 'sf')

sys.path.insert(0, os.path.join(SCRIPT_DIR))
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))

from address_library import AddressLibrary
from ids_parser import collect_all as collect_id_symbols
from pe_version import get_pe_version


def _detect_sf_version():
    """Return the PE version tuple of the first Starfield.exe in EXES_DIR.

    Returns None when no exe is present or when the version can't be parsed.
    Steam-DRM-packed binaries are handled by pe_version's FileVersion-string
    fallback (VS_FIXEDFILEINFO is scrambled by SteamStub).
    """
    if not os.path.isdir(EXES_DIR):
        return None
    for fname in sorted(os.listdir(EXES_DIR)):
        if not fname.lower().endswith('.exe'):
            continue
        if 'unpacked' in fname.lower():
            continue
        v = get_pe_version(os.path.join(EXES_DIR, fname))
        if v:
            return v
    return None


def _make_symbols(funcs, labels):
    """Convert ids_parser output into the SYMBOLS array used by the import script.

    ``sf_off`` carries the offset; the script-side ``version_key`` map
    looks symbols up by the ``'sf'`` key (see scripts/core/ghidra_import_gen.py).
    """
    symbols = []
    seen = set()

    for f in funcs:
        full_name = '{}::{}'.format(f['class_'], f['name']) if f.get('class_') else f['name']
        key = (full_name, 'func', f['sf_off'])
        if key in seen:
            continue
        seen.add(key)
        symbols.append({
            'n':   full_name,
            't':   'func',
            'sig': '',
            'sf':  f['sf_off'],
            'src': 'CommonLibSF',
        })

    for l in labels:
        key = (l['name'], 'label', l['sf_off'])
        if key in seen:
            continue
        seen.add(key)
        symbols.append({
            'n':   l['name'],
            't':   'label',
            'sig': '',
            'sf':  l['sf_off'],
            'src': 'CommonLibSF',
        })

    return symbols


SF_IMAGE_BASE = 0x140000000
# The offline naming corpus in refs/ was produced against this binary.
CORPUS_SOURCE_VERSION = (1, 16, 236, 0)


def _build_fallback_symbols(addr_lib, sf_version, verbose=True):
    """Assemble FALLBACK_SYMBOLS from the two on-disk name pools:

      1. ``extern/AddressLibraryDatabase/starfield.rename`` -- meh321's
         curated ID->name database (~974 entries).  ID-keyed, so it
         resolves against ANY versionlib: fully version-portable.
      2. ``refs/sf116_named_from_combined_final.csv`` -- the offline
         enrichment corpus (~64k ``0xVA,name`` rows: byte-sig + BSim +
         RTTI-walk names harvested from the user's Combined project).
         VA-keyed against 1.16.236; when the detected exe is a different
         patch the RVAs are remapped 236-RVA -> ID -> detected-RVA via
         the two versionlibs.

    Fallback symbols only ever rename FUN_/sub_ placeholders at apply
    time, so lower-confidence corpus names are safe to ship.
    """
    out = []
    by_rva = set()

    # --- 1. starfield.rename (curated, ID-keyed -- takes priority) ---
    rename_path = os.path.join(PROJECT_DIR, 'extern',
                               'AddressLibraryDatabase', 'starfield.rename')
    n_rename = 0
    if os.path.isfile(rename_path):
        with open(rename_path, 'r', encoding='utf-8', errors='replace') as f:
            for ln in f:
                parts = ln.split(None, 1)
                if len(parts) != 2 or not parts[0].isdigit():
                    continue  # version header / malformed
                rva = addr_lib.sf_db.get(int(parts[0]))
                if not rva or rva in by_rva:
                    continue
                name = parts[1].strip()
                # meh321 wildcard convention: trailing _* means "append
                # address" -- drop it; Ghidra names must be unique anyway
                # and the apply path suffixes on collision.
                if name.endswith('_*'):
                    name = name[:-2]
                if not name:
                    continue
                out.append({'n': name, 't': 'func', 'sig': '',
                            'sf': rva, 'src': 'starfield.rename'})
                by_rva.add(rva)
                n_rename += 1
    if verbose:
        print('Fallback pool 1 (starfield.rename): {} resolved'.format(n_rename))

    # --- 2. offline corpus (VA-keyed at 1.16.236) ---
    corpus_path = os.path.join(SCRIPT_DIR, 'refs',
                               'sf116_named_from_combined_final.csv')
    n_corpus = n_remap_miss = 0
    if os.path.isfile(corpus_path):
        det = tuple(sf_version) + (0,) * (4 - len(sf_version))
        same_build = det[:4] == CORPUS_SOURCE_VERSION
        rev_236 = None
        det_db = None
        if not same_build:
            # Remap chain: corpus 236-RVA -> versionlib ID -> detected RVA.
            try:
                src_lib = AddressLibrary()
                src_lib.load_all(os.path.join(PROJECT_DIR, 'addresslibrary'),
                                 pe_version=CORPUS_SOURCE_VERSION)
                rev_236 = {rva: i for i, rva in src_lib.sf_db.items()}
                det_db = addr_lib.sf_db
                if verbose:
                    print('Corpus remap active: 1.16.236 -> {} via versionlib IDs'
                          .format('.'.join(str(x) for x in det[:4])))
            except FileNotFoundError:
                print('WARNING: no versionlib for 1.16.236 -- corpus names '
                      'skipped (cannot remap to detected build).')
                rev_236 = {}
        with open(corpus_path, 'r', encoding='utf-8', errors='replace') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('target_va'):
                    continue
                parts = ln.split(',', 1)
                if len(parts) != 2:
                    continue
                try:
                    va = int(parts[0], 16)
                except ValueError:
                    continue
                rva236 = va - SF_IMAGE_BASE
                if rva236 <= 0:
                    continue
                if same_build:
                    rva = rva236
                else:
                    id_ = rev_236.get(rva236) if rev_236 else None
                    rva = det_db.get(id_) if (id_ is not None and det_db) else None
                    if rva is None:
                        n_remap_miss += 1
                        continue
                if rva in by_rva:
                    continue
                name = parts[1].strip()
                if not name:
                    continue
                out.append({'n': name, 't': 'func', 'sig': '',
                            'sf': rva, 'src': 'sf116_corpus'})
                by_rva.add(rva)
                n_corpus += 1
    if verbose:
        print('Fallback pool 2 (sf116 corpus): {} loaded{}'.format(
            n_corpus,
            ', {} dropped (no ID remap)'.format(n_remap_miss) if n_remap_miss else ''))
        print('Total fallback symbols: {}'.format(len(out)))
    return out


def _try_clang_types(verbose=True):
    """Best-effort clang AST parse of CommonLibSF headers.

    Wrapped in a broad try/except: CommonLibSF uses C++23 features and may
    need additional system include stubs.  When the parse fails we return
    empty type containers so the rest of the pipeline still produces a
    usable labels-only script.
    """
    try:
        from clang_types import collect_types, _setup_include_paths
        from ghidra_import_gen import (
            build_vtable_structs,
            inject_vtable_fields,
            flatten_structs,
            apply_secondary_vtable_typing,
        )

        stub_dir   = os.path.join(os.path.dirname(SCRIPT_DIR), 'core', '_clang_stubs')
        parse_args = _setup_include_paths(COMMONLIB_INCLUDE, stub_dir)
        # libxse/commonlibsf split out the REL/ and REX/ headers into a
        # nested commonlib-shared submodule (same shape as F4 already uses).
        # The old SR-E/Starfield-Reverse-Engineering tree had them inline
        # under include/, so adding -I unconditionally is harmless if the
        # nested submodule isn't present (clang ignores missing dirs).
        shared_include = os.path.join(PROJECT_DIR, 'extern', 'CommonLibSF',
                                      'lib', 'commonlib-shared', 'include')
        if os.path.isdir(shared_include):
            parse_args = ['-I' + shared_include] + parse_args
        # CommonLibSF uses C++23 features.  -std=c++23 is widely supported by
        # recent clang; older clang falls back to c++latest.
        parse_args = ['-std=c++23'] + parse_args

        if verbose:
            print('Parsing CommonLibSF headers via clang AST...')
        enums, structs, template_source = collect_types(
            STARFIELD_H, RE_INCLUDE, parse_args,
            verbose=verbose,
            root_namespace='RE',
            category_prefix='/CommonLibSF',
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
        # clang_types.collect_types() calls sys.exit() when clang.exe isn't
        # on PATH, so catch SystemExit too.
        print('WARNING: CommonLibSF AST parse failed ({}: {})'.format(type(e).__name__, e))
        print('         Falling back to labels-only output (no struct/enum types).')
        return {}, {}, {}, ''


def main():
    print('=== CommonLibSF -> Ghidra import script ===')
    print('PROJECT_DIR        =', PROJECT_DIR)
    print('COMMONLIB_INCLUDE  =', COMMONLIB_INCLUDE)
    print('STARFIELD_H        =', STARFIELD_H)
    print('OUTPUT_DIR         =', OUTPUT_DIR)
    print()

    if not os.path.isfile(STARFIELD_H):
        print('ERROR: {} not found.  Run `git submodule update --init` first.'.format(
            STARFIELD_H))
        sys.exit(1)

    # 1. Address library -- match the bin to the installed Starfield.exe.
    sf_version = _detect_sf_version()
    if sf_version is None:
        print('ERROR: Could not detect Starfield.exe version in {}.  '
              'Drop a Starfield.exe in that directory.'.format(EXES_DIR))
        sys.exit(1)
    print('Detected Starfield.exe version: {}'.format(
        '.'.join(str(x) for x in sf_version)))

    addr_lib = AddressLibrary()
    try:
        addr_lib.load_all(os.path.join(PROJECT_DIR, 'addresslibrary'),
                          pe_version=sf_version)
    except FileNotFoundError as e:
        print('ERROR: {}'.format(e))
        sys.exit(1)
    if not addr_lib.sf_db:
        print('ERROR: Starfield address library loaded zero entries.')
        sys.exit(1)
    print('Address library: versionlib-{}.bin ({:,} entries)'.format(
        '-'.join(str(x) for x in (addr_lib.sf_version or sf_version)),
        len(addr_lib.sf_db)))

    # 2. Manifest symbol scan
    func_syms, label_syms = collect_id_symbols(RE_INCLUDE, addr_lib, verbose=True)

    # 3. Type extraction via libclang (best-effort)
    enums, structs, vtable_structs, template_source = _try_clang_types(verbose=True)

    # 4. Assemble SYMBOLS array
    symbols      = _make_symbols(func_syms, label_syms)
    symbols_json = _json.dumps(symbols, separators=(',', ':'))

    n_func  = sum(1 for s in symbols if s['t'] == 'func')
    n_label = sum(1 for s in symbols if s['t'] == 'label')
    print('\nSymbols: {} total ({} funcs, {} labels)'.format(
        len(symbols), n_func, n_label))

    # 5. Verify hand-checked vtable slot anchors before emitting.
    # Single-version pipeline today, but the seam exists so future SF
    # patch revisions can ship anchor CSVs that catch silent drift.
    # Skip when vtable_structs is empty (labels-only run without clang):
    # the verifier expects parsed vtables and would fail with "class not
    # found" on every anchor row.  Anchor drift is meaningless when no
    # vtables were inferred in the first place.
    if vtable_structs:
        from anchor_verifier import verify_or_exit as _verify_anchors_or_exit
        from vtable_matcher import load_json as _load_shift_map_json
        from vtable_patcher import patch_vtable_structs as _patch_vtable_structs

        # Apply per-version shift map (if one exists) to remap onto the
        # actual binary layout.  Single-version pipeline today but symmetric
        # with the SSE/F4 builds; future SF patches can drop in a shift map
        # without touching this code.
        shift_map_path = os.path.join(SCRIPT_DIR, 'refs', 'shift_sf.json')
        shift_map = _load_shift_map_json(shift_map_path)
        if shift_map:
            print('Applying SF vtable shift map: {}'.format(shift_map_path))
            _patch_vtable_structs(vtable_structs, shift_map, 'sf')

        _verify_anchors_or_exit('sf', vtable_structs,
                                os.path.join(SCRIPT_DIR, 'anchors', 'sf.csv'))
    else:
        print('Skipping vtable anchor verification: no vtable_structs '
              '(labels-only run -- needs clang.exe for AST-based vtable '
              'inference to produce anchorable structs).')

    # 6. Fallback symbols: starfield.rename + the offline naming corpus.
    # Primary CommonLibSF symbols win on RVA collision at apply time
    # (fallbacks only rename FUN_/sub_ placeholders).
    print()
    fallback_symbols = _build_fallback_symbols(addr_lib, sf_version)
    primary_rvas = {s['sf'] for s in symbols if s.get('sf')}
    fallback_symbols = [s for s in fallback_symbols
                        if s['sf'] not in primary_rvas]
    print('Fallback symbols after primary-RVA dedup: {}'.format(
        len(fallback_symbols)))
    fallback_symbols_json = _json.dumps(fallback_symbols, separators=(',', ':'))

    # 7. Generate the Ghidra Jython import script
    from ghidra_import_gen import generate_script
    output_path = os.path.join(OUTPUT_DIR, 'CommonLibImport_SF.py')
    n_enums, n_structs = generate_script(
        enums, structs, vtable_structs,
        output_path,
        version='sf',
        symbols_json=symbols_json,
        fallback_symbols_json=fallback_symbols_json,
        template_source=template_source,
        project_name='CommonLibSF',
    )
    print('\nWrote {}'.format(output_path))
    print('  {} enums, {} structs, {} vtable structs, {} symbols, {} fallback'.format(
        n_enums, n_structs, len(vtable_structs), len(symbols),
        len(fallback_symbols)))


if __name__ == '__main__':
    main()
