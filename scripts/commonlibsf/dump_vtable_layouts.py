#!/usr/bin/env python3
"""Dump per-class vtable layouts from a CommonLib-imported Starfield project.

Walks ``VTABLE_<Class>`` symbols in the named Ghidra project, reads each
vtable's function-pointer entries inline, looks the slot targets up
against Ghidra's function manager, and emits a ``vtable_layout`` CSV that
``scripts/core/build_shift_map.py`` can diff against another version's
layout.

Vtable bounds are determined by sorting all ``VTABLE_*`` symbol addresses
within the same memory block and reading slots from each vtable's start
until the next vtable's start (or the end of the block).  This avoids
having to know slot counts ahead of time and stays robust against
multi-inheritance secondary vtables (``VTABLE_<Class>_<N>``) which are
treated as their own entries.

Fingerprint: first ``FP_BYTES`` bytes of each slot function, as
space-separated hex (no masking yet -- raw bytes are good enough for
SF intra-version-line matching since CommonLib applies the same names
across patches; masking can be added later if the matcher needs it).

Usage::

    python -m dump_vtable_layouts \\
        --project-dir C:/GhidraProjects/Starfield \\
        --project-name StarfieldProject \\
        --program Starfield.exe \\
        --label sf_1_16_236 \\
        --out scripts/commonlibsf/refs/sf_1-16-236-0_vtables.csv

When invoked with no args it auto-fills from the BGS pipeline
defaults (``ghidraprojects/BethesdaGhidraScripts/`` project, current
SF PE version detected from ``exes/starfield/sf/Starfield.exe``).
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"
SCRIPT_DIR  = Path(__file__).resolve().parent
CORE_DIR    = REPO_DIR / "scripts" / "core"

sys.path.insert(0, str(CORE_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

FP_BYTES = 32
MAX_SLOTS_PER_VTABLE = 384   # hard cap; real vtables top out around 250


def _parse_args():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  required=True, help='Ghidra project directory (e.g. C:/GhidraProjects/Starfield)')
    ap.add_argument('--project-name', required=True, help='Ghidra project name (e.g. StarfieldProject)')
    ap.add_argument('--program',      default='Starfield.exe', help='program filename inside the project')
    ap.add_argument('--label',        required=True, help='binary label embedded in CSV rows (e.g. sf_1_16_236)')
    ap.add_argument('--out',          required=True, help='output CSV path')
    ap.add_argument('--no-fingerprints', action='store_true',
                    help='skip per-slot function fingerprint extraction (faster, weaker cross-version matching)')
    return ap.parse_args()


def _find_program(project, program_name):
    root = project.getProjectData().getRootFolder()

    def walk(folder):
        for f in folder.getFiles():
            if f.getName() == program_name:
                return f
        for sub in folder.getFolders():
            r = walk(sub)
            if r is not None:
                return r
        return None

    return walk(root)


def _enumerate_vtables(program):
    """Return [(class_name, vtable_addr_int, primary_or_secondary_index, sym_name)].

    Recognizes two conventions:
      ``VTABLE_<Class>``        flat (CommonLib import script convention)
      ``VTABLE_<Class>_N``      flat secondary vtable (N=1,2,...)
      ``<Class>::vftable``      namespace-scoped (Ghidra RTTI analyzer)
      ``<Class>::vftable_N``    namespace-scoped secondary

    Classes named under both conventions are deduped by address, keeping
    the first encountered.  This matters: CommonLib import doesn't always
    create flat labels for classes Ghidra's RTTI already found.
    """
    sm = program.getSymbolTable()
    seen_addrs = {}
    out = []

    def _record(cls, idx, sym):
        addr_int = sym.getAddress().getOffset()
        if addr_int in seen_addrs:
            return
        seen_addrs[addr_int] = True
        out.append((cls, addr_int, idx, sym.getName(True)))

    for s in sm.getAllSymbols(True):
        n = s.getName()
        if n.startswith('VTABLE_'):
            rest = n[len('VTABLE_'):]
            idx = 0
            cls = rest
            if '_' in rest:
                head, _, tail = rest.rpartition('_')
                if tail.isdigit():
                    idx = int(tail)
                    cls = head
            _record(cls, idx, s)
            continue
        # Ghidra RTTI namespace-scoped: <Class>::vftable[_N]
        if n == 'vftable' or n.startswith('vftable_'):
            ns = s.getParentNamespace()
            if ns is None or ns.isGlobal():
                continue
            cls = ns.getName(True).replace('::', '__')
            idx = 0
            if n.startswith('vftable_'):
                tail = n[len('vftable_'):]
                if tail.isdigit():
                    idx = int(tail)
            _record(cls, idx, s)
            continue
    return out


def _get_typed_vtable_length(program, vaddr_int):
    """Return byte length of the vftable struct type applied at vaddr.

    When Ghidra's RTTI analyzer or CommonLib's import script has typed a
    vtable as a ``<Class>__vftable`` / ``::vftable`` struct, the struct's
    getLength() is the exact byte count of the vtable -- the most reliable
    slot bound, since it doesn't depend on adjacent ``VTABLE_*`` symbol
    placement (gaps fool the next-symbol heuristic when intervening
    vtables don't have symbols).  Returns None for untyped vtables.
    """
    af = program.getAddressFactory().getDefaultAddressSpace()
    listing = program.getListing()
    data = listing.getDataAt(af.getAddress(vaddr_int))
    if data is None:
        return None
    dt = data.getDataType()
    if dt is None:
        return None
    name = (dt.getName() or '').lower()
    if 'vftable' not in name and 'vtbl' not in name:
        return None
    length = dt.getLength()
    if length is None or length <= 0:
        return None
    return length


def _vtable_terminator_map(program, vtable_entries):
    """For each vtable address, find the address where the vtable ends.

    Resolution priority:
      1. ``<Class>__vftable`` struct length at the vtable address (most
         reliable -- Ghidra knows the exact slot count).
      2. Next ``VTABLE_*`` symbol address in the same memory block (loose
         but bounds the over-read for typed-less vtables).
      3. Memory block end (final fallback for isolated vtables).
    """
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    addrs = sorted({e[1] for e in vtable_entries})
    end_by_addr = {}
    for i, a in enumerate(addrs):
        typed_len = _get_typed_vtable_length(program, a)
        if typed_len is not None:
            end_by_addr[a] = a + typed_len
            continue
        block = mem.getBlock(af.getAddress(a))
        if block is None:
            end_by_addr[a] = a + 8 * 256
            continue
        block_end = block.getEnd().getOffset() + 1
        next_a = addrs[i + 1] if i + 1 < len(addrs) else block_end
        end_by_addr[a] = min(next_a, block_end)
    return end_by_addr


def _read_slot_pointers(program, vaddr_int, end_addr_int):
    """Read 8-byte function pointers from vaddr until end_addr or hard cap.

    Terminates on the first slot whose pointer:
      - is null
      - is outside the image (x64, image base 0x140000000)
      - doesn't resolve to a known function via the function manager
        (catches over-read into adjacent data once Ghidra's analysis is
        good enough to mark vfuncs as functions)
    Also capped at ``MAX_SLOTS_PER_VTABLE`` regardless of terminator -- the
    next-VTABLE-symbol heuristic doesn't bound tightly when sections have
    sparse vtable clustering, so we cap to avoid running off into pointer-
    shaped data after the real vtable ends.
    """
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    fm = program.getFunctionManager()
    out = []
    cur = vaddr_int
    max_end = min(end_addr_int, vaddr_int + MAX_SLOTS_PER_VTABLE * 8)
    while cur + 8 <= max_end:
        try:
            ptr = mem.getLong(af.getAddress(cur))
        except Exception:
            break
        if ptr == 0:
            break
        if ptr < 0x140000000 or ptr > 0x200000000:
            break
        ptr_addr = af.getAddress(ptr & 0xFFFFFFFFFFFFFFFF)
        # Require the slot to point at (or into) a known function.  Avoids
        # over-reading into the next vtable header / RTTI structures.
        if fm.getFunctionAt(ptr_addr) is None and fm.getFunctionContaining(ptr_addr) is None:
            break
        out.append(ptr & 0xFFFFFFFFFFFFFFFF)
        cur += 8
    return out


def _read_fingerprint(program, func_addr_int, n=FP_BYTES):
    mem = program.getMemory()
    af = program.getAddressFactory().getDefaultAddressSpace()
    try:
        buf = bytearray(n)
        for i in range(n):
            buf[i] = mem.getByte(af.getAddress(func_addr_int + i)) & 0xFF
    except Exception:
        return ''
    return ' '.join('{:02X}'.format(b) for b in buf)


def _func_name_at(program, addr_int):
    fm = program.getFunctionManager()
    af = program.getAddressFactory().getDefaultAddressSpace()
    f = fm.getFunctionAt(af.getAddress(addr_int))
    if f is None:
        f = fm.getFunctionContaining(af.getAddress(addr_int))
        if f is None:
            return ''
    # getName(True) includes namespace path (Class::method)
    return f.getName(True)


def main():
    args = _parse_args()

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    from vtable_layout import BinaryLayout, ClassVtable, SlotEntry, save_csv

    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        domain_file = _find_program(project, args.program)
        if domain_file is None:
            print('ERROR: {} not found in project'.format(args.program))
            sys.exit(1)
        print('Found program: {}'.format(domain_file.getPathname()))

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, False, False, monitor)
        try:
            print('Enumerating VTABLE_* symbols...')
            t0 = time.time()
            entries = _enumerate_vtables(program)
            print('  found {} vtable symbols ({:.1f}s)'.format(len(entries), time.time() - t0))
            if not entries:
                print('ERROR: no VTABLE_* symbols found.  Apply CommonLibImport_SF.py first.')
                sys.exit(1)

            print('Computing vtable bounds...')
            end_by_addr = _vtable_terminator_map(program, entries)

            print('Walking slots + naming functions...')
            layout = BinaryLayout(binary_label=args.label, binary_path=args.program)
            t0 = time.time()
            n_slots = 0
            for i, (cls, vaddr, idx, sym_name) in enumerate(entries):
                if i % 200 == 0 and i:
                    elapsed = time.time() - t0
                    pace = i / elapsed
                    remaining = (len(entries) - i) / pace
                    print('  {} / {} vtables ({:.0f}/s, ~{:.0f}s remaining)'.format(
                        i, len(entries), pace, remaining))
                # Distinguish primary vs secondary in the layout's class key.
                layout_cls = cls if idx == 0 else '{}__{}'.format(cls, idx)
                end_addr = end_by_addr.get(vaddr, vaddr + 8 * 256)
                slot_ptrs = _read_slot_pointers(program, vaddr, end_addr)
                if not slot_ptrs:
                    continue
                cv = layout.upsert(layout_cls, vaddr)
                for slot, fptr in enumerate(slot_ptrs):
                    name = _func_name_at(program, fptr)
                    fp = '' if args.no_fingerprints else _read_fingerprint(program, fptr)
                    cv.add(SlotEntry(slot=slot, func_addr=fptr,
                                     func_name=name, fingerprint=fp))
                    n_slots += 1
            print('  done: {} vtables, {} slots ({:.1f}s)'.format(
                len(layout.classes), n_slots, time.time() - t0))

            rows = save_csv(layout, args.out)
            print('Wrote {} rows to {}'.format(rows, args.out))
        finally:
            program.release(consumer)


if __name__ == '__main__':
    main()
