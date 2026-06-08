#!/usr/bin/env python3
"""Byte-signature port directly against Ghidra programs in a combined
project — no exe files required.

Uses the 1.11.221 Bethesda debug PDB as the source name pool by default
(~31k publics, much richer than CommonLibF4 alone) and ports matching
names into the other Fallout 4 binaries imported in the same Ghidra
project (OG / NG / AE / VR).  Renames functions in place so no separate
apply pass is needed.

For each target the .text bytes are pulled straight out of the program
via Memory.getBytes; source-name bytes come from the source program's
.text at each name's RVA.  Exact 32-byte match (Pass 1) plus masked
48-byte retry wildcarding rel32 / rip-rel operands (Pass 2) -- same
algorithm as scripts/core/bytesig_port.py.

Usage:
  python scripts/commonlibf4/bytesig_port_combined.py
       [--project-dir C:/GhidraProjects --project-name Combined]
       [--source 221] [--targets og ng ae vr]

Defaults work for the C:/GhidraProjects/Combined.gpr layout with the
``Fallout4_<VER>_<patch>.exe`` naming we observed in the project tree.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path

REPO_DIR     = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR   = REPO_DIR / "tools" / "ghidra"
GENERATED    = REPO_DIR / "ghidrascripts"
PDB_PUBLICS  = REPO_DIR / "scripts" / "commonlibf4" / "refs" / "f4_221_pdb_publics.txt"

sys.path.insert(0, str(REPO_DIR / "scripts" / "core"))
from bytesig_port import build_prefix_index, port_symbols  # noqa: E402


# Version → (CommonLibImport filename, [path-substring hints used to find
# the binary inside a combined project]).  Mirrors apply_f4_to_user_project.
VERSIONS = {
    'og':  ('CommonLibImport_F4_OG.py',  ['_og_', '_og.', '1_10_163', '1.10.163']),
    'ng':  ('CommonLibImport_F4_NG.py',  ['_ng_', '_ng.', '1_10_984', '1.10.984', '1_10_980', '1.10.980']),
    'ae':  ('CommonLibImport_F4_AE.py',  ['_ae_', '_ae.', ' ae.exe', '1_11_191', '1.11.191']),
    'vr':  ('CommonLibImport_F4_VR.py',  ['fallout4vr', 'fallout4_vr', '1_2_72', '1.2.72']),
    '221': ('CommonLibImport_F4_221.py', ['_221.exe', '_221_', '1_11_221', '1.11.221']),
}

VERSION_TO_RVA_KEY = {'og': 'og', 'ng': 'ng', 'ae': 'a', 'vr': 'v', '221': '221'}

_JSON_LOADS_RE = re.compile(r"^_json(?:_sym)?\.loads\((.+)\)$")


def _read_symbols_from_script(version: str) -> dict[str, int]:
    """{name: rva} from CommonLibImport_F4_<VER>.py SYMBOLS array.

    Tolerates both the raw-JSON and ``_json_sym.loads(...)`` wrapped
    forms emitted by ghidra_import_gen.py.
    """
    script_name = VERSIONS[version][0]
    p = GENERATED / script_name
    if not p.is_file():
        return {}
    content = p.read_text(encoding="utf-8")
    m = re.search(r"^SYMBOLS = (.+?)$", content, re.M)
    if not m:
        return {}
    val = m.group(1).strip()
    wrap = _JSON_LOADS_RE.match(val)
    if wrap is not None:
        val = ast.literal_eval(wrap.group(1))
    syms = json.loads(val)
    rva_key = VERSION_TO_RVA_KEY[version]
    out: dict[str, int] = {}
    for s in syms:
        if s.get('t') != 'func':
            continue
        rva = s.get(rva_key)
        name = s.get('n', '')
        if not rva or not name or '<' in name or '>' in name:
            continue
        out.setdefault(name, rva)
    return out


def _read_f4_221_pdb_publics() -> dict[str, int]:
    """{name: rva} from the 1.11.221 debug PDB publics dump."""
    if not PDB_PUBLICS.is_file():
        return {}
    line_re = re.compile(r"^\s*public\s+\[0x([0-9A-Fa-f]+)\]\s+(\S.*?)\s*$")
    bad_substr = ("RTTI_", "::`vftable'", "::`RTTI",
                  "type_info::", "`typeinfo for", "anonymous namespace",
                  "`vector-deleting-destructor", "<lambda_")
    name_rx = re.compile(r"^[A-Za-z_][\w:]*$")
    out: dict[str, int] = {}
    with open(PDB_PUBLICS, "r", encoding="utf-8", errors="replace") as f:
        for ln in f:
            m = line_re.match(ln)
            if not m:
                continue
            try:
                rva = int(m.group(1), 16)
            except ValueError:
                continue
            if rva == 0:
                continue
            raw = m.group(2)
            if any(b in raw for b in bad_substr):
                continue
            qname = raw.split("(", 1)[0].strip()
            if not qname or "<" in qname or ">" in qname:
                continue
            if not name_rx.match(qname):
                continue
            out.setdefault(qname, rva)
    return out


def _find_program(root, hints: list[str], stem: str = "Fallout4"):
    """Return the domain file whose path contains any of ``hints`` and whose
    name starts with ``stem`` (or contains ``vr`` for the VR stem).  None on
    no match or multiple unambiguous matches.
    """
    matches = []

    def walk(folder, prefix=""):
        for f in folder.getFiles():
            n = f.getName()
            full = prefix + "/" + n
            if not n.lower().endswith('.exe'):
                continue
            if any(h in full.lower() for h in hints):
                matches.append((full, f))
        for sub in folder.getFolders():
            walk(sub, prefix + "/" + sub.getName())

    walk(root)
    if len(matches) == 1:
        return matches[0]
    return None


def _load_text_block(program):
    """Return (image_base, text_rva, text_bytes) for the .text block.

    Reads via a Java byte[] in 64 KB chunks (a Python bytearray passes
    by value and stays all zeros, and a one-shot 37 MB JArray sometimes
    fails class resolution depending on JVM init order).  Mirrors the
    chunked pattern in core/run_vtable_pipeline.py.
    """
    import jpype
    mem = program.getMemory()
    block = mem.getBlock('.text')
    if block is None:
        raise RuntimeError(f"{program.getName()}: no .text block")
    image_base = program.getImageBase().getOffset() & 0xFFFFFFFFFFFFFFFF
    start_addr = block.getStart()
    text_rva = (start_addr.getOffset() & 0xFFFFFFFFFFFFFFFF) - image_base
    size = block.getSize()

    ByteArray = jpype.JArray(jpype.JByte)
    CHUNK = 64 * 1024
    out = bytearray(size)
    for off in range(0, size, CHUNK):
        n = min(CHUNK, size - off)
        buf = ByteArray(n)
        block.getBytes(start_addr.add(off), buf, 0, n)
        for i in range(n):
            out[off + i] = buf[i] & 0xff
    return image_base, text_rva, bytes(out)


def _rename_in_program(program, ported: list[tuple[str, int]]) -> dict[str, int]:
    """Apply (name, rva) renames in-place.  Returns stat counters."""
    from ghidra.program.model.symbol import SourceType
    fm = program.getFunctionManager()
    base = program.getImageBase()
    stats = {'renamed': 0, 'already_named': 0, 'no_func': 0, 'errored': 0}
    for name, rva in ported:
        try:
            addr = base.add(int(rva))
            f = fm.getFunctionAt(addr)
            if f is None:
                stats['no_func'] += 1
                continue
            curr = f.getName()
            if not (curr.startswith('FUN_') or curr.startswith('sub_')):
                stats['already_named'] += 1
                continue
            f.setName(name, SourceType.USER_DEFINED)
            stats['renamed'] += 1
        except Exception:
            stats['errored'] += 1
    return stats


def _port_pair(src_name_to_rva, src_text_rva, src_text,
               tgt_text_rva, tgt_text):
    """Run Pass 1 (exact 32 B) + Pass 2 (masked 48 B) and return ported list."""
    src_pairs = list(src_name_to_rva.items())
    tgt_idx = build_prefix_index(tgt_text, k=6)
    ported, stats = port_symbols(
        src_pairs, src_text_rva, src_text,
        tgt_text_rva, tgt_text, tgt_idx,
        window=32, prefix_k=6, masked=False, progress_every=0)
    print(f"    exact: ok={stats['ok']:,} no_prefix={stats['no_prefix']:,} "
          f"ambig={stats['ambiguous_or_zero']:,} miss_src={stats['missing_src']:,}")
    ported_names = {n for n, _ in ported}
    unmatched = [(n, r) for n, r in src_pairs if n not in ported_names]
    if unmatched:
        print(f"  Pass 2: masked 48-byte retry on {len(unmatched):,} ...")
        try:
            ported2, stats2 = port_symbols(
                unmatched, src_text_rva, src_text,
                tgt_text_rva, tgt_text, tgt_idx,
                window=48, prefix_k=6, masked=True, progress_every=0)
            ported.extend(ported2)
            print(f"    masked: ok={stats2['ok']:,} "
                  f"no_prefix={stats2['no_prefix']:,} "
                  f"ambig={stats2['ambiguous_or_zero']:,}")
        except ImportError as e:
            print(f"    SKIPPED ({e}) — install capstone+numpy for Pass 2")
    return ported


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--source', default='221', choices=sorted(VERSIONS),
                    help="Source F4 variant whose name pool drives the port "
                         "(default 221 — has the richest PDB pool)")
    ap.add_argument('--targets', nargs='+', default=['og', 'ng', 'ae', 'vr'],
                    choices=sorted(VERSIONS),
                    help="Target F4 variants to enrich (default: all except 221)")
    args = ap.parse_args()

    if args.source in args.targets:
        args.targets = [t for t in args.targets if t != args.source]

    src_names = _read_symbols_from_script(args.source)
    print(f"Source: F4 {args.source.upper()}")
    print(f"  CommonLibImport_F4_{args.source.upper()}.py SYMBOLS: {len(src_names):,}")
    if args.source == '221':
        pdb = _read_f4_221_pdb_publics()
        new_pdb = sum(1 for n in pdb if n not in src_names)
        for n, r in pdb.items():
            src_names.setdefault(n, r)
        print(f"  + 1.11.221 PDB publics: {len(pdb):,} ({new_pdb} new)")
    print(f"  Source name pool: {len(src_names):,} unique")

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"\nOpening project: {args.project_dir}/{args.project_name}.gpr")
    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        # Source program (read-only: just need .text bytes)
        src_hint = VERSIONS[args.source][1]
        src_match = _find_program(root, src_hint)
        if src_match is None:
            print(f"ERROR: source {args.source} program not found in project.")
            sys.exit(1)
        src_path, src_df = src_match
        print(f"Source program: {src_path}")

        consumer = java.lang.Object()
        src_prog = src_df.getDomainObject(consumer, False, False, monitor)
        try:
            _, src_text_rva, src_text = _load_text_block(src_prog)
            print(f"  source .text rva={src_text_rva:#x} size={len(src_text):,}")
        finally:
            src_prog.release(consumer)

        # Target programs
        grand_total = 0
        for tgt in args.targets:
            tgt_hint = VERSIONS[tgt][1]
            tgt_match = _find_program(root, tgt_hint)
            if tgt_match is None:
                print(f"\n  {tgt.upper()}: program not found in project — skip")
                continue
            tgt_path, tgt_df = tgt_match
            print(f"\n--- {args.source.upper()} -> {tgt.upper()}  ({tgt_path}) ---")

            tgt_prog = tgt_df.getDomainObject(consumer, True, False, monitor)
            try:
                _, tgt_text_rva, tgt_text = _load_text_block(tgt_prog)
                print(f"  target .text rva={tgt_text_rva:#x} size={len(tgt_text):,}")
                print("  Pass 1: exact 32-byte match ...")
                ported = _port_pair(src_names, src_text_rva, src_text,
                                    tgt_text_rva, tgt_text)
                if not ported:
                    print("  no matches — nothing to apply")
                    continue
                print(f"  Applying {len(ported):,} renames to {tgt_path} ...")
                tx = tgt_prog.startTransaction(
                    f"bytesig port {args.source}->{tgt}")
                try:
                    stats = _rename_in_program(tgt_prog, ported)
                finally:
                    tgt_prog.endTransaction(tx, True)
                print(f"  renamed={stats['renamed']:,} "
                      f"already_named={stats['already_named']:,} "
                      f"no_func={stats['no_func']:,} "
                      f"errored={stats['errored']:,}")
                grand_total += stats['renamed']
                tgt_prog.save(f"bytesig port {args.source}->{tgt}", monitor)
            finally:
                tgt_prog.release(consumer)

        print(f"\nTOTAL renames applied across {len(args.targets)} target(s): "
              f"{grand_total:,}")


if __name__ == '__main__':
    main()
