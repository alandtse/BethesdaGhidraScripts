#!/usr/bin/env python3
"""Extract Havok struct layouts from SDK library PDBs via llvm-pdbutil.

For the modern Havok generations (2016+/2021, the hknp/hkReflect API used
by Starfield) there are no compilable reflection-registration lists, but
the Havok *AI* SDK 2021 ships library PDBs (hkBase.pdb, hkcd*.pdb,
hkai*.pdb, ...) whose type info carries exact MSVC x64 member offsets.
``llvm-pdbutil pretty -class-definitions=layout`` prints them as:

    class hkStringPtr [sizeof = 8] {
      data +0x00 [sizeof=8] char* m_stringAndFlag
    }

with nested ``base``/``data`` lines for inheritance/embedding.  This parses
that into the same JSON shape as build_layouts.py (so apply_structs.py can
consume it): outermost data members kept, base-class subobjects flattened
to absolute offsets, embedded record members kept as one sized field.

Covers SF's Common-base + Geometry (hkcd*) + AI (hkai*) classes -- NOT the
hknp physics module (no public SDK for it).  Layouts are Havok 2021.2;
SF's exact version may differ slightly, so names are reliable and most
offsets transfer (validate name-match against the binary before trusting).

Usage:
  python scripts/havok/build_pdb_layouts.py PDB [PDB ...] --out NAME.json
"""
import argparse
import json
import re
import subprocess
from pathlib import Path

REFS = Path(__file__).resolve().parent / "refs"
PDBUTIL = r"C:/Program Files/LLVM/bin/llvm-pdbutil.exe"

HDR = re.compile(r'^(\s*)(?:const\s+)?(?:class|struct|union)\s+(.+?)\s+\[sizeof = (\d+)\]\s*\{')
DATA = re.compile(r'^(\s+)data \+0x([0-9a-fA-F]+) \[sizeof=(\d+)\] (.+?)\s+([A-Za-z_]\w*(?:\[\d+\])?)\s*$')
BASE = re.compile(r'^(\s+)base \+0x([0-9a-fA-F]+) \[sizeof=(\d+)\] ')
END = re.compile(r'^(\s*)\}\s*$')


def parse(text):
    records = {}
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        m = HDR.match(lines[i])
        if not m:
            i += 1
            continue
        base_indent = len(m.group(1))
        name = m.group(2).strip()
        size = int(m.group(3))
        # empty class: "struct X [sizeof = N] {}" has { and } on one line --
        # do NOT enter the member loop (it would run away to the next } and
        # swallow following class headers, e.g. hknpBody).
        if lines[i].rstrip().endswith('{}'):
            records[name] = {'size': size, 'align': 8, 'vtable': False,
                             'fields': []}
            i += 1
            continue
        i += 1
        fields = []
        skip_deeper = None
        while i < n:
            ln = lines[i]
            em = END.match(ln)
            if em is not None and len(em.group(1)) <= base_indent:
                break
            dm = DATA.match(ln)
            bm = BASE.match(ln)
            if dm:
                ind = len(dm.group(1))
                if skip_deeper is not None and ind > skip_deeper:
                    i += 1
                    continue
                skip_deeper = ind            # skip this member's own expansion
                off = int(dm.group(2), 16)
                fname = dm.group(5)
                ftype = dm.group(4).strip()
                fields.append({'offset': off, 'type': ftype, 'name': fname})
            elif bm:
                ind = len(bm.group(1))
                if skip_deeper is not None and ind <= skip_deeper:
                    skip_deeper = None       # back out to a base level: descend
                # base markers: don't record, don't skip -> inherited fields kept
            i += 1
        # de-dup by (offset,name)
        seen = set()
        uniq = []
        for f in fields:
            k = (f['offset'], f['name'])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(f)
        records[name] = {'size': size, 'align': 8, 'vtable': False,
                         'fields': uniq}
    return records


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pdbs', nargs='+')
    ap.add_argument('--out', default='havok_layouts_2021_pdb.json')
    ap.add_argument('--prefix', nargs='*', default=['hk', 'bhk'])
    args = ap.parse_args()
    merged = {}
    for pdb in args.pdbs:
        p = subprocess.run(
            [PDBUTIL, 'pretty', '-classes', '-class-definitions=layout', pdb],
            capture_output=True, text=True, errors='replace')
        recs = parse(p.stdout)
        kept = 0
        for k, v in recs.items():
            # keep only real named (non-template) havok classes with fields
            if '<' in k or '::' in k or not k.startswith(tuple(args.prefix)):
                continue
            if not v['fields']:
                continue
            if k not in merged or len(v['fields']) > len(merged[k]['fields']):
                merged[k] = v
                kept += 1
        print("%-28s %d named hk classes kept" % (Path(pdb).name, kept))
    REFS.mkdir(exist_ok=True)
    out = REFS / args.out
    json.dump(merged, open(out, 'w'), indent=1)
    print("merged %d classes -> %s" % (len(merged), out))


if __name__ == '__main__':
    main()
