#!/usr/bin/env python3
"""Import SDK-derived Havok struct layouts (build/havok/havok_layouts.json)
into a Ghidra program's Data Type Manager as proper structs with named
fields at authoritative MSVC-ABI offsets, under category /Havok.

Two passes: (1) create every struct empty-but-sized so members/pointers can
cross-reference; (2) place each field -- scalars and pointers get real
Ghidra types (pointers typed to the referenced havok struct when known),
embedded class/array members get the referenced struct or an undefined blob
sized from the layout.  Gaps stay undefined (compiler padding).

Also reports how many imported classes have a matching RTTI/VTABLE_ symbol
in the program (i.e. are actually present and now typable).

Run via apply_enrichment_to_user_project-style pyghidra, or standalone:
  python scripts/havok/apply_structs.py
     --project-dir C:/GhidraProjects/Fallout --project-name F4VR
     --program-path /Fallout4.exe [--dry-run]
Knob: only x64 programs (the SDK layout is x64 MSVC).
"""
import argparse
import json
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR = REPO / "tools" / "ghidra"
LAYOUTS = Path(__file__).resolve().parent / "refs" / "havok_layouts.json"

SCALAR = {
    'hkBool': 1, 'hkChar': 1, 'hkInt8': 1, 'hkUint8': 1, 'char': 1,
    'signed char': 1, 'unsigned char': 1, 'bool': 1, '_Bool': 1,
    'hkInt16': 2, 'hkUint16': 2, 'hkHalf': 2, 'hkFloat16': 2, 'short': 2,
    'unsigned short': 2, 'hkObjectIndex': 2,
    'hkInt32': 4, 'hkUint32': 4, 'hkReal': 4, 'float': 4, 'int': 4,
    'unsigned int': 4, 'unsigned': 4, 'hkResult': 4, 'hkSingle': 4,
    'long': 4, 'unsigned long': 4,
    'hkInt64': 8, 'hkUint64': 8, 'hkUlong': 8, 'hkLong': 8, 'double': 8,
    'long long': 8, 'unsigned long long': 8, 'hk_size_t': 8, 'hkPadSpu': 8,
}


def base_name(t):
    """Strip qualifiers/template args/ref to a bare type name."""
    t = t.strip()
    t = re.sub(r'\bconst\b', '', t)
    t = re.sub(r'\bvolatile\b', '', t)
    for kw in ('class ', 'struct ', 'union ', 'enum '):
        t = t.replace(kw, '')
    t = t.split('<', 1)[0]              # drop template args
    t = t.replace('*', ' ').replace('&', ' ')   # drop pointer/ref tokens
    return t.strip()


def run(program, records, dry_run, monitor):
    from ghidra.program.model.data import (
        StructureDataType, CategoryPath, DataTypeConflictHandler,
        Undefined, PointerDataType, UnsignedIntegerDataType,
        UnsignedShortDataType, UnsignedCharDataType, IntegerDataType,
        ShortDataType, CharDataType, FloatDataType, DoubleDataType,
        UnsignedLongLongDataType, LongLongDataType, ByteDataType)
    dtm = program.getDataTypeManager()
    cat = CategoryPath("/Havok")
    KEEP = DataTypeConflictHandler.REPLACE_HANDLER

    gh_scalar = {
        1: UnsignedCharDataType.dataType, 2: UnsignedShortDataType.dataType,
        4: UnsignedIntegerDataType.dataType, 8: UnsignedLongLongDataType.dataType}
    named = {
        'hkReal': FloatDataType.dataType, 'float': FloatDataType.dataType,
        'hkSingle': FloatDataType.dataType, 'double': DoubleDataType.dataType,
        'hkInt8': ByteDataType.dataType, 'char': CharDataType.dataType,
        'hkInt16': ShortDataType.dataType, 'hkInt32': IntegerDataType.dataType,
        'hkInt64': LongLongDataType.dataType,
    }

    # pass 1: create sized empty structs
    structs = {}
    for name, rec in records.items():
        size = rec['size'] or 1
        sdt = StructureDataType(cat, name, size)
        structs[name] = sdt
    if not dry_run:
        tx = program.startTransaction("havok: create structs")
        try:
            for name in records:
                structs[name] = dtm.addDataType(structs[name], KEEP)
        finally:
            program.endTransaction(tx, True)

    def field_type_and_size(ftype):
        bn = base_name(ftype)
        if ftype.rstrip().endswith('*'):
            tgt = structs.get(bn)
            return (PointerDataType(tgt) if tgt else PointerDataType()), 8
        if ftype in SCALAR:
            sz = SCALAR[ftype]
            return named.get(ftype, gh_scalar[sz]), sz
        if bn in SCALAR:
            sz = SCALAR[bn]
            return named.get(bn, gh_scalar[sz]), sz
        if bn in structs and not ftype.startswith(('hkArray', 'class hkArray',
                                                   'hkSmallArray', 'class hkSmallArray')):
            dt = structs[bn]
            return dt, dt.getLength()
        return None, None                 # composite/unknown -> size by delta

    # pass 2: place fields
    placed = total_fields = 0
    if not dry_run:
        tx = program.startTransaction("havok: fields")
    try:
        for name, rec in records.items():
            sdt = structs[name]
            flds = sorted(rec['fields'], key=lambda f: f['offset'])
            size = rec['size']
            for i, f in enumerate(flds):
                total_fields += 1
                off = f['offset']
                nxt = flds[i + 1]['offset'] if i + 1 < len(flds) else size
                dt, dsz = field_type_and_size(f['type'])
                if dt is None or dsz is None or off + dsz > nxt:
                    # unknown or would overlap -> undefined blob to next field
                    dsz = max(1, nxt - off)
                    dt = Undefined.getUndefinedDataType(dsz) if dsz <= 8 else None
                    if dt is None:
                        from ghidra.program.model.data import ArrayDataType, Undefined1DataType
                        dt = ArrayDataType(Undefined1DataType.dataType, nxt - off, 1)
                        dsz = nxt - off
                if off + dsz > size:
                    continue
                if not dry_run:
                    try:
                        sdt.replaceAtOffset(off, dt, dsz, f['name'], None)
                        placed += 1
                    except Exception:
                        pass
                else:
                    placed += 1
    finally:
        if not dry_run:
            program.endTransaction(tx, True)

    # coverage report: which imported classes exist in the binary (by symbol)
    st = program.getSymbolTable()
    present = 0
    sample = []
    for name in list(records)[:0]:
        pass
    allnames = set(records)
    seen = set()
    si = st.getSymbolIterator()
    pat = re.compile(r'\b(hk[A-Za-z0-9_]+|bhk[A-Za-z0-9_]+)')
    for sym in st.getAllSymbols(False):
        nm = sym.getName()
        if 'hk' not in nm:
            continue
        for cand in pat.findall(nm):
            if cand in allnames and cand not in seen:
                seen.add(cand)
    present = len(seen)
    print("havok-structs (%s): %d structs, %d/%d fields placed%s"
          % (program.getName(), len(records), placed, total_fields,
             ' [DRY-RUN]' if dry_run else ''))
    print("  classes also present in binary (by symbol): %d/%d"
          % (present, len(records)))
    if not dry_run:
        program.save("havok structs imported", monitor)
        print("  saved.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program-path', required=True)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--layouts', default=str(LAYOUTS))
    args = ap.parse_args()

    records = json.load(open(args.layouts))
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()
    pdir, pname = args.project_dir, args.project_name
    if "/" in pname:
        pdir = pdir + "/" + pname.rsplit("/", 1)[0]
        pname = pname.rsplit("/", 1)[1]
    with pyghidra.open_project(pdir, pname, create=False) as project:
        root = project.getProjectData().getRootFolder()
        match = []

        def walk(folder, prefix=""):
            for f in folder.getFiles():
                if prefix + "/" + f.getName() == args.program_path:
                    match.append(f)
            for sub in folder.getFolders():
                walk(sub, prefix + "/" + sub.getName())
        walk(root)
        if not match:
            print("not found:", args.program_path)
            return
        consumer = java.lang.Object()
        program = match[0].getDomainObject(consumer, not args.dry_run, False, monitor)
        try:
            if program.getDefaultPointerSize() != 8:
                print("x86 program -- havok SDK layout is x64; skipping")
                return
            run(program, records, args.dry_run, monitor)
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
