#!/usr/bin/env python3
"""Type the `this` (param_1) of Havok member functions to <class>* so the
imported /Havok structs (see apply_structs.py) actually surface as named
fields in the decompiler.

Havok ships without RTTI, so Ghidra can't label the raw hk* vtables -- but
CommonLib names many havok member functions as ``<class>::<method>`` or
``<class>_<method>``.  This is the reliable signal: for every function
whose leading identifier is a known /Havok class, set its first parameter
(the `this`) to <class>*.

CONSERVATIVE: only touches a param that is currently undefined / void* / a
generic or integer-typed pointer slot, never an existing meaningful type.
Reversible (it's a parameter retype).

  python scripts/havok/apply_this.py --project-dir C:/GhidraProjects/Fallout
     --project-name F4VR --program-path /Fallout4.exe [--dry-run]
"""
import argparse
import os
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
GHIDRA_DIR = REPO / "tools" / "ghidra"
LEAD_RE = re.compile(r'^((?:hk|bhk)[A-Za-z0-9]+)(?:::|_)')
OVERRIDE = {'void *', 'pointer', 'longlong', 'ulonglong', 'undefined8',
            'undefined', 'undefined *', 'void', 'int', 'uint', 'long', 'ulong'}


def run(program, dry_run, monitor):
    from ghidra.program.model.data import CategoryPath, PointerDataType
    from ghidra.program.model.symbol import SourceType
    dtm = program.getDataTypeManager()
    cat = dtm.getCategory(CategoryPath("/Havok"))
    if cat is None:
        print("no /Havok category -- run apply_structs.py first")
        return
    hk = {dt.getName(): dt for dt in cat.getDataTypes()}
    ptr_cache = {}
    fm = program.getFunctionManager()

    matched = typed = skipped = 0
    by_class = {}
    tx = None if dry_run else program.startTransaction("havok: this-typing")
    try:
        for f in fm.getFunctions(True):
            m = LEAD_RE.match(f.getName())
            if not m:
                continue
            cls = m.group(1)
            dt = hk.get(cls)
            if dt is None:
                continue
            matched += 1
            params = f.getParameters()
            if len(params) < 1:
                skipped += 1
                continue
            p0 = params[0]
            cn = p0.getDataType().getName().lower()
            if not ('undefined' in cn or cn in OVERRIDE):
                skipped += 1
                continue
            if cls not in ptr_cache:
                ptr_cache[cls] = PointerDataType(dt)
            if not dry_run:
                try:
                    p0.setDataType(ptr_cache[cls], SourceType.USER_DEFINED)
                    typed += 1
                    by_class[cls] = by_class.get(cls, 0) + 1
                except Exception:
                    skipped += 1
            else:
                typed += 1
                by_class[cls] = by_class.get(cls, 0) + 1
    finally:
        if tx is not None:
            program.endTransaction(tx, True)

    print("havok-this (%s): %d funcs match a /Havok class, %d this-typed, "
          "%d skipped%s" % (program.getName(), matched, typed, skipped,
                            ' [DRY-RUN]' if dry_run else ''))
    top = sorted(by_class.items(), key=lambda x: -x[1])[:12]
    if top:
        print("  top classes: " + ", ".join("%s(%d)" % (c, n) for c, n in top))
    if not dry_run:
        program.save("havok this-typing", monitor)
        print("  saved.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', required=True)
    ap.add_argument('--program-path', required=True)
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
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
            print("not found:", args.program_path); return
        consumer = java.lang.Object()
        program = match[0].getDomainObject(consumer, not args.dry_run, False, monitor)
        try:
            if program.getDefaultPointerSize() != 8:
                print("x86 -- skip"); return
            run(program, args.dry_run, monitor)
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
