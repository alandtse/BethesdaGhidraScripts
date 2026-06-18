#!/usr/bin/env python3
"""Type-discovery sequencer: run the binary-derived enrichment drivers
across every x64 program in a combined Ghidra project.

Drivers (scripts/core/, ported from alandtse's CommonLibVR fork):
  1. string_anchored_rename  -- name FUN_/sub_/thunk_ from self-naming
                                debug strings (mutates; idempotent)
  2. ctor_mine               -- decompile constructors -> field name+type
                                proposals CSV (read-only)
  3. globals_harvest         -- type untyped global singletons by the
                                class whose methods consume them (read-only)

The project lock is exclusive, so programs are processed SEQUENTIALLY:
the project is opened once and each program is driven in turn.  Per
program the rename driver runs first (and the program is saved), then
the two read-only proposal miners.

Usage:
  python scripts/discover_combined.py
      [--project-dir C:/GhidraProjects --project-name Combined]
      [--drivers string_anchored_rename ctor_mine globals_harvest]
      [--programs /Skyrim/SkyrimSE_1_5_97.exe ...]   # default: all x64 below
      [--apply-rename]            # BGS_ENRICH_APPLY=go for the rename driver
      [--ctor-max-classes N] [--globals-max-funcs N]

The PowerPC FalloutNV_Xbox_Debug build is excluded (the x86/x64
decompiler pcode model the drivers assume doesn't apply).
"""
import argparse
import os
import sys
from pathlib import Path

REPO_DIR   = Path(__file__).resolve().parent.parent
GHIDRA_DIR = REPO_DIR / "tools" / "ghidra"
CORE_DIR   = REPO_DIR / "scripts" / "core"

DRIVER_PATHS = {
    'string_anchored_rename': CORE_DIR / 'string_anchored_rename.py',
    'ctor_mine':              CORE_DIR / 'ctor_mine.py',
    'globals_harvest':        CORE_DIR / 'globals_harvest.py',
    'globals_apply':          CORE_DIR / 'globals_apply.py',
}
# Drivers that mutate the program (require a save).  globals_apply only
# mutates when BGS_ENRICH_APPLY=go; saving an unchanged program is a
# no-op, so listing it here is safe either way.
MUTATING = {'string_anchored_rename', 'globals_apply'}

# Default target set: every x64 MSVC program in the standard Combined.gpr
# layout.  FalloutNV_Xbox_Debug (PPC) is deliberately absent.
DEFAULT_PROGRAMS = [
    '/Skyrim/SkyrimSE_1_5_97.exe',
    '/Skyrim/SkyrimAE_1_6_1170.exe',
    '/Skyrim/SkyrimAE_GOG Edition.exe',
    '/Skyrim/SkyrimVR_1_4_15.exe',
    '/Fallout4/Fallout4_OG_1_10_163.exe',
    '/Fallout4/Fallout4_NG_1_10_984.exe',
    '/Fallout4/Fallout4_AE_1_11_191.exe',
    '/Fallout4/Fallout4_1_11_221.exe',
    '/Fallout4/Fallout4VR_1_2_72.exe',
    '/FalloutNV/FalloutNV_1_4_0_525.exe',
    '/Starfield/Starfield 1.16.236',
]


def _find(root, path):
    hit = []

    def walk(folder, prefix=""):
        for f in folder.getFiles():
            if prefix + "/" + f.getName() == path:
                hit.append(f)
        for sub in folder.getFolders():
            walk(sub, prefix + "/" + sub.getName())

    walk(root)
    return hit[0] if hit else None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--drivers', nargs='+', default=list(DRIVER_PATHS),
                    choices=list(DRIVER_PATHS))
    ap.add_argument('--programs', nargs='+', default=DEFAULT_PROGRAMS)
    ap.add_argument('--apply-rename', action='store_true',
                    help="actually rename (sets BGS_ENRICH_APPLY=go); "
                         "default dry-run for the rename driver")
    ap.add_argument('--ctor-max-classes', type=int, default=0)
    ap.add_argument('--globals-max-funcs', type=int, default=0)
    args = ap.parse_args()

    if args.apply_rename:
        os.environ['BGS_ENRICH_APPLY'] = 'go'
    if args.ctor_max_classes:
        os.environ['BGS_CTOR_MAX_CLASSES'] = str(args.ctor_max_classes)
    if args.globals_max_funcs:
        os.environ['BGS_GLOBALS_MAX_FUNCS'] = str(args.globals_max_funcs)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)
    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    import time
    results = []
    print(f"Opening project: {args.project_dir}/{args.project_name}.gpr")
    with pyghidra.open_project(args.project_dir, args.project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()
        for prog_path in args.programs:
            df = _find(root, prog_path)
            if df is None:
                print(f"\n### {prog_path}: NOT FOUND — skip")
                results.append((prog_path, 'not-found', 0))
                continue
            for driver in args.drivers:
                # Per-program, per-driver output goes to a stable CSV path so
                # ctor_mine/globals_harvest don't collide across programs.
                tag = prog_path.strip('/').replace('/', '_').replace(' ', '_').replace('.', '_')
                gq = str(CORE_DIR / 'refs' / f'globals_queue_{tag}.csv')
                os.environ['BGS_CTOR_CSV'] = str(CORE_DIR / 'refs' / f'ctor_fields_{tag}.csv')
                os.environ['BGS_GLOBALS_CSV'] = gq          # globals_harvest writes
                os.environ['BGS_GLOBALS_APPLY_CSV'] = gq    # globals_apply reads
                label = f"{prog_path}  [{driver}]"
                print(f"\n{'=' * 70}\n{label}\n{'=' * 70}")
                t0 = time.time()
                consumer = java.lang.Object()
                program = df.getDomainObject(consumer, True, False, monitor)
                try:
                    pyghidra.ghidra_script(
                        str(DRIVER_PATHS[driver]), project, program,
                        echo_stdout=True, echo_stderr=True)
                    if driver in MUTATING and args.apply_rename:
                        program.save(f"discover: {driver}", monitor)
                    rc = 'OK'
                except Exception as e:  # noqa: BLE001
                    print(f"  ERROR: {type(e).__name__}: {e}")
                    rc = 'FAIL'
                finally:
                    program.release(consumer)
                dt = time.time() - t0
                results.append((label, rc, dt))
                print(f"--- {label}: {rc} ({dt:.0f}s) ---")

    print(f"\n{'=' * 70}\nDISCOVERY SUMMARY\n{'=' * 70}")
    for label, rc, dt in results:
        print(f"  {rc:<10} {dt:>6.0f}s  {label}")


if __name__ == "__main__":
    main()
