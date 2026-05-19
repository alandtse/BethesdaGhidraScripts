#!/usr/bin/env python3
"""Post-pipeline SF shift-map check + auto-generation.

Called by ``run.py`` after a successful ``generate_scripts`` +
``run_headless`` pass that included Starfield.  Looks at the just-
imported Starfield.exe's PE version and decides what to do:

* **PE version == anchor reference (1.16.236)** -- the build is fully
  in-namespace with CommonLibSF's headers, no shifts needed.  If a
  reference layout CSV is missing, dump it now from the BGS pipeline
  project so future-version users have something to diff against.

* **PE version != anchor reference** -- dump the user's layouts, diff
  against the anchor reference layout if it's committed, write
  ``refs/shift_sf.json``, and tell the user to re-run the pipeline
  so ``parse_commonlib_types.py`` picks up the shift map at the next
  script-generation pass.

Designed to be cheap on the common case: if both layouts already
exist and the shift map is current, this script does ~nothing
(under 1 second).  Slow path is the first run on a fresh SF version:
~30 seconds for the dump (pyghidra-based, in-process, no MCP).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional, Tuple

REPO_DIR    = Path(__file__).resolve().parent.parent.parent
SCRIPT_DIR  = Path(__file__).resolve().parent
CORE_DIR    = REPO_DIR / "scripts" / "core"
REFS_DIR    = SCRIPT_DIR / "refs"
EXES_DIR    = REPO_DIR / "exes" / "starfield" / "sf"
PROJECTS_DIR = REPO_DIR / "ghidraprojects"

# CommonLibSF's authoring version.  All other SF versions get a shift
# map computed against this one's vtable layouts.
ANCHOR_VERSION = (1, 16, 236, 0)
GHIDRA_PROJECT_NAME = "BethesdaGhidraScripts"

sys.path.insert(0, str(CORE_DIR))


def _ver_filename(v: Tuple[int, ...]) -> str:
    parts = list(v)
    while len(parts) < 4:
        parts.append(0)
    return '-'.join(str(x) for x in parts[:4])


def _ver_label(v: Tuple[int, ...]) -> str:
    parts = list(v)
    while len(parts) < 4:
        parts.append(0)
    return '.'.join(str(x) for x in parts[:4])


def _detect_sf_version() -> Optional[Tuple[int, ...]]:
    from pe_version import get_pe_version
    if not EXES_DIR.is_dir():
        return None
    for fname in sorted(os.listdir(str(EXES_DIR))):
        if not fname.lower().endswith('.exe'):
            continue
        if 'unpacked' in fname.lower():
            continue
        v = get_pe_version(str(EXES_DIR / fname))
        if v and len(v) >= 3:
            while len(v) < 4:
                v = v + (0,)
            return v[:4]
    return None


def _layout_csv(version: Tuple[int, ...]) -> Path:
    return REFS_DIR / 'sf_{}_vtables.csv.gz'.format(_ver_filename(version))


def _dump_layouts(version: Tuple[int, ...]) -> bool:
    """Invoke dump_vtable_layouts.py against the BGS pipeline project.

    Returns True on success.
    """
    project_dir = PROJECTS_DIR / GHIDRA_PROJECT_NAME
    if not (project_dir / '{}.gpr'.format(GHIDRA_PROJECT_NAME)).is_file():
        print('  WARNING: BGS pipeline project not found at {}'.format(project_dir))
        print('           Run `python run.py build` first to import Starfield.')
        return False

    out_csv = _layout_csv(version)
    REFS_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, str(SCRIPT_DIR / 'dump_vtable_layouts.py'),
        '--project-dir', str(project_dir),
        '--project-name', GHIDRA_PROJECT_NAME,
        '--program', 'Starfield.exe',
        '--label', 'sf_' + _ver_filename(version).replace('-', '_'),
        '--out', str(out_csv),
    ]
    print('  Dumping vtable layouts for SF {} ...'.format(_ver_label(version)))
    r = subprocess.run(cmd, cwd=str(REPO_DIR))
    if r.returncode != 0:
        print('  ERROR: vtable dump failed (exit {}).'.format(r.returncode))
        return False
    return out_csv.is_file()


def _build_shift_map(ref_csv: Path, target_csv: Path,
                     target_version: Tuple[int, ...]) -> bool:
    """Diff target layout vs reference, write refs/shift_sf.json."""
    out_json = REFS_DIR / 'shift_sf.json'
    cmd = [
        sys.executable, str(CORE_DIR / 'build_shift_map.py'),
        '--ref', str(ref_csv),
        '--ref-label', 'sf',
        '--target', str(target_csv),
        '--target-label', 'sf_' + _ver_filename(target_version).replace('-', '_'),
        '--out', str(out_json),
    ]
    print('  Building shift map vs SF {} reference ...'.format(_ver_label(ANCHOR_VERSION)))
    env = os.environ.copy()
    env['PYTHONPATH'] = str(CORE_DIR) + os.pathsep + env.get('PYTHONPATH', '')
    r = subprocess.run(cmd, cwd=str(REPO_DIR), env=env)
    return r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--force-redump', action='store_true',
                    help='re-dump even if a layout for this version already exists')
    args = ap.parse_args()

    version = _detect_sf_version()
    if version is None:
        print('SF shift check: no Starfield.exe in {} -- skipping.'.format(EXES_DIR))
        return 0

    print('SF shift check: detected version {}'.format(_ver_label(version)))

    ref_csv    = _layout_csv(ANCHOR_VERSION)
    target_csv = _layout_csv(version)

    # Case 1: PE version IS the anchor.  Make sure the reference CSV exists.
    if version == ANCHOR_VERSION:
        if ref_csv.is_file() and not args.force_redump:
            print('  Reference layout already at {} -- nothing to do.'.format(ref_csv.name))
            return 0
        print('  No reference layout yet; dumping now to seed it.')
        if not _dump_layouts(version):
            return 1
        print('  Reference seeded at {}.'.format(ref_csv))
        print('  Commit this file so future-version users have something to diff against.')
        return 0

    # Case 2: PE version != anchor.  Dump target layouts.
    if not target_csv.is_file() or args.force_redump:
        if not _dump_layouts(version):
            return 1

    # If the anchor reference is missing, we can't build a shift map.
    if not ref_csv.is_file():
        print('  WARNING: anchor reference {} is missing.'.format(ref_csv.name))
        print('           Cannot build shift map without it.  CommonLib vtable')
        print('           struct field names may be misaligned for SF {}.'.format(_ver_label(version)))
        print()
        print('  To seed the reference, run `python run.py build` against a')
        print('  1.16.236 Starfield.exe at least once; the reference CSV will')
        print('  be saved automatically.')
        return 0

    # Build the shift map.
    if not _build_shift_map(ref_csv, target_csv, version):
        print('  ERROR: shift map build failed.')
        return 1

    print()
    print('  ============================================================')
    print('  Shift map generated at refs/shift_sf.json.')
    print('  Re-run `python run.py build` to apply the slot shifts to')
    print("  CommonLibSF's vtable structs (parse_commonlib_types.py picks")
    print('  up the shift map on the next pass).')
    print('  ============================================================')
    print()
    print('  Also: please open a GitHub issue and attach')
    print('    {}'.format(target_csv))
    print('  so the maintainer can ship a pre-built shift map for SF {}'.format(_ver_label(version)))
    print('  in the next release (saves all future {}+ users the dump pass).'.format(_ver_label(version)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
