#!/usr/bin/env python3
"""Sequencer: enrich every game/version program inside Combined.gpr.

Runs the following passes back-to-back so you only have to close
Ghidra once.  Each step is a subprocess so a fail/skip in one step
doesn't cascade.

  1. apply_f4_to_user_project   --version ae     # re-apply F4 AE (+~7k names from 221 PDB bytesig)
  2. apply_f4_to_user_project   --version 221    # re-apply F4 1.11.221 (+~2.5k names from AE bytesig)
  3. apply_skyrim_to_user_project --version se   # apply SE: 1.7k enums + 38k structs + 7k new symbols
  4. apply_skyrim_to_user_project --version ae   # apply AE: same gains
  5. apply_skyrim_to_user_project --version vr   # apply VR: same gains, was failing before shift_svr fix
  6. commonlibsse/bytesig_port_combined          # SE -> AE/VR bytesig port (94k pool)

Defaults assume C:/GhidraProjects/Combined.gpr with the user's typical
multi-binary layout.  Each step prints its full output (no quiet mode)
so progress is visible.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_DIR / "scripts"

# (label, script_relative_to_scripts_dir, extra_args)
STEPS = [
    ("F4 AE re-apply",
     "apply_f4_to_user_project.py",
     ["--version", "ae",
      "--program-path", "/Fallout4/Fallout4_AE_1_11_191.exe"]),
    ("F4 1.11.221 re-apply",
     "apply_f4_to_user_project.py",
     ["--version", "221",
      "--program-path", "/Fallout4/Fallout4_1_11_221.exe"]),
    ("Skyrim SE apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "se",
      "--program-path", "/Skyrim/SkyrimSE_1_5_97.exe"]),
    ("Skyrim AE apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "ae",
      "--program-path", "/Skyrim/SkyrimAE_1_6_1170.exe"]),
    ("Skyrim VR apply",
     "apply_skyrim_to_user_project.py",
     ["--version", "vr",
      "--program-path", "/Skyrim/SkyrimVR_1_4_15.exe"]),
    ("Skyrim SE -> AE/VR bytesig port",
     "commonlibsse/bytesig_port_combined.py",
     []),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default="C:/GhidraProjects")
    ap.add_argument('--project-name', default="Combined")
    ap.add_argument('--skip', nargs='+', default=[], metavar='STEP',
                    help="Skip step(s) by 1-based index (e.g. --skip 1 2)")
    args = ap.parse_args()
    skip = {int(s) for s in args.skip if s.isdigit()}

    common = ['--project-dir', args.project_dir,
              '--project-name', args.project_name]

    overall_start = time.time()
    results = []
    for i, (label, script, extra) in enumerate(STEPS, 1):
        if i in skip:
            print(f"\n{'=' * 70}\nSTEP {i} SKIPPED: {label}\n{'=' * 70}")
            results.append((label, 'skipped', 0))
            continue
        script_path = SCRIPTS_DIR / script
        cmd = [sys.executable, str(script_path), *common, *extra]
        print(f"\n{'=' * 70}\nSTEP {i}/{len(STEPS)}: {label}\n"
              f"  cmd: {' '.join(cmd)}\n{'=' * 70}")
        step_start = time.time()
        rc = subprocess.run(cmd).returncode
        elapsed = time.time() - step_start
        status = 'OK' if rc == 0 else f'FAIL (rc={rc})'
        results.append((label, status, elapsed))
        print(f"\n--- STEP {i} {status} ({elapsed:.0f}s) ---")

    total = time.time() - overall_start
    print(f"\n{'=' * 70}\nSUMMARY ({total:.0f}s total)\n{'=' * 70}")
    for i, (label, status, elapsed) in enumerate(results, 1):
        print(f"  {i:>2}. {status:<14}  {elapsed:>6.0f}s  {label}")


if __name__ == '__main__':
    main()
