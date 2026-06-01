#!/usr/bin/env python3
"""Apply CommonLibImport_FNV.py to FalloutNV.exe in the user's F4VR.gpr
combined project via pyghidra.

The F4VR.gpr project is a multi-binary container holding F4 OG + F4 NG +
F4VR + FalloutNV.exe.  This script targets the FNV binary inside it.

pyghidra acquires an exclusive lock on the project, so the Ghidra GUI
must NOT be open while this script runs.

Headless mode -- no GUI required.
"""
import argparse
import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"
SCRIPT_PATH = REPO_DIR / "ghidrascripts" / "CommonLibImport_FNV.py"

PROJECT_DIR  = Path(r"C:/GhidraProjects/Fallout")
PROJECT_NAME = "F4VR"
PROGRAM_NAME = "FalloutNV.exe"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-dir',  default=str(PROJECT_DIR),
                    help="Directory containing F4VR.gpr (default: %(default)s)")
    ap.add_argument('--project-name', default=PROJECT_NAME,
                    help="Project name without .gpr (default: %(default)s)")
    ap.add_argument('--program',      default=PROGRAM_NAME,
                    help="Program file to find inside the project")
    ap.add_argument('--script',       default=str(SCRIPT_PATH),
                    help="CommonLibImport_FNV.py path")
    args = ap.parse_args()

    project_dir  = Path(args.project_dir)
    project_name = args.project_name
    program_name = args.program
    script_path  = Path(args.script)

    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    print(f"Opening project: {project_dir}/{project_name}.gpr")
    with pyghidra.open_project(project_dir, project_name, create=False) as project:
        root = project.getProjectData().getRootFolder()

        # The F4VR combined project layout typically has FNV under
        # /Fallout New Vegas/ or /fnv/ -- walk recursively.  Also match
        # Steamless-unpacked variants (FalloutNV.exe.unpacked.exe etc).
        stem = program_name.rsplit('.', 1)[0]

        def find(folder):
            for f in folder.getFiles():
                n = f.getName()
                if n == program_name or (n.startswith(stem) and n.lower().endswith('.exe')):
                    return f
            for sub in folder.getFolders():
                hit = find(sub)
                if hit is not None:
                    return hit
            return None

        domain_file = find(root)
        if domain_file is None:
            print(f"ERROR: {program_name} not found in project tree")
            print("\nProject tree:")
            def walk(folder, depth=0):
                for f in folder.getFiles():
                    print("  " * depth + "- " + f.getName())
                for sub in folder.getFolders():
                    print("  " * depth + "[" + sub.getName() + "]")
                    walk(sub, depth + 1)
            walk(root)
            sys.exit(1)
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            print(f"Running {script_path.name} via pyghidra...")
            stdout, stderr = pyghidra.ghidra_script(
                script_path, project, program,
                echo_stdout=True, echo_stderr=True)
            if stderr:
                print("STDERR:", stderr, file=sys.stderr)
            print("Saving...")
            program.save("CommonLibFNV import (" + script_path.name + ")", monitor)
            print("Done.")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
