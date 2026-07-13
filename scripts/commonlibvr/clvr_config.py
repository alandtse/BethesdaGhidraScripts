"""Shared config defaults for the CommonLibVR ("ng") Ghidra-script pipeline.

Every script in this package reads the same generated-import path and the
same script directory, each overridable per-invocation via the same env
vars. Previously each script redefined these identically (copy-pasted
env-var-default boilerplate); this module is the single source of truth so a
future rename/move of the canonical import file or this directory is one
edit instead of N.

Usage (matches the sys.path pattern already used to import sibling modules
like layout_diff):

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from clvr_config import IMPORT_PATH, SCRIPT_DIR, TYPES_CAT
"""
import os

# The generated CommonLibImport_CLVR_<RUNTIME>.py this pipeline applies.
# Override per-invocation (e.g. to target SE/AE instead of VR) via CLVR_IMPORT.
IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')

# This package's own directory (scripts/commonlibvr). Override via CLVR_SCRIPT_DIR.
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')

# Project convention: manual RE / generated CommonLib types live in /types.h
# (see ~/.claude/skyrim-re.md's "Ghidra naming & structs" section).
TYPES_CAT = '/types.h'
