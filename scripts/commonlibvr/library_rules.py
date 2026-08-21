"""CommonLibVR's LibraryRules implementation -- the reference implementation for the
Phase 2 Rules promotion (this was already the cleanest existing per-library config in
the repo). `clvr_config.py` is kept as a re-export shim so none of this package's ~19
existing `from clvr_config import ...` call sites need to change.

Named `library_rules.py`, not `rules.py`: a bare `import rules` would collide with
`core.rules` (the LibraryRules protocol package) whenever both scripts/commonlibvr and
scripts/core are on sys.path at once -- which many drivers now need simultaneously
(e.g. for core.engine.tx). Every per-library Rules implementation should use this name.

Usage (matches the sys.path pattern already used to import sibling modules like
layout_diff):

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from library_rules import IMPORT_PATH, SCRIPT_DIR, TYPES_CAT, RULES
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

ENV_PREFIX = 'CLVR'
# AE1799 tracks Skyrim 1.7.99's address-library format-5 + struct-layout
# break as its own version, so RE propagation covers it distinctly from
# 1.6.353-1.6.1179's shared AE layout (see CommonLibVR-ng PR #298 for the
# verified layout diffs: AttackBlockHandler, PlayerCharacter, SkyrimVM).
RUNTIMES = ['SE', 'AE', 'VR', 'AE1799']
VERSION_TUPLES = {
    'SE': (1, 5, 97, 0),
    'AE': (1, 6, 1170, 0),
    'VR': (1, 4, 15, 0),
    'AE1799': (1, 7, 99, 0),
}
INCLUDE_PATHS = [
    r'E:\Documents\source\repos\BethesdaGhidraScripts\extern\CommonLibVR\include',
]


class CommonLibVRRules:
    """Satisfies core.rules.base.LibraryRules. Grammar/format methods
    (parse_id_file, load_address_library, format_relocation,
    fallback_name_sources) are Phase-4 work -- not implemented yet."""

    name = 'commonlibvr'
    import_path = IMPORT_PATH
    script_dir = SCRIPT_DIR
    types_category = TYPES_CAT
    include_paths = INCLUDE_PATHS
    env_prefix = ENV_PREFIX
    runtimes = RUNTIMES
    version_tuples = VERSION_TUPLES


RULES = CommonLibVRRules()
