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

# Extra AE point-release variants beyond the four baseline RUNTIMES above -- an AE
# point release (like 1.7.99) that changed the address-library on-disk FORMAT (not
# the compiled struct layout: same '-DENABLE_SKYRIM_AE=1' defines, see VERSIONS in
# parse_commonlib_types.py) reuses the shared AE RELOCATION_ID/VariantID id-space, so
# its RVA is found by reverse-mapping a known ae_off to that id, then looking the id
# up in this variant's own address-library file (`reloc_parser._attach_extra_ae_variants`).
#
#   key       - internal short name; address-library attribute is '<key>_db'
#   sym_key   - SYMBOLS dict offset field (single letter/short code, e.g. 'a9')
#   id_key    - SYMBOLS dict address-library-id field (e.g. 'ai9')
#   filename  - versionlib-*.bin under addresslibrary/sse/
#   format    - 'v5' (dense uint32[] format, AddressLibrary.load_bin_v5) or 'v2'
#               (legacy delta/varint format, AddressLibrary.load_bin)
#   version   - (major, minor, patch, sub) tuple, informational
#   vt_match  - substrings matched against a Version Tracking destination program's
#               name (case-sensitive substring, first match wins) -- include every
#               spelling Ghidra might show (a stale cached Program name can lag an
#               on-disk rename; see test_vt_plan.py's ae1799_by_stale_cached_name)
#   label     - human-readable "SE->X" label for logging
EXTRA_AE_VARIANTS = [
    {
        'key': 'ae1799',
        'sym_key': 'a9',
        'id_key': 'ai9',
        'filename': 'versionlib-1-7-99-0.bin',
        'format': 'v5',
        'version': (1, 7, 99, 0),
        'vt_match': ('1.7.99', '1.7.79', '1799'),
        'label': 'SE->AE1799',
    },
    {
        'key': 'ae1104',
        'sym_key': 'a4',
        'id_key': 'ai4',
        'filename': 'versionlib-1-7-104-0.bin',
        'format': 'v5',
        'version': (1, 7, 104, 0),
        'vt_match': ('1.7.104', '1104'),
        'label': 'SE->AE1104',
    },
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
