"""Fallout New Vegas (xNVSE + Xbox 360) LibraryRules implementation (Phase 2 stub --
data fields only; see core/rules/base.py for why the grammar/format methods are
deliberately deferred to Phase 4, a separate later effort). Mirrors
commonlibvr/library_rules.py's shape.

FNV is "the odd one out" among these targets: x86 32-bit, no versionlib/REL::ID, and
the Xbox 360 side is PowerPC big-endian -- a wholly different ISA from every other
CommonLib target here. `runtimes` below covers the two BINARIES this pipeline
cross-references (PC and Xbox), not build-version variants like the other libraries.
"""
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_PREFIX = 'CLNV'
RUNTIMES = ['PC', 'XBOX']
VERSION_TUPLES = {}   # FNV has no versionlib-style build-number scheme
INCLUDE_PATHS = [
    r'E:\Documents\source\repos\BethesdaGhidraScripts\extern\xNVSE\nvse\nvse',
]
IMPORT_PATH = os.environ.get(
    'CLNV_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_FNV.py')
TYPES_CAT = '/xNVSE'


class CommonLibNVSERules:
    """Satisfies core.rules.base.LibraryRules."""

    name = 'commonlibnvse'
    import_path = IMPORT_PATH
    script_dir = SCRIPT_DIR
    types_category = TYPES_CAT
    include_paths = INCLUDE_PATHS
    env_prefix = ENV_PREFIX
    runtimes = RUNTIMES
    version_tuples = VERSION_TUPLES


RULES = CommonLibNVSERules()
