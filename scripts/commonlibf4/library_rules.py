"""CommonLibF4's LibraryRules implementation (Phase 2 stub -- data fields only;
see core/rules/base.py for why the grammar/format methods are deliberately deferred
to Phase 4, a separate later effort). Mirrors commonlibvr/library_rules.py's shape.

Not yet wired into parse_commonlib_types.py / bytesig_port_combined.py / etc -- those
keep their own inline constants for now. This stub exists so commonlibf4 satisfies
core.rules.base.LibraryRules today, and so Phase 4 has a real per-library home to add
parse_id_file/load_address_library/format_relocation/fallback_name_sources to.

F4's VR runtime uses a DISJOINT id namespace from OG/NG/AE (unlike Skyrim, where SE
and VR share one namespace) -- see the Phase 4 follow-on for why this matters to
parse_id_file/load_address_library once those are implemented.
"""
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_PREFIX = 'CLF4'
RUNTIMES = ['OG', 'NG', 'AE', 'VR', '221']
VERSION_TUPLES = {
    'OG': (1, 10, 163, 0),
    'NG': (1, 10, 984, 0),
    'AE': (1, 11, 191, 0),
    'VR': (1, 2, 72, 0),
    '221': (1, 11, 221, 0),
}
INCLUDE_PATHS = [
    r'E:\Documents\source\repos\BethesdaGhidraScripts\extern\CommonLibF4\include',
]
IMPORT_PATH = os.environ.get(
    'CLF4_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_F4_NG.py')
TYPES_CAT = '/CommonLibF4'


class CommonLibF4Rules:
    """Satisfies core.rules.base.LibraryRules."""

    name = 'commonlibf4'
    import_path = IMPORT_PATH
    script_dir = SCRIPT_DIR
    types_category = TYPES_CAT
    include_paths = INCLUDE_PATHS
    env_prefix = ENV_PREFIX
    runtimes = RUNTIMES
    version_tuples = VERSION_TUPLES


RULES = CommonLibF4Rules()
