"""CommonLibSSE's LibraryRules implementation (Phase 2 stub -- data fields only;
see core/rules/base.py for why the grammar/format methods are deliberately deferred
to Phase 4, a separate later effort). Mirrors commonlibvr/library_rules.py's shape.

Not yet wired into parse_commonlib_types.py / build_svr_shift_map.py / etc -- those
keep their own inline constants for now. This stub exists so commonlibsse satisfies
core.rules.base.LibraryRules today, and so Phase 4 has a real per-library home to add
parse_id_file/load_address_library/format_relocation/fallback_name_sources to.
"""
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_PREFIX = 'CLSE'
RUNTIMES = ['SE', 'AE', 'VR']
VERSION_TUPLES = {
    'SE': (1, 5, 97, 0),
    'AE': (1, 6, 1170, 0),
    'VR': (1, 4, 15, 0),
}
INCLUDE_PATHS = [
    r'E:\Documents\source\repos\BethesdaGhidraScripts\extern\CommonLibSSE\include',
]
IMPORT_PATH = os.environ.get(
    'CLSE_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_SE.py')
TYPES_CAT = '/CommonLibSSE'


class CommonLibSSERules:
    """Satisfies core.rules.base.LibraryRules."""

    name = 'commonlibsse'
    import_path = IMPORT_PATH
    script_dir = SCRIPT_DIR
    types_category = TYPES_CAT
    include_paths = INCLUDE_PATHS
    env_prefix = ENV_PREFIX
    runtimes = RUNTIMES
    version_tuples = VERSION_TUPLES


RULES = CommonLibSSERules()
