"""CommonLibSF (Starfield)'s LibraryRules implementation (Phase 2 stub -- data fields
only; see core/rules/base.py for why the grammar/format methods are deliberately
deferred to Phase 4, a separate later effort). Mirrors commonlibvr/library_rules.py's
shape.

Not yet wired into parse_commonlib_types.py / dump_vtable_layouts.py / etc -- those
keep their own inline constants for now. This stub exists so commonlibsf satisfies
core.rules.base.LibraryRules today, and so Phase 4 has a real per-library home to add
parse_id_file/load_address_library/format_relocation/fallback_name_sources to.
"""
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_PREFIX = 'CLSF'
RUNTIMES = ['SF17', 'SF116']
VERSION_TUPLES = {
    'SF17': (1, 7, 23, 0),
    'SF116': (1, 16, 236, 0),
}
INCLUDE_PATHS = [
    r'E:\Documents\source\repos\BethesdaGhidraScripts\extern\CommonLibSF\include',
]
IMPORT_PATH = os.environ.get(
    'CLSF_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_SF.py')
TYPES_CAT = '/CommonLibSF'


class CommonLibSFRules:
    """Satisfies core.rules.base.LibraryRules."""

    name = 'commonlibsf'
    import_path = IMPORT_PATH
    script_dir = SCRIPT_DIR
    types_category = TYPES_CAT
    include_paths = INCLUDE_PATHS
    env_prefix = ENV_PREFIX
    runtimes = RUNTIMES
    version_tuples = VERSION_TUPLES


RULES = CommonLibSFRules()
