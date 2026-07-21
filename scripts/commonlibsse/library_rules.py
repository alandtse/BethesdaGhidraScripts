"""CommonLibSSE's LibraryRules implementation, now including the Phase 4
grammar/format methods (LibraryRulesFormat). These are thin delegates to this
folder's own pre-existing parser/loader -- reloc_parser.py's collect_relocations
(RELOCATION_ID(se,ae) dual-macro + Offsets.h #ifdef-split header scanner) and
address_library.py's AddressLibrary.load_bin (meh321 V1/V2 compressed .bin) --
not new algorithms; see those modules for the real logic.

Not yet wired into parse_commonlib_types.py / build_svr_shift_map.py / etc -- those
keep their own inline constants for now. This class satisfies both
core.rules.base.LibraryRules and LibraryRulesFormat.
"""
import importlib.util as _ilu
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load(modname, fname):
    """Dynamic, uniquely-named load so this library's reloc_parser.py/
    address_library.py never collides with another library's same-named
    sibling module when multiple library_rules.py modules are imported in the
    same process (as core/test_all_library_rules.py does) -- a bare `import
    reloc_parser` would silently reuse whichever library's copy loaded first."""
    spec = _ilu.spec_from_file_location(modname, os.path.join(SCRIPT_DIR, fname))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


reloc_parser = _load('clse_reloc_parser', 'reloc_parser.py')
_address_library_mod = _load('clse_address_library', 'address_library.py')
AddressLibrary = _address_library_mod.AddressLibrary

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

    def parse_id_file(self, re_include, addr_lib, verbose=False, root_namespace='RE'):
        """Scan CommonLibSSE's RE/ headers for RELOCATION_ID/REL::ID symbols.
        Delegates to reloc_parser.collect_relocations verbatim; returns its
        native 6-tuple (func_syms, label_syms, offset_id_map, static_methods,
        se_offset_map, ae_offset_map)."""
        return reloc_parser.collect_relocations(re_include, addr_lib, verbose, root_namespace)

    def load_address_library(self, path):
        """Read a meh321 V1/V2 compressed .bin into {id: offset}."""
        return AddressLibrary().load_bin(path)

    def format_relocation(self, ids):
        """Render CommonLibSSE's dual-ID macro: RELOCATION_ID(se, ae)."""
        return 'RELOCATION_ID(%d, %d)' % (ids['SE'], ids['AE'])

    def fallback_name_sources(self):
        return ['.rename overlay', 'PDB publics', 'globals-sigs']


RULES = CommonLibSSERules()
