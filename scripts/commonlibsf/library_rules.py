"""CommonLibSF (Starfield)'s LibraryRules implementation, now including the
Phase 4 grammar/format methods (LibraryRulesFormat) -- thin delegates to this
folder's own pre-existing ids_parser.py (collect_all: IDs.h/IDs_RTTI.h/
IDs_NiRTTI.h/IDs_VTABLE.h single-ID REL::ID manifests) and address_library.py
(AddressLibrary.load_bin: meh321 V5 flat uint32[id] array), not new algorithms.

Not yet wired into parse_commonlib_types.py / dump_vtable_layouts.py / etc --
those keep their own inline constants for now.
"""
import importlib.util as _ilu
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load(modname, fname):
    """Dynamic, uniquely-named load so this library's ids_parser.py/
    address_library.py never collides with another library's same-named
    sibling module when multiple library_rules.py modules are imported in the
    same process (as core/test_all_library_rules.py does) -- a bare `import
    address_library` would silently reuse whichever library's copy loaded first."""
    spec = _ilu.spec_from_file_location(modname, os.path.join(SCRIPT_DIR, fname))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ids_parser = _load('clsf_ids_parser', 'ids_parser.py')
_address_library_mod = _load('clsf_address_library', 'address_library.py')
AddressLibrary = _address_library_mod.AddressLibrary

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

    def parse_id_file(self, re_include, addr_lib, verbose=False):
        """Scan CommonLibSF's IDs*.h manifests. Delegates to
        ids_parser.collect_all verbatim; returns its native
        (func_syms, label_syms) pair."""
        return ids_parser.collect_all(re_include, addr_lib, verbose)

    def load_address_library(self, path):
        """Read a meh321 V5 flat uint32[id]-indexed versionlib.bin into {id: offset}."""
        return AddressLibrary().load_bin(path)

    def format_relocation(self, ids):
        """Render CommonLibSF's single-ID registry reference: REL::ID(id)."""
        return 'REL::ID(%d)' % ids['id']

    def fallback_name_sources(self):
        return ['versionlib IDs.h manifests', 'PDB publics']


RULES = CommonLibSFRules()
