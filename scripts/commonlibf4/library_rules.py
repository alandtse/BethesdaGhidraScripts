"""CommonLibF4's LibraryRules implementation, now including the Phase 4
grammar/format methods (LibraryRulesFormat) -- thin delegates to this folder's
own pre-existing reloc_parser.py (collect_relocations: centralized IDs.h
registry, single ae_off per symbol) and address_library.py
(F4AddressLibrary.load_bin: flat uint64-count + (id,offset) pairs), not new
algorithms.

F4's VR runtime uses a DISJOINT id namespace from OG/NG/AE (unlike Skyrim, where
SE and VR share one namespace) -- load_address_library reads whichever .bin/.csv
path it's given; namespace disjointness is a caller-side concern (which db to
load), not something the loader itself needs to know.

Not yet wired into parse_commonlib_types.py / bytesig_port_combined.py / etc --
those keep their own inline constants for now.
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


reloc_parser = _load('clf4_reloc_parser', 'reloc_parser.py')
_address_library_mod = _load('clf4_address_library', 'address_library.py')
F4AddressLibrary = _address_library_mod.F4AddressLibrary

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

    def parse_id_file(self, re_include, addr_lib, verbose=False, root_namespace='RE'):
        """Scan CommonLibF4's RE/ headers for IDs.h-registry symbols. Delegates
        to reloc_parser.collect_relocations verbatim; returns its native
        3-tuple (func_syms, label_syms, static_methods)."""
        return reloc_parser.collect_relocations(re_include, addr_lib, verbose, root_namespace)

    def load_address_library(self, path):
        """Read a flat uint64-count + (id,offset) .bin into {id: offset}."""
        return F4AddressLibrary().load_bin(path)

    def format_relocation(self, ids):
        """Render CommonLibF4's single-ID registry reference: REL::ID(id)."""
        return 'REL::ID(%d)' % ids['id']

    def fallback_name_sources(self):
        return ['IDA names', '1.11.221 PDB']


RULES = CommonLibF4Rules()
