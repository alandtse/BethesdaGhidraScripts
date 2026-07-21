"""Fallout New Vegas (xNVSE + Xbox 360) LibraryRules implementation, now
including the Phase 4 grammar/format methods (LibraryRulesFormat) -- a thin
delegate to this folder's own pre-existing addresses.py (collect_all: scans
xNVSE headers for hardcoded VAs + a CSV name overlay), not a new algorithm.

FNV is "the odd one out" among these targets: x86 32-bit, no versionlib/REL::ID, and
the Xbox 360 side is PowerPC big-endian -- a wholly different ISA from every other
CommonLib target here. `runtimes` below covers the two BINARIES this pipeline
cross-references (PC and Xbox), not build-version variants like the other libraries.

load_address_library documents (rather than fakes) that FNV has no
address-library binary format at all: addresses are hardcoded VAs baked
directly into the frozen 1.4.0.525 xNVSE headers, so there is no {id: offset}
lookup table to read -- parse_id_file (via addresses.py) IS the address
source for this library.
"""
import importlib.util as _ilu
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _load(modname, fname):
    """Dynamic, uniquely-named load so this library's addresses.py never
    collides with another library's same-named sibling module when multiple
    library_rules.py modules are imported in the same process (as
    core/test_all_library_rules.py does)."""
    spec = _ilu.spec_from_file_location(modname, os.path.join(SCRIPT_DIR, fname))
    m = _ilu.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


addresses = _load('clnv_addresses', 'addresses.py')

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

    def parse_id_file(self, xnvse_root, refs_dir, verbose=False):
        """Scan xNVSE headers for hardcoded FNV 1.4.0.525 VAs + apply the CSV
        name overlay. Delegates to addresses.collect_all verbatim; returns its
        native (func_syms, label_syms) pair."""
        return addresses.collect_all(xnvse_root, refs_dir, verbose)

    def load_address_library(self, path):
        """FNV has no address-library binary format (no versionlib/REL::ID) --
        addresses are hardcoded VAs baked into the xNVSE headers themselves
        (see parse_id_file). Always returns {} rather than faking a lookup
        table that doesn't exist for this game."""
        return {}

    def format_relocation(self, ids):
        """Render FNV's hardcoded-VA convention: a plain hex address literal."""
        return '0x%08X' % ids['va']

    def fallback_name_sources(self):
        return ['xNVSE headers', 'refs/fnv_names.csv overlay']


RULES = CommonLibNVSERules()
