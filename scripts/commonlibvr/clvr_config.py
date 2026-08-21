"""Backward-compat re-export shim.

The real implementation moved to library_rules.py (Phase 2 of the DRY refactor --
CommonLibVRRules is the reference LibraryRules implementation). Kept as a thin shim,
not deleted, so this package's ~19 existing `from clvr_config import ...` call sites
don't need to change. New code should import from library_rules.py directly.
"""
import importlib.util as _ilu
import os as _os

# Uniquely-named load (not a bare `from library_rules import ...`): this
# basename is shared with every other library's own library_rules.py, and a
# bare import would alias whichever one lands in sys.modules first when
# multiple such modules are imported in the same process (e.g. pytest
# collecting commonlibsse/ and commonlibvr/ together) -- see
# commonlibvr/reloc_parser.py's identical concern.
_spec = _ilu.spec_from_file_location(
    'clvr_config_library_rules',
    _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'library_rules.py'))
_lr = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_lr)

IMPORT_PATH = _lr.IMPORT_PATH
SCRIPT_DIR = _lr.SCRIPT_DIR
TYPES_CAT = _lr.TYPES_CAT
