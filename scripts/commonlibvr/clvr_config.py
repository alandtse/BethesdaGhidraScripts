"""Backward-compat re-export shim.

The real implementation moved to library_rules.py (Phase 2 of the DRY refactor --
CommonLibVRRules is the reference LibraryRules implementation). Kept as a thin shim,
not deleted, so this package's ~19 existing `from clvr_config import ...` call sites
don't need to change. New code should import from library_rules.py directly.
"""
from library_rules import IMPORT_PATH, SCRIPT_DIR, TYPES_CAT  # noqa: F401
