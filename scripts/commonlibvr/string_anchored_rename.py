"""Thin wrapper: run the shared string-anchored rename driver
(core/engine/string_anchored_rename.py) with CommonLibVR's defaults.

The real driver now lives in core/engine/string_anchored_rename.py -- a merge of this
package's old inline reimplementation and core's version, which had already properly
factored the regex/consensus logic into plans/string_anchor_match.py (this package's
old driver had duplicated that same logic inline instead of importing it). This
wrapper only sets CommonLibVR's env var name (CLVR_RENAME) before delegating -- the
shared driver already checks CLVR_RENAME directly, so this is mostly a pass-through;
kept as a wrapper (not a straight delete) so `python commonlibvr/string_anchored_rename.py`
keeps working as an entry point.
"""
import importlib.util as _ilu
import os
import sys

_CORE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core')
sys.path.insert(0, _CORE_DIR)
_spec = _ilu.spec_from_file_location(
    'clvr_string_anchored_rename_driver', os.path.join(_CORE_DIR, 'engine', 'string_anchored_rename.py'))
_mod = _ilu.module_from_spec(_spec)
# exec_module() runs the loaded module in its OWN fresh namespace -- Ghidra's
# eval_python injects currentProgram/monitor into THIS script's globals, not into a
# dynamically-loaded module's, so they must be forwarded explicitly or the shared
# driver's bare `currentProgram`/`monitor` references raise NameError.
_mod.currentProgram = currentProgram  # noqa: F821
_mod.monitor = monitor  # noqa: F821
_spec.loader.exec_module(_mod)   # runs the shared driver's run() fresh, every call
