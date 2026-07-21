"""Thin wrapper: run the shared globals harvester (core/engine/globals_harvest.py)
with CommonLibVR's defaults.

The real driver now lives in core/engine/globals_harvest.py -- a superset merge of
this package's old version and core's (core's `_param0_class_name` used proper
Pointer/Structure type introspection instead of this package's naive string-suffix
stripping via clvr_ghidra_util.param0_class_name, a correctness fix adopted for both).
This wrapper only sets CommonLibVR's specific historical defaults before delegating:

  - CLVR_GLOBALS_MIN_INDEG defaults to 15, CLVR_GLOBALS_SAMPLES to 6 (this package's
    old tuning -- the shared driver's own defaults are 8/4, core's old tuning; both
    original per-library configs are preserved exactly, neither picked as "more
    correct" since there's no structural reason to prefer one over the other).
  - CLVR_GLOBALS_CSV defaults to <IMPORT_PATH>.globals_queue.csv (this package's old
    output-path convention).
"""
import importlib.util as _ilu
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from library_rules import IMPORT_PATH  # noqa: E402

os.environ.setdefault('CLVR_GLOBALS_MIN_INDEG', '15')
os.environ.setdefault('CLVR_GLOBALS_SAMPLES', '6')
os.environ.setdefault('CLVR_GLOBALS_CSV', IMPORT_PATH + '.globals_queue.csv')

_CORE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core')
sys.path.insert(0, _CORE_DIR)
_spec = _ilu.spec_from_file_location('clvr_globals_harvest_driver', os.path.join(_CORE_DIR, 'engine', 'globals_harvest.py'))
_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_mod)   # runs the shared driver's run() fresh, every call
