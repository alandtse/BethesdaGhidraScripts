"""Thin wrapper: run the shared constructor-mining driver (core/engine/ctor_mine.py)
with CommonLibVR's defaults.

The real driver now lives in core/engine/ctor_mine.py -- a superset merge of this
package's old name-heuristic-only ctor_mine.py and core's structural (vtable-based)
version, since neither detection strategy alone covers every candidate. This wrapper
only sets CommonLibVR's specific defaults before delegating:

  - CLVR_CTOR_CATEGORY defaults to '/types.h' (this package's old hardcoded
    category filter -- the shared driver's own default is '', i.e. all structs,
    since other callers want the unrestricted scan).
  - CLVR_CTOR_CSV defaults to <IMPORT_PATH>.ctor_fields.csv (this package's old
    output-path convention), so existing invocations/tooling that read that path
    keep working unchanged.

CLVR_CTOR_MAX_CLASSES / CLVR_CTOR_TIMEOUT already work unchanged (the shared driver
checks the CLVR_CTOR_* namespace directly).

Loaded via importlib.util.spec_from_file_location (not a plain `import`), matching
this repo's convention for driver scripts that must re-run their module-level `run()`
call every invocation: a plain import would only execute core/engine/ctor_mine.py's
top-level code (including its unconditional `run()` call) ONCE per Python process --
harmless for a one-shot script execution, but wrong in a persistent PyGhidra/eval_python
session where sys.modules survives across separate invocations of this wrapper.
"""
import importlib.util as _ilu
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from library_rules import IMPORT_PATH, TYPES_CAT  # noqa: E402

os.environ.setdefault('CLVR_CTOR_CATEGORY', TYPES_CAT)
os.environ.setdefault('CLVR_CTOR_CSV', IMPORT_PATH + '.ctor_fields.csv')

_CORE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core')
sys.path.insert(0, _CORE_DIR)
_spec = _ilu.spec_from_file_location('clvr_ctor_mine_driver', os.path.join(_CORE_DIR, 'engine', 'ctor_mine.py'))
_mod = _ilu.module_from_spec(_spec)
# exec_module() runs the loaded module in its OWN fresh namespace -- Ghidra's
# eval_python injects currentProgram/monitor into THIS script's globals, not into a
# dynamically-loaded module's, so they must be forwarded explicitly or the shared
# driver's bare `currentProgram`/`monitor` references raise NameError.
_mod.currentProgram = currentProgram  # noqa: F821
_mod.monitor = monitor  # noqa: F821
_spec.loader.exec_module(_mod)   # runs the shared driver's run() fresh, every call
