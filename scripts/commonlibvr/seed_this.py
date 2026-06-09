"""Seed typed `this` on class-namespace functions (safe replacement for the naive
PopulateParameters).

For each function whose parent is a GhidraClass, resolve the class struct from
`/types.h`, and -- only when the current param-0 is untyped and the signature is
not IMPORTED/USER_DEFINED, and the method is not static/operator -- set param-0 to
`Class*` (named `this`) with SourceType.ANALYSIS. This extends typed-`this`
coverage beyond CommonLib's id-bound signatures (e.g. vtable-walk-named and
reparented functions), giving a downstream call-graph type-propagation fixpoint
more anchors to radiate from.

Non-destructive by construction: never clobbers PDB/hand-curated prototypes, only
fills untyped slots, and uses ANALYSIS source so any human edit or CommonLib
re-import outranks it. Dry-run by default (counts + sample); CLVR_SEED=go to apply.
Decision logic is in seed_plan.py (unit-tested).
"""
import json
import os

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
APPLY = os.environ.get('CLVR_SEED', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_seed_plan', os.path.join(SCRIPT_DIR, 'seed_plan.py'))
sp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(sp)

import re as _re  # noqa: E402
_DUP = _re.compile(r'(?:_[0-9A-Fa-f]{6,})+$')


def _static_map():
    """{ 'Class::Method': is_static } from CommonLib SYMBOLS (sd[2])."""
    out = {}
    try:
        with open(IMPORT_PATH) as f:
            for line in f:
                if line.startswith('SYMBOLS = '):
                    for s in json.loads(line[len('SYMBOLS = '):]):
                        if s.get('t') == 'func' and s.get('sd'):
                            out[s['n']] = bool(s['sd'][2])
                    break
    except Exception:
        pass
    return out


def run():
    from ghidra.program.model.symbol import SymbolType, SourceType
    from ghidra.program.model.data import CategoryPath
    from ghidra.program.model.listing import ParameterImpl
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    fm = cp.getFunctionManager()
    gns = cp.getGlobalNamespace()
    static_of = _static_map()

    seeded = skipped = errors = 0
    reasons = {}
    sample = []
    dt_before = dtm.getDataTypeCount(True)
    tx = cp.startTransaction('CommonLibVR this-seed') if APPLY else None
    try:
        for f in fm.getFunctions(True):
            parent = f.getParentNamespace()
            if parent is gns or parent.getSymbol() is None:
                continue
            if parent.getSymbol().getSymbolType() != SymbolType.CLASS:
                continue
            cls = parent.getName()
            leaf = _DUP.sub('', f.getName())
            struct = dtm.getDataType(CategoryPath('/types.h'), cls)
            params = f.getParameters()
            p0t = params[0].getDataType().getName() if params else None
            src = f.getSignatureSource()
            srcname = src.name() if hasattr(src, 'name') else str(src)
            is_static = static_of.get(cls + '::' + leaf, False)

            action, reason = sp.should_seed_this(struct is not None, leaf, p0t, srcname, is_static)
            if action == 'skip':
                skipped += 1
                reasons[reason] = reasons.get(reason, 0) + 1
                continue
            if len(sample) < 15:
                sample.append('%s::%s  (p0 %s -> %s*)' % (cls, leaf, p0t, cls))
            if not APPLY:
                seeded += 1
                continue
            try:
                ptr = dtm.getPointer(struct, 8)
                if params:
                    params[0].setDataType(ptr, SourceType.ANALYSIS)
                    params[0].setName('this', SourceType.ANALYSIS)
                else:
                    f.insertParameter(0, ParameterImpl('this', ptr, cp), SourceType.ANALYSIS)
                seeded += 1
            except Exception:
                errors += 1
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)

    dt_after = dtm.getDataTypeCount(True)
    print('this-seed (%s): %s  seeded=%d skipped=%d errors=%d'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN', seeded, skipped, errors))
    print('  skip reasons: %s' % reasons)
    print('  data types %d -> %d (%s)'
          % (dt_before, dt_after, 'unchanged' if dt_before == dt_after else 'changed'))
    for s in sample:
        print('   ' + s)


run()
