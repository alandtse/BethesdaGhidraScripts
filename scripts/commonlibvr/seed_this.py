"""Make class-namespace functions proper `__thiscall` members (safe replacement
for the naive PopulateParameters; the correct mechanism vs. hand-typing param-0).

For each function whose parent is a GhidraClass with a `/types.h` struct, and only
when the method is not static/operator and the signature is not IMPORTED/
USER_DEFINED, set the calling convention to `__thiscall`. Ghidra then auto-inserts
a `this` param and -- because our GhidraClass namespaces are associated with their
structs -- auto-TYPES it to `Class*`. If that association does not yield a type
(`this` stays untyped), FALL BACK to setting param-0 explicitly to `Class*`
(SourceType.ANALYSIS). This extends typed-`this` coverage beyond CommonLib's
id-bound signatures (vtable-walk-named / reparented functions) so a downstream
call-graph type-propagation fixpoint has more anchors to radiate from.

Non-destructive: never touches PDB/hand-curated prototypes or static members; the
explicit fallback uses ANALYSIS source so a human edit or CommonLib re-import
outranks it. Dry-run by default (a single transaction that is ROLLED BACK, so it
reports the real auto-this-vs-fallback split without persisting); CLVR_SEED=go to
apply. Decision logic is in seed_plan.py (unit-tested).
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
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    fm = cp.getFunctionManager()
    gns = cp.getGlobalNamespace()
    static_of = _static_map()

    via_thiscall = via_fallback = skipped = errors = 0
    reasons = {}
    sample = []
    # Single transaction: committed when APPLY, ROLLED BACK in dry-run -- so the
    # dry-run measures the real auto-this-vs-fallback split without persisting.
    tx = cp.startTransaction('CommonLibVR thiscall set')
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
            conv = f.getCallingConventionName()
            src = f.getSignatureSource()
            srcname = src.name() if hasattr(src, 'name') else str(src)
            is_static = static_of.get(cls + '::' + leaf, False)

            action, reason = sp.should_set_thiscall(struct is not None, leaf, conv, srcname, is_static)
            if action == 'skip':
                skipped += 1
                reasons[reason] = reasons.get(reason, 0) + 1
                continue
            try:
                # Primary: __thiscall auto-inserts + auto-types `this` from the
                # class<->struct association.
                from ghidra.program.model.data import Pointer
                f.setCallingConvention('__thiscall')
                ps = f.getParameters()
                dt0 = ps[0].getDataType() if ps else None
                # success only if `this` is an actual (non-void/undefined) pointer
                # -- a leftover primitive like `longlong` must still fall back.
                if dt0 is not None and isinstance(dt0, Pointer) and not sp.is_untyped(dt0.getName()):
                    via_thiscall += 1
                    tag = 'thiscall->%s' % dt0.getName()
                else:
                    # Fallback: association didn't yield a type -> set it explicitly.
                    ptr = dtm.getPointer(struct, 8)
                    if ps:
                        ps[0].setDataType(ptr, SourceType.ANALYSIS)
                        ps[0].setName('this', SourceType.ANALYSIS)
                    else:
                        from ghidra.program.model.listing import ParameterImpl
                        f.insertParameter(0, ParameterImpl('this', ptr, cp), SourceType.ANALYSIS)
                    via_fallback += 1
                    tag = 'fallback->%s*' % cls
                if len(sample) < 15:
                    sample.append('%s::%s  [%s]' % (cls, leaf, tag))
            except Exception:
                errors += 1
    finally:
        cp.endTransaction(tx, APPLY)   # commit only when applying

    total = via_thiscall + via_fallback
    print('thiscall-set (%s): %s  candidates=%d  (auto-this=%d, explicit-fallback=%d) skipped=%d errors=%d'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN (rolled back)',
             total, via_thiscall, via_fallback, skipped, errors))
    print('  skip reasons: %s' % reasons)
    for s in sample:
        print('   ' + s)


run()
