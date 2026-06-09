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

It also CONVERTS members that already have an explicit `this` under the wrong
convention (__fastcall): it removes the explicit `this` and sets __thiscall so the
auto-this is the only one (no double / storage shift), since __thiscall is the
correct convention for a member. IMPORTED (PDB) functions are left alone (their
convention may be deliberate / they may be non-members).

Non-destructive: each function is changed in its OWN transaction that commits only
when applying AND the result verifies (param count preserved, `this` is a typed
pointer); any anomaly/error -- or the whole run in dry-run -- rolls back. So a bad
conversion can never persist. Dry-run by default; CLVR_SEED=go to apply. Decision
logic is in seed_plan.py (unit-tested).
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

    from ghidra.program.model.data import Pointer
    from ghidra.program.model.listing import ParameterImpl
    via_thiscall = via_fallback = converted = anomalies = skipped = errors = 0
    reasons = {}
    sample = []
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
        ps0 = f.getParameters()
        dt0 = ps0[0].getDataType() if ps0 else None
        has_this = dt0 is not None and isinstance(dt0, Pointer) and not sp.is_untyped(dt0.getName())

        action, reason = sp.should_set_thiscall(
            struct is not None, leaf, conv, srcname, is_static, has_this)
        if action == 'skip':
            skipped += 1
            reasons[reason] = reasons.get(reason, 0) + 1
            continue

        # Per-function transaction: a verified-good change commits only when
        # applying; an anomaly/error (or dry-run) rolls back JUST this function, so
        # a bad conversion can never persist.
        kind = None
        tag = ''
        tx = cp.startTransaction('thiscall ' + leaf)
        ok = False
        try:
            if action == 'convert':
                before_n = len(ps0)
                f.removeParameter(0)            # drop explicit this...
                f.setCallingConvention('__thiscall')   # ...auto-this replaces it
                ps = f.getParameters()
                d0 = ps[0].getDataType() if ps else None
                if (len(ps) == before_n and d0 is not None
                        and isinstance(d0, Pointer) and not sp.is_untyped(d0.getName())):
                    kind, tag, ok = 'convert', 'convert->%s' % d0.getName(), True
                else:
                    kind, tag = 'anomaly', 'convert-ANOMALY(%d->%d)' % (before_n, len(ps))
            else:
                f.setCallingConvention('__thiscall')
                ps = f.getParameters()
                d0 = ps[0].getDataType() if ps else None
                if d0 is not None and isinstance(d0, Pointer) and not sp.is_untyped(d0.getName()):
                    kind, tag, ok = 'thiscall', 'thiscall->%s' % d0.getName(), True
                else:
                    ptr = dtm.getPointer(struct, 8)
                    if ps:
                        ps[0].setDataType(ptr, SourceType.ANALYSIS)
                        ps[0].setName('this', SourceType.ANALYSIS)
                    else:
                        f.insertParameter(0, ParameterImpl('this', ptr, cp), SourceType.ANALYSIS)
                    kind, tag, ok = 'fallback', 'fallback->%s*' % cls, True
        except Exception:
            kind = 'error'
        finally:
            cp.endTransaction(tx, APPLY and ok)   # commit only a verified change

        if kind == 'convert':
            converted += 1
        elif kind == 'thiscall':
            via_thiscall += 1
        elif kind == 'fallback':
            via_fallback += 1
        elif kind == 'anomaly':
            anomalies += 1
        else:
            errors += 1
        if ok and len(sample) < 15:
            sample.append('%s::%s  [%s]' % (cls, leaf, tag))

    print('thiscall-set (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN (rolled back)'))
    print('  gap-fill: auto-this=%d, explicit-fallback=%d' % (via_thiscall, via_fallback))
    print('  convert (remove this + __thiscall): %d   ANOMALIES=%d' % (converted, anomalies))
    print('  skipped=%d  errors=%d' % (skipped, errors))
    print('  skip reasons: %s' % reasons)
    for s in sample:
        print('   ' + s)


run()
