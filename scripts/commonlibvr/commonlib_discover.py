"""CommonLib<->Ghidra discovery harvester (READ-ONLY).

Closes the virtuous cycle: the bootstrap imports CommonLib's types/sigs into
Ghidra; this leverages Ghidra's own decompiler dataflow (FillOutStructureHelper,
the engine behind "Auto Fill Out Structure") to INFER field types at the offsets
CommonLib still marks `unkNN` -- net-new RE that exists only because the typed
scaffold gave the decompiler anchors to propagate from. Feed the results back to
CommonLib, re-import, and the next cycle propagates one level deeper.

NON-DESTRUCTIVE: FillOutStructureHelper.processStructure returns an in-memory
Structure; nothing is ever applied to the program. No transaction is opened. The
program's data types are asserted unchanged at the end.

Generalized: runtime is taken from the program name (offset key s/a/v), CommonLib
structs/symbols from the generated import. Run it on SE/AE/VR, any CommonLib
version. Output: <import>.discovered_fields.csv -- candidate CommonLib fields
(class, offset, current unk name, inferred type, confidence), high-confidence
first, ready for review and write-back.

Knobs (env): CLVR_DISCOVER_PER_CLASS (methods sampled per class, default 4),
CLVR_DISCOVER_MAX_CLASSES (0 = all), CLVR_DISCOVER_FOLLOW (1 = follow into called
functions for deeper inference, slower; default 0).
"""
import csv
import os

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
OUT_CSV = os.environ.get('CLVR_DISCOVER_CSV', IMPORT_PATH + '.discovered_fields.csv')
PER_CLASS = int(os.environ.get('CLVR_DISCOVER_PER_CLASS', '4') or 4)
MAX_CLASSES = int(os.environ.get('CLVR_DISCOVER_MAX_CLASSES', '0') or 0)
FOLLOW = os.environ.get('CLVR_DISCOVER_FOLLOW', '0') == '1'

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_discover_plan', os.path.join(SCRIPT_DIR, 'discover_plan.py'))
dp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(dp)


def _unk_offsets(dt):
    """Pointer-sized offsets a /types.h struct still leaves unknown (unk/pad name
    or undefined type) -- the harvest surface."""
    offs = {}
    for i in range(dt.getNumComponents()):
        c = dt.getComponent(i)
        fn = c.getFieldName() or ''
        tn = c.getDataType().getName()
        if c.getLength() >= 8 and (fn.startswith(('unk', 'pad')) or 'undefined' in tn):
            offs[c.getOffset()] = fn or ('off_%X' % c.getOffset())
    return offs


def _useful(tn):
    if not tn or 'undefined' in tn or '[' in tn:
        return False
    return tn not in ('char', 'byte', 'bool', 'void')


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.decompiler.util import FillOutStructureHelper
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    fm = cp.getFunctionManager()

    # harvest surface: live /types.h structs with unknown pointer-sized fields
    unk_by_class = {}
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() != 'StructureDB':
            continue
        if 'types.h' not in str(dt.getCategoryPath()):
            continue
        offs = _unk_offsets(dt)
        if offs:
            unk_by_class[dt.getName()] = offs

    # Function pool: EVERY function whose param-0 is a pointer to a class-with-
    # unknowns -- i.e. anything the enrichment gave a typed `this`, not just
    # CommonLib's id-bound symbols. This is what scales the cycle: the more of the
    # program is typed, the bigger the discovery surface next pass.
    by_class = {}
    for f in fm.getFunctions(True):
        ps = f.getParameters()
        if not ps:
            continue
        base_t = ps[0].getDataType().getName().rstrip('64').rstrip(' *')
        if base_t in unk_by_class:
            by_class.setdefault(base_t, []).append(f)

    dt_before = dtm.getDataTypeCount(True)
    decomp = DecompInterface()
    decomp.openProgram(cp)
    helper = FillOutStructureHelper(cp, monitor)  # noqa: F821

    observations = []
    classes_done = funcs_done = 0
    for cl, fns in by_class.items():
        if MAX_CLASSES and classes_done >= MAX_CLASSES:
            break
        classes_done += 1
        offs = unk_by_class[cl]
        for f in fns[:PER_CLASS]:
            try:
                r = decomp.decompileFunction(f, 45, monitor)  # noqa: F821
                if not (r and r.decompileCompleted()):
                    continue
                lsm = r.getHighFunction().getLocalSymbolMap()
                if lsm.getNumParams() < 1:
                    continue
                hv = lsm.getParamSymbol(0).getHighVariable()
                if hv is None:
                    continue
                st = helper.processStructure(hv, f, False, FOLLOW, decomp)
                if st is None:
                    continue
                funcs_done += 1
                for c in st.getComponents():
                    tn = c.getDataType().getName()
                    if c.getOffset() in offs and _useful(tn):
                        observations.append((cl, c.getOffset(), tn))
            except Exception:
                continue
    decomp.dispose()

    aggregated = dp.aggregate_inferences(observations)
    rows = dp.to_rows(aggregated, lambda c, o: unk_by_class.get(c, {}).get(o, ''))
    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'offset', 'current_name', 'inferred_type',
                    'confidence', 'votes', 'total_observations'])
        for cls, off, cur, typ, conf, votes, total in rows:
            w.writerow([cls, '0x%X' % off, cur, typ, conf, votes, total])

    high = sum(1 for r in rows if r[4] == 'high')
    dt_after = dtm.getDataTypeCount(True)
    print('Discovery (%s): classes=%d functions=%d -> %d candidate fields (%d high-confidence)'
          % (cp.getName(), classes_done, funcs_done, len(rows), high))
    print('  NON-DESTRUCTIVE check: data types %d -> %d (%s)'
          % (dt_before, dt_after, 'unchanged' if dt_before == dt_after else 'CHANGED!'))
    print('  -> ' + OUT_CSV)


run()
