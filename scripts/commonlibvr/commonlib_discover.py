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
import collections
import csv
import os

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
OUT_CSV = os.environ.get('CLVR_DISCOVER_CSV', IMPORT_PATH + '.discovered_fields.csv')
# Per class, how many functions to mine. 0 = ALL (default): vfuncs and methods are
# where a class reveals its own field layout, so walk them all -- sampling just
# leaves fields undiscovered. Set a positive N only to cap runtime; functions are
# ordered `this`-methods first so a cap still mines the class's own methods.
PER_CLASS = int(os.environ.get('CLVR_DISCOVER_PER_CLASS', '0') or 0)
MAX_CLASSES = int(os.environ.get('CLVR_DISCOVER_MAX_CLASSES', '0') or 0)
# Follow the class pointer into the functions it is passed to (callee review):
# FillOutStructureHelper observes field accesses one call-edge deeper. Default on;
# set 0 to disable for speed.
FOLLOW = os.environ.get('CLVR_DISCOVER_FOLLOW', '1') == '1'
# Default is read-only (write a CSV only). CLVR_DISCOVER_APPLY=go also WRITES the
# high-confidence named fields into the /types.h structs -- the edge that lets the
# in-Ghidra population cycle compound (a newly-typed field is an anchor next pass).
APPLY = os.environ.get('CLVR_DISCOVER_APPLY', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_discover_plan', os.path.join(SCRIPT_DIR, 'discover_plan.py'))
dp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(dp)
_pspec = _ilu.spec_from_file_location('clvr_populate_plan', os.path.join(SCRIPT_DIR, 'populate_plan.py'))
pl = _ilu.module_from_spec(_pspec)
_pspec.loader.exec_module(pl)


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
    struct_by_class = {}                 # name -> live StructureDB (for apply)
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() != 'StructureDB':
            continue
        if 'types.h' not in str(dt.getCategoryPath()):
            continue
        offs = _unk_offsets(dt)
        if offs:
            unk_by_class[dt.getName()] = offs
            struct_by_class[dt.getName()] = dt

    # Function pool: every function with a pointer to a class-with-unknowns in ANY
    # parameter (not just param-0). param-0 is the class's own `this` (its methods
    # and vfuncs -- the richest field-layout source); a non-0 param is a function
    # that takes the class as an argument (a caller / cross-class user that still
    # reads its fields). We mine the matching param in each. Entries are ordered
    # `this`-first so a PER_CLASS cap still mines the class's own methods before the
    # argument-takers. Callee review is the FillOutStructureHelper FOLLOW flag below.
    def _base(tn):
        return tn.rstrip('64').rstrip(' *') if tn else ''

    by_class = {}                            # cls -> [(function, param_index), ...]
    for f in fm.getFunctions(True):
        seen_cls = set()
        for idx, p in enumerate(f.getParameters()):
            base_t = _base(p.getDataType().getName())
            if base_t in unk_by_class and base_t not in seen_cls:
                seen_cls.add(base_t)
                by_class.setdefault(base_t, []).append((f, idx))
    for cl in by_class:                      # `this`-methods (idx 0) first
        by_class[cl].sort(key=lambda fi: fi[1])

    dt_before = dtm.getDataTypeCount(True)
    decomp = DecompInterface()
    decomp.openProgram(cp)
    helper = FillOutStructureHelper(cp, monitor)  # noqa: F821

    observations = []
    dt_by_typename = {}                  # inferred typename -> its live DataType
    classes_done = funcs_done = 0
    total_classes = min(len(by_class), MAX_CLASSES) if MAX_CLASSES else len(by_class)
    per = 'ALL' if PER_CLASS <= 0 else str(PER_CLASS)
    print('Discovery: %d structs have unknown fields; %d have functions to mine '
          '(per-class=%s, callee-follow=%s).'
          % (len(unk_by_class), len(by_class), per, FOLLOW))
    for cl, fns in by_class.items():
        if MAX_CLASSES and classes_done >= MAX_CLASSES:
            break
        classes_done += 1
        if classes_done % 25 == 0 or classes_done == total_classes:
            monitor.setMessage('discover %d/%d classes, %d fields' % (  # noqa: F821
                classes_done, total_classes, len(observations)))
            print('  [%d/%d classes] functions=%d observations=%d'
                  % (classes_done, total_classes, funcs_done, len(observations)))
        offs = unk_by_class[cl]
        for f, pidx in (fns if PER_CLASS <= 0 else fns[:PER_CLASS]):
            try:
                r = decomp.decompileFunction(f, 45, monitor)  # noqa: F821
                if not (r and r.decompileCompleted()):
                    continue
                lsm = r.getHighFunction().getLocalSymbolMap()
                if lsm.getNumParams() <= pidx:
                    continue
                hv = lsm.getParamSymbol(pidx).getHighVariable()
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
                        dt_by_typename.setdefault(tn, c.getDataType())
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

    # APPLY: write high-confidence named fields into the /types.h structs so the
    # next cycle propagates from them. Only fills an unknown slot with a concrete
    # same-size type (should_apply_field); never creates a type (so the data-type
    # count is still invariant) and never clobbers existing RE.
    applied = 0
    apply_samples = []
    apply_skips = collections.Counter()
    if APPLY:
        tx = cp.startTransaction('discover-apply fields')
        try:
            for (cls, off), info in aggregated.items():
                struct = struct_by_class.get(cls)
                dt = dt_by_typename.get(info['type'])
                if struct is None or dt is None:
                    apply_skips['unresolved'] += 1
                    continue
                comp = struct.getComponentAt(off)
                if comp is None or comp.getOffset() != off:
                    apply_skips['no-slot'] += 1
                    continue
                cur_name = comp.getFieldName() or ''
                ok, why = pl.should_apply_field(
                    cur_name, comp.getDataType().getName(), info['type'],
                    dt.getLength(), comp.getLength(), info['confidence'])
                if not ok:
                    apply_skips[why] += 1
                    continue
                # Rename off the unk*/pad* prefix so the field LEAVES the discovery
                # surface (won't be re-mined, and the coverage metric counts it as
                # resolved). Keep the offset digits for write-back traceability:
                # 'unk58' -> 'fld58'.
                digits = ''.join(ch for ch in cur_name if ch.isalnum())
                for pre in ('unk', 'pad', 'off_'):
                    if digits.lower().startswith(pre):
                        digits = digits[len(pre):]
                        break
                new_name = 'fld%s' % (digits or ('%X' % off))
                try:
                    struct.replaceAtOffset(off, dt, dt.getLength(), new_name,
                                           'clvr-discovered ' + info['type'])
                    applied += 1
                    if len(apply_samples) < 15:
                        apply_samples.append('%s +0x%X %s -> %s %s'
                                             % (cls, off, cur_name, new_name, info['type']))
                except Exception:
                    apply_skips['replace-error'] += 1
        finally:
            cp.endTransaction(tx, True)   # always commit; never poison the group

    high = sum(1 for r in rows if r[4] == 'high')
    named = sum(1 for r in rows if r[3] not in dp.GENERIC_TYPES)
    classes_with_hits = len({r[0] for r in rows})
    per_class = collections.Counter(r[0] for r in rows)
    dt_after = dtm.getDataTypeCount(True)
    print('\n=== Discovery summary (%s) ===' % cp.getName())
    print('  classes mined=%d  functions analyzed=%d' % (classes_done, funcs_done))
    print('  candidate fields=%d  (high-confidence=%d, named-type=%d, size-only=%d)'
          % (len(rows), high, named, len(rows) - named))
    print('  classes with >=1 discovery=%d / %d unknown-bearing'
          % (classes_with_hits, len(unk_by_class)))
    print('  top classes by yield: %s'
          % ', '.join('%s(%d)' % (c, n) for c, n in per_class.most_common(6)))
    if APPLY:
        print('  APPLIED %d fields into /types.h structs   skips=%s'
              % (applied, dict(apply_skips)))
        for s in apply_samples:
            print('     ' + s)
    else:
        print('  READ-ONLY (CLVR_DISCOVER_APPLY=go to write fields into structs)')
    print('  data-type count %d -> %d (%s; apply only retypes fields, never creates)'
          % (dt_before, dt_after, 'unchanged' if dt_before == dt_after else 'CHANGED'))
    print('  -> ' + OUT_CSV)


run()
