"""Repair scrambled flat structs in place (phase `repair`).

Auto-imported structs sometimes list their members at the wrong offsets while every machine-named
member still ends in its true hex offset. This pass re-places them by that suffix. The rules live
in core/plans/struct_repair_plan.py (pure, unit-tested); this file only reads components from
Ghidra and applies each plan to a temporary same-length structure that replaces the original
(replaceWith is atomic: a failure leaves the original untouched).

Scope: structs in /types.h and /CommonLibSSE/RE. Structs that need a rebuild on an RTTI parent
(VR flat structs that used SE offsets) are not handled here.

Dry-run by default; CLVR_REPAIR=go to write. Writes <import>.repair.json (override
CLVR_REPAIR_JSON) holding each changed struct's before-snapshot as the rollback record, and the
refusal reasons, in both modes. Notes about dropped duplicates go into the struct description.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))
from engine.tx import transaction  # noqa: E402
from plans import struct_repair_plan as sr  # noqa: E402

APPLY = os.environ.get('CLVR_REPAIR', 'dry').lower() == 'go'
REPAIR_JSON = os.environ.get('CLVR_REPAIR_JSON', IMPORT_PATH + '.repair.json')
CATEGORIES = ('/types.h', '/CommonLibSSE/RE')


def _comps(s):
    out = []
    for c in s.getComponents():
        out.append({'offset': c.getOffset(), 'length': c.getLength(), 'name': c.getFieldName() or '',
                    'defined': c.getDataType().getName() != 'undefined'})
    return out


def _snapshot(s):
    return {'cat': str(s.getCategoryPath()), 'name': s.getName(), 'length': s.getLength(),
            'comps': [{'off': c.getOffset(), 'len': c.getLength(), 'name': c.getFieldName(),
                       'type': c.getDataType().getPathName(), 'comment': c.getComment()}
                      for c in s.getComponents()]}


def _plan_all(cp, monitor):
    from ghidra.program.model.data import Structure
    dtm = cp.getDataTypeManager()
    work, refused = [], {}
    for dt in dtm.getAllStructures():
        monitor.checkCancelled()
        if not isinstance(dt, Structure) or str(dt.getCategoryPath()) not in CATEGORIES:
            continue
        plan, notes, reason = sr.plan_unscramble(dt.getName(), dt.getLength(), _comps(dt),
                                                 packed=dt.isPackingEnabled())
        if reason:
            refused[dt.getPathName()] = reason
        elif plan:
            work.append((dt, plan, notes))
    return work, refused


def _apply(cp, dt, plan, notes):
    from ghidra.program.model.data import StructureDataType
    comps = {c.getOrdinal(): c for c in dt.getComponents()}
    tmp = StructureDataType(dt.getCategoryPath(), dt.getName(), dt.getLength(), cp.getDataTypeManager())
    for p in plan:
        src = comps.get(p['src']) if p['src'] is not None else None
        if src is not None:
            tmp.replaceAtOffset(p['offset'], src.getDataType(), p['length'], p['name'], src.getComment())
        else:
            from ghidra.program.model.data import ArrayDataType, ByteDataType
            tmp.replaceAtOffset(p['offset'], ArrayDataType(ByteDataType.dataType, p['length'], 1), p['length'], p['name'], None)
    if notes:
        tmp.setDescription(((dt.getDescription() or '') + ' [struct repair: ' + '; '.join(notes) + ']').strip())
    else:
        tmp.setDescription(dt.getDescription())
    length = dt.getLength()
    dt.replaceWith(tmp)
    got = {c.getFieldName(): c.getOffset() for c in dt.getComponents() if c.getDataType().getName() != 'undefined'}
    return dt.getLength() == length and sr.verify_plan(plan, got)


def run(cp, monitor):
    work, refused = _plan_all(cp, monitor)
    print('structs to repair: %d; refused: %d' % (len(work), len(refused)))
    for dt, plan, notes in work[:10]:
        print('   %s (%d members) %s' % (dt.getPathName(), len(plan), notes[:1]))
    record = {'repaired': [_snapshot(dt) for dt, _p, _n in work], 'refused': refused}
    with open(REPAIR_JSON, 'w') as fh:
        json.dump(record, fh, indent=1)
    if not APPLY:
        print('DRY-RUN (CLVR_REPAIR=go to write); record: %s' % REPAIR_JSON)
        return
    ok = bad = 0
    with transaction(cp, 'CommonLibVR struct repair'):
        for dt, plan, notes in work:
            try:
                if _apply(cp, dt, plan, notes):
                    ok += 1
                else:
                    bad += 1
                    print('   VERIFY FAILED: ' + dt.getPathName())
            except Exception as e:
                bad += 1
                print('   ERROR %s: %s' % (dt.getPathName(), e))
    print('APPLIED: %d repaired, %d failed. Restore from %s if needed.' % (ok, bad, REPAIR_JSON))


if 'currentProgram' in globals():
    run(currentProgram, monitor)  # noqa: F821
