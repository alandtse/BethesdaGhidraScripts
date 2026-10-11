"""Rebuild VR flat structs on their RTTI parent (phase `rebase`).

A VR struct imported flat uses SE offsets for its own members. This phase moves them by the
VR parent's size delta and adds the parent as `_base`. The rules live in
core/plans/vr_rebase_plan.py (pure, unit-tested); the class table (direct parent, allocation
size) comes from rtti_facts.py, so classes CommonLib does not define are covered.

Two steps, because the SE members are read from the SE program:
  CLVR_REBASE=export  on SE: write <import>.rebase_facts.json (class -> alloc, parent, len, comps)
  CLVR_REBASE=dry|go  on VR: CLVR_REBASE_SE_JSON=<that file>; dry-run reports each class as
                      PLAN or SKIP with the reason, go rebuilds the planned structs

Each rebuilt struct's before-snapshot goes to <import>.rebase.json (override CLVR_REBASE_JSON).
CLVR_REBASE_CLASSES=A,B limits the run to the named classes.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))
from engine.tx import transaction  # noqa: E402
from plans import vr_rebase_plan as rb  # noqa: E402
from rtti_facts import class_table  # noqa: E402

import importlib.util as _ilu  # noqa: E402
_gspec = _ilu.spec_from_file_location('clvr_ghidra_util', os.path.join(SCRIPT_DIR, 'clvr_ghidra_util.py'))
gu = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(gu)

MODE = os.environ.get('CLVR_REBASE', 'dry').lower()
FACTS_JSON = os.environ.get('CLVR_REBASE_FACTS_JSON', IMPORT_PATH + '.rebase_facts.json')
SE_JSON = os.environ.get('CLVR_REBASE_SE_JSON', '')
SNAPSHOT_JSON = os.environ.get('CLVR_REBASE_JSON', IMPORT_PATH + '.rebase.json')
ONLY = {c for c in os.environ.get('CLVR_REBASE_CLASSES', '').split(',') if c}
CATEGORIES = ('/types.h', '/CommonLibSSE/RE')
ALIASES = {'NiTriBasedGeom': 'NiTriBasedGeometry'}    # RTTI class label -> Ghidra struct name
_ARRAY = re.compile(r'^(\w+)\[(\d+)\]$')


def _find(dtm, by_name, name):
    for cat in CATEGORIES:
        dt = dtm.getDataType(cat + '/' + name)
        if dt is not None:
            return dt
    return by_name.get(name)


def _comps(dt):
    return [(c.getOffset(), c.getLength(), c.getFieldName() or '', c.getDataType().getName())
            for c in dt.getComponents() if c.getDataType().getName() != 'undefined']


def _facts(cp, monitor):
    dtm = cp.getDataTypeManager()
    by_name = gu.build_by_name(dtm)
    out = {}
    for cls, info in class_table(cp, monitor).items():
        dt = _find(dtm, by_name, cls)
        if dt is not None and hasattr(dt, 'getComponents'):
            out[cls] = {'alloc': info['alloc'], 'parent': info['parent'], 'len': dt.getLength(),
                        'comps': _comps(dt)}
    return out


def _resolve(dtm, by_name, tname, length, existing):
    """Live type for a planned member, or None. Arrays and pointers are rebuilt from their
    element type; anything unresolved falls back to the VR struct's own member at that offset."""
    from ghidra.program.model.data import ArrayDataType
    m = _ARRAY.match(tname)
    if m:
        elem = _find(dtm, by_name, m.group(1))
        if elem is not None and elem.getLength() > 0 and length == elem.getLength() * int(m.group(2)):
            return ArrayDataType(elem, int(m.group(2)), elem.getLength())
    else:
        dt = gu.resolve_type(dtm, by_name, tname)
        if dt is not None and dt.getLength() == length:
            return dt
    if existing is not None and existing.getLength() == length and existing.getDataType().getName() != 'undefined':
        return existing.getDataType()
    return None


def _plan_all(cp, monitor, se_facts):
    dtm = cp.getDataTypeManager()
    by_name = gu.build_by_name(dtm)
    vr_facts = _facts(cp, monitor)
    plans, skipped = {}, {}
    for cls, v in vr_facts.items():
        if ONLY and cls not in ONLY:
            continue
        s = se_facts.get(cls)
        dt = _find(dtm, by_name, cls)
        if s is None or dt is None or dt.getNumComponents() == 0:
            continue
        if dt.getComponent(0) is not None and dt.getComponent(0).getFieldName() == '_base':
            continue
        pname = ALIASES.get(v['parent'], v['parent'])
        pdt = _find(dtm, by_name, pname) if pname else None
        plan, reason = rb.plan_rebase(v, s, vr_facts.get(v['parent']) if v['parent'] else None,
                                      se_facts.get(v['parent']) if v['parent'] else None,
                                      pdt.getLength() if pdt is not None else None)
        if plan is None:
            skipped[cls] = reason
        else:
            plans[cls] = (dt, pdt, plan)
    return plans, skipped, dtm, by_name


def _apply(cp, dtm, by_name, cls, dt, pdt, plan):
    from ghidra.program.model.data import ArrayDataType, ByteDataType, StructureDataType
    snapshot = {'name': cls, 'length': dt.getLength(),
                'comps': [(c.getOffset(), c.getLength(), c.getFieldName(), c.getDataType().getPathName())
                          for c in dt.getComponents()]}
    tmp = StructureDataType(dt.getCategoryPath(), cls, plan['length'], dtm)
    tmp.replaceAtOffset(0, pdt, plan['parent_len'], '_base', None)
    unresolved = []
    for m in plan['members']:
        existing = dt.getComponentAt(m['offset'])
        if existing is not None and existing.getOffset() != m['offset']:
            existing = None
        mdt = _resolve(dtm, by_name, m['type'], m['length'], existing)
        if mdt is None:
            mdt = ArrayDataType(ByteDataType.dataType, m['length'], 1)
            unresolved.append('%s:%s' % (m['name'], m['type']))
        tmp.replaceAtOffset(m['offset'], mdt, m['length'], m['name'], 'SE %s@0x%X' % (m['type'], m['se_offset']))
    tmp.setDescription('[rebased on _base: parent %s, own members from SE shifted by 0x%X]'
                       % (pdt.getName(), plan['delta']))
    dt.replaceWith(tmp)
    return snapshot, unresolved


def run(cp, monitor):
    if MODE == 'export':
        facts = _facts(cp, monitor)
        with open(FACTS_JSON, 'w') as fh:
            json.dump(facts, fh)
        print('exported %d classes to %s' % (len(facts), FACTS_JSON))
        return
    if not SE_JSON or not os.path.isfile(SE_JSON):
        raise SystemExit('set CLVR_REBASE_SE_JSON to the SE program\'s rebase_facts.json (CLVR_REBASE=export on SE)')
    with open(SE_JSON) as fh:
        se_facts = json.load(fh)
    plans, skipped, dtm, by_name = _plan_all(cp, monitor, se_facts)
    print('PLAN %d classes, SKIP %d' % (len(plans), len(skipped)))
    for cls, (_dt, pdt, plan) in list(plans.items())[:15]:
        print('   PLAN %s on %s: delta 0x%X, %d own members' % (cls, pdt.getName(), plan['delta'], len(plan['members'])))
    for cls, reason in list(skipped.items())[:15]:
        print('   SKIP %s: %s' % (cls, reason))
    if MODE != 'go':
        print('DRY-RUN (CLVR_REBASE=go to write)')
        return
    snapshots, done = [], 0
    with transaction(cp, 'CommonLibVR VR struct rebase'):
        for cls, (dt, pdt, plan) in plans.items():
            snap, unresolved = _apply(cp, dtm, by_name, cls, dt, pdt, plan)
            snapshots.append(snap)
            done += 1
            if unresolved:
                print('   %s: unresolved member types kept as bytes: %s' % (cls, unresolved[:4]))
    with open(SNAPSHOT_JSON, 'w') as fh:
        json.dump(snapshots, fh)
    print('APPLIED: %d structs rebuilt; before-snapshots in %s' % (done, SNAPSHOT_JSON))


if 'currentProgram' in globals():
    run(currentProgram, monitor)  # noqa: F821
