"""Name the functions around each class's vtable, from the binary alone (phase `roles`).

For every RTTI class this names, as flat `Class::Role` strings (the `classes` phase then
reparents them into the class namespace and the `thiscall` phase types `this`, so this
driver does no namespace or signature work):

  Class::dtor_deleting   slot 0 of the primary vtable, when it has the deleting-destructor shape
  Class::~Class          the real destructor (the wrapper's first callee when it poisons the vtable)
  Class::CreateClone     slot 23 of a NiObject-derived class, when it is this class's own function
  Class::Create          the function that allocates the object and stores the vtable
  Class::ctor            the one non-allocating function that stores the vtable into `this`

The rules live in core/plans/vtable_roles_plan.py (pure, unit-tested); this file only gathers
the facts from Ghidra. Vtables and class names come from recover_rtti_vtables.py's RTTI
discovery (run that first: labels must be at the real vtables), so classes CommonLib does not
know are covered too.

Only auto-generated or known-wrong names are replaced (plan.is_placeholder_name); established
names are never overwritten. Dry-run by default; CLVR_ROLES=go to write. Writes
<import>.roles.csv (entry, class, role, old name) as the rollback record in both modes.
Run order: recover_rtti_vtables -> this phase -> `classes` -> `thiscall`.
"""
import csv
import os
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))
from engine.tx import transaction  # noqa: E402
from plans import vtable_roles_plan as vr  # noqa: E402

import importlib.util as _ilu  # noqa: E402
_rspec = _ilu.spec_from_file_location('clvr_recover_rtti', os.path.join(SCRIPT_DIR, 'recover_rtti_vtables.py'))
rr = _ilu.module_from_spec(_rspec)
_rspec.loader.exec_module(rr)
_gspec = _ilu.spec_from_file_location('clvr_ghidra_util', os.path.join(SCRIPT_DIR, 'clvr_ghidra_util.py'))
gu = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(gu)

APPLY = os.environ.get('CLVR_ROLES', 'dry').lower() == 'go'
ROLES_CSV = os.environ.get('CLVR_ROLES_CSV', IMPORT_PATH + '.roles.csv')


def _u32(blocks, a):
    blk = rr._block_of(blocks, a)
    return struct.unpack_from('<I', blk[1], a - blk[0])[0] if blk else None


def _u64(blocks, a):
    blk = rr._block_of(blocks, a)
    return struct.unpack_from('<Q', blk[1], a - blk[0])[0] if blk else None


def _base_names(blocks, image_base, vaddr):
    """RTTI type-descriptor names of the class and all its bases (COL -> class hierarchy)."""
    col = _u64(blocks, vaddr - 8)
    chd = _u32(blocks, col + 0x10) if col else None
    if chd is None:
        return []
    chd += image_base
    n = _u32(blocks, chd + 8) or 0
    arr = image_base + (_u32(blocks, chd + 0x0C) or 0)
    out = []
    for i in range(min(n, 40)):
        bcd = image_base + (_u32(blocks, arr + 4 * i) or 0)
        td = image_base + (_u32(blocks, bcd) or 0)
        out.append(rr._cstring(blocks, td + 0x10) or '')
    return out


class Facts(object):
    """Function facts for the planner, built on demand and cached per entry."""

    def __init__(self, cp):
        self.cp = cp
        self.fm = cp.getFunctionManager()
        self.listing = cp.getListing()
        self.cache = {}

    def func_name(self, addr):
        f = self.fm.getFunctionAt(addr)
        return f.getName() if f is not None else None

    def of(self, f):
        key = f.getEntryPoint().getOffset()
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        insns = []
        entries = set()
        for ins in self.listing.getInstructions(f.getBody(), True):
            text = str(ins)
            refs = [r.getToAddress().getOffset() for r in ins.getReferencesFrom()]
            flows = []
            if text.startswith(('CALL', 'JMP')):
                for fl in (ins.getFlows() or []):
                    flows.append(self.func_name(fl))
                    tf = self.fm.getFunctionAt(fl)
                    if tf is not None:
                        entries.add(tf.getEntryPoint().getOffset())
            insns.append((text, refs, flows))
        hit = {'entry': key, 'func': f, 'insns': insns, 'bytes': int(f.getBody().getNumAddresses()),
               'name': f.getName(), 'callees': entries}
        self.cache[key] = hit
        return hit


def _target_name(f, cls, role, global_ns):
    """The name to set: flat `Class::Role` for a function in the global namespace, but just the
    role leaf for one already inside namespace `cls` (a qualified name there would double the
    prefix). Functions placed in some other namespace keep the flat form for `classes` to judge."""
    flat = vr.flat_name(cls, role)
    parent = f.getParentNamespace()
    if parent is not global_ns and parent.getName() == cls:
        return flat.split('::', 1)[1]
    return flat


def run(cp, monitor):
    from ghidra.program.model.symbol import SourceType

    image_base = cp.getImageBase().getOffset()
    blocks = rr._cache_blocks(cp, monitor)
    col_meta, col_name = rr._collect_cols(blocks, image_base, monitor)
    by_class = rr._map_vtables(blocks, col_meta, col_name, monitor)
    primaries = [(vaddr, raw) for grp in by_class.values() for (vaddr, sub_off, raw) in grp if sub_off == 0]
    print('RTTI primary vtables:', len(primaries))

    st = cp.getSymbolTable()
    rm = cp.getReferenceManager()
    af = cp.getAddressFactory().getDefaultAddressSpace()
    facts = Facts(cp)

    def addr(v):
        return af.getAddress(v)

    slot0 = {}
    slot23 = {}
    for vaddr, _raw in primaries:
        slot0[vaddr] = _u64(blocks, vaddr)
        slot23[vaddr] = _u64(blocks, vaddr + 8 * 23)
    slot0_owners = Counter(slot0.values())
    slot23_owners = Counter(slot23.values())

    plans = []          # (entry, class, role, old name)
    skipped = Counter()
    wrappers_of_callee = Counter()
    per_class = []
    for vaddr, raw in primaries:
        monitor.checkCancelled()
        labels = []
        for s in st.getSymbols(addr(vaddr)):
            n = s.getName()
            if n.startswith('VTABLE_'):
                labels.append(n[len('VTABLE_'):])
        names = [n[:-2] if n.endswith('_0') else n for n in labels]
        cls = vr.pick_class_name(raw, names)
        if cls is None:
            skipped['no usable class label'] += 1
            continue
        wf = cp.getFunctionManager().getFunctionAt(addr(slot0[vaddr])) if slot0[vaddr] else None
        if wf is None or slot0_owners[slot0[vaddr]] > 1:
            skipped['slot 0 missing or shared'] += 1
            continue
        w = facts.of(wf)
        if not vr.is_deleting_wrapper(w['insns'], w['bytes']):
            skipped['slot 0 is not a deleting wrapper'] += 1
            continue
        size = vr.free_size([i[0] for i in w['insns']])
        first_callee = None
        for ins in cp.getListing().getInstructions(wf.getBody(), True):
            if str(ins).startswith('CALL') and ins.getFlows():
                first_callee = cp.getFunctionManager().getFunctionAt(ins.getFlows()[0])
                break
        if first_callee is not None:
            wrappers_of_callee[first_callee.getEntryPoint().getOffset()] += 1
        refs = {}
        for r in rm.getReferencesTo(addr(vaddr)):
            ins = cp.getListing().getInstructionAt(r.getFromAddress())
            if ins is None or not str(ins).startswith('LEA'):
                continue
            f = cp.getFunctionManager().getFunctionContaining(r.getFromAddress())
            if f is not None:
                fa = facts.of(f)
                refs[fa['entry']] = fa
        s23 = slot23[vaddr]
        roles, stats = vr.plan_class_roles(
            vaddr, refs, w['entry'], s23, slot23_owners[s23] if s23 else 0, w['callees'], size,
            vr.is_niobject(_base_names(blocks, image_base, vaddr)), {x for x in slot0.values() if x})
        for k, v in stats.items():
            skipped[k] += v
        per_class.append((cls, vaddr, w, first_callee, roles, refs))

    for cls, vaddr, w, first_callee, roles, refs in per_class:
        if vr.is_placeholder_name(w['name']) or w['name'] == 'dtor_deleting':
            plans.append((w['entry'], cls, 'dtor_deleting', w['name']))
        if (first_callee is not None and wrappers_of_callee[first_callee.getEntryPoint().getOffset()] == 1
                and vr.is_placeholder_name(first_callee.getName())):
            fa = facts.of(first_callee)
            if vr.real_destructor(fa['insns'], vaddr):
                plans.append((fa['entry'], cls, 'dtor', first_callee.getName()))
        for entry, role in roles.items():
            old = refs[entry]['name']
            if vr.is_placeholder_name(old):
                plans.append((entry, cls, role, old))
            else:
                skipped['established name kept'] += 1

    # one function must receive one name
    seen = Counter(p[0] for p in plans)
    plans = [p for p in plans if seen[p[0]] == 1]
    todo = [p for p in plans if vr.flat_name(p[1], p[2]) != p[3]]
    print('classes planned: %d; function names to set: %d; skipped: %s' % (len(per_class), len(todo), dict(skipped)))
    print('by role:', dict(Counter(p[2] for p in todo)))
    with open(ROLES_CSV, 'w', newline='') as fh:
        wtr = csv.writer(fh)
        wtr.writerow(['entry', 'class', 'role', 'old_name'])
        for entry, cls, role, old in todo:
            wtr.writerow(['%x' % entry, cls, role, old])
    for entry, cls, role, old in todo[:8]:
        print('   %x %s -> %s' % (entry, old, vr.flat_name(cls, role)))
    if not APPLY:
        print('DRY-RUN (CLVR_ROLES=go to write); record: %s' % ROLES_CSV)
        return
    done = errs = 0
    with transaction(cp, 'CommonLibVR vtable roles'):
        fm = cp.getFunctionManager()
        global_ns = cp.getGlobalNamespace()
        for entry, cls, role, _old in todo:
            f = fm.getFunctionAt(addr(entry))
            if f is None:
                continue
            try:
                gu.set_name_verified(f, _target_name(f, cls, role, global_ns), SourceType.USER_DEFINED)
                done += 1
            except Exception:
                errs += 1
    print('APPLIED: %d names set, %d errors. Next: CLVR_PHASE=classes, then thiscall.' % (done, errs))


if 'currentProgram' in globals():
    run(currentProgram, monitor)  # noqa: F821
