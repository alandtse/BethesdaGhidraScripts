"""Ghidra driver: constructor-mining field recovery (READ-ONLY).
Technique adapted from alandtse's CommonLibVR fork.

A class constructor assigns each member from a typed, named parameter
(``this->Object_18 = a_object``, ``a_object:TESBoundObject*``), so one
decompile yields a field's NAME and TYPE together -- far more reliable
than size-only dataflow guesses.

For each CommonLib/PDB struct with unknown fields (``unk*``/``pad*``/
``undefined*``) this finds its constructor (param-0 is the class, name
looks like a ctor), decompiles it, and reads ``this->field@offset =
a_param`` assignments out of the pcode.  Proposals -- (class, offset,
type, name) -- are written to a CSV, unknown-slot fillers first.

NON-DESTRUCTIVE: only decompiles + writes a CSV; never modifies the
program.  Knobs (env):
  BGS_CTOR_CSV          output path (default: <repo>/scripts/core/refs/ctor_fields_<prog>.csv)
  BGS_CTOR_CATEGORY     only mine structs whose category path contains this
                        substring (default: empty = all structs)
  BGS_CTOR_MAX_CLASSES  cap classes mined (0 = all)
  BGS_CTOR_TIMEOUT      decompile seconds per function (default 45)
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ctor_plan as cp_plan  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATEGORY = os.environ.get('BGS_CTOR_CATEGORY', '')
MAX_CLASSES = int(os.environ.get('BGS_CTOR_MAX_CLASSES', '0') or 0)
TIMEOUT = int(os.environ.get('BGS_CTOR_TIMEOUT', '45') or 45)


def _high_name(vn):
    h = vn.getHigh() if vn is not None else None
    return h.getName() if h is not None else None


def _addr_off(vn, this_name, pc, depth=0):
    """Back-trace varnode ``vn`` to ``this + k``; return k or None.  Matches
    ``this`` by param NAME (Ghidra hands out distinct HighVariable objects
    for param-0 body instances, so identity comparison fails)."""
    if vn is None or depth > 7:
        return None
    if _high_name(vn) == this_name:
        return 0
    d = vn.getDef()
    if d is None:
        return None
    oc, ins = d.getOpcode(), d.getInputs()
    if oc in (pc.COPY, pc.CAST, pc.INDIRECT) and ins:
        return _addr_off(ins[0], this_name, pc, depth + 1)
    # PTRADD is pointer arithmetic base + index*elem_size: the BYTE offset is
    # ins[1] (index) * ins[2] (element size), NOT the raw index.  Using the
    # raw index yields offset/8 for 8-byte pointer fields (a pointer field
    # reported at +0x9 instead of +0x48).
    if oc == pc.PTRADD and len(ins) >= 3 and ins[1].isConstant() and ins[2].isConstant():
        s = _addr_off(ins[0], this_name, pc, depth + 1)
        if s is not None:
            return s + int(ins[1].getOffset()) * int(ins[2].getOffset())
    # PTRSUB / INT_ADD carry the byte offset directly in ins[1].
    if oc in (pc.INT_ADD, pc.PTRSUB) and len(ins) >= 2 and ins[1].isConstant():
        s = _addr_off(ins[0], this_name, pc, depth + 1)
        if s is not None:
            return s + int(ins[1].getOffset())
    return None


def _val_param(vn, param_names, pc, depth=0):
    """If ``vn`` (through copy/cast/phi) is one of the parameters by name,
    return its name; else None."""
    if vn is None or depth > 5:
        return None
    nm = _high_name(vn)
    if nm in param_names:
        return nm
    d = vn.getDef()
    if d is None:
        return None
    if d.getOpcode() in (pc.COPY, pc.CAST, pc.INDIRECT, pc.MULTIEQUAL):
        for iv in d.getInputs():
            r = _val_param(iv, param_names, pc, depth + 1)
            if r is not None:
                return r
    return None


def _ctor_assignments(hf, this_name):
    """{offset: (typename, param_name)} for ``this->field@off = a_param``."""
    from ghidra.program.model.pcode import PcodeOp
    lsm = hf.getLocalSymbolMap()
    param_type = {}
    for i in range(1, lsm.getNumParams()):
        ps = lsm.getParamSymbol(i)
        param_type[ps.getName()] = ps.getDataType().getName()
    out = {}
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.STORE:
            continue
        ins = op.getInputs()
        if len(ins) < 3:
            continue
        off = _addr_off(ins[1], this_name, PcodeOp)
        if off is None:
            continue
        pn = _val_param(ins[2], param_type, PcodeOp)
        if pn is None:
            continue
        out[off] = (param_type[pn], pn)
    return out


def _unk_offsets(dt):
    offs = set()
    for i in range(dt.getNumComponents()):
        c = dt.getComponent(i)
        fn = c.getFieldName() or ''
        if fn.startswith(('unk', 'pad')) or 'undefined' in c.getDataType().getName():
            offs.add(c.getOffset())
    return offs


def _vtable_class_map(prog):
    """{vtable_address_offset: class_name} from VTABLE_<Class> symbols."""
    st = prog.getSymbolTable()
    out = {}
    it = st.getAllSymbols(False)
    while it.hasNext():
        sym = it.next()
        n = sym.getName()
        if n.startswith('VTABLE_'):
            out[sym.getAddress().getOffset()] = n[len('VTABLE_'):]
    return out


def _const_addr_off(vn, depth=0):
    """Resolve a varnode to a constant RAM address offset (the ``&VTABLE``
    target) through copy/cast/ptrsub.  None if not a constant address."""
    from ghidra.program.model.pcode import PcodeOp
    if vn is None or depth > 6:
        return None
    if vn.isConstant():
        return int(vn.getOffset())
    if vn.isAddress():
        return int(vn.getAddress().getOffset())
    d = vn.getDef()
    if d is None:
        return None
    oc, ins = d.getOpcode(), d.getInputs()
    if oc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INDIRECT) and ins:
        return _const_addr_off(ins[0], depth + 1)
    if (oc == PcodeOp.PTRSUB and len(ins) >= 2
            and ins[0].isConstant() and ins[1].isConstant()):
        return int(ins[0].getOffset()) + int(ins[1].getOffset())
    return None


def _constructed_class(hf, this_name, vtmap):
    """If the function stores a known vtable address to ``this+0``, return
    the class name (from vtmap).  Identifies a constructor STRUCTURALLY --
    a ctor writes its class vtable to offset 0 -- so it works regardless of
    whether the function carries a constructor-shaped NAME (ours don't)."""
    from ghidra.program.model.pcode import PcodeOp
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.STORE:
            continue
        ins = op.getInputs()
        if len(ins) < 3:
            continue
        if _addr_off(ins[1], this_name, PcodeOp) != 0:
            continue
        v = _const_addr_off(ins[2])
        if v is not None and v in vtmap:
            return vtmap[v]
    return None


def run():
    from ghidra.app.decompiler import DecompInterface
    prog = currentProgram  # noqa: F821
    dtm = prog.getDataTypeManager()
    fm = prog.getFunctionManager()

    out_csv = os.environ.get('BGS_CTOR_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'ctor_fields_%s.csv' % prog.getName().replace('.', '_'))

    unk_by_class = {}
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() != 'StructureDB':
            continue
        if CATEGORY and CATEGORY not in str(dt.getCategoryPath()):
            continue
        offs = _unk_offsets(dt)
        if offs:
            unk_by_class[dt.getName()] = offs

    # Candidate constructors are found STRUCTURALLY, not by name: a ctor
    # references (and stores to this+0) its class's vtable.  Our binaries
    # don't carry constructor-shaped function names, so the name heuristic
    # (cp_plan.is_ctor) finds nothing -- the vtable cross-reference does.
    rm = prog.getReferenceManager()
    af = prog.getAddressFactory().getDefaultAddressSpace()
    vtmap = _vtable_class_map(prog)
    target_vt = {off: c for off, c in vtmap.items() if c in unk_by_class}

    cand_funcs = set()
    for off in target_vt:
        addr = af.getAddress(off)
        for ref in rm.getReferencesTo(addr):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is not None:
                cand_funcs.add(f)
    cand_list = list(cand_funcs)
    if MAX_CLASSES:
        cand_list = cand_list[:MAX_CLASSES * 6]

    decomp = DecompInterface()
    decomp.openProgram(prog)
    rows = []
    named = typed_unk = 0
    best_by_class = {}                      # cls -> (n_assign, assignments)
    print('ctor-mine: %d unk-bearing structs, %d unk-class vtables, '
          '%d functions reference a target vtable'
          % (len(unk_by_class), len(target_vt), len(cand_list)))
    for f in cand_list:
        try:
            r = decomp.decompileFunction(f, TIMEOUT, monitor)  # noqa: F821
            if not (r and r.decompileCompleted()):
                continue
            hf = r.getHighFunction()
            lsm = hf.getLocalSymbolMap()
            if lsm.getNumParams() < 1:
                continue
            this_name = lsm.getParamSymbol(0).getName()
            cls = _constructed_class(hf, this_name, vtmap)
            if cls is None or cls not in unk_by_class:
                continue
            asg = _ctor_assignments(hf, this_name)
            if not asg:                     # destructors write vtables too but
                continue                    # carry no field=param writes -> skip
            prev = best_by_class.get(cls)
            if prev is None or len(asg) > prev[0]:
                best_by_class[cls] = (len(asg), asg)
        except Exception:
            continue
    decomp.dispose()

    for cls, (_n, asg) in best_by_class.items():
        unk = unk_by_class.get(cls, set())
        for off, (tn, pname) in sorted(asg.items()):
            label = cp_plan.field_label(pname) or ''
            is_unk = off in unk
            rows.append((cls, '0x%X' % off, tn, label,
                         'unknown' if is_unk else 'known'))
            if label:
                named += 1
            if is_unk:
                typed_unk += 1
    classes_done = len(best_by_class)

    rows.sort(key=lambda r: (r[4] != 'unknown', r[0], int(r[1], 16)))
    if not os.path.isdir(os.path.dirname(out_csv)):
        os.makedirs(os.path.dirname(out_csv))
    with open(out_csv, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'offset', 'type', 'name', 'slot_state'])
        for r in rows:
            w.writerow(r)
    print('ctor-mine (%s): %d classes mined, %d field proposals '
          '(%d name a field, %d fill an unknown slot)'
          % (prog.getName(), classes_done, len(rows), named, typed_unk))
    for r in rows[:20]:
        print('   %s +%s %s %s [%s]' % r)
    print('  -> ' + out_csv)


run()
