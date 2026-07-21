"""Ghidra driver: constructor-mining field recovery (READ-ONLY).

A class constructor assigns each member from a typed, named parameter
(`this->Object_18 = a_object`, `a_object:TESBoundObject*`), so one decompile yields a
field's NAME and TYPE together -- far more reliable than size-only dataflow guesses
(which mis-typed Crime+0x58 as a faction; the ctor showed 0x18 is the TESBoundObject
`object` and 0x58 a 4-byte scalar).

Superset merge of two independently-forked drivers (core/ctor_mine.py and
commonlibvr/ctor_mine.py) that used two DIFFERENT, complementary ways to find
candidate constructors:

  - NAME HEURISTIC (plans.ctor_plan.is_ctor): works when functions already carry a
    ctor-shaped name (`Class_ctor`, `Class::Class`) -- true for CommonLibVR targets
    that have already been through a naming pass.
  - STRUCTURAL (vtable store to `this+0`): a ctor writes its class's vtable to offset
    0 regardless of what the function is currently named -- necessary for binaries
    (e.g. Starfield/FNV) whose functions aren't ctor-named yet, where the name
    heuristic finds nothing.

Both run; candidates are UNIONED per class so either signal can surface constructors
the other misses. For each candidate this also extracts embedded-object information
(`CALL ctor_of_T(this+off, ...)` -- the member at `this+off` is constructed by T's
own constructor, so field@off has type T; off==0 is a base-class subobject) in
addition to direct `this->field = a_param` assignments, since a constructor may
initialize some members via sub-constructor calls rather than typed-parameter
assignment (particularly common on targets CommonLib hasn't typed yet).

For each struct with unknown fields (`unk*`/`pad*`/`undefined*`) this finds
candidate constructors, decompiles them, and reads assignments + embedded-object
calls out of the pcode. Proposals -- (class, offset, type, name) -- are written to a
CSV, unknown-slot fillers first.

NON-DESTRUCTIVE: only decompiles + writes a CSV; never modifies the program.

Env (both fork's original namespaces are honored; CTOR_* checked first, falling back
to the per-fork prefix so neither caller's existing invocation habits break):
  CTOR_CSV / BGS_CTOR_CSV / CLVR_CTOR_CSV                 output path
  CTOR_CATEGORY / BGS_CTOR_CATEGORY / CLVR_CTOR_CATEGORY  only mine structs whose
      category path contains this substring (default: empty = all structs -- a
      caller that wants the old commonlibvr default of '/types.h' should set this
      explicitly; see commonlibvr/ctor_mine.py, now a thin wrapper)
  CTOR_MAX_CLASSES / BGS_CTOR_MAX_CLASSES / CLVR_CTOR_MAX_CLASSES  cap classes mined
  CTOR_TIMEOUT / BGS_CTOR_TIMEOUT / CLVR_CTOR_TIMEOUT      decompile seconds/function
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plans import ctor_plan as cp_plan  # noqa: E402


def _env(key, default=''):
    return (os.environ.get('CTOR_' + key)
            or os.environ.get('BGS_CTOR_' + key)
            or os.environ.get('CLVR_CTOR_' + key)
            or default)


CATEGORY = _env('CATEGORY', '')
MAX_CLASSES = int(_env('MAX_CLASSES', '0') or 0)
TIMEOUT = int(_env('TIMEOUT', '45') or 45)


def _high_name(vn):
    h = vn.getHigh() if vn is not None else None
    return h.getName() if h is not None else None


def _addr_off(vn, this_name, pc, depth=0):
    """Back-trace varnode `vn` to `this + k`; return k or None. Matches
    `this` by param NAME (Ghidra hands out distinct HighVariable objects
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
    # ins[1] (index) * ins[2] (element size), NOT the raw index. Using the
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
    """If `vn` (through copy/cast/phi) is one of the parameters by name,
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
    """{offset: (typename, param_name)} for `this->field@off = a_param`."""
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


def _embedded_objects(hf, this_name, vtmap, fm, callee_class):
    """{offset: class_name} for `CALL ctor_of_T(this+off, ...)` -- the
    object at `this+off` is constructed by T's constructor, so field@off
    has type T. off==0 is the base-class subobject (inheritance); off!=0
    is an embedded member."""
    from ghidra.program.model.pcode import PcodeOp
    out = {}
    it = hf.getPcodeOps()
    while it.hasNext():
        op = it.next()
        if op.getOpcode() != PcodeOp.CALL:
            continue
        ins = op.getInputs()
        if len(ins) < 2 or not ins[0].isAddress():
            continue
        off = _addr_off(ins[1], this_name, PcodeOp)   # arg0 (RCX) == this+off?
        if off is None or off in out:
            continue
        cf = fm.getFunctionAt(ins[0].getAddress())
        if cf is None:
            continue
        cc = callee_class(cf)
        if cc is not None:
            out[off] = cc
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
    """Resolve a varnode to a constant RAM address offset (the `&VTABLE`
    target) through copy/cast/ptrsub. None if not a constant address."""
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
    """If the function stores a known vtable address to `this+0`, return
    the class name (from vtmap). Identifies a constructor STRUCTURALLY --
    a ctor writes its class vtable to offset 0 -- so it works regardless of
    whether the function carries a constructor-shaped NAME."""
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

    out_csv = _env('CSV') or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'refs',
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

    # Strategy 1 (structural): a ctor references (and stores to this+0) its class's
    # vtable -- works even when functions carry no ctor-shaped name.
    rm = prog.getReferenceManager()
    af = prog.getAddressFactory().getDefaultAddressSpace()
    vtmap = _vtable_class_map(prog)
    target_vt = {off: c for off, c in vtmap.items() if c in unk_by_class}

    cand_by_class = {}
    for off, cls in target_vt.items():
        addr = af.getAddress(off)
        for ref in rm.getReferencesTo(addr):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is not None:
                cand_by_class.setdefault(cls, set()).add(f)

    # Strategy 2 (name heuristic): param-0 type matches the class AND the function's
    # current name looks ctor-shaped -- works once a naming pass has run.
    for f in fm.getFunctions(True):
        ps = f.getParameters()
        if not ps:
            continue
        cls = ps[0].getDataType().getName().rstrip('64').rstrip(' *')
        if cls in unk_by_class and cp_plan.is_ctor(f.getName(), cls):
            cand_by_class.setdefault(cls, set()).add(f)

    targets = list(cand_by_class.items())
    if MAX_CLASSES:
        targets = targets[:MAX_CLASSES]

    decomp = DecompInterface()
    decomp.openProgram(prog)
    # second decompiler for callee-class resolution -- calling decompile on
    # the main interface again would invalidate the in-flight HighFunction.
    decomp2 = DecompInterface()
    decomp2.openProgram(prog)
    ctor_class_memo = {}                     # callee entry -> class or None

    def callee_class(fn):
        ea = fn.getEntryPoint().getOffset()
        if ea in ctor_class_memo:
            return ctor_class_memo[ea]
        ctor_class_memo[ea] = None
        try:
            r2 = decomp2.decompileFunction(fn, TIMEOUT, monitor)  # noqa: F821
            if r2 and r2.decompileCompleted():
                hf2 = r2.getHighFunction()
                lsm2 = hf2.getLocalSymbolMap()
                if lsm2.getNumParams() >= 1:
                    ctor_class_memo[ea] = _constructed_class(
                        hf2, lsm2.getParamSymbol(0).getName(), vtmap)
        except Exception:
            pass
        return ctor_class_memo[ea]

    rows = []
    named = typed_unk = n_embed = 0
    classes_done = 0
    print('ctor-mine: %d unk-bearing structs, %d have a candidate constructor '
          '(structural vtable match + ctor-shaped name, unioned)'
          % (len(unk_by_class), len(cand_by_class)))
    for cls, funcs in targets:
        classes_done += 1
        best = None   # (score, asg, emb)
        for f in list(funcs)[:6]:
            try:
                r = decomp.decompileFunction(f, TIMEOUT, monitor)  # noqa: F821
                if not (r and r.decompileCompleted()):
                    continue
                hf = r.getHighFunction()
                lsm = hf.getLocalSymbolMap()
                if lsm.getNumParams() < 1:
                    continue
                this_name = lsm.getParamSymbol(0).getName()
                asg = _ctor_assignments(hf, this_name)
                emb = _embedded_objects(hf, this_name, vtmap, fm, callee_class)
                if not asg and not emb:      # destructors / no usable info
                    continue
                score = len(asg) + len(emb)
                if best is None or score > best[0]:
                    best = (score, asg, emb)
            except Exception:
                continue
        if best is None:
            continue
        _n, asg, emb = best
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
        for off, ecls in sorted(emb.items()):
            if off in asg:                  # param-assignment already covers it
                continue
            is_unk = off in unk
            kind = 'base' if off == 0 else 'embedded'
            rows.append((cls, '0x%X' % off, ecls, kind,
                         'unknown' if is_unk else 'known'))
            n_embed += 1
            if is_unk:
                typed_unk += 1
    decomp.dispose()
    decomp2.dispose()

    rows.sort(key=lambda r: (r[4] != 'unknown', r[0], int(r[1], 16)))
    out_dir = os.path.dirname(out_csv)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(out_csv, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'offset', 'type', 'name', 'slot_state'])
        for r in rows:
            w.writerow(r)
    print('ctor-mine (%s): %d classes mined, %d field proposals '
          '(%d name a field, %d embedded-object types, %d fill an unknown slot)'
          % (prog.getName(), classes_done, len(rows), named, n_embed, typed_unk))
    for r in rows[:20]:
        print('   %s +%s %s %s [%s]' % r)
    print('  -> ' + out_csv)


run()
