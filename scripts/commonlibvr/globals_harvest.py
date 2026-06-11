"""Globals harvester (READ-ONLY): identify untyped global singletons by the class
whose methods they are passed to.

Engine singletons live in untyped global data (`DAT_*`, an `undefined8` slot). The
decompiler can't propagate field accesses through an untyped global, so a class only
reached via a global is invisible to commonlib_discover (which mines `this`-PARAMETER
methods). This finds those globals: when a global flows into a call as arg-0 (`this`)
and the callee's param-0 is a known class C, that global is very likely a `C *`.

It decompiles each function once (reusing the DecompInterface pattern), walks CALL
pcode ops, back-traces arg-0 to a global data address, and records (global, class,
caller). globals_plan aggregates to a per-global consensus type + confidence, written
to <import>.globals_queue.csv -- a review worklist (same accept-then-apply pattern as
the field review queue). Typing the global is left to review/apply (a later step);
this stage only proposes, and never writes.

Why it matters beyond naming: a typed global is (a) a new discovery anchor -- its
referencing functions become mineable -- and (b) a dependency edge the incremental
cycle currently can't see (a class can depend on another's layout THROUGH a global).

Read-only always. Knobs: CLVR_GLOBALS_CSV (output), CLVR_GLOBALS_MAX_FUNCS (cap
functions decompiled, 0 = all). Run programs SEQUENTIALLY (shared os.environ).
"""
import csv
import os

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
OUT_CSV = os.environ.get('CLVR_GLOBALS_CSV', IMPORT_PATH + '.globals_queue.csv')
MAX_FUNCS = int(os.environ.get('CLVR_GLOBALS_MAX_FUNCS', '0') or 0)
# Scan scope: default to class-method functions (parent namespace is a CLASS) -- where
# singleton usage concentrates and ~half the decompile cost. CLVR_GLOBALS_ALL=1 scans
# every function (catches singletons used only in free/global functions).
SCAN_ALL = os.environ.get('CLVR_GLOBALS_ALL', '0') == '1'

import importlib.util as _ilu  # noqa: E402
_gpspec = _ilu.spec_from_file_location('clvr_globals_plan', os.path.join(SCRIPT_DIR, 'globals_plan.py'))
gp = _ilu.module_from_spec(_gpspec)
_gpspec.loader.exec_module(gp)
_gspec = _ilu.spec_from_file_location('clvr_ghidra_util', os.path.join(SCRIPT_DIR, 'clvr_ghidra_util.py'))
gu = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(gu)


def _ram_addr(vn, mem, addr_space, depth=0):
    """Back-trace an arg varnode to the global data address it denotes -- the inline
    singleton's address (`&g`) or the pointer slot it was loaded from. None if it does
    not resolve to a data-section address within a few hops. Returns (addr, is_ptr):
    is_ptr is True when the value was LOADed from the address (the global is a pointer
    SLOT holding a `T *`), False when the address is the object itself (an INLINE
    singleton, type `T`). That distinction is what the apply step needs to choose
    between typing the global `T *` vs `T`."""
    from ghidra.program.model.pcode import PcodeOp
    if vn is None or depth > 4:
        return (None, False)
    if vn.isConstant():
        try:
            a = addr_space.getAddress(vn.getOffset())
        except Exception:
            return (None, False)
        return (a, False) if mem.contains(a) else (None, False)
    if vn.isAddress():
        a = vn.getAddress()
        return (a, False) if (a.isMemoryAddress() and mem.contains(a)) else (None, False)
    d = vn.getDef()
    if d is None:
        return (None, False)
    op = d.getOpcode()
    if op in (PcodeOp.CAST, PcodeOp.COPY, PcodeOp.PTRSUB, PcodeOp.PTRADD,
              PcodeOp.INT_ADD, PcodeOp.MULTIEQUAL):
        # MULTIEQUAL is a phi: following input-0 is a heuristic (one branch may not be
        # the global), but a wrong guess only adds a review-queue row a human rejects.
        return _ram_addr(d.getInput(0), mem, addr_space, depth + 1)
    if op == PcodeOp.LOAD:
        addr, _ = _ram_addr(d.getInput(1), mem, addr_space, depth + 1)
        return (addr, True)              # loaded FROM a global slot -> it holds a T *
    return (None, False)


def run():
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.pcode import PcodeOp
    cp = currentProgram  # noqa: F821
    fm = cp.getFunctionManager()
    mem = cp.getMemory()
    addr_space = cp.getAddressFactory().getDefaultAddressSpace()

    # only globals in non-executable (data) memory are singleton candidates
    def _in_data(addr):
        blk = mem.getBlock(addr)
        return blk is not None and not blk.isExecute()

    decomp = DecompInterface()
    decomp.openProgram(cp)

    # scope the scan (class-method functions by default -- singleton usage lives there)
    from ghidra.program.model.symbol import SymbolType
    gns = cp.getGlobalNamespace()

    def _is_class_method(f):
        p = f.getParentNamespace()
        return (p is not gns and p.getSymbol() is not None
                and p.getSymbol().getSymbolType() == SymbolType.CLASS)

    funcs = [f for f in fm.getFunctions(True) if SCAN_ALL or _is_class_method(f)]
    observations = []
    ptr_votes = {}                       # addr -> [is_ptr bools]; majority -> CSV column
    n = done = 0
    print('Globals harvest (%s): scanning %d %s functions for global-as-this ...'
          % (cp.getName(), len(funcs), 'all' if SCAN_ALL else 'class-method'))
    for f in funcs:
        if MAX_FUNCS and done >= MAX_FUNCS:
            break
        done += 1
        if done % 2000 == 0:
            monitor.setMessage('globals: %d funcs, %d obs' % (done, len(observations)))  # noqa: F821
            print('  ... %d funcs scanned, %d observations' % (done, len(observations)))
        try:
            r = decomp.decompileFunction(f, 30, monitor)  # noqa: F821
            if not (r and r.decompileCompleted()):
                continue
            hf = r.getHighFunction()
            for op in hf.getPcodeOps():
                if op.getOpcode() != PcodeOp.CALL or op.getNumInputs() < 2:
                    continue
                target = op.getInput(0)
                if not target.isAddress():
                    continue
                callee = fm.getFunctionAt(target.getAddress())
                if callee is None:
                    continue
                cls = gu.param0_class_name(callee)
                if not cls:
                    continue
                gaddr, is_ptr = _ram_addr(op.getInput(1), mem, addr_space)
                if gaddr is None or not _in_data(gaddr):
                    continue
                observations.append((gaddr.getOffset(), cls, f.getName()))
                ptr_votes.setdefault(gaddr.getOffset(), []).append(is_ptr)
                n += 1
        except Exception:
            continue
    decomp.dispose()

    aggregated = gp.aggregate_global_types(observations)
    rows = gp.to_rows(aggregated)
    st = cp.getSymbolTable()
    with open(OUT_CSV, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['global_addr', 'current_symbol', 'inferred_type', 'is_pointer',
                    'confidence', 'votes', 'total', 'distinct_classes', 'class_votes',
                    'callers', 'decision_type'])
        for g, typ, conf, votes, total, distinct, classes_str, callers in rows:
            addr = addr_space.getAddress(g)
            sym = st.getPrimarySymbol(addr)
            cur = sym.getName() if sym is not None else ''
            pv = ptr_votes.get(g, [])
            is_ptr = sum(1 for b in pv if b) > len(pv) / 2.0    # majority loaded-from
            w.writerow(['0x%X' % g, cur, typ, '1' if is_ptr else '0', conf, votes,
                        total, distinct, classes_str, callers, ''])

    high = sum(1 for r in rows if r[2] == 'high')
    med = sum(1 for r in rows if r[2] == 'medium')
    print('\n=== Globals harvest summary (%s) ===' % cp.getName())
    print('  functions scanned=%d  global-as-this observations=%d' % (done, n))
    print('  candidate globals=%d  (high=%d, medium=%d, low=%d)'
          % (len(rows), high, med, len(rows) - high - med))
    for g, typ, conf, votes, total, distinct, classes_str, callers in rows[:15]:
        print('   0x%X -> %s* [%s] votes=%d/%d  %s' % (g, typ, conf, votes, total, classes_str))
    print('  -> ' + OUT_CSV)
    print('  (read-only: review/fill decision_type, then apply to type the global)')


run()
