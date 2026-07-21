"""Ghidra driver: globals harvester (READ-ONLY) -- identify untyped global
singletons by the class whose methods they are passed to.

Engine singletons live in untyped global data (`DAT_*`, an `undefined8` slot). The
decompiler can't propagate field accesses through an untyped global, so a class only
reached via a global is invisible to constructor/this-parameter discovery. When a
global flows into a call as arg-0 (`this`) and the callee's param-0 is a known class
C, that global is very likely a `C *`.

This decompiles each in-scope function, walks CALL pcode ops, back-traces arg-0 to a
global data address, and records (global, class, caller). plans.globals_plan
aggregates to a per-global consensus type + confidence, written to a review CSV.
Read-only: proposes, never writes.

Superset merge of two independently-forked drivers (core/globals_harvest.py and
commonlibvr/globals_harvest.py). The only real behavioral difference: this driver's
`_param0_class_name` does proper Pointer/Structure type introspection (adopted from
core's version) rather than the naive string-suffix stripping
(`.rstrip('64').rstrip(' *')`) commonlibvr's driver used via clvr_ghidra_util --
the naive version lets Ghidra builtins (`longlong`, `bool`, `code *`, ...) masquerade
as "classes", inflating the competing-class count and demoting a genuinely consistent
singleton to low confidence. Adopted as a strict correctness improvement, not a
judgment call (nothing the naive version could classify that this one can't).

Env (both fork's original namespaces are honored; GLOBALS_* checked first, falling
back to the per-fork prefix so neither caller's existing invocation habits break):
  GLOBALS_CSV / BGS_GLOBALS_CSV / CLVR_GLOBALS_CSV       output path
  GLOBALS_SCOPE / BGS_GLOBALS_SCOPE / CLVR_GLOBALS_SCOPE  data|class|all (default
      data -- GLOBALS-FIRST sampling: a cheap reference pass ranks untyped globals by
      in-degree, keeps high-in-degree singleton candidates, and decompiles only a
      SAMPLE of each one's referrers -- enough for type consensus. This bounds work by
      (candidate globals x sample cap), not the caller set (a singleton can be
      referenced by tens of thousands of functions).
  GLOBALS_MAX_FUNCS / BGS_GLOBALS_MAX_FUNCS / CLVR_GLOBALS_MAX_FUNCS   cap functions
  GLOBALS_MIN_INDEG / BGS_GLOBALS_MIN_INDEG / CLVR_GLOBALS_MIN_INDEG   min distinct
      referrers for a data-scope global (default 8 -- commonlibvr's wrapper raises
      this to 15, its own historical default; see commonlibvr/globals_harvest.py)
  GLOBALS_SAMPLES / BGS_GLOBALS_SAMPLES / CLVR_GLOBALS_SAMPLES   referrers sampled
      per candidate global (default 4 -- commonlibvr's wrapper raises this to 6)
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plans import globals_plan as gp  # noqa: E402


def _env(key, default=''):
    return (os.environ.get('GLOBALS_' + key)
            or os.environ.get('BGS_GLOBALS_' + key)
            or os.environ.get('CLVR_GLOBALS_' + key)
            or default)


SCOPE = _env('SCOPE', 'data').lower()
MAX_FUNCS = int(_env('MAX_FUNCS', '0') or 0)
MIN_INDEG = int(_env('MIN_INDEG', '8') or 8)
SAMPLES = int(_env('SAMPLES', '4') or 4)


def _param0_class_name(callee):
    """Class name of the callee's param-0 (the `this` type), but ONLY when
    param-0 is a pointer to an actual Structure (class).

    A name-string reject list is not enough: every Ghidra builtin
    (`longlong`, `float`, `bool`, `uint64_t`, `code *` ...) would
    otherwise pass as a "class", giving an untyped global a bogus vote that
    inflates the competing-class count and demotes a genuinely consistent
    singleton to low confidence. So we unwrap pointer levels and require
    the base to be a Structure.
    """
    from ghidra.program.model.data import Pointer, Structure
    ps = callee.getParameters()
    if not ps:
        return None
    dt = ps[0].getDataType()
    while isinstance(dt, Pointer):
        dt = dt.getDataType()
    if not isinstance(dt, Structure):
        return None
    return dt.getName()


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
    from ghidra.program.model.symbol import SymbolType
    cp = currentProgram  # noqa: F821
    fm = cp.getFunctionManager()
    mem = cp.getMemory()
    addr_space = cp.getAddressFactory().getDefaultAddressSpace()
    listing = cp.getListing()
    gns = cp.getGlobalNamespace()

    out_csv = _env('CSV') or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'refs',
        'globals_queue_%s.csv' % cp.getName().replace('.', '_'))

    # only globals in non-executable (data) memory are singleton candidates
    def _in_data(addr):
        blk = mem.getBlock(addr)
        return blk is not None and not blk.isExecute()

    def _is_untyped_data(addr):
        # a fillable global: raw-undefined (no data item) or an undefined* placeholder,
        # in data memory. A concrete-typed datum (string, typed pointer) is not a target.
        if not _in_data(addr):
            return False
        d = listing.getDefinedDataAt(addr)
        return d is None or d.getDataType().getName().startswith('undefined')

    def _is_class_method(f):
        p = f.getParentNamespace()
        return (p is not gns and p.getSymbol() is not None
                and p.getSymbol().getSymbolType() == SymbolType.CLASS)

    def _data_scoped_funcs():
        # globals-first: rank untyped globals by in-degree (distinct referrers), keep
        # the high-in-degree singleton candidates, and sample a few referrers of each
        # to decompile. Returns (functions_to_decompile, candidate_global_offsets).
        rm = cp.getReferenceManager()
        refs_by_g = {}                       # gaddr offset -> set(function)
        scanned = 0
        it = rm.getReferenceIterator(mem.getMinAddress())
        while it.hasNext():
            ref = it.next()
            scanned += 1
            rt = ref.getReferenceType()
            if not rt.isData() or ref.isStackReference() or ref.isRegisterReference():
                continue
            to = ref.getToAddress()
            if not _is_untyped_data(to):
                continue
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is not None:
                refs_by_g.setdefault(to.getOffset(), set()).add(f)
        cand_globals = set(g for g, s in refs_by_g.items() if len(s) >= MIN_INDEG)
        sampled = set()
        for g in cand_globals:
            for f in list(refs_by_g[g])[:SAMPLES]:
                sampled.add(f)
        print('  data-scope: %d refs scanned, %d untyped globals, %d with in-degree>=%d, '
              'sampling<=%d referrers -> %d funcs to decompile'
              % (scanned, len(refs_by_g), len(cand_globals), MIN_INDEG, SAMPLES, len(sampled)))
        return list(sampled), cand_globals

    cand_globals = None                      # data-scope filters observations to these
    if SCOPE == 'all':
        funcs = list(fm.getFunctions(True))
    elif SCOPE == 'class':
        funcs = [f for f in fm.getFunctions(True) if _is_class_method(f)]
    else:                                    # 'data' (default)
        funcs, cand_globals = _data_scoped_funcs()

    decomp = DecompInterface()
    decomp.openProgram(cp)
    observations = []
    ptr_votes = {}                       # addr -> [is_ptr bools]; majority -> CSV column
    n = done = 0
    print('Globals harvest (%s): scope=%s, scanning %d functions for global-as-this ...'
          % (cp.getName(), SCOPE, len(funcs)))
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
                cls = _param0_class_name(callee)
                if not cls:
                    continue
                gaddr, is_ptr = _ram_addr(op.getInput(1), mem, addr_space)
                if gaddr is None or not _in_data(gaddr):
                    continue
                # in data-scope, only the high-in-degree singleton candidates count
                if cand_globals is not None and gaddr.getOffset() not in cand_globals:
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
    out_dir = os.path.dirname(out_csv)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(out_csv, 'w', newline='') as fh:
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
    print('  -> ' + out_csv)
    print('  (read-only: review/fill decision_type, then apply to type the global)')


run()
