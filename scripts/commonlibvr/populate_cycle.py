"""In-Ghidra population cycle orchestrator (the convergence driver).

Closes the loop WITHOUT leaving Ghidra. Each cycle runs three enrich stages in
order and the output of each is an anchor for the next:

  1. thiscall  (seed_this.py)        -- widen the typed-`this` surface
  2. propagate (propagate.py)        -- commit concrete param/return types the
                                        decompiler infers from those anchors
  3. discover+apply (commonlib_discover.py, CLVR_DISCOVER_APPLY=go)
                                     -- infer struct-field types via dataflow and
                                        WRITE the high-confidence ones into the
                                        /types.h structs

A field typed in cycle N is a new anchor the decompiler propagates from in cycle
N+1, so coverage compounds. Between cycles we snapshot four coverage metrics and
stop when a pass yields fewer than MIN_GAIN net improvements -- the practical
fixpoint. Export back to CommonLib is deliberately OUT OF SCOPE here: this drives
the live Ghidra program to a stable, maximally-populated state first.

Coverage metrics (populate_plan): thiscall members, concrete-named /types.h fields
(up), still-unknown /types.h fields (down), concrete-typed function params (up).

Modes:
  dry (default)  -- measure current coverage once and print the snapshot; no work.
  CLVR_CYCLE=go  -- run the apply loop to convergence.

Each sub-stage stays non-destructive (ANALYSIS source, protect IMPORTED/
USER_DEFINED, one always-committed transaction -- never commit=False). Knobs:
CLVR_CYCLE_MAX (cycles, default 5), CLVR_CYCLE_MIN_GAIN (default 5), plus every
sub-stage's own env (CLVR_PROP_SEED, CLVR_DISCOVER_PER_CLASS, ...) passes through.
"""
import csv
import os

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
APPLY = os.environ.get('CLVR_CYCLE', 'dry').lower() == 'go'
MAX_CYCLES = int(os.environ.get('CLVR_CYCLE_MAX', '5') or 5)
MIN_GAIN = int(os.environ.get('CLVR_CYCLE_MIN_GAIN', '5') or 5)
COVERAGE_CSV = os.environ.get('CLVR_CYCLE_CSV', IMPORT_PATH + '.coverage.csv')

import importlib.util as _ilu  # noqa: E402
_pspec = _ilu.spec_from_file_location('clvr_populate_plan', os.path.join(SCRIPT_DIR, 'populate_plan.py'))
pl = _ilu.module_from_spec(_pspec)
_pspec.loader.exec_module(pl)


def _concrete(typename):
    """True if a type names real RE (struct/class/enum), not a size-only generic."""
    t = (typename or '').replace(' ', '')
    while t.endswith('*') or t.endswith('64'):
        t = t[:-2] if t.endswith('64') else t[:-1]
    if not t:
        return False
    low = t.lower()
    if low.startswith('undefined'):
        return False
    return not pl.is_generic_type(low)


def measure_coverage(cp):
    """Snapshot the four coverage metrics from the live program (no decompile --
    cheap; safe to call any time, including dry-run)."""
    from ghidra.program.model.symbol import SymbolType
    fm = cp.getFunctionManager()
    gns = cp.getGlobalNamespace()
    dtm = cp.getDataTypeManager()
    thiscall = typed_params = 0
    for f in fm.getFunctions(True):
        p = f.getParentNamespace()
        is_cls = (p is not gns and p.getSymbol() is not None
                  and p.getSymbol().getSymbolType() == SymbolType.CLASS)
        if is_cls and f.getCallingConventionName() == '__thiscall':
            thiscall += 1
        for prm in f.getParameters():
            if _concrete(prm.getDataType().getName()):
                typed_params += 1
    named_fields = unk_fields = 0
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() != 'StructureDB':
            continue
        if 'types.h' not in str(dt.getCategoryPath()):
            continue
        for i in range(dt.getNumComponents()):
            c = dt.getComponent(i)
            if c.getLength() < 8:
                continue
            fn = c.getFieldName() or ''
            tn = c.getDataType().getName()
            if fn.startswith(('unk', 'pad')) or 'undefined' in tn:
                unk_fields += 1
            elif _concrete(tn):
                named_fields += 1
    return {'thiscall': thiscall, 'named_fields': named_fields,
            'unk_fields': unk_fields, 'typed_params': typed_params}


def _run_stage(name, env, cp, monitor):
    """exec a sub-stage script with its apply env set, sharing this program."""
    for k, v in env.items():
        os.environ[k] = v
    path = os.path.join(SCRIPT_DIR, name)
    g = dict(globals())
    g['__name__'] = '__main__'
    g['currentProgram'] = cp
    g['monitor'] = monitor
    with open(path) as fh:
        code = fh.read()
    print('\n----- stage: %s -----' % name)
    exec(compile(code, path, 'exec'), g)


def run():
    cp = currentProgram  # noqa: F821
    mon = monitor        # noqa: F821

    snapshots = []
    base = measure_coverage(cp)
    snapshots.append((0, base, None))
    print('=== population cycle (%s) ===' % cp.getName())
    print('  cycle 0 (baseline): %s' % base)

    if not APPLY:
        print('\nDRY: coverage snapshot only. Set CLVR_CYCLE=go to run the apply '
              'loop (thiscall -> propagate -> discover+apply) to convergence.')
    else:
        prev = base
        for cyc in range(1, MAX_CYCLES + 1):
            print('\n########## CYCLE %d/%d ##########' % (cyc, MAX_CYCLES))
            _run_stage('seed_this.py', {'CLVR_SEED': 'go'}, cp, mon)
            _run_stage('propagate.py', {'CLVR_PROP': 'go'}, cp, mon)
            _run_stage('commonlib_discover.py', {'CLVR_DISCOVER_APPLY': 'go'}, cp, mon)
            cur = measure_coverage(cp)
            delta = pl.coverage_delta(prev, cur)
            prog = pl.progress(delta)
            snapshots.append((cyc, cur, delta))
            print('\n  cycle %d coverage: %s' % (cyc, cur))
            print('  cycle %d delta:    %s  (progress=%d)' % (cyc, delta, prog))
            prev = cur
            if pl.is_regression(delta):
                print('  >>> REGRESSION (progress %d < 0): a stage made the program '
                      'WORSE by the metrics. Stopping for inspection -- NOT a fixpoint.'
                      % prog)
                break
            if pl.is_converged(delta, MIN_GAIN):
                print('  >>> CONVERGED (0 <= progress %d < min_gain %d) after %d cycles'
                      % (prog, MIN_GAIN, cyc))
                break
        else:
            print('  >>> reached MAX_CYCLES=%d without full convergence' % MAX_CYCLES)

    try:
        with open(COVERAGE_CSV, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['cycle', 'thiscall', 'named_fields', 'unk_fields',
                        'typed_params', 'd_thiscall', 'd_named_fields',
                        'd_unk_fields', 'd_typed_params', 'progress'])
            for cyc, snap, delta in snapshots:
                d = delta or {}
                w.writerow([cyc, snap['thiscall'], snap['named_fields'],
                            snap['unk_fields'], snap['typed_params'],
                            d.get('thiscall', ''), d.get('named_fields', ''),
                            d.get('unk_fields', ''), d.get('typed_params', ''),
                            pl.progress(d) if delta else ''])
        print('\n  coverage trace -> %s' % COVERAGE_CSV)
    except Exception as e:
        print('  (coverage CSV write failed: %s)' % e)


run()
