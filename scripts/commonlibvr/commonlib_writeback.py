"""Ghidra -> CommonLib write-back detector (read-only report).

Closes the loop: the pipeline imports CommonLib into Ghidra; this reports what
the live Ghidra program knows that CommonLib does not, so it can flow back to the
canonical source. For each CommonLib function symbol it compares the live Ghidra
function's name against CommonLib's at that address and classifies the delta:

  NAME_DELTA        Ghidra has a trusted (USER_DEFINED/IMPORTED) name whose leaf
                    differs from CommonLib's -> write-back candidate (PDB/manual
                    RE knows a different name; review which is right vs binary).
  MISSING_IN_GHIDRA CommonLib named it but the Ghidra function is still generic
                    or only analyzer-named -> a gap in our own apply (QA signal).

Writes <import>.writeback.csv with the cross-version ids so each row is locatable
in CommonLib. Read-only: never mutates the program. Run inside Ghidra against the
target program; the runtime is taken from the program name (s/a/v offset key).

Signature deltas are intentionally out of v1 (cross-representation signature
normalization is a separate step); commonlib_delta.classify_delta already has the
SIG_DELTA path, tested, for when that lands.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR, EXTRA_AE_VARIANTS  # noqa: E402
OUT_CSV = os.environ.get('CLVR_WRITEBACK_CSV', IMPORT_PATH + '.writeback.csv')

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location(
    'clvr_commonlib_delta', os.path.join(SCRIPT_DIR, 'commonlib_delta.py'))
cd = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(cd)


def _load_symbols():
    """Extract SYMBOLS from a generated CommonLibImport_CLVR_*.py.

    The generator emits either a bare JSON literal (``SYMBOLS = [...]``) or,
    for large files, ``SYMBOLS = _json_sym.loads('...')`` (a call, not a
    literal -- see ghidra_import_gen.py) after its own ``import json as
    _json_sym`` line. A plain ``json.loads()`` on the line's tail only
    handles the first form; exec the real source up through the SYMBOLS
    line (in a throwaway namespace) so both forms resolve correctly.
    """
    with open(IMPORT_PATH) as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        if line.startswith('SYMBOLS = '):
            # Some module-level lines (e.g. `dtm = currentProgram.getDataTypeManager()`)
            # run eagerly, so this needs the same Ghidra globals _load_generated_ns()
            # injects -- pull them from this module's own globals (the caller running
            # commonlib_writeback.py's source is expected to have set them there).
            ns = dict(globals())
            exec(compile(''.join(lines[:i + 1]), IMPORT_PATH, 'exec'), ns)
            return ns['SYMBOLS']
    raise RuntimeError('SYMBOLS not found in ' + IMPORT_PATH)


_VKEYS = ('s', 'a', 'v') + tuple(variant['sym_key'] for variant in EXTRA_AE_VARIANTS)


def _detect_vkey(cp, fm, base, symbols):
    """Which offset key (s/a/v/<variant sym_key>...) matches the currently open
    program.

    The program's display name is not a reliable signal on its own -- a
    renamed/typo'd import (e.g. an AE 1.7.99 dump saved as "...1.7.79.exe")
    can defeat any substring check. Sample up to 200 known offsets per key
    and see which one resolves to real functions in THIS program most
    often; the name only breaks ties when two keys are close.
    """
    nm = cp.getName().lower()
    name_hint = 'v' if 'vr' in nm else next(
        (variant['sym_key'] for variant in EXTRA_AE_VARIANTS
         if any(m.lower() in nm for m in variant['vt_match'])),
        'a' if ('1170' in nm or 'ae' in nm) else 's')

    samples = {k: [] for k in _VKEYS}
    for s in symbols:
        if s.get('t') != 'func':
            continue
        for k in _VKEYS:
            off = s.get(k)
            if off and len(samples[k]) < 200:
                samples[k].append(off)
        if all(len(v) >= 200 for v in samples.values()):
            break

    hits = {}
    for k, offs in samples.items():
        n = sum(1 for off in offs if fm.getFunctionAt(base.add(int(off))) is not None)
        hits[k] = n / len(offs) if offs else 0.0

    best = max(hits, key=hits.get)
    # A clear winner (or nothing sampled) -- trust the data. A near-tie
    # (within 10%) falls back to the name hint, which is cheap and usually
    # right when the data itself is ambiguous (e.g. a mostly-unanalyzed
    # program with few resolvable functions yet).
    runner_up = max((v for k, v in hits.items() if k != best), default=0.0)
    if hits[best] - runner_up < 0.1:
        return name_hint
    return best


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    fm = cp.getFunctionManager()
    base = cp.getImageBase()
    trusted = (SourceType.USER_DEFINED, SourceType.IMPORTED)

    symbols = _load_symbols()
    vkey = _detect_vkey(cp, fm, base, symbols)
    rows = []
    counts = {}
    for s in symbols:
        if s.get('t') != 'func':
            continue
        off = s.get(vkey)
        if not off:
            continue
        f = fm.getFunctionAt(base.add(int(off)))
        if f is None:
            continue
        gname = f.getName()
        src = f.getSignatureSource()
        g_generic = cd.is_generic(gname) or src not in trusted
        kind = cd.classify_delta(s['n'], gname, g_generic, '', '', None)
        counts[kind] = counts.get(kind, 0) + 1
        if kind in ('NAME_DELTA', 'MISSING_IN_GHIDRA'):
            rows.append((kind, s['n'], gname,
                         '0x%X' % f.getEntryPoint().getOffset(),
                         s.get('si') or '', s.get('ai') or ''))

    rows.sort()
    with open(OUT_CSV, 'w') as fh:
        w = csv.writer(fh)
        w.writerow(['kind', 'commonlib_name', 'ghidra_name', 'address', 'se_id', 'ae_id'])
        for r in rows:
            w.writerow(r)
    print('Write-back deltas (%s): %s' % (cp.getName(), counts))
    print('  NAME_DELTA + MISSING_IN_GHIDRA logged: %d -> %s' % (len(rows), OUT_CSV))


if __name__ == '__main__':
    # Guards against a plain `import commonlib_writeback` (e.g. for testing
    # _detect_vkey) triggering a live Ghidra run -- see apply_enrich.py's
    # identical guard/comment for the incident this mirrors.
    run()
