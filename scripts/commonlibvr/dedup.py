"""Duplicate-type deduper -- merge duplicates into the canonical type so references
(signatures, struct fields) point at the populated CommonLib type.

A program with its MS PDB loaded carries duplicate STRUCT types per name: Ghidra's
auto-conflict copies (`X.conflict`) and the `/SkyrimSE.pdb/X` vs `/types.h/X` twins.
References to a duplicate miss the RE on the canonical type (132 of ~2.5k AE typed
signatures pointed at `/SkyrimSE.pdb/*` twins; PDB struct fields point at `*.conflict`).
`dtm.replaceDataType(dup, keeper)` merges a duplicate away AND rewires every reference
to the keeper -- so they finally resolve to the canonical populated type.

Four SAFE passes (only unambiguous same-size merges; size-conflicts are flagged, never
auto-merged -- the in-memory `Memory::Allocate` size is ground truth, not CommonLib or
the PDB blindly):
  -1. Any type shadowing a real Ghidra builtin primitive (e.g. a PDB-imported `bool`
      typedef alongside the true BooleanDataType) -> the builtin. See
      purge_builtin_shadows for why this runs first.
  A. `X.conflict*` -> `X` in the SAME category (Ghidra's conflict copy IS a dup of the
     same-category, same-name type). Same size only.
  B. `/SkyrimSE.pdb/X` -> the UNIQUE same-size `/types.h/X` (skip if 0 or >1 /types.h
     candidates -- ambiguous leaf like nested RUNTIME_DATA/Data/Entry).
  C. Named aliases (KNOWN_ALIASES below, or CLVR_DEDUP_ALIASES env override): two
     ENTIRELY DIFFERENT names for the same class that passes A/B can never find, since
     both key on same-name matching (a `.conflict` suffix, or a shared leaf across
     categories). A stale hand-named struct from an earlier RE pass sitting alongside
     the real CommonLib-matching name is invisible to that logic -- it takes a person
     (or a fact recorded here from a prior manual fix) to say "these are the same
     type." Confirmed case: SkyrimVR.exe carried a stale, PDB-derived `MenuManager`
     struct (456B, missing VR's 8-byte tail) that 7 functions -- including the exact
     function in a real recurring crash chain -- were still typed against, instead of
     the correct, already-CommonLib-matching `UI` struct (464B on VR). Same size-gate
     as passes A/B: a size disagreement refuses, never auto-merges.

     Set CLVR_DEDUP_ALIAS_ONLY=1 to run ONLY this pass (skip the builtin-shadow purge,
     .conflict purge, and full struct sweep of A/B) -- for spot-fixing one just-found
     alias pair quickly, without paying for a full-database dedup run.

NON-DESTRUCTIVE intent: only merges types proven duplicate (same size); never changes a
layout. Dry-run by default (counts + a <import>.dedup_conflicts.csv of size-disagreeing
groups for binary review); CLVR_DEDUP=go to apply. replaceDataType is SLOW (~2-3s each,
rescans all functions) -- applied in batched transactions. Run programs SEQUENTIALLY.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH, SCRIPT_DIR  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))
from engine.tx import transaction  # noqa: E402
APPLY = os.environ.get('CLVR_DEDUP', 'dry').lower() == 'go'
BATCH = int(os.environ.get('CLVR_DEDUP_BATCH', '40') or 40)
CONFLICT_CSV = IMPORT_PATH + '.dedup_conflicts.csv'
ALIAS_ONLY = os.environ.get('CLVR_DEDUP_ALIAS_ONLY', '').lower() in ('1', 'true', 'go')

# Curated record of stale-name -> canonical-name pairs found by manual RE, one class at
# a time (see Pass C in the module docstring for why these can't be found
# algorithmically). Add an entry here whenever a same-class differently-named
# duplicate turns up again after a fresh PDB/CommonLib re-import, so the fix is
# reproducible instead of a one-off Ghidra API call. CLVR_DEDUP_ALIASES can add more
# pairs at invocation time without editing this file, e.g. for a first-time spot-fix
# before promoting it here: "Old1=New1,Old2=New2".
KNOWN_ALIASES = {
    'MenuManager': 'UI',
}


def _load_aliases():
    aliases = dict(KNOWN_ALIASES)
    extra = os.environ.get('CLVR_DEDUP_ALIASES', '')
    for pair in extra.split(','):
        pair = pair.strip()
        if not pair:
            continue
        old, _, canon = pair.partition('=')
        if old and canon:
            aliases[old.strip()] = canon.strip()
    return aliases

import importlib.util as _ilu  # noqa: E402
_dspec = _ilu.spec_from_file_location('clvr_dedup_plan', os.path.join(SCRIPT_DIR, 'dedup_plan.py'))
dp = _ilu.module_from_spec(_dspec)
_dspec.loader.exec_module(dp)


def _canon_of(dtm, dt, depth=0):
    """Resolve the canonical (non-.conflict) twin of any datatype kind, rebuilding
    pointer / array wrappers around the canonical element. Returns None if no twin."""
    import ghidra.program.model.data as D
    if dt is None or depth > 12:
        return None
    if isinstance(dt, D.Pointer):
        b = _canon_of(dtm, dt.getDataType(), depth + 1)
        return dtm.getPointer(b) if b is not None else None
    if isinstance(dt, D.Array):
        b = _canon_of(dtm, dt.getDataType(), depth + 1)
        return D.ArrayDataType(b, dt.getNumElements(), b.getLength()) if b is not None else None
    p = dt.getPathName()
    i = p.find('.conflict')
    if i < 0:
        return dt
    return dtm.getDataType(p[:i] + p[i + len('.conflict'):].lstrip('0123456789'))


def _all_conflicts(dtm):
    out = []
    it = dtm.getAllDataTypes()
    while it.hasNext():
        d = it.next()
        if '.conflict' in d.getName():
            out.append(d)
    return out


def purge_builtin_shadows(cp, dtm, apply, mon):
    """Merge any non-builtin type that shadows a real Ghidra builtin primitive (same
    name -- e.g. a PDB-imported `bool` typedef sitting alongside the true
    BooleanDataType) into the builtin.

    Ghidra's PDB analyzer routinely mints its own per-module primitive typedefs
    instead of reusing the DataTypeManager's builtins. Nothing else in this pipeline
    merges them away, so they sit as an inert duplicate until someone (a person doing
    manual type cleanup) deletes the "wrong" one by hand -- which orphans every struct
    field and signature that referenced it into `-BAD-` instead of rewiring them first.
    Confirmed: exactly this happened for `bool` (3535 orphaned fields across SE+AE
    after a manual delete). Running this pass BEFORE anyone touches a shadowed
    primitive makes that failure mode structurally impossible: the real builtin
    always wins as keeper, and every reference is safely rewired via replaceDataType
    before the shadow is gone. Not limited to bool -- any BuiltIn-shadowing name."""
    import ghidra.program.model.data as D

    by_name = {}
    it = dtm.getAllDataTypes()
    while it.hasNext():
        d = it.next()
        by_name.setdefault(d.getName(), []).append(d)

    merges = []       # (shadow_dt, builtin_dt)
    conflicts = []
    for name, dts in by_name.items():
        if len(dts) < 2:
            continue
        # Dynamic/Factory builtins (e.g. StringDataType, a variable-length "string")
        # can't be a replaceDataType target -- skip, there's no fixed-size instance to
        # rewire references onto.
        builtins = [d for d in dts if isinstance(d, D.BuiltIn)
                    and not isinstance(d, (D.Dynamic, D.FactoryDataType))]
        if not builtins:
            continue
        keeper = builtins[0]
        shadows = [d for d in dts if d is not keeper and not isinstance(d, D.BuiltIn)]
        if not shadows:
            continue
        sizes = set(d.getLength() for d in shadows + [keeper] if d.getLength() > 0)
        if len(sizes) > 1:
            conflicts.append((name, [(d.getLength(), str(d.getCategoryPath())) for d in dts]))
            continue
        for s in shadows:
            merges.append((s, keeper))

    print('purge_builtin_shadows (%s): %d shadow merges queued, %d size-conflicts'
          % (cp.getName(), len(merges), len(conflicts)))
    for m, k in merges[:15]:
        print('   merge %s -> %s' % (m.getPathName(), k.getPathName()))

    if not apply:
        print('  DRY-RUN: set CLVR_DEDUP=go to apply.')
        return (len(merges), 0, len(conflicts))

    done = err = 0
    with transaction(cp, 'dedup: purge builtin shadows'):
        for m, k in merges:
            try:
                dtm.replaceDataType(m, k, True)
                done += 1
            except Exception:
                err += 1
    print('purge_builtin_shadows APPLIED (%s): merged=%d errors=%d' % (cp.getName(), done, err))
    return (len(merges), done, err)


def purge_conflicts(cp, dtm, apply, mon):
    """Collapse every ``X.conflict`` onto its canonical twin ``X`` so exactly one
    canonical type survives.

    Ghidra's default conflict handler mints ``X.conflict`` copies whenever a type /
    vtable struct / function-definition is re-added with a differing definition (PDB
    import, repeated signature application, re-runs of the importer). These form a
    self-contained, often cyclic cluster (class struct -> __vftable.conflict * ->
    *_VFTable.conflict -> _func_*.conflict) that the struct-only Pass A never fully
    clears. Strategy: rewire any .conflict referenced by a REAL (non-.conflict) type
    or a function signature onto its canonical via replaceDataType; then delete the
    rest (the cluster has no external references, so cycles don't matter and the
    cheap remove() -- no function rescan -- suffices). A .conflict that still has a
    non-.conflict referrer after the rewire pass (rewire failed) is never deleted."""
    import ghidra.program.model.data as D
    confs = _all_conflicts(dtm)
    if not confs:
        print('purge_conflicts (%s): no .conflict types' % cp.getName())
        return (0, 0, 0)

    # function signatures reference datatypes outside the datatype-parent graph, so
    # collect the .conflict types used by any function prototype up front.
    sig_refs = set()
    fi = cp.getFunctionManager().getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        try:
            used = [f.getReturnType()] + [p.getDataType() for p in f.getParameters()]
        except Exception:
            continue
        for t in used:
            bt = t
            while isinstance(bt, (D.Pointer, D.Array)):
                bt = bt.getDataType()
            if bt is not None and '.conflict' in bt.getName():
                sig_refs.add(t.getPathName())

    def _ext(d):
        return any('.conflict' not in p.getName() for p in d.getParents()) or \
            d.getPathName() in sig_refs

    print('purge_conflicts (%s): %d .conflict types (%d externally / signature referenced)'
          % (cp.getName(), len(confs), sum(1 for d in confs if _ext(d))))
    if not apply:
        print('  DRY-RUN: set CLVR_DEDUP=go to apply.')
        return (len(confs), 0, 0)

    rewired = removed = skipped = 0
    with transaction(cp, 'dedup: purge .conflict'):
        for d in _all_conflicts(dtm):
            if not _ext(d):
                continue
            c = _canon_of(dtm, d)
            if c is not None and c is not d:
                try:
                    dtm.replaceDataType(d, c, True)
                    rewired += 1
                except Exception:
                    skipped += 1
        for d in _all_conflicts(dtm):
            # never delete one that still has a real referrer (its rewire failed)
            if any('.conflict' not in p.getName() for p in d.getParents()):
                skipped += 1
                continue
            try:
                dtm.remove(d, mon)
                removed += 1
            except Exception:
                skipped += 1
    print('purge_conflicts APPLIED (%s): rewired=%d removed=%d skipped=%d remaining=%d'
          % (cp.getName(), rewired, removed, skipped, len(_all_conflicts(dtm))))
    return (rewired, removed, skipped)


def merge_named_aliases(cp, dtm, apply, mon, aliases):
    """Pass C: merge each explicit (stale_name -> canonical_name) pair in `aliases`.
    Looks both up by exact name anywhere in the data type manager (any category) --
    unlike passes A/B there's no algorithmic same-name grouping here, the pairing IS
    the input. Same safety gate as the other passes: refuse on a size disagreement."""
    from java.util import ArrayList

    def _find_one(name):
        dts = ArrayList()
        dtm.findDataTypes(name, dts)
        # prefer an exact-name, non-pointer/array composite if multiple paths share
        # the leaf name (e.g. a nested category); first hit is fine for a curated,
        # human-verified alias pair.
        for d in dts:
            if d.getName() == name:
                return d
        return None

    planned = []   # (old_dt, canon_dt)
    conflicts = []
    missing = []
    for old_name, canon_name in aliases.items():
        old_dt = _find_one(old_name)
        canon_dt = _find_one(canon_name)
        if old_dt is None or canon_dt is None or old_dt is canon_dt:
            if old_dt is not None and canon_dt is None:
                missing.append((old_name, canon_name))
            continue
        should, reason = dp.plan_alias_merge(old_name, canon_name, old_dt.getLength(), canon_dt.getLength())
        if should:
            planned.append((old_dt, canon_dt))
        else:
            conflicts.append((old_name, canon_name, old_dt.getLength(), canon_dt.getLength(), reason))

    print('merge_named_aliases (%s): %d pairs queued, %d size-conflicts, %d canonical-missing'
          % (cp.getName(), len(planned), len(conflicts), len(missing)))
    for old_dt, canon_dt in planned:
        print('   merge %s -> %s' % (old_dt.getPathName(), canon_dt.getPathName()))
    for old_name, canon_name, os_, cs, reason in conflicts:
        print('   SKIP %s (0x%X) -> %s (0x%X): %s' % (old_name, os_, canon_name, cs, reason))
    for old_name, canon_name in missing:
        print('   SKIP %s -> %s: canonical name not found in this program' % (old_name, canon_name))

    if not apply:
        print('  DRY-RUN: set CLVR_DEDUP=go to apply.')
        return (len(planned), 0, len(conflicts))

    done = err = 0
    with transaction(cp, 'dedup: merge named aliases'):
        for old_dt, canon_dt in planned:
            try:
                dtm.replaceDataType(old_dt, canon_dt, True)
                done += 1
            except Exception:
                err += 1
    print('merge_named_aliases APPLIED (%s): merged=%d errors=%d' % (cp.getName(), done, err))
    return (len(planned), done, err)


def run():
    from ghidra.program.model.data import Structure
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()

    if ALIAS_ONLY:
        # Fast spot-fix path: just the named-alias pass, skip the full-database sweep.
        merge_named_aliases(cp, dtm, APPLY, monitor, _load_aliases())  # noqa: F821
        return

    # Pass -1: merge any shadow of a real Ghidra builtin primitive (bool, char, ...)
    # into the builtin, so it can never be orphaned by a later manual delete.
    purge_builtin_shadows(cp, dtm, APPLY, monitor)  # noqa: F821

    # Pass 0: collapse every .conflict copy onto its canonical twin (all datatype
    # kinds, incl. the cyclic vtable/funcdef plumbing the struct passes miss).
    purge_conflicts(cp, dtm, APPLY, monitor)  # noqa: F821

    # Pass C: named aliases -- two different names for the same class, found by a
    # person (or recorded from a prior manual fix), not by same-name matching.
    merge_named_aliases(cp, dtm, APPLY, monitor, _load_aliases())  # noqa: F821

    structs = [d for d in dtm.getAllDataTypes() if isinstance(d, Structure)]

    # Pass A: .conflict copies -> same-category base, grouped by (category, base leaf)
    by_qual = {}
    for d in structs:
        key = (str(d.getCategoryPath()), dp.base_name(d.getName()))
        by_qual.setdefault(key, []).append(d)

    merges = []        # (dup_dt, keeper_dt)
    conflicts = []     # (name, [(size, category), ...])
    for (_cat, _bn), dts in by_qual.items():
        if len(dts) < 2:
            continue
        variants = [{'key': i, 'name': d.getName(), 'category': str(d.getCategoryPath()),
                     'size': d.getLength(), 'ndefined': d.getNumDefinedComponents()}
                    for i, d in enumerate(dts)]
        keeper_key, merge_keys, conflict, _reason = dp.plan_merge(variants)
        if conflict:
            conflicts.append((dts[0].getName(), [(d.getLength(), str(d.getCategoryPath())) for d in dts]))
            continue
        for mk in merge_keys:
            merges.append((dts[mk], dts[keeper_key]))

    # Pass B: /SkyrimSE.pdb/X -> the UNIQUE same-size /types.h/X (by leaf name)
    typesh_by_leaf = {}
    for d in structs:
        if 'types.h' in str(d.getCategoryPath()):
            typesh_by_leaf.setdefault(d.getName(), []).append(d)
    pdb_twin = pdb_ambig = 0
    for d in structs:
        if 'SkyrimSE.pdb' not in str(d.getCategoryPath()):
            continue
        cand = typesh_by_leaf.get(d.getName(), [])
        if len(cand) == 1 and cand[0].getLength() == d.getLength() and cand[0] is not d:
            merges.append((d, cand[0]))
            pdb_twin += 1
        elif cand:
            pdb_ambig += 1

    # de-dup the merge list (a dt could be both a .conflict AND a pdb twin target)
    seen = set()
    uniq = []
    for m, k in merges:
        mp = m.getPathName()
        if mp in seen or m is k:
            continue
        seen.add(mp)
        uniq.append((m, k))

    print('dedup (%s): %d duplicate merges queued (pass A .conflict + pass B pdb-twin=%d, '
          'pdb-ambiguous-skipped=%d), %d size-conflict groups flagged'
          % (cp.getName(), len(uniq), pdb_twin, pdb_ambig, len(conflicts)))
    for m, k in uniq[:15]:
        print('   merge %s -> %s' % (m.getPathName(), k.getPathName()))

    try:
        with open(CONFLICT_CSV, 'w', newline='') as fh:
            w = csv.writer(fh)
            w.writerow(['name', 'variant_sizes_and_categories'])
            for nm, info in conflicts:
                w.writerow([nm, ' | '.join('0x%X@%s' % (s, c) for s, c in info)])
    except Exception as e:
        print('  (conflict CSV write failed: %s)' % e)

    if not APPLY:
        print('  DRY-RUN: no merges applied. Set CLVR_DEDUP=go to apply.')
        print('  size-conflicts (binary-verify) -> %s' % CONFLICT_CSV)
        return

    done = err = 0
    for i in range(0, len(uniq), BATCH):
        batch = uniq[i:i + BATCH]
        with transaction(cp, 'dedup batch %d' % (i // BATCH)):
            for m, k in batch:
                try:
                    dtm.replaceDataType(m, k, False)
                    done += 1
                except Exception:
                    err += 1
        if (i // BATCH) % 5 == 0:
            monitor.setMessage('dedup %d/%d merged' % (done, len(uniq)))  # noqa: F821
            print('  ... %d/%d merged' % (done, len(uniq)))
    print('dedup APPLIED: %d merged, %d errors. size-conflicts -> %s' % (done, err, CONFLICT_CSV))


# Auto-run when exec'd directly in Ghidra. Importers (e.g. apply_enrich) pre-seed
# AUTORUN=False to reuse purge_conflicts() without running the full dedup.
if globals().get('AUTORUN', True):
    run()
