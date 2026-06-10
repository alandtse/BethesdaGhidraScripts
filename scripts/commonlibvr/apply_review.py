"""Apply LLM/human review decisions to /types.h struct fields (authoritative).

Consumes the review queue commonlib_discover emits (`<import>.review_queue.csv`)
once a reviewer has filled the `decision_type` column with a concrete Ghidra type
(or left it blank / `skip`). For each decision it fills the unknown struct slot with
that type -- the same non-destructive guards as the automated apply (slot must still
be unknown, the type's size must match the slot), but with NO confidence/generic
filter, because the human IS the authority. The field is renamed off its `unk*`
prefix and commented `clvr-review`. Each resolved field becomes a new anchor, so a
following population cycle discovers more from it -- review breaks the plateau.

This closes the human-in-the-loop half of the "scripts vs LLM" division: scripts do
the rule-expressible apply and emit the queue; the LLM/human resolves the judgement
tail; this writes those calls back. Decisions outrank the cycle's ANALYSIS seeds.

NON-DESTRUCTIVE: one always-committed transaction (never commit=False -- the MCP
nests it), only fills unknown slots, never clobbers existing RE, never resizes.
Dry-run by default (lists what it WOULD apply + any unresolved type names);
CLVR_REVIEW_APPLY=go to write. Knobs: CLVR_DISCOVER_REVIEW_CSV (input path).
"""
import csv
import os

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
REVIEW_CSV = os.environ.get('CLVR_DISCOVER_REVIEW_CSV', IMPORT_PATH + '.review_queue.csv')
APPLY = os.environ.get('CLVR_REVIEW_APPLY', 'dry').lower() == 'go'

import importlib.util as _ilu  # noqa: E402
_rspec = _ilu.spec_from_file_location('clvr_review_plan', os.path.join(SCRIPT_DIR, 'review_plan.py'))
rp = _ilu.module_from_spec(_rspec)
_rspec.loader.exec_module(rp)


def _resolve_type(dtm, by_name, name):
    """Resolve a reviewer's type string (e.g. `Actor *`, `NavMeshInfoMap *64`,
    `BSTArray<RE::TESForm *>`) to a live DataType. Strips Ghidra pointer/width
    decoration to a base name, looks it up (preferring /types.h), and re-applies the
    pointer depth. Returns None if the base name is not found (reported for fixup)."""
    t = name.strip()
    ptr = 0
    while True:
        t = t.strip()
        if t.endswith('64') and t[:-2].rstrip().endswith('*'):
            t = t[:-2]
        elif t.endswith('*'):
            t = t[:-1]
            ptr += 1
        else:
            break
    base = by_name.get(t.strip())
    if base is None:
        return None
    dt = base
    for _ in range(ptr):
        dt = dtm.getPointer(dt, 8)
    return dt


def _struct_metrics(s):
    """(length, protected_bytes): bytes carrying RE we must not lose (non-unk*/pad*
    name AND non-undefined type). Improve-or-nop invariant: length unchanged AND
    protected_bytes not decreased after an apply."""
    pb = 0
    for i in range(s.getNumComponents()):
        c = s.getComponent(i)
        fn = c.getFieldName() or ''
        tn = c.getDataType().getName()
        if not fn.startswith(('unk', 'pad')) and 'undefined' not in tn:
            pb += c.getLength()
    return s.getLength(), pb


def run():
    from ghidra.program.model.data import CategoryPath
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()

    if not os.path.exists(REVIEW_CSV):
        print('No review queue at %s -- run commonlib_discover first.' % REVIEW_CSV)
        return

    # name -> DataType, /types.h preferred (so a reviewer's `Actor` resolves to our
    # struct, not a same-named library type).
    by_name = {}
    for dt in dtm.getAllDataTypes():
        nm = dt.getName()
        if nm not in by_name or 'types.h' in str(dt.getCategoryPath()):
            by_name[nm] = dt

    decisions = []
    with open(REVIEW_CSV, newline='') as fh:
        for row in csv.DictReader(fh):
            dec = rp.parse_decision(row.get('decision_type'))
            if dec is not None:
                decisions.append((row['class'], int(row['offset'], 16), dec))

    if not decisions:
        print('Review queue has 0 filled decisions (%s). Fill decision_type to apply.'
              % REVIEW_CSV)
        return

    applied = unresolved = skipped = 0
    samples = []
    tx = cp.startTransaction('apply review decisions') if APPLY else None
    try:
        for cls, off, dec in decisions:
            dt = _resolve_type(dtm, by_name, dec)
            if dt is None:
                unresolved += 1
                if len(samples) < 25:
                    samples.append('UNRESOLVED %s +0x%X  "%s" (no such type)' % (cls, off, dec))
                continue
            struct = dtm.getDataType(CategoryPath('/types.h'), cls)
            comp = struct.getComponentAt(off) if struct is not None else None
            if comp is None or comp.getOffset() != off:
                skipped += 1
                continue
            cur = comp.getFieldName() or ''
            cur_t = comp.getDataType().getName()
            # human-authority guards: unknown slot only, exact size only
            if not (cur.startswith(('unk', 'pad', 'off_')) or 'undefined' in cur_t):
                skipped += 1
                continue
            if dt.getLength() != comp.getLength():
                skipped += 1
                if len(samples) < 25:
                    samples.append('SIZE-MISMATCH %s +0x%X  %s is %dB, slot %dB'
                                   % (cls, off, dec, dt.getLength(), comp.getLength()))
                continue
            digits = ''.join(ch for ch in cur if ch.isalnum())
            for pre in ('unk', 'pad', 'off_'):
                if digits.lower().startswith(pre):
                    digits = digits[len(pre):]
                    break
            new_name = 'fld%s' % (digits or ('%X' % off))
            if APPLY:
                # PROVABLE improve-or-nop: validate on a detached copy first; only
                # touch the live struct if length is unchanged and no RE is lost.
                base = _struct_metrics(struct)
                try:
                    test = struct.copy(dtm)
                    test.replaceAtOffset(off, dt, dt.getLength(), new_name, '')
                    tm = _struct_metrics(test)
                except Exception as e:
                    skipped += 1
                    if len(samples) < 25:
                        samples.append('ERROR %s +0x%X %s: %s' % (cls, off, dec, str(e)[:40]))
                    continue
                if tm[0] != base[0] or tm[1] < base[1]:
                    skipped += 1
                    if len(samples) < 25:
                        samples.append('UNSAFE %s +0x%X %s would change struct size/RE'
                                       % (cls, off, dec))
                    continue
                try:
                    struct.replaceAtOffset(off, dt, dt.getLength(), new_name,
                                           'clvr-review ' + dec)
                    applied += 1
                except Exception as e:
                    skipped += 1
                    if len(samples) < 25:
                        samples.append('ERROR %s +0x%X %s: %s' % (cls, off, dec, str(e)[:40]))
                    continue
            else:
                applied += 1
            if len(samples) < 25:
                samples.append('%s %s +0x%X %s -> %s'
                               % ('apply' if APPLY else 'would', cls, off, comp.getFieldName(), dec))
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)   # always commit; never poison the group

    print('apply-review (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN'))
    print('  decisions=%d  %s=%d  unresolved=%d  skipped=%d'
          % (len(decisions), 'applied' if APPLY else 'would-apply', applied,
             unresolved, skipped))
    for s in samples:
        print('   ' + s)
    if not APPLY:
        print('  set CLVR_REVIEW_APPLY=go to write these as authoritative field types.')


run()
