"""Apply reviewed GLOBAL types (phase 2 of the globals workflow).

globals_harvest emits <import>.globals_queue.csv -- candidate singleton globals and
the class each is passed to as `this`. Once a reviewer fills `decision_type` (or
accepts the inferred type via CLVR_GLOBALS_ACCEPT_CONF), this types the global data:
a pointer SLOT (is_pointer=1) becomes `T *`, an INLINE singleton (is_pointer=0)
becomes `T`. Typing the global is the lever: the decompiler then propagates T through
EVERY use of the global, so a function that stores the singleton into `C->field`
finally shows `field` is a `T *` -- the "globals reveal class membership" payoff.

Feedback into the cycle: after typing, it collects the classes whose methods reference
the newly-typed globals (reference manager -> caller -> its class) and writes them to
the discovery dirty file, so the next discovery pass re-mines exactly those classes and
harvests the now-visible fields. This also closes the incremental cycle's blind spot --
a dependency that ran THROUGH an untyped global is now a typed edge the deref model
sees.

NON-DESTRUCTIVE: only types globals whose target bytes are currently UNDEFINED (never
clobbers defined data), only renames DEFAULT (DAT_*) symbols, one always-committed
transaction. Dry-run by default; CLVR_GLOBALS_APPLY=go to write. Knobs:
CLVR_GLOBALS_CSV (input), CLVR_GLOBALS_ACCEPT_CONF (auto-accept inferred type at/above
this confidence when decision_type is blank: high|medium|none, default none).
"""
import csv
import os

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
IN_CSV = os.environ.get('CLVR_GLOBALS_CSV', IMPORT_PATH + '.globals_queue.csv')
DIRTY_FILE = os.environ.get('CLVR_DISCOVER_DIRTY', IMPORT_PATH + '.discover_dirty.txt')
APPLY = os.environ.get('CLVR_GLOBALS_APPLY', 'dry').lower() == 'go'
# auto-accept the inferred type when the reviewer left decision_type blank, if the
# harvester's confidence is at/above this bar (none = require an explicit decision).
ACCEPT_CONF = os.environ.get('CLVR_GLOBALS_ACCEPT_CONF', 'none').lower()

import importlib.util as _ilu  # noqa: E402
_rspec = _ilu.spec_from_file_location('clvr_review_plan', os.path.join(SCRIPT_DIR, 'review_plan.py'))
rp = _ilu.module_from_spec(_rspec)
_rspec.loader.exec_module(rp)
_gspec = _ilu.spec_from_file_location('clvr_ghidra_util', os.path.join(SCRIPT_DIR, 'clvr_ghidra_util.py'))
gu = _ilu.module_from_spec(_gspec)
_gspec.loader.exec_module(gu)

_CONF_RANK = {'high': 2, 'medium': 1, 'low': 0}


def _accept(row):
    """Return the chosen type string for a row, or None to skip. An explicit
    decision_type wins; otherwise auto-accept the inferred type if its confidence
    clears ACCEPT_CONF. `skip`/blank with no auto-accept -> None."""
    dec = rp.parse_decision(row.get('decision_type'))
    if dec is not None:
        return dec
    if ACCEPT_CONF in _CONF_RANK and _CONF_RANK.get(row.get('confidence', 'low'), 0) >= _CONF_RANK[ACCEPT_CONF]:
        return row.get('inferred_type') or None
    return None


def _span_undefined(listing, addr, length):
    """True only if every byte in [addr, addr+length) is undefined OR a placeholder
    `undefined`/`undefinedN` data item -- the non-destructive guard. Ghidra marks raw
    data slots as `undefined8` (a DEFINED type), so we must treat the undefined* family
    as fillable; only a CONCRETE type (a struct, a typed pointer, ...) blocks the fill."""
    a = addr
    for _ in range(length):
        d = listing.getDefinedDataAt(a)
        if d is not None and not d.getDataType().getName().startswith('undefined'):
            return False
        a = a.next()
        if a is None:
            return False
    return True


def run():
    from ghidra.program.model.data import DataUtilities
    ClearDataMode = DataUtilities.ClearDataMode
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    listing = cp.getListing()
    aspace = cp.getAddressFactory().getDefaultAddressSpace()
    fm = cp.getFunctionManager()

    if not os.path.exists(IN_CSV):
        print('No globals queue at %s -- run globals_harvest first.' % IN_CSV)
        return

    by_name = gu.build_by_name(dtm)
    rows = []
    with open(IN_CSV, newline='') as fh:
        for row in csv.DictReader(fh):
            rows.append(row)

    typed = 0
    skips = {}
    dirty_classes = set()
    samples = []
    tx = cp.startTransaction('apply global types') if APPLY else None
    try:
        for row in rows:
            chosen = _accept(row)
            if not chosen:
                skips['no-decision'] = skips.get('no-decision', 0) + 1
                continue
            addr = aspace.getAddress(int(row['global_addr'], 16))
            base = gu.resolve_type(dtm, by_name, chosen)
            if base is None:
                skips['unresolved-type'] = skips.get('unresolved-type', 0) + 1
                continue
            # pointer slot vs inline singleton: T * vs T
            is_ptr = str(row.get('is_pointer', '0')) == '1'
            dt = dtm.getPointer(base, 8) if (is_ptr and not chosen.strip().endswith('*')) else base
            # non-destructive: only type undefined bytes
            if not _span_undefined(listing, addr, dt.getLength()):
                skips['occupied(defined-data)'] = skips.get('occupied(defined-data)', 0) + 1
                continue
            # collect feedback dirty classes: classes whose methods reference this global
            for ref in cp.getReferenceManager().getReferencesTo(addr):
                caller = fm.getFunctionContaining(ref.getFromAddress())
                if caller is not None:
                    c = gu.param0_class_name(caller)
                    if c:
                        dirty_classes.add(c)
            if APPLY:
                try:
                    DataUtilities.createData(cp, addr, dt, dt.getLength(), False,
                                             ClearDataMode.CLEAR_ALL_CONFLICTING_DATA)
                    # name a still-default (DAT_*) symbol for readability
                    sym = cp.getSymbolTable().getPrimarySymbol(addr)
                    if sym is not None and sym.getSource().toString() == 'DEFAULT':
                        from ghidra.program.model.symbol import SourceType
                        nm = 'g_' + row['inferred_type'] + ('Ptr' if is_ptr else '')
                        sym.setName(nm, SourceType.USER_DEFINED)
                except Exception as e:
                    skips['write-error'] = skips.get('write-error', 0) + 1
                    if len(samples) < 20:
                        samples.append('ERROR 0x%X %s: %s' % (addr.getOffset(), chosen, str(e)[:40]))
                    continue
            typed += 1
            if len(samples) < 20:
                samples.append('%s 0x%X -> %s%s' % ('type' if APPLY else 'would-type',
                               addr.getOffset(), dt.getName(), '' if APPLY else ''))
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)   # always commit; never poison the group

    # write the feedback dirty file so the next discovery pass re-mines the classes that
    # use the now-typed globals (where the new field RE will surface).
    if dirty_classes and APPLY:
        try:
            with open(DIRTY_FILE, 'w') as fh:
                fh.write('\n'.join(sorted(dirty_classes)))
        except Exception as e:
            print('  (dirty-file write failed: %s)' % e)

    print('apply-globals (%s): %s' % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN'))
    print('  %s=%d  skips=%s' % ('typed' if APPLY else 'would-type', typed, skips))
    print('  feedback: %d classes reference the typed globals -> %s'
          % (len(dirty_classes), DIRTY_FILE if APPLY else '(dry: not written)'))
    for s in samples:
        print('   ' + s)
    if not APPLY:
        print('  set CLVR_GLOBALS_APPLY=go to type these globals and seed the dirty file.')


run()
