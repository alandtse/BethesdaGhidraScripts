"""Ghidra driver: type + name high-confidence global singletons from a
globals_harvest review queue.  Technique adapted from alandtse's
CommonLibVR fork (the apply half of the globals review pattern).

Reads a ``globals_queue_<prog>.csv`` produced by globals_harvest and,
for each row meeting the confidence bar, sets the global's data type to
the inferred class (or a pointer to it) and renames the ``DAT_*`` slot
to a readable singleton name.  A typed global lets the decompiler
propagate field accesses through it -- the downstream payoff that makes
the next discovery pass resolve one level deeper.

DEFAULT IS DRY-RUN.  Set BGS_ENRICH_APPLY=go to write.  Only rows whose
``decision_type`` column is blank are auto-decided by confidence; a
reviewer can hard-override a row by filling ``decision_type`` (that
value wins, or ``skip`` excludes the row).

Knobs (env):
  BGS_ENRICH_APPLY=go        actually type/name (default dry-run)
  BGS_GLOBALS_APPLY_CSV      input queue CSV (default: refs/globals_queue_<prog>.csv)
  BGS_GLOBALS_MIN_CONF       min confidence to auto-apply: high|medium (default high)
"""
import csv
import os
import sys

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'
MIN_CONF = os.environ.get('BGS_GLOBALS_MIN_CONF', 'high').lower()
_CONF_RANK = {'high': 2, 'medium': 1, 'low': 0}


def _resolve_struct(dtm, name):
    """Find the StructureDB datatype named ``name`` (any category)."""
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name and dt.getClass().getSimpleName() == 'StructureDB':
            return dt
    return None


def run():
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.data import PointerDataType
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    listing = cp.getListing()
    st = cp.getSymbolTable()
    af = cp.getAddressFactory().getDefaultAddressSpace()

    in_csv = os.environ.get('BGS_GLOBALS_APPLY_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'globals_queue_%s.csv' % cp.getName().replace('.', '_'))
    if not os.path.isfile(in_csv):
        print('globals-apply: no queue CSV at ' + in_csv)
        return

    rows = list(csv.DictReader(open(in_csv, newline='')))
    typed = renamed = skipped = missing = 0
    tx = cp.startTransaction('globals-apply') if APPLY else None
    try:
        for r in rows:
            decision = (r.get('decision_type') or '').strip()
            conf = (r.get('confidence') or '').strip().lower()
            cls = r.get('inferred_type', '').strip()
            if decision.lower() == 'skip':
                skipped += 1
                continue
            # decision_type hard-override wins; else gate on confidence.
            if decision:
                cls = decision
            elif _CONF_RANK.get(conf, 0) < _CONF_RANK.get(MIN_CONF, 2):
                skipped += 1
                continue
            try:
                addr = af.getAddress(int(r['global_addr'], 16))
            except (ValueError, KeyError):
                continue
            struct = _resolve_struct(dtm, cls)
            if struct is None:
                missing += 1
                continue
            is_ptr = r.get('is_pointer', '0').strip() == '1'
            dt = PointerDataType(struct) if is_ptr else struct

            if not APPLY:
                typed += 1
                renamed += 1
                continue
            try:
                listing.clearCodeUnits(addr, addr.add(dt.getLength() - 1), False)
                listing.createData(addr, dt)
                typed += 1
            except Exception:
                pass
            # Name the slot: g_<Class> (singleton convention).  Skip if a
            # non-default symbol is already present (don't clobber).
            try:
                sym = st.getPrimarySymbol(addr)
                if sym is None or sym.getName().startswith(('DAT_', 'g_')):
                    st.createLabel(addr, 'g_' + cls, SourceType.USER_DEFINED)
                    renamed += 1
            except Exception:
                pass
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)

    print('globals-apply (%s): %s  min-conf=%s'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN', MIN_CONF))
    print('  %s=%d  %s=%d  skipped(low-conf)=%d  struct-not-found=%d'
          % ('typed' if APPLY else 'would-type', typed,
             'named' if APPLY else 'would-name', renamed, skipped, missing))
    if not APPLY:
        print('  set BGS_ENRICH_APPLY=go to apply.')


run()
