"""Ghidra driver: APPLY ctor_mine field proposals to the program's structs.

ctor_mine.py writes proposals (class, offset, type, name, slot_state) to a
CSV but nothing applied them -- so every recovered field type/name sat
unused.  This applies them CONSERVATIVELY:

  * only touches slots whose CURRENT component is undefined / unk* / pad*
    (re-checked live, not trusted from the CSV) -- never overwrites a real
    field;
  * embedded-object proposals (name == 'embedded') set field@off to the
    proposed struct type, but only if that type exists in the DTM and fits
    without overrunning the next defined component;
  * 'base' proposals (off==0 inheritance) are skipped -- CommonLib already
    inlines base classes, and retyping offset 0 is risky;
  * param-derived proposals (name is a field label) rename the slot and, if
    the proposed type resolves, retype it.

Dry-run default; BGS_ENRICH_APPLY=go to write.  Reads the CSV from
BGS_CTOR_CSV (same default path ctor_mine writes).
"""
import csv
import os

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'


def _resolve_type(dtm, name):
    name = name.strip()
    its = dtm.getAllDataTypes()
    # exact name match (first); structs/typedefs live in various categories
    for dt in dtm.getAllDataTypes():
        if dt.getName() == name:
            return dt
    return None


def run():
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()
    csv_path = os.environ.get('BGS_CTOR_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'ctor_fields_%s.csv' % cp.getName().replace('.', '_'))
    if not os.path.isfile(csv_path):
        print('ctor-apply (%s): no proposals CSV at %s' % (cp.getName(), csv_path))
        return

    # index structs by name
    structs = {}
    for dt in dtm.getAllDataTypes():
        if dt.getClass().getSimpleName() == 'StructureDB':
            structs[dt.getName()] = dt

    def is_unk_at(sdt, off):
        """Current component at off is undefined/unk/pad (safe to fill)?"""
        dtc = sdt.getComponentAt(off) if hasattr(sdt, 'getComponentAt') else None
        if dtc is None:
            return True
        fn = dtc.getFieldName() or ''
        tn = dtc.getDataType().getName().lower()
        return (dtc.getOffset() == off and
                (fn.startswith(('unk', 'pad')) or 'undefined' in tn or not fn))

    def next_defined_off(sdt, off):
        best = sdt.getLength()
        for c in sdt.getDefinedComponents():
            o = c.getOffset()
            if o > off and o < best:
                best = o
        return best

    rows = list(csv.DictReader(open(csv_path)))
    typed = renamed = skipped_known = skipped_fit = skipped_notype = 0
    tx = cp.startTransaction('ctor-apply') if APPLY else None
    try:
        for r in rows:
            cls = r['class']
            sdt = structs.get(cls)
            if sdt is None:
                continue
            try:
                off = int(r['offset'], 16)
            except ValueError:
                continue
            kind = r['name']
            tname = r['type']
            if kind == 'base':                       # off==0 inheritance: skip
                continue
            if not is_unk_at(sdt, off):              # don't overwrite real field
                skipped_known += 1
                continue
            if kind == 'embedded':
                dt = structs.get(tname) or _resolve_type(dtm, tname)
                if dt is None:
                    skipped_notype += 1
                    continue
                sz = dt.getLength()
                if off + sz > next_defined_off(sdt, off) or off + sz > sdt.getLength():
                    skipped_fit += 1
                    continue
                if APPLY:
                    try:
                        sdt.replaceAtOffset(off, dt, sz, None, 'ctor-mine')
                        typed += 1
                    except Exception:
                        skipped_fit += 1
                else:
                    typed += 1
            else:                                    # param-derived field label
                dt = _resolve_type(dtm, tname)
                label = kind or None
                if dt is None:
                    # name-only: just rename the undefined slot if possible
                    skipped_notype += 1
                    continue
                sz = dt.getLength()
                if off + sz > next_defined_off(sdt, off):
                    skipped_fit += 1
                    continue
                if APPLY:
                    try:
                        sdt.replaceAtOffset(off, dt, sz, label, 'ctor-mine')
                        typed += 1
                        if label:
                            renamed += 1
                    except Exception:
                        skipped_fit += 1
                else:
                    typed += 1
                    if label:
                        renamed += 1
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)

    print('ctor-apply (%s): %s  %d fields typed (%d named), '
          'skipped %d already-defined, %d no-fit, %d type-missing'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN', typed, renamed,
             skipped_known, skipped_fit, skipped_notype))


run()
