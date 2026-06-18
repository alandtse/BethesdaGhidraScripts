"""Ghidra driver: name + type global game-setting objects by their key's
Hungarian prefix.  Technique adapted from alandtse's CommonLibVR notes.

A setting object (RE::Setting / SettingT<T>) stores a pointer to its key
string (``fJumpHeightMin``) whose first char encodes the value type.
This scans defined strings for Hungarian setting keys, follows the data
xref back to the Setting object that points at each key, names that
object ``setting_<key>``, and types the value union from the prefix.

Per-game geometry (value union @0x8 in all):
  SSE / F4 : key pointer @0x10, struct size 0x18
  Starfield: key pointer @0x18, struct size 0x20  (carries _defaultValue@0x10)
FNV (x86) uses a different settings layout and is skipped.

NON-DESTRUCTIVE: only names DAT_/undefined slots and types the value
slot; never clobbers an existing name/type.  Dry-run default;
BGS_ENRICH_APPLY=go to write.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import settings_match as sm  # noqa: E402

APPLY = os.environ.get('BGS_ENRICH_APPLY', 'dry').lower() == 'go'


def _is_data_addr(mem, addr):
    blk = mem.getBlock(addr)
    return blk is not None and blk.isInitialized()


def run():
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.model.data import (
        FloatDataType, IntegerDataType, UnsignedIntegerDataType,
        BooleanDataType, CharDataType, ByteDataType, PointerDataType)
    cp = currentProgram  # noqa: F821
    if cp.getDefaultPointerSize() != 8:
        print('settings-harvest (%s): x86 program -- skipped (FNV settings '
              'layout differs)' % cp.getName())
        return

    name_is_sf = 'starfield' in cp.getName().lower()
    NAME_OFF = 0x18 if name_is_sf else 0x10
    VALUE_OFF = 0x8

    listing = cp.getListing()
    rm = cp.getReferenceManager()
    fm = cp.getFunctionManager()
    mem = cp.getMemory()
    st = cp.getSymbolTable()
    af = cp.getAddressFactory().getDefaultAddressSpace()

    _TYPE = {'float': FloatDataType(), 'int': IntegerDataType(),
             'uint': UnsignedIntegerDataType(), 'bool': BooleanDataType(),
             'char': CharDataType(), 'byte': ByteDataType()}

    named = typed = scanned = skipped = 0
    tx = cp.startTransaction('settings-harvest') if APPLY else None
    try:
        di = listing.getDefinedData(True)
        seen_base = set()
        while di.hasNext():
            d = di.next()
            tn = d.getDataType().getName().lower()
            if 'char' not in tn and 'string' not in tn:
                continue
            v = d.getValue()
            if v is None:
                continue
            key = sm.setting_key(str(v).strip())
            if key is None:
                continue
            scanned += 1
            vt = sm.value_type(key)
            # The Setting object's key field points at this string; find it.
            for ref in rm.getReferencesTo(d.getAddress()):
                frm = ref.getFromAddress()
                # only a data slot (not a code LEA) is the object key field
                if fm.getFunctionContaining(frm) is not None:
                    continue
                if not _is_data_addr(mem, frm):
                    continue
                base_off = frm.getOffset() - NAME_OFF
                if base_off in seen_base:
                    continue
                base = af.getAddress(base_off)
                # validate: object[0] is a vtable ptr into initialized mem
                try:
                    vptr = mem.getLong(base) & 0xFFFFFFFFFFFFFFFF
                    if not _is_data_addr(mem, af.getAddress(vptr)):
                        continue
                except Exception:
                    continue
                seen_base.add(base_off)

                if not APPLY:
                    named += 1
                    if vt:
                        typed += 1
                    continue
                # name the object slot setting_<key> (only DAT_/none)
                try:
                    sym = st.getPrimarySymbol(base)
                    if sym is None or sym.getName().startswith(('DAT_', 'setting_')):
                        st.createLabel(base, 'setting_' + key, SourceType.USER_DEFINED)
                        named += 1
                except Exception:
                    pass
                # type the value union slot (only if currently undefined)
                if vt:
                    valt, width = vt
                    va = base.add(VALUE_OFF)
                    ex = listing.getDefinedDataAt(va)
                    if ex is None or ex.getDataType().getName().startswith('undefined'):
                        dt = (PointerDataType() if valt == 'ptr'
                              else _TYPE.get(valt))
                        if dt is not None:
                            try:
                                listing.clearCodeUnits(va, va.add(width - 1), False)
                                listing.createData(va, dt)
                                typed += 1
                            except Exception:
                                pass
    finally:
        if tx is not None:
            cp.endTransaction(tx, True)

    print('settings-harvest (%s): %s  (game=%s, key@0x%X)'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN',
             'SF' if name_is_sf else 'SSE/F4', NAME_OFF))
    print('  setting keys scanned=%d  %s=%d  values-typed=%d'
          % (scanned, 'named' if APPLY else 'would-name', named, typed))
    if not APPLY:
        print('  set BGS_ENRICH_APPLY=go to apply.')


run()
