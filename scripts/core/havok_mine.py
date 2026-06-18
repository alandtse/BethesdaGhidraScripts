"""Ghidra driver: mine havok hkClass reflection descriptors (READ-ONLY).
EXPERIMENTAL / INCOMPLETE -- see the LAYOUT NOTE below.

Havok ships POD reflection descriptors (hkClass / hkClassMember) that
survive in retail Skyrim/F4 x64 builds.  Each hkClass names a havok
class and lists its members with exact name + type + byte offset --
authoritative field layout for the entire havok subsystem (hkp*/hkb*/
hknp*/hka*/bhk*), far beyond what CommonLib defines.

LAYOUT NOTE (why this finds 0 today): the reflection data IS present
(F4: 1053 hk-class-name strings, 777 data slots pointing at them), but
the structure is a multi-type GRAPH, not a flat hkClass[] array.  A
data-scan for slots pointing at a class-name string lands mostly on
hkClassEnum.name and a hkTypeInfo-style registry (hkBase/hkInt32/...),
NOT hkClass.name -- so the simple hkClass{name@0,objSize@0x10,
members@0x28,num@0x30} model below validates nothing.  To finish this:
decompile the F4 1.11.221 PDB-named accessors hkClass::getDeclaredMembers
/ getNumDeclaredMembers / hkClassMember::getOffset (addresses pinned in
scripts/commonlibf4/refs/bytesig_ported_ae.csv) to read the EXACT field
offsets, then walk only true hkClass instances (reachable from the
<Type>::staticClass accessors / hkVtableClassRegistry).  Left here as a
scaffold + the validated discovery (string set + data-slot scan) for a
future dedicated pass.

x64 layout (Havok 2014.x ABI, corroborated by named accessors in
scripts/commonlibf4/refs/bytesig_ported_ae.csv):
  hkClass        name@0x00  objectSize@0x10  declaredMembers@0x28  numMembers@0x30
  hkClassMember  name@0x00  type@0x18(u8)    offset@0x1E(u16)      sizeof 0x28

Discovery: havok class-name strings start with a known prefix (hk/bhk).
Follow each string's data xref back to the hkClass.name field, validate
the surrounding layout (sane objectSize, members ptr -> array whose
entries have ASCII names), then walk the member array.

READ-ONLY: writes a proposals CSV (class, member_offset, member_type,
member_name, object_size); never modifies the program.  Apply is a
separate reviewed step (typing havok structs touches the whole DTM).
Knob: BGS_HAVOK_CSV (output path).
"""
import csv
import os

# hkClassMember::Type enum -> a readable type token (subset; the rest
# keep their THKMEMBER name).  Applied downstream, not here.
_HK_TYPE = {
    0: 'void', 1: 'bool', 2: 'char', 3: 'i8', 4: 'u8', 5: 'i16', 6: 'u16',
    7: 'i32', 8: 'u32', 9: 'i64', 10: 'u64', 11: 'float', 12: 'hkVector4',
    13: 'hkQuaternion', 14: 'hkMatrix3', 15: 'hkRotation', 16: 'hkQsTransform',
    17: 'hkMatrix4', 18: 'hkTransform', 20: 'ptr', 21: 'funcptr',
    22: 'hkArray', 23: 'hkInplaceArray', 24: 'enum', 25: 'struct',
    26: 'hkSimpleArray', 28: 'hkVariant', 29: 'char*', 30: 'ulong',
    31: 'flags', 32: 'half', 33: 'hkStringPtr', 34: 'hkRelArray',
}

_NAME_PREFIXES = ('hk', 'bhk')
HKCLASS_NAME, HKCLASS_OBJSIZE = 0x00, 0x10
HKCLASS_MEMBERS, HKCLASS_NUMMEMBERS = 0x28, 0x30
HKMEMBER_NAME, HKMEMBER_TYPE, HKMEMBER_OFFSET = 0x00, 0x18, 0x1E
HKMEMBER_SIZE = 0x28


def run():
    import re
    cp = currentProgram  # noqa: F821
    if cp.getDefaultPointerSize() != 8:
        print('havok-mine (%s): x86 -- skipped (havok ABI here is x64)'
              % cp.getName())
        return
    mem = cp.getMemory()
    listing = cp.getListing()
    rm = cp.getReferenceManager()
    af = cp.getAddressFactory().getDefaultAddressSpace()
    out_csv = os.environ.get('BGS_HAVOK_CSV') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'refs',
        'havok_members_%s.csv' % cp.getName().replace('.', '_'))

    _ident = re.compile(r'^[A-Za-z_]\w*$')

    def _ptr(va):
        try:
            return mem.getLong(af.getAddress(va)) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            return None

    def _cstr(va, maxlen=96):
        if va is None:
            return None
        a = af.getAddress(va)
        blk = mem.getBlock(a)
        if blk is None or not blk.isInitialized():
            return None
        try:
            bs = bytearray(maxlen)
            n = mem.getBytes(a, bs)
            s = ''
            for i in range(n):
                ch = bs[i] & 0xFF
                if ch == 0:
                    break
                if ch < 0x20 or ch > 0x7E:
                    return None
                s += chr(ch)
            return s
        except Exception:
            return None

    def _u(va, width):
        try:
            a = af.getAddress(va)
            if width == 2:
                return mem.getShort(a) & 0xFFFF
            if width == 4:
                return mem.getInt(a) & 0xFFFFFFFF
            return mem.getByte(a) & 0xFF
        except Exception:
            return None

    def _in_data(va):
        blk = mem.getBlock(af.getAddress(va)) if va else None
        return blk is not None and blk.isInitialized() and not blk.isExecute()

    # Collect havok class-name string ADDRESSES (hk*/bhk* identifiers).
    hkstr = {}                          # string-addr -> name
    di = listing.getDefinedData(True)
    while di.hasNext():
        d = di.next()
        tn = d.getDataType().getName().lower()
        if 'char' not in tn and 'string' not in tn:
            continue
        v = d.getValue()
        if v is None:
            continue
        nm = str(v).strip()
        if nm.startswith(_NAME_PREFIXES) and _ident.match(nm):
            hkstr[d.getAddress().getOffset()] = nm
    n_hkstr = len(hkstr)

    # Find hkClass bases by SCANNING initialized data for an 8-byte slot
    # that points at one of those strings -- that slot is hkClass.name@0.
    # (Ghidra often doesn't create a data->string reference for a raw
    # undefined8 pointer slot, so a reference-based lookup misses them.)
    # Bulk-read each block and scan in Python (per-slot mem reads are far
    # too slow over tens of MB of data).
    import jpype
    import struct as _struct
    ByteArray = jpype.JArray(jpype.JByte)
    seen = set()
    classes = []                        # (base, name, objsize, members_ptr, nmem)
    n_nameslot = 0
    for blk in mem.getBlocks():
        if not blk.isInitialized() or blk.isExecute():
            continue
        size = blk.getSize()
        start = blk.getStart().getOffset()
        raw = bytearray(size)
        CHUNK = 1 << 20
        ok = True
        for c in range(0, size, CHUNK):
            n = min(CHUNK, size - c)
            buf = ByteArray(n)
            try:
                blk.getBytes(blk.getStart().add(c), buf, 0, n)
            except Exception:
                ok = False
                break
            raw[c:c + n] = bytes(buf)
        if not ok:
            continue
        # scan 8-byte-aligned slots for pointers into the hk-string set
        for i in range(0, size - 8, 8):
            p = _struct.unpack_from('<Q', raw, i)[0]
            if p not in hkstr:
                continue
            n_nameslot += 1
            base = start + i             # name slot == hkClass base (name@0)
            if base in seen:
                continue
            if os.environ.get('BGS_HAVOK_DEBUG') and n_nameslot <= 8:
                dump = []
                for o in (0x8, 0x10, 0x14, 0x18, 0x20, 0x24, 0x28, 0x30, 0x38, 0x40):
                    dump.append('+%02X=%X' % (o, (_ptr(base + o) or 0) & 0xFFFFFFFFFFFF))
                print('  DBG %s @%X: %s' % (hkstr[p], base, ' '.join(dump)))
            objsize = _u(base + HKCLASS_OBJSIZE, 4)
            members = _ptr(base + HKCLASS_MEMBERS)
            nmem = _u(base + HKCLASS_NUMMEMBERS, 4)
            if (objsize is None or not (0 < objsize <= 0x20000)
                    or nmem is None or not (0 < nmem <= 512)
                    or members is None or not _in_data(members)):
                continue
            m0name = _cstr(_ptr(members + HKMEMBER_NAME))
            m0off = _u(members + HKMEMBER_OFFSET, 2)
            if (m0name is None or not _ident.match(m0name)
                    or m0off is None or m0off >= objsize):
                continue
            seen.add(base)
            classes.append((base, hkstr[p], objsize, members, nmem))
    n_hkref = n_nameslot

    rows = []
    for base, cname, objsize, members, nmem in classes:
        for i in range(nmem):
            ma = members + i * HKMEMBER_SIZE
            mn = _cstr(_ptr(ma + HKMEMBER_NAME))
            if mn is None or not _ident.match(mn):
                continue
            mtype = _u(ma + HKMEMBER_TYPE, 1)
            moff = _u(ma + HKMEMBER_OFFSET, 2)
            if moff is None or moff >= objsize:
                continue
            rows.append((cname, '0x%X' % moff,
                         _HK_TYPE.get(mtype, 'hkType%d' % (mtype or 0)),
                         mn, str(objsize)))

    rows.sort(key=lambda r: (r[0], int(r[1], 16)))
    if not os.path.isdir(os.path.dirname(out_csv)):
        os.makedirs(os.path.dirname(out_csv))
    with open(out_csv, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['hkclass', 'offset', 'type', 'member', 'object_size'])
        for r in rows:
            w.writerow(r)
    print('havok-mine (%s): %d hk-strings, %d hk-string-refs, %d hkClass '
          'descriptors, %d member fields'
          % (cp.getName(), n_hkstr, n_hkref, len(classes), len(rows)))
    for r in rows[:20]:
        print('   %s +%s %s %s' % (r[0], r[1], r[2], r[3]))
    print('  -> ' + out_csv)


run()
