"""Python port of ghidraTools/RecoverRttiVtablesScript.java for MCP eval_python.

The original is a real GhidraScript (Java), which the MCP `scripts` tool can't invoke
by path (it only sees Ghidra-install script dirs). This is a faithful behavioral port
so RTTI vtable recovery can run the same way as the rest of this pipeline (exec'd
inside Ghidra via eval_python) -- needed for EVERY new program this pipeline targets,
most recently AE 1.7.99, and will be needed again for the next AE version bump.

What it does (see the Java original's own header comment for the full algorithm):
finds RTTI Complete Object Locators by their self-reference (COL.pSelf RVA resolves
back to its own address), groups vtables by class (type-descriptor address), and
renames every VTABLE_* label to the readable, MS-demangled C++ class name (keeping
<> :: * intact) -- the canonical convergence naming this whole pipeline uses. Also
renames FUN_/sub_/thunk_ destructor functions found via each vtable's meta pointer.

Known gotcha this port fixes (see project memory
`vr-addr-tools-reference-ghidra-rtti-classhierarchy-walk` and this repo's own hard-won
lesson): ``MemoryBlock.getBytes(Address, byte[])`` SILENTLY returns all zeros when the
byte[] passed in is a plain Python bytearray instead of a real JPype Java array --
no exception, no warning, just zeroed data that makes every downstream scan find
nothing. Always read via ``bytes(jpype.JArray(jpype.JByte)(size))`` after getBytes,
never a bare Python bytearray. (`bytes(jarr)` uses the buffer protocol and is fast;
manually iterating the array element-by-element, e.g. ``bytes(x & 0xFF for x in
jarr)``, works but is 100-1000x slower -- large enough to look like a hang.)

Also does NOT call CreateFunctionCmd to create new destructor functions at
undiscovered addresses (unlike the Java original) -- under the MCP's own outer
transaction, a command that can trigger synchronous re-analysis risked a deadlock in
practice. This only renames destructors where a function ALREADY exists at the
target address; it never creates one. If dtor coverage matters, run Ghidra's own
function-creation/analysis first, then this script.

Run inside Ghidra via eval_python against the target program -- relies on
eval_python's own outer transaction (see that MCP tool's own docs); run() opens
none of its own, so invoking it any other way will raise NoTransactionException
on the first setName()/createLabel() when RTTI_APPLY=go. Dry-run by default
(reports counts only, no writes); RTTI_APPLY=go to write. Expect a real run over a
~30-60MB binary's non-exec sections to take low-single-digit-minutes for discovery
plus roughly a minute for the naming/write pass over several thousand classes --
budget a generous timeout_seconds (this repo's own AE1799 run needed ~1200s+).
"""
import os
import re
import struct

# Ghidra/JPype imports are deliberately deferred into the functions that need them
# (not top-level) so this module -- specifically clean_demangled_name(), the pure
# logic -- stays importable and unit-testable outside a live Ghidra process. See
# test_recover_rtti_vtables.py.

APPLY = os.environ.get('RTTI_APPLY', 'dry').lower() == 'go'

_RTTI_SUFFIX = re.compile(r"_`RTTI_Type_Descriptor'$")
_QUALIFIER = re.compile(r"(^|[<,(])(class|struct|enum|union)_")
_PTR_NOISE = re.compile(r"_*__ptr(32|64)")
_PRE_BRACKET = re.compile(r"_+(?=[>,])")


def _cache_blocks(cp, monitor):
    """(start_offset, bytes, is_exec, name) for every initialized block Ghidra will
    let us bulk-read (matches the Java original's own size filter).

    MUST read via a real JPype array, never a bare Python bytearray -- see the
    module docstring's getBytes gotcha.
    """
    import jpype
    blocks = []
    for b in cp.getMemory().getBlocks():
        monitor.checkCancelled()
        if not b.isInitialized() or b.getSize() <= 0x800 or b.getSize() >= 0x4000000:
            continue
        sz = int(b.getSize())
        jarr = jpype.JArray(jpype.JByte)(sz)
        b.getBytes(b.getStart(), jarr)
        blocks.append([b.getStart().getOffset(), bytes(jarr), b.isExecute(), b.getName()])
    return blocks


def _block_of(blocks, a):
    for blk in blocks:
        if blk[0] <= a < blk[0] + len(blk[1]):
            return blk
    return None


def _cstring(blocks, a):
    blk = _block_of(blocks, a)
    if blk is None:
        return None
    d = blk[1]
    off = a - blk[0]
    if off < 0:
        return None
    end = off
    limit = min(len(d), off + 400)
    while end < limit and d[end] != 0:
        end += 1
    if end >= len(d) or d[end] != 0:
        return None
    try:
        return d[off:end].decode('ascii')
    except Exception:
        return None


def _collect_cols(blocks, image_base, monitor):
    """RTTICompleteObjectLocator (x64): +0 signature, +4 subobject offset,
    +0x0C pTypeDescriptor(RVA), +0x14 pSelf(RVA). Identified by pSelf resolving
    back to its own address -- no prior analysis required."""
    col_meta, col_name = {}, {}
    unpack = struct.unpack_from
    for blk in blocks:
        monitor.checkCancelled()
        if blk[2]:
            continue
        start, d = blk[0], blk[1]
        limit = len(d) - 0x18
        o = 0
        while o <= limit:
            sig = unpack('<I', d, o)[0]
            if sig <= 1:
                selfref = image_base + unpack('<I', d, o + 0x14)[0]
                if selfref == start + o:
                    td_addr = image_base + unpack('<I', d, o + 0x0C)[0]
                    tn = _cstring(blocks, td_addr + 0x10)
                    if tn is not None and tn.startswith('.?A'):
                        col = start + o
                        sub_off = unpack('<I', d, o + 4)[0]
                        col_meta[col] = (sub_off, td_addr)
                        col_name[col] = tn
            o += 4
    return col_meta, col_name


def _map_vtables(blocks, col_meta, col_name, monitor):
    """A vtable's meta pointer (vtable-8) holds the COL address; vtable = that
    slot + 8. Groups by class (type-descriptor address)."""
    by_class = {}
    unpack = struct.unpack_from
    for blk in blocks:
        monitor.checkCancelled()
        if blk[2]:
            continue
        start, d = blk[0], blk[1]
        limit = len(d) - 8
        o = 0
        while o <= limit:
            col = unpack('<Q', d, o)[0]
            m = col_meta.get(col)
            if m is not None:
                sub_off, td_addr = m
                by_class.setdefault(td_addr, []).append((start + o + 8, sub_off, col_name.get(col)))
            o += 8
    return by_class


def clean_demangled_name(cpp):
    """Pure post-processing of a demangled RTTI type-descriptor name: strip the
    ``_`RTTI_Type_Descriptor'`` suffix, drop the ``class_``/``struct_``/etc.
    qualifier tokens and ``__ptr32/64`` noise MSVC's demangler leaves in, collapse
    spaces, and drop a stray trailing ``_`` before ``>``/``,``. Split out from
    `_readable_name` so this logic is unit-testable without a live Ghidra demangler
    (see test_recover_rtti_vtables.py)."""
    if not cpp:
        return cpp
    cpp = _RTTI_SUFFIX.sub('', cpp)
    cpp = _QUALIFIER.sub(r'\1', cpp)
    cpp = _PTR_NOISE.sub('', cpp)
    cpp = cpp.replace(' ', '')
    cpp = _PRE_BRACKET.sub('', cpp)  # drop stray '_' before '>' or ','
    return cpp


def _readable_name(demangler, type_name):
    """Demangle the RTTI type-descriptor name (.?AV...@@) to a readable C++ class
    name, keeping <> :: * intact. None if it can't be demangled."""
    if type_name is None or len(type_name) < 4:
        return None
    wrapped = "??_R0" + type_name[1:] + "@8"  # type-descriptor decorated symbol
    try:
        d = demangler.demangle(wrapped)
        if d is None:
            return None
        cpp = d.getName()
    except Exception:
        return None
    if not cpp:
        return None
    return clean_demangled_name(cpp)


def _existing_vtable_symbol(symtab, addr, label):
    """The (single) VTABLE_ symbol at the address, preferring an exact label match."""
    any_sym = None
    for s in symtab.getSymbols(addr):
        n = s.getName()
        if n.startswith('VTABLE_'):
            if n == label:
                return s
            any_sym = s
    return any_sym


def _to_addr(cp, a):
    try:
        return cp.getAddressFactory().getDefaultAddressSpace().getAddress(a)
    except Exception:
        return None


def _name_destructor(cp, blocks, fm, vt, readable, apply):
    """Rename an already-EXISTING FUN_/sub_/thunk_ function at the vtable's meta
    pointer to <readable>__dtor. Never creates a new function (see module
    docstring). Eligibility is checked (and counted) even in dry-run; only the
    actual write is gated on `apply`."""
    blk = _block_of(blocks, vt)
    if blk is None:
        return False
    off = vt - blk[0]
    d = blk[1]
    if off + 8 > len(d):
        return False
    h = struct.unpack_from('<Q', d, off)[0]
    hb = _block_of(blocks, h)
    if hb is None or not hb[2]:
        return False
    f = fm.getFunctionAt(_to_addr(cp, h))
    if f is None:
        return False
    n = f.getName()
    if not (n.startswith('FUN_') or n.startswith('sub_') or n.startswith('thunk_')):
        return False
    if not apply:
        return True
    from ghidra.program.model.symbol import SourceType
    try:
        f.setName(re.sub(r'[^A-Za-z0-9]', '_', readable) + '__dtor', SourceType.USER_DEFINED)
        return True
    except Exception:
        return False


def run(current_program, monitor):
    from ghidra.app.util.demangler.microsoft import MicrosoftDemangler
    from ghidra.program.model.symbol import SourceType

    cp = current_program

    lang_id = cp.getLanguageID().getIdAsString().lower()
    if 'x86' not in lang_id or cp.getDefaultPointerSize() != 8:
        print("This script targets x64 Windows PE binaries only.")
        return

    image_base = cp.getImageBase().getOffset()
    blocks = _cache_blocks(cp, monitor)
    print("cached blocks:", [(x[3], len(x[1]), x[2]) for x in blocks])

    col_meta, col_name = _collect_cols(blocks, image_base, monitor)
    print("Complete Object Locators (self-ref):", len(col_name))

    by_class = _map_vtables(blocks, col_meta, col_name, monitor)
    total = sum(len(v) for v in by_class.values())
    print("Vtables mapped from COLs: {} across {} classes".format(total, len(by_class)))

    demangler = MicrosoftDemangler()
    symtab = cp.getSymbolTable()
    fm = cp.getFunctionManager()

    renamed = created = unchanged = dtors = undemangled = 0
    for td_addr, group in by_class.items():
        monitor.checkCancelled()
        group.sort(key=lambda v: v[1])
        readable = _readable_name(demangler, group[0][2])
        if readable is None:
            undemangled += len(group)
            continue
        for i, (vaddr, sub_off, type_name) in enumerate(group):
            label = "VTABLE_" + readable + ("" if i == 0 else "_%d" % (i + 1))
            a = _to_addr(cp, vaddr)
            if a is None:
                continue
            existing = _existing_vtable_symbol(symtab, a, label)
            if existing is not None and existing.getName() == label:
                unchanged += 1
            elif existing is not None:
                if APPLY:
                    try:
                        existing.setName(label, SourceType.USER_DEFINED)
                        renamed += 1
                    except Exception:
                        pass
                else:
                    renamed += 1
            else:
                if APPLY:
                    try:
                        symtab.createLabel(a, label, SourceType.USER_DEFINED)
                        created += 1
                    except Exception:
                        pass
                else:
                    created += 1
            # Slot 0 is only the scalar-deleting destructor on the PRIMARY vtable
            # (sub_off == 0); on a secondary/interface vtable it's that base's own
            # first virtual method, and misnaming it here would silently corrupt an
            # unrelated function.
            if sub_off == 0 and _name_destructor(cp, blocks, fm, vaddr, readable, APPLY):
                dtors += 1

    print("VTABLE labels ({}): {} renamed, {} created, {} already correct, "
          "{} destructors, {} undemanglable.".format(
              'APPLIED' if APPLY else 'DRY-RUN', renamed, created, unchanged, dtors, undemangled))


# Only auto-run when exec'd via eval_python (which injects these as globals) --
# guarded so this module can also be imported plainly (e.g. by
# test_recover_rtti_vtables.py) to unit-test clean_demangled_name() without a
# live Ghidra process.
if 'currentProgram' in globals():
    run(currentProgram, monitor)  # noqa: F821
