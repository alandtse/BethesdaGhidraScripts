"""Pure (Ghidra-free) struct/vtable layout comparison used by conflict_report.

Kept separate from conflict_report.py (which imports ghidra.program.model.data at
module level) so this logic is unit-testable without a Ghidra runtime, matching the
vt_plan.py / dedup_plan.py convention in this package.
"""


def _class_of(tn):
    """Coarse type-class for a member typename, so cosmetic name/typedef spelling
    differences don't trigger a false DIVERGENT. 'ptr'/'func ptr' collapse together
    (both are 8-byte pointer-shaped slots -- the common case for a vtable's function
    pointers, which are typed as bare function-pointer typedefs, not 'struct:X *').
    Primitives of the same byte width also collapse (uint32/int32 are interchangeable
    at the ABI level and differ constantly between hand-RE and clang-generated layouts)."""
    t = (tn or '').lower()
    if t.endswith('*') or 'vtbl' in t or 'vftable' in t or t.startswith('function') or t.startswith('code *'):
        return 'ptr'
    if t in ('undefined1', 'byte', 'sbyte', 'bool', 'char', 'uchar'):
        return 'u8'
    if t in ('undefined2', 'ushort', 'short', 'word'):
        return 'u16'
    if t in ('undefined4', 'uint', 'int', 'dword', 'float'):
        return 'u32'
    if t in ('undefined8', 'ulong', 'long', 'ulonglong', 'longlong', 'uint64_t', 'qword', 'double'):
        return 'u64'
    return t


def layout_diverges(existing_members, gen_members):
    """True if, DESPITE existing_size == generated_size, the two layouts disagree
    at some offset in a way that isn't just a cosmetic name/typedef difference.

    This is the fix for a real bug: a struct/vtable can grow a bogus extra field
    (or drop a real one) that shifts every subsequent member's offset while the
    TOTAL size happens to stay the same (an existing member elsewhere is also off
    by the same amount, or padding absorbs the delta) -- classify()'s old
    ``esize == gsize -> MATCH`` treated this as "already correct" and skipped
    reapplying the freshly-generated (correct) layout, permanently protecting the
    stale/wrong one. This happened concretely to ``RE::Actor``'s vtable: a bogus
    ``Unk_84`` declaration shifted every subsequent vtable slot by one, but the
    struct's total size still matched, so the drift went uncorrected across
    however many pipeline runs happened since it was introduced.

    Deliberately lenient about what counts as "diverges" -- only offset+type-class
    disagreement or a differing field count trips it. A bare name difference alone
    (e.g. Ghidra's own better name for a placeholder, or a cosmetic rename) is NOT
    treated as divergence: forcing every hand-renamed field back through DIVERGENT
    review just because clang's generated name differs would make DIVERGENT so noisy
    that real cases stop getting attention.

    existing_members: [(offset, length, typename, fieldname)]  (Ghidra side)
    gen_members:       [(fname, ftype_str, foffset, fsize)]    (generated side)
    """
    if len(existing_members) != len(gen_members):
        return True
    by_off_e = {o: (ln, tn) for (o, ln, tn, _fn) in existing_members}
    by_off_g = {foff: (fsize, ftype) for (fname, ftype, foff, fsize) in gen_members}
    offsets = set(by_off_e) | set(by_off_g)
    for off in offsets:
        e = by_off_e.get(off)
        g = by_off_g.get(off)
        if e is None or g is None:
            return True  # a slot exists on one side only -> real structural disagreement
        e_len, e_tn = e
        g_len, g_tn = g
        if e_len != g_len:
            return True
        if _class_of(e_tn) != _class_of(g_tn):
            return True
    return False
