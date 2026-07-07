"""Pure (Ghidra-free) struct/vtable layout comparison used by conflict_report.

Kept separate from conflict_report.py (which imports ghidra.program.model.data at
module level) so this logic is unit-testable without a Ghidra runtime, matching the
vt_plan.py / dedup_plan.py convention in this package.
"""
import re

_AUTO_SUFFIX = re.compile(r'_[0-9A-Fa-f]{1,4}$')

_PLACEHOLDER_TYPES = frozenset((
    'undefined', 'uint', 'int', 'byte', 'sbyte', 'ushort', 'short',
    'ulong', 'long', 'ulonglong', 'longlong', 'uint64_t',
    'undefined1', 'undefined2', 'undefined4', 'undefined8'))


def _placeholder_typename(tn):
    """True if a member's declared type is still a raw/unfinished placeholder
    (a primitive, `undefined*`, or a `char[]`/`byte[]` blob array) rather than a
    real, specific type."""
    t = (tn or '').lower()
    return (t in _PLACEHOLDER_TYPES or t.startswith('undefined') or
            t.startswith('char[') or t.startswith('byte['))


def auto_extract_score(members):
    """Fraction of members whose name is the auto-extraction signature
    'Name_<hex>' (e.g. Enabled_8, CasterRefId_34, FormFlags_10) or _pad_/unk
    filler, OR whose declared type is still a raw placeholder (undefined /
    primitive / char[]/byte[] blob -- see _placeholder_typename) despite having
    a field name. NOTE: the hex token is the ORIGINAL (often SE) offset baked
    into the name and need not equal the member's current offset, so we match
    the pattern, not the value. High score => machine-generated/unfinished
    (safe to overwrite); low score => clean descriptive names with real types
    (PDB symbols or hand RE) -> protect.

    The type check matters because a partial extraction pass can leave behind
    named "remainder" fields (e.g. a `_base`/`_middle`/`_tail` split around a
    few manually-identified members, or an `apply_enrich.py`-style `<name>_raw`
    padding stub) that are NOT machine-suffix-named but are still unfinished
    placeholders -- without it, a struct that is mostly untyped byte blobs with
    a couple of real fields poked in scores as "hand-curated" and is protected
    forever instead of being reapplied. This is the fix for a real bug found on
    ``Character``: its existing struct is `_base_raw (byte[688]), Rotation,
    Position, _middle (char[192]), EditorLocPosition, _tail (char[388])` -- none
    of the placeholder fields matched the old name-only patterns, so the score
    came out low and the struct was permanently protected as "hand-curated"
    despite `_base_raw` alone being exactly the size of (and meant to embed) the
    generated `Actor` base.

    members: [(offset, length, typename, fieldname)]
    """
    if not members:
        return 1.0
    auto = 0
    for (o, ln, tn, fn) in members:
        nm = fn or ''
        low = nm.lower()
        if low.startswith('_pad') or low.startswith('pad') or low.startswith('unk') or \
           low.startswith('field_') or low.endswith('_raw') or 'vftable' in low or not nm:
            auto += 1
        elif _AUTO_SUFFIX.search(nm):
            auto += 1
        elif _placeholder_typename(tn):
            auto += 1
    return float(auto) / len(members)


_KIND_PREFIXES = ('struct:', 'enum:', 'union:', 'class:', 'typedef:')


def _class_of(tn):
    """Coarse type-class for a member typename, so cosmetic name/typedef spelling
    differences don't trigger a false DIVERGENT. 'ptr'/'func ptr' collapse together
    (both are 8-byte pointer-shaped slots -- the common case for a vtable's function
    pointers, which are typed as bare function-pointer typedefs, not 'struct:X *').
    Primitives of the same byte width also collapse (uint32/int32 are interchangeable
    at the ABI level and differ constantly between hand-RE and clang-generated layouts).

    A named struct/enum/union type is normalized to its bare leaf name (kind prefix
    and C++ namespace qualification stripped) before falling through to the raw
    string, so e.g. the generated side's 'struct:DirectX::XMFLOAT3' and the Ghidra
    side's bare 'XMFLOAT3' -- the SAME type, just spelled differently by each
    pipeline stage -- compare equal instead of permanently tripping DIVERGENT. This
    is the fix for a real bug: any generated field whose type is a named
    struct/enum (basically every non-primitive field) failed this comparison on
    namespace spelling alone, so structs with already-correct live fields (e.g.
    ``DirectX::BoundingBox``, fully resolved to `Center`/`Extents: XMFLOAT3`) kept
    reclassifying DIVERGENT and getting endlessly, pointlessly re-applied by every
    batch run with zero actual change."""
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
    for pfx in _KIND_PREFIXES:
        if t.startswith(pfx):
            t = t[len(pfx):]
            break
    t = re.sub(r':\d+$', '', t)  # enum bitfield-width suffix, e.g. 'bool_bits:4'
    if '::' in t:
        t = t.rsplit('::', 1)[-1]
    return t


def has_overlapping_fields(gen_members):
    """True if the generated field list itself has two fields occupying overlapping
    byte ranges at different offsets-with-size (not just two zero-length fields
    sharing an offset).

    This detects an anonymous C++ union that the CommonLib type-extraction step
    flattened into a single flat tuple list instead of modeling as a union -- e.g.
    ``union { struct { BYTE b,g,r,a; }; UINT c; }`` (DirectX's XMCOLOR) becomes
    ``[('b','u8',0,1), ('c','u32',0,4), ('g','u8',1,1), ...]``: 'b'@0..1 and
    'c'@0..4 both claim offset 0, and 'g'@1..2 sits inside 'c'@0..4 too. There is
    no valid non-overlapping flat layout that satisfies both views simultaneously,
    so such a generated struct can never be correctly filled/replaced as an
    ordinary struct -- every batch run would keep re-selecting and "successfully"
    reapplying it with zero actual change, permanently wasting batch budget. Real
    fix is proper union modeling in the generator; this is the cheap classify()-side
    guard so these get excluded from the eligible pool instead of looping forever.

    gen_members: [(fname, ftype, foffset, fsize)]
    """
    spans = sorted((foff, foff + fsize) for (_fname, _ftype, foff, fsize) in gen_members
                   if fsize > 0)
    for i in range(1, len(spans)):
        if spans[i][0] < spans[i - 1][1]:
            return True
    return False


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
