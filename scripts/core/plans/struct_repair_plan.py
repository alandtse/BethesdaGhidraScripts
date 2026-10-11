"""Pure (Ghidra-free) planner for repairing scrambled flat structs.

Defect: an auto-imported, flat (no `_base`) struct whose members are listed in the wrong
order/offsets. Every machine-named member ends in its TRUE hex offset (`WorldTransform_7C`,
`vftable_TESFullName_30`, `_pad_108`), so sorting by that suffix tiles the struct. Types, lengths
and names are intact; only the placement is wrong. (The suffix regex is the one
layout_diff.auto_extract_score uses to recognise machine-generated names.)

This is an existing-types-only repair, independent of CommonLib (CommonLib-driven replacement is
the `types` phase of apply_enrich); it covers the structs that phase cannot, e.g. classes CommonLib
does not define. The result for one struct is a placement plan the driver applies to a temporary
same-length structure and swaps in with replaceWith (atomic: a failure leaves the original).

Rules:
  * a member whose name ends in `_<hex>` is placed at that offset; `_pad_*` blocks are trimmed to
    the free runs left after everything else is placed;
  * members WITHOUT such a suffix were hand-added at their true offset and stay;
  * a suffixed member that duplicates a hand-added one (same offset and length) or lies inside it
    is the stale twin and is dropped; a stale duplicate hand-added name (one copy overlaps, one is
    clean) drops the overlapping copy; the drops are returned as notes for the struct description;
  * zero-length member types cannot be placed and are omitted with a note;
  * any remaining overlap, a member past the end, a `_base` member, a packed struct, fewer than 4
    placed members or coverage under `min_coverage` refuses the struct (reason returned).
Vtable structs (`*_vtbl`, `*_vtbl_<N>`, `*__VFTable`) use slot indices as suffixes and Windows SDK
types use numeric suffixes: both are excluded by name.
"""
import re
from collections import Counter

AUTO_SUFFIX = re.compile(r'_([0-9A-Fa-f]{1,4})$')    # same shape as layout_diff._AUTO_SUFFIX
_VTABLE_NAME = re.compile(r'(_vtbl(_\d+)?(\.conflict\d*)?$|__VFTable)')
MIN_COVERAGE = 0.6


def is_candidate_name(name):
    """False for vtable structs, `.conflict` duplicates and SDK / anonymous names."""
    if _VTABLE_NAME.search(name) or '.conflict' in name:
        return False
    return not name.startswith(('_', 'tag', 'anonymous'))


def _is_pad(name):
    return name.startswith('_pad')


def plan_unscramble(name, length, comps, packed=False, min_coverage=MIN_COVERAGE):
    """Plan the repair of one struct.

    comps: [{'offset', 'length', 'name', 'defined'}] for every component, `defined` False for
    `undefined` filler. Returns (plan, notes, reason): plan is a list of
    {'offset', 'length', 'name', 'src'} sorted by offset (`src` = index into comps, or None for a
    new padding block); plan is None when there is nothing to do or the struct is refused, with
    `reason` saying which ('' when nothing to do)."""
    if packed or not is_candidate_name(name):
        return None, [], ''
    real = [(i, c) for i, c in enumerate(comps) if c['defined']]
    if len(real) < 4:
        return None, [], ''
    members = []   # [offset, comp index, kind, length, name]
    suffixed = 0
    for i, c in real:
        n = c['name'] or ''
        if n.startswith('_base'):
            return None, [], ''
        m = AUTO_SUFFIX.search(n)
        if m:
            members.append([int(m.group(1), 16), i, 'pad' if _is_pad(n) else 'sfx', c['length'], n])
            suffixed += 1
        else:
            members.append([c['offset'], i, 'manual', c['length'], n])
    if suffixed < 4:
        return None, [], ''
    if not any(k != 'manual' and off != comps[i]['offset'] for off, i, k, _l, _n in members):
        return None, [], ''           # already in place

    notes = []
    kept = []
    for m in members:
        if m[3] <= 0:
            notes.append('omitted %s (zero-length type) at 0x%X' % (m[4], m[0]))
        else:
            kept.append(m)
    manual = [m for m in kept if m[2] == 'manual']
    for mo, _mi, _mk, ml, mn in manual:
        for m in list(kept):
            if m[2] == 'sfx' and m[0] == mo and m[3] == ml:
                kept.remove(m)
                notes.append('dropped scrambled twin %s (kept hand-added %s) at 0x%X' % (m[4], mn, mo))
    for mo, _mi, _mk, ml, mn in [m for m in kept if m[2] == 'manual']:
        for m in list(kept):
            if m[2] == 'sfx' and mo <= m[0] and m[0] + m[3] <= mo + ml:
                kept.remove(m)
                notes.append('dropped scrambled %s (inside hand-added %s) at 0x%X' % (m[4], mn, m[0]))

    def overlaps(a, b):
        return a[0] < b[0] + b[3] and b[0] < a[0] + a[3]

    solid = [m for m in kept if m[2] != 'pad']
    counts = Counter(m[4] for m in solid if m[2] == 'manual')
    for nm, n in counts.items():
        if n < 2:
            continue
        inst = [m for m in solid if m[2] == 'manual' and m[4] == nm]
        clean = [m for m in inst if not any(o is not m and overlaps(m, o) for o in solid)]
        if clean:
            for m in inst:
                if m not in clean:
                    kept.remove(m)
                    solid.remove(m)
                    notes.append('dropped stale duplicate %s at 0x%X' % (nm, m[0]))
    solid.sort(key=lambda m: m[0])
    for a, b in zip(solid, solid[1:]):
        if b[0] < a[0] + a[3]:
            return None, notes, 'overlap: %s [0x%X+%d] vs %s [0x%X+%d]' % (a[4], a[0], a[3], b[4], b[0], b[3])
    plan = [{'offset': m[0], 'length': m[3], 'name': m[4], 'src': m[1]} for m in solid]
    for m in [x for x in kept if x[2] == 'pad']:
        free = [(m[0], m[0] + m[3])]
        for o in solid:
            a0, a1 = o[0], o[0] + o[3]
            nxt = []
            for f0, f1 in free:
                if a1 <= f0 or a0 >= f1:
                    nxt.append((f0, f1))
                else:
                    if f0 < a0:
                        nxt.append((f0, a0))
                    if a1 < f1:
                        nxt.append((a1, f1))
            free = nxt
        for f0, f1 in free:
            plan.append({'offset': f0, 'length': f1 - f0, 'name': '_pad_%X' % f0, 'src': None})
    plan.sort(key=lambda p: p['offset'])
    pos = covered = 0
    for p in plan:
        if p['offset'] < pos or p['offset'] + p['length'] > length:
            return None, notes, 'member past end or overlap after trimming: %s @0x%X+%d' % (p['name'], p['offset'], p['length'])
        pos = p['offset'] + p['length']
        covered += p['length']
    if covered < min_coverage * length:
        return None, notes, 'low coverage %.2f' % (covered / float(length))
    return plan, notes, ''


def verify_plan(plan, got):
    """After the swap: every planned member sits at its planned offset. `got` {name: offset}."""
    return all(got.get(p['name']) == p['offset'] for p in plan)


def vtable_stores_consistent(vftable_member_offsets, stored_offsets):
    """Independent evidence for a polymorphic struct: the offsets where the constructor stores the
    class's own vtable pointers must all be `vftable_*` member offsets (offset 0 is implied by the
    primary vtable). Returns 'pass' (no contradiction and at least one non-zero confirmation),
    'n/a' (nothing to compare) or 'fail'."""
    exp = set(vftable_member_offsets)
    got = set(stored_offsets)
    if not got or not (exp - {0}):
        return 'n/a'
    if got - exp - {0}:
        return 'fail'
    return 'pass' if (got & exp) - {0} else 'n/a'
