"""Pure (Ghidra-free) planner for rebuilding a VR flat struct on its RTTI parent.

A VR struct imported flat (no `_base`) used SE offsets for its own members, but a VR class
sits after a VR parent that is a different size, so every own member of the VR class is shifted
by the parent's size delta. The rebuild is: a `_base` member for the parent at offset 0, then
the SE class's own members (those past the SE parent) moved by that delta.

Inputs are plain dicts so the rule is testable without Ghidra:
  vr / se       {'alloc': object size from the deleting destructor, 'len': Ghidra struct length,
                 'comps': [(offset, length, name, type name)]}   (comps from SE only)
  vr_parent / se_parent   {'alloc': ...} of the direct RTTI parent
  parent_len    the Ghidra struct length of the VR parent type

A class whose VR parent is the same size as on SE needs no rebuild and is skipped.

Refusals (reason returned, plan None) are the conditions under which the arithmetic is not
trustworthy: unknown sizes, a parent whose Ghidra length is not its allocation size, a class whose
Ghidra length is not its allocation size, SE and VR growth that differ from the parent delta, or an
SE member that straddles the end of the SE parent.
"""
import re

_HEX_SUFFIX = re.compile(r'^(.*)_([0-9A-Fa-f]{1,4})$')


def strip_offset_suffix(name):
    """`WorldTransform_7C` -> `WorldTransform` (the suffix is the stale SE offset); padding and
    unsuffixed names are returned unchanged."""
    if not name or name.startswith('_pad'):
        return name
    m = _HEX_SUFFIX.match(name)
    return m.group(1) if m else name


def _hx(v):
    return hex(v) if isinstance(v, int) else str(v)


def plan_rebase(vr, se, vr_parent, se_parent, parent_len):
    """Plan one struct. Returns (plan, reason): plan is {'length', 'parent_len', 'delta',
    'members': [{'offset', 'length', 'name', 'type', 'se_offset'}]} or None with a reason."""
    if not vr or not se or not se.get('comps'):
        return None, 'missing info'
    cv, cs = vr.get('alloc'), se.get('alloc')
    pv, ps = (vr_parent or {}).get('alloc'), (se_parent or {}).get('alloc')
    if not parent_len or not pv or not ps or not cv or not cs:
        return None, 'size unresolved (parent len %s, alloc vr/se %s/%s, parent alloc vr/se %s/%s)' % (
            _hx(parent_len), _hx(cv), _hx(cs), _hx(pv), _hx(ps))
    if parent_len != pv:
        return None, 'VR parent Ghidra len %s != alloc %s' % (_hx(parent_len), _hx(pv))
    if vr.get('len') != cv:
        return None, 'VR Ghidra len %s != alloc %s' % (_hx(vr.get('len')), _hx(cv))
    if cv - cs != pv - ps:
        return None, 'delta mismatch (class %s, parent %s)' % (_hx(cv - cs), _hx(pv - ps))
    delta = pv - ps
    if delta == 0:
        return None, 'no shift (parent sizes equal): the flat layout is already right'
    comps = [c for c in se['comps'] if not (c[2] or '').startswith('_pad')]
    if any(off < ps < off + ln for off, ln, _n, _t in comps):
        return None, 'member straddles parent end'
    members = []
    for off, ln, name, tname in comps:
        if off < ps or off + ln > cs:
            continue
        members.append({'offset': off + delta, 'length': ln,
                        'name': strip_offset_suffix(name),
                        'type': tname, 'se_offset': off})
    members.sort(key=lambda m: m['offset'])
    for a, b in zip(members, members[1:]):
        if b['offset'] < a['offset'] + a['length']:
            return None, 'own members overlap after shift: %s / %s' % (a['name'], b['name'])
    return {'length': cv, 'parent_len': pv, 'delta': delta, 'members': members}, ''
