"""Pure (Ghidra-free) logic for naming the functions around a class's vtable.

Everything here is derived from the binary alone (RTTI class names, the vtable symbol,
and the shape of the code that stores that vtable), so it applies to classes CommonLib
does not know, and it is the single definition of these rules (the driver is
commonlibvr/apply_vtable_roles.py; recover_rtti_vtables.py reuses `is_deleting_wrapper`).

Roles, for a class C with primary vtable V and object size S:

  dtor_deleting  slot 0 of V. `TEST reg,1` (delete flag), `MOV EDX,S` and a free call. Often
                 has the real destructor inlined (hence the larger size limit).
  ~C             the real destructor: the wrapper's first call target when that function
                 stores V into `this` first (it poisons the vtable before tearing down).
  CreateClone    slot 23 of a NiObject-derived class when it is this class's own function.
  Create         a function that allocates S bytes (`MOV E[DC]X,S`) and stores V.
  ctor           the one non-allocating function that stores V into `this` early.

False-positive rules:
  * the real destructor also stores V, so wrapper callees are never constructors;
  * a destructor that ends in a tail `JMP` to its base destructor has no CALL, so jumps
    are inspected as well as calls;
  * static initialisers (`atexit`, global registration) reference V but never use `this`;
  * slot-0 functions and anything shaped like a deleting wrapper are not Create/ctor;
  * a function shared by several vtables' slot 0 (or slot 23) belongs to none of them.

An instruction is passed as `(text, refs, flows)`: its disassembly text, the addresses it
references, and the callee names of its call/jump flow targets (None for unnamed ones).
"""
import re

# Names a free routine can carry. The sweep renames the thunk and its target.
FREE_NAMES = frozenset(('NiMemFree', 'FreeMemory'))

WRAPPER_PLAIN_MAX = 80       # bytes: wrapper that calls an out-of-line real destructor
WRAPPER_INLINE_MAX = 700     # bytes: wrapper with the destructor body inlined
CTOR_SCAN = 40               # instructions inspected for the vtable store
CTOR_MAX_BYTES = 400         # larger functions are not constructors
PLACEHOLDER_RE = re.compile(
    r'^(sub_|FUN_|thunk_FUN_|Func\d*(_[0-9A-Fa-f]+)?$|dtor(_[0-9A-Fa-f]+)?$|Ctor$|ctor$|'
    r'CreateClone_[0-9A-Fa-f]+$|Create_[0-9A-Fa-f]+$|~NiRefObject$|\?\?_G|.*scalar_deleting|.*__dtor$|'
    r'.*_ctor$|.*Delete_[0-9A-Fa-f]+$)')

_NORM_RE = re.compile(r'[^A-Za-z0-9]')
_ODD_CLASS_RE = re.compile(r'::|<|>| |,|\*')


def norm(s):
    return _NORM_RE.sub('', s)


def is_placeholder_name(name):
    """True when `name` is an auto-generated or known-wrong label that may be replaced."""
    return bool(name) and bool(PLACEHOLDER_RE.search(name))


def rtti_key(raw):
    """(normalised class key, is_template) from an RTTI type-descriptor name such as
    `.?AVBSTriShape@@` or `.?AV?$NiPointer@VNiNode@@@@` (templates are truncated to their base)."""
    n = raw or ''
    for pre in ('.?AV', '.?AU'):
        if n.startswith(pre):
            n = n[len(pre):]
    if n.startswith('?$'):
        return norm(n[2:].split('@')[0]), True
    parts = [p for p in n.split('@') if p]
    return norm(''.join(reversed(parts))), False


def rtti_matches(raw, cls):
    """Does the label class `cls` (any spelling) denote the RTTI type `raw`?"""
    key, is_template = rtti_key(raw)
    c = norm(cls)
    return c.startswith(key) if is_template else c == key


def pick_class_name(raw, names):
    """The usable class spelling among `names` (VTABLE_ label spellings of one vtable) that
    matches the RTTI name and has no namespace/template punctuation; None if there is none."""
    good = [n for n in names if rtti_matches(raw, n)]
    clean = [n for n in good if not _ODD_CLASS_RE.search(n)]
    return clean[0] if clean else None


def is_niobject(base_names):
    """base_names: RTTI type-descriptor names of the class and its bases."""
    return any(b.startswith('.?AVNiObject@@') for b in base_names)


def _mnemonic(text):
    return text.split(' ', 1)[0]


def free_size(insn_texts):
    """The object size loaded into EDX for the free call (`MOV EDX,0x..`), or None."""
    size = None
    for t in insn_texts:
        if t.startswith('MOV EDX,0x'):
            size = int(t.split('0x')[1], 16)
    return size


def is_deleting_wrapper(insns, size_bytes):
    """Shape test for a (scalar) deleting destructor. `insns` is a list of (text, refs, flows);
    `size_bytes` is the function's byte length."""
    if size_bytes > WRAPPER_INLINE_MAX:
        return False
    texts = [i[0] for i in insns]
    if not any(t.startswith('TEST ') and t.endswith(',0x1') for t in texts):
        return False
    if free_size(texts) is None:
        return False
    if size_bytes <= WRAPPER_PLAIN_MAX:
        return sum(1 for t in texts if _mnemonic(t) == 'CALL') >= 2
    return any(f in FREE_NAMES for i in insns for f in i[2])


def _calls_forbidden(insns):
    for _t, _r, flows in insns:
        for name in flows:
            if name and (name.startswith('~') or 'dtor' in name or 'atexit' in name.lower()
                         or name in FREE_NAMES):
                return True
    return False


def strict_ctor(insns, vtable_addr):
    """True when the function stores `vtable_addr` into `this` (RCX or a register copy of it)
    within the first CTOR_SCAN instructions, calls no destructor/free/atexit (including by
    tail jump)."""
    if _calls_forbidden(insns):
        return False
    regs = {'RCX', 'ECX'}
    scan = insns[:CTOR_SCAN]
    for k, (text, refs, _flows) in enumerate(scan):
        m = re.match(r'MOV (R[A-Z0-9]+),RCX$', text)
        if m:
            regs.add(m.group(1))
        if text.startswith('LEA') and vtable_addr in refs:
            dest = text.split()[1].split(',')[0]
            for nxt_text, _r, _f in insns[k + 1:k + 7]:
                m2 = re.match(r'MOV qword ptr \[(R[A-Z0-9]+)(?: \+ 0x[0-9a-fA-F]+)?\],' + re.escape(dest) + '$', nxt_text)
                if m2 and m2.group(1) in regs:
                    return True
            return False
    return False


def allocates(insns, size):
    """Does the function pass the object size to the allocator (`MOV EDX,S` / `MOV ECX,S`)?"""
    pat = re.compile(r'MOV E[DC]X,0x%X$' % size)
    return any(pat.match(i[0]) for i in insns)


def plan_class_roles(vtable_addr, vtable_refs, wrapper, slot23, slot23_owners, wrapper_callees, size,
                     niobject, slot0_functions):
    """Decide the role of each function that references the class's vtable.

    vtable_addr     address of the class's primary vtable V
    vtable_refs     {entry: {'insns': [...], 'bytes': int, 'name': str}}  functions with a LEA of V
    wrapper         entry of the slot-0 function
    slot23          entry of slot 23 (or None)
    slot23_owners   number of vtables whose slot 23 is that function
    wrapper_callees set of entries the wrapper calls/jumps to
    size            object size S (from the wrapper's free call)
    niobject        class derives from NiObject
    slot0_functions set of entries that are slot 0 of any vtable

    Returns {entry: role} with role in {'CreateClone', 'Create', 'ctor'}, and a stats dict of the
    reasons for skipping."""
    stats = {'several allocating': 0, 'several ctors': 0, 'looks like wrapper': 0, 'not a ctor': 0}
    cand = {}
    for entry, f in vtable_refs.items():
        if entry == wrapper or entry in wrapper_callees or entry in slot0_functions:
            continue
        if f['name'].startswith('~') or f['name'] == 'dtor_deleting':
            continue
        if any(t.startswith('TEST ') and t.endswith(',0x1') for t, _r, _f in f['insns']):
            stats['looks like wrapper'] += 1
            continue
        cand[entry] = f
    roles = {}
    clone = slot23 if (niobject and slot23 in cand and slot23_owners == 1) else None
    if clone is not None:
        roles[clone] = 'CreateClone'
    alloc, ctor = [], []
    for entry, f in cand.items():
        if entry == clone or f['bytes'] > CTOR_MAX_BYTES:
            continue
        if allocates(f['insns'], size):
            alloc.append(entry)
        elif strict_ctor(f['insns'], vtable_addr):
            ctor.append(entry)
        else:
            stats['not a ctor'] += 1
    if len(alloc) == 1:
        roles[alloc[0]] = 'Create'
    elif len(alloc) > 1:
        stats['several allocating'] += 1
    if len(ctor) == 1:
        roles[ctor[0]] = 'ctor'
    elif len(ctor) > 1:
        stats['several ctors'] += 1
    return roles, stats


def real_destructor(wrapper_first_callee_insns, vtable_addr):
    """The wrapper's first call target is the real destructor when it stores the class's own
    vtable within its first 12 instructions (it poisons the vtable before tearing down)."""
    for text, refs, _f in wrapper_first_callee_insns[:12]:
        if text.startswith('LEA') and vtable_addr in refs:
            return True
    return False


def flat_name(cls, role):
    """Flat `Class::Role` name; apply_enrich's `classes` phase reparents it into the class
    namespace and the `thiscall` phase then types `this`, so no namespace/signature work is
    duplicated here."""
    return '%s::%s' % (cls, ('~' + cls) if role == 'dtor' else role)


def label_class(label):
    """Class spelling inside a `VTABLE_<Class>[_0]` label, or None for a non-VTABLE_ name."""
    if not label.startswith('VTABLE_'):
        return None
    c = label[len('VTABLE_'):]
    return c[:-2] if c.endswith('_0') else c


def stale_vtable_labels(labels, real_addrs):
    """Stale duplicate `VTABLE_` labels: ones NOT at an RTTI vtable although the same class
    already has a label at a real vtable (seeded imports carry labels at wrong addresses; the
    correct label exists elsewhere, so the stray one only misleads).

    labels     {address: [label names]}
    real_addrs set of addresses that are RTTI vtables
    Returns [(address, label)]. Labels of classes with no real vtable are left alone: they
    may belong to a vtable without RTTI."""
    real_classes = set()
    for addr, names in labels.items():
        if addr in real_addrs:
            for n in names:
                c = label_class(n)
                if c:
                    real_classes.add(norm(c))
    out = []
    for addr, names in labels.items():
        if addr in real_addrs:
            continue
        for n in names:
            c = label_class(n)
            if c and norm(c) in real_classes:
                out.append((addr, n))
    return out
