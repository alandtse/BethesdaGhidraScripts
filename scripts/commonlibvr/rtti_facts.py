"""Shared RTTI facts for the vtable-driven phases (`roles`, `rebase`).

One definition of the per-class facts read from a program's RTTI: the class hierarchy of a
vtable, the cached function instruction facts, and the class table (direct parent and
allocation size of every class with a primary vtable). Class discovery comes from
recover_rtti_vtables.py; the shape rules live in core/plans/vtable_roles_plan.py.
"""
import importlib.util as _ilu
import os
import struct
import sys

from clvr_config import SCRIPT_DIR

sys.path.insert(0, os.path.join(os.path.dirname(SCRIPT_DIR), 'core'))
from plans import vtable_roles_plan as vr  # noqa: E402

_rspec = _ilu.spec_from_file_location('clvr_recover_rtti', os.path.join(SCRIPT_DIR, 'recover_rtti_vtables.py'))
rr = _ilu.module_from_spec(_rspec)
_rspec.loader.exec_module(rr)


def u32(blocks, a):
    blk = rr._block_of(blocks, a)
    return struct.unpack_from('<I', blk[1], a - blk[0])[0] if blk else None


def u64(blocks, a):
    blk = rr._block_of(blocks, a)
    return struct.unpack_from('<Q', blk[1], a - blk[0])[0] if blk else None


def base_names(blocks, image_base, vaddr):
    """RTTI type-descriptor names of the class and all its bases (COL -> class hierarchy)."""
    col = u64(blocks, vaddr - 8)
    chd = u32(blocks, col + 0x10) if col else None
    if chd is None:
        return []
    chd += image_base
    n = u32(blocks, chd + 8) or 0
    arr = image_base + (u32(blocks, chd + 0x0C) or 0)
    out = []
    for i in range(min(n, 40)):
        bcd = image_base + (u32(blocks, arr + 4 * i) or 0)
        td = image_base + (u32(blocks, bcd) or 0)
        out.append(rr._cstring(blocks, td + 0x10) or '')
    return out


class Facts(object):
    """Function facts for the planner, built on demand and cached per entry."""

    def __init__(self, cp):
        self.cp = cp
        self.fm = cp.getFunctionManager()
        self.listing = cp.getListing()
        self.cache = {}

    def func_name(self, addr):
        f = self.fm.getFunctionAt(addr)
        return f.getName() if f is not None else None

    def of(self, f):
        key = f.getEntryPoint().getOffset()
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        insns = []
        entries = set()
        for ins in self.listing.getInstructions(f.getBody(), True):
            text = str(ins)
            refs = [r.getToAddress().getOffset() for r in ins.getReferencesFrom()]
            flows = []
            if text.startswith(('CALL', 'JMP')):
                for fl in (ins.getFlows() or []):
                    flows.append(self.func_name(fl))
                    tf = self.fm.getFunctionAt(fl)
                    if tf is not None:
                        entries.add(tf.getEntryPoint().getOffset())
            insns.append((text, refs, flows))
        hit = {'entry': key, 'func': f, 'insns': insns, 'bytes': int(f.getBody().getNumAddresses()),
               'name': f.getName(), 'callees': entries}
        self.cache[key] = hit
        return hit


def class_table(cp, monitor):
    """{class name: {'parent': direct base class name or None, 'alloc': object size or None}}
    for every class with a primary RTTI vtable and a usable `VTABLE_<Class>` label. `alloc` is the
    size the deleting destructor frees (None when slot 0 is not a deleting wrapper)."""
    image_base = cp.getImageBase().getOffset()
    blocks = rr._cache_blocks(cp, monitor)
    col_meta, col_name = rr._collect_cols(blocks, image_base, monitor)
    by_class = rr._map_vtables(blocks, col_meta, col_name, monitor)
    st = cp.getSymbolTable()
    af = cp.getAddressFactory().getDefaultAddressSpace()
    facts = Facts(cp)
    primaries = [(vaddr, raw) for grp in by_class.values() for (vaddr, sub_off, raw) in grp if sub_off == 0]
    raw_to_cls = {}
    for vaddr, raw in primaries:
        labels = [s.getName()[len('VTABLE_'):] for s in st.getSymbols(af.getAddress(vaddr))
                  if s.getName().startswith('VTABLE_')]
        cls = vr.pick_class_name(raw, [n[:-2] if n.endswith('_0') else n for n in labels])
        if cls is not None:
            raw_to_cls[raw] = cls
    table = {}
    for vaddr, raw in primaries:
        monitor.checkCancelled()
        cls = raw_to_cls.get(raw)
        if cls is None or cls in table:
            continue
        bases = base_names(blocks, image_base, vaddr)
        parent = raw_to_cls.get(bases[1]) if len(bases) > 1 else None
        alloc = None
        slot0 = u64(blocks, vaddr)
        wf = cp.getFunctionManager().getFunctionAt(af.getAddress(slot0)) if slot0 else None
        if wf is not None:
            w = facts.of(wf)
            if vr.is_deleting_wrapper(w['insns'], w['bytes']):
                alloc = vr.free_size([i[0] for i in w['insns']])
        table[cls] = {'parent': parent, 'alloc': alloc}
    return table
