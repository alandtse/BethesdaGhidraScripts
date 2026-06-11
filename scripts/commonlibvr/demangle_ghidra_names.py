"""Restore proper C++ names for Ghidra's `_`-mangled template types.

The import names template instantiations with the IDA-style mangling `<>,:* &` -> `_`
(`NiPointer_NiAVObject_`, `BSTArray_BGSPerk__`). We shouldn't carry that -- our type
names should read like the CommonLib C++ they came from.

De-mangling a name in isolation is lossy (a trailing `_` is `>` or `*>`), so instead we
go the RELIABLE direction: take CommonLib's PROPER spellings (the `<>`-form types in
commonlib_typed_members.csv), MANGLE each the same way the import does, and match that
against Ghidra's type names. Every match gets renamed back to the proper spelling -- or,
if a proper-named type already exists (the import emitted both forms), MERGED into it
with replaceDataType so references converge.

NON-DESTRUCTIVE: only touches /types.h types whose name is exactly a known mangled form;
rename is a pure relabel, merge rewires references to an existing identical type. Dry-run
default (reports rename/merge counts + samples); CLVR_DEMANGLE=go to apply. replaceDataType
is slow (rescans functions) -- merges run in batched transactions. Run per program.
"""
import csv
import os

MEMBERS_CSV = os.environ.get(
    'CLVR_TYPED_MEMBERS_CSV',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\commonlib_typed_members.csv')
APPLY = os.environ.get('CLVR_DEMANGLE', 'dry').lower() == 'go'
BATCH = int(os.environ.get('CLVR_DEMANGLE_BATCH', '40') or 40)


def mangle(proper):
    """The import's mangling: drop RE::, then `<>,:* &` -> `_` (so a CommonLib proper
    spelling maps to the Ghidra type name the import created for it)."""
    out = proper.replace('RE::', '')
    for ch in '<>,:* &':
        out = out.replace(ch, '_')
    return out


def _proper_names():
    """Collect CommonLib's proper template spellings (the `<>`-form member types)."""
    propers = set()
    if not os.path.exists(MEMBERS_CSV):
        return propers
    for r in csv.DictReader(open(MEMBERS_CSV)):
        t = r['cpp_type'].strip()
        while t.endswith('*'):
            t = t[:-1].strip()
        if '<' in t:
            propers.add(t.replace('RE::', ''))
    return propers


def run():
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()

    # mangled Ghidra name -> proper CommonLib spelling
    mmap = {}
    for proper in _proper_names():
        m = mangle(proper)
        if m != proper:
            mmap_key = m
            mmap_val = proper
            mmap_prev = mmap_key in mmap and mmap_val != mmap[mmap_key]
            if not mmap_prev:                          # ignore ambiguous mangle collisions
                mmap[mmap_key] = mmap_val

    types_by_name = {}
    for dt in dtm.getAllDataTypes():
        if 'types.h' in str(dt.getCategoryPath()):
            types_by_name.setdefault(dt.getName(), dt)

    renames = []        # (dt, proper)
    merges = []         # (dt, keeper)
    for name, dt in list(types_by_name.items()):
        proper = mmap.get(name)
        if not proper or proper == name:
            continue
        keeper = types_by_name.get(proper)
        if keeper is not None and keeper is not dt:
            merges.append((dt, keeper))                # proper already exists -> merge
        else:
            renames.append((dt, proper))

    print('demangle names (%s): %d mangled types matched -> %d rename, %d merge'
          % (cp.getName(), len(renames) + len(merges), len(renames), len(merges)))
    for dt, proper in renames[:12]:
        print('   rename %s -> %s' % (dt.getName(), proper))
    for dt, keeper in merges[:6]:
        print('   merge  %s -> %s' % (dt.getName(), keeper.getName()))

    if not APPLY:
        print('  set CLVR_DEMANGLE=go to apply.')
        return

    done_r = err = 0
    tx = cp.startTransaction('demangle rename')
    try:
        for dt, proper in renames:
            try:
                dt.setName(proper)
                done_r += 1
            except Exception:
                err += 1
    finally:
        cp.endTransaction(tx, True)
    done_m = 0
    for i in range(0, len(merges), BATCH):
        tx = cp.startTransaction('demangle merge %d' % (i // BATCH))
        try:
            for dt, keeper in merges[i:i + BATCH]:
                try:
                    dtm.replaceDataType(dt, keeper, False)
                    done_m += 1
                except Exception:
                    err += 1
        finally:
            cp.endTransaction(tx, True)
    print('  APPLIED: %d renamed, %d merged, %d errors' % (done_r, done_m, err))


run()
