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
import glob
import os
import re

MEMBERS_CSV = os.environ.get(
    'CLVR_TYPED_MEMBERS_CSV',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\commonlib_typed_members.csv')
RE_DIR = os.environ.get('CLVR_RE_DIR', r'E:\Documents\source\repos\CommonLibVR\include\RE')
APPLY = os.environ.get('CLVR_DEMANGLE', 'dry').lower() == 'go'
BATCH = int(os.environ.get('CLVR_DEMANGLE_BATCH', '40') or 40)

# engine template wrappers whose `Wrapper<...>` spellings the import mangles -- scanned
# from EVERY context (members, params, returns, nested), not just struct members.
_WRAPS = ('NiPointer', 'NiTSmartPointer', 'BSTSmartPointer', 'GPtr', 'BSTAutoPointer',
          'NiTPointer', 'BSTArray', 'NiTArray', 'BSTSmallArray', 'BSScrapArray',
          'BSSimpleList', 'BSTHashMap', 'BSTScatterTable', 'NiTPrimitiveArray', 'NiRect',
          'BSTSet', 'BSTTuple', 'BSTSingletonSDM', 'BSTStaticArray', 'BSTObjectArrayBase',
          'NiTObjectArray', 'BSTHashMap2', 'BSTBTreeNode')
_WRAP_RE = re.compile(r'\b(' + '|'.join(_WRAPS) + r')<')


def mangle(proper):
    """The import's mangling: drop RE::, then `<>,:* &` -> `_` (so a CommonLib proper
    spelling maps to the Ghidra type name the import created for it)."""
    out = proper.replace('RE::', '')
    for ch in '<>,:* &':
        out = out.replace(ch, '_')
    return out


def _scan_headers(re_dir):
    """Every `Wrapper<...>` template spelling in the headers, balanced-bracket matched
    so nested templates come out whole (BSTArray<NiPointer<NiAVObject>>)."""
    propers = set()
    for path in glob.glob(os.path.join(re_dir, '**', '*.h'), recursive=True):
        try:
            text = open(path, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for m in _WRAP_RE.finditer(text):
            j = m.end() - 1                            # at the '<'
            depth = 0
            while j < len(text):
                if text[j] == '<':
                    depth += 1
                elif text[j] == '>':
                    depth -= 1
                    if depth == 0:
                        break
                elif text[j] in ';{}\n' and depth == 1:
                    j = -1                             # malformed -> bail
                    break
                j += 1
            if j > 0 and depth == 0:
                spell = re.sub(r'\s+', ' ', text[m.start():j + 1]).replace('RE::', '').strip()
                propers.add(spell)
    return propers


def _proper_names():
    """CommonLib's proper template spellings -- from member types AND a full header scan
    (params/returns/nested), so the de-mangle covers every mangled type, not just
    members."""
    propers = set()
    if os.path.exists(MEMBERS_CSV):
        for r in csv.DictReader(open(MEMBERS_CSV)):
            t = r['cpp_type'].strip()
            while t.endswith('*'):
                t = t[:-1].strip()
            if '<' in t:
                propers.add(t.replace('RE::', ''))
    propers |= _scan_headers(RE_DIR)
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
