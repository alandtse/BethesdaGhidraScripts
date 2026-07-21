"""Restore proper C++ names for Ghidra's `_`-mangled types (templates AND nested types).

The import names types with the IDA-style mangling `<>,:* &` -> `_` and `::` -> `__`
(`NiPointer_NiAVObject_`, `BSTArray_BGSPerk__`, `TESObjectWEAP__Data`). We shouldn't
carry that -- our type names should read like the CommonLib C++ they came from
(`NiPointer<NiAVObject>`, `TESObjectWEAP::Data`). Covers both template instantiations
(header scan) and nested class/enum types (`Parent::Nested`, from the generated import's
qualified `struct:`/`enum:` references).

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
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clvr_config import IMPORT_PATH  # noqa: E402
import apply_plan  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core'))
from engine.tx import transaction  # noqa: E402

MEMBERS_CSV = os.environ.get(
    'CLVR_TYPED_MEMBERS_CSV',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\commonlib_typed_members.csv')
# Generated CommonLib import (parse_commonlib_types output): its type references carry the
# proper qualified names (struct:RE::A::B, enum:RE::A::B) for NESTED class/enum types --
# the names template-only harvesting misses. Used to converge `Parent__Nested` -> `Parent::Nested`.
# CLVR_IMPORT_PY is kept as a distinct override (defaulting to the shared IMPORT_PATH) for
# backward compatibility with anyone already setting it specifically for this script.
IMPORT_PY = os.environ.get('CLVR_IMPORT_PY', IMPORT_PATH)
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


def _scan_import_qualified(import_py):
    """Proper qualified names of NESTED class/enum types (`Parent::Nested`,
    `A::B::C`) harvested from the generated import's type references
    (`struct:RE::...`, `enum:RE::...`). Templates are covered separately; this adds the
    plain `::`-nested types so `TESObjectWEAP__Data` -> `TESObjectWEAP::Data` converges."""
    propers = set()
    if not os.path.exists(import_py):
        return propers
    try:
        text = open(import_py, encoding='utf-8', errors='replace').read()
    except Exception:
        return propers
    for q in re.findall(r'(?:struct|enum):RE::([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)', text):
        propers.add(q)
    return propers


def _proper_names():
    """CommonLib's proper spellings -- template instantiations (member types + header
    scan) AND nested class/enum types (from the generated import), so the de-mangle
    covers every mangled type, not just templates."""
    propers = set()
    if os.path.exists(MEMBERS_CSV):
        for r in csv.DictReader(open(MEMBERS_CSV)):
            t = r['cpp_type'].strip()
            while t.endswith('*'):
                t = t[:-1].strip()
            if '<' in t:
                propers.add(t.replace('RE::', ''))
    propers |= _scan_headers(RE_DIR)
    propers |= _scan_import_qualified(IMPORT_PY)
    return propers


def run():
    cp = currentProgram  # noqa: F821
    dtm = cp.getDataTypeManager()

    # mangled Ghidra name -> proper CommonLib spelling (pure logic in apply_plan)
    mmap = apply_plan.build_mangle_map(_proper_names())

    types_by_name = {}
    for dt in dtm.getAllDataTypes():
        if 'types.h' in str(dt.getCategoryPath()):
            types_by_name.setdefault(dt.getName(), dt)

    name_renames, name_merges = apply_plan.plan_demangle(mmap, types_by_name.keys())
    renames = [(types_by_name[n], proper) for n, proper in name_renames]           # (dt, proper)
    merges = [(types_by_name[n], types_by_name[proper]) for n, proper in name_merges]  # (dt, keeper)

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
    with transaction(cp, 'demangle rename'):
        for dt, proper in renames:
            try:
                dt.setName(proper)
                done_r += 1
            except Exception:
                err += 1
    done_m = 0
    for i in range(0, len(merges), BATCH):
        with transaction(cp, 'demangle merge %d' % (i // BATCH)):
            for dt, keeper in merges[i:i + BATCH]:
                try:
                    dtm.replaceDataType(dt, keeper, False)
                    done_m += 1
                except Exception:
                    err += 1
    print('  APPLIED: %d renamed, %d merged, %d errors' % (done_r, done_m, err))


run()
