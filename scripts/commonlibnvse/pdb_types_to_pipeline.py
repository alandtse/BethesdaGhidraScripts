#!/usr/bin/env python3
"""Convert Fallout_Debug_types.json (parsed PDB pretty dump) into the
struct dict shape that ghidra_import_gen.generate_script consumes.

Source: ``parse_pdb_pretty.py`` produced
``{class_name: {size, fields: [{off, size, type, name}, ...]}}``.

Target shape (per struct entry):
    {
      'name':       str,
      'full_name':  str,
      'size':       int,
      'category':   '/xNVSE/PDB',     # bucket PDB-derived types separately
      'fields':     [
        {'name': str, 'offset': int, 'size': int, 'type': str_pipeline},
        ...
      ],
      'bases':      [],               # PDB pretty dump doesn't surface
      'pdb_bases':  [],               # base classes cleanly
      'has_vtable': False,
      'vmethods':   {},
      'methods':    {},
      '_overload_aliases': {},
    }

Type string conversion (PDB -> pipeline):
    unsigned char/char/UCHAR    -> u8/i8
    unsigned short/short        -> u16/i16
    unsigned long/long/int/UINT -> u32/i32
    unsigned __int64/__int64    -> u64/i64
    float                       -> f32
    double                      -> f64
    bool                        -> bool
    <anything>*                 -> ptr  (32-bit pointers in FNV)
    <type>[N]                   -> arr:<type>:N
    <known struct name>         -> struct:<name>  (if matches another entry)
    <unknown>                   -> bytes:<size>   (raw padding fallback)

Public API:
    convert_pdb_types(json_path) -> dict   # structs dict, ready to merge
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Set


# Primitive PDB type names (normalized to lowercase) -> pipeline type
_PRIMITIVES = {
    'bool':                'bool',
    'char':                'i8',
    'signed char':         'i8',
    'unsigned char':       'u8',
    'uchar':               'u8',
    'short':               'i16',
    'short int':           'i16',
    'unsigned short':      'u16',
    'unsigned short int':  'u16',
    'ushort':              'u16',
    'wchar_t':             'u16',
    'int':                 'i32',
    'long':                'i32',
    'long int':            'i32',
    'unsigned int':        'u32',
    'unsigned long':       'u32',
    'unsigned long int':   'u32',
    'uint':                'u32',
    'ulong':               'u32',
    'dword':               'u32',
    'long long':           'i64',
    '__int64':             'i64',
    'unsigned long long':  'u64',
    'unsigned __int64':    'u64',
    'qword':               'u64',
    'float':               'f32',
    'double':              'f64',
    'long double':         'f64',
    'void':                'void',
    # Common Windows typedefs
    'BYTE':  'u8',
    'WORD':  'u16',
    'DWORD': 'u32',
    'HANDLE': 'ptr',
    'HRESULT': 'i32',
    'BOOL':  'i32',
    'LONG':  'i32',
    'ULONG': 'u32',
    'INT':   'i32',
    'UINT':  'u32',
    'SHORT': 'i16',
    'USHORT': 'u16',
    'CHAR': 'i8',
    'UCHAR': 'u8',
    'PVOID': 'ptr',
    'LPVOID': 'ptr',
    'LPCSTR': 'ptr',
    'LPSTR': 'ptr',
    'LPCWSTR': 'ptr',
    'LPWSTR': 'ptr',
    'SIZE_T': 'u32',
    'INT_PTR': 'i32',
    'UINT_PTR': 'u32',
    'LONG_PTR': 'i32',
    'ULONG_PTR': 'u32',
}


# Sizes for primitives, used when emitting bytes:N fallback
_PRIMITIVE_SIZES = {
    'bool': 1, 'i8': 1, 'u8': 1,
    'i16': 2, 'u16': 2,
    'i32': 4, 'u32': 4, 'f32': 4,
    'i64': 8, 'u64': 8, 'f64': 8,
    'ptr': 4,  # 32-bit FNV
    'void': 0,
}


_ARRAY_RE = re.compile(r'^(.*?)\[(\d+)\]\s*$')


def _strip_qualifiers(t: str) -> str:
    t = t.strip()
    for q in ('const ', 'volatile ', '__unaligned ', '__restrict '):
        while t.startswith(q):
            t = t[len(q):]
    return t.strip()


def _convert_one(type_str: str, field_size: int, known_structs: Set[str]) -> str:
    """Convert a single PDB type string to pipeline format."""
    t = _strip_qualifiers(type_str)
    if not t:
        return f'bytes:{field_size}' if field_size > 0 else 'u8'

    # Pointer / reference -> ptr (always 4 bytes in 32-bit FNV)
    if t.endswith('*') or t.endswith('&'):
        return 'ptr'

    # Function-pointer-ish (T (*)(args))
    if '(*)' in t or '(__cdecl*' in t or '(__thiscall*' in t or '(__stdcall*' in t:
        return 'ptr'

    # Array: ``<inner>[N]``
    m = _ARRAY_RE.match(t)
    if m:
        inner = m.group(1).rstrip()
        count = int(m.group(2))
        elem_size = field_size // count if count > 0 else 0
        inner_pipeline = _convert_one(inner, elem_size, known_structs)
        # arr:T:N expects T to be a simple token (no further :)
        if ':' in inner_pipeline:
            # Inner is itself complex (e.g. bytes:8) -- fall back to raw bytes
            return f'bytes:{field_size}'
        return f'arr:{inner_pipeline}:{count}'

    # Primitive match (case-sensitive first, then lowered)
    if t in _PRIMITIVES:
        return _PRIMITIVES[t]
    lowered = t.lower()
    if lowered in _PRIMITIVES:
        return _PRIMITIVES[lowered]

    # Bitfield (PDB pretty dump emits ``unsigned long Foo : 32``);
    # handled in caller; here treat as the underlying primitive.

    # Anonymous/nested type -> raw bytes
    if '<unnamed' in t or '<anonymous' in t or '::<unnamed-' in t:
        return f'bytes:{field_size}' if field_size > 0 else 'u8'

    # Known struct reference?
    if t in known_structs:
        return f'struct:{t}'
    # Drop templated suffix (Foo<T> -> Foo) for matching
    base = t.split('<', 1)[0].rstrip()
    if base in known_structs:
        return f'struct:{t}'

    # Enum-ish: typeless lookup -> fall back to raw bytes of declared size
    return f'bytes:{field_size}' if field_size > 0 else 'u8'


def convert_pdb_types(json_path: Path) -> Dict[str, dict]:
    """Convert a parsed pretty-dump types JSON to a structs dict ready to
    merge with the clang-AST-derived structs in parse_commonlib_types.py.

    Skips entries with size==0 or no fields, and entries whose names
    look like compiler-internal anonymous tags (``<unnamed-tag>``).
    """
    data = json.loads(json_path.read_text(encoding='utf-8'))

    # First pass: collect names of structs we'll emit, so type strings can
    # reference them via ``struct:Name``.
    known_structs: Set[str] = set()
    for cls, entry in data.items():
        if entry.get('size', 0) == 0:
            continue
        if not entry.get('fields'):
            continue
        if '<unnamed' in cls or '<anonymous' in cls:
            continue
        known_structs.add(cls)
        # Also expose the bare class name (no template args) for matching
        bare = cls.split('<', 1)[0].rstrip()
        known_structs.add(bare)

    structs: Dict[str, dict] = {}
    n_fields_total = 0
    n_skipped = 0
    for cls, entry in data.items():
        if entry.get('size', 0) == 0 or not entry.get('fields'):
            n_skipped += 1
            continue
        if '<unnamed' in cls or '<anonymous' in cls:
            n_skipped += 1
            continue
        size = entry['size']
        out_fields = []
        for fld in entry['fields']:
            fname = fld['name']
            fsize = fld.get('size', 0)
            # PDB pretty dump emits arrays as ``unsigned char Data4[8]``
            # i.e. the [N] dimension is in the NAME, not the type.  Detect
            # and rewrap so we emit `arr:T:N` instead of `T` with [N] in
            # the field name.
            am = re.match(r'^(\w+)\[(\d+)\]$', fname)
            if am:
                base_name = am.group(1)
                count = int(am.group(2))
                inner_type = _convert_one(fld['type'],
                                          fsize // count if count > 0 else 0,
                                          known_structs)
                if count > 0 and ':' not in inner_type:
                    ftype = f'arr:{inner_type}:{count}'
                else:
                    ftype = f'bytes:{fsize}' if fsize > 0 else 'u8'
                fname = base_name
            else:
                ftype = _convert_one(fld['type'], fsize, known_structs)
            out_fields.append({
                'name':   fname,
                'offset': fld['off'],
                'size':   fsize,
                'type':   ftype,
            })
            n_fields_total += 1
        structs[cls] = {
            'name':              cls.split('::')[-1],
            'full_name':         cls,
            'size':              size,
            'category':          '/xNVSE/PDB',
            'fields':            out_fields,
            'bases':             [],
            'pdb_bases':         [],
            'has_vtable':        False,
            'vmethods':          {},
            'methods':           {},
            '_overload_aliases': {},
        }
    return structs, n_skipped, n_fields_total


if __name__ == '__main__':
    import sys
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(r'C:\GhidraProjects\scripts\Fallout_Debug_types.json')
    structs, skipped, n_fields = convert_pdb_types(p)
    print(f'  Converted PDB structs: {len(structs):,}')
    print(f'  Total fields:          {n_fields:,}')
    print(f'  Skipped (empty/anon):  {skipped:,}')
