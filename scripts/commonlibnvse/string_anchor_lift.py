#!/usr/bin/env python3
"""Lift function names by string-anchoring across Xbox PDB ↔ PC FNV.exe.

Two complementary strategies:

  1. **Self-naming strings** -- many Bethesda functions log their own
     fully-qualified name as a string literal (e.g. ``"AbstractHeap::
     BaseAllocate: invalid handle"``).  For each PC FNV string that
     starts with or contains a known PDB function name pattern, find
     x86 xrefs to that string -- the function containing the xref is
     that named function.

  2. **Xbox/PC unique-string pairing** -- for strings appearing in
     EXACTLY one Xbox function (per PDB xref) AND EXACTLY one PC FNV
     function, name the PC function after its Xbox counterpart.
     (Stage 2 -- requires Xbox xref extraction, separate script.)

This script implements (1).  Output: ``string_anchor_names.csv`` with
``RVA|name|source_string`` per line; consumed by ``pdb_naming.py``.

Run:
    python string_anchor_lift.py \\
        <FalloutNV.exe> <fnv_pc_strings.txt> <pdb_function_names.txt> [out.csv]
"""
from __future__ import annotations

import re
import struct
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple


# ---------------------------------------------------------------------------
# PE parsing (32-bit x86)
# ---------------------------------------------------------------------------

def parse_pe_x86(path: Path):
    data = path.read_bytes()
    assert data[:2] == b'MZ'
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    coff = pe_off + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    opt = coff + 20
    opt_sz = struct.unpack_from('<H', data, coff + 16)[0]
    image_base = struct.unpack_from('<I', data, opt + 28)[0]
    sect_off = opt + opt_sz
    sects = []
    for i in range(nsec):
        so = sect_off + i * 40
        name = data[so:so+8].rstrip(b'\x00').decode('latin-1', 'replace')
        vsize = struct.unpack_from('<I', data, so + 8)[0]
        vaddr = struct.unpack_from('<I', data, so + 12)[0]
        rsize = struct.unpack_from('<I', data, so + 16)[0]
        rptr  = struct.unpack_from('<I', data, so + 20)[0]
        chars = struct.unpack_from('<I', data, so + 36)[0]
        sects.append({'name': name, 'vaddr': vaddr, 'vsize': vsize,
                       'rptr': rptr, 'rsize': rsize, 'chars': chars})
    return data, image_base, sects


def find_text_section(sects):
    for s in sects:
        if s['chars'] & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            return s
    return None


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

def load_pdb_names(path: Path) -> Set[str]:
    """One name per line, free of leading/trailing junk.

    pdb_all_function_names.txt contains demangled qualified C++ names like
    ``AILinearTaskThread::OnStartup``.  We keep ONLY names that look like
    real qualified identifiers (``Class::method``) -- single-segment names
    (``main``, ``WinMain``) are too generic to anchor confidently.
    """
    out = set()
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        ln = ln.strip()
        # Require ClassNamespace::method form: at least one '::' AND every
        # segment is a C-identifier (allow ~ for dtors, ` for compiler-gen).
        if '::' not in ln:
            continue
        # Drop compiler-generated names with backticks (``scalar deleting
        # destructor``, ``vector deleting destructor``) -- their strings,
        # if present, are non-unique.
        if '`' in ln:
            continue
        if not re.fullmatch(r'[A-Za-z_~][A-Za-z0-9_~]*'
                            r'(?:::[A-Za-z_~][A-Za-z0-9_~]*)+', ln):
            continue
        out.add(ln)
    return out


def load_strings(path: Path) -> List[Tuple[int, str]]:
    """0xVA|len|text per line.  Returns [(va, text), ...]."""
    out = []
    for ln in path.read_text(encoding='utf-8', errors='replace').splitlines():
        if not ln or ln.startswith('#'):
            continue
        parts = ln.split('|', 2)
        if len(parts) < 3:
            continue
        try:
            va = int(parts[0], 16)
        except ValueError:
            continue
        # Un-escape \r \n \t \\
        text = (parts[2].replace('\\r', '\r').replace('\\n', '\n')
                .replace('\\t', '\t').replace('\\\\', '\\'))
        out.append((va, text))
    return out


# ---------------------------------------------------------------------------
# Step 1: pick PC strings that match a PDB function name
# ---------------------------------------------------------------------------

_PREFIX_PATTERNS = [
    # Pure name as the whole string (most common for ROCK-style logging).
    lambda s: s.strip(),
    # ``ClassName::method called`` or ``ClassName::method:``
    lambda s: re.match(r'^[A-Za-z_][\w]*(?:::[A-Za-z_~][\w~]*)+', s.lstrip()),
]


def extract_candidate_names(text: str) -> Set[str]:
    """Yield strings inside `text` that LOOK like ``Class::method`` patterns.

    Bethesda logging includes ``"BSGameLogic::Update() entered"``,
    ``"AbstractHeap::BaseAllocate"`` etc.  We yank every such substring.
    """
    out = set()
    for m in re.finditer(
        r'[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_~][A-Za-z0-9_~]*)+',
        text,
    ):
        s = m.group(0)
        # Skip trivially-short matches like ``a::b``
        if len(s) < 8 or '::' not in s[1:]:
            continue
        out.add(s)
    return out


def match_strings_to_pdb_names(
    strings: List[Tuple[int, str]], pdb_names: Set[str]
) -> List[Tuple[int, str, str]]:
    """Return [(string_va, matched_name, full_string_text), ...].

    A PC string anchors a PDB name iff some substring of the PC string
    is a known PDB qualified name.  We DO allow the same name to appear
    in multiple distinct strings (``Foo::Bar()`` + ``Foo::Bar failed``);
    those all genuinely point to the same function.

    To stay precise we drop names that show up across more than ~5
    distinct strings -- at that point they're too generic (e.g. names
    that match coincidentally inside longer text).
    """
    name_to_strings: Dict[str, List[Tuple[int, str]]] = {}
    for va, text in strings:
        candidates = extract_candidate_names(text)
        for c in candidates:
            if c in pdb_names:
                name_to_strings.setdefault(c, []).append((va, text))

    out = []
    too_generic = 0
    for name, hits in name_to_strings.items():
        if len(hits) > 5:
            too_generic += 1
            continue
        for va, text in hits:
            out.append((va, name, text))
    print(f'  matched (string, name) pairs: {len(out)}')
    print(f'  distinct names matched: '
          f'{len({n for _, n, _ in out})}')
    print(f'  names too generic (>5 strings, skipped): {too_generic}')
    return out


# ---------------------------------------------------------------------------
# Step 2: byte-scan .text for x86 xrefs to each anchored string VA
# ---------------------------------------------------------------------------

# Common x86 instructions that embed a 32-bit absolute address as an immediate
# operand.  We just look for the 4-byte little-endian VA following one of these
# leading bytes -- this matches the vast majority of string-literal uses.
#
# 0x68  push imm32
# 0xBA-0xBF  mov r32, imm32  (BA=edx, BB=ebx, BD=ebp, BE=esi, BF=edi, BC=esp)
# 0xB8-0xBF range covers all `mov reg, imm32`
# 0xC7 [modrm] imm32  -- `mov r/m32, imm32` (most common: mov [esp+x], imm32)
#                        (we keep it simple and just match the imm32 anywhere)
#
# The cheap-and-correct way: search for the 4-byte LE encoding of each VA
# anywhere in .text.  Almost any byte sequence equal to a VA in .rdata/.data
# is genuinely a reference to that VA (random 4-byte coincidences are
# astronomically unlikely given the address space).

def find_xrefs_in_text(text_bytes: bytes, text_vaddr: int,
                       string_vas: Set[int]) -> Dict[int, List[int]]:
    """For each string_va, return list of .text byte offsets where the
    4-byte LE encoding of string_va appears.

    Output: {string_va: [xref_rva_within_text, ...]}
    """
    out: Dict[int, List[int]] = {va: [] for va in string_vas}
    # Build a quick lookup: take each 4-byte window of text_bytes, check if
    # it's in string_vas.  For 12MB of text and 5k anchor VAs this is fast
    # enough as a flat scan.
    sva = string_vas
    n = len(text_bytes)
    # Use struct.iter_unpack for speed
    # We need positions, so iterate manually.  Step by 1 (not 4) because
    # xrefs aren't 4-byte aligned in x86 code.
    for i in range(0, n - 4):
        va = (text_bytes[i] | (text_bytes[i+1] << 8) |
              (text_bytes[i+2] << 16) | (text_bytes[i+3] << 24))
        if va in sva:
            out[va].append(text_vaddr + i)
    return out


# ---------------------------------------------------------------------------
# Step 3: walk backwards from each xref to find function start
# ---------------------------------------------------------------------------

def find_function_start(text_bytes: bytes, text_vaddr: int, xref_va: int,
                        search_bytes: int = 0x800) -> int:
    """Walk backwards from xref to nearest function start.

    Heuristic: function starts are either preceded by INT3 padding (0xCC)
    or are 16-byte aligned and begin with a known prologue byte.  We scan
    backwards looking for the LAST occurrence of ``CC CC`` followed by a
    prologue byte (push/sub/mov ebp etc.).
    """
    end_off = xref_va - text_vaddr
    start_off = max(0, end_off - search_bytes)
    # Scan backwards for INT3 padding ending; the next byte after is fn start
    i = end_off
    while i > start_off:
        # Look for two or more consecutive 0xCC at i-2 .. i-1
        if (text_bytes[i-1] == 0xCC and text_bytes[i-2] == 0xCC):
            # Walk forward past padding
            j = i
            while j < end_off and text_bytes[j] == 0xCC:
                j += 1
            if j < end_off and _is_prologue(text_bytes, j):
                return text_vaddr + j
        i -= 1
    # Fallback: nearest 16-byte aligned address with a prologue
    i = end_off & ~0xF
    while i > start_off:
        if _is_prologue(text_bytes, i):
            return text_vaddr + i
        i -= 0x10
    return 0


_PROLOGUE_BYTES = {
    0x55,  # push ebp
    0x53, 0x56, 0x57,  # push ebx/esi/edi
    0x83,  # sub esp, imm8 / and esp etc.
    0x81,  # sub esp, imm32
    0x8B,  # mov reg, reg (rare prologue)
    0x6A,  # push imm8
    0x68,  # push imm32
    0xA1,  # mov eax, [imm32]
    0xB8, 0xB9, 0xBA, 0xBB, 0xBD, 0xBE, 0xBF,  # mov reg, imm32
    0xE8, 0xE9,  # call/jmp (thunks)
    0xFF,  # call/jmp r/m32 (thunks)
}


def _is_prologue(text_bytes: bytes, off: int) -> bool:
    if off >= len(text_bytes):
        return False
    b = text_bytes[off]
    return b in _PROLOGUE_BYTES


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 4:
        print(__doc__); sys.exit(1)
    exe_path     = Path(sys.argv[1])
    strings_path = Path(sys.argv[2])
    pdb_path     = Path(sys.argv[3])
    out_path     = Path(sys.argv[4]) if len(sys.argv) > 4 else \
                   Path('string_anchor_names.csv')

    print(f'Loading PDB names: {pdb_path}')
    pdb_names = load_pdb_names(pdb_path)
    print(f'  qualified PDB names: {len(pdb_names):,}')

    print(f'Loading PC strings: {strings_path}')
    strings = load_strings(strings_path)
    print(f'  strings: {len(strings):,}')

    print('Step 1: matching strings to PDB qualified names...')
    anchored = match_strings_to_pdb_names(strings, pdb_names)

    print(f'Step 2: byte-scanning PC FNV.exe .text for xrefs to {len(anchored)} string VAs')
    data, image_base, sects = parse_pe_x86(exe_path)
    text_sect = find_text_section(sects)
    text_bytes = data[text_sect['rptr']:text_sect['rptr'] + text_sect['rsize']]
    text_vaddr = image_base + text_sect['vaddr']
    print(f'  .text: vaddr=0x{text_vaddr:08X} size=0x{len(text_bytes):X}')

    string_vas = {va for va, _, _ in anchored}
    xrefs = find_xrefs_in_text(text_bytes, text_vaddr, string_vas)
    n_xref_hits = sum(1 for vlist in xrefs.values() if vlist)
    print(f'  strings with at least one xref: {n_xref_hits}/{len(anchored)}')

    print('Step 3: walking back from xrefs to function starts')
    name_to_funcs: Dict[str, List[int]] = {}
    string_to_name = {va: name for va, name, _ in anchored}
    string_to_text = {va: text for va, _, text in anchored}

    for sva, xref_list in xrefs.items():
        name = string_to_name.get(sva)
        if not name:
            continue
        for xref_va in xref_list:
            fn_va = find_function_start(text_bytes, text_vaddr, xref_va)
            if fn_va:
                name_to_funcs.setdefault(name, []).append(fn_va)

    # Dedup + emit
    rows = []
    multi_fn = 0
    for name, fns in name_to_funcs.items():
        uniq = list(set(fns))
        if len(uniq) == 1:
            rows.append((uniq[0], name, string_to_text.get(
                next(v for v, n, _ in anchored if n == name), '')))
        else:
            multi_fn += 1
    print(f'  names resolved to exactly one fn: {len(rows)}')
    print(f'  names resolved to multiple fns (skipped): {multi_fn}')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        f.write('# string_anchor: PC RVA | qualified name | source string text\n')
        for fn_va, name, src in sorted(rows):
            rva = fn_va - image_base
            esc = src.replace('|', '\\|').replace('\n', '\\n').replace('\r', '\\r')[:120]
            f.write(f'0x{rva:08X}|{name}|{esc}\n')
    print(f'Wrote {out_path}: {len(rows)} string-anchored names')


if __name__ == '__main__':
    main()
