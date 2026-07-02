#!/usr/bin/env python3
"""Extract ASCII strings from PC FalloutNV.exe with their VAs.

Walks all initialized data sections (.rdata, .data) looking for
4-or-more-character ASCII NUL-terminated strings.  Emits one line per
string:

    0xVA|length|<string>

Used downstream by ``match_string_anchors.py`` to pair PC FNV string
literals with Xbox PDB function names that appear as logging strings.

Run:
    python extract_pc_fnv_strings.py <FalloutNV.exe> <out.txt>
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path


def parse_pe(path: Path):
    data = path.read_bytes()
    assert data[:2] == b'MZ'
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[pe_off:pe_off + 4] == b'PE\x00\x00'
    coff = pe_off + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    opt = coff + 20
    opt_sz = struct.unpack_from('<H', data, coff + 16)[0]
    magic = struct.unpack_from('<H', data, opt)[0]
    is_pe32_plus = (magic == 0x20B)
    image_base = struct.unpack_from('<Q' if is_pe32_plus else '<I',
                                     data, opt + (24 if is_pe32_plus else 28))[0]
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


def extract_strings(data, sects, image_base, min_len=4):
    """Yield (va, text) for NUL-terminated ASCII strings >= min_len chars.

    Scans every initialized-data section that isn't executable.
    """
    results = []
    for s in sects:
        # IMAGE_SCN_MEM_EXECUTE = 0x20000000 -- skip code sections
        if s['chars'] & 0x20000000:
            continue
        if s['rsize'] == 0:
            continue
        section = data[s['rptr']:s['rptr'] + s['rsize']]
        i = 0
        n = len(section)
        while i < n:
            # Look for printable ASCII run
            j = i
            while j < n:
                b = section[j]
                if 0x20 <= b <= 0x7E or b == 0x09:
                    j += 1
                else:
                    break
            if j - i >= min_len and j < n and section[j] == 0:
                # Found a NUL-terminated ASCII run
                text = section[i:j].decode('latin-1', 'replace')
                va = image_base + s['vaddr'] + i
                results.append((va, text))
                i = j + 1
            else:
                i = j + 1 if j > i else i + 1
    return results


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    exe_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    print(f'Parsing PE: {exe_path}')
    data, image_base, sects = parse_pe(exe_path)
    print(f'  image_base=0x{image_base:X}  sections={len(sects)}')
    for s in sects:
        flag = 'X' if s['chars'] & 0x20000000 else '-'
        print(f'    [{flag}] {s["name"]:8s} vaddr=0x{s["vaddr"]:08X} vsize=0x{s["vsize"]:X}')

    print('Extracting strings...')
    strings = extract_strings(data, sects, image_base, min_len=4)
    print(f'  {len(strings):,} strings found')

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open('w', encoding='utf-8') as f:
        for va, text in strings:
            # Escape newlines/tabs so each record is single-line
            esc = text.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            f.write(f'0x{va:08X}|{len(text)}|{esc}\n')
    print(f'Wrote {out_path} ({out_path.stat().st_size:,} bytes)')


if __name__ == '__main__':
    main()
