#!/usr/bin/env python3
"""Parse ``llvm-pdbutil pretty --globals`` output from SkyrimSE.pdb into
an RVA-keyed function-record JSON.

The --globals stream is the only place SkyrimSE.pdb exposes full
function SIGNATURES (return type + calling convention + arg types) and
function SIZES -- ``pretty --classes`` emits zero ``func`` lines for
this PDB and DIA finds no frame data.  Format per record::

    func [0x002326d0+ 0 - 0x00232789-185 | sizeof=185] (FPO) void __fastcall TESObjectWEAP::ClearData_1402326D0()
    func [0x0031d910+ ...] (FPO) void __fastcall ConsoleFunc__handler::FunctionToggle...(...)

Output JSON: ``{ "0xRVA": {"sig": "<ret conv qname(args)>", "size": N}, ... }``

The sig text feeds commonlibnvse/pdb_sig_to_structured.parse_sig at
generation time to attach structured signatures ('sd') to Skyrim
symbols, mirroring what the FNV pipeline does with its Xbox PDB sigs.

Run:
    python parse_pdb_globals.py [globals.txt] [out.json]
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REFS_DIR   = SCRIPT_DIR / 'refs'

# func [0x<rva>+<prolog> - 0x<end>-<epilog> | sizeof=N] (FPO)? <sig>
_FUNC_LINE = re.compile(
    r'^\s+func\s+'
    r'\[0x(?P<rva>[0-9A-Fa-f]+)\+\s*\d+\s+-\s+0x[0-9A-Fa-f]+-\s*\d+\s*'
    r'\|\s*sizeof=\s*(?P<size>\d+)\]\s+'
    r'(?:\(FPO\)\s+)?'
    r'(?P<sig>.+?)\s*$'
)

# Names carry embedded address suffixes (``ClearData_1402326D0``) --
# strip so parse_sig sees a clean method name and the sd survives a
# rename-suffix mismatch.
_ADDR_SUFFIX = re.compile(r'_14[0-9A-Fa-f]{6,12}(?=\()')

# FUN_/sub_-style placeholder qnames carry no usable name info but the
# signature is still valuable -- keep them (the sd attaches by RVA).


def parse(in_path: Path) -> dict:
    out = {}
    n_func = 0
    with in_path.open('r', encoding='utf-8', errors='replace') as f:
        for ln in f:
            m = _FUNC_LINE.match(ln)
            if not m:
                continue
            n_func += 1
            rva = int(m.group('rva'), 16)
            sig = _ADDR_SUFFIX.sub('', m.group('sig'))
            key = '0x{:08X}'.format(rva)
            if key not in out:
                out[key] = {'sig': sig, 'size': int(m.group('size'))}
    print('  func records: {:,} ({:,} unique RVAs)'.format(n_func, len(out)))
    return out


def main():
    in_path  = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        REFS_DIR / 'skyrimse_pdb_globals.txt'
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else \
        REFS_DIR / 'skyrimse_pdb_func_sigs.json'
    print('Parsing {}...'.format(in_path))
    out = parse(in_path)
    out_path.write_text(json.dumps(out), encoding='utf-8')
    print('Wrote {}: {:,} bytes'.format(out_path, out_path.stat().st_size))


if __name__ == '__main__':
    main()
