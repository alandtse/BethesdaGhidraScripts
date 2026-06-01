#!/usr/bin/env python3
"""Build a {qualified_name -> C signature} index from Fallout_Debug_funcs.json
(produced by parse_pdb_pretty.py).

The JSON has shape ``{class_name: [{va, end, size, sig, name}, ...]}``.
Each ``sig`` is a full C++ signature like
``void __cdecl Class::Method(int x, float y)``.

We index by ``name`` (the qualified ``Class::method`` form _extract_qname
produced) and strip MSVC-specific keywords (``__cdecl``, ``virtual``,
``static``) that Ghidra's CParserUtils.parseSignature doesn't tolerate
in arbitrary positions.

For overloaded methods (multiple sigs with the same qualified name)
we keep the FIRST one -- consistent with the order PDB emits.

Public API:
    load_sigs(json_path) -> Dict[qualified_name, c_signature_string]
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict


_STRIP_KEYWORDS = re.compile(
    r'\b('
    r'__cdecl|__thiscall|__stdcall|__fastcall|__vectorcall|__clrcall|'
    r'virtual|static|inline|explicit|friend|register'
    r')\s+'
)


def clean_sig(sig: str) -> str:
    """Strip MSVC calling conventions and inheritance qualifiers."""
    s = _STRIP_KEYWORDS.sub('', sig)
    # Collapse multiple spaces
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def load_sigs(json_path: Path) -> Dict[str, str]:
    """Return ``{qualified_name: cleaned_c_signature}``.

    Overloads: first-emitted sig wins (matches the order PDB lists
    methods, which is link order = earliest in binary).
    """
    if not json_path.is_file():
        return {}
    data = json.loads(json_path.read_text(encoding='utf-8'))
    out: Dict[str, str] = {}
    for _cls, fns in data.items():
        for fn in fns:
            qname = fn.get('name', '')
            sig   = fn.get('sig', '')
            if not qname or not sig:
                continue
            if qname in out:
                continue
            cleaned = clean_sig(sig)
            # Drop sigs whose method name doesn't appear in the signature
            # body -- defensive, the PDB sometimes emits class-method
            # forward declarations whose sig text isn't a proper proto.
            if '(' not in cleaned or ')' not in cleaned:
                continue
            out[qname] = cleaned
    return out


if __name__ == '__main__':
    import sys
    p = Path(sys.argv[1]) if len(sys.argv) > 1 else \
        Path(r'C:\GhidraProjects\scripts\Fallout_Debug_funcs.json')
    sigs = load_sigs(p)
    print(f'  qualified names with signatures: {len(sigs):,}')
    # Show 3 samples
    for k in list(sigs)[:3]:
        print(f'    {k!r} -> {sigs[k]!r}')
