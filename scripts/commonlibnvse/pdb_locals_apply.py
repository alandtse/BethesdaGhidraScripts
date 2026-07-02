#!/usr/bin/env python3
"""Load Fallout_Debug_locals.json (DIA-derived per-function param +
local var data) and apply it to the FNV fallback symbols:

  - Replace structured-sig ``sd`` with the DIA-derived params (always
    more accurate than regex-parsing the raw sig text).
  - Build a plate-comment annotation listing parameters + locals with
    types, surfaced via the symbol's ``src`` field.

Public API:
    load_locals() -> {qualified_name: {rva, len, params, locals}}
    sd_from_dia(qname, types_known, enums_known, typedefs) -> [ret, params, is_static] | None
    annotate_comment(qname) -> short text or None
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_types_to_pipeline import _convert_one  # noqa: E402


_LOCALS_PATH = Path(r'C:\GhidraProjects\scripts\Fallout_Debug_locals.json')


_cache = {}


def load_locals() -> Dict[str, dict]:
    if 'data' in _cache:
        return _cache['data']
    if not _LOCALS_PATH.is_file():
        _cache['data'] = {}
        return {}
    _cache['data'] = json.loads(_LOCALS_PATH.read_text(encoding='utf-8'))
    return _cache['data']


def sd_from_dia(qname: str, ret_sig_hint: str,
                 types_known: Set[str], enums_known: Set[str],
                 typedefs: Dict[str, str]) -> Optional[list]:
    """Build structured sig ``[ret, [[pname, ptype], ...], is_static]``
    using DIA-extracted param names and types.

    ``ret_sig_hint`` is the raw sig string (e.g. ``void Foo::Bar(...)``)
    that we'll use to extract the return type when DIA's data doesn't
    have it directly.
    """
    data = load_locals()
    entry = data.get(qname)
    if not entry:
        return None
    raw_params = entry.get('params', [])
    if not raw_params and ret_sig_hint and '(' in ret_sig_hint:
        # No params -- still emit empty
        pass

    # Detect static via the presence of ObjectPtr ("this") -- absence means static
    is_static = not any(p.get('kind') == 'ObjectPtr' for p in raw_params)

    params_out = []
    for p in raw_params:
        if p.get('kind') == 'ObjectPtr':
            # Skip ``this`` -- structured-sig builder synthesizes it for
            # non-static class methods
            continue
        pname = p.get('name') or f'p{len(params_out)}'
        ptype_raw = p.get('type', '?')
        ptype = _convert_one(ptype_raw, 4, types_known, enums_known, typedefs)
        params_out.append([pname, ptype])

    # Return type: parse from raw sig hint (DIA only stores it on the
    # function's IDiaSymbol.type, which we didn't extract).
    ret = 'void'
    if ret_sig_hint:
        m = re.match(r'^\s*(?:static\s+|virtual\s+|inline\s+|explicit\s+)*'
                     r'((?:[\w:<>\[\]\* &]+?))\s+\w', ret_sig_hint)
        if m:
            ret_raw = m.group(1).strip()
            for kw in ('__cdecl', '__thiscall', '__stdcall', '__fastcall'):
                ret_raw = ret_raw.replace(kw, '').strip()
            ret = _convert_one(ret_raw, 4, types_known, enums_known, typedefs)
            if ret.startswith('bytes:'):
                ret = 'void'

    return [ret, params_out, is_static]


def annotate_comment(qname: str, max_locals: int = 6) -> Optional[str]:
    """Build a short plate-comment fragment listing parameters + locals.

    Returns ``"params: a, b; locals: x:int, y:bool"`` or None.
    """
    data = load_locals()
    entry = data.get(qname)
    if not entry:
        return None
    pieces = []
    params = entry.get('params', [])
    if params:
        plist = ', '.join(
            f"{p.get('name', '?')}:{p.get('type', '?')}"
            for p in params if p.get('kind') == 'Param'
        )
        if plist:
            pieces.append(f'params({plist})')
    locals_ = entry.get('locals', [])
    if locals_:
        llist = ', '.join(
            f"{l.get('name', '?')}:{l.get('type', '?')}"
            for l in locals_[:max_locals]
        )
        if locals_[max_locals:]:
            llist += f' +{len(locals_) - max_locals}'
        pieces.append(f'locals({llist})')
    return '; '.join(pieces) if pieces else None
