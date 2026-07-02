#!/usr/bin/env python3
"""Convert raw C signature strings (from pdb_signatures.load_sigs) into
the structured form ghidra_import_gen.apply_structured_sig consumes:

    [return_type_pipeline,
     [[param_name, param_type_pipeline], ...],
     is_static_bool]

Pipeline types use the same vocabulary as struct fields
(u32/i32/f32/ptr/bytes:N/struct:Name/enum:Name/...).  When type
conversion fails for a parameter, the whole sig falls back to the raw
string form so the existing CParserUtils path still applies.

Public API:
    parse_sig(sig_text, known_structs, known_enums, typedefs)
        -> [ret_pipeline, [[pname, ptype], ...], is_static] | None
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pdb_types_to_pipeline import _convert_one, normalize_struct_name  # noqa


_STATIC_RE = re.compile(r'^\s*static\s+')


def _strip_modifiers(s: str) -> str:
    """Drop calling conv keywords + visibility annotations.

    ``virtual void __cdecl Foo::Bar(int x)`` -> ``void Foo::Bar(int x)``
    """
    s = re.sub(r'\b(virtual|inline|explicit|friend|register)\s+', '', s)
    s = re.sub(r'\b(__cdecl|__thiscall|__stdcall|__fastcall|'
               r'__vectorcall|__clrcall)\s+', '', s)
    return s.strip()


def _split_top_level_commas(s: str) -> List[str]:
    """Split on commas not nested inside ``<>`` or ``()``."""
    parts = []
    depth_a = depth_p = 0
    last = 0
    for i, ch in enumerate(s):
        if ch == '<': depth_a += 1
        elif ch == '>': depth_a -= 1
        elif ch == '(': depth_p += 1
        elif ch == ')': depth_p -= 1
        elif ch == ',' and depth_a == 0 and depth_p == 0:
            parts.append(s[last:i].strip())
            last = i + 1
    tail = s[last:].strip()
    if tail:
        parts.append(tail)
    return parts


def _split_outermost_parens(s: str) -> Tuple[str, str]:
    """Find the OUTERMOST balanced ``(...)`` and return (before, inside).

    ``void Foo::Bar(int x, float y)`` -> (``void Foo::Bar``, ``int x, float y``).
    Returns (s, '') if no outer parens found.
    """
    # Walk forward to find the first '(' at top depth
    depth_p = 0
    open_at = -1
    for i, ch in enumerate(s):
        if ch == '(':
            if depth_p == 0:
                open_at = i
            depth_p += 1
        elif ch == ')':
            depth_p -= 1
            if depth_p == 0 and open_at >= 0:
                return s[:open_at].rstrip(), s[open_at + 1:i]
    return s.rstrip(), ''


def _split_param(p: str) -> Tuple[str, str]:
    """``Type Name`` (or just ``Type``) -> (type, name).

    Walks backwards counting ``<>`` and ``()`` to find the last whitespace
    at depth 0 -- everything after that is the name (if it looks like a
    C identifier).
    """
    p = p.strip()
    if not p:
        return '', ''
    depth_a = depth_p = 0
    name_start = -1
    for i in range(len(p) - 1, -1, -1):
        ch = p[i]
        if ch == '>': depth_a += 1
        elif ch == '<': depth_a -= 1
        elif ch == ')': depth_p += 1
        elif ch == '(': depth_p -= 1
        elif ch.isspace() and depth_a == 0 and depth_p == 0:
            name_start = i + 1
            break
    if name_start < 0:
        # No whitespace at depth 0 -- whole thing is the type
        return p, ''
    candidate_name = p[name_start:]
    # Name must be a plain C identifier; otherwise it's part of the type
    if re.fullmatch(r'[A-Za-z_][\w]*', candidate_name):
        return p[:name_start].rstrip(), candidate_name
    return p, ''


def _qname_template_aware_split(s: str) -> Tuple[str, str]:
    """Split ``ReturnType Class::method`` -> (return_type, qname).

    Walks backwards counting ``<>`` depth so template commas don't
    break the split.
    """
    depth_a = 0
    for i in range(len(s) - 1, -1, -1):
        ch = s[i]
        if ch == '>': depth_a += 1
        elif ch == '<': depth_a -= 1
        elif ch.isspace() and depth_a == 0:
            return s[:i].rstrip(), s[i + 1:].strip()
    return '', s.strip()


def parse_sig(sig_text: str,
              known_structs: Set[str],
              known_enums: Set[str] = None,
              typedefs: Dict[str, str] = None) -> Optional[list]:
    """Return ``[ret, [[pname, ptype], ...], is_static]`` or None on failure.

    All type strings are pipeline-format (u32/ptr/struct:Name/...).
    """
    if known_enums is None: known_enums = set()
    if typedefs is None:    typedefs = {}

    s = sig_text.strip()
    is_static = bool(_STATIC_RE.match(s))
    s = _STATIC_RE.sub('', s).strip()
    s = _strip_modifiers(s)

    head, params_blob = _split_outermost_parens(s)
    if not head:
        return None
    # head is now ``ReturnType Class::method``
    ret_raw, _qname = _qname_template_aware_split(head)
    if not ret_raw:
        # Constructors / destructors have no explicit return type
        ret_raw = 'void'

    ret_pipeline = _convert_one(ret_raw, 4, known_structs, known_enums, typedefs)
    if ret_pipeline.startswith('bytes:'):
        # Couldn't resolve return type -- safer to fall back to raw sig
        return None

    params = []
    if params_blob.strip() and params_blob.strip() != 'void':
        for i, p in enumerate(_split_top_level_commas(params_blob)):
            ptype_raw, pname = _split_param(p)
            if not ptype_raw:
                return None
            ptype_pipeline = _convert_one(ptype_raw, 4, known_structs,
                                           known_enums, typedefs)
            if ptype_pipeline.startswith('bytes:'):
                # One arg couldn't resolve -- bail to raw sig
                return None
            if not pname:
                pname = f'p{i}'
            params.append([pname, ptype_pipeline])

    return [ret_pipeline, params, is_static]


if __name__ == '__main__':
    # Smoke test
    test_sigs = [
        'void HighActorCuller::Operate(MobileObject* apMob)',
        'bool TESActorBase::DoesSwim()',
        'static void Foo::Bar(int x, float y)',
        'BSSimpleArray<int,1024>::~BSSimpleArray<int,1024>()',
    ]
    for s in test_sigs:
        r = parse_sig(s, {'MobileObject'}, set(), {})
        print(f'{s!r}\n  -> {r!r}\n')
