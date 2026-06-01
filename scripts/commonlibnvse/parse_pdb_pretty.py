#!/usr/bin/env python3
"""Parse ``llvm-pdbutil pretty --classes`` output and extract:

  1. Per-class function entries with VA + signature -> JSON
     ``{class_name: [{va, sig, name}, ...]}``
  2. Per-class field layouts with offset + size + type -> JSON
     ``{class_name: {size, fields: [{off, size, type, name}, ...]}}``

The pretty dump is far richer than `--externals`: it lists EVERY
declared method (including inlined / private ones with no public
symbol), so we go from ~88k function symbols to ~130k.

Run:
    python parse_pdb_pretty.py <pretty.txt> <funcs.json> <types.json>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


# class/struct/union NAME [sizeof = N] {
_TYPE_HDR = re.compile(
    r'^(?P<indent>\s*)'
    r'(?:const\s+|volatile\s+)*'
    r'(?:class|struct|union)\s+'
    r'(?P<name>[\w:<>\?\$\@,\s\*&\(\)\.\-\+]+?)\s+'
    r'\[sizeof\s*=\s*(?P<size>\d+)\]\s*\{?\s*$'
)

# func [0x<va>+<prolog> - 0x<end>- 0 | sizeof=N] (FPO?) <return> __cdecl Class::method(args)
_FUNC_LINE = re.compile(
    r'^\s+func\s+'
    r'\[0x(?P<va>[0-9A-Fa-f]+)\+\d+\s+-\s+0x(?P<end>[0-9A-Fa-f]+)-\s*\d+\s*'
    r'\|\s*sizeof=(?P<size>\d+)\]\s+'
    r'(?:\(FPO\)\s+)?'
    r'(?P<sig>.+)\s*$'
)

# data +0xOFF [sizeof=N] <type> <name>
# We capture the indent so we can reject lines that belong to a NESTED
# struct expansion -- pretty-dump emits inner struct fields at deeper
# indent, and folding them into the parent at literal offsets creates
# bogus field overlaps.
_DATA_LINE = re.compile(
    r'^(?P<indent>\s+)data\s+\+0x(?P<off>[0-9A-Fa-f]+)\s+'
    r'\[sizeof=(?P<size>\d+)\]\s+'
    r'(?P<rest>.+)\s*$'
)

# ``: public Foo, protected Bar { ...`` continuation line right after a
# class header.  Captures the entire base-list section.
_BASE_LIST = re.compile(
    r'^\s+:\s+(?P<bases>(?:(?:public|protected|private|virtual\s+\w+)\s+'
    r'[^,{}\s][^,{}\n]*?(?:,\s*)?)+)\s*\{?\s*$'
)

# Outermost ``base +0xOFF [sizeof=N] BaseClass`` line under a class.
_BASE_LINE = re.compile(
    r'^(?P<indent>\s+)base\s+\+0x(?P<off>[0-9A-Fa-f]+)\s+'
    r'\[sizeof=(?P<size>\d+)\]\s+(?P<name>\S.+?)\s*$'
)


def _extract_qname(sig: str) -> str:
    """``static? <ret> __cdecl Class::method(args)`` -> ``Class::method``."""
    # Strip args by finding the LAST unparenthesized '('
    depth = 0
    last_paren = -1
    for i in range(len(sig) - 1, -1, -1):
        if sig[i] == ')':
            depth += 1
        elif sig[i] == '(':
            depth -= 1
            if depth == 0:
                last_paren = i
                break
    if last_paren > 0:
        sig = sig[:last_paren].rstrip()
    # Last token is Class::method (or Class<T>::method)
    # Handle multi-word names by walking from right until we hit a known sep
    toks = sig.split()
    if not toks:
        return sig
    # Strip ``__cdecl`` etc. -- name is the LAST token after the calling conv
    return toks[-1]


def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    in_path = Path(sys.argv[1])
    out_funcs = Path(sys.argv[2])
    out_types = Path(sys.argv[3]) if len(sys.argv) > 3 else None

    print(f'Parsing {in_path}...')
    funcs_by_class = {}  # {class_name: [{'va','end','size','sig','name'}]}
    types_by_class = {}  # {class_name: {'size': N, 'fields': [...]}}
    cur_class = None
    cur_class_size = 0
    cur_class_fields = []
    cur_class_bases  = []
    cur_indent = -1            # outer struct header indent
    cur_outer_data_indent = -1 # indent of the first data line under this class
    cur_outer_base_indent = -1 # indent of the first base line (immediate bases)

    with in_path.open('r', encoding='utf-8', errors='replace') as f:
        for ln in f:
            m = _TYPE_HDR.match(ln)
            if m:
                # Flush previous class
                if cur_class is not None and (cur_class_fields or cur_class_bases):
                    types_by_class[cur_class] = {
                        'size':   cur_class_size,
                        'fields': cur_class_fields,
                        'bases':  cur_class_bases,
                    }
                cur_class = m.group('name').strip()
                cur_class_size = int(m.group('size'))
                cur_class_fields = []
                cur_class_bases  = []
                cur_indent = len(m.group('indent'))
                cur_outer_data_indent = -1   # established on first data line
                cur_outer_base_indent = -1   # established on first base line
                continue

            if cur_class is None:
                continue

            # Continuation: ``: public Base, protected OtherBase {``
            mbl = _BASE_LIST.match(ln)
            if mbl and not cur_class_bases:
                raw = mbl.group('bases')
                for part in raw.split(','):
                    p = part.strip()
                    p = re.sub(r'^(public|protected|private|virtual\s+\w+)\s+',
                               '', p)
                    p = p.strip().rstrip('{').strip()
                    if p and not any(b[0] == p for b in cur_class_bases):
                        # Offset is unknown here; ``base +0xOFF`` lines
                        # below will fill it in (and the dedup keeps both
                        # entries pointing at the same name).
                        cur_class_bases.append([p, 0])
                continue

            # ``base +0xOFF [sizeof=N] BaseClass`` -- immediate bases only
            mbi = _BASE_LINE.match(ln)
            if mbi:
                ind = len(mbi.group('indent'))
                if cur_outer_base_indent == -1:
                    cur_outer_base_indent = ind
                if ind == cur_outer_base_indent:
                    base_name = mbi.group('name').strip()
                    base_off  = int(mbi.group('off'), 16)
                    existing = next((b for b in cur_class_bases
                                     if b[0] == base_name), None)
                    if existing:
                        existing[1] = base_off
                    else:
                        cur_class_bases.append([base_name, base_off])
                continue

            mf = _FUNC_LINE.match(ln)
            if mf:
                sig = mf.group('sig').strip()
                qname = _extract_qname(sig)
                funcs_by_class.setdefault(cur_class, []).append({
                    'va':   int(mf.group('va'), 16),
                    'end':  int(mf.group('end'), 16),
                    'size': int(mf.group('size')),
                    'sig':  sig,
                    'name': qname,
                })
                continue

            md = _DATA_LINE.match(ln)
            if md:
                ind = len(md.group('indent'))
                # First data line under this class sets the "outer" indent.
                # Subsequent lines deeper than this are nested-struct
                # expansions -- skip them to avoid bogus field overlaps.
                if cur_outer_data_indent == -1:
                    cur_outer_data_indent = ind
                elif ind > cur_outer_data_indent:
                    continue
                rest = md.group('rest').strip()
                # Detect bitfield syntax: ``<type> <name> : <width>``.  We
                # don't model individual bits; just preserve the underlying
                # primitive at that byte offset (dedup-by-range will keep
                # the FIRST bitfield member per offset, which is fine
                # because Ghidra would show the byte as the primitive too).
                bitfield_width = 0
                m_bf = re.search(r'\s*:\s*(\d+)\s*$', rest)
                if m_bf:
                    bitfield_width = int(m_bf.group(1))
                    rest = rest[:m_bf.start()].strip()
                # ``<type> <name>`` -- type may contain spaces (e.g. ``unsigned long``)
                # Best-effort split on last token = name
                rest_tokens = rest.split()
                if len(rest_tokens) >= 2:
                    name = rest_tokens[-1]
                    type_ = ' '.join(rest_tokens[:-1])
                    cur_class_fields.append({
                        'off':  int(md.group('off'), 16),
                        'size': int(md.group('size')),
                        'type': type_,
                        'name': name,
                        **({'bf_width': bitfield_width} if bitfield_width else {}),
                    })
                continue

    if cur_class is not None and (cur_class_fields or cur_class_bases):
        types_by_class[cur_class] = {
            'size':   cur_class_size,
            'fields': cur_class_fields,
            'bases':  cur_class_bases,
        }

    n_funcs = sum(len(v) for v in funcs_by_class.values())
    n_fields = sum(len(v['fields']) for v in types_by_class.values())
    print(f'  classes (functions): {len(funcs_by_class):,}')
    print(f'  total functions: {n_funcs:,}')
    print(f'  classes (types): {len(types_by_class):,}')
    print(f'  total fields: {n_fields:,}')

    out_funcs.parent.mkdir(parents=True, exist_ok=True)
    out_funcs.write_text(json.dumps(funcs_by_class), encoding='utf-8')
    print(f'Wrote {out_funcs}: {out_funcs.stat().st_size:,} bytes')

    if out_types:
        out_types.parent.mkdir(parents=True, exist_ok=True)
        out_types.write_text(json.dumps(types_by_class), encoding='utf-8')
        print(f'Wrote {out_types}: {out_types.stat().st_size:,} bytes')


if __name__ == '__main__':
    main()
