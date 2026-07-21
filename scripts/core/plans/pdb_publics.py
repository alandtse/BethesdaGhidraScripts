"""Shared llvm-pdbutil `pretty --externals` publics-dump parser.

Every CommonLib target's PDB pulls from a dump shaped:

    public [0xRVA] DemangledQualifiedName(args)

Pure text parsing -- no Ghidra, no per-game state. `iter_publics()` is the one truly
identical primitive (same regex, same RVA/zero-RVA handling) shared by every consumer;
`load_bytesig_publics()` additionally merges three byte-identical `{name: rva}` loaders
that were independently copy-pasted in `commonlibsse/bytesig_port_combined.py`,
`commonlibf4/bytesig_port_combined.py`, and `commonlibf4/run_bytesig_port.py`.

NOT merged here: `commonlibsse/pdb_publics_skyrim.py::load_pdb_names` (returns
`{rva: name}`, keeps template names, strips an address suffix) and
`commonlibf4/pdb_publics_f4_221.py::load_publics` (returns a list of
`{n,t,sig,<ver>,src}` dicts, classifies label-vs-func) have genuinely different output
contracts and filtering policy from each other and from `load_bytesig_publics` -- forcing
them into one shape would be a lossy merge, not a DRY win. Both are rebuilt on top of
`iter_publics()` instead, so the line-parsing itself is still shared.
"""
from __future__ import annotations

import os
import re
from typing import Dict, Iterator, Tuple

_LINE_RE = re.compile(
    r'^\s*public\s+\[0x(?P<rva>[0-9A-Fa-f]+)\]\s+(?P<name>\S.*?)\s*$')

# Shared across every "load a bytesig-port name pool" caller.
_BYTESIG_BAD_SUBSTR = (
    'RTTI_', "::`vftable'", "::`RTTI",
    'type_info::', '`typeinfo for', 'anonymous namespace',
    '`vector-deleting-destructor', '<lambda_',
)
_BYTESIG_NAME_RE = re.compile(r'^[A-Za-z_][\w:]*$')


def iter_publics(path: str) -> Iterator[Tuple[int, str]]:
    """Yield (rva, raw_name) for each `public [0xRVA] name` line in an
    llvm-pdbutil `pretty --externals` dump at `path`. Skips unparseable lines
    and zero-RVA placeholder entries. Yields nothing if `path` doesn't exist."""
    if not os.path.isfile(path):
        return
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for ln in fh:
            m = _LINE_RE.match(ln)
            if not m:
                continue
            try:
                rva = int(m.group('rva'), 16)
            except ValueError:
                continue
            if rva == 0:
                continue
            name = m.group('name').strip()
            if not name:
                continue
            yield rva, name


def load_bytesig_publics(path: str) -> Dict[str, int]:
    """Return `{qualified_name: rva}` for byte-sig-port name pooling: drops
    RTTI/vftable/typeinfo/lambda/anonymous-namespace noise, strips trailing
    `(args)`, rejects anything that isn't a plain qualified C++ identifier
    (no template args -- callers needing those use a different loader), and
    keeps the first RVA seen for a duplicate name."""
    out: Dict[str, int] = {}
    for rva, raw in iter_publics(path):
        if any(b in raw for b in _BYTESIG_BAD_SUBSTR):
            continue
        qname = raw.split('(', 1)[0].strip()
        if not qname or '<' in qname or '>' in qname:
            continue
        if not _BYTESIG_NAME_RE.match(qname):
            continue
        out.setdefault(qname, rva)
    return out
