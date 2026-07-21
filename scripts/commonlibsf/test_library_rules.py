#!/usr/bin/env python3
"""Unit tests for commonlibsf's LibraryRulesFormat implementation.

Run: python -m pytest test_library_rules.py
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core'))
from rules.base import LibraryRules, LibraryRulesFormat  # noqa: E402
import library_rules as lr  # noqa: E402


def _write_v5_bin(path, rva_by_id):
    """meh321 V5: fmt(u32=5) + version[4](u32 each) + name[64] + ptr_size(u64) +
    addr_count(u32) + u32[addr_count] indexed by id, matching
    AddressLibrary._parse_bytes's fmt==5 branch in address_library.py."""
    addr_count = max(rva_by_id) + 1 if rva_by_id else 0
    with open(path, 'wb') as f:
        f.write(struct.pack('<I', 5))            # fmt
        f.write(struct.pack('<4I', 1, 16, 236, 0))  # version
        f.write(b'\x00' * 64)                     # name
        f.write(struct.pack('<Q', 8))              # ptr_size
        f.write(struct.pack('<I', addr_count))     # addr_count
        for i in range(addr_count):
            f.write(struct.pack('<I', rva_by_id.get(i, 0)))


def test_satisfies_library_rules_and_format_protocols():
    assert isinstance(lr.RULES, LibraryRules)
    assert isinstance(lr.RULES, LibraryRulesFormat)


def test_load_address_library_reads_v5_flat_array():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'versionlib-1-16-236-0.bin')
        _write_v5_bin(path, {3: 0x500, 7: 0x900})
        db = lr.RULES.load_address_library(path)
    assert db == {3: 0x500, 7: 0x900}


def test_load_address_library_missing_file_returns_empty():
    assert lr.RULES.load_address_library(r'Z:\does\not\exist.bin') == {}


def test_format_relocation_single_id_registry():
    assert lr.RULES.format_relocation({'id': 97400}) == 'REL::ID(97400)'


def test_fallback_name_sources_is_ordered_list():
    assert lr.RULES.fallback_name_sources() == ['versionlib IDs.h manifests', 'PDB publics']


def test_parse_id_file_delegates_to_ids_parser_collect_all(monkeypatch):
    calls = []

    def fake_collect_all(re_include, addr_lib, verbose):
        calls.append((re_include, addr_lib, verbose))
        return ([], [])

    monkeypatch.setattr(lr.ids_parser, 'collect_all', fake_collect_all)
    sentinel_addr_lib = object()
    result = lr.RULES.parse_id_file('/some/RE/include', sentinel_addr_lib, verbose=True)
    assert calls == [('/some/RE/include', sentinel_addr_lib, True)]
    assert result == ([], [])


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            if fn.__code__.co_argcount:
                continue
            fn(); print('PASS', fn.__name__)
        except Exception:
            failed += 1; print('FAIL', fn.__name__); traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
