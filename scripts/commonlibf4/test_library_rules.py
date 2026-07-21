#!/usr/bin/env python3
"""Unit tests for commonlibf4's LibraryRulesFormat implementation.

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


def _write_f4_bin(path, entries):
    """uint64 count + count x (uint64 id, uint64 offset), matching
    F4AddressLibrary.load_bin's decoder in address_library.py."""
    with open(path, 'wb') as f:
        f.write(struct.pack('<Q', len(entries)))
        for id_, off in entries:
            f.write(struct.pack('<QQ', id_, off))


def test_satisfies_library_rules_and_format_protocols():
    assert isinstance(lr.RULES, LibraryRules)
    assert isinstance(lr.RULES, LibraryRulesFormat)


def test_load_address_library_reads_flat_bin():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'versionlib-1-11-191-0.bin')
        _write_f4_bin(path, [(500, 0x3000), (600, 0x4000)])
        db = lr.RULES.load_address_library(path)
    assert db == {500: 0x3000, 600: 0x4000}


def test_load_address_library_missing_file_returns_empty():
    assert lr.RULES.load_address_library(r'Z:\does\not\exist.bin') == {}


def test_format_relocation_single_id_registry():
    assert lr.RULES.format_relocation({'id': 424242}) == 'REL::ID(424242)'


def test_fallback_name_sources_is_ordered_list():
    assert lr.RULES.fallback_name_sources() == ['IDA names', '1.11.221 PDB']


def test_parse_id_file_delegates_to_reloc_parser_collect_relocations(monkeypatch):
    calls = []

    def fake_collect_relocations(re_include, addr_lib, verbose, root_namespace):
        calls.append((re_include, addr_lib, verbose, root_namespace))
        return ([], [], set())

    monkeypatch.setattr(lr.reloc_parser, 'collect_relocations', fake_collect_relocations)
    sentinel_addr_lib = object()
    result = lr.RULES.parse_id_file('/some/RE/include', sentinel_addr_lib, verbose=True)
    assert calls == [('/some/RE/include', sentinel_addr_lib, True, 'RE')]
    assert result == ([], [], set())


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
