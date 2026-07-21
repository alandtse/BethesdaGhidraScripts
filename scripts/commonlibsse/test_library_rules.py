#!/usr/bin/env python3
"""Unit tests for commonlibsse's LibraryRulesFormat implementation
(parse_id_file/load_address_library/format_relocation/fallback_name_sources).

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


def _write_meh321_bin(path, entries):
    """entries: list of (id, offset). Encodes each with the simplest byte-form
    the format supports (type_byte 0x00 -> full 8-byte id + full 8-byte offset),
    matching AddressLibrary.load_bin's decoder in address_library.py."""
    with open(path, 'wb') as f:
        f.write(b'\x00' * 4)                      # fmt
        f.write(b'\x00' * 16)                      # version
        f.write(struct.pack('<I', 0))              # name_len
        f.write(struct.pack('<I', 8))              # ptr_size
        f.write(struct.pack('<I', len(entries)))   # addr_count
        for id_, off in entries:
            f.write(bytes([0x00]))
            f.write(struct.pack('<Q', id_))
            f.write(struct.pack('<Q', off))


def test_satisfies_library_rules_and_format_protocols():
    assert isinstance(lr.RULES, LibraryRules)
    assert isinstance(lr.RULES, LibraryRulesFormat)


def test_load_address_library_reads_meh321_bin():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'version-1-5-97-0.bin')
        _write_meh321_bin(path, [(100, 0x1000), (200, 0x2000)])
        db = lr.RULES.load_address_library(path)
    assert db == {100: 0x1000, 200: 0x2000}


def test_load_address_library_missing_file_returns_empty():
    assert lr.RULES.load_address_library(r'Z:\does\not\exist.bin') == {}


def test_format_relocation_dual_id_macro():
    assert lr.RULES.format_relocation({'SE': 12345, 'AE': 67890}) == 'RELOCATION_ID(12345, 67890)'


def test_fallback_name_sources_is_ordered_list():
    srcs = lr.RULES.fallback_name_sources()
    assert srcs == ['.rename overlay', 'PDB publics', 'globals-sigs']


def test_parse_id_file_delegates_to_reloc_parser_collect_relocations(monkeypatch):
    calls = []

    def fake_collect_relocations(re_include, addr_lib, verbose, root_namespace):
        calls.append((re_include, addr_lib, verbose, root_namespace))
        return ([], [], {}, set(), {}, {})

    monkeypatch.setattr(lr.reloc_parser, 'collect_relocations', fake_collect_relocations)
    sentinel_addr_lib = object()
    result = lr.RULES.parse_id_file('/some/RE/include', sentinel_addr_lib, verbose=True)
    assert calls == [('/some/RE/include', sentinel_addr_lib, True, 'RE')]
    assert result == ([], [], {}, set(), {}, {})


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            if fn.__code__.co_argcount:
                continue   # skip monkeypatch-fixture tests in the manual runner
            fn(); print('PASS', fn.__name__)
        except Exception:
            failed += 1; print('FAIL', fn.__name__); traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
