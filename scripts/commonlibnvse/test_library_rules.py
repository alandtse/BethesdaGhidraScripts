#!/usr/bin/env python3
"""Unit tests for commonlibnvse's LibraryRulesFormat implementation.

Run: python -m pytest test_library_rules.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'core'))
from rules.base import LibraryRules, LibraryRulesFormat  # noqa: E402
import library_rules as lr  # noqa: E402


def test_satisfies_library_rules_and_format_protocols():
    assert isinstance(lr.RULES, LibraryRules)
    assert isinstance(lr.RULES, LibraryRulesFormat)


def test_load_address_library_always_empty_no_such_format_for_fnv():
    assert lr.RULES.load_address_library(r'Z:\anything.bin') == {}
    assert lr.RULES.load_address_library('') == {}


def test_format_relocation_hardcoded_va():
    assert lr.RULES.format_relocation({'va': 0x0071D0A0}) == '0x0071D0A0'


def test_fallback_name_sources_is_ordered_list():
    assert lr.RULES.fallback_name_sources() == ['xNVSE headers', 'refs/fnv_names.csv overlay']


def test_parse_id_file_delegates_to_addresses_collect_all(monkeypatch):
    calls = []

    def fake_collect_all(xnvse_root, refs_dir, verbose):
        calls.append((xnvse_root, refs_dir, verbose))
        return ([], [])

    monkeypatch.setattr(lr.addresses, 'collect_all', fake_collect_all)
    result = lr.RULES.parse_id_file('/some/xnvse/root', '/some/refs', verbose=True)
    assert calls == [('/some/xnvse/root', '/some/refs', True)]
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
