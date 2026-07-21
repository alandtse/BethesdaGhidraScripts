#!/usr/bin/env python3
"""Unit tests for rules.base (pure logic, no Ghidra).

Run: python -m pytest test_rules_base.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rules.base import LibraryRules, LibraryRulesFormat, env  # noqa: E402


def test_env_reads_prefixed_var(monkeypatch):
    monkeypatch.setenv('CLVR_DEDUP', 'go')
    assert env('CLVR', 'DEDUP') == 'go'


def test_env_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv('CLF4_DEDUP', raising=False)
    assert env('CLF4', 'DEDUP', 'dry') == 'dry'


def test_env_default_is_empty_string():
    assert env('NOPE', 'MISSING_VAR_XYZ') == ''


class _DataOnlyRules:
    """Shape every current (Phase 2/3) rules module actually has -- no grammar
    methods yet."""
    name = 'commonlibvr'
    import_path = '/x/CommonLibImport_CLVR_VR.py'
    script_dir = '/x/scripts/commonlibvr'
    types_category = '/types.h'
    include_paths = ['/x/CommonLibVR/include']
    env_prefix = 'CLVR'
    runtimes = ['SE', 'AE', 'VR']
    version_tuples = {'SE': (1, 5, 97, 0)}


def test_data_only_object_satisfies_libraryrules():
    assert isinstance(_DataOnlyRules(), LibraryRules)


def test_data_only_object_does_not_satisfy_libraryrulesformat():
    # LibraryRulesFormat additionally requires the Phase-4 grammar methods --
    # nothing implements those yet, and isinstance must reflect that honestly.
    assert not isinstance(_DataOnlyRules(), LibraryRulesFormat)


class _FullRules(_DataOnlyRules):
    """A hypothetical Phase-4-complete rules module."""

    def parse_id_file(self, text):
        return {}

    def load_address_library(self, path):
        return {}

    def format_relocation(self, ids):
        return ''

    def fallback_name_sources(self):
        return []


def test_full_object_satisfies_both_protocols():
    assert isinstance(_FullRules(), LibraryRules)
    assert isinstance(_FullRules(), LibraryRulesFormat)


class _IncompleteRules:
    name = 'incomplete'
    # missing every other required field/method


def test_object_missing_fields_does_not_satisfy_protocol():
    assert not isinstance(_IncompleteRules(), LibraryRules)


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v) and 'monkeypatch' not in v.__code__.co_varnames]
    failed = 0
    for fn in fns:
        try:
            fn(); print('PASS', fn.__name__)
        except Exception:
            failed += 1; print('FAIL', fn.__name__); traceback.print_exc()
    print('\n{}/{} passed (monkeypatch-based tests only run under pytest)'.format(
        len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
