#!/usr/bin/env python3
"""Cross-library check: every CommonLib target's library_rules.py must satisfy
core.rules.base.LibraryRules (the Phase 2 data contract).

Run: python -m pytest test_all_library_rules.py
"""
import importlib.util
import os
import sys

CORE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.dirname(CORE_DIR)
sys.path.insert(0, CORE_DIR)
from rules.base import LibraryRules, LibraryRulesFormat  # noqa: E402

LIBRARIES = ['commonlibsse', 'commonlibvr', 'commonlibf4', 'commonlibnvse', 'commonlibsf']

# Phase 4: libraries with a real per-library id-file parser/address-library
# loader to delegate to (see each library_rules.py's docstring). commonlibvr
# is deliberately excluded -- its ids come pre-resolved from the sibling
# vr_address_tools repo's generated import, not from an address-library
# reader in this repo, so there is nothing existing to delegate to yet.
FORMAT_LIBRARIES = ['commonlibsse', 'commonlibf4', 'commonlibnvse', 'commonlibsf']


def _load_rules_module(lib_name):
    path = os.path.join(SCRIPTS_DIR, lib_name, 'library_rules.py')
    spec = importlib.util.spec_from_file_location(lib_name + '_library_rules', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_library_has_a_library_rules_module():
    for lib in LIBRARIES:
        path = os.path.join(SCRIPTS_DIR, lib, 'library_rules.py')
        assert os.path.isfile(path), '%s is missing library_rules.py' % lib


def test_every_library_rules_satisfies_libraryrules_protocol():
    for lib in LIBRARIES:
        mod = _load_rules_module(lib)
        assert isinstance(mod.RULES, LibraryRules), \
            '%s.RULES does not satisfy LibraryRules' % lib


def test_every_library_rules_name_matches_its_directory():
    for lib in LIBRARIES:
        mod = _load_rules_module(lib)
        assert mod.RULES.name == lib


def test_every_library_rules_env_prefix_is_unique():
    prefixes = [_load_rules_module(lib).RULES.env_prefix for lib in LIBRARIES]
    assert len(prefixes) == len(set(prefixes)), 'env_prefix collision: %s' % prefixes


def test_format_libraries_satisfy_libraryrulesformat_protocol():
    for lib in FORMAT_LIBRARIES:
        mod = _load_rules_module(lib)
        assert isinstance(mod.RULES, LibraryRulesFormat), \
            '%s.RULES does not satisfy LibraryRulesFormat' % lib


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print('PASS', fn.__name__)
        except Exception:
            failed += 1; print('FAIL', fn.__name__); traceback.print_exc()
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
