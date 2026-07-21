#!/usr/bin/env python3
"""Unit tests for plans.pdb_publics (pure text parsing, no Ghidra).

Run: python -m pytest test_pdb_publics.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from plans import pdb_publics  # noqa: E402


def _dump(text):
    fd, path = tempfile.mkstemp(suffix='.txt')
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
    return path


def test_iter_publics_missing_file_yields_nothing():
    assert list(pdb_publics.iter_publics('/no/such/file.txt')) == []


def test_iter_publics_parses_rva_and_name():
    path = _dump('public [0x1234] Foo::Bar\n')
    try:
        assert list(pdb_publics.iter_publics(path)) == [(0x1234, 'Foo::Bar')]
    finally:
        os.remove(path)


def test_iter_publics_skips_zero_rva():
    path = _dump('public [0x0] Foo::Bar\npublic [0x10] Foo::Baz\n')
    try:
        assert list(pdb_publics.iter_publics(path)) == [(0x10, 'Foo::Baz')]
    finally:
        os.remove(path)


def test_iter_publics_skips_unparseable_lines():
    path = _dump('not a public line\npublic [0x10] Foo::Baz\n')
    try:
        assert list(pdb_publics.iter_publics(path)) == [(0x10, 'Foo::Baz')]
    finally:
        os.remove(path)


def test_load_bytesig_publics_strips_args_and_keeps_plain_name():
    path = _dump('public [0x100] Foo::Bar(int, char*)\n')
    try:
        assert pdb_publics.load_bytesig_publics(path) == {'Foo::Bar': 0x100}
    finally:
        os.remove(path)


def test_load_bytesig_publics_drops_rtti_vftable_typeinfo_lambda_noise():
    path = _dump(
        'public [0x10] RTTI_Foo\n'
        "public [0x20] Foo::`vftable'\n"
        'public [0x30] Foo::`RTTI Complete Object Locator\n'
        'public [0x40] type_info::something\n'
        'public [0x50] `typeinfo for Foo\n'
        "public [0x60] `anonymous namespace'::hidden\n"
        "public [0x70] Foo::`vector-deleting-destructor'\n"
        'public [0x80] Foo::<lambda_1>::operator()\n'
        'public [0x90] Foo::RealMethod\n'
    )
    try:
        assert pdb_publics.load_bytesig_publics(path) == {'Foo::RealMethod': 0x90}
    finally:
        os.remove(path)


def test_load_bytesig_publics_rejects_template_names():
    path = _dump('public [0x100] BSTArray<TESForm*>::push_back\n')
    try:
        assert pdb_publics.load_bytesig_publics(path) == {}
    finally:
        os.remove(path)


def test_load_bytesig_publics_keeps_first_rva_for_duplicate_name():
    path = _dump('public [0x100] Foo::Bar\npublic [0x200] Foo::Bar\n')
    try:
        assert pdb_publics.load_bytesig_publics(path) == {'Foo::Bar': 0x100}
    finally:
        os.remove(path)


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
