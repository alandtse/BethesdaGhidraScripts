#!/usr/bin/env python3
"""Unit tests for commonlib_writeback.py's _detect_vkey (runtime auto-detection)
and _load_symbols (parsing a generated CommonLibImport_CLVR_*.py).

Run: python -m pytest test_commonlib_writeback.py
"""
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commonlib_writeback as wb  # noqa: E402


class _FakeAddr:
    def __init__(self, v):
        self.v = v

    def add(self, off):
        return _FakeAddr(self.v + off)

    def __hash__(self):
        return hash(self.v)

    def __eq__(self, other):
        return isinstance(other, _FakeAddr) and self.v == other.v


class _FakeProgram:
    def __init__(self, name):
        self._name = name

    def getName(self):
        return self._name


def _fake_fm(present_offsets):
    """A function manager where getFunctionAt returns non-None only for the
    given set of (already-based) offsets."""
    present = set(present_offsets)

    class FM:
        def getFunctionAt(self, addr):
            return object() if addr.v in present else None
    return FM()


def _symbols(n, real_key):
    """n synthetic symbols where every offset key holds a distinct value,
    but only `real_key`'s offsets are "real" (will be marked present)."""
    syms = []
    for i in range(n):
        syms.append({
            't': 'func',
            's': 1000 + i,
            'a': 2000 + i,
            'v': 3000 + i,
            'a9': 4000 + i,
        })
    return syms


def test_detect_vkey_picks_key_with_highest_hit_rate():
    symbols = _symbols(50, 'a9')
    present = {s['a9'] for s in symbols}  # only AE1799 offsets resolve
    fm = _fake_fm(present)
    base = _FakeAddr(0)
    cp = _FakeProgram('SkyrimSE.1.7.79.exe')  # typo'd name, would mislead a name check
    assert wb._detect_vkey(cp, fm, base, symbols) == 'a9'


def test_detect_vkey_falls_back_to_name_hint_on_near_tie():
    symbols = _symbols(50, 'a9')
    # Both 'a' and 'a9' resolve equally (near-tie) -- ambiguous data, so the
    # name hint (a program named with "1799") should decide.
    present = {s['a'] for s in symbols} | {s['a9'] for s in symbols}
    fm = _fake_fm(present)
    base = _FakeAddr(0)
    cp = _FakeProgram('SkyrimSE.1799.exe')
    assert wb._detect_vkey(cp, fm, base, symbols) == 'a9'


def test_detect_vkey_handles_no_symbols_present():
    symbols = _symbols(10, 's')
    fm = _fake_fm(set())  # nothing resolves
    base = _FakeAddr(0)
    cp = _FakeProgram('SkyrimVR.exe')
    assert wb._detect_vkey(cp, fm, base, symbols) == 'v'


def _write_import(path, symbols_line, needs_currentprogram=False):
    with open(path, 'w') as f:
        if needs_currentprogram:
            f.write('dtm = currentProgram.getDataTypeManager()\n')
        f.write(symbols_line + '\n')


def test_load_symbols_bare_json_literal():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'CommonLibImport_CLVR_SE.py')
        _write_import(path, 'SYMBOLS = [{"n": "Foo", "t": "func", "s": 1}]')
        wb.IMPORT_PATH = path
        assert wb._load_symbols() == [{'n': 'Foo', 't': 'func', 's': 1}]


def test_load_symbols_json_loads_call_form():
    # The real generator's form for large files: SYMBOLS = _json_sym.loads('...').
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'CommonLibImport_CLVR_AE1799.py')
        _write_import(
            path,
            "import json as _json_sym\n"
            'SYMBOLS = _json_sym.loads(\'[{"n": "Bar", "t": "func", "a9": 2}]\')')
        wb.IMPORT_PATH = path
        assert wb._load_symbols() == [{'n': 'Bar', 't': 'func', 'a9': 2}]


def test_load_symbols_uses_injected_ghidra_globals():
    # A module-level line before SYMBOLS may reference currentProgram (as the
    # real generated files do) -- _load_symbols must see the same globals
    # commonlib_writeback.py itself was run with, not a bare empty namespace.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'CommonLibImport_CLVR_AE1799.py')
        _write_import(path, 'SYMBOLS = [{"n": "Baz"}]', needs_currentprogram=True)
        wb.IMPORT_PATH = path
        wb.currentProgram = types.SimpleNamespace(
            getDataTypeManager=lambda: 'fake-dtm')
        try:
            assert wb._load_symbols() == [{'n': 'Baz'}]
        finally:
            del wb.currentProgram


def test_load_symbols_missing_symbols_line_raises():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'CommonLibImport_CLVR_SE.py')
        _write_import(path, 'NOT_SYMBOLS = []')
        wb.IMPORT_PATH = path
        try:
            wb._load_symbols()
            assert False, 'expected RuntimeError'
        except RuntimeError:
            pass


if __name__ == '__main__':
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith('test_') and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print('PASS', fn.__name__)
        except Exception:
            failed += 1
            print('FAIL', fn.__name__)
            traceback.print_exc()
    sys.exit(1 if failed else 0)
