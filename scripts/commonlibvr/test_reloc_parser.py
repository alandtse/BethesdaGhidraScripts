#!/usr/bin/env python3
"""Unit tests for reloc_parser.py's _attach_ae1799 (AE 1.7.99 offset attachment).

Run: python -m pytest test_reloc_parser.py
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reloc_parser as rp  # noqa: E402


def _addr_lib(ae_db, ae1799_db):
    lib = types.SimpleNamespace()
    lib.ae_db = ae_db
    lib.ae1799_db = ae1799_db
    return lib


def test_attach_ae1799_maps_shared_ae_id_to_1799_offset():
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={100: 0x5000})
    syms = [{'name': 'Foo', 'ae_off': 0x2000}]
    rp._attach_ae1799(syms, addr_lib)
    assert syms[0]['ae1799_off'] == 0x5000


def test_attach_ae1799_skips_symbol_with_no_ae_off():
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={100: 0x5000})
    syms = [{'name': 'Foo'}]
    rp._attach_ae1799(syms, addr_lib)
    assert 'ae1799_off' not in syms[0]


def test_attach_ae1799_skips_when_id_not_in_1799_db():
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={})
    syms = [{'name': 'Foo', 'ae_off': 0x2000}]
    rp._attach_ae1799(syms, addr_lib)
    assert 'ae1799_off' not in syms[0]


def test_attach_ae1799_skips_when_ae_off_unknown_to_ae_db():
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={100: 0x5000})
    syms = [{'name': 'Foo', 'ae_off': 0x9999}]
    rp._attach_ae1799(syms, addr_lib)
    assert 'ae1799_off' not in syms[0]


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
