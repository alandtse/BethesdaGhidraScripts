#!/usr/bin/env python3
"""Unit tests for reloc_parser.py's _attach_extra_ae_variants (AE point-release
offset attachment, e.g. AE 1.7.99).

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
    rp._attach_extra_ae_variants(syms, addr_lib)
    assert syms[0]['ae1799_off'] == 0x5000


def test_attach_ae1799_skips_symbol_with_no_ae_off():
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={100: 0x5000})
    syms = [{'name': 'Foo'}]
    rp._attach_extra_ae_variants(syms, addr_lib)
    assert 'ae1799_off' not in syms[0]


def test_attach_ae1799_skips_when_id_not_in_1799_db():
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={})
    syms = [{'name': 'Foo', 'ae_off': 0x2000}]
    rp._attach_extra_ae_variants(syms, addr_lib)
    assert 'ae1799_off' not in syms[0]


def test_attach_ae1799_skips_when_ae_off_unknown_to_ae_db():
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={100: 0x5000})
    syms = [{'name': 'Foo', 'ae_off': 0x9999}]
    rp._attach_extra_ae_variants(syms, addr_lib)
    assert 'ae1799_off' not in syms[0]


def test_attach_extra_ae_variants_is_table_driven():
    # Proves the next AE version bump only needs a new EXTRA_AE_VARIANTS entry --
    # no reloc_parser.py code change -- by adding a second, hypothetical variant
    # at test time and confirming it gets attached alongside ae1799.
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={100: 0x5000})
    addr_lib.futurever_db = {100: 0x9000}
    saved = rp.EXTRA_AE_VARIANTS
    try:
        rp.EXTRA_AE_VARIANTS = saved + [{'key': 'futurever'}]
        syms = [{'name': 'Foo', 'ae_off': 0x2000}]
        rp._attach_extra_ae_variants(syms, addr_lib)
        assert syms[0]['ae1799_off'] == 0x5000
        assert syms[0]['futurever_off'] == 0x9000
    finally:
        rp.EXTRA_AE_VARIANTS = saved


def test_attach_extra_ae_variants_missing_db_is_skipped():
    # A variant declared in the table but with no addr_lib.<key>_db attribute
    # (e.g. this addr_lib was built before the table gained the entry) is a no-op,
    # not an AttributeError.
    addr_lib = _addr_lib(ae_db={100: 0x2000}, ae1799_db={100: 0x5000})
    saved = rp.EXTRA_AE_VARIANTS
    try:
        rp.EXTRA_AE_VARIANTS = saved + [{'key': 'nodb'}]
        syms = [{'name': 'Foo', 'ae_off': 0x2000}]
        rp._attach_extra_ae_variants(syms, addr_lib)
        assert 'nodb_off' not in syms[0]
        assert syms[0]['ae1799_off'] == 0x5000
    finally:
        rp.EXTRA_AE_VARIANTS = saved


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
