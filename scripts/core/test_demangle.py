#!/usr/bin/env python3
"""Unit tests for engine.demangle (pure text logic, no Ghidra).

Run: python -m pytest test_demangle.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.demangle import demangle_class  # noqa: E402


def test_non_msvc_prefix_returned_unchanged():
    assert demangle_class("SomethingElse") == "SomethingElse"


def test_simple_class_name():
    assert demangle_class(".?AVFoo@@") == "Foo"


def test_simple_struct_name():
    assert demangle_class(".?AUFoo@@") == "Foo"


def test_enum_class_prefix():
    assert demangle_class(".?AWFoo@@") == "Foo"


def test_nested_class_reverses_at_signs_to_double_colon():
    # MSVC encodes Outer::Inner as "Inner@Outer@@" (innermost first)
    assert demangle_class(".?AVInner@Outer@@") == "Outer::Inner"


def test_deeply_nested_class():
    assert demangle_class(".?AVLeaf@Mid@Root@@") == "Root::Mid::Leaf"


def test_empty_body_returns_unknown_class():
    assert demangle_class(".?AV@@") == "UnknownClass"


def test_template_name_falls_back_to_sanitized_flat_form():
    # BSTArray<Foo> mangles roughly as ".?AV?$BSTArray@VFoo@@@@"
    mangled = ".?AV?$BSTArray@VFoo@@@@"
    result = demangle_class(mangled)
    assert "T_" in result
    assert "?" not in result


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
