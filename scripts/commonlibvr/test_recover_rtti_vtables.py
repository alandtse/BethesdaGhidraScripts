#!/usr/bin/env python3
"""Unit tests for recover_rtti_vtables.py's clean_demangled_name (the pure,
Ghidra-free post-processing of a demangled RTTI type-descriptor name).

Run: python -m pytest test_recover_rtti_vtables.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import recover_rtti_vtables as rtti  # noqa: E402


def test_clean_strips_rtti_type_descriptor_suffix():
    # the demangler's own separator before the suffix is a literal underscore
    # (Foo`RTTI_Type_Descriptor' is not a form it emits) -- see _RTTI_SUFFIX.
    assert rtti.clean_demangled_name("Foo_`RTTI_Type_Descriptor'") == "Foo"


def test_clean_strips_class_qualifier():
    assert rtti.clean_demangled_name("class_Foo") == "Foo"


def test_clean_strips_qualifier_after_angle_bracket_and_comma():
    assert rtti.clean_demangled_name(
        "ConcreteFormFactory<class_AlchemyItem,struct_Bar>") == "ConcreteFormFactory<AlchemyItem,Bar>"


def test_clean_leaves_qualifier_alone_mid_identifier():
    # only strip class_/struct_/etc. right after start, '<', ',' or '(' -- never
    # inside an unrelated identifier that merely contains "class_" as a substring.
    assert rtti.clean_demangled_name("Fooclass_Bar") == "Fooclass_Bar"


def test_clean_strips_ptr_noise():
    assert rtti.clean_demangled_name("Foo___ptr64") == "Foo"
    assert rtti.clean_demangled_name("Foo__ptr32") == "Foo"


def test_clean_removes_all_spaces():
    assert rtti.clean_demangled_name("Foo Bar Baz") == "FooBarBaz"


def test_clean_drops_stray_underscore_before_bracket_or_comma():
    assert rtti.clean_demangled_name("Foo_>Bar") == "Foo>Bar"
    assert rtti.clean_demangled_name("Foo_,Bar") == "Foo,Bar"


def test_clean_combined_realistic_template_name():
    # Mirrors CommonLib's own half-mangled import form's un-doing: a template
    # instantiation with a qualifier, ptr noise, and a stray trailing underscore
    # from the old mangling all present together.
    raw = "ConcreteFormFactory<class_AlchemyItem,46_>__ptr64"
    assert rtti.clean_demangled_name(raw) == "ConcreteFormFactory<AlchemyItem,46>"


def test_clean_passthrough_on_empty_or_none():
    assert rtti.clean_demangled_name('') == ''
    assert rtti.clean_demangled_name(None) is None


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
