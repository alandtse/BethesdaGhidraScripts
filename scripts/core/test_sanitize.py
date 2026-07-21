#!/usr/bin/env python3
"""Unit tests for engine.sanitize (pure text logic, no Ghidra).

Run: python -m pytest test_sanitize.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.sanitize import sanitize_component, sanitize_qualified, split_namespaced  # noqa: E402


def test_sanitize_component_passes_through_safe_name():
    assert sanitize_component("Foo") == "Foo"


def test_sanitize_component_replaces_disallowed_chars():
    assert sanitize_component("Foo Bar!") == "Foo_Bar_"


def test_sanitize_component_prefixes_leading_digit():
    assert sanitize_component("123Foo") == "_123Foo"


def test_sanitize_component_empty_or_whitespace_becomes_underscore():
    assert sanitize_component("") == "_"
    assert sanitize_component("   ") == "_"


def test_sanitize_component_keeps_template_and_ghidra_safe_punctuation():
    # <>$~?@- are all explicitly allowed
    assert sanitize_component("Foo<Bar>$~?@-") == "Foo<Bar>$~?@-"


def test_sanitize_component_rejects_colon_since_component_should_be_presplit():
    assert sanitize_component("Foo:Bar") == "Foo_Bar"


def test_split_namespaced_splits_on_double_colon_and_sanitizes_each_part():
    assert split_namespaced("Foo::Bar Baz::123Qux") == ["Foo", "Bar_Baz", "_123Qux"]


def test_sanitize_qualified_keeps_double_colon_separators():
    assert sanitize_qualified("Foo::Bar") == "Foo::Bar"


def test_sanitize_qualified_sanitizes_within_each_part_only():
    assert sanitize_qualified("Foo Bar::Baz!Qux") == "Foo_Bar::Baz_Qux"


def test_sanitize_qualified_allows_colon_and_period_within_a_part():
    # the wider allowed-charset is the whole point of this variant existing
    assert sanitize_qualified("Foo::v1.2.3") == "Foo::v1.2.3"


def test_sanitize_qualified_prefixes_leading_digit_per_part():
    assert sanitize_qualified("Foo::123Bar") == "Foo::_123Bar"


def test_sanitize_qualified_empty_part_becomes_underscore():
    assert sanitize_qualified("Foo::::Bar") == "Foo::_::Bar"


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
