#!/usr/bin/env python3
"""Unit tests for plans.string_anchor_match (string-anchored rename matching logic).
No Ghidra required.

Was core/test_enrichment_plans.py before the DRY refactor's Phase 3 moved
string_anchor_match.py itself into core/plans/ (it was already the correctly-factored
shared module -- commonlibvr/string_anchored_rename.py had instead reimplemented the
identical regex/resolve logic inline instead of importing it).

Run: python -m pytest test_string_anchor_match.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plans import string_anchor_match as sam  # noqa: E402


def test_timer_name():
    assert sam.timer_name('TthkbWorld::step') == 'hkbWorld::step'
    assert sam.timer_name('LtBSOffsetAnimationGenerator::generate') == \
        'BSOffsetAnimationGenerator::generate'
    assert sam.timer_name('hkbWorld::step') is None          # no Lt/Tt prefix
    assert sam.timer_name('Tt has a space here') is None


def test_message_name():
    assert sam.message_name(
        'BGSSaveLoadManager::CopySaveGamesFromHost failed to read header') == \
        'BGSSaveLoadManager::CopySaveGamesFromHost'
    assert sam.message_name('GFxDrawText::Display is called without') == \
        'GFxDrawText::Display'
    # hk* excluded, too-short message excluded, deep nesting excluded
    assert sam.message_name('hkThing::foo bar baz qux') is None
    assert sam.message_name('A::b two') is None              # <3 words after
    assert sam.message_name('short') is None


def test_telemetry_name():
    assert sam.telemetry_name('bnet::Telemetry::Log', {'bnet'}) == 'bnet::Telemetry::Log'
    assert sam.telemetry_name('hkCachedHashMap::Elem', {'bnet'}) is None  # ns not allowed
    assert sam.telemetry_name('bnet::X', set()) is None      # empty allowlist


def test_match_any_prefers_timer_and_flags_it():
    name, is_timer = sam.match_any('TthkbWorld::step', {'bnet'})
    assert name == 'hkbWorld::step' and is_timer is True


def test_match_any_falls_back_to_message_then_telemetry():
    name, is_timer = sam.match_any(
        'BGSSaveLoadManager::CopySaveGamesFromHost failed to read header', {'bnet'})
    assert name == 'BGSSaveLoadManager::CopySaveGamesFromHost' and is_timer is False
    name2, is_timer2 = sam.match_any('bnet::Telemetry::Log', {'bnet'})
    assert name2 == 'bnet::Telemetry::Log' and is_timer2 is False


def test_match_any_no_match_returns_none():
    name, is_timer = sam.match_any('not a match at all!!', {'bnet'})
    assert name is None and is_timer is False


def test_resolve_consensus():
    # one function, one consistent name, name unique -> applied
    by_func = {0x10: ('fA', {'Foo::bar'}), 0x20: ('fB', {'Baz::qux'})}
    plan, ambiguous = sam.resolve(by_func)
    assert (0x10, 'Foo::bar') in plan and (0x20, 'Baz::qux') in plan
    assert not ambiguous


def test_resolve_ambiguous():
    # same name from two functions -> ambiguous, not guessed
    by_func = {0x10: ('fA', {'Foo::bar'}), 0x20: ('fB', {'Foo::bar'})}
    plan, ambiguous = sam.resolve(by_func)
    assert not plan and 'Foo::bar' in ambiguous
    # one function, two names -> ambiguous
    by_func2 = {0x30: ('fC', {'A::b', 'C::d'})}
    plan2, ambiguous2 = sam.resolve(by_func2)
    assert not plan2 and ambiguous2


def test_resolve_returns_sorted_plan():
    by_func = {0x20: ('fB', {'Baz::qux'}), 0x10: ('fA', {'Foo::bar'})}
    plan, _ = sam.resolve(by_func)
    assert plan == sorted(plan)


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
