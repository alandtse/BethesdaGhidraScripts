"""Unit tests for the pure string_anchor_match enrichment planner.
No Ghidra required -- run with::

    python scripts/core/test_enrichment_plans.py
    # or: pytest scripts/core/test_enrichment_plans.py

ctor_plan's and globals_plan's tests moved to plans/test_ctor_plan.py and
plans/test_globals_plan.py as part of the DRY refactor's Phase 3 (both modules
turned out identical between core and commonlibvr, so they were merged into
core/plans/ rather than staying duplicated here).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import string_anchor_match as sam


# --------------------------------------------------------------------------
# string_anchor_match
# --------------------------------------------------------------------------
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


def _run():
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            print('  ok', name)
            n += 1
    print('%d tests passed' % n)


if __name__ == '__main__':
    _run()
