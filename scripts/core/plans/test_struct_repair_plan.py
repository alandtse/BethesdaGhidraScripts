#!/usr/bin/env python3
"""Unit tests for plans.struct_repair_plan (pure scrambled-struct placement rules).

Run: python -m pytest test_struct_repair_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plans import struct_repair_plan as sr  # noqa: E402


def C(offset, length, name, defined=True):
    return {'offset': offset, 'length': length, 'name': name, 'defined': defined}


def scrambled():
    # true layout: A_0 @0, B_8 @8, C_10 @0x10, D_18 @0x18 ; listed at wrong offsets
    return [C(0, 8, 'D_18'), C(8, 8, 'C_10'), C(0x10, 8, 'B_8'), C(0x18, 8, 'A_0')]


def test_candidate_names():
    assert sr.is_candidate_name('NiTimeController')
    for n in ('NiNode_vtbl', 'NiNode_vtbl_2', 'Foo__VFTable', 'Foo.conflict', '_GUID', 'tagRECT', 'anonymous_1'):
        assert not sr.is_candidate_name(n), n


def test_sorts_by_suffix():
    plan, notes, reason = sr.plan_unscramble('S', 0x20, scrambled())
    assert reason == '' and notes == []
    assert [(p['offset'], p['name']) for p in plan] == [(0, 'A_0'), (8, 'B_8'), (0x10, 'C_10'), (0x18, 'D_18')]


def test_already_in_place_or_small_is_untouched():
    ok = [C(0, 8, 'A_0'), C(8, 8, 'B_8'), C(0x10, 8, 'C_10'), C(0x18, 8, 'D_18')]
    assert sr.plan_unscramble('S', 0x20, ok) == (None, [], '')
    assert sr.plan_unscramble('S', 0x10, scrambled()[:3]) == (None, [], '')
    assert sr.plan_unscramble('S', 0x20, scrambled(), packed=True) == (None, [], '')
    assert sr.plan_unscramble('S_vtbl', 0x20, scrambled()) == (None, [], '')


def test_base_member_is_never_touched():
    comps = scrambled()
    comps[0] = C(0, 8, '_base')
    assert sr.plan_unscramble('S', 0x20, comps) == (None, [], '')


def test_hand_added_member_stays_and_twin_is_dropped():
    comps = scrambled() + [C(0x20, 8, 'handAdded')]
    comps.append(C(0x20, 8, 'Twin_20'))
    plan, notes, reason = sr.plan_unscramble('S', 0x28, comps)
    assert reason == ''
    assert [p['name'] for p in plan] == ['A_0', 'B_8', 'C_10', 'D_18', 'handAdded']
    assert any('twin' in n for n in notes)


def test_suffixed_member_inside_hand_added_is_dropped():
    comps = scrambled() + [C(0x20, 0x10, 'blob'), C(0, 4, 'Inner_24')]
    plan, notes, reason = sr.plan_unscramble('S', 0x30, comps)
    assert reason == ''
    assert 'Inner_24' not in [p['name'] for p in plan]
    assert any('inside hand-added' in n for n in notes)


def test_zero_length_member_is_omitted():
    comps = scrambled() + [C(0, 0, 'Empty_20')]
    plan, notes, reason = sr.plan_unscramble('S', 0x20, comps)
    assert reason == '' and 'Empty_20' not in [p['name'] for p in plan]
    assert any('zero-length' in n for n in notes)


def test_overlap_refuses():
    comps = scrambled()
    comps[0] = C(0, 16, 'D_18')       # 0x18..0x28 collides with nothing, but make C overlap
    comps[1] = C(8, 16, 'C_10')       # 0x10..0x20 overlaps D_18
    plan, _notes, reason = sr.plan_unscramble('S', 0x28, comps)
    assert plan is None and reason.startswith('overlap')


def test_pad_is_trimmed_to_free_runs():
    comps = [C(0, 8, 'D_18'), C(8, 8, 'C_10'), C(0x10, 8, 'B_8'), C(0x18, 8, 'A_0'),
             C(0x20, 0x20, '_pad_20')]
    comps.append(C(0x40, 8, 'E_28'))
    plan, _n, reason = sr.plan_unscramble('S', 0x40, comps)
    assert reason == ''
    pads = [(p['offset'], p['length']) for p in plan if p['src'] is None]
    assert pads == [(0x20, 8), (0x30, 0x10)]


def test_low_coverage_refuses():
    comps = [C(0, 4, 'A_0'), C(4, 4, 'B_10'), C(8, 4, 'C_20'), C(12, 4, 'D_30')]
    plan, _n, reason = sr.plan_unscramble('S', 0x1000, comps)
    assert plan is None and reason.startswith('low coverage')


def test_verify_plan():
    plan = [{'offset': 0, 'name': 'A_0'}, {'offset': 8, 'name': 'B_8'}]
    assert sr.verify_plan(plan, {'A_0': 0, 'B_8': 8})
    assert not sr.verify_plan(plan, {'A_0': 0, 'B_8': 16})


def test_vtable_stores_consistent():
    assert sr.vtable_stores_consistent({0, 0x30}, {0, 0x30}) == 'pass'
    assert sr.vtable_stores_consistent({0, 0x30}, {0x38}) == 'fail'
    assert sr.vtable_stores_consistent({0}, {0}) == 'n/a'
    assert sr.vtable_stores_consistent({0, 0x30}, set()) == 'n/a'
