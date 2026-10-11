#!/usr/bin/env python3
"""Unit tests for plans.vr_rebase_plan (pure VR struct rebase rules).

Run: python -m pytest test_vr_rebase_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plans import vr_rebase_plan as rb  # noqa: E402


def case(**over):
    base = dict(
        vr={'alloc': 0x170, 'len': 0x170},
        se={'alloc': 0x148, 'comps': [(0x00, 0x138, 'base_blob', 'char[312]'),
                                      (0x138, 0xC, 'lodTriangleCounts_138', 'uint32[3]'),
                                      (0x144, 4, '_pad_144', 'uint32')]},
        vr_parent={'alloc': 0x160}, se_parent={'alloc': 0x138}, parent_len=0x160)
    base.update(over)
    return base


def test_own_members_move_by_the_parent_delta_and_lose_stale_suffixes():
    plan, reason = rb.plan_rebase(**case())
    assert reason == ''
    assert plan['delta'] == 0x28 and plan['length'] == 0x170 and plan['parent_len'] == 0x160
    assert plan['members'] == [{'offset': 0x160, 'length': 0xC, 'name': 'lodTriangleCounts',
                                'type': 'uint32[3]', 'se_offset': 0x138}]


def test_zero_delta_is_skipped_as_already_right():
    plan, reason = rb.plan_rebase(
        vr={'alloc': 0x148, 'len': 0x148},
        se={'alloc': 0x148, 'comps': [(0x138, 8, 'counts_138', 'uint64')]},
        vr_parent={'alloc': 0x138}, se_parent={'alloc': 0x138}, parent_len=0x138)
    assert plan is None and reason.startswith('no shift')


def test_refusals():
    cases = {
        'missing info': case(se={}),
        'size unresolved': case(vr={'alloc': None, 'len': 0x170}),
        'VR parent Ghidra len': case(parent_len=0x150),
        'VR Ghidra len': case(vr={'alloc': 0x170, 'len': 0x100}),
        'delta mismatch': case(vr={'alloc': 0x180, 'len': 0x180}),
    }
    for needle, kwargs in cases.items():
        plan, reason = rb.plan_rebase(**kwargs)
        assert plan is None and needle in reason, (needle, reason)


def test_member_straddling_the_parent_end_refuses():
    se = {'alloc': 0x148, 'comps': [(0x130, 0x10, 'straddler', 'char[16]')]}
    plan, reason = rb.plan_rebase(**case(se=se))
    assert plan is None and 'straddles' in reason


def test_members_past_the_class_end_are_dropped():
    se = {'alloc': 0x148, 'comps': [(0x138, 8, 'ok_138', 'uint64'), (0x146, 8, 'beyond', 'uint64')]}
    plan, _ = rb.plan_rebase(**case(se=se))
    assert [m['name'] for m in plan['members']] == ['ok']


def test_strip_offset_suffix():
    assert rb.strip_offset_suffix('WorldTransform_7C') == 'WorldTransform'
    assert rb.strip_offset_suffix('_pad_7C') == '_pad_7C'
    assert rb.strip_offset_suffix('plain') == 'plain'
    assert rb.strip_offset_suffix(None) is None
