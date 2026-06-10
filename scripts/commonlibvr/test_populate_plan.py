#!/usr/bin/env python3
"""Unit tests for populate_plan (population-cycle decision logic).

Run: python -m pytest test_populate_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import populate_plan as pp  # noqa: E402


def test_is_generic_type():
    assert pp.is_generic_type('undefined8')
    assert pp.is_generic_type('longlong')
    assert pp.is_generic_type('void *')
    assert pp.is_generic_type('void *64')      # decorated bare-void pointer
    assert pp.is_generic_type('void*')
    assert pp.is_generic_type('undefined8 *')
    assert pp.is_generic_type('')
    assert pp.is_generic_type(None)
    assert not pp.is_generic_type('Actor *')
    assert not pp.is_generic_type('NiNode *')
    assert not pp.is_generic_type('BSTArray<void *>')   # named structural type is a gain
    assert not pp.is_generic_type('AITimer')


def test_should_apply_field_accepts_named_same_size_into_unknown():
    ok, why = pp.should_apply_field('unk88', 'undefined8', 'Actor *', 8, 8, 'high')
    assert ok and why == 'ok'
    ok, _ = pp.should_apply_field('pad40', 'undefined4', 'NiNode *', 8, 8, 'high')
    assert ok
    # undefined-typed slot with a non-unk name still counts as unknown
    ok, _ = pp.should_apply_field('field_x', 'undefined8', 'TESForm *', 8, 8, 'high')
    assert ok


def test_should_apply_field_refuses_clobber_generic_lowconf_mismatch():
    # existing real RE -> never overwrite
    assert not pp.should_apply_field('flags', 'NiNode *', 'Actor *', 8, 8, 'high')[0]
    # size-only generic inference -> not worth writing
    assert pp.should_apply_field('unk88', 'undefined8', 'longlong', 8, 8, 'high') == \
        (False, 'generic-size-only')
    # low confidence -> hold
    assert pp.should_apply_field('unk88', 'undefined8', 'Actor *', 8, 8, 'low') == \
        (False, 'low-confidence')
    # size mismatch -> would shift/overlap the next member
    assert pp.should_apply_field('unk88', 'undefined8', 'Actor', 16, 8, 'high') == \
        (False, 'size-mismatch')
    # a bare-void pointer is no better than the unk it would replace
    assert pp.should_apply_field('unk88', 'undefined8', 'void *64', 8, 8, 'high') == \
        (False, 'generic-size-only')


def test_coverage_delta_and_progress():
    before = {'thiscall': 100, 'named_fields': 50, 'unk_fields': 200, 'typed_params': 30}
    after = {'thiscall': 110, 'named_fields': 58, 'unk_fields': 188, 'typed_params': 34}
    d = pp.coverage_delta(before, after)
    assert d == {'thiscall': 10, 'named_fields': 8, 'unk_fields': -12, 'typed_params': 4}
    # progress = 10 + 8 + 4 - (-12) = 34
    assert pp.progress(d) == 34


def test_is_converged():
    big = pp.coverage_delta(
        {'thiscall': 0, 'named_fields': 0, 'unk_fields': 100, 'typed_params': 0},
        {'thiscall': 5, 'named_fields': 5, 'unk_fields': 90, 'typed_params': 5})
    assert not pp.is_converged(big)            # progress 25 >= 5
    tiny = pp.coverage_delta(
        {'thiscall': 10, 'named_fields': 10, 'unk_fields': 100, 'typed_params': 10},
        {'thiscall': 11, 'named_fields': 11, 'unk_fields': 99, 'typed_params': 10})
    assert pp.is_converged(tiny)               # progress 3 in [0,5)
    # exact fixpoint
    same = pp.coverage_delta({'thiscall': 1}, {'thiscall': 1})
    assert pp.is_converged(same)


def test_regression_is_not_convergence():
    # named_fields dropped / unk rose -> negative progress: a regression, NOT a fixpoint
    reg = pp.coverage_delta(
        {'thiscall': 100, 'named_fields': 145915, 'unk_fields': 1127, 'typed_params': 18282},
        {'thiscall': 100, 'named_fields': 145904, 'unk_fields': 1128, 'typed_params': 18282})
    assert pp.progress(reg) == -12
    assert pp.is_regression(reg)
    assert not pp.is_converged(reg)            # the bug we caught: must not claim converged


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
