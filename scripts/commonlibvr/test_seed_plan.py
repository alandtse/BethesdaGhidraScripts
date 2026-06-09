#!/usr/bin/env python3
"""Unit tests for seed_plan (this-pointer seeder decision logic).

Run: python -m pytest test_seed_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import seed_plan as sp  # noqa: E402


def test_is_untyped():
    assert sp.is_untyped(None)
    assert sp.is_untyped('')
    assert sp.is_untyped('undefined8')
    assert sp.is_untyped('undefined *')
    assert sp.is_untyped('void *')
    assert sp.is_untyped('void *64')
    assert not sp.is_untyped('Actor *')
    assert not sp.is_untyped('NiNode *64')


def test_seed_when_untyped_and_unprotected():
    assert sp.should_seed_this(True, 'ClearData', 'undefined8', 'ANALYSIS', False)[0] == 'seed'
    assert sp.should_seed_this(True, 'ClearData', None, 'DEFAULT', False)[0] == 'seed'
    # constructors/destructors take a this too
    assert sp.should_seed_this(True, '~Actor', 'void *', 'ANALYSIS', False)[0] == 'seed'


def test_skip_protected_source():
    assert sp.should_seed_this(True, 'ClearData', 'undefined8', 'IMPORTED', False) == \
        ('skip', 'protected-source')
    assert sp.should_seed_this(True, 'ClearData', None, 'USER_DEFINED', False)[0] == 'skip'


def test_skip_already_typed():
    assert sp.should_seed_this(True, 'ClearData', 'Actor *', 'ANALYSIS', False) == \
        ('skip', 'already-typed')


def test_skip_static_operator_unknown_class():
    assert sp.should_seed_this(True, 'GetSingleton', None, 'ANALYSIS', True)[0] == 'skip'
    assert sp.should_seed_this(True, 'operator==', None, 'ANALYSIS', False)[0] == 'skip'
    assert sp.should_seed_this(False, 'ClearData', None, 'ANALYSIS', False) == \
        ('skip', 'class-type-not-found')


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
