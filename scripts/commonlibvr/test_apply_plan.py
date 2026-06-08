#!/usr/bin/env python3
"""Unit tests for apply_plan.select_fill_targets (CommonLibVR enrich apply planning).

Regression coverage for the enum/struct name-collision crash: the apply once
re-derived its fill targets from the shared `created` name->dt map, which the enum
pass also writes to, so an enum sharing a struct's leaf name redirected a fill onto
the enum object and crashed (EnumDB has no getNumDefinedComponents). Fill targets
must instead be tracked at creation time. These tests run without Ghidra.

Run: python -m pytest test_apply_plan.py   (or: python test_apply_plan.py)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import apply_plan  # noqa: E402


def _st(name, size):
    # (name, size, category, fields, bases, has_vtable) -- only name/size used here
    return (name, size, '/CommonLibSSE/RE', [], [], False)


def _run(structs, status_map):
    """Drive select_fill_targets with fake dt factories and a created[] map that
    the enum pass would clobber. Returns (fill_list, staging, created)."""
    def classify_fn(st, live):
        return {'status': status_map[st[0]], 'best': ('EXISTING', st[0])}

    created = {}

    def create_struct(name, size):
        return ('STRUCT', name)

    def stage_struct(name, size, existing):
        return ('STAGE', name)

    def register(st, dt):
        created[st[0]] = dt

    fill_list, staging = apply_plan.select_fill_targets(
        structs, classify_fn, None, create_struct, stage_struct, register=register)
    return fill_list, staging, created


def test_enum_name_collision_does_not_pollute_fill_targets():
    # 'Color' is a CREATE struct that also exists as an enum elsewhere.
    structs = [_st('Color', 16), _st('Foo', 8), _st('Bar', 4)]
    status = {'Color': 'NEW', 'Foo': 'DIVERGENT', 'Bar': 'MATCH'}
    fill_list, staging, created = _run(structs, status)

    # The enum pass clobbers created['Color'] with an enum-like object (the old bug).
    created['Color'] = ('ENUM', 'Color')

    targets = [dt for dt, _st_ in fill_list]
    # fill targets are the struct/stage shells captured at creation, never the enum
    assert ('STRUCT', 'Color') in targets
    assert ('STAGE', 'Foo') in targets
    assert ('ENUM', 'Color') not in targets
    assert all(dt[0] in ('STRUCT', 'STAGE') for dt in targets)


def test_reuse_and_protect_are_never_filled():
    structs = [_st('A', 8), _st('B', 8), _st('C', 8), _st('D', 8)]
    status = {'A': 'MATCH', 'B': 'GEN_EMPTY', 'C': 'HANDCURATED', 'D': 'SUSPICIOUS'}
    fill_list, staging, created = _run(structs, status)
    assert fill_list == []          # nothing created/staged -> nothing filled
    assert staging == {}
    # existing types are registered but untouched
    assert created['A'] == ('EXISTING', 'A')
    assert created['C'] == ('EXISTING', 'C')


def test_replace_actions_populate_staging():
    structs = [_st('S', 8), _st('E', 8), _st('V', 8)]
    status = {'S': 'STUB_UPGRADE', 'E': 'EXTENDS', 'V': 'DIVERGENT'}
    fill_list, staging, created = _run(structs, status)
    assert set(staging.keys()) == {'S', 'E', 'V'}
    for name, (sdt, existing) in staging.items():
        assert sdt == ('STAGE', name)
        assert existing == ('EXISTING', name)
    assert len(fill_list) == 3      # all three staged shells get filled


def test_new_creates_shell_and_fills():
    structs = [_st('NewType', 24)]
    fill_list, staging, created = _run(structs, {'NewType': 'NEW'})
    assert staging == {}
    assert fill_list == [(('STRUCT', 'NewType'), _st('NewType', 24))]


def test_unknown_status_defaults_to_protect():
    structs = [_st('Weird', 8)]
    fill_list, staging, created = _run(structs, {'Weird': 'NOT_A_REAL_STATUS'})
    assert fill_list == []          # unknown -> PROTECT -> not filled
    assert created['Weird'] == ('EXISTING', 'Weird')


def test_enum_parent_key_disambiguates_bare_names():
    # same leaf 'Flag' under different parents must not collide
    k1 = apply_plan.enum_parent_key('/CommonLibSSE/RE/ACTOR_BASE_DATA', 'Flag')
    k2 = apply_plan.enum_parent_key('/CommonLibVR.pdb/ACTOR_BASE_DATA', 'Flag')
    k3 = apply_plan.enum_parent_key('/CommonLibSSE/RE/TESForm', 'Flag')
    assert k1 == ('ACTOR_BASE_DATA', 'Flag')
    assert k1 == k2          # same parent across root categories -> match
    assert k1 != k3          # different parent -> distinct


def test_classify_enum_new():
    action, add = apply_plan.classify_enum(4, [('A', 0), ('B', 1)], None, [])
    assert action == 'NEW'
    assert add == [('A', 0), ('B', 1)]


def test_classify_enum_match_when_subset():
    action, add = apply_plan.classify_enum(4, [('A', 0)], 4, ['A', 'B'])
    assert action == 'MATCH'
    assert add == []


def test_classify_enum_extend_adds_only_missing():
    # generated has B,C that existing lacks; existing A is preserved
    action, add = apply_plan.classify_enum(4, [('A', 0), ('B', 1), ('C', 2)], 4, ['A'])
    assert action == 'EXTEND'
    assert add == [('B', 1), ('C', 2)]


def test_classify_enum_keep_on_size_diff():
    action, add = apply_plan.classify_enum(1, [('A', 0), ('B', 1)], 4, ['A'])
    assert action == 'KEEP_SIZE'
    assert add == []


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
    print('\n{}/{} passed'.format(len(fns) - failed, len(fns)))
    sys.exit(1 if failed else 0)
