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

    def create_struct(name, size, cat=None):
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


def test_doubled_is_replaced():
    # an exact 2x import-doubling artifact must be replaced with the generated layout
    assert apply_plan.ACTION['DOUBLED'] == 'REPLACE'
    structs = [_st('_GUID', 16)]
    fill_list, staging, created = _run(structs, {'_GUID': 'DOUBLED'})
    assert '_GUID' in staging                 # staged for replaceDataType
    assert len(fill_list) == 1                 # and filled with generated layout


def test_pdb_is_not_specially_protected():
    # PDB is just another data source, not authoritative: a size disagreement is a
    # plain DIVERGENT (replaced + logged for binary verification), never protected.
    assert 'PDB_DIVERGENT' not in apply_plan.ACTION
    structs = [_st('BSLightingShader', 248)]
    fill_list, staging, created = _run(structs, {'BSLightingShader': 'DIVERGENT'})
    assert 'BSLightingShader' in staging        # replaced, not protected


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


def test_split_qualified_simple():
    assert apply_plan.split_qualified('Actor::ClearData') == ['Actor', 'ClearData']
    assert apply_plan.split_qualified('A::B::C') == ['A', 'B', 'C']
    assert apply_plan.split_qualified('freefunc') == ['freefunc']


def test_split_qualified_ignores_template_colons():
    # the '::' inside <> must NOT split
    assert apply_plan.split_qualified('BSTArray<RE::TESForm>::push_back') == \
        ['BSTArray<RE::TESForm>', 'push_back']
    assert apply_plan.split_qualified('NiTMap<RE::A::B, RE::C>::Find') == \
        ['NiTMap<RE::A::B, RE::C>', 'Find']


def test_split_qualified_destructor_and_nested_template():
    assert apply_plan.split_qualified('NiPointer<RE::NiNode>::~NiPointer') == \
        ['NiPointer<RE::NiNode>', '~NiPointer']
    assert apply_plan.split_qualified('A::B<C<D::E>>::F') == ['A', 'B<C<D::E>>', 'F']


def test_class_namespace_plan_known_class():
    cn = {'Actor', 'BSGraphics::Renderer'}
    ns, leaf, ci = apply_plan.class_namespace_plan('Actor::ClearData', cn)
    assert ns == ['Actor'] and leaf == 'ClearData' and ci == 0
    ns2, leaf2, ci2 = apply_plan.class_namespace_plan('BSGraphics::Renderer::Init', cn)
    # 'Renderer' is the class (full 'BSGraphics::Renderer' known), BSGraphics is ns
    assert ns2 == ['BSGraphics', 'Renderer'] and leaf2 == 'Init' and ci2 == 1


def test_class_namespace_plan_unknown_is_namespace():
    # a C++ namespace (not a class) -> class_index None, components stay namespaces
    ns, leaf, ci = apply_plan.class_namespace_plan(
        'XAPOBaseWaveHlpNameSpace::IsValidXmaWaveFormat', set())
    assert ci is None and leaf == 'IsValidXmaWaveFormat'


def test_class_namespace_plan_drops_empty_components():
    # double-colon artifact 'Class::::Func1' must not yield an empty namespace
    ns, leaf, ci = apply_plan.class_namespace_plan(
        'SynchronizedQueue_IOTask::::Func1', {'SynchronizedQueue_IOTask'})
    assert '' not in ns
    assert ns == ['SynchronizedQueue_IOTask'] and leaf == 'Func1' and ci == 0


def test_ida_double_underscore_becomes_class_member():
    # IDA-style Class__Method (no '::') -> Class::Method when Class is known
    cn = {'BGSAttackData', 'BSStringPool'}
    ns, leaf, ci = apply_plan.class_namespace_plan('BGSAttackData__Ctor', cn)
    assert ns == ['BGSAttackData'] and leaf == 'Ctor' and ci == 0
    ns2, leaf2, ci2 = apply_plan.class_namespace_plan('BSStringPool__DrainQueue', cn)
    assert ns2 == ['BSStringPool'] and leaf2 == 'DrainQueue' and ci2 == 0


def test_double_underscore_unknown_head_left_alone():
    # head is not a known class -> not split (e.g. a Name__<addr> artifact)
    assert apply_plan.class_namespace_plan('Update_RegenDelay__140620CC0', {'Actor'}) is None
    assert apply_plan.class_namespace_plan('_helper_func_cdecl__1405C0870', {'Actor'}) is None


def test_redundant_doubled_class_prefix_stripped():
    # Class::Class_Method -> leaf Method
    cn = {'MessageBoxMenu'}
    ns, leaf, ci = apply_plan.class_namespace_plan(
        'MessageBoxMenu::MessageBoxMenu_RemoveMessageFromQueue', cn)
    assert ns == ['MessageBoxMenu'] and leaf == 'RemoveMessageFromQueue' and ci == 0


def test_class_namespace_plan_free_function():
    assert apply_plan.class_namespace_plan('malloc', {'Actor'}) is None


def test_class_namespace_plan_template_class_not_missplit():
    cn = {'BSTArray<RE::TESForm>'}
    ns, leaf, ci = apply_plan.class_namespace_plan(
        'BSTArray<RE::TESForm>::push_back', cn)
    assert ns == ['BSTArray<RE::TESForm>'] and leaf == 'push_back' and ci == 0


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
