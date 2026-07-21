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
    # STUB_UPGRADE (wrong-size empty stub) / EXTENDS / DIVERGENT stage a new shell and
    # swap via replaceDataType.
    structs = [_st('S', 8), _st('E', 8), _st('V', 8)]
    status = {'S': 'STUB_UPGRADE', 'E': 'EXTENDS', 'V': 'DIVERGENT'}
    fill_list, staging, created = _run(structs, status)
    assert set(staging.keys()) == {'S', 'E', 'V'}
    for name, (sdt, existing) in staging.items():
        assert sdt == ('STAGE', name)
        assert existing == ('EXISTING', name)
    assert len(fill_list) == 3


def test_stub_fill_fills_existing_in_place():
    # STUB_FILL (same-size empty stub) must FILL the existing type in place -- NOT
    # stage + replaceDataType (~2-3s each; hours for AE's ~16.9k same-size stubs).
    structs = [_st('S', 8)]
    fill_list, staging, created = _run(structs, {'S': 'STUB_FILL'})
    assert staging == {}                                   # no staging / replaceDataType
    assert fill_list == [(('EXISTING', 'S'), _st('S', 8))]  # fills the EXISTING type


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
    # Class::Class_Method -> leaf Method (single and double underscore)
    ns, leaf, ci = apply_plan.class_namespace_plan(
        'MessageBoxMenu::MessageBoxMenu_RemoveMessageFromQueue', {'MessageBoxMenu'})
    assert ns == ['MessageBoxMenu'] and leaf == 'RemoveMessageFromQueue' and ci == 0
    ns2, leaf2, _ = apply_plan.class_namespace_plan('Actor::Actor__ProcessInWater', {'Actor'})
    assert leaf2 == 'ProcessInWater'   # double underscore fully stripped, no leading _


def test_overload_disambiguator_not_stripped():
    # Class_2 is an overload disambiguator, not a doubled prefix -> keep it
    ns, leaf, ci = apply_plan.class_namespace_plan(
        'CombatBehaviorAcquireResource::CombatBehaviorAcquireResource_2',
        {'CombatBehaviorAcquireResource'})
    assert leaf == 'CombatBehaviorAcquireResource_2'   # not reduced to '2'


def test_class_namespace_plan_free_function():
    assert apply_plan.class_namespace_plan('malloc', {'Actor'}) is None


def test_class_namespace_plan_template_class_not_missplit():
    cn = {'BSTArray<RE::TESForm>'}
    ns, leaf, ci = apply_plan.class_namespace_plan(
        'BSTArray<RE::TESForm>::push_back', cn)
    assert ns == ['BSTArray<RE::TESForm>'] and leaf == 'push_back' and ci == 0


def _plan_row(name, action):
    # (name, status, action, gen_size, existing_size, existing_category) --
    # select_write_targets only reads the first 3 fields.
    return (name, action, action, 0, 0, '/types.h')


def test_select_write_targets_no_cap_no_exclude_selects_all_writes():
    plan = [_plan_row('A', 'CREATE'), _plan_row('B', 'REUSE'), _plan_row('C', 'REPLACE')]
    assert apply_plan.select_write_targets(plan) == {'A', 'C'}


def test_select_write_targets_excludes_named_structs():
    plan = [_plan_row('Actor', 'REPLACE'), _plan_row('B', 'FILL')]
    allowed = apply_plan.select_write_targets(plan, exclude_names=['Actor'])
    assert allowed == {'B'}


def test_select_write_targets_excluded_name_never_counts_against_cap():
    plan = [_plan_row('Actor', 'REPLACE'), _plan_row('B', 'FILL'), _plan_row('C', 'CREATE')]
    allowed = apply_plan.select_write_targets(plan, exclude_names=['Actor'], max_writes=1)
    assert allowed == {'B'}   # cap consumed by B, not by the excluded Actor


def test_select_write_targets_cap_takes_first_n_in_plan_order():
    plan = [_plan_row('A', 'CREATE'), _plan_row('B', 'FILL'), _plan_row('C', 'REPLACE')]
    assert apply_plan.select_write_targets(plan, max_writes=2) == {'A', 'B'}


def test_select_write_targets_zero_cap_means_unlimited():
    plan = [_plan_row('A', 'CREATE'), _plan_row('B', 'FILL')]
    assert apply_plan.select_write_targets(plan, max_writes=0) == {'A', 'B'}


def test_select_write_targets_resumable_across_calls():
    # Simulates re-running with the same cap after a batch already landed: structs
    # applied in call 1 reclassify as REUSE (no longer write-actioned) in call 2, so
    # the same cap makes forward progress on the remaining backlog automatically.
    plan_call1 = [_plan_row('A', 'CREATE'), _plan_row('B', 'CREATE'), _plan_row('C', 'CREATE')]
    call1 = apply_plan.select_write_targets(plan_call1, max_writes=2)
    assert call1 == {'A', 'B'}
    plan_call2 = [_plan_row('A', 'REUSE'), _plan_row('B', 'REUSE'), _plan_row('C', 'CREATE')]
    call2 = apply_plan.select_write_targets(plan_call2, max_writes=2)
    assert call2 == {'C'}


def _cat_row(name, action, category):
    return (name, action, action, 0, 0, category)


def test_select_write_targets_prioritize_category_drains_first_under_cap():
    # A '/CommonLibSSE/std' noise entry sits BEFORE the '/types.h' entry in plan
    # order -- without prioritization the cap would pick the noise entry first.
    plan = [
        _cat_row('_Conjunction<true, X>', 'FILL', '/CommonLibSSE/std'),
        _cat_row('RealActorStruct', 'REPLACE', '/types.h'),
    ]
    allowed = apply_plan.select_write_targets(plan, max_writes=1, prioritize_category='/types.h')
    assert allowed == {'RealActorStruct'}


def test_select_write_targets_prioritize_category_preserves_order_within_group():
    plan = [
        _cat_row('A', 'CREATE', '/types.h'),
        _cat_row('Noise1', 'FILL', '/CommonLibSSE/std'),
        _cat_row('B', 'CREATE', '/types.h'),
        _cat_row('Noise2', 'FILL', '/CommonLibSSE/std'),
    ]
    allowed = apply_plan.select_write_targets(plan, max_writes=3, prioritize_category='/types.h')
    # both /types.h entries first (in original relative order), then one noise entry
    assert allowed == {'A', 'B', 'Noise1'}


def test_select_write_targets_no_prioritize_category_keeps_plain_plan_order():
    # Default behavior (no prioritize_category) is unchanged from before this feature.
    plan = [
        _cat_row('Noise1', 'FILL', '/CommonLibSSE/std'),
        _cat_row('A', 'CREATE', '/types.h'),
    ]
    allowed = apply_plan.select_write_targets(plan, max_writes=1)
    assert allowed == {'Noise1'}


def test_select_write_targets_only_names_restricts_to_named_structs():
    # single-struct spot-fix: apply just the one name asked for, ignore the rest of
    # the (fully computed) plan even though they're also write-actioned.
    plan = [_plan_row('A', 'CREATE'), _plan_row('B', 'REPLACE'), _plan_row('C', 'FILL')]
    allowed = apply_plan.select_write_targets(plan, only_names=['B'])
    assert allowed == {'B'}


def test_select_write_targets_only_names_unmatched_name_is_noop():
    plan = [_plan_row('A', 'CREATE')]
    allowed = apply_plan.select_write_targets(plan, only_names=['NotInPlan'])
    assert allowed == set()


def test_select_write_targets_only_names_combines_with_exclude():
    # exclude_names still wins even if the same name is also requested via only_names.
    plan = [_plan_row('A', 'CREATE'), _plan_row('B', 'REPLACE')]
    allowed = apply_plan.select_write_targets(plan, exclude_names=['A'], only_names=['A', 'B'])
    assert allowed == {'B'}


def test_select_write_targets_only_names_reuse_or_protect_never_selected():
    # only_names can't force a non-write action (REUSE/PROTECT) to be applied --
    # it's still a filter over write-ACTIONED entries only, not a status override.
    plan = [_plan_row('A', 'REUSE'), _plan_row('B', 'PROTECT')]
    allowed = apply_plan.select_write_targets(plan, only_names=['A', 'B'])
    assert allowed == set()


# The four tests below cover pure logic extracted from apply_enrich.py itself
# (DRY refactor Phase 3) -- previously embedded inline, coupled to a live Ghidra
# object, and untested.

def test_is_placeholder_type_name_recognizes_known_placeholders():
    for n in ('undefined', 'uint', 'int', 'byte', 'sbyte', 'ushort', 'short',
              'ulong', 'long', 'ulonglong', 'longlong'):
        assert apply_plan.is_placeholder_type_name(n)
    assert apply_plan.is_placeholder_type_name('undefined4')
    assert apply_plan.is_placeholder_type_name('char[16]')


def test_is_placeholder_type_name_none_is_placeholder():
    assert apply_plan.is_placeholder_type_name(None)


def test_is_placeholder_type_name_rejects_concrete_types():
    assert not apply_plan.is_placeholder_type_name('TESForm')
    assert not apply_plan.is_placeholder_type_name('NiAVObject *')
    assert not apply_plan.is_placeholder_type_name('BSTArray<TESForm*>')


def test_relocation_id_comment_both_ids():
    assert apply_plan.relocation_id_comment(123, 456) == 'RELOCATION_ID(123, 456)'


def test_relocation_id_comment_se_only():
    assert apply_plan.relocation_id_comment(123, None) == 'REL::ID(123)'
    assert apply_plan.relocation_id_comment(123, 0) == 'REL::ID(123)'


def test_relocation_id_comment_ae_only():
    assert apply_plan.relocation_id_comment(None, 456) == 'REL::ID(456)'
    assert apply_plan.relocation_id_comment(0, 456) == 'REL::ID(456)'


def test_relocation_id_comment_neither_returns_none():
    assert apply_plan.relocation_id_comment(None, None) is None
    assert apply_plan.relocation_id_comment(0, 0) is None


def test_sig_key_combines_return_and_params():
    assert apply_plan.sig_key('void', ['int', 'char *']) == ('void', ('int', 'char *'))


def test_sig_key_no_params():
    assert apply_plan.sig_key('bool', []) == ('bool', ())


def test_sig_key_equal_for_same_signature_different_list_identity():
    a = apply_plan.sig_key('void', ['int', 'float'])
    b = apply_plan.sig_key('void', ['int', 'float'])
    assert a == b


def test_should_upgrade_signature_rejects_curated_sources():
    assert not apply_plan.should_upgrade_signature('USER_DEFINED')
    assert not apply_plan.should_upgrade_signature('IMPORTED')


def test_should_upgrade_signature_allows_auto_inferred_sources():
    assert apply_plan.should_upgrade_signature('DEFAULT')
    assert apply_plan.should_upgrade_signature('ANALYSIS')


# The tests below cover pure logic extracted from demangle_ghidra_names.py (same DRY
# refactor pattern) -- previously embedded inline, coupled to live Ghidra DataType
# objects only via .getName(), and untested.

def test_mangle_type_name_strips_re_namespace_and_template_punctuation():
    assert apply_plan.mangle_type_name('NiPointer<NiAVObject>') == 'NiPointer_NiAVObject_'


def test_mangle_type_name_strips_re_prefix():
    assert apply_plan.mangle_type_name('RE::TESObjectWEAP::Data') == 'TESObjectWEAP__Data'


def test_mangle_type_name_no_special_chars_is_unchanged():
    assert apply_plan.mangle_type_name('TESForm') == 'TESForm'


def test_build_mangle_map_maps_mangled_to_proper():
    mmap = apply_plan.build_mangle_map({'NiPointer<NiAVObject>', 'TESForm'})
    assert mmap == {'NiPointer_NiAVObject_': 'NiPointer<NiAVObject>'}


def test_build_mangle_map_drops_ambiguous_collisions():
    # two different proper spellings that happen to mangle to the same string ->
    # neither should be guessed; the whole key is dropped.
    proper_a = 'Foo<Bar>'
    proper_b = 'Foo,Bar,'   # mangles to the same 'Foo_Bar_' as proper_a
    assert apply_plan.mangle_type_name(proper_a) == apply_plan.mangle_type_name(proper_b)
    mmap = apply_plan.build_mangle_map({proper_a, proper_b})
    assert 'Foo_Bar_' not in mmap


def test_plan_demangle_renames_when_proper_name_absent():
    mmap = {'NiPointer_NiAVObject_': 'NiPointer<NiAVObject>'}
    renames, merges = apply_plan.plan_demangle(mmap, ['NiPointer_NiAVObject_', 'TESForm'])
    assert renames == [('NiPointer_NiAVObject_', 'NiPointer<NiAVObject>')]
    assert merges == []


def test_plan_demangle_merges_when_proper_name_already_exists():
    mmap = {'NiPointer_NiAVObject_': 'NiPointer<NiAVObject>'}
    renames, merges = apply_plan.plan_demangle(
        mmap, ['NiPointer_NiAVObject_', 'NiPointer<NiAVObject>'])
    assert renames == []
    assert merges == [('NiPointer_NiAVObject_', 'NiPointer<NiAVObject>')]


def test_plan_demangle_ignores_names_not_in_map():
    renames, merges = apply_plan.plan_demangle({}, ['TESForm', 'Actor'])
    assert renames == [] and merges == []


def test_plan_demangle_ignores_self_mapped_names():
    # a name that mangles to itself (mmap wouldn't include it, but defensively check
    # plan_demangle also skips a no-op mapping if one were present)
    renames, merges = apply_plan.plan_demangle({'TESForm': 'TESForm'}, ['TESForm'])
    assert renames == [] and merges == []


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
