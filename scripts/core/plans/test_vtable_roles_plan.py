#!/usr/bin/env python3
"""Unit tests for plans.vtable_roles_plan (pure vtable-role naming rules).

Run: python -m pytest test_vtable_roles_plan.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plans import vtable_roles_plan as vr  # noqa: E402

V = 0x141234560


def I(text, refs=(), flows=()):  # noqa: E743 - short on purpose, mirrors (text, refs, flows)
    return (text, list(refs), list(flows))


def wrapper_plain(size_imm=0x148, callee='sub_1'):
    return [I('MOV qword ptr [RSP + 0x8],RBX'), I('MOV EBX,EDX'), I('CALL 0x1', flows=[callee]),
            I('TEST BL,0x1'), I('MOV EDX,0x%X' % size_imm), I('CALL 0x2', flows=['NiMemFree'])]


def ctor_insns(tail_jump_to=None):
    head = [I('MOV RBX,RCX'), I('CALL 0x5', flows=['NiTriShape::ctor']),
            I('LEA RAX,[0x%X]' % V, refs=[V]), I('MOV qword ptr [RBX],RAX')]
    if tail_jump_to:
        return head + [I('JMP 0x9', flows=[tail_jump_to])]
    return head + [I('MOV RAX,RBX'), I('RET')]


def test_rtti_key_and_matching():
    assert vr.rtti_key('.?AVBSTriShape@@') == ('BSTriShape', False)
    assert vr.rtti_key('.?AVDevNull@BSResource@@') == ('BSResourceDevNull', False)
    assert vr.rtti_key('.?AV?$NiPointer@VNiNode@@@@')[1] is True
    assert vr.rtti_matches('.?AVBSTriShape@@', 'BSTriShape')
    assert not vr.rtti_matches('.?AVBSTriShape@@', 'BSGeometry')
    assert vr.rtti_matches('.?AV?$NiPointer@VNiNode@@@@', 'NiPointer_NiNode_')
    assert vr.rtti_matches('.?AUAsyncFunctor@LooseFileSBTraits@BSResource@@',
                           'BSResource__LooseFileSBTraits__AsyncFunctor')


def test_pick_class_name_prefers_clean_spelling():
    raw = '.?AV?$SettingCollection@VSetting@@@@'
    assert vr.pick_class_name(raw, ['SettingCollection<Setting>', 'SettingCollection_Setting_']) == 'SettingCollection_Setting_'
    assert vr.pick_class_name('.?AVFoo@@', ['Other']) is None
    assert vr.pick_class_name('.?AVFoo@@', ['A::Foo']) is None   # namespace spelling only


def test_is_niobject():
    assert vr.is_niobject(['.?AVNiTriShape@@', '.?AVNiObject@@'])
    assert not vr.is_niobject(['.?AVTESForm@@'])


def test_deleting_wrapper_shapes():
    assert vr.is_deleting_wrapper(wrapper_plain(), 60)
    # inlined destructor: bigger, only recognised through a call to the free routine
    big = [I('CMP dword ptr [RCX],0'), I('TEST BL,0x1'), I('MOV EDX,0x160'), I('CALL 0x3', flows=['FreeMemory'])]
    assert vr.is_deleting_wrapper(big, 300)
    no_free = [I('CMP dword ptr [RCX],0'), I('TEST BL,0x1'), I('MOV EDX,0x160'), I('CALL 0x3', flows=['other'])]
    assert not vr.is_deleting_wrapper(no_free, 300)
    assert not vr.is_deleting_wrapper(wrapper_plain(), 800)                     # too large
    assert not vr.is_deleting_wrapper([I('MOV EDX,0x10'), I('CALL 0x1')], 20)  # no delete flag


def test_free_size_uses_last_load():
    assert vr.free_size(['MOV EDX,0x10', 'MOV EDX,0x148']) == 0x148
    assert vr.free_size(['XOR EDX,EDX']) is None


def test_strict_ctor_accepts_a_real_constructor():
    assert vr.strict_ctor(ctor_insns(), V)


def test_strict_ctor_rejects_destructor_with_tail_jump():
    # real destructor shape seen in the binary: stores the vtable, then jumps to the base destructor
    assert not vr.strict_ctor(ctor_insns(tail_jump_to='~QueuedFile'), V)


def test_strict_ctor_rejects_static_initialiser_and_wrong_vtable():
    static_init = [I('LEA RAX,[0x%X]' % V, refs=[V]), I('MOV qword ptr [0x143000000],RAX'),
                   I('CALL 0x1', flows=['atexit'])]
    assert not vr.strict_ctor(static_init, V)
    assert not vr.strict_ctor(ctor_insns(), V + 8)
    other = [I('LEA RAX,[0x%X]' % V, refs=[V]), I('MOV qword ptr [RDX],RAX')]   # stores into something that is not this
    assert not vr.strict_ctor(other, V)


def test_strict_ctor_follows_register_copy_of_this():
    insns = [I('MOV RDI,RCX'), I('LEA RAX,[0x%X]' % V, refs=[V]), I('MOV qword ptr [RDI + 0x10],RAX')]
    assert vr.strict_ctor(insns, V)


def test_plan_class_roles_names_create_clone_and_ctor():
    create = [I('MOV EDX,0x148'), I('CALL 0x1', flows=['MemoryManager::Allocate']),
              I('LEA RAX,[0x%X]' % V, refs=[V]), I('MOV qword ptr [RBX],RAX')]
    clone = create + [I('CALL 0x2')]
    refs = {10: {'insns': create, 'bytes': 100, 'name': 'FUN_a'},
            11: {'insns': clone, 'bytes': 120, 'name': 'FUN_b'},
            12: {'insns': ctor_insns(), 'bytes': 40, 'name': 'FUN_c'}}
    roles, _stats = vr.plan_class_roles(V, refs, wrapper=99, slot23=11, slot23_owners=1, wrapper_callees=set(),
                                        size=0x148, niobject=True, slot0_functions={99})
    # slot 23 is also the allocating function here, so CreateClone wins and Create stays unassigned
    assert roles == {11: 'CreateClone', 10: 'Create', 12: 'ctor'}


def test_plan_class_roles_excludes_wrapper_callees_and_wrapper_shapes():
    refs = {12: {'insns': ctor_insns(), 'bytes': 40, 'name': 'FUN_c'},        # callee of the wrapper = real dtor
            13: {'insns': wrapper_plain(), 'bytes': 60, 'name': 'FUN_w'}}     # looks like a wrapper
    roles, stats = vr.plan_class_roles(V, refs, wrapper=99, slot23=None, slot23_owners=0, wrapper_callees={12},
                                       size=0x148, niobject=False, slot0_functions=set())
    assert roles == {}
    assert stats['looks like wrapper'] == 1


def test_plan_class_roles_shared_slot23_is_owned_by_nobody():
    refs = {11: {'insns': [I('MOV EDX,0x148'), I('LEA RAX,[0x%X]' % V, refs=[V]), I('MOV qword ptr [RBX],RAX')],
                 'bytes': 50, 'name': 'FUN_b'}}
    roles, _ = vr.plan_class_roles(V, refs, wrapper=99, slot23=11, slot23_owners=2, wrapper_callees=set(),
                                   size=0x148, niobject=True, slot0_functions=set())
    assert 'CreateClone' not in roles.values()


def test_plan_class_roles_skips_ambiguous_ctors():
    refs = {1: {'insns': ctor_insns(), 'bytes': 40, 'name': 'FUN_1'}, 2: {'insns': ctor_insns(), 'bytes': 44, 'name': 'FUN_2'}}
    roles, stats = vr.plan_class_roles(V, refs, wrapper=99, slot23=None, slot23_owners=0, wrapper_callees=set(),
                                       size=0x148, niobject=False, slot0_functions=set())
    assert roles == {}
    assert stats['several ctors'] == 1


def test_real_destructor_poisons_vtable_first():
    assert vr.real_destructor([I('SUB RSP,0x28'), I('LEA RAX,[0x%X]' % V, refs=[V])], V)
    assert not vr.real_destructor([I('SUB RSP,0x28'), I('CALL 0x1')], V)


def test_flat_names():
    assert vr.flat_name('BSTriShape', 'dtor_deleting') == 'BSTriShape::dtor_deleting'
    assert vr.flat_name('BSTriShape', 'dtor') == 'BSTriShape::~BSTriShape'
    assert vr.flat_name('NiNode', 'ctor') == 'NiNode::ctor'


def test_placeholder_names():
    for n in ('FUN_140001000', 'sub_1', 'Func1', 'Func24', 'dtor_140C8E410', '~NiRefObject', 'dtor',
              'CreateClone_140C8DDD0', 'BSLODTriShape__dtor', '??_GFoo@@UEAAPEAXI@Z', 'ctor'):
        assert vr.is_placeholder_name(n), n
    for n in ('NiNode::AsNode', 'GetHeight', 'dtor_deleting', 'Update'):
        assert not vr.is_placeholder_name(n), n


def test_stale_vtable_labels():
    labels = {0x1000: ['VTABLE_Foo'], 0x2000: ['VTABLE_Foo_0'], 0x3000: ['VTABLE_Bar'], 0x4000: ['VTABLE_Baz<int>']}
    real = {0x1000, 0x4000}
    # Foo has a label at a real vtable, so the stray Foo label at 0x2000 goes; Bar has no real vtable: kept
    assert vr.stale_vtable_labels(labels, real) == [(0x2000, 'VTABLE_Foo_0')]
    assert vr.label_class('VTABLE_Foo_0') == 'Foo' and vr.label_class('not_a_vtable') is None
