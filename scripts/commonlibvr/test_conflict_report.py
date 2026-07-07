#!/usr/bin/env python3
"""Unit tests for conflict_report's pure (Ghidra-free) helpers.

Run: python -m pytest test_conflict_report.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import layout_diff as cr  # noqa: E402


def _e(offset, length, typename, fieldname=''):
    return (offset, length, typename, fieldname)


def _g(fname, ftype, foffset, fsize):
    return (fname, ftype, foffset, fsize)


def test_identical_layout_does_not_diverge():
    existing = [_e(0, 8, 'undefined8', 'unk0'), _e(8, 8, 'undefined8', 'unk8')]
    gen = [_g('unk0', 'u64', 0, 8), _g('unk8', 'u64', 8, 8)]
    assert not cr.layout_diverges(existing, gen)


def test_cosmetic_name_difference_does_not_diverge():
    # Ghidra's own hand-given name differs from clang's generated name, same
    # offset/size/type-class -- must NOT trip divergence (would make DIVERGENT
    # noisy for every hand-renamed field).
    existing = [_e(0, 8, 'undefined8', 'someHandRenamedField')]
    gen = [_g('unk0', 'u64', 0, 8)]
    assert not cr.layout_diverges(existing, gen)


def test_pointer_typedef_spelling_does_not_diverge():
    # A vtable slot's pointer typename spelled differently (bare function-pointer
    # typedef vs 'struct:X *') should collapse to the same 'ptr' class.
    existing = [_e(0, 8, 'PFN_SomeCallback *', 'vftable_ptr')]
    gen = [_g('method', 'struct:RE::SomeClass *', 0, 8)]
    assert not cr.layout_diverges(existing, gen)


def test_same_offsets_same_type_classes_does_not_diverge_even_if_names_differ():
    # A same-count, same-offset/size/type-class layout is treated as matching
    # even when field names differ from the generated ones -- the real RE::Actor
    # bug (a bogus extra field pushing every subsequent slot's offset out of
    # alignment) is caught by the differing-field-count / missing-slot paths
    # below (test_differing_field_count_diverges,
    # test_missing_slot_on_one_side_diverges), not by this offset-preserving case.
    existing = [_e(0, 8, 'undefined8', 'a'), _e(8, 8, 'undefined8', 'renamed_b'),
                _e(16, 8, 'undefined8', 'c')]
    gen = [_g('a', 'u64', 0, 8), _g('b', 'u64', 8, 8), _g('c', 'u64', 16, 8)]
    assert not cr.layout_diverges(existing, gen)


def test_differing_field_count_diverges():
    existing = [_e(0, 8, 'undefined8', 'a'), _e(8, 8, 'undefined8', 'bogus_extra'),
                _e(16, 8, 'undefined8', 'c')]
    gen = [_g('a', 'u64', 0, 8), _g('c', 'u64', 8, 8)]
    assert cr.layout_diverges(existing, gen)


def test_missing_slot_on_one_side_diverges():
    existing = [_e(0, 8, 'undefined8', 'a'), _e(8, 8, 'undefined8', 'b')]
    gen = [_g('a', 'u64', 0, 8), _g('c', 'u64', 16, 8)]
    assert cr.layout_diverges(existing, gen)


def test_type_class_disagreement_at_same_offset_diverges():
    # Same offset/size, but existing is a pointer where gen expects a float --
    # a real, meaningful ABI-level disagreement, not a spelling difference.
    existing = [_e(0, 8, 'undefined8 *', 'ptrField')]
    gen = [_g('floatField', 'f64', 0, 8)]
    assert cr.layout_diverges(existing, gen)


def test_size_disagreement_at_same_offset_diverges():
    existing = [_e(0, 4, 'undefined4', 'a')]
    gen = [_g('a', 'u64', 0, 8)]
    assert cr.layout_diverges(existing, gen)


def test_auto_extract_score_recognizes_raw_middle_tail_remainder_fields():
    # The real Character bug: a handful of genuinely-identified fields poked
    # into an otherwise-untyped struct, with the remainder split into named
    # byte-blob chunks. None of _base_raw/_middle/_tail match the old
    # name-only patterns (_pad/unk/field_/Name_<hex>), so the old score saw
    # this as "mostly hand-named" and protected it as HANDCURATED forever.
    existing = [
        _e(0, 688, 'byte[688]', '_base_raw'),
        _e(688, 12, 'NiPoint3', 'Rotation'),
        _e(700, 12, 'NiPoint3', 'Position'),
        _e(712, 192, 'char[192]', '_middle'),
        _e(904, 12, 'NiPoint3', 'EditorLocPosition'),
        _e(916, 388, 'char[388]', '_tail'),
    ]
    score = cr.auto_extract_score(existing)
    # 3 of 6 fields (_base_raw, _middle, _tail) are placeholder-typed remainder
    # chunks -> score must land at/above the 0.5 handcurated threshold so this
    # struct is no longer misclassified as hand-curated.
    assert score >= 0.5


def test_auto_extract_score_still_protects_genuinely_hand_curated_struct():
    # A struct where every field has both a real name AND a real (non-placeholder)
    # type must still score as hand-curated -- the fix must not become so broad
    # that deliberately-typed RE work gets treated as an unfinished stub.
    existing = [
        _e(0, 4, 'ActorValue', 'actorValue'),
        _e(4, 4, 'float', 'magnitude'),
        _e(8, 8, 'struct:RE::TESForm *', 'sourceForm'),
    ]
    score = cr.auto_extract_score(existing)
    assert score < 0.5


def test_placeholder_typename_recognizes_byte_arrays_like_char_arrays():
    assert cr._placeholder_typename('byte[688]')
    assert cr._placeholder_typename('char[192]')
    assert not cr._placeholder_typename('struct:RE::NiPoint3')
