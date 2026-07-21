#!/usr/bin/env python3
"""Unit tests for commonlib_typed_members (pure header-parsing logic, no Ghidra).

Run: python -m pytest test_commonlib_typed_members.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import commonlib_typed_members as ctm  # noqa: E402


def _scan(header_text):
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, 'Test.h'), 'w') as fh:
            fh.write(header_text)
        return list(ctm.typed_members(d))


def test_concrete_class_member_with_slash_slash_offset():
    rows = _scan('class Foo {\n'
                  '    NiAVObject* obj; // 10\n'
                  '};\n')
    assert rows == [('Foo', 0x10, 'NiAVObject*', 'obj')]


def test_concrete_member_with_block_comment_offset():
    rows = _scan('class Foo {\n'
                  '    BSTArray<TESForm*> forms; /* 28 */\n'
                  '};\n')
    assert rows == [('Foo', 0x28, 'BSTArray<TESForm*>', 'forms')]


def test_placeholder_uint_types_skipped():
    rows = _scan('class Foo {\n'
                  '    std::uint32_t unk10; // 10\n'
                  '    std::uint8_t unk14; // 14\n'
                  '    void* unk18; // 18\n'
                  '    std::byte unk20; // 20\n'
                  '};\n')
    assert rows == []


def test_member_without_offset_comment_skipped():
    rows = _scan('class Foo {\n'
                  '    NiAVObject* obj;\n'
                  '};\n')
    assert rows == []


def test_union_struct_enum_using_keywords_skipped():
    # these match the member-line regex's <type> <name>; shape but aren't real
    # concretely-typed members -- e.g. a `union { ... } name;` anonymous-union tail line.
    rows = _scan('class Foo {\n'
                  '    union thing; // 10\n'
                  '    struct thing2; // 14\n'
                  '    enum thing3; // 18\n'
                  '    using thing4; // 1c\n'
                  '};\n')
    assert rows == []


def test_smart_pointer_and_template_types_are_concrete():
    rows = _scan('class Foo {\n'
                  '    NiPointer<NiAVObject> ptr; // 30\n'
                  '    BSTSmallArray<std::uint32_t, 4> arr; // 40\n'
                  '};\n')
    assert rows == [
        ('Foo', 0x30, 'NiPointer<NiAVObject>', 'ptr'),
        ('Foo', 0x40, 'BSTSmallArray<std::uint32_t, 4>', 'arr'),
    ]


def test_multiple_classes_in_one_file():
    rows = _scan('class Foo {\n'
                  '    NiAVObject* a; // 10\n'
                  '};\n'
                  'struct Bar {\n'
                  '    TESForm* b; // 20\n'
                  '};\n')
    assert ('Foo', 0x10, 'NiAVObject*', 'a') in rows
    assert ('Bar', 0x20, 'TESForm*', 'b') in rows


def test_hex_offset_with_letters_parses_correctly():
    rows = _scan('class Foo {\n'
                  '    NiAVObject* obj; // A8\n'
                  '};\n')
    assert rows == [('Foo', 0xA8, 'NiAVObject*', 'obj')]


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
