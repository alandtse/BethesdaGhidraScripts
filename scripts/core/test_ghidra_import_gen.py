"""Unit tests for the pure parts of ghidra_import_gen's type-resolution helpers.

`ghidra_import_gen.py` calls `currentProgram.getDataTypeManager()` at module
level, so it can't be imported directly outside Ghidra. `_resolve_struct_name`
only depends on module-level `created`/`TEMPLATE_TYPE_MAP` dicts, so its source
is extracted and exec'd in a sandboxed namespace with fake dicts -- no Ghidra
required. Run with::

    python scripts/core/test_ghidra_import_gen.py
    # or: pytest scripts/core/test_ghidra_import_gen.py
"""
import os
import re

_SRC_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ghidra_import_gen.py')


def _load_resolve_struct_name(created, template_type_map):
    """Extract `_resolve_struct_name`'s exact source and exec it against fake
    `created`/`TEMPLATE_TYPE_MAP` globals, returning the live function object."""
    with open(_SRC_PATH, 'r') as f:
        text = f.read()
    m = re.search(r'\ndef _resolve_struct_name\(name\):.*?(?=\n_SIZED_ENUM_CACHE)', text, re.DOTALL)
    assert m, 'could not find _resolve_struct_name in ghidra_import_gen.py'
    ns = {'created': created, 'TEMPLATE_TYPE_MAP': template_type_map}
    exec(compile(m.group(0), _SRC_PATH, 'exec'), ns)
    return ns['_resolve_struct_name']


def test_resolve_struct_name_simple_namespaced():
    # regression guard: plain 'NS::Type' still resolves via bare-name fallback
    created = {'TESForm': 'TESFORM_DT'}
    resolve = _load_resolve_struct_name(created, {})
    assert resolve('RE::TESForm') == 'TESFORM_DT'
    assert resolve('TESForm') == 'TESFORM_DT'


def test_resolve_struct_name_template_full_name_hit():
    # a template instantiation emitted directly under its full qualified name
    created = {'RE::BSTArray<int>': 'ARR_DT'}
    resolve = _load_resolve_struct_name(created, {})
    assert resolve('RE::BSTArray<int>') == 'ARR_DT'


def test_resolve_struct_name_template_alias():
    created = {'BSTArray<int>_ALIAS_DT': 'ALIAS_DT'}
    template_map = {'RE::BSTArray<int>': 'BSTArray<int>_ALIAS_DT'}
    resolve = _load_resolve_struct_name(created, template_map)
    assert resolve('RE::BSTArray<int>') == 'ALIAS_DT'


def test_resolve_struct_name_nested_namespaced_template_arg():
    # the bug case: outer namespace prefix must be stripped, but the template
    # argument's OWN namespace qualification must be left untouched -- Ghidra's
    # live type name keeps 'RE::' inside the <> but not outside it.
    created = {'BSTEventSink<RE::MenuOpenCloseEvent>': 'SINK_DT'}
    resolve = _load_resolve_struct_name(created, {})
    assert resolve('RE::BSTEventSink<RE::MenuOpenCloseEvent>') == 'SINK_DT'


def test_resolve_struct_name_nested_template_arg_naive_split_would_break():
    # a naive name.split('::')[-1] on 'RE::BSTEventSink<RE::MenuOpenCloseEvent>'
    # would yield 'MenuOpenCloseEvent>' (splitting inside the template argument)
    # and never find the real type -- confirm that mangled lookup is NOT what
    # gets tried (i.e. registering only the mangled name must NOT resolve).
    created = {'MenuOpenCloseEvent>': 'WRONG_DT'}
    resolve = _load_resolve_struct_name(created, {})
    assert resolve('RE::BSTEventSink<RE::MenuOpenCloseEvent>') is None


def test_resolve_struct_name_template_no_match_returns_none():
    created = {}
    resolve = _load_resolve_struct_name(created, {})
    assert resolve('RE::BSTEventSink<RE::SomeUnknownEvent>') is None


def _run():
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
            print('  ok', name)
            n += 1
    print('%d tests passed' % n)


if __name__ == '__main__':
    _run()
