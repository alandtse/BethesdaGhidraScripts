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


def test_resolve_struct_name_degenerate_self_alias_falls_through():
    # a real-world case: TEMPLATE_TYPE_MAP mapped this exact name to ITSELF (a
    # no-op alias that resolves nowhere in 'created'). An early-return on any
    # truthy alias would give up here even though the namespace-stripped bare
    # name is registered and resolvable -- must fall through instead.
    name = 'RE::BSTEventSink<RE::MenuOpenCloseEvent>'
    created = {'BSTEventSink<RE::MenuOpenCloseEvent>': 'SINK_DT'}
    template_map = {name: name}  # degenerate self-alias
    resolve = _load_resolve_struct_name(created, template_map)
    assert resolve(name) == 'SINK_DT'


def _select_types():
    import importlib.util
    spec = importlib.util.spec_from_file_location('gig_under_test', _SRC_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.select_types


def _st(full, fields=(), bases=()):
    return {'full_name': full, 'name': full.split('::')[-1], 'size': 8,
            'fields': [{'type': t} for t in fields], 'bases': list(bases)}


def _tables():
    structs = {s['full_name']: s for s in (
        _st('RE::Outer::State', ['struct:RE::NiPoint2', 'arr:struct:RE::NiColorA:4',
                                 'ptr:struct:RE::Far', 'enum:RE::Mode:1'], ['RE::Base']),
        _st('RE::BSGraphics::State'),
        _st('RE::NiPoint2'), _st('RE::NiColorA'), _st('RE::Far'), _st('RE::Base'),
        _st('RE::Unrelated'))}
    enums = {'RE::Mode': {'full_name': 'RE::Mode'}, 'RE::Other': {'full_name': 'RE::Other'}}
    vts = {'a': {'class_full_name': 'RE::Base'}, 'b': {'class_full_name': 'RE::Unrelated'}}
    return structs, enums, vts


def test_select_types_follows_by_value_not_pointers():
    structs, enums, vts = _tables()
    s, e, v = _select_types()(structs, enums, vts, ['Outer::State'])
    assert sorted(s) == ['RE::Base', 'RE::NiColorA', 'RE::NiPoint2', 'RE::Outer::State']
    assert sorted(e) == ['RE::Mode']
    assert [x['class_full_name'] for x in v.values()] == ['RE::Base']


def test_select_types_ambiguous_bare_name_raises():
    structs, enums, vts = _tables()
    try:
        _select_types()(structs, enums, vts, ['State'])
    except ValueError as ex:
        assert 'RE::Outer::State' in str(ex) and 'RE::BSGraphics::State' in str(ex)
    else:
        raise AssertionError('expected ValueError')


def test_select_types_unknown_name_raises():
    structs, enums, vts = _tables()
    try:
        _select_types()(structs, enums, vts, ['Nope'])
    except ValueError:
        return
    raise AssertionError('expected ValueError')


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
