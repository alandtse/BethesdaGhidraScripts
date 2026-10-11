#!/usr/bin/env python3
"""Unit tests for vtable_name_reconciler._rename_slot / _promote_existing_symbol (fake Ghidra objects).

Run: python -m pytest test_vtable_name_reconciler.py
"""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vtable_name_reconciler as vnr  # noqa: E402

SourceType = types.SimpleNamespace(USER_DEFINED='user')


class Sym:
    def __init__(self, name, primary):
        self.name, self.primary = name, primary

    def getName(self, full=False):
        return self.name

    def isPrimary(self):
        return self.primary

    def setPrimary(self):
        self.primary = True


class Ns:
    def __init__(self, glob):
        self.glob = glob

    def isGlobal(self):
        return self.glob


class Func:
    def __init__(self, in_class, refuses=False):
        self.ns, self.refuses, self.name = Ns(not in_class), refuses, 'old'

    def getParentNamespace(self):
        return self.ns

    def setName(self, name, source):
        if self.refuses:
            raise RuntimeError('DuplicateNameException')
        self.name = name


class Cu:
    def __init__(self):
        self.comment = None

    def getComment(self, kind):
        return self.comment

    def setComment(self, kind, text):
        self.comment = text


class Addr:
    def getOffset(self):
        return 0x1000


class Program:
    def __init__(self, syms):
        self.syms, self.cu = syms, Cu()

    def getSymbolTable(self):
        return types.SimpleNamespace(getSymbols=lambda a: self.syms)

    def getListing(self):
        return types.SimpleNamespace(getCodeUnitAt=lambda a: self.cu)


def test_flat_function_gets_the_qualified_name_and_a_note():
    f, p = Func(in_class=False), Program([])
    assert vnr._rename_slot(f, Addr(), p, 'Actor::Update', 'Update', 'Old::Update', SourceType)
    assert f.name == 'Actor::Update'
    assert p.cu.comment == 'Reconciled from stale name: Old::Update'


def test_function_in_a_class_namespace_takes_the_leaf():
    f = Func(in_class=True)
    assert vnr._rename_slot(f, Addr(), Program([]), 'Actor::Update', 'Update', 'x', SourceType)
    assert f.name == 'Update'


def test_existing_nonprimary_symbol_is_promoted_when_setname_refuses():
    f, existing = Func(in_class=False, refuses=True), Sym('Actor::Update', primary=False)
    assert vnr._rename_slot(f, Addr(), Program([Sym('stale', True), existing]), 'Actor::Update', 'Update', 'stale', SourceType)
    assert existing.primary


def test_failed_rename_is_reported_not_reconciled():
    f = Func(in_class=False, refuses=True)
    assert not vnr._rename_slot(f, Addr(), Program([Sym('stale', True)]), 'Actor::Update', 'Update', 'stale', SourceType)


def test_promote_already_primary_is_true_and_missing_is_false():
    assert vnr._promote_existing_symbol(Program([Sym('A', True)]), Addr(), 'A')
    assert not vnr._promote_existing_symbol(Program([Sym('B', True)]), Addr(), 'A')
