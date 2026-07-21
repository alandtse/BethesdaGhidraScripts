#!/usr/bin/env python3
"""Unit tests for engine.tx (pure control-flow logic, fake Ghidra stub -- no real Ghidra).

Run: python -m pytest test_tx.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from engine.tx import transaction  # noqa: E402


class _FakeCP:
    """Stands in for a Ghidra Program/DomainFile: records start/end calls."""

    def __init__(self):
        self.calls = []
        self._next_id = 1

    def startTransaction(self, label):
        tid = self._next_id
        self._next_id += 1
        self.calls.append(("start", tid, label))
        return tid

    def endTransaction(self, tid, commit):
        self.calls.append(("end", tid, commit))


def test_apply_true_starts_and_always_commits():
    cp = _FakeCP()
    with transaction(cp, "do the thing", apply=True):
        pass
    assert cp.calls == [("start", 1, "do the thing"), ("end", 1, True)]


def test_apply_true_yields_the_transaction_id():
    cp = _FakeCP()
    with transaction(cp, "label", apply=True) as tx:
        assert tx == 1


def test_apply_false_opens_no_transaction():
    cp = _FakeCP()
    with transaction(cp, "label", apply=False):
        pass
    assert cp.calls == []


def test_apply_false_yields_none():
    cp = _FakeCP()
    with transaction(cp, "label", apply=False) as tx:
        assert tx is None


def test_apply_true_still_commits_on_exception():
    # "always commit; never poison the group" -- an exception inside the block must
    # not skip endTransaction(..., True).
    cp = _FakeCP()
    try:
        with transaction(cp, "label", apply=True):
            raise ValueError("boom")
    except ValueError:
        pass
    assert cp.calls == [("start", 1, "label"), ("end", 1, True)]


def test_apply_false_propagates_exception_without_touching_cp():
    cp = _FakeCP()
    try:
        with transaction(cp, "label", apply=False):
            raise ValueError("boom")
    except ValueError:
        pass
    assert cp.calls == []


def test_default_apply_is_true():
    cp = _FakeCP()
    with transaction(cp, "label"):
        pass
    assert cp.calls == [("start", 1, "label"), ("end", 1, True)]


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
