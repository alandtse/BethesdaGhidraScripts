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


class _FakeDomainFile:
    def __init__(self, prog):
        self.prog = prog

    def getLatestVersion(self):
        return self.prog.version

    def packFile(self, f, monitor):
        self.prog.saved.append(str(f))


class _FakeProgram(_FakeCP):
    def __init__(self, version=1, changed=False):
        super().__init__()
        self.saved = []
        self.version = version
        self.changed = changed

    def getName(self):
        return 'Fake.exe'

    def isChanged(self):
        return self.changed

    def getDomainFile(self):
        return _FakeDomainFile(self)


def _stub_java(monkeypatch):
    import types
    java_io = types.ModuleType('java.io')
    java_io.File = lambda p: p
    monkeypatch.setitem(sys.modules, 'java', types.ModuleType('java'))
    monkeypatch.setitem(sys.modules, 'java.io', java_io)
    task = types.ModuleType('ghidra.util.task')
    task.TaskMonitor = types.SimpleNamespace(DUMMY=object())
    for n in ('ghidra', 'ghidra.util'):
        monkeypatch.setitem(sys.modules, n, types.ModuleType(n))
    monkeypatch.setitem(sys.modules, 'ghidra.util.task', task)


def test_backup_before_transaction_dedupes_by_saved_version(monkeypatch, tmp_path):
    from engine import tx as txmod
    _stub_java(monkeypatch)
    monkeypatch.setenv('CLVR_BACKUP_DIR', str(tmp_path))
    monkeypatch.delenv('CLVR_BACKUP', raising=False)
    txmod._backed.clear()
    prog = _FakeProgram()
    with transaction(prog, 'first'):
        pass
    assert len(prog.saved) == 1 and prog.saved[0].endswith('.first.gzf')
    assert prog.calls[0][0] == 'start'
    with transaction(prog, 'second'):      # same saved version: no new snapshot
        pass
    assert len(prog.saved) == 1
    prog.changed = True                    # this run's own edits: earlier snapshot stands
    with transaction(prog, 'third'):
        pass
    assert len(prog.saved) == 1
    prog.changed, prog.version = False, 2  # user saved: new restore point
    with transaction(prog, 'fourth'):
        pass
    assert len(prog.saved) == 2


def test_unsaved_changes_refuse_and_no_transaction_starts(monkeypatch, tmp_path):
    from engine import tx as txmod
    _stub_java(monkeypatch)
    monkeypatch.setenv('CLVR_BACKUP_DIR', str(tmp_path))
    monkeypatch.delenv('CLVR_BACKUP', raising=False)
    txmod._backed.clear()
    prog = _FakeProgram(changed=True)
    try:
        with transaction(prog, 'x'):
            raise AssertionError('body must not run')
    except RuntimeError as e:
        assert 'unsaved' in str(e)
    assert prog.calls == [] and prog.saved == []


def test_backup_skip_and_dry_run(monkeypatch, tmp_path):
    from engine import tx as txmod
    monkeypatch.setenv('CLVR_BACKUP_DIR', str(tmp_path))
    txmod._backed.clear()
    prog = _FakeProgram()
    monkeypatch.setenv('CLVR_BACKUP', 'skip')
    with transaction(prog, 'x'):
        pass
    monkeypatch.delenv('CLVR_BACKUP')
    with transaction(prog, 'y', apply=False):
        pass
    assert prog.saved == []


def test_target_mismatch_refuses_before_any_transaction(monkeypatch):
    prog = _FakeProgram()
    monkeypatch.setenv('CLVR_PROGRAM', 'Other.exe')
    try:
        with transaction(prog, 'x'):
            raise AssertionError('body must not run')
    except RuntimeError as e:
        assert 'target mismatch' in str(e)
    assert prog.calls == []
    monkeypatch.setenv('CLVR_PROGRAM', 'Fake.exe')
    monkeypatch.setenv('CLVR_BACKUP', 'skip')
    with transaction(prog, 'ok'):
        pass
    assert prog.calls[0][0] == 'start'
