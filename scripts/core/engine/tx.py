"""Shared Ghidra transaction lifecycle: "always commit; never poison the group."

Copy-pasted verbatim (often with that exact comment) across 13+ driver files in
commonlibvr alone: `tx = cp.startTransaction(label)` (or `... if APPLY else None` for a
dry-run-gated caller), `try: ... finally: cp.endTransaction(tx, True)`.

Deliberately narrow: a context manager over the tx lifecycle only, NOT a generic
"iterate items, call a do_one callback" apply framework. The 13+ call sites' actual
loop bodies are NOT structurally uniform -- different per-file accumulator state
(counters, skip-reason dicts, sample lists, changed-class sets), different control
flow (early returns, nested try/except-continue, conditional sub-transactions). Forcing
them into one generic iterate+callback shape would risk real behavioral changes with no
Ghidra unit-test oracle to catch a mistake. This wrapper instead removes ONLY the
boilerplate around each site's untouched body: no behavior change, no judgment call
per site, so it's safe within Phase 1's mechanical scope.

Always-commit is deliberate, not an oversight: a nested `commit=False` poisons an
outer MCP-wrapped transaction and silently discards the whole run (see
`reference_ghidra_mcp_nested_transaction_poison` -- confirmed reproduced in an earlier
session). Every call site in this repo already commits unconditionally in its finally
block; this wrapper preserves that.
"""
from __future__ import annotations

import os
import time
from contextlib import contextmanager

_backed = {}           # program name -> saved version of its newest snapshot


def _program_of(obj):
    """The Program behind `obj` (a Program, or a program's DataTypeManager), else None."""
    if hasattr(obj, 'getDomainFile'):
        return obj
    getter = getattr(obj, 'getProgram', None)
    prog = getter() if callable(getter) else None
    return prog if prog is not None and hasattr(prog, 'getDomainFile') else None


def check_target(cp):
    """Refuse to write when $CLVR_PROGRAM (the program name you meant to change) differs from the
    program this transaction is on. The MCP's program routing is shared between concurrent
    tasks, so a write can otherwise land on the wrong program."""
    want = os.environ.get('CLVR_PROGRAM')
    prog = _program_of(cp)
    if want and prog is not None and str(prog.getName()) != want:
        raise RuntimeError('target mismatch: CLVR_PROGRAM=%s but this transaction is on %s'
                           % (want, prog.getName()))


def backup_program(cp, label, monitor=None):
    """Snapshot the program's SAVED state to a packed .gzf before a write, so the run can be
    undone by importing the .gzf (Ghidra's own undo is gone once the program is saved).

    The snapshot is the saved database (`DomainFile.packFile`; `saveToPackedFile` cannot lock
    while the MCP's own transaction is open), so unsaved edits are not in it: a program with
    unsaved changes is refused unless this process already snapshotted it (then the changes are
    this run's own and the earlier snapshot still is the pre-run state). Save, then re-run.

    Directory: $CLVR_BACKUP_DIR (default ~/.clvr_backups). CLVR_BACKUP=skip disables it. A
    clean program already snapshotted at its current version is not snapshotted again. Objects
    that are not Ghidra programs (test fakes) are skipped. Returns the path, or None if skipped.
    A failure raises: a write that cannot be undone does not start."""
    if os.environ.get('CLVR_BACKUP', '').lower() == 'skip':
        return None
    prog = _program_of(cp)
    if prog is None:
        return None
    name = str(prog.getName())
    df = prog.getDomainFile()
    if prog.isChanged():
        if name in _backed:
            return None
        raise RuntimeError('%s has unsaved changes; File > Save first so the backup captures them '
                           '(or CLVR_BACKUP=skip)' % name)
    version = df.getLatestVersion()
    if _backed.get(name) == version:
        return None
    directory = os.environ.get('CLVR_BACKUP_DIR') or os.path.join(os.path.expanduser('~'), '.clvr_backups')
    os.makedirs(directory, exist_ok=True)
    safe = ''.join(ch if ch.isalnum() or ch in '._-' else '_' for ch in label)[:60]
    path = os.path.join(directory, '%s.%s.%s.gzf' % (name, time.strftime('%Y%m%d-%H%M%S'), safe))
    from java.io import File
    if monitor is None:
        from ghidra.util.task import TaskMonitor
        monitor = TaskMonitor.DUMMY
    df.packFile(File(path), monitor)
    _backed[name] = version
    print('BACKUP: %s (undo: import this .gzf over the program)' % path)
    return path


@contextmanager
def transaction(cp, label: str, apply: bool = True):
    """If `apply`, start a Ghidra transaction named `label` on `cp` (anything exposing
    `startTransaction`/`endTransaction` -- a Program, a DomainFile session object, etc.)
    and always commit it in a finally block, even on an unhandled exception inside the
    `with` block. If not `apply`, this is a no-op context (yields None, opens no
    transaction) -- matching every dry-run call site's existing convention of running
    its counting/preview logic without ever calling a Ghidra mutation API. Before any applying
    transaction the program is snapshotted (`backup_program`), so every driver gets an undo point."""
    if not apply:
        yield None
        return
    check_target(cp)
    backup_program(cp, label)
    tx = cp.startTransaction(label)
    try:
        yield tx
    finally:
        cp.endTransaction(tx, True)
