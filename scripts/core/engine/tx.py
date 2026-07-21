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

from contextlib import contextmanager


@contextmanager
def transaction(cp, label: str, apply: bool = True):
    """If `apply`, start a Ghidra transaction named `label` on `cp` (anything exposing
    `startTransaction`/`endTransaction` -- a Program, a DomainFile session object, etc.)
    and always commit it in a finally block, even on an unhandled exception inside the
    `with` block. If not `apply`, this is a no-op context (yields None, opens no
    transaction) -- matching every dry-run call site's existing convention of running
    its counting/preview logic without ever calling a Ghidra mutation API."""
    if not apply:
        yield None
        return
    tx = cp.startTransaction(label)
    try:
        yield tx
    finally:
        cp.endTransaction(tx, True)
