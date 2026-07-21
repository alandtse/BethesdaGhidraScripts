"""Shared, Ghidra-free PURE decision logic (classify/plan functions), matching this
repo's `*_plan.py` convention: no `import ghidra`, unit-testable in isolation, consumed
by a thin driver elsewhere that does the actual Ghidra I/O.

Populated incrementally by an ongoing DRY refactor consolidating pure logic that was
independently forked per CommonLib target instead of shared.
"""
