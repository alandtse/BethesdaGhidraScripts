"""Shared, generic Ghidra-manipulation mechanics (transaction/dry-run/batch runner,
MSVC demangler, name sanitizer, ...) with no per-library game-specific data rules.

Populated incrementally by an ongoing DRY refactor: the same generic mechanics were
independently reimplemented per CommonLib target (commonlibsse/vr/f4/nvse/sf) instead
of shared here. Pointer-width/ISA-parameterized algorithms (RTTI-vtable-walk,
constructor/thunk-scan) and per-game ID-file grammar are a separate, later follow-on --
this package currently holds only the algorithmically-identical mechanical merges.
"""
