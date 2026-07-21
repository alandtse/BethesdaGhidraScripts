"""Shared minimal MSVC class TypeDescriptor demangler.

Was reimplemented independently four times -- `core/run_vtable_pipeline.py`,
`commonlibsse/build_svr_shift_map.py` (whose own docstring already said "same logic as
scripts/commonlibsf"), `commonlibsf/find_all_vtables_rtti.py`, and
`commonlibnvse/rtti_audit_fnv.py` -- with the first three byte-identical and only nvse's
copy missing the template-name (`?$`) fallback branch. That's a plain capability gap,
not a deliberate divergence (nvse's copy has no special-case logic of its own to lose),
so this merge upgrades nvse's behavior to match the other three rather than special-casing.
"""
from __future__ import annotations


def demangle_class(mangled: str) -> str:
    """`.?AVClassName@@` -> `ClassName`; `.?AVOuter@@Inner@@`-style nesting -> `Inner::Outer`.

    Strips the leading `.?A[VUW]` (V=class, U=struct, W=enum class) and trailing `@@`
    terminator, then reverses `@`-separated namespace/nesting components into `::`
    form. Templated names (containing MSVC's `?$` template marker) can't be split this
    way without breaking on the embedded `@`s inside the template argument list, so
    those fall back to a flat, sanitized rendering (`@` -> `::`, `?$` -> `T_`,
    remaining `?` -> `_`) instead of a proper reversed nesting.
    """
    if mangled.startswith((".?AV", ".?AU", ".?AW")):
        rest = mangled[4:]
    else:
        return mangled
    if rest.endswith("@@"):
        rest = rest[:-2]
    parts = [p for p in rest.split("@") if p]
    if not parts:
        return "UnknownClass"
    if any("?$" in p for p in parts):
        return rest.replace("@", "::").replace("?$", "T_").replace("?", "_")
    return "::".join(reversed(parts))
