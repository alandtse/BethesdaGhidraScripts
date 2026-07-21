"""Shared Ghidra-safe symbol-name sanitizers.

Two genuinely distinct, each independently reimplemented several times:

- `sanitize_component`: make ONE path/namespace component safe (used after already
  splitting on `::`). Byte-identical across `core/run_vtable_pipeline.py` and six
  `commonlibsf/*.py` files (`apply_names_to_program.py`, `apply_ported_to_sf116.py`,
  `create_funcs_and_rename.py`, `sync_bgs_from_combined.py`,
  `replace_placeholders_with_real_names.py`).
- `sanitize_qualified`: split a FULLY-qualified `A::B::C` name on `::`, sanitize each
  part, rejoin with `::`. Byte-identical across `commonlibsf/apply_ported_via_mcp.py`
  (`sanitize_full_name`), `commonlibsf/bsim_query_apply.py` (`sanitize_name`), and
  `commonlibnvse/bsim_query_fnv_intra.py` (`sanitize`).

These use different allowed-character sets on purpose (the qualified-name sanitizer
additionally allows `:` and `.` within a part), so `sanitize_qualified` is NOT built on
`sanitize_component` -- they stay two functions with two regexes, not one generalized
one, matching the two distinct historical implementations rather than forcing a
false unification.

NOT merged: `commonlibnvse/find_fnv_constructors.py::_sanitize_class_for_ctor` looked
like a naming-cluster match by grep but is a different operation entirely (extracts the
bare last-segment class name for MSVC constructor naming, e.g.
`BSSimpleArray<X,1024>` -> `BSSimpleArray`), not a Ghidra-symbol-safety sanitizer.
"""
from __future__ import annotations

import re

_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_<>$~?@-]")
_SAFE_QUALIFIED_RE = re.compile(r"[^A-Za-z0-9_<>$~?@:.-]")


def sanitize_component(part: str) -> str:
    """Make one path/namespace component safe for Ghidra's symbol parser:
    replace disallowed characters with `_`, prefix a leading digit with `_`,
    and never return an empty string (falls back to `_`)."""
    part = part.strip()
    if not part:
        return "_"
    cleaned = _SAFE_COMPONENT_RE.sub("_", part)
    if cleaned and cleaned[0].isdigit():
        cleaned = "_" + cleaned
    return cleaned or "_"


def sanitize_qualified(name: str) -> str:
    """Sanitize a fully-qualified `A::B::C` name, keeping the `::` separators
    intact: split on `::`, sanitize each part with a slightly wider allowed
    character set than `sanitize_component` (also permits `:` and `.` within a
    part), then rejoin."""
    parts = []
    for p in name.split("::"):
        p = p.strip()
        p = _SAFE_QUALIFIED_RE.sub("_", p)
        if p and p[0].isdigit():
            p = "_" + p
        parts.append(p or "_")
    return "::".join(parts)


def split_namespaced(full: str) -> list:
    """`A::B::C` -> `[sanitize_component(A), sanitize_component(B), sanitize_component(C)]`."""
    return [sanitize_component(p) for p in full.split("::")]
