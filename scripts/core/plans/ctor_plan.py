"""Pure (Ghidra-free) logic for constructor-mining field recovery.

A class constructor assigns each member from a typed, named parameter
(`this->Object_18 = a_object` where `a_object` is `TESBoundObject*`), so one decompile
yields a field's NAME and TYPE together -- far more reliable than the size-only
dataflow guesses the discovery cycle makes on its own (which mis-typed Crime+0x58 as a
faction; the ctor showed 0x18 is the TESBoundObject `object` and 0x58 a 4-byte scalar).

This module holds the rule-expressible bits: recognizing a constructor by name and
turning a constructor parameter name into a field name. The driver (core/engine's
ctor_mine.py) finds the constructor, decompiles it, and reads the `this->field =
a_param` assignments out of the pcode; the proposals feed the review queue /
cross-version apply (high-accuracy field names + types). Kept Ghidra-free so it is
unit-testable.

Was independently forked as commonlibvr/ctor_plan.py -- that copy turned out to be
functionally identical (same regex, same logic), only the docstrings diverged in
wording. Merged here with no behavioral reconciliation needed.
"""
import re

_ARG_PREFIX = re.compile(r'^(?:a_|p_|param_?)', re.IGNORECASE)
# Generic decompiler-invented arg names that carry no field meaning.
_NOISE = {'this', 'param', 'arg', 'a', 'p', 'x', 'in', 'out', 'result', 'retval'}


def is_ctor(func_name, class_name):
    """Heuristic: is `func_name` a constructor of `class_name`?

    Matches a `_ctor` suffix, the bare class-name leaf (`Class::Class`),
    a trailing `::Class`, or 'constructor' in the leaf. Conservative --
    a `_ctor` suffix is the strong signal; a bare 'ctor' substring would
    false-match names like 'DoActor'.
    """
    if not func_name:
        return False
    leaf = func_name.split('::')[-1]
    return (leaf == class_name
            or leaf.endswith('_ctor')
            or leaf.endswith('::' + class_name)
            or 'constructor' in leaf.lower())


def field_label(param_name):
    """Constructor parameter name -> field name.

    Drops the `a_`/`p_` arg prefix ('a_object' -> 'object'). Returns
    None for absent or noise-only names so the driver keeps the type but
    not a meaningless name.
    """
    if not param_name:
        return None
    n = _ARG_PREFIX.sub('', param_name).strip()
    if not n or n.lower() in _NOISE:
        return None
    return n


def best_ctor(candidates):
    """Pick the most informative constructor from (func_id, assign_count).

    The one that assigns the most fields (ties -> first); None if none
    assign any.
    """
    best = None
    for fid, n in candidates:
        if n > 0 and (best is None or n > best[1]):
            best = (fid, n)
    return best[0] if best else None
