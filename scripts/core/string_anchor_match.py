"""Pure (Ghidra-free) matchers for string-anchored function renaming.

Technique adapted from alandtse's CommonLibVR fork.  The engine embeds
debug strings that name the enclosing function (and often its ``this``
class) outright -- the highest-signal, cheapest RE anchor.  Three
self-naming patterns:

  1. TIMER ZONE -- ``TthkbWorld::step`` / ``LtBSOffsetAnimationGenerator::
     generate`` stored into the TLS profiler buffer at function ENTRY
     (HK_TIMER_BEGIN macro).  The ``Lt``/``Tt`` prefix is the marker; the
     rest is the function's own qualified name.
  2. SELF-NAMING MESSAGE -- an assert/log string LEADING with a qualified
     name then a message: ``"BGSSaveLoadManager::CopySaveGamesFromHost
     failed to read ..."``.  The leading identifier names the function.
  3. TELEMETRY SDK -- a bare qualified name an SDK logs per call
     (``LEA arg,[name]; CALL log``).  Gated to a namespace allowlist so a
     bare type name (``hkCachedHashMap::Elem``) isn't mislabeled.

Match is by STRING, not address, so the same name applies in SE/AE/VR
(and across F4/SF builds) without any address mapping.  Factored out of
the Ghidra driver (string_anchored_rename.py) so the matching + consensus
logic is unit-testable.
"""
import re
from collections import Counter

# Timer-zone label: [LT]t macro prefix + qualified name.  The prefix
# guarantees a method, so no per-namespace restriction.
_TIMER = re.compile(r'^[LT]t([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)$')
# Self-naming message: a qualified C++ name, whitespace, then a message.
_LEAD = re.compile(r'^([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)\s+([A-Za-z].*)$')
# Bare qualified name (telemetry tier; gated by an allowlist).
_BARE = re.compile(r'^([A-Za-z_]\w*(?:::[A-Za-z_]\w*)+)$')


def timer_name(s):
    """Return the qualified name from a timer-zone label, or None."""
    if ' ' in s or len(s) > 80:
        return None
    m = _TIMER.match(s)
    return m.group(1) if m else None


def message_name(s):
    """Return the leading qualified name of a self-naming message, or None.

    Rejects havok (``hk*``) leads, messages under 3 words, and names
    nested deeper than 3 segments (those are usually nested types, not
    the enclosing method).
    """
    if len(s) < 14:
        return None
    m = _LEAD.match(s)
    if not m:
        return None
    ident, msg = m.group(1), m.group(2)
    if ident.startswith('hk') or msg.count(' ') < 2 or len(ident.split('::')) > 3:
        return None
    return ident


def telemetry_name(s, allow_ns):
    """Return a bare qualified name whose top namespace is in ``allow_ns``."""
    if ' ' in s or len(s) > 80:
        return None
    m = _BARE.match(s)
    if not m or m.group(1).split('::')[0] not in allow_ns:
        return None
    return m.group(1)


def match_any(s, allow_ns):
    """Return (name, is_timer) for the first pattern that matches, else
    (None, False).  ``is_timer`` lets the driver enforce the entry-window
    constraint only for timer labels."""
    t = timer_name(s)
    if t:
        return t, True
    return (message_name(s) or telemetry_name(s, allow_ns)), False


def resolve(by_func):
    """Decide which functions to rename.

    ``by_func`` is ``{func_key: (func_obj, set(candidate_names))}``.  A
    name is applied only when a function maps to a SINGLE consistent
    identifier AND that identifier maps to a single function in this
    program (ambiguous strings are reported, never guessed).

    Returns ``(plan, ambiguous)`` where ``plan`` is a sorted list of
    ``(func_key, name)`` and ``ambiguous`` is a set of skipped labels.
    """
    single = {k: next(iter(names))
              for k, (_f, names) in by_func.items() if len(names) == 1}
    multi = {k for k, (_f, names) in by_func.items() if len(names) > 1}
    counts = Counter(single.values())

    plan, ambiguous = [], set()
    for k, name in single.items():
        if counts[name] > 1:
            ambiguous.add(name)
        else:
            plan.append((k, name))
    for k in multi:
        ambiguous.add('|'.join(sorted(by_func[k][1])))
    plan.sort()
    return plan, ambiguous
