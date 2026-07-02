"""Pure (Ghidra-free) logic for the GameSettings harvester.

A Bethesda game setting object (RE::Setting / SettingT<T>) encodes its
value TYPE in the first character of its key string -- the Hungarian
prefix (``fJumpHeightMin`` is a float, ``iMaxAttachedArrows`` an int,
``bAllowScriptedAutosave`` a bool).  So one string match both NAMES the
global setting object and TYPES its value union, with no stored type
field.

This module holds the rule-expressible bits: recognizing a Hungarian
setting key and mapping its prefix to a pipeline value type.  The driver
(settings_harvest.py) does the string scan + xref + Ghidra typing.
Per-game struct geometry (value/name offsets, struct size) lives in the
driver since it's just constants.
"""
import re

# A setting key: a Hungarian prefix char then an upper/lower identifier.
# Prefixes per the engine convention (a/c/h/r are F4/SF additions).
_KEY_RE = re.compile(r'^([abcfhirsSu])([A-Z][A-Za-z0-9_]{2,})$')

# Prefix -> (pipeline value type, byte width within the 8-byte union slot).
# 's'/'S' are an 8-byte char*; everything else is a 4-byte scalar in the
# low dword of the union.
_PREFIX_TYPE = {
    'f': ('float', 4),
    'i': ('int', 4),
    'u': ('uint', 4),
    'b': ('bool', 4),     # 1-byte value, 4-byte slot
    'c': ('char', 4),     # signed char, F4/SF
    'h': ('byte', 4),     # unsigned char, F4/SF
    'a': ('uint', 4),     # RGBA packed
    'r': ('uint', 4),     # RGB packed
    's': ('ptr', 8),      # static string literal char*
    'S': ('ptr', 8),      # dynamically-allocated string char*
}


def setting_key(s):
    """Return the key string if ``s`` is a Hungarian setting key, else None."""
    if not s or len(s) > 64 or ' ' in s:
        return None
    return s if _KEY_RE.match(s) else None


def value_type(key):
    """Return (pipeline_type, width) for a setting key's value union, or None."""
    m = _KEY_RE.match(key or '')
    if not m:
        return None
    return _PREFIX_TYPE.get(m.group(1))
