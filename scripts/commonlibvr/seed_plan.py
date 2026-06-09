"""Pure (Ghidra-free) decision logic for the `this`-pointer seeder.

Replaces the naive PopulateParameters approach: resolve the class from the real
GhidraClass namespace (the driver does that) and decide, per function, whether to
set param-0 to `Class*`. Non-destructive by construction -- only seeds when the
slot is currently untyped and the signature is not authoritative, never touching
IMPORTED/USER_DEFINED prototypes or static/operator members. Seeds use
SourceType.ANALYSIS so a human edit or a CommonLib re-import always outranks them.

These extra typed `this` anchors are what a downstream call-graph type-propagation
fixpoint radiates from.
"""

_PROTECTED_SOURCES = ('IMPORTED', 'USER_DEFINED')
_SKIP_LEAF_PREFIX = ('operator',)


def is_untyped(typename):
    """True if a param type carries no class information (so seeding `this` is an
    improvement, not a clobber): absent, undefined, or a bare void pointer."""
    if not typename:
        return True
    t = typename.replace(' ', '')
    while t.endswith(('*', '64')):
        t = t[:-2] if t.endswith('64') else t[:-1]
    return t == '' or t.startswith('undefined') or t == 'void'


def should_seed_this(class_known, leaf, param0_typename, sig_source, is_static):
    """Decide whether to set param-0 to `Class*`. Returns (action, reason) where
    action is 'seed' or 'skip'.

      class_known      a /types.h struct for the class exists
      leaf             the method short name (to exclude operators/lambdas)
      param0_typename  current type of param 0 (None if the function has none)
      sig_source       'IMPORTED'/'USER_DEFINED'/'ANALYSIS'/'DEFAULT'
      is_static        the method is static (no `this`) -- from CommonLib if known
    """
    if is_static:
        return ('skip', 'static-no-this')
    if not class_known:
        return ('skip', 'class-type-not-found')
    if not leaf or leaf.startswith(_SKIP_LEAF_PREFIX) or '<lambda' in leaf:
        return ('skip', 'operator-or-lambda')
    if sig_source in _PROTECTED_SOURCES:
        return ('skip', 'protected-source')   # never clobber PDB / hand-curated
    if not is_untyped(param0_typename):
        return ('skip', 'already-typed')
    return ('seed', 'ok')
