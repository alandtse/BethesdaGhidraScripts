"""Ghidra driver: name unnamed functions from the debug strings the engine
embeds about itself.

Scans `FUN_*`/`sub_*`/`thunk_*` functions for three self-naming string patterns
(timer-zone profiler labels, self-naming assert/log messages, telemetry SDK names --
see plans/string_anchor_match.py) and renames them to the real `Namespace::method`.

NON-DESTRUCTIVE: only renames functions still carrying a placeholder name; never
clobbers an established name. A name is applied only when a function maps to a
SINGLE consistent identifier that is unique across the program (ambiguous strings
are reported, never guessed).

CROSS-VERSION: match is by STRING, so the same debug string names the same function
in SE/AE/VR (and across F4/SF builds) without any address mapping. Run per program
(File->Save after each; symbols can't be saved from inside eval).

Superset merge of two independently-forked drivers (core/string_anchored_rename.py
and commonlibvr/string_anchored_rename.py). The two forks' actual matching/consensus
LOGIC turned out identical -- commonlibvr's driver had reimplemented the regex
patterns and resolve() algorithm inline instead of importing the already-shared,
already-tested plans/string_anchor_match.py, which this merged driver now calls into
(no logic duplicated in the driver itself). VR's ambiguous-example printing is kept
as a superset addition.

Env (both forks' original names are honored; the two forks used entirely different
names for the apply toggle, not just different prefixes, so all three are checked):
  RENAME_APPLY / BGS_ENRICH_APPLY / CLVR_RENAME=go    actually rename (default: dry-run)
  RENAME_TELEMETRY_NS / BGS_RENAME_TELEMETRY_NS / CLVR_RENAME_TELEMETRY_NS
      comma list of telemetry namespaces (default: bnet)
  RENAME_ENTRY_WINDOW / BGS_ENRICH_ENTRY_WINDOW
      timer ref must sit within N bytes of entry (default 0x80 -- commonlibvr's fork
      hardcoded this with no override; the merged driver keeps the same default but
      makes it overridable, a harmless additive capability)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from plans import string_anchor_match as sam  # noqa: E402
from engine.tx import transaction  # noqa: E402


def _env(*names, default=''):
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


APPLY = _env('RENAME_APPLY', 'BGS_ENRICH_APPLY', 'CLVR_RENAME', default='dry').lower() == 'go'
ENTRY_WINDOW = int(_env('RENAME_ENTRY_WINDOW', 'BGS_ENRICH_ENTRY_WINDOW', default='0x80'), 0)
TELEMETRY_NS = set(_env('RENAME_TELEMETRY_NS', 'BGS_RENAME_TELEMETRY_NS',
                        'CLVR_RENAME_TELEMETRY_NS', default='bnet').split(','))


def _is_placeholder(name):
    return (name.startswith('FUN_') or name.startswith('sub_')
            or name.startswith('thunk_FUN'))


def _iter_strings(listing):
    di = listing.getDefinedData(True)
    while di.hasNext():
        d = di.next()
        tn = d.getDataType().getName().lower()
        if 'char' not in tn and 'string' not in tn:
            continue
        v = d.getValue()
        if v is None:
            continue
        yield d, str(v).strip()


def _collect(cp):
    """func-entry-offset -> (func, set(candidate names)) from all patterns."""
    fm, listing, rm = (cp.getFunctionManager(), cp.getListing(),
                       cp.getReferenceManager())
    by_func = {}
    for d, s in _iter_strings(listing):
        name, is_timer = sam.match_any(s, TELEMETRY_NS)
        if not name:
            continue
        for ref in rm.getReferencesTo(d.getAddress()):
            f = fm.getFunctionContaining(ref.getFromAddress())
            if f is None or not _is_placeholder(f.getName()):
                continue
            ep = f.getEntryPoint().getOffset()
            if is_timer and ref.getFromAddress().getOffset() - ep > ENTRY_WINDOW:
                continue  # timer string must be at entry
            by_func.setdefault(ep, (f, set()))[1].add(name)
    return by_func


def _namespace(cp, st, parts):
    from ghidra.program.model.symbol import SourceType
    ns = cp.getGlobalNamespace()
    for part in parts:
        child = st.getNamespace(part, ns)
        if child is None:
            child = st.createNameSpace(ns, part, SourceType.USER_DEFINED)
        ns = child
    return ns


def run():
    from ghidra.program.model.symbol import SourceType
    cp = currentProgram  # noqa: F821
    st = cp.getSymbolTable()
    by_func = _collect(cp)
    plan, ambiguous = sam.resolve(by_func)

    applied = errors = 0
    with transaction(cp, 'string-anchored rename', APPLY):
        for ep, name in plan:
            f = by_func[ep][0]
            parts = name.split('::')
            if APPLY:
                try:
                    f.setParentNamespace(_namespace(cp, st, parts[:-1]))
                    f.setName(parts[-1], SourceType.USER_DEFINED)
                    applied += 1
                except Exception:
                    errors += 1

    print('string-anchored rename (%s): %s'
          % (cp.getName(), 'APPLIED' if APPLY else 'DRY-RUN'))
    print('  %s=%d  errors=%d  ambiguous-skipped=%d'
          % ('renamed' if APPLY else 'would-rename',
             applied if APPLY else len(plan), errors, len(ambiguous)))
    for ep, name in plan[:40]:
        print('   0x%X -> %s' % (ep, name))
    for a in sorted(ambiguous)[:10]:
        print('   AMBIGUOUS (skipped): %s' % a)
    if not APPLY:
        print('  set RENAME_APPLY=go (or BGS_ENRICH_APPLY / CLVR_RENAME) to apply.')


run()
