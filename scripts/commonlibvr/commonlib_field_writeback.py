"""Field write-back to CommonLibVR headers (the export half of the cycle).

Reads the three per-runtime `resolved_fields.csv` (the cross-version-reconciled struct
field TYPES the pipeline discovered), and rewrites the matching `unkNN` members in the
CommonLibVR C++ headers to their resolved type -- closing the loop CommonLib -> Ghidra
-> populate -> CommonLib.

CONSERVATIVE, non-destructive by design:
  * Only SAFE demangled types (pointers / primitives / arrays -- see
    field_writeback_plan) and only when the runtimes AGREE; templates, bitfields,
    inline classes and cross-runtime conflicts are reported, never written.
  * The member NAME is KEPT (`unk168` stays `unk168`); only the type token changes, so
    no consumer that references the member breaks. The `// NN` offset comment is kept.
  * A class type is written only if the header ALREADY references it (forward-decl or
    include present) -- we never inject forward declarations (placement/namespace risk).
  * Each member is located inside its own `class`/`struct` brace region, matched by the
    exact `unkNN` name, so we never touch a same-named member of another class.

Dry-run by default (writes <out>.field_writeback.report.csv of every would-change /
skip-reason); CLVR_FWB=go applies the edits to the working tree (run on a branch and
review the diff). Env: CLVR_RE_DIR (CommonLibVR/include/RE), CLVR_RESOLVED_DIR
(dir holding the *.resolved_fields.csv).
"""
import csv
import glob
import os
import re

RE_DIR = os.environ.get('CLVR_RE_DIR', r'E:\Documents\source\repos\CommonLibVR\include\RE')
RESOLVED_DIR = os.environ.get(
    'CLVR_RESOLVED_DIR', r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR', r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
APPLY = os.environ.get('CLVR_FWB', 'dry').lower() == 'go'
REPORT = os.path.join(RESOLVED_DIR, 'field_writeback.report.csv')

import importlib.util as _ilu  # noqa: E402
_spec = _ilu.spec_from_file_location('clvr_field_writeback_plan',
                                     os.path.join(SCRIPT_DIR, 'field_writeback_plan.py'))
wp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(wp)

_RT = {'SE': 'se', 'AE': 'ae', 'VR': 'vr'}


def _load_resolved():
    rows = {}
    for tag, rt in _RT.items():
        path = os.path.join(RESOLVED_DIR, 'CommonLibImport_CLVR_%s.py.resolved_fields.csv' % tag)
        if not os.path.exists(path):
            continue
        with open(path, newline='') as fh:
            rows[rt] = [(r['class'], r['cl_offset'], r['typename']) for r in csv.DictReader(fh)]
    return rows


def _index_headers():
    """Map each `class X`/`struct X` name -> list of (file, body_start, body_end) brace
    regions across the RE headers, so a member can be located within its own type."""
    idx = {}
    decl = re.compile(r'\b(?:class|struct)\s+([A-Za-z_]\w*)\b')
    for path in glob.glob(os.path.join(RE_DIR, '**', '*.h'), recursive=True):
        try:
            text = open(path, encoding='utf-8', errors='replace').read()
        except Exception:
            continue
        for m in decl.finditer(text):
            brace = text.find('{', m.end())
            if brace < 0:
                continue
            end = _match_brace(text, brace)
            if end > brace:
                idx.setdefault(m.group(1), []).append((path, brace, end))
    return idx


def _match_brace(text, open_idx):
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i
    return -1


def _type_known(text, cpp):
    """The base class name of a pointer/inline type is already referenced in the file
    (forward-decl or include) -- so writing it won't fail to compile."""
    base = cpp.replace('*', '').replace('std::', '').strip()
    if base in ('std::uint8_t', 'uint8_t', 'std::uint16_t', 'std::uint32_t',
                'std::uint64_t', 'std::int8_t', 'std::int16_t', 'std::int32_t',
                'std::int64_t', 'char', 'bool', 'float', 'double', 'void'):
        return True
    if not re.match(r'^[A-Za-z_]\w*$', base):     # arrays/templates handled by caller
        return True
    return re.search(r'\b%s\b' % re.escape(base), text) is not None


def run():
    rows = _load_resolved()
    if not rows:
        print('No resolved_fields.csv found in %s' % RESOLVED_DIR)
        return
    decisions = wp.reconcile(rows)
    idx = _index_headers()
    print('field-writeback: %d resolved (class,offset) keys, %d classes indexed in %s'
          % (len(decisions), len(idx), RE_DIR))

    edits = []          # (path, old_line, new_line, cls, off)
    report = []         # (cls, off, ghidra, cpp, status)
    file_text = {}      # path -> current text (mutated as we apply)

    for (cls, off), rec in sorted(decisions.items()):
        off_n = int(off, 16)
        member = 'unk%X' % off_n
        if rec['conflict']:
            report.append((cls, off, rec['ghidra'], rec['cpp'] or '', 'skip:runtime-conflict'))
            continue
        if not rec['safe']:
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:%s' % rec['kind']))
            continue
        regions = idx.get(cls)
        if not regions:
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:class-not-found'))
            continue
        # member declaration line within the class body, named exactly unk<OFF>
        pat = re.compile(r'(^[ \t]*)([A-Za-z_][\w:<>,\* \t]*?)\b(%s)\b([ \t]*;)' % member, re.M)
        located = None
        for path, bs, be in regions:
            text = file_text.get(path) or open(path, encoding='utf-8', errors='replace').read()
            file_text[path] = text
            body = text[bs:be]
            mm = pat.search(body)
            if mm and _is_member_name(member, mm):
                located = (path, bs, mm)
                break
        if located is None:
            report.append((cls, off, rec['ghidra'], str(rec['cpp']), 'skip:member-not-found'))
            continue
        path, bs, mm = located
        cppdecl = wp.cpp_member(rec['cpp'], rec['kind'], member)
        text = file_text[path]
        if rec['kind'] != 'array' and not _type_known(text, rec['cpp']):
            report.append((cls, off, rec['ghidra'], rec['cpp'], 'skip:type-not-in-header'))
            continue
        old_line = mm.group(0)
        indent = mm.group(1)
        new_line = '%s%s;' % (indent, cppdecl)        # keep member name; retype only
        edits.append((path, off, bs, mm.start(), mm.end(), old_line, new_line, cls))
        report.append((cls, off, rec['ghidra'], rec['cpp'], 'rewrite' if APPLY else 'would-rewrite'))

    # apply edits per file (offsets shift -> apply back-to-front within each file)
    applied = 0
    if APPLY:
        byfile = {}
        for e in edits:
            byfile.setdefault(e[0], []).append(e)
        for path, es in byfile.items():
            text = file_text[path]
            for e in sorted(es, key=lambda x: x[2] + x[3], reverse=True):
                _p, _off, bs, ms, me, old, new, _cls = e
                a, b = bs + ms, bs + me
                text = text[:a] + new + text[b:]
                applied += 1
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(text)

    def _cppstr(cpp):
        if cpp is None:
            return ''
        if isinstance(cpp, tuple):              # array (base, 'array', n)
            return '%s[%s]' % (cpp[0], cpp[2])
        return str(cpp)

    with open(REPORT, 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['class', 'cl_offset', 'ghidra_type', 'cpp_type', 'status'])
        for cls, off, gh, cpp, status in sorted(report, key=lambda r: (r[4], r[0], r[1])):
            w.writerow([cls, off, gh, _cppstr(cpp), status])

    from collections import Counter
    tally = Counter(r[4].split(':')[0] for r in report)
    print('  %s: %d fields -> %s' % ('APPLIED' if APPLY else 'DRY-RUN', len(report), dict(tally)))
    print('  rewrite candidates: %d (applied=%d)' % (len(edits), applied))
    for e in edits[:15]:
        print('     %s +%s  %s' % (e[7], e[1], e[6].strip()[:70]))
    print('  report -> %s' % REPORT)
    if not APPLY:
        print('  set CLVR_FWB=go to apply (run on a CommonLibVR branch; review the diff).')


def _is_member_name(member, mm):
    """The matched `unkNN` is the declared member, not part of a longer identifier."""
    return mm.group(3) == member


run()
