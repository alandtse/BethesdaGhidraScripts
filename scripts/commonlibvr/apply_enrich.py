"""CommonLibVR -> Ghidra ENRICH-ONLY apply (conflict-aware, non-destructive).

Runs INSIDE Ghidra against the target program. Reads a generated
``CommonLibImport_CLVR_*.py`` and applies its types using the per-type policy from
conflict_report.classify(), instead of the generated script's blanket
REPLACE-everything behaviour:

  NEW          -> create in /types.h
  MATCH        -> reuse existing type (register, no write)
  GEN_EMPTY    -> keep existing (CommonLibVR opaque, no write)
  STUB_UPGRADE -> replaceDataType (fill empty stub)
  EXTENDS      -> replaceDataType (generated is a superset)
  DIVERGENT    -> replaceDataType (generated = validated VR layout; existing is
                  auto-extracted SE-sized)
  HANDCURATED  -> PROTECT: keep existing, never overwrite (listed for review)
  VFTABLE_LOSS -> PROTECT: keep existing (replace would drop a vtable pointer)

replaceDataType() rewires every reference and leaves function signatures intact
(the type identity is swapped, params/returns preserved).

SAFETY: DRY_RUN is the default. It writes NOTHING to the program and emits an
apply-plan CSV + summary. To actually apply, set env CLVR_APPLY=go.

  Dry-run:  exec this file in Ghidra (default)              -> plan only
  Apply:    set os.environ['CLVR_APPLY']='go' then exec     -> writes types
"""
import os

from ghidra.program.model.data import (
    StructureDataType, CategoryPath, DataTypeConflictHandler)

IMPORT_PATH = os.environ.get(
    'CLVR_IMPORT',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\ghidrascripts\CommonLibImport_CLVR_VR.py')
SCRIPT_DIR = os.environ.get(
    'CLVR_SCRIPT_DIR',
    r'E:\Documents\source\repos\BethesdaGhidraScripts\scripts\commonlibvr')
CONFLICT_REPORT = os.path.join(SCRIPT_DIR, 'conflict_report.py')
PLAN_CSV = os.environ.get('CLVR_PLAN', IMPORT_PATH + '.apply_plan.csv')
NEW_CAT = '/types.h'
STAGING_CAT = '/CommonLibVR_staging'

DRY_RUN = os.environ.get('CLVR_APPLY', 'dry').lower() != 'go'

# status -> high-level action
ACTION = {
    'NEW': 'CREATE',
    'MATCH': 'REUSE',
    'GEN_EMPTY': 'REUSE',
    'STUB_UPGRADE': 'REPLACE',
    'EXTENDS': 'REPLACE',
    'DIVERGENT': 'REPLACE',
    'HANDCURATED': 'PROTECT',
    'VFTABLE_LOSS': 'PROTECT',
    'SUSPICIOUS': 'PROTECT',
    'EMBED_BASE': 'PROTECT',
}


def _load_generated_ns():
    """exec the generated import file WITHOUT its trailing run() so we get its
    data (ENUMS/STRUCTS/VTABLES/SYMBOLS) and helpers (resolve_type/created/dtm).
    """
    with open(IMPORT_PATH, 'r') as f:
        text = f.read()
    cut = text.rfind('\nrun()')
    if cut < 0:
        raise RuntimeError('could not find trailing run() to strip')
    body = text[:cut]
    gns = dict(globals())             # inherit flat API
    gns.update(_ghidra_globals())     # currentProgram/monitor are name-injected, not in globals()
    exec(compile(body, IMPORT_PATH, 'exec'), gns)
    return gns


def _load_classifier():
    cns = dict(globals())
    cns.update(_ghidra_globals())
    cns['AUTORUN'] = False
    exec(compile(open(CONFLICT_REPORT).read(), CONFLICT_REPORT, 'exec'), cns)
    return cns


def _ghidra_globals():
    """currentProgram/monitor are injected as names by pyghidra but are not keys
    in globals(); collect the ones the generated/report code reads."""
    g = {}
    for nm in ('currentProgram', 'monitor', 'state', 'currentAddress',
               'createFunction', 'createLabel', 'getCurrentProgram'):
        try:
            g[nm] = eval(nm)
        except Exception:
            pass
    return g


def run():
    gns = _load_generated_ns()
    cns = _load_classifier()
    classify = cns['classify']
    build_live = cns['build_live']

    dtm = gns['dtm']
    resolve_type = gns['resolve_type']
    make_padding = gns['make_padding']
    created = gns['created']
    STRUCTS = gns['STRUCTS']
    ENUMS = gns['ENUMS']
    VTABLES = gns['VTABLES']
    _U8 = gns['_BYTE']; _U16 = gns['_U16']; _U32 = gns['_U32']; _U64 = gns['_U64']
    KEEP = DataTypeConflictHandler.KEEP_HANDLER

    live = build_live(dtm)

    # ---- decide an action for every generated struct ----
    plan = []          # (name, status, action, gen_size, existing_size, category)
    counts = {}
    for st in STRUCTS:
        name = st[0]
        c = classify(st, live)
        status = c['status']
        action = ACTION.get(status, 'PROTECT')
        counts[action] = counts.get(action, 0) + 1
        plan.append((name, status, action, c['gen_size'], c['existing_size'],
                     c['existing_category']))

    # ---- always: write the plan CSV + summary (no program writes here) ----
    try:
        with open(PLAN_CSV, 'w') as out:
            out.write('name,status,action,gen_size,existing_size,existing_category\n')
            for p in plan:
                out.write(','.join('' if x is None else str(x) for x in p) + '\n')
        print('Wrote apply plan: {}'.format(PLAN_CSV))
    except Exception as e:
        print('plan CSV write failed:', e)

    print('\n=== apply plan ({} structs) ==='.format(len(STRUCTS)))
    for a in ('CREATE', 'REUSE', 'REPLACE', 'PROTECT'):
        print('  {:9s} {}'.format(a, counts.get(a, 0)))
    print('  (+ {} enums, {} vtable structs to create/reuse)'.format(len(ENUMS), len(VTABLES)))
    prot = [p for p in plan if p[2] == 'PROTECT']
    if prot:
        print('\n--- PROTECT (kept as-is, NOT overwritten) ---')
        for p in prot[:30]:
            print('  {} [{}] gen={} existing={} {}'.format(p[0], p[1], p[3], p[4], p[5]))
    rep = [p for p in plan if p[2] == 'REPLACE']
    print('\n--- REPLACE sample (existing -> generated VR layout) ---')
    for p in rep[:15]:
        print('  {} [{}] {} -> {}  ({})'.format(p[0], p[1], p[4], p[3], p[5]))

    if DRY_RUN:
        print('\nDRY_RUN: no changes written. Set env CLVR_APPLY=go to apply.')
        return counts

    # =========================== APPLY ===========================
    print('\n*** APPLYING (CLVR_APPLY=go) ***')
    tx = dtm.startTransaction('CommonLibVR enrich apply')
    try:
        # Phase 1: register created[] target for every struct + enum + vtable.
        # REUSE/PROTECT -> existing dt; CREATE -> shell in /types.h; REPLACE ->
        # staging shell (filled later, then swapped via replaceDataType).
        staging = {}   # name -> (staging_dt, existing_dt)
        for st in STRUCTS:
            name, gsize, gcat, gfields, gbases, ghas_vt = st
            c = classify(st, live)
            action = ACTION.get(c['status'], 'PROTECT')
            ns_alias = '::'.join(gcat.strip('/').split('/')[1:])
            if action in ('REUSE', 'PROTECT'):
                dt = c['best']
            elif action == 'CREATE':
                dt = dtm.addDataType(StructureDataType(CategoryPath(NEW_CAT), name, gsize), KEEP)
            else:  # REPLACE -> staging
                sdt = StructureDataType(CategoryPath(STAGING_CAT), name, gsize)
                dt = dtm.addDataType(sdt, DataTypeConflictHandler.REPLACE_HANDLER)
                staging[name] = (dt, c['best'])
            created[name] = dt
            created[gcat + '/' + name] = dt
            if ns_alias:
                created[ns_alias + '::' + name] = dt

        # enums: reuse if a same-named enum exists anywhere, else create in /types.h
        EnumDataType = gns['EnumDataType']
        live_enum = {}
        import ghidra.program.model.data as _D
        for d in dtm.getAllDataTypes():
            if isinstance(d, _D.Enum):
                live_enum.setdefault(d.getName(), d)
        for en in ENUMS:
            ename, esize, ecat, evals = en
            ex = live_enum.get(ename)
            if ex is not None:
                created[ename] = ex
                continue
            e = EnumDataType(CategoryPath(NEW_CAT), ename, esize)
            for vname, vval in evals:
                try:
                    e.add(vname, vval)
                except Exception:
                    e.add(vname + '_', vval)
            created[ename] = dtm.addDataType(e, KEEP)

        # vtable structs (NEW names like X_vtbl) -> create in /types.h
        _create_vtable_structs(gns, dtm, NEW_CAT)

        # Phase 2: fill fields for CREATE shells + REPLACE staging shells.
        replace_names = set(staging.keys())
        for st in STRUCTS:
            name, gsize, gcat, gfields, gbases, ghas_vt = st
            target = created.get(name)
            if target is None:
                continue
            # only fill things we own (created new or staged); never edit REUSE/PROTECT existing
            is_create = (target.getCategoryPath().getPath() == NEW_CAT and name not in replace_names
                         and target.getNumDefinedComponents() == 0)
            if name in replace_names:
                s = staging[name][0]
            elif is_create:
                s = target
            else:
                continue
            _fill_struct(s, gsize, gfields, resolve_type, make_padding, _U16, _U32, _U64, _U8)

        # Phase 3: swap each staged replacement in for the existing type (rewires
        # all refs; function signatures preserved). updateCategoryPath=True moves
        # the staged type into the existing type's category and removes existing.
        swapped = 0
        for name, (sdt, existing) in staging.items():
            try:
                dtm.replaceDataType(existing, sdt, True)
                swapped += 1
            except Exception as e:
                print('replace failed for {}: {}'.format(name, e))
        print('Replaced {} existing types via replaceDataType'.format(swapped))
    finally:
        dtm.endTransaction(tx, True)
    print('Type enrich-apply complete. (symbols/vtable-names are a separate pass)')
    return counts


def _fill_struct(s, size, gfields, resolve_type, make_padding, _U16, _U32, _U64, _U8):
    for field in gfields:
        fname, ftype_str, foffset, fsize = field
        if str(ftype_str).startswith('bf:'):
            parts = ftype_str.split(':')
            bit_off = int(parts[1]); width = int(parts[2])
            bw = 4; base = _U32
            for _bw, _bd in [(1, _U8), (2, _U16), (4, _U32), (8, _U64)]:
                bits = _bw * 8
                sb = (bit_off // bits) * _bw
                if bit_off % bits + width <= bits and sb + _bw <= size:
                    bw = _bw; base = _bd; break
            storage = (bit_off // (bw * 8)) * bw
            in_storage = bit_off % (bw * 8)
            try:
                s.insertBitFieldAt(storage, bw, in_storage, base, width, fname, '')
            except Exception:
                pass
            continue
        if fsize <= 0 or foffset + fsize > size:
            continue
        dtf = resolve_type(ftype_str)
        if dtf and dtf.getLength() == fsize:
            use_dt, use_name = dtf, fname
        else:
            use_dt, use_name = make_padding(fsize), fname + '_raw'
        try:
            s.replaceAtOffset(foffset, use_dt, fsize, use_name, '')
        except Exception:
            pass


def _create_vtable_structs(gns, dtm, cat):
    """Mirror the generated _import_types vtable-struct creation, targeting `cat`
    and only creating ones that don't already exist (KEEP handler)."""
    StructureDataType_ = gns['StructureDataType']
    FunctionDefinitionDataType = gns['FunctionDefinitionDataType']
    ParameterDefinitionImpl = gns['ParameterDefinitionImpl']
    CategoryPath_ = gns['CategoryPath']
    resolve_type = gns['resolve_type']
    created = gns['created']
    _PTR = gns['_PTR']
    KEEP = DataTypeConflictHandler.KEEP_HANDLER
    for vt in gns['VTABLES']:
        vname, class_full_name, vtbl_size, category, slots = vt
        s = StructureDataType_(CategoryPath_(cat), vname, vtbl_size)
        for slot_off, slot_name, slot_ret, slot_params in slots:
            field_name = slot_name.replace('~', '_dtor_') if slot_name.startswith('~') else slot_name
            if slot_off + 8 > vtbl_size:
                continue
            try:
                if slot_ret is not None and slot_params is not None:
                    fdef = FunctionDefinitionDataType(CategoryPath_(cat), field_name + '_t', dtm)
                    ret_dt = resolve_type(slot_ret)
                    if ret_dt:
                        fdef.setReturnType(ret_dt)
                    if slot_params:
                        pdefs = []
                        for pname, ptype in slot_params:
                            pdefs.append(ParameterDefinitionImpl(pname, resolve_type(ptype) or _PTR, ''))
                        fdef.setArguments(pdefs)
                    fptr = dtm.getPointer(dtm.addDataType(fdef, KEEP), 8)
                    s.replaceAtOffset(slot_off, fptr, 8, field_name, '')
                else:
                    s.replaceAtOffset(slot_off, _PTR, 8, field_name, '')
            except Exception:
                pass
        created['vtbl:' + vname] = dtm.addDataType(s, KEEP)


run()
