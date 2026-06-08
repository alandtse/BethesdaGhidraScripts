"""Pure (Ghidra-free) planning logic for the CommonLibVR enrich apply.

Kept separate from apply_enrich.py (which imports Ghidra) so the decision logic is
unit-testable without a Ghidra session. apply_enrich imports ACTION and
select_fill_targets from here.
"""

# Conflict-status -> high-level apply action.
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


def enum_parent_key(category, name):
    """Parent-scoped match key for an enum: (last category component, leaf name),
    ignoring the root category (/CommonLibSSE, /CommonLibVR.pdb, /types.h, ...).
    Bare leaf names collide (every class has a 'Flag'); the parent component
    disambiguates, e.g. ('ACTOR_BASE_DATA', 'Flag')."""
    _ROOTS = ('CommonLibSSE', 'CommonLibVR.pdb', 'CommonLibVR', 'types.h',
              'Demangler', 'SkyrimSE.pdb', 'SkyrimVR.pdb', 'SkyrimAE.pdb', 'auto_structs')
    parts = [p for p in category.strip('/').split('/') if p]
    if parts and parts[0] in _ROOTS:
        parts = parts[1:]
    return (parts[-1] if parts else '', name)


def classify_enum(gen_size, gen_values, existing_size, existing_names):
    """Decide how a generated enum relates to an existing one. Lossless: EXTEND only
    ADDS names the existing enum lacks; it never removes manual values.

    Returns (action, add_values):
      NEW       existing is None                          -> create with gen_values
      KEEP_SIZE size differs                              -> keep existing, review (no repack)
      MATCH     same size, gen names subset of existing   -> reuse, nothing to add
      EXTEND    same size, gen has names existing lacks    -> add those (name,value) pairs
    """
    if existing_size is None:
        return ('NEW', list(gen_values))
    if gen_size != existing_size:
        return ('KEEP_SIZE', [])
    have = set(existing_names)
    add = [(n, v) for (n, v) in gen_values if n not in have]
    return ('MATCH', []) if not add else ('EXTEND', add)


def select_fill_targets(structs, classify_fn, live, create_struct, stage_struct,
                        register=None, action_map=ACTION):
    """Decide an action per generated struct and return (fill_list, staging).

    fill_list : [(struct_dt, st)] -- the shells WE own and must fill (CREATE +
                REPLACE). REUSE/PROTECT structs are never filled (existing types
                are not edited).
    staging   : {name: (staging_dt, existing_dt)} for the REPLACE swaps.

    create_struct(name, size, category) -> dt  creates a new shell (caller picks the
                                               target category from the generated one).
    stage_struct(name, size, existing) -> dt creates a staging shell to swap in.
    register(st, dt)                        optional: record dt (e.g. into created[]).

    REGRESSION GUARD: fill_list is built ONLY from struct CREATE/REPLACE actions,
    captured at creation time. It must never be re-derived from a shared name->dt
    map (e.g. `created`) that the enum pass also writes to -- an enum sharing a
    struct's leaf name would otherwise redirect a fill onto the enum object and
    crash (EnumDB has no getNumDefinedComponents). See
    test_apply_plan.test_enum_name_collision_does_not_pollute_fill_targets.
    """
    staging = {}
    fill_list = []
    for st in structs:
        name, gsize = st[0], st[1]
        c = classify_fn(st, live)
        action = action_map.get(c['status'], 'PROTECT')
        if action == 'CREATE':
            dt = create_struct(name, gsize, st[2])   # st[2] = generated category
            fill_list.append((dt, st))
        elif action == 'REPLACE':
            dt = stage_struct(name, gsize, c['best'])
            staging[name] = (dt, c['best'])
            fill_list.append((dt, st))
        else:  # REUSE / PROTECT -> keep existing, never fill
            dt = c['best']
        if register is not None:
            register(st, dt)
    return fill_list, staging
