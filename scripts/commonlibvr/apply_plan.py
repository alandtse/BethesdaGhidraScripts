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


def select_fill_targets(structs, classify_fn, live, create_struct, stage_struct,
                        register=None, action_map=ACTION):
    """Decide an action per generated struct and return (fill_list, staging).

    fill_list : [(struct_dt, st)] -- the shells WE own and must fill (CREATE +
                REPLACE). REUSE/PROTECT structs are never filled (existing types
                are not edited).
    staging   : {name: (staging_dt, existing_dt)} for the REPLACE swaps.

    create_struct(name, size) -> dt        creates a new shell in /types.h.
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
            dt = create_struct(name, gsize)
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
