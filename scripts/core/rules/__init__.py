"""Per-library configuration and data-format rules (include paths, category paths,
env-var namespace, version tuples, ID-file grammar, address-library binary format) --
the genuinely game-specific half of the DRY split, kept separate from the generic
mechanics in `core.engine` / `core.plans`.

`base.py` defines the `LibraryRules` protocol; each CommonLib target's own `rules.py`
implements it.
"""
