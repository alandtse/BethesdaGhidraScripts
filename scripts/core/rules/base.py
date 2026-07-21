"""LibraryRules: the per-CommonLib-target configuration/data-format contract.

Duck-typed (a `Protocol`, not a forced base class) to match this repo's existing
`sys.path.insert`-based sibling-import style rather than requiring real inheritance.
Fields are pure data (include paths, category paths, env-var namespace, version
tuples); grammar/format methods are the escape hatch for genuine per-game algorithmic
divergence (ID-file parsing, address-library binary format).

Phase 2 only requires the data fields (`LibraryRules` below) -- every current CommonLib
target's rules module implements those now. `LibraryRulesFormat` extends it with the
grammar/format methods; real per-game implementations of those are Phase-4 work (a
separate, later effort): unifying ID-file grammar / address-library reading across
x86 (nvse)/x64 (sf, sse)/PPC (nvse-Xbox) is exactly the kind of pointer-width/ISA-
parameterized work Phase 1-3 deliberately deferred (see the mechanical-merge
commits in core/engine/ for why forcing structurally different algorithms into one
shape without a Ghidra test oracle is a real risk, not a mechanical no-judgment merge).
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LibraryRules(Protocol):
    """The Phase 2 contract: pure data only, satisfiable by every current
    CommonLib target's rules module right now. Deliberately does NOT include the
    grammar/format methods (see LibraryRulesFormat below) -- Protocol isinstance
    checks require EVERY declared member to be present, so mixing not-yet-
    implemented methods into this protocol would make it unsatisfiable until
    Phase 4, defeating its use as a Phase 2/3 completeness check."""

    name: str                 # e.g. 'commonlibvr'
    import_path: str          # generated CommonLibImport_*.py this pipeline applies
    script_dir: str            # this library's own scripts/<name> directory
    types_category: str        # Ghidra category path RE types live under, e.g. '/types.h'
    include_paths: list        # CommonLib header roots for clang_types
    env_prefix: str             # env-var namespace, e.g. 'CLVR' -> gates CLVR_DEDUP, ...

    # --- version model (pure data) ---
    runtimes: list              # e.g. ['SE', 'AE', 'VR'] or ['OG', 'NG', 'VR'] or ['SF']
    version_tuples: dict         # runtime name -> build-id tuple


@runtime_checkable
class LibraryRulesFormat(LibraryRules, Protocol):
    """The Phase 4 contract: LibraryRules plus the grammar/format methods for
    per-game ID-file parsing and address-library reading. `isinstance(x,
    LibraryRulesFormat)` is the intended way to check whether a given library's
    Phase-4 work has landed.

    Phase 4 found that every implementing library already HAD its own working
    parser/loader (reloc_parser.py's collect_relocations, ids_parser.py's
    collect_all, address_library.py's AddressLibrary.load_bin, addresses.py's
    collect_all for FNV's header-only scheme) -- these methods are thin
    delegates to that pre-existing code, not new algorithms. Because the real
    per-game entry points take different shapes (a header directory + an
    address-library object for SE/F4/SF; an xNVSE root + a refs overlay dir for
    FNV, which has no address-library binary at all), `runtime_checkable`
    Protocol isinstance checks only require the METHOD NAMES to exist -- Python
    does not check call signatures -- so each library's implementation keeps
    its own natural parameter list rather than being forced into one artificial
    shape. See each library's `library_rules.py` docstring for its actual
    signature and what it delegates to."""

    def parse_id_file(self, *args, **kwargs):
        """Parse this game's ID-file grammar (e.g. SE's dual-ID RELOCATION_ID(se,ae)
        macro + #ifdef SKYRIM_SUPPORT_AE sections, vs F4's single-ID REL::ID registry,
        vs SF's versionlib, vs FNV's hardcoded-VA xNVSE headers) into that library's
        own symbol-list shape -- see the implementing class for its exact signature
        and return shape."""
        ...

    def load_address_library(self, path: str):
        """Read this game's address-library binary format (meh321 compressed V1/V2
        delta-encoded for SE, flat count+(id,offset) for F4, flat uint32[id] array for
        SF) into a uniform {id: offset} shape. FNV has no such format (no versionlib/
        REL::ID); its implementation documents that rather than faking one."""
        ...

    def format_relocation(self, ids: dict) -> str:
        """Render a relocation-id reference in this game's source-code convention
        (VR's single REL::VariantID(se,ae,vr) vs SE's #ifdef-split RELOCATION_ID(se,ae))."""
        ...

    def fallback_name_sources(self) -> list:
        """This game's ordered list of fallback name sources (SE: [.rename, PDB
        publics, globals-sigs]; F4: [IDA names, 1.11.221 PDB])."""
        ...


def env(prefix: str, key: str, default: str = '') -> str:
    """Resolve an env var under a library's namespace, e.g. env('CLVR', 'DEDUP') reads
    CLVR_DEDUP. Centralizes the '{prefix}_{key}' convention every *.py driver in this
    repo already follows by hand (os.environ.get('CLVR_DEDUP', 'dry'))."""
    import os
    return os.environ.get('%s_%s' % (prefix, key), default)
