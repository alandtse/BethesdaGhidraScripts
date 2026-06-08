# commonlibvr — CommonLibVR (alandtse) multi-runtime source

Additive source module that imports Skyrim SE/AE/VR types from **`alandtse/CommonLibVR`**
instead of `powerof3/CommonLibSSE`. Nothing in `scripts/commonlibsse/` is modified; this lives
alongside it, exactly like `commonlibf4`/`commonlibsf`/`commonlibnvse`.

## Why a separate source
`powerof3/CommonLibSSE` has **no VR layouts** — BGS parses Skyrim VR using the SE define set and
only attaches VR offsets afterward (`commonlibsse/parse_commonlib_types.py`, `svr` config). So VR
*structs/vtables* are approximated as SE. `alandtse/CommonLibVR` is a true multi-runtime codebase
that models the real VR divergence (larger structs, shifted vtables), so it yields **accurate VR
layouts**.

## Submodule
`.gitmodules` adds `extern/CommonLibVR` → `https://github.com/alandtse/CommonLibVR` (branch `ng`).
For offline iteration a directory junction to a local checkout works:
`extern/CommonLibVR` → `E:\Documents\source\repos\CommonLibVR`.

## The two layers

### 1. Types / vtables / layouts — a CONFIG change (validated)
CommonLibVR selects layout by runtime via `REL/Common.h`:
- exactly one `ENABLE_SKYRIM_{SE|AE|VR}=1` → `EXCLUSIVE_SKYRIM_{SE|AE|VR}` (concrete layout)
- two-or-more with VR → `SKYRIM_CROSS_VR` (strips runtime-divergent members; **never use for parsing**)

So the per-runtime parse is just the right define, isolated:

| version | define | resolves to |
|---|---|---|
| se | `-DENABLE_SKYRIM_SE=1` | EXCLUSIVE_SKYRIM_SE / FLAT |
| ae | `-DENABLE_SKYRIM_AE=1` | EXCLUSIVE_SKYRIM_AE / FLAT |
| svr | `-DENABLE_SKYRIM_VR=1` | EXCLUSIVE_SKYRIM_VR |

The umbrella `RE/Skyrim.h` self-primes (`#include "SKSE/Impl/PCH.h"`), so no extra prelude is needed.
The VR build pulls two deps the powerof3 path never did:
- **openvr** — real headers at `extern/CommonLibVR/extern/openvr/headers` (`-I`)
- **DirectXTK `SimpleMath.h`** — via `RE/State.h` (use BGS's stub/shadow pattern; a raw vcpkg include
  conflicts with the PCH macros — confirmed 20 errors)

**Validated** (clang 20.1.7, `--target=x86_64-pc-windows-msvc -std=c++23`):
`RE::NiAVObject` → `sizeof=0x138`, `flags @ 0x10C` under `ENABLE_SKYRIM_VR` — matches CommonLibVR's
VR `static_assert` exactly. (Flat is `0x110`.)

`scripts/commonlibsse/parse_commonlib_types.py` is import-safe (no top-level side effects), so the
type layer can be a **thin wrapper**: import it, override `COMMONLIB_INCLUDE`/`VERSIONS`, append the
openvr + DirectXTK `-I` args, reuse `core/clang_types`.

### 2. Addresses — additive `reloc_parser.py` + `main()` (built, validated)
CommonLibVR's address model differs from powerof3 in two spots; everything else is reused:

| item | powerof3 | CommonLibVR | how we handle it |
|---|---|---|---|
| functions | `RELOCATION_ID(se, ae)` | same (2-arg) | reuse base header/src scanners verbatim |
| VR func offset | `vr_db[se_id]` | same | reuse; src scanner extended to attach `vr_db[se_id]` |
| RTTI/VTABLE | `REL::ID` + `#ifdef SKYRIM_SUPPORT_AE` | `REL::VariantID(se, ae, vr_literal)`, single section | **new** scanner `_scan_variant_rtti_vtable_file` |
| `Offset::` ns | `Offsets.h` | none | offset maps empty (no-op) |
| VR DB source | meh321 | **`vr_address_tools/version-1-4-15-0.csv`** (from `database.csv`) | `BGS_VR_CSV` env, falls back to `addresslibrary/sse/` |

`reloc_parser.py` loads the powerof3 base by explicit path under a distinct module name
(`commonlibsse_reloc_parser`) to avoid the shared-basename `sys.modules` collision, reuses its
`_ContextTracker` + function scanners, and replaces only the RTTI/VTABLE scanner for the
`VariantID` form. `parse_commonlib_types.py main()` builds the SE/AE/VR address DBs, collects
symbols, attaches `si`/`ai` ids, and feeds them to the same `base.run_version`.

**Validated** (svr, address layer in isolation): 16540 labels (7687 RTTI + 410 NiRTTI + 8443
VTABLE) + 1161 functions = **17701 symbols, VR coverage 17149 (97%)**. Spot-checks:
`RTTI_AlchemyItem` → VR `0x1ed6d60` (the literal third `VariantID` arg); `ActorMagicCaster::
CheckAttachCastingArt` → VR `vr_db[33403]` from `RELOCATION_ID(33403, 34185)`.

Run: `python parse_commonlib_types.py svr` (full, with addresses) or `... svr --types-only` (fast,
layouts only).

### 3. Apply into Ghidra — conflict-aware, non-destructive (`conflict_report.py` + `apply_enrich.py`)
The generated import is clobber-by-default (REPLACE handler, creates parallel duplicate types in
`/CommonLibSSE/RE` alongside the program's real `/types.h` types). `apply_enrich.py` instead classifies
every struct against the live program (`conflict_report.classify`, single source of truth) and acts per
status, only ever *writing* existing types via `dtm.replaceDataType` (rewires refs, **leaves function
signatures intact**):

| status | action | why |
|---|---|---|
| NEW | create in `/types.h` | no existing type |
| MATCH / GEN_EMPTY | reuse existing | size match / CommonLib opaque |
| STUB_UPGRADE / EXTENDS | replace (fill / superset) | provably safe |
| DIVERGENT | replace (generated = validated VR layout) | existing is SE-sized/auto-extracted |
| HANDCURATED | **protect** | clean (PDB/hand) member names |
| VFTABLE_LOSS | **protect** | replace would drop a vtable pointer |
| SUSPICIOUS | **protect** | size ratio ≥4× ⇒ leaf-name collision (e.g. `RE::BSJobs::JobList`[8] vs `/types.h/JobList`[216]) |
| EMBED_BASE | **protect** | existing uses compositional base embedding |

Matching is namespace-aware (category → namespace; `/types.h`+pdb = RE/global) to avoid false collisions
like `RE::Color` vs `DirectX::SimpleMath::Color`. `apply_enrich.py` is DRY_RUN by default (writes a plan
CSV); `CLVR_APPLY=go` applies in one transaction. Sampling confirmed generated matches CommonLibVR's own
`static_assert(sizeof)`/`STATIC_ASSERT_SIZE(...,VR,...)` for every divergent case checked.

### 4. Inheritance representation — embed vs flatten (`embed_structs`)
By default the parser **embeds** each base as a struct member at its `pdb_bases` offset (compositional,
e.g. `NiNode { _base: NiAVObject; children; }`) rather than flattening base fields into every derived.
clang's `-fdump-record-layouts` supplies exact base offsets (incl. multiple inheritance, EBO, vbase) —
already parsed into `pdb_bases` — so no ABI layout logic is reimplemented. Where MSVC reuses a base's
**tail padding** (a sibling base/field starts before `base_off + base.size`), a **trimmed** base variant
(`X__embed_<size>`) is embedded instead, because a full-size embedded member is atomic and overlapping it
silently clears it (verified in Ghidra). Any base that can't be cleanly embedded falls back to a
flattened (byte-accurate) layout per struct, so field data is never lost. `CLVR_EMBED=0` reverts to pure
flatten. The primary base at offset 0 carries the shared vtable, so the derived's injected `__vftable@0`
is dropped (covered by the base member).

Implementation detail: this needs `SKIP_NESTED_BASE_FIELDS=True` in `clang_types` (set by the wrapper)
so `_parse_layouts_with_bases` records only **direct** bases + **own** fields (clang's layout dump nests
the full base tree under each record). `has_vtable` is detected from the whole layout block so the skip
does not suppress it; `dsize` is captured for the trim length.

**Tradeoff (inherent to embedding):** C++ shares the 8-byte vptr slot between base and derived, and a
Ghidra struct field can hold only one type, so a derived class's vptr ends up typed (through the `_base`
chain) to the **root** vtable struct, not the most-derived one. Per-class vtable structs and virtual-
function naming are unaffected (they go through the `VTABLE_*` symbols/addresses, not the field type) —
only the vptr field's *type* shows root methods. `CLVR_EMBED=0` (flatten) types the vptr to the
most-derived vtable instead, at the cost of no base composition. Pick per preference.

## Status
- [x] Additive submodule + junction; powerof3 path untouched
- [x] Per-runtime define set validated (VR layout correct)
- [x] Thin type-layer wrapper (config + openvr/DirectXTK includes) → emits `CommonLibImport_CLVR_{SE,AE,VR}.py`
      — VR run validated end-to-end: 846 enums / 27646 structs, 2761 vtable structs; `RE::NiAVObject`
      came out **312 (0x138)** with `flags @ 0x10C` and the VR-only `ApplyLocalTransformToWorld` slot
      (not the flat 0x110 the powerof3 path yields).
- [x] Address layer (`reloc_parser.py` VariantID 3-arg + RELOCATION_ID, VR addrlib from
      vr_address_tools) — validated in isolation: 17701 symbols, 97% VR coverage. Full
      generation (clang VR parse + symbols → `CommonLibImport_CLVR_VR.py`) wired into `main()`.
- [x] Conflict-aware non-destructive apply (`conflict_report.py` classify + `apply_enrich.py`
      replaceDataType); dry-run plan validated: CREATE ~25.8k / REUSE ~1.4k / REPLACE ~445 / PROTECT 17
      (0 vftable loss). Protect guards: HANDCURATED / VFTABLE_LOSS / SUSPICIOUS / EMBED_BASE.
- [x] Inheritance embedding (`embed_structs`, default on; trimmed variants for tail-padding reuse;
      per-struct flatten fallback). `CLVR_EMBED=0` to flatten.
- [ ] Apply for real (`CLVR_APPLY=go`) once embedded build is re-validated.
