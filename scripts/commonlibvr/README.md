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

### 5. Enrich phases (`CLVR_PHASE`) — run order for a full import
`apply_enrich.py` dispatches on the `CLVR_PHASE` env var. Run it inside Ghidra (exec the file,
or via the MCP eval) against the target program **in this order**; each is enrich-safe and
idempotent, and each is **dry-run by default** with its own `*=go` flag to write:

| order | `CLVR_PHASE` | what it does | apply flag |
|---|---|---|---|
| 1 | `types` (default) | create/replace types per `conflict_report.classify` | `CLVR_APPLY=go` |
| 2 | `symbols` | label + name FUN_/sub_ functions, apply CommonLib sigs, vtable-slot + fallback naming. Upgrades auto-inferred (DEFAULT/ANALYSIS) sigs; never clobbers USER_DEFINED/IMPORTED | (writes in-txn) |
| 3 | `sigconflict` | where a CommonLib sig **differs** from an existing USER_DEFINED/IMPORTED one, decompile both ways and keep the cleaner (`decompile_score`) | `CLVR_SIGCONFLICT=go` |
| 4 | `classes` | reparent flat `Class::Method` names into namespaces, create/promote GhidraClass per class, re-point straggler vftable fields | `CLVR_CLASSES=go` |

Phase 3 writes a decision CSV (`<import>.sigconflict.csv`); `CLVR_SIGCONFLICT_MAX` caps the
count. Phase 4 `CLVR_CLASSES_MAX` caps reparents. Pure decision logic is unit-tested
(`pytest scripts/commonlibvr/` — `apply_plan`, `decompile_score`); pre-commit runs ruff + these.

The program is modified **in-memory only** — the MCP/transaction layer can't save, so
**File→Save in Ghidra** after the phases to persist. Validated on SkyrimVR.exe: phase 3 chose
CommonLib in 429/913 conflicts (incl. 175/260 PDB overrides); phase 4 reparented ~14.3k
functions and produced ~2k GhidraClasses.

### 6. Version Tracking — exact cross-version matches from ids (`version_track.py`)
CommonLib's `RELOCATION_ID(se, ae)` / `VariantID(se, ae, vr)` give each symbol's exact address in
every runtime; the generated SYMBOLS carry them as `s`/`a`/`v` offsets. `version_track.py` turns
that ground truth into Ghidra Version Tracking ACCEPTED matches — far more precise than the
heuristic correlators (which match by bytes/instructions and drift onto adjacent functions):

- **SEED** — for a source address with no accepted match, inject the exact `src->dst` manual match
  and accept it (type Function for `func`, Data for labels).
- **AUDIT** — where a source already has an accepted match to a *different* dst, that is a
  correlator error (or a stale id); record it to `<import>.vt_audit.csv` for review. Never
  auto-changed.

Run inside Ghidra with the SE/AE/VR programs and the VT sessions open; dry-run by default,
`VT_APPLY=go` to seed. Decision logic is in `vt_plan.py` (unit-tested). Validated: seeded ~16.2k
(SE↔AE) + ~15.5k (SE↔VR) exact matches into the manual set (which had ~93 before), and surfaced
436 correlator conflicts to audit. Most conflicts were adjacent-function drift where the id mapping
is authoritative.

### 7. Write-back detection — Ghidra -> CommonLib (`commonlib_writeback.py`)
The pipeline imports CommonLib INTO Ghidra; this closes the other half of the loop by reporting
what the live program knows that CommonLib does not, so RE/PDB knowledge can flow back to the
canonical source. Per CommonLib function symbol it compares the live Ghidra name against
CommonLib's at that address (`commonlib_delta`, unit-tested):
- **NAME_DELTA** — Ghidra has a trusted (USER_DEFINED/IMPORTED) name whose base differs. Either a
  naming-convention difference to reconcile (`GetCurrentWeapon` vs PDB `GetCurrentlyEquippedWeapon`)
  or, when wildly different (`IsValid` vs `ResizeWindow`), a sign CommonLib's address for that
  runtime is wrong -- a `database.csv` bug to verify against the binary.
- **MISSING_IN_GHIDRA** — CommonLib named it but Ghidra is still generic: a gap in our own apply.

Read-only; writes `<import>.writeback.csv` with cross-version ids so each row is locatable in
CommonLib. The classes-phase `_<addr>` overload-disambiguation suffix is stripped before comparing.
Signature deltas are out of v1 (need cross-representation normalization; the `SIG_DELTA` path is
tested and ready). Validated: VR 143 / SE 155 / AE 281 name deltas.

`writeback_aggregate.py` (plain Python, no Ghidra) joins the three reports by symbol name and
triages each by HOW the disagreement is distributed across the runtimes it is *mapped* in
(presence comes from the generated SYMBOLS, so MATCH is distinguished from ABSENT = not yet
mapped). CommonLib is iterative -- a symbol may start SE/AE-only and gain a VR offset later -- so:
- **RUNTIME_SPECIFIC** (delta in some mapped runtimes, MATCH in others) names the suspect runtime
  vs the trusted ones. `suspect=vr` with SE MATCH (AE often ABSENT) is the prime case: an
  iteratively-added VR offset that may point at the wrong function -> verify against the binary /
  `vr_address_tools` database.csv.
- **RECONCILE** (delta in EVERY mapped runtime) -> one CommonLib name fix.
- **APPLY_GAP** -> our apply left it generic (often an AE-program intake gap).
Run: `python writeback_aggregate.py [import_dir] [out_csv]`. Validated: 263 RUNTIME_SPECIFIC /
79 RECONCILE / 90 APPLY_GAP, with the AE PDB intake the systematically noisiest source.

### 8. Discovery cycle — bootstrap Ghidra to find net-new RE (`commonlib_discover.py`)
The point of the bootstrap is not to re-export what CommonLib already knows -- it is to let
Ghidra's OWN tools discover what CommonLib doesn't, *because* the typed scaffold gives them anchors
to reason from. `commonlib_discover.py` drives Ghidra's decompiler dataflow inference
(`FillOutStructureHelper`, the engine behind "Auto Fill Out Structure") to infer field types at the
offsets CommonLib still marks `unkNN`:

- For each `/types.h` struct with unknown pointer-sized fields, it samples functions whose param-0 is
  that type (i.e. anything enrichment gave a typed `this` -- not just CommonLib's id-bound symbols,
  which is what scales the yield), runs read-only structure inference, and records the inferred type
  at each `unk` offset. `discover_plan` ranks them (a named type beats a size-only `ulonglong`;
  consensus across functions raises confidence).
- **NON-DESTRUCTIVE**: `processStructure` returns an in-memory `Structure`; nothing is applied to the
  program (asserted: data-type count unchanged). It only writes `<import>.discovered_fields.csv`.

This closes the loop and **compounds**: feed the discovered fields back to CommonLib, re-import, and
the now-typed field lets the decompiler propagate one level deeper next pass. Validated on SE: 60
classes / 92 functions -> 171 candidate fields, 142 high-confidence (e.g. `TESObjectCELL +0xB0 ->
TESForm*` x3, `CombatInventory +0xB0 -> BSTArray<TESForm*>`, `UI3DSceneManager +0x10 ->
NiPointer<BSShaderAccumulator>`) -- and only 60 of 217 unknown-bearing classes had typed methods this
pass, so coverage grows every cycle. Knobs: `CLVR_DISCOVER_PER_CLASS`, `CLVR_DISCOVER_FOLLOW=1`
(follow into callees, deeper + slower), `CLVR_DISCOVER_MAX_CLASSES`.

### 9. Scripts vs LLM-in-the-loop — division of labor
The **scripts are the focus**: the deterministic, reproducible artifact others run. They decide
everything rule-expressible — layouts, addresses, type/conflict classification, signature
application, and the bulk of conflict resolution and class population. Re-running them on a fresh
program reproduces that work.

A residual tail is genuine **judgment** the scripts can't reliably call: e.g. signature conflicts
where the two decompiles score within the margin, or dispositions that need reading the actual
code. There each script stops at a **defensible default** (keep the incumbent) and emits a
**decision log** (`<import>.sigconflict.csv`) so the picks are auditable. An LLM connected to
Ghidra — directly, or by reading that log plus both decompilations — can finish those cases by
reading the code. That step improves on the heuristic but is **not bit-reproducible**.

Working rules:
- **Fix the script when the failure is rule-expressible.** Fold the lesson back in so the
  deterministic core gets better over time (e.g. "an undeclared incoming-register param is a
  decisive signature defect" became a weight in `decompile_score`; static-method `this` handling
  became a generator fix).
- **Use the LLM for the irreducible-judgment tail**, and treat its applied corrections as
  authoritative. Do **not** regenerate over them with a script just to be "pure" — the decision
  logs keep LLM picks auditable, and a pure re-run can be *worse* (the heuristic is the fallback,
  not the ground truth).

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
- [x] Apply for real — all four phases applied to SkyrimVR.exe (`types`/`symbols`/`sigconflict`/
      `classes`). Enrich phases documented above; pure logic unit-tested.
