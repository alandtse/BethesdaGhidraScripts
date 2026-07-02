# Bethesda Ghidra Scripts

Automatically imports CommonLib type definitions, vtable layouts, function
signatures, and address-library symbols into Ghidra for Bethesda game binaries.

## Quick start

1. Clone the repo:

```bash
git clone https://github.com/1001Bits/BethesdaGhidraScripts.git
cd BethesdaGhidraScripts
```

2. Drop your game executables into the matching folders (any combination):

```
exes/skyrim/se/SkyrimSE.exe       Skyrim SE    (1.5.97)
exes/skyrim/ae/SkyrimSE.exe       Skyrim AE    (1.6.1170+)
exes/skyrim/vr/SkyrimVR.exe       Skyrim VR    (1.4.15)
exes/f4/og/Fallout4.exe           Fallout 4 OG (1.10.163) — types only
exes/f4/ng/Fallout4.exe           Fallout 4 NG (1.10.984)
exes/f4/ae/Fallout4.exe           Fallout 4 AE (1.11.191)
exes/f4/221/Fallout4.exe          Fallout 4 AE (1.11.221)
exes/f4/vr/Fallout4VR.exe         Fallout 4 VR (1.2.72)   — types only
exes/starfield/sf/Starfield.exe   Starfield    (1.16.236 / 1.16.242 / 1.16.244) — labels + vtables
exes/fnv/og/FalloutNV.exe         Fallout NV   (1.4.0.525, x86) — xNVSE-sourced
```

Fallout New Vegas now flows through the same pipeline as the other versions
(symbol source: xNVSE headers + optional `scripts/commonlibnvse/refs/fnv_names.csv`
overlay). Menu option 9 (enrich-existing) still works against any other FNV
project you have lying around, but option 7 (full rebuild) handles FNV
end-to-end like Skyrim / F4 / Starfield.

3. Run:

```bash
python run.py
```

This opens an interactive menu:

```
============================================================
  Bethesda Ghidra Scripts
============================================================

  Tools:
    Ghidra      : 12.0.4
    Clang       : clang version 22.1.5
    Steamless   : OK
    Python pkgs : OK

  Executables:
    f4/ae: Fallout4.exe
    skyrim/ae: SkyrimSE.exe
    skyrim/se: SkyrimSE.exe
    starfield/sf: Starfield.exe

  Output:
    Import scripts : OK
    Ghidra project : OK

----------------------------------------
  1) Install prerequisites (Python packages, Ghidra, Clang, Steamless)
  2) Update CommonLib submodules to latest
  3) Process a specific version (per-version menu)
  4) Generate import scripts (all detected versions)
  5) Run headless Ghidra import
  6) Open Ghidra
  7) Full rebuild (generate + import all)
  8) Clean Ghidra project (start fresh)
  9) Enrich an existing Ghidra project (RTTI vtable pipeline)
  q) Quit
----------------------------------------
```

The status panel at the top shows what's installed and detected. Menu options:

| Option | What it does |
|--------|-------------|
| **1** | Installs Python packages (`pdbparse`, `pyghidra`, `capstone`, `numpy`), downloads Ghidra, LLVM/Clang, and Steamless if missing. Safe to run multiple times -- skips anything already installed. |
| **2** | Runs `git submodule update --init --recursive --remote` to pull the latest CommonLib (SSE/F4/SF) and AddressLibraryDatabase commits. Run this when upstream CommonLib has new types or fixes. |
| **3** | Per-version submenu: pick one detected version (e.g. just Skyrim VR, or just Fallout 4 OG) and run a subset of the pipeline against it -- generate only that version's script, import only its binary, etc. Useful when you don't want to rerun every game. |
| **4** | Parses every supported CommonLib's headers with clang and generates the Ghidra import scripts under `ghidrascripts/` for **all** detected versions. Requires clang (option 1 installs it). |
| **5** | Runs the generated import scripts against your executables in headless Ghidra. Creates or updates the Ghidra project with all types, symbols, and signatures. Steam DRM is stripped automatically via Steamless. |
| **6** | Opens Ghidra with the project loaded. |
| **7** | Runs options 4 + 5 back-to-back. Use this after updating submodules or replacing an executable. |
| **8** | Deletes the Ghidra project and state file so the next import starts from scratch. |
| **9** | Picks an existing Ghidra project (yours, not the BGS one) and runs the generic RTTI-walk vtable-naming pipeline against it. Works on any MSVC PE that Ghidra has finished auto-analyzing (x64 or x86), including binaries this repo has no CommonLib for -- Fallout New Vegas, modded engine builds, etc. Only renames functions whose name is still Ghidra's default `FUN_*` placeholder; never overwrites imported or user-set symbols. |

**First-time setup:** run **1**, then **2**, then **7** (or just **7** if you
already have clang installed). After that, **6** opens Ghidra with everything
imported. Option **9** is still available as an enrich-only pass against any
externally-prepared Ghidra project (handy when you already have a heavily-
annotated FNV / modded-engine project somewhere else).

### Non-interactive mode

For CI or scripting, pass a subcommand instead of using the menu:

```bash
python run.py setup   # option 1 + 2: install tools and update submodules
python run.py build   # option 7: generate scripts + headless import
python run.py all     # setup + build + open Ghidra
```

### How it works

All binaries end up in a single Ghidra project at
`ghidraprojects/BethesdaGhidraScripts/`, organized into `/<game>/<version>/`
folders.

The address library for each executable is selected automatically based on
the detected PE version. For Skyrim AE, all versions from 1.6.317 to 1.6.1179
are supported via the AddressLibraryDatabase.

### Requirements

- **Python 3.10+** (64-bit)
- **Git**

Clang, Ghidra, Steamless, and Python packages are all fetched automatically on
first run.

---

## Supported games

| Game           | Folder              | Address library    | CommonLib                                         |
|----------------|---------------------|--------------------|---------------------------------------------------|
| Skyrim SE      | `exes/skyrim/se`    | `1-5-97-0`         | `powerof3/CommonLibSSE`                           |
| Skyrim AE      | `exes/skyrim/ae`    | `1-6-1170-0`       | `powerof3/CommonLibSSE`                           |
| Skyrim VR      | `exes/skyrim/vr`    | `1-4-15-0` (csv)   | `powerof3/CommonLibSSE`                           |
| Fallout 4 OG   | `exes/f4/og`        | `1-10-163-0`       | `libxse/commonlibf4`                              |
| Fallout 4 NG   | `exes/f4/ng`        | `1-10-984-0`       | `libxse/commonlibf4`                              |
| Fallout 4 AE   | `exes/f4/ae`, `exes/f4/221` | `1-11-191-0` / `1-11-221-0` | `libxse/commonlibf4` (+ 1.11.221 PDB publics) |
| Fallout 4 VR   | `exes/f4/vr`        | `1-2-72-0` (csv)   | `libxse/commonlibf4`                              |
| Starfield      | `exes/starfield/sf` | `1-16-236-0` / `1-16-242-0` / `1-16-244-0` (V5, auto) | `Starfield-Reverse-Engineering/CommonLibSF`       |
| Fallout NV     | `exes/fnv/og`       | n/a — xNVSE hardcoded VAs | `xNVSE/NVSE` (x86) + optional `refs/fnv_names.csv` |

You don't need all of them. The script detects which executables are present
and only generates and runs what's needed.

Skyrim VR shares the SE-derived ID namespace with SE/AE, so the same
`CommonLibSSE` headers generate a VR-targeting script that resolves SE IDs
against the VR address library.  The VR address library ships as a CSV
(community-maintained) rather than meh321's binary format.

CommonLibF4's IDs sit in the NG/AE namespace (1.10.984 / 1.11.191), so those
two versions get full type + function symbol coverage from the address
library alone.  F4 OG (1.10.163) and F4 VR (1.2.72) use disjoint ID
namespaces that CommonLibF4 does not reference; the address library can't
transfer names directly because looking up an AE-namespace ID against the
OG or VR DB only finds coincidental low-ID matches at wrong addresses.

To get function names onto OG and VR anyway, the F4 pipeline runs a
cross-version byte-signature port (`scripts/commonlibf4/run_bytesig_port.py`)
after script generation.  Anchored at AE (or NG when AE is absent), it scans
each AE-named function's first 32 bytes for an exact, unique match in the
OG/VR binary; unmatched names get a 48-byte masked retry that wildcards
rel32 and rip-relative operands so cross-build jump targets stop confusing
the match.  Matched (name, target_rva) pairs are merged back into the
generated `CommonLibImport_F4_OG.py` / `_VR.py` scripts so they apply
function names alongside the types when the script runs.

The byte-sig port only runs when both AE (or NG) and the target binary are
present in `exes/f4/`; without them, OG/VR fall back to types-only coverage.

Starfield uses the `Starfield-Reverse-Engineering/CommonLibSF` headers and
meh321's **V5** address-library binary format (flat `uint32[id]` array
indexed by ID -- much simpler than the V1/V2 delta encoding SSE/F4 use).
Function-name coverage on Starfield is currently bounded by what
CommonLibSF's `IDs.h` / `IDs_RTTI.h` / `IDs_NiRTTI.h` / `IDs_VTABLE.h`
manifests cover plus the vtable-walk pass that names virtual function
implementations from RTTI labels -- ~2,933 named functions on a fresh
Starfield 1.16.236.0 import, versus 299 from auto-analysis alone.

The SF pipeline reads the FileVersion resource from `Starfield.exe`
(SteamStub scrambles `VS_FIXEDFILEINFO`, but the string table is
untouched) and loads the matching `versionlib-X-Y-Z-W.bin` from
`addresslibrary/starfield/`.  1.16.236, 1.16.242 and 1.16.244 ship pre-bundled;
to support a future SF patch, drop the new bin into that directory and
the loader picks it up automatically.  Mismatched builds fail loud
(listing what IS available) instead of silently mis-naming functions.
CommonLibSF's ID manifests are authored against 1.16.236, but meh321's
append-only ID convention keeps those resolutions stable across the
1.16.x line -- only ID-namespace-changing patches (1.15 → 1.16 was one)
break compatibility.

**Auto-generated shift maps for non-1.16.236 builds.**  After a successful
SF import, `run.py` invokes
`scripts/commonlibsf/sf_shift_check.py`, which:

1. Reads the detected PE version against the canonical 1.16.236 anchor.
2. Dumps the freshly-imported binary's per-class vtable layouts via a
   small pyghidra script (`scripts/commonlibsf/dump_vtable_layouts.py`,
   in-process — no MCP, ~30 seconds for a full SF binary).
3. Diffs the dump against the committed 1.16.236 reference layout at
   `scripts/commonlibsf/refs/sf_1-16-236-0_vtables.csv.gz` and writes
   `refs/shift_sf.json` when the target diverges.
4. Tells the user to re-run `python run.py build` so
   `parse_commonlib_types.py` picks up the shift map on the next pass
   and emits vtable structs whose slot names line up with the target
   binary's layout.

If you're on a build that doesn't have a pre-shipped shift map (e.g.
1.16.242 / 1.16.244 today), please share the dumped
`scripts/commonlibsf/refs/sf_<version>_vtables.csv.gz` in a GitHub
issue so the next release can ship a pre-built shift map for everyone
else on that version.

Fallout NV uses `xNVSE/NVSE` as its symbol/type source. FNV 1.4.0.525 is
frozen so the hardcoded virtual addresses baked into xNVSE headers
(`DEFINE_MEMBER_FN`, typed-constant addresses, casted fn-pointer
constants) are stable -- the scanner converts them to RVAs by subtracting
the standard 0x00400000 image base. Type extraction runs the same libclang
AST + record-layout pipeline as the other versions; xNVSE's game types
live at global scope (no `RE::` namespace) so they land under category
`/xNVSE/` rather than `/CommonLibSSE/RE/`. Names that xNVSE doesn't expose
can be added by dropping a CSV into `scripts/commonlibnvse/refs/fnv_names.csv`
(see `fnv_names.csv.example` for the format).

For any other MSVC-built game we don't have a CommonLib for, menu option 9
still runs the generic RTTI-driven vtable pipeline
(`scripts/core/run_vtable_pipeline.py`) against an existing Ghidra project.
It walks COL/TypeDescriptor pairs that Ghidra's own analyzer found, derives
vtable struct layouts, and renames the virtual function bodies they point
to -- conservatively, only if the function's name is still Ghidra's
`FUN_*`/`thunk_FUN_*` placeholder. Works on both x64 and x86 binaries.

---

## What gets imported

Each binary receives:

- All enums, structs, and classes from CommonLib headers with exact field
  offsets and sizes (parsed via clang `-ast-dump` and `-fdump-record-layouts`)
- Primary and secondary vtable structs for multi-inheritance hierarchies
- Virtual function names from vtable address walks
- Function signatures built from CommonLib type descriptors
- Address-library symbols (function labels, RTTI, vtable pointers)
- Fallback symbols from PDB (`SkyrimSE.pdb`) and IDA scripts where available
- `Source:` plate comments on named functions showing which symbol table
  provided the name

### Accuracy

Every emitted struct field and signature parameter uses the **exact** type from
the source. Anything that can't be pinned to an exact type is left as `void *`
rather than guessed. In practice ~99.75% of struct fields are fully typed.

| | F4 AE | Skyrim AE | Skyrim SE |
| --- | --- | --- | --- |
| Struct fields | 24,216 | 34,243 | 34,231 |
| Fully typed | 99.76% | 99.75% | 99.75% |
| Vtable structs | 1,292 | 2,023 | 2,024 |

---

## Enrichment drivers (beyond CommonLib import)

CommonLib import gets you exact types where CommonLib has coverage. On top of
that, the repo ships **binary-derived enrichment drivers** that recover names
and types straight from the analyzed binary — valuable where CommonLib is thin
(newer builds, Starfield, FNV) or absent. They run against any analyzed Ghidra
project via `scripts/discover_combined.py` (multi-program sequencer) or
`scripts/apply_enrichment_to_user_project.py` (one driver, one program), and
only touch `FUN_*`/undefined slots — never imported or user-set names.

| Driver | What it recovers |
|---|---|
| `string_anchored_rename` | Names `FUN_*` from self-identifying debug/log strings the function references |
| `ctor_mine` / `ctor_apply` | Mines constructors for field names + embedded-object types, applies them to the struct |
| `globals_harvest` / `globals_apply` | Types global singletons by the class whose methods consume them |
| `settings_harvest` | Names + types game-setting value fields (`fXxx`/`bXxx`/`iXxx`) |
| `console_harvest` / `console_harvest_sf` | Names console-command handlers (`Cmd_*`) — table-based, plus Starfield's code-based registration |

---

## Advanced usage

### Running pipeline scripts directly

The `run.py` menu is the recommended interface. If you need to run individual
pipeline steps (e.g. regenerating only one game, or importing a single target):

```bash
# Generate import scripts only (requires clang)
python scripts/commonlibsse/parse_commonlib_types.py   # Skyrim SE + AE
python scripts/commonlibf4/parse_commonlib_types.py    # Fallout 4 AE

# Run headless Ghidra import (requires generated scripts + Ghidra)
python scripts/run_headless.py                # all targets
python scripts/run_headless.py skyrim         # all skyrim versions
python scripts/run_headless.py skyrim ae      # specific target
python scripts/run_headless.py f4 ae
```

### Symbol priority

Symbols are applied in priority order. Higher-priority sources take precedence:

1. `RELOCATION_ID(SE, AE)` / `REL::ID` macros (CommonLib)
2. `Offsets_RTTI.h`, `Offsets_NiRTTI.h`, `Offsets_VTABLE.h` labels
3. `RE::Offset::` namespace IDs (Skyrim)
4. CommonLibSSE `src/*.cpp` cross-references (Skyrim only)
5. AE rename DB (`skyrimae.rename`) -- Skyrim AE only
6. PDB public symbols (`SkyrimSE.pdb`) -- Skyrim
7. IDA names (`IDAImportNames_1.11.191.0.py`) -- Fallout 4 AE

### Project layout

```
.
├── run.py                           Interactive launcher / menu
├── extern/                          CommonLib submodules (auto-updated)
├── addresslibrary/                  Address library .bin files
├── extras/                          Fallback symbol sources (PDB, IDA)
├── exes/                            Game executables (you provide these)
├── scripts/                         Pipeline source code
│   ├── run_headless.py              Headless Ghidra runner
│   ├── core/                        Shared: clang parser, script emitter
│   ├── commonlibsse/                Skyrim SE/AE pipeline
│   └── commonlibf4/                 Fallout 4 AE pipeline
├── ghidrascripts/                   Generated import scripts (output)
├── ghidraprojects/                  Ghidra project (output)
└── tools/                           Ghidra, Steamless, LLVM (auto-downloaded)
```

---
