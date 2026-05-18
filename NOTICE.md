# Third-Party Notices

This repository (and any release bundle built from it) aggregates several
third-party components, each under its own license. The aggregate work is
distributed under **GPL v3** (see `LICENSE`) because that is the strongest
copyleft license among the components that are redistributed in source form.

If you want a permissive-licensed core, the original pipeline code under
`run.py`, `scripts/`, and `tools/` (excluding any inlined snippets from
GPL-licensed sources) is also available under the **MIT License** terms at
the top of this file. The MIT grant applies only to the original
BethesdaGhidraScripts code in this repository — it does not extend to
bundled submodules, which retain their own licenses below.

---

## Original code — MIT License

Copyright (c) 2024-2026 BethesdaGhidraScripts contributors
(1001Bits, doodlum, and contributors)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

---

## Bundled third-party components

### CommonLibSSE (`extern/CommonLibSSE/`)

- Upstream: <https://github.com/powerof3/CommonLibSSE>
- License: **MIT**
- Copyright (c) 2018 Ryan-rsm-McKenzie
- See `extern/CommonLibSSE/LICENSE` for the full text.

Used by `scripts/commonlibsse/parse_commonlib_types.py` to extract type
definitions and address-library symbols for Skyrim SE/AE/VR import scripts.

### CommonLibF4 (`extern/CommonLibF4/`)

- Upstream: <https://github.com/libxse/commonlibf4>
- License: **MIT**
- Copyright (c) 2019 Ryan-rsm-McKenzie
- See `extern/CommonLibF4/LICENSE` for the full text.

Used by `scripts/commonlibf4/parse_commonlib_types.py` to extract type
definitions and address-library symbols for Fallout 4 OG/NG/AE/VR import
scripts. Fallout New Vegas (x86) reuses portions of this pipeline.

### CommonLibSF (`extern/CommonLibSF/`)

- Upstream: <https://github.com/Starfield-Reverse-Engineering/CommonLibSF>
- License: **GPL v3 with Modding Exception + GPL-3.0 Linking Exception**
- See `extern/CommonLibSF/COPYING` (GPL v3) and
  `extern/CommonLibSF/EXCEPTIONS` (Modding + Linking exceptions).

This is the most restrictive license among the bundled components. Because
this repository redistributes CommonLibSF in source form, the aggregate
release bundle is licensed under **GPL v3** (see top-level `LICENSE`). The
Modding Exception covers runtime linking between a mod and the library —
it does not waive the source-distribution requirements of GPL v3.

If you fork or redistribute this bundle, you must:

1. Preserve `LICENSE`, `extern/CommonLibSF/COPYING`, and
   `extern/CommonLibSF/EXCEPTIONS`.
2. Make Corresponding Source available for the combined work (the bundle
   itself is the source, so the requirement is satisfied by redistributing
   the bundle unmodified or with patches included).
3. Preserve all attribution and license notices in modified files.

### AddressLibraryDatabase (`extern/AddressLibraryDatabase/`)

- Upstream: <https://github.com/meh321/AddressLibraryDatabase>
- License: **No explicit license file in the upstream repository.**

The upstream `meh321/AddressLibraryDatabase` repository contains only
auxiliary data (CSVs / shift maps) used by Address Library tooling. We
include it as a submodule for parity with the upstream CommonLib*
pipelines. The pre-built address-library `.bin` / `.csv` files we ship
under `addresslibrary/` are sourced from meh321's public Nexus releases
(Address Library for SKSE / F4SE / SFSE Plugins) which are publicly
distributed under the project's own terms.

If you are the maintainer of `meh321/AddressLibraryDatabase` and would
like a specific license declaration applied to this bundle's use of your
data, please open an issue on
<https://github.com/1001Bits/BethesdaGhidraScripts>.

### Address Library binary files (`addresslibrary/*.bin`, `addresslibrary/*.csv`)

- Source: meh321's public Nexus mod pages (Address Library for SKSE /
  F4SE / SFSE Plugins).
- These files are factual offset tables — Bethesda binary RVAs keyed by
  numeric IDs — and are widely redistributed across SKSE/F4SE/SFSE plugin
  source repositories under each plugin's own license.

### Clang / libclang stub headers (`scripts/core/_clang_stubs/`)

- Minimal `<intrin.h>` / `<mmintrin.h>` etc. shims required to make
  CommonLib* headers parse under libclang. Original code, MIT-licensed
  (see "Original code" above).

---

## What we do NOT redistribute

- Bethesda game binaries (`*.exe`, `*.dll` from the Skyrim / Fallout /
  Starfield install). Users supply these from their own legitimately
  purchased copy.
- Microsoft PDB files. Where these appear in the development repository
  they are excluded from release bundles by `tools/build_release_bundle.ps1`.
- Reverse-engineered name corpora that were derived directly from game
  binaries (e.g. `*.relib`, raw `*.pdb` dumps). These are excluded from
  release bundles.

---

## Tooling that the pipeline downloads at runtime

`run.py`'s "Install prerequisites" step downloads:

- **Ghidra** (Apache 2.0) — <https://github.com/NationalSecurityAgency/ghidra>
- **LLVM/Clang** (Apache 2.0 with LLVM Exception) — <https://github.com/llvm/llvm-project>
- **Steamless** (MIT) — <https://github.com/atom0s/Steamless>
- **JDK 21** (GPL v2 with Classpath Exception, when using OpenJDK
  distributions) — installed by the user manually if not present.

These are fetched into local working directories (`tools/`,
`C:\Development\LLVM\`, etc.) and are not redistributed in the source
bundle. Each carries its own license at the download location.
