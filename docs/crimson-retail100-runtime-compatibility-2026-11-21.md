# Crimson Skies retail US/DE 1.00 — offline runtime-compatibility feasibility (2026-11-21)

> **Research only.** None of the RVA candidates below is authorization to patch or execute an unverified 1.00 game. The current CrimsonSkiesFix release/runtime remains locked to the exact 1.02 SHA-256. No commercial EXE, Microsoft update, game code, binary delta or key material is included here.

## Independent input identities

The owner-supplied original retail US/Europe and German CD loaders + ICDs independently reconstruct **the same 2,560,000-byte candidate PE32**, with SHA-256 `11242994ee568065a30fcfcfa1c9c23f86d60ea56f937bb00648bf9558fa1e70`, via [unsafedisk PR #4](https://github.com/legluondunet/unsafedisk/pull/4). The French original CD and the authentic Microsoft 1.02 updater separately reconstruct the 2,580,480-byte 1.02 reference, SHA-256 `43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75`.

The 1.00 and 1.02 files differ in executable code and layouts, **not only SafeDisc protection**: 1.02 `.text` is 20,480 bytes larger and imports `TranslateMessage` and `DispatchMessageA` in USER32 that 1.00 does not. An experiment generating a compressed binary delta from independently owned files was deleted and is not publishable as a substitute for an authorized version update.

## Read-only proof-of-feasibility mapping of selected 1.02 code sites

An offline comparison inspected 24 symbolic RVA sites from the **checked-in 1.02 runtime source**, using both locally reconstructed owner's binaries. For every code site, it searched for *unique* 20-byte anchors in the relocated-`HIGHLOW`-masked `.text` bytes at up to 80 bytes from the 1.02 site. It then computed a candidate 1.00 site by subtracting the anchor's relative offset. Up to 41 anchor positions were considered per site (4-byte spacing).

- **18 sites had at least one candidate mapping**. Most had multiple consistent unique anchors. Example candidates include `menu_scene` loader `0x406D30 -> 0x4069F0` (17 anchors); `menu_gos_event` observer `0x4075D6 -> 0x407296` (15); `menu_resolution_label` formatter `0x4054B0 -> 0x405170` (38); `startup_selector` getter `0x4404F0 -> 0x43FD30` (16).
- **3 addresses are game-state/data globals**, not in the executable `.text` section and cannot be assessed by this method.
- **3 code sites were unmapped**, including `lighting_default` registration at `0x4021C4` and two `native_widescreen_full` sites near RVA `0x20254A`/ `0x20254F`.
- A candidate `menu_mode_event` callback site at `0x407811 -> 0x4074D1` had only 4 supporting anchors and 1 alternative alignment: this one needs extra disassembly validation.

**This is *not* a runtime patch map**: unique nearby instruction data do not guarantee ABI equivalence, preserved control flow, hook safety, correct data/global addresses, or functional equivalence. A version-specific patch may need different original-byte checks, structure offsets and semantics, even if its surrounding code matches. Do not automatically transplant 1.02 patches at these addresses.

## Technical roadmap without unauthorized Microsoft bytes

1. [unsafedisk PR #6](https://github.com/legluondunet/unsafedisk/pull/6) exposes the *strictly SHA-validated* 1.00 US/DE reconstruction as an **in-process Rust API** so CrimsonSkiesFix can eventually package a single EXE, with no auxiliary tool. The same code produces the same candidate from either CD; this API is a preparation component, not runtime support.
2. First validate an **unmodified 1.00 game installation** with a locally reconstructed candidate under Wine/Windows, without attempting 1.02-specific in-memory hooks. Record menus, first mission, input, videos and clean exit, and verify the original CD files and game resource layout.
3. If native 1.00 support is pursued, add a **separate exact-SHA runtime profile** to CrimsonSkiesFix with a clear incompatibility/default-disabled gate. Validate each hook's true 1.00 preimage/ABI before enabling it. Do **not** merely relax the 1.02 SHA gate. Avoid modifying existing FR verified behavior.
4. Port only version-independent DirectDraw/window handling initially, then version-specific widescreen/FOV, HUD, menu, cursor and GOS pieces after individual functional checks. Preserve save files and rollback semantics.
5. A runtime capable of handling 1.00 would **not by itself turn the game into official 1.02**. The original requirement for an offline **1.02** install from only US/DE CD remains unmet unless the actual updated game code can be legally provided or independently reimplemented. Any update-byte distribution requires rights review.

**Security/compatibility invariant:** never install or launch a 1.00 candidate through the *existing 1.02-only runtime* until a distinct audited 1.00 branch has been compiled and functionally validated; retain both strict SHA gates and reject unknown files. No silent fallback to SafeDisc loaders, alternative cracks or externally acquired proprietary executables.

## Supporting artifacts and limits

The owner-only static report `crimson_US_DE_hook_mapping_2026-11-21.json` contains the full 24-site mapping and counts; this documentation intentionally includes only non-proprietary address/algorithm metadata. No complete CD image or Windows gameplay capture was available inside the research runtime. The **successful FR Wine 11.19 installation is a separate validated profile** and cannot establish US/DE functionality.
