# Rayman 2 — historical Rayman Control Panel DRM and disc patches

Status: **public-source audit (2026-11-15)**. No owner game files changed, no decoder built, no gameplay test. Supplement to [SafeDisc versus in-game anti-tamper](rayman2-anti-tamper-evidence.md).

## Two separate, historically documented utilities

### RemoveDRM: in-game pirate-head DRM, not SafeDisc unpacking

Primary source: [2022-10-09 removal commit](https://github.com/RayCarrot/RaymanControlPanel/commit/d3123ce39a6058d958e7c23e6a56fcc4729bbb4f), deleting `src/RayCarrot.RCP.Metro/Utilities/Games/Rayman 2/RemoveDRM/Utility_Rayman2_RemoveDRM_ViewModel.cs` and `src/RayCarrot.RCP.Metro/Files/Rayman2/R2_Sna_Drm_Offsets.json`.

The old utility walked `Data/World/Levels/**/*.sna`, matched file basenames to a historical JSON offset manifest, backed up files on initial application, called `R2SNADataEncoder.DecodeBuffer`, replaced *four decoded bytes* at each selected position with `00 01 00 00`, then called `EncodeBuffer` and saved the result. Revert restored the file backups.

The removed table contains **28 SNA file basenames and 48 total offsets**, including `Bast_10.sna`, `Learn_10.sna`, and `Whale_00.sna`. These are offsets within the **decoded** data, not on-disk byte positions. This source does not validate any specific regional revision, original CD sample, or current GOG file. Never apply unverified offsets automatically.

Version trap: the [2020-02-05 update](https://github.com/RayCarrot/RaymanControlPanel/commit/4bf45b62f9ab) changed the entire offset table; `Bast_10.sna`, for example, moved from `1228515, 1233843` to `11665, 12369`. The reason for the shift requires independent verification before attempting to translate offsets between implementations. The 2022-deleted manifest uses the later values.

The 2022 removal commit notes that this functionality had become a patch. This does **not** indicate that Rayman Control Panel ever decrypted the retail executable.

### DiscPatch: replace the retail executable with GOG

Primary sources: [2019-10-29 addition](https://github.com/RayCarrot/RaymanControlPanel/commit/e13747c1578f), [2022-01-07 removal](https://github.com/RayCarrot/RaymanControlPanel/commit/a0f90f20b21b). Removed class: `Utility_Rayman2_DiscPatch_ViewModel.cs`.

The code detected `RAYMAN2.ICD`, then wrote a bundled GOG `Rayman2.exe`, bundled GOG `GXSetup.exe` and default `ubi.ini`; it also deleted the ICD and several legacy numbered DAT entries. This was a *GOG binary substitution*, not original retail SafeDisc reconstruction. Do not reuse the destructive replacement recipe or redistribute commercial EXEs in unsafedisk.

## Boundaries and next checks for unsafedisk

Keep three mechanisms distinct: (1) original SafeDisc loader/media authentication, (2) Rayman 2's internal pirate-head anti-tamper, (3) installed data/CD path and archive availability. Historical RemoveDRM informs (2), while DiscPatch only documents a GOG workaround for (1)/(3). **Neither produces the original unwrapped 676,352-byte Rayman2.exe, its authentic runtime plaintext, or a SafeDisc key.**

Useful optional **read-only** next step for the in-game layer: decode SHA-identified original `.sna` samples, compare four-byte contexts at the historic 48 offsets, report match/mismatch by edition. No automatic patching. For the actual executable, continue the separate SHA-pinned original-vs-GOG dataflow and runtime-state investigation.

Branch policy: draft PR #3 experimental only. Leave `main`, the Crimson Skies decoder, and Rayman2Fix unchanged.
