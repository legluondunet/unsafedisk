# Crimson Skies retail 1.00 → 1.02: owner-file validation (21 Nov 2026)

> Experimental research only. No native Windows or Wine game launch has been tested. Do not merge or claim gameplay validation on the basis of this document.

## Reproduced offline, using only authenticated owner files

| Source | Native command | Verified result |
| --- | --- | --- |
| German retail CD 1.0.0.1 | PR #4 `unwrap-retail100` | 2,560,000 bytes; SHA-256 `11242994ee568065a30fcfcfa1c9c23f86d60ea56f937bb00648bf9558fa1e70` |
| US/Europe retail CD 1.0.0.1 | PR #4 `unwrap-retail100` | Byte-identical to German result (2,560,000 / 2,560,000) |
| French original CD 1.0.2.0 | PR #2 `unwrap` | 2,580,480 bytes; SHA-256 `43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75` |
| Official Microsoft 1.02 update, original LZX CAB pair | PR #2 `unwrap` | Byte-identical to independent decrypted 1.02 reference (2,580,480 / 2,580,480) |

The 2,315,728-byte official updater was SHA-256 authenticated (`8e1c04f3e32c318a58ef3e2bbd8f13b9894ff055d4492f80ee14ce53851616af`); libarchive recovered five expected CAB members from its embedded archive without executing the installer. The extracted protected loader and ICD matched known size and complete SHA-256. Three deliberately mismatched loader/ICD pairings were rejected without output.

All temporary proprietary extractions and reconstructed test files were deleted after use. No executable, decrypted code, delta, original Microsoft update or private file is committed.

## Key findings from direct PE32 comparison

- Decrypted retail 1.00 and 1.02 have identical six named sections but different geometry: 1.00 `.text` has 2,084,864 raw bytes and entry RVA `0x1F2F1C`; 1.02 `.text` has 2,105,344 raw bytes and entry RVA `0x1F7056`.
- Both import from 21 DLLs. In 1.02, USER32 has 62 imported functions versus 60 in 1.00, including `TranslateMessage` and `DispatchMessageA`; import-table ordering can change across versions.
- Matching relocation-masked `.text` segments with sampled exact anchors allowed examination of 1,921 IAT-site pairings: 1,892 named-API agreements; 29 differences primarily in jump relays, including MFC42 ordinal thunks. **This is heuristic evidence, not proof of semantic identity or a demonstrated corruption.**
- A local Zstandard `--patch-from` experiment on the decrypted 1.00→1.02 pair created a 338,112-byte compressed delta; decoding recreated the exact 1.02 hash. The delta was immediately deleted and **must not be distributed**: it may embed copyrighted game code.

## Implications for CrimsonSkiesFix

1. FR: reconstruct 1.02 directly from original CD using the native PR #2 engine; no separate updater needed.
2. US/DE *with a locally obtained, authentic 1.02 updater*: existing CrimsonSkiesFix PR #56 can read the protected patch pair in memory, then native PR #2 can unwrap it. This is an offline process; it does not download, execute or redistribute the updater, but still **requires its local presence**.
3. US/DE *with only original retail 1.00 discs*: the PR #4 native engine reconstructs 1.00, but that is **not the hashed 1.02 executable** currently required by CrimsonSkiesFix. A true code-level 1.00→1.02 migration algorithm has not been proven. A patch containing 1.02 code must not be smuggled into the open-source installer.
4. Keep PR #2 and PR #4 as drafts. Next priorities: integration and licensing review of native CD-FR rebuild; optional verified-local-updater path for US/DE; isolated Windows/Wine gameplay testing; separate research of genuine game-version changes.

**Scope:** Static reconstruction, hash validation, import inspection and private local cross-version analysis only. No Windows gameplay validation, and no claim that 1.02 can be generated from a US/DE CD alone.
