# Rayman 2 — CD-playable PE32 reference versus portable V2 and offset-subtraction V3

**15 November 2026 — controlled two-byte experimental patch, no commercial bytes distributed.**

## Empirical progress

The owner successfully started and played `Rayman2-PE32-test.exe` derived from the original retail CD PE32, with mounted volume `RAYMAN2` recognized by Wine at drive F:. The 45-second file-I/O observation (`rayman2-pe32-reference-playable.json`, exact PE32 SHA-256 `f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703`) reported `time_limit`, `wine_launcher_exit_code=-15`, **no reported 0x45DCC5 crash**, and 408 asset-path lines. This is a time-bounded success, not proof the whole game works.

The reference's captured asset-path excerpts explicitly include attempts to open **F:\\Data\\World\\Levels\\LEVELS0.DAT, MAP0.DAT, MENU0.DAT, TEXTURES1.DAT, ANIMS1.DAT, SOUNDS0.DAT, LEVELS1.DAT, LEVELS2.DAT, GRAPHICS0.DAT and MUSIC2.DAT**, plus ordinary local `.gpt` and `.rt*` assets. A path in an excerpt is evidence of an *attempt*, not proof a separate DAT supplies actual contents. The complete I/O trace was not retained; the excerpts are not exhaustive.

The V2 failed without the disc at EIP `0x45DCC5`, EDI=0, after successfully opening the installed single `Data/World/Levels/LEVELS0.DAT` (150,775,808 bytes). Its active code at `0x44F13A` selects `[0x4A2090]`, always `LEVELS0.DAT`, rather than the original `[0x4A2090+EBX*4]`. In the latest Wine crash, `0x9F9A412B * 8 mod 2^32 == 0xFCD20958`, so the giant inferred resource-record count is a direct consumer of a preceding 4-byte resource read. Data bytes and source offsets have **not** been captured; the exact root cause remains unproven.

The local game installation contains only `LEVELS0.DAT` among the 24 indexed names. The CD ISO has historically shown oversized/suspicious other DAT directory entries. Do not fabricate files or assume all 23 missing names contain valid data, and do not confuse the ordinary resource fallback with physical SafeDisc authentication.

## Controlled hypothesis V3

Read-only PE disassembly of the *original* and the separately modified *GOG* comparator confirms the original `0x44F133` instruction `29 0E` (**`SUB DWORD PTR [ESI],ECX`**) becomes `90 90` (two NOPs) in GOG. The same nearby code shows GOG also skips two unrelated 512-byte reads, which **V3 intentionally retains**.

This subtraction follows index math and a first 512-byte probe, and changes the caller-supplied resource byte offset used by a second file handle. Because V2 has replaced the original index-selected DAT with `LEVELS0.DAT`, preserving that offset subtraction could direct the reader to a wrong place in the local DAT. This is a **plausible hypothesis**, not a demonstrated cause. V3 tests just this difference; it does not patch the original 512-byte reads, CD volume behavior, file path formatting, arithmetic remainder, or other engine code.

| Field | Exact value |
|---|---|
| Input V2 SHA-256 | `35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d` |
| Output V3 SHA-256 | `6df04e1c18d9318c9f8566a14018abc6f0e8dd84f7649eb4c411e81fabeb61f7` |
| Input/output size | 676,352 bytes |
| Site | `.text` VA `0x0044F133`, file offset `0x0004E533` |
| Original bytes | `29 0E` |
| Candidate bytes | `90 90` |
| Changed bytes from V2 | exactly **2** |
| GOG differences not copied | both extra 512-byte read skips and other independent modifications |

The script enforces whole-file and structural PE32 signatures, full input hash, opcode anchors before and after the two-byte site, exact output hash, no overwrite and symlink rejection. No executable is committed or distributed.

## Reproduce locally (owner's V2 EXE only)

```sh
python3 scripts/rayman2_dat_offset_probe_v3.py \
  ./Rayman2-portable-v2-test.exe ./Rayman2-portable-v3-offset-test.exe
```

Test without the CD mounted, in the same installed game directory and Wine prefix as the failed V2. Observe whether the previous `0x45DCC5` crash remains and whether the startup/game menu appears; do not infer decryption or general no-CD compatibility from a single image. The user should **retain the known working CD-mounted PE32 version unchanged**.

## Validation scope

The script was run against a V2 reconstructed from the exact owner-provided original CD EXE using the previously published V1/V2 tools. The V2 SHA exactly matched the observed Wine binary, and the V3 SHA matched the independently calculated digest. **13/13 local Python tests passed**, including synthetic PE fixtures, wrong-hash failures, bad anchors, refusing changes outside the two-byte site, and private original integration. No V3 Wine execution or validation of a complete gameplay session has occurred. PR remains experimental/draft; not ready for merge or release.
