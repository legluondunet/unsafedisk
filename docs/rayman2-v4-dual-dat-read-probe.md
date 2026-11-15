# Rayman 2 — V4 experiment: bypass two 512-byte DAT probes (not pirate-head sprite)

Date: 2026-11-15. Status: EXPERIMENTAL, untested under Wine; no release or merge.

## Empirical reasons

- User's original 676,352-byte CD binary (SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`) starts and supports a short gameplay session with the PE32/WoW64 scanner correction and original CD mounted as `F:`. Its tested 25-byte PE32-only executable SHA-256 is `f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703`.
- V1 removes only the logical volume-label gate and rewrites five path strings, but reaches the original DAT-loading error.
- V2 substitutes the original 24-entry DAT filename selection at `0x44F13A` with fixed `LEVELS0.DAT`; it crashes in the resource reader at EIP `0x45DCC5` following out-of-range record-count values.
- V3 keeps the V2 selector and neutralizes the 2-byte `SUB [ESI],ECX` at `0x44F133`; this removes the earlier immediate crash. The user reports reaching the first level **without CD**, followed by a large Robo-Pirate head covering the picture, the well-known separate *Rayman 2* in-game anti-copy protection. That overlay may also coincide with missing level entities, not just a replaceable texture.
- Subsequent user attempt to copy all 24 `.DAT` directory entries from the retail CD into a new uppercase `Data/World/Levels/` tree caused nine `EIO` errors and created up to 6 GiB of questionable copies. The owner then quarantined all 24, preserving a separate lowercase `data/world/levels/levels0.dat` (150,775,808 bytes). Do not repeat the bulk copy.

## Byte-level V4 hypothesis

The original CD and separately modified 1,468,928-byte GOG comparator (`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`) were independently inspected at the *active file-backed* `.text` code addresses (not GOG `.extra` archival data). GOG itself is not a pristine retail decrypted binary.

After V3, **two deliberate GOG differences remain together in the DAT-specific subroutine**:

| RVA/VA | V3 (same as retail CD) | V4 candidate (matches GOG at these exact bytes) |
| --- | --- | --- |
| `VA 0x0044F102`, 40 bytes | Call original `SetFilePointer` at `0x44F10D`, then read 512 bytes at `0x44F125` from the first DAT, with adjacent argument setup | 40 one-byte `NOP`s (`90`) |
| `VA 0x0044F1CC`, 2 bytes | `8B 0E` / `MOV ECX,[ESI]`, before second seek/read | `EB 23` / `JMP SHORT 0x44F1F1`, jumping over the second seek/read to the *existing unchanged epilogue* |

**42 actual changed bytes in exactly two source sites**, both checked against GOG's active `.text`. Critically, the second dead code area is **not overwritten** (no `INT3` transplant), because the short unconditional branch prevents fall-through; minimum intervention.

V4 leaves intact the previous V1 relative path/PE32 fix, V2 fixed DAT filename, V3 no-op subtraction, the two original 16/4-byte header reads, actual `CreateFileA` opens and errors/retry, ordinary resource reader, game renderer, and the original in-game Robo-Pirate DRM logic. No asset files are altered. It does NOT simply hide the pirate-head image or force any in-game protection flag.

## Strict identity and SHA-256 gate

- **Input**: original V3 only, 676352 bytes, SHA-256 `6df04e1c18d9318c9f8566a14018abc6f0e8dd84f7649eb4c411e81fabeb61f7`.
- **Output**: 676352 bytes, SHA-256 **`ef656c7a80272726508ec20aace94ddbaed655c8e25151c87e3d520abebcbbf0`**.
- Output is a *new* file only. Unknown binaries, altered byte anchors, symlink source or destination, unexpected PE layout, and existing destination all cause refusal. `--dry-run` verifies a V4 candidate without writing.
- Code uses an exact input *whole-file* SHA, exact output SHA, and five anchored code spans.

## User test to run later

The original CD should be **unmounted**, and the directory should be the intact lowercase existing installation **after quarantine**. Do not recreate, merge, rename or copy the 24 suspect dummy DAT entries, and do not run from another directory.

```
python3 ./rayman2_dat_read_probe_v4.py \
  ./Rayman2-portable-v3-offset-test.exe ./Rayman2-portable-v4-dat-read-test.exe \
&& WINEDEBUG=-all wine ./Rayman2-portable-v4-dat-read-test.exe \
  2>&1 | tee ./rayman2-v4-dat-read-test.log
```

Test: main menu, start a **new game**, then load the first level. Record whether the giant pirate head appears, whether Rayman can move and important level objects appear, and any dialog/crash. **A short successful game session does not prove all levels or SafeDisc decryption.** If the giant pirate head persists, stop and investigate independent game-data DRM and check resource integrity; do not simply remove the head graphic.

## Tests and limitations

19 tests pass locally, including the **exact original retail CD -> V1 -> V2 -> V3 -> V4 reconstruction** with expected SHA-256, a separate exact-GOG-active-code comparison of both modified regions, synthetic PE fixtures, altered-anchors negative cases, no-overwrite, symlink refusal and dry-run. GNU `objdump -D -Mintel` on an ephemeral private V4 confirms `JMP 0x44F1F1`, correct fall-through of the 40 NOPs, and preserved error-check/epilogue. No Wine is available in the analyst container, so actual V4 runtime behavior is **unverified**.

The V4 change is a **specific hypothesis** about original extra DAT file reads, not an assertion that they are SafeDisc checks or the entire cause of the overlay. The GOG version has additional changes and does not guarantee successful restoration simply by copying these two transforms. Keep experimental PR #3 in draft; preserve owner files and do not distribute proprietary executables or resource content.
