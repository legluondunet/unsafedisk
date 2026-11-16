# Rayman 2 V4 — isolate the original CD DAT path colon (15 Nov 2026)

## Newly observed owner runtime outcome

The owner launched the **SHA-locked V4 CD-scan-only control** (original retail CD volume scanner, five V1 relative path format modifications, plus V2–V4 DAT changes), with the original CD mounted and the temporary `./F -> /run/media/romain/RAYMAN2` symlink created by `scripts/rayman2_v4_relative_F_alias_probe.sh`. **The first level loaded without the Robo-Pirate overlay.** The prior attempt of the same EXE without `./F` displayed the game's `Rayman 2 CD not found` dialog and did not load the game.

This is **positive, controlled evidence for a wrong relative resource path**, not evidence that the program can be run without the CD or that any copy protection was decrypted. The original retail CD remains essential to the currently working scanner variant. The alias script removes its own symlink on exit, and is never a production fix.

The Wine relay evidence from the alias-free run specifically showed:

- Original volume scanner `GetDriveTypeA("F:\\")` returns 5 (`DRIVE_CDROM`).
- `GetVolumeInformationA("F:\\")` returns 1 (`TRUE`).
- Subsequent resource-open failure produces the *same text* from `MessageBoxA` return VA `0x44E0E1`, **not** from the volume scanner's earlier `0x449339` dialog.
- In the exact source CD binary's disassembly, the resource path call near `0x44DEB7` references formatter `0x4A2264`, and the later `CreateFileA` failure branch heads to the `0x44E0DB` dialog. V1 changed the formatter's third byte from ASCII `:` to `\`, causing a drive-letter `F` to produce `F\...` rather than `F:\...` for this call.

## New 1-byte A/B discriminator

`rayman2_v4_cd_dat_path_probe.py` accepts only the exact owner's `Rayman2-v4-cd-scan-only-test.exe`:

- Input length 676,352, SHA256 `14be1a73f6cb016d0ee3ba039b92bf7f339e078bab2980c3ea887968dfe2f133`.
- Restores **only one** ASCII colon at VA `0x4A2266` in `.data`, changing the format at VA `0x4A2264` back to `%c:\\%s\\%s` (Python `b'%c:\\%s\\%s\0'`).
- Output is `Rayman2-v4-cd-dat-path-test.exe`, SHA256 `f09ebfc18d065eac771d4212a2c7f76bedee5a9c2e0217a8f530bfa4fb3f6d8f`.
- Original CD scanner **unchanged**, remaining four V1 relative path formats **unchanged**, V2–V4 DAT modifications **unchanged**. No bundled proprietary game EXE. SHA-pinned, validated PE32 mapping/expected original bytes, no existing file overwrite.
- The output **requires a mounted CD**. It must be tested **without any `./F` symlink**.
- 16 Python tests passed on local Linux, including the user-provided 676,352-byte CD-derived V4 scan-only binary; the public CI test runs with a synthetic fixture and skips the private user-input integration test.

### Test protocol

From the game directory with the original `RAYMAN2` disc mounted and visible on Wine `F:`, **no local `./F` alias**:

```sh
curl -fL --retry 3 -o ./rayman2_v4_cd_dat_path_probe.py \
  'https://raw.githubusercontent.com/legluondunet/unsafedisk/feature/safedisc-135-rayman2-inspection/scripts/rayman2_v4_cd_dat_path_probe.py' && \
python3 ./rayman2_v4_cd_dat_path_probe.py \
  ./Rayman2-v4-cd-scan-only-test.exe \
  ./Rayman2-v4-cd-dat-path-test.exe && \
WINEDEBUG=-all wine ./Rayman2-v4-cd-dat-path-test.exe \
  2>&1 | tee ./rayman2-v4-cd-dat-path-test.log
```

The script refuses if destination already exists; use a different output name if rerunning. Verify `test ! -e ./F && test ! -L ./F` first; do not delete a preexisting alias unless you own it. The owner should report the visual outcome: game enters first level? Pirate head? CD-not-found? GameFrame stdout is not sufficient to prove these.

**Interpretation:** If level loads without alias and no Robo-Pirate image, this one formatter is sufficient to correct the presently observed CD-required resource-load failure in the first level, not proof that remaining four formats are safe globally. If dialog persists, at least one additional formatter or separate filesystem dependency matters. Next steps should inspect actual `CreateFileA` paths, not change more bytes randomly. No merges/releases from this experiment.