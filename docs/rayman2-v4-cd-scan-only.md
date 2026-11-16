# Rayman 2 — V4 CD-scanner-only discriminator (15 Nov 2026)

## Observation

The owner's known-good retail PE32 reference plays with the CD mapped as Wine `F:`. The no-CD V4, even with that CD mounted, triggers the giant Robo-Pirate anti-copy image in the first level. A V4 control candidate restoring **both** the 11-byte original CD scanner and five original path-format colons (16 changed bytes total) does **not** display the pirate image with the CD. This result is visually reported by the owner; the GameFrame log alone does not identify the executable or report game-level DRM state.

## Narrow next hypothesis

The script `scripts/rayman2_v4_cd_scan_only.py` takes the *exact previously working CD-routes control* (SHA-256 `48185e5e320c3532731c71b3ae2b2a231aab3af9e361aa531872bb7c23e9464d`) and changes only the **five ASCII `':' -> '\\'` characters** in the path-format strings at VA `0x49F396`, `0x49F3A6`, `0x4A06DA`, `0x4A2266`, `0x4A268A`. This restores V4's relative-path string formats but **retains the original CD scanner at `0x448E5A`** and retains every V2/V3/V4 DAT patch unchanged.

Output: `Rayman2-v4-cd-scan-only-test.exe`, 676,352 bytes, SHA-256 `14be1a73f6cb016d0ee3ba039b92bf7f339e078bab2980c3ea887968dfe2f133`. The input and output are SHA-locked; no input overwrites, no proprietary data in repo, no external CD changes. This is a **CD-mounted diagnostic**, NOT a no-CD fix.

## Run

From the installed game directory, with original CD mounted and accessible as `F:` in the same Wine prefix:

```bash
curl -fL --retry 3 \
  -o ./rayman2_v4_cd_scan_only.py \
  'https://raw.githubusercontent.com/legluondunet/unsafedisk/feature/safedisc-135-rayman2-inspection/scripts/rayman2_v4_cd_scan_only.py' && \
python3 ./rayman2_v4_cd_scan_only.py \
  ./Rayman2-v4-cd-routes-test.exe \
  ./Rayman2-v4-cd-scan-only-test.exe && \
WINEDEBUG=-all wine ./Rayman2-v4-cd-scan-only-test.exe \
  2>&1 | tee ./rayman2-v4-cd-scan-only-test.log
```

**Interpretation:** Pirate head *absent* = restoring the CD scanner alone is sufficient under these conditions, and the original V1 forced-`.` drive selector is implicated. Pirate head *present* or game can't enter level = the five original path formats also matter (possibly in interaction with the scanner), so study their call sites next. Neither outcome proves an executable is no-CD compatible or that all in-game anti-copy checks are disabled. Keep `Vignette.cnt`, `levels0.dat`, the original PE32 reference, and the quarantined decoy DATs unchanged.

## Verification

14 targeted Python tests passed on Linux, including replay of the full V1–V4 patch sequence on the owner's exact SHA-pinned retail executable and A/B control verification. Linux and Windows CI will also run the synthetic fixture tests (the owner-only test is skipped when files are absent). The previous Windows vignette-case-sensitive test fixture issue was fixed separately in the draft PR.