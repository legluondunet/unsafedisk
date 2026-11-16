# Rayman 2 — V4 retail-CD route A/B control (15 November 2026)

## Why a CD-based differential is now the best experiment

The owner reproduced the giant Robo-Pirate anti-copy image with **V4 both with and without the original retail CD**. `rayman2-v4-with-cd-test.log` contains GameFrame graphics output and no visible crash, but it does **not** instrument CD volume or DAT file opens. The known PE32-scanner-only retail reference, by contrast, is playable with the same real CD mounted and mapped as Wine `F:`. The installed `data/vignette.cnt` has been checked byte-identical to a CD source (21,758,404 bytes); `data/world/levels/levels0.dat` is present (150,775,808 bytes). These facts rule out simple missing-CD and missing-vignette assumptions, **not** all anti-tamper or corrupted-resource possibilities.

**Two competing hypotheses**:
1. The earlier V1 modifications at original VA `0x448E5A` and five `.data` format strings change the observed CD drive selector and relative paths. Some in-game CD check may use the altered state even when the disc exists.
2. Changes introduced in V2–V4 to DAT index selection, offset arithmetic, and two 512-byte reads cause an original in-game integrity check to fail (or another unexamined difference does).

## Controlled candidate

Standalone script `scripts/rayman2_v4_cd_route_control.py` accepts only the SHA-pinned **V4** (676,352 bytes, SHA-256 `ef656c7a80272726508ec20aace94ddbaed655c8e25151c87e3d520abebcbbf0`). It produces `Rayman2-v4-cd-routes-test.exe`, SHA-256 `48185e5e320c3532731c71b3ae2b2a231aab3af9e361aa531872bb7c23e9464d`.

Changes **exactly 16 bytes relative to V4**: restore original 11-byte CD volume scanning function body at VA `0x448E5A`, and restore ':' at the five format string VAs `0x49F396`, `0x49F3A6`, `0x4A06DA`, `0x4A2266`, `0x4A268A`. **Retain exactly** V2 fixed DAT name selector (`0x44F13A`), V3 arithmetic NOP (`0x44F133`), V4 512-byte read changes (`0x44F102`, `0x44F1CC`), and the working 25-byte PE32 module scanner correction (`0x447C20`). Preserve original files, do not modify the game installation or Wine config.

The output is a **CD-required control**, not an improved portable/no-CD EXE. It can be built from V4, and was also independently reconstructed from the owner's exact CD-origin executable by replaying the V1–V4 SHA-locked generators in order and restoring only V1 routing. 15 synthetic/integration local tests passed, with the owner-file integration optional in public CI.

## Protocol

With original physical CD mounted and accessible as `F:` in Wine, from the *game directory* containing the exact V4 EXE:

```bash
curl -fL --retry 3 -o ./rayman2_v4_cd_route_control.py \
  'https://raw.githubusercontent.com/legluondunet/unsafedisk/feature/safedisc-135-rayman2-inspection/scripts/rayman2_v4_cd_route_control.py' && \
python3 ./rayman2_v4_cd_route_control.py \
  ./Rayman2-portable-v4-dat-read-test.exe ./Rayman2-v4-cd-routes-test.exe && \
WINEDEBUG=-all wine ./Rayman2-v4-cd-routes-test.exe \
  2>&1 | tee ./rayman2-v4-cd-routes-test.log
```

Try to enter the first level and **report whether the giant pirate head appears**. Do not infer success solely from no crash or GameFrame FPS.

If head **disappears**, V1 volume/path modifications are implicated (not proof of which one, and not yet a no-CD solution). If head **persists**, V1 routing changes are insufficient to explain the symptom, and DAT modifications / independent integrity conditions remain candidates. Either outcome calls for further comparison, not random patch accumulation. The source tool verifies the V4 input and candidate SHA and refuses overwriting existing output or symlink destinations.