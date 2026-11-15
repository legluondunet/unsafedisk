# Rayman 2 — V4 still triggers Robo-Pirate; test the original Vignette.cnt on disc

15 November 2026. The user has confirmed that the V4 DAT probe launches without CD and can reach the first level, but the giant Robo-Pirate head remains visible. The V4 output log contains GameFrame rendering at about 60 FPS for 12,300+ frames, and no recorded unhandled exception. This is **not** proof of a functioning no-CD game: hidden anti-piracy gameplay restrictions may remain.

## Independent retail-media evidence

A contemporary Rayman community report about the **original retail installer** identifies exactly two files sometimes omitted from the hard-disk installation: `Data/Vignette.cnt` and `Data/World/Levels/LEVELS0.DAT`:

https://raymanpc.com/forum/threads/cancelled-rayman-2-installer-for-newer-systems.24570/page-2

The user's current clean installation already has `./data/world/levels/levels0.dat` (150,775,808 bytes), but its **local Vignette.cnt presence and checksum are not yet known**. The same community has documented triggering the head through changed content checksums, including vignette files:

https://raymanpc.com/forum/threads/rayman-2-pc-widescreen-patch-16-9-16-10-21-9-32-9-pc-32-bit-depth-fix-widescreen-for-dc-psx-ps2.21665/

The 24 enormous DAT names on original CDs contain dummy files and should not be repeatedly copied. The user's earlier failed copies were isolated into `./rayman2-dat-quarantine/`; leave them alone.

## Targeted one-file validation, not a blind patch

New Python module: `scripts/rayman2_vignette_probe.py`, with 11 passing synthetic tests in `scripts/test_rayman2_vignette_probe.py`. It checks one original `Data/Vignette.cnt` on the user's mounted CD, compares size and SHA-256 with an existing local `./data/vignette.cnt` (case-insensitive match), and **never overwrites an existing local file**. With an explicit `--copy-if-missing` flag, it copies only an absent file into the existing lowercase `./data/` directory, validates the resulting SHA-256 byte-for-byte against the disc, and publishes it atomically using a temporary file + exclusive hard link. Existing inconsistent upper-/lowercase data dirs and symlinks cause refusal, not silent overwrite.

From the installed game's folder **with original CD mounted under** `/run/media/romain/RAYMAN2`:

```sh
python3 scripts/rayman2_vignette_probe.py --disc /run/media/romain/RAYMAN2 --game . --copy-if-missing --out ./rayman2-vignette-check.json
```

If the report shows `action=copied_and_verified`, unmount the CD and re-test the **unmodified V4** to see if the head still triggers. If the report shows `installed.status=identical` with `action=unchanged`, the missing-Vignette hypothesis is excluded for that exact file. If `installed.status=different`, do not overwrite or delete it automatically; investigate provenance, game edition and other data differences first.

The script intentionally does not assert it has verified the CD's volume label or mounted state; it checks actual accessible file bytes. This is an independent **asset completeness test**, not SafeDisc decryption or proof the other anti-piracy conditions are disabled. Keep PR #3 draft, do not merge this diagnostic as a production fix until the runtime test confirms the actual cause.
