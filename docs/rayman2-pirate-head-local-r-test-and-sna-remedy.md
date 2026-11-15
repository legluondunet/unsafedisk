# Rayman 2: local-R pirate-head report and historical SNA repair

15 November 2026. Experimental; PR #3 remains unmerged. No proprietary game binary/assets are shipped.

## Real test

The owner reports the giant pirate-head overlay when launching the new local-R prototype without a physical CD. The attached rayman2-local-R-test.log has 137 lines of GameFrame/OpenGL startup and frames up to 10,500 around 60 FPS. It has no file I/O or in-game protection trace. Therefore local-CD routing alone is insufficient. Do not infer that a particular SafeDisc loader check failed, or that all DAT/SNA content was opened correctly.

Earlier CD-required controls were playable without the pirate head only with the original CD available through a valid path. Different executable changes and media conditions prevent singling out one cause.

## Historical tool recovery

The original Rayman Control Panel RemoveDRM utility, removed from upstream in this verified 2022 commit, fixed an in-game pirate-head anti-tamper feature, NOT SafeDisc unwrapping:

https://github.com/RayCarrot/RaymanControlPanel/commit/d3123ce39a6058d958e7c23e6a56fcc4729bbb4f

It selected 28 known Data/World/Levels SNA basenames and 48 offsets measured in decoded SNA buffers. Every selected four-byte window was replaced by hexadecimal 00 01 00 00. Before writing it made backups, decoded each SNA with R2SNADataEncoder, edited, and re-encoded. The original decoder, MIT licensed, remains here:

https://github.com/BinarySerializer/BinarySerializer.OpenSpace/blob/main/src/Encoders/R2SNADataEncoder.cs

The decoder uses an XOR keystream keyed by state 0x6AB5CC79 and updated with a salted Park-Miller recurrence. Since decode and encode use the same XOR, the new independent Python utility computes keystream bytes only for those 48 known offset windows, leaving all other source data, including the first four original file bytes, unchanged.

Contemporary public explanation of this tool and its checksum motivation:
https://www.raymanpc.com/forum/threads/rayman-2.1032/page-468

## New experimental utility

Source: scripts/rayman2_sna_pirate_head.py
Synthetic tests: scripts/test_rayman2_sna_pirate_head.py

The script is read-only by default. It searches real Data/World/Levels directories for SNA files with the historical names. It refuses symlink files and invalid offsets. Only an explicit apply action writes. Before changing ANY file, it creates a NEW backup directory outside the SNA level tree and verifies a byte-exact hashed copy of every candidate, recording both original and candidate SHA-256 in a manifest. It refuses existing backup directories. Atomic replacement limits partial file writes. The restore action verifies backups and current candidate hashes, refusing game files modified by another process. Backups remain after restore.

Start with a scan against the **actual installed** real level directory (not the local R symlink):

    python3 scripts/rayman2_sna_pirate_head.py --levels "/path/to/Rayman2Fix/Data/World/Levels" --action scan

If the scan finds no historical SNA files, do not apply. Identify the actual assets first. Some installations use archives.

Apply only on the user's disposable installed game folder (not on mounted CD files):

    python3 scripts/rayman2_sna_pirate_head.py --levels "/path/to/Rayman2Fix/Data/World/Levels" --action apply --backup-dir "/path/to/NEW-rayman2-sna-original-backups"

Then run the same local-R game executable briefly and report the visual pirate-head outcome. Do not infer success from missing log errors or graphics alone.

Restore from the intact backup folder:

    python3 scripts/rayman2_sna_pirate_head.py --levels "/path/to/Rayman2Fix/Data/World/Levels" --action restore --backup-dir "/path/to/NEW-rayman2-sna-original-backups"

## Boundaries

This targeted SNA edit is NOT a SafeDisc decryptor, an original PE unwrapping, a physical media authentication bypass or a fix for missing original DAT resources. The user has not yet run it on proprietary actual SNA data. A positive visual result would establish only that the historic in-game SNA anti-tamper repair helps the local-R run. A negative result means another code, media, installation, or data integrity condition remains.

Keep this experimental and reversible until the owner tests on real data and CI tests pass.

## Follow-up after historical SNA patch (owner test #2)

The owner performed the suggested historical SNA patch test and still reported the **giant pirate head** when running local-R. The attached `rayman2-local-R-test(1).log` has **176 lines**: it reaches `glide: 14600 frames` near 60 FPS, with no visible asset-path or anti-tamper diagnostics. It provides no direct evidence of what SNA/DAT files the process actually opened, or even whether the new historical SNA values were ever read.

**Important experimental confounder we should have checked first:** the SNA patch was applied under the installed `./data/world/levels` tree, while the local-R executable intentionally prefixes some original resource paths by **`./R`**. In the documented workflow `R` is a symlink to **a separate extraction of the original CD**. Thus a file loaded from `R/Data/World/Levels` could be an unchanged copy even when all 28 installed SNA files have been patched. Some resources are opened from DAT archives instead of standalone SNA files. The visual no-change outcome cannot yet disprove the SNA mitigation; nor prove that it works.

A new read-only helper `scripts/rayman2_local_r_asset_provenance.py` compares actual installed-vs-`R` tree path resolution, SHA-256 of the 28 historic SNA files, their decoded four-byte patch status, and inventories DATs without reading their large content. It does **not** launch the game, does not traverse symlink subtrees other than the explicitly named `R` root, and cannot certify files read at runtime:

    python3 scripts/rayman2_local_r_asset_provenance.py --game-dir . --r-root ./R \
      --installed-levels ./data/world/levels > rayman2-local-r-provenance.json

Inspect the report *before* any further SNA edits. If installed and R trees differ, the previous experiment changed the wrong physical copy for that potential resource path. Even if equal, use a bounded Wine file trace next to determine which DAT/SNA source is actually read. **Do not patch the original CD, mounted ISO, or the R symlink target.** Do not merge PR #3 or claim a SafeDisc bypass based on this test.
