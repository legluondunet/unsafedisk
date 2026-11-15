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

## Critical owner clarification: original CD cannot be fully copied

The owner confirms that several nominal original-CD files are multiple gigabytes and **cannot be copied**. Other Rayman 2 installation work already encountered ISO directory extents outside the actual roughly 662 MB disc volume. These entries are likely malformed/decoy entries related to the disc's copy protection, but their exact purpose is not independently established here. **Retract the full-CD-extraction prerequisite** from the initial local-R proposal. Never instruct the owner to copy them, turn them into placeholder/zero-filled files, or assume that a failed bulk copy demonstrates missing valid game content.

Protocol adjustment:

1. Preserve the original mounted disc/ISO and the already working CD-required control as the **CD-present reference**. A mount is not a local copy and does not validate no-CD functionality.
2. The installer's established extraction can still retrieve *valid and needed* small/normal files, following known setup file lists and rejecting out-of-volume extents. Never attempt to expand bogus multi-gigabyte entries.
3. The current **read-only local-R provenance helper** can inventory already available real assets, but cannot establish that the inaccessible oversized entries are mandatory or that a resource was opened by the game. Run it only if `R` actually exists and compare only file-backed known SNA/DAT files. Its results are descriptive and cannot justify further game patches on their own.
4. Before another no-CD launch or another SNA rewrite, capture a **bounded runtime file trace of actual requested resource paths, successful opens/read sizes, and errors** while the original is running with the disc. Then compare candidate behavior with those requests to identify the minimal genuine asset set and distinguish missing resources from another protection check. Do not patch mounted CD content.

The pirate head persisted after the installed SNA patch. This is a negative outcome of that precise experiment, not evidence that full-CD copying is required, and not proof that SafeDisc cryptography caused the visual symptom.

## 15 November follow-up: exact installed/R provenance and next bounded runtime discriminator

Owner-provided `rayman2-local-r-provenance.json` confirms a local `R` symlink to a **directory** named `CD`, not to a verified mounted original-disc volume. The two accessible file trees differ:

| Exact observed filesystem inventory | Installed `data/world/levels` | `R/Data/World/Levels` |
|---|---:|---:|
| Historical SNA basenames | 28 | 28 |
| Fully corrected historic SNA copies | **28** | **0** |
| SNA SHA-256 differences between trees | 28 of 28 | 28 of 28 |
| DAT directory entries | **1** (`levels0.dat`) | **24** (eight groups x banks 0/1/2) |
| Sum of declared DAT file lengths | **150,775,808 B** | **6,368,056,591 B** |

The last figure is **logical lengths only**. It is **not** verified allocated filesystem capacity, actual readable data, physical CD content or authenticated resources; the original disc's malformed/oversized ISO records are known to make a full copy impossible. Do not ask the owner to copy the alleged 6.37 GB, allocate fake replacements, or edit the local `CD` directory.

The previous SNA experiment changed only installed data, while the candidate may construct relative paths under `R`. Therefore its continuing pirate-head overlay **cannot establish that the modified SNA copy was read**. Even finding an R file name does not establish actual reads, because DAT fallback and runtime resource selection have different semantics.

### New bounded read-only Wine trace

`scripts/rayman2_local_r_filetrace.py` uses the previously tested `rayman2_v2_filetrace.py` streaming observer. It first **reverses the known local-R candidate's 25-byte scanner correction, 11-byte volume selector and five formatter bytes in memory**, then compares the full restored SHA-256 to the **exact original retail digest**. Unknown executable modifications are rejected. The source EXE is not modified on disk.

It then launches the approved local-R EXE under Wine, records only bounded file-API path samples and class counts, and writes a compact JSON. It caps observation to 10..180 seconds (90 default) and Wine output consumed to 64 MiB, and terminates only the child process group on timeout. The game installation, CD folder, Wine registry, SNA and DAT files remain unmodified. It **does not copy or hash the multi-GB DAT contents** and does not retain a raw Wine trace.

From the known game directory, where `Rayman2-local-R-test.exe` resides, download **both** plain-Python sources from the same PR branch (the second supplies the proven stream/timeout utility):

    curl -fL -o rayman2_v2_filetrace.py 'https://raw.githubusercontent.com/legluondunet/unsafedisk/feature/safedisc-135-rayman2-inspection/scripts/rayman2_v2_filetrace.py'
    curl -fL -o rayman2_local_r_filetrace.py 'https://raw.githubusercontent.com/legluondunet/unsafedisk/feature/safedisc-135-rayman2-inspection/scripts/rayman2_local_r_filetrace.py'
    python3 rayman2_local_r_filetrace.py --exe ./Rayman2-local-R-test.exe --seconds 90 --out ./rayman2-local-r-filetrace.json

The user may end playback after the pirate head and let the bounded observer stop/terminate the temporary session. The report distinguishes *attempted opens whose path text contains `R/Data` or `CD/Data`* from installed `Data/World/Levels` requests, and lists DAT/SNA path examples. This classification is **heuristic and text-derived**; multiple Wine API records can reflect one logical request, and ReadFile successes are **not matched to a particular path** without a handle-aware trace. Do not infer a SafeDisc verdict or a working no-CD game from these path records.

This is the **first diagnostic to ask the owner to run** after the no-effect SNA patch and provenance comparison; no new binary or asset modification is justified before its results. Keep the PR draft, and do not repeat the installed-only SNA patch.

## Gamescope support for bounded local-R file trace

The optional `--gamescope` mode of `scripts/rayman2_local_r_filetrace.py` launches the *same* Wine process via the native Gamescope binary while keeping the existing bounded trace collector and process-group timeout. The launch wrapper is `gamescope -f -W 1920 -H 1080 -w 2048 -h 1536 -- wine <verified-local-R-exe>` by default. Gamescope output is 1920×1080 fullscreen; the game virtual mode is 2048×1536 (matching GameFrame's observed 2x window for a 1024×768 Glide mode). This preserves the original 4:3 aspect ratio through letter/pillarboxing rather than stretching the picture to 16:9. The script checks that Gamescope is installed; it fails explicitly if requested but missing and has no implicit fallback that would unexpectedly launch without the requested compositor. Width/height can be changed using `--screen-width`, `--screen-height`; internal virtual mode via `--game-width`, `--game-height`.

The exact tracked source still requires both scripts in one directory, and the same CD-derived local-R executable. No original CD copy is attempted:

    python3 rayman2_local_r_filetrace.py --gamescope --exe ./Rayman2-local-R-test.exe --seconds 150 --out rayman2-local-r-filetrace-gamescope.json

Gamescope's display wrapper is independent of game-data provenance, SafeDisc checks, and the pirate-head trigger. It only makes this diagnostic test easier to view on the monitor. The output JSON records its requested output and virtual resolutions. The synthetic unit tests verify generated Gamescope arguments and reject invalid resolution input; actual Gamescope runtime and display mode must be verified on the owner's Manjaro computer.
