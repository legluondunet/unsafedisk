# Rayman 2 — local-CD resource routing prototype

Status: **experimental code, built and synthetically tested on Linux + Windows on 15 November 2026. The user's real game and CD content have NOT been tested with this candidate.** PR #3 remains a draft. No game binaries are bundled.

## Question and independent precedent

The owner's original retail CD executable is a readable x86 PE with game code on disk. The already verified PE32-only fix allows it to run under Wine with the original physical CD; without the CD the retail build displays the original CD-not-found dialog. A separate V4 experiment with a local F folder alias to the original mounted CD reached the first playable level **without the giant Robo-Pirate image**. Other V2–V4 changes to indexed DAT routing caused serious parser failures. See docs/rayman2-portable-relative-cd-probe.md and docs/rayman2-v4-cd-dat-path-experiment.md.

**New A/B test:** can the *original DAT reader*, untouched, read its originally expected CD assets from an ordinary local directory, after bypassing only the initial CD drive-type/volume-label selection? This experiment does NOT imply a decrypted SafeDisc loader, replacement game code or working full no-CD release.

## Native binary

Source: src/bin/rayman2-local-disc-probe.rs, compiled by .github/workflows/unsafedisc-linux.yml.

The tool requires exactly one of two SHA-pinned user-provided 676352-byte sources:

- Original CD Rayman2.exe SHA-256: 7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3.
- The same CD file with only our known PE32 module-scanner correction, SHA-256: f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703.

The tool refuses GOG and unknown editions, checks original PE section layout, original bytes and the five existing drive-format strings. It writes a **new output file only**, refusing overwrites and symbolic link output targets.

Two modes share two code changes:

- The already verified original-only PE32 module-scanner guard at VA 00447C20 (25-byte replacement). This protects Wine WoW64 startup from treating PE32+ DLL exports as PE32 exports.
- A single 11-byte replacement at original VA 00448E5A, *after the unchanged original guard and prologue*, sets the original global CD drive selector to R at 004A6AD8, and returns using the original stack-frame epilogue. It does not replace DAT loader code, V2–V4 resource mutations, or any other code.

Mode **relative-folder** also changes exactly five colon bytes in original .data format strings from the form percent-c, colon, backslash to percent-c, backslash, backslash. With the R selector this produces **R\...** relative to the current working directory. Give the game an R directory or symlink containing files **extracted from the owner's original disc**. No Wine registry or virtual drive mapping is needed.

Mode **wine-drive** preserves every original .data format byte. With the R selector this produces **R:\...**, requiring an existing Windows/Wine R: mapping to a suitable local directory. The tool does not modify drive mappings. This can isolate relative-path rewriting from the selector change.

## Recommended first test under Linux

Download the Linux artifact, unzip its native executable, and put it in the game directory. **Important correction: do NOT attempt to copy or fully extract the original CD.** The owner's Rayman 2 CD exposes oversized/malformed entries (several gigabytes, with extents that may exceed the real image volume), which cannot reliably be copied and may be deliberate protection/decoy entries. Such entries must not be treated as missing mandatory game assets, synthesized as sparse/zero-filled files, or used as evidence that the portable prototype has passed copy protection. The earlier requirement of a 'complete extracted CD root' was invalid and is withdrawn.

For a **CD-present control only**, use the already known playable original retail-CD configuration with the genuine mounted image/disc and its native source paths, without copying the whole filesystem. This is not evidence of no-CD functionality. For a **no-CD candidate**, supply only the verified real extracted assets that the game is observed to request; determine those paths from a bounded Wine file trace. The fixed local-R prefix can be a source of failure, and partial extraction cannot by itself establish whether pirate-head activation is a DRM response or a missing/incorrect resource. If a path lands on an oversized/unreadable ISO entry, record the read failure and investigate it rather than retrying enormous copies.

From the directory from which the game is normally launched:

    chmod +x rayman2-local-disc-probe
    ./rayman2-local-disc-probe --source '/path/to/original/Rayman2.exe' \
      --output ./Rayman2-local-R-test.exe --mode relative-folder

Optional local-R test **only after tracing which genuine assets are needed** (do not link to a supposedly complete copy of the CD; no full-copy requirement):

    test ! -e ./R && test ! -L ./R && \
      ln -s -- '/path/to/selected-real-assets-root' ./R

Then launch from this directory, without using the physical CD:

    WINEDEBUG=-all wine ./Rayman2-local-R-test.exe \
      2>&1 | tee ./rayman2-local-R-test.log

Check for playable first-level visuals, not merely successful process creation. Report the CD-not-found message versus the giant pirate-head overlay versus game-load success. Avoid rewatching all cinematics; a short first-level test is sufficient at this stage.

For the Windows artifact the command-line option names are identical. On Windows, the wine-drive mode can be used with an independently created R: mapping. Do not alter an existing R: mapping.

## Limits and controls

This is a candidate generator, not a packaged proprietary Rayman2.exe. Only a user-supplied original game input can produce that binary. No game files are provided or modified in the repository. The resulting executable is **not authenticated by a known expected output SHA** until executed on the exact original. The tool prints both hashes, and all modified bytes must remain within allowlisted PE code/data ranges.

Success with a tested, independently verified no-CD asset set would be evidence that one logical CD-selection hurdle and file paths can be satisfied without a physical CD, not evidence of recovery of SafeDisc encryption or all later in-game anti-tamper. Failure may come from missing/incomplete original DAT resources, a remaining in-game protection, or another runtime dependency. The historical Rayman Control Panel anti-piracy SNA patch is a separate mechanism.

Do not merge or tag a release without a real owner runtime test and code review.
