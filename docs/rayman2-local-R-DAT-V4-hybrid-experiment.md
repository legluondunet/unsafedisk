# Rayman 2: local-R + DAT V4 controlled hybrid experiment

Status: experimental feature branch, no release, no proven no-CD gameplay.

## Evidence

The owner's original local-R test enters the first level, then displays the Robo-Pirate head and "CD MISSING! INSERT THE CD AND RESTART THE GAME". The previous time-limited runs did not crash; the diagnostics ended them. Gamescope was functional.

Installed Vignette.cnt and LEVELS0.DAT have byte-for-byte matching SHA-256 against the available CD copies. The ISO primary directory has 18 out of the original 24 DAT names; every pair of those 18 declared DAT intervals overlaps (153 of 153), and eight nominal lengths end beyond the physical ISO. All eight extracted R copies of those impossible-length DAT entries are shorter and have sizes that are exact multiples of 3 MiB. Six original table names (TEXTURES0..2, GRAPHICS0..2) are absent from the primary ISO directory but exist in R. These metadata findings do not prove DAT payload identity or what check triggers the overlay.

Previously researched SHA-locked CD-versus-GOG code differences include a first-DAT filename selector, an offset subtraction instruction, and two retail-only 512-byte DAT reads. A CD-present V4 control was known to load the first level using the mounted original CD with a separate F path alias; no corresponding no-CD success was established.

## Hybrid producer

scripts/rayman2_local_r_dat_v4_probe.py consumes the *existing* Rayman2-local-R-test.exe, not an original or recompiled commercial game binary. It creates a NEW Rayman2-local-R-DAT-V4-test.exe.

Before patching, it verifies all previous Rust local-R modifications (the 25-byte module scanner fix, 11-byte local R selector, five relative drive formatters), reverses those edits in memory, and compares the entire recovered binary to the exact 676,352-byte retail CD SHA-256 7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3. Unknown executable variants are rejected.

It then changes ONLY these verified machine-code sites within the existing local-R candidate:

| Virtual address | Bytes | Change |
| --- | --- | --- |
| 0x0044F102 | 40 | NOP first original 512-byte DAT seek/read |
| 0x0044F133 | 2 | NOP indexed-word subtraction |
| 0x0044F13A | 7 | Replace indexed DAT filename selector with LEVELS0.DAT |
| 0x0044F1CC | 2 | Short JMP over second original 512-byte DAT seek/read |

The input local-R route, all five relative formatters, original level resource paths and retail PE layout are preserved. The script modifies no game assets, DAT/SNA files, CD image, Wine registry or original input executable. It refuses destination overwrites, supports --dry-run, and records hashes of source/output and changed-site count.

scripts/rayman2_local_r_filetrace.py also now accepts this exact hybrid after reversing the four DAT sites and proving original SHA lineage; it continues to accept the prior original-DAT local-R version. Its default remains Gamescope output 1920x1080, virtual 2048x1536 at 4:3, no automatic timer. The user may exit normally or interrupt from the terminal to save a bounded JSON trace.

## Proposed owner-side test

Only after CI and synthetic tests pass, from the installation with the previous local-R original available and the existing R link, run the producer with --dry-run. If all checks pass, run again without --dry-run to create a NEW output executable.

Then test the new output with the updated no-time-limit Gamescope trace launcher and no mounted CD; the R directory continues to provide the already available resources. Observe the first-level transition and whether pirate head appears. Do not change SNA/DAT data at the same time, to preserve a controlled comparison.

The four DAT code changes are applied as one grouped hypothesis. A successful result would not isolate an individual causal instruction, nor prove later-level gameplay. A failed result would not disprove other anti-piracy paths. The feature does NOT unwrap SafeDisc 1.35 and is not a production fix.
