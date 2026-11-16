# Rayman 2 CD — minimal relative-path diagnostic on the authentic retail executable

**15 November 2026 · Experimental, opt-in, exact-SHA-locked. Not a validated SafeDisc 1.35 removal.**

## Why this experiment is justified by *actual* runtime observations

The user tested the exact original CD executable (with the known 25-byte PE32/WoW64 scanner fix) under Wine. The scanner no longer froze, and after the game received a usable `Ubi.ini` in the legacy Windows `UbiSoft` location, the game started with the CD available. Repeating the test without the mounted CD produced the authentic **"Rayman 2 CD not found"** Retry/Cancel dialog. The dialog corresponds byte-for-byte to the previously inspected volume search at `0x448E30`, including its `GetLogicalDrives`, `GetDriveTypeA == DRIVE_CDROM (5)`, `GetVolumeInformationA` and seven-byte label match `RAYMAN2`.

The above is direct evidence that **a logical drive selection** blocks launch without a CD. It is **not** evidence that there are no later DRM checks.

## Input identity

- Owner's *original* CD `Rayman2.exe`: 676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- Existing **25-byte PE32-module-scanner-only diagnostic**: same size, SHA-256 `f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703`.
- Modified GOG comparator **is not a clean original unwrapped executable**: 1,468,928 bytes, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.

The script accepts **only** the first two exact input hashes, never GOG. Output is a **new file only**; no overwrite, no proprietary bytes committed.

## Previously missed finding: **five** colon-containing drive-format strings

An exhaustive file-backed `.data` search for the exact literal `%c:\` found **five**, not just the two documented in the prior DAT audit. All five are independently present in the original GOG comparator with only the colon byte replaced by a second backslash:

| Original format VA | Original | Proposed same-size relative-path format | Purpose in original code |
| --- | --- | --- | --- |
| `0x49F394` | `%c:\%s/%s/%s.%s` | `%c\\%s/%s/%s.%s` | Path into named subdirectories and extension |
| `0x49F3A4` | `%c:\%s/*` | `%c\\%s/*` | File enumeration pattern |
| `0x4A06D8` | `%c:\%s` | `%c\\%s` | Shared drive-prefixed open path, used at many call sites |
| `0x4A2264` | `%c:\%s\%s` | `%c\\%s\%s` | Two-part DAT/resource path |
| `0x4A2688` | `%c:\` | `%c\\` | Root prefix for ancillary resource path |

A literal `.` used as the `%c` argument now yields **` .\...` (without the space)** rather than `D:\...`, keeping all the old varargs and the same length. The actual Win32 file-operation results remain untested; relative paths are resolved from the **working directory**, so any future test must launch the game from the installed game directory.

**Important distinction:** GOG changes its DAT opening logic at `0x44F13A`, replaces an indexed filename from the original 24-entry table with the fixed pointer `LEVELS0.DAT`, and skips two original 512-byte reads and other internal arithmetic adjustments. **This prototype does NOT transplant those changes.** The original dataflow is deliberately preserved so that any next failure can be classified separately from the simple CD-volume check.

## Exact changes in the proposed diagnostic output

| Original VA | Changed code/data | Number of overwritten bytes | What is preserved |
| --- | --- | ---: | --- |
| `0x447C20..0x447C38` | Previously validated PE32-only guard for WoW64 module scanning | 25 | Original PE process scanning except PE32+ rejection |
| `0x448E5A..0x448E64` | With the original guard/prologue unchanged, set drive-selector global `0x4A6AD8` to `'.'` and return using the original x86 stack epilogue | 11 | Entire remaining original CD-search body and all normal callers on disk |
| `0x49F396` | One colon to slash | 1 | String size and argument count |
| `0x49F3A6` | Ditto | 1 | Ditto |
| `0x4A06DA` | Ditto | 1 | Ditto |
| `0x4A2266` | Ditto | 1 | Ditto |
| `0x4A268A` | Ditto | 1 | Ditto |

- Input **original CD** → experimental output: **38 different bytes** in **7 finite regions**. Some replaced opcode bytes happen to be unchanged; the total *overwritten span lengths* are 25+11+5=41.
- Input **already PE32-patched** → same experimental output: **16 different bytes**.
- Both modes produce a **676,352-byte PE32**, SHA-256 **`6702ff583cb0ee1f1023cc4b334ef4dab3f737a0ee7f272fe31dd13a9f23ce71`**.
- Independent `objdump` disassembly confirms the two conditional branches in the PE32 fix still land at `0x447C77` and the new CD-volume path restores `ESP=EBP`, pops EBP and returns. The new 11-byte body and all five updated path strings **match the exact bytes at those VAs in active GOG**, but no other GOG instruction or asset is included.
- **Original DAT readers, original 24-entry indexed selection, resources/generic engine, old protected media checks elsewhere, and the binary's PE sections and imports are untouched.**

## Python reproduction (private files only)

```sh
python3 scripts/rayman2_portable_cd_probe.py \
    ./Rayman2.exe ./Rayman2-portable-probe.exe --dry-run

# Only after inspecting the dry-run summary; creates a NEW file, refuses overwrite
python3 scripts/rayman2_portable_cd_probe.py \
    ./Rayman2.exe ./Rayman2-portable-probe.exe

python3 -m unittest discover -s scripts -p 'test_rayman2_portable_cd_probe.py'
```

For a future Wine launch, the target executable must be started from the **installation directory** with all required extracted data files present and with the same known-working Wine prefix/GLI configuration. The current script does **not** redirect the legacy `Ubi.ini` lookup to the local file: this is an independent, still-outstanding portability concern. It also does **not** control GameFrame output resolution; the 1024×768 internal mode is normal without the Rayman2Fix launcher.

## Test limits and remaining discriminants

This session's static tests and private binary SHA integration are **not** a game-launch or no-CD-playability test. No Wine executable, CD, GameFrame driver or physical SafeDisc media ran in this analysis environment.

**Likely next fork:**

- If no-CD game reaches an asset-loading failure, first identify the actual path, required file and whether it lies under the installed `DATA` directory; **do not immediately suppress the original DAT pipeline**.
- If the original DAT selection references an invalid index or fails a file read, obtain a read-only call trace or same-edition source resource evidence before considering selected additional transformations.
- If execution hits an actual SafeDisc driver/media-authentication failure, diagnose it independently from the logical volume check. No original SafeDisc key recovery, `.ICD` reconstruction or copy-protection decryption is demonstrated by this patch.

**Status:** a small, verifiable **no-logical-CD prototype generator**, not a validated playable **no-SafeDisc** version. Keep the PR draft; don't merge or issue a release until tested and reviewed.
