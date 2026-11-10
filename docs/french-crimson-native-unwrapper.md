# Native Crimson Skies SafeDisc unwrap — standalone release candidate (2026-11-01)

**Current status (supersedes the original French-only experiment documented below):**
Both SHA-256-identified protected Crimson Skies 1.0.2.0 editions, original
and French, are reconstructed using **one Rust command**, with no Windows 98
capture, proprietary DLL execution, Wine, or external modifier file.

```sh
./unsafedisc-linux unwrap --loader CRIMSON.EXE --icd CRIMSON.ICD \
  --output CRIMSON-UNWRAPPED.EXE
```

The 57 F1/F2 EAX arithmetic operations have been independently represented
as native Rust operations with derived constants, **not proprietary DLL byte
strings**. Exact historical Win98 modifier snapshot input remains optional:
`--modifier-snapshot CS98-DLL-00.BIN` validates operation-by-operation
equivalence and must match the original trusted snapshot SHA-256.

**Validated on Linux using GitHub Actions-built Rust executables and both
original protected editions:**
- Original ICD `0e3b4724…146e9833b`, launcher `675a3c76…a8afa736`,
  checksum `0x1B09633B`.
- French ICD `f3fe7c1e…e7262eb`, launcher `cf9ec313…4712ae`,
  checksum `0x5C03ECF6`.
- In both cases, the new output exactly matches the **2,580,480-byte**
  Windows 98 reference, SHA-256
  `43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75`
  (verified using bytewise `cmp`).
- The same exact output is achieved **without providing a reference file**.
  Including `--reference testme.exe` adds an explicit bytewise check.
- Existing output paths and corrupted protected ICD inputs are rejected;
  a rejected input never creates a game executable.
- GitHub Actions compilation and synthetic Rust tests succeeded on Linux
  and Windows. **Gameplay stability is not yet tested.**

The older research notes below document why a verified Win98 capture was
initially required. That requirement is **no longer applicable** to
`unwrap`; the exact original v1.0.2.0 SHA guards and version-specific
import permutations still apply. This tool is not a generic SafeDisc
unwrapper.

---

# Native French Crimson Skies unSafeDisc unwrap — validated 2026-10-31

This document describes **one exact title/edition** under user-owned
research. No game binaries, proprietary DLL content, or memory snapshots
are included in the repository.

## Achievement

A Linux-built Rust `unsafedisc-linux` produced a new 2,580,480-byte
PE32 EXE from the user's 2,580,578-byte *protected French*
`CRIMSON.ICD`, 344,925-byte `CRIMSON.EXE`, and 167,936-byte
historical mapped Windows 98 DLL snapshot. Running `cmp` against
the user's separately produced unSafeDisc 1.5.5 `TESTME.EXE`
confirmed **zero differing bytes**.

| Item | SHA-256 |
|---|---|
| French protected ICD | `f3fe7c1ee6f62be1c9fa216ad90b57cc3653d2673095704bf439d1592e7262eb` |
| French protected launcher | `cf9ec31364e1893c21636f53bc9410d0e1aa49ee6c32a555cf3adab9df4712ae` |
| User-supplied Win98 modifier snapshot | `5931af1ba40b0f28b0bb3e9fabc663127bbd9a8c1de8ea1e9c87b56154c84519` |
| Historical TESTME.EXE and newly generated Rust output | `43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75` |

## Running the Rust port

```sh
./unsafedisc-linux unwrap-french \
  --loader crimson.exe \
  --icd crimson.icd \
  --modifier-snapshot CS98-DLL-00.BIN \
  --output NEW-CRIMSON.EXE \
  --reference testme.exe
```

`--reference` is optional and is **never read to construct output**.
Instead, the complete output hash is verified against the separately
established unSafeDisc Windows 98 fingerprint. The user selects a
**new nonexistent output path**; existing outputs are refused.

The test on Linux completed with:

```text
Independent Windows 98 reference: byte-for-byte identical.
Exact French inputs authenticated; code checksum 0x5C03ECF6
TEA F1/F2 reconstruction: .text 440422 words, .data 42018 words
Imports: 136 API names, 136 ILT/IAT entries and 245 callsites restored
Full reconstructed PE: 2580480 bytes
SHA-256: 43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75 VERIFIED
CREATED: NEW-CRIMSON.EXE
```

An attempted repeat using the **same output path** was rejected before
input processing: `REFUSING: output path already exists`. The new file
was verified again using the system `sha256sum` and `cmp`.

## Cryptographic reconstruction and independently established stages

- The French `.text` checksum is `0x5C03ECF6`, calculated using the
  historical relocation-excluded, page-bounded weighted checksum. Two
  independent Rust walkers agree on the complete result. There are
  558 relocation blocks and 71,114 HIGHLOW DWORD relocations.
- The first TEA word `0x6A966E30` was inferred from all 134 nonzero
  encrypted import pointers. The historical unSafeDisc 1.5.5 key
  staging combines this word, the checksum, the French loader's four
  `CRPE` raw words and the original ICD entry RVA to reconstruct:
  `6A966E30 F7C77870 D110DFA0 9CF5E390`.
- **Independent TEA-only oracle:** 28,947/28,947 eligible fragment
  tails, representing 58,076/58,076 bytes, match when TEA's overlap
  is reversed. The incorrectly assumed inherited-TEA-key candidate
  fails dramatically (35/28,947 exact tails).
- The SHA-verified Win98 capture contains two EAX arithmetic routines,
  F1 (24 operations) and F2 (33 operations). Applying these to the
  indexed encrypted DWORD fragments before the validated TEA inverse
  reproduces **1,855,489/1,855,489** non-HIGHLOW `.text` bytes and
  **168,072/168,072** `.data` bytes exactly.
- `.idata` reconstruction restores 136 API-name records, ILT and IAT
  tables, and 21 descriptor timestamps; its 16,384-byte SHA-256 is
  `c8674927a6a2f6c53330b9692dca084084cb5cfef9acc3ecaab1bb8a0cbd7534`.
  The **order** of the 136 imports uses reference-guided,
  edition-specific permutations; a generic SafeDisc reorder algorithm
  is **not** claimed to be recovered.
- The 245 import callsite DWORDs (183 KERNEL32 and 62 USER32) are
  restored using an arithmetic offset rotation, the independently
  inferred French import XOR, and an exact edition-specific callsite
  list. These restore all 61,743 HIGHLOW slots in `.text`.
- The final PE header/padding format reproduces the original
  unSafeDisc 1.5.5 output, including its historical ASCII tag,
  timestamp, legacy module name capitalization and two raw-section
  trailers. These cosmetic legacy conventions are **not** described
  as a generic recovered SafeDisc algorithm. In particular the
  `0x054313` trailer is an **observed canonical output constant**
  for this game version, not the 344,925-byte French wrapper size.

## Safety and limitations

1. SHA-256 gates are checked for **each** input. A different language,
   loader build, snapshot or edited ICD is refused.
2. The output file is **not opened or created until every reconstruction
   stage completes and the full expected output SHA-256 matches**.
   Files are created only with `create_new`; no file overwrite or
   symlink-following output clobbering is allowed.
3. The Win98 snapshot is still an external input to this build. **No
   Windows 98 installation, Wine process, SafeDisc DLL execution or
   legacy driver is required at execution time.** Removing even the
   snapshot data dependency is future interoperability work.
4. The test verifies the EXE bytes, **not actual gameplay, mission
   progression, stability, or Wine compatibility**. The user may test
   those independently with their existing game installation and
   CrimsonSkiesFix.
5. The tool is a strict version-specific preservation prototype, **not
   a generic SafeDisc remover**. No complete general algorithm for
   arbitrary games/variants is asserted.

All implementation remains on the dedicated `unsafedisk` research
branch/PR until owner validation. Do not merge `main` without explicit
user approval.

## German-labelled Crimson Skies 1.02 archive — verified 2026-11-01

The user's `crimson_skies_de.7z` archive (2,095,879 bytes, SHA-256
`4d8f5c5bdd92c767290d6c51d096398f348798b17ac1f9a6ad3685d0b6092a52`)
contained exactly three SafeDisc files:

| File | Size | SHA-256 |
|---|---:|---|
| `CRIMSON.EXE` | 344,851 | `675a3c768c3676a525240d365f6d225b2886f51cf81fd24c271ce1c0a8afa736` |
| `CRIMSON.ICD` | 2,580,578 | `0e3b4724f045e0bedf7203cd40cdeb5b6e0b9a0bab78c3d04c278cb146e9833b` |
| `dplayerx.dll` | 138,752 | `dc43dbae45a8bfc39299ab0d1d5dbc72302f3bc37faf7c3b41e8ffdf4c6838ff` |

**All three files are byte-for-byte identical to the already supported
original protected Crimson Skies 1.0.2.0 edition.** Thus this German-labelled
disc is **not a third unique protected executable variant** based on these
files; localization differences may reside in data outside the archive.

Ran the release Rust Linux executable without any Win98 snapshot or DLL:

```sh
./unsafedisc-linux unwrap --loader CRIMSON.EXE --icd CRIMSON.ICD \
  --output decoded_test.exe
```

The command detected `original`, reconstructed 136 import names and 245
callsites, and produced **2,580,480 bytes**, SHA-256
`43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75`.
An independent `cmp` against the owner's historical `testme.exe`
returned **zero differing bytes**. Actual German-language gameplay
and installation have **not** been tested.

