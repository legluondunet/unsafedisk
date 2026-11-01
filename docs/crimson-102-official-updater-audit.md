# Static audit of the official Crimson Skies 1.02 updater (`crmsk102.exe`)

Audited on 2026-11-01 using a user-supplied official update executable.
**No Windows code was executed.** The PE32 resources and embedded CAB
were inspected and decompressed statically.

## Original patch identity

- File: `crmsk102.exe`
- Size: **2,315,728 bytes**
- SHA-256: `8e1c04f3e32c318a58ef3e2bbd8f13b9894ff055d4492f80ee14ce53851616af`
- MD5: `37af1ee0ce98a17dbeab68e4cd217f9f`
- The MD5 and length match the archived official v1.02 patch at
  https://www.moddb.com/games/crimson-skies/downloads/crimson-skies-update-v102

The PE has a `CABFILE` resource called **`FILESUSA.CAB`** (US English
Win32 resource language `0x0409`). CAB data begins at file offset
`0x346F0` and is **2,091,693 bytes** (`MSCF` CAB signature).
The resource `SETUPBINARY/SETUPDATA` names both target game files
and a registry version target `1.02`.

## Embedded, full replacement files

The CAB archive was extracted without starting the updater:

| CAB path | Extracted size | SHA-256 |
|---|---:|---|
| `setupenu.dll` | 32,768 | `35baf7d1a968d0ce4c4f535693b881199b479cfd94e3f4396e2c14b39ba82547` |
| `readmeUSA.rtf` | 57,539 | `dd8f7bc14e96b68f974f95d252663a4a17aac8a5a318779616fdfa908409be75` |
| **`CRIMSON.EXE`** | **344,851** | **`675a3c768c3676a525240d365f6d225b2886f51cf81fd24c271ce1c0a8afa736`** |
| **`CRIMSON.ICD`** | **2,580,578** | **`0e3b4724f045e0bedf7203cd40cdeb5b6e0b9a0bab78c3d04c278cb146e9833b`** |
| `gosdata/assets/CRIMPTCH.ROF` | 797 | `7ae28cfb65645a3e22aadc64a68badc23e2543bc56356d599fb59375d9ebbefe` |

**Both entire protected executable files are byte-for-byte identical**
to the user's earlier `crimson_skies_de.7z` German-labelled v1.02
files and the previously supported original Crimson files. This is
not a binary delta that must be reconstructed from an earlier language
edition: full replacement executables are already present.

The v1.02 French CD's protected executables are **different**:
- Protected French loader SHA-256:
  `cf9ec31364e1893c21636f53bc9410d0e1aa49ee6c32a555cf3adab9df4712ae`
- Protected French ICD SHA-256:
  `f3fe7c1ee6f62be1c9fa216ad90b57cc3653d2673095704bf439d1592e7262eb`

Both protected variants have previously been natively unwrapped to
the **same exact 2,580,480-byte PE**, SHA-256
`43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75`.

## Interpretation and limits

- **Proved:** The official November 2000 updater *contains* the
  already-supported original SafeDisc-wrapped v1.02 EXE and ICD.
  If these full replacement files are installed, the outcome is the
  same protected code regardless of the previously installed bytes.
- **Not proved:** that this installer can be applied successfully to
  **every** original-language installation. Its embedded resource is
  named `FILESUSA.CAB`, the installer helper is `setupenu.dll`,
  and the readme is `readmeUSA.rtf`. This is an English/USA
  patch package, though a later preservation site has labelled
  `crmsk102.exe` internationally compatible.
  A German-language news item from 23 November 2000 explicitly
  announced v1.02 as a patch for the *English* game version:
  https://www.gameswelt.de/crimson-skies
  Actual installer gating for French and German originals has not
  been executed or proven.
- **Not proved:** that *all* files after update are identical; the
  CAB contains an additional `CRIMPTCH.ROF` resource and does not
  replace all localized sound, text, or resource files.
- **Not proved:** why the French already-v1.02 CD was protected
  differently. A distinct mastering or localization protection
  pass is a plausible hypothesis, not a documented production fact.

No protected executable file, installer CAB, or commercial game data
was committed to this repository: only metadata and SHA-256 values.
