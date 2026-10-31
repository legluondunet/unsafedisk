# French Crimson Skies ICD vs historical Windows 98 unSafeDisc output

Evidence collected 2026-10-31 from user-supplied files. Read-only comparison;
no copyrighted game binaries or RAM images are checked in.

| File | Bytes | SHA-256 |
|---|---:|---|
| French protected `crimson.icd` | 2,580,578 | `f3fe7c1ee6f62be1c9fa216ad90b57cc3653d2673095704bf439d1592e7262eb` |
| French historical `TESTME.EXE` (unSafeDisc 1.5.5 on Win98 per owner) | 2,580,480 | `43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75` |
| Existing `CRIMSON-UNWRAPPED.EXE` reference | 2,580,480 | `43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75` |
| French SafeDisc launcher `crimson.exe` | 344,925 | `cf9ec31364e1893c21636f53bc9410d0e1aa49ee6c32a555cf3adab9df4712ae` |
| `dplayerx.dll` | 138,752 | `dc43dbae45a8bfc39299ab0d1d5dbc72302f3bc37faf7c3b41e8ffdf4c6838ff` |

The French output `TESTME.EXE` and previously validated unwrapped reference are
byte-for-byte identical, not just the same length or PE entry point.

Both French ICD and decrypted output have PE32 x86 entry RVA `0x001F7056`,
six matching section names/raw lengths, and the following **positional**
raw-data differences:

| Section | Raw bytes | Differing bytes | Percentage |
|---|---:|---:|---:|
| .text | 2,105,344 | 1,812,843 | 86.11% |
| .rdata | 90,112 | 0 | 0.00% |
| .data | 172,032 | 167,384 | 97.30% |
| .idata | 16,384 | 3,360 | 20.51% |
| .rsrc | 24,576 | 0 | 0.00% |
| .reloc | 167,936 | 2 | 0.00% |

The ICD has an extra 98 bytes beyond output size. The byte-difference
counts alone **do not** identify which differences are encryption,
relocations, import reconstruction or PE-header edits.

Repeat using `python scripts/compare_pe_sections.py crimson.icd TESTME.EXE`.
The new Rust `inspect --generic-inspect` collects structural data without
relaxing exact-hash restrictions of the historical reconstruction paths.

Next research steps: inspect raw section-byte transformations; localize the
2-byte reloc difference and 98-byte length delta; verify section and header
differences. Do not extrapolate per-version keys from this match alone.

## Follow-up offset-level findings

Independent byte-level verification against the user's French ICD and its
historical Windows 98 `TESTME.EXE` output:

- The extra 98 bytes appended to the protected ICD occur after the PE section
  raw extent. The tail contains an `NB10` CodeView-style marker and the ASCII
  path `z:\\zipper\\CrimsonRun\\run\\Crimson.pdb`, plus other opaque bytes.
  This should not be mistaken for 98 bytes of encrypted game code.
- `.reloc` differs at **exactly two absolute file offsets**, `0x275FFD`
  and `0x275FFE` (`00 00` in ICD, `27 60` in historical TESTME).
- Header differences include PE offsets `0xF6`/`0xF7` and a large
  human-readable marker beginning at offset `0x300` in the TESTME output.
- `.rdata` and `.rsrc` are byte-identical across the two files.

These observations do **not** demonstrate the encryption key, transform
order, SafeDisc variant equivalence or native unwrapper correctness.


## 2026-10-31: import descriptor follow-up

A separate bounded parse of the PE32 `.idata` section found **21**
`IMAGE_IMPORT_DESCRIPTOR` entries. Each is 20 bytes (five DWORDs),
and the only descriptor field changed between the French protected ICD and
the Win98 TESTME output is `TimeDateStamp` at descriptor-relative +4:
`0x00000000 -> 0xAD2B0000` for all 21 entries.
This accounts for exactly 42 changed bytes out of the 3,360 total
changed bytes within `.idata`; **3,318 changes remain outside these
21 timestamp words**. The other descriptor fields
(`OriginalFirstThunk`, `ForwarderChain`, `Name`, `FirstThunk`)
are unchanged on this comparison.

Caution: `0xAD2B0000` is a descriptor field *value*, not proven to be
a SafeDisc cipher key. The remaining byte differences may include
import name/thunk data or other content, and need separate characterization.

Reproduction:
`python scripts/audit_import_deltas.py --icd crimson.icd --unwrapped testme.exe`.

This script is strictly read-only and does not claim to reproduce
decryption or generate a modified game binary.


## Further .idata byte inspection

Direct read-only hexdump inspection identifies two categories beyond the
21 descriptor timestamp fields:

- At file offset `0x2432D8` the ICD contains DWORD
  `0x6AF47C3C` where TESTME contains `0x00620E42`; successive DWORDs
  likewise change from `0x6AF4....`-range values to valid PE-image RVAs
  (`0x00620E4E`, `0x00620E5A`, etc.). This is evidence of restoration or
  normalization of import lookup/thunk content, not yet an identified cipher.
- At file offset `0x245000` the TESTME output contains readable import
  API names, including `LoadLibraryA` and `FreeLibrary`, whereas the
  corresponding ICD bytes are not readable ASCII. Additional API-name
  regions occur near file offset `0x2464C2` with
  `InitializeCriticalSection` and `DeleteCriticalSection`.

No constant XOR or subtraction transform should be assumed from the sample
DWORD pairs; sampled XOR/subtraction deltas are not constant.

The **next justified task** is separating thunk-array transformations from
import-name restoration, and determining whether they share decoder logic
with the native Rust SafeDisc stages. The exact complete unwrapping
algorithm remains unverified.

## Exhaustive structural .idata classification (2026-10-31)

The enhanced read-only script accepts `--coverage` and assigns each
changed byte to a region referenced by decoded PE import descriptors.
Observed on the owner-provided French ICD / Windows 98 TESTME pair:

| Region | Differing bytes |
|---|---:|
| 21 import descriptor timestamps | 42 |
| Import lookup tables (ILT) | 541 |
| Import address tables (IAT) | 541 |
| IMAGE_IMPORT_BY_NAME records (hint + API name) | 2,234 |
| DLL name strings | 2 |
| Unclassified | **0** |
| **Total** | **3,360** |

Of the 21 imported DLLs, only the kernel and user imports have changed
lookup/address-table DWORD entries: **74 entries each in ILT/IAT for
KeRNeL32.dll** and **62 each in ILT/IAT for USER32.dll**.
Two changed DLL-name characters affect the mixed-case
`KeRNeL32.dll` spelling; these are not cipher-key evidence.

These are *output-guided structural categories*, not an inferred decoder:
the transformation generating 1,082 changed thunk bytes and 2,234 changed
import-name/hint bytes still has to be reconstructed.

```sh
python scripts/audit_import_deltas.py --icd crimson.icd --unwrapped TESTME.EXE --coverage
```

## Runtime validation of the Rust import-name decoder

The user successfully tested the Rust executable's command
`inspect-import-codec --icd crimson.icd --reference testme.exe`:

- exact French ICD SHA-256 matched `f3fe7c1e…e7262eb`
- 136 protected API-name records restored in RAM
- exactly 2,234 changed bytes reproduced against historical Win98 output
- `.idata` difference count fell from 3,360 to **1,126**
- no output executable generated

### Remaining 1,126 bytes: structural follow-up

Direct analysis of the user's original and historical reference confirms
identical contents for ILT and IAT within **each** of the two affected DLLs,
both before and after unSafeDisc:

- `KERNEL32.dll`: 74 thunk entries; ILT and IAT match in each file.
- `USER32.dll`: 62 thunk entries; ILT and IAT match in each file.
- The original protected table's first thunk of each of these DLLs is zero;
  the Win98-unwrapped table instead points to its first import-name record.
- Most other protected thunk values fall in the `0x6AF4xxxx` range.
  There is no demonstrated constant-XOR or direct arithmetic mapping from
  these words to the recovered IMAGE_IMPORT_BY_NAME RVAs.
- Descriptor timestamps contribute 42 changed bytes, and capitalization of
  the `KERNEL32.dll` name contributes 2. The rest (1,082 changed bytes)
  is duplicated between ILT and IAT.

The matching ILT/IAT values let future work model **one 136-entry mapping**
and apply it consistently to both tables. Such a mapping must be derived or
explicitly identified as reference-guided data; it must not be described as
a proven general SafeDisc decryptor.
