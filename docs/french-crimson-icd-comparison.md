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
