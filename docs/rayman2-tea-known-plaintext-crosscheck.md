# Rayman 2 — historical TEA known-plaintext crosscheck

**14 November update:** Three newly examined owner files,
`00000001.TMP`, `0000040C.016`, and `0000040C.256`,
extend this historical two-key TEA test to
**eight exact file samples**, adding **461,995
eight-byte overlapping ciphertext windows**,
with zero historical-key matches. Across the
eight files, **1,548,469** eight-byte windows
were checked with **zero matches for either
key**. The new files also regenerate entirely
as masked Park–Miller streams, preserving
their 0/2-byte initial prefixes. This remains
a negative test only for the *fixed-key
on-disk* relationship. See
[eight-file research](rayman2-eight-safedisc-auxiliary-streams.md).

**13 November 2026 — negative result, not a SafeDisc decoder.** Tested only on six SHA-256-pinned owner samples; no proprietary bytes or outputs published.

## Exact test

Protected original EXE: 676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.

For each of **676,345 overlapping 8-byte EXE windows** (**482,382 distinct blocks**), compute 32-round TEA encryption with delta `0x9E3779B9` and a repeated 32-bit key. Test both the historical key `0xC15CF2E5` and the documented transcription-error variant `0xC1552FE5`. Search every resulting ciphertext against all **overlapping 8-byte windows** of the owner's five exact opaque samples, irrespective of block alignment. The historical zero-block known-answer check is `3E CD DE 58 A2 75 01 7F`.

| Opaque sample | Candidate windows | Matches: historical key | Matches: misprinted key |
|---|---:|---:|---:|
| `RAYMAN2.ICD` | 683,558 | 0 | 0 |
| `DPLAYERX.DLL` | 165,881 | 0 | 0 |
| `CLOKSPL.EXE` | 177,145 | 0 | 0 |
| `CLCD32.DLL` | 27,641 | 0 | 0 |
| `DRVMGT.DLL` | 32,249 | 0 | 0 |
| **Total** | **1,086,474** | **0** | **0** |

A **C11 independent implementation** and the new standalone **Python 3 implementation** agree for both keys. The Python command passed **5/5 synthetic local tests** and SHA-256 validation of all six real inputs. The committed Python blob SHA-1 `58a9ba7002404af99950babce3aff3c347bfdefd` matches the exact locally executed file; test module blob SHA-1 `bc020452d6452ff371fbd0e7b36376fdaab1ab57` also matches the locally run tests. No GitHub CI was triggered.

The two scripts are `scripts/rayman2_tea_known_plaintext.py` and `scripts/test_rayman2_tea_known_plaintext.py`. Run with private original files only:

```sh
python scripts/rayman2_tea_known_plaintext.py \
  --retail /private/Rayman2.exe \
  --icd /private/RAYMAN2.ICD \
  --dplayerx /private/DPLAYERX.DLL \
  --clokspl /private/CLOKSPL.EXE \
  --clcd32 /private/CLCD32.DLL \
  --drvmgt /private/DRVMGT.DLL
python -m unittest discover -s scripts -p 'test_rayman2_tea_known_plaintext.py'
```

The CLI is read-only, size/SHA-256 gated, and refuses symlinks, nonregular files and oversized inputs. It emits JSON counts only. A nonzero match would be a candidate requiring validation, not automatic proof of a correct unwrapping.

## Distinguish disk stages from loaded sections

The five owner-provided streams comprise **271,627 observed PRNG words, all 271,627 distinct**, with no overlap within or between their observed intervals. Their original physical-disc provenance remains unverified.

[The January 2000 Rayman 2-specific SafeDisc study](https://www.scribd.com/document/659005728/safedisc) describes `.text` at `0x9A200` raw bytes and an original decrypted entrypoint at `0x0045FCC0`. The exact owner's **on-disk protected EXE already contains that matching entrypoint prologue and section size**; therefore that prologue alone cannot establish successful runtime decryption. The study's DPLAYERX `.rdata` refers to a loaded module image, not the initial PRNG DWORDs of the non-PE sample.

The owner's [Rayman2Fix physical-ISO inspection history](https://github.com/legluondunet/Rayman2Fix/blob/main/docs/lutris-cd-install.md) reports **3,718 file records, 7,450,158,839 declared bytes and 678,168,576 physical bytes**. The separately analyzed GOG edition's virtual table instead reports **3,716 records, 7,453,062,614 declared bytes and 680,755,200 simulated CD-capacity bytes**. These counts differ by **2 records, 2,903,775 nominal bytes and 2,586,624 capacity bytes**. The original ISO bytes were not available to inspect in this audit, so the figures do **not** establish a file-by-file difference within the same physical edition. Also distinguish Rayman2Fix's `DXPLAYERX.DLL` exclusion from the examined `DPLAYERX.DLL` sample; the spellings are not interchangeable.

**Conclusion:** the five provided opaque streams are not simply fixed-key TEA encryptions of arbitrary 8-byte windows from the supplied retail EXE. This does **not** reject post-load transformations, a different cipher stage, alternative key/parameters or physical-CD-dependent authorization. Next high-value evidence: same-edition original CD/install file hashes and an authenticated loaded DPLAYERX section/decoder trace. No Crimson Skies changes.
