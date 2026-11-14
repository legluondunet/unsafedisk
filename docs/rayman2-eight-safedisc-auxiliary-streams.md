# Rayman 2 original CD — eight exact masked-PRNG auxiliary files

**14 November 2026 | Private, read-only, full-byte verification.** Earlier research proved five owner-provided files were complete pseudo-random streams, not PE executables. Three additional original-CD-associated files were discovered in the owner's existing file library, and have now been inspected at the byte level: `00000001.tmp`, `0000040c.016`, and `0000040c.256`.

## Historically, .016/.256 are SafeDisc splash BMP files — but these copies are not BMPs

Three mutually supporting **external historical accounts**
must be distinguished from our exact private byte findings:

1. [Gravure-News, 28 June 2004](https://www.gravure-news.com/article/identification-manuelle-des-protections-2-2.php)
   associates SafeDisc `.016` and `.256` files,
   typically the `0000040C` language-identifier pair,
   with **logos displayed during the authentication
   or decryption splash**. It explicitly notes that
   these filenames can also appear on **SafeDisc 1**
   CDs; they are not a SafeDisc 2 discriminator.
2. A [2011 contemporary protection discussion]
   (https://www.fileforums.com/showthread.php?goto=nextoldest&t=104458)
   describes `.016` and `.256` files as
   renamed BMP images used for the startup logo,
   not essential encrypted executable sections.
   This is historical community experience,
   not a verifier of our Rayman 2 edition.
3. [Redump's SafeDisc preservation guide]
   (https://wiki.redump.info/SafeDisc)
   says standard SafeDisc has intentionally
   defective **C2 error sectors near the
   first ~10,000 sectors**, and that `.tmp`
   dummy files correlate with those error
   regions. Some disc-authentication information
   occurs outside ordinary ISO9660 file payloads.
   It warns that remnant SafeDisc files may
   persist even if active protection is removed.

**Against the owner's actual exact `.016/.256` bytes:**

| Filename | Supplied byte count | First 2 bytes | Raw BMP signature at offset 0 | Completely reproducible as PRNG |
|---|---:|---|---|---|
| `0000040C.016` | 153,718 | `AB DE` | **no** | **yes**, after 2-byte prefix |
| `0000040C.256` | 308,278 | `4D C7` | **no** | **yes**, after 2-byte prefix |

For reference, an **ordinary uncompressed 640×480
8-bit Windows BMP with a full 256-entry 4-byte
palette** has nominal size
`14 (BITMAPFILEHEADER) + 40 (BITMAPINFOHEADER)
+ 1024 (palette) + 640*480 (pixel bytes)
= 308,278 bytes`: exactly the length of
the supplied `.256`. This **size equality
is compatible** with such a splash picture,
but does **not** reveal its pixels, prove
the intended dimensions or authenticate
the file contents. The `.016` file is
likewise not a standard plain BMP at offset
zero; no dimensions are inferred.

Since **every byte** of the two actual owner
files was independently regenerated from
public PRNG arithmetic, neither is a
plain readable bitmap or an arbitrary
independently encrypted unknown image
payload *in its current representation*.
These may be synthetic replacements,
protection-related padding or an
unverified extraction/install stage; the
evidence does **not** decide which.
Crucially, these two files are now **poor
targets for attempting to reconstruct
Rayman 2 executable code**. A separate
working SafeDisc loader/ICD stage, if
one exists on this edition, must be
verified independently.

**Physical-disc limitation:** the archived
Rayman2Fix logs describe an ISO9660
**2048-byte-sector ISO**. Even if all its
ordinary payload sectors are copied
correctly, that representation does not
include the physical-drive's C2 error
observations, drive authentication
signatures or full subchannel metadata.
Redump's description applies to standard
SafeDisc discs generally; the actual
Rayman 2 copy has not been measured
for those properties in this study.

## Breakthrough: all 5 partial-prefix bytes derive from previous generator states

Earlier, the eight SHA-256-identified owner samples were fully reproduced
using **eight initial 31-bit words plus five preserved prefix bytes**
(one in `RAYMAN2.ICD`, two each in the `.016`/`.256` samples).
Those prefix bytes were provisionally treated as independent data.

**New independent falsifiable result:** each prefix is exactly the
**low-order little-endian bytes of the immediately preceding 32-bit
PRNG state**, recovered by a mathematical inverse of the same
masked recurrence. The modular inverse of `16807`
modulo `2147483647` is **`1407677000`**,
or **`0x53E77248`**. For any
nonzero valid state `current`, its predecessor is:

```python
M, A, SALT = 2147483647, 16807, 0x075BD924
A_INV = pow(A, -1, M)                  # 0x53E77248
previous = ((current * A_INV) % M) ^ SALT
assert 0 <= previous < M
assert (A * (previous ^ SALT)) % M == current
```

For the three non-word-aligned files:

| Sample | Actual prefix | First full state | Inverted previous state | Predicted *low* byte(s) |
|---|---|---|---|---|
| `RAYMAN2.ICD` | `5B` | `0x6EE4C08A` | **`0x5611AA5B`** | `5B` |
| `0000040C.016` | `AB DE` | `0x6B5C5E78` | **`0x47EFDEAB`** | `AB DE` |
| `0000040C.256` | `4D C7` | `0x777390EF` | **`0x255AC74D`** | `4D C7` |

For each input, reading the first full DWORD and **reversing one
state** predicts the prefix *without using its bytes as input*.
In particular, it is the **first one or two bytes**, not
the high-order tail, of that predecessor's little-endian
encoding. Then moving forward through all subsequent full words
rebuilds the **entire file byte-for-byte and reproduces its
whole SHA-256**. The two-byte prefixes had been exactly
the part unexplained by a naïve four-byte-aligned reader;
they are now explained by the same PRNG as the rest.

**Independent full-data audit:** the eight exact owner
files from the private library were read again. The
stronger backtracked generator reproduced **8/8 full
file byte sequences and 8/8 SHA-256 checks**.
It successfully backtracked **200,000** successive
synthetic states (the case `current == 0` must
be handled as ambiguous and is rejected by the
inversion API). No executable, runtime output or
commercial contents were added to GitHub.

### Consequence: a tighter description-length upper bound

With file lengths, the known recurrence, and eight initial
PRNG states held fixed as the model, **there are no remaining
independent prefix bytes**. All eight files totalling
**1,548,525 bytes** are now uniquely determined by **only
eight 31-bit words** (an upper bound of **248 variable
seed bits**). Previous notes estimating
**8×31 + 5×8 = 288 bits** are superseded.
This bound concerns a *known deterministic generator's
description length*, not measured Shannon entropy.
It does not prove the files were created by one
common seed, nor does it recover their physical
CD provenance or the historical genuine loaded
SafeDisc PE stage.

The existing
`scripts/rayman2_auxiliary_stream_audit.py`
now contains `reverse_masked_prng_state` and
`verify_predecessor_prefix`, explicitly
**rejecting unpredicted prefix bytes** on
known exact-SHA reference samples. New unit
tests exercise the three known reversals,
a deliberately wrong prefix, zero-state
rejection and 10,000 forward/inverse
synthetic pairs. Original artifact bytes
are never written by that tool.

## Eight filenames absent as literals from the original game EXE

A separate direct byte scan used the exact original
`Rayman2.exe` (676,352 bytes, SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`)
and the exact separately modified GOG executable
(1,468,928 bytes, SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).

For **each of the eight exact uppercase filename
spellings**, a case-insensitive ASCII substring scan
and an ASCII-case-insensitive UTF-16LE scan of the
**entire raw on-disk executable** found:

| Test | Original CD EXE | Edited GOG EXE |
|---|---:|---:|
| Eight case-insensitive ASCII filename literals | **0/8** | **8/8**, each once |
| Eight UTF-16LE filename literals | **0/8** | **0/8** |

All eight GOG ASCII matches correspond to the names
in its separately verified virtual-CD `.extra2` catalog.
The GOG result must not be misread as an original
game code reference to each file; these matches
can be explained entirely by the appended metadata table.
The original EXE's known `.data` table of 24
`DATA/WORLD/LEVELS/*.DAT` filenames is separate
and does not include the eight protection-era
auxiliary names.

The existing SHA-256-gated
`scripts/rayman2_auxiliary_stream_audit.py` now accepts
`--retail ORIGINAL-EXE` to report the *ASCII/UTF-16LE*
literal-search counts for the selected exact-identified
auxiliary files. Additional synthetic tests check
both encodings and that an unrelated EXE cannot
pass the original retail hash gate. A separate
independent local scan of the **two actual owner
EXEs** confirmed the 8/8 absence/presence cases.

**Scope limitation:** lack of plaintext filename
literals is not proof that the original game or
SafeDisc loader never opens these files. It could
construct names at runtime, use another module,
use an encoded string table, or access raw disc
sectors without referencing filesystem filenames.

## Complete eight-file audit

The same recurrence works for **all eight**:

```
state_next = (16807 * (state XOR 0x075BD924)) mod 2147483647
```

Each word is 32-bit little-endian; the *exact listed prefix bytes*, if any, precede the first state. A raw filename extension, reported SafeDisc version or GOG catalog entry is not used to derive the recurrence. The seed is the first complete little-endian DWORD at the correct offset; deriving the XOR constant from the first two words and the modular inverse of 16807 gives the same `0x075BD924` for the new `.016` and `.256` files, and all their subsequent transitions are independently verified.

| Owner-supplied name | Bytes | Prefix (hex) | First state | Total states | Valid adjacent transitions |
|---|---:|---|---|---:|---:|
| `RAYMAN2.ICD` | 683,565 | `5B` | `0x6EE4C08A` | 170,891 | 170,890 / 170,890 |
| `DPLAYERX.DLL` | 165,888 | empty | `0x0030FBEC` | 41,472 | 41,471 / 41,471 |
| `CLOKSPL.EXE` | 177,152 | empty | `0x67EC2AF6` | 44,288 | 44,287 / 44,287 |
| `CLCD32.DLL` | 27,648 | empty | `0x4F2BFCA6` | 6,912 | 6,911 / 6,911 |
| `DRVMGT.DLL` | 32,256 | empty | `0x2B38CA9A` | 8,064 | 8,063 / 8,063 |
| `00000001.TMP` | 20 | empty | `0x2D1B9F61` | 5 | 4 / 4 |
| `0000040C.016` | 153,718 | `AB DE` | `0x6B5C5E78` | 38,429 | 38,428 / 38,428 |
| `0000040C.256` | 308,278 | `4D C7` | `0x777390EF` | 77,069 | 77,068 / 77,068 |
| **Total** | **1,548,525** | | | **387,130** | **387,122 / 387,122** |

**Full SHA-256 independently checked against the exact user's bytes after complete in-memory regeneration:**

```
RAYMAN2.ICD   4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6
DPLAYERX.DLL  0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee
CLOKSPL.EXE   6efcb3f4ba8052ab8bbd58be703a1de0f9e6eacc8f47c0d6501b0981380edaeb
CLCD32.DLL    432074cae948d0cee2704f66b47f72a4dee2f9bed288e23912fbc531b041f2a5
DRVMGT.DLL    6111ab0664948e05171468835be20b00f6b69d366fab28d7cd1ca9d9b67af35b
00000001.TMP  06ba601c966e6770747d84fe1c3fafaab9f48b07db6eae07a9250f7232415396
0000040C.016 5c53568c900404bea863ef5ac6e87e49193d95a06674f3a49d70dcefd3f28608
0000040C.256 5f25849ffa80abb15d3897ba5f4bc44ffa6f06819e370b873e9d172fc00f9933
```

The alternate owner-uploaded `0000040c(1).256` is **byte-for-byte identical** to `0000040c.256` (same exact SHA-256). No distinct 9th sample is implied.

**All 387,130 observed PRNG states are distinct, with zero overlap across the eight finite file ranges.** This is not a demonstration that the eight global generator periods are independently seeded; it describes exactly these observed sequences. For the 20-byte TMP, only **four transitions** are available; they all match the *same independently derived constant* as the much longer streams, but the short file alone is not enough to validate a generic unknown-PRNG detector. The exact owner SHA-256 gate is essential for its identity.

**Important prefix nuance:** for ICD, `.016`, and `.256`, the first 1 or 2 prefix bytes are **preserved from the observed file**, not generated from the PRNG seed; the *entire* file is still perfectly reproducible from this small fixed prefix, the initial DWORD, and the common recurrence. No unaccounted large payload remains in these eight byte streams. This does **not** prove the streams are disposable, nor does it establish their runtime role.

## Two external provenance crosschecks

The previously verified Rayman2Fix **original ISO inspection log** and the separately modified GOG EXE's **3,716-entry `.extra2` virtual-CD metadata** both show the following file-name / declared-length pairs:

| Name | ISO log length | GOG catalog length |
|---|---:|---:|
| `00000001.TMP` | 20 | 20 |
| `0000040C.016` | 153,718 | 153,718 |
| `0000040C.256` | 308,278 | 308,278 |
| `RAYMAN2.ICD` | 683,565 | 683,565 |

The other four PRNG file names/lengths also appear in GOG's virtual catalog; the original ISO log omitted only installer-excluded paths and therefore does not independently list all of them. **A name/size match does not establish that the bytes in the owner's uploaded copies are sector-identical to the original physical ISO.** The physical ISO itself is not available in this investigation.

`040C` in the two filenames corresponds to the Windows language ID `0x040C` for **French (France)** (Microsoft: https://learn.microsoft.com/fr-fr/windows-hardware/manufacture/desktop/available-language-packs-for-windows?view=windows-11). This is a useful **filename-level French-language clue**, not authenticated evidence of the exact game release or of the file format. Other vintage games also distribute paired `.016` and `.256` root files; their contents and SafeDisc roles are not assumed identical to Rayman 2.

## Historical fixed-key TEA crosschecks extended to all eight files

The earlier independently checked historical TEA known-plaintext test used the two candidate repeated-word keys `0xC15CF2E5` and `0xC1552FE5`, 32 rounds, and an all-alignment search for blocks from the 676,352-byte owner retail EXE. Repeating that exact method on the **three new samples** gives **zero matches for both keys**:

| New file | All 8-byte sliding windows | Matches with key `C15CF2E5` | Matches with key `C1552FE5` |
|---|---:|---:|---:|
| `00000001.TMP` | 13 | 0 | 0 |
| `0000040C.016` | 153,711 | 0 | 0 |
| `0000040C.256` | 308,271 | 0 | 0 |
| **Additional windows** | **461,995** | **0** | **0** |

The earlier five-file scan had 1,086,474 candidate windows. Combined: **1,548,469 raw eight-byte windows over eight files**, with **zero direct historical-fixed-key TEA matches** for either candidate key. This strictly falsifies this naive direct-on-disk relationship; it does not disprove use of TEA with a different runtime delta, key, input staging or actual ICD loaded section.

## Reproducibility and next experiment

The existing exact-SHA-gated **read-only** audit tool `scripts/rayman2_auxiliary_stream_audit.py` is extended to eight named options (`--tmp`, `--file016`, `--file256` in addition to the five earlier ones), including an observed-range-overlap report. Its tests now cover all eight in-RAM golden SHA-256 streams, alignment, bit corruption, the five-state short TMP, and all eight optional GOG length references. The separate `scripts/rayman2_tea_known_plaintext.py` source inventory is likewise updated to accept the new samples. **Independent full-byte regeneration, all eight seed transitions, cross-file collision checks, the three new file TEA tests and the GOG/ISO name-size lookups were executed locally.** The newest GitHub test files have not been run under CI; do not overstate build confidence.

Example, using only user-owned original files:

```sh
python scripts/rayman2_auxiliary_stream_audit.py \
  --icd /private/RAYMAN2.ICD \
  --dplayerx /private/DPLAYERX.DLL \
  --clokspl /private/CLOKSPL.EXE \
  --clcd32 /private/CLCD32.DLL \
  --drvmgt /private/DRVMGT.DLL \
  --tmp /private/00000001.TMP \
  --file016 /private/0000040C.016 \
  --file256 /private/0000040C.256 \
  --gog /private/GOG-Rayman2.exe
```

**Remaining unknown:** source and role of the genuine SafeDisc *loaded* DPLAYERX and ICD executable sections. Eight exact PRNG files leave **no independently encoded PE payload in these bytes** unless another external source or a highly structured substitution exists. The original disc's `SECDRV.SYS` is named in the ISO inventory (14,368 bytes) but has **not** been supplied as analyzable bytes, and cannot be judged from its name/size alone. The owner-original CD image (including any non-file-addressable sectors) and a trusted runtime memory trace remain missing. Do not infer that these eight files can be deleted from a functional original installation or that the Rayman 2 game EXE is completely unprotected.