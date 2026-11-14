# Rayman 2 — auxiliary PRNG file boundaries and installer provenance

**14 November 2026. Read-only research.** This note separates the exact
owner-provided file bytes, partial original ISO evidence, and the separately
modified GOG virtual catalog. The original ISO's raw sectors and any
physical-disc C2-error measurements remain unavailable here.

## Eight exact owner-file streams do not link over short generator gaps

The following eight owner-supplied files have exact SHA-256-pinned, wholly
reproducible masked Park–Miller content with salt `0x075BD924`, multiplier
`16807` and modulus `2147483647`:

`RAYMAN2.ICD`, `DPLAYERX.DLL`, `CLOKSPL.EXE`, `CLCD32.DLL`,
`DRVMGT.DLL`, `00000001.TMP`, `0000040C.016`, `0000040C.256`.

The first *effective generator state* for the files with a partial
leading PRNG word is the **one-step inverted predecessor**, already
proved to yield the exact 1/2-byte prefix.
All other files start at the first complete DWORD. For each file,
the last complete DWORD is the terminal state.

| Input | Effective start state | Last complete state | Next generated state |
|---|---|---|---|
| `RAYMAN2.ICD` | `0x5611AA5B` | `0x29041FEC` | `0x11F38C41` |
| `DPLAYERX.DLL` | `0x0030FBEC` | `0x34E5AEAD` | `0x1D99DDE9` |
| `CLOKSPL.EXE` | `0x67EC2AF6` | `0x687BE760` | `0x2DD81B5B` |
| `CLCD32.DLL` | `0x4F2BFCA6` | `0x580E68CF` | `0x7313EC32` |
| `DRVMGT.DLL` | `0x2B38CA9A` | `0x14A1A9B0` | `0x1EF50ECB` |
| `00000001.TMP` | `0x2D1B9F61` | `0x19AEEE53` | `0x750C7581` |
| `0000040C.016` | `0x47EFDEAB` | `0x3451C41B` | `0x5D062D46` |
| `0000040C.256` | `0x255AC74D` | `0x2FDA2769` | `0x6E5E8601` |

A first independent check verified that **none of the eight next states
equals the first effective state of any of the other seven files**.
Then an independent local Python probe generated **1,000,000 successive
states after each file's final DWORD** and looked for any of the other
seven effective first states. It evaluated **8,000,000 state transitions**
and **56 ordered distinct-file pairs**: **zero matches**.

This falsifies immediate concatenation and connections separated by at
most one million whole-state iterations **within this specific
generator model**. It does not exclude a common producer with larger
gaps, dynamically reseeded files or other generation stages. The
one-million-step horizon is a negative bound, not evidence of complete
generator-cycle independence.

The existing SHA-256-gated
`scripts/rayman2_auxiliary_stream_audit.py` now offers
`--probe-boundaries STEPS` (1 through 1,000,000) to repeat
the bounded search for any two through eight exact sample files.
It records only counts and any discovered filename-pair gap;
default behavior does not perform the potentially expensive scan.
Synthetic tests exercise a deliberately directly concatenated pair
and reject invalid ranges. **No proprietary payload output.**

## A live cross-project discrepancy in Rayman2Fix's CD exclusions

The currently published Rayman2Fix main branch contains
[`include/rayman2fix/cd_exclusions.hpp`]
(https://github.com/legluondunet/Rayman2Fix/blob/main/include/rayman2fix/cd_exclusions.hpp).
Its exact six case-normalized **root-only** exclusion names are:

- `00000001.tmp`
- `0000040c.016`
- `0000040c.256`
- `secdrv.sys`
- `rayman2.icd`
- **`dxplayerx.dll`**

The fifth named SafeDisc-era file from the user's own samples and
GOG's hash-pinned virtual-media manifest is **`DPLAYERX.DLL`**
(**165,888 bytes, GOG record #6**), **not `DXPLAYERX.DLL`**.
The exact GOG catalog has `DPLAYERX.DLL` and no record with the
`DXPLAYERX.DLL` spelling. The original ISO omission log has entries
for the three numbered files, `RAYMAN2.ICD` and `SECDRV.SYS` but
**no omission entry for DPLAYERX.DLL**. The other three exact PRNG
files (`CLOKSPL.EXE`, `CLCD32.DLL`, `DRVMGT.DLL`)
are also absent from the six root-only exclusions.

The corresponding
[`src/disc/disc.cpp`]
(https://github.com/legluondunet/Rayman2Fix/blob/main/src/disc/disc.cpp)
does **not** generate or substitute PRNG bytes during extraction:
it takes ISO9660 file extents, checks bounds, and streams source
sectors to the selected output destination, skipping only
excluded files and invalid/disallowed entries. The archived owner
CD inspection has `suspect_files=0` and reports **3,718**
files in the ISO, but logs only the **1,618 omitted** files,
not all retained file extents. That is not enough to authenticate
the bytes of retained auxiliary files from original physical sectors.

This means the specifically written
`dxplayerx.dll` exclusion does **not** cover
the `dplayerx.dll` name present in our
current evidence. It is a concrete **name-matching mismatch**
to review in Rayman2Fix's installation policy, not proof that a
working game cannot tolerate that file. The current SafeDisc
research PR deliberately **does not modify Rayman2Fix**
or conclude, without a verified installation dependency,
that all companion filenames can safely be dropped.

## No plain eight-file seed literals in the original game EXE

The eight known initial 31-bit file-stream states are absent
as little-endian DWORDs from the exact original retail
and separately modified GOG game EXEs. The original
runtime seed path instead uses QueryPerformanceCounter
or `0x12345678` on failure and generates 281 states
in memory at `0x510EA0`. The eight file starts
do not match any of the **281 fallback words**
in that known deterministic initialization.
This is limited evidence against directly equating the
static files with a preserved QPC-fallback startup
buffer, not against other original seed sources.

## What matters for SafeDisc 1.35 next

The complete byte-level reconstruction of eight auxiliary
files makes another brute-force TEA pass over those files
low-value. The remaining actionable questions are:
**was the original physical CD edition really built with
these stream bytes; is there an additional, differently
loaded DPLAYERX/ICD stage; and what do original setup and
legitimate loader I/O read in practice?**

A verified same-edition original ISO/installed-files hash
comparison would be materially more informative than another
unrestricted scan of synthetic PRNG streams. A 2,048-byte
ISO file alone does not provide physical C2-error
observations needed for standard SafeDisc disc authentication.

**No game executable was decrypted, modified or distributed,
and no Chromium/Windows/Wine game execution was done
during this bounded boundary investigation.**
