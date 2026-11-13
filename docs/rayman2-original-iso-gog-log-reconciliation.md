# Rayman 2 — original ISO inspection logs versus GOG virtual-CD metadata

Read-only provenance and installation-stage investigation, **14 November 2026**.
The **original ISO image was not uploaded** into this research environment.
The ISO figures below come from two prior owner-supplied Rayman2Fix
inspection logs. The GOG reference executable's exact SHA-256 is
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.
This is not a physical-CD authenticity certificate.

## Independently checked private inputs

1. `Rayman2Fix(2).log`: **9 Nov 2026**, Rayman2Fix running on **native
   Windows 11**, 3,718 ISO file records, 7,450,158,839 declared bytes,
   678,168,576 physical image bytes, **1,613 explicit omitted files**.
   Their lengths total **6,926,316,824 bytes**, matching that log's
   own summary exactly.
2. `Rayman2Fix(10).log`: **10 Nov 2026**, under **Wine 11.17**, same
   full-ISO counts and sizes, **1,618 explicitly omitted files**.
   Their lengths total **6,927,476,773 bytes**, matching its summary
   exactly. The five additional omissions are:
   `00000001.tmp`, `0000040c.016`, `0000040c.256`,
   `rayman2.icd` and `secdrv.sys`.
3. Independently parse all **3,716 unique filename/length records**
   in the exact GOG executable's `.extra2` section, refusing malformed
   entry boundaries, duplicate paths or a missing terminator.

Both original ISO inspection logs agree on the entire ISO-level
`files=3718`, `declared_bytes=7450158839`,
`image_bytes=678168576` and volume `RAYMAN2`.
This corroborates two *software reports about a disc*, not an
authenticated dump of the disc's contents.

## Comparison, without assuming all CD files were logged

| Source log | Explicit exclusions | Name + size exactly match GOG | Absent from GOG | Matching names with other lengths |
|---|---:|---:|---:|---:|
| Windows, 9 Nov | 1,613 | **1,607** | **6** | **0** |
| Wine, 10 Nov | 1,618 | **1,612** | **6** | **0** |

The same **six original ISO file paths**, entirely within
`acrobat/`, are absent from the GOG virtual catalog:

| Original ISO Acrobat filename | Original declared bytes |
|---|---:|
| `ACROBAT/RS405DEU.EXE` | 8,193,238 |
| `ACROBAT/RS405DUT.EXE` | 7,982,002 |
| `ACROBAT/RS405ENG.EXE` | 6,678,967 |
| `ACROBAT/RS405ESL.EXE` | 6,880,183 |
| `ACROBAT/RS405FRE.EXE` | 8,066,650 |
| `ACROBAT/RS405ITA.EXE` | 7,607,553 |
| **Total (six)** | **45,408,593** |

Instead, the GOG catalog includes `ACROBAT/AR32E301.EXE`
(**4,018,104 bytes**) and `ACROBAT/AR32F301.EXE`
(**4,197,768 bytes**). Their combined **8,215,872** declared
bytes and the different filenames explain *some* catalog divergence,
but **not** the global original-ISO/GOG difference. The inspected
logs enumerate omissions only; they do **not** provide the other
2,100 original-CD file records. Do not claim all differing entries
have been found, or that the whole GOG virtual catalog is authentic.

The six-file Adobe difference amounts to **37,192,721 declared
bytes** in favor of the ISO. Yet the full GOG catalog reports
**2,903,775 more nominal bytes** than the ISO inspection summary.
Thus, other unobserved files/size discrepancies must also contribute
to the total; the exact paths remain unverified.

The matching original `RAYMAN2.ICD` catalog metadata
(**683,565 bytes**) is also observed directly in the 10 November
ISO omission log, independent of the research file's SHA-256.
This establishes a **size/name crosscheck**, not a sector-by-sector
hash match.

## Why this matters for actual SafeDisc decryption

The historical Rayman 2 investigation
[ArthaXerXès, *The Twilight of Safedisc*, Jan 2000]
(https://www.scribd.com/document/659005728/safedisc)
reports **a decrypted .ICD .text section of 0x9A200 bytes**
and entrypoint **0x0045FCC0** with a normal x86 function prologue.
The owner's *on-disk* 676,352-byte original
`Rayman2.exe` (SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`)
**already has both of those exact structural properties and the
literal prologue**:

- `PUSH EBP; MOV EBP,ESP; PUSH FFFFFFFFh`;
- `PUSH 0049C9D0h; PUSH 0045FF90h`;
- `MOV EAX,FS:[0]`.

The same unmodified entrypoint is present in the separately
edited GOG binary. This is significant **evidence that the
provided on-disk EXE contains real clear x86 game code**;
the matching prologue is **not** a decryption success test
for the supplied pseudo-random ICD. It does not prove all
game checks are neutralized or that the EXE is a clean,
already-unwrapped retail ICD.

In contrast, the owner's exact `RAYMAN2.ICD` and
`DPLAYERX.DLL`, together with three further companion
files, consist completely of deterministic masked PRNG
streams and do not have PE32 headers. The historical
document's *loaded DPLAYERX runtime* must not be conflated
with the owner's opaque on-disc bytes.

## Reproduce

```sh
python scripts/rayman2_cd_log_gog_compare.py \
  --inspection-log '/private/Rayman2Fix(10).log' \
  --gog '/private/GOG-Rayman2.exe'
python scripts/rayman2_cd_log_gog_compare.py \
  --inspection-log '/private/Rayman2Fix(2).log' \
  --gog '/private/GOG-Rayman2.exe'
python -m unittest discover -s scripts -p 'test_rayman2_cd_log_gog_compare.py'
```

The exact GitHub source and test file blob hashes match the
locally executed Python files:
`258a1c4e0f35741c39da7910578a5b2e97ceea98` and
`a8bab9f824d756fc09c1aaee9f9bcb441d8c45a4`.
**5/5 synthetic tests passed**; both owner log + GOG
comparisons were run locally. No GitHub Actions job or native
Rust rebuild was triggered.

**Remaining discriminator:** a same-edition *original CD*
or original setup result with file hashes for the actual
`DPLAYERX.DLL`, `DXPLAYERX.DLL` (separate names) and `RAYMAN2.ICD`,
plus an original SafeDisc-loaded PE memory image, is required before
treating the historical TEA-stage ICD/DPLAYERX as corresponding to
our supplied on-disk pseudo-streams. This script never writes,
decrypts, patches or executes original game content.
