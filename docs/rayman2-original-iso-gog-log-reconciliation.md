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

## The 23 oversized DAT references match exactly, separately

The original ISO inspection logs **explicitly omit 23** of the
24 family-number file paths of the form
`DATA/WORLD/LEVELS/{ANIMS,GRAPHICS,LEVELS,MAP,MENU,MUSIC,SOUNDS,TEXTURES}{0,1,2}.DAT`;
the retained 24th path is the genuine `LEVELS0.DAT`.
The 23 omitted records have **6,777,257,404 declared bytes
in aggregate**, about ten times the size of the entire
678,168,576-byte ISO. They are individual nominal-size
metadata entries, **not** proof of 6.78 GB of data present
in the 678 MB physical image.

**All 23 paths and their individual nominal byte lengths
match the GOG virtual-CD table exactly, in both independently
generated ISO logs.** This is especially useful for
understanding why GOG preserves implausibly large original
file-size metadata alongside its modified executable.
It cannot independently prove that a particular in-game
anti-tamper check reads those paths or that their data
can/should be physically extracted.

The read-only verifier now reports an explicit structured
`historical_23_omitted_dat` result, requiring all
**23/23** matches before marking this subgroup complete.
Its sixth synthetic test exercises both the complete
positive case and a missing-record negative case.
Locally, both original owner logs produce
`all_23_confirmed_in_both: true` and the exact sum
`6777257404`.

## Removing the 23 nominally oversized entries reconciles CD capacity

The **complete nominal original ISO** file-size sum is
`7,450,158,839` bytes. Subtracting only the **23 individually
corroborated** `DATA/WORLD/LEVELS` anomalous entries
(`6,777,257,404` bytes) leaves **`672,901,435` bytes**:
**`5,267,141` bytes less than the image's `678,168,576` bytes**.

The full GOG `.extra2` virtual file-size sum is
`7,453,062,614` bytes. Subtracting the **same exact 23
per-file lengths** gives **`675,805,210` bytes**:
**`4,949,990` bytes less than the previously established
`680,755,200` simulated CD geometry**.

| Observable nominal totals | Owner original ISO report | GOG virtual-CD metadata |
|---|---:|---:|
| Full nominal filename/size sum | 7,450,158,839 | 7,453,062,614 |
| The same 23 atypically large DAT records | 6,777,257,404 | 6,777,257,404 |
| Remainder after excluding 23 | **672,901,435** | **675,805,210** |
| Reported physical / simulated CD capacity | 678,168,576 | 680,755,200 |
| Capacity minus remaining nominal lengths | **5,267,141** | **4,949,990** |

### More appropriate ISO volume (not physical-image padding)

The `DISC:` lines also specify **`volume_bytes=677853184`**
from the ISO9660 primary descriptor, while `image_bytes`
is `678168576`. The latter is **315,392 bytes larger**,
so it includes bytes outside the nominal logical volume.
The GOG virtual-CD geometry measured separately from its
modified executable is **`680755200` bytes**.

| Compare after excluding the same 23 atypical DAT lengths | Original ISO primary volume | GOG simulated CD |
|---|---:|---:|
| Declared logical volume/capacity | 677,853,184 | 680,755,200 |
| Remaining file lengths | 672,901,435 | 675,805,210 |
| Volume capacity minus remaining lengths | **4,951,749** | **4,949,990** |

**These two residual margins differ by only 1,759 bytes.**
The nominal-file sum difference (`2,903,775`) and
the logical-volume-size difference (`2,902,016`)
also differ by exactly **1,759**. This is more
informative than comparing the ISO file length
(which includes padding) to GOG's virtual volume size.
The very close remaining margins are compatible with a
rebuilt CD image with broadly related file inventory and
similar filesystem overhead, but **not a proof of identical
underlying files or filesystem extents**.

This volume comparison is only reported by the tool when
(a) **all 23** atypical lengths are corroborated in both
metadata sources and (b) `volume_bytes` is explicitly
available from the original ISO log. The GOG geometry is
an earlier **statically verified constant tied to the
exact hash-pinned GOG executable**, not read from the
`.extra2` filename table. Both historical logs report
the same primary volume and return the same **1,759**
difference. A new eighth synthetic test verifies these
results and the image-padding distinction; **8/8 local
tests pass**. Updated Git blob SHA-1s exactly match the
locally executed files:
`dc000c8b53772f23ae86236954ea094cc8b1a08d`
and `e0722ca7f6911a59f7acc4f9290aada444abedca`.

This calculation establishes that **these 23 records alone account
for all the gross nominal-size inflation** in both inventories,
with the remaining nominal file lengths smaller than the respective
image/virtual CD size. It **cannot** demonstrate unique physical
extents, byte-identical contents, a legitimate CD authentication,
or that all other declared files could be independently read.

A separate static inspection of the two SHA-256-pinned EXEs confirms
all 23 `*.DAT` leaf filename literals already appear in the
**original executable's `.data` section** (addresses in the
`0x004A20F0..0x004A2210` region). The same `.data` strings
remain at the same virtual addresses in the edited GOG EXE;
GOG also lists the same names separately in its `.extra2`
catalog. Earlier read-only proof identified the **24-element
pointer table at VA `0x004A2090`**, used by a retail
indexed file-selector at `0x0044F13A`. The synthesis
demonstrates that the name families occur in **all three**:
the original ISO metadata report, the original program's
file-name selection table, and the edited GOG virtual catalog.
It **does not** prove which branch executes at runtime or
that the filename selection is a SafeDisc decryption stage.

The `rayman2_cd_log_gog_compare.py` report now adds a bounded
`full_23_dat_declared_size_reconciliation` object **only
when all 23 files are found and have identical declared
lengths in both metadata inventories**. Otherwise it emits
`null` for that object. Both original owner logs passed.
The added seventh and eighth synthetic unit tests passed locally,
including a deliberately missing-file negative control.
**8/8 tests pass**, with GitHub file blob SHA values
`dc000c8b53772f23ae86236954ea094cc8b1a08d`
and `e0722ca7f6911a59f7acc4f9290aada444abedca`,
both independently matching the executed local source.

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
`7344d4fc25d38784ea92b8dfa22d7c24add00f5c` and
`117f1b743d36688cd21a8b24bf53a1a033e43914`.
**8/8 synthetic tests passed**; both owner log + GOG
comparisons were run locally. No GitHub Actions job or native
Rust rebuild was triggered.

**Remaining discriminator:** a same-edition *original CD*
or original setup result with file hashes for the actual
`DPLAYERX.DLL`, `DXPLAYERX.DLL` (separate names) and `RAYMAN2.ICD`,
plus an original SafeDisc-loaded PE memory image, is required before
treating the historical TEA-stage ICD/DPLAYERX as corresponding to
our supplied on-disk pseudo-streams. This script never writes,
decrypts, patches or executes original game content.
