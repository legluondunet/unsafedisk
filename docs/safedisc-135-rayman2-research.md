# Rayman 2 retail CD — SafeDisc 1.35 research

Status: **read-only classification implemented; native unwrapping not implemented.**
**Latest read-only crosscheck:** [Rayman 2 historical TEA known-plaintext analysis](rayman2-tea-known-plaintext-crosscheck.md) independently excludes direct fixed-key TEA encoding of the on-disk retail EXE into any of the five owner-supplied PRNG streams (all overlapping 8-byte offsets, two historical key readings); it does **not** reconstruct a decrypted runtime section.


Additional independent historical and installer-stage evidence, with a separate
read-only asset-checking script: [Rayman 2 SafeDisc versus in-game anti-tamper](rayman2-anti-tamper-evidence.md).
The 2009 Wine description of **~650 MB media / ~6.9 GB file sizes** is
numerically consistent with **649.219 MiB virtual CD capacity / 6.941 GiB
reported file lengths** in the GOG reference, but does not authenticate the
3,716 GOG entries as the original CD directory.


**Focused 23-file subgroup:** the original ISO logs explicitly
omit 23 atypically large `DATA/WORLD/LEVELS` numbered
DAT records. Their combined declared size is
**6,777,257,404 bytes**, whereas the physical original
ISO image is **678,168,576 bytes**. The
`rayman2_cd_log_gog_compare.py` tool independently
confirms **23/23 exact filename and size matches** to
GOG's `.extra2` virtual-CD catalog, in both archived
logs; all **six** synthetic tests passed locally.
This confirms metadata retention only, not physical file
contents or an executed in-game anti-tamper predicate.

**Capacity normalisation:** The 23 original ISO
and GOG catalog DAT entries have **6,777,257,404
nominal bytes** in both. Removing exactly these 23
nominal values leaves **672,901,435 bytes** for the
ISO and **675,805,210 bytes** for GOG. The logical
ISO volume has **4,951,749 bytes** of nominal slack
(vs. **4,949,990 bytes** for GOG's previously
verified virtual volume): a difference of **1,759
bytes**. The ISO image's extra **315,392 bytes**
of padding must not be confused with the volume's
capacity. These are metadata/accounting results,
not physical extents or cryptographic CD identity.
The checker and its eight synthetic tests were run
locally with both owner logs and exact GOG data.

## Two original ISO inspection logs corroborate the GOG virtual catalog (14 November 2026)

[Read-only original-ISO versus GOG log reconciliation]
(rayman2-original-iso-gog-log-reconciliation.md)
uses an earlier *native Windows* Rayman2Fix CD inspection log
(1,613 omission records) and an independently generated *Wine*
inspection log (1,618 omission records). Both report **3,718
ISO files** and **7,450,158,839 nominal bytes**. Relative to
GOG's 3,716-entry `.extra2` catalog, respectively **1,607**
and **1,612** omitted original paths have **matching names and
exact nominal sizes**, with **zero size discrepancies**.
Both show the same six original ISO files absent from GOG:
multilingual Adobe Reader installers. GOG instead lists two
other Acrobat installer files. This is a meaningful corroboration
of partial original-CD metadata, **not** the 3,718-file original
ISO content or the claim that our PRNG bytes were actually
read from the physical CD. An actual physical image was not
available in this investigation.

The original 676,352-byte `Rayman2.exe` already has the
**same PE32 entrypoint 0x45FCC0, x86 prologue, and .text raw
size 0x9A200** that the January 2000 reverse-engineering
paper identifies for a *decrypted* ICD section. This is
strong evidence of real readable game code **already present
on disk**, but does not certify the entire PE is fully
unprotected or substitute a post-decryption ICD memory
dump. It is therefore unsafe to treat the paper's
decrypted-ICD recipe as directly applicable to our
fully synthetic `RAYMAN2.ICD` bytes.

The tool and its five new synthetic tests were executed
against the two exact owner logs and hash-pinned GOG EXE,
with the committed Git blobs verified to be exactly the
locally tested files. **No Windows/Wine runtime decryption,
Rust compilation or CI was performed.**

## Source-level SafeDisc V1 caution: logo placeholders, disc C2 errors, remnant files (14 November 2026)

Three independent background sources were checked against
the **eight exact user-supplied byte streams**:

- [CD Media World — SafeDisc 1](https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc.shtml)
  describes the classic V1 **game.EXE loader +
  encrypted game.ICD payload** model, with helper
  `00000001.TMP`, `CLOKSPL.EXE`,
  `CLCD32.DLL`, `DPLAYERX.DLL`;
  its historical revision/size table maps the
  **165,888-byte** DPLAYERX to *r2*, not *r3*.
- [Gravure-News, 2004](https://www.gravure-news.com/article/identification-manuelle-des-protections-2-2.php)
  and a [2011 SafeDisc splash-file discussion]
  (https://www.fileforums.com/showthread.php?goto=nextoldest&t=104458)
  identify the `.016` and `.256`
  language-suffixed files as **splash-screen
  bitmaps**; the same file types may occur on
  **SafeDisc 1** as well as 2/3. Yet the
  owner's `0000040C.016` and `.256`
  both have **non-BMP prefixes**, are entirely
  masked PRNG streams, and cannot be used as
  plain image data. Interestingly, the
  `.256` byte count **308,278** exactly
  equals a standard uncompressed **640×480
  8-bit BMP with a full palette**; size alone
  does not authenticate the intended bitmap
  or reveal its missing pixel data.
- [Redump's SafeDisc preservation notes]
  (https://wiki.redump.info/SafeDisc) state that
  standard SafeDisc disc mastering often relies
  on **physical C2 errors near the beginning
  of the disc**, correlating with `.tmp`
  dummy-file entries, and explain that
  **SafeDisc-era remnant files may remain
  even when active protection was removed**.
  The user's historic 2048-byte-sector ISO
  inspection provides *file metadata* but
  **no physical C2 error log or raw-sector
  authentication record**.

Thus the usual V1 narrative
"encrypted ICD + small loader EXE"
**conflicts with the observed stage**:
our SHA-pinned 676,352-byte `Rayman2.exe`
already contains clear full game-engine code,
and our SHA-pinned 683,565-byte
`RAYMAN2.ICD` is 100% reproducible
pseudo-random data without an independent
PE payload. There are several **unresolved
possibilities**, including an originally
different disc revision, an already modified
or partly unwrapped image, preserved
protection filename placeholders, or an
installation/runtime transformation.
None has been proven from the available
data, and neither the historical study's
TEA key nor the presence of `.ICD`
authenticates a working V1 encrypted
payload in these exact bytes.

**Prioritize original media/source provenance
and true loader input identification
before investing more in blind TEA
searches.** At present the original
`SECDRV.SYS` has only a known nominal
size of **14,368 bytes** in the
original-ISO logs and virtual GOG catalog;
its real bytes have not been available
to this analysis. There is **no
recovered executable payload or
loaded DPLAYERX PE memory image**.

## Three further owner-provided CD file streams verified (14 November 2026)

[Complete eight-file original SafeDisc-era PRNG
research](rayman2-eight-safedisc-auxiliary-streams.md)
extends the five earlier, already SHA-256-pinned,
whole-file masked-Park–Miller streams by three
**directly reexamined owner files**:

| Exact file | Bytes | Unexplained-independent-code bytes | Prefix | Seed | Observed words |
|---|---:|---:|---|---|---:|
| `00000001.TMP` | 20 | 0 | none | `0x2D1B9F61` | 5 |
| `0000040C.016` | 153,718 | 0 | `AB DE` | `0x6B5C5E78` | 38,429 |
| `0000040C.256` | 308,278 | 0 | `4D C7` | `0x777390EF` | 77,069 |

The total **eight** owner files comprise **1,548,525
bytes**. All **387,122 adjacent state transitions**
match the exact same `0x075BD924` masked recurrence;
full byte regeneration, preserving 1/2-byte file
prefixes, matches all eight SHA-256 values.
The **387,130 observed states are all distinct**,
including across files. The separate duplicate
`.256` upload is byte-identical. The three
new filenames/lengths are also explicitly present
in both the original Rayman2Fix ISO inspection log
and GOG's 3,716-entry catalog; **this is size
corroboration, not a physical-sector hash**.

An extended fixed historical-key TEA known-plaintext
scan found **0 matches** among **461,995 additional
overlapping eight-byte windows** of these files.
The `.016` and `.256` suffixes share the
`040C` designation associated with
French (France) by Microsoft; this is
a filename clue, not authentication.

**Important:** the 20-byte `.TMP` file has
only four transitions, too few for a generic
unknown-file classifier; its exact owner SHA-256
gate and consistency with the other seven files
are essential. Without the original runtime
DPLAYERX loaded image and disc authentication
trace, the exact SafeDisc 1.35 stage remains
unresolved. Do not equate these PRNG sequences
with ordinary PE executable sections.

## Historical Rayman 2 paper vs the exact owner EXE (14 November 2026)

A separate [read-only binary-anchor audit]
(rayman2-january2000-binary-anchor-audit.md)
checked the *January 2000* paper's Rayman 2
**decoded ICD** entrypoint and three additional
specified code addresses against **the exact
SHA-256-pinned 676,352-byte CD EXE** and
the separately edited **GOG EXE**.

The **original disk EXE already has the historical
0x0045FCC0 prologue** and 0x9A200-byte raw
`.text`, but three other location-specific
historical opcode prefixes **do not match**
in either on-disk EXE, and three original
paper patch signatures are absent from both
`.text` sections. **All four sampled 32-byte
address spans are mutually identical between
retail and GOG**. The GOG `.text` is 0x9B000
raw bytes (rather than retail's 0x9A200); its
extra 0xE00 bytes are zero padding, not
new game code.

The historical author **tentatively** called
the analyzed CD's protection *r3*;
the historical CDMediaWorld size table
associates the **165,888-byte DPLAYERX** size
with *r2* rather than its reported *r3*
size of 172,544. A **different SafeDisc
revision, transformed runtime stage, or
historical address mismatch** could explain
the inconsistencies. **None is proven**.
This is critical: neither the historical TEA
key nor the historic function offsets should
be used as an edition-locked decryption
proof for our actual ICD/DPLAYERX files.

**Execution:** 5 synthetic unit tests passed;
full owner-EXE integration passed; exact
GitHub script/test blobs match the local
files, no CI or Wine game execution.
`scripts/rayman2_historical_anchors.py`
generates only metadata.

## Five owner-supplied SafeDisc-era filenames are exact PRNG streams (13 November 2026)

**New primary input evidence: all FIVE exact samples were retrieved again
from the owner's private file library and independently hashed and
checked, not merely inferred from the earlier two-file metadata.**
The three newly inspected files were uploaded on 9 November 2026,
before the subsequent 12 November ICD/DPLAYERX duplicate submissions.
They require no opaque decompression to account for every byte.

| File | Physical bytes | Exact PRNG start | Prefix | GOG virtual-CD index |
|---|---:|---|---:|---:|
| `RAYMAN2.ICD` | 683,565 | `0x6EE4C08A` | `5B` | 18 |
| `DPLAYERX.DLL` | 165,888 | `0x0030FBEC` | none | 6 |
| `CLOKSPL.EXE` | 177,152 | `0x67EC2AF6` | none | 5 |
| `CLCD32.DLL` | 27,648 | `0x4F2BFCA6` | none | 4 |
| `DRVMGT.DLL` | 32,256 | `0x2B38CA9A` | none | 7 |

All states are 32-bit **little-endian** words, beginning after
the optional one-byte ICD prefix; all five obey the same
`state_next = (16807 * (state XOR 0x075BD924)) mod 2147483647`
for **every word**. An **independent complete regeneration**
of each file in RAM matched both the original bytes and
their complete SHA-256 hashes:

- `RAYMAN2.ICD`: `4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6`
- `DPLAYERX.DLL`: `0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee`
- `CLOKSPL.EXE`: `6efcb3f4ba8052ab8bbd58be703a1de0f9e6eacc8f47c0d6501b0981380edaeb`
- `CLCD32.DLL`: `432074cae948d0cee2704f66b47f72a4dee2f9bed288e23912fbc531b041f2a5`
- `DRVMGT.DLL`: `6111ab0664948e05171468835be20b00f6b69d366fab28d7cd1ca9d9b67af35b`

**None of these five owner-provided bytes, at their current on-disk
stage, is a directly loadable Win32 PE32 image.** The exact GOG
edited executable's separate `.extra2` record list contains
all five matching *declared sizes*, strengthening the evidence
that the filenames belong to the same Rayman 2 release lineage.
This does **not** validate the physical CD filesystem, installer
transformations, CD defect-sector key or the GOG metadata as
an authentic original CD manifest.

**Cross-version control:** a separately preserved Crimson Skies
`DPLAYERX.DLL` of **138,752 bytes**, SHA-256
`dc43dbae45a8bfc39299ab0d1d5dbc72302f3bc37faf7c3b41e8ffdf4c6838ff`,
is a **valid six-section PE32 DLL**, not a complete instance of
this masked-MINSTD stream. Thus the observed pseudo-file pattern
is not a universal property of all SafeDisc 1.x `DPLAYERX.DLL`
files. Different game/version/installation stages remain possible.

**Most important conclusion:** the original-CD installation path
and the historical **loaded** DPLAYERX with working `.rdata`
must still be distinguished from the five **provided opaque
on-disk streams**. It would be premature to label them inert
junk, genuine installed DLLs, or directly decryptable ciphertext.
A raw PRNG stream cannot directly satisfy a Windows PE DLL
loader without an additional transformation or substitute.
Do not remove these files from installation logic based solely
on the mathematical reconstruction.

**Reproducible tool:** `scripts/rayman2_auxiliary_stream_audit.py`
reads any subset of the five **exact SHA-256-pinned** owner
references (with arbitrary pathnames) and optionally checks
their declared lengths in the exact GOG executable. It reports
metadata only. No proprietary file bytes or executable output
are written to the repository:

```sh
python scripts/rayman2_auxiliary_stream_audit.py \\
  --icd /local/RAYMAN2.ICD \\
  --dplayerx /local/DPLAYERX.DLL \\
  --clokspl /local/CLOKSPL.EXE \\
  --clcd32 /local/CLCD32.DLL \\
  --drvmgt /local/DRVMGT.DLL \\
  --gog /local/GOG-Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_auxiliary_stream_audit.py'
```

A standalone, independently written local verifier reproduced
**5/5 byte-exact files** and checked all five specified GOG
manifest records. The newly committed Python test module remains
**untested on GitHub/CI**. SafeDisc executable unwrapping is still
unimplemented.

## Exact on-disk historical-TEA negative controls, checked twice (13 November 2026)

Four SHA-256-identified owner's inputs were scanned literally for
the historical TEA **key `0xC15CF2E5`**, **delta `0x9E3779B9`**,
**32-round aggregate `0xC6EF3720`**, and the
**zero-block ciphertext `3ECDDE58A275017F`**: none of these
literals occur in any of the four disk files. This is NOT
evidence that an unloaded/transformed runtime DPLAYERX lacks
those constants or that TEA is unused.

The original masked-PRNG XOR salt `0x075BD924` appears **73
times** in the protected original PE `.text`.
The GOG executable has **29 occurrences in its active `.text`**,
and **73 more inside the archival non-executable `.extra`** copy
of retail `.text`, for 102 occurrences when naively scanning
the whole GOG *file*. **102 must not be confused with 102
occurrences in live executable code.**

Two **independent implementations (C11 and Python)** of
historical standard TEA with repeated word key
`0xC15CF2E5`, 32 rounds, delta `0x9E3779B9`
decrypted every complete 8-byte block in the owner's exact
ICD and DPLAYERX byte streams at each of **eight possible
block alignments**. Both returned the same incidental
`MZ` counts, but **ZERO `MZ` plus `PE\\0\\0`**
header pairs with a plausible PE layout for either file
on any alignment. This specifically rejects a **naïve
whole-file, fixed-key, raw-TEA-to-PE** reconstruction
model; it does not refute section-only TEA decryption,
a different container or dynamic loaded-memory parameters.

**Reproduction without original game payload output:**

```sh
python scripts/rayman2_historical_tea.py \\
  --scan /local/RAYMAN2.ICD --scan-fixed-tea-pe
python scripts/rayman2_historical_tea.py \\
  --scan /local/DPLAYERX.DLL --scan-fixed-tea-pe
```

The Python scanner does not emit transformed file contents.
A **synthetic 4-KiB one-section PE32** was encrypted in
8-byte blocks beginning at alignment 5 and then tested
across all eight offsets: the independent positive-control
scanner recovered exactly one valid PE header at alignment
5, none elsewhere. This demonstrates detection ability
without using any proprietary PE data. New tests in
`scripts/test_rayman2_historical_tea.py` enforce this
positive case and malformed-input refusal; its exact
GitHub version has not yet run on CI. The historical
algorithm remains a lead, **not a decoded Rayman 2 executable**.

## Newly reproduced Rayman 2-specific historical TEA known-answer vector (13 November 2026)

**Independent mathematical result; historical cipher only, NOT an
authenticated decoder for the owner's on-disc Rayman 2 sample.**

ArthaXerXès's *The Twilight of Safedisc* (25 January 2000),
[§3.2.3](https://www.scribd.com/document/659005728/safedisc),
describes the Rayman 2 runtime section decryptor using **8-byte
blocks and 32 Feistel rounds**, with four repeated 32-bit key
words and a `.rdata`-supplied per-round constant/counter.

Implementing the exact stated left/right operations as **standard
TEA** (delta `0x9E3779B9`, 32 rounds, four identical key words
`0xC15CF2E5`) yields this independent known-answer vector:

```text
Plaintext:                00 00 00 00 00 00 00 00
TEA key words:            C15CF2E5 C15CF2E5 C15CF2E5 C15CF2E5
Delta / rounds:           9E3779B9 / 32
Calculated ciphertext:    3E CD DE 58 A2 75 01 7F
Decryption of ciphertext: 00 00 00 00 00 00 00 00
```

**All seven bytes** `CD DE 58 A2 75 01 7F` that remain visible
in the online transcription of the essay's encrypted-zero
example match the **last seven** bytes of this calculated
ciphertext. The computed leading byte is `3E`. This validates
the historical TEA/key/constant combination against a 56-bit
printed known-answer suffix; it does not prove the first byte
in the original printed document was missing or correct the
original text with certainty.

**Transcription warning:** the historical essay separately prints
an original code-patch instruction `B9 E5 F2 5C C1`, which correctly
loads `ECX=0xC15CF2E5` (matching its written key), but another
example prints the inconsistent bytes `E5 2F 55 C1`, which represent
`0xC1552FE5`. The latter alternative fails the known-answer vector
(the eight-byte ciphertext for zero under that alternative,
with the same delta/rounds, is `12 43 84 B8 EC 16 31 15`).
Do not silently substitute the inconsistent byte sequence.

**Boundary against our actual files:** independently regenerating
the two SHA-256-identified owner-provided pseudo-random streams
from their seeds reproduced the full ICD and DLL hashes exactly.
A bytewise scan of those complete **in-memory reconstructions**
found **zero occurrences** of either the full 8-byte historical
zero-ciphertext vector, or its published 7-byte suffix.
Every scanned 8-byte window in each reconstructed stream was
unique. These negative results are expected for PRNG data and
**do not exclude** later intermediate layers, actual loaded
DPLAYERX image data, a separate encrypted section, or the
historical key applying only after a different installation/runtime
transformation.

### 13 November independent whole-stream TEA signature falsification

The historical essay explicitly locates the per-round constant at
the **first DWORD of loaded DPLAYERX `.rdata`** and the round
count at its **second DWORD**, before passing through a
`32-round / 8-byte` decryption loop. Those are loaded-memory
values, not the first two words of the owner's opaque on-disc
`DPLAYERX.DLL`.

A new **synthetic-data-only, no-input** option,
`python scripts/rayman2_historical_tea.py --verify-known-streams`,
regenerates the two previously independently confirmed PRNG
streams, recomputes their full SHA-256 identifiers and searches for
the historical ciphertext of a zero block as well as its seven-byte
transcription. The outputs are only metadata, never the generated
bytes:

| Exact owner-supplied file SHA-256 | Generated bytes | 8-byte historical zero block | 7-byte published suffix |
|---|---:|---:|---:|
| `4daeae51…` (ICD) | 683565 | **0** | **0** |
| `0d5160b1…` (DPLAYERX) | 165888 | **0** | **0** |

A separate local reproduction of the full regeneration and scan
agrees with the calculations; the **updated exact GitHub test
module has not been run in CI**. Negative signature results do
not disprove use of TEA *in a later reconstructed or loaded stage*,
and do not establish which physical original-disc bytes were
ever read by the game.

**Concrete next source requirement:** obtain and verify an
authentic *loaded* DPLAYERX image (including its readable
`.rdata`) or a documented original-CD runtime trace showing
the input blocks to the section decryptor. A 100% PRNG
file is not a DLL that can simply be loaded as PE32 to
read its `.rdata`. The 2000 paper's
`0x008F800A` and `0x00908980` addresses refer
to the author's **loaded runtime**, not to mapped VAs in the
owner's 676,352-byte retail `Rayman2.exe`.

The historical prose also inconsistently calls the repeated
TEA key "32 bytes"; the displayed x86 offsets `+0, +4, +8,
+0xC` use **four DWORDs = 16 bytes**. The paper
lists key `0xC15CF2E5` but once transcribes an inconsistent
little-endian byte string `E5 2F 55 C1` instead of the
consistent `E5 F2 5C C1`. Our historical zero-block vector
tests the repeated-DWORD interpretation, not the inaccurate
prose. Source: [The Twilight of Safedisc, chapter 3.2.3]
(https://www.scribd.com/document/659005728/safedisc).

**Implementation:** new read-only
`scripts/rayman2_historical_tea.py` offers a standard-TEA
single-block candidate decoder and signature scanner, with
`scripts/test_rayman2_historical_tea.py` synthetic inverse,
known-answer, wrong-key and scan tests. No proprietary bytes
or decrypted PE are stored in the repository. This does
**not** replace the generic SafeDisc inspector or establish an
ICD unwrapping algorithm.

To reproduce the algebraic vector without any protected files:

```sh
python scripts/rayman2_historical_tea.py
python -m unittest discover -s scripts -p 'test_rayman2_historical_tea.py'
```

**Still required to connect the historical cipher to the retail
EXE:** a trustworthy decrypted/code-stage reference, including
the *actual* loaded DPLAYERX `.rdata` parameters and the section
bytes being passed to the 8-byte decoder. The opaque CD
`DPLAYERX.DLL` is not itself a normal PE with accessible
`.rdata` on disk; interpreting its first two PRNG words as
the paper's runtime parameters would be an unjustified leap.

## Critical scope correction — retail EXE code is already mostly native, not a proven encrypted bulk payload (13 November 2026)

A new exact-file PE boundary audit changes the **decryption research priority**.
Against the **two SHA-256-locked full PE32 EXEs** supplied by the owner
(original protected CD \`Rayman2.exe\`, separately edited GOG \`Rayman2.exe\`):

| On-disk PE evidence | Verified result |
|---|---:|
| Original retail executable \`.text\` raw bytes | **631,296** |
| Exact corresponding bytes in the executable GOG \`.text\` | **618,027** (97.8981%) |
| Total different code bytes | **13,269** (2.1019%) |
| Differing code bytes replaced with GOG \`INT3\` / \`0xCC\` | **10,851** |
| Other different bytes in active GOG \`.text\` | **2,418** |
| Contiguous changed-byte spans | **102** |
| 4-KiB code pages with any difference | **14 of 155** |
| 4-KiB code pages byte-identical | **141 of 155** |
| Longest continuous unchanged code stretch | **268,900 bytes** |
| Shared PE32 original/GOG entrypoint | **0x0045FCC0** |
| First 16 KiB from entrypoint | **Byte-identical** |
| Shared \`.rdata\` raw bytes | **12,288 / 12,288 identical** |
| Shared \`.data\` | **127 bytes altered** (described below) |

The exact modified executable pages (RVA) are
\`0x1000, 0x2000, 0x5000, 0x47000, 0x48000, 0x49000,
0x4D000, 0x4E000, 0x4F000, 0x50000, 0x51000,
0x67000, 0x70000, 0x7B000\`.
All other executable-code pages in that original 631,296-byte
raw section match **at the same VA**. The two binaries start
at the same native x86 entrypoint; a real disassembly of
the original entrypoint begins with an ordinary \`PUSH EBP;
MOV EBP,ESP\` prologue and subsequent runtime/API calls.

**Independent archival copy check:** GOG's \`.extra\` PE
section is **not marked executable** (PE section
characteristics lack \`IMAGE_SCN_MEM_EXECUTE\`). At
offset **0x1000** inside that section, it contains a
**byte-exact copy of the original retail \`.text\`**,
SHA-256 **\`43ce6eff6082f2c7491cd249d3cfeffbcb56e63313a67246dd2b14f1985751c3\`**,
surrounded by zero padding. This archival copy does
*not* establish that the active GOG code is a pristine
SafeDisc-decrypted retail build; GOG intentionally
changed/removed additional executable logic.

The separately supplied **ICD and \`dplayerx.dll\`**
are both completely reproducible as known masked
Park–Miller pseudo-random streams (see tests below).
Thus **neither supplied opaque file has been
established as carrying a conventionally encrypted
original PE executable image**; their possible roles
as a protection state, key stream, decoy or generated
resource require independent evidence. Do not infer
a decryptable PE payload merely from the filename
\`RAYMAN2.ICD\`.

**What this DOES and DOES NOT prove:** It is strong
negative evidence *against* a simple model in which
the entire on-disk original game \`.text\` is an
unreadable encrypted blob that must first be decrypted.
It does **not** exclude smaller encrypted regions,
post-load transformation, encrypted disc sectors,
checks performed by another module, or functions
whose behavior depends on the original CD and
SafeDisc driver. The exact point or algorithm of
SafeDisc 1.35's protection-stage unwrapping
**remains unidentified**.

**Practical consequence:** stop treating GOG as a
clean "decrypted EXE" oracle. Investigate
only the precisely changed original code islands
and the loading/driver authorization path, and
seek a **same-edition original physical CD/install
or a validated post-load memory observation** before
claiming a portable 1.35 decrypter. In this repository,
\`scripts/rayman2_sample_provenance.py\` now adds a
bounded whole-\`.text\` page-diff diagnostic with exact
sample hashes; \`scripts/test_rayman2_sample_provenance.py\`
has synthetic and optional private-input tests. A separate
independent local audit ran **7/7 tests** on the exact
private PE pair and refused mutated inputs, generating
\`rayman2_binary_boundary_verified_20261113.json\`.
Only hashes, byte counts, RVAs and limitation flags
are reported; no game bytes are redistributed.


## Original SafeDisc-era startup-to-API relay: preserved caller, neutralized GOG callees (13 November 2026)

This is the next **protection-stage** research target following the
whole-PE code boundary audit. The following evidence was verified
byte-for-byte against the owner's **two exact SHA-256-known original
CD and separately modified GOG executable files**, not reconstructed
from the GOG archival \`.extra\` copy.

**Both active executables use the same native startup CALL at
VA 0x00401EFA** into **0x00449360**. The complete **331 bytes at
0x00449360..0x004494AA** are *byte-identical* in the two active
executables; their SHA-256 is
\`508fb5bc006002d4a7efb27d30747ef453b843219f7fadd1f67b471e7ac30448\`.
This initializer seeds a **281-word pseudo-random generator**
at runtime global \`0x00510EA0\`, then prepares a
module-table pointer and dispatches five original
E8-relative CALL instructions.

| CALL instruction VA | Original function VA | GOG active function |
|---|---|---|
| **0x0044947C** | **0x004478A0** | **RET + INT3 padding**; original special \`GetModuleHandleA\` bootstrap |
| **0x00449485** | **0x00448DB0** | **RET + INT3 padding**; original 7-module handle loop |
| **0x0044948E** | **0x00448D80** | **RET + INT3 padding**; original 35 ordinary API descriptor loop |
| **0x0044949A** | **0x00447DE0** | **RET + INT3 padding**; original runtime masked-API-dependent helper |
| **0x0044949F** | **0x00448E30** | Retains its first 42 bytes, then changes original logic at **0x00448E5A** into a short path initializer that writes the character **\`.\`** at global **0x004A6AD8** |

**A new distinction among the disabled callees:** the original
fourth function at **0x00447DE0** is not an
identified ICD decryptor. Its initial five
pointer-presence checks at **0x00447E04**,
**0x00447E11**, **0x00447E1E**,
**0x00447E2B** and **0x00447E38**
use masked API descriptors 19–23. Those
descriptors decode exactly as
\`CreateToolhelp32Snapshot\`, \`Process32First\`,
\`Process32Next\`, \`Module32First\` and
\`Module32Next\`. This directly establishes a
**process/module enumeration dependency**.
It is consistent with environment inspection,
but does **not** by itself establish an
anti-debug verdict, copy-protection challenge,
SafeDisc driver exchange, or decrypted code.
GOG makes the entire function immediately return.
The five descriptor-name matches and their
five original x86 pointer-load instructions are
now verified by the existing diagnostic.

The last two CALLs are behind a branch at **0x00449496**:
they require a nonzero \`EBX\` (the routine's caller-supplied
argument). The first three CALLs are outside that branch.
Original functionality and its exact inferred role must
not be extrapolated from GOG's stubs.

**Independent startup compatibility edit, not decryption:**
at **0x00401D8E**, original retail code calls the Win32
\`GetWindowsDirectoryA\` IAT entry **0x0049C0B4** to
initialize a path, then uses its original
\`/UbiSoft\` and \`/ubi.ini\` strings for the game's
configuration setup. GOG instead stores the literal
character **\`.\`** into the path buffer, jumps
directly to the common path continuation at
**0x00401DEE**, and replaces 88 original bytes
with INT3; GOG also uses backslash variants of
those two path strings. This is evidence of a
Windows installation-directory behavior change,
not a SafeDisc decryption cipher. Both editions
still contain ordinary later code for accessing
a \`ubi.ini\` file.

**Why this helps unwrapping:** the original call chain
from the executable entrypoint to the
\`GetModuleHandleA\` bootstrap, module-handle
acquisition and masked Win32 function resolution
is now explicit and testable. Its **GOG neutralization
is target-specific**, not equivalent to "GOG decrypted
all of the retail executable." It identifies concrete
places to **observe** state in an original legitimate
runtime (module-handle table, pointer descriptors,
callback success) and possible smaller protected
code paths, but neither proves a disk authentication
transaction nor recovers a SafeDisc 1.35 key, decrypted
ICD or post-load game image.

**Reproducibility:** existing
\`scripts/rayman2_trampoline_proof.py\`
now includes \`verify_retained_bootstrap_chain\`
with exact original/GOG SHA verification, six
relative CALL instruction checks, nine shared
generator anchors, four GOG RET/INT3 no-op sites,
and original/GOG startup path modifications.
Companion \`scripts/test_rayman2_trampoline_proof.py\`
has **20 synthetic/optional owner-file test methods**;
the independent full private-file local
audit additionally executed **11/11 passing tests**
and refused SHA-modified inputs. A local metadata-only
JSON report is
\`retail_gog_protection_bootstrap_verified_20261113.json\`.
No proprietary samples are committed and no protected
game binary is executed.


## New four-sample provenance and contemporary Rayman 2-specific study (13 November 2026)

A **full, independent byte-level crosscheck** now links the user's exact
four known Rayman 2 samples to the *GOG release's virtual-CD file inventory*.
Every owner-supplied source is locked by exact SHA-256 before any conclusion.

The **GOG .extra2 virtual-CD manifest**, parsed directly as 3,716
\`(declared_size_u32, filename_length_u32, ASCII_NUL_filename)\` entries
with a \`FFFFFFFF 00000000\` sentinel at offset **139,366**, declares:

| Filename | GOG-declared bytes | Owner file bytes | Match |
|---|---:|---:|---|
| RAYMAN2.EXE | 676,352 | 676,352 | Exact length |
| RAYMAN2.ICD | 683,565 | 683,565 | Exact length |
| DPLAYERX.DLL | 165,888 | 165,888 | Exact length |
| SECDRV.SYS | 14,368 | **not supplied** | Not tested |

Additionally, the entirety of the **631,296-byte protected retail
\`.text\` section** is present, unchanged byte-for-byte, beginning
at **offset 0x1000 inside GOG .extra** (virtual VA \`0x00518000\`).
All bytes before and after this embedded section within the
\`.extra\` raw section are zero padding. This strong lineage/metadata
correlation does **not** authenticate that a file with the same name
and size on the physical original disc contains identical bytes.
The source is specifically **modified GOG**, not original CD ISO.

The same four-reference verifier rechecked that every byte of the
683,565-byte ICD and 165,888-byte DLL follows their previously
reconstructed masked Park–Miller stream; the code generated no game
files and never executed proprietary PE instructions. **Crucial
interpretation correction:** complete PRNG reconstructibility of
these inputs does **NOT** establish that they are inert dummy files,
nor rule out a multi-stage transformation involving on-disk EXE
content or an authenticated CD-dependent key. Static stream structure
cannot settle the processing stage or physical source.

### Historical primary source: The Twilight of Safedisc (25 January 2000)

A contemporary 2000 research paper by **ArthaXerXès**,
[*The Twilight of Safedisc*](https://www.scribd.com/document/659005728/safedisc),
uses **Rayman 2 itself** as its worked example. The author describes
DPLAYERX processing, recovery of reconstructed/decrypted executable
sections **in memory**, separate checks against original CD media,
and additional game-managed CD checks. Because the accessible
historical online transcription has some damaged filename links, its
anecdotal procedures are best treated as technical research leads.

Two independent numeric anchors match the owner's actual protected
on-disk reference exactly:

- Described original entrypoint **0x0045FCC0**: identical to this
  PE32's \`ImageBase+AddressOfEntryPoint\` and on-disk entrypoint
  prologue (\`55 8B EC 6A FF 68 D0 C9 49 00\`).
- Described \`.text\` dump length **0x9A200**: exactly the raw
  section length of the owner's protected PE.

**But the paper's reported code addresses are NOT universally
transferable to our on-disk sample.** For example, it describes
a protection-checking function at **0x004064D0** whose
prologue is different from the actual on-disk code at the same VA,
which begins \`53 8B 5C 24 08 55 8B\`. At
**0x004028FD** its described decrypted checksum code does
not match the current file's actual GUI event-dispatch instructions
(the latter lie inside an x86 instruction at that VA). The
paper explicitly discusses **post-deciphering in-memory sections**,
whereas our file checks are of **protected on-disk bytes**; a
different code stage or an edition/revision difference could explain
these discrepancies. The original retail and GOG **on-disk code is
identical at both these addresses**, so merely comparing the two
available disk EXEs cannot resolve the historical discrepancy. Do **not** infer an actionable patch offset
or unwrapping key from such historical VA matches alone.

Taken together, the historically observed *in-memory decrypted
state* and our *on-disk PRNG streams* suggest a concrete next
experiment: independently establish exactly which bytes and
sections exist before versus after any SafeDisc loader stage,
without inferring the real target from GOG substitutions alone.
No runtime dump of the owner's original CD session is presently
available. We **do not claim to have decrypted SafeDisc 1.35**.

Read-only exact-reference reproduction:

\`\`\`sh
python scripts/rayman2_sample_provenance.py \
  --retail /path/to/original/Rayman2.exe \
  --gog /path/to/GOG/Rayman2.exe \
  --icd /path/to/original/RAYMAN2.ICD \
  --dplayerx /path/to/original/dplayerx.dll

python -m unittest discover -s scripts -p 'test_rayman2_sample_provenance.py'
\`\`\`

**12/12 local Python tests actually passed**, including private
integration with all four SHA-pinned owner files, the complete
GOG manifest and full-stream PRNG regeneration; all synthetic
fixtures contain no commercial bytes. Both GitHub script/test
blob hashes exactly matched the tested local files. No game
run, original CD disc-image verification, Rust compilation,
new GitHub Actions run, unwrapping or PR merge was performed.


## Exhaustive original-vs-GOG data delta: 127 bytes, no changed API descriptors (13 Nov 2026)

A new exact-SHA, read-only audit of **both entire PE32 section byte arrays**,
not just selected opcode sites, accounts for all backed bytes changed in
the shared \`.data\` and \`.rdata\` sections of the user's two samples:

| Item | Verified result |
|---|---:|
| Original and GOG \`.rdata\` (12,288 bytes) | **Byte-identical** |
| Shared \`.data\` backed bytes (31,744 each) | **127 changed** |
| Contiguous edit ranges in \`.data\` | **16** |
| Seven encoded DLL names converted to padded plaintext | **107 changed bytes** |
| Nine path/config string edit ranges | **20 changed bytes** |
| Masked API descriptors (35 × 76 bytes = 2,660 bytes) | **Byte-identical** |
| Original and GOG descriptor SHA-256 | \`69055fdb231a4c88226978030386473a66fa3dc119363914f0c7f19513560a75\` |
| Masked pointer field at offset +0x30 | **35/35 zero on disk in both** |

**Seven changed module-name records** (45 bytes each), beginning at
VA \`0x004A1268\` and separated by stride \`0x2D\`:
\`Kernel32.dll\`, \`User32.dll\`, \`PSAPI.dll\`, \`ADVAPI32.dll\`,
\`GDI32.dll\`, \`VERSION.dll\`, \`WINMM.dll\`.
The retail strings use the additive/XOR encoding; GOG replaces them
with uppercase ASCII names followed by zero padding. The names are
case-insensitively identical (Windows DLL name semantics). The exact
GOG plaintext array therefore changes only *their storage encoding*
and not which seven modules those descriptor records name.

The nine remaining changed ranges are at original-data virtual
addresses: \`0x49F128\`, \`0x49F134\`, \`0x49F396\`,
\`0x49F3A6\`, \`0x49F40C\`, \`0x49F410\` (12 bytes),
\`0x4A06DA\`, \`0x4A2266\`, \`0x4A268A\`. They change
path separators, drive-format text, and shorten an \`Ubi.ini\` path.
Their combined changed-byte count is exactly **20**; seven module-name
regions account for the other **107**. There are no unexplained
data-byte changes in these two shared backed sections.

The **35 masked export-name records** at VA \`0x004A141C\` through
the 35th 76-byte record (last one-based record no. 35) have exactly
the same encoded content, pointer fields and SHA-256 in retail and GOG.
In particular the generated Win32 forwarding stubs and their encoded
name records must not be conflated: GOG modified *how* several APIs
are called in \`.text\`, not the on-disk records containing all 35
names in this specific shared \`.data\`.

**Independent standard PE import inventory:** the two known EXEs
contain the same **163 ordinary imported functions** in the same
seven import DLL groups (USER32 26, GDI32 1, WINMM 4, MSVCRT 70,
KERNEL32 60, SHELL32 1, DINPUT 1). Neither ordinary import table
includes \`DeviceIoControl\`, \`VirtualProtect\` or \`VirtualAlloc\`.
The 35 separately encoded export names also do not include those
three APIs. **Absence from these two inventories is not proof of
runtime non-use**: \`LoadLibraryA\` and \`GetProcAddress\` are
available, the game's other modules and kernel-driver stage were not
instrumented, and dynamically generated API names are possible.
The 35 masked names **do** include file, disk/volume and
process/module enumeration functions, so generic user-mode
inspection capabilities are present on disk.

This is a *static differentiation of the exact original CD versus
modified GOG EXE*, not evidence of an original-CD SafeDisc key,
a safe patch, or any physical CD authorization transaction.

**Tool and validation:** extend existing
\`scripts/rayman2_sample_provenance.py\` with a complete
\`audit_cd_gog_data_changes\` check; reject unexpected byte ranges,
unexpected name encoding, unequal 35-record tables and nonzero
uninitialized pointer slots.
Five additional synthetic tests raised
\`scripts/test_rayman2_sample_provenance.py\` from **12 to 17 tests**.
**All 17 passed in a real local run, including integration on the
four exact private samples**, and both committed Git blobs match the
locally executed scripts byte for byte. No game, CD extraction,
Rust compilation or GitHub Actions execution occurred.


## Source correction — GOG reference is not an original retail no-DRM image

**Owner clarification (13 November 2026):** the 1,468,928-byte
`Rayman2.exe` (SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`)
is supplied by the **GOG release**, **not** a verified reconstruction of
the unmodified original retail executable with only SafeDisc removed.

The comparisons below remain **accurate byte-level observations
between two specific files**, but they **do not identify SafeDisc
patches**. GOG could have introduced unrelated compatibility patches,
code changes, resources, version-specific alterations, installer
metadata, or additional sections; the origin of each change remains
unknown. In particular:

- The 10,851 changed bytes that became `0xCC` (`INT3`) **cannot
  all be attributed to DRM neutralization** without an independent
  call-path proof. The same applies to `0x90` (`NOP`) changes.
- The `.extra`, `.extra2`, and `.rsrc` sections may have been
  introduced or changed by GOG or an earlier third party. Their
  presence **does not establish** the original SafeDisc unpacking
  format or the origin of the embedded manifest.
- The `.extra2` file list of 3,716 entries **is found in the
  GOG executable**. Its filenames and claimed sizes can be
  independently compared to the owner's original disc, but the
  list **must not be presented as a verified original CD manifest**
  without that comparison.

**Required research separation:** "retail protected EXE" is one
input; "GOG executable, DRM-free but potentially otherwise modified"
is a second input. Use the latter as a **comparative reference only**,
not a pristine ground truth, not an automatically valid original
binary, and not a universal no-SafeDisc patch blueprint. Future
work should isolate proven DRM behavior via code-flow analysis
or additional independently verified retail-version evidence.

## New exact section-copy evidence — GOG `.extra` (13 November 2026)

**Strong, fully reproducible byte identity:** The GOG reference's
`.extra` section contains a **100%-identical copy of the protected
retail `.text` section** (631,296 bytes), starting at offset
`0x1000` *within the GOG `.extra` section*.

| Property | Exact result |
|---|---|
| Source | Protected CD `.text`, RVA `0x1000`, length **631,296** |
| Destination | GOG `.extra`, section-relative offset **`0x1000`** |
| Destination file offset | **`0xA7C00`** |
| Destination RVA / VA | **`0x118000` / `0x00518000`** |
| Matching bytes | **631,296 / 631,296 (100%)** |
| SHA-256 of both code blocks | `43ce6eff6082f2c7491cd249d3cfeffbcb56e63313a67246dd2b14f1985751c3` |
| Before the copied block | **4,096 zero bytes** |
| After the copied block | **3,584 zero bytes** |
| GOG `.extra` PE characteristics | **`0x40000040`**: initialized, readable, **not marked executable** |

The exact equality is stronger than coincidental x86 disassembly:
**the supposed "new code" at GOG VA `0x00518000` is precisely
the unchanged protected CD code copied elsewhere.** In particular,
disassembly there **must not** be described as newly written GOG
routines or a verified SafeDisc relocation. It is a byte-for-byte
embedded copy with zero padding.

We do **not know why** the GOG executable retains that copy.
The non-executable section-header flag does not absolutely prohibit
later runtime permission changes, so no claim of execution or
non-execution is made. The original protected code contains
absolute addresses; merely finding the same bytes at a different
RVA is not proof that they can execute unmodified.

The generic read-only Python tool `scripts/pe_reference_diff.py`
now automatically finds such **full, nontrivial, cross-section byte
copies**, reporting offsets, SHA-256, zero padding and PE
section characteristics. Its synthetic tests require full byte
identity and reject one-bit changes and constant filler.
**No proprietary bytes** are embedded in the tool or tests.

This changes the research priority: compare the **GOG-modified
`.text`** against both the **original protected `.text`** and
the identical preserved copy in `.extra`. Attribute individual
edits to SafeDisc, GOG compatibility changes or other modifications
**only when justified by control-flow or independent provenance
evidence**. Do not generate a retail deprotection patch by blindly
replaying the GOG differences.

## Direct protected / unprotected PE32 comparison (13 November 2026)

The owner previously supplied a **GOG edition (DRM-free, potentially otherwise modified)**
`Rayman2.exe` (**1,468,928 bytes**, SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).
This SHA-256 is also recorded as the approved GOG-derived runtime in
[Rayman2Fix architecture](https://github.com/legluondunet/Rayman2Fix/blob/main/docs/architecture.md).
The protected source `Rayman2.exe` is **676,352 bytes**, SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
**Both exact user-owned files were analyzed read-only.**

Their PE32 entry RVA **`0x5FCC0`**, image base **`0x400000`**,
import data-directory RVA **`0x9D0D8`** and export data-directory
RVA **`0x9DDD0`** agree. The protected EXE is **not** merely an
empty launcher: much of the original game code is present already.

**Compare section contents at matching virtual RVAs**, not at file
offsets: the protected `.text` begins at raw offset `0x400`,
whereas the GOG reference begins at raw offset `0x1000`.
A naive file-position byte comparison misleadingly reports massive
differences. Correctly aligned by RVA:

| Shared section | Compared backed bytes | Identical bytes | Identity | Changed bytes |
|---|---:|---:|---:|---:|
| `.text` (RVA `0x1000`) | 631,296 | 618,027 | **97.8981%** | 13,269 |
| `.rdata` (RVA `0x9C000`) | 12,288 | 12,288 | **100%** | 0 |
| `.data` (RVA `0x9F000`) | 31,744 | 31,617 | **99.5999%** | 127 |

**Control-flow neutralization pattern:** among the **13,269**
changed backed bytes in shared `.text`, **10,851 bytes** are
replaced by `0xCC` (`INT3`) and **1,520 bytes** are replaced by
`0x90` (`NOP`). A large original code range beginning at
RVA `0x474B0` is filled with `INT3` in the GOG reference.
This strongly indicates intentional invalidation/neutralization of
some original code paths, **not** necessarily the exact SafeDisc
module boundary, and does not by itself provide safe code relocation.

**Corrected interpretation of `0x00518000`:** this address
marks the start of the exact, **unchanged 631,296-byte protected
`.text` copy embedded in GOG `.extra`**, not newly discovered
GOG-written code. A disassembler naturally sees x86 instructions
because these are identical to the protected code. The containing
section is flagged read-only data and is not marked executable.
No execution path or SafeDisc patch intent is inferred.
No additional proprietary code is committed.

The `.text` byte changes occupy **14** distinct 4-KiB virtual pages,
with the largest concentrations in page ranges near RVAs
`0x47000`, `0x48000` and `0x4E000`. Changed-byte addresses
and density are diagnostics only: they are **not** automatically
identified as SafeDisc routines. The GOG reference has
three additional sections:

| Additional section | RVA | Backed length | Remark |
|---|---:|---:|---|
| `.extra` | `0x117000` | 638,976 | Purpose not established |
| `.extra2` | `0x1B3000` | 143,360 | Begins with a size/name-length file inventory |
| `.rsrc` | `0x1D6000` | 3,584 | PE resource section, absent from the protected EXE |

The GOG EXE's PE resource data directory is nonzero; the
protected counterpart has no ordinary resource directory. These
differences **do not establish how the unprotected EXE was produced**
or imply a general-purpose SafeDisc 1.35 decoding method.

### Bootstrap guard `0x5113EC`: precise static branches and bounded xrefs

An independent read-only linear-disassembly scan of the two
SHA-256-matched executables refines the unresolved bootstrap path:

1. Both builds call `0x449360` from `0x401EFA`.
2. `0x449366` reads the DWORD at **`0x5113EC`**, a
   **virtual zero-filled** `.data` location (not a file-backed value).
3. `0x449370` branches to `0x44938D` **if that DWORD is zero**,
   entering the normal body. With a **nonzero** value, the alternate
   path stores `0x44938D` at `0x510DC8` and `0x4494A4`
   at `0x510C08`, then returns at `0x44938C` without calling
   the preparation functions.
4. In the normal body, the nonzero argument supplied by the
   startup `PUSH 1` selects `0x4493F8`; the subsequent
   `CALL` instructions are identical in the two executables,
   even though the GOG callees are return stubs.

The existing generic `descriptor_asm_xrefs.py` scanner was
run against independent `objdump -d -M intel` listings,
treating `0x5113EC` as **one watched address**, not a
descriptor-array entry:

```sh
python scripts/descriptor_asm_xrefs.py \
  --objdump retail-objdump.txt \
  --base 0x5113ec --stride 4 --count 1 --slot-offset 0

python scripts/descriptor_asm_xrefs.py \
  --objdump gog-objdump.txt \
  --base 0x5113ec --stride 4 --count 1 --slot-offset 0
```

| Linear-disassembly reference class | Retail-CD `.text` | GOG `.text` |
|---|---:|---:|
| Direct absolute-address reads/comparisons | **28** | **16** |
| Direct absolute-address candidate writes | **0** | **0** |
| Address-only literal uses | **0** | **0** |

**This is *not* a proof that the guard is always zero.**
The scan cannot see computed-address stores, generated
instructions, loader-time patching or other memory writers.
The first-run value must be established by observing a
real Windows/Wine process or proving every prior
write path; no execution was performed here.

### Hardened PE reference-file ingestion

The generic `pe_reference_diff.py` reader no longer
trusts just a pathname `stat()` followed by an
unbounded reopen. It now opens each candidate through
`os.open()` with `O_NOFOLLOW` on supporting platforms,
checks **the opened descriptor** for regular-file type
and the 16 MiB limit, compares device/inode against
pre-open metadata, reads at most **16 MiB + 1 byte**,
and checks size/mtime again after reading.
These checks are best effort, not an atomic snapshot
against a malicious concurrent writer.

Two synthetic GitHub regression tests cover
oversized/symlink paths and replacement between
stat/open. In a separate local reproduction of
the new reader, **5/5 checks passed**, including
reading the owner's two actual EXEs to their
preverified SHA-256, symlinks, sparse oversize
and a deterministic replacement simulation.
The entire exact GitHub Python suite has **not
been run in this environment**.

### GOG-provided CD-ROM information callbacks (13 Nov 2026)

A direct read-only inspection of the SHA-256-pinned **GOG reference**
(`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`)
reveals three **hardcoded Win32-compatible media-information
callbacks**, wired to the callback initializer at `0x00467130`.
These functions are **not** inferred from SafeDisc decoder output.

| Dispatch slot | GOG installer VA | GOG callback | Static operation |
|---|---|---|---|
| `+0x10` | `0x0046717C` / `0x00467182` | `0x00448EC4` | `MOV EAX,5; RET 4`: drive type **`DRIVE_CDROM`** |
| `+0x28` | `0x0046718C` / `0x00467191` | `0x00448E6C` | Fills volume information outputs then `RET 0x20` |
| `+0x0C` | `0x0046719B` / `0x004671A0` | `0x00448ED0` | Fills disk geometry outputs then `RET 0x14` |

The first returns `5`, the documented **`DRIVE_CDROM`**
code of [Microsoft `GetDriveTypeA`]
(https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea).
The second matches the output-argument layout and stack
cleanup of [`GetVolumeInformationA`]
(https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa):

| Volume output | Hardcoded value |
|---|---|
| Volume name | **`RAYMAN2`**, NUL-terminated |
| File-system name | **`CDFS`**, NUL-terminated |
| Serial number | `0x6D380AE8` |
| Maximum filename component | `110` |
| File-system flags | `5` |
| Return value | `TRUE` (EAX = 1) |

The third matches the four output fields and one input of
[`GetDiskFreeSpaceA`]
(https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespacea):

| Disk geometry output | Hardcoded value |
|---|---:|
| Sectors per cluster | **1** |
| Bytes per sector | **2,048** |
| Free clusters | **0** |
| Total clusters | **332,400** |
| Return value | **TRUE** (EAX = 1) |

These parameters imply **680,755,200 bytes (649.22 MiB)**
of *reported* storage geometry: a plausible CD-sized
volume. This is not a measurement of the original
CD's actual ISO capacity, and is entirely distinct
from the 7.45 GB of *claimed individual file lengths*
in the GOG embedded inventory.

**Evidence quality:** these precise constants,
instruction byte patterns, callback-table stores,
and original GOG SHA-256 were verified locally
using the owner-supplied executable without
executing it. The results are saved as a
JSON report. The correspondence to these Win32
APIs is based on their exact argument/output
layouts and Microsoft documentation; the
**actual call through each callback has not
been observed**.

This is stronger static evidence that **GOG
virtualizes an expected CD-ROM environment**
(including CD drive type, volume label and
disk size) to accommodate the game without
requiring the original physical disc. It
does **not** show whether a particular edit
was introduced by GOG itself versus an
earlier third-party patch, nor does it
identify a generally applicable SafeDisc
1.35 decryption mechanism.

### All sixteen callbacks assigned by GOG `0x00467130`

A second independent read-only scan of the *same hash-pinned*
GOG executable reconstructed **all 16 assignments**
to the game-level callback table between
`0x00467130` and `0x00467205`.
The scan identifies x86 `MOV reg,imm32`,
`MOV [EAX+offset],reg`, and immediate
`MOV [EAX+offset],imm32` instructions in
this narrow, separately disassembled range.

| Table offset | Stored value or source | Known static role |
|---|---|---|
| `+0x00` | `0x00448F08` | constant-return callback |
| `+0x04` | `0x00467050` | other GOG function, PRNG code present |
| `+0x08` | `0x00448F60` | filename lookup in GOG `.extra2` |
| `+0x0C` | `0x00448ED0` | disk-free-space geometry callback |
| `+0x10` | `0x00448EC4` | `DRIVE_CDROM = 5` callback |
| `+0x14` | `0x00448F08` | same callback as `+0x00` |
| `+0x18` | `0x0045FEBC` | function, detailed role unverified |
| `+0x1C` | `0x00449010` | callback invoking filename/size lookup |
| `+0x20` | `0x00448FD0` | lookup of declared file size by index |
| `+0x24` | `0x00448F18` | function, detailed role unverified |
| `+0x28` | `0x00448E6C` | volume label `RAYMAN2` and `CDFS` |
| `+0x2C` | `0x00448DE0` | returns 1 in GOG |
| `+0x30` | `0x00448AB0` | function, detailed role unverified |
| `+0x34` | **DWORD loaded from `[0x0049C0C8]`** | live IAT pointer, **not a fixed function VA** |
| `+0x38` | `0x00448F00` | constant-return callback |
| `+0x3C` | `0x00448F10` | constant-return callback |

This provides a **complete static assignment map:
15 literal function addresses and one runtime-loaded
import pointer**, all sixteen 4-byte slots from
`+0x00` to `+0x3C` accounted for.
The extraction tool and the resulting metadata-only
JSON were locally checked against the original
GOG SHA-256. The one IAT-fed slot must **not**
be represented as a constant target address.

The reproducible **generic** read-only parser
[`scripts/pe_callback_table_map.py`](../scripts/pe_callback_table_map.py)
was added to the research branch. It requires a narrowly
specified VA interval and recognizes only simple
`MOV`/register-to-slot assignments in existing
`objdump -d -M intel` text. It distinguishes
**literal targets** from **pointers loaded from an
import slot**, refuses missing or duplicate callback
entries, and labels its output **candidate assignments**,
not verified runtime execution.

```sh
objdump -d -M intel Rayman2-GOG.exe > gog-disasm.txt
python scripts/pe_callback_table_map.py \
  --objdump gog-disasm.txt \
  --start-va 0x467130 --end-va 0x467206 \
  --expected-slots 16
python -m unittest discover -s scripts \
  -p 'test_pe_callback_table_map.py'
```

The parser's **five synthetic tests** passed locally,
as did the real-file 16-slot validation using the
previously generated GOG disassembly (15 literal
assignments and one imported-pointer assignment).
**The exact GitHub version has not run in CI**.
Do not use this narrow parser as a general-purpose
x86 disassembler.

The table combines file lookups, volume/drive
metadata and other callbacks. Its structure
supports a **GOG-specific replacement of
several original CD-related Win32 operations**,
but is not proof that every callback executes,
that every listed function has been accurately
identified, or that all differences are SafeDisc
removal rather than game-compatibility changes.

### Startup path: unchanged caller, GOG return stubs (13 Nov 2026)

**New, independently measured evidence from both owner-supplied
SHA-256-pinned PE32 files.** The startup sequence from the
retail CD is not simply removed in GOG:

- `0x00401EF8`–`0x00401F00` (9 bytes): **identical**
  `PUSH 1; CALL 0x00449360; ADD ESP,4`.
- `0x00449360`–`0x004494AA` (**331 bytes**):
  **completely identical** in protected retail and GOG.
  The shared body includes `CALL` instructions at
  `0x44947C`, `0x449485`, `0x44948E`,
  `0x44949A` and `0x44949F`.
- GOG substitutes **safe early-return stubs at the
  *called functions***, rather than removing
  those `CALL` instructions:

| Function VA | Protected CD | Exact GOG entry bytes | Static result |
|---|---|---|---|
| `0x4478A0` | Module preparation | `C3` | immediate `RET` |
| `0x448DB0` | Module iteration | `C3` | immediate `RET` |
| `0x448D80` | 1–35 API descriptor iteration | `C3` | immediate `RET` |
| `0x447DE0` | Auxiliary routine | `C3` | immediate `RET` |
| `0x448DE0` | Another auxiliary routine | `33 C0 40 C3` | `XOR EAX,EAX; INC EAX; RET` (returns 1) |

This **resolves the apparent conflict** noted in the prior
research: GOG retains calls from `0x449360` into
functions whose **bodies** were otherwise filled
with `INT3`, but preserves a one-byte `RET`
at the three iteration function **entrypoints**.
Such calls can return without entering the
`INT3` padding. An unconditional claim
that those retained calls immediately crash
would therefore be **incorrect**.

At `0x448E30`, the function's common prefix
remains largely unchanged, but its branch at
`0x448E5A` is different: GOG executes
`MOV AL,0x2E; MOV [0x004A6AD8],AL`, then
restores the frame and returns. The retail
branch instead continues through the
PRNG-based generated-stub construction.
Neither file was executed during this analysis.

#### Distinguish file-backed and virtual-zero-fill globals

Both PE files declare `.data` with
**RVA `0x9F000`, virtual size `0x776D0`,
raw backed length `0x7C00`**. Thus:

| Virtual address | Storage at PE load | Research role |
|---|---|---|
| `0x004A141C` | file-backed `.data` | encoded descriptor records |
| `0x00510EA0` | **virtual zero-fill `.data` tail** | scratch area used for generated stubs |
| `0x005113E8` | **virtual zero-fill `.data` tail** | module iteration bound |
| `0x005113EC` | **virtual zero-fill `.data` tail** | branch/initialization state flag |
| `0x005113F0` | **virtual zero-fill `.data` tail** | API iteration bound |

The four addresses in the virtual tail do not
have file-backed initial DWORDs. On a normal PE
image load that virtual tail begins as zero
fill, but subsequent code can write to it.
**A file-only scan cannot determine the value of
`0x5113EC` when `0x449360` actually runs.**
Do not equate `no file-backed value` with
`always zero at runtime`.

The generic PE comparison script now provides
`--entry-va VA` to classify tiny entrypoint
stubs and `--map-va VA` to distinguish
file-backed data from an initialized-on-load
virtual tail. These classify stored bytes
without executing the game or attributing
the changes to SafeDisc alone.

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --entry-va 0x4478a0 --entry-va 0x448db0 \
  --entry-va 0x448d80 --entry-va 0x447de0 \
  --entry-va 0x448de0 \
  --map-va 0x4a141c --map-va 0x510ea0 \
  --map-va 0x5113e8 --map-va 0x5113ec \
  --map-va 0x5113f0 \
  --code-span 0x401ef8:9 \
  --code-span 0x449360:331 \
  --code-span 0x448e5a:10
```

Seven new synthetic tests for entrypoint stubs
and PE virtual-zero-fill mapping have been
added to GitHub. Their exact new repository
versions **have not been run in Rust or GitHub
Actions**; the local independent byte-level
verification of both original binaries passed.

### Follow-up audit: GOG neutralizes retail export-resolution code (13 Nov 2026)

**The user has established that the reference is a GOG build, not
pristine retail with SafeDisc alone removed.** Independent comparison
of the two exact SHA-256-verified files by **virtual address** shows
that GOG physically replaced the following original retail
functions with full ranges of `0xCC` / x86 `INT3`:

| Original retail routine VA range | Retail function | GOG bytes |
|---|---|---|
| `0x004474D0`–`0x00447539` (106 bytes) | Decode obfuscated module/DLL name | **106/106 `INT3`** |
| `0x00447730`–`0x00447894` (357 bytes) | Match obfuscated API name to a module export | **357/357 `INT3`** |
| `0x00447AF0`–`0x00447BD8` (233 bytes) | Resolve export and store XOR-masked pointer | **233/233 `INT3`** |
| `0x00448D80`–`0x00448DA9` (42 bytes) | Iterate API descriptors 1–35 | **`RET` at entry plus 41 `INT3` bytes** |
| `0x004493F8`–`0x004494A9` (178 bytes) | Shared initialization sequence | **178/178 identical** |

**Important control-flow limitation:** The preserved initialization
sequence still contains direct call instructions targeting the
disabled routines. These are **file-level facts**, not evidence that
the calls are actually reached on GOG. The GOG path may bypass the
initialization or redirect control before those calls. Static
byte identity cannot settle reachability; runtime tracing on a
supported, owner-controlled installation is needed before claiming a
crash, execution or bypass.

These observations also explain why GOG's seven plaintext module
names cannot be used as proof that its *original* encoded-name
decoder runs: that decoder is entirely overwritten with `INT3`.
The decoded export names remain verifiable from the retail copy.
The masked import mechanism described below applies to the
**retail original**, not as an automatically usable GOG runtime
implementation.

#### Two GOG references to the preserved code-image section

The two known GOG literal references to the non-executable
`.extra` section base `0x00517000` replace specific
PRNG-based dispatch calculations at their respective VAs:

| GOG instruction VA | GOG bytes / meaning | Retail bytes / meaning |
|---|---|---|
| `0x00470051` | `MOV EAX,0x00517000` then `JMP 0x004700B3` | `CDQ; MOV ECX,0x455; IDIV ECX` |
| `0x0047B1C3` | `MOV EAX,0x00517000` then `JMP 0x0047B225` | Same kind of `CDQ; MOV ECX,0x455; IDIV ECX` |

In both sites, a **fixed pointer to the beginning of the GOG
`.extra` section** replaces the retail calculated value and
an unconditional short branch skips over part of the
original dynamic-stub construction code.

This establishes **literal pointer flow into the remainder of the
GOG routines**, not that the `.extra` bytes execute. Recall that
`.extra` consists of a 4096-byte zero prefix, the exact
631296-byte retail `.text` copy, and a 3584-byte zero suffix,
and its section header does **not** mark it executable.
The address `0x00517000` points at the **prefix**, while the
copied code starts at `0x00518000`. Do not confuse them.

#### Generic read-only regression aid

The PE comparator now offers repeatable `--code-span VA:LENGTH`
to compute exact backed-byte identity, INT3/NOP replacements,
and per-span hashes while **explicitly declining to attribute
them to SafeDisc**.

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --code-span 0x4474d0:106 \
  --code-span 0x447730:357 \
  --code-span 0x447af0:233 \
  --code-span 0x448d80:42 \
  --code-span 0x4493f8:178 \
  --code-span 0x470051:8 \
  --code-span 0x47b1c3:8
```

Four synthetic regression tests have been added for complete
`INT3` ranges, partial NOP changes, invalid/unbacked
regions, and read-only JSON metadata. Independent local checks
of the same algorithm against the two owner-provided inputs
validated all seven spans. **This is not a claim of full
runtime disassembly, a native SafeDisc decoder, or an executed
Rust build.** GitHub Actions have not been invoked.

### Major update: static writer and export-name resolver recovered

**13 November 2026, independent static audit of the SHA-256-verified
retail CD executable.** The former question about who writes the
descriptor `+0x30` fields is **resolved at the instruction level**.

**Exact write mechanism:** function `0x00447AF0`, called with
a one-based descriptor index `i`, computes:

```text
ESI = 76 * i
destination = 0x004A1400 + ESI
            = 0x004A141C + 76*(i-1) + 0x30
```

When a nonzero function address is obtained, the routine uses:

```asm
447BC0: xor ebx,eax                    ; mask XOR resolved export VA
447BC2: mov [esi+0x004A1400],ebx       ; store masked callback
```

When a function lookup fails, the branch at `0x00447BCD`
can instead write **zero** into the same destination.
Thus the paired callsite `stored XOR mask` recovers the
previously resolved function pointer **if resolution succeeded**.
No code is executed and no runtime address was observed during
this audit.

**Call chain, conditional initialization path:**

- `0x004493FA` sets the **module count to 7**
  (global `0x005113E8`).
- `0x00449404` sets the descriptor iteration bound to
  **36** (`0x24`, global `0x005113F0`) in the nonzero-argument
  branch of the initialization routine.
- `0x0044947C` calls module preparation `0x004478A0`.
- `0x00449485` calls `0x00448DB0` to walk module indices.
- `0x0044948E` calls `0x00448D80`, which iterates
  **descriptor indices 1 through 35** and invokes
  `0x00447AF0` at `0x00448D96`.
- Two additional direct `0x00447AF0` calls at
  `0x00448196` and `0x004481A2` explicitly
  reference descriptor indices **24 and 25**.

This **establishes a static writer and its initialization
loop**; it supersedes older statements that the writer's
identity was unknown. It does **not** prove this path
always executes under Windows/Wine, that every export is
found, or that all 35 fields become nonzero.

#### The names are obfuscated, not absent

The static routines `0x004474D0` (module-name
construction) and `0x00447730` (export-name
comparison) reveal a simple per-character encoding in
the protected on-disk descriptors:

```text
key_sub, key_xor, increment_sub, increment_xor = record[0..4]
name_length = record[4]
for each encoded character:
    plain = ((encoded - key_sub) mod 256) XOR key_xor
    key_sub = (key_sub + increment_sub) mod 256
    key_xor = (key_xor + increment_xor) mod 256
```

This is **name obfuscation**, not evidence of a SafeDisc
cipher for the actual executable or files on the CD.

The seven decoded module records (`0x004A1268`,
stride **45 bytes**) are:

```text
0 KERNEL32.dll
1 USER32.dll
2 PSAPI.dll
3 ADVAPI32.dll
4 GDI32.dll
5 VERSION.dll
6 WINMM.dll
```

The **35 API names** in the 76-byte records starting
at `0x004A141C` were all decoded and are associated
with module indices stored at record offset `+0x34`:
**33 names target KERNEL32.dll and two target
PSAPI.dll** (`EnumProcesses`, `EnumProcessModules`).
The remaining five module names may be used through
other paths and are not evidence of 35 different
loaded libraries.

Representative decoded exports:

| One-based record | Module | Exact decoded export name |
|---|---|---|
| 1 | KERNEL32 | `FlushInstructionCache` |
| 8 | KERNEL32 | `CreateFileA` |
| 10 | KERNEL32 | `ReadFile` |
| 18 | KERNEL32 | `GetFileSize` |
| 24 | PSAPI | `EnumProcesses` |
| 25 | PSAPI | `EnumProcessModules` |
| 35 | KERNEL32 | `GetLogicalDrives` |

One descriptor spells `FlushFileBuffer` (singular);
the standard documented Win32 API is
[`FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
**Do not silently change the decoded name.** This
possible deliberately unresolved or variant-specific
symbol requires checking actual exported names and
runtime outcome before any repair.

#### GOG changes the module-name storage separately

In the hash-identified **GOG** executable, the
seven records at the same module-table VAs contain
**plaintext uppercase NUL-terminated DLL names with
zero padding**, whereas the retail CD stores
the obfuscated names. The **35 API descriptors
themselves remain byte-identical**, including their
encoded export names and zero on-disk pointer slots.
Thus GOG's changes distinguish the **DLL naming /
module loading layer** from the still-encoded
Windows export-name descriptor layer.
Do not infer GOG's original rationale or assume it
only disabled SafeDisc.

#### Static cross-reference limits

A scan of the *linearly disassembled retail `.text`*
for exact absolute VAs of all 35 descriptor slots
(`+0x30`) found **97 rendered direct memory reads**,
**30 immediate/address-literal uses** and **no
direct absolute writes**. There were references
to **24 of the 35** slots. These counts are
**not a complete call graph** and do not preclude
indirect writes. In fact the indexed
`mov [esi+0x004A1400],ebx` at `0x00447BC2`
**is the confirmed indirect write** missed by
a direct-VA scan. This demonstrates why a
zero direct-write count is not a negative
result about actual runtime initialization.

Reproduce offline:

```sh
python scripts/pe_masked_api_inventory.py Rayman2-CD-protected.exe \
  --module-base 0x4a1268 --module-stride 45 --module-count 7 \
  --api-base 0x4a141c --api-stride 76 --api-count 35 \
  --module-selector-offset 0x34 --pointer-slot-offset 0x30

# GOG: use same API descriptor layout, but plain module-name records
python scripts/pe_masked_api_inventory.py Rayman2-GOG.exe \
  --module-mode plain \
  --module-base 0x4a1268 --module-stride 45 --module-count 7 \
  --api-base 0x4a141c --api-stride 76 --api-count 35 \
  --module-selector-offset 0x34 --pointer-slot-offset 0x30

objdump -d -M intel Rayman2-CD-protected.exe > retail-disasm.txt
python scripts/descriptor_asm_xrefs.py \
  --objdump retail-disasm.txt \
  --base 0x4a141c --stride 0x4c --count 35 --slot-offset 0x30
```

These standard-library-only, **read-only** diagnostic
tools do not execute or patch the protected EXE.
They ship with **eight synthetic name decoder
tests and four synthetic xref tests**.
Locally, both original SHA-256-pinned executables
decoded to the **same 35 API names** and
**same seven module names (ignoring case)**.
The disassembly scan was reproduced on the
retail protected file, and all **12 new
synthetic tests passed**.

### Retail masked-call descriptor array: 35 active records, 76-byte stride

A new file-backed-data audit found a **regular, byte-identical
structure in both SHA-256-verified executables**:

| Property | Observed value |
|---|---|
| Base VA | `0x004A141C` in `.data` |
| Record stride | **`0x4C` bytes (76 bytes)** |
| Nonzero-initialized records | **35** (indices 0–34) |
| Following all-zero record | index **35** (`0x004A1E80`) |
| Total compared range | **36 × 76 = 2,736 bytes** |
| SHA-256 of full range in **both** files | `f4a498cafd1b76536b3367c27b5fc6142b918ecc4525cadb0c2df4c8f2951cd5` |
| First DWORD `+0x00` | nonzero and unique in each of 35 active records |
| DWORD `+0x30` | **zero for all 36 records** |
| Original-CD vs GOG | **2,736/2,736 bytes identical** |

The 35 entries followed by one all-zero record are
**consistent with an array of fixed-size descriptors plus a
sentinel-like terminator**, but the full field semantics are
not yet proven. In particular, the `+0x30` field is a
**zero-initialized location on disk**, not a demonstrated
runtime-resolved callback pointer.

The 12 masked callback-table stores in the **retail
`0x00467130` initializer** all reference record pairs with
this exact geometry:

```text
mask_or_first_field = 0x004A141C + (index * 0x4C)
other_field         = mask_or_first_field + 0x30
computed_from_file  = [other_field] XOR [mask_or_first_field]
```

Representative callback-table slots:

| Callback offset | Record index | First field VA | `+0x30` field VA |
|---|---:|---|---|
| `+0x08` | **7** | `0x004A1630` | `0x004A1660` |
| `+0x1C` | **30** | `0x004A1D04` | `0x004A1D34` |
| `+0x20` | **17** | `0x004A1928` | `0x004A1958` |

On disk, each `+0x30` value is zero, and the first
DWORD is not a valid directly callable GOG pointer. **No
runtime-resolved pointer is implied by a direct XOR of
these original file bytes.** The unchanged 2,736-byte
descriptor block also proves that **GOG did not
change this table on disk**, even though GOG modified
the callback initializer to install several literal
functions instead.

#### Explicit x86 stub construction in the retail EXE

A distinct protected-only code path at `0x0044F28C`
writes an executable-style 13-byte sequence into a
PRNG-offset scratch buffer:

```asm
A1 60 16 4A 00       ; mov eax, [0x004A1660]
33 05 30 16 4A 00    ; xor eax, [0x004A1630]
FF E0                ; jmp eax
```

The 13 bytes are **constructed at runtime**, not a
contiguous block of instructions present in the
retail EXE file. The code writes the opcode bytes
and operands separately at `0x0044F28C`–`0x0044F2A9`,
then performs indirect dispatch at `0x0044F2FA`.
Similar dynamic-stub construction appears around
`0x0044DED2` and `0x00450B42`.

This connects the regular descriptor array to actual
**masked indirect control-flow construction** in the
protected game code. The **static writer, address
calculation, module/export lookup and 1..35
initialization loop are now described above**.
However, successful runtime resolution and actual
addresses under Windows or Wine have **not** been
observed, and this is **not proof that all 35
records correspond to independent SafeDisc callbacks**.

#### Repeat the comparisons without patching either EXE

The generic read-only `pe_reference_diff.py` CLI now
accepts `--descriptor-layout BASE:STRIDE:COUNT:MASK_OFFSET:SLOT_OFFSET`
and repeatable `--masked-pair FIRST:SECOND`. It uses
file-backed PE virtual addresses, checks bounds, and
labels its results **on-disk observations only**:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --descriptor-layout 0x4a141c:0x4c:36:0:0x30 \
  --masked-pair 0x4a1660:0x4a1630 \
  --masked-pair 0x4a1d34:0x4a1d04 \
  --masked-pair 0x4a1958:0x4a1928
```

Four additional synthetic tests check complete-record
comparisons despite differing raw PE offsets, a single
changed record, invalid/unbacked ranges and CLI JSON
safety. A separate local inspection of the owner's
actual SHA-256-pinned binaries confirms the **35+1
record structure and full 2,736-byte identity**.

### Independent GOG CD-ROM API shims: volume, drive type and free space (13 Nov 2026)

A further **read-only x86 disassembly**, with both input SHA-256
values rechecked, identifies three more GOG-installed callback
functions besides the previously documented manifest-name and
manifest-size handlers. These are **static compatibility shims**
that return preset optical-disc properties; they **do not prove**
that a drive is contacted, nor authenticate the original CD
volume or geometry.

| GOG initializer VA | Callback-table slot | Installed function VA | Observed static result |
|---|---|---|---|
| `0x46718C` / store `0x467191` | `+0x28` | `0x448E6C` | Volume-information-style shim |
| `0x46717C` / store `0x467182` | `+0x10` | `0x448EC4` | Drive-type-style shim |
| `0x46719B` / store `0x4671A0` | `+0x0C` | `0x448ED0` | Disk-free-space-style shim |

The corresponding function bodies have **fixed literal results**:

- `0x448E6C` (volume information): when optional output
  pointers are non-null, it writes volume label **`RAYMAN2`**,
  filesystem **`CDFS`**, filesystem flags **`5`**,
  maximum component length **`110`**, and volume serial
  **`0x6D380AE8`**. It returns **success (1)** and ends
  with `RET 0x20`.
- `0x448EC4`: `MOV EAX,5; RET 4`, returning the Win32
  **`DRIVE_CDROM`** drive-type constant.
- `0x448ED0`: fills disk geometry output pointers with
  **1 sector/cluster**, **2,048 bytes/sector**, **0 free
  clusters**, **332,400 total clusters**, and returns **1**.
  This corresponds to a *claimed* total of 680,755,200 bytes.
  It is a hardcoded API response, **not** a measurement of
  the owner's physical CD or its ISO extents.

These 32-bit x86 instructions and the initializer's
`MOV reg, immediate` / `MOV [table+offset], reg`
pairs were independently checked against the
GOG PE by GNU binutils. A local read-only verification
script checks the exact opcode/immediate patterns and
the pairings without executing GOG or the retail EXE.

This strengthens the explanation of **GOG's disc-less
compatibility layer**: one dispatch table contains
filename and declared-file-size lookups **and**
optical-media information shims. It does **not**
demonstrate that these functions are invoked at
runtime, that their behavior is sufficient by
itself to bypass SafeDisc, or that the results
describe the original CD faithfully. Avoid
transplanting GOG-specific values into the
generic retail SafeDisc unwrap.

The existing general-purpose RVA comparison tool
can collect candidate function pointer references:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --trace-va 0x448E6C \
  --trace-va 0x448EC4 \
  --trace-va 0x448ED0 \
  --code-span 0x448E6C:84 \
  --code-span 0x448EC4:8 \
  --code-span 0x448ED0:47
```

### Dispatch-table linkage: GOG filename/size routines are assigned to game callbacks

A follow-up read-only **two-binary disassembly and byte comparison**
establishes a much stronger static link than literal references alone.

**At identical virtual address `0x00467130`**, both the retail-CD
protected EXE and the GOG reference implement a callback-table
initializer. **Two direct `CALL rel32` instructions to that same
initializer are byte-identical in both files**:

- `0x004674C8`: `CALL 0x00467130`, passing a stack-resident
  callback table.
- `0x0047B01B`: `CALL 0x00467130`, passing a second stack-resident
  callback table.

The **GOG initializer** stores explicit code addresses into the
table at several offsets. The two connections to the file-list
functions are particularly clear:

| Callback-table offset | GOG initializer instruction | Target |
|---|---|---|
| `+0x08` | `0x00467151: MOV EDX, 0x00448F60`, then `MOV [EAX+8], EDX` | Manifest filename lookup at `0x00448F60` |
| `+0x1C` | `0x00467160: MOV ECX, 0x00449010`, then `MOV [EAX+0x1C], ECX` | A GOG callback which invokes the size lookup |
| `+0x20` | `0x004671DF: MOV EDX, 0x00448FD0`, followed by `MOV [EAX+0x20], EDX` at `0x004671FB` | Manifest index-to-size lookup at `0x00448FD0` |

The GOG code also has `CALL 0x00448FD0` at
`0x0044905A` inside the `0x00449010` callback.

At precisely the same table slots, the retail protected
initializer obtains pointer values from XOR-masked global memory
rather than from literal function addresses:

| Offset | Retail-CD masked pointer source |
|---|---|
| `+0x08` | `[0x004A1660] XOR [0x004A1630]` |
| `+0x1C` | `[0x004A1D34] XOR [0x004A1D04]` |
| `+0x20` | `[0x004A1958] XOR [0x004A1928]` |

In the **on-disk original retail image**, the first member
of each of these pairs is **zero** and the second appears
masked/random. A direct XOR of the *on-disk* values does **not**
produce the GOG callback addresses. **This is not proof of an
incorrect file or a particular SafeDisc key**: the runtime
initialization and mutation of those global variables must
be traced before inferring the original callback targets.

#### Path-matching behavior

The GOG `0x00448F60` callback only enters the manifest
search after testing its input path has a **drive prefix**:
the two bytes at offsets 1 and 2 must be `:\` (x86
`CMP WORD PTR [ESI+1],0x5C3A`). It then skips the initial
three path bytes (`ADD ESI,3`) and compares the
remaining path against the manifest's names, converting
lowercase ASCII letters to uppercase during comparison.

The `0x00448FD0` callback traverses the entries by a
zero-based index and returns the entry's **declared size**,
or zero at the sentinel. These are **static instruction-level
observations**; no actual runtime call through the table
has been observed or claimed.

**Interpretation:** GOG does more than merely store a CD file
list: it installs path and size lookup callbacks in a shared
game-level dispatch structure. Because the two initializer
call sites are common to the protected EXE, we have a
concrete correspondence for studying original file-handling
behavior. Still, do **not** treat the GOG replacements as
pure SafeDisc deprotection, or the list as an authenticated
original-CD manifest.

#### Reproducible reference tracing

`scripts/pe_reference_diff.py` supports optional **generic**
`--trace-va` arguments. It scans executable sections for raw
x86 `E8 rel32` call patterns and `B8..BF imm32`
register-loading patterns, then reports candidate instruction
virtual addresses in both input PE files.

```sh
python scripts/pe_reference_diff.py \
  --protected "Rayman2-protected.exe" \
  --reference "Rayman2-GOG.exe" \
  --reference-origin GOG \
  --trace-va 0x467130 \
  --trace-va 0x448F60 \
  --trace-va 0x448FD0 \
  --trace-va 0x449010
```

Expected, separately inspected static candidates:

- `0x467130`: two identical `CALL rel32` sites
  `0x4674C8` and `0x47B01B` in **both** binaries.
- `0x448F60`: GOG `MOV r32,imm32` at
  `0x467151`; no direct equivalent in the protected
  bytes at that address.
- `0x448FD0`: GOG `MOV` at `0x4671DF`
  and GOG direct `CALL` at `0x44905A`;
  neither candidate occurs in the protected binary.
- `0x449010`: GOG `MOV` at `0x467160`,
  not in protected bytes.

The scanner **is not a disassembler** and must not be
used alone to assert that matched bytes are executable
instructions or reachable code. The listed sites above
were **independently checked with GNU objdump**.

### Stronger proof: GOG callbacks match exact retail export descriptors

The API identities below are **not inferred from calling
conventions alone**. They are explicitly named in the
**encoded import descriptors of the original protected
retail `Rayman2.exe`**, independently decoded via the
original export-name algorithm:

| One-based retail descriptor | Original decoded export (KERNEL32.dll) | Descriptor and pointer slot VAs | GOG replacement callback |
|---:|---|---|---|
| **15** | **`GetDriveTypeA`** | record `0x004A1844`, slot `0x004A1874` | **`0x00448EC4`** at GOG table offset `+0x10` |
| **16** | **`GetVolumeInformationA`** | record `0x004A1890`, slot `0x004A18C0` | **`0x00448E6C`** at offset `+0x28` |
| **28** | **`GetDiskFreeSpaceA`** | record `0x004A1C20`, slot `0x004A1C50` | **`0x00448ED0`** at offset `+0x0C` |

For each record, the **entire 76 bytes** are
**identical between retail and GOG**, including
its encoded API name and zero-on-disk pointer
slot at offset `+0x30`. The original retail
dispatch initializer reads `[slot] XOR [record base]`;
GOG instead installs the literal callback
address at the corresponding dispatch table
slot. This is an exact cross-version **functional
correspondence in the initializer**, not just a
similar-looking helper function.

Independent local validation decoded these three
retail export names directly from the protected
file and checked the correct record/slot VAs,
identical GOG data records, and zero on-disk
slots. Together with the GOG static opcode
checks, the local test suite now passes
**14/14 tests**.

**Scope:** The evidence proves GOG installs
replacements for the *three named Windows
APIs*. It does **not** prove their actual
invocation, the authenticity of GOG's
hard-coded disc values, or an algorithm
for reconstructing an unprotected retail EXE.

### Further GOG file-metadata hooks: original `GetFileTime` and `GetFileInformationByHandle`

Two more callback slots can be matched **directly to
decoded original-CD API descriptor names**, not just
inferred from x86 calling conventions:

| Retail descriptor | Original Win32 import | GOG callback-table offset | GOG function |
|---:|---|---|---|
| **31** | `GetFileInformationByHandle` | **`+0x1C`** | **`0x00449010`** |
| **34** | `GetFileTime` | **`+0x24`** | **`0x00448F18`** |

Both names were decoded independently from the
SHA-256-pinned protected CD EXE. The GOG callback
initializer at `0x467160` explicitly loads
`0x449010` into the `+0x1C` table slot,
and at `0x4671D7` loads `0x448F18`
for `+0x24`.

**GOG `GetFileTime`-replacement at `0x448F18`:**
Writes the 64-bit little-endian FILETIME constant
`0x01BEF910C69E2B00` to the creation-time
and last-write-time buffers (if present), and
zeros the last-access-time buffer. The constant
corresponds to **1999-09-07 09:10:06 UTC**.
The code returns 1 and ends with `RET 0x10`,
matching the four-argument
[GetFileTime](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletime)
signature.

**GOG `GetFileInformationByHandle`-replacement
at `0x449010`:** Writes a structure resembling
[BY_HANDLE_FILE_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information):
file attributes `1` (read-only), the same
fixed FILETIME fields, volume serial
`0x6D380AE8`, and additional file metadata.
It calls **`0x448FD0` at `0x44905A`**
(the GOG inventory index/size lookup) and
stores the returned number at offset
`+0x24` of its output structure
(`nFileSizeLow`), thus connecting the
**3,716-entry `.extra2` inventory** to a
simulated file-information API.

**Caution:** one observed store in this
GOG routine uses `[EDI+8]` instead of
`[EAX+8]` for part of a FILETIME.
Without a runtime trace or further control-flow
analysis, do not assert every output field is
populated correctly or that the exact Win32
contract is followed. Do not copy this
implementation into a general compatibility
layer merely because its apparent intent
is identifiable.

The fixed date belongs to GOG's static
replacement and **must not be treated
as an authenticated date from the original
retail CD**. No dynamic calls or game execution
were observed.

A new cross-reference check against the actual
retail and GOG binaries, together with the
earlier three CD-geometry replacement checks,
has **16/16 independent local tests passing**.
These checks are deliberately read-only.

### GOG CD-ROM compatibility callbacks: three concrete static replacements

**13 November 2026: verified on the actual two SHA-256-pinned
executables; 13 independent local read-only regression tests passed.**
This finding is specific to the GOG reference, which may include
compatibility changes beyond SafeDisc removal. It must **not** be
copied blindly to the original retail executable.

The GOG-modified callback initializer at VA `0x00467130`
installs *three* functions that return fixed CD-like answers:

| GOG table slot | GOG callback VA | Evidence in x86 | Win32 interface (independently confirmed by retail descriptor) |
|---|---|---|---|
| `+0x10` | `0x00448EC4` | `MOV EAX,5; RET 4` | `GetDriveTypeA`: `DRIVE_CDROM = 5` |
| `+0x28` | `0x00448E6C` | writes volume labels, serial, flags; `RET 0x20` | `GetVolumeInformationA` (8 arguments) |
| `+0x0C` | `0x00448ED0` | writes sector/cluster values; `RET 0x14` | `GetDiskFreeSpaceA` (5 arguments) |

The decoded original-CD descriptor names, byte patterns and calling conventions match the
[GetDriveTypeA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypea),
[GetVolumeInformationA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationa)
and [GetDiskFreeSpaceA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdiskfreespacea)
interfaces. The three API names are **confirmed by the original retail encoded descriptors**, not inferred solely from function signatures. Runtime invocation and actual effects remain unverified.

#### Exact GOG-supplied values

**Callback `0x448E6C` (volume information):**

| Output | Value | Evidence |
|---|---|---|
| Volume label | ASCII `RAYMAN2\0` | stores at `0x448EAE`, `0x448EB4` |
| File-system name | ASCII `CDFS\0` | stores at `0x448E76`, `0x448E7C` |
| Volume serial | `0x6D380AE8` | store at `0x448EA1` |
| Maximum component length | `110` | store at `0x448E94` |
| File-system flags | `0x00000005` | store at `0x448E87` |
| Return | `1` | `XOR EAX,EAX; INC EAX; RET 0x20` |

**Callback `0x448ED0` (disk-free-space-like data):**

| Output | Value |
|---|---|
| Sectors per cluster | `1` |
| Bytes per sector | **`2048`** |
| Free clusters | `0` |
| Total clusters | **`332400`** (`0x51270`) |
| Return | `1`; `RET 0x14` |

The values imply a *reported* total disk capacity of
`332400 * 1 * 2048 = 680755200` bytes
(about 649.2 MiB). **This is a GOG hard-coded response,
not a verified measurement of the original CD's capacity.**
The fake `CDFS` and `DRIVE_CDROM` responses explain how
GOG can plausibly satisfy older disc-presence checks when the
application is run without physical CD media.

**Callback `0x448EC4` (drive type):** exact bytes
`B8 05 00 00 00 C2 04 00`, corresponding to
`MOV EAX,5; RET 4`. In the initializer, GOG loads
this address at `0x46717C` and stores the pointer
into table slot `+0x10` at `0x467182`.
Crucially, the **three-byte store instruction itself
is identical** between retail and GOG; the
preceding function-pointer source is modified.

**Important limits:**

- These callbacks are **statically assigned** in the GOG
  executable. Their actual invocation or success under Wine
  or Windows was **not** measured.
- `GetVolumeInformationA` normally has size arguments for
  its output buffers; the observed GOG code writes fixed
  ASCII strings and does not establish full Win32 contract
  compliance for arbitrary user-provided buffer lengths.
- No conclusion about the *original disc's actual label*,
  its authentic serial number or its physical size follows
  from hard-coded GOG outputs.
- The original CD protected executable contains **different
  byte sequences** at all nine tested GOG callback/constant
  sites; these are GOG modifications, without SafeDisc-only
  attribution.

#### Reproducible read-only verification

The evidence was checked against the exact retail protected
SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`
and GOG SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`
with independently mapped PE virtual addresses, comparing
the literal stored x86 bytes at the volume/space/drive
functions and their callback-table assignment sites.

The generic script `scripts/pe_reference_diff.py`
now also recognizes `MOV EAX,imm32; RET imm16`
constant-return stubs, including the exact
`GetDriveTypeA`-like case above. A synthetic
regression case is added. The **local separate test
suite passed 13/13**, and a JSON evidence summary
was generated without distributing proprietary
binary data. The Rust inspector still requires
compilation; no GitHub Actions jobs were triggered.

### Static GOG code references to the embedded file inventory

Unlike the inert-looking byte-copy hypothesis for `.extra`,
the **GOG-modified `.text` contains two explicit x86
immediates referencing the base of `.extra2`**.
The section's RVA is `0x1B3000`, so its image-base-adjusted
virtual address is **`0x005B3000`**.

Verified by independent `objdump -D -M intel` of the SHA-256-pinned
GOG EXE and compared to the protected CD bytes at the same VAs:

| GOG instruction VA | Exact observation |
|---|---|
| `0x00448F80` | `MOV EDI, 0x005B3000` — base of `.extra2` |
| `0x00448F85`–`0x00448FBD` | Loop checks the `0xFFFFFFFF` sentinel, compares a caller-supplied path to table entry names (ASCII lowercase normalized), and advances by a record's prefixed length |
| `0x00448FD7` | `MOV ESI, 0x005B3000` — same table base |
| `0x00448FE0`–`0x00448FF5` | Second loop traverses records, selects an entry by index and reads its claimed size |
| `0x0044905A` | `CALL 0x00448FD0` — call to the size-lookup routine |

The corresponding protected retail `.text` contains **different
instructions** at these addresses (in particular obfuscated
PRNG/control-flow code), so these two manifest readers are
**GOG-reference-specific static modifications**. This establishes
a concrete intended **file-path and file-size lookup** use for the
`.extra2` table in GOG's code. It does **not** prove whether those
functions are reached at runtime, whether a particular file is
emulated, or why GOG chose the declared values. In particular,
it does not authenticate the 3,716 records as the true original
physical CD file inventory.

Separately, the GOG `.text` has two literal VA operands
referring to `.extra`'s base `0x00517000`
(at `0x00470052` and `0x0047B1C4`). The first corresponds to
`MOV EAX, 0x00517000` at `0x00470051`. Their role must be
traced; **the fact that the protected `.text` is preserved in
`.extra` does not mean it is executed there**.

The generic comparator now lists byte-pattern occurrences of the
absolute base VAs of *reference-only* PE sections inside
executable-designated sections. Such matches are labeled
**literal candidates**, not automatically decoded x86 instructions.
One synthetic regression test validates the bounded reference mapping
and its absence when the bytes are not present.

### Exact extent of GOG `.extra2` inventory

The entire `143,360` backed bytes of GOG `.extra2` consist
of **139,366 bytes of 3,716 length-prefixed records**, followed by
the **8-byte termination sentinel** `FF FF FF FF 00 00 00 00`,
followed by **3,986 bytes of zeros**. There are no additional
nonzero bytes after the manifest terminator within this section.

The read-only parser now reports `bytes_after_sentinel` and
`remaining_bytes_all_zero` independently of the claimed file sizes.
This is evidence about the actual **GOG section contents**,
not a certificate that this table came from the original CD or that
its 7.45 GB of claimed sizes were physically present.

### Embedded file inventory inside `.extra2`

The first part of the GOG reference's `.extra2` has a reproducible,
length-prefixed sequence of **3,716 distinct filenames**:

```text
<u32 claimed_file_size><u32 name_length><name_bytes_including_NUL>
...
<u32 0xFFFFFFFF><u32 0>       # end marker
```

The table occupies **139,366 bytes** before the end marker and
is followed by ordinary section padding. Some directly verified
entries:

| Manifest path | Manifest claim | Owner's original file |
|---|---:|---|
| `RAYMAN2.EXE` | 676,352 bytes | protected EXE: 676,352 |
| `RAYMAN2.ICD` | 683,565 bytes | supplied ICD: 683,565 |
| `DPLAYERX.DLL` | 165,888 bytes | supplied DLL: 165,888 |
| `SECDRV.SYS` | 14,368 bytes | no separate source file checked |

The table names **`DPLAYERX.DLL`**, not
`DXPLAYERX.DLL` (the latter spelling appeared in an earlier
Rayman2Fix exclusion list). This is useful evidence for auditing
the original file layout, but the two names must still not be
silently equated.

**The sum of all 3,716 *declared* sizes is 7,453,062,614 bytes
(7.45 GB)**, far more than the physical Rayman 2 CD image.
Many individual data files declare hundreds of megabytes.
Those totals are **not actual byte extents to extract**, and
are consistent with the prior observation of fake/oversized CD
entries designed to complicate direct copying. The precise
origin and function of the manifest itself remain to be proven.
Do not allocate 7.45 GB or attempt to extract the listed sizes.

### Reproducibility and validation

A new **generic** standard-library-only tool
[`scripts/pe_reference_diff.py`](../scripts/pe_reference_diff.py)
compares shared sections at matched RVAs, requires bounded PE32
headers/section tables, prints JSON metadata only, and optionally
scans such a length-prefixed manifest (no file extraction):

```sh
python scripts/pe_reference_diff.py \
  --protected "Rayman2-protected.exe" \
  --reference "Rayman2-GOG.exe" \
  --manifest-section .extra2 \
  --focus-name RAYMAN2.EXE \
  --focus-name RAYMAN2.ICD \
  --focus-name DPLAYERX.DLL
python -m unittest discover -s scripts -p 'test_pe_reference_diff.py'
```

The first command does **not** write a patched EXE, copy protected
data, or claim a decrypted result. The CLI refuses self-comparison
to avoid a misleading independent-provenance claim.
**Nine synthetic Python tests pass locally** on the independent
working copy: section file-offset shifts, exact changed RVA, extra
sections, parser bounds, corrupted manifest entries, self-comparison,
and read-only JSON output. Native Rust tests remain uncompiled due
to absent Rust toolchain; the existing Crimson Skies unwrap code
was not modified.

## Verified breakthrough — BOTH uploaded opaque files are exact masked-MINSTD streams

**2026-11-12 correction:** Earlier research incorrectly interpreted the ICD as
big-endian words starting at byte zero. Scanning all **four offsets and both
endiannesses** exposes the only valid whole-stream alignment: the ICD's
actual 31-bit words start **after one leading byte**, in **little-endian**.

Both user-supplied files satisfy the **identical** masked Park–Miller recurrence:

```text
next = 16807 * (current XOR 0x075BD924) mod 2147483647
```

| Exact sample | Leading bytes | First 31-bit word | Words | Exact transitions |
|---|---|---|---:|---:|
| `RAYMAN2.ICD` | `5B` (1 byte) | `0x6EE4C08A` | 170,891 | **170,890 / 170,890** |
| `dplayerx.dll` | none | `0x0030FBEC` | 41,472 | **41,471 / 41,471** |

With the one-byte ICD prefix preserved, independently regenerating **all
683,565 ICD bytes** from its first word and the recurrence produces an
**identical SHA-256**:
`4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6`.
The corresponding full 165,888-byte DLL regeneration also matches
`0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee`.
Both are exact **byte-for-byte** verifications; no game bytes are stored.

Each supplied file is fully specified by a short prefix (if present),
one 31-bit seed, the common constant, and its length. Such a stream
cannot represent an **arbitrary independently encoded PE executable or
DLL payload** without additional information. This strongly suggests
synthetic filler or another protection-related PRNG artifact, but its
actual role/origin on the CD remains unverified. This **does not**
establish that a separately installed ICD is absent or that the genuine
game cannot be restored from other user-owned files.

**Reproduce using the read-only Python tool, without writing outputs:**

```sh
python scripts/safedisc_prng_recurrence.py RAYMAN2.ICD --auto-align
python scripts/safedisc_prng_recurrence.py dplayerx.dll --auto-align
# or explicitly: --endian little --offset 1 (ICD), --offset 0 (DLL)
python -m unittest discover -s scripts -p 'test_*.py'
```

The Rust inspector now scans all **eight** word-layout candidates, but this
new Rust code is **not yet compiled or tested**. The corresponding
Python auto-alignment implementation passed eight synthetic tests and
both genuine-sample SHA-256 regeneration checks locally.

**Supersession:** Earlier claims that the ICD did not follow masked
MINSTD, that its final byte `0x29` was an unaligned tail, or that
big-endian offset-zero words represented its native encoding are
**incorrect**. At offset +1 the last byte belongs to the **last
little-endian word**, and every ICD transition matches.
Earlier negative generator tests using the wrong word alignment are
not evidence about the correct stream.



The user reports that [Redump disc 47594](https://redump.org/disc/47594/)
identifies the disc as SafeDisc **1.35.000**. Independently, a
[Wine bug report from 24 December 2009](https://list.winehq.org/hyperkitty/list/wine-bugs%40list.winehq.org/thread/PBMSSMOUG42FC3AE5YDT7WPIEDJIBKC5/)
is titled **"SafeDisc v1.35.000 and Rayman 2"**, corroborating that
this protection version was used for *a* Rayman 2 PC edition. That
does **not** authenticate the exact protected files supplied here.
The tool does not infer a SafeDisc version from a filename, file
size or entropy.

## Owner-supplied inputs, identified by SHA-256 only

| Role | Original name | Size (bytes) | SHA-256 |
|---|---|---:|---|
| Loader | Rayman2.exe | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Protected data | RAYMAN2.ICD | 683,565 | `4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6` |
| Companion | dplayerx.dll | 165,888 | `0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee` |

The second uploaded set was byte-identical to the first set. No game
binary, ICD, DLL or decoded output is committed to this repository.

## Read-only inspection

```sh
cargo run --bin unsafedisc-linux -- inspect --generic-inspect \
  --loader Rayman2.exe --icd RAYMAN2.ICD --dplayerx dplayerx.dll \
  --layout --sections
```

Expected properties from the sample (not exhaustive):

- The loader has a valid PE32 x86 header, entry RVA `0x0005FCC0`,
  and three sections.
- The ICD and companion DLL lack an `MZ` prefix and therefore are
  **opaque on-disk input**, not valid PE32 files at offset zero.
- The ICD and DLL have measured Shannon entropies of approximately
  **7.9539** and **7.9525 bits/byte**. High entropy is *not proof* of
  encryption, compression, SafeDisc identity or decryptability.
- A successful generic inspection is a metadata report only. It cannot
  create an EXE or validate gameplay.

The original `inspect --generic-inspect` stopped on these inputs with
`not an MZ executable`. This branch handles opaque files as research
inputs while preserving the existing exact-hash restrictions and
fail-closed behavior in `unwrap` and strict `inspect`.

## Independent static profile of these inputs (2026-11-12)

The following observations were obtained on the original user-supplied files
without loading or executing them (Python standard library, `file`,
`objdump -x`, `objdump -d`).

| Property | `Rayman2.exe` |
|---|---|
| DOS/NT headers | `MZ` at file offset `0x0`; `PE\\0\\0` at `0xB8` |
| PE machine / format | i386 / PE32, GUI |
| Image base | `0x00400000` |
| Entry-point RVA | `0x0005FCC0` |
| Reported PE timestamp | 1999-10-15 23:19:39 UTC (header value; not provenance proof) |
| Sections | `.text`, `.rdata`, `.data` |
| Import DLLs | `USER32.dll`, `GDI32.dll`, `WINMM.dll`, `MSVCRT.dll`, `KERNEL32.dll`, `SHELL32.dll`, `DINPUT.dll` |
| Export directory | Claims `MainWinf.exe`, 110 exported ordinals |
| `CRPE\\0\\0` signature | Not found in this loader |
| `DPLAYERX` plaintext string | Not found in this loader |

The `CRPE` marker used in the *separate* Crimson Skies SafeDisc 1.50.20
research is therefore **not portable as an assumed key-lookup location**.
No hard-coded replacement offset should be invented for 1.35.

The `MZ` and `PE\\0\\0` byte patterns also appear inside the executable
`.text` as x86 instruction operands in code which appears to validate
mapped PE headers and inspect `KERNEL32`. These matches are **not**
additional embedded PE images. This routine is a candidate for further
static cross-reference analysis, not proof of a particular SafeDisc stage.

Measured per-file whole-byte Shannon entropy:

| File | Entropy (bits/byte) | First 16 bytes |
|---|---:|---|
| `Rayman2.exe` | 6.627897 | `4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00` |
| `RAYMAN2.ICD` | 7.953942 | `5B 8A C0 E4 6E BF 24 2F 01 6C CE B5 6A 5A B0 3A` |
| `dplayerx.dll` | 7.952524 | `EC FB 30 00 46 7C B8 0A 0D CC 7E 5C 7E 65 90 5F` |

For equal-length 4 KiB blocks (discarding the final incomplete block),
the entropy profiles are:

| Opaque file | Full 4 KiB blocks | Min. block entropy | Max. block entropy |
|---|---:|---:|---:|
| `RAYMAN2.ICD` | 166 | 7.893266 | 7.927141 |
| `dplayerx.dll` | 40 | 7.894593 | 7.917976 |

No low-entropy 4 KiB region stands out in either file. This does
**not** distinguish encryption from compression or establish cipher
boundaries. The new `--generic-inspect --layout` report prints this
profile for any sufficiently large input.

The ICD is `0xA6E2D` bytes long (not a round PE alignment size),
and the opaque DLL is `0x28800` bytes long. Neither begins with `MZ`
or contains a `PE\\0\\0` signature. A plain `dplayerx.dll` import
is **not present in the static import table** of the loader; this
does not rule out dynamic loading.

**Important:** `Rayman2.exe` has an extensive, genuine PE code,
import and export structure; describing it as “only an encrypted stub”
would go beyond these findings. Its actual protected launch sequence
must be traced before planning a decoder.

### Candidate protected-loader cross-reference (unconfirmed)

At image VA `0x00447C0C`, the executable compares an in-memory DOS
signature to `0x5A4D` (`MZ`), and at `0x00447C18` compares the PE
signature to `0x00004550` (`PE\\0\\0`). It then tests bytes
matching `KERNEL32.DLL` (case folding). At `0x00447D47`, a nearby
routine reads `FS:[0x30]` (Windows process environment block).
These locations are **research leads only**, and may belong to game
runtime code rather than SafeDisc. No key or protected payload boundary
is derived from them.

### Reproducibility

On a system with GNU binutils:

```sh
sha256sum Rayman2.exe RAYMAN2.ICD dplayerx.dll
file Rayman2.exe RAYMAN2.ICD dplayerx.dll
objdump -x Rayman2.exe
objdump -d -M intel --start-address=0x447BE0 --stop-address=0x447E20 Rayman2.exe
```

`objdump` emits the executable's image-base addresses rather than
raw file offsets. The `--start-address` range above is for preliminary
static code inspection, not an exploit or validated key schedule.

## Additional validation: accidental signatures are not PE files

A bounded read-only scan was performed on each owner-supplied input. Every
`MZ` sequence was checked as a possible start of a **structurally valid
x86 PE32** with a DOS header pointer, PE signature, bounded optional header
and section table. Merely counting `MZ` in high-entropy bytes is misleading.

| File | `MZ` occurrences anywhere | Structurally valid PE32 candidates | Candidate offsets |
|---|---:|---:|---|
| `Rayman2.exe` | 2 | 1 | `0x0` |
| `RAYMAN2.ICD` | 16 | 0 | none |
| `dplayerx.dll` | 4 | 0 | none |

The extra `MZ` match in the EXE occurs within executable instructions, not
a second embedded image. None of the 20 `MZ` matches in the opaque inputs
passes PE32 structural checks. This is **not** evidence that decrypted PE
code is absent; the expected protected ICD is not meant to be a plain PE.

The generic Rust inspector now displays these two distinct counts with
`--layout`. It also **rejects a corrupt/non-PE loader** instead of silently
calling it an opaque successful inspection; only ICD and companion DLL
inputs are allowed to lack a PE header. These are read-only diagnostics
with synthetic tests; compilation and execution of the new Rust code
remain pending.

## Historical variant clue from original SafeDisc documentation

[CD Media World, *SafeDisc protection/version reference*]
(https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc.shtml)
catalogues a **165,888-byte `DPLAYERX.DLL`** as an early **r2**
family and **138,752 bytes** as a later **r4** family. Our Rayman 2
sample is 165,888 bytes while the previously validated Crimson Skies
sample is 138,752 bytes. This suggests **different protection families**
and a reason not to reuse the Crimson-specific loader/DLL assumptions.

This is a historical third-party classification based on **DLL size**,
not authenticated version metadata: it does **not** independently verify
SafeDisc `1.35.000` or prove that all files of equal size share a
decryption algorithm. The observed file size should be stored as
descriptive data, **not** used as an authorization to decrypt.

In particular, the Rayman 2 EXE contains a normal PE32 import table,
a `MainWinf.exe` export-name field with 110 exported ordinals, and
game-related strings (including `Please insert the CD`). Its entry
RVA `0x5FCC0` begins with what looks like C runtime initialization
rather than an obviously isolated SafeDisc entry stub. This is
important counterevidence against treating the entire EXE as a
recognizable dedicated SafeDisc loader without further trace analysis.
The relationship between this PE and the encrypted ICD is **not yet
established**.

## Independent reproducible research probe (Python 3)

The repository includes `scripts/safedisc_v1_probe.py`. It is a separate
**read-only, standard-library-only** verifier of the PE32/magic/entropy
observations, not a decryptor or SafeDisc recognizer. It requires the
user's own files; none are bundled:

```sh
python scripts/safedisc_v1_probe.py \
  --loader Rayman2.exe \
  --icd RAYMAN2.ICD \
  --dplayerx dplayerx.dll
python -m unittest discover -s scripts -p 'test_safedisc_v1_probe.py'
```

The first command prints machine-readable JSON to standard output;
it does not write any output file. It records explicit
`decryption_attempted: false` and `safedisc_version_asserted: false`
rather than suggesting a successful unwrap.

**Offline validation:** all seven synthetic Python unit tests passed
locally, and the standalone probe was executed against the original
user-supplied Rayman 2 files with the expected three SHA-256 signatures,
2/16/4 total `MZ` occurrences and 1/0/0 structurally valid PE
candidates. The pre-change Rust binary was also run against those files:
it reached the ICD and failed with `ERROR: not an MZ executable`, as
expected. The **new** Rust implementation has *not* been compiled or
executed yet because no Rust compiler is available in the working
container, and GitHub Actions billing is exhausted.

## Read-only IAT cross-reference map (2026-11-12)

A second standard-library-only tool, `scripts/pe_import_xrefs.py`, parses
the original **loader EXE's** bounded x86 PE32 import directory and looks
for the byte-level x86 opcode patterns `FF 15 <IAT VA>` (indirect
`CALL`) and `FF 25 <IAT VA>` (indirect `JMP`) in executable sections.
It does **not** execute any input, attempt decryption, or claim the
patterns are reachable instructions. Seven additional **synthetic**
unit tests validate PE header and import-bound checks.

Results on the owner's SHA-256-verified `Rayman2.exe`:

- **163 imported API entries** across **7 DLLs**:
  `DINPUT.dll`, `GDI32.dll`, `KERNEL32.dll`, `MSVCRT.dll`,
  `SHELL32.dll`, `USER32.dll`, `WINMM.dll`.
- **424 direct IAT CALL/JMP byte-pattern candidates**, across
  **154 import targets**. These are candidate static references, not a
  full executable call graph.

| Imported Win32 function | IAT VA | Candidate direct-call VAs |
|---|---|---|
| `CreateFileA` | `0x0049C058` | `0x00450C16`, `0x0045486F` |
| `ReadFile` | `0x0049C04C` | `0x0044CFB7`, `0x0044D5F7`, `0x0044F897`, `0x004510AE`, `0x004512DA`, `0x0045497F` |
| `GetFileSize` | `0x0049C040` | `0x00454847` |
| `LoadLibraryA` | `0x0049C084` | `0x00421889`, `0x0045894F`, `0x00458B1E`, `0x004590EE`, `0x00459323` |
| `GetProcAddress` | `0x0049C088` | `0x00455D29`, `0x00458A02` |

```sh
python scripts/pe_import_xrefs.py Rayman2.exe > import-xrefs.json
python -m unittest discover -s scripts -p 'test_pe_import_xrefs.py'
```

**Follow-up candidates:** `CreateFileA` appears at `0x450C16`
in a routine which also contains indirect calls through computed
function pointers and writes pseudorandom-looking bytes into a buffer;
another direct file-open pattern occurs at `0x45486F`. At
`0x44EC50` and `0x44F18C`, code references a
`CDROM not found!` string (VA `0x4A2270`) near file-open
handling. These routines must be traced using valid instruction boundaries
before claiming they implement CD checking or a SafeDisc stage.
The executable entry VA `0x45FCC0` begins with an ordinary-looking
SEH/C-runtime prologue; neither this nor file I/O proves that this
EXE is only a protected stub. A full call graph and ICD decoding
remain **unsolved**.

## Historical unSafeDisc 1.5.5 branch condition: important new lead

Existing primary research in
[`docs/unsafedisc-linux.md`](unsafedisc-linux.md)
records disassembly of the user's original historical 20,480-byte
`unSafedisc.exe`, rather than guessing from the separate 18,944-byte
modified public release.

At `0x401F43..0x401F62`, the historical implementation performs an
**extra pre-TEA processing step if the supplied `dplayerx.dll` is
exactly `0x21E00` bytes (138,752)**. This applies to the Crimson Skies
reference, but **not** to the Rayman 2 DLL of `0x28800` bytes
(165,888). The implementation also has a generic 32-round TEA-like
decryption stage at `0x401A55`, subject to other prerequisites.

This is a **specific branch condition in a particular historical tool**,
not an attestation that Rayman 2's ICD follows the same TEA geometry,
that the needed key is known, or that running the old tool would work.
The visible Rayman ICD does not have a PE header, so header restoration
and correct loader/DLL key derivation must be established first.
Do not substitute the Crimson Skies F1/F2 modifier or its fixed keys.

Research priority: reconstruct the **early-family loader -> DLL ->
ICD** data path and its header-handling stage, using read-only static
evidence. The branch above suggests that a universal 1.x implementation
should **identify its applicable algorithmic path**, not merely
rename hard-coded Crimson Skies constants.

## Strong four-byte lane constraint (2026-11-12)

An independent whole-file scan of the owner's exact SHA-256-verified Rayman 2
inputs discovered a previously unrecognized **bit-level invariant**. Using
nonoverlapping groups of four bytes from file offset zero:

| Input | Complete groups | High-bit=1 counts, lanes 0/1/2/3 | Leftover bytes |
|---|---:|---|---:|
| \`Rayman2.exe\` | 169,088 | 73,986 / 74,194 / 71,483 / 71,432 | 0 |
| \`RAYMAN2.ICD\` | **170,891** | **0** / 85,432 / 85,193 / 85,523 | **1** |
| \`dplayerx.dll\` | **41,472** | 20,636 / 20,735 / 20,654 / **0** | 0 |

Every single ICD byte at offsets \`0, 4, 8, ...\` is below \`0x80\`;
the other three lanes use all eight bits. Every single companion DLL
byte at offsets \`3, 7, 11, ...\` is below \`0x80\`; its other lanes
use all eight bits. The byte at the end of the ICD is \`0x29\`; under the **correct offset +1** word layout it is part of the last word, **not** an extra trailing byte.

**Corrected interpretation:** the high-bit-lane count by itself is
**ambiguous**. A clear lane 0 at file offset zero fits either a
big-endian word starting at zero **or** a little-endian word starting at
offset one. The full mathematical recurrence and exact regeneration
identify the second interpretation for the ICD. The DLL uses
little-endian words starting at zero.

The earlier statement that the files had **three shared 31-bit values**
used *incorrectly aligned* ICD words; it is withdrawn. Comparing the
correctly aligned streams gives **no common words** between all
170,891 ICD states and all 41,472 DLL states. The words within each
file are also distinct. Neither file is the other's immediately
following segment: the successor of the ICD's last state is
`0x11F38C41` (not the DLL seed `0x0030FBEC`), while the successor
of the DLL's last state is `0x1D99DDE9` (not the ICD seed
`0x6EE4C08A`). These are bounded **observations**, not proof
that the generator seeds are unrelated globally.

The full-file PRNG demonstration at the beginning of this document
supersedes weaker entropy and speculative cipher classifications.

**Reproduce without executing a protected binary:**

\`\`\`sh
python scripts/safedisc_v1_probe.py \
  --loader Rayman2.exe --icd RAYMAN2.ICD --dplayerx dplayerx.dll
python -m unittest discover -s scripts -p 'test_safedisc_v1_probe.py'
\`\`\`

The JSON \`four_byte_lanes\` member reports the group count, ignored
tail, per-lane high-bit counts, and a cautious representation hint.
The Rust \`inspect --generic-inspect --layout\` report now contains
the corresponding read-only high-bit counts. Synthetic tests cover
opposite byte orders, lone high-bit bit-flips and partial tails.
The new Rust code still requires compilation validation; no protected
file is distributed.

**Next decoding research:** determine how the 31-bit restrictions arise
from the historic SafeDisc 1.x loader and DLL processing stages. Do not
discard the bit or blindly reinterpret words as compressed PE code.

## Historical algorithm boundary: SafeDisc 1.30 to 1.50

A contemporary June 2001 technical study,
[*An overview of SafeDisc versions* by ArthaXerXès]
(https://gbppr.net/cracking/krobar/other/com26.html), reports the following
implementation changes:

- **1.30.0**: import RVAs are XOR-encoded using one 32-bit TEA key word;
  the original 128-bit TEA key still consists of **four identical words**.
  The described loader search targets a literal \`00 00 00 00\` DWORD
  followed by \`A, A, B, B\` DWORD pairs.
- **1.40.4**: an additional callsite repair stage changes selected
  x86 \`FF 15\` references using version-specific arithmetic.
- **1.45.11**: repeated-key weakness was eliminated; per-title
  DPLAYERX EAX modification appeared.
- **1.50.20**: added a separate pre-decryption layer involving DPLAYERX
  routines, which is the extra stage already investigated for Crimson Skies.

**If the owner's Rayman 2 version is indeed 1.35.000**, it lies
between the first two changes, suggesting an early repeated-key TEA
path *may* apply. This exact-version link is **not verified directly**
from the opaque ICD and therefore cannot yet enable any decoder.

A read-only search for the **literal contiguous**
\`0, A, A, B, B\` 32-bit sequence (with nonzero, distinct A and B)
in the user's **676,352-byte Rayman2.exe**, across all four byte
alignments, returned **zero candidates**. Neither \`DECRPE\\0\\0\`
nor \`CRPE\\0\\0\` occurs in that executable. These negative
findings invalidate a naive re-use of the historical loader-pattern
heuristic on this input; they do not disprove TEA, an alternate key
location or the user's SafeDisc version claim.

Further work must first validate the file-pair relationship and
reconstruct a trustworthy PE/header stage before inferring an import
table or deriving a TEA key. No game binary, DLL, decrypted output
or proprietary component is copied into the repository.

## File-format interpretation and optional provenance comparison

A SafeDisc 1 protected CD normally contains an `EXE` loader paired
with a game `ICD` containing **encrypted executable content**
([CD Media World, SafeDisc v1](https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc.shtml)).
Therefore **absence of a readable `MZ`/PE32 header at offset zero
inside the on-disc ICD is not a corruption indicator, not evidence of
an incorrect file, and not a reason to halt read-only cipher research**.

The supplied files have these **descriptive** properties:

| Component | File-header observation | Interpretation |
|---|---|---|
| `Rayman2.exe` | valid x86 PE32, `.text/.rdata/.data` | Known protected retail EXE SHA-256, corroborated by Rayman2Fix |
| `RAYMAN2.ICD` | no plain PE32 at offset zero | Consistent with an encrypted payload; no direct `CreateProcess` use is claimed for raw on-disc bytes |
| `dplayerx.dll` | no plain PE32 at offset zero | May require SafeDisc-specific transformation before standard DLL loading; stage unverified |

A [historical Wine developer description (April 2002)]
(https://www.winehq.org/pipermail/wine-devel/2002-April/005861.html)
mentions `.txt`/`.txt2` loader sections and a decoding/loading
sequence, but this was **one implementation example**, not a universal
header/section requirement for all SafeDisc 1.35 games. Its differences
from Rayman 2 do not establish wrong or corrupt input.

The files also exhibit a repeatable 31-bit word-lane constraint; that
is **strong evidence of structured encoding**, but does not establish
the compression/encryption format, authenticity, or decoding key.

To check file provenance **independently** and avoid mixing different
original retail editions, the optional
[`compare_safedisc_stages.py`](../scripts/compare_safedisc_stages.py)
tool compares root-level file names, sizes and SHA-256 between the
owner's disc image and an unmodified original installation. Its results
must not be interpreted as an authenticity certificate.

**Research may proceed offline on the hash-identified encrypted inputs**
without waiting for a second copy of the same files; a CD-vs-install
comparison is a complementary verification, not a prerequisite for
investigating their 31-bit encoding or the SafeDisc 1.35 algorithm.
Do not commit, redistribute, or execute proprietary protected payloads.

## Cross-check against the separate Rayman2Fix repository

The owner's separate `legluondunet/Rayman2Fix` source
[`docs/architecture.md`](https://github.com/legluondunet/Rayman2Fix/blob/main/docs/architecture.md)
records the expected SHA-256 of its **protected retail Rayman 2 EXE**
as `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
This matches our exact uploaded `Rayman2.exe` hash. A separate
SHA-256-pinned *unprotected* executable is used for actual launch by
Rayman2Fix. Thus, this sample's protected-EXE identity is
**corroborated by the owner's own independent project**, even though
the provenance of its paired ICD/DLL still requires verification.

The Rayman2Fix CD extraction documentation explicitly warns that
**raw ISO extraction is not necessarily equivalent to installed game
files**, including possible transformation of content by the
original installer. The project's root-exclusion list includes a
file named **`dxplayerx.dll`**, whereas the uploaded research
sample is named **`dplayerx.dll`**. These two spellings differ
(the former has an additional `x` immediately after `d`).
We must **not silently equate them**: inspect the original CD file
listing and the actual installation receipt before deciding
whether the supplied 165,888-byte sample is the intended SafeDisc
auxiliary file. File extension and user-visible name alone are
insufficient provenance evidence.

The current evidence supports analyzing the known protected
`Rayman2.exe` as genuine. It does **not** support treating the
non-PE `RAYMAN2.ICD` and `dplayerx.dll` as directly loadable
Windows binaries, or asserting they are bad/corrupt without
checking the physical CD and installation stages.

## Reproducible original-CD vs original-installation comparison

A new cross-platform, standard-library-only, read-only helper,
[`scripts/compare_safedisc_stages.py`](../scripts/compare_safedisc_stages.py),
tests the most important unresolved hypothesis: **whether the original
installer transforms or substitutes the ICD and companion DLL**.

Keep separate directories containing (1) the files extracted from the
original CD and (2) the files copied from the **unmodified original
game installation**, before any Rayman2Fix patching. The directories
may be on Linux or Windows, and this diagnostic does not require
Wine, the game's EXE to be runnable, or a mounted CD at inspection time.

```sh
python scripts/compare_safedisc_stages.py \
  --cd-root "/path/to/original-CD-root" \
  --installed-root "/path/to/original-install-folder"
python -m unittest discover -s scripts -p 'test_compare_safedisc_stages.py'
```

The JSON output reports root-level `rayman2.exe`, `rayman2.icd`,
`dplayerx.dll`, and `dxplayerx.dll` **separately**. For each file,
the result is `identical`, `different`, `cd_only`,
`installed_only`, or `absent_both`, with any present file's actual
name, size and SHA-256. An `alias_discrepancy`-style flag highlights
the distinct DLL spellings, **without treating them as interchangeable**.
No original files or proprietary data are copied into the repository
or changed. Nine synthetic local regression tests pass.

**Interpretation constraints:**

- Two matching SHA-256 hashes establish equality between the *two
  user-supplied roots*, not that either root is a genuine CD copy.
- Missing original-install files may be installer-only media auxiliaries:
  they are not automatically corrupt.
- A `different` result establishes a transformation or version
  mismatch, but does not reveal how it occurred.
- This tool checks only the specified root directories; it does not
  recursively inspect a disc/installation or reconstruct the original
  installer. Directory contents should first be obtained from the
  owner's authentic, same-edition installation.

### Primary-source version clue

A [2002 SafeDisc FAQ by a Wine developer]
(https://www.winehq.org/pipermail/wine-devel/2002-April/005861.html)
associates a **165,888-byte `dplayerx.dll`** with SafeDisc 1.35.0.
The owner-supplied Rayman 2 file has exactly this size, but is
**demonstrably a deterministic PRNG byte stream, not a loadable DLL**.
Its size should therefore **not** be treated as independent proof of
this exact file's version or authenticity. A separate Wine report
links a Rayman 2 edition to SafeDisc 1.35.000.

### Earlier negative generator checks (wrong ICD alignment; superseded)

These were performed on the initial big-endian offset-zero ICD word
layout, now known to be **incorrect** for the PRNG stream. They do not
refute masked MINSTD at offset +1 in little-endian order.


For both 31-bit word streams (big-endian ICD and little-endian DLL),
read-only numerical tests found no support for:

- The classic **glibc `random()` additive recurrence** with lags
  3 and 31 (output (x_i) must equal the two lagged outputs plus
  a 0-or-1 carry modulo (2^{31})); first 15,000 eligible values
  fail immediately in both files.
- A single affine recurrence `x[n+1] = a*x[n]+c (mod 2^31)`
  throughout the stream. The first three words may suggest a
  candidate when a difference is odd, but it does not reproduce
  subsequent values; a simple LCG is not established.

These *negative controls* only reject those specific generator
models; they do not show the content is encrypted, random, or fake.
These older, alignment-dependent negative results are superseded
by the exact two-file masked-MINSTD reconstruction.

## Corrected version-marker interpretation: `BoG_` belongs to SafeDisc 2+

The `BoG_ *90.0&!!  Yy>` signature is documented as a **SafeDisc 2**
version marker, notably by
[CD Media World — SafeDisc v2](https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc_v2.shtml)
and [Gravure-News (2004)](https://www.gravure-news.com/article/identification-manuelle-des-protections-2-2.php).
It is **not an appropriate version gate for SafeDisc 1.35**.
Earlier research notes incorrectly treated it as a generic
SafeDisc 1 wrapper marker; this section supersedes those notes.

The literal `BoG_` prefix and its longer 20-byte sequence were absent
from all three supplied Rayman 2 files, as previously measured.
**That absence is expected for this SafeDisc 1 investigation and
should not be cited as evidence of a malformed, wrong-version or
transformed file.** It does not distinguish original CD bytes from
installed bytes, and cannot be used to determine this edition's
version. Do not add `BoG_` as a required signature for the 1.35
decoder or inspector.

## Breakthrough: full DPLAYERX byte stream is a deterministic PRNG (2026-11-12)

**Verified against the owner-supplied 165,888-byte `dplayerx.dll`**
(SHA-256 `0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee`).
Interpret its content as 41,472 little-endian, nonnegative 31-bit words.
Let `x[0] = 0x0030FBEC`. The **entire file** satisfies:

```text
x[i + 1] = (16807 * (x[i] XOR 0x075BD924)) mod 2147483647
```

All **41,471 of 41,471** adjacent transitions match, with **zero
exceptions**. Regenerating the 165,888 bytes *entirely from this first
word plus the fixed XOR/multiplier/modulus* produced an **exact
byte-for-byte copy** in memory with the original SHA-256. No real
protected game bytes are included in the repository.

This is not an arbitrary fitted one-step equation: the XOR constant
`0x075BD924` and the classic Park–Miller constants `16807` and
`0x7FFFFFFF` appear directly in **the supplied protected
`Rayman2.exe` executable code**, including x86 instructions around
image VA **`0x00450C5A` to `0x00450CA3`**. That routine applies
an XOR to a stored state, multiplies by `0x41A7`, reduces modulo
`0x7FFFFFFF`, and stores the result. Its immediate callers and
its relationship to on-disc file creation are not yet established.

**Consequence:** these particular bytes of `dplayerx.dll` are
entirely determined by the PRNG seed and public generator constants;
they cannot additionally encode an arbitrary unknown 165,888-byte
Windows PE/DLL payload without other information. This is strong
evidence of **synthetic/pseudorandom content**, not a conventional
encrypted PE. Whether this file is deliberate disc filler, a
protection auxiliary, or a substituted extraction-stage component
is **not yet established**. The filename and matching historic
DLL size are not sufficient to assign a functional DLL role.

**Corrected ICD result:** The old big-endian offset-zero test
returned only one forced transition because it used a **wrong word
alignment**. With one prefix byte and little-endian words, the ICD
matches **170,890 of 170,890 transitions**, and its full byte content
regenerates exactly. This proves the uploaded ICD bytes are a
deterministic PRNG stream; it does **not** reconstruct a commercial PE.

### Reproduce this result without running DRM code

```sh
python scripts/safedisc_prng_recurrence.py dplayerx.dll --auto-align
python scripts/safedisc_prng_recurrence.py RAYMAN2.ICD --auto-align
python -m unittest discover -s scripts -p 'test_safedisc_prng_recurrence.py'
```

The Rust `inspect --generic-inspect --layout` diagnostic also now
checks this full masked-MINSTD recurrence in all four offsets and
both byte orders. It
reports a **verified match only when at least 256 complete words**
satisfy **every** transition, including the independently derived
XOR salt. Two additional synthetic Rust tests cover a 512-word
little-endian positive case, one-bit corruption, wrong byte order,
minimum sample length, and explicit **rejection of partial
trailing bytes** as a claim of complete-file reconstruction. This
new Rust branch is **not yet compiled**, so those tests are pending
Rust toolchain availability.

The read-only script derives a **candidate** constant from the first
two words via the modular inverse of 16807 and validates **every**
following word. It never writes files. Six synthetic tests check
positive little/big-endian streams, wrong byte order, bit-flip
negative controls, arbitrary opaque input, and input validation.

This finding now applies to **both supplied files**, not just
`dplayerx.dll`. Neither byte stream contains an arbitrary independently
encoded Windows PE without another source of information. Research
should locate/verify the genuine installed game data, compare the
protected/unprotected EXEs already held privately by the owner, and
study the role of these synthetic files. Do **not** attempt to decrypt
these particular PRNG bytes as if they contained executable code.

## Static call-path lead: PRNG-based x86 trampoline (2026-11-13)

Independently disassembled the exact **protected** `Rayman2.exe`
(SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`)
with GNU binutils, without executing it:

```sh
objdump -d -M intel --start-address=0x450C5A \
  --stop-address=0x450D03 Rayman2.exe
```

Key x86 instructions from the protected EXE's `.text`:

| VA | Observation |
|---|---|
| `0x450C5A` | Load PRNG state from `0x510BF0` |
| `0x450C65` | XOR state with `0x075BD924` |
| `0x450C70` | Multiply by `0x41A7` (16807) |
| `0x450CA9` | Signed division by `0x455` to select an offset |
| `0x450CAD` | Add buffer base `0x510EA0` to offset register |
| `0x450CB3` | Store opcode `68` (`PUSH imm32`) in that buffer |
| `0x450CC2` | Store opcode `C3` (`RET`) five bytes later |
| `0x450CC8` | Store the 32-bit immediate after `PUSH` |
| `0x450CF6` | Indirect `CALL ESI` to the constructed stub |

The sequence creates and calls a six-byte **`PUSH immediate; RET`**
trampoline, plausibly for runtime control-flow obfuscation. In other
words, the generator is used in at least one executable-code
construction path; **we have not established a call path which writes
either of the observed ICD/DLL files**. Do not conflate the
mathematically established stream encoding with the unproven
on-disc-file producer.

Separately, [PCGamingWiki's Rayman 2 entry]
(https://www.pcgamingwiki.com/wiki/Rayman_2) records that the
retail release contains **dummy/junk files** in addition to SafeDisc.
This strengthens the *possible* interpretation of these two
completely reproducible streams as protection-related filler, but
does **not** authenticate their specific disc roles.

**Bounded stream comparison:** the correct offset+1 little-endian
ICD stream has **170,891 unique states**; the offset+0 little-endian
DLL stream has **41,472 unique states**, and their observed sets
have **zero overlap**. The next state after the ICD's last is
`0x11F38C41`, not the DLL seed `0x0030FBEC`; the next state after
the DLL's last is `0x1D99DDE9`, not the ICD seed `0x6EE4C08A`.
This excludes immediate concatenation or overlap **in the observed
ranges** only; it is not a general proof that the seeds are unrelated.

## Protected EXE file-I/O and obfuscated indirect calls

Further offline static audit of the original hash-identified
`Rayman2.exe` (`objdump -d -M intel`):

- **73** disassembled `XOR reg,0x075BD924` immediate instructions
  occur in the executable (raw disassembly matches, not a count of
  dynamically reachable functions). This is substantial evidence that
  the masked PRNG is a **reused runtime mechanism**, not solely a
  single CD-file-generation helper.
- At `0x450A80`–`0x450C32`, an apparent file-open wrapper uses the
  PRNG to select an offset within a buffer at `0x510EA0`. It writes
  a short executable stub and invokes it indirectly. A separate
  branch invokes the imported **`CreateFileA` at `0x450C16`**
  (IAT VA `0x0049C058`).
- At `0x450C40`–`0x450D86`, a neighboring wrapper builds
  `PUSH imm32; RET` and calls it at `0x450CF6`. The alternate
  branch calls **`CloseHandle` at `0x450D6F`**
  (IAT VA `0x0049C0E0`).
- The EXE's imports additionally contain `WriteFile`
  (direct call candidate `0x4549BF`). This is generic Windows
  file I/O; no direct reference to the ICD or fake DLL has been
  established, and these observations **do not** prove creation
  of either on-disc PRNG stream.
- Case-insensitive readable-string search finds no literal
  `RAYMAN2.ICD`, `dplayerx.dll` or `dxplayerx.dll` in the
  supplied protected EXE.

**Interpretation:** the obfuscated runtime Win32 calls provide a
concrete target for further control-flow reconstruction. Do not
confuse a widely reused PRNG with evidence that the game
executes or decrypts these two CD-resident synthetic files.

## Validation boundary: full byte coverage versus complete words

The Python `--auto-align` mode and the native Rust generic inspector
now require every byte after an optional 0–3-byte prefix to be accounted
for by complete reconstructed PRNG words. A file ending in additional,
unexplained bytes can still have a 100% matching **word recurrence**,
but **cannot** be advertised as a verified whole-file match.

A new synthetic Python regression test and native Rust tests cover
the partial-tail negative case. The **local Python mirror passes 47
unit tests**; Rust code remains **uncompiled** because no Rust
toolchain is available in the current execution environment.
The Crimson Skies exact-hash-gated decoder remains unchanged.

## Reliability audit — 13 November 2026

**On-owner reference golden tests without distributing binary files:**

- The native Rust `src/unsafedisc_generic_inspect.rs` unit tests
  regenerate the **683,565-byte ICD stream** (prefix `5B`,
  170,891 little-endian words, seed `0x6EE4C08A`) and the
  **165,888-byte DLL stream** (41,472 words, seed `0x0030FBEC`)
  completely in memory from the common masked MINSTD recurrence.
  They assert the original independently verified SHA-256 for both
  outputs. **No proprietary binary fixtures are in the repository.**
- The Python synthetic alignment suite now has an equivalent
  **SHA-256 golden test**, including unique offset/endian detection.
  This golden test passed against locally generated bytes; the
  owner-supplied source files also have matching SHA-256.
- The Rust generic inspector now uses a **bounded file-descriptor
  read** (`MAX_INPUT_LEN + 1` limit), checks the opened file's size
  and modification metadata, and on Unix compares pre-open
  device/inode against the file descriptor. It retains symlink
  rejection and a new test for an oversized sparse file.
  This closes the former unbounded `fs::read` race after a
  pathname-only metadata check. Platform-specific race-hardening
  should still be reviewed during Windows validation.
- The optional CD vs installed-file comparator now rejects
  **self-comparison** via `Path.samefile`. Such a comparison could
  otherwise incorrectly imply independent corroboration.
- The Python PRNG analyzer computes its three-word-window
  diagnostic **once per candidate** rather than twice.

**Verified execution:** local mirror of the Python research suite,
**49 tests passed** after these changes. The native Rust code
has **not** been compiled or executed here: `cargo`/`rustc` are
not installed, and network access for fetching a toolchain is
unavailable. GitHub Actions were deliberately not used.

Recommended next verification when a Rust toolchain is available:

```sh
cargo test --bin unsafedisc-linux
cargo run --bin unsafedisc-linux -- inspect --generic-inspect \
  --loader Rayman2.exe --icd RAYMAN2.ICD --dplayerx dplayerx.dll \
  --layout --sections
```

The first command tests native code using **only synthetic and
regenerated-in-memory** fixtures; the second uses the owner's own
protected files for independent integration validation.

## Next research milestones

1. Verify the original disc and unmodified installer outputs, keeping
   `dplayerx.dll` and `dxplayerx.dll` distinctly identified.
2. Trace the exact game's file-production and loading logic to establish
   **why** the two on-disc files are masked-MINSTD streams and whether
   actual protected payloads exist elsewhere.
3. Compare the owner's hash-pinned protected and independently acquired
   unprotected Rayman 2 EXEs without distributing proprietary binaries.
4. Preserve Crimson Skies exact-hash reconstruction tests and run
   Rust compilation/tests on Linux and Windows when toolchain and
   budget permit; do not merge draft PRs prematurely.

**Neither synthetic PRNG stream has been decrypted into game code.
No generic SafeDisc 1.35 decryption is claimed.**
