# unSafeDisc — historical SafeDisc research

This standalone repository preserves independent SafeDisc research, native Rust and Python tools, and the legacy Crimson Skies patcher. These files were migrated from [`CrimsonSkiesFix`](https://github.com/legluondunet/CrimsonSkiesFix), which now focuses on its separate DirectDraw `ddraw.dll` project.


## Legal notice — personal preservation research

This repository is maintained for **private, personal research** into
legacy SafeDisc protection, preservation, and software interoperability.
It does not include or redistribute commercial games, protected game
executables, decrypted game binaries, or proprietary SafeDisc DLLs.
Users are responsible for complying with applicable copyright and
anti-circumvention laws; lawful possession of a game is not, by itself,
an unconditional authorization to bypass its copy protection.

**Warning:** Unlawful use of tools that remove or neutralize software
protection mechanisms may be subject to the legal penalties applicable
to copyright infringement. In France, this warning is addressed by
[Article L122-6-2 of the French Intellectual Property Code](https://www.legifrance.gouv.fr/codes/article_lc/LEGIARTI000006278921/).

**Avertissement (France) :** L'utilisation illicite de moyens visant
à neutraliser une protection logicielle peut entraîner les sanctions
prévues en matière de contrefaçon (article L122-6-2 du CPI).

This notice does not establish that a particular use or distribution
is authorized; the applicable law and the specific circumstances
still determine that question.

## Rust research

- `src/bin/unsafedisc-linux.rs`: native Linux/Windows SafeDisc
  inspection and reconstruction research CLI
- `src/unsafedisc_*.rs`: verified historical unSafeDisc 1.5.5
  disassembly/reconstruction stages and PE section/relocation work
- `src/main.rs`: conservative Crimson Skies EXE/Wine patcher
- `docs/`: detailed SafeDisc 1.x notes and validation evidence
- `archive/legacy-safedisc-102/`: earlier, otherwise unmerged SafeDisc
  secdrv protocol and Wine research source retained for provenance;
  deliberately **not** compiled into the active Rust crate

Build from the repository root:

```sh
cargo test 
cargo build --release 
```

## Native standalone Crimson Skies SafeDisc unwrap — two editions verified

**The Rust `unsafedisc-linux unwrap` command reconstructs the original
Crimson Skies 1.0.2.0 EXE from either of two exact protected editions.**
It runs on Linux and Windows, requires **no Windows 98 memory dump,
original SafeDisc DLL, Wine, or SafeDisc kernel driver**, and recognizes
the edition through an exact SHA-256 match of the protected ICD.

```sh
./unsafedisc-linux unwrap \
  --loader CRIMSON.EXE \
  --icd CRIMSON.ICD \
  --output CRIMSON-UNWRAPPED.EXE
```

You may optionally supply `--reference testme.exe` to verify equality
against a historical unSafeDisc 1.5.5 output. `--modifier-snapshot
CS98-DLL-00.BIN` is also **optional**: when supplied, the tool verifies
that all 57 original F1/F2 arithmetic operations match the standalone
implementation. Neither file is needed to generate an output.

### Validated edition matrix

| Protected edition | ICD SHA-256 (prefix) | Loader bytes | Result |
|---|---|---:|---|
| Original | `0e3b4724…` | 344,851 | Verified |
| French | `f3fe7c1e…` | 344,925 | Verified |

For both editions, the independently generated output is precisely
**2,580,480 bytes**, with SHA-256
`43540fc97347210d6f4c10b77edbd4cdab1f03d57554d638223c2430a6c37d75`.
Both were independently executed on the owner's actual protected inputs
under Linux and checked byte-for-byte with their known Win98 output:
**zero differing bytes**. The optional historical snapshot was also
validated against the native arithmetic; all 57 operations matched.

The output path must **not exist**. SHA-256 gates on source files and
the full reconstructed EXE are enforced before any write. The optional
snapshot and reference are never bundled, nor are any original game binaries.
This is an exact-version preservation tool, **not a generic SafeDisc
decryptor**; actual gameplay and compatibility still need validation.

See [native-unwrapper research](docs/french-crimson-native-unwrapper.md)
for the underlying TEA/F1/F2, import, relocation, and legacy PE format
proofs. The French-specific historical command `unwrap-french` remains
as a compatibility alias for `unwrap`.

## Generic read-only inspection (unknown protected editions)

For a different SafeDisc edition, for example retail CD Rayman 2:

```sh
unsafedisc-linux inspect --generic-inspect \\
  --loader Rayman2.exe --icd RAYMAN2.ICD --dplayerx dplayerx.dll \\
  --layout --sections
```

Prints sizes, SHA-256, Shannon entropy, PE32 entry points and section
metadata for a valid PE32 loader. With `--layout` it also reports
4 KiB block entropy ranges, a bounded hex prefix, superficial `MZ`
occurrences, and the offsets of structurally valid unencrypted PE32
images (if any). The loader must be a valid x86 PE32 executable; ICD
and companion DLL inputs may be opaque without an `MZ` header.
An `MZ` occurrence alone is not an executable. This is **not**
decryption, unpacking, an encryption verdict or
a compatibility assertion. Research flags such as `--strings`,
`--key-research` and `--modifier-research` are prohibited in this mode.
The legacy `inspect` behavior remains exact-SHA-gated.

The `--layout` report also prints per-position high-bit counts in
complete four-byte groups. **That alone cannot determine a word stream's
actual starting offset or endian order.** The native Rust diagnostic
now additionally scans all four offsets and both byte orders for the
complete masked Park–Miller recurrence. This updated Rust code **has
not yet been compiled or tested**.

**Rayman 2 breakthrough (verified locally):** both exact user-supplied
opaque files are entirely deterministic, masked Park–Miller streams
using the **same XOR salt** `0x075BD924`:

| Sample | Word offset / order | Seed | Verified transitions |
|---|---|---|---:|
| `RAYMAN2.ICD` | +1 / little-endian, prefix `5B` | `0x6EE4C08A` | 170,890 / 170,890 |
| `dplayerx.dll` | +0 / little-endian | `0x0030FBEC` | 41,471 / 41,471 |

**Every byte of both files was regenerated in memory**, with exact
SHA-256 matches. The auto-align mode now explicitly **rejects matches
with unexplained trailing bytes**; a complete-word recurrence is not
sufficient to claim whole-file regeneration. The initial big-endian offset-zero reading of ICD was
**incorrect**; its final byte is part of the last little-endian word.
These specific files are reproducible PRNG data, not independently
encoded arbitrary PE executable/DLL payloads. Their **role and
authenticity** on the original game CD remain unverified, and the
discovery is **not** SafeDisc 1.35 executable decryption.

```sh
python scripts/safedisc_prng_recurrence.py RAYMAN2.ICD --auto-align
python scripts/safedisc_prng_recurrence.py dplayerx.dll --auto-align
```

The historical **23 oversized** `DATA/WORLD/LEVELS/*{0,1,2}.DAT`
records omitted by the ISO installer have a combined
**6,777,257,404 nominal bytes** and are **23/23
name-and-size-identical** to entries in GOG's virtual
catalog, independently confirmed with both owner logs.
This illustrates preservation of unusual CD metadata,
**not** proof that the game actually reads those entries
as real file payloads. Six synthetic local tests pass.

**Capacity reconciliation:** After subtracting the 23
exactly corroborated anomalous DAT nominal lengths
(6,777,257,404 bytes), the original ISO's 677,853,184-byte
*logical volume* has **4,951,749 bytes** of nominal slack;
the GOG's separately verified 680,755,200-byte
virtual CD has **4,949,990 bytes**. The margins differ by
**only 1,759 bytes**, while the ISO file has 315,392
bytes of padding beyond its logical volume. This
supports related CD inventories without proving identical
file data or runtime decryption. The read-only
metadata checker reports these values after all 23
corroboration checks; **8 synthetic local tests pass**.

**Original ISO versus GOG catalog (14 Nov):** Two archived Rayman2Fix
CD-inspection logs (Windows and Wine) were independently reconciled
with GOG's hash-pinned virtual-CD catalog, using the new read-only
`scripts/rayman2_cd_log_gog_compare.py`.
The Wine log shows **1,612 matching names and sizes among 1,618
omitted CD records**; the Windows log independently shows
**1,607/1,613**. The same six absent files are Adobe Reader
installers from `ACROBAT/` and **no shared name has a mismatched
declared size**. The original ISO bytes were not available here,
so this verifies historical metadata **only**, not CD content
hashes. See [the reconciliation report]
(docs/rayman2-original-iso-gog-log-reconciliation.md).

**Extended five-file finding (13 Nov 2026):**

**SafeDisc splash-file role and physical-CD caveat:**
Historical SafeDisc sources identify `.016`/`.256`
as **bitmap splash-screen images** (also possible
on SafeDisc 1), and Redump reports physical
C2-error sectors plus `.tmp` placeholder
files in standard SafeDisc mastering.
Yet the exact owner `.016`/`.256`
are **pure PRNG states after two prefix bytes**,
not files starting with BMP magic `BM`.
The `.256` length **308,278 bytes** happens
to equal the full uncompressed **640×480
8-bit BMP** size (54 header + 1024 palette
+ 307200 pixels), without establishing
picture content or intended dimensions.
The owner's ISO9660 2048-byte-sector
image log does not include physical C2
error measurements; file-size matches
to GOG cannot authenticate disc sectors.
See the [eight-file report]
(docs/rayman2-eight-safedisc-auxiliary-streams.md).
Do **not** assume these bytes are working
bitmap resources, a loaded SafeDisc DLL
or the original encrypted ICD payload.

**Eight auxiliary filename cross-references (14 Nov):**
a direct scan of the owner SHA-pinned retail and GOG
EXEs confirms **zero ASCII/UTF-16LE spelling
occurrences of all eight auxiliary filenames** in
the original on-disk game, versus **one ASCII
occurrence each** in the edited GOG binary's
appended virtual-CD catalog. This absence only
rules out *plaintext literal name references
on disk*, not dynamically generated names,
SafeDisc module access or raw-sector reads.
The eight-file read-only audit now optionally
accepts `--retail` and reports the counts
after exact source hash verification. See the
[eight-file research](docs/rayman2-eight-safedisc-auxiliary-streams.md).

**Exact original/GOG obfuscation-site breakdown:**
64 original `MOV ECX,[0x510BF0]`
instruction starts were identified;
**22 survive unchanged in GOG**,
while the other **42** now start
with **31 INT3, 3 NOPs, 4 normal
Win32 forwarding prologues and
4 other edits**. The four
forwarder entry VAs
(`0x448500`, `0x44E750`,
`0x44F220`, `0x44F380`)
match prior independent
`rayman2_win32_forwarders.py`
research. These are **static
instruction-site counts, not
runtime execution evidence**.
See [the runtime PRNG audit]
(docs/rayman2-runtime-prng-bootstrap.md).

**SafeDisc 1.35 is a size fingerprint, not validated loader code:**
the connected GitHub source of
[BurnOutSharp's SafeDisc V1 detector]
(https://github.com/claunia/BurnOutSharp/blob/master/BurnOutSharp/ProtectionFind.cs)
maps `DPLAYERX.DLL` of **165,888
bytes** to `1.35`, and **172,544
bytes** to `1.40` — *using only
the file's length*. Our **165,888-byte
owner sample** therefore matches the
1.35 fingerprint even though its
body is a **complete PRNG stream
rather than a valid PE32 DLL**.
A version-detection hit is not proof
that the loaded 1.35 SafeDisc decoder
exists in these exact bytes.
See [boundary and installer-source audit]
(docs/rayman2-prng-boundary-and-install-exclusions.md).

**Inter-file PRNG continuity and installer-name audit (14 Nov):**
after SHA-256 checking all **eight** owner auxiliary files,
a fully independent local checker advanced
**one million further generated states after
each file**, finding **zero links** to any
other file's effective first generator
state (**8 million transitions; 56 ordered pairs**).
A positive synthetic two-step join was
detected, so the check can find actual
links. This rejects only near-contiguous
assembly; longer gaps and different
initializations remain possible.

An unrelated but actionable
[Rayman2Fix CD exclusion-name discrepancy]
(docs/rayman2-prng-boundary-and-install-exclusions.md)
was also identified: its current root
filter names **`dxplayerx.dll`**,
whereas GOG's catalog and the
owner-supplied PRNG file are
**`dplayerx.dll`** (no X after D).
Neither `CLOKSPL.EXE`, `CLCD32.DLL`
nor `DRVMGT.DLL` is in the six-name
exclusion list. This is a
**file-selection policy review item**,
not an automatic justification to
change or delete files. No
Rayman2Fix code was changed.

**Complete eight-file inverse PRNG reconstruction (14 Nov):**
the previously unexplained **one ICD prefix byte**
(`5B`) and two bytes in each
`0000040C.016`/`.256`
(`AB DE`, `4D C7`)
are **exactly the low little-endian
bytes of the preceding PRNG state**.
The unique preceding words for these
three nonzero states are
`0x5611AA5B`,
`0x47EFDEAB`, and
`0x255AC74D` respectively.
They are recovered by applying the
modular inverse `0x53E77248`
of multiplier `16807`
modulo `2^31-1`, then XOR
`0x075BD924`.
**All eight exact owner file
SHA-256 hashes match the rebuilt
byte streams** without any
independent prefix bytes.
Only **8×31 = 248 variable
seed bits** are needed to specify
the 1,548,525-byte eight-file set
when file lengths and recurrence
are known; the earlier **288-bit**
upper bound is superseded.
The audit now *enforces* the
reverse-prefix check and rejects
nonmatching partial words.
[Mathematical proof and reproducible
file-by-file tests]
(docs/rayman2-eight-safedisc-auxiliary-streams.md).
**No actual SafeDisc executable
decryption is claimed.**

**Runtime PRNG provenance breakthrough (14 Nov):**
[QPC/bootstrap and 8-page GOG code-diff audit]
(docs/rayman2-runtime-prng-bootstrap.md).
The exact **331-byte original and GOG initializer**
is identical, seeded by
`QueryPerformanceCounter`'s low DWORD
(or `0x12345678` on failure), and writes
**281 PRNG states** to `0x510EA0`
before retaining the last value at
`0x510BF0`. The first step requires
**signed 32-bit x86 arithmetic** if the
timer's bit 31 is set. The fallback
ends at `0x7A833570` after 281 steps;
the correct high-bit example
`0x80000000 -> 0x1F0C8C9B`.
An independent C11 arithmetic test passed
**200,000 full-range inputs** and matches
the exact source committed in this branch.

GOG retains **68/196** original-code
references to `0x510BF0`, and **29/73**
XOR salt occurrences at unchanged RVAs,
without adding any new. The **128**
removed state references and **44**
removed salt occurrences are confined
to **8 specific RVA pages**,
separate from GOG's non-executable
archived retail-code copy. Neither
executable contains any of the eight
CD PRNG initial states as literal
DWORDs. This is static code forensics,
**not evidence of an active SafeDisc
decoder or decrypted game payload**.

**New eight-file SafeDisc evidence (14 Nov):** Three further
owner-supplied original-CD-associated files — `00000001.TMP`
(20 bytes), `0000040C.016` (153,718 bytes) and
`0000040C.256` (308,278 bytes) — are also fully reproducible
masked Park–Miller byte streams with the **identical
`0x075BD924` XOR salt**. The `.016`/`.256`
streams begin after **two retained prefix bytes**.
The combined **eight** files total 1,548,525 bytes,
**387,130 observed states, all distinct**,
with **387,122/387,122 verified PRNG transitions**
and zero finite-range overlap. Exact in-memory
regeneration matched all eight owner SHA-256 values.
The new three names/sizes are confirmed in a
Rayman2Fix original ISO inspection log **and** GOG
virtual CD metadata; content equality to the
original physical ISO remains unverified.

The updated `rayman2_auxiliary_stream_audit.py`
and `rayman2_tea_known_plaintext.py`
now accept these three new private inputs.
The direct historical-key TEA known-plaintext scan
also yields **zero matches for the three new files**.
See [eight SafeDisc-era PRNG streams]
(docs/rayman2-eight-safedisc-auxiliary-streams.md).
This does **not** reconstruct a SafeDisc-loaded DLL
or an original game PE, and the 20-byte TMP is only
exact-SHA validated rather than generically
classified from its four transitions alone.

**January 2000 historical Rayman 2 code-stage audit (14 Nov):**
[exact-SHA anchored comparison](docs/rayman2-january2000-binary-anchor-audit.md)
against the paper's claimed **decoded ICD** code identifies
the matching game entrypoint `0x0045FCC0`, but **3/4
tested location-specific opcode prefixes disagree** at their
stated addresses and **all three separately published
byte patterns are absent** from both on-disk retail and
GOG `.text`. The 32-byte code spans at all four
locations are identical between the two current
samples. The paper's author tentatively called the
protection *r3*, whereas a contemporaneous
DPLAYERX size table associates our **165,888-byte**
sample size with *r2*. These are **version/stage
clues, not proof** of a version mismatch or a
completed decryption. The SHA-locked read-only
`rayman2_historical_anchors.py` and **five
synthetic tests** were exercised locally against
both exact owner EXEs; they do not run the game.

**TEA five-file known-plaintext test:** [independently reproduced negative crossmatch](docs/rayman2-tea-known-plaintext-crosscheck.md); both historical key spellings, all overlapping eight-byte offsets, strict source SHA-256 gates and five synthetic tests. **Not an ICD decrypter**.

 three further
owner-supplied files — `CLOKSPL.EXE` (177,152 bytes),
`CLCD32.DLL` (27,648 bytes) and `DRVMGT.DLL`
(32,256 bytes) — are also **entirely reproducible with the same
masked Park–Miller recurrence**. They are individually SHA-256
verified, and their names/declared sizes occur in GOG's virtual-CD
manifest alongside the ICD and DPLAYERX. This does **not**
authenticate the original physical CD or establish whether an
original installer produces different working files.

Use `python scripts/rayman2_auxiliary_stream_audit.py --help`
to verify any subset of the five exact owner samples in read-only
mode. Separately, `scripts/rayman2_historical_tea.py`
reproduces the 2000 historical TEA known-answer vector
and can optionally test all eight naive fixed-key block
alignments for a PE header. **No native Rayman 2 SafeDisc
unwrapping is implemented or claimed.**

The two streams have no shared 31-bit state in their sampled ranges
and do not follow one another immediately. This does **not** prove
their seeds are globally independent, only that these two specific
byte ranges are distinct. PCGamingWiki documents junk/dummy files
on retail Rayman 2 discs; that context supports—but does **not prove**—
an auxiliary/filler explanation for the two deterministic samples.

See [Rayman 2 SafeDisc 1.35 research](docs/safedisc-135-rayman2-research.md)
for the complete proof, limits, and next steps.

**Regression and safety status (13 Nov 2026):** The Rust generic
inspector now has **golden SHA-256 tests** that regenerate both PRNG
streams in memory using only seeds and arithmetic (no bundled game
files). File input is limited to 16 MiB and is read through an open
file handle with size/modification checks and Unix device/inode
verification. The original CD/installation comparator also refuses
to compare a directory against itself.

Locally, **49 Python mirror tests pass**. Rust has **not yet been
compiled**: `cargo`/`rustc` are unavailable in the working
environment. Before merging the stacked draft PRs, run:

```sh
cargo test --bin unsafedisc-linux
```

**Reference provenance warning:** The 1,468,928-byte reference executable
below is from the **GOG edition**. Although it is DRM-free and its hash
is known, it may contain unrelated GOG/third-party modifications.
Differences from the original CD executable, including `INT3`/`NOP`
bytes and added sections, **cannot be attributed exclusively to
SafeDisc removal**. The 3,716-entry inventory resides in this GOG
reference; it is **not an independently authenticated original-CD
manifest**.

**Important new GOG provenance finding:** The added GOG section
`.extra` contains the **entire 631,296-byte protected CD `.text`
section verbatim**, starting at internal offset `0x1000`,
surrounded by exactly 4,096 leading and 3,584 trailing zero
bytes. Its byte-for-byte SHA-256 matches
`43ce6eff6082f2c7491cd249d3cfeffbcb56e63313a67246dd2b14f1985751c3`.
The `.extra` section header is **readable, not executable**
(`0x40000040`). Thus the x86 instructions seen there are
**copied original protected code**, not evidence of independently
added GOG functions. No specific runtime behavior or SafeDisc-only
modification is inferred.

The `pe_reference_diff.py` tool now reports exact copies of
nontrivial sections inside differently named PE sections, including
the copy's byte offset, RVA, hash, padding and section flags.
Two new synthetic tests verify exact matches and reject one-bit
changes and all-zero false matches.

**Evidence of GOG-specific manifest use:** The GOG `.text` contains
`MOV EDI, 0x005B3000` at VA `0x00448F80` and
`MOV ESI, 0x005B3000` at `0x00448FD7`, pointing exactly to
its `.extra2` table. Static loops at these locations traverse
the entries and appear to perform filename/claimed-size lookups.
The retail protected bytes at these VAs are different. The table
is therefore used by identifiable **GOG-specific code**, not an
independently verified original-CD installation manifest.
Runtime reachability and file-system behavior remain untested.

`pe_reference_diff.py` now also reports literal references to
added section base VAs, cautiously labeled byte-pattern candidates.
The local synthetic comparison suite passed **13 tests**.

**GOG includes static optical-disc compatibility callbacks
(not present in the retail code at those addresses):**
its shared dispatch table installs functions at
`0x448E6C` (fixed `RAYMAN2`/`CDFS` volume
information), `0x448EC4` (returns Win32
`DRIVE_CDROM = 5`) and `0x448ED0`
(reports 2048-byte sectors and 332400
total sectors). The same GOG dispatch table
also installs path and file-size lookup
functions backed by its `.extra2` manifest.
This is strong **static evidence** for
GOG's disc-less compatibility adaptations.
No runtime calls, physical disc properties,
or SafeDisc-only change origins are proven.

**Bootstrap guard check:** the shared
`0x449360` initializer first tests
`0x5113EC`, a virtual-zero-fill
`.data` value. The nonzero branch returns
early; the zero branch runs the preparations.
The generic read-only `descriptor_asm_xrefs.py`
scanner found **28 direct reads / 0 direct
writes** in the retail linear disassembly
and **16 reads / 0 direct writes** in GOG
for this exact address. These counts do
not exclude indirect writes or demonstrate
the live guard value.

**Complete GOG dispatch map (static, read-only):** The
initializer at `0x00467130` fills **16
four-byte callback slots** (`+0x00` through
`+0x3C`). Independent analysis finds
**15 literal function addresses and one
import pointer read from `[0x0049C0C8]`**
(the `+0x34` slot). The latter cannot
be inferred to be a fixed target address.
The generic research utility
[`pe_callback_table_map.py`](scripts/pe_callback_table_map.py)
can reproduce the mapping from an owner's
`objdump -d -M intel` output:

```sh
objdump -d -M intel Rayman2-GOG.exe > gog-disasm.txt
python scripts/pe_callback_table_map.py \
  --objdump gog-disasm.txt \
  --start-va 0x467130 --end-va 0x467206 \
  --expected-slots 16
```

The **five synthetic unit tests** pass
locally; the complete 16-slot GOG mapping
was also checked offline. Results are
only candidate x86 assignments, not
proof of code execution or SafeDisc-only
changes.

**GOG virtual CD-ROM compatibility callbacks (static evidence,
13 Nov 2026):** The GOG callback initializer assigns:
`+0x10 → 0x448EC4` (returns **5 = `DRIVE_CDROM`**),
`+0x28 → 0x448E6C` (writes volume label
**`RAYMAN2`**, file system **`CDFS`**,
serial `0x6D380AE8`, component length 110,
flags 5), and `+0x0C → 0x448ED0`
(writes **1 sector per cluster, 2,048 bytes per
sector, 0 free clusters and 332,400 total clusters**).
The last values describe a **680,755,200-byte /
649.22-MiB apparent CD-ROM**. The function
signatures and stack cleanups correspond to the
Win32 APIs `GetDriveTypeA`,
`GetVolumeInformationA` and
`GetDiskFreeSpaceA`.

These constants and callback-table stores were
verified against the owner-supplied GOG EXE's exact
SHA-256. **No live invocation or real CD geometry
was measured**; this cannot be attributed to SafeDisc
alone or copied directly into a retail-CD fix.
See [the Rayman 2 research notes](docs/safedisc-135-rayman2-research.md)
for the three instruction addresses, verification
limits and source references.

**The GOG virtual-CD layer also synthesizes file metadata:**
The retail encoded export descriptors #31
(`GetFileInformationByHandle`) and #34
(`GetFileTime`) correspond exactly to GOG
callbacks `0x449010` (table `+0x1C`) and
`0x448F18` (`+0x24`). GOG returns a fixed
FILETIME equivalent to **1999-09-07 09:10:06 UTC**
and the same synthetic disc serial
`0x6D380AE8`. Crucially, its
`GetFileInformationByHandle`-like callback
calls the `0x448FD0` `.extra2` manifest-size
lookup, then places the result into the
`nFileSizeLow`-style field of its output.
This is independent static evidence that
the 3,716-entry GOG file inventory supplies
**synthetic file metadata**, not merely
names. Full runtime contract compliance
is **not established**.

Five GOG callbacks are now mapped to exact
retail encoded API export names:
`GetDriveTypeA`, `GetVolumeInformationA`,
`GetDiskFreeSpaceA`, `GetFileTime`,
`GetFileInformationByHandle`.
**16/16 local real-file tests pass**.
Do not confuse GOG's hard-coded answers
with the true retail disc's properties.

**GOG also emulates CD-ROM properties (static evidence):**
Three callbacks in the GOG-specific dispatch table return fixed
answers resembling Win32 CD-drive functions:

- Slot `+0x10` → `0x448EC4`:
  `MOV EAX,5; RET 4` (`DRIVE_CDROM`, `GetDriveTypeA` signature).
- Slot `+0x28` → `0x448E6C`: writes
  `RAYMAN2`, `CDFS`, serial `0x6D380AE8`
  and other hard-coded volume information
  (`GetVolumeInformationA`-like signature).
- Slot `+0x0C` → `0x448ED0`: reports
  2048-byte sectors, one sector per cluster,
  0 free clusters and 332,400 total clusters
  (`GetDiskFreeSpaceA`-like signature).
  Its reported capacity is 680,755,200 bytes.

These are **hard-coded GOG outputs**, not authenticated
properties of the original CD. The functions were
identified by exact instruction and parameter-layout
inspection, **not by running the game**.
See `docs/safedisc-135-rayman2-research.md`.

The generic PE analyzer now classifies
`MOV EAX,imm32; RET imm16` return stubs,
including the 8-byte drive-type example above;
its synthetic regression test is committed.
Independent local real-file byte checks passed
**13/13**. No protected binaries are committed
and no GitHub Actions run was launched.

**GOG startup bypass identified statically (13 Nov 2026):**
The direct CD/GOG startup call `0x401EFA → 0x449360`
and the **complete 331-byte initializer at `0x449360`**
are byte-identical. GOG nevertheless replaces the
three called preparation functions
`0x4478A0`, `0x448DB0`, `0x448D80`
with single-byte `RET` entries; `0x447DE0`
also becomes `RET` and `0x448DE0`
becomes `XOR EAX,EAX; INC EAX; RET`.
This explains how GOG can keep the original
`CALL` instructions without necessarily entering
the `INT3` padding behind those entries.
The branch of `0x448E30` at `0x448E5A`
is also replaced by a short code path that writes
an ASCII `'.'` byte and returns.

**PE zero-fill distinction:** original and GOG
`.data` have identical **virtual size `0x776D0`**
but only **`0x7C00` raw-backed bytes**.
The state at `0x5113EC`, iteration bounds
`0x5113E8`/`0x5113F0` and generated-stub
buffer `0x510EA0` lie in the **virtual
zero-filled tail**. They do **not** have
file-backed initial values, and their runtime
values may change.

Use the read-only comparison options:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --entry-va 0x4478a0 --entry-va 0x448db0 \
  --entry-va 0x448d80 --entry-va 0x447de0 \
  --entry-va 0x448de0 \
  --map-va 0x510ea0 --map-va 0x5113ec \
  --code-span 0x449360:331
```

These are **stored-binary observations**, not
proof of runtime reachability, a Windows/Wine
validation or a generic SafeDisc removal method.
The comparison code has **seven new synthetic
tests** for return-stub classification and virtual
data-tail handling, while independent local
checks of the exact retail/GOG files pass.

**GOG is not a drop-in implementation of the retail import
resolver (verified 13 Nov 2026).** The GOG reference replaces
the retail DLL-name decoder `0x004474D0` (106 bytes),
export-name matcher `0x00447730` (357 bytes)
and masked export resolver `0x00447AF0` (233 bytes)
**entirely with `INT3` instructions**. A common
178-byte part of the initializer at `0x004493F8`
remains unchanged, but its runtime reachability is
unknown. GOG also replaces the PRNG-based calculation
at `0x00470051` and `0x0047B1C3` with
`MOV EAX,0x00517000` and a short jump, introducing
literal pointers to the **beginning of `.extra`**.
That is the padded non-executable section containing
the exact original `.text` copy, **not proof that
the copy executes**.

The general-purpose `pe_reference_diff.py`
now offers bounded `--code-span VA:SIZE` to
compare exact code bytes, NOP/INT3 changes and
hashes between the protected retail and GOG files:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --code-span 0x4474d0:106 \
  --code-span 0x447730:357 \
  --code-span 0x447af0:233
```

**Do not infer runtime function calls, a safe retail
deprotection patch or any SafeDisc-only provenance
from these byte-level differences.** Four new synthetic
code-span tests were added; Rust remains uncompiled
and GitHub Actions were not triggered.

**Masked callback writer and export-name lookup now identified
(13 Nov 2026):** The retail `0x004493F8`
initialization path sets a 7-module and 36-record
iteration bound, then calls `0x00448D80` to
iterate indices **1–35**. Each iteration calls
`0x00447AF0`, which resolves an export through
module/export-name metadata and writes
`resolved_address XOR record_mask` to the
corresponding `+0x30` descriptor slot through
an **indexed store at `0x00447BC2`**.
On unsuccessful resolution, the slot may instead
be cleared. **This identifies the static writer,
not any actual runtime-resolved function address.**

The module and API names can also be decoded
without executing the game. The retail executable
contains **7 encoded DLL names** at `0x004A1268`
(stride 45) and **35 obfuscated API names** at
`0x004A141C` (stride 76); the latter
reference **33 KERNEL32.dll and 2 PSAPI.dll
exports**. GOG changes the seven DLL names to
uppercase plaintext NUL-terminated strings while
leaving the 35 API descriptors **unchanged**.

```sh
python scripts/pe_masked_api_inventory.py Rayman2-CD-protected.exe \
  --module-base 0x4a1268 --module-stride 45 --module-count 7 \
  --api-base 0x4a141c --api-stride 76 --api-count 35 \
  --module-selector-offset 0x34 --pointer-slot-offset 0x30
# For the GOG executable: add --module-mode plain
```

A separate `descriptor_asm_xrefs.py` read-only
scanner classifies direct address uses from
`objdump -d -M intel`. In the retail
`.text` it found **97 direct reads,
30 address literals and zero direct absolute
writes**; the **actual indexed write**
at `0x00447BC2` is the critical exception
that makes those raw statistics insufficient.
The new tools have **12 synthetic tests**;
the local research mirror passed **32/32 tests**.
Rust changes still require compilation,
and no proprietary binary is committed.

**Retail on-disk XOR descriptor structure (new):** A `.data`
block beginning at VA `0x004A141C` contains **35 nonzero
76-byte records**, followed by a 36th all-zero record.
The whole **2,736-byte block** is identical in the
protected CD and GOG executables (SHA-256
`f4a498cafd1b76536b3367c27b5fc6142b918ecc4525cadb0c2df4c8f2951cd5`).
For every record, the DWORD at offset `+0x30` is zero
on disk. **12 masked callback slots** in the retail
initializer use a record's first DWORD and that
`+0x30` DWORD as XOR operands. A retail routine at
`0x0044F28C` dynamically constructs instructions
equivalent to `mov eax,[slot]; xor eax,[mask]; jmp eax`.
**The actual runtime target values are not known.**
GOG keeps the on-disk records unchanged but installs
several callbacks explicitly.

The read-only `pe_reference_diff.py` tool can now
inspect this generic fixed-stride layout and individual
on-disk XOR pairs without asserting decoded pointers:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --descriptor-layout 0x4a141c:0x4c:36:0:0x30 \
  --masked-pair 0x4a1660:0x4a1630
```

**GOG callback-table linkage (static, read-only):** Both retail
protected and GOG PE32 files call the same callback initializer
at VA `0x00467130`, from identical `CALL rel32` sites at
`0x004674C8` and `0x0047B01B`. GOG changes the initializer
to place literal pointers to its file-name lookup
(`0x00448F60`) and file-size lookup (`0x00448FD0`)
into table slots `+0x08` and `+0x20`,
respectively. The retail initializer instead uses
XOR-masked pointer values from global memory, whose
**on-disk** values do not directly resolve to the
GOG addresses. There is **no proven SafeDisc-only
patch or runtime call path yet**.

The PE comparator can independently compare direct
`E8 rel32` and `MOV reg,imm32` **byte-pattern
candidates** in both images:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --trace-va 0x467130 --trace-va 0x448F60 \
  --trace-va 0x448FD0 --trace-va 0x449010
```

Results are research hints, **not a disassembly or proof
of runtime reachability**. The specific addresses above
were independently checked against GNU objdump output.
This comparison must never be used to blindly replay
GOG changes onto the original CD executable.

**New direct EXE comparison:** The owner's independent 1,468,928-byte
GOG `Rayman2.exe` (SHA-256 `9bae484b…`) and the
676,352-byte protected EXE (SHA-256 `7927a106…`) share the same
entry RVA and unchanged import/export data directories. When aligned
by PE section RVA rather than file offsets, **97.8981% of backed
`.text` bytes, 100% of `.rdata`, and 99.5999% of `.data`
are identical**. Of 13,269 changed `.text` bytes, **10,851
become `INT3` (0xCC)**; the GOG reference additionally has
`.extra`, `.extra2` and `.rsrc`.

Its `.extra2` contains a length-prefixed inventory of **3,716
file names and claimed lengths from the GOG image**, including exactly
matching sizes for `RAYMAN2.EXE`, `RAYMAN2.ICD` and `DPLAYERX.DLL`.
The declared sizes add up to **7,453,062,614 bytes (7.45 GB)**:
this manifest is **not** an extraction plan or proof of physical
disc extents (many entries are oversized/fake).

Use the generic, read-only PE/manifest analyzer with the owner's
own copies:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-protected.exe \
  --reference Rayman2-GOG.exe \
  --manifest-section .extra2 \
  --focus-name RAYMAN2.EXE \
  --focus-name RAYMAN2.ICD \
  --focus-name DPLAYERX.DLL
python -m unittest discover -s scripts -p 'test_pe_reference_diff.py'
```

This comparator has **13 synthetic tests validated locally** against
the independently developed working copy. The native Rust inspector
remains uncompiled; no new GitHub Actions runs have been triggered.
Neither this analysis nor the presence of `INT3` constitutes a
universal SafeDisc 1.35 decryption.

The optional Python 3 read-only research tools expose reproducible JSON without
executing or decrypting protected files:

```sh
python scripts/safedisc_v1_probe.py --loader Rayman2.exe --icd RAYMAN2.ICD --dplayerx dplayerx.dll
python scripts/pe_import_xrefs.py Rayman2.exe
python scripts/compare_safedisc_stages.py --cd-root "/path/to/original/CD" --installed-root "/path/to/original/install"
python -m unittest discover -s scripts -p 'test_*.py'
```

`pe_import_xrefs.py` maps PE32 static imports and candidate `FF 15`/`FF 25`
IAT references in executable sections; the results are byte-pattern
candidates, **not** proof that the instructions execute or belong to SafeDisc.

`compare_safedisc_stages.py` compares sizes and SHA-256 for root-level
`rayman2.exe`, `rayman2.icd`, `dplayerx.dll`, and
`dxplayerx.dll` between independently supplied CD-extraction and
original-installation folders. It refuses ambiguous names and symlinks;
missing or changed files do not automatically mean corruption.
A 2002 Wine developer FAQ associates the **165,888-byte**
`dplayerx.dll` with SafeDisc **1.35.0**, but actual source authenticity
and any needed install-time transformation remain unverified.

## Verified French SafeDisc import-name decoding

The native Rust CLI can reconstruct **136 protected KERNEL32/USER32 API-name
records** from the exact SHA-256 verified French `CRIMSON.ICD`, fully in
memory, with no Windows 98 dependency:

```sh
./unsafedisc-linux inspect-import-codec --icd crimson.icd --reference testme.exe
```

The `--reference` option is optional, but with the owner-provided historical
Win98 unSafeDisc 1.5.5 `TESTME.EXE` it verifies that the 2,234 modified
API-name bytes match the known-good output exactly. It leaves 1,126
additional `.idata` changes unrelated to these names.

The recovered name transform is a running XOR with an initial byte `0xC1`;
the two-byte encoded record header stores `name_length+1` and the first
ASCII character XOR `0x3D`. Three bounded, validated regions in the
exact French ICD are supported. This is **only a name decoder**, not an
EXE unpacker, import-table rebuilder or SafeDisc removal utility.
Files on disk are never modified. Other hashes/versions are rejected.

### Historical French import-section inspection (in memory)

The next research stage extends the 136 verified API names to the entire
`.idata` section of the exact French ICD:

```sh
./unsafedisc-linux inspect-import-codec \
  --icd crimson.icd --rebuild-tables --reference testme.exe
```

- Discovers the import-pointer XOR constant **0x6A966E30** directly from
  the 134 nonzero protected thunk words and the 136 encoded name-record
  RVAs; all 134 resolve to distinct valid name addresses.
- Reconstructs ILT and IAT using two version-specific **permutation tables
  derived offline from the owner's historical Win98 output**. The permutations
  are reference-guided metadata, not a general SafeDisc shuffle algorithm.
- Restores the 21 descriptor timestamps and two historical DLL name-case
  bytes for exact output formatting.
- Checks the complete rebuilt **16,384-byte** `.idata` section against
  its fixed SHA-256 `c8674927a6a2f6c53330b9692dca084084cb5cfef9acc3ecaab1bb8a0cbd7534`.
  The optional historical reference verifies 0 remaining differing bytes.

The `inspect-import-codec` command remains **read-only**. The unified
`unwrap` command now assembles an exact-version EXE.
Both paths are fail-closed to the exact French ICD SHA-256.

### French executable code / TEA research (read-only)

The French ICD import section and all **245 modified import-callsite
relocation DWORDs** in `.text` can now be reconstructed in memory:

```sh
./unsafedisc-linux inspect-french-callsites --icd crimson.icd --reference testme.exe
```

This read-only diagnostic restores only the selected relocated IAT pointers; the non-relocated
game code is unchanged by this diagnostic. The separate `unwrap` command decrypts it. The tool validates the exact French input
SHA-256 and the expected partially reconstructed `.text` SHA-256.

The previous hypothesis that the French import XOR was the first TEA
word and the other three TEA words remained unchanged was **disproved**
using the owner-supplied Win98 snapshot. A correct key was subsequently
reconstructed from the French relocation-excluded `.text` checksum,
the original CRPE loader raw words and the historical 1.5.5 key schedule:

```text
checksum = 0x5C03ECF6
TEA      = 6A966E30 F7C77870 D110DFA0 9CF5E390
```

The `inspect-french-tea-tail` command validates all 58,076 unchanged
fragment-tail bytes. The `inspect-french-crypto` command, with exact
`--loader`, `--icd`, `--reference` and `--modifier-snapshot`, validates
**1,855,489 / 1,855,489 non-relocated `.text` bytes** and
**168,072 / 168,072 non-relocated `.data` bytes**, without writing a file.
The separate `unwrap-french` command now combines these stages.

## Python v0.9 prototype (restored from the original archive)

The separate **Crimson Skies unwrapping prototype v0.9** is preserved
unaltered in `python/unwrapper/`:

- `crimson_unwrap_candidate.py` — SHA-pinned candidate PE32 unwrapper
- `analyze_modifiers.py` — bounded analysis of F1/F2 modifications
- `historical_output_profile.py` — exact-title historical output style
- `import_site_rvas.txt`, `permutation_metadata.txt`
- `README-FR.md` — original French documentation and limitations

This is **not** a generic SafeDisc remover. It targets an exact known
Crimson Skies 1.0.2.0 version, requires the owner's original protected
ICD and a separate SHA-validated Win98 memory snapshot
(`CS98-DLL-00.BIN`), and does not ship game binaries or snapshots.
Output candidates were compared with an historical reference, but
**successful gameplay was not established by that comparison**.
Read the original `python/unwrapper/README-FR.md` before use.

## Python v0.8 historical snapshot

The earlier independent v0.8 Python prototype is also retained in
`python/archive/v0.8/` with its exact original source and French
README, so comparisons with the later v0.9 implementation remain
possible. The shared `analyze_modifiers.py` and static metadata files
are preserved byte-for-byte in both versions.

## Additional Python/Wine research

`scripts/` contains the restored `analyze-safedisc-relay.py`
and `winedbg-export-breakpoint.py` helpers from the historical
`feature/safedisc-102-pair-validation` branch, along with their
unit tests and shell probe. They are separate from the v0.9 unwrapper.

Run synthetic, offline Python checks:

```sh
python -m compileall -q python/unwrapper scripts
python -m unittest discover -s scripts -p 'test_*.py'
```

## CI isolation

The research workflows are `build.yml` (Windows patcher) and
`unsafedisc-linux.yml` (Linux/Windows research). They run only for this dedicated research repository, independently of the CrimsonSkiesFix DirectDraw DLL project.

Licensed GPL-3.0-or-later; see the top-level LICENSE.

## Provenance

Migrated from `legluondunet/CrimsonSkiesFix` (branch `feature/crimsonfix-ddraw-proxy-poc`, commit `eb0d7203ca8bd078986b77eafd9ab96e56d23ceb`) on 2026-10-30. No proprietary game executables, DLLs or RAM snapshots are distributed.
