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
