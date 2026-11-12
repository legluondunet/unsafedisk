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

## Generic read-only inspection (other language editions)

For a different SafeDisc edition, for example the French Crimson Skies files:

```sh
unsafedisc-linux inspect --generic-inspect \\
  --loader crimson.exe --icd crimson.icd --dplayerx dplayerx.dll \\
  --layout --sections
```

Prints sizes, SHA-256, Shannon entropy, PE32 entry points and section
metadata where a valid PE32 exists. For opaque on-disk ICD or DLL data
without an MZ header, it reports the file without rejecting the whole
inspection. This is **not** decryption, unpacking, an encryption verdict or
a compatibility assertion. Research flags such as `--strings`,
`--key-research` and `--modifier-research` are prohibited in this mode.
The legacy `inspect` behavior remains exact-SHA-gated.

See [Rayman 2 SafeDisc 1.35 research](docs/safedisc-135-rayman2-research.md)
for a second set of original protected inputs and planned work.

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
