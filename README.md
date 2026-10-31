# unSafeDisc — historical SafeDisc research

This standalone repository preserves independent SafeDisc research, native Rust and Python tools, and the legacy Crimson Skies patcher. These files were migrated from [`CrimsonSkiesFix`](https://github.com/legluondunet/CrimsonSkiesFix), which now focuses on its separate DirectDraw `ddraw.dll` project.

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

## Generic read-only inspection (other language editions)

For a different SafeDisc edition, for example the French Crimson Skies files:

```sh
unsafedisc-linux inspect --generic-inspect \\
  --loader crimson.exe --icd crimson.icd --dplayerx dplayerx.dll \\
  --layout --sections
```

Prints sizes, SHA-256, PE32 entry points and section metadata, without using
game-specific keys or offsets. This is **not** decryption, unpacking or
a compatibility assertion. Research flags such as `--strings`,
`--key-research` and `--modifier-research` are prohibited in this mode.
The legacy `inspect` behavior remains exact-SHA-gated.

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

### Full French import-section reconstruction (in memory)

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

The source ICD is still not decrypted beyond imports, and **no EXE is
generated**. `--rebuild-tables` is fail-closed to the exact French ICD
SHA-256 and should not be used on other language editions.

### French executable code / TEA research (read-only)

The French ICD import section and all **245 modified import-callsite
relocation DWORDs** in `.text` can now be reconstructed in memory:

```sh
./unsafedisc-linux inspect-french-callsites --icd crimson.icd --reference testme.exe
```

This restores only the selected relocated IAT pointers; the non-relocated
game code is still encrypted. The tool validates the exact French input
SHA-256 and the expected partially reconstructed `.text` SHA-256.

There is also an **unverified, falsifiable** first-TEA-word hypothesis
for the French edition, using the historical **SHA-verified** Win98 F1/F2
memory snapshot. Its last three TEA words are provisionally inherited
from the previous edition. The command compares all non-relocated
`.text` and `.data` bytes, without writing anything:

```sh
./unsafedisc-linux inspect-french-crypto \
  --icd crimson.icd --reference testme.exe \
  --modifier-snapshot CS98-DLL-00.BIN
```

The snapshot is not bundled with the project and this French-key
hypothesis has **not** yet been tested on its actual contents.
Successful compilation is not evidence that it decrypts the game.
The legacy Windows 98 reference and original files are never bundled.

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
