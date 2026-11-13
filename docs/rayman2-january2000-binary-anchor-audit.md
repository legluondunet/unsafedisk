# Rayman 2 — 2000 SafeDisc paper vs owner's original game EXE

**14 November 2026; read-only forensic comparison.** The source is ArthaXerXès, *The Twilight of Safedisc*, 25 January 2000: https://www.scribd.com/document/659005728/safedisc. The two actual on-disk source files were identified by full SHA-256 before examination:

- Original CD-sourced `Rayman2.exe`: 676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- Separately modified GOG `Rayman2.exe`: 1,468,928 bytes, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.

The historical author thought the analysed SafeDisc revision was **r3**, explicitly expressing uncertainty. Historic CD Media World version listings classify a 165,888-byte DPLAYERX file with **r2** and 172,544 bytes with **r3**. This is **suggestive of a revision mismatch only**: neither filename/size nor the author's uncertain version label authenticates a decoder or CD. Source: https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc.shtml.

## Independent byte-level tests

The paper describes a decoded ICD entrypoint at `0x0045FCC0` and a 631,296-byte (`0x9A200`) game `.text`. **Both characteristics match the owner's on-disk original executable**, and the historical first 10 prologue bytes match as well.

Three additional **historical code-location anchors** were checked in the owner's original and GOG code sections:

| Source paper's VA | Claimed historical opcode prefix | Original on-disk PE | GOG on-disk PE |
|---|---|---|---|
| `0x0045FCC0` | entrypoint's `PUSH EBP; MOV EBP,ESP; PUSH -1; PUSH 0049C9D0h` | **match** | **match** |
| `0x004028FD` | `PUSH 2` preceding checksum call | **not found at that VA** | **not found at that VA** |
| `0x004115D9` | `PUSH` of section offset in checksum dispatch | **not found at that VA** | **not found at that VA** |
| `0x004124F0` | `SUB ESP,104h` at beginning of the paper's CD check routine | **not found at that VA** | **not found at that VA** |

Importantly, **all four 32-byte spans at these four VAs are byte-identical between the owner's CD and GOG samples**; thus differences between the paper and these particular spans are not explained by GOG modifying them at the same address.

Three longer literal hexadecimal signatures explicitly suggested in the original paper are absent from **both** on-disk `.text` sections:

| Original essay's byte motif | Original occurrences | GOG occurrences |
|---|---:|---:|
| `0F 85 35 01` (historical local-file branch) | 0 | 0 |
| `55 8B EC 83 EC 0C 53 56 57 EB 01 EE` (historical checksum routine) | 0 | 0 |
| `02 EB 0B EB FC D7 E1 4A 76 BA 98 05 A5 0D 8B` (historical checksum-patch context) | 0 | 0 |

These are **literal byte scans, not exhaustive decompilation**, and the study's various code snippets may describe **memory after decoding** rather than the CD-sourced bytes. Differences could be a variant version, installed-stage transformations, runtime modifications, or historical transcription errors; *this result alone does not settle which*.

## Independent original game-program identity evidence

Both exact SHA-256-pinned owner files have an identical PE32 export
directory with **110 export-address entries**, an internal
export-module name **`MainWinf.exe`**, and COFF/PE timestamp
`0x3807B68B` (15 October 1999, 23:19:39 UTC).
Among its human-readable exports are `SND_PrintUsedStaticMemory`,
`SND_fn_bInitDataLoadSnd` and multiple
`_SND_fn_b...@` engine audio functions.

These are independently obtained with GNU binutils:
```sh
objdump -p /private/original-Rayman2.exe
objdump -p /private/GOG-Rayman2.exe
```
This is positive evidence of actual native game code with a
game-engine API/export table already present **on disk**,
not merely a tiny generic opaque SafeDisc bootstrap.
It is **not** an assertion that all the original game
code has been unwrapped, that a runtime CD check
cannot exist, or that a PE timestamp proves provenance.

Both editions also import `KERNEL32.dll!GetModuleFileNameA`,
`GetFileAttributesA`, `CreateFileA` and
`GetProcAddress` under their usual PE import names;
**neither file has a direct `GetDriveTypeA` nor
`DeviceIoControl` import**. Because the game already
resolves Windows API pointers dynamically, that
absence does **not** rule out a delayed or obfuscated
API resolution at runtime. It does mean that the
historical essay's CD check must **not** be presumed
to reside unchanged at its old address in this
file, simply because the entrypoint matches.

## PE code layout caution

The original `.text` has `0x9A200` raw bytes (631,296) and virtual size `0x9A1D0`. GOG `.text` occupies `0x9B000` physical bytes (634,880). **Its additional 3,584 trailing bytes are all zero padding**. For meaningful original/GOG comparison only the first `0x9A200` bytes are comparable as corresponding content, and previous 97.8981% identity pertains to this common span. The extra GOG `.extra` section copies this *original* 631,296-byte `.text` separately as non-executable data.

## Interpretation and remaining barrier

The on-disk executable already contains readable native x86 game code and the DAT metadata/selector machinery. **An entrypoint prologue alone is not a known-answer test for a SafeDisc 1.35 decryption.** The historical paper's specific byte locations are not stable anchors for our SHA-256-gated edition. The owner's `RAYMAN2.ICD`, `DPLAYERX.DLL` and three related auxiliaries are exactly regenerable PRNG streams, not available memory-loaded executable sections.

This comparison **does not** establish that the user's EXE is fully SafeDisc-unprotected, that the five files are inert, that the original physical media bytes are authenticated, or that the historical algorithm would fail on an actual loaded DPLAYERX from the same edition. A post-loader memory snapshot or an original-CD/install stage trace is needed to resolve this.

Reproduce with the exact owner's private inputs:

```sh
python scripts/rayman2_historical_anchors.py \
  --retail /private/original-Rayman2.exe \
  --gog /private/GOG-Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_historical_anchors.py'
```

The tool is read-only, exact SHA-256 gated, does not reveal proprietary bytes, and contains synthetic-only tests. **5/5 local synthetic tests and the two-real-binary integration audit passed.** The published GitHub blobs of the script and tests match the locally tested files (SHA-1 Git blobs `629935a37c1e5f06a444d160285484333a048ccc` and `d9aca5823c4f93d0a5ab4d7844c73b4db4bb3103`). No Wine execution, native Rust build, or GitHub Actions job was requested.