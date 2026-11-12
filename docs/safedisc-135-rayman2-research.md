# Rayman 2 retail CD — SafeDisc 1.35 research

Status: **read-only classification implemented; native unwrapping not implemented.**

The user reports that [Redump disc 47594](https://redump.org/disc/47594/)
identifies this disc as SafeDisc **1.35.000**. This is a hypothesis to validate
against the protected loader and the specific uploaded files; the tool does
not infer a SafeDisc version from a filename, file size, or entropy.

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

## Next research milestones

1. Identify and document the protected loader's format and the specific
   SafeDisc version using reproducible evidence, with no execution of
   unknown binaries or protected DLL code in the inspector.
2. Map the encrypted/compressed container boundaries and decode transforms
   from primary evidence, rather than reusing unverified title-specific
   Crimson Skies offsets and keys.
3. Reconstruct PE sections, imports, entry points and metadata and validate
   independently against legitimate user-owned references where available.
4. Keep the existing Crimson Skies hashes and output checks intact; test
   Windows and Wine gameplay only after a sound reconstruction is produced.

**No generic SafeDisc 1.35 decryption is claimed at this stage.**
