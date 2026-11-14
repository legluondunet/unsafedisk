# Rayman 2 — data-driven DAT fallback, path list and GOG relative paths

**14 November 2026. Read-only audit on the owner's exact CD-sourced and GOG PE32 executables.** This extends `rayman2-dat-loader-caller-chain.md` and `rayman2-dat-io-gate-and-index-bounds.md`. It is **not** a SafeDisc unwrapping or a game-runtime trace.

## Inputs and evidence boundaries

| Role | Size | SHA-256 |
|---|---:|---|
| Original CD-sourced `Rayman2.exe` | 676,352 bytes | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG-modified `Rayman2.exe` (not pristine retail) | 1,468,928 bytes | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

All reported code-span checks use the **active `.text`** section and actual PE virtual address mapping (never GOG's archival `.extra` copy). Strings were separately checked through the file-backed **`.data`** section. The tool reads files strictly, verifies both whole-file hashes and opcode anchors against disassembly, and never edits or executes either binary.

## New observation: the fallback search and path-table loader are byte-identical

The complete original **`0x44D990..0x44DC3F` (688 bytes)** resource fallback is **byte-for-byte unchanged in GOG**. The original path-list loader **`0x44F9A0..0x44FA7B` (220 bytes)** and its `0x44F8B0..0x44F927` record reader (120 bytes) are likewise unchanged. The `0x4508A0..0x45093A` (155 bytes) binary dispatch function also matches exactly. Four SHA-256 subrange fingerprints are recorded in the machine-readable JSON.

`0x44D990` first tries the known DAT path through `0x44D9F4 -> 0x44E8A0` (which calls `0x44EB40`). If that stage says failure, the branch at `0x44D9FE` goes to `0x44DA09`, where a second search selects a name/path from an **in-memory table**. The fallback also contains an independent `0x450A80` file-opening call, a drive-prefixed retry and the original message-box retry/cancel path. This establishes a *resource search and fallback*, **not** a confirmed physical-CD authenticity decision.

## The table is populated from a binary resource stream, not hardcoded protection names

The original `0x4508A0` function reads a binary tag through `0x44F950`, checks it against `0x78`, and dispatches through two embedded read-only tables at `0x45097C` (121 one-byte case selectors) and `0x45094C` (12 virtual-address targets). Both tables are byte-identical in CD and GOG.

**Exact decoded dispatch:** input tag **`0x1E`** maps to case **1**, jumps to `0x4508DB`, and calls `0x44F9A0`. Within that list parser, **`0x1F`** is the path-record tag. The list terminates on tag `0xFFFF`; this is not the same marker as the `0x1F` path records.

`0x44F8B0` reads four-byte tag words using the common structured reader `0x450D90` and source file-handle global `0x5116C0`. `0x44F8F0` reads an additional 16-bit length and the corresponding data bytes from that stream. The parser's `0x44FA24` increments its one-byte entry count, stored at **`0x500FA2`**, and `0x44FA41` computes the insertion address by indexing a **30-byte-stride** path array at **`0x500642`**.

For index `i`:

```
path_slot(i) = 0x500642 + 30 * i
```

The address difference between the path-array start and the adjacent count byte is **2,400 bytes**, sufficient for **80 30-byte slots** before that byte. **This is an address-layout observation, not proof that 80 is an enforced runtime maximum.** The audited local parser has no explicit `<80` bound check or independent length check before the copy; whether the real resource data ever approaches either boundary remains unobserved. No claim of exploitable overflow or authentic-file corruption is made.

The fallback's `0x44DA09..0x44DA23` uses the same `30*i` addressing. The `0x44DBF1..0x44DC0B` auxiliary matching routine uses the global count and same base/stride. Those original operations are retained unchanged in GOG.

## Five extensions, and the exact two GOG format substitutions

The unchanged five-way switch table at `0x44DBCC` chooses the following leaf-file suffixes based on a byte selector (0–4):

| Selector | Original and GOG literal | String VA |
|---|---|---|
| 0 | `.rtb` | `0x4A2248` |
| 1 | `.rtp` | `0x4A2240` |
| 2 | `.rts` | `0x4A2230` |
| 3 | `.rtt` | `0x4A2238` |
| 4 | `.rtl` | `0x4A2228` |

The **function code** of the fallback is unchanged, but two of its **format strings are modified** in `.data`:

| String VA | Original CD | GOG |
|---|---|---|
| `0x4A06D8` | `%c:\%s` | `%c\\%s` |
| `0x4A2264` | `%c:\%s\%s` | `%c\\%s\%s` |

The relevant byte-level modification is **`':' -> '\'`**, rather than deletion of `':'`: GOG uses **two consecutive backslashes**, leaving each string the same length. At GOG `0x448E5A`, the original PRNG-based CD-drive search is replaced with **`MOV AL,0x2E; MOV [0x4A6AD8],AL`**, storing `'.'` as the prefix character.

Thus the static formatting changes take original drive-prefixed paths such as `D:\...` toward dot-prefixed relative path strings such as `.\\...` (two path separators in the result). This is a **static string and instruction finding**, not a runtime file-open success measurement. In particular, other GOG changes may exist beyond these two strings and this one initializer.

## Consequences and limitations

The evidence supports keeping the fallback code and data-driven resource-name resolution **intact** when preparing any legitimate CD-independent restoration. The active original executable already contains the ordinary loader and path parser. Removing the entire `0x44D990` fallback would risk breaking asset access. The GOG-modified comparator shows one approach to adapting prefixes, but it is **not** a trustworthy all-purpose patch recipe for the original protected executable.

None of these findings demonstrates a real SafeDisc C2 sector verification, an ICD decryption stage, a successful or failed runtime file-open operation, an authentic `LEVELS0.DAT` value, or a DRM-free retail executable. The original same-edition physical media and runtime paths remain unverified.

## Reproduction and validation

```
python scripts/rayman2_dat_path_fallback_audit.py \
  --retail /private/CD/Rayman2.exe --gog /private/GOG/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

Local results: **14 new synthetic/integration tests**, all passing, and **133/133 tests** across nine research modules. The script is independent of proprietary code and contains only static opcode anchors and bounded structural checks. No game execution, Rust compilation, GitHub Actions run or merge was performed for this study.