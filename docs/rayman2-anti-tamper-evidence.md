# Rayman 2: SafeDisc 1.35 versus in-game anti-tamper (research note)

Status: **external evidence and reproducible diagnostics, not a decoder**. Created 2026-11-13. This note supplements [the SafeDisc 1.35 investigation](safedisc-135-rayman2-research.md) without changing Crimson Skies or merging the draft PR.

## Three separate issues, not one cipher

1. **SafeDisc 1.x media authentication / loader.** A Wine developer's 2005 explanation describes the `Secdrv.sys` kernel driver, `DeviceIoControl`, and a typical encrypted `.ICD` payload. This description is of a *different game* and must not overrule measurements on our exact Rayman 2 samples. Source: https://list.winehq.org/hyperkitty/list/wine-devel@list.winehq.org/thread/A2SGOS3ZAABYF3LBHRLGNSFL3GQRBDIO/
2. **Rayman 2's own in-game protection.** The original Wine bug report, 2009-12-24, records gameplay reaching several levels with a real CD before the pirate-head condition appeared. It also reports a 650 MB CD whose declared file sizes total about 6.9 GB; this is a historical *observation*, not an authenticated manifest. The later 2011 Wine correspondence discusses SafeDisc 1.3x driver initialization separately from the pirate-head condition. Source: https://list.winehq.org/hyperkitty/list/wine-bugs@list.winehq.org/thread/PBMSSMOUG42FC3AE5YDT7WPIEDJIBKC5/
3. **Missing installed game data.** A retail-install comparison posted on Rayman Pirate-Community on 2016-08-15 reports that `Data/Vignette.cnt` and `Data/World/Levels/LEVELS0.DAT` may not be copied from the CD by the original installer; a no-CD-based executable then showed a CD-related error until both files were present. This is a *single-user account*, not independent proof for our owner's edition. Sources: https://raymanpc.com/forum/threads/cancelled-rayman-2-installer-for-newer-systems.24570/page-2 and https://www.raymanpc.com/forum/threads/rayman-2-pc-widescreen-patch-16-9-16-10-21-9-32-9-pc-32-bit-depth-fix-widescreen-for-dc-psx-ps2.21665/page-3

**Path correction:** the older forum post misspells `World/Level` (singular); the same author later explicitly writes `World/Levels`. The independently listed *Steam* content manifest also contains `Data/World/Levels/LEVELS0.DAT` (about 143.79 MiB) and `Data/Vignette.cnt` (about 20.75 MiB). These Steam sizes do **not** authenticate the old CD edition or its hashes: https://steamdb.info/depot/15061/

## Exact binary findings that remain valid

- The owner's **683,565-byte** `RAYMAN2.ICD` (SHA-256 `4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6`) is *fully regenerable* from a 1-byte prefix, 31-bit initial word and masked Park–Miller PRNG.
- The owner's **165,888-byte** `dplayerx.dll` (SHA-256 `0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee`) is also *fully regenerable* from its first 31-bit word and the same recurrence.
- The owner's **676,352-byte protected** `Rayman2.exe` is a valid PE32 with substantial game code. It shares 97.8981% of the bytes of its `.text` section with the **1,468,928-byte GOG reference**. The latter is *not* a pristine retail unwrapping.
- GOG's `.extra` has an exact, separately stored copy of retail protected `.text`. Its `.extra2` contains a 3,716-entry filename/size table, while GOG installs callbacks returning virtual CD-ROM properties. **Hypothesis only:** that copy may be used to satisfy original file-integrity reads. No runtime trace or proof of this purpose exists.
- Therefore these two specific on-disc opaque files are **not established as recoverable encrypted Windows executable payloads**, even though the conventional SafeDisc 1.x description uses such an ICD. Investigate actual file provenance and runtime paths before claiming a decoder.

## Independent numerical cross-check of historical CD anomalies

The 2009 Wine report describes Rayman 2 media as approximately **650 MB physically** but **6.9 GB of listed files**. The independently analyzed **GOG** binary's `.extra2` table declares **7,453,062,614 bytes = 6.941 GiB** of file sizes, while its CD geometry callback reports **332,400 x 2,048 = 680,755,200 bytes = 649.219 MiB**. The ratio of declared sizes to virtual capacity is **10.95:1**.

This is a **notable two-number correlation**: a historical original-disc observer used rounded “650 MB / 6.9 GB” and the GOG-emulated numbers round to approximately **649 MiB / 6.94 GiB**. Decimal GB versus binary GiB usage in the 2009 post is unspecified; no exact match is asserted. The witness and GOG executable are independent observations but this does **not** prove the 3,716 individual GOG records are the authentic CD directory, or that this is the same regional disc edition. Falsifiable next check: compare directory counts, names and declared sizes against the same-edition retail ISO filesystem (not against GOG alone), explicitly accounting for ISO9660 extents and deliberately bogus lengths.


## Exact SHA-pinned executable comparison: CD file access (13 November 2026)

New independent read-only **byte-level and x86-assembly analysis of the owner's
two actual files**, after validating both SHA-256 identifiers:

- retail protected Rayman2.exe 676,352 bytes: \`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3\`;
- GOG reference Rayman2.exe 1,468,928 bytes: \`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713\`.

The data from VA **\`0x004A2090\`** consists of **24 little-endian pointer entries**, byte-identical across the two builds (SHA-256 of the 96-byte pointer block:
\`55816453eb99c6e442f0d1303e117efb19ff9be61b5f52f9737c5b78acf27911\`). Each points to a readable filename in an identical adjacent string table. Three numbered banks (0/1/2) each contain the eight names \`LEVELS\`, \`MAP\`, \`TEXTURES\`, \`ANIMS\`, \`SOUNDS\`, \`MUSIC\`, \`GRAPHICS\`, \`MENU\` with \`.DAT\` extension.

**11 independently inspected code anchors** expose differences beyond the earlier generic callback map:

| VA | Protected CD | GOG |
|---|---|---|
| \`0x0044EB82\`, \`0x0044EB89\`, \`0x0044EB94\` | Passes the drive letter to a formatter with \`%c:\%s\%s\` | Omits the drive-letter argument and uses \`%s\%s\` |
| \`0x0044EB97\` | Calls \`0x00448480\` while constructing an obfuscated file opener | Short jump to \`0x0044EC0B\`; old instruction range replaced by \`INT3\` |
| \`0x0044EC24\` | \`CALL ESI\`, an indirect file-open call | \`CALL [0x0049C058]\`; PE import table confirms \`KERNEL32.dll!CreateFileA\` |
| \`0x0044F133\` | \`SUB [ESI], ECX\` | Two NOPs |
| \`0x0044F13A\` | \`MOV EDX,[EBX*4+0x004A2090]\`: chooses among 24 DAT file names | \`MOV EDX,[0x004A2090]\`: chooses **\`LEVELS0.DAT\`** at this specific site |
| \`0x0044F155\`, \`0x0044F156\`, \`0x0044F161\` | Drive-letter formatter at another file-I/O site | Formatter without a drive-letter argument |
| \`0x0044F1CC\` | Continues further file operations | Short jump to the \`0x0044F1F1\` epilogue |

**Correction of an easy misreading:** the GOG format string at \`0x004A2268\` is \`%s\%s\`, **without** a leading backslash; the original at \`0x004A2264\` is \`%c:\%s\%s\`. The second string is an interior pointer into the first string.

The changed instructions offer a *specific* investigation target: they simplify
legacy file I/O and indexing, and skip certain retail code paths. They **do not**
prove that \`LEVELS0.DAT\` is the whole anti-tamper mechanism, nor that the GOG
changes are solely SafeDisc removals. GOG may also carry unrelated game fixes.

**Reproducible tool, no code execution:**

\`\`\`sh
python scripts/rayman2_cd_io_diff.py \
  --retail /path/to/retail/Rayman2.exe \
  --gog /path/to/gog/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_cd_io_diff.py'
\`\`\`

The script uses strict SHA-256 gating, actual PE RVA-to-file mapping and IAT
lookup, and checks each original/GOG opcode anchor. It reports 24 names and
11 anchors, never emits proprietary executable bytes and never changes input.
**11/11 synthetic Python tests pass locally**; exact known retail and GOG
file integration analysis succeeded locally. Rust, Wine gameplay and GitHub
Actions were **not** run for this study.

**Next research experiment:** construct a bounded *control-flow*
reconstruction at \`0x0044EB40\` and \`0x0044F130\` to determine which
branches can actually execute and how the indexed data-file bank feeds
integrity checks. Compare all three numbered file groups in an independently
verified same-edition CD image/install, without assuming GOG is original.

## Read-only, falsifiable checks

`scripts/rayman2_anti_tamper_assets.py` inspects only the two historical asset names and hashes, with case-insensitive per-component lookup, link rejection and bounded reading. Example:

```sh
python scripts/rayman2_anti_tamper_assets.py --cd-root /path/to/original-cd --installed-root /path/to/unmodified-install
python -m unittest discover -s scripts -p 'test_rayman2_anti_tamper_assets.py'
```

Outcomes: `identical`, `different`, `cd_only`, `installed_only`, `absent_both`. None prove authenticity, SafeDisc status, or activation of the pirate-head check. The files can be in installer archives, alternate paths or ISO multi-extent records; missing from an extracted tree is not proof of missing from the physical disc.

**Next controlled test:** capture which paths, handles and returned data the *retail* program reads from the same-edition original CD and an unmodified installed tree; isolate file-read and anti-tamper behavior from the kernel-level media verification. Contrast the GOG callback behavior with retail only after validating provenance. The GOG code/manifest must never be copied as a stand-in for the retail loader. Don't execute or distribute proprietary binaries as fixtures.

No SafeDisc key, decrypted ICD, native Rust build, gameplay test or universal crack is claimed here.
