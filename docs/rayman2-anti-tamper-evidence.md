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


## Four exact API-forwarding replacements and 11 direct call sites (13 November 2026)

A further *independent* read-only static audit on the owner's two **SHA-256-pinned**
executables shows four repeated obfuscated file-I/O wrappers from the retail
build replaced with small ordinary Win32 forwarding stubs in **GOG**.

| Entry VA | GOG API (verified via PE import directory and stdcall arguments) | Args | GOG IAT pointer |
|---|---|---:|---|
| \`0x00448500\` | \`KERNEL32.dll!CloseHandle\` | 1 | \`0x0049C0E0\` |
| \`0x0044E750\` | \`KERNEL32.dll!ReadFile\` | 5 | \`0x0049C04C\` |
| \`0x0044F220\` | \`KERNEL32.dll!CreateFileA\` | 7 | \`0x0049C058\` |
| \`0x0044F380\` | \`KERNEL32.dll!SetFilePointer\` | 4 | \`0x0049C048\` |

Every matching original entry begins with \`MOV ECX,[0x00510BF0]\` and,
within the first 32 bytes, \`XOR ECX,0x075BD924\` (the same
masked Park–Miller salt already measured in the exact opaque ICD/DLL
streams). GOG instead uses \`PUSH [EBP+args]\` in reverse order,
\`CALL [IAT]\`, and \`RET N\` with correct stdcall cleanup. GOG's
\`CreateFileA\` wrapper at \`0x0044F220\`, for example, returns via
\`RET 0x1C\`, consistent with seven 32-bit arguments.

This is evidence that the **masked PRNG is integral to obfuscating
routine Win32 file operations** in the original build, not just an
on-disc-file producer. There is still no proof that the two opaque
files are legitimate encrypted game executable payloads.

Direct \`E8 rel32\` call site inventory, verified on exact instruction
boundaries independently with \`objdump\`:

| Wrapper | Retail direct calls | Retained as identical direct calls in GOG |
|---|---:|---:|
| CloseHandle \`0x448500\` | 2 | 2 |
| ReadFile \`0x44E750\` | 5 | 3 |
| CreateFileA \`0x44F220\` | 2 | 2 |
| SetFilePointer \`0x44F380\` | 2 | 0 |
| **Total** | **11** | **7** |

The four changed callsite opcodes are
\`0x0044F10D\` and \`0x0044F1D4\` (retail
\`SetFilePointer\` calls), and \`0x0044F125\` and \`0x0044F1EC\`
(retail \`ReadFile\` calls). Inspection of GOG shows the first
read/seek region at \`0x0044F102..\` replaced with NOPs,
and the later read block under \`0x0044F1CC\` bypassed by a jump
followed by \`INT3\`. **These are not proof of a runtime-executed
anti-piracy check, nor a recommendation to copy GOG patches.**
The direct-call inventory also excludes dynamic and indirect calls.

An explicit reproducibility helper, \`scripts/rayman2_win32_forwarders.py\`,
validates exact file SHA-256, PE imports, stdcall argument count, four
original PRNG anchors, and the 11 callsite instruction encodings.
It does not execute the files, make edits, or distribute bytes.
Nine synthetic-only tests are provided in
\`scripts/test_rayman2_win32_forwarders.py\`.
An independent local implementation of the algorithm ran successfully
against **both original SHA-256-identified executable files**,
reporting four GOG forwarders, 11 retail direct calls and seven
GOG-preserved direct calls; **ten local synthetic mirror tests pass**.
The exact newly committed GitHub versions have not been re-run via
CI or compiled with Rust; make no stronger claim than this.

Reproduction with user-owned files:

\`\`\`sh
python scripts/rayman2_win32_forwarders.py \
  --retail /path/to/original/Rayman2.exe \
  --gog /path/to/gog/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_win32_forwarders.py'
\`\`\`

**Research boundary:** Modern descriptions of SafeDisc v1 generally
portray \`GAME.ICD\` as a conventionally encrypted executable and
\`GAME.EXE\` as a loader. The two particular *owner-supplied*
Rayman 2 opaque files were instead established as fully reproducible
short-seed PRNG output, whereas its 676,352-byte original \`Rayman2.exe\`
is a valid PE with substantial game code. Consequently **we cannot
assume their distribution/installation stage or role**. The path
from physical CD/installer to those sample bytes must be verified.
Primary historical context: https://list.winehq.org/hyperkitty/list/wine-devel%40list.winehq.org/thread/A2SGOS3ZAABYF3LBHRLGNSFL3GQRBDIO/
(2005, a different title). This historical general description
does not override the exact measured Rayman 2 bytes.


### Deeper original-code finding: resolved descriptor slots, not an unknown file cipher

For these four wrappers, the original x86 stubs **do not operate on
unexplained random executable bytes**: they recover an API pointer
from the existing 76-byte/record, 36-record masked function-descriptor
table whose 35 nonzero records were decoded earlier.

For records numbered **one-based**, the descriptor record base is
\`0x004A141C + (record-1)*0x4C\`, and its resolved masked pointer
is at base \`+0x30\`. The original retail wrapper writes or synthesizes
a tiny trampoline:

| GOG-confirmed API | Original wrapper | Descriptor | Base / stored pointer |
|---|---|---:|---|
| CreateFileA | \`0x44F220\` | **8** | \`0x4A1630 / 0x4A1660\` |
| ReadFile | \`0x44E750\` | **10** | \`0x4A16C8 / 0x4A16F8\` |
| CloseHandle | \`0x448500\` | **11** | \`0x4A1714 / 0x4A1744\` |
| SetFilePointer | \`0x44F380\` | **12** | \`0x4A1760 / 0x4A1790\` |

At \`0x44F28C–0x44F2A9\`, the retail code constructs 13 bytes
corresponding to the following x86 semantics:

\`\`\`asm
mov eax, dword ptr [0x004A1660]  ; descriptor 8, +0x30
xor eax, dword ptr [0x004A1630]  ; descriptor 8, base
jmp eax
\`\`\`

The corresponding \`ReadFile\` and \`SetFilePointer\` wrappers construct
the same \`MOV / XOR / JMP\` shape with their own paired addresses.
\`CloseHandle\` at \`0x448556–0x44856B\` instead reads the two DWORDs,
XORs them, and creates a six-byte \`PUSH imm32; RET\` trampoline
containing the resulting pointer. This demonstrates *two* concrete
ways in which original code hides and invokes an import that GOG
forwards directly.

The actual runtime pointer values cannot be derived from the
uninitialized \`+0x30\` fields on disk. The masked descriptor
initialization routine must run before the trampoline is callable;
**no full runtime trace or decrypted ICD follows from this result**.

The names \`CreateFileA\` (record 8) and \`ReadFile\` (record 10)
are additionally independently confirmed by the existing encoded
export-name decoder. The other two names in this table are confirmed
from the GOG import-forwarding stubs and matching original descriptor
address construction, not from a newly published entire decoded
export list.


### Execution-permission caveat for the original dynamic trampoline buffer

Independent inspection of both exact PE32 section tables shows that the
trampoline buffer **\`0x00510EA0\`** lies at offset \`0x71EA0\` in
the virtual \`.data\` section (virtual size \`0x776D0\`, raw file size
\`0x7C00\`). It is in *zero-filled virtual memory*, not original
backed-on-disk bytes. That section is marked **\`0xC0000040\` = read/write,
non-executable**, in both sampled PE headers.

The retail code near \`0x44F286\` constructs x86 instructions at a
PRNG-selected offset of this buffer and appears to call them
indirectly. This creates a **possible DEP/NX compatibility issue** on
modern Windows and Wine: a section header which is not executable does
not itself establish the protection of its pages *at runtime*, and
the game may use additional memory-management code or compatibility
behavior. The PE import directory does not directly list
\`VirtualProtect\` or \`VirtualAlloc\`; dynamically resolved functions
are not excluded. **No DEP fault was observed or demonstrated**, so
this is a research question and not a confirmed crash cause.

The GOG forwarders dispense with these particular generated stubs,
which is consistent with a simpler modern Win32 I/O path. This
observation is **not** an instruction to make writable memory
executable or to disable system security features.

## Read-only, falsifiable checks

`scripts/rayman2_anti_tamper_assets.py` inspects only the two historical asset names and hashes, with case-insensitive per-component lookup, link rejection and bounded reading. Example:

```sh
python scripts/rayman2_anti_tamper_assets.py --cd-root /path/to/original-cd --installed-root /path/to/unmodified-install
python -m unittest discover -s scripts -p 'test_rayman2_anti_tamper_assets.py'
```

Outcomes: `identical`, `different`, `cd_only`, `installed_only`, `absent_both`. None prove authenticity, SafeDisc status, or activation of the pirate-head check. The files can be in installer archives, alternate paths or ISO multi-extent records; missing from an extracted tree is not proof of missing from the physical disc.

**Next controlled test:** capture which paths, handles and returned data the *retail* program reads from the same-edition original CD and an unmodified installed tree; isolate file-read and anti-tamper behavior from the kernel-level media verification. Contrast the GOG callback behavior with retail only after validating provenance. The GOG code/manifest must never be copied as a stand-in for the retail loader. Don't execute or distribute proprietary binaries as fixtures.

No SafeDisc key, decrypted ICD, native Rust build, gameplay test or universal crack is claimed here.
