# Rayman 2: SafeDisc 1.35 versus in-game anti-tamper (research note)

Status: **external evidence and reproducible diagnostics, not a decoder**. Created 2026-11-13. This note supplements [the SafeDisc 1.35 investigation](safedisc-135-rayman2-research.md) without changing Crimson Skies or merging the draft PR.

## Four-sample provenance: retail EXE, ICD, DLL and GOG virtual media

A new [SHA-256-locked, read-only four-sample verifier](../scripts/rayman2_sample_provenance.py)
correlates the three owner's original Rayman 2 sample sizes
(676,352 EXE, 683,565 ICD, 165,888 DPLAYERX.DLL) with three
**exact-length entries** in GOG's 3,716-record virtual-CD table.
The same modified GOG executable embeds an exact, complete copy of
the original retail 631,296-byte `.text` section at offset 0x1000
inside its `.extra` section. The virtual manifest also lists
SECDRV.SYS as 14,368 bytes; no owner sample of that file is available.

**Do not equate metadata matching with actual original-disc file
identity.** The source of the manifest is a modified GOG executable,
and equality of file size does not establish equality of content.

A contemporary [January 2000 Rayman 2 SafeDisc study by ArthaXerXès]
(https://www.scribd.com/document/659005728/safedisc)
describes *in-memory* section deciphering and independently gives
an original entrypoint of 0x45FCC0 and .text size of 0x9A200;
both match the original owner's PE. Its code at 0x4064D0 and
0x4028FD does **not** match the on-disk code at the same VAs,
possibly because it describes a post-decryption stage or another
revision. This is evidence to keep the original SafeDisc loader,
decrypted runtime game sections and GOG substitutions as **three
separate referents**.

**Critical:** The completely regenerable PRNG pattern in the two
opaque ICD/DLL samples is a mathematical fact, **not proof that
these files are disposable decoys**. This ambiguity is now explicit
in the [main research report](safedisc-135-rayman2-research.md).
Twelve local tests pass for the four-file provenance verifier;
GitHub Actions and Windows/Wine gameplay were not run.


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

## Original loader's instruction-cache protocol — verified four times (13 November 2026)

A new, **SHA-256-locked, read-only PE32 diagnostic** now independently verifies the *exact opcode sequences* which were previously only described in disassembly:

- Original descriptors **1** and **2** decode to `FlushInstructionCache` and `GetCurrentProcess`, respectively; **all 35 one-based descriptors** have a zero `+0x30` pointer field *on disk*. These are not runtime resolved function addresses.
- Four original masked Win32 wrappers, for `CloseHandle`, `ReadFile`, `CreateFileA` and `SetFilePointer`, build either a 6-byte `PUSH resolvedVA; RET` trampoline or a 13-byte `MOV EAX,[ptr]; XOR EAX,[mask]; PUSH EAX; RET` / `...; JMP EAX` trampoline. Each builds its code using its own masked API-descriptor record (**11**, **10**, **8**, **12**, respectively).
- **All four wrappers call through descriptor 2 (`GetCurrentProcess`), then descriptor 1 (`FlushInstructionCache`)** with a buffer base `0x00510EA0` and byte count `0x464` (1,124), before invoking the generated stub via `CALL ESI`. Exact code-generation and helper-call signatures have been checked on all four instruction regions.
- PRNG relocation uses a signed remainder of `0x455` (1,109). For a nonnegative state the selected offset lies in **0..1,108**. The maximum used region for a 13-byte generated stub is **1,121 bytes**, inside the **1,124-byte** cache-flush region. *Caveat:* without dynamic observation, the residue's actual sign and buffer bounds in all runtime states have not been established.
- The `0x00510EA0` buffer lies in zero-filled virtual `.data` space; its PE section flags are **read/write but not marked executable** (`0xC0000040`). Both the exact original CD and GOG EXEs have `DllCharacteristics=0x0000` and therefore **`IMAGE_DLLCHARACTERISTICS_NX_COMPAT` is absent**. This contextualizes, rather than proves, a DEP/NX compatibility concern. The original PE's 163 directly imported functions and the 35 decoded masked exports do not list `VirtualProtect` or `VirtualAlloc` (though computed/dynamic routes and operating-system behavior are not ruled out).
- Microsoft specifies that `FlushInstructionCache` synchronizes generated instructions, **not** that it changes page-execution protection. Executable memory permissions are separately governed by mechanisms such as `VirtualProtect`. Neither the static PE flags nor the absence of an NX opt-in determines actual runtime permissions. References: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-flushinstructioncache and https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect and https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

Reproduction on the owner's exact protected CD executable:

```sh
python scripts/rayman2_trampoline_proof.py Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_trampoline_proof.py'
```

**Local validation:** exact SHA-pinned private original executable passed all 4 code-generator signatures, all 4 helper-call signatures, all 4 indirect-call signatures, 35 encoded export records and the virtual section check. **8/8 synthetic tests for the repo-ready implementation succeeded locally** using compatibility shims for the existing repository helper APIs; 14 more tests for a separate standalone independent local verifier passed. No game byte, file write, Wine gameplay, Rust compilation, or new GitHub Actions job was involved. The exact remote GitHub script/test have not yet run in a CI job.

This is a **static validation of pointer masking and cache flushing**, not a decryption of the Rayman 2 SafeDisc layer. It does **not** establish whether the same code is dynamically reached during a specific gameplay transition, whether the loader would run under particular DEP policies, or the actual runtime value of any masked pointer.

## Exact PRNG buffer lifecycle, post-call rewrite and timer seed (13 November 2026)

**New independent verification on the actual SHA-256-identified owner's retail
and GOG executables; no binaries are redistributed or executed.**

The unchanged startup callsite \`0x00401EF8\` passes argument \`1\`
to initializer \`0x00449360\` in **both** builds. A direct static call is
not a full runtime reachability proof: \`0x005113EC\` is checked by the
initializer as a guard, and its actual value at the call has not been
observed.

Under the zero-guard path, instructions at \`0x0044938D\` call the
**standard PE32 import** \`KERNEL32.dll!QueryPerformanceCounter\`
through IAT \`0x0049C060\`. Only the low DWORD of the 64-bit
\`LARGE_INTEGER\` result is used as the PRNG initial value. If the call
returns zero, the hardcoded fallback is **\`0x12345678\`**. This
describes a run-dependent *in-memory* seed; it does not identify the
independent seeds of the two previously observed dummy PRNG files.
Microsoft documents \`QueryPerformanceCounter\` as writing a
\`LARGE_INTEGER\` and returning a \`BOOL\`:
https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter

Next, the original instruction sequence writes **\`0x119 = 281\`
32-bit PRNG words** beginning at \`0x00510EA0\`. Therefore it fills
**\`0x464 = 1,124\` bytes**. The \`QueryPerformanceCounter\`,
fallback, buffer-base/count/loop and final state-store
instruction bytes are **identical for the first 99 bytes** of
\`0x44938D\` in retail and GOG. This verifies that GOG *retains the
initialization routine*, not that every subsequent original function
or call is still live.

**New result beyond the four trampoline construction signatures:**
all **four original file-I/O wrappers** also execute a PRNG-based
**15-byte post-call rewrite of the temporary trampoline region**.
The x86 sequence \`CALL ESI; LEA end,[ESI+0xF]\` is followed by a
15-iteration loop storing a byte from a fresh masked PRNG state,
with an unconditional original \`JB\` back-edge. This is **not**
a zero-fill or a guaranteed secure erasure; it overwrites temporary
instructions with pseudorandom-looking data.

| Original API wrapper | Indirect call + setup | Rewrite loop | Loop tail |
|---|---|---|---|
| CloseHandle | \`0x44859D\` | \`0x4485A8\` | \`0x4485F3\` |
| ReadFile | \`0x44E820\` | \`0x44E82D\` | \`0x44E88D\` |
| CreateFileA | \`0x44F2FA\` | \`0x44F307\` | \`0x44F367\` |
| SetFilePointer | \`0x44F44B\` | \`0x44F458\` | \`0x44F4B8\` |

The same five bytes at the corresponding original indirect-call
locations have been replaced with **\`INT3\` (0xCC × 5)** in the exact
GOG reference. This is a static comparison of **specific addresses**,
not an assertion about the whole GOG program.

**A previously incomplete bound is now explained:**

| Quantity | Bytes |
|---|---:|
| Buffer initialized at startup: \`281 × 4\` | **1,124** |
| Largest unsigned/nonnegative remainder from division by \`0x455=1,109\` | **1,108** |
| Maximum generated trampoline body | 13 |
| **Post-call rewrite length** | **15** |
| Furthest possible rewritten byte, 0-based | **1,122** |
| Largest rewrite span, offset + length | **1,123** |
| Remaining buffer capacity | **1 byte** |

The \`0x464\` byte flush region exactly matches the 281-word startup
buffer. The 15-byte scrub loop *also fits*, even at the maximum
nonnegative PRNG offset. This is stronger evidence for deliberate
buffer sizing than the earlier 13-byte-only calculation.

Read-only, reproducible script:
\`scripts/rayman2_buffer_lifecycle.py\`.
11 synthetic tests:
\`scripts/test_rayman2_buffer_lifecycle.py\`.

\`\`\`sh
python scripts/rayman2_buffer_lifecycle.py \
  --retail /path/to/original/Rayman2.exe \
  --gog /path/to/GOG/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_buffer_lifecycle.py'
\`\`\`

**Validation:** the exact two private PE32 files pass all asserted byte
anchors and the full cross-build inspection using a local
compatibility mirror of the existing PE helper interfaces; 11/11
new synthetic tests pass. Both newly committed Python files have
been checked by their Git blob SHA against the tested local files.
This **does not mean** the repository's complete Python/Rust test
suite has been executed: no GitHub Actions, Rust build or Wine
runtime test was initiated.

**Limitations:** The code path has not been traced dynamically.
The original PE's \`.data\` section flags and missing \`NX_COMPAT\`
bit do not establish actual executable memory protections. No
SafeDisc key, CD authorization exchange, decrypted executable
payload or general SafeDisc 1.35 algorithm has been found.

## Corroboration externe importante : fichiers DAT fictifs et inventaire GOG (13 novembre 2026)

A [Rayman Pirate-Community discussion dated June 8, 2020](https://raymanpc.com/forum/threads/tonic-trouble-launcher-retail.27633/page-3)
quotes RibShark describing 24 pseudo-files in Rayman 2 using the same
scheme as Tonic Trouble: directory records with large artificial lengths
that may point to the same physical CD region. The account explicitly
says that GOG selects LEVELS0.DAT rather than choosing among names such
as SOUNDS1.DAT and GRAPHICS0.DAT. This independently corroborates, but
does not by itself prove, our original-vs-GOG static finding.

The actual owner-supplied protected retail PE picks an entry from the
24-name table at VA 0x004A2090 using EBX*4 at VA 0x0044F13A.
The SHA-pinned GOG PE at the same VA loads the first table entry,
LEVELS0.DAT, directly. The pointer table bytes are identical across
the two executable files; the 24 names form eight families numbered
0, 1, 2 under DATA/WORLD/LEVELS.

**Fresh independently parsed GOG PE .extra2 data (not a retail CD):**
the 143,360-byte section begins at file offset 0x142C00, contains
3,716 filename/declared-length pairs occupying 139,366 bytes,
followed by an eight-byte sentinel and 3,986 zero bytes.
The new parse matches every entry in the saved owner GOG reference
inventory, confirming these totals:

| Names in GOG .extra2 | Combined declared bytes |
|---|---:|
| 24 DAT candidate entries | **6,928,033,212** |
| Remaining 3,692 entries | **525,029,402** |
| All 3,716 entries | **7,453,062,614** |

Thus **92.9555%** of all *claimed file lengths* come from just 24
DAT entries. The 525 MB balance is below GOG's virtual CD geometry
(680,755,200 bytes). This explains the anomalous 7.45 GB sum,
but cannot establish the original CD's authentic sector extents.

**New, offline, read-only ISO9660 metadata probe:**
scripts/iso9660_alias_probe.py. It reads primary descriptor and directory
metadata only, never trusts huge file lengths as payload extents and
never extracts the 24 DAT files. It reports per-file start LBA, declared
length, endian-field consistency, physical-image overflow, and groups
different names with matching start LBAs. It rejects symlinks, refuses
unsupported 2352-byte raw BIN/CUE, and bounds record and directory
counts; it does not claim to handle all Joliet or multi-extent cases.

Reproduce on a user-owned 2048-byte-sector ISO:

    python scripts/iso9660_alias_probe.py /path/to/retail-Rayman2.iso
    python -m unittest discover -s scripts -p 'test_iso9660_alias_probe.py'

Eleven synthetic test cases passed locally, including nested
DATA/WORLD/LEVELS directories, duplicate fake extents,
false oversized lengths, malformed directory metadata and symlink refusal.
Both new GitHub file blob SHA values exactly match the locally tested
file contents. A real original retail ISO is **not** present in the
research environment: **no physical original-CD LBA evidence is claimed**.

## Original DAT I/O: 4-byte read retained, two 512-byte reads removed in GOG

Additional **strictly SHA-256-identified, offline** code verification narrows
the changes around the original DAT pseudo-file selection. The new tool
scripts/rayman2_dat_read_paths.py uses PE RVA mapping and checks the
actual KERNEL32.dll ReadFile IAT pointer (VA 0x0049C04C) in both EXEs:

| Instruction address | Protected original CD | GOG reference |
|---|---|---|
| 0x0044F0A6 / 0x0044F0AA | 4-byte ReadFile through generated indirect-call trampoline | **Same 4-byte read**, but direct IAT ReadFile |
| 0x0044F0C8..0x0044F101 | **58 original bytes shared**: a 4-byte result is transformed by SUB/XOR and written via a caller pointer | Exact same 58-byte code |
| 0x0044F10D / 0x0044F125 | SetFilePointer followed by an additional **512-byte ReadFile** | Region 0x0044F102..0x0044F129 replaced by NOPs |
| 0x0044F133 | Subtracts a computed quantity from the caller-owned DWORD | Two NOPs |
| 0x0044F13A | Indexed entry from 24-name pseudo-file table | Fixed first entry LEVELS0.DAT |
| 0x0044F1D4 / 0x0044F1EC | Second SetFilePointer followed by **512-byte ReadFile** | Early JMP at 0x0044F1CC to exit at 0x0044F1F1; remaining bytes INT3 |

These are exactly **two distinct requested 512-byte reads in the original
code** which GOG removes or bypasses. GOG retains the initial requested
4-byte read and its transformation. All listed signatures, including
the original relative CALL destinations and GOG replacement bytes, have
been checked on the two private owner-supplied executables.

**Important cautions:** static code and byte equivalence do not prove
that the path is taken in a particular gameplay session, that the
ReadFile calls succeed, that the selected files carry valid game
resource data, or that a particular change is attributable to SafeDisc
rather than another GOG modification. Do not automatically transplant
these code modifications into the original retail executable.

Reproduce:

    python scripts/rayman2_dat_read_paths.py \
      --retail /path/to/retail/Rayman2.exe --gog /path/to/GOG/Rayman2.exe
    python -m unittest discover -s scripts -p 'test_rayman2_dat_read_paths.py'

**Local validation:** the exact two SHA-256-pinned files pass this
comparison, and six new synthetic tests pass using the existing local
PE helper mirrors. Combined with the earlier 43 local tests and
11 ISO9660 tests, **60/60 local tests pass**. The exact GitHub script
and test blob SHA values match locally tested contents. No native
Rust compilation, Wine gameplay execution or new GitHub Actions job
was initiated.

## New: Rayman 2 DAT four-DWORD header and indexed word decoder (13 November 2026)

**This corrects and expands the previous description of only one
meaningful four-byte DAT read.** Static disassembly was repeated on
the *actual* protected retail and separately modified GOG EXEs, whose
full SHA-256 values are pinned in the research scripts.

The full retained data path, in both versions, is:

| Address | Original code | GOG code | Argument semantics |
|---|---|---|---|
| 0x0044EE39..0x0044EE4F | Compute base offset P | Same instructions | P is a runtime-dependent affine expression, NOT assumed to be zero |
| 0x0044EEC3 / 0x0044EEC9 | Masked SetFilePointer | Direct IAT | FILE_BEGIN, offset P |
| 0x0044EF53 / 0x0044EF5D | Masked ReadFile | Direct IAT | **16 bytes** into the four-DWORD local area at EBP-0x20 |
| 0x0044EF7B..0x0044EF9F | Adjust first two DWORDs using the remaining DWORDs and index n | Byte-identical | A <- A+n*C; B <- B+n*D (modulo 2^32) |
| 0x0044F009 / 0x0044F016 | Masked SetFilePointer | Direct IAT | FILE_CURRENT, relative displacement **4*n** |
| 0x0044F09D / 0x0044F0AA | Masked ReadFile | Direct IAT | **4 bytes** into local DWORD T |
| 0x0044F0C8..0x0044F0D9 | Read T, A_n and B_n, SUB then XOR, store output | Byte-identical | **R = ((T-A_n) mod 2^32) XOR B_n** |

The 16-byte local area is interpreted as four *little-endian*
unsigned DWORDs (A, B, C, D), at the file position P chosen by the
program. Given the index n:

    A_n = (A + n*C) mod 2^32
    B_n = (B + n*D) mod 2^32
    R   = ((T - A_n) mod 2^32) XOR B_n

**If and only if the preceding Win32 operations succeeded and
returned all requested bytes**, T is fetched from file offset
**P+16+4*n**. The method is not a generic SafeDisc decoder:
it describes a local data transformation and cannot supply an
unknown retail DAT payload, a missing runtime P, or a disc
authentication proof. GOG retains the transformation even though it
changes the filename selection.

The two **512-byte reads** at retail VAs 0x0044F125 and 0x0044F1EC
write into the stack arrays at EBP-0x334 and EBP-0x534,
respectively. A bounded disassembly of function 0x0044EB40..0x0044F1F9
shows **one direct encoded frame reference to each buffer**, at
0x0044F118 and 0x0044F1DF: both are LEA instructions passing
their buffer to ReadFile. There are no further direct frame
references to these two arrays within the function. The immediate
ReadFile return values also are **not tested** at these call sites.
This supports the hypothesis that these are artificial CD reads, not
the payload required for R. However, static non-use by the same
function is **not evidence of successful I/O**, nor proof that the
buffers or file API have no indirect side effects.

The already existing diagnostic script has been **extended**, not
duplicated: scripts/rayman2_dat_read_paths.py now verifies the
original and GOG instructions and their import targets for the
FILE_BEGIN +16-byte + FILE_CURRENT +4-byte path. It offers a pure
synthetic-testable function
\`derive_dat_word(header_16_bytes, indexed_word_u32, index)\`.
Seven new unit tests cover zero/nonzero index, uint32 overflow,
invalid header length and invalid value/index bounds; the file's
test count increases **from 6 to 13**.

**Independent actual-file verification:** Python/objdump checked
the real SHA-pinned retail and GOG binary pairs (12 original
critical byte patterns plus five base-seek signatures), including
the once-only stack-frame displacement references. Eight independent
local tests passed, including actual-file anchors and synthetic
formula/validation checks. **The exact updated repository test module
has not been run in GitHub Actions** or on this environment;
no claim of 67/67 repository-wide tests is made here.
No original ISO or physical LEVELS0.DAT payload was available for
decoding. This study never runs game code or edits protected bytes.


## 1024-entry DAT window and preserved caller/alias arithmetic (13 Nov 2026)

The previously modeled DAT word index was validated too loosely: the
diagnostic originally allowed up to 65,535 indices. A new independent
disassembly and byte check on **both SHA-256-pinned owner executables**
identifies the actual four-branch computation at
\`0x0044ED2C..0x0044ED8E\`. The four-way switch table at
\`0x0044F204\` contains the exact target addresses:
\`0x44ED8E\`, \`0x44ED80\`, \`0x44ED83\`, \`0x44ED88\` for cases
0, 1, 2 and 3, respectively. Both code and table are **identical
between CD and GOG**.

Let \`b0\` be the zero-extended low byte at \`0x005116F0\`, let
\`b1\` be the next state byte at \`0x005116F1\`, and \`d\` be the
nonzero 32-bit runtime modulus at \`0x00511750\`. The original
unsigned division and switch implement:

    q = b0 % d                       # 0 <= q <= 255, if d >= 1
    r = b1 & 3                      # r = 0..3
    n = 4*q + r                     # n = 0..1023

The previously identified four-DWORD header (16 bytes) followed by
4-byte indexed words is therefore capable of selecting **at most
1,024 entries** in a **4,112-byte window**:

    16-byte header + (1,024 x 4-byte words) = 4,112 bytes

The last legal word begins at offset \`16+4*1023=4108\` and ends
at byte offset 4111 inclusive. **This is a structural upper bound
deduced from the code; no original physical DAT file was inspected
to confirm that an actual 4,112-byte table begins at every
runtime-selected base position.**

The conditional caller chain is likewise present in both files:

    0x44D9F4 -> 0x44E8A0 -> 0x44EB40
    [the inner function writes a decoded DWORD via caller pointer]
    0x44E8D3     exact direct CALL to 0x44EB40
    0x44E99F     seek with SetFilePointer(handle, decoded/adjusted R,
                                               0, FILE_BEGIN)
    0x44EA97     caller saves the returned handle in its state structure

The caller is **conditional**: the test at \`0x44D9EF\` may bypass
it, and the original loader also has a guard at \`0x44E8A6\`.
An identical call instruction is **not proof of a runtime reachability
trace**. At \`0x44E8F2\` GOG skips an original PRNG-generated
\`SetFilePointer\` trampoline and at \`0x44E9A5\` performs the
same seek through its plain \`KERNEL32.dll!SetFilePointer\` import.
This demonstrates a retained *functional* data-read call chain
in GOG, not simply a dead chunk of unreferenced original code.

**Additional 24-name alias selection derivation:**
both binaries still compute a runtime-dependent unit

    unit = ((global_0x5117B0 // global_0x5117C0) << 11) modulo 2^32
    bucket_count = R // unit       # requires nonzero unit
    k = PRNG % bucket_count        # if bucket_count > 0; otherwise k=0

The original at \`0x44F133\` subtracts \`k*unit\` from the
decoded file position, then at \`0x44F13A\` uses
\`DAT_name_table[k]\`. The GOG EXE **still contains the unit,
quotient and PRNG-remainder instructions** at \`0x44F0DA\`,
\`0x44F0F4\` and \`0x44F12A\`, but it NOPs the subtraction and
selects the first table name \`LEVELS0.DAT\`. All exact
instruction anchors were independently byte-verified. The runtime
values of the globals and \`k\` have not been observed; **we cannot
guarantee \`k<24\` or a valid seek for arbitrary synthetic inputs**.
The above describes only an execution path assuming valid, nonzero
divisors and a nonnegative PRNG result. It does not reconstruct
a SafeDisc 1.35 decryption key.

**Diagnostics updated in place**, not duplicated:
\`scripts/rayman2_dat_read_paths.py\` now verifies the 4-case
branch table, the three-entry conditional call chain, and the
retained alias-selection arithmetic. It exposes the pure helper
\`derive_dat_index(byte0, byte1, divisor)\` and restricts
\`derive_dat_word\` to **0..1023**. Eight additional synthetic tests
raised \`scripts/test_rayman2_dat_read_paths.py\` from 13 to
**21 tests**.

**Tests actually executed in this research session:** an
independent Python verifier rechecked both exact on-disk EXE
SHA-256 hashes, 16 shared and 2/3 edition-specific x86
sites, the four switch-target pointers, and 19 locally
executed synthetic/integration tests (including the earlier
16+4-byte read inspection). These are **not** claims that
the full repository Python/Rust test suite or new GitHub Actions
have been executed. The GitHub PR remains a draft.

## Bootstrap DAT 48-byte metadata model and floating-point selector (13 November 2026)

The earlier exploration established how individual DAT words are decoded, but
did not identify **where the six global parameters came from**. Rechecking the
owner's exact original-CD PE32 and the separately modified GOG PE32 provides
the missing static dependency chain:

- The initialization function at VA **0x0044DE90 .. 0x0044E748**
  selects the **first** DAT filename-table pointer at VA **0x004A2090**:
  this resolves to **LEVELS0.DAT** at **0x004A221C in BOTH retail CD
  and GOG**, independently of the later 24-name pseudo-file selector.
  The editions differ in how they format the drive path (format VA
  0x004A2264 versus 0x004A2268), but both request a **16-byte header**
  using their 16-byte ReadFile call at **0x0044E28D**.
- It requests **eight further 4-byte words** at VAs
  **0x44E387, 0x44E43C, 0x44E4FE, 0x44E5B8, 0x44E662,
  0x44E6B0, 0x44E6E5, 0x44E71A**.
  The first five of these are indirect calls through the dynamically
  generated retail ReadFile trampoline; the last three are direct CALLs
  to the shared wrapper at 0x44E750. GOG uses direct IAT calls for the
  first five and retains the last three direct wrapper calls.
- The 16-byte header initializes little-endian DWORDs A, B, C, D.
  The code increments A by C and B by D between subsequent words, in
  unsigned 32-bit arithmetic. For the word with zero-based index i,
  starting at i=1, the decoded value is

      value_i = ((word_i - (A+i*C)) mod 2^32) XOR ((B+i*D) mod 2^32)

  Six result values are saved as globals. The first (i=0) and last
  (i=7) additional words are **not assigned to those six globals**
  in this local function; their ReadFile calls still happen on the
  analyzed path and may have other side effects.
- The value for i=2 is additionally shifted **right by two bits**
  before assignment.

| Additional 4-byte read | Global variable written | Write instruction |
|---|---|---|
| word 1 (second) | 0x005117B0 | 0x0044E471 |
| word 2 (third) | 0x00511750, decoded value >> 2 | 0x0044E52C |
| word 3 (fourth) | 0x005117B4 | 0x0044E6AA |
| word 4 (fifth) | 0x005117C0 | 0x0044E6CA |
| word 5 (sixth) | 0x00511754 | 0x0044E714 |
| word 6 (seventh) | 0x005117BC | 0x0044E732 |

**This implies a nominal 48-byte initialization window**
(16 + 8*4), not a full authenticated DAT format.
The code's file reads are requests; return values are not proven
to indicate full-length successful reads in a runtime trace.
No original CD LEVELS0.DAT bytes were present for validation.
Both retail and GOG preserve the six global arithmetic/write sites
byte-for-byte even though GOG simplifies Win32 calls.

**New independent reproducible diagnostic**:
scripts/rayman2_dat_bootstrap.py, with
scripts/test_rayman2_dat_bootstrap.py.
Only the two known exact PE SHA-256 pairs pass the binary comparison.
The pure mathematical helper, decode_bootstrap_48, accepts only 48 bytes
and has no game code or proprietary-data fixture. A real local Python
unittest run completed **11/11 tests**, including private integration
against both exact binaries (absent on other computers: that integration
test safely skips). The new GitHub files were compared against the
tested local Python files and verified by exact Git blob SHA.
There is **no** claim that 48 bytes from the authentic CD were decoded.

### Next dependency: the floating-point seek offset

At **0x0044ED92 .. 0x0044EE4D**, the word decoder derives its
starting file position from additional global values just identified.

- A third state byte at VA 0x005116F2 is reduced modulo the
  *decoded* positive divisor at 0x005117B4. If its remainder m is
  zero, the branch at **0x0044EDB2** returns before the indexed
  file read. Thus an index 0..1023 does *not* imply a read on every call.
- For m > 0, original x87 instructions compute an accumulator
  initialized to **1.06913**, then iterate i=0..m-1, adding
  **0.69314 * abs(sin(1.69314 * i*i)) + 0.52658**.
- CRT calls through original IAT pointers **0x49C12C (modf)**,
  **0x49C13C (floor)** and **0x49C1AC (_ftol)** respectively
  retain the fractional part, quantize it to six decimal places,
  and convert a resulting scaled value to an integer j.
  The exact double constants also include **1,000,000.0**
  and **0.000001**. The corresponding six double values from VA
  0x0049C940..0x0049C96F are bit-identical between retail and GOG.
- At VA **0x0044EE39**, the CRT _ftol returns j. Instructions at
  **0x0044EE40..0x0044EE4D** compute

      position_P = global_0x511754 + j * global_0x5117BC  (modulo 2^32)

  These code bytes are unchanged in the two sample EXEs.
  The exact x87/CRT rounding and signed 32-bit conversion behavior,
  unknown actual global values, and I/O success require further
  verification before claiming a fully bit-for-bit standalone emulator.

**The original file-position selector therefore uses a decoded DAT
base and stride plus a nontrivial x87 trig/quantization calculation,
rather than simply seeking to a random multiple of 4.**
This is evidence about Rayman 2's resource-access logic, *not*
a SafeDisc 1.35 decryption algorithm.


## Retained x87 DAT position selector: formula and verified opcode anchors (13 Nov 2026)

The independent investigation of both **exact owner-supplied SHA-256-known
retail CD and modified GOG EXEs** has now pinned the complete unchanged
**192-byte** x87/CRT calculation at VAs **0x0044ED8E..0x0044EE4D**.
All **six double-precision constants** at VA **0x0049C940** and
**15 x86 instruction anchors** match both files. The imported CRT thunks
at **0x45FF52**, **0x45FF4C** and **0x45FEB0** are respectively
\`modf\`, \`floor\` and \`_ftol\`, validated in each PE.

For valid positive runtime divisor \`D = [0x5117B4]\`, let
\`m = byte([0x5116F2]) % D\`. If **m = 0**, the path branches
directly to **0x0044F1FA** and does not make the indexed DAT read.
Otherwise the floating-point calculation is approximately:

\`\`\`python
S = 1.06913
for i in range(m):                      # m <= 255
    S += 0.69314 * abs(sin(1.69314 * i*i)) + 0.52658
fraction = modf(S).fractional_part
quantized = floor(fraction * 1000000.0) * 0.000001
j = floor(quantized * decoded_global_0x5117B0)
P = (decoded_global_0x511754
     + j * decoded_global_0x5117BC) & 0xFFFFFFFF
\`\`\`

The quantized fractional coordinate lies between zero and one for
the positive finite ideal arithmetic; for a safely representable
positive 32-bit signed count \`C\`, the ideal \`j\` lies in
\`[0, C-1]\`. That makes the selector a **deterministic bounded
position choice within C stride slots** given the decoded globals,
rather than an unrestricted random disk offset.

**Critical limitation:** \`FSIN\` works on x87 80-bit intermediates,
and the exact historical \`modf\`, \`floor\`, \`_ftol\` results depend
on floating-point rounding/precision and possible conversion
overflow. Python's \`math.sin\`/binary64 is **NOT bit-exact x87
emulation**; synthetic \`j\` and P values near rounding boundaries
can differ from the real game. Runtime DAT values, valid Win32 file
reads, and original CD sector provenance have not been observed.
The code is not established as a SafeDisc decryption algorithm.

Instead of adding another standalone script to an already broad
research PR, the existing
\`scripts/rayman2_dat_bootstrap.py\` was **extended in place** with
\`verify_seek_selector\` (the exact opcode/constant checks) and
\`approximate_dat_seek\` (the explicitly inexact mathematical model).
Its companion test module gained eight new cases, giving **19 actual
local test executions passing**, including the two private
authenticated binary inputs and a sweep over many synthetic state
values. GitHub's exact Python blobs are identical to the tested files
(script \`7f968acdc73dcd890ef47a4fb95fedd957dd7ec5\`, tests
\`6cab41e1dc9c70cf161f592ec8349d5d2de81ccb\`).

No new GitHub Actions run or Rust build was launched; no game code was
executed or modified, and PR #3 remains a draft. The logical next
research check is to compare real original-CD \`LEVELS0.DAT\` data,
with its authentic file/ISO offset, against a runtime trace of P and
the six decoded globals—not to infer correctness from GOG's
modified executable alone.

## Missing LEVELS0.DAT: the same ordinary Win32 Retry/Cancel dialog in CD and GOG (13 Nov 2026)

A further **exact SHA-256-pinned retail-vs-GOG x86 examination** finds that
the **entire 290-byte error branch at VA 0x0044DFC9..0x0044E0EA is
byte-for-byte identical** in both executables. This path handles the
initial failure to open the **fixed bootstrap DAT file LEVELS0.DAT**,
rather than a specific proof that a SafeDisc hardware media check ran.

At 0x0044DFC9 the code compares the return value from its
CreateFileA attempt with **INVALID_HANDLE_VALUE = 0xFFFFFFFF**,
and jumps past the dialog on success. If the open fails, the original
and GOG both reconstruct two messages using individual x86
\`MOV BYTE PTR [EBP+disp8], imm8\` and
\`MOV BYTE PTR [EBP+disp8], BL\` stores on the stack. The
latter writes spaces (BL = 0x20).

The resulting **unmodified** Win32 dialog:

- Caption: \`Rayman 2 CD not found\`
- Message: \`Please, insert Rayman II CD in CDROM Drive\`
- Function: **USER32.dll!MessageBoxA**, called via IAT
  **0x0049C270** at VA **0x0044E0DB**.
- \`uType = 5\` = **MB_RETRYCANCEL**.
- Result **2** = **IDCANCEL**; the code at VA
  **0x0044E0E6** calls the game's teardown routine
  **0x004011C0** on Cancel.

On Retry, the two editions differ in **how they invoke
CreateFileA**, not in their dialog behavior:

| Stage / VA | Original retail | GOG reference |
|---|---|---|
| Retry after dialog, 0x0044E0EB | Calls masked PRNG code builder 0x00448480 | Direct short jump to 0x0044E15F |
| Build arguments, 0x0044E15F..0x0044E177 | Same 7-arg read-only CreateFileA arguments | Same instructions |
| Invoke CreateFileA at 0x0044E178 | Generated indirect \`CALL ESI\` | Direct \`CALL [0x0049C058]\` |
| Recheck return, 0x0044E1F8 | Compare with INVALID_HANDLE_VALUE; on failure jump to dialog at 0x0044DFD6 | Same control flow |
| Success, 0x0044E203 | Continue to DAT initialization | Same control flow |

The existing \`scripts/rayman2_dat_bootstrap.py\` has been
**extended in place** with a bounded \`verify_missing_dat_dialog\`
and a tiny specific-instruction stack-string decoder. It validates
both known SHA-256 input files, the shared 290-byte region,
MessageBoxA and the two edition-specific retry callsites, with no
runtime execution or commercial data embedded in the tests.
\`scripts/test_rayman2_dat_bootstrap.py\` gained six new cases,
raising it **from 19 to 25 unit tests**.

A real local test run using both owner's authentic EXEs finished
**25 tests, 25 passes, zero skips**. The two exact GitHub code blobs
match the tested local files (see PR comment for IDs).
No original ISO or actual DAT file was inspected; these are **static
branches** and not a test of whether either retail/GOG installation
would display the error on a modern machine.

**Practical implication:** if this specific dialog appears under
Wine/Windows, the first thing to check is whether the *bootstrap*
\`LEVELS0.DAT\` can be opened through the expected constructed path,
not to assume SafeDisc or secdrv.sys has blocked the CD. The original
retail may of course have separate SafeDisc and in-game anti-tamper
mechanisms; this finding neither proves nor rules them out.

### Two additional retained DAT errors: the game's window-aware Retry/Cancel dispatcher

Beyond the fixed bootstrap's dialog, **two more shared original/GOG file
opening failure branches** are byte-identical across the private exact
SHA-pinned executable pair. These occur inside the indexed DAT lookup
and its selected-file opening flow:

| Branch / stage | Byte-identical retail vs GOG code | Error UI call |
|---|---:|---|
| At VA 0x0044EC44..0x0044EC6A, first selected file open error | **39 bytes** | \`CALL 0x004028F0\` at 0x0044EC59 |
| At VA 0x0044F184..0x0044F1A6, second file open error | **35 bytes** | \`CALL 0x004028F0\` at 0x0044F195 |
| Shared GUI error-dispatch routine VA 0x004028F0..0x00402949 | **90 bytes** | \`MessageBoxA\` or \`SendMessageA\` |

Both callers push **uType=5** (Retry/Cancel), a caption pointer at
\`0x004A2270\` (ASCII **"CDROM not found!"**) and a message
pointer at \`0x004A06C0\` (ASCII **"Please insert the CD"**)
before calling \`0x004028F0\`.

The shared dispatcher checks a runtime GUI handle at \`0x004A6AC0\`.
If no GUI handle is present, it calls
**USER32.dll!MessageBoxA** at IAT \`0x0049C270\`
(assembly \`0x00402940\`); if the handle is present, it
uses **USER32.dll!SendMessageA** via IAT \`0x0049C228\`
(at \`0x00402921\`). The two routes can therefore present differently
at runtime; only the **static dispatch logic** is proven here.

This means the original and GOG contain *three independently verified
DAT file-opening failure branches*, not one. Both later errors share
Retry/Cancel behavior and Cancel calls the program's shutdown
routine \`0x004011C0\`, but their GUI path is conditional.
No SafeDisc physical-disc challenge, secdrv.sys request, or proprietary
CD sector check is demonstrated by any of these three strings.

The same existing \`scripts/rayman2_dat_bootstrap.py\` verifier now checks
all three branch ranges, the shared dispatcher, two constant messages,
and both USER32 import callsite opcodes. The previously added
\`test_rayman2_dat_bootstrap.py\` private sample integration asserts the
extra findings. **25 of 25 actual local tests pass, no skips** when
the owner's private binaries are present; GitHub code files match
the locally exercised blobs byte-for-byte. There is no Wine gameplay
test or original CD image involved.

## Verified producer of the original masked Win32 API pointer slots (13 Nov 2026)

**New direct evidence from both SHA-256-identified protected CD and modified
GOG PE32 samples.** Previous research established how several original
trampolines *consume* a masked pointer, but had not found the writer of its
initially-zero record slot. That producer is the protected retail
routine at **VA 0x00447AF0..0x00447BD9**.

The function accepts a **one-based descriptor index**. The x86 LEA/SHL
sequence at 0x00447B21 computes ESI = index*76; with the previously
confirmed 76-byte descriptor stride, the exact addresses are:

    index           = 1 .. 35
    descriptor_base = 0x004A13D0 + 76 * index
                    = 0x004A141C + 76 * (index-1)
    slot            = 0x004A1400 + 76 * index
                    = descriptor_base + 0x30

At 0x00447B2A the code reads the descriptor's **module index**
(offset +0x34). At 0x00447B30 it obtains the **32-bit XOR mask**
at descriptor_base. At 0x00447B36 it looks up a previously loaded
module in the module table at runtime global **0x00510BA4**.

There are **two original loader-local PE traversal functions**:
- **0x00447730** inspects the loaded DLL's **export directory**
  at PE optional-header +0x60 (NT header +0x78), traverses the
  name/ordinal/function tables and compares decoded API names.
- **0x00447540** inspects the module's **import directory** at
  PE optional-header +0x68 (NT header +0x80) and traverses
  imported names, comparing decoded record names.

**A special index-zero bootstrap supplies the module handles.**
Unlike the 35 regular descriptors indexed 1..35, the descriptor at
**0x004A13D0 (index 0)** decodes to **GetModuleHandleA** (not
LoadLibraryA). Its mask is at 0x004A13D0 and its pointer slot is
**0x004A1400**, also initially zero on disk.

At **0x004478E3**, the original 0x004478A0 bootstrap calls the
manual export resolver. After adding the module base to the
returned export RVA, instructions **0x004478F9** and
**0x004478FB** XOR the pointer with the mask and save it at
0x004A1400. Later, helper **0x00447A90** decodes an encoded
DLL name, reconstructs GetModuleHandleA at
**0x00447ABC..0x00447ACE**, invokes it and saves the returned
**HMODULE** into the module-handle table at global 0x00510BA4.
This is acquisition of a handle to an **already loaded module**,
not proven LoadLibrary-based loading of new DLL code.

GOG changes the beginning of the 0x004478A0 bootstrap into
**RET followed by INT3**, and replaces helper 0x00447A90
with INT3 as well. The special record-zero data stays
byte-identical across the actual two disk executables. The
existing diagnostic now locks **10 additional original
instruction anchors** for the special bootstrap and confirms
its GOG disablement. The independent local exact-sample probe
verified all 10 signatures and passed the previous seven
checks after their addition.

The API entry writer calls the export resolver at **0x00447B50**
or **0x00447B86**, and the import walker at **0x00447B7B**,
depending on the original branch. At nonzero successful result:

    0x00447BC0: XOR EBX,EAX                   ; mask XOR API address
    0x00447BC2: MOV [ESI + 0x004A1400],EBX   ; write slot[index]

Consequently the producer stores the **resolved API address XOR the
same descriptor mask**, exactly matching the inverse XOR performed
by the four earlier Win32 trampolines. The code clears the slot on
failure, at 0x00447B3D or 0x00447BCF. All 35 slots are still
**zero in both actual on-disk samples**: their runtime values
are **not** derivable from those zero bytes alone.

**Edition contrast:** GOG's executable .text section replaces the
entire **234-byte** region at **0x00447AF0..0x00447BD9**
with INT3 (0xCC), as well as the starts of the associated
DLL-name decoder and PE import/export helpers, while keeping
all 35 descriptor records byte-identical. Its separate .extra
section retains a non-executing copy of the original .text;
do not mistake the copy for active restored code.

Five original E8-relative callsites were independently verified:
three calls at **0x00448196, 0x004481A2, 0x00448D96**
target the API-slot producer, and two calls at
**0x0044818A, 0x00448DC3** target the module-handle helper
0x00447A90. These are *static callsites*, not runtime traces.

The original existing diagnostic,
**scripts/rayman2_trampoline_proof.py**, now includes a
15-anchor slot-producer check, 10 bootstrap anchors, five callsite checks and
an optional --gog comparison of all 35 records and the GOG INT3
region. Its companion test module adds index-bound and
optional private-sample tests. A **separate independent local
PE probe actually passed 7 tests against the two exact private
files**, including deliberately corrupted-hash refusal.
The updated GitHub test module has not been run through CI.

This proves the **masked-pointer producer/consumer arithmetic**
and local PE resolver paths, **not** a SafeDisc media
authentication transaction, an observed successful DLL import,
or decrypted game-code sections.

## 16-slot original CD callback vector versus GOG virtual-CD simulation (13 Nov 2026)

The SHA-256-verified original CD EXE and the *separately modified*
GOG EXE both retain two direct E8-relative callers
at **0x004674C8** and **0x0047B01B** into callback-table constructor
**0x00467130**. It initializes a **16-entry / 64-byte callback
table** supplied by its caller.

The original retail code constructs **12 entries** by reading the
corresponding encoded Win32 API pointer descriptor **+0x30** and
XORing the matching descriptor mask (35 named descriptors were
decoded in earlier work). Another **four entries** use fixed local
function pointers; these four stores are byte-identical between
CD and GOG. Thus all **16 final pointer-field store instructions**
are preserved, but the **values** produced differ.

| Callback offset | Original CD API / handler | Modified GOG callback |
|---|---|---|
| 0x00 | CloseHandle (#11) | local 0x00448F08 |
| 0x04 | local 0x00467050 | unchanged |
| 0x08 | CreateFileA (#8) | local 0x00448F60, virtual filename enumeration |
| 0x0C | GetDiskFreeSpaceA (#28) | local 0x00448ED0, fabricated geometry |
| 0x10 | GetDriveTypeA (#15) | local 0x00448EC4, returns DRIVE_CDROM |
| 0x14 | GetFileAttributesA (#30) | local 0x00448F08 |
| 0x18 | local 0x0045FEBC | unchanged |
| 0x1C | GetFileInformationByHandle (#31) | local 0x00449010 |
| 0x20 | GetFileSize (#18) | local 0x00448FD0, virtual-file record lengths |
| 0x24 | GetFileTime (#34) | local 0x00448F18 |
| 0x28 | GetVolumeInformationA (#16) | local 0x00448E6C, fabricated label, filesystem and serial |
| 0x2C | local 0x00448DE0 | unchanged |
| 0x30 | local 0x00448AB0 | unchanged |
| 0x34 | SetErrorMode (#32) | direct KERNEL32 IAT at **0x0049C0C8** |
| 0x38 | SetFileAttributesA (#29) | local 0x00448F00 |
| 0x3C | SetFileTime (#33) | local 0x00448F10 |

GOG therefore replaces the **12 original masked Windows API
entries** with **11 local compatibility handlers and one direct
imported API**. The other four game-local callbacks remain intact.
Not all handlers simply forward to Windows: several **synthesize
CD-specific results**. Exact instruction checks establish:

| GOG helper | Evidence from actual GOG instructions |
|---|---|
| 0x00448EC4 GetDriveType replacement | Returns **5 = DRIVE_CDROM** |
| 0x00448E6C GetVolumeInformation replacement | Label **RAYMAN2**; filesystem **CDFS**; serial **0x6D380AE8**; maximum component length 110; flags 5 |
| 0x00448ED0 GetDiskFreeSpace replacement | Sectors/cluster = **1**, bytes/sector = **2,048**, free clusters = **0**, total clusters = **332,400** |
| 0x00448F60 and 0x00448FD0 | Inspect the **0x005B3000 virtual-file list** to resolve filenames and metadata |

This permits a precise **independent arithmetic cross-check**:

    332,400 sectors x 2,048 bytes/sector = 680,755,200 bytes

This is exactly the capacity previously recovered from GOG's
virtual-CD emulation. It is **not** the 7,453,062,614-byte *sum of
declared lengths* of all 3,716 GOG metadata entries (which includes
24 artificially oversized DAT names). A physical CD cannot be
inferred by summing the directory's declared file lengths.

**Why this matters:** we can now identify a distinct GOG
CD-compatibility boundary, rather than equating its modified
Win32 calls with decrypted original retail code. This confirms
GOG simulates a Rayman 2 CD-ROM for selected game file callbacks;
it does **not** reveal how the original SafeDisc media driver
authenticates a physical disc or whether those two static call
paths execute in a particular game session.

The existing
**scripts/rayman2_win32_forwarders.py** was extended in place
(no extra new analyzer), with 16 table-slot assertions,
12 exact descriptor/name/mask checks, four preserved game-local
stores, two retained E8-relative callers, and 15 known GOG
media-stub opcode anchors.
**scripts/test_rayman2_win32_forwarders.py** gained five
new synthetic/optional-private-sample tests, for **14 test
methods** in that module. The independent local read-only
prototype has already verified both actual private binaries;
the updated repository module's success should be checked in
GitHub Actions before claiming full regression coverage.

Reproduce against the user's own original and GOG EXEs:

    python scripts/rayman2_win32_forwarders.py \
      --retail /path/to/original/Rayman2.exe \
      --gog /path/to/GOG/Rayman2.exe
    python -m unittest discover -s scripts -p 'test_rayman2_win32_forwarders.py'

Both editions are SHA-256 locked. No proprietary PE content is
committed or distributed; GOG is an edited third-party executable,
not a clean original executable with only SafeDisc removed.

## GOG virtual-CD handles: record indices, not Win32 kernel objects (13 Nov 2026)

A follow-up to the 16-slot callback audit reveals exactly how
the **modified GOG executable simulates file handles** for its
Rayman 2 CD metadata queries.

The GOG callback at **0x00448F60** is placed in the original
**CreateFileA** table slot (offset 0x08). It does **not** call
the real Win32 CreateFileA API on its accepted path.
Its instructions at 0x00448F65..0x00448FC5:

1. Reject \`dwDesiredAccess & GENERIC_WRITE\` (bit 0x40000000).
2. Require a non-null pointer and a path whose second and
   third characters are a colon and a backslash, e.g. \`D:\`.
   The first character is treated as the drive letter.
3. Skip the first **three path bytes**, then compare the remaining
   filename with successive entries in the virtual table at
   **VA 0x005B3000**, uppercasing only ASCII a..z from the input.
4. Return the **zero-based integer position** of the matching
   filename in the ordered table of 3,716 records, **not** a
   native Windows HANDLE. Return **0xFFFFFFFF** if no file matches.

At **0x00448FD0**, its callback for **GetFileSize** uses that
integer as a record index, walks the same packed metadata records
(their entries are \`u32 declared_length\`, \`u32 filename_bytes\`,
\`NUL-terminated name\`), and returns the record's
**declared 32-bit file length** while clearing the output high
DWORD to zero. If the index runs beyond the sentinel, the function
returns **zero**, not \`INVALID_FILE_SIZE\`. It does not read actual
file contents, and the declared values for the 24 DAT pseudofiles
still do not describe trustworthy physical CD extents.

The other GOG callback implementations confirm the same virtual
filesystem contract:

| GOG code | Static return or metadata behavior |
|---|---|
| \`0x00448F08\` (CloseHandle) | Returns TRUE = 1, without calling native CloseHandle |
| \`0x00448F08\` (GetFileAttributesA) | Returns **1 = FILE_ATTRIBUTE_READONLY** |
| \`0x00448F00\` (SetFileAttributesA) | Returns FALSE = 0 |
| \`0x00448F10\` (SetFileTime) | Returns FALSE = 0 |
| \`0x00448F18\` (GetFileTime) | Fabricates file timestamps |
| \`0x00449010\` (GetFileInformationByHandle) | Fills read-only file attributes, volume serial 0x6D380AE8, link count 1, size via the same virtual index, and file index equal to that index |

The fixed GOG FILETIME bytes correspond to
**1999-09-07 09:10:06 UTC**. One **unverified implementation hazard**
was noted: at **0x00449023**, the GOG
\`GetFileInformationByHandle\` shim stores the high timestamp DWORD
through **[EDI+8]**, whereas adjacent fields use the output pointer
in **EAX**. No runtime register trace was collected, so it would be
premature to call this a demonstrable crash or to patch the
executable on that basis. It is recorded only as a static anomaly.

### Independent correlation against all real GOG records

The ordered 3,716-name manifest (from its actual \`.extra2\` section)
is now parsed and checked alongside **30 independent instruction
signatures**. These verified index/size pairs illustrate why the
returned integer is a synthetic handle:

| Virtual handle | GOG manifest filename | Declared size |
|---:|---|---:|
| 6 | DPLAYERX.DLL | 165,888 |
| 17 | RAYMAN2.EXE | 676,352 |
| 18 | RAYMAN2.ICD | 683,565 |
| 21 | SECDRV.SYS | 14,368 |
| 43 | DATA\WORLD\LEVELS\LEVELS0.DAT | 150,775,808 |
| 46 | DATA\WORLD\LEVELS\MAP0.DAT | 187,087,845 |
| 56 | DATA\WORLD\LEVELS\SOUNDS1.DAT | 339,690,633 |

The \`CreateFileA\` shim accepts these paths with differing
drive letters and ASCII capitalization, while \`GetFileSize\`
returns their declared byte counts. The original CD's physical
LBA layout and the actual data read path are **not** inferred.

**Reproducible implementation:** the existing
\`scripts/rayman2_win32_forwarders.py\` now checks the 30 opcode
signatures and the seven specific manifest indices through
\`inspect_gog_virtual_handles\`. The existing
\`scripts/test_rayman2_win32_forwarders.py\` contains
**21 test methods**, including a private-file test that skips
when the owner PE samples are unavailable. A separate local
read-only independent audit completed **13 tests with the exact
SHA-256-pinned GOG executable**, including bad-hash refusal and
synthetic file-index behavior. Neither this nor CI executes the
proprietary game executable.

**Important boundary:** these are **CD-file metadata APIs**.
The caller-facing table does not provide a complete emulation
of native \`ReadFile\`; no conclusion about SafeDisc 1.35's physical
disc authentication or the live data-loading path follows from
these static GOG stubs.

## Separate real-file stream I/O: two original masked ReadFile variants replaced by direct readers (13 Nov 2026)

The previously identified GOG \`CreateFileA\` **virtual CD callback** at
\`0x00448F60\` only simulates names, handles and metadata. A **different
file-stream API** still opens real OS handles and reads actual data.
Do not conflate these two interfaces.

**Original and GOG both retain:**

- A direct \`KERNEL32.dll!CreateFileA\` call through IAT
  **0x0049C058** at **0x00450C16**, saving the resulting real
  Windows HANDLE at **0x00450C1C**.
- Structure constructor **0x00450A00**, called from
  **0x00450A8E**, which writes the selected read handler into
  **[stream + 0x24]** at **0x00450A4D / 0x00450A70**.
- Read dispatch **0x00450D90**, with indirect call
  **\`CALL [EBX+0x24]\` at 0x00450DD5**. Here EBX points
  to the stream's callback-bearing state, not to a synthetic
  GOG filename-list handle.

### Exact 118-byte constructor diff: only two bytes

The **entire 118-byte constructor body** from VA
**0x00450A00..0x00450A75** was compared byte for byte between
the two exact owner's SHA-256-known CD and modified GOG EXEs:

| Location | Original x86 | GOG x86 | Effect on callback choice |
|---|---|---|---|
| \`0x00450A46\` / displacement byte \`0x00450A47\` | \`75 28\` | \`75 00\` | GOG always falls through to the direct-IAT, XOR-transforming reader |
| \`0x00450A69\` / displacement byte \`0x00450A6A\` | \`75 05\` | \`75 00\` | GOG always falls through to the direct-IAT, raw reader |

**Every other byte in that constructor is unchanged.**
In the original code, the two conditions can select masked
Windows-\`ReadFile\` variants, depending on stream flags. In GOG,
the zero-displacement branches ensure the pointer chosen in
EAX is overwritten by the direct-IAT variant before it is stored
at offset +0x24.

**Four original reader implementations, paired by role:**

| Original reader VA | Static role | Modified GOG \`.text\` |
|---|---|---|
| **0x00451090** | Direct \`ReadFile\` followed by a per-byte XOR stream transformation | **128 contiguous bytes remain exactly identical** |
| **0x00451110** | PRNG-built masked \`ReadFile\`, then a per-byte XOR stream transformation | **432 bytes replaced with \`INT3\`** |
| **0x004512C0** | Direct \`ReadFile\` with no subsequent payload XOR | **64 contiguous bytes remain exactly identical** |
| **0x00451300** | PRNG-built masked \`ReadFile\`, without subsequent payload XOR | **305 bytes replaced with \`INT3\`** |

The two preserved direct calls are **\`CALL [0x0049C04C]\`**
at **0x004510AE** and **0x004512DA**.
The original masked callsites are **\`CALL ESI\`**
at **0x004511E2** and **0x004513BB**.

**Critically, the per-byte XOR transformation still exists in
GOG.** At 0x004510CD it XORs a read byte with state
\`[stream + 0x15]\` and updates a masked pseudo-random
32-bit state under \`[stream + 0x14]\`. Although this
resembles a Park–Miller-style recurrence, the exact x86 reduction
is **not** mathematically interchangeable with modular arithmetic
for every state (see the new subsection below). The masked
original variant performs analogous XOR operations beginning
at 0x0045126B. This supports pairing the routines by *type
of processing*; it is **not** a runtime proof that every
result is bit-for-bit identical, or evidence that this XOR
is SafeDisc's native PE unwrapping cipher.

The existing
**\`scripts/rayman2_cd_io_diff.py\`** now performs exact
two-branch-byte matching, verification of 15 shared opcode
anchors, three original-only anchors, comparison of preserved
reader regions, and checks that both masked-reader ranges are
completely \`INT3\` in the GOG executable. The same file's
read-only input loader was also made portable to Windows:
strict \`dev/inode\` equality remains on POSIX; Windows uses
the common size/mtime snapshot fields to avoid a false
\`stat()/fstat()\` identity mismatch. Windows read-only input
is still subject to general TOCTOU caveats.

Five new tests in
**\`scripts/test_rayman2_cd_io_diff.py\`** create synthetic
PE-backed code regions and reject unexpected branch bytes,
unneutralized GOG masked reader code and altered direct-IAT
ReadFile. An optional exact-file test is skipped on CI
runners that do not have the user's private PE samples.

**Independent local verification actually executed:**
12 tests against exact owner-supplied protected CD/GOG EXEs
and synthetic validation passed, no skips.
Saved local JSON:
\`rayman2_stream_reader_verified_20261113.json\`.
A complete hosted CI result should be confirmed separately
for the final PR commit.

**Interpretation boundary:** this isolates the real file I/O
read callback contract from GOG's virtual-CD metadata callback
contract, but does not trace which real game files use a
particular mode at runtime, how SafeDisc authenticates a disc,
or how post-unwrapping original game sections differ.

### Exact per-byte stream XOR: a 32-bit reduction, not a generic modulo (13 Nov 2026)

The direct-IAT **ReadFile + XOR** loop at
**0x004510CD..0x00451108** is byte-for-byte identical in the
SHA-256-known protected CD and modified GOG PE32 files.
The original **masked ReadFile + XOR** loop at
**0x0045126B..0x004512A6** uses the same multiplication,
magic constant, shift and XOR operations, but the corresponding
GOG executable bytes are all INT3.

**Stream-mode flags are independent:** function **0x00450EC0**
extracts **bit 1** of stream option byte **[stream+0x18]**:
when set, initializer **0x00450A2D** sets state
**[stream+0x14] = 0x6AB5CC79** and chooses the XOR reader.
Function **0x00450ED0** extracts **bit 2** of that same option
byte and originally chooses a generated masked Win32 API
reader versus a direct-IAT reader. GOG's two altered JNE
displacements neutralize only the masked variant selection.
Therefore the XOR still has a separate runtime option.

**Exact byte transform for a fully read buffer:** The native
reader calls actual \`KERNEL32!ReadFile\`; at
**0x004510BF..0x004510C8** it compares the returned number
of bytes with the requested count and skips its XOR loop on
a mismatch. It records the API's BOOL result separately.
When the counts match, for each byte at position \`i\`:

    output[i] = input[i] XOR ((state >> 8) & 0xFF)
    state = x86_step(state)

**The byte used is the SECOND-LEAST-SIGNIFICANT state byte**,
from \`MOV CL, BYTE PTR [EDI+0x15]\` (not the low byte
at +0x14). To model \`x86_step\` exactly, preserve each
32-bit intermediate truncation in the following x86 reduction:

\`\`\`python
mask = 0xFFFFFFFF
v = state ^ 0x075BD924
high = (v * 0x069C16BD) >> 32   # unsigned MUL upper DWORD
low = (v * 16807) & mask        # IMUL lower DWORD
q = (v - high) & mask
q = (q >> 1)
q = (q + high) & mask
q >>= 16
edx = (-q) & mask
edx = (edx << 31) & mask
edx = (edx - q) & mask
state = (low - edx) & mask
\`\`\`

This deliberately **is not replaced** with the attractive
but incorrect expression

    state = ((state ^ 0x075BD924) * 16807) % 2147483647

because the original **magic-constant quotient can differ
from the mathematical exact quotient** for some states.
For the actual initial state \`0x6AB5CC79\`, the two
versions first differ after 70 updates:

| Check | Exact x86 | Simplified modulo |
|---|---|---|
| State after 70 bytes | \`0xFEF02481\` | \`0x7EF02480\` |
| First different XOR-key byte | **offset 71** | **offset 71** |

The state difference at byte offset 70 does not yet change
the byte at \`state+1\` (both use 0x24), but subsequent
state evolution yields different key bytes at offset 71.

**Synthetic golden vectors, no copyrighted data:**

| Vector | Exact result |
|---|---|
| First 16 XOR bytes for 16 zero input bytes | \`ccc5dfcceebdf8ceaf15bbae35a91340\` |
| SHA-256 of 256 zero-input XOR bytes | \`8eeed8d4e85f19dd1a78d818003c41056e15755dd1bff524afb49c8cda0bc957\` |
| Stream state after 256 bytes | \`0x2A88DE34\` |
| SHA-256 of 512 zero-input XOR bytes | \`1f91a5cac736fa9301f3a256fda143ede53fb3edf862aa62adc579bbb31691c5\` |

**Reproducibility and scope:** 
\`scripts/rayman2_cd_io_diff.py\` now implements
\`stream_xor_step32\`, \`stream_xor_transform\`, and
\`inspect_stream_xor_x86\` with **16 original/GOG
direct-reader opcode anchors** and **nine original-only masked
reader anchors**. \`scripts/test_rayman2_cd_io_diff.py\`
has **28 test methods** including deterministic 10,000-state
crosschecks with an independently written x86 register-level
interpreter, XOR-involution and split-buffer resumption checks,
two golden SHA-256 vectors, and explicit modulo-divergence
regressions. A separate independent local verifier executed
**14/14 tests against actual SHA-256-identified retail/GOG
files and synthetic data**. Its private JSON report is
\`rayman2_stream_xor_exact_verified_20261113.json\`.

The test code models transformed bytes **only after a full
ReadFile byte count**, never actual file I/O itself. No source
LEVELS0.DAT bytes or verified CD runtime file reads were used.
**This is a game stream transform, not a proven general
SafeDisc 1.35 executable/ICD decryption algorithm.**

## Third stream option: rolling DWORD checksum (not another decryption layer)

An additional full-region comparison of the **original CD and edited GOG
PE32** proves the stream dispatch function **0x00450D90..0x00450EAF**
(**288 byte-identical code bytes**) and the three bit-extraction helpers
**0x00450EB0..0x00450EDF** (**48 identical bytes**). A new read-only,
SHA-256-locked verifier checks **26 exact x86 opcode sites** from both
files, including multiple original stream-open callsites.

The stream option byte at **[stream+0x18]** combines independent bits:

| Bit | Stream option | Original behavior |
|---|---|---|
| 0x01 (bit 0) | Rolling DWORD XOR checksum | After a successful read callback, accumulate little-endian 32-bit words without modifying the caller's buffer |
| 0x02 (bit 1) | Bytewise XOR transform | Modify each byte using the seed 0x6AB5CC79 and exact x86 PRNG state update, as documented above |
| 0x04 (bit 2) | Masked Win32 I/O | In original CD, choose generated/trampoline Win32 file-opening and ReadFile; GOG forces ordinary IAT calls |

For the **0x01** flag, the accumulator at
**[stream+0x10]** is initialized to **zero** when opening a
stream. At **0x00450DD5**, the program calls the stream's selected
reader \`CALL [EBX+0x24]\`. If that callback reports failure,
the accumulator is not updated. Otherwise
\`0x00450DE6\` calls the bit-0 helper, and when enabled
\`0x00450E55..0x00450E61\` and
\`0x00450E70..0x00450E7E\` fold complete 4-byte little-endian
words into the 32-bit XOR accumulator.

**Chunk handling matters:** when a read ends after 1–3
unpaired bytes, those bytes stay in a separate pending buffer at
**[stream+0x08]**, with its length in **[stream+0x0C]**.
They are only XORed into the accumulator once the next read
completes a four-byte word. The implementation does **not**
zero-pad or immediately incorporate the final incomplete word.
This makes the rolling checksum independent of how the
same successfully read bytes are divided between calls.

It is important not to call this a second payload decryption:
**the DWORD XOR stage never writes transformed bytes back
to the caller's data buffer**. It only changes stream bookkeeping.
When both bits 0 and 1 are enabled, the callback's per-byte XOR
runs **first**, and this stage accumulates the resulting
already-transformed bytes.

Verified hardcoded original/GOG caller instructions include
**mode 0x03** at \`0x0044D50B\` (both accumulator and bytewise
XOR), **mode 0x00** at \`0x0044DACF\`,
**mode 0x06** at \`0x0044EA1C\` (bytewise XOR and original masked
I/O, inside DAT handling), and **mode 0x02**
at \`0x0044F769\`. These are static callsites, *not*
proof of which modes occur during actual gameplay.

### Another precise GOG edit: the original masked CreateFileA opener is removed

In addition to the two reader-selector JNE bytes and masked
ReadFile routines documented above, GOG completely removes
the **original stream-open masked CreateFileA branch**:

- Original **0x00450ADE** checks flag bit 2, generates a
  masked Win32 \`CreateFileA\` trampoline, then invokes it by
  \`CALL ESI\` at **0x00450B9E**.
- GOG instead has **\`E9 22 01 00 00\` at 0x00450ADE**:
  a direct jump to the plain-API opener **0x00450C05**.
  Every following byte from **0x00450AE3 through
  0x00450C04** is **INT3** — exactly **290 bytes**.
- The following **46 bytes at 0x00450C05..0x00450C32**
  remain *byte-identical* in both files, including
  direct \`KERNEL32!CreateFileA\` via IAT **0x0049C058**.

This further establishes the boundary between original
generated-API call obfuscation and GOG's explicit bypass.
It does **not** show that either edition authenticates a
physical SafeDisc CD through this routine.

The existing \`scripts/rayman2_cd_io_diff.py\` now provides
\`stream_word_xor_checksum\` for an explicitly **pure
synthetic model** and \`inspect_stream_word_checksum\` for
on-disk opcode verification. Companion tests check little-endian
DWORDs, pending carry across reads, byte-for-byte chunk
invariance, failure paths and intentionally corrupted
signatures. The independent owner-file local suite passed
**20/20 tests**, with SHA-256 validation of both original
executables and checks on the GOG 290-byte INT3 range.
It does not use original CD DAT payload bytes, execute
proprietary instructions, or establish a SafeDisc decryption key.


## Read-only, falsifiable checks

`scripts/rayman2_anti_tamper_assets.py` inspects only the two historical asset names and hashes, with case-insensitive per-component lookup, link rejection and bounded reading. Example:

```sh
python scripts/rayman2_anti_tamper_assets.py --cd-root /path/to/original-cd --installed-root /path/to/unmodified-install
python -m unittest discover -s scripts -p 'test_rayman2_anti_tamper_assets.py'
```

Outcomes: `identical`, `different`, `cd_only`, `installed_only`, `absent_both`. None prove authenticity, SafeDisc status, or activation of the pirate-head check. The files can be in installer archives, alternate paths or ISO multi-extent records; missing from an extracted tree is not proof of missing from the physical disc.

**Next controlled test:** capture which paths, handles and returned data the *retail* program reads from the same-edition original CD and an unmodified installed tree; isolate file-read and anti-tamper behavior from the kernel-level media verification. Contrast the GOG callback behavior with retail only after validating provenance. The GOG code/manifest must never be copied as a stand-in for the retail loader. Don't execute or distribute proprietary binaries as fixtures.

No SafeDisc key, decrypted ICD, native Rust build, gameplay test or universal crack is claimed here.
