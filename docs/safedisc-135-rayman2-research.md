# Rayman 2 retail CD — SafeDisc 1.35 research

Status: **read-only classification implemented; native unwrapping not implemented.**

## Source correction — GOG reference is not an original retail no-DRM image

**Owner clarification (13 November 2026):** the 1,468,928-byte
`Rayman2.exe` (SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`)
is supplied by the **GOG release**, **not** a verified reconstruction of
the unmodified original retail executable with only SafeDisc removed.

The comparisons below remain **accurate byte-level observations
between two specific files**, but they **do not identify SafeDisc
patches**. GOG could have introduced unrelated compatibility patches,
code changes, resources, version-specific alterations, installer
metadata, or additional sections; the origin of each change remains
unknown. In particular:

- The 10,851 changed bytes that became `0xCC` (`INT3`) **cannot
  all be attributed to DRM neutralization** without an independent
  call-path proof. The same applies to `0x90` (`NOP`) changes.
- The `.extra`, `.extra2`, and `.rsrc` sections may have been
  introduced or changed by GOG or an earlier third party. Their
  presence **does not establish** the original SafeDisc unpacking
  format or the origin of the embedded manifest.
- The `.extra2` file list of 3,716 entries **is found in the
  GOG executable**. Its filenames and claimed sizes can be
  independently compared to the owner's original disc, but the
  list **must not be presented as a verified original CD manifest**
  without that comparison.

**Required research separation:** "retail protected EXE" is one
input; "GOG executable, DRM-free but potentially otherwise modified"
is a second input. Use the latter as a **comparative reference only**,
not a pristine ground truth, not an automatically valid original
binary, and not a universal no-SafeDisc patch blueprint. Future
work should isolate proven DRM behavior via code-flow analysis
or additional independently verified retail-version evidence.

## New exact section-copy evidence — GOG `.extra` (13 November 2026)

**Strong, fully reproducible byte identity:** The GOG reference's
`.extra` section contains a **100%-identical copy of the protected
retail `.text` section** (631,296 bytes), starting at offset
`0x1000` *within the GOG `.extra` section*.

| Property | Exact result |
|---|---|
| Source | Protected CD `.text`, RVA `0x1000`, length **631,296** |
| Destination | GOG `.extra`, section-relative offset **`0x1000`** |
| Destination file offset | **`0xA7C00`** |
| Destination RVA / VA | **`0x118000` / `0x00518000`** |
| Matching bytes | **631,296 / 631,296 (100%)** |
| SHA-256 of both code blocks | `43ce6eff6082f2c7491cd249d3cfeffbcb56e63313a67246dd2b14f1985751c3` |
| Before the copied block | **4,096 zero bytes** |
| After the copied block | **3,584 zero bytes** |
| GOG `.extra` PE characteristics | **`0x40000040`**: initialized, readable, **not marked executable** |

The exact equality is stronger than coincidental x86 disassembly:
**the supposed "new code" at GOG VA `0x00518000` is precisely
the unchanged protected CD code copied elsewhere.** In particular,
disassembly there **must not** be described as newly written GOG
routines or a verified SafeDisc relocation. It is a byte-for-byte
embedded copy with zero padding.

We do **not know why** the GOG executable retains that copy.
The non-executable section-header flag does not absolutely prohibit
later runtime permission changes, so no claim of execution or
non-execution is made. The original protected code contains
absolute addresses; merely finding the same bytes at a different
RVA is not proof that they can execute unmodified.

The generic read-only Python tool `scripts/pe_reference_diff.py`
now automatically finds such **full, nontrivial, cross-section byte
copies**, reporting offsets, SHA-256, zero padding and PE
section characteristics. Its synthetic tests require full byte
identity and reject one-bit changes and constant filler.
**No proprietary bytes** are embedded in the tool or tests.

This changes the research priority: compare the **GOG-modified
`.text`** against both the **original protected `.text`** and
the identical preserved copy in `.extra`. Attribute individual
edits to SafeDisc, GOG compatibility changes or other modifications
**only when justified by control-flow or independent provenance
evidence**. Do not generate a retail deprotection patch by blindly
replaying the GOG differences.

## Direct protected / unprotected PE32 comparison (13 November 2026)

The owner previously supplied a **GOG edition (DRM-free, potentially otherwise modified)**
`Rayman2.exe` (**1,468,928 bytes**, SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).
This SHA-256 is also recorded as the approved GOG-derived runtime in
[Rayman2Fix architecture](https://github.com/legluondunet/Rayman2Fix/blob/main/docs/architecture.md).
The protected source `Rayman2.exe` is **676,352 bytes**, SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
**Both exact user-owned files were analyzed read-only.**

Their PE32 entry RVA **`0x5FCC0`**, image base **`0x400000`**,
import data-directory RVA **`0x9D0D8`** and export data-directory
RVA **`0x9DDD0`** agree. The protected EXE is **not** merely an
empty launcher: much of the original game code is present already.

**Compare section contents at matching virtual RVAs**, not at file
offsets: the protected `.text` begins at raw offset `0x400`,
whereas the GOG reference begins at raw offset `0x1000`.
A naive file-position byte comparison misleadingly reports massive
differences. Correctly aligned by RVA:

| Shared section | Compared backed bytes | Identical bytes | Identity | Changed bytes |
|---|---:|---:|---:|---:|
| `.text` (RVA `0x1000`) | 631,296 | 618,027 | **97.8981%** | 13,269 |
| `.rdata` (RVA `0x9C000`) | 12,288 | 12,288 | **100%** | 0 |
| `.data` (RVA `0x9F000`) | 31,744 | 31,617 | **99.5999%** | 127 |

**Control-flow neutralization pattern:** among the **13,269**
changed backed bytes in shared `.text`, **10,851 bytes** are
replaced by `0xCC` (`INT3`) and **1,520 bytes** are replaced by
`0x90` (`NOP`). A large original code range beginning at
RVA `0x474B0` is filled with `INT3` in the GOG reference.
This strongly indicates intentional invalidation/neutralization of
some original code paths, **not** necessarily the exact SafeDisc
module boundary, and does not by itself provide safe code relocation.

**Corrected interpretation of `0x00518000`:** this address
marks the start of the exact, **unchanged 631,296-byte protected
`.text` copy embedded in GOG `.extra`**, not newly discovered
GOG-written code. A disassembler naturally sees x86 instructions
because these are identical to the protected code. The containing
section is flagged read-only data and is not marked executable.
No execution path or SafeDisc patch intent is inferred.
No additional proprietary code is committed.

The `.text` byte changes occupy **14** distinct 4-KiB virtual pages,
with the largest concentrations in page ranges near RVAs
`0x47000`, `0x48000` and `0x4E000`. Changed-byte addresses
and density are diagnostics only: they are **not** automatically
identified as SafeDisc routines. The GOG reference has
three additional sections:

| Additional section | RVA | Backed length | Remark |
|---|---:|---:|---|
| `.extra` | `0x117000` | 638,976 | Purpose not established |
| `.extra2` | `0x1B3000` | 143,360 | Begins with a size/name-length file inventory |
| `.rsrc` | `0x1D6000` | 3,584 | PE resource section, absent from the protected EXE |

The GOG EXE's PE resource data directory is nonzero; the
protected counterpart has no ordinary resource directory. These
differences **do not establish how the unprotected EXE was produced**
or imply a general-purpose SafeDisc 1.35 decoding method.

### Major update: static writer and export-name resolver recovered

**13 November 2026, independent static audit of the SHA-256-verified
retail CD executable.** The former question about who writes the
descriptor `+0x30` fields is **resolved at the instruction level**.

**Exact write mechanism:** function `0x00447AF0`, called with
a one-based descriptor index `i`, computes:

```text
ESI = 76 * i
destination = 0x004A1400 + ESI
            = 0x004A141C + 76*(i-1) + 0x30
```

When a nonzero function address is obtained, the routine uses:

```asm
447BC0: xor ebx,eax                    ; mask XOR resolved export VA
447BC2: mov [esi+0x004A1400],ebx       ; store masked callback
```

When a function lookup fails, the branch at `0x00447BCD`
can instead write **zero** into the same destination.
Thus the paired callsite `stored XOR mask` recovers the
previously resolved function pointer **if resolution succeeded**.
No code is executed and no runtime address was observed during
this audit.

**Call chain, conditional initialization path:**

- `0x004493FA` sets the **module count to 7**
  (global `0x005113E8`).
- `0x00449404` sets the descriptor iteration bound to
  **36** (`0x24`, global `0x005113F0`) in the nonzero-argument
  branch of the initialization routine.
- `0x0044947C` calls module preparation `0x004478A0`.
- `0x00449485` calls `0x00448DB0` to walk module indices.
- `0x0044948E` calls `0x00448D80`, which iterates
  **descriptor indices 1 through 35** and invokes
  `0x00447AF0` at `0x00448D96`.
- Two additional direct `0x00447AF0` calls at
  `0x00448196` and `0x004481A2` explicitly
  reference descriptor indices **24 and 25**.

This **establishes a static writer and its initialization
loop**; it supersedes older statements that the writer's
identity was unknown. It does **not** prove this path
always executes under Windows/Wine, that every export is
found, or that all 35 fields become nonzero.

#### The names are obfuscated, not absent

The static routines `0x004474D0` (module-name
construction) and `0x00447730` (export-name
comparison) reveal a simple per-character encoding in
the protected on-disk descriptors:

```text
key_sub, key_xor, increment_sub, increment_xor = record[0..4]
name_length = record[4]
for each encoded character:
    plain = ((encoded - key_sub) mod 256) XOR key_xor
    key_sub = (key_sub + increment_sub) mod 256
    key_xor = (key_xor + increment_xor) mod 256
```

This is **name obfuscation**, not evidence of a SafeDisc
cipher for the actual executable or files on the CD.

The seven decoded module records (`0x004A1268`,
stride **45 bytes**) are:

```text
0 KERNEL32.dll
1 USER32.dll
2 PSAPI.dll
3 ADVAPI32.dll
4 GDI32.dll
5 VERSION.dll
6 WINMM.dll
```

The **35 API names** in the 76-byte records starting
at `0x004A141C` were all decoded and are associated
with module indices stored at record offset `+0x34`:
**33 names target KERNEL32.dll and two target
PSAPI.dll** (`EnumProcesses`, `EnumProcessModules`).
The remaining five module names may be used through
other paths and are not evidence of 35 different
loaded libraries.

Representative decoded exports:

| One-based record | Module | Exact decoded export name |
|---|---|---|
| 1 | KERNEL32 | `FlushInstructionCache` |
| 8 | KERNEL32 | `CreateFileA` |
| 10 | KERNEL32 | `ReadFile` |
| 18 | KERNEL32 | `GetFileSize` |
| 24 | PSAPI | `EnumProcesses` |
| 25 | PSAPI | `EnumProcessModules` |
| 35 | KERNEL32 | `GetLogicalDrives` |

One descriptor spells `FlushFileBuffer` (singular);
the standard documented Win32 API is
[`FlushFileBuffers`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers).
**Do not silently change the decoded name.** This
possible deliberately unresolved or variant-specific
symbol requires checking actual exported names and
runtime outcome before any repair.

#### GOG changes the module-name storage separately

In the hash-identified **GOG** executable, the
seven records at the same module-table VAs contain
**plaintext uppercase NUL-terminated DLL names with
zero padding**, whereas the retail CD stores
the obfuscated names. The **35 API descriptors
themselves remain byte-identical**, including their
encoded export names and zero on-disk pointer slots.
Thus GOG's changes distinguish the **DLL naming /
module loading layer** from the still-encoded
Windows export-name descriptor layer.
Do not infer GOG's original rationale or assume it
only disabled SafeDisc.

#### Static cross-reference limits

A scan of the *linearly disassembled retail `.text`*
for exact absolute VAs of all 35 descriptor slots
(`+0x30`) found **97 rendered direct memory reads**,
**30 immediate/address-literal uses** and **no
direct absolute writes**. There were references
to **24 of the 35** slots. These counts are
**not a complete call graph** and do not preclude
indirect writes. In fact the indexed
`mov [esi+0x004A1400],ebx` at `0x00447BC2`
**is the confirmed indirect write** missed by
a direct-VA scan. This demonstrates why a
zero direct-write count is not a negative
result about actual runtime initialization.

Reproduce offline:

```sh
python scripts/pe_masked_api_inventory.py Rayman2-CD-protected.exe \
  --module-base 0x4a1268 --module-stride 45 --module-count 7 \
  --api-base 0x4a141c --api-stride 76 --api-count 35 \
  --module-selector-offset 0x34 --pointer-slot-offset 0x30

# GOG: use same API descriptor layout, but plain module-name records
python scripts/pe_masked_api_inventory.py Rayman2-GOG.exe \
  --module-mode plain \
  --module-base 0x4a1268 --module-stride 45 --module-count 7 \
  --api-base 0x4a141c --api-stride 76 --api-count 35 \
  --module-selector-offset 0x34 --pointer-slot-offset 0x30

objdump -d -M intel Rayman2-CD-protected.exe > retail-disasm.txt
python scripts/descriptor_asm_xrefs.py \
  --objdump retail-disasm.txt \
  --base 0x4a141c --stride 0x4c --count 35 --slot-offset 0x30
```

These standard-library-only, **read-only** diagnostic
tools do not execute or patch the protected EXE.
They ship with **eight synthetic name decoder
tests and four synthetic xref tests**.
Locally, both original SHA-256-pinned executables
decoded to the **same 35 API names** and
**same seven module names (ignoring case)**.
The disassembly scan was reproduced on the
retail protected file, and all **12 new
synthetic tests passed**.

### Retail masked-call descriptor array: 35 active records, 76-byte stride

A new file-backed-data audit found a **regular, byte-identical
structure in both SHA-256-verified executables**:

| Property | Observed value |
|---|---|
| Base VA | `0x004A141C` in `.data` |
| Record stride | **`0x4C` bytes (76 bytes)** |
| Nonzero-initialized records | **35** (indices 0–34) |
| Following all-zero record | index **35** (`0x004A1E80`) |
| Total compared range | **36 × 76 = 2,736 bytes** |
| SHA-256 of full range in **both** files | `f4a498cafd1b76536b3367c27b5fc6142b918ecc4525cadb0c2df4c8f2951cd5` |
| First DWORD `+0x00` | nonzero and unique in each of 35 active records |
| DWORD `+0x30` | **zero for all 36 records** |
| Original-CD vs GOG | **2,736/2,736 bytes identical** |

The 35 entries followed by one all-zero record are
**consistent with an array of fixed-size descriptors plus a
sentinel-like terminator**, but the full field semantics are
not yet proven. In particular, the `+0x30` field is a
**zero-initialized location on disk**, not a demonstrated
runtime-resolved callback pointer.

The 12 masked callback-table stores in the **retail
`0x00467130` initializer** all reference record pairs with
this exact geometry:

```text
mask_or_first_field = 0x004A141C + (index * 0x4C)
other_field         = mask_or_first_field + 0x30
computed_from_file  = [other_field] XOR [mask_or_first_field]
```

Representative callback-table slots:

| Callback offset | Record index | First field VA | `+0x30` field VA |
|---|---:|---|---|
| `+0x08` | **7** | `0x004A1630` | `0x004A1660` |
| `+0x1C` | **30** | `0x004A1D04` | `0x004A1D34` |
| `+0x20` | **17** | `0x004A1928` | `0x004A1958` |

On disk, each `+0x30` value is zero, and the first
DWORD is not a valid directly callable GOG pointer. **No
runtime-resolved pointer is implied by a direct XOR of
these original file bytes.** The unchanged 2,736-byte
descriptor block also proves that **GOG did not
change this table on disk**, even though GOG modified
the callback initializer to install several literal
functions instead.

#### Explicit x86 stub construction in the retail EXE

A distinct protected-only code path at `0x0044F28C`
writes an executable-style 13-byte sequence into a
PRNG-offset scratch buffer:

```asm
A1 60 16 4A 00       ; mov eax, [0x004A1660]
33 05 30 16 4A 00    ; xor eax, [0x004A1630]
FF E0                ; jmp eax
```

The 13 bytes are **constructed at runtime**, not a
contiguous block of instructions present in the
retail EXE file. The code writes the opcode bytes
and operands separately at `0x0044F28C`–`0x0044F2A9`,
then performs indirect dispatch at `0x0044F2FA`.
Similar dynamic-stub construction appears around
`0x0044DED2` and `0x00450B42`.

This connects the regular descriptor array to actual
**masked indirect control-flow construction** in the
protected game code. The **static writer, address
calculation, module/export lookup and 1..35
initialization loop are now described above**.
However, successful runtime resolution and actual
addresses under Windows or Wine have **not** been
observed, and this is **not proof that all 35
records correspond to independent SafeDisc callbacks**.

#### Repeat the comparisons without patching either EXE

The generic read-only `pe_reference_diff.py` CLI now
accepts `--descriptor-layout BASE:STRIDE:COUNT:MASK_OFFSET:SLOT_OFFSET`
and repeatable `--masked-pair FIRST:SECOND`. It uses
file-backed PE virtual addresses, checks bounds, and
labels its results **on-disk observations only**:

```sh
python scripts/pe_reference_diff.py \
  --protected Rayman2-CD-protected.exe \
  --reference Rayman2-GOG.exe --reference-origin GOG \
  --descriptor-layout 0x4a141c:0x4c:36:0:0x30 \
  --masked-pair 0x4a1660:0x4a1630 \
  --masked-pair 0x4a1d34:0x4a1d04 \
  --masked-pair 0x4a1958:0x4a1928
```

Four additional synthetic tests check complete-record
comparisons despite differing raw PE offsets, a single
changed record, invalid/unbacked ranges and CLI JSON
safety. A separate local inspection of the owner's
actual SHA-256-pinned binaries confirms the **35+1
record structure and full 2,736-byte identity**.

### Dispatch-table linkage: GOG filename/size routines are assigned to game callbacks

A follow-up read-only **two-binary disassembly and byte comparison**
establishes a much stronger static link than literal references alone.

**At identical virtual address `0x00467130`**, both the retail-CD
protected EXE and the GOG reference implement a callback-table
initializer. **Two direct `CALL rel32` instructions to that same
initializer are byte-identical in both files**:

- `0x004674C8`: `CALL 0x00467130`, passing a stack-resident
  callback table.
- `0x0047B01B`: `CALL 0x00467130`, passing a second stack-resident
  callback table.

The **GOG initializer** stores explicit code addresses into the
table at several offsets. The two connections to the file-list
functions are particularly clear:

| Callback-table offset | GOG initializer instruction | Target |
|---|---|---|
| `+0x08` | `0x00467151: MOV EDX, 0x00448F60`, then `MOV [EAX+8], EDX` | Manifest filename lookup at `0x00448F60` |
| `+0x1C` | `0x00467160: MOV ECX, 0x00449010`, then `MOV [EAX+0x1C], ECX` | A GOG callback which invokes the size lookup |
| `+0x20` | `0x004671DF: MOV EDX, 0x00448FD0`, followed by `MOV [EAX+0x20], EDX` at `0x004671FB` | Manifest index-to-size lookup at `0x00448FD0` |

The GOG code also has `CALL 0x00448FD0` at
`0x0044905A` inside the `0x00449010` callback.

At precisely the same table slots, the retail protected
initializer obtains pointer values from XOR-masked global memory
rather than from literal function addresses:

| Offset | Retail-CD masked pointer source |
|---|---|
| `+0x08` | `[0x004A1660] XOR [0x004A1630]` |
| `+0x1C` | `[0x004A1D34] XOR [0x004A1D04]` |
| `+0x20` | `[0x004A1958] XOR [0x004A1928]` |

In the **on-disk original retail image**, the first member
of each of these pairs is **zero** and the second appears
masked/random. A direct XOR of the *on-disk* values does **not**
produce the GOG callback addresses. **This is not proof of an
incorrect file or a particular SafeDisc key**: the runtime
initialization and mutation of those global variables must
be traced before inferring the original callback targets.

#### Path-matching behavior

The GOG `0x00448F60` callback only enters the manifest
search after testing its input path has a **drive prefix**:
the two bytes at offsets 1 and 2 must be `:\` (x86
`CMP WORD PTR [ESI+1],0x5C3A`). It then skips the initial
three path bytes (`ADD ESI,3`) and compares the
remaining path against the manifest's names, converting
lowercase ASCII letters to uppercase during comparison.

The `0x00448FD0` callback traverses the entries by a
zero-based index and returns the entry's **declared size**,
or zero at the sentinel. These are **static instruction-level
observations**; no actual runtime call through the table
has been observed or claimed.

**Interpretation:** GOG does more than merely store a CD file
list: it installs path and size lookup callbacks in a shared
game-level dispatch structure. Because the two initializer
call sites are common to the protected EXE, we have a
concrete correspondence for studying original file-handling
behavior. Still, do **not** treat the GOG replacements as
pure SafeDisc deprotection, or the list as an authenticated
original-CD manifest.

#### Reproducible reference tracing

`scripts/pe_reference_diff.py` supports optional **generic**
`--trace-va` arguments. It scans executable sections for raw
x86 `E8 rel32` call patterns and `B8..BF imm32`
register-loading patterns, then reports candidate instruction
virtual addresses in both input PE files.

```sh
python scripts/pe_reference_diff.py \
  --protected "Rayman2-protected.exe" \
  --reference "Rayman2-GOG.exe" \
  --reference-origin GOG \
  --trace-va 0x467130 \
  --trace-va 0x448F60 \
  --trace-va 0x448FD0 \
  --trace-va 0x449010
```

Expected, separately inspected static candidates:

- `0x467130`: two identical `CALL rel32` sites
  `0x4674C8` and `0x47B01B` in **both** binaries.
- `0x448F60`: GOG `MOV r32,imm32` at
  `0x467151`; no direct equivalent in the protected
  bytes at that address.
- `0x448FD0`: GOG `MOV` at `0x4671DF`
  and GOG direct `CALL` at `0x44905A`;
  neither candidate occurs in the protected binary.
- `0x449010`: GOG `MOV` at `0x467160`,
  not in protected bytes.

The scanner **is not a disassembler** and must not be
used alone to assert that matched bytes are executable
instructions or reachable code. The listed sites above
were **independently checked with GNU objdump**.

### Static GOG code references to the embedded file inventory

Unlike the inert-looking byte-copy hypothesis for `.extra`,
the **GOG-modified `.text` contains two explicit x86
immediates referencing the base of `.extra2`**.
The section's RVA is `0x1B3000`, so its image-base-adjusted
virtual address is **`0x005B3000`**.

Verified by independent `objdump -D -M intel` of the SHA-256-pinned
GOG EXE and compared to the protected CD bytes at the same VAs:

| GOG instruction VA | Exact observation |
|---|---|
| `0x00448F80` | `MOV EDI, 0x005B3000` — base of `.extra2` |
| `0x00448F85`–`0x00448FBD` | Loop checks the `0xFFFFFFFF` sentinel, compares a caller-supplied path to table entry names (ASCII lowercase normalized), and advances by a record's prefixed length |
| `0x00448FD7` | `MOV ESI, 0x005B3000` — same table base |
| `0x00448FE0`–`0x00448FF5` | Second loop traverses records, selects an entry by index and reads its claimed size |
| `0x0044905A` | `CALL 0x00448FD0` — call to the size-lookup routine |

The corresponding protected retail `.text` contains **different
instructions** at these addresses (in particular obfuscated
PRNG/control-flow code), so these two manifest readers are
**GOG-reference-specific static modifications**. This establishes
a concrete intended **file-path and file-size lookup** use for the
`.extra2` table in GOG's code. It does **not** prove whether those
functions are reached at runtime, whether a particular file is
emulated, or why GOG chose the declared values. In particular,
it does not authenticate the 3,716 records as the true original
physical CD file inventory.

Separately, the GOG `.text` has two literal VA operands
referring to `.extra`'s base `0x00517000`
(at `0x00470052` and `0x0047B1C4`). The first corresponds to
`MOV EAX, 0x00517000` at `0x00470051`. Their role must be
traced; **the fact that the protected `.text` is preserved in
`.extra` does not mean it is executed there**.

The generic comparator now lists byte-pattern occurrences of the
absolute base VAs of *reference-only* PE sections inside
executable-designated sections. Such matches are labeled
**literal candidates**, not automatically decoded x86 instructions.
One synthetic regression test validates the bounded reference mapping
and its absence when the bytes are not present.

### Exact extent of GOG `.extra2` inventory

The entire `143,360` backed bytes of GOG `.extra2` consist
of **139,366 bytes of 3,716 length-prefixed records**, followed by
the **8-byte termination sentinel** `FF FF FF FF 00 00 00 00`,
followed by **3,986 bytes of zeros**. There are no additional
nonzero bytes after the manifest terminator within this section.

The read-only parser now reports `bytes_after_sentinel` and
`remaining_bytes_all_zero` independently of the claimed file sizes.
This is evidence about the actual **GOG section contents**,
not a certificate that this table came from the original CD or that
its 7.45 GB of claimed sizes were physically present.

### Embedded file inventory inside `.extra2`

The first part of the GOG reference's `.extra2` has a reproducible,
length-prefixed sequence of **3,716 distinct filenames**:

```text
<u32 claimed_file_size><u32 name_length><name_bytes_including_NUL>
...
<u32 0xFFFFFFFF><u32 0>       # end marker
```

The table occupies **139,366 bytes** before the end marker and
is followed by ordinary section padding. Some directly verified
entries:

| Manifest path | Manifest claim | Owner's original file |
|---|---:|---|
| `RAYMAN2.EXE` | 676,352 bytes | protected EXE: 676,352 |
| `RAYMAN2.ICD` | 683,565 bytes | supplied ICD: 683,565 |
| `DPLAYERX.DLL` | 165,888 bytes | supplied DLL: 165,888 |
| `SECDRV.SYS` | 14,368 bytes | no separate source file checked |

The table names **`DPLAYERX.DLL`**, not
`DXPLAYERX.DLL` (the latter spelling appeared in an earlier
Rayman2Fix exclusion list). This is useful evidence for auditing
the original file layout, but the two names must still not be
silently equated.

**The sum of all 3,716 *declared* sizes is 7,453,062,614 bytes
(7.45 GB)**, far more than the physical Rayman 2 CD image.
Many individual data files declare hundreds of megabytes.
Those totals are **not actual byte extents to extract**, and
are consistent with the prior observation of fake/oversized CD
entries designed to complicate direct copying. The precise
origin and function of the manifest itself remain to be proven.
Do not allocate 7.45 GB or attempt to extract the listed sizes.

### Reproducibility and validation

A new **generic** standard-library-only tool
[`scripts/pe_reference_diff.py`](../scripts/pe_reference_diff.py)
compares shared sections at matched RVAs, requires bounded PE32
headers/section tables, prints JSON metadata only, and optionally
scans such a length-prefixed manifest (no file extraction):

```sh
python scripts/pe_reference_diff.py \
  --protected "Rayman2-protected.exe" \
  --reference "Rayman2-GOG.exe" \
  --manifest-section .extra2 \
  --focus-name RAYMAN2.EXE \
  --focus-name RAYMAN2.ICD \
  --focus-name DPLAYERX.DLL
python -m unittest discover -s scripts -p 'test_pe_reference_diff.py'
```

The first command does **not** write a patched EXE, copy protected
data, or claim a decrypted result. The CLI refuses self-comparison
to avoid a misleading independent-provenance claim.
**Nine synthetic Python tests pass locally** on the independent
working copy: section file-offset shifts, exact changed RVA, extra
sections, parser bounds, corrupted manifest entries, self-comparison,
and read-only JSON output. Native Rust tests remain uncompiled due
to absent Rust toolchain; the existing Crimson Skies unwrap code
was not modified.

## Verified breakthrough — BOTH uploaded opaque files are exact masked-MINSTD streams

**2026-11-12 correction:** Earlier research incorrectly interpreted the ICD as
big-endian words starting at byte zero. Scanning all **four offsets and both
endiannesses** exposes the only valid whole-stream alignment: the ICD's
actual 31-bit words start **after one leading byte**, in **little-endian**.

Both user-supplied files satisfy the **identical** masked Park–Miller recurrence:

```text
next = 16807 * (current XOR 0x075BD924) mod 2147483647
```

| Exact sample | Leading bytes | First 31-bit word | Words | Exact transitions |
|---|---|---|---:|---:|
| `RAYMAN2.ICD` | `5B` (1 byte) | `0x6EE4C08A` | 170,891 | **170,890 / 170,890** |
| `dplayerx.dll` | none | `0x0030FBEC` | 41,472 | **41,471 / 41,471** |

With the one-byte ICD prefix preserved, independently regenerating **all
683,565 ICD bytes** from its first word and the recurrence produces an
**identical SHA-256**:
`4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6`.
The corresponding full 165,888-byte DLL regeneration also matches
`0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee`.
Both are exact **byte-for-byte** verifications; no game bytes are stored.

Each supplied file is fully specified by a short prefix (if present),
one 31-bit seed, the common constant, and its length. Such a stream
cannot represent an **arbitrary independently encoded PE executable or
DLL payload** without additional information. This strongly suggests
synthetic filler or another protection-related PRNG artifact, but its
actual role/origin on the CD remains unverified. This **does not**
establish that a separately installed ICD is absent or that the genuine
game cannot be restored from other user-owned files.

**Reproduce using the read-only Python tool, without writing outputs:**

```sh
python scripts/safedisc_prng_recurrence.py RAYMAN2.ICD --auto-align
python scripts/safedisc_prng_recurrence.py dplayerx.dll --auto-align
# or explicitly: --endian little --offset 1 (ICD), --offset 0 (DLL)
python -m unittest discover -s scripts -p 'test_*.py'
```

The Rust inspector now scans all **eight** word-layout candidates, but this
new Rust code is **not yet compiled or tested**. The corresponding
Python auto-alignment implementation passed eight synthetic tests and
both genuine-sample SHA-256 regeneration checks locally.

**Supersession:** Earlier claims that the ICD did not follow masked
MINSTD, that its final byte `0x29` was an unaligned tail, or that
big-endian offset-zero words represented its native encoding are
**incorrect**. At offset +1 the last byte belongs to the **last
little-endian word**, and every ICD transition matches.
Earlier negative generator tests using the wrong word alignment are
not evidence about the correct stream.



The user reports that [Redump disc 47594](https://redump.org/disc/47594/)
identifies the disc as SafeDisc **1.35.000**. Independently, a
[Wine bug report from 24 December 2009](https://list.winehq.org/hyperkitty/list/wine-bugs%40list.winehq.org/thread/PBMSSMOUG42FC3AE5YDT7WPIEDJIBKC5/)
is titled **"SafeDisc v1.35.000 and Rayman 2"**, corroborating that
this protection version was used for *a* Rayman 2 PC edition. That
does **not** authenticate the exact protected files supplied here.
The tool does not infer a SafeDisc version from a filename, file
size or entropy.

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

## Independent static profile of these inputs (2026-11-12)

The following observations were obtained on the original user-supplied files
without loading or executing them (Python standard library, `file`,
`objdump -x`, `objdump -d`).

| Property | `Rayman2.exe` |
|---|---|
| DOS/NT headers | `MZ` at file offset `0x0`; `PE\\0\\0` at `0xB8` |
| PE machine / format | i386 / PE32, GUI |
| Image base | `0x00400000` |
| Entry-point RVA | `0x0005FCC0` |
| Reported PE timestamp | 1999-10-15 23:19:39 UTC (header value; not provenance proof) |
| Sections | `.text`, `.rdata`, `.data` |
| Import DLLs | `USER32.dll`, `GDI32.dll`, `WINMM.dll`, `MSVCRT.dll`, `KERNEL32.dll`, `SHELL32.dll`, `DINPUT.dll` |
| Export directory | Claims `MainWinf.exe`, 110 exported ordinals |
| `CRPE\\0\\0` signature | Not found in this loader |
| `DPLAYERX` plaintext string | Not found in this loader |

The `CRPE` marker used in the *separate* Crimson Skies SafeDisc 1.50.20
research is therefore **not portable as an assumed key-lookup location**.
No hard-coded replacement offset should be invented for 1.35.

The `MZ` and `PE\\0\\0` byte patterns also appear inside the executable
`.text` as x86 instruction operands in code which appears to validate
mapped PE headers and inspect `KERNEL32`. These matches are **not**
additional embedded PE images. This routine is a candidate for further
static cross-reference analysis, not proof of a particular SafeDisc stage.

Measured per-file whole-byte Shannon entropy:

| File | Entropy (bits/byte) | First 16 bytes |
|---|---:|---|
| `Rayman2.exe` | 6.627897 | `4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00` |
| `RAYMAN2.ICD` | 7.953942 | `5B 8A C0 E4 6E BF 24 2F 01 6C CE B5 6A 5A B0 3A` |
| `dplayerx.dll` | 7.952524 | `EC FB 30 00 46 7C B8 0A 0D CC 7E 5C 7E 65 90 5F` |

For equal-length 4 KiB blocks (discarding the final incomplete block),
the entropy profiles are:

| Opaque file | Full 4 KiB blocks | Min. block entropy | Max. block entropy |
|---|---:|---:|---:|
| `RAYMAN2.ICD` | 166 | 7.893266 | 7.927141 |
| `dplayerx.dll` | 40 | 7.894593 | 7.917976 |

No low-entropy 4 KiB region stands out in either file. This does
**not** distinguish encryption from compression or establish cipher
boundaries. The new `--generic-inspect --layout` report prints this
profile for any sufficiently large input.

The ICD is `0xA6E2D` bytes long (not a round PE alignment size),
and the opaque DLL is `0x28800` bytes long. Neither begins with `MZ`
or contains a `PE\\0\\0` signature. A plain `dplayerx.dll` import
is **not present in the static import table** of the loader; this
does not rule out dynamic loading.

**Important:** `Rayman2.exe` has an extensive, genuine PE code,
import and export structure; describing it as “only an encrypted stub”
would go beyond these findings. Its actual protected launch sequence
must be traced before planning a decoder.

### Candidate protected-loader cross-reference (unconfirmed)

At image VA `0x00447C0C`, the executable compares an in-memory DOS
signature to `0x5A4D` (`MZ`), and at `0x00447C18` compares the PE
signature to `0x00004550` (`PE\\0\\0`). It then tests bytes
matching `KERNEL32.DLL` (case folding). At `0x00447D47`, a nearby
routine reads `FS:[0x30]` (Windows process environment block).
These locations are **research leads only**, and may belong to game
runtime code rather than SafeDisc. No key or protected payload boundary
is derived from them.

### Reproducibility

On a system with GNU binutils:

```sh
sha256sum Rayman2.exe RAYMAN2.ICD dplayerx.dll
file Rayman2.exe RAYMAN2.ICD dplayerx.dll
objdump -x Rayman2.exe
objdump -d -M intel --start-address=0x447BE0 --stop-address=0x447E20 Rayman2.exe
```

`objdump` emits the executable's image-base addresses rather than
raw file offsets. The `--start-address` range above is for preliminary
static code inspection, not an exploit or validated key schedule.

## Additional validation: accidental signatures are not PE files

A bounded read-only scan was performed on each owner-supplied input. Every
`MZ` sequence was checked as a possible start of a **structurally valid
x86 PE32** with a DOS header pointer, PE signature, bounded optional header
and section table. Merely counting `MZ` in high-entropy bytes is misleading.

| File | `MZ` occurrences anywhere | Structurally valid PE32 candidates | Candidate offsets |
|---|---:|---:|---|
| `Rayman2.exe` | 2 | 1 | `0x0` |
| `RAYMAN2.ICD` | 16 | 0 | none |
| `dplayerx.dll` | 4 | 0 | none |

The extra `MZ` match in the EXE occurs within executable instructions, not
a second embedded image. None of the 20 `MZ` matches in the opaque inputs
passes PE32 structural checks. This is **not** evidence that decrypted PE
code is absent; the expected protected ICD is not meant to be a plain PE.

The generic Rust inspector now displays these two distinct counts with
`--layout`. It also **rejects a corrupt/non-PE loader** instead of silently
calling it an opaque successful inspection; only ICD and companion DLL
inputs are allowed to lack a PE header. These are read-only diagnostics
with synthetic tests; compilation and execution of the new Rust code
remain pending.

## Historical variant clue from original SafeDisc documentation

[CD Media World, *SafeDisc protection/version reference*]
(https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc.shtml)
catalogues a **165,888-byte `DPLAYERX.DLL`** as an early **r2**
family and **138,752 bytes** as a later **r4** family. Our Rayman 2
sample is 165,888 bytes while the previously validated Crimson Skies
sample is 138,752 bytes. This suggests **different protection families**
and a reason not to reuse the Crimson-specific loader/DLL assumptions.

This is a historical third-party classification based on **DLL size**,
not authenticated version metadata: it does **not** independently verify
SafeDisc `1.35.000` or prove that all files of equal size share a
decryption algorithm. The observed file size should be stored as
descriptive data, **not** used as an authorization to decrypt.

In particular, the Rayman 2 EXE contains a normal PE32 import table,
a `MainWinf.exe` export-name field with 110 exported ordinals, and
game-related strings (including `Please insert the CD`). Its entry
RVA `0x5FCC0` begins with what looks like C runtime initialization
rather than an obviously isolated SafeDisc entry stub. This is
important counterevidence against treating the entire EXE as a
recognizable dedicated SafeDisc loader without further trace analysis.
The relationship between this PE and the encrypted ICD is **not yet
established**.

## Independent reproducible research probe (Python 3)

The repository includes `scripts/safedisc_v1_probe.py`. It is a separate
**read-only, standard-library-only** verifier of the PE32/magic/entropy
observations, not a decryptor or SafeDisc recognizer. It requires the
user's own files; none are bundled:

```sh
python scripts/safedisc_v1_probe.py \
  --loader Rayman2.exe \
  --icd RAYMAN2.ICD \
  --dplayerx dplayerx.dll
python -m unittest discover -s scripts -p 'test_safedisc_v1_probe.py'
```

The first command prints machine-readable JSON to standard output;
it does not write any output file. It records explicit
`decryption_attempted: false` and `safedisc_version_asserted: false`
rather than suggesting a successful unwrap.

**Offline validation:** all seven synthetic Python unit tests passed
locally, and the standalone probe was executed against the original
user-supplied Rayman 2 files with the expected three SHA-256 signatures,
2/16/4 total `MZ` occurrences and 1/0/0 structurally valid PE
candidates. The pre-change Rust binary was also run against those files:
it reached the ICD and failed with `ERROR: not an MZ executable`, as
expected. The **new** Rust implementation has *not* been compiled or
executed yet because no Rust compiler is available in the working
container, and GitHub Actions billing is exhausted.

## Read-only IAT cross-reference map (2026-11-12)

A second standard-library-only tool, `scripts/pe_import_xrefs.py`, parses
the original **loader EXE's** bounded x86 PE32 import directory and looks
for the byte-level x86 opcode patterns `FF 15 <IAT VA>` (indirect
`CALL`) and `FF 25 <IAT VA>` (indirect `JMP`) in executable sections.
It does **not** execute any input, attempt decryption, or claim the
patterns are reachable instructions. Seven additional **synthetic**
unit tests validate PE header and import-bound checks.

Results on the owner's SHA-256-verified `Rayman2.exe`:

- **163 imported API entries** across **7 DLLs**:
  `DINPUT.dll`, `GDI32.dll`, `KERNEL32.dll`, `MSVCRT.dll`,
  `SHELL32.dll`, `USER32.dll`, `WINMM.dll`.
- **424 direct IAT CALL/JMP byte-pattern candidates**, across
  **154 import targets**. These are candidate static references, not a
  full executable call graph.

| Imported Win32 function | IAT VA | Candidate direct-call VAs |
|---|---|---|
| `CreateFileA` | `0x0049C058` | `0x00450C16`, `0x0045486F` |
| `ReadFile` | `0x0049C04C` | `0x0044CFB7`, `0x0044D5F7`, `0x0044F897`, `0x004510AE`, `0x004512DA`, `0x0045497F` |
| `GetFileSize` | `0x0049C040` | `0x00454847` |
| `LoadLibraryA` | `0x0049C084` | `0x00421889`, `0x0045894F`, `0x00458B1E`, `0x004590EE`, `0x00459323` |
| `GetProcAddress` | `0x0049C088` | `0x00455D29`, `0x00458A02` |

```sh
python scripts/pe_import_xrefs.py Rayman2.exe > import-xrefs.json
python -m unittest discover -s scripts -p 'test_pe_import_xrefs.py'
```

**Follow-up candidates:** `CreateFileA` appears at `0x450C16`
in a routine which also contains indirect calls through computed
function pointers and writes pseudorandom-looking bytes into a buffer;
another direct file-open pattern occurs at `0x45486F`. At
`0x44EC50` and `0x44F18C`, code references a
`CDROM not found!` string (VA `0x4A2270`) near file-open
handling. These routines must be traced using valid instruction boundaries
before claiming they implement CD checking or a SafeDisc stage.
The executable entry VA `0x45FCC0` begins with an ordinary-looking
SEH/C-runtime prologue; neither this nor file I/O proves that this
EXE is only a protected stub. A full call graph and ICD decoding
remain **unsolved**.

## Historical unSafeDisc 1.5.5 branch condition: important new lead

Existing primary research in
[`docs/unsafedisc-linux.md`](unsafedisc-linux.md)
records disassembly of the user's original historical 20,480-byte
`unSafedisc.exe`, rather than guessing from the separate 18,944-byte
modified public release.

At `0x401F43..0x401F62`, the historical implementation performs an
**extra pre-TEA processing step if the supplied `dplayerx.dll` is
exactly `0x21E00` bytes (138,752)**. This applies to the Crimson Skies
reference, but **not** to the Rayman 2 DLL of `0x28800` bytes
(165,888). The implementation also has a generic 32-round TEA-like
decryption stage at `0x401A55`, subject to other prerequisites.

This is a **specific branch condition in a particular historical tool**,
not an attestation that Rayman 2's ICD follows the same TEA geometry,
that the needed key is known, or that running the old tool would work.
The visible Rayman ICD does not have a PE header, so header restoration
and correct loader/DLL key derivation must be established first.
Do not substitute the Crimson Skies F1/F2 modifier or its fixed keys.

Research priority: reconstruct the **early-family loader -> DLL ->
ICD** data path and its header-handling stage, using read-only static
evidence. The branch above suggests that a universal 1.x implementation
should **identify its applicable algorithmic path**, not merely
rename hard-coded Crimson Skies constants.

## Strong four-byte lane constraint (2026-11-12)

An independent whole-file scan of the owner's exact SHA-256-verified Rayman 2
inputs discovered a previously unrecognized **bit-level invariant**. Using
nonoverlapping groups of four bytes from file offset zero:

| Input | Complete groups | High-bit=1 counts, lanes 0/1/2/3 | Leftover bytes |
|---|---:|---|---:|
| \`Rayman2.exe\` | 169,088 | 73,986 / 74,194 / 71,483 / 71,432 | 0 |
| \`RAYMAN2.ICD\` | **170,891** | **0** / 85,432 / 85,193 / 85,523 | **1** |
| \`dplayerx.dll\` | **41,472** | 20,636 / 20,735 / 20,654 / **0** | 0 |

Every single ICD byte at offsets \`0, 4, 8, ...\` is below \`0x80\`;
the other three lanes use all eight bits. Every single companion DLL
byte at offsets \`3, 7, 11, ...\` is below \`0x80\`; its other lanes
use all eight bits. The byte at the end of the ICD is \`0x29\`; under the **correct offset +1** word layout it is part of the last word, **not** an extra trailing byte.

**Corrected interpretation:** the high-bit-lane count by itself is
**ambiguous**. A clear lane 0 at file offset zero fits either a
big-endian word starting at zero **or** a little-endian word starting at
offset one. The full mathematical recurrence and exact regeneration
identify the second interpretation for the ICD. The DLL uses
little-endian words starting at zero.

The earlier statement that the files had **three shared 31-bit values**
used *incorrectly aligned* ICD words; it is withdrawn. Comparing the
correctly aligned streams gives **no common words** between all
170,891 ICD states and all 41,472 DLL states. The words within each
file are also distinct. Neither file is the other's immediately
following segment: the successor of the ICD's last state is
`0x11F38C41` (not the DLL seed `0x0030FBEC`), while the successor
of the DLL's last state is `0x1D99DDE9` (not the ICD seed
`0x6EE4C08A`). These are bounded **observations**, not proof
that the generator seeds are unrelated globally.

The full-file PRNG demonstration at the beginning of this document
supersedes weaker entropy and speculative cipher classifications.

**Reproduce without executing a protected binary:**

\`\`\`sh
python scripts/safedisc_v1_probe.py \
  --loader Rayman2.exe --icd RAYMAN2.ICD --dplayerx dplayerx.dll
python -m unittest discover -s scripts -p 'test_safedisc_v1_probe.py'
\`\`\`

The JSON \`four_byte_lanes\` member reports the group count, ignored
tail, per-lane high-bit counts, and a cautious representation hint.
The Rust \`inspect --generic-inspect --layout\` report now contains
the corresponding read-only high-bit counts. Synthetic tests cover
opposite byte orders, lone high-bit bit-flips and partial tails.
The new Rust code still requires compilation validation; no protected
file is distributed.

**Next decoding research:** determine how the 31-bit restrictions arise
from the historic SafeDisc 1.x loader and DLL processing stages. Do not
discard the bit or blindly reinterpret words as compressed PE code.

## Historical algorithm boundary: SafeDisc 1.30 to 1.50

A contemporary June 2001 technical study,
[*An overview of SafeDisc versions* by ArthaXerXès]
(https://gbppr.net/cracking/krobar/other/com26.html), reports the following
implementation changes:

- **1.30.0**: import RVAs are XOR-encoded using one 32-bit TEA key word;
  the original 128-bit TEA key still consists of **four identical words**.
  The described loader search targets a literal \`00 00 00 00\` DWORD
  followed by \`A, A, B, B\` DWORD pairs.
- **1.40.4**: an additional callsite repair stage changes selected
  x86 \`FF 15\` references using version-specific arithmetic.
- **1.45.11**: repeated-key weakness was eliminated; per-title
  DPLAYERX EAX modification appeared.
- **1.50.20**: added a separate pre-decryption layer involving DPLAYERX
  routines, which is the extra stage already investigated for Crimson Skies.

**If the owner's Rayman 2 version is indeed 1.35.000**, it lies
between the first two changes, suggesting an early repeated-key TEA
path *may* apply. This exact-version link is **not verified directly**
from the opaque ICD and therefore cannot yet enable any decoder.

A read-only search for the **literal contiguous**
\`0, A, A, B, B\` 32-bit sequence (with nonzero, distinct A and B)
in the user's **676,352-byte Rayman2.exe**, across all four byte
alignments, returned **zero candidates**. Neither \`DECRPE\\0\\0\`
nor \`CRPE\\0\\0\` occurs in that executable. These negative
findings invalidate a naive re-use of the historical loader-pattern
heuristic on this input; they do not disprove TEA, an alternate key
location or the user's SafeDisc version claim.

Further work must first validate the file-pair relationship and
reconstruct a trustworthy PE/header stage before inferring an import
table or deriving a TEA key. No game binary, DLL, decrypted output
or proprietary component is copied into the repository.

## File-format interpretation and optional provenance comparison

A SafeDisc 1 protected CD normally contains an `EXE` loader paired
with a game `ICD` containing **encrypted executable content**
([CD Media World, SafeDisc v1](https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc.shtml)).
Therefore **absence of a readable `MZ`/PE32 header at offset zero
inside the on-disc ICD is not a corruption indicator, not evidence of
an incorrect file, and not a reason to halt read-only cipher research**.

The supplied files have these **descriptive** properties:

| Component | File-header observation | Interpretation |
|---|---|---|
| `Rayman2.exe` | valid x86 PE32, `.text/.rdata/.data` | Known protected retail EXE SHA-256, corroborated by Rayman2Fix |
| `RAYMAN2.ICD` | no plain PE32 at offset zero | Consistent with an encrypted payload; no direct `CreateProcess` use is claimed for raw on-disc bytes |
| `dplayerx.dll` | no plain PE32 at offset zero | May require SafeDisc-specific transformation before standard DLL loading; stage unverified |

A [historical Wine developer description (April 2002)]
(https://www.winehq.org/pipermail/wine-devel/2002-April/005861.html)
mentions `.txt`/`.txt2` loader sections and a decoding/loading
sequence, but this was **one implementation example**, not a universal
header/section requirement for all SafeDisc 1.35 games. Its differences
from Rayman 2 do not establish wrong or corrupt input.

The files also exhibit a repeatable 31-bit word-lane constraint; that
is **strong evidence of structured encoding**, but does not establish
the compression/encryption format, authenticity, or decoding key.

To check file provenance **independently** and avoid mixing different
original retail editions, the optional
[`compare_safedisc_stages.py`](../scripts/compare_safedisc_stages.py)
tool compares root-level file names, sizes and SHA-256 between the
owner's disc image and an unmodified original installation. Its results
must not be interpreted as an authenticity certificate.

**Research may proceed offline on the hash-identified encrypted inputs**
without waiting for a second copy of the same files; a CD-vs-install
comparison is a complementary verification, not a prerequisite for
investigating their 31-bit encoding or the SafeDisc 1.35 algorithm.
Do not commit, redistribute, or execute proprietary protected payloads.

## Cross-check against the separate Rayman2Fix repository

The owner's separate `legluondunet/Rayman2Fix` source
[`docs/architecture.md`](https://github.com/legluondunet/Rayman2Fix/blob/main/docs/architecture.md)
records the expected SHA-256 of its **protected retail Rayman 2 EXE**
as `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
This matches our exact uploaded `Rayman2.exe` hash. A separate
SHA-256-pinned *unprotected* executable is used for actual launch by
Rayman2Fix. Thus, this sample's protected-EXE identity is
**corroborated by the owner's own independent project**, even though
the provenance of its paired ICD/DLL still requires verification.

The Rayman2Fix CD extraction documentation explicitly warns that
**raw ISO extraction is not necessarily equivalent to installed game
files**, including possible transformation of content by the
original installer. The project's root-exclusion list includes a
file named **`dxplayerx.dll`**, whereas the uploaded research
sample is named **`dplayerx.dll`**. These two spellings differ
(the former has an additional `x` immediately after `d`).
We must **not silently equate them**: inspect the original CD file
listing and the actual installation receipt before deciding
whether the supplied 165,888-byte sample is the intended SafeDisc
auxiliary file. File extension and user-visible name alone are
insufficient provenance evidence.

The current evidence supports analyzing the known protected
`Rayman2.exe` as genuine. It does **not** support treating the
non-PE `RAYMAN2.ICD` and `dplayerx.dll` as directly loadable
Windows binaries, or asserting they are bad/corrupt without
checking the physical CD and installation stages.

## Reproducible original-CD vs original-installation comparison

A new cross-platform, standard-library-only, read-only helper,
[`scripts/compare_safedisc_stages.py`](../scripts/compare_safedisc_stages.py),
tests the most important unresolved hypothesis: **whether the original
installer transforms or substitutes the ICD and companion DLL**.

Keep separate directories containing (1) the files extracted from the
original CD and (2) the files copied from the **unmodified original
game installation**, before any Rayman2Fix patching. The directories
may be on Linux or Windows, and this diagnostic does not require
Wine, the game's EXE to be runnable, or a mounted CD at inspection time.

```sh
python scripts/compare_safedisc_stages.py \
  --cd-root "/path/to/original-CD-root" \
  --installed-root "/path/to/original-install-folder"
python -m unittest discover -s scripts -p 'test_compare_safedisc_stages.py'
```

The JSON output reports root-level `rayman2.exe`, `rayman2.icd`,
`dplayerx.dll`, and `dxplayerx.dll` **separately**. For each file,
the result is `identical`, `different`, `cd_only`,
`installed_only`, or `absent_both`, with any present file's actual
name, size and SHA-256. An `alias_discrepancy`-style flag highlights
the distinct DLL spellings, **without treating them as interchangeable**.
No original files or proprietary data are copied into the repository
or changed. Nine synthetic local regression tests pass.

**Interpretation constraints:**

- Two matching SHA-256 hashes establish equality between the *two
  user-supplied roots*, not that either root is a genuine CD copy.
- Missing original-install files may be installer-only media auxiliaries:
  they are not automatically corrupt.
- A `different` result establishes a transformation or version
  mismatch, but does not reveal how it occurred.
- This tool checks only the specified root directories; it does not
  recursively inspect a disc/installation or reconstruct the original
  installer. Directory contents should first be obtained from the
  owner's authentic, same-edition installation.

### Primary-source version clue

A [2002 SafeDisc FAQ by a Wine developer]
(https://www.winehq.org/pipermail/wine-devel/2002-April/005861.html)
associates a **165,888-byte `dplayerx.dll`** with SafeDisc 1.35.0.
The owner-supplied Rayman 2 file has exactly this size, but is
**demonstrably a deterministic PRNG byte stream, not a loadable DLL**.
Its size should therefore **not** be treated as independent proof of
this exact file's version or authenticity. A separate Wine report
links a Rayman 2 edition to SafeDisc 1.35.000.

### Earlier negative generator checks (wrong ICD alignment; superseded)

These were performed on the initial big-endian offset-zero ICD word
layout, now known to be **incorrect** for the PRNG stream. They do not
refute masked MINSTD at offset +1 in little-endian order.


For both 31-bit word streams (big-endian ICD and little-endian DLL),
read-only numerical tests found no support for:

- The classic **glibc `random()` additive recurrence** with lags
  3 and 31 (output (x_i) must equal the two lagged outputs plus
  a 0-or-1 carry modulo (2^{31})); first 15,000 eligible values
  fail immediately in both files.
- A single affine recurrence `x[n+1] = a*x[n]+c (mod 2^31)`
  throughout the stream. The first three words may suggest a
  candidate when a difference is odd, but it does not reproduce
  subsequent values; a simple LCG is not established.

These *negative controls* only reject those specific generator
models; they do not show the content is encrypted, random, or fake.
These older, alignment-dependent negative results are superseded
by the exact two-file masked-MINSTD reconstruction.

## Corrected version-marker interpretation: `BoG_` belongs to SafeDisc 2+

The `BoG_ *90.0&!!  Yy>` signature is documented as a **SafeDisc 2**
version marker, notably by
[CD Media World — SafeDisc v2](https://www.cdmediaworld.com/hardware/cdrom/cd_protections_safedisc_v2.shtml)
and [Gravure-News (2004)](https://www.gravure-news.com/article/identification-manuelle-des-protections-2-2.php).
It is **not an appropriate version gate for SafeDisc 1.35**.
Earlier research notes incorrectly treated it as a generic
SafeDisc 1 wrapper marker; this section supersedes those notes.

The literal `BoG_` prefix and its longer 20-byte sequence were absent
from all three supplied Rayman 2 files, as previously measured.
**That absence is expected for this SafeDisc 1 investigation and
should not be cited as evidence of a malformed, wrong-version or
transformed file.** It does not distinguish original CD bytes from
installed bytes, and cannot be used to determine this edition's
version. Do not add `BoG_` as a required signature for the 1.35
decoder or inspector.

## Breakthrough: full DPLAYERX byte stream is a deterministic PRNG (2026-11-12)

**Verified against the owner-supplied 165,888-byte `dplayerx.dll`**
(SHA-256 `0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee`).
Interpret its content as 41,472 little-endian, nonnegative 31-bit words.
Let `x[0] = 0x0030FBEC`. The **entire file** satisfies:

```text
x[i + 1] = (16807 * (x[i] XOR 0x075BD924)) mod 2147483647
```

All **41,471 of 41,471** adjacent transitions match, with **zero
exceptions**. Regenerating the 165,888 bytes *entirely from this first
word plus the fixed XOR/multiplier/modulus* produced an **exact
byte-for-byte copy** in memory with the original SHA-256. No real
protected game bytes are included in the repository.

This is not an arbitrary fitted one-step equation: the XOR constant
`0x075BD924` and the classic Park–Miller constants `16807` and
`0x7FFFFFFF` appear directly in **the supplied protected
`Rayman2.exe` executable code**, including x86 instructions around
image VA **`0x00450C5A` to `0x00450CA3`**. That routine applies
an XOR to a stored state, multiplies by `0x41A7`, reduces modulo
`0x7FFFFFFF`, and stores the result. Its immediate callers and
its relationship to on-disc file creation are not yet established.

**Consequence:** these particular bytes of `dplayerx.dll` are
entirely determined by the PRNG seed and public generator constants;
they cannot additionally encode an arbitrary unknown 165,888-byte
Windows PE/DLL payload without other information. This is strong
evidence of **synthetic/pseudorandom content**, not a conventional
encrypted PE. Whether this file is deliberate disc filler, a
protection auxiliary, or a substituted extraction-stage component
is **not yet established**. The filename and matching historic
DLL size are not sufficient to assign a functional DLL role.

**Corrected ICD result:** The old big-endian offset-zero test
returned only one forced transition because it used a **wrong word
alignment**. With one prefix byte and little-endian words, the ICD
matches **170,890 of 170,890 transitions**, and its full byte content
regenerates exactly. This proves the uploaded ICD bytes are a
deterministic PRNG stream; it does **not** reconstruct a commercial PE.

### Reproduce this result without running DRM code

```sh
python scripts/safedisc_prng_recurrence.py dplayerx.dll --auto-align
python scripts/safedisc_prng_recurrence.py RAYMAN2.ICD --auto-align
python -m unittest discover -s scripts -p 'test_safedisc_prng_recurrence.py'
```

The Rust `inspect --generic-inspect --layout` diagnostic also now
checks this full masked-MINSTD recurrence in all four offsets and
both byte orders. It
reports a **verified match only when at least 256 complete words**
satisfy **every** transition, including the independently derived
XOR salt. Two additional synthetic Rust tests cover a 512-word
little-endian positive case, one-bit corruption, wrong byte order,
minimum sample length, and explicit **rejection of partial
trailing bytes** as a claim of complete-file reconstruction. This
new Rust branch is **not yet compiled**, so those tests are pending
Rust toolchain availability.

The read-only script derives a **candidate** constant from the first
two words via the modular inverse of 16807 and validates **every**
following word. It never writes files. Six synthetic tests check
positive little/big-endian streams, wrong byte order, bit-flip
negative controls, arbitrary opaque input, and input validation.

This finding now applies to **both supplied files**, not just
`dplayerx.dll`. Neither byte stream contains an arbitrary independently
encoded Windows PE without another source of information. Research
should locate/verify the genuine installed game data, compare the
protected/unprotected EXEs already held privately by the owner, and
study the role of these synthetic files. Do **not** attempt to decrypt
these particular PRNG bytes as if they contained executable code.

## Static call-path lead: PRNG-based x86 trampoline (2026-11-13)

Independently disassembled the exact **protected** `Rayman2.exe`
(SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`)
with GNU binutils, without executing it:

```sh
objdump -d -M intel --start-address=0x450C5A \
  --stop-address=0x450D03 Rayman2.exe
```

Key x86 instructions from the protected EXE's `.text`:

| VA | Observation |
|---|---|
| `0x450C5A` | Load PRNG state from `0x510BF0` |
| `0x450C65` | XOR state with `0x075BD924` |
| `0x450C70` | Multiply by `0x41A7` (16807) |
| `0x450CA9` | Signed division by `0x455` to select an offset |
| `0x450CAD` | Add buffer base `0x510EA0` to offset register |
| `0x450CB3` | Store opcode `68` (`PUSH imm32`) in that buffer |
| `0x450CC2` | Store opcode `C3` (`RET`) five bytes later |
| `0x450CC8` | Store the 32-bit immediate after `PUSH` |
| `0x450CF6` | Indirect `CALL ESI` to the constructed stub |

The sequence creates and calls a six-byte **`PUSH immediate; RET`**
trampoline, plausibly for runtime control-flow obfuscation. In other
words, the generator is used in at least one executable-code
construction path; **we have not established a call path which writes
either of the observed ICD/DLL files**. Do not conflate the
mathematically established stream encoding with the unproven
on-disc-file producer.

Separately, [PCGamingWiki's Rayman 2 entry]
(https://www.pcgamingwiki.com/wiki/Rayman_2) records that the
retail release contains **dummy/junk files** in addition to SafeDisc.
This strengthens the *possible* interpretation of these two
completely reproducible streams as protection-related filler, but
does **not** authenticate their specific disc roles.

**Bounded stream comparison:** the correct offset+1 little-endian
ICD stream has **170,891 unique states**; the offset+0 little-endian
DLL stream has **41,472 unique states**, and their observed sets
have **zero overlap**. The next state after the ICD's last is
`0x11F38C41`, not the DLL seed `0x0030FBEC`; the next state after
the DLL's last is `0x1D99DDE9`, not the ICD seed `0x6EE4C08A`.
This excludes immediate concatenation or overlap **in the observed
ranges** only; it is not a general proof that the seeds are unrelated.

## Protected EXE file-I/O and obfuscated indirect calls

Further offline static audit of the original hash-identified
`Rayman2.exe` (`objdump -d -M intel`):

- **73** disassembled `XOR reg,0x075BD924` immediate instructions
  occur in the executable (raw disassembly matches, not a count of
  dynamically reachable functions). This is substantial evidence that
  the masked PRNG is a **reused runtime mechanism**, not solely a
  single CD-file-generation helper.
- At `0x450A80`–`0x450C32`, an apparent file-open wrapper uses the
  PRNG to select an offset within a buffer at `0x510EA0`. It writes
  a short executable stub and invokes it indirectly. A separate
  branch invokes the imported **`CreateFileA` at `0x450C16`**
  (IAT VA `0x0049C058`).
- At `0x450C40`–`0x450D86`, a neighboring wrapper builds
  `PUSH imm32; RET` and calls it at `0x450CF6`. The alternate
  branch calls **`CloseHandle` at `0x450D6F`**
  (IAT VA `0x0049C0E0`).
- The EXE's imports additionally contain `WriteFile`
  (direct call candidate `0x4549BF`). This is generic Windows
  file I/O; no direct reference to the ICD or fake DLL has been
  established, and these observations **do not** prove creation
  of either on-disc PRNG stream.
- Case-insensitive readable-string search finds no literal
  `RAYMAN2.ICD`, `dplayerx.dll` or `dxplayerx.dll` in the
  supplied protected EXE.

**Interpretation:** the obfuscated runtime Win32 calls provide a
concrete target for further control-flow reconstruction. Do not
confuse a widely reused PRNG with evidence that the game
executes or decrypts these two CD-resident synthetic files.

## Validation boundary: full byte coverage versus complete words

The Python `--auto-align` mode and the native Rust generic inspector
now require every byte after an optional 0–3-byte prefix to be accounted
for by complete reconstructed PRNG words. A file ending in additional,
unexplained bytes can still have a 100% matching **word recurrence**,
but **cannot** be advertised as a verified whole-file match.

A new synthetic Python regression test and native Rust tests cover
the partial-tail negative case. The **local Python mirror passes 47
unit tests**; Rust code remains **uncompiled** because no Rust
toolchain is available in the current execution environment.
The Crimson Skies exact-hash-gated decoder remains unchanged.

## Reliability audit — 13 November 2026

**On-owner reference golden tests without distributing binary files:**

- The native Rust `src/unsafedisc_generic_inspect.rs` unit tests
  regenerate the **683,565-byte ICD stream** (prefix `5B`,
  170,891 little-endian words, seed `0x6EE4C08A`) and the
  **165,888-byte DLL stream** (41,472 words, seed `0x0030FBEC`)
  completely in memory from the common masked MINSTD recurrence.
  They assert the original independently verified SHA-256 for both
  outputs. **No proprietary binary fixtures are in the repository.**
- The Python synthetic alignment suite now has an equivalent
  **SHA-256 golden test**, including unique offset/endian detection.
  This golden test passed against locally generated bytes; the
  owner-supplied source files also have matching SHA-256.
- The Rust generic inspector now uses a **bounded file-descriptor
  read** (`MAX_INPUT_LEN + 1` limit), checks the opened file's size
  and modification metadata, and on Unix compares pre-open
  device/inode against the file descriptor. It retains symlink
  rejection and a new test for an oversized sparse file.
  This closes the former unbounded `fs::read` race after a
  pathname-only metadata check. Platform-specific race-hardening
  should still be reviewed during Windows validation.
- The optional CD vs installed-file comparator now rejects
  **self-comparison** via `Path.samefile`. Such a comparison could
  otherwise incorrectly imply independent corroboration.
- The Python PRNG analyzer computes its three-word-window
  diagnostic **once per candidate** rather than twice.

**Verified execution:** local mirror of the Python research suite,
**49 tests passed** after these changes. The native Rust code
has **not** been compiled or executed here: `cargo`/`rustc` are
not installed, and network access for fetching a toolchain is
unavailable. GitHub Actions were deliberately not used.

Recommended next verification when a Rust toolchain is available:

```sh
cargo test --bin unsafedisc-linux
cargo run --bin unsafedisc-linux -- inspect --generic-inspect \
  --loader Rayman2.exe --icd RAYMAN2.ICD --dplayerx dplayerx.dll \
  --layout --sections
```

The first command tests native code using **only synthetic and
regenerated-in-memory** fixtures; the second uses the owner's own
protected files for independent integration validation.

## Next research milestones

1. Verify the original disc and unmodified installer outputs, keeping
   `dplayerx.dll` and `dxplayerx.dll` distinctly identified.
2. Trace the exact game's file-production and loading logic to establish
   **why** the two on-disc files are masked-MINSTD streams and whether
   actual protected payloads exist elsewhere.
3. Compare the owner's hash-pinned protected and independently acquired
   unprotected Rayman 2 EXEs without distributing proprietary binaries.
4. Preserve Crimson Skies exact-hash reconstruction tests and run
   Rust compilation/tests on Linux and Windows when toolchain and
   budget permit; do not merge draft PRs prematurely.

**Neither synthetic PRNG stream has been decrypted into game code.
No generic SafeDisc 1.35 decryption is claimed.**
