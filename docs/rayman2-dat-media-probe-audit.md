# Rayman 2 — original `.DAT` media-probe pipeline versus GOG

**14 November 2026 — exact-SHA-256, read-only PE32/x86 investigation.**

The study uses the owner-supplied 676,352-byte CD-sourced `Rayman2.exe` (SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`) and separately modified 1,468,928-byte GOG `Rayman2.exe` (SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`). **GOG is not a pristine retail decryption oracle.** The inspection does not execute, decrypt, patch, repair or distribute any game binary.

## Newly verified caller chain and gating

- In both files, the executable contains direct `CALL 0x418960` at `0x44D9EA`, a `TEST AL,AL` followed by the conditional branch `0x44D9F1`, and direct `CALL 0x44E8A0` at **`0x44D9F4`**. **The original on-disk body at `0x418960` is just `MOV AL,1; RET`**, identical to GOG; the outcome at this particular call is therefore true *if the two instructions are executed unmodified*, rather than the return value of an external CD-authentication operation. Dynamic rewriting has not been excluded.
- The `0x44E8A0` routine calls **`0x44EB40` at `0x44E8D3`**, passing the address of a local DWORD; both direct call edges are bit-for-bit unchanged in GOG. The helper's entry checks the zero-initialised global **`0x5113EC`** and may return early; the runtime value of that guard is unknown.
- The helper at `0x44EB40` starts with the first 32-bit pointer from the table at `0x4A2090`, **`LEVELS0.DAT`**, constructs a path, and uses an original dynamically generated `CreateFileA` transfer at `0x44EC24`. GOG converts that original `CALL ESI` to `CALL [0x49C058]` (`CreateFileA` in its PE imports).

### An independent earlier consumer of the first `.DAT` pointer

The same 96-byte pointer table also has a **third** direct code reference at **`0x44DE9D`**, in another helper path that loads its first pointer (`LEVELS0.DAT`). In the CD build, a `CALL 0x448480` at `0x44DEC5` starts a PRNG-backed API-trampoline builder and the later `0x44DF52` opens the file via `CALL ESI`. GOG changes `0x44DEC5` to a short `JMP 0x44DF39`, explicitly bypassing that local generator, and changes the same final `0x44DF52` to `CALL [0x49C058]`, the ordinary `CreateFileA` IAT entry. This earlier path also drops the CD drive-letter formatting argument and uses the same `%s\\%s` GOG string. All these source byte patterns have been checked in both files. They prove a second *local* file-open simplification, **not** the count of times either path is executed at runtime.

## 24-file index table is *unchanged* in GOG

The complete **96 bytes** of the pointer table at **VA `0x4A2090`** are identical in both binaries, SHA-256 `55816453eb99c6e442f0d1303e117efb19ff9be61b5f52f9737c5b78acf27911`. Every pointer is in a valid PE-backed `.data` address, and all 24 pointed-to ASCII names are identical in both binaries. There are three banks `0`, `1`, `2`, each with eight members in this exact order: `LEVELS`, `MAP`, `TEXTURES`, `ANIMS`, `SOUNDS`, `MUSIC`, `GRAPHICS`, `MENU`, all suffixed `.DAT`.

At **`0x44F13A`**, original code performs `MOV EDX,[EBX*4+0x4A2090]`, an **index-dependent filename selection**; GOG substitutes `MOV EDX,[0x4A2090]`, a fixed pointer to **`LEVELS0.DAT`**. The tables are identical, so this is specifically a *consumer-code* change. The analysis does **not** establish a runtime bound for `EBX`, a particular choice among all 24, or which listed `.DAT` files are physically readable on the original CD.

## Specific file I/O that GOG preserves versus removes

All opcode assertions below were independently checked in the two exact samples, not inferred solely from GOG file metadata:

| Source site(s) | Original CD | GOG active code |
|---|---|---|
| `0x44EF59` / `0x44EF5D` | 16-byte `ReadFile` via dynamic `CALL ESI` | 16-byte `ReadFile` via `CALL [IAT]` |
| `0x44F0A6` / `0x44F0AA` | 4-byte `ReadFile` via dynamic `CALL ESI` | 4-byte `ReadFile` via `CALL [IAT]` |
| `0x44F10D` / `0x44F11E` / `0x44F125` | File seek, then **512-byte `ReadFile`** | `0x44F102..0x44F129` all NOP; seek/read not executed from the same fall-through path |
| `0x44F133` | `SUB DWORD PTR [ESI],ECX`, changes an in/out DWORD | Two NOPs |
| `0x44F13A` | Indexed pointer `[EBX*4+0x4A2090]` | Fixed pointer `[0x4A2090]` |
| `0x44F156` / `0x44F161` | Formatting string **`%c:\\%s\\%s`** and 20-byte stack cleanup | **`%s\\%s`** and 16-byte cleanup |
| `0x44F17D` / `0x44F1C0` | Retained direct calls to `0x44F220` (CreateFileA wrapper) | Same direct calls, GOG wrapper forwards to Win32 directly |
| `0x44F1D4` / `0x44F1E5` / `0x44F1EC` | Second seek, then **512-byte `ReadFile`** | `0x44F1CC` becomes a direct `JMP 0x44F1F1`; its following original seek/read region becomes `INT3` |

The preserved initial reads are structurally notable: GOG does **not** simply delete all file-reading operations. The original mathematical operations following the first reads and the later indexed file selection may implement a probe, integrity computation, or normal data-loading logic. **No executed anti-tamper predicate, expected checksum value, validated failing input, or physical SafeDisc-driver I/O has been established.**

Both builds also preserve the failed-file-open retry sequence at `0x44F189..0x44F1CA` using the **different** strings `Please insert the CD` and `CDROM not found!`. These are **not** the earlier `Rayman 2 CD not found` / `Please, insert Rayman II CD in CDROM Drive` strings of the logical volume-label scanner. The file-open retry checks for `-1` from `CreateFileA` and uses the existing dialog callback at `0x4028F0`; this is a separate CD-file error path.

## Research limits and next discriminator

The two verified executables contain the required code and metadata, but no authentic original same-edition *physical* CD-sector contents or loaded SafeDisc module. The earlier inspection logs only establish ISO9660 names, declared byte counts and exclusions; the 23 oversized `.DAT` records cannot be treated as physical file extents. Moreover, GOG carries changes beyond SafeDisc removal. Thus these static differences cannot yet be classified as DRM-specific patches or be safely transplanted to the original EXE.

The most useful next experiment is **a controlled, read-only runtime trace of the original routine's actual `ReadFile` return values, file offsets, buffer contents and selected index `EBX`**, correlated with the same-edition CD sector evidence. Before any runtime work, complete a bounded static dataflow walk of the initial 16/4-byte reads through `0x44F0D4..0x44F13A`. Keep the distinction between a *logical volume check*, a *file access probe*, and *physical disc authentication* explicit.

## Reproduction and test coverage

The standalone Python script `rayman2_dat_media_audit.py` requires the two owner files at their exact SHA-256s, GNU `objdump`, and the existing read-only analyzers; it enumerates all 24 pointers, validates each name and the shared 96-byte table hash, verifies all identified call edges/opcode differences and imports, and emits *only* source addresses, file names, sizes and status flags to JSON. It never writes an EXE. Its own **21** unit/integration tests passed, including intentionally altered opcodes, wrong branch targets, wrong IAT imports, changed source messages, malformed pointers and wrong read lengths. The local combined five-module suite passed **60/60 tests** (including 18 CD-volume, 11 indirect-taxonomy, 7 trampoline, 3 direct-call and 21 new DAT-probe tests). No GitHub Actions job or Rust binary build was run for this result.