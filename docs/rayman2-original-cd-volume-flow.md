# Rayman 2 — original CD-ROM volume search and GOG bypass (read-only x86 audit)

**14 November 2026.** This report documents only the **known owner-supplied exact SHA-256 executables**:

| Version | Bytes | SHA-256 |
|---|---:|---|
| Original CD-sourced Rayman2.exe | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG comparison Rayman2.exe | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

GOG is **not a known pristine retail unwrapping**. All x86 control-flow findings are static, restricted to a linear GNU `objdump -d -M intel` disassembly; no execution or physical CD authentication has been observed.

## Reconstructed CD search in the original executable

The two PE files retain the exact direct `CALL` **`0x44949F -> 0x448E30`** within their common runtime initialiser `0x449360`. In both builds, the callee checks the zero-initialised guard DWORD at `0x5113EC`; if zero, it enters the body at `0x448E5A`.

The original body contains 13-byte masked Win32 API trampolines that the prior **106-site indirect-call taxonomy** independently decoded by the 76-byte export descriptor table. Three calls were verified in their original sequential execution region:

| Original call VA | Recovered API | Purpose evidenced by opcode context |
|---|---|---|
| `0x448F02` | `GetLogicalDrives` | Retrieves a bitmap of available drive letters |
| `0x449037` | `GetDriveTypeA` | Returns drive type; test at `0x449096` requires **`5`** (`DRIVE_CDROM`) |
| `0x449158` | `GetVolumeInformationA` | Retrieves the volume-name buffer, then tests its characters |

The original code performs **seven 1-byte comparisons**, in non-sequential instruction order, against buffer offsets `0..6`. Reordering by stack-buffer byte position yields the exact seven-letter label **`RAYMAN2`**. It also explicitly checks that the terminated string has **length 7**, at `0x449203`, and branches to success at `0x449219`.

On the success branch `0x449219`, the zero-based drive index is converted to a letter with `ADD AL,0x41` and written at **`0x449225` to global byte `0x4A6AD8`**. This is stronger than the mere presence of `RAYMAN2` in the PE string table: the code contains the complete per-character check and success write.

If no matching volume was found, the program prepares a `MessageBoxA` at `0x449339` via **IAT slot `0x49C270`**, with two stack-constructed strings:

- Prompt: `Please, insert Rayman II CD in CDROM Drive`
- Title: `Rayman 2 CD not found`

The messagebox style argument is **`5` (`MB_RETRYCANCEL`)**. Result `2` (`IDCANCEL`) calls the exit/cleanup routine at **`0x4011C0`** (`0x449344`); otherwise the branch at `0x44934B` jumps back to `0x448F78` to search again. These findings are based on raw instruction offsets, the import directory and the independently reconstructed byte writes, **not a witnessed user dialog**.

## Changed GOG implementation, shared consumers

GOG leaves the outer `CALL 0x448E30` and the guard logic unchanged, but replaces **the body at `0x448E5A`** with `MOV AL,0x2E` (ASCII `'.'`), followed by the **same global-byte write** at `0x448E5C` and an immediate return. The original CD search, seven-byte label match and retry dialog block are **neutralised by `INT3`** in active GOG `.text`.

A separate complete linear-disassembly inventory found **17 direct reads** and exactly **one direct write** of that global byte in *each* executable. **All 17 direct read instructions are byte-identical at the same VA** between CD and GOG. The unique direct write changes from CD `0x449225` (selected CD drive letter) to GOG `0x448E5C` (`'.'`). This confirms that GOG changes how the shared byte is initialised, not every consumer of it. It does **not** exclude indirect/dynamically generated reads or writes.

Another independently documented retail/GOG difference at `0x44F156` simplifies the format string from `%c:\%s\%s` to `%s\%s`, removing its use of the original CD drive letter for that specific file path. Combined with the GOG initialiser `'.'`, this supports a deliberate file-location adaptation rather than merely skipping a checksum.

## Interpretation

1. **Proven statically:** a complete **logical CD volume/name check**, error/retry branch, and changed GOG initialisation for a globally reused drive selector.
2. **Not proven:** physical disc C2 error verification, an actual SafeDisc driver exchange, disc authenticity, runtime branch reachability, or a decrypted loaded `.ICD` payload.
3. **No claim:** this is **not** a working SafeDisc unwrapping, no-CD patch or evidence that all original retail tests are solved. The exact sample `RAYMAN2.ICD` remains a separately identified fully regenerable PRNG stream; its original provenance is unresolved.

## Reproduction and validation

The local, read-only program `rayman2_cd_volume_branch_audit.py` checks the two SHA-256 identities; compares raw x86 branch targets and opcode anchors; crosschecks the named masked Win32 descriptors; decodes the seven label comparisons and the two constructed stack messages; checks the `MessageBoxA` IAT entry; and counts the 17 preserved direct byte-read references. It emits `cd_volume_branch.json` containing only addresses, names, counts and verification flags — never PE bytes or a new executable.

The new module has **18/18 synthetic tests passed**. Together with the 21 previous synthetic tests of the direct/indirect call and trampoline audit, **39/39 tests passed locally**. A new integration run against both original exact-SHA executables reproduced the report values. A CI run on the GitHub checkout and Windows/Wine runtime verification have **not** been performed. No proprietary game files are added to the repository.

Next priority: investigate *which* checks, if any, occur after the logical volume search (for example, data-file size checks versus original media authentication) before proposing any original-CD executable reconstruction.