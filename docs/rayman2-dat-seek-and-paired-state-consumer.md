# Rayman 2: masked DAT seek wrapper and two-value consumer (exact x86 evidence)

**14 November 2026 | Read-only, SHA-256 locked, no decrypted executable.**

## Scope

The only executable inputs used are the owner's original CD-sourced
`Rayman2(3).exe` (676,352 bytes; SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`)
and the separately modified GOG `Rayman2.exe` (1,468,928 bytes;
SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).
GOG must **not** be treated as a pristine decrypted original.

## 1. The first DAT seek is an obfuscated Win32 call, not decoded game data

The common `0x44E8D3` call obtains an initial DAT handle and a
file offset from `0x44EB40`. An error path branches away at
`0x44E8E3` if the handle is `INVALID_HANDLE_VALUE`.

On the original CD executable, `0x44E944` selects a pseudo-random
offset using divisor `0x455 = 1109`, `0x44E94E` adds
the `0x510EA0` runtime buffer base, and seven byte/word stores
at `0x44E954..0x44E971` create this **13-byte x86 stub**:

```asm
MOV  EAX, [0x4A1790]
XOR  EAX, [0x4A1760]
PUSH EAX
RET
```

The mask/source addresses are obfuscated API pointers, not a file
payload. Other previously committed SafeDisc research independently
identifies this call's final target as Win32 `SetFilePointer`, which
is corroborated by GOG's import table. The original code resolves
`GetCurrentProcess` and calls `FlushInstructionCache`
with pointer `0x510EA0` and length `0x464 = 1124`
before the generated call. It then executes:

```asm
0x44E99F PUSH 0
0x44E9A1 PUSH 0
0x44E9A3 PUSH EDI
0x44E9A4 PUSH EBX
0x44E9A5 CALL ESI
```

These are the four parameters of `SetFilePointer`:
file handle, low offset, NULL high-offset pointer, and `FILE_BEGIN`.
The PRNG-driven loop starting at `0x44E9A7` then scrubs
**15 bytes** starting at the generated stub location. This is a
separate side effect that must not be silently treated as a game
asset decryptor.

GOG replaces the original `0x44E8F2` masked-generator branch
with `JMP 0x44E99F`. The arguments are preserved; at
`0x44E9A5` it instead executes `CALL [0x49C048]`,
an IAT call to `SetFilePointer`, and `0x44E9AB JMP
0x44EA18` skips the stub-scrubbing region. The import
`SetFilePointer` at `0x49C048` was independently confirmed
using `objdump -p` on the original executable.
The original's generator region is absent from active GOG
`.text`, not evidence of the file payload being decrypted.

This is a concrete original-to-GOG **Win32 ABI preservation**:
both variants make a seek with the same four stack arguments.
It does not prove the original disc uses identical offsets at
runtime or that the original copy-protection check is gone.

## 2. The following XOR reader saves *pairs* for later engine use

The exact `0x44EA18..0x44EA7D` constructor/seed path is retained
in both builds. The code overwrites the constructor's initial
seed with its data-derived state at `0x44EA7D`.
It then uses two nearby DWORD tables:

| Producer | Base | Value written |
| --- | --- | --- |
| `0x44EA8C` | `0x511760` | Modified global state DWORD from `0x5116F0` |
| `0x44EAB6` | `0x511700` | DWORD returned by the file reader in `[EBP-8]` |

The same slot number is loaded from `0x5117C4` and
incremented at `0x44EABD`, then stored at `0x44EAC4`.
This is a **one-pair-per-observed-source-iteration** static
storage sequence; actual runtime iteration count is not known.
The two base addresses differ by `0x60 = 96 bytes`,
suggesting room for 24 DWORD slots each, but there is no
verified universal runtime 24-item bound at this producer.

At `0x46729F` the shared engine code reads the slot count
and iterates from index zero. For each index:

- `0x4672AD` reads `[0x511760 + index*4]`, passes its DWORD
  into the generic typed-value callback `0x4817B0` at `0x4672C4`.
- `0x4672CC` reads `[0x511700 + index*4]`, and passes its DWORD
  to **the same** `0x4817B0` at `0x4672E6`.
- Both calls prepare the generic type-code `6` at
  `0x4672BD` and `0x4672DC`.
- This code is byte-identical across the original and GOG.
  The loop's local index is truncated to 8 bits at
  `0x467300`, so its runtime count needs measurement
  before assuming it covers arbitrary table lengths.

This is **downstream use of decoded data**, not a demonstrated
comparison to a reference checksum. The callback `0x4817B0`
is reused in the engine's typed-value system. Its potential
indirect effects remain out of scope without live object data.

## 3. Reproduction and next discriminant

```sh
python scripts/rayman2_dat_seek_pairs_audit.py \
  --retail /private/CD/Rayman2.exe \
  --gog /private/GOG/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_dat_seek_pairs_audit.py'
```

The script refuses unapproved executable hashes, maps only
file-backed PE32 regions, verifies the original/GOG machine-code
anchors, checks real rel32 branch destinations and emits **only
metadata**, not binary payloads. Local independent analysis of
the two exact owner-supplied PE files reproduced all source anchors
and both generic callback addresses. Eight local tests for the
equivalent static model passed with the private inputs; GitHub CI
also exercises synthetic tests and skips private integration when
those files are absent.

**Next discriminant:** passively capture, at the original
`0x44EA34` and `0x44EAA0`, the modified global `0x5116F0`,
actual selected DAT handle/file, seek position and first
four file bytes, then compare the DWORD emitted to the two
stored table entries. This identifies the DAT data protocol
without guessing which unrelated SafeDisc physical-disc routines
might be involved.

**Not demonstrated:** an authentic physical SafeDisc 1.35 sector
read, a live stream initial state on retail, an integrity-failure
branch, or a decrypted `Rayman2.exe`.
