# Rayman 2 — read-only reconstruction of 15 dynamic Win32 trampolines

**14 November 2026. Static x86 audit, not a SafeDisc decoder.** Inputs are the owner-supplied exact SHA-256 files:

- Original CD-sourced `Rayman2.exe`, 676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- GOG `Rayman2.exe`, 1,468,928 bytes, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`. **GOG is not a pristine retail-unwrapped reference.**

## Independently checked same-site IAT conversions

Across the original's linear `objdump -d -M intel` disassembly, there are **367 indirect `CALL register`** instruction sites, compared with **261 preserved exact sites** in active GOG `.text`. At the other **106 original sites**, the exact indirect call is no longer present.

**Fifteen** of these original sites are specifically a `CALL ESI` that GOG replaces at precisely the same VA with a `CALL DWORD PTR [IAT]`. Each of the 15 sites independently satisfies all of the following:

1. The original source instructions explicitly write **all seven components** of a 13-byte trampoline into memory: the `A1` byte, pointer operand at offset 1, `33 05` at offsets 5–6, mask operand at offset 7, and one of two control-transfer tails at offsets 11–12.
2. The pointer and mask immediates form a valid pair in the exact 35-entry, stride-76 descriptor table beginning at `0x4A141C`; the pointer field is the mask base plus `0x30`.
3. The descriptor's original encoded Windows export name decodes to **exactly the import name** referenced by GOG's substitute IAT call, checked against `objdump -p` of the GOG PE imports.

The generated code takes one of two 13-byte shapes. Both compute `EAX = [masked_pointer_slot] XOR [mask]`, then transfer control without discarding the original caller's return address:

```asm
A1 <ptr32> 33 05 <mask32> FF E0   ; MOV EAX,[ptr]; XOR EAX,[mask]; JMP EAX
A1 <ptr32> 33 05 <mask32> 50 C3   ; MOV EAX,[ptr]; XOR EAX,[mask]; PUSH EAX; RET
```

**Four `CreateFileA` calls use `JMP EAX`; eight `ReadFile` and three `SetFilePointer` calls use `PUSH EAX; RET`.** The latter is a stack-based indirect transfer, not an ordinary function epilogue. The 13 bytes are reconstructed *from original instructions that write them*, not extracted from any runtime memory dump.

| Retail VA of `CALL ESI` | Export / descriptor index | Generated transfer | GOG IAT call slot |
|---|---|---|---|
| `0x44DF52` | CreateFileA / 8 | JMP EAX | `0x49C058` |
| `0x44E178` | CreateFileA / 8 | JMP EAX | `0x49C058` |
| `0x44E28D` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |
| `0x44E387` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |
| `0x44E43C` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |
| `0x44E4FE` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |
| `0x44E5B8` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |
| `0x44E662` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |
| `0x44E9A5` | SetFilePointer / 12 | PUSH EAX; RET | `0x49C048` |
| `0x44EC24` | CreateFileA / 8 | JMP EAX | `0x49C058` |
| `0x44ECF8` | CreateFileA / 8 | JMP EAX | `0x49C058` |
| `0x44EEC9` | SetFilePointer / 12 | PUSH EAX; RET | `0x49C048` |
| `0x44EF5D` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |
| `0x44F016` | SetFilePointer / 12 | PUSH EAX; RET | `0x49C048` |
| `0x44F0AA` | ReadFile / 10 | PUSH EAX; RET | `0x49C04C` |

These calls are in a cluster near `0x44DF52..0x44F0AA`. The original builds a trampoline near `0x510EA0` using PRNG-derived offsets, and original source code around the calls also resolves `GetCurrentProcess` and often calls the masked `FlushInstructionCache` descriptor (index 1), directly or through the original helper `0x4484D0`. This is corroborating evidence for runtime code generation, **not** proof that these paths were executed in an observed game session.

## Scope and next step

The independent local research tool `rayman2_trampoline_audit.py` and its seven synthetic tests were executed together with the prior direct-call audit: **10/10 tests passed**. The report was reproduced on both exact inputs, including **261 preserved / 106 modified** original indirect-reg call sites and all **15/15** verified IAT bridges. No game or SafeDisc driver ran, no native Rust compilation or Actions workflow was started, and no proprietary executable or derived executable was committed.

This establishes a precise way to replace *selected proven indirect Win32 calls* with normal IAT calls in a future prototype. It does **not** establish that every obfuscated call can be replaced this way, that the original retail program is runnable without other integrity checks, or that the pseudo-random SafeDisc-era companion files are authentic physical-CD loader payloads.

Next priority: recover the original **remaining 91 modified indirect-register call sites** and their control-flow predecessors, distinguishing transient generator calls, loader checks, API calls and GOG-only edits **without making an unverified binary patch**.
