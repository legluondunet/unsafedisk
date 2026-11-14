# Rayman 2 — static taxonomy of all 106 changed indirect-register CALL sites

**14 November 2026 — read-only, exact-SHA-256 study of the original CD-sourced executable versus GOG.** No runnable unwrapped executable has been created; GOG is a separately modified comparison build, *not* a certified pristine retail baseline.

| Original sample | Bytes | SHA-256 |
|---|---:|---|
| CD-sourced `Rayman2(3).exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

## Audit result: all 106 exact sites have a recognised static pattern

GNU `objdump -d -M intel` on the original active `.text` locates **367** two-byte `FF D0..FF D7` `CALL register` sites. **261** are byte-identical at the *same virtual address* in active GOG `.text`; **106** have changed. The comparison does not count GOG's `.extra` archival copy of retail code. Original register counts for changed sites are **38 EAX, 32 ECX, 36 ESI**.

| Type, determined from the CD's source opcodes | Sites | Target identified? |
|---|---:|---|
| Masked `CALL EAX` for `GetCurrentProcess` | **37** | Yes, descriptor #2 |
| Masked `CALL EAX` for `FlushInstructionCache` | **1** | Yes, descriptor #1 |
| Masked `CALL ECX` for `FlushInstructionCache` | **31** | Yes, descriptor #1 |
| `CALL ECX` through bootstrap descriptor index #0 | **1** | Yes, `GetModuleHandleA` |
| Dynamically built 13-byte `MOV/XOR/JMP` or `MOV/XOR/PUSH/RET` trampoline | **30** | Yes, encoded API descriptors |
| Dynamically built `PUSH imm32; RET` | **3** | Yes, `CloseHandle` descriptor #11 |
| Dynamically built `JMP rel32` | **2** | Yes, `Module32First` / `Module32Next` descriptors #22 / #23 |
| Dynamically built `MOV EAX,[ptr]; XOR EAX,[mask]; JMP EAX` using bootstrap descriptor #0 | **1** | Yes, `GetModuleHandleA` |
| **Total** | **106** | **106 named, none unnamed** |

## Newly recognised bootstrap API descriptor #0

The two previously unnamed transfers use the pair `0x4A1400 / 0x4A13D0`. The latter is **exactly one 0x4C-byte descriptor stride before the former #1 at `0x4A141C`**. Decoding its length-16 encoded export name with the same subtract/XOR recurrence yields **`GetModuleHandleA`**. The 76-byte descriptor SHA-256 is `c2b66e4d6b60b7691e82f2dc1ed82e2266406be57b77ca2599b61bd1bb50dd0b`, **identical in the original and GOG files**; the pointer field `+0x30` is zero on disk in both.

- Original `0x447ACE`: masked `CALL ECX` with `EDX=[0x4A1400]`, `ECX=[0x4A13D0]`, `XOR ECX,EDX`. Its caller passes an EAX argument (consistent with a module name).
- Original `0x448B8E`: a constructed 13-byte `MOV EAX,[0x4A1400]; XOR EAX,[0x4A13D0]; JMP EAX` trampoline, with `EDI` loaded with `0x4A13D0` at `0x448ABE`. The call passes `NULL` (consistent with `GetModuleHandleA(NULL)`).
- In original routine `0x4478A0`, a direct `MOV [0x4A1400],EAX` at `0x4478FB` writes the masked pointer, and `0x447A76` overwrites or clears it on a later path. This establishes a specific bootstrap initialisation and validation mechanism, **not observed success at runtime**.

Hence we have **36 named records**: a bootstrap record index zero at `0x4A13D0` and the already-known 35 numbered records 1–35 at `0x4A141C` onward; the previously documented all-zero sentinel after record 35 is a separate slot.

### Named API histogram across all 106 matching sites

| Decoded API name | Sites |
|---|---:|
| `GetCurrentProcess` | 37 |
| `FlushInstructionCache` | 32 |
| `ReadFile` | 11 |
| `CreateFileA` | 6 |
| `SetFilePointer` | 5 |
| `CloseHandle` | 3 |
| `LoadLibraryA` | 2 |
| `CreateToolhelp32Snapshot` | 2 |
| `GetModuleHandleA` | 2 |
| `EnumProcessModules`, `GetDriveTypeA`, `GetLogicalDrives`, `GetVolumeInformationA`, `Module32First`, `Module32Next` | 1 each |
| **Total** | **106** |

These names are independently obtained by decoding the CD's **36** static masked Win32 API descriptor records (bootstrap index zero plus 1–35), not by assuming every changed GOG instruction is an equivalent operation.

## Five newly decoded special call sites

The special code forms perform a masked pointer lookup from the *same* 35-descriptor table; they simply emit a different trampoline opcode.

| Original `CALL ESI` VA | Dynamic instruction emitted in memory | Pointer/mask descriptor | Named Windows API |
|---|---|---|---|
| `0x44859D` | `PUSH imm32; RET` | `0x4A1744 / 0x4A1714` (#11) | `CloseHandle` |
| `0x448946` | `PUSH imm32; RET` | `0x4A1744 / 0x4A1714` (#11) | `CloseHandle` |
| `0x450CF6` | `PUSH imm32; RET` | `0x4A1744 / 0x4A1714` (#11) | `CloseHandle` |
| `0x44878B` | `JMP rel32` | `0x4A1A88 / 0x4A1A58` (#22) | `Module32First` |
| `0x448883` | `JMP rel32` | `0x4A1AD4 / 0x4A1AA4` (#23) | `Module32Next` |

The `JMP rel32` case computes `target_masked_pointer XOR mask - stub_address - 5`, and writes that displacement to `[ESI+1]` following an `E9` opcode. The `PUSH imm32; RET` case writes the masked `CloseHandle` destination into `[ESI+1]` after opcode `68` and ends with `C3`. A previous *nearest-builder-only* heuristic would misclassify `0x44878B` by inheriting an older descriptor; this audit requires the **nearby exact source loads and generated opcode/displacement write**.

## What changed in GOG at the 106 original instruction sites?

Static linear disassembly at identical original VAs found: **71 `INT3`, 15 `CALL`, 14 `NOP`, 3 `MOV`, 1 `XOR`, 1 `RET`, and 1 without an instruction boundary at that VA**. Of the 15 direct `CALL [IAT]` replacements, the independently verified IAT import-name match covers **4 `CreateFileA` + 8 `ReadFile` + 3 `SetFilePointer`**. These counts describe *specific instruction addresses*, not overall game runtime call frequencies.

## Verification and limitations

Three local Python analyzer/test pairs were exercised: **21/21 synthetic unit tests passed**. The additional taxonomy was run against the two original user files whose SHA-256 hashes are stated above: **106 changed sites identified, 106 classified, zero unclassified**, and the encoded descriptor index/name was verified for all 106 named sites. The machine-readable JSON lists each site, its opcode-derived classification, masked pointer locations and the GOG mnemonic at the same VA.

This is a **bounded static statement**, not a proof of runtime reachability. Linear disassembly is not a control-flow graph. The 35 descriptor slots are zero on disk and require runtime initialisation before corresponding decoded exports can be called. Dynamic code generation, different disc mastering, runtime anti-tamper, and unrelated GOG edits remain possible. None of these findings validates the historical 1.35 driver module's actual physical-CD provenance, removes SafeDisc end-to-end, proves gameplay, or justifies distributing reconstructed game binaries.

**Next target:** trace whether the bootstrap record #0 (`GetModuleHandleA`) is successfully initialised in Windows/Wine, and then follow the later import resolution, physical-CD checks and anti-tamper paths. Neither a named export nor its masked slot proves any particular runtime execution result.
