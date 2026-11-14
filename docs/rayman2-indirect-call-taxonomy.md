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
| `CALL ECX` through masked pair outside the API descriptor table | **1** | No named export established |
| Dynamically built 13-byte `MOV/XOR/JMP` or `MOV/XOR/PUSH/RET` trampoline | **30** | Yes, encoded API descriptors |
| Dynamically built `PUSH imm32; RET` | **3** | Yes, `CloseHandle` descriptor #11 |
| Dynamically built `JMP rel32` | **2** | Yes, `Module32First` / `Module32Next` descriptors #22 / #23 |
| Dynamically built `MOV EAX,[ptr]; XOR EAX,[mask]; JMP EAX` with **non-table** mask | **1** | No named export established |
| **Total** | **106** | **104 named, 2 same non-table pointer pair** |

The two not-yet-named transfers share the **exact on-disk pointer/mask address pair `0x4A1400 / 0x4A13D0`**. The first at `0x447ACE` is `CALL ECX` within the loader/resolver pathway. At `0x448B8E`, the loader constructs a 13-byte trampoline whose pointer DWORD is `0x4A1400` and whose mask DWORD is supplied by `EDI`, loaded with `0x4A13D0` at `0x448ABE`. These are a shared code mechanism, **not proof** of which runtime export/function they call or that their actual targets are identical on all executions.

### Named API histogram across the 104 matching sites

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
| `EnumProcessModules`, `GetDriveTypeA`, `GetLogicalDrives`, `GetVolumeInformationA`, `Module32First`, `Module32Next` | 1 each |
| **Total** | **104** |

These names are independently obtained by decoding the CD's **35** static masked Win32 API descriptor records, not by assuming every changed GOG instruction is an equivalent operation.

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

Three local Python analyzer/test pairs were exercised: **21/21 synthetic unit tests passed**. The additional taxonomy was run against the two original user files whose SHA-256 hashes are stated above: **106 changed sites identified, 106 classified, zero unclassified**, and the descriptor index/name was verified for all 104 named sites. The machine-readable JSON lists each site, its opcode-derived classification, masked pointer locations and the GOG mnemonic at the same VA.

This is a **bounded static statement**, not a proof of runtime reachability. Linear disassembly is not a control-flow graph. The 35 descriptor slots are zero on disk and require runtime initialisation before corresponding decoded exports can be called. Dynamic code generation, different disc mastering, runtime anti-tamper, and unrelated GOG edits remain possible. None of these findings validates the historical 1.35 driver module's actual physical-CD provenance, removes SafeDisc end-to-end, proves gameplay, or justifies distributing reconstructed game binaries.

**Next target:** determine the live initialisation and target of the shared out-of-table masked-pointer pair `0x4A1400 / 0x4A13D0` (especially the original resolver at `0x447ACE`), including its call arguments and dataflow. Treat `GetProcAddress` or `LoadLibraryA` as hypotheses, **not established identities**.
