# Rayman 2 — five original object-dispatch registry families, delimited exactly

**14 November 2026 — read-only PE32/x86 research.** This extends the `0x170` provenance work, not a retail SafeDisc decryption. The two exact owner-supplied inputs are verified before analysis:

| Input | Size | SHA-256 |
|---|---:|---|
| CD-sourced `Rayman2(3).exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Separately modified GOG `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

## New complete on-disk map of the first five byte classes

The shared generic engine evaluator at `0x480B90` reads a byte from `[record+7]` at `0x480B9B` and calls `[0x4A4180 + class*4]` at `0x480BA4`. Its 41-entry parser table was already separately SHA-pinned in our prior audit. **For the first five classes only**, each selected wrapper reads a DWORD type/index from the beginning of an 8-byte record and fetches an in-engine function pointer from a distinct static table. Each wrapper then advances the record pointer by eight bytes before transferring control indirectly.

| Byte class | Wrapper | Getter | Table start | Valid consecutive entries | Stride | Distinct handlers | Flag 0 / 1 | Non-handler bytes immediately afterwards |
|---:|---|---|---|---:|---:|---:|---|---:|
| 0 | `0x480800` | `0x487D50` | `0x4A5E80` | **20** | 4 | 15 | n/a | 16 |
| 1 | `0x480830` | `0x487D70` | `0x4A5EE0` | **149** | 8 | 39 | 64 / 85 | 16 |
| 2 | `0x4808B0` | `0x487D80` | `0x4A6398` | **28** | 4 | 8 | n/a | 16 |
| 3 | `0x480880` | `0x487820` | `0x4A5460` | **314** | 8 | 106 | 159 / 155 | 80 |
| 4 | `0x480900` | `0x482690` | `0x4A43E0` | **514** | 8 | 159 | 215 / 299 | 112 |

All five first-table spans and following non-handler spans have **the same SHA-256 in CD and GOG**, separately checked. Each table pointer is within the original active `.text` virtual-address range. Where a stride is eight, the second DWORD is an observed 0/1 metadata flag; its semantics remain unproven.

The class wrappers have these exact static target chains in both images:

```text
0x480B90 -> class[0] 0x480800 -> getter 0x487D50 -> [0x4A5E80 + tag*4]
0x480B90 -> class[1] 0x480830 -> getter 0x487D70 -> [0x4A5EE0 + tag*8]
0x480B90 -> class[2] 0x4808B0 -> getter 0x487D80 -> [0x4A6398 + tag*4]
0x480B90 -> class[3] 0x480880 -> getter 0x487820 -> [0x4A5460 + tag*8]
0x480B90 -> class[4] 0x480900 -> getter 0x482690 -> [0x4A43E0 + tag*8]
