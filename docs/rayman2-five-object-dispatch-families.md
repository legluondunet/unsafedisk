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
```

Both `CALL E8 rel32` instructions selecting a getter and `CALL register` instructions running the returned function are checked against their **actual PE bytes** at their exact VAs. The table getters are each only 12 bytes long (`MOV EAX,[ESP+4]`, `MOV EAX,[EAX*scale+table]`, `RET`) and are independently checked byte-for-byte, including scale 4 versus 8.

**Important correction of scope:** The previous audit had completed only the class-4 514-record registry and the byte-class dispatch array. We can now confirm the separate **class-3 314-record** array, the **class-0 20-pointer** array, the **class-1 149-record** array and the **class-2 28-pointer** array. These are **maximal adjacent spans matching the stated pointer/flag pattern** before explicit nonfunction data. This is **not** a demonstrated runtime-enforced maximum index; no per-lookup bounds test was found in these tiny getter functions. Invalid record indices could read nearby data. The caller or resource loader may enforce bounds elsewhere.

### Why the old broader table boundaries were misleading

The four newly delimited arrays each terminate in other data, including repeated 16-byte numerical blocks beginning with a recognizable floating-point constant pattern. The **class-3 table** terminates at `0x4A5E30` and has **80 bytes** of nonhandler values; this interval also includes path-like text, so it should not all be called a numeric table. The class-0, -1 and -2 arrays each have exactly **16 trailing bytes** before the next table. Including those bytes as function entries yields impossible virtual addresses or metadata flags outside 0/1, even when the layout looks superficially regular.

## Stronger meaning for the prior `0x170` / `0x11B` result

The prior independent type registry showed:

- **Class 4:** the `0x170` tag selects `0x470000` through table `0x4A43E0` (`[0x4A43E0 + 0x170*8]`). The wrapper `0x480900` advances the cursor by eight bytes, which precisely explains why the handler reads the current object's tag at `[cursor-8]`. It then computes the 64-bit sum-of-squares result using a later nested expression; the comparison to any reference checksum remains **unproven**.
- **Class 3:** the `0x11B` tag selects `0x47B170` through table `0x4A5460` (`[0x4A5460 + 0x11B*8]`). The wrapper `0x480880` also advances the cursor by eight bytes. This establishes that the two module-read routines belong to **different byte classes and different function registries**, rather than two entries in one registry.

The names `class` and `tag` are structural reverse-engineering labels, not original source names. The `decode_object_header` helper checks a synthetic 8-byte header, producing a **proposed static route only**. There are currently **no authentic serialized records** proving real level data ever instantiates either tag.

**Class 5 is different:** its parser pointer at `0x4A4194` is `0x480A50`, which enters context-dependent logic and uses global state (`0x4E939C`) and other generic helpers. The new audit explicitly **does not** misrepresent that branch as another static indexed handler table. The remaining classes 6–40 have not been mapped to corresponding registries in this audit, although the parent 41-entry parser table itself is authenticated.

## Verification and boundaries of the conclusion

The new standard-library Python script `scripts/rayman2_five_object_dispatch_audit.py` checks input sizes and exact SHA-256, PE section mappings, all five tables and their trailing regions by pinned SHA-256, the parent 41-entry dispatch-table hash, the exact wrapper and getter instruction sequences, computed `E8` call targets and the two known type tags. It emits **summary metadata only**, never executable bytes or reconstructed game instructions. Its 29 tests cover genuine local owner inputs, synthetic data structures and deliberate in-memory mutations of table pointers, trailers and opcode bytes.

**Local results: 29/29 new tests; 272/272 across the research test modules.** No game executed, no CI/Windows/Wine runtime validation was performed, no file was patched, and no proprietary binary was committed. GOG remains a modified reference rather than a trustworthy clean unwrapped CD executable.

Next discriminating task: identify the authentic **resource record container** that can carry class 4 / tag `0x170` or class 3 / tag `0x11B`. A passive record trace should log `(byte class, 32-bit tag, cursor offset, selected handler, resulting typed value)` and any downstream conditional branch, while **excluding raw game-data bytes from logs**. Without such evidence, do not claim an observed SafeDisc checksum, a bypass, or a native Rayman 2 decryption.
