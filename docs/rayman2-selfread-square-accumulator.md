# Rayman 2 — type `0x170` reads a module DWORD, squares it, and accumulates 64 bits

**14 November 2026 — read-only research, no executed DRM, no decrypted game.**

## Sample provenance

| Sample | Bytes | SHA-256 |
|---|---:|---|
| Original CD-sourced `Rayman2(3).exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Separately modified GOG `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

The audit verifies the *exact* owner files via SHA-256 before inspection; only metadata, code addresses, and structural facts are emitted. GOG is **not** a pristine retail unwrapping.

## Main new result — unsigned 64-bit square-and-accumulate

The earlier registry audit established that expression type **`0x170`** dispatches to `0x470000`. This handler builds a masked `GetModuleHandleA(NULL)` trampoline on the original CD, while GOG instead loads `0x517000`, the base of its non-executable archive of original retail `.text` bytes. The handler then continues on the same code sequence in both programs. The new audit establishes:

| Original and GOG VA | Opcode-level interpretation |
|---|---|
| `0x47010E` | Compare current expression type to `0x170` |
| `0x470187` | Proceed only if conversion helper `0x4815F0` returned status `1` |
| `0x4701A6` | Invoke typed-object parser `0x480B90` to obtain an address offset |
| `0x4701BC` | `MOV EAX, [EAX+EDX]` reads a **DWORD** at module base plus computed offset |
| `0x4701BA..0x4701C2` | Clear ECX (zero high half), push **two zero-extended copies** of the DWORD |
| `0x4701C3` | Call **`0x4979D0`**, a conventional unsigned 64-bit multiplication helper |
| `0x4701C8` | `ADD ESI,EAX` adds product low DWORD to accumulator low DWORD |
| `0x4701CE` | `ADC EDI,EDX` adds product high DWORD **and carry** to high DWORD |
| `0x4701D9`, `0x4701DD` | Save accumulated `ESI:EDI` as two DWORDs in a temporary value object |
| `0x4701E5` | Set temporary value-object tag **`0x15`** |
| `0x4701ED` | Invoke generic callback dispatcher **`0x481800`** with the temporary object |
| `0x4701F2` | Overwrite EAX return register on the immediate continuation, without directly testing callback EAX |

The multiplication helper at `0x4979D0` takes two unsigned 64-bit arguments and has a fast path (`0x4979E0..0x4979E6`) that uses x86 **`MUL`** if both high halves are zero; both are explicitly zero at the call site. In this context, its exact result is `x * x`, **not** a floating-point approximation or an `IMUL` truncation. The `ADD; ADC` sequence implements:

```text
A = ((EDI << 32) | ESI)
x = unsigned32([module_base + parsed_offset])
A_next = (A + x*x) mod 2**64
```

This is now a **specific checksum-like arithmetic candidate**, more informative than noting that the handler reads the executable. It still does **not** identify a final integrity comparison, expected checksum value, active gameplay object, error path, or positive/negative SafeDisc authentication event. The generic callback may itself have side effects beyond the immediate function; no assertion is made that it is harmless or an anti-tamper function.

## Separate type `0x11B`

Registry type `0x11B` dispatches to `0x47B170` and, at `0x47B2A9`, separately reads one DWORD from `[module_base + parsed_offset]`. It writes a **type-7** result at `0x47B30C..0x47B30E`; the `0x170` handler's *square-and-accumulate* operations are **not present in this `0x11B` branch**. Do not merge the two opcodes into a single apparent checksum.

## Second dispatch: what happens to the accumulated value?

The type-`0x170` handler creates a 16-byte temporary typed result and calls `0x481800`, which obtains a field callback from table `0x4A4278` based on the target object's field-type metadata, then invokes it indirectly at `0x481847`. The separately checked **type-index `0x15`** row in that table contains exactly:

```text
0x15 -> metadata 0x29, callbacks 0x4815A0 and 0x4817B0
```

**Caution:** The temporary value's *output tag* `0x15` should not be automatically equated to the dynamically selected destination field type in `0x481800`. Identifying the actual destination and callback requires a concrete runtime object and its field index.

## Static availability of expression objects and GOG archive bounds

A complete overlapping little-endian DWORD scan of the file-backed `.rdata` and `.data` sections of **both** exact PE files finds **zero `0x00000170` and zero `0x0000011B` DWORD literals**. This means these ordinary non-code sections do not contain an uncompressed literal of either exact type, **not** that the game has no such objects. Objects may be read from external `*.DAT`, compressed/encoded, constructed dynamically or represented differently. The two exact executables do not provide the needed runtime object data.

GOG's archive contains a faithful original `.text` copy at offsets corresponding to original module RVAs **`0x1000` up to but excluding `0x9B200`**. A parser-produced offset outside this interval is **not guaranteed** to see the original live process's bytes when using base `0x517000`. The observed active-data mapping strongly supports preservation of *code-specific self-reads*, but a runtime trace of the sampled offsets is necessary before claiming complete equivalence for arbitrary offsets.

## Reproduction and limitations

```sh
python scripts/rayman2_selfread_square_accumulator_audit.py \
  --retail /private/Rayman2-CD.exe --gog /private/Rayman2-GOG.exe
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

New script imports only standard Python modules plus the existing `rayman2_selfread_archive_audit.py` helper. It checks **23 opcode anchors** and **3 rel32 destinations in each executable**, registry type `0x170`, distinct type `0x11B`, the `0x15` callback row, literal-type absence in ordinary file-backed non-code sections, and the entire GOG `.extra` archive mirror. The new **18 tests** include 10,000 independent modulo-`2**64` numerical comparisons, deliberately corrupted instruction, registry and archive inputs, and exact original-file integration.

**Actual local results: 18/18 new tests and 193/193 total tests pass.** These are read-only tests performed on the owner's exact binaries; no game was executed, no SafeDisc driver was inspected in memory, no physical-CD C2 authentication was measured, and no Windows executable was patched, rebuilt, or distributed.

**Highest-value next experiment:** with the same edition's `*.DAT` game data, locate objects using opcode `0x170` and the typed parser-generated offsets, then observe whether the 64-bit accumulated result is compared to an expected constant. An alternative is narrowly scoped, read-only debugger tracing of `0x4701BC`, `0x4701C3`, and `0x4701ED`, including the runtime callback and field-type metadata. A changing 64-bit accumulator alone is **not** proof of anti-piracy verification.