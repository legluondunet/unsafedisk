# Rayman 2 — registry-based expression dispatch and the type `0x11B` original-code read

**14 November 2026.** Read-only, reproducible PE32/x86 research. The original CD-sourced game is **not yet unwrapped**. GOG is a separately modified comparator and must not be treated as a pristine decrypted retail executable.

## Exact inputs

| Reference | Bytes | SHA-256 |
|---|---:|---|
| CD-sourced `Rayman2(3).exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

The integrated audit opens each file with a bounded, exact-SHA-256 reader before parsing. It emits **only metadata**, not executable code/data sections or a changed binary.

## Newly recovered dispatch chain

The expression engine uses **two distinct typed-operation registry tables**. The first table examined here at **VA `0x4A5460`** has eight-byte records: a **DWORD function VA** followed by a **DWORD flag**. At `0x487820`, `MOV EAX,[EAX*8+0x4A5460]` retrieves the handler, while `0x487810` reads the low byte of its flag at `[EAX*8+0x4A5464]`. The wrapper at **`0x480880`** calls `0x487820`, then invokes the returned handler through `CALL EAX` at `0x48089E`.

Separately, the typed-object parser at **`0x480B90`** reads a byte discriminator from `[object+7]` and calls through its own pointer table at **`0x4A4180`**. **Entry 3** in that table points to `0x480880`, thereby linking one byte-discriminator path to the eight-byte registry. A byte-type value of 3 and a registry opcode are different fields; do not conflate them.

Twelve registry rows `0x110` through `0x11B` (addresses `0x4A5CE0..0x4A5D38`) were mapped **from `.data` RVA**, independently on both PE files; all 12 pointer/flag pairs are **identical**:

| Registry type | Handler | Flag | Interpretation |
|---|---|---:|---|
| `0x110` | `0x47AE10` | 1 | Another handler, not analyzed here |
| `0x111` | `0x47AEB0` | 0 | Another handler, not analyzed here |
| `0x112` | `0x47B0E0` | 1 | Separate handler with arithmetic/PRNG path |
| `0x113`, `0x114`, `0x115` | `0x47B170` | 0 | Shared expression handler |
| **`0x116`** | **`0x47B340`** | 0 | **Separate unary bitwise-NOT handler** |
| `0x117`, `0x118`, `0x119`, `0x11A` | `0x47B170` | 0 | Shared expression handler |
| **`0x11B`** | **`0x47B170`** | 0 | **Special module-image DWORD-read branch** |

The `0x11B` record starts at `0x4A5460+8*0x11B = 0x4A5D38`, and has the exact pointer `0x47B170` in **both** files.

In the shared handler, `0x47B185` loads the registry opcode from `[input-8]` into EBP, and `0x47B29B` compares it to `0x11B`. Only on that branch does `0x47B2A9` read a DWORD from `[module_base+parser-derived_offset]`; the common tail at `0x47B30C` writes the result and at `0x47B30E` marks the typed result as 7. This is a **conditional, object-defined read**, not a fixed hard-coded checksum address and not a demonstrated runtime anti-tamper verdict.

## Second type registry identifies the other archived-code read

Another 8-byte `{function VA, flag}` registry begins at **VA `0x4A43E0`**. The independent accessor at `0x482690` uses `MOV EAX,[EAX*8+0x4A43E0]`, and wrapper **`0x480900`** calls it at `0x480909`, then performs **`CALL EDI` at `0x480926`**. This is a *separate dispatch table*, not an alias of the `0x4A5460` registry above.

Five original and GOG entries were checked at their exact section-backed PE virtual addresses:

| Registry type | Record VA | Handler | Flag |
|---|---|---|---:|
| `0x16E` | `0x4A4F50` | `0x46FF90` | 0 |
| `0x16F` | `0x4A4F58` | `0x472F90` | 0 |
| **`0x170`** | **`0x4A4F60`** | **`0x470000`** | **1** |
| `0x171` | `0x4A4F68` | `0x470210` | 0 |
| `0x172` | `0x4A4F70` | `0x4708B0` | 0 |

The `0x470000` handler checks the opcode `0x170` at **`0x47010E`**, and has a later conditional `MOV EAX,[EAX+EDX]` at **`0x4701BC`** in its typed-value handling path. The original code obtains its module base through an obfuscated `GetModuleHandleA(NULL)` trampoline; GOG changes `0x470051` to `MOV EAX,0x517000; JMP 0x4700B3`. At `0x4700B7`, GOG additionally inserts `JMP 0x47010E`, bypassing the original PRNG-based overwrite of the temporary trampoline.

Both `0x170` and `0x11B` are recognised *registry opcodes*, but **in different registries**, associated with different functions. The fact that they can read a DWORD relative to an archived module base does not show that they run in the same session, read identical offsets or implement one specific checksum. The source of the 32-bit offset, its bounds, and downstream use still need real object data or runtime observation.

## Downstream callback trace from opcode `0x170`

The `0x470000` handler's success gate is a **`CMP AL,1; JNE` at `0x470187`**, after the indirect callback machinery at `0x4815F0`. If that gate is satisfied, the handler continues via an indexed DWORD read at `0x4701BC` and invokes **`0x481800` at `0x4701ED`**. Following `0x481800` shows another **generic table-driven callback dispatch**: its helper `0x481860` resolves a function pointer through the table at **`0x4A4280`**, which is finally called indirectly through `CALL EAX` at `0x481847`. The adjacent helper `0x481850` reads a parallel table at `0x4A427C`. The x86 instructions at all **nine** checked secondary sites are **byte-identical** in CD and GOG.

This establishes a concrete code path and a *nontrivial success gate*, but **does not establish that the gate is a SafeDisc checksum, that the indexed read validates executable integrity, or which callback is selected by real game data**. Further analysis would need both runtime object identity and the concrete selected callback.

## Important correction to the previous eight-way table

The shared handler `0x47B170` contains a local eight-way jump table for `0x113..0x11A`. Its local case for `0x116` yields the initialized zero value. **This does not mean the normal engine dispatch for registry type `0x116` yields zero.** The actual registry routes that type to a *different* handler, `0x47B340`, whose final operation at `0x47B460` is **`NOT EDX`** and which produces a type-7 result. The eight-way table previously reported must therefore be labelled *local to `0x47B170`*, not a canonical mapping of all registered expression types. Whether that local zero case is reachable through a nonstandard route is not established.

## GOG modifications in all three relevant handlers

1. The CD's `0x470000` handler corresponds to registry type `0x170`; GOG replaces its obfuscated module-base lookup at `0x470051` with `MOV EAX,0x517000; JMP 0x4700B3`, and skips temporary-trampoline overwriting at `0x4700B7`. The later indexed DWORD read at `0x4701BC` is unchanged.
2. The CD's `0x47B170` handler builds an obfuscated `GetModuleHandleA(NULL)` trampoline. GOG replaces the code at `0x47B1C3` with `MOV EAX,0x517000; JMP 0x47B225`, thus passing the archived retail `.text` image base as data rather than dynamically obtaining the active module. **GOG also changes `0x47B229` to a short jump to `0x47B280`, bypassing the original trampoline's PRNG-based 15-byte overwrite loop**. The actual conditional read at `0x47B2A9` is unchanged.
3. In the CD's **separate** unary `0x116` handler at `0x47B340`, the code also builds and invokes an obfuscated module-handle trampoline. GOG changes `0x47B388` to a direct relative jump to `0x47B441`, bypassing that preparation. The final unary `NOT EDX` and type-7 result store at `0x47B460` onward are **unchanged**. This is a second, separately verified PRNG-generation bypass, **not** evidence that the NOT operation itself is part of SafeDisc.

These are **five exact branch/opcode differences verified independently in the original and GOG active `.text`**. The unchanged parser/registry instructions were also anchored at **30 sites** in both files. The existing archival `.extra` audit separately checks byte-identical original `.text` and non-executable section properties; this new audit builds on that evidence.

## Reproduce and limitations

```sh
python scripts/rayman2_expression_registry_audit.py \
    --retail /private/Rayman2-CD.exe \
    --gog /private/Rayman2-GOG.exe
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

In the local research directory, **13/13 new tests passed**, including full integration with the two exact binaries and deliberate corruption of a GOG registry pointer, GOG trampoline branch and a shared dispatch instruction; the complete suite passed **175/175 tests**. Synthetic registry-format tests and real-sample checks are both present. No GitHub Actions workflow or Windows/Wine gameplay was executed, no physical-CD authentication captured, and no modified game executable was produced.

**Next discriminator:** identify real game objects carrying registry type `0x11B` and the parser-derived RVA, then follow the downstream type-7 value to an actual compare/failure branch. Read-only gameplay tracing or access to actual original game data is required before treating the byte read as an integrity check. It would be unsafe to disable the generic interpreter or unary NOT handler.