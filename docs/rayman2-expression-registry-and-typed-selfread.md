# Rayman 2 — registry-based expression dispatch and the type `0x11B` original-code read

**14 November 2026.** Read-only, reproducible PE32/x86 research. The original CD-sourced game is **not yet unwrapped**. GOG is a separately modified comparator and must not be treated as a pristine decrypted retail executable.

## Exact inputs

| Reference | Bytes | SHA-256 |
|---|---:|---|
| CD-sourced `Rayman2(3).exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

The integrated audit opens each file with a bounded, exact-SHA-256 reader before parsing. It emits **only metadata**, not executable code/data sections or a changed binary.

## Newly recovered dispatch chain

A previously unexamined table at **VA `0x4A5460`** has eight-byte records: a **DWORD function VA** followed by a **DWORD flag**. At `0x487820`, `MOV EAX,[EAX*8+0x4A5460]` retrieves the handler, while `0x487810` reads the low byte of its flag at `[EAX*8+0x4A5464]`. The wrapper at **`0x480880`** calls `0x487820`, then invokes the returned handler through `CALL EAX` at `0x48089E`.

Separately, the typed-object parser at **`0x480B90`** reads a byte discriminator from `[object+7]` and calls through its own pointer table at **`0x4A4180`**. **Entry 3** in that table points to `0x480880`, thereby linking one byte-discriminator path to the eight-byte registry. A byte-type value of 3 and a registry opcode are different fields; do not conflate them.

All twelve registry rows `0x110` through `0x11B` (addresses `0x4A5CE0..0x4A5D38`) were mapped **from `.data` RVA**, independently on both PE files; all 12 pointer/flag pairs are **identical**:

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

## Important correction to the previous eight-way table

The shared handler `0x47B170` contains a local eight-way jump table for `0x113..0x11A`. Its local case for `0x116` yields the initialized zero value. **This does not mean the normal engine dispatch for registry type `0x116` yields zero.** The actual registry routes that type to a *different* handler, `0x47B340`, whose final operation at `0x47B460` is **`NOT EDX`** and which produces a type-7 result. The eight-way table previously reported must therefore be labelled *local to `0x47B170`*, not a canonical mapping of all registered expression types. Whether that local zero case is reachable through a nonstandard route is not established.

## GOG modifications in both relevant handlers

1. The CD's `0x47B170` handler builds an obfuscated `GetModuleHandleA(NULL)` trampoline. GOG replaces the code at `0x47B1C3` with `MOV EAX,0x517000; JMP 0x47B225`, thus passing the archived retail `.text` image base as data rather than dynamically obtaining the active module. **GOG also changes `0x47B229` to a short jump to `0x47B280`, bypassing the original trampoline's PRNG-based 15-byte overwrite loop**. The actual conditional read at `0x47B2A9` is unchanged.
2. In the CD's **separate** unary `0x116` handler at `0x47B340`, the code also builds and invokes an obfuscated module-handle trampoline. GOG changes `0x47B388` to a direct relative jump to `0x47B441`, bypassing that preparation. The final unary `NOT EDX` and type-7 result store at `0x47B460` onward are **unchanged**. This is a second, separately verified PRNG-generation bypass, **not** evidence that the NOT operation itself is part of SafeDisc.

These are **three exact branch/opcode differences verified independently in the original and GOG active `.text`**. The unchanged parser/registry instructions were also anchored at **14 sites** in both files. The existing archival `.extra` audit separately checks byte-identical original `.text` and non-executable section properties; this new audit builds on that evidence.

## Reproduce and limitations

```sh
python scripts/rayman2_expression_registry_audit.py \
    --retail /private/Rayman2-CD.exe \
    --gog /private/Rayman2-GOG.exe
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

In the local research directory, **10/10 new tests passed**, including full integration with the two exact binaries and deliberate corruption of a GOG registry pointer, GOG trampoline branch and a shared dispatch instruction; the complete suite passed **172/172 tests**. Synthetic registry-format tests and real-sample checks are both present. No GitHub Actions workflow or Windows/Wine gameplay was executed, no physical-CD authentication captured, and no modified game executable was produced.

**Next discriminator:** identify real game objects carrying registry type `0x11B` and the parser-derived RVA, then follow the downstream type-7 value to an actual compare/failure branch. Read-only gameplay tracing or access to actual original game data is required before treating the byte read as an integrity check. It would be unsafe to disable the generic interpreter or unary NOT handler.