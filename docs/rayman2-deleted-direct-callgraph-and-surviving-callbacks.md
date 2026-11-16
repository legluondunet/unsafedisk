# Rayman 2 — 11 removed guarded bodies, 16 direct callers, and surviving indirect callback fields

**2026-11-14 — read-only static audit against two exact SHA-256 owner-provided PE32 inputs. No decrypted retail EXE.**

Original CD-sourced Rayman2(3).exe: **676,352 B**, SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
GOG-modified comparison: **1,468,928 B**, SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.
GOG is not a certified pristine retail unwrapping.

This report extends the [28-region guard-registration audit](rayman2-28-guarded-code-ranges.md). It avoids comparing unaligned file offsets and excludes GOG's nonexecuting archival copy in `.extra`. The original executable's active section contains **631,296 raw bytes** starting at RVA `0x1000`.

## 1. Exact original/GOG direct-call graph, including removed callers

Eleven of the previously authenticated guarded function bodies are **entirely filled with `CC` (INT3)** in GOG. Their original function entrypoints, however, have **three different replacement types**, all verified at their precise byte addresses:

| GOG entry code | Original function entries |
| --- | --- |
| 16 bytes beginning `CC CC` | `0x4481B0`, `0x448610`, `0x447D10`, `0x447540`, `0x447730`, `0x447A90`, `0x447AF0`, `0x447BE0` |
| `C3 CC...` (`RET`) | `0x447DE0`, `0x4478A0` |
| `33 C0 C3 CC...` (`XOR EAX,EAX; RET`) | `0x448AB0` |

An exhaustive scan of **raw `E8 rel32` opcode patterns** in the original 631,296-byte `.text` yields **16** candidates targeting these **11 exact original function entry VAs**. Independently, the same 16 sites were observed as `CALL` instruction boundaries in the original GNU `objdump` linear disassembly. The candidate scanner alone is not a complete control-flow graph.

GOG's active `.text` retains **only two** of those 16 direct calls: `0x44947C → 0x4478A0` and `0x44949A → 0x447DE0`. Both destinations are now immediate `RET` stubs. Each of the other **14 former five-byte `CALL` sites is exactly `CC CC CC CC CC`** in GOG. The audit checks all source bytes and recomputes each `E8 rel32` destination.

The 14 removed direct callers are distributed as follows:

- **3** were inside guarded body slot 8 (`0x4478CD..0x447A7B`).
- **3** inside slot 16 (`0x447B18..0x447BD5`).
- **3** inside slot 6 (`0x447E04..0x4481AA`).
- **2** inside partially changed slot 3 (`0x448E04..0x448E27`).
- **3** were outside the 28 previously enumerated guarded spans (`0x447CD7`, `0x448D96`, `0x448DC3`).

These observations show a **coordinated call-chain deletion**, not that replacing just the eleven bodies is a correct portable bypass. An original EXE copied with GOG's INT3 fillings but without its caller edits would be inconsistent.

## 2. Important correction: no direct caller does not mean no active reference

The original function `0x448AB0` has **zero direct `E8 rel32` call sites** and becomes `XOR EAX,EAX; RET` in GOG. **It is *not* necessarily unused**:

- At **`0x4671EB`**, both versions have the exact instruction `MOV DWORD [EAX+0x2C],0x448DE0`.
- At **`0x4671F4`**, both have `MOV DWORD [EAX+0x30],0x448AB0`.
- This same function-vector constructor at `0x467130` is called directly by the original and GOG at **`0x4674C8`** and **`0x47B01B`**.
- At target `0x448DE0`, GOG substitutes **`XOR EAX,EAX; INC EAX; RET`** (return value **1**).
- At target `0x448AB0`, GOG substitutes **`XOR EAX,EAX; RET`** (return value **0**).

Thus GOG preserves two registered callback pointers while changing the corresponding functions to return fixed, *different* values. This is a much stronger candidate for a callback/validation protocol than a purely orphaned function inferred from a direct-call census. The precise semantics (SafeDisc, media check, generic initialization or something else) and whether the objects are used during normal game execution remain **unobserved**.

## 3. Exclude a false indirect consumer; leave the other unclassified

Two original and GOG instruction sites have a code-form calling a `[base+0x30]` field:

- `0x42E087: CALL DWORD [ECX+0x30]`.
- `0x45224F: CALL DWORD [EDX+EDI+0x30]`.

Merely matching the `+0x30` offset **does not establish the object identity**. In fact, near the first site the unchanged code does the following:

```
0x42E074  MOV EDX,[EAX+8]
0x42E077  MOV DWORD [EDX+0x30],0x495890
0x42E082  MOV ECX,[EAX+8]
0x42E087  CALL DWORD [ECX+0x30]
```

So **`0x42E087` does *not* call the preserved `0x448AB0` pointer through that particular object path**: it first overwrites the same object slot with `0x495890`. The second indirect-call site fetches its table base from global `0x4B749C`; its relation to the stack-built vector at `0x467130` has **not** been proven. Do not infer either as an actual SafeDisc verdict.

## 4. Reproduction and next required observation

```bash
python scripts/rayman2_removed_callgraph_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/rayman2(4).exe'
python -m unittest discover -s scripts -p 'test_rayman2_removed_callgraph_audit.py'
```

The analyzer fails closed on unknown input hashes and unexpected section layout, function-boundary classes, caller counts, relative branches, fixed callback stores, GOG 0/1 stubs, vector-constructor callers and the misleading overwritten indirect-call site. It generates metadata only. **8/8 tests passed locally**, including private integration with both exact owner inputs. GitHub Actions can run the public synthetic checks without proprietary game files and skips the optional binary integration.

**Next decisive step:** read-only trace of **which object** is constructed at `0x467130`, where it is stored, whether its **`+0x2C`** and **`+0x30`** fields are invoked, and how their returned statuses are consumed. In parallel, continue watching the separate `0x5113EC` global and the 28 code bounds. Until these dynamic links and any genuine SafeDisc authentication failure are observed, do not patch the 0/1 stubs into retail or distribute a supposedly decrypted game executable.

**Not done:** runtime execution, confirmed Win32/Wine gameplay, CD C2-sector readback, ICD recovery, executable decryption, main-branch merge, release.
