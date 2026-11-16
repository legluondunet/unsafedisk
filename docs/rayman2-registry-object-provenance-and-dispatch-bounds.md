# Rayman 2 — provenance of object type `0x170` and complete static dispatch-table boundaries

**14 November 2026. Read-only, exact-SHA-256-locked x86/PE32 audit.** These findings describe only the owner's two exact executable files. The separate GOG build is a modified reference, *not* a clean retail-unwrapped executable. There was no game execution, runtime object capture, physical-CD C2 error record, SafeDisc decryption, or patch of any commercial code.

| Role | Bytes | SHA-256 |
|---|---:|---|
| Original CD-sourced EXE `Rayman2(3).exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG comparator `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

## Discovery 1: first function registry has 514 consecutive, valid pointer-and-flag records

The first type registry begins at original virtual address **`0x4A43E0`**, with a stride of **8 bytes**: a DWORD handler address followed by a DWORD that is `0` or `1`. Static inspection of **514 consecutive entries** (`0x000..0x201`) finds:

| Observation | Result (CD and GOG, independently) |
|---|---:|
| Valid contiguous registry records | **514** |
| Distinct handler addresses | **159** |
| Flag value `0` | **215** |
| Flag value `1` | **299** |
| Handler `0x470000` occurrences | **1**, only row `0x170` |
| Type `0x170` entry | **`(0x470000, 1)`** |
| Neighbor type `0x171` entry | **`(0x470210, 0)`** |
| SHA-256 of 4,112 record bytes | `b6cbd675c8faa32c8f94631d81e6ebcb3321365893ac8adf8e3fe209075fb41a` |

The flag itself does **not** identify a SafeDisc-only entry: **299** types have flag `1`, and the reader at `0x482680` is called at **68 separate direct instruction sites** (all unchanged in GOG). The semantics of the flag have not been established from these counts.

**Why stop at 514?** Immediately after entry `0x201` (VA **`0x4A53F0`**), the 112 bytes up to the *other* registry at `0x4A5460` are **seven 16-byte constant blocks**, not plausible function/flag pairs. Each starts with the identical 12-byte constant prefix and ends with a DWORD 0 (except block index 5 with DWORD 1). This is a validated on-disk boundary and prevents confusing numeric data with 14 extra handlers. These numbers **do not establish a runtime-checked maximum ID**; the lookup `0x482690` itself indexes by type ID without an immediately adjacent bounds check.

- Full record table SHA-256 is identical in CD and GOG.
- The 112-byte numeric separator SHA-256 is identical: `b16f973515e4ce20338a0d7d87aff735b5786b68cc25553112dbf376ad1b75f6`.
- The loader/engine may validate IDs before calling `0x482690`; a local bounds check at this particular lookup is not required to be the only validation mechanism.

## Discovery 2: the byte-class parser contains **41**, not just 16, function-pointer entries

The generic object evaluator `0x480B90` executes a dispatch through **`CALL DWORD PTR [class*4 + 0x4A4180]`**, where `class` is read from **`[object+7]`**. An earlier focused study inspected only the first 16 pointers. The complete consecutive table contains:

| Property | Exact result |
|---|---|
| Table base | **`0x4A4180`** |
| Consecutive function pointers | **41**, class IDs `0..40` |
| Distinct handler addresses | **38** |
| Class `2` | `0x4808B0` |
| Class `3` | `0x480880` |
| First following DWORD | **zero** at `0x4A4224` (class index 41) |
| Table SHA-256 (164 bytes) | `c5b610b43699e6e64e75a171968d5aa35ca20a260a1082ef4fbc0ea96543f7b3` |

All 41 pointer DWORDs, their SHA-256, and the following zero DWORD are identical in the CD and GOG input. After the zero DWORD, the following bytes are other data. **This demonstrates the complete contiguous on-disk sequence; it does not prove the runtime parser's input class byte always falls within `0..40`.** No such claim should be made until authentic resource inputs are tested or observed.

## Discovery 3: the `0x170` handler takes a data record, optionally resolves a nested record, then uses generic engine helpers

The original handler beginning `0x470000` is registered only for type ID `0x170` in the 514-entry table. The concrete chain in **both CD and GOG active `.text`** is:

1. **`0x470032`**: `MOV EBP,[EBX-8]` loads a type ID **eight bytes before** the current data cursor.
2. **`0x47010E`**: `CMP EBP,0x170` followed by a conditional branch at `0x470114` to the handled path.
3. **`0x47012C`**: `CMP BYTE PTR [EBX+7],2` selects an optional nested decoding path.
4. **`0x470140`**: for this class-2 case, `CALL 0x481C10` performs additional data/record resolution. In turn, **`0x481C23`** calls the generic evaluator `0x480B90`, and **`0x481C35`** calls the unrelated helper `0x4136D0`. The routine returns a revised cursor and writes an output word.
5. **`0x47017F`**: `CALL 0x4815F0` attempts conversion and **`0x470187`** requires `AL==1` to proceed.
6. **`0x4701A6`**: `CALL 0x480B90` calculates the offset; **`0x4701BC`** performs the module-image DWORD load. Subsequent instructions square the result, accumulate 64 bits, and use **`0x4701ED`** to pass a typed result to generic dispatcher `0x481800` (documented independently).

The nearby **`0x11B`** handler obtains its type ID using the same relative layout: `MOV EBP,[EAX-8]` at `0x47B185`, followed by a `CMP EBP,0x11B` at `0x47B29B`. Both tags therefore belong to a data-driven expression/record system. They need **not** be present as immediate DWORD literals in code outside their respective handlers.

**Independent generic reuse evidence:** GNU `objdump` recognises **15** direct instruction-boundary calls into `0x481C10`, **757** into `0x480B90`, **68** into the generic flag reader `0x482680` and **one** into the function registry reader `0x482690` in active `.text` in each build, and all those locations are identical between the two builds. Every direct `E8 rel32` instruction byte was revalidated. These are static sites, not runtime frequencies or a complete call graph.

In both PE files, there are **zero literal DWORD `0x170` and `0x11B` matches in the on-disk `.rdata` and `.data` raw sections**. This is only a statement about these two specific sections; type IDs might be generated, encrypted, read from external resources, or instantiated dynamically. It **does not prove** that `0x170` is unused or that SafeDisc enforcement is absent.

## GOG compatibility differences, not proof of an integrity verdict

The original handler `0x470000` synthesizes a masked call to `GetModuleHandleA(NULL)` for its module base. GOG instead substitutes an address in the archived retail-code `.extra` section and bypasses the temporary trampoline generation. The **object tag check, nested parser, 41-pointer parser table, 514-pointer type table, offset evaluator, DWORD read, 64-bit sum of squares and typed-result dispatch remain part of the game code**. The parallel handler `0x47B170` (type `0x11B`) has an analogous substitution. These GOG modifications do **not** certify a complete SafeDisc removal recipe for the original executable.

## Reproduce

```sh
python scripts/rayman2_registry_object_provenance_audit.py \
  --retail /private/owner/Rayman2-CD.exe \
  --gog /private/owner/Rayman2-GOG.exe
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

The audit authenticates the two inputs by exact SHA-256 and length, validates PE32 section-backed addresses, 24 shared opcode anchors, six direct call targets, both complete data tables and their expected SHA-256 hashes, the boundary constants, and the complete 15/757/68/1 direct-call-site inventories by GNU `objdump` plus independent raw `E8 rel32` calculation. **24 new tests, 243/243 local suite tests passed**; the integration tests are skipped if the user-owned executable files are unavailable to the runner. No GitHub Actions CI, Wine runtime game execution, compiled Rust artifact or original-CD raw-sector capture occurred.

**Next genuinely discriminating observation:** capture *real object data* for a `0x170` record and its parser-dispatched offset (and the later typed-result consumer) from authentic Rayman 2 resources or a strictly read-only runtime trace. Without that, the existence of a sum-of-squares function and its dispatch is **not** sufficient to identify a checksum reference value, failure branch, or working SafeDisc decryption.
