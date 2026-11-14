# Rayman 2 — classes 5–40 of the generic typed-object interpreter

**14 November 2026. Static x86/PE32 research; neither a SafeDisc decrypter nor a runtime trace.** This study continues the [first five object-dispatch families](rayman2-five-object-dispatch-families.md) and the [type `0x170` self-read accumulator](rayman2-selfread-square-accumulator.md). Only the two owner-supplied SHA-256-pinned sample executables were read:

| Input | Bytes | SHA-256 |
|---|---:|---|
| CD-sourced `Rayman2(3).exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| GOG comparison `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

GOG is a **separately edited** game, not an authenticated clean, unwrapped CD copy.

## 41 byte-class dispatcher entries: the remaining 35 are not all complex

The byte-class dispatch table at VA **`0x4A4180`** has 41 valid entries, indexed 0–40. The 35 entries indexed **6–40** point into the code span `0x480220..0x4807FF`. This span is 1,504 bytes and is *exactly identical* in CD and GOG (SHA-256 `028b75a304843ed411f05ef284914992220d7728de3e180a078f30f82c95d69f`). The following `0x480800..0x480BAF` span, including the class 5 handler `0x480A50` and common parser `0x480B90`, is another **944 identical bytes** (SHA-256 `dcf64fe7acdbbe5493ee1823745ba07e12dddab4dc32d2563faa4f18d82efc16`). The 164-byte pointer table is SHA-256 `c5b610b43699e6e64e75a171968d5aa35ca20a260a1082ef4fbc0ea96543f7b3` in both.

- **24/35 class slots** use the *same exact 23-byte opcode template* (with one different literal per distinct handler): `MOV EAX,[ESP+8]; MOV ECX,[ESP+12]; MOV EDX,[EAX]; MOV DWORD [ECX+12],type; MOV [ECX],EDX; ADD EAX,8; RET`. These are simple DWORD-to-typed-result decoders, not checksum routines in the observed instructions.
- The other **11/35 class slots** use nine distinct handlers (some shared between adjacent byte classes). All 35 class slots refer to **32 distinct handler addresses**. The 24 simple slots account for 23 distinct 23-byte functions; the 11 special slots account for nine more.
- The **class 5** handler (`0x480A50`) is handled separately because it is a context-dependent, multi-branch parser, **not** a simple indexed typed-result function.

### All 24 simple class identifiers and their resulting type tags

| Byte class → output type | Byte class → output type | Byte class → output type |
|---|---|---|
| 12 → `0x06` | 13 → `0x08` | 14 → `0x19` |
| 18 → `0x16` | 19 → `0x17` | 20 → `0x09` |
| 21 → `0x1C` | 22 → `0x20` | 23 → `0x0B` |
| 24 → `0x18` | 25 → `0x1E` | 26 → `0x0A` |
| 27 → `0x24` | 28 → `0x22` | 29 → `0x16` |
| 30 → `0x21` | 31 → `0x1D` | 32 → `0x26` |
| 33 → `0x25` | 34 → `0x27` | 35 → `0x28` |
| 36 → `0x2A` | 37 → `0x2B` | 38 → `0x2C` |

Classes **18 and 29 share exactly the same function** at `0x4805F0`; no separate decoder exists for their two class entries.

### The other 11 class slots

| Byte class | Handler | Opcode-observed behaviour |
|---|---|---|
| 6, 7 | `0x4806F0` | Returns numeric zero as type `0x14`, advancing eight bytes |
| 8 | `0x4806D0` | Writes numeric `0x10` as type `0x14`, **returns input cursor unchanged** |
| 9 | `0x4803D0` | Calls generic validator `0x487CF0`; on a false return it calls common error helper `0x480FB0` |
| 10, 11 | `0x480400` | Calls generic converter `0x4815F0` on an input byte |
| **15** | `0x4805A0` | Copies **three DWORDs** from an object referenced in the input and marks the result **type `0x15`** |
| **16** | `0x480510` | Makes **three nested calls to `0x480B90`**, assembles three DWORDs and marks the result **type `0x15`** |
| 17 | `0x480630` | Loads a **16-bit word** with zero extension; marks it type `0x1A` |
| 39 | `0x480220` | Complex nested/stateful handler using `0x4826A0` and `0x480BD0` and error/status checks |
| 40 | `0x4807F0` | Moves the input cursor forward eight bytes and returns, without a typed output write in this eight-byte function |

**Interpretation of `0x15`:** The previous type-`0x170` self-read code forms a temporary result tagged `0x15`, but classes **15 and 16 independently construct tag `0x15` values** from three regular 32-bit components. The tag therefore **cannot be specific to SafeDisc**. Its original engine name and the semantic meaning of the numeric components remain unproven; no anti-piracy interpretation should be imposed on the shared type tag.

## Stateful class 5 is not a static registry lookup

The class-5 pointer is `0x480A50`. That function accesses mutable engine globals at `0x4B9C1C`, `0x4B9C20`, `0x4E939C`, and `0x4E939A` and calls helpers such as `0x4826E0`, `0x480A30`, `0x482870`, `0x482730`, `0x482760`, and `0x4809E0`. It checks two context-dependent conditions at `0x480A9A` and `0x480B35`; on its observed fallback at `0x480B6B` it calls `0x480FB0` and produces a zero result tagged `0x14`. These operations are typical of stateful interpretation/validation, **not independently identified SafeDisc rejection logic**. The helper at `0x480FB0` performs a common diagnostic/error call through `0x402810`. An independent original/GOG instruction-site inventory finds **59 direct `E8 rel32` calls to `0x480FB0` in each executable, at exactly the same 59 VAs**; all instructions were checked against their backing PE bytes. This includes calls at `0x4803F2` (class 9), `0x480B6F` (class 5 fallback), and `0x47011A` (unexpected type in `0x170` handler). Consequently, a call to this routine is **not specific to SafeDisc** and is not evidence by itself of an authenticity failure.

The common dispatcher at `0x480B90` reads a class byte at `[record+7]` and performs an indirect call through `0x4A4180+class*4`. **There is no local comparison against 40 in this tiny dispatcher.** This does not prove that malformed class indices occur in authentic resources, or that earlier resource-loading code fails to validate them.

## Reproduction and what remains missing

The new standard-library Python analysis tool `scripts/rayman2_remaining_object_classes_audit.py` performs strict SHA checks through the existing helper, checks all three complete code/table span hashes, 23 opcode anchors and 15 direct call destinations, classifies every 6–40 table entry, and crosschecks CD/GOG equality. Its paired tests check the instruction template, expected class/handler relationships, real-file integration and deliberate in-memory mutations. **24/24 new tests and 296/296 research tests passed locally.** The owner's proprietary binaries are only read as local inputs; nothing is patched, loaded into Windows/Wine or distributed.

We now understand the structure of the **entire 0–40 byte-class dispatch table** at this static level, but **not** the authentic source of type-`0x170` object records. Neither the relevant `LEVELS0.DAT` content, a live type-`0x170` object, a comparison against a reference checksum, a proven disc-authentication error, nor a runnable decrypted retail binary has been obtained. The next decisive experiment needs an authentic resource stream or a narrowly scoped, passive runtime trace of `(class, tag, offset, resulting type, consumer branch)`; do **not** replace or disable the generic interpreter based on these findings.
