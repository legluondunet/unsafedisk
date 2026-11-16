# Rayman 2 — typed expression evaluator and conditional module-image DWORD read

**14 November 2026. Read-only binary research on the exact SHA-256-identified original CD and GOG executables.** GOG is a separately modified comparator, not a pristine decrypted original. This audit executes neither executable, changes no proprietary bytes, and does not claim to decrypt SafeDisc.

## New result

The previously identified GOG `.extra` module-base substitution at `0x47B1C3` feeds a **conditional typed-value evaluator**, not a single fixed checksum read. The same x86 code at `0x47B288..0x47B31A` is present in the original and GOG active `.text`. Its byte window SHA-256 is `8c228690fb8ff717f77a606a4df2e37e3cb0519deebefebb6fcf8dc5b5d3844b` in both builds.

The path uses `0x480B90` twice to dispatch object values according to a one-byte type field at `[object+7]`, with handler table at `0x4A4180`. The first dispatch supplies an offset in a stack out-parameter, retrieved at `0x47B294`.

A `CMP EBP,0x11B` at `0x47B29B` selects a special case. For that case, `0x47B2A5` loads a module base from `[ESP+0x10]` and `0x47B2A9` reads `EBX=[EDX+ESI]`, where `ESI` is the parser-derived offset. In the original CD path, the base comes from a dynamically built call equivalent to `GetModuleHandleA(NULL)`; in GOG, the base is explicitly replaced with `0x517000` (the non-executable `.extra` archive of original `.text`). The offset's runtime range, actual object identity and whether the branch executes in real gameplay remain **unknown**.

For other type codes, the evaluator subtracts `0x113` from the type and branches through eight DWORD entries at `0x47B31C`. The table is byte-for-byte identical in CD and GOG:

| Object type | Table destination | Operation on two 32-bit operands |
|---|---|---|
| `0x113` | `0x47B2D1` | XOR |
| `0x114` | `0x47B2D7` | AND |
| `0x115` | `0x47B2DD` | OR |
| `0x116` | `0x47B305` | Retain the previously zero-initialized result **in this local eight-way switch only**; ordinary registry dispatch uses another handler (see note below) |
| `0x117` | `0x47B2E3` | Unsigned division, faults on zero divisor |
| `0x118` | `0x47B2EF` | 32-bit multiplication |
| `0x119` | `0x47B2F6` | Addition modulo `2^32` |
| `0x11A` | `0x47B2FF` | Subtraction modulo `2^32` |

**Clarification (new independent registry audit):** this is a switch *inside* the shared handler `0x47B170`, not a complete enumeration of the normal engine handlers. The actual type registry at `0x4A5460` selects the **separate unary NOT handler `0x47B340` for type `0x116`**, while type `0x11B` selects `0x47B170` and the self-read branch. The earlier wording could incorrectly imply that a normally dispatched `0x116` expression returns zero. The corresponding original/GOG dispatch and five redirects are now verified in [the full registry audit](rayman2-expression-registry-and-typed-selfread.md); see also the second registry base `0x4A43E0` for `0x170 → 0x470000`.

An unsigned bounds check at `0x47B2C5..0x47B2C8` ensures the jump table covers only values 0..7 after subtraction. The common tail writes a 32-bit result at `0x47B30C` and a value-type tag `7` at `0x47B30E`; **no checksum-equality verdict is visible in that tail**. The original section outside this immediate tail, indirect callers, object provenance, or eventual consumers may impose additional meaning.

## Consequence for DRM research

The read of the image's own bytes is a concrete potential mechanism by which GOG can present unmodified retail code to a *self-reference* in an otherwise modified build. However, the surrounding code's **generic typed-expression operation table** argues against automatically declaring this path itself to be a dedicated SafeDisc checksum. The same evaluator also performs arithmetic and logical operations not intrinsically linked to DRM. A downstream comparison of the returned type-7 value with an expected reference and a demonstrable failure path would be required to identify a specific anti-tamper check.

In particular, **do not patch or suppress** `0x480B90`, the eight-way switch or the `0x11B` case on the basis of this static observation alone. Such changes could break ordinary engine expression evaluation.


## Scope of the archived image and limitation on offsets

The non-executable GOG `.extra` copy is exactly `0x9C000` bytes long. Its first `0x1000` bytes are **zero** (unlike the original CD image, whose first two bytes are `MZ`). Original CD `.text` occupies RVA `0x1000..0x9B1FF` in raw file-backed bytes and is identically mirrored at those same offsets from GOG's substitute base `0x517000`. The trailing `0xE00` bytes of `.extra` are zero. The original PE `.rdata` begins at RVA `0x9C000` and `.data` at RVA `0x9F000`, **outside the archive's extent**. Thus `.extra` is **not a complete PE module view**: it cannot generally substitute for real module-base reads of headers, imports, `.rdata` or `.data`.

The conditional typed `0x11B` read becomes equivalent to reading original code only if the dynamically computed offset falls within the mirrored `.text` interval (and the read does not cross its boundary). **No actual runtime offset has been measured**, so do not infer that every module-base read is satisfied by this mapping, let alone that a self-integrity check passed.

## Reproduction

```
python scripts/rayman2_typed_selfread_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/Rayman2.exe'
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

The new script verifies both known SHA-256 inputs before analysis, reads section-mapped PE32 instructions without executing them, checks **25 opcode anchors**, validates all eight table destinations, and produces only structured metadata. Nine new targeted tests (including a real-sample integration test, negative corrupted-instruction test, division-by-zero case, type bounds and 32-bit wraparound) passed. The complete local research test suite passed **162/162** tests. No CI, Windows/Wine game execution, Rust compilation, or executable unwrapping was performed.

**Next experiment:** trace the original object type and byte offset returned by `0x480B90` for `type 0x11B`, and identify downstream consumers of its type-7 value with read-only instrumentation or a fully grounded call graph. Source-code and byte-level comparison is insufficient to infer the physical-disc/SafeDisc authentication outcome.