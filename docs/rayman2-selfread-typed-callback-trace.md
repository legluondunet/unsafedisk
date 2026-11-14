# Rayman 2 — type `0x170` is handled by a generic typed-value callback pipeline

**14 November 2026. Exact-file, read-only PE32/x86 audit — no executable patch, code decryption, gameplay trace, DRM authentication or claim of bypass.**

## Input identity and reproducibility

| Input | Exact bytes | SHA-256 |
|---|---:|---|
| Owner-provided retail CD-sourced EXE | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Modified GOG reference EXE | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

Our independently written Python audit combines the previously vetted strict SHA-256 PE reader, in-memory RVA-backed bytes, and **GNU `objdump -d -M intel -j .text`** for active-code **instruction-boundary** discovery. It excludes the archival `.extra` section. Every reported `E8 rel32` call site is then independently checked against the original bytes. The test suite mutates copies of the two inputs **in memory only**.

## Discovery 1: result type `0x15` is a member of a shared six-record family

In both exact PE images, the type record table at `0x4A4278` uses 12-byte records. All **six** type entries `0x12` to `0x17` contain **the same triple**:

| Record values | Exact value |
|---|---|
| First DWORD (metadata) | `0x29` |
| Second DWORD (first callback) | `0x4815A0` |
| Third DWORD (second callback) | `0x4817B0` |

The adjacent table entries `0x11` and `0x18` are different, establishing the six-entry family boundary in this region. This family includes the **type `0x15`** assigned to the temporary object at original `0x4701E5`, after the preceding code has accumulated a 64-bit sum of squares.

**Interpretation:** a value with tag `0x15` does **not** have a unique callback in this table. It is handled by the same generic conversion/assignment functions as the five surrounding types. This strongly reduces the evidence for the interpretation of the callback itself as a *special, dedicated DRM verdict*. It **does not** exclude a later integrity comparison using the value.

## Discovery 2: all 16 same-address calls into the generic value dispatcher remain in GOG

The active-code disassembly contains exactly **16 direct `E8 rel32` calls** to `0x481800` in each sample, all at identical VAs:

```
0x46790D  0x46BBAA  0x46BBFE  0x46F8D7
0x46F95A  0x46FD5C  0x4701ED  0x475AEF
0x475EB9  0x478F66  0x478F91  0x478FC7
0x48243C  0x48AB81  0x48AF49  0x48B543
```

Only **one** of these 16 direct call sites belongs to the particular `0x170` handler (`0x4701ED`). The others establish that the dispatcher is heavily reused by the broader engine. This inventory is for `objdump`-recognised direct calls in active `.text`; it is not a complete dynamic call graph or a runtime call count.

## Discovery 3: how the returned 64-bit result is passed onward

The following instructions are byte-identical at exact VA in both EXEs:

- At `0x4701E1`, the handler stores a pointer/field in the temporary object. At `0x4701E5`, it writes the tag `0x15`; at `0x4701ED`, it calls **`0x481800`**.
- At `0x481800`, the common dispatcher retrieves a property/type-dependent callback through nested in-memory pointers. At `0x481822` it calls helper **`0x481860`**, which indexes the third callback pointer in the 12-byte type metadata table (`[0x4A4280 + 12*type]`). At `0x481847` the dispatcher performs `CALL EAX` through the selected callback.
- The callback **`0x4817B0`** itself performs another type-dependent callback lookup through `0x481860` and dynamically invokes a handler at `0x4817E0` or `0x4817F9` based on a generic metadata/type test.
- The `0x170` handler tail at `0x4701F2..0x470202` restores saved registers, returns its original object pointer and **does not directly compare** the 64-bit accumulated quantity to an expected checksum constant or branch on such a comparison in this tail.

**Important qualifier:** the target type selected inside `0x481800` is read from runtime object/context fields; it is **not necessarily `0x15`** at the first lookup simply because a temporary object carries tag `0x15`. Therefore this report does **not** claim that the generic `0x4817B0` path is always taken by the specific `0x170` call. The table metadata, the dynamic dispatch code, and the tag are independently verified static facts.

## Tests and limits

The new `rayman2_selfread_typed_callback_audit.py` reports the six-record family, the 16 exact call sites, and the 14 cross-checked opcode anchors for each exact PE. **20 new Python unit tests** include full two-file integration, negative in-memory opcode/descriptor mutations, malformed x86 rel32 rejection, extraction of disassembler instruction sites and missing-call detection. Full locally run suite: **216/216 tests passed** (196 previous + 20 new). CI, Wine gameplay, actual SafeDisc driver, and physical CD errors were not tested here.

**What the results mean:** the engine contains a real module-memory sum-of-squares path, but its immediate output dispatch is a generic typed-value system. No known static checksum constant or dedicated comparison/rejection branch has been established at this junction. The input records of type `0x170` and their expected outputs would have to be found in authentic resource data or observed read-only at runtime before classifying this path as executable anti-piracy enforcement. Do not change or neutralise the generic `0x481800` dispatcher.

Reproduce locally, with *user-owned* EXEs and GNU `objdump`:

```sh
python scripts/rayman2_selfread_typed_callback_audit.py \
  --retail '/private/Rayman2-CD.exe' \
  --gog '/private/Rayman2-GOG.exe'
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```