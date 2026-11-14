# Rayman 2 — arithmetic dataflow of the original DAT media probe

**14 November 2026. Read-only, exact SHA-256-locked static audit.** This builds on `docs/rayman2-dat-media-probe-audit.md` in the `unsafedisk` research PR. This report does **not** create a SafeDisc decoder, execute the game or certify authentic physical CD sectors.

## Input provenance

| Role | Size | SHA-256 |
|---|---:|---|
| User-owned CD-sourced original `Rayman2.exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Separately modified GOG reference `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

Both were validated byte-for-byte by SHA-256 before analysis. GOG is **not** a verified post-decryption unmodified retail reference. All observations below refer only to these exact inputs and the active PE32 `.text` section, never to the archival `.extra` copy in GOG.

## New 1 — the 1,024-way internal selector and the 24-entry DAT table are separate

At VA `0x44ED6C..0x44ED8B`, the original computes an **internal** unsigned selector from bytes at globals `0x5116F0` and `0x5116F1`. The first byte is multiplied by four. The second is reduced to two bits and selects one of four switch cases via the jump table at `0x44F204` (four DWORD targets, identical in both EXEs):

| Case | Jump target | Added to the first-byte multiple |
|---|---|---|
| 0 | `0x44ED8E` | +0 |
| 1 | `0x44ED80` | +1 |
| 2 | `0x44ED83` | +2 |
| 3 | `0x44ED88` | +3 |

Formula at this stage: `n = 4 * reduced_byte_0x5116F0 + (byte_0x5116F1 & 3)`, with range **0..1023**. **Important refinement (14 Nov):** `0x44ED38` first divides the original low byte by the data-derived `global_0x511750` and `0x44ED45` writes the remainder back to the low byte. Thus the complete preselector is `n = 4*(original_byte_0x5116F0 % global_0x511750) + (original_byte_0x5116F1 & 3)` when the divisor is nonzero. See [the verified preselector audit](rayman2-dat-preselector-normalization.md). This is **not** the later `EBX` used to index the 24 filename pointers at `0x4A2090`; `EBX` is subsequently overwritten by a different quotient/remainder calculation. The four jump targets were verified directly in both exact PE files, not inferred from printed disassembly alone.

## New 2 — precise formula from the 16- and 4-byte reads

The original `ReadFile` at `0x44EF5D` places 16 bytes in `[EBP-0x20]`, interpreted by subsequent instructions as four little-endian DWORDs `w0,w1,w2,w3`. The arithmetic at `0x44EF82..0x44EFA0` modifies two of them using the above selector `n`. The `ADD; DEC; JNE` loop at `0x44EF98` executes **exactly `n` times** (for positive `n`), not `n-1` times:

- `w0' = (w0 + w2 * n) mod 2^32`.
- `w1' = (w1 + w3 * n) mod 2^32`.

After a separate `ReadFile` of four bytes into `[EBP-0x8]` at `0x44F0AA`, the code at `0x44F0C8..0x44F0D8` computes:

```text
result = ((sample - w0') mod 2^32) XOR w1'
[caller_output_DWORD] = result
```

The entire **58-byte span `0x44F0C8..0x44F101` is identical** between the CD and GOG versions. This means GOG preserves the original output-word calculation, even though it removes later media reads. The two file-derived globals `0x5117B0` and `0x5117C0` are assigned by original code at `0x44E471` and `0x44E6CA` (using `SUB` and `XOR` calculations from other loaded DWORDs); GOG preserves the associated assignments. They are **not static constants**.

The follow-up calculation at `0x44F0DA..0x44F100` effectively divides `result` by a scale containing `(global_5117B0 / global_5117C0) << 11`, then applies a PRNG/remainder to select the later `EBX` index. **Do not claim its final range is 0..23:** its denominator, quotient, input and division-by-zero safety depend on runtime values not present in the EXE. No known expected checksum or explicit integrity verdict was discovered in this span.

## New 3 — neither 512-byte read buffer is directly consumed in the audited function

Two 512-byte read destinations occupy adjacent, **nonoverlapping** 512-byte local stack regions within the `0x534`-byte stack frame declared at `0x44EB43`:

| Stage | Stack buffer | Only direct local address reference after `0x44F102` | Original read call | GOG |
|---|---|---|---|---|
| 1 | `[EBP-0x334 .. EBP-0x135]` | `LEA EAX,[EBP-0x334]` at `0x44F118` | `ReadFile` at `0x44F125` | Seek/read block replaced with NOPs |
| 2 | `[EBP-0x534 .. EBP-0x335]` | `LEA EAX,[EBP-0x534]` at `0x44F1DF` | `ReadFile` at `0x44F1EC` | Jump from `0x44F1CC` skips whole block; body is INT3 |

Within the disassembled original function region, the **only direct references** to the two respective stack-buffer offsets are the `LEA` instructions that supply them as `lpBuffer` to `ReadFile`. The bytes in those buffers are not compared, hashed or subsequently read *directly by an instruction referring to those offsets*. The respective `ReadFile` return values also have no immediate conditional test. This contrasts with the 16-byte and four-byte buffers above, which have visible data dependencies.

**Limits:** absence of direct references in linear disassembly is **not** proof of no aliases, asynchronous use, dynamic self-modification, unusual API side effects, device errors or other indirect paths. A read can also change a file position or trigger a media error even when its output bytes are unused. Do not label these operations as known SafeDisc sector-authentication checks, nor conclude that GOG removed a byte-level checksum of these buffers. This result is compatible with *media/access probes* or obfuscation, but the real mechanism requires same-edition runtime and/or physical-disc evidence.

## Verified source and tests

New tool `scripts/rayman2_dat_dataflow_audit.py`: standard-library Python + GNU `objdump`, exact hash gating, bounded PE32 `.text` mapping, instruction opcode anchors validated twice (real `.text` bytes + disassembly), byte-exact four-target switch table, guarded synthetic arithmetic model, and a structured JSON result. No Windows binary is written or executed. The test module `scripts/test_rayman2_dat_dataflow_audit.py` has **15 synthetic unit tests**, including independent iterative arithmetic for **8,000** seeded examples and a complete **1,024/1,024** selector-domain coverage test, as well as rejection of malformed PE headers, wrong instruction anchors, symlinks and invalid input sizes.

**Verified locally in this session:** new **15/15** tests; combined five prior modules plus new module **75/75** tests; exact inputs produce `shared_derivation_on_gog: true`, two expected 512-byte buffer-reference sites, expected jump-table addresses, and two file-derived denominator global assignment sites. These are tests on the local checked-out helper sources and the exact user-provided binaries, *not* a CI result, Wine runtime trace or native Rust compilation.

## Next discriminating observation

Rather than applying GOG's removed code blindly, trace read-only the real `LEVELS0.DAT` **first 16 bytes, subsequent four-byte `ReadFile` result, file offsets, call status, computed `n` and selected final `EBX`** on the same-edition retail environment. That will distinguish a repeatable expected geometry/index selection from an erroneous or intentionally failing disc-path. A physical SafeDisc C2-error measurement requires a source capable of capturing such errors; ISO9660-only inspection logs are insufficient. No playable, decrypted retail EXE has been recovered.