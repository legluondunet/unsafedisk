# Rayman 2 — stream flags versus masked Win32 file readers

**14 November 2026 · experimental, read-only, no decrypted executable.**

This audit is restricted to two user-provided, SHA-256-pinned PE32 executables:

- CD-sourced original 676,352 B: `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`
- Modified GOG 1,468,928 B: `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`

The GOG build is **not** an authenticated, otherwise pristine post-decryption retail sample.

## Exact bits (do not confuse flags 3 and 6)

The common constructor `0x450A00` stores the flags byte to `[stream+0x18]`. Its subroutines:

- `0x450EC0` computes `(flags >> 1) & 1`: **0x02 enables bytewise XOR**.
- `0x450ED0` computes `(flags >> 2) & 1`: **0x04 selects a masked Win32 ReadFile wrapper**.

It then stores a selected function pointer to `[stream+0x24]`; the existing dispatcher later calls that pointer. The exact branch displacement bytes at `0x450A46` and `0x450A69` are **75 28** and **75 05** on CD, but **75 00** and **75 00** on GOG. This forces *direct* readers on GOG while preserving the payload-XOR decision.

| Flags | CD reader | GOG reader |
| --- | --- | --- |
| 0 or 1 | `0x4512C0` direct/raw | `0x4512C0` direct/raw |
| 2 or 3 | `0x451090` direct/XOR | `0x451090` direct/XOR |
| 4 or 5 | `0x451300` masked/raw | `0x4512C0` direct/raw |
| 6 or 7 | `0x451110` masked/XOR | `0x451090` direct/XOR |

Other high bits do not affect these two selector tests. In particular **3 is *not* masked**: its binary value is 0b0011, which does not set 0x04.

## Verified direct call sites

Nine direct `CALL rel32` instructions target the open wrapper `0x450A80`, which passes the flags argument through to constructor `0x450A00`:

| Site VAs | Observed flags | Reader classification |
| --- | --- | --- |
| `0x44D510`, `0x44D56A`, `0x44D5A3` | immediate 3 | direct/XOR on both |
| `0x44DADA`, `0x44DB48`, `0x44DB87` | immediate 0 | direct/raw on both |
| `0x44F782`, `0x44F7E9`, `0x44F823` | dynamic 1 or 2 | direct/raw or direct/XOR on both |

For the dynamic three, the preserved instruction sequence `0x44F76B..0x44F77C` compares the **first byte of a caller-supplied pointer** against ASCII `'w'`, computes 1 if equal or 2 if unequal, and retains the flag byte for all three call sites. Its runtime input value and source file identity have **not** been observed.

**Distinct important case:** a separate direct `CALL 0x450A00` at **`0x44EA1E`**, preceded by `PUSH 6` at `0x44EA1C`, is **unchanged in GOG**. On CD this selects the masked/XOR reader `0x451110`; with the GOG branch edits it selects the still-preserved direct/XOR reader `0x451090`. This is a concrete static owner of the removed masked reader, not proof of SafeDisc authentication. The earlier code range is part of the DAT file-stream processing family, whose full data provenance remains under study.

## Reproduction and limits

```sh
python scripts/rayman2_stream_mode_audit.py --retail /private/Rayman2-CD.exe --gog /private/Rayman2-GOG.exe
python -m unittest discover -s scripts -p 'test_rayman2_stream_mode_audit.py'
```

The local integration run verified both exact SHA-256 inputs, PE image mapping, 9 wrapper calls, the direct flag-6 constructor call, flag construction opcodes, both selection branches, and the retained XOR reader instructions. **11/11 synthetic/integration tests passed locally**. The binary inputs are private and must not be committed; the integration unit test skips without two environment variables.

Static call-site coverage does **not** establish runtime execution, file contents, a complete dynamic call graph, availability of a physical C2-protected disc, or success in decrypting a SafeDisc 1.35 executable. No executable bytes are exported and no protected program is run or patched.

**Next discriminant:** resolve the origin of the stream pointer and file path passed into `0x44EA1E`, follow the selected `[stream+0x24]` callback to its actual `ReadFile` calls, and observe the first input bytes/state under a legitimate runtime or bounded read-only trace before attempting an executable fix.
