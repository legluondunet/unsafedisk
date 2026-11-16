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

**Next discriminant:** after identifying the flag-6 `LEVELS0.DAT` path, recover its actual runtime initial XOR state, first input DWORD and reader status with a bounded read-only trace. Do not assume the file is `RAYMAN2.ICD`.

## Further discrimination: flag-6 stream reads LEVELS0.DAT

A new exact-PE anchor chain connects the previously identified flag-6
direct constructor call to a **concrete resource filename** (rather than the
opaque RAYMAN2.ICD):

1. `0x44E8D3 CALL 0x44EB40`: opens an initial DAT file.
2. `0x44EB6C MOV EAX,[0x4A2090]`: the pointer table's **first slot**
   contains `0x4A221C`, pointing to the literal `LEVELS0.DAT`.
3. `0x44EB89`: the CD code pushes format address `0x4A2264`
   containing `%c:\\%s\\%s` (drive letter plus two path components);
   GOG pushes `0x4A2268`, format `%s\\%s` (no drive letter).
   The intermediate directory string is runtime-owned; its exact
   contents were not observed. These on-disk formats, pointers and
   strings were checked in both PE images.
4. `0x44E8D3`'s caller saves the opened file handle in
   `[EBP-0xC]`, then `0x44EA1C PUSH 6` and `0x44EA1E CALL
   0x450A00` install a reader callback.
5. **Important seed distinction**: the constructor writes immediate
   `0x6AB5CC79` to `[stream+0x14]` at `0x450A2D`.
   Before the read, `0x44EA7D MOV [ESI+0x14],EDI` **overwrites that
   seed with a dynamically calculated value** derived in the preceding
   instructions from a global masked PRNG state. Thus the immediate
   constructor seed is *not* demonstrated to be the effective
   state used for the following file read.
6. The reader's `0x44EAA0 CALL 0x450D90` receives a destination
   buffer `[EBP-8]`, element size `4`, count `1`, and the
   stream pointer. The dispatcher multiplies size and count and calls
   `[stream+0x24]` at `0x450DD5`. The resulting DWORD is read at
   `0x44EAAA` and stored into a global table at `0x44EAB6`.

**Result:** the masked/XOR read at this exact CD call site is part
of a static chain processing a `LEVELS0.DAT` resource. The XOR
transform must not be broadly classified as *exclusively* SafeDisc
decryption. This is consistent with the previously documented DAT
loader/dataflow chain, and explains why simply XOR-transforming the
supplied `RAYMAN2.ICD` from file offset zero with the constructor
immediate seed is not a validated decryption procedure.

**Limits:** static code alone does not prove this branch executes on
the owner's retail CD, the actual runtime folder, the computed XOR
state, the four plaintext bytes, or whether media-authentication
side effects are mixed into the resource-loading path. No valid
retail post-decryption EXE was created. The same script now checks
the filename pointer, original/GOG format selection, seed
replacement and four-byte dispatch in its exact-SHA integration.

## Correction of DAT handle provenance (14 November, follow-up)

**Important correction to the shorthand above:** an initial resource name
`LEVELS0.DAT` is opened by `0x44EB40`, but the returned OS HANDLE for
the flag-6 stream is not necessarily this first file on the original CD.
At `0x44F13A`, the retail code selects **`[EBX*4+0x4A2090]`** from
its 24-entry DAT name table, opens that second filename at `0x44F17D`,
and returns its HANDLE via `MOV EAX,EDI` at `0x44F1F2`. The flag-6
constructor then receives the returned handle at `0x44EA97`.

In GOG, the dynamic indexed name read at `0x44F13A` is replaced with
`MOV EDX,[0x4A2090]`, choosing the first entry `LEVELS0.DAT`, and
the second 512-byte probe is skipped. Thus the flag-6 **actual stream
file is dynamically selected on retail, but pinned to the first DAT
entry in the GOG branch**. Runtime selected EBX/file and status remain
unobserved. Any earlier sentence claiming that this read always comes
from LEVELS0.DAT should be interpreted as referring only to the initial
probe, not to the retail returned handle.

The new separate SHA-gated
`scripts/rayman2_stream_seed_audit.py` models the full x86 state update
and compares it to the different recurrence observed in auxiliary PRNG
files; see `docs/rayman2-xor-stream-seed-vs-auxiliary-prng.md`.
