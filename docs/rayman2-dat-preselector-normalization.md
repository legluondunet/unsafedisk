# Rayman 2 — DAT-dependent preselector and FPU-loop normalization

**14 November 2026. Original-CD/GOG exact-SHA-256 read-only x86 audit.**

This report extends the static `rayman2-dat-dataflow-arithmetic.md` and `rayman2-dat-io-gate-and-index-bounds.md` investigations. It makes **no claim of SafeDisc decryption or runtime authentication**. Both original and GOG active `.text` sections are independently checked at the actual PE32 file-backed virtual addresses; the non-executable GOG `.extra` archive is excluded.

## Verified inputs

| Binary | Byte length | Exact SHA-256 |
|---|---:|---|
| Owner's original CD-sourced `Rayman2.exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Separately modified GOG `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

## Finding 1: the 1,024-valued internal selector is first reduced by a data-derived divisor

The original code `0x44ED2C..0x44ED8B` (unchanged in GOG) performs, in this exact order:

1. `0x44ED2C`: `MOV EAX,[0x5116F0]` followed by `AND EAX,0xFF` at `0x44ED33` — only the low original byte `b0` matters.
2. `0x44ED38`: unsigned x86 `DIV DWORD PTR [0x511750]`, with `EDX` cleared first. This yields quotient in `EAX`, **remainder in `EDX`**. The divisor must be nonzero.
3. `0x44ED45`: `MOV [0x5116F0],DL`, **writes the remainder back into the low byte**.
4. `0x44ED40..0x44ED59`: reads the second byte `b1`, reduces it by `AND EAX,3` and stores the result at `0x5116F1`. The two intervening `CDQ; XOR; SUB` sequences are exact x86 instructions but have zero sign mask in this path because `EAX` contains only a byte at that point.
5. `0x44ED5E..0x44ED8B`: shifts the reduced first byte by two, then adds 0, 1, 2 or 3 using the four-entry switch table at `0x44F204`.

For any **nonzero unsigned 32-bit** divisor `D1 = [0x511750]`, the correct value is:

```
r0 = b0 % D1
r1 = b1 & 3
n  = 4*r0 + r1
0 <= n <= 4*min(255,D1-1)+3 <= 1023
```

The earlier formula `n=4*b0+(b1&3)` is only valid when `b0` was **already normalized** (or `D1 > b0`). The old `initial_index()` helper continues to correctly model that *post-normalization* value; the new `normalized_initial_index()` models the full preceding `DIV`.

Examples, **not observed runtime values**: `D1=1` forces `n` to 0–3; `D1=4` limits `n` to 0–15; `D1=6` limits `n` to 0–23; `D1>=256` permits 0–1023. This `n` is **not** the later `EBX` indexing the 24 filename pointers at `0x4A2090`.

**Where does `D1` come from?** `0x44E525 SUB EDX,EAX`, `0x44E527 XOR EDX,ECX`, `0x44E529 SHR EDX,2`, then `0x44E52C MOV [0x511750],EDX`. The participating registers derive from the preceding file-processing path. Nothing in the verified local bytes establishes that the actual runtime divisor is nonzero; therefore an x86 divide fault remains a theoretical concern, **not an observed failure**.

## Finding 2: an independent modulo gates an FPU calculation, not an authentication-error branch

At `0x44ED8E..0x44EDB2` (also identical in both binaries):

```
EAX = zero_extend(byte [0x5116F2])
EDX = 0
DIV DWORD PTR [0x5117B4]
r2  = EDX = (b2 % D2)
MOV [0x5116F2],DL
CMP EDX,ESI  ; ESI was XORed with itself at 0x44ED97, so ESI=0
JBE 0x44F1FA
```

Thus `JBE` at `0x44EDB2` is taken **exactly when `r2==0`**. The target at `0x44F1FA` executes `FSTP ST(0)` to balance the x87 stack and then `JMP 0x44EDEB`, rejoining the normal arithmetic flow. Otherwise the code at `0x44EDB8..0x44EDE6` iterates as specified by the positive remainder. The loop count is bounded **0..255** for any valid unsigned 32-bit `D2`.

`D2` is itself stored at `0x44E6AA` into global `0x5117B4` after a `SUB`/`XOR` calculation based on data in the preceding file-processing code. A zero `D2` would fault in `DIV`, but we have **no same-edition runtime data** proving it occurs.

The zero-remainder branch **does not lead directly to the CD-insertion message box, an integrity-error return, or a game shutdown**. It takes a purely numerical fast path around a floating-point loop. This refines the boundary between plausible anti-copy code and ordinary numeric control flow.

## Validation and limits

- **32 exact instruction sites** are independently anchored in both files (64 byte-level checks), including both data-derived DIV operands, both global-writing instructions, the computed switch, FPU branch, `FSTP`, and rejoin `JMP`. Both relative branch targets are decoded from signed machine operands and verified.
- **17 new synthetic Python unit tests pass**, including a separate x86-register-style model agreeing with the formula over 10,000 seeded cases, all 1,024 possible indices for `D1=256`, division-by-zero rejection, and zero/nonzero FPU remainder cases.
- **108/108 tests pass** across the seven currently available local research modules (91 earlier + 17 new). No GitHub Actions job or Windows/Wine game runtime was launched.
- The user-owned `LEVELS0.DAT` and a matching Rayman 2 ISO are **not present in the checked local files or available Library entries of type `.dat`/`.iso`/`.bin`/`.cue`**. The values of `D1`, `D2`, `n`, and the later 24-name selector in gameplay remain unobserved.

### Reproduction

```sh
python scripts/rayman2_dat_preselector_audit.py \
  --retail /path/to/owner/CD/Rayman2.exe \
  --gog /path/to/owner/GOG/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_dat_preselector_audit.py'
```

The source uses only Python's standard library, GNU `objdump`, and the existing exact-hash-gated `rayman2_dat_dataflow_audit.py`. It reads binaries without modifying them and reports formulas/virtual addresses, **not proprietary game bytes or a patched executable**.

**Next useful experiment:** given the exact same-edition `LEVELS0.DAT`, determine the read offsets and compute `D1` and `D2` from the actual data, then check the later `EBX<24` selection condition. Until those values are observed, a universally valid deprotection patch would be speculative.
