# Rayman 2 — direct I/O status checks and dynamic DAT index bounds

**14 November 2026. Read-only, exact-SHA-256 binary audit.** This note builds on `rayman2-dat-dataflow-arithmetic.md` and `rayman2-dat-media-probe-audit.md`. No executable was altered, launched, decrypted or distributed.

## Exact provenance

| Role | Bytes | SHA-256 |
|---|---:|---|
| Original CD-sourced `Rayman2.exe` | 676,352 | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Separately modified GOG `Rayman2.exe` | 1,468,928 | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

Both files are checked before parsing their active PE32 `.text` sections; the inactive GOG `.extra` copy of the original is excluded. GOG is **not a pristine, decrypted retail edition**.

## The two extra 512-byte reads do not directly gate success on their results

The original code from `0x44F102` to `0x44F1F9` performs the following distinct actions:

| Stage | Original VA | Original operation | GOG equivalent |
|---|---|---|---|
| 1 | `0x44F10D` | `SetFilePointer` on the **first** file handle (with the computed offset, `FILE_BEGIN`) | Removed: NOPs |
| 2 | `0x44F125` | `ReadFile` 512 bytes into `[EBP-0x334]`, bytes-read out parameter at `[EBP-0x10]` | Removed: NOPs |
| 3 | `0x44F133` | Subtract `EBX × ESI` from the output-file offset word | Removed: NOPs |
| 4 | `0x44F13A` | Read a filename pointer from the **24-entry** table `[EBX*4+0x4A2090]` | First fixed pointer `[0x4A2090]` = `LEVELS0.DAT` |
| 5 | `0x44F17D` | `CreateFileA` on the newly selected file | Preserved at the same call site |
| 6 | `0x44F184..0x44F1CA` | On invalid handle (`INVALID_HANDLE_VALUE`), show the Retry/Cancel dialog and reopen | Preserved, including error/retry branch |
| 7 | `0x44F1D4` | `SetFilePointer` on the **second** file handle | Bypassed |
| 8 | `0x44F1EC` | `ReadFile` 512 bytes into `[EBP-0x534]`, same bytes-read out parameter | Bypassed: jump at `0x44F1CC` to `0x44F1F1`; skipped body is `INT3` |
| 9 | `0x44F1F2` | Return the second file handle in `EAX` (`MOV EAX,EDI`) | Preserved unchanged |

Exact near-call instruction targets for both original `ReadFile` calls are `0x44E750`, for both original `SetFilePointer` calls `0x44F380`, and for the second `CreateFileA` call `0x44F220`. These earlier research results have now been explicitly rechecked in the new standalone audit.

### Status and buffer dataflow boundaries

- Immediately after the **first** 512-byte `ReadFile` at `0x44F125`, the straight-line sequence `MOV ECX,EBX; PUSH EDI; IMUL ECX,ESI; MOV ESI,[EBP+8]; SUB [ESI],ECX` is followed by a `CloseHandle` call. It does **not read or branch on** the returned `EAX` status of `ReadFile`.
- Immediately after the **second** 512-byte `ReadFile` at `0x44F1EC`, `POP EBX; MOV EAX,EDI` overwrites the return register before returning. Again there is **no direct status test**.
- The only direct references to `[EBP-0x10]` (the returned byte count) in this audited tail are two `LEA` instructions supplying it as an **output** argument, not reading it. The two distinct 512-byte local buffers have no later direct stack-offset reference within the tail after being supplied to `ReadFile`.
- In contrast, the **second file open** is explicitly checked (`CMP EDI,-1` at `0x44F184`, branch at `0x44F187`), and an error path calls a dialog at `0x44F195`, followed by a Retry/Cancel condition.

**Therefore the two extra reads do not by themselves constitute a verified checksum/integrity *verdict* in this function.** This is **not** proof that the media reads are irrelevant: physical CD I/O, `ReadFile` side effects, failure behavior, aliases, external callbacks and runtime-patched code were **not** observed. The exact runtime control-flow paths remain unverified.

## Newly explicit bound analysis of the 24-name selector

The original code computes the output word `R` using the earlier verified 16-byte header and 4-byte sample (unchanged in GOG). At `0x44F0DA..0x44F100`:

```text
Q = floor(unsigned(global_5117B0) / unsigned(global_5117C0))
D = (Q << 11) modulo 2^32
C = floor(unsigned(R) / unsigned(D))
EBX = 0, if C == 0; else (nonnegative_PRNG_state % C)
```

All calculations are x86-32 compatible; the two DIV instructions require nonzero divisors. The code uses `IDIV EBX` for the final PRNG reduction, but the original masked generator at `0x448480` returns nonnegative 31-bit states, and `C` cannot exceed 2,097,151 when `D` is a nonzero multiple of 2048. Thus the signed remainder is nonnegative in this particular model.

The next filename lookup at `0x44F13A` uses `[EBX*4+0x4A2090]` **with no bounds-checking comparison or branch between the final remainder and this indexed memory access**. A sufficient runtime safety condition would be `C <= 24`; no such condition is demonstrable from the current on-disk binaries alone because `global_5117B0`, `global_5117C0` and `R` depend on previously read data.

A synthetic legal arithmetic input `R=204800`, `global_5117B0=1`, `global_5117C0=1`, PRNG state `82` produces `C=100` and **EBX=82**, outside the 24-name table. This **demonstrates that the formula is not unconditionally in bounds for arbitrary states**; it does **not** demonstrate an out-of-bounds access on the owner's authentic retail disc. There is also a potential zero-divisor hazard if `global_5117C0=0`, if `Q=0`, or if the 32-bit shift yields zero. None has been observed at runtime.

In GOG, the selector calculation is **still present** but the actual indexed pointer dereference is replaced with the first fixed entry. The altered filename selection is therefore an independently verifiable **GOG implementation change**, not proof of the purpose of the original selection or a recommendation to patch the retail game.

## Reproduction and scope

New Python audit `scripts/rayman2_dat_io_gate_audit.py` relies on the existing exact-SHA read-only `rayman2_dat_dataflow_audit.py`, GNU `objdump`, and checks **both raw PE bytes and disassembled instructions** at the exact VA anchors. It validates original API-forwarding destinations, GOG skip target, status/result dataflow, buffer/bytesRead references, and the absence of a branch or comparison in the original post-remainder tail. Its synthetic pure-Python selector model handles 32-bit overflow and rejects forbidden zero DIV denominators.

```sh
python scripts/rayman2_dat_io_gate_audit.py \
  --retail /private/CD/Rayman2.exe \
  --gog /private/GOG/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

**Verified locally on the actual two known binaries:** all anchored instructions, original call destinations, error branch, GOG branch target, two status-ignored intervals, 24-entry lookup, and preserved epilogue. **16/16 new synthetic tests passed; 91/91 tests passed across the six current research modules.** No new GitHub Actions run or Rust compilation has been performed. No SafeDisc driver, Wine gameplay, original physical CD sectors or post-decryption memory dump were observed.

**Next discriminator:** capture *read-only* original runtime values `R`, `global_5117B0`, `global_5117C0`, both `ReadFile` statuses and the selected `EBX` (as well as whether the first and second opens succeed). A successful 512-byte read or failed 512-byte read alone does **not** prove the game's expected authentication logic. Avoid an executable patch until this distinction is established.