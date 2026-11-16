# Rayman 2 — DAT loader callers and error-propagation chain

**14 November 2026. Exact-SHA-256, read-only comparison of the CD-sourced and GOG executables.** This research is static x86 disassembly, not a gameplay test or SafeDisc bypass.

## Direct-call inventory and original program function

The entry at **`0x44DC40`** has exactly **12 direct `CALL rel32` callers** within the original active `.text` section. All 12 occur at the **same virtual addresses with byte-identical call encodings in GOG**:

| Region | Caller virtual addresses |
|---|---|
| Early game code | `0x402A34`, `0x402B32`, `0x402EF2`, `0x403044`, `0x403964`, `0x403A41`, `0x404186`, `0x404294` |
| File/resource utilities | `0x44CE78`, `0x44CF2C`, `0x44D2D8`, `0x44D619` |

Within the same two hash-locked files, the preserved direct call chain is:

```text
0x44DC40  (structured data loader)
  0x44DC80 CALL 0x44D990
    0x44D9F4 CALL 0x44E8A0
      0x44E8D3 CALL 0x44EB40 (earlier DAT media probe)
```

**A direct-call chain does not prove every branch executes.** The role of the entry is nevertheless clearer from ordinary subsequent instructions: after the call to `0x44D990`, `0x44DC40` uses `0x450D90` for further data reads, calls `0x45DC60` to allocate storage, and populates record fields at offsets `+0x04` and `+0x08` in its data structures. The exact instruction sites `0x44DCA1`, `0x44DCAB`, `0x44DCBB`, `0x44DDAC`, `0x44DDB2`, `0x44DDB5` are preserved in both PE files.

This is strong evidence that the pipeline serves **ordinary resource/data loading**, although the original may additionally perform media-dependent checks; code within the chain must **not** be wholesale classified as SafeDisc merely because GOG changes some inner reads.

## Three independently verified branch decisions

1. **Inner file handle:** `0x44E8DD CMP EBX,-1`, followed by `0x44E8E3 JE 0x44EB33`. The target sets `AL=0` (failure return); a separate path at `0x44EB2A` sets `AL=1`. These are explicit status transfers of the inner file-open process, *not* checks of the individual 512-byte read-return values.
2. **Fallback when inner lookup fails:** `0x44D9FC TEST AL,AL`, `0x44D9FE JE 0x44DA09`. Failure from `0x44E8A0` thus leads to an **alternate file/path lookup** in `0x44D990`, not directly to the final caller's failure return. Do not treat the first failed open as a decisive anti-copy verdict.
3. **Outer structured loader:** `0x44DC88 TEST AL,AL`, `0x44DC8A JNE 0x44DC95`. When `0x44D990` ultimately returns zero, the outer loader returns zero at `0x44DC8C..0x44DC94`; on a nonzero result, it enters the structured-data parsing path. The same control flow exists in GOG.

The exact machine bytes at each branch and caller are checked, including the actual relative call/jump destination decoded from its signed operand. **No such success/failure branch by itself demonstrates a cryptographic checksum or a physical SafeDisc authenticity decision.**

## Read-only reproducibility

The new tool `scripts/rayman2_dat_caller_chain_audit.py` verifies SHA-256 of both owner files, scans only the original `.text` range of each file with GNU `objdump`, verifies **all 12/12 caller opcodes** against file-backed bytes, then confirms the three-stage call chain and checked branch instructions in both executables. The separate `test_rayman2_dat_caller_chain_audit.py` has **11 synthetic tests** for relative call and conditional-branch decoding, including positive/negative cases.

**Results:** exact retail/GOG integration passes and **119/119 local tests** pass across the eight current research modules (108 earlier, 11 new). GitHub Actions and Rust compilation were not run; no Windows/Wine game execution, no original-disc raw-sector authentication and no decryption performed.

Inputs are exact original CD-sourced `Rayman2.exe` (676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`) and independently modified GOG `Rayman2.exe` (1,468,928 bytes, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`). GOG is not a pristine retail-unwrapped baseline.

```sh
python scripts/rayman2_dat_caller_chain_audit.py --retail /private/CD/Rayman2.exe --gog /private/GOG/Rayman2.exe
python -m unittest discover -s scripts -p 'test_rayman2_dat_caller_chain_audit.py'
```

**Next question:** establish the concrete `LEVELS0.DAT` values and actual runtime branches before attributing the media-probe operations to anti-piracy. An unsupported global removal of this chain risks breaking asset loading.
