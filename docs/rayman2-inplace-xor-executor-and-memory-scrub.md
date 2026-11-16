# Rayman 2 — two-span in-memory XOR decode, indirect execution, and pseudorandom scrub

**14 November 2026 — exact-owner-SHA, read-only research, not a retail SafeDisc unwrapper.**

## Inputs and independently verified unchanged code

- Original CD `Rayman2(3).exe` — **676,352 B**, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- Separately modified GOG `rayman2(4).exe` — **1,468,928 B**, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.

The full **590-byte** code of `0x467350..0x46759D` is byte-for-byte identical in the two active `.text` regions, SHA-256 `b33fb63041764dfbd2a35ae1d591e7ad61b21484b4e6594053cf626d2ce37dc3`.

The **519-byte** expression handler `0x47AEB0..0x47B0B6` is also identical, SHA-256 `9a8100740e09394246133eac3e0fb41e044bac91fe6daf36db807887445f5ac9`. Its original and GOG registry record is **type `0x111`**, `(handler=0x47AEB0, flag=0)`, at `0x4A5460 + 8*0x111 = 0x4A5CE8`.

**Existing research credit:** the `0x467130` 16-slot callback vector, its 12 masked original Win32 APIs and GOG virtual-CD replacements were **already** described in [the anti-tamper evidence report](rayman2-anti-tamper-evidence.md), section “16-slot original CD callback vector versus GOG virtual-CD simulation” (13 Nov). The *new* result here is its actual two consumers, the retained two-span code decoding and post-return memory destruction.

## Newly reconstructed function `0x467350`

The x86 code computes **two addresses and two ends** using object-derived metadata, not literal file offsets:

- **Range A** begins at `[EBP-0x7C]` derived at `0x4673F3..0x4673FA` using a +`0x10` object offset; its end is `[EBP-0x28]`, involving another +`0x20` offset.
- **Range B** begins at `[EBP-0x78]` derived at `0x467413..0x46741A` using +`0x30`; its end is `[EBP-0x24]`, involving +`0x40`.

Their actual runtime addresses and lengths have **not** been obtained. The loops process DWORDs while the current pointer is below its end, with no explicit partial-DWORD-tail handling.

At `0x467477`, the code sets `C=0x00EC8B55`; its low three bytes are the familiar `55 8B EC` x86 function prologue. At `0x467484..0x467493`, it reads the original first encrypted DWORD `c0` and establishes the mask:

```python
seed = c0 ^ (c0 | 0x00EC8B55)
# algebraically the same as
seed = (~c0) & 0x00EC8B55
```

The first decoded DWORD becomes `c0 | 0x00EC8B55`, forcing selected prologue bits. **This is not guaranteed to equal the exact prologue**, as any extra set bits in `c0` remain set.

Two consecutive in-place XOR loops then apply the exact same recurrence:

```python
# For each *original encrypted* DWORD c, in A then B:
plaintext = c ^ previous_ciphertext
previous_ciphertext = c
```

- **A loop `0x467496..0x4674C2`** begins with `seed`.
- **B loop `0x4674D6..0x467508`** continues from A's last **encrypted** DWORD. It does **not** reset the mask.
- At `0x4674C8`, in between the loops, the function builds the previously established **16-slot file/volume callback vector** on the stack.
- At `0x467525..0x46752B`, a separate condition may overwrite B's first byte with the current CD drive character from `[0x4A6AD8]`.
- At **`0x467535: CALL [EBP-0x7C]`**, the function invokes the **A entrypoint**, passing **(B pointer, 16-slot vector pointer)**, with x86 right-to-left stack arguments. The actual target bytes and runtime return status have not been witnessed.

**Critical newly confirmed last stage:** after that call returns, `0x46753E..0x467559` overwrites A *byte by byte*, and `0x467568..0x467583` overwrites B *byte by byte*. Each byte is the low eight bits of the return from `0x448480`, an existing pseudo-random state updater at `[0x510BF0]`. This appears designed to **destroy the transient decoded content**, not restore the original encrypted words.

The callback return is then converted to a generic typed-value **tag 6** by `0x481770` at `0x46758F`. A comparison against a DRM reference value or an active authentication failure **has not** been established.

## Independent expression-object executor `0x47AEB0`

Registry handler type `0x111` at `0x47AEB0` has a distinct path:

1. At `0x47AEED`, matches runtime object type `0x111`.
2. Computes a function pointer from parsed data at `0x47AF7A..0x47AF7E`, stored as `[EBP-0x54]`, and a data pointer at `0x47B010..0x47B014`, stored at `[EBP-0x5C]`.
3. Builds the same 16-entry callback vector at `0x47B01B`.
4. Calls **`[EBP-0x54]`** at **`0x47B072`** with **(data pointer, vector pointer)**.
5. Stores the result as generic typed **tag 6** at `0x47B0A6`.

Unlike `0x467350`, this expression handler does **not** contain the same explicit chained-XOR/scrub sequence. The two target functions cannot be assumed identical.

## Reproduction / negative controls

```sh
python scripts/rayman2_inplace_xor_executor_audit.py \
    --retail '/private/Rayman2(3).exe' --gog '/private/rayman2(4).exe'
python -m unittest discover -s scripts -p 'test_rayman2_inplace_xor_executor_audit.py'
```

The script verifies **66 exact x86 source-opcode anchors**, **13 rel8/rel32 branch targets**, both complete identical code spans, and both `0x111` registry records. The pure two-span XOR helper accepts **synthetic DWORD values only**; it never emits original game bytes. **12/12 tests passed locally**, including 100,000 deterministic randomized synthetic two-span cases, exact-owner integration and deliberate mutation of opcode/registry bytes (with a controlled temporary hash gate). In GitHub CI, three exact-owner tests are intentionally skipped when private files are not installed.

### Next decisive observation

For a legitimate live run, a passive breakpoint at **`0x4674C4`** gives `A_start=[EBP-0x7C]`, `A_end=[EBP-0x28]`, `B_start=[EBP-0x78]`, `B_end=[EBP-0x24]`. Break at **`0x467535`**, **before** the decoded code is called and before both scrub loops: record target address, short instruction classification, bounded sizes and memory-range hashes, along with whether execution reaches this path. At **`0x46753B`**, record the return in EAX and follow downstream result handling; do not assume a DRM verdict. In the separate expression path, observe the computed target `[EBP-0x54]` at `0x47B072`.

**Not achieved:** an observed runtime callback, a recovered protected EXE payload, an identified SafeDisc C2/media transaction or failure comparison, a decryption key, or a functional decrypted original executable. GOG remains a modified comparator, not a pristine retail binary. No proprietary bytes or modifications were committed.
