# Rayman 2 — 28 guarded code-range registrations and GOG active-code differences

**14 November 2026 — SHA-256-gated, read-only research. This is not SafeDisc decryption.**

The two user-owned inputs are:

| Role | Length | SHA-256 |
|---|---:|---|
| Original CD-sourced `Rayman2(3).exe` | 676,352 bytes | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Separately modified GOG `Rayman2.exe` | 1,468,928 bytes | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

**Do not conflate GOG with a pristine post-decryption retail binary.** The GOG executable contains extra changes and an inactive copy of the retail `.text`; all comparisons below refer exclusively to the **active executable `.text`** mapped by RVA.

## Key discovery: the guard is a source of paired code bounds

A previous audit proved global DWORD `0x5113EC` is initially zero-filled PE memory, and that the original executable's active `.text` has 28 direct reads/compares of it, versus GOG's 16.

We now extracted the **two absolute DWORD stores** in the nonzero-guard branch of every one of those 28 retail functions. They write addresses that bound a contiguous span of x86 code in the same `.text`.

* 24 functions store starts at `0x510DC0 + 4*i` and ends at `0x510C00 + 4*i`, **i = 0..23**. The slot pointers differ by `0x1C0`.
* Four additional functions store starts at `0x511400 + 4*i` and ends at `0x511320 + 4*i`, with **i = 0,1,2,5**. Their pointers differ by `0xE0`. Slots 3–4 are not seen in the present *direct guard reference* census, but this is **not a proof that no indirect writer exists**.
* Every corresponding conditional `JZ rel8` transfers to the recorded code begin (27 functions), **except `0x405856`**, whose branch goes to `0x405877`, eight bytes before the recorded begin `0x40587F`, after an additional setup instruction.
* All **28 regions are file-backed, lie in the original active `.text`, and do not overlap**. Their total length is **14,757 bytes**. This is an on-disk code-range registration pattern; it does **not** demonstrate that the registered ranges are decrypted, copied or executed dynamically.

The 56 unique literal table-slot pointers occur at the recording stores exactly once each, except `0x510C00`, which also appears as a DWORD literal in a **descriptor-like data region embedded within executable `.text`** at `0x497FE7`. That occurrence is **not** established as an instruction and must not be misrepresented as a real code reader or consumer.

## Independently measured GOG changes with correct PE layout mapping

The original retail `.text` has raw file offset `0x400`, RVA `0x1000`, raw length **631,296** bytes. GOG's active `.text` starts at raw offset **`0x1000`** with the same RVA, so naive same-file-offset comparisons are **wrong**. This audit explicitly aligns the two sections by RVA, never by raw file offset or by GOG's inactive `.extra`.

| Measure | Exact count |
| --- | ---: |
| Registered disjoint regions | **28** |
| Total registered code bytes | **14,757** |
| Registered fraction of original active `.text` | **2.3376%** |
| Changed bytes in all aligned active `.text` | **13,269** |
| Changed bytes within registered spans | **8,669** |
| Changed bytes outside registered spans | **4,600** |
| Share of GOG's changed code inside registered spans | **65.3327%** |
| Changed density inside those ranges | **58.7450%** |
| Changed density outside those ranges | **0.7461%** |
| Descriptive density ratio (inside/outside) | **78.74×** |

This strong concentration is **a structural correlation, not proof of SafeDisc-specific encryption**. GOG's changes may also include regular file location and engine compatibility adaptations.

**Classification of the 28 registered regions:**

- **12** are byte-identical in the two active `.text` sections.
- **16** contain at least one difference.
- Of those, **11 primary-family spans are completely filled with `0xCC` (INT3) in GOG** — slots 4, 5, 6, 7, 8, 9, 13, 14, 15, 16 and 17. They account for **4,738 bytes** of entirely INT3-filled ranges. One of those was already partly `0xCC` in retail, so “entirely filled in GOG” does not imply *every byte* changed.
- The five other modified spans include partial replacements or normal code changes, including preserved DAT-resource functionality.
- All four secondary-family spans are identical between retail and active GOG.

Do **not** remove all registered spans, set the guard to a constant, or copy GOG's `INT3` fills into the original. Several registered spans remain live, ordinary engine code in both executables, and GOG's control flow has been changed elsewhere to avoid removed function entries.

## Proven limits and next decisive experiment

The retail PE loader initializes guard `0x5113EC` to zero. Its **first nonzero runtime value and any indirect writer have not been observed**. No direct write to the guard occurs among the audited exact literal references. A nonzero value causes registration and early return in the observed prologues. It is *possible* an external loader, a calculated address or self-modified code sets the guard; the static census alone neither proves nor rules that out.

The next meaningful discriminators are:

1. During a legitimate original-game startup, **passively watch writes to `0x5113EC`**. If it changes, capture the exact writer and call stack; if it stays zero, the registration branches may be dormant in that run.
2. If the branches run, watch for **reads of the 24 start/end pairs** and identify who consumes the tables, rather than equating stored metadata with the decryption operation.
3. Trace the original CD's live DAT path separately; do not mistake its masked `ReadFile` and `SetFilePointer` calls for a standalone protection verifier.
4. Only after an actual code/data consumer and a real authenticity failure are identified should a minimal supported original-executable modification be considered.

**No executable payload was decrypted or generated, no physical SafeDisc C2-error authentication was measured, and neither game binary was committed.**

## Reproduction

```sh
python scripts/rayman2_guarded_ranges_audit.py \
    --retail /private/Rayman2-CD.exe \
    --gog /private/Rayman2-GOG.exe

python -m unittest discover -s scripts \
    -p 'test_rayman2_guarded_ranges_audit.py'
```

The script verifies whole-file SHA-256s, PE32 section bounds, paired writes, branch targets, disjoint spans, and aligned active-code differences. It fails closed on unexpected layouts. Its synthetic tests run in GitHub Actions without bundled game files, while its exact-owner integration test requires environment variables `RAYMAN2_RETAIL_EXE` and `RAYMAN2_GOG_EXE`. Local private integration verified all 28 ranges and all numerical results. A separate CI check validates Python and native Rust code on Windows and Linux.

**No claim of a functional Rayman 2 SafeDisc 1.35 unwrapper is made.**
