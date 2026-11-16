# Rayman 2 — CD/GOG .text hotspots and retained XOR file reader

**14 November 2026. Read-only comparison of exact owner-supplied executables.** CD-sourced `Rayman2(3).exe`: **676,352 bytes**, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`. Separately modified GOG `Rayman2.exe`: **1,468,928 bytes**, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.

## Delta concentration in the 631,296-byte common active .text

**13,269** differing bytes in **102** maximal runs. Grouping runs with at most **512 unchanged intervening bytes** gives **ten clusters**. This grouping is an *analytic convention*, not a protection boundary.

| Virtual-address span, end exclusive | Changed bytes | Code role previously statically investigated |
|---|---:|---|
| `0x4474B0..0x449360` | **7,704** | Masked Win32 resolver and CD-volume scanner |
| `0x44DEB0..0x44F4C9` | **3,646** | DAT file-access / selector chain |
| `0x450A47..0x451440` | **1,612** | Win32 file wrappers and handler selections |
| Remaining seven small clusters, combined | **307** | Heterogeneous, significance not automatically assigned |
| **Total** | **13,269** | Three large clusters: **12,962 / 13,269 = 97.686337%** |

GOG adds other PE sections and compatibility changes. It is **not** a certified pristine post-decryption retail executable.

## A preserved file reader performs a masked-PRNG XOR byte transform

The **128 bytes** of code at `0x451090..0x45110F` are byte-identical between CD and GOG. The handler calls Win32 `ReadFile` at `0x4510AE`. For each byte, the instruction at `0x4510CD` takes byte **+1** of a DWORD state (bits 8–15), not the low byte. The XOR occurs near `0x4510D2`, with an updated state stored at `0x451105`:

```text
output[i] = input[i] XOR ((state >> 8) & 0xff)
state = (16807 * (state XOR 0x075BD924)) mod 2147483647
```

The observed state DWORD occupies `[object+0x14]`; the mask byte is `[object+0x15]`. Opcode anchors verify `0x4510CD`, `0x4510D2`, `0x4510D9`, `0x4510DE`, `0x4510E8`, `0x451105` in both files. The mathematical transform is invertible by repeating it with the **same initial state**, and carries its state over consecutive chunks. **Actual runtime seed, source file and reachability have not been observed**. This does **not** demonstrate that the supplied opaque `RAYMAN2.ICD` is decrypted by this handler.

Other preserved file handlers: `0x4512C0..0x4512F0` (49-byte `ReadFile` + size check), `0x450C05..0x450C32` (46-byte `CreateFileA`), and `0x450D6B..0x450D86` (28-byte `CloseHandle`).

## Five exact GOG branch substitutions

- `0x450A46`: CD `JNE +0x28` to GOG `JNE +0x00`.
- `0x450A69`: CD `JNE +0x05` to GOG `JNE +0x00`.

In both, a conditional branch with **zero displacement** converges at the immediately following instruction regardless of the flags; these changes favor the unchanged file-reader handlers.

Three further original instruction spans are replaced in GOG with five-byte unconditional `JMP rel32`: at `0x450ADE → 0x450C05`, `0x450C52 → 0x450D6B`, and `0x450F5D → 0x451078`. All source bytes and calculated destinations were verified on both exact PE images.

## Static candidate seed and negative ICD prefix test

In both exact PE files, `0x450A2D` is `C7 46 14 79 CC B5 6A`, or `MOV DWORD PTR [ESI+0x14],0x6AB5CC79`. The preceding conditional `CALL 0x450EC0` tests **bit 1** of the flags byte at `[ESI+0x18]`, and the following `CALL 0x450ED0` tests **bit 2**. If bit 1 is set and bit 2 clear, the CD initializer selects the preserved `0x451090` XOR reader; if bit 2 is set, it selects a different reader `0x451110`. In GOG, `JNE +0` at `0x450A46` removes that alternative and consistently chooses `0x451090` in this branch. These flag conditions are **static control flow**, not a runtime execution trace.

The particular user-owned 683,565-byte `RAYMAN2(1).ICD`, exact SHA-256 `4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6`, was tested in-memory with the above per-byte XOR model and seed `0x6AB5CC79` from file offset zero. The **first four transformed bytes are `97 4F 1F 28`**, **not** an `MZ` DOS executable header. Reinitializing the same seed at offsets 1, 2, 16, 512 and 2048 similarly did not yield an `MZ` prefix. This is a **negative test of one simplistic hypothesis only**; it does not establish actual runtime handler use on this ICD, rule out other starting states or offsets, or prove absence of an encrypted payload at some other stage.

## Verification and scope

The local SHA-pinned Python helper `rayman2_gog_delta_hotspots_audit.py` and `test_rayman2_gog_delta_hotspots_audit.py` were executed against both exact owner inputs. **18 new tests** passed; the complete local Rayman 2 research suite passed **314/314 tests** on 14 November 2026. The tool, tests, full JSON result and test log are retained in a separate downloadable research archive, **not yet committed as Python source to this PR**. This report documents precisely the measured result; no game bytes are exported by the helper, no Wine game run, native build, CI, or dynamic tracing occurred.

**Next discriminator:** trace, strictly read-only, the real `ReadFile` path, input length and initial state when `0x451090` is called. Do **not** claim a working SafeDisc decoder, an authenticated physical-CD read, a decrypted ICD or an executable patch based only on the static XOR recurrence.
