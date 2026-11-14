# Rayman 2 — preserved WinMain startup relay and changed downstream bodies

**14 November 2026. Exact-SHA, read-only binary analysis. No retail EXE decryption or patch.**

The owner-supplied source binaries were verified before any instruction comparison:

- Original CD-sourced `Rayman2(3).exe`: 676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- GOG-modified `Rayman2.exe`: 1,468,928 bytes, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.

The source for this note is an independently rechecked sequence of **file-backed active PE32 `.text` instructions** in both inputs. GOG is a *modified comparison binary*, not a known original retail decryption. No copy-protected file contents enter the repository.

## Observed startup control-flow edges

The standard startup path contains an identical `PUSH 1` at `0x401EF8` immediately followed by an identical `CALL rel32 0x449360` at `0x401EFA`, in both builds. This is **an exact argument**, not a conjectured calling convention. The initializer `0x449360` also retains:

- `0x449366` reads global guard `[0x5113EC]` (initially zero-filled PE `.data`); `0x449370 JZ 0x44938D` enters its normal body when zero. **No runtime guard value has been captured.**
- `0x449391` uses `QueryPerformanceCounter`; `0x44939E` falls back to `0x12345678` if the API fails, and `0x4493A8 MOV EDI,0x119` selects **281 pseudo-random state iterations** (masked Park–Miller family), written from `0x510EA0`.
- `0x4493E7` copies the caller argument into `EBX`, and `0x4493F0 TEST EBX,EBX` conditionally skips a subsequent temporary allocation if zero. With the literal `1` argument on this caller path, it enters a `PUSH 0x1C` (28-byte) allocation branch.
- `0x4493FA` writes `7` to `[0x5113E8]`, `0x449404` writes `36` to `[0x5113F0]`, and a subsequent loop stores seven generated state words. These state counts and arithmetic are retained in GOG, even though some **downstream consumers** are subsequently disabled.

The tail of this initializer contains **five unchanged direct CALL rel32 edges** in both builds. All direct branch destinations were decoded and checked from actual instruction displacements rather than inferred from disassembler labels:

| Call site (both) | Target | GOG active target |
| --- | --- | --- |
| `0x44947C` | `0x4478A0` | `RET; INT3...` |
| `0x449485` | `0x448DB0` | `RET; INT3...` |
| `0x44948E` | `0x448D80` | `RET; INT3...` |
| `0x44949A` | `0x447DE0` | `RET; INT3...` |
| `0x44949F` | `0x448E30` | Body changed, but guard/prologue retained |

At each of the first **four** GOG targets, the **first sixteen bytes** are exactly `C3 CC CC...` (one `RET`, then fifteen `INT3`), whereas the original CD target begins with a different, verified live x86 instruction sequence. The common initializer still calls them.

The fourth and fifth edges are conditional on the nonzero argument at `0x449496..0x449498`; the literal `1` passed at `0x401EF8` meets this condition under the documented ordinary control-flow path. Neither code reachability under a separately activated guard nor a real game run is established by this static evidence.

At `0x448E30`, GOG retains the original guard-and-range-registration prefix but replaces the original physical CD-volume search from `0x448E5A` with `MOV AL,'.'` followed by `MOV [0x4A6AD8],AL; RET`. The original's separate volume-label examination is described in [original CD volume flow](rayman2-original-cd-volume-flow.md). The GOG bytes were verified, **not copied** into the retail file.

**Important separation:** the GOG change makes four former routines no-ops and replaces one drive-selection body. That is different from decrypting the original program or reconstructing SafeDisc 1.35 driver/media interactions. We must keep legitimate DAT readers and type-conversion routines, many of which reside in the 28 previously registered spans.

## Negative control for tempting checksum-labelled strings

The CD and GOG `.data` each contain a literal `CheckSum.lst` at VA `0x4A1F30` and the format string `%i - Begin: 0x%08x End: 0x%08x Checksum: 0x%08x` at `0x4A1EFC`. An independent byte-level scan of all executable `.text` bytes for the exact **four-byte little-endian pointer operands** to either full string yields **zero hits** in each build; a second GNU `objdump` scan finds no direct operand reference either. This is **not proof the strings are unused**: a dynamically calculated string pointer, an embedded resource index, or other producer remains possible. There is no basis to call these two strings an observed SafeDisc verification function merely because of their names.

## Reproduction and limits

```bash
python scripts/rayman2_startup_dispatch_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/Rayman2.exe'
python -m unittest discover -s scripts \
  -p 'test_rayman2_startup_dispatch_audit.py'
```

The analyzer checks whole-file SHA-256 identities, PE section mapping, unchanged startup/PRNG constants, five direct-call targets, four GOG RET+INT3 stubs and the GOG drive-byte substitution. It returns addresses and booleans only and creates no executable. Its **eight local tests passed**, including an exact-owner-input integration test. GitHub CI runs the synthetic tests but skips private game binaries.

**Next discriminator:** use a passive memory/data breakpoint for the first write to `0x5113EC`, paired with read-only tracing of any writes into or reads out of `0x510C00`/`0x510DC0` tables. Without the actual writer and consumer, forcing a guard value would be speculative and could break gameplay. Separately, identify a real, observed SafeDisc authentication failure before producing a minimal, supportable unprotected retail executable.
