# Rayman 2 — direct-call removal audit (CD versus GOG)

**14 November 2026. Static, read-only and exact-SHA-256-gated investigation.**

This report compares the owner's original CD-sourced PE32
`Rayman2.exe` (676,352 bytes, SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`)
against the **independently modified GOG** `Rayman2.exe`
(1,468,928 bytes, SHA-256
`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).
GOG is **not** an authenticated post-decryption, otherwise pristine CD build.

## New result — no preserved direct calls into GOG INT3 entry sites

GNU `objdump -d -M intel` was run on the matching
`0x00401000..0x0049B1FF` range of the two active `.text`
sections (never on GOG's non-executable `.extra` archival copy).

For **32** retail `CALL rel32` instructions (opcode `E8`) which
directly target **14** original function entry addresses, the same
target addresses in active GOG `.text` begin with `INT3` (`CC`).

- **32/32** original call instructions are **no longer retained as an
  identical direct call** at their original virtual addresses in GOG.
- The same linear-disassembly scan of active GOG `.text` found
  **0 direct `E8` calls** into a byte currently equal to `INT3`.
- Four **unchanged startup call instructions**
  (`0x44947C`, `0x449485`, `0x44948E`, `0x44949A`) instead
  land at GOG's immediate `RET` stubs (`0x4478A0`, `0x448DB0`,
  `0x448D80`, `0x447DE0`), not at the discarded `INT3` entries.
- This is consistent with a deliberate edit to the *direct-call*
  structure. It does **not** prove all rewritten code was SafeDisc code.

| Target of retail direct calls | Retail caller count | GOG at target |
|---|---:|---|
| `0x4474B0` | 3 | `INT3` |
| `0x4474D0` | 4 | `INT3` |
| `0x447540` | 2 | `INT3` |
| `0x447730` | 3 | `INT3` |
| `0x447A90` | 2 | `INT3` |
| `0x447AF0` | 3 | `INT3` |
| `0x447BE0` | 1 | `INT3` |
| `0x447C80` | 4 | `INT3` |
| `0x447CB6` | 1 | `INT3` |
| `0x447D10` | 1 | `INT3` |
| `0x4481B0` | 1 | `INT3` |
| `0x4484D0` | 5 | `INT3` |
| `0x448610` | 1 | `INT3` |
| `0x448970` | 1 | `INT3` |
| **Total** | **32** | **14 targets** |

## Interpretation and limitations

The already documented initializer `0x449360` is byte-for-byte
identical in both files, while its callees are replaced by simple
returns. The new call-edge audit **independently extends** the
evidence from those four stubs to the **14 INT3 entry sites** and
their **32 original direct callers**. It reinforces prioritising
these original functions and their **indirect** callers for
reverse-engineering, before attempting to decode the eight proven
pseudo-random auxiliary files again.

A linear disassembler does not provide a verified control-flow graph.
It can misinterpret code and data; it misses calls via registers,
memory, trampoline-generated code, exceptions, DLL exports, and
runtime-patched memory. `0 GOG direct calls into INT3` is a
**bounded static observation**, not a runtime no-crash guarantee.
It does not prove those original functions executed from the CD,
that the historical physical disc has been authenticated, or that
GOG's other changes were exclusively DRM removal.

## Reproduction

```sh
python scripts/rayman2_direct_call_audit.py \
  /private/CD/Rayman2.exe /private/GOG/Rayman2.exe > audit.json
python -m unittest discover -s scripts -p 'test_rayman2_direct_call_audit.py'
```

The tool takes only the two *exact SHA-256* inputs, uses GNU
`objdump` on their PE32 `.text`, and emits counts and virtual
addresses only. No binaries, decrypted bytes or game content are
included in the source tree. The code and the three synthetic unit
tests were executed independently in a local matching environment:
**3/3 tests passed**, and the exact two original files gave
**32 discarded direct calls / 14 target entries / 0 remaining GOG
direct calls into `INT3`**. GitHub Actions and Rust compilation
were **not** run for this audit; no game was launched and no
SafeDisc unwrapping or playable retail executable is claimed.
