# Rayman 2 — startup guard is zero-filled PE data, not known SafeDisc verdict

**14 November 2026 — read-only static analysis of the owner's exact-SHA PE32 executables.**

Inputs: CD-sourced `Rayman2(3).exe` (676,352 bytes, SHA-256
`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`)
and separately modified GOG `Rayman2.exe` (1,468,928 bytes,
SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).
GOG is not a pristine post-decryption retail executable.

## First new result: initial 0x5113EC DWORD is BSS, not file data

Both PE files use ImageBase `0x400000`, with a `.data` section at
RVA `0x9F000`. That section declares **0x776D0 bytes of virtual memory
but only 0x7C00 bytes of raw file data**. Global VA `0x5113EC`
corresponds to RVA `0x1113EC`, relative `.data` offset `0x723EC`.
This is strictly inside the **zero-filled uninitialized tail**, in
both builds. Therefore the Windows PE loader's initial value is zero.

The original executable contains **28 direct DWORD references** to
the address in its executable `.text`: **26 `MOV reg,[0x5113EC]`
and 2 `CMP DWORD [0x5113EC],0`**. All 28 were individually confirmed
against both raw operand bytes and GNU `objdump` instruction boundaries.
There are **no directly addressed writes** in this approved original
code scan; the SHA-gated helper fails closed if any unrecognized
literal operand form is encountered.

In GOG's active `.text`, exactly **16** direct references remain
(**14 `MOV`, 2 `CMP`), all at **the same addresses with the same
operand forms** as original. The 12 absent original instructions are:

```
0x447546 0x447736 0x4478A6 0x447A93 0x447AF3 0x447BE3
0x447D14 0x447DE0 0x4481BD 0x448619 0x448AB6 0x448DE3
```

They belong to the original startup/resolver group that GOG rewrites.
An unchanged four-call startup chain in both files still directly calls:

| Original unchanged caller | Original callee |
| --- | --- |
| `0x44947C` | `0x4478A0` |
| `0x449485` | `0x448DB0` |
| `0x44948E` | `0x448D80` |
| `0x44949A` | `0x447DE0` |

On GOG these target routines are replaced with immediate `RET`
stubs, a previously established separate fact. Their callers being
preserved does **not** mean the original behavior runs in GOG.

GOG's `.extra` is a **non-executable archive** containing a
byte-perfect **631,296-byte original `.text` copy** at `.extra+0x1000`.
It contains all 28 old guard references. **Never count that archive
as active code**, or conclude that GOG still executes the twelve removed
functions.

## Scope and interpretation

**Proved:** memory initialisation, exact active-code reference counts,
twelve deleted references, four unchanged startup calls, and a
non-executable original-code archive.

**Not proved:** the guard's meaning, that it stays zero after the
PE loader initializes memory, whether pointers or runtime-generated
code write to it, a SafeDisc driver handshake, a decrypted
`RAYMAN2.ICD`, a bypass, or a playable retail EXE.

Do **not** patch the guard to a constant or remove all guarded functions
without a runtime trace. Its uses include ordinary startup and DAT
resource-loading code. A useful next observation is a narrowly scoped
data watchpoint on `0x5113EC` during original-game initialization:
capture the instruction that first changes the initial value (if any),
and compare to a modified GOG startup under otherwise equivalent
conditions. Use a legitimate test copy; avoid invasive code modification.

## Reproduction

```sh
python scripts/rayman2_guard_provenance_audit.py \
  --retail /private/Rayman2-CD.exe --gog /private/Rayman2-GOG.exe

python -m unittest discover -s scripts \
  -p 'test_rayman2_guard_provenance_audit.py'
```

The script uses the standard library, verifies both full SHA-256s,
validates PE32 section extents, recognizes only three known direct
read/compare opcodes and rejects unknown references. It emits metadata
and addresses only. Eight local tests passed, including integration on
both owner inputs; CI exercises seven synthetic tests and skips
private samples when absent.
