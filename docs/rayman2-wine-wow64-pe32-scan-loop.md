# Rayman 2 CD: Wine WoW64 module-scanner exception loop (15 Nov 2026)

**Status: first actual startup trace from owner, exact CD comparison and experimental read-only/patch-on-copy prototype. NO playable SafeDisc-unwrapped executable obtained.**

## Input identities and runtime provenance

- Owner's original CD-sourced reference `Rayman2(3).exe`: 676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- Owner's *different, modified* GOG comparator: 1,468,928 bytes, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.
- Runtime ZIP from owner (`rayman2-wine-startup.log.zip`): single log of **727,158,166 decompressed bytes / 7,493,789 lines**, produced with `WINEDEBUG=+seh,+loaddll`, Wine-staging **11.17**.
- The process is explicitly loaded from `.../Rayman 2/Rayman2Fix/Rayman2.exe` at image base `0x00400000`. **The exact SHA-256 of this executed file is not logged.** Do not automatically equate it with either exact reference executable. The observed x86 instructions, however, belong to the original-code region that GOG's *active* executable replaces with `INT3`.
- Wine also loads native **64-bit** WoW64 modules including `wow64cpu.dll` at **`0x7BC40000`** and a 32-bit `KERNEL32.dll` at **`0x7BAB0000`**.

## Precise exception statistics

An independent native line scan of the whole 727 MB log gives:

| Exception site (x86 EIP) | 32-bit dispatches | 64-bit WoW64 mirrored dispatches | Total |
|---|---:|---:|---:|
| `0x00447CCD` | 1,026 | 1,026 | 2,052 |
| `0x00447C39` | 257,367 | 257,368 | 514,735 |
| **Total** | **258,393** | **258,394** | **516,787** |

The total of **516,787** corresponds exactly to the two per-address histograms above. The x86 and 64-bit WoW64 representations should **not** be interpreted as 516,787 independent crashes. There are **258,393 x86 exception dispatches**, each mirrored by 64-bit logging except the final unpaired entry at EOF.

The x86 exception handler at `0x00447C8A` reported return `0` exactly **258,393** times. The trace ends **inside the repeated exception sequence**, not at a clean exit or an unhandled-fault report. A 64-bit dispatch and x86 dispatch can be two views of the **same exception**; the above tallies are *trace records*, not separate failures.

Initial x86 `0x447CCD` context: `EAX=0x80000000, ECX=0x1000, EDX=0x10000`. The code scans virtual memory backward at 64-KiB steps; on a bad read, its SEH handler updates the saved context and retries.

After encountering the module at **`0x7BC40000`**, the exception site changes to **`0x447C39`**, trying to read a DLL's export-directory Name. The **first invalid ECX is `0x7FC400BA`**; the last fully recorded x86 ECX is **`0x7FC01364`**. Their difference is exactly **257,366 bytes**. This directly matches the **257,367 successive x86 events**: the handler decrements ECX by *one* on each fault and retries. The log does not show completion.

No string `SECDRV`, `CLCD32`, `DPLAYERX`, `CLOKSPL` or `SafeDisc` occurs in this **particular** Wine log, and there is no explicit load of these modules. Absence of a string is not proof the game contains no later physical media checks.

## Root-cause candidate directly established by CD machine code

The first-stage function `0x00447C80..0x00447D07` iterates over memory looking for `KERNEL32.DLL`:

- `0x447CCD: MOV EBX,[EAX]` fetches each candidate header; its locally installed SEH handler is `0x447C8A`.
- `0x447CD7: CALL 0x447BE0` tests an accessible candidate and iterates until it finds the named DLL.
- `0x447C0C: CMP WORD [EDX],0x5A4D` checks `MZ`.
- `0x447C18: CMP DWORD [ECX],0x4550` checks `PE`.
- **`0x447C20: ADD ECX,0x18; 0x447C27: MOV ECX,[ECX+0x60]` reads the export directory as PE32 without checking the OptionalHeader Magic** (`0x10B` for PE32, `0x20B` for PE32+). PE32+ uses `+0x70` for its data directory.
- `0x447C34: MOV ECX,[ECX+0x0C]; 0x447C37: ADD ECX,EDX` calculates the supposed export Name pointer; **`0x447C39: MOV EDX,[ECX]`** faults on the invalid pointer.
- The exception handler modifies CONTEXT EAX and ECX, respectively at `[CONTEXT+0xB0]` and `[CONTEXT+0xAC]`. The latter is the **supposed exported-name pointer at this later call site**, not the original memory-page iteration count. Decrement-and-retry gets trapped in a very long scan of unrelated addresses.

On this owner's run, the encountered `0x7BC40000` module is the WoW64 CPU DLL, *not* 32-bit KERNEL32. This and the PE32-only export parse are **a strong explanation** for the observed pre-window hang. A live dump of the actual module OptionalHeader Magic is still needed for a definitive PE32+ assertion. Official references: Microsoft PE/COFF format, Wine 11.0 new WoW64 release notes.

## Minimal experimental correction (exact-title, patch-on-copy only)

`rayman2_pe32_module_scan_test.py` produces a new EXE after verifying the **entire SHA-256**, original scanner opcodes, adjacent guards, PE32 geometry and output nonexistence. It modifies **only 25 bytes at VA `0x447C20..0x447C38`**:

- preserve the original pointer to OptionalHeader;
- add `CMP WORD [ECX],0x10B; JNE 0x447C77` to skip non-PE32 modules;
- preserve original PE32 export RVA read, zero-RVA check, name lookup, and subsequent checks at `0x447C39` onward;
- remove only redundant null-pointer tests after the already-validated PE header and following addition.

No original executable is overwritten. No CD driver or SafeDisc check is patched or bypassed intentionally. No GOG content is transplanted. The script is **not a SafeDisc decryptor** and cannot show a valid game launch without independent Wine/Windows testing.

Exact local reference test produced **676,352 bytes**, SHA-256 `f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703`, with all other bytes identical to the original source. The output itself is **not published or bundled**, only the patcher and synthetic tests.

`python -m unittest discover -s scripts -p 'test_rayman2_pe32_module_scan_test.py'` passes **16 synthetic checks**; with the optional owner-provided file `RAYMAN2_CD_EXE` set, **17/17 tests** pass, including the exact private input and expected patched digest.

## Next runtime discriminator

First confirm the launched executable's SHA. On a **separate copy of the installed game**, run the strict patcher against an original `Rayman2.exe` matching the pinned SHA and inspect what happens next under Wine. If it reaches a later failure, collect a *bounded* trace, not another unbounded 727-MB `+seh` log. If the full hash differs, do not force this patch; identify that exact binary first.

**Not established:** playable output; decryption of SafeDisc, driver/mount authentication, or correct behavior after the early scanner.
