# Rayman 2 — V2 crash after successful DAT reads: runtime evidence and CD reference comparison

**15 November 2026 — actual user Wine trace, exact runtime PE test.** This is a read-only diagnostic and a comparison plan, **not** a SafeDisc bypass or an executable repair. The user-supplied `rayman2-v2-resource-trace.json` was parsed directly in the analysis environment, and the crash registers were supplied in the same conversation.

## The previously hypothetical read failure is contradicted by the trace

- The input EXE SHA-256 is `35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d`, the exact known **V2** build, 676,352 bytes. The runner exited with code 5 after 11,999 trace lines (about 1.42 MB processed).
- The installed directory has 2,115 files, including 71 `.GPT` files and **one** `.DAT`: `data/world/levels/levels0.dat` at **150,775,808 bytes**. This is an inventory of the user's current portable folder, **not** evidence that the original CD should contain only one DAT file.
- Wine tried `Data\World\Levels/whale_10/whale_10.dsc` and got `c0000034` (object name not found). It then successfully opened `./Data\World\Levels\LEVELS0.DAT` (Windows handle `0xCC`, `CreateFileW returning 000000CC`). The missing `.dsc` may be an ordinary fallback trigger, not an error if DAT fallback succeeds.
- The same handle `0xCC` has many reported successful reads: at least one 16-byte read, multiple 4-byte reads, two **512-byte** reads, then a 1-byte / 4-byte / 1-byte / 1-byte / **4-byte** sequence immediately before the crash. The **final** pair is:

  ```text
  0134:trace:file:ReadFile 000000CC 0414FBD4 4 0414FB58 00000000
  0134:trace:file:NtReadFile (0xcc,...,0x414fbd4,0x00000004,...)
  0134:trace:file:NtReadFile = SUCCESS (4)
  ```

- `EBP=0x0414FBE0`; therefore `EBP-0xC = 0x0414FBD4`, exactly the buffer address of that final successful 4-byte read. The game frame contains the value `0x8F25F658` at that address. The raw x86 at `0x44DD49..0x44DD57` passes `[EBP-0xC]` to the generic reader `0x450D90` and then loads that DWORD.
- `0x8F25F658 = 2,401,629,784`. Its 32-bit multiple of eight is `0x792FB2C0`, the register `EDX` and saved stack size seen when allocation at `0x44DD69` failed. The allocator at `0x45DCC5` subsequently tries to clear memory via `REP STOSD` while `EDI=0`, causing the observed null write. The prior test at the same fault had a different alleged count `0x153E3D8C`.

**Correction to earlier assessment:** while `0x44DD52` indeed does not check the *generic reader's* success flag, **this particular trace shows a successful underlying 4-byte Windows read into the exact output buffer**. A missing `ReadFile` return is not the demonstrated cause. This does not yet prove whether the 4-byte value was transformed by a callback, taken from a wrong file offset, or reflects genuine resource structure.

## Independent static validation on the known CD and GOG samples

The owner-provided exact-SHA retail CD and GOG modified executables were disassembled with GNU `objdump`. Their active `.text` bytes are **identical** across both `0x44DC40..0x44DDDE` (resource structure parser) and `0x450D90..0x450EAF` (generic reader). The V2 experiment differs from the original CD at earlier file-selection and portable-path points. Thus simply copying one more arbitrary opcode from GOG in this shared parser would not address the unverified upstream resource position.

The trace **does not expose the actual file offset** used for the final read: `NtSetInformationFile` lines include pointers to structures, not their dereferenced positions. Do not infer the contents of `LEVELS0.DAT` from the register alone.

## Next discriminator: one read-only A/B with the confirmed working PE32-only build

1. Mount the same original Rayman 2 CD used for the prior successful launch.
2. Run the **known, already working** `Rayman2-PE32-test.exe` with the same Wine prefix and game folder, enabling the bounded `+file` tracer. **Do not apply a new patch**.
3. Compare the asset paths and read sizes against the **existing failing V2 trace**, preserving the distinction between (a) media/resource paths, (b) reads from `LEVELS0.DAT`, and (c) actual parsed content/offsets not visible to Wine's `+file` channel.

The helper `scripts/rayman2_cd_reference_trace.py` checks the precise PE32-only SHA-256 `f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703`, validates the known V2 JSON against SHA-256, and uses the previous read-only tracer `scripts/rayman2_v2_filetrace.py`. It records first/tail excerpt summaries and a comparison JSON, caps observation duration and trace bytes, and modifies **no game file**. The script does **not** independently verify the CD is mounted; its flag is only an acknowledgement by the tester.

A successful real-game CD trace compared with V2 may identify **which files** the two paths use, and whether one path invokes a different read sequence. It will **not by itself** identify the four bytes at the actual offset or prove a SafeDisc verdict. A subsequent file-offset probe, if needed, must be justified by these results.

Local verification before GitHub publication: **24/24 tests passed** (14 original V2 observer tests + 10 new pure/synthetic and one private JSON integration test, excluded from public CI when the input trace is absent). Windows runner execution is not supported, but Python syntax/tests do not require Wine.
