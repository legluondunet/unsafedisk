# Rayman 2 — passive Wine/Linux page-rights and guard probe

**15 November 2026. Experimental observation aid, read-only; not a SafeDisc unwrapper or a Rayman 2 fix.** No Wine process or game binary was executed during the development of this tool. An independent synthetic Linux process was used for an end-to-end test.

## Why a new tool is needed

Prior exact-SHA offline audits of the CD `Rayman2(3).exe` and modified GOG `rayman2(4).exe` establish that the original game writes machine-code trampolines into a 1,124-byte (`0x464`) buffer starting at **VA `0x510EA0`**. This buffer is in the virtual, zero-filled portion of `.data`, whose PE header reports **`0xC0000040` = read/write, no execute flag**. Both executables set `DllCharacteristics=0` (no `NX_COMPAT` opt-in). Selected original callers invoke the constructed code, while corresponding paths in GOG have been modified.

**Static PE flags are not the actual runtime page protections.** On Linux, a running Wine process has host mappings described by `/proc/<pid>/maps`. Reading those maps can give a *momentary* assessment of `rwx` permissions, without invasive breakpoints, disabling DEP, changing protections, writing to the game or attaching a debugger.

### Exact 4 KiB page geometry

| VA or range | Computation | Consequence |
|---|---|---|
| Generated-code buffer | `[0x510EA0, 0x511304)` | Spans `0x464=1124` bytes |
| First host page on a 4096-byte page system | `[0x510000,0x511000)` | Early generated stub locations |
| Second host page | `[0x511000,0x512000)` | Later generated stub locations |
| Guard value | `0x5113EC` | In the **second** page, `0xE8=232` bytes after the buffer's end |
| Original masked API pointer slots | `0x4A1400`, `0x4A1468`, `0x4A1498` | Initially zero in the on-disk PE, may be populated in the running process |
| Backend-selection flag | `0x510BF4` | Another sampled DWORD, not a verified DRM verdict |

The observer uses the actual Linux host page size, not a hardcoded 4096. On host systems with 64 KiB pages, the same buffer would fit in one host page. **Linux host rights still do not by themselves identify a SafeDisc failure.** A detected `r-xp` page says that mapping permits execution at that instant; it does not prove that a particular `CALL` happened. A non-executable page does not prove that a particular game path attempted execution there.

## Usage on Manjaro / Wine / Proton

Install nothing: Python 3 standard library only. Start the watcher in one terminal, then start the **original CD-sourced** game with Wine or Proton in another terminal:

```sh
python3 scripts/rayman2_wine_passive_pages.py \
  --watch 60 --poll-ms 100 --jsonl \
  > rayman2-pages.jsonl
```

To also *attempt* five read-only 32-bit memory samples:

```sh
python3 scripts/rayman2_wine_passive_pages.py \
  --watch 60 --poll-ms 100 --sample-state --jsonl \
  > rayman2-pages-and-state.jsonl
```

Or, if the PID of the **real `Rayman2.exe` Wine process** is known:

```sh
python3 scripts/rayman2_wine_passive_pages.py --pid 12345 --sample-state
```

- Auto-discovery requires the Linux `/proc/<pid>/comm` value to be `Rayman2.exe` (case-insensitive), to avoid probing arbitrary processes. If there are multiple matching processes, specify `--pid`. A launcher or Lutris helper is **not** the game process.
- Default mode reads **only `/proc/<pid>/comm`, `/proc/<pid>/stat` and `/proc/<pid>/maps`**. It reports the host-page execute bit for both buffer pages, the guard's page protection, and whether the game's entrypoint address is mapped executable.
- Optional `--sample-state` attempts *only five fixed DWORDs* via Linux `process_vm_readv`, with read-only `/proc/<pid>/mem` as fallback when the first system call is unavailable or denied. It emits the numeric value for the guard (`0x5113EC`) and backend flag (`0x510BF4`), and **booleans** for three masked API pointer slots. No payload or commercial instructions are printed or saved.
- Linux process access rules (Yama, namespaces, UID, SELinux/AppArmor, sandbox restrictions) may deny these reads. An unknown value (`null`) **is not zero**. No `sudo`, debugger configuration, permission bypass, system toggle or game patch is requested.
- Each record includes `/proc/PID/stat` field 22 (`process_start_ticks`, time since boot in clock ticks), verified before and after sampling. This detects PID recycling during a read and separates two processes that happen to reuse a PID; the Linux PID/name alone does not authenticate an EXE. The record never includes the full process command line or memory dump.
- `/proc/PID/maps` and optional memory samples are not an atomic snapshot. Even with stable PID identity, permissions or guard values can change between reads.
- `--watch` polls for up to five minutes, emitting only changes rather than every sample. Polling may miss short events. The first observed nonzero guard **is not the first writer instruction**. To identify the actual writer would require a separate, carefully scoped instrumented runtime trace.
- If only GOG runs, this probe records GOG behavior, not the original CD protection. The process name alone cannot authenticate an executing binary by its SHA-256; a user must independently verify which game build is launched.

## Validation performed here

1. The exact user-provided original EXE SHA-256 was rechecked (`7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`), and GOG SHA-256 independently rechecked (`9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`). The PE-specific page and guard sites come from existing exact-file opcode audits, not from an unverified pattern search.
2. Synthetic tests cover 4 KiB and 64 KiB page geometry, disjoint/overlapping/missing mappings, permission changes, candidate process filtering, PID-start-time parsing and recycling rejection, blocked memory reads, fixed-address whitelist, cross-platform parsers, and CLI output. They do not require the game binaries.
3. A **small synthetic native PIE program** named `Rayman2.exe` in `/proc` mapped its own harmless 32-bit test data at **the same virtual addresses** as the researched executable, with `/proc` permissions `rw-p/rw-p` and the entrypoint page `r-xp`. The watcher read the mock guard value `0x1234` and backend `1` and correctly identified its API slot booleans.
4. In that synthetic process, `mprotect` changed **only the second mapped page** to `r-xp`. The watcher independently re-read `/proc/<pid>/maps` and observed `rw-p/r-xp`, while the numeric guard still read `0x1234`. No generated code was executed, and no executable code was extracted from Rayman 2.
5. The native process fixture is strictly for tests and does **not** simulate SafeDisc, game logic, an ICD decoder, or an authentication failure. This upgraded version passes **30/30 Python tests** under Linux, including the native fixture and four additional PID-identity regression tests; Windows CI exercises the portable tests and skips the Linux-only fixture. Windows and actual Wine runtime behavior remain unverified.

```sh
python3 -m unittest discover -s scripts -p 'test_rayman2_wine_passive_pages.py' -v
```

The optional native smoke test compiles a synthetic C fixture only on Linux when `gcc` is available. It uses `MAP_FIXED_NOREPLACE` to refuse clobbering any existing mapping, and it never installs a module, uses privileged debugging or modifies another process.

**Conclusions supported:** We can now safely *observe* whether Wine maps the two buffer pages as executable, track the backend/guard **values** if OS policy allows, and separate these observations from the previous static PE section flags. **Not supported:** a runtime page protection result for the actual game; first writer of `0x5113EC`; successful execution of a generated stub; SafeDisc authentication check; executable decryption; playable CD game.
