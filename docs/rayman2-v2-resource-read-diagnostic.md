# Rayman 2 — V2 no-CD crash: unchecked resource read and bounded Wine file trace

**15 November 2026. Diagnostic only. No new game patch and no claim of SafeDisc unwrapping.**

## What was actually observed

The owner launched the exact V2 candidate produced by the previous two SHA-locked generators on Manjaro Wine-staging 11.17, without the CD. The process terminated with a 32-bit write AV at `0x0045DCC5` (`REP STOSD` with `EDI=0`). The report contains `EDX=0xA9F1EC60`. The original code at `0x44DD61` requests `8*N` bytes; `0xA9F1EC60 / 8` is `0x153E3D8C = 356,400,524` records. This is evidence of an implausible allocation request, **not** proof that those four bytes were present in any file.

## Precise static dataflow, original CD and modified GOG both retain it

This audit uses the exact archived user-provided retail CD `Rayman2(3).exe` (676,352 bytes, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`) and the separately modified GOG comparator `rayman2(4).exe` (1,468,928 bytes, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`). All the following opcode spans have been checked against the **active** PE `.text`, rather than GOG's archival `.extra` section:

| Site | Bytes / action | Inference bound |
|---|---|---|
| `0x44DC80` | `E8 0B FD FF FF` → `CALL 0x44D990` | The engine chooses a resource stream, using DAT or a fallback path |
| `0x44DC88` | `TEST AL,AL; JNE 0x44DC95` | The parser proceeds only on the loader's reported success |
| `0x44DD52` | `E8 39 30 00 00` → `CALL 0x450D90` with a local 4-byte output at `[EBP-0x0C]` | Requests four bytes from the resource reader |
| `0x450DD5..0x450DE5` | `CALL [EBX+0x24]`; on `AL=0`, returns `EAX=0` | The reader can explicitly report failure |
| `0x44DD57..0x44DD69` | `MOV EAX,[EBP-0x0C]; ADD ESP,16; TEST EAX,EAX; ... LEA ECX,[EAX*8]; PUSH ECX; CALL 0x45DC60` | **The caller does not check the reader's return value**, only the output DWORD. If the read failed, the output value is not established by this call path. |
| `0x45DC8E..0x45DCC5` | Allocation result stored in `ESI`; if NULL, an error routine is called, then flow reaches `REP STOSD` with `EDI=ESI` | Consistent with the observed NULL-write crash. Does not prove the reason the 4-byte read failed. |

The original `0x44DC40` frame reserves `0x40` bytes but contains **no explicit initialization of `[EBP-0x0C]` prior to `0x44DD52`** on the audited path. Thus it is possible that the large count is uninitialized stack content after a failed read, rather than malformed bytes from a real DAT. Disambiguating those cases requires the actual file open/read outcomes or a live data breakpoint; guessing and patching the allocator would mask the upstream problem.

**An earlier attribution is now corrected:** *both* `0x44DB5A` (resource fallback) and `0x44F195` (second DAT file open) show the **same** `CDROM not found!` / `Please insert the CD` dialog. The screenshot of V1 alone did not distinguish the two branches. Therefore the V2 fixed-filename transplant was not a logically sufficient fix.

## Safer next experiment: record file events only, without producing another game EXE

A **standalone, bounded Linux-only observer** is provided as `scripts/rayman2_v2_filetrace.py`. It:

1. Refuses any executable except the exact V2 SHA-256 `35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d` (source EXE is never modified).
2. Inventory-checks the 24 expected DAT basenames, their relative locations and sizes, and counts `.GPT` files without reading their contents, following symlinks or scanning outside the installation folder.
3. Launches that V2 from its own working directory with `WINEDEBUG=-all,trace+file,err+all`; streams the output **without saving raw gigabytes**, retaining bounded first/last file operations, DAT/GPT/RT* file-path mentions and error/status lines.
4. Stops its *own new launcher process group* after 35 seconds if still running (user may see an exception dialog). Never calls `wineserver -k`, does not attach to an existing process, and does not alter the Wine prefix.
5. Saves one JSON report, including open/read activity and the static resource inventory; no game binary, DAT content, decrypted code or runtime memory dump.

Example in the installed game directory, **with the CD unmounted** and the same `WINEPREFIX` as before:

```sh
python3 scripts/rayman2_v2_filetrace.py ./Rayman2-portable-v2-test.exe \
  --seconds 35 --out "$HOME/rayman2-v2-resource-trace.json"
```

If the JSON includes a missing resource path or failed read, diagnose that first. If it does not, the retained samples may be insufficient: the script does **not** claim exhaustive per-handle coverage nor an observed call instruction. More intrusive debugging can be considered only with a concrete reason. The Wine `file` trace channel and its return-status syntax are described by the Wine debugging documentation; this script's parsing has been exercised only against synthetic examples because Wine is not installed in the research container.

## Validation boundaries

- 14 synthetic tests verify exact-hash gate, symlink and overwrite refusal, expected 24 DAT names, bounded inventory, Win32-style file/event matching, bounded output, fake Wine exit and timeout cleanup.
- The optional exact-owner `Rayman2(3).exe` and GOG bytes were inspected locally with GNU `objdump` and direct PE32 mapped bytes; the relevant source opcodes are identical in both active `.text` regions.
- A locally generated exact V2 from the CD file passed the new observer's `--inventory-only` integration. This checked identity and inventory handling, **not a real Wine trace**.
- No revised `Rayman2.exe` binary is built or published in this step. The experimental V2 remains **unvalidated** and must not be promoted to a release.
