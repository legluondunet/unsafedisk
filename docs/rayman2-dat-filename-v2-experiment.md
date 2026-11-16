# Rayman 2 — second CD dialog after relative-path prototype: DAT name V2 experiment

**15 November 2026. Experimental local executable *copy* only, no protected-game file committed.**

## First observed runtime symptom after V1

The owner ran the SHA-pinned V1 `Rayman2-portable-test.exe` with the CD unmounted. Unlike the prior CD volume-label prompt, the game displayed its main window, then the distinct messagebox **`CDROM not found!`**, with body **`Please insert the CD`** and **Retry / Cancel** buttons. The screenshot is user evidence of the dialog, not an instrumented stack trace.

The original CD function `0x44EB40` first obtains a handle to `LEVELS0.DAT`. Later, the function computes the **EBX selector** based on data from an earlier 16-byte and 4-byte read, then at **`0x44F13A`** reads the filename pointer **`[EBX*4 + 0x4A2090]`** from a 24-record DAT-name table. The next `CreateFileA` call at **`0x44F17D`** returns the second handle, checked against **`-1`** at `0x44F184`, and on failure the `0x44F195` path displays `CDROM not found!`. This is the static control-flow path consistent with the second screenshot. **The selected EBX and actual requested pathname have not been dynamically observed.**

Unlike the earlier logical volume-label detector, this path reports a real **file-open failure**. The selected file could be missing, inaccessible, misnamed, or otherwise fail to open. Previous ISO inspection logs contain many oversized/suspect DAT entries omitted by the portable installer; their declared ISO extents do not guarantee real file bytes. Do **not** create fabricated DAT files or equate the dialogue to proven SafeDisc C2-sector authentication.

## Exactly one V2 hypothesis

GOG modifies the original selection in place:

| Active VA | CD original | Modified GOG reference / V2 proposal |
|---|---|---|
| `0x44F13A` (7 bytes) | `8B 14 9D 90 20 4A 00` — `MOV EDX,[EBX*4 + 0x4A2090]` | `8B 15 90 20 4A 00 90` — `MOV EDX,[0x4A2090]; NOP` |

`[0x4A2090]` points to **`LEVELS0.DAT`**. V2 changes this specific filename selection and leaves **all the original DAT reads, the two extra 512-byte file reads, arithmetic operations, return-value logic, and other callsites in place**. This is more discriminating than transplanting GOG's additional DAT changes as a batch.

V2 works **only on the exact V1 candidate** produced by the already published `rayman2_portable_cd_probe.py`, with input SHA-256:

`6702ff583cb0ee1f1023cc4b334ef4dab3f737a0ee7f272fe31dd13a9f23ce71`

Expected V2 output: 676,352-byte PE32, SHA-256:

`35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d`

**Exactly six different byte values** occur within the one seven-byte instruction span. Source file is never overwritten; existing output names are rejected. Neither proprietary input nor resulting executable is distributed.

## Verification

- 11/11 Python tests passed locally, including the independent synthetic PE fixture and the optional exact original/GOG integration test.
- Exact original CD file SHA-256: `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
- GOG is *not* a pristine deprotected original; comparing these seven opcode bytes does not mean all GOG modifications are safe for the CD edition.
- With the owner-supplied CD and prior V1 generator, the generated V2 hash was independently checked; code and file size beyond this seven-byte span remain unchanged relative to V1.
- This change **has not yet been executed under Wine**. It does not establish SafeDisc removal, no-CD playability, or even elimination of the second CD message.

To run the optional owner-only tests:

```sh
RAYMAN2_RETAIL_ORIGINAL='/private/Rayman2-CD.exe' \
RAYMAN2_GOG_REFERENCE='/private/Rayman2-GOG.exe' \
python -m unittest discover -s scripts -p 'test_rayman2_dat_name_probe_v2.py'
```

To generate the V2 *from the exact V1* without modifying the input:

```sh
python scripts/rayman2_dat_name_probe_v2.py Rayman2-portable-test.exe Rayman2-portable-v2-test.exe
```

A further read-only `WINEDEBUG=trace+file` run is valuable **if the same error remains**: capture the last attempted `.DAT` pathname and file-system failure near the dialog. The debug log should be filtered to avoid gigabytes of unrelated output, and no live DRM conclusions drawn from filenames alone.

The V1 logical CD removal and V2 DAT filename choice are **two distinct game-layer dependencies**. Neither is evidence of a recovered SafeDisc executable-decryption algorithm. Keep the PR in draft; no merge or release until runtime findings justify them.
