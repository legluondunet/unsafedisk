# Rayman 2 — guard registration, code/data boundary, historical 2006 crosscheck

**14 November 2026. Read-only static PE32 audit, SHA-locked to the owner's two original samples. No retail decryption, no patched game executable.**

## File identity and historical provenance

The owner's CD-sourced `Rayman2(3).exe` is **676,352 bytes**, SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`.
The separately modified **GOG** `Rayman2.exe` is **1,468,928 bytes**, SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`.

A previously overlooked independent **December 18, 2006** FileForums post about Rayman 2 directly lists two opcodes, including their original virtual addresses:

- `0x00448E39 MOV EAX,DWORD PTR DS:[5113EC]`;
- `0x00405856 MOV EAX,DWORD PTR DS:[5113EC]`.

Source: https://fileforums.com/showthread.php?nojs=1&p=334047 (post #15, cdkiller; other participants note that they cannot always distinguish CD checks from genuine CD resource reads).

**Both exact five-byte `A1 EC 13 51 00` instructions are present at those original VAs in both owner binaries**, corroborated by `objdump`. The historical post reported an EXE size of **676,397 bytes** and identified it as **Petite v2.2**. Our CD-sourced PE input is **45 bytes shorter** and already contains a complete mapped plaintext x86 `.text`. Similar instruction sites and identical `0x45FCC0` original entrypoint do not prove the on-disk files are byte-identical or the same edition/representation. Do not transfer file-offset patches or hash assumptions across them.

The 2006 post described changing the guard loads to literal `1` as a *partial experiment* (the author's claim was only that an earlier missing-DLL problem no longer appeared). In the owner's verified x86 bytes, **both functions immediately register a code start/end pair and return when the guard is nonzero**, instead of executing their ordinary body. Therefore setting this DWORD to `1` **cannot be accepted as verified playable SafeDisc 1.35 removal**. The test would skip legitimate CD-volume and engine setup, at least. We do **not** apply it.

## Exact owner PE metadata

The two PE32 inputs both have:

- fixed ImageBase `0x400000`, AddressOfEntryPoint RVA `0x5FCC0` (VA `0x45FCC0`);
- `IMAGE_FILE_RELOCS_STRIPPED` set;
- both `IMAGE_DIRECTORY_ENTRY_BASERELOC` and `IMAGE_DIRECTORY_ENTRY_TLS` present with **zero RVA/zero length** (i.e., *no declared relocation or TLS callback directory*);
- BSS-like zero-filled `.data` containing `0x5113EC` (previously demonstrated in [guard BSS census](rayman2-startup-guard-bss-census.md)).

These facts show only the file-declared loader metadata. They do **not** rule out calculated pointers, indirect writes, dynamically generated code, external DLL/DRM bootstrap code or other runtime mutation.

## Literal-pointer census by **PE section** (new)

The previous [28-span audit](rayman2-28-guarded-code-ranges.md) independently verified:

- **28** direct guard reads in the original, **16** in active GOG;
- **56** distinct address slots (24 primary start/end pairs, four secondary pairs);
- every directly active guard branch emits exactly **two 10-byte `MOV DWORD [imm32],imm32` stores** registering a code interval;
- **56** such stores in original, **32** in GOG active code.

For the new audit, every one of the **57 exact DWORD target addresses** (the guard plus 56 table slots) is searched at **every byte offset in every file-backed PE section**, not only at instruction boundaries. Values are compared section by section. Results:

| Section / role | CD input | GOG input |
| --- | ---: | ---: |
| Active executable `.text` | **85** literal occurrences | **49** |
| `.rdata` | **0** | **0** |
| File-backed `.data` | **0** | **0** |
| GOG non-executable `.extra` archive | — | **85** |
| GOG `.extra2` | — | **0** |
| GOG `.rsrc` | — | **0** |

In original active `.text`, 85 = **28 guard reads + 56 table-slot stores + one extra exact slot-address literal**. The one extra `0x510C00` value is at **VA `0x497FE7`** in an embedded code/data ambiguity already analysed; this occurrence **is not established as a real table reader**. In GOG active `.text`, 49 = **16 guard reads + 32 table-slot stores + the same extra literal**.

The archived `.extra` contains a byte-for-byte copy of the original `.text` at section raw offset `+0x1000`, so its 85 matches are the **old instructions stored as data**. That section's PE flags do not include `IMAGE_SCN_MEM_EXECUTE`. Counting them as live xrefs would manufacture missing readers and overcount removed protection code.

**Most important negative-control result:** there is **no additional exact four-byte literal address for these 57 constants** in the active file-backed `.rdata` or `.data` of either sample. There is also no newly identified direct `.text` read of the slot pointers by name. **This is *not* proof of no consumer**: a consumer could take a base address then add an index, use a calculated address/offset, be written dynamically, execute in an external module or be invoked before the sampled code's entrypoint. Nor does absence of TLS metadata rule out a separate SafeDisc loader.

The above results are generated from exact SHA-verified inputs by `scripts/rayman2_guard_boundary_audit.py`. The original and GOG are **never rewritten**, and the script publishes only addresses, counts, hashes and structural flags.

## Practical next discriminant, without guesswork

A passive runtime trace of the authentic CD-sourced image is the needed missing evidence:

1. Place a **write watchpoint on `0x5113EC`** from process creation or as early as the debugger can attach. Record first writer instruction, thread/module and actual value.
2. If a nonzero value is observed, record execution of any of the 28 guard prologues (for example `0x405856`, `0x448E39`, `0x449366`) and whether paired stores at `0x510C00/0x510DC0` actually occur.
3. Watch for a **read** of registered intervals. If no direct in-module reader is found, identify any external module or dynamically computed pointer. Save only module names, instruction addresses, values and call stacks; game resources or decrypted commercial code are not needed in the report.
4. Separately observe the subsequent CD-volume check and DAT resource access; these are normal game requirements in addition to any physical SafeDisc driver/authentication.

An unchanged BSS initial value of zero in our static PE files **does not prove** a running, normally protected process never modifies it. And forcing `1` would produce a different control-flow path, **not** a validated clean retail unpack.

## Test and reproduction

```sh
python scripts/rayman2_guard_boundary_audit.py \
  --retail '/private/Rayman2(3).exe' \
  --gog '/private/Rayman2.exe'
python -m unittest discover -s scripts -p 'test_rayman2_guard_boundary_audit.py'
```

All results are guarded by the two exact whole-file SHA-256 fingerprints, validated PE sections, 28 source ranges, 56 original and 32 GOG stores, expected 85/49/85 literal counts, actual original-code archive equality, and exact historical instruction sites. The local private-input equivalent passed 10/10 tests; CI runs synthetic tests with private integration skipped by default. A successful CI run **does not** mean a decrypted or runnable Rayman 2 retail executable has been created.
