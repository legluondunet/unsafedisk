# Rayman 2 — exact runtime PRNG bootstrap and original/GOG code-reference map

**14 November 2026. Read-only, exact-SHA binary evidence, not a SafeDisc decoder.**

The source files inspected offline are the owner's **676,352-byte original CD-sourced Rayman2.exe** (SHA-256 `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3`) and the separately modified **1,468,928-byte GOG Rayman2.exe** (SHA-256 `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713`).

## Exact executable bootstrap, unchanged in GOG

The whole **331-byte** original code interval **VA `0x00449360..0x004494AA`** is **byte-identical** in both EXEs: SHA-256 `508fb5bc006002d4a7efb27d30747ef453b843219f7fadd1f67b471e7ac30448`.

Actual source-code disassembly and an independent short-opcode-anchor check establish:

| VA | Original 32-bit x86 operation | Meaning |
|---|---|---|
| `0x00401EF8` | `PUSH 1; CALL 0x449360` | Call the common bootstrap with argument 1 |
| `0x00449391` | `CALL [0x49C060]` | IAT entry is `KERNEL32!QueryPerformanceCounter`, confirmed in both PE imports |
| `0x00449397` | `MOV ECX,[EBP-8]` | Read low DWORD of the 64-bit performance counter |
| `0x0044939E` | `MOV ECX,0x12345678` | Substitute fallback if QPC returned failure |
| `0x004493A3` | `MOV ESI,0x510EA0` | Buffer base for generated DWORD states |
| `0x004493A8` | `MOV EDI,0x119` | Exactly **281 iterations**, 1,124 bytes of state data |
| `0x004493AD` | `XOR ECX,0x075BD924` | Common masked PRNG salt |
| `0x004493BC` | `IMUL ECX,ECX,0x41A7` | Multiply by **16807** |
| `0x004493DF` | `MOV [ESI],ECX` | Store the newly generated DWORD |
| `0x004493EA` | `MOV [0x510BF0],ECX` | Retain the final state in global storage |

**Important distinction:** this is a *runtime-initialized* PRNG, seeded from QPC or a fixed fallback. None of the eight **on-disc pseudo-file PRNG seeds** is present as a raw 32-bit little-endian literal anywhere in either entire executable. This is no proof that a separate producer did (or did not) generate those eight files.

### Correct first step when QPC low DWORD has bit 31 set

The loop uses x86 signed integer arithmetic. When the 32-bit initial input has its high bit set, a naive **unsigned** multiplication produces a wrong first output. The faithful normalised algebra is:

```python
salt = 0x075BD924
multiplier = 16807
modulus = 2147483647
masked = (seed32 ^ salt) & 0xffffffff
signed = masked if masked < 0x80000000 else masked - 0x100000000
state = (signed * multiplier) % modulus
```

For a nonnegative 31-bit input this agrees with the eight file-stream recurrence; the difference only matters for an arbitrary initial QPC low DWORD. The first step already produces a state in `[0, 2147483646]`; subsequent iterations follow the ordinary 31-bit recurrence.

| Input seed | x86-equivalent signed first output | Incorrect unsigned first output |
|---|---|---|
| `0x12345678` | `0x4F2CEC02` | same |
| `0x80000000` | **`0x1F0C8C9B`** | `0x1F0D0FE9` |
| `0xFFFFFFFF` | **`0x60F2F016`** | `0x60F37364` |

The signed/unsigned first-word discrepancy is `2*16807 = 33614` modulo `2^31-1`. The fallback seed `0x12345678` yields the terminal state **`0x7A833570` after exactly 281 steps**.

**Independent arithmetic verification:** a Python instruction-by-instruction x86-width model was compared to the signed expression on **200,000 full-range 32-bit inputs**, without mismatch. A separate **C11** implementation independently reproduces the key instruction operations (including signed high-word multiplication, arithmetic shift and zero-normalisation) and agrees with the signed expression on another **200,000 synthetic 32-bit inputs**, including both signs. Six golden vectors and the fallback's full 281 iterations passed. The C test was compiled and run locally with `gcc -std=c11 -Wall -Wextra -Werror -O2`. The exact committed Git blob SHA-1 `6225a02fff2c04a0dbee9cdd408ca29da2f56e74` matches the locally compiled source.

## 196 original global PRNG references; exactly 128 removed from active GOG code

Scan **only PE sections**, not whole files. The original executable has 196 raw little-endian occurrences of global state VA `0x00510BF0` and 73 of salt `0x075BD924` in `.text`. All match the corresponding `objdump -d -M intel` disassembly counts. The active GOG `.text` has 68 and 29 respectively, **all retained at the exact original RVA offsets, none new**.

| Literal DWORD occurrence | Original CD `.text` | GOG active `.text` | GOG's non-executable archival copy of original `.text` |
|---|---:|---:|---:|
| Global PRNG pointer `0x00510BF0` | **196** | **68** | **196** |
| XOR salt `0x075BD924` | **73** | **29** | **73** |

**128 removed pointer occurrences and 44 removed XOR salt occurrences** map to the following **eight** RVA pages in the original `.text`. The page distribution is derived by comparing byte offsets, with independently pinned common section RVA `0x1000`:

| RVA page | Removed global pointer occurrences | Removed XOR salt occurrences |
|---|---:|---:|
| `0x47000` | 12 | 4 |
| `0x48000` | 45 | 15 |
| `0x49000` | 9 | 3 |
| `0x4D000` | 3 | 1 |
| `0x4E000` | 17 | 6 |
| `0x4F000` | 12 | 4 |
| `0x50000` | 15 | 5 |
| `0x51000` | 15 | 6 |
| **Total** | **128** | **44** |

The edited GOG's non-executable `.extra` contains a **byte-exact copy of the original `.text`** at `.extra+0x1000`, including those 196 and 73 old references. **Never count this archival copy as active GOG code.** None of these static counts is a runtime call counter or by itself sufficient to assign particular changes to SafeDisc rather than GOG's other modifications.

## Which old masked-pointer instruction beginnings did GOG remove?

An independent, read-only search looked for the **actual
x86 instruction prefix** `8B 0D F0 0B 51 00`,
meaning `MOV ECX,[0x510BF0]`, in both active
`.text` sections at the *same virtual addresses*.
This is a narrower probe than simply searching the
four-byte pointer operand anywhere.

| Instruction-site classification | Count |
|---|---:|
| Original sites starting with this MOV instruction | **64** |
| Preserved at exactly the same site in active GOG | **22** |
| Changed sites in GOG | **42** |
| — replaced with `INT3` (`CC`) at old start | **31** |
| — replaced with `NOP` (`90`) at old start | **3** |
| — replaced with ordinary `PUSH EBP; MOV EBP,ESP` prologue | **4** |
| — other replacement at old start | **4** |

The **four new ordinary function prologues** occur
at `0x00448500`, `0x0044E750`,
`0x0044F220` and `0x0044F380`.
The existing independent
`scripts/rayman2_win32_forwarders.py`
research verifies these as normal
**CloseHandle / ReadFile / CreateFileA /
SetFilePointer** Win32 forwarders in
GOG, respectively. This new categorisation
must not be used to infer that the
remaining 38 changed instruction starts
were all separate function entries or
exclusively SafeDisc protection routines.
A separate synthetic unit test now covers
all four replacement categories.

The counts complement the **128 removed raw
pointer DWORD occurrences** (which include
references to the shared global in more
forms than this one six-byte MOV opcode).
Neither count proves live execution
or a specific original-CD authentication step.

## Formal limitation of the eight on-disc PRNG files

The eight previously verified SHA-256-pinned auxiliary files contain **1,548,525 total bytes**, yet all are generated from eight 31-bit initial states plus **5 retained prefix bytes** with a fully known recurrence and known file lengths. Conditioned on the recurrence and lengths, that is an **upper bound of 8×31+5×8 = 288 bits of variable source data**, for over **12 million output bits**. This is a deterministic description-length bound, **not a measured Shannon entropy estimate**.

Those exact bytes therefore cannot independently encode a general, unknown multi-hundred-KiB native PE executable. Recovering any such game payload would require an **external data source, different disc stage or additional provenance**. Do not assume that their SafeDisc-style names prove they contain a genuine encrypted loader image.

## Reproduction and scope

The existing `scripts/rayman2_auxiliary_stream_audit.py` now emits `original_vs_gog_rng_code`, including the per-page reference-diff map, and `runtime_rng_initializer` if given both exact hash-gated EXEs alongside at least one exact owner auxiliary sample. No protected bytes are output.

```sh
python scripts/rayman2_auxiliary_stream_audit.py \
  --icd /private/RAYMAN2.ICD \
  --retail /private/retail-Rayman2.exe \
  --gog /private/GOG-Rayman2.exe

python -m unittest discover -s scripts \
  -p 'test_rayman2_auxiliary_stream_audit.py'
gcc -std=c11 -Wall -Wextra -Werror -O2 \
  scripts/test_rayman2_runtime_prng_x86.c \
  -o /tmp/test_rayman2_runtime_prng_x86
/tmp/test_rayman2_runtime_prng_x86
```

**Validated:** original and GOG full SHA-256; original-to-archival 631,296-byte identity; non-executable `.extra` flags; 10 original/GOG instruction anchors and the exact 331-byte initializer SHA; both `objdump` counts; the eight-page histogram; Python 200,000-input and C11 200,000-input signed mathematical controls; C11 test source identical to GitHub's blob. **The newly modified GitHub Python unit-test module itself has not been run as an exact repository checkout or in GitHub Actions**. No game, DRM module or original commercial PE payload was executed or committed. No native SafeDisc 1.35 executable unwrapping is claimed.
