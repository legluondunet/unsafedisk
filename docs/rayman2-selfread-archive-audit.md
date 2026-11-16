# Rayman 2 — GOG's archived retail code as a substitute module base

**14 November 2026 — strictly read-only, SHA-256-gated PE32/x86 study.**

The two original user-owned inputs were independently authenticated:

| Input | Length | SHA-256 |
|---|---:|---|
| CD-sourced `Rayman2.exe` | 676,352 bytes | `7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3` |
| Separately modified GOG `Rayman2.exe` | 1,468,928 bytes | `9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713` |

**GOG is not a pristine post-decryption retail baseline.** The analysis neither executes nor patches either EXE, and no proprietary executable bytes are included here.

## Directly established connection between GOG's `.extra` archive and original module-base readers

The owner-provided CD executable is a PE32 image with base **`0x400000`**, `.text` at RVA **`0x1000`**, and **`0x9A200 = 631,296`** raw `.text` bytes. GOG retains the same PE image base and adds a **readable, non-executable** `.extra` section at VA **`0x517000`**, size **`0x9C000 = 638,976`** bytes, with section characteristics `0x40000040`.

The whole `.extra` payload is now accounted for:

| `.extra` offset | Length | Bytes |
|---|---:|---|
| `+0x0000` | `0x1000` = 4,096 | All zero |
| `+0x1000` | `0x9A200` = 631,296 | **Exact byte-for-byte original CD `.text`** |
| `+0x9B200` | `0xE00` = 3,584 | All zero |

The exact 631,296-byte copy and the original `.text` have SHA-256 **`43ce6eff6082f2c7491cd249d3cfeffbcb56e63313a67246dd2b14f1985751c3`**. By contrast, **13,269** of those 631,296 code bytes differ in the active GOG `.text`. This comparison always excludes the archival section from counts of *active* code.

In the original CD `.text`, two instruction regions build obfuscated 13-byte trampolines that invoke `GetModuleHandleA(NULL)`, i.e. retrieve the running module's image base. Both GOG sites change to the **same literal substitute** `MOV EAX,0x517000; JMP rel8`:

| Branch VA | CD original | GOG replacement | First shared instruction after GOG short jump |
|---|---|---|---|
| `0x470051` | PRNG-derived trampoline + `PUSH 0; CALL ESI` at `0x4700AC..0x4700AE` | `MOV EAX,0x517000; JMP 0x4700B3` | `0x4700B3: MOV [ESP+0x14],EAX` |
| `0x47B1C3` | PRNG-derived trampoline + `PUSH 0; CALL ESI` at `0x47B21E..0x47B220` | `MOV EAX,0x517000; JMP 0x47B225` | `0x47B225: MOV [ESP+0x10],EAX` |

The on-disk source, control-transfer bytes and shared continuation instructions have been checked in **both** exact executables. A separate complete raw-literal search of active GOG `.text` finds **only two occurrences** of the little-endian DWORD `0x00517000`, at operand sites `0x470052` and `0x47B1C4`.

Crucially, the second code path goes on to:

```asm
0x47B2A5: MOV EDX,[ESP+0x10]   ; saved module base
0x47B2A9: MOV EBX,[EDX+ESI]    ; read a DWORD at base + calculated offset
```

Both instructions are **unchanged** in CD and GOG, and the base saved at `0x47B225` is loaded by the first one. The `ESI` offset is read from a local at `0x47B294`, but its complete dynamic origin and range have **not** yet been proved.

With an RVA-like offset in the game's `.text`, the replacement maps the original address into the archive **at the corresponding offset**, e.g.:

| Offset | CD image address | GOG substitute address | Direct comparison |
|---|---|---|---|
| `0x70051` | `0x470051` | `0x587051` | Exact same original 16 bytes |
| `0x7B1C3` | `0x47B1C3` | `0x5921C3` | Exact same original 16 bytes |
| `0x4E8A0` | `0x44E8A0` | `0x5658A0` | Exact same original 16 bytes |

**Interpretation:** GOG is deliberately able to substitute a *data view of original CD code* where the original engine expects a module-base pointer. This provides a concrete byte-level mechanism by which self-referential reads could see unmodified retail `.text` despite GOG's altered *active* `.text`.

**Do not overinterpret:** the exact runtime `ESI` values, whether these paths execute during gameplay, whether all reads stay in the mirrored `.text`, and whether the reads enforce a checksum/anti-piracy decision are **not yet observed**. A plausible integrity role is not proof of the specific SafeDisc routine. `.extra` is non-executable: the analysis does not claim GOG is running the archived code or that `GetModuleHandleA` literally returns that pointer in the modified program.

This mechanism is distinct from the **`.extra2` virtual-CD manifest**, the original game's resource loader, and SafeDisc physical C2-error authentication. The supplied original CD `.ICD` and `DPLAYERX.DLL` remain fully reproducible PRNG data, not demonstrated encrypted PE payloads.

## Exact reproducibility and tests

```sh
python scripts/rayman2_selfread_archive_audit.py \
  --retail /private/Rayman2-CD.exe \
  --gog /private/Rayman2-GOG.exe
python -m unittest discover -s scripts -p 'test_rayman2_*.py'
```

The standalone audit checks input hashes, PE32 section bounds, `.extra` non-executability, the exact code mirror and padding, both patch opcodes and their short-jump targets, the original `PUSH NULL; CALL ESI` trampolines, preserved base stores, and the `MOV [module_base+index]` read. The code scans only active `.text` for archive-base literals and emits **metadata and addresses, not copied game bytes**. Synthetic tests reject corrupted archive data, wrong section flags, wrong branch bytes, unknown base-index reads, malformed PE structures, symlinks and unexpected extra archive-base literals.

**Local result:** **16/16 new synthetic tests**, and **149/149** tests in the combined standalone Rayman 2 research suite. Integration was run against the two exact owner-provided SHA-256 inputs. **No Windows/Wine gameplay, physical-disc validation, Rust compilation, or GitHub Actions job was run.** No unwrapped executable was generated.

**Recommended next discriminator:** recover the provenance and runtime range of `ESI` at `0x47B2A9`, and identify whether the resulting original-code DWORD is used in a compare/decision. Prefer read-only call/branch instrumentation over any executable patch until the code/data ambiguity is resolved.
