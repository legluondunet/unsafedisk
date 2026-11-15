# Rayman 2 — A/B Wine trace: CD reference not established, V2 still crashes

15 November 2026. User-provided runtime evidence: `rayman2-cd-ab-comparison.json` plus screenshot and Wine stack trace. No original game file is distributed or modified by this report.

## Two distinct outcomes

- The verified **PE32-only** executable (SHA-256 `f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703`) displayed the original `Rayman 2 CD not found` / `Please, insert Rayman II CD in CDROM Drive` prompt. Its diagnostic run exited with code **254**, and the *sampled* trace did not include a level resource open. This run does **not** provide a working-CD comparison; despite `--cd-mounted`, the diagnostic did not ascertain a CD-ROM-type Windows drive with volume label `RAYMAN2`.
- The verified **portable V2** (SHA-256 `35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d`) exited with code **5** and repeated the exact `0x45DCC5` write-to-null exception. This time the stack local feeding the count was `0x9F9A412B` (2,677,686,571 decimal), and its 32-bit `count*8` equals **`0xFCD20958`**, matching `EDX` in the crash. Earlier V2 attempts yielded different huge counts. Do not equate the resulting modulo-32 size with a successful allocation request.

## Successful local DAT opens are not proof of correct resource offsets

- The diagnostic found **one installed DAT**: `Data/World/Levels/LEVELS0.DAT` (150,775,808 bytes) and 71 `.GPT` files. This is *installation* inventory, not a catalog of the physical original CD.
- The V2 trace confirms successful opening and repeated reads of 1, 4, 16 and 512 bytes from local `LEVELS0.DAT`, not a file-not-found failure at the last four-byte resource read. The recorded attempts to open `whale_00`, `whale_05`, `whale_10` `.dsc` paths report missing entries and are followed by DAT fallback attempts. Do not infer those `.dsc` files must be independent on-disk assets.
- Wine `+file` in this report does **not** reveal the source offsets or the returned four-byte contents. A successful `ReadFile` therefore does not certify correct stream position, data decoding or length interpreted by the original engine.

## Correction to the comparison script

In original PR commit `9cf5ff4`, the field `working_cd_mounted_confirmed: false` was **hardcoded**: the script never checked the disc. It cannot be construed as actual evidence that the physical/virtual disc was unmounted. The only observed statement is that **the original executable did not discover a matching CD-ROM volume**. From this update onward, the schema reports `version:3` and `cd_mount_verification: not_performed`, and stdout warns that `--cd-mounted` is only acknowledgement.

## Next discriminating test

Without applying any new binary patch, use the **same prefix** as the previously successful CD-based prototype to examine Wine drive mappings and labels. The retail scanner demands **both** a drive with `GetDriveTypeA == DRIVE_CDROM (5)` and a 7-character label `RAYMAN2`. A folder mounted as a regular Wine drive may not satisfy the type test. The relevant API settings are reflected under `HKLM\Software\Wine\Drives` and actual drive access is governed by the prefix mapping `dosdevices/` and the source media permissions. A probe should not change registry, Wine settings or game files. Only after the original PE32 test successfully reaches the game with this same CD should an actual A/B run be repeated.

### Interpretation limits

The current observations do not establish whether a subsequent SafeDisc physical-media validation is performed. Do not claim V2 works without CD or that changing the `LEVELS0.DAT` selector fixes the resource format; V2 has repeatedly failed in the original unchanged parser. Keep PR #3 experimental, do not merge into main, do not disable legitimate resource readers.
