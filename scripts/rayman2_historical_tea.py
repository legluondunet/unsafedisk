#!/usr/bin/env python3
"""Read-only probe of the *historical* Rayman 2 SafeDisc block cipher.

The January 2000 ArthaXerXes essay describes an 8-byte, 32-round
TEA-like operation. Its published 7-byte zero-block ciphertext suffix
matches standard TEA with a repeated 0xC15CF2E5 word. This is a
historical known-answer vector, NOT proof that the owner's supplied
ICD/DPLAYERX streams can be decrypted with this key.

No program is executed, patched, saved or extracted.
Source: https://www.scribd.com/document/659005728/safedisc
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

MASK = 0xFFFFFFFF
KEY = 0xC15CF2E5
DELTA = 0x9E3779B9
ROUNDS = 32
ZERO_CIPHER = bytes.fromhex("3E CD DE 58 A2 75 01 7F")
PUBLISHED_SUFFIX = bytes.fromhex("CD DE 58 A2 75 01 7F")


def _word(value: int) -> int:
    return value & MASK


def _mix(value: int, total: int, key: int) -> int:
    """TEA round term; all intermediate arithmetic is 32-bit unsigned."""
    return _word(
        _word((_word(value << 4)) + key)
        ^ _word(value + total)
        ^ _word((value >> 5) + key)
    )


def encrypt_block(block: bytes, key: int = KEY) -> bytes:
    """Encode one 8-byte block; repeated-word key from the historical paper."""
    if len(block) != 8 or not 0 <= key <= MASK:
        raise ValueError("need eight bytes and an unsigned 32-bit key")
    left, right = struct.unpack("<II", block)
    total = 0
    for _ in range(ROUNDS):
        total = _word(total + DELTA)
        left = _word(left + _mix(right, total, key))
        right = _word(right + _mix(left, total, key))
    return struct.pack("<II", left, right)


def decrypt_block(block: bytes, key: int = KEY) -> bytes:
    """Inverse of encrypt_block; historical candidate, not an ICD decoder."""
    if len(block) != 8 or not 0 <= key <= MASK:
        raise ValueError("need eight bytes and an unsigned 32-bit key")
    left, right = struct.unpack("<II", block)
    total = _word(DELTA * ROUNDS)
    for _ in range(ROUNDS):
        right = _word(right - _mix(left, total, key))
        left = _word(left - _mix(right, total, key))
        total = _word(total - DELTA)
    return struct.pack("<II", left, right)


def historical_vector() -> dict:
    actual = encrypt_block(bytes(8))
    return {
        "candidate_key": f"0x{KEY:08X}",
        "standard_tea_delta": f"0x{DELTA:08X}",
        "rounds": ROUNDS,
        "encrypted_zero_block_hex": actual.hex(),
        "published_seven_byte_suffix_match": actual[1:] == PUBLISHED_SUFFIX,
        "reconstructed_eight_byte_vector_match": actual == ZERO_CIPHER,
        "inverse_returns_zero_block": decrypt_block(actual) == bytes(8),
        "verified_for_owner_retail_icd": False,
        "cipher_params_from_runtime_dplayerx_verified": False,
    }


def scan_known_zero(data: bytes) -> dict:
    """Look for this ONE historical 8-byte signature at all byte alignments.

    Presence only flags a follow-up candidate; absence does not disprove
    TEA when a different key, layout, or pre-decryption stage is used.
    """
    positions = []
    start = 0
    while True:
        index = data.find(ZERO_CIPHER, start)
        if index < 0:
            break
        positions.append(index)
        start = index + 1
    return {
        "bytes_scanned": len(data),
        "candidate_zero_block_count": len(positions),
        "candidate_offsets_first_16": positions[:16],
        "candidate_offsets_by_eight_byte_alignment": {
            str(i): sum(pos % 8 == i for pos in positions) for i in range(8)
        },
        "signature_is_not_a_decryption_proof": True,
    }




def _pe32_headers_in_bytes(data: bytes) -> list[int]:
    """Look for plausible complete PE32 headers, not accidental 'MZ' bytes.

    This is a strict *structural* validator for the read-only diagnostic:
    it is not a PE loader, parser, or executable authenticity proof.
    """
    found = []
    start = 0
    limit = len(data)
    while True:
        pos = data.find(b"MZ", start)
        if pos < 0:
            return found
        start = pos + 1
        if pos + 0x40 > limit:
            continue
        nt = struct.unpack_from("<I", data, pos + 0x3C)[0]
        if nt < 0x40 or nt > 0x1000 or pos + nt + 0x18 > limit:
            continue
        head = pos + nt
        if data[head:head+4] != b"PE\0\0":
            continue
        machine, sections = struct.unpack_from("<HH", data, head + 4)
        optional_size = struct.unpack_from("<H", data, head + 20)[0]
        if (machine != 0x14c or not 1 <= sections <= 96 or
                not 0x60 <= optional_size <= 0x400):
            continue
        optional_start = head + 24
        table_end = optional_start + optional_size + sections * 40
        if table_end > limit or data[optional_start:optional_start+2] != b"\x0b\x01":
            continue
        found.append(pos)


def scan_fixed_tea_for_pe32(data: bytes) -> dict:
    """Try all eight *naive* fixed-key TEA block alignments, never save data.

    This is a falsification test for an oversimplified on-disc model.
    The real SafeDisc loader may use a different key, sections only,
    staging, or runtime parameters; no PE finding is not a DRM verdict.
    """
    if not isinstance(data, bytes) or not 8 <= len(data) <= 2 * 1024 * 1024:
        raise ValueError("fixed-key scan accepts 8..2097152 bytes")
    alignments = []
    for alignment in range(8):
        decoded = bytearray(data)
        for off in range(alignment, len(data) - 7, 8):
            decoded[off:off+8] = decrypt_block(data[off:off+8])
        candidate_positions = _pe32_headers_in_bytes(decoded)
        alignments.append({
            "alignment": alignment,
            "decrypted_blocks": (len(data) - alignment) // 8,
            "incidental_mz_count": decoded.count(b"MZ"),
            "plausible_pe32_offsets_first_16": candidate_positions[:16],
            "plausible_pe32_header_count": len(candidate_positions),
        })
    return {
        "input_sha256": hashlib.sha256(data).hexdigest(),
        "mode": "naive-32-round-historical-TEA-four-identical-keywords",
        "key": f"0x{KEY:08X}",
        "assumed_delta": f"0x{DELTA:08X}",
        "tested_alignments": 8,
        "alignments": alignments,
        "valid_pe32_structure_is_not_a_decryption_proof": True,
        "absence_does_not_rule_out_section_only_or_runtime_stage": True,
        "payload_bytes_emitted": False,
    }


def verify_known_prng_samples() -> dict:
    """Reconstruct BOTH owner-hash-matched opaque files in volatile memory.

    This does not recover any PE/DLL payload. A fully reproducible PRNG
    stream need not be inert, and the file provenance on physical media
    is not established. No bytes are written or emitted.
    """
    streams = (
        ("RAYMAN2.ICD", 0x6EE4C08A, 170891, bytes.fromhex("5b"),
         "4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6"),
        ("DPLAYERX.DLL", 0x0030FBEC, 41472, b"",
         "0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee"),
    )
    out = {}
    for name, seed, nwords, prefix, expected_sha in streams:
        state = seed
        generated = bytearray(prefix)
        for _ in range(nwords):
            generated.extend(struct.pack("<I", state))
            state = 16807 * (state ^ 0x075BD924) % 2147483647
        content = bytes(generated)
        digest = hashlib.sha256(content).hexdigest()
        if digest != expected_sha:
            raise AssertionError("PRNG regeneration failed independent SHA-256 check")
        signature = scan_known_zero(content)
        out[name] = {
            "byte_length": len(content),
            "reconstructed_sha256": digest,
            "sha256_matches_owner_sample": True,
            "historical_complete_zero_block_hits": signature["candidate_zero_block_count"],
            "historical_seven_byte_suffix_hits": content.count(PUBLISHED_SUFFIX),
            "no_decrypted_payload_recovered": True,
        }
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decrypt-block", metavar="16_HEX_DIGITS",
                        help="Show the candidate plaintext for ONE 8-byte block")
    parser.add_argument("--scan", type=Path,
                        help="Read-only scan for repeated historical zero-block ciphertext")
    parser.add_argument("--scan-fixed-tea-pe", action="store_true",
                        help="With --scan, try all 8 historical TEA block alignments for PE32 headers")
    parser.add_argument("--verify-known-streams", action="store_true",
                        help="Regenerate owner-identified PRNG streams in RAM; never save files")
    args = parser.parse_args(argv)
    if args.scan_fixed_tea_pe and args.scan is None:
        parser.error("--scan-fixed-tea-pe requires --scan FILE")
    result = historical_vector()
    if args.verify_known_streams:
        result["known_streams"] = verify_known_prng_samples()
    if args.decrypt_block is not None:
        try:
            cipher = bytes.fromhex(args.decrypt_block)
            plaintext = decrypt_block(cipher)
        except ValueError as exc:
            parser.error(str(exc))
        result["candidate_plaintext_hex"] = plaintext.hex()
        result["candidate_plaintext_is_verified_original"] = False
    if args.scan is not None:
        # Reuse the existing bounded, no-symlink and file-descriptor-aware reader.
        from rayman2_cd_io_diff import safe_read
        try:
            scan_data = safe_read(args.scan)
        result["scan"] = scan_known_zero(scan_data)
        if args.scan_fixed_tea_pe:
            result["fixed_tea_pe_scan"] = scan_fixed_tea_for_pe32(scan_data)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
