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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--decrypt-block", metavar="16_HEX_DIGITS",
                        help="Show the candidate plaintext for ONE 8-byte block")
    parser.add_argument("--scan", type=Path,
                        help="Read-only scan for repeated historical zero-block ciphertext")
    args = parser.parse_args(argv)
    result = historical_vector()
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
            result["scan"] = scan_known_zero(safe_read(args.scan))
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
