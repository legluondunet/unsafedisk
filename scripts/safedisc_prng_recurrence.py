#!/usr/bin/env python3
"""Read-only 31-bit word recurrence fingerprint for SafeDisc-era research.

This is an empirical PRNG identity check, not an ICD decryptor.
A complete recurrence match proves deterministic generation from a seed;
it does not establish whether the file is a dummy, DRM resource or artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

MAX_INPUT = 16 * 1024 * 1024
MODULUS = 2_147_483_647
MULTIPLIER = 16_807
INVERSE = pow(MULTIPLIER, -1, MODULUS)


def analyse(data: bytes, endian: str) -> dict:
    if endian not in ("little", "big"):
        raise ValueError("endianness must be little or big")
    if len(data) > MAX_INPUT:
        raise ValueError("input exceeds 16 MiB")
    count = len(data) // 4
    if count < 3:
        raise ValueError("need at least three complete 32-bit words")
    fmt = ("<" if endian == "little" else ">") + f"{count}I"
    words = struct.unpack(fmt, data[:count * 4])
    out_of_range = sum(value >= MODULUS for value in words)
    if out_of_range:
        return {
            "endianness": endian, "word_count": count,
            "out_of_range_words": out_of_range,
            "full_recurrence_match": False,
            "algorithm_asserted": False,
        }

    # This is a derived *candidate*. One transition can always be fitted,
    # so do not claim identification without verifying every next word.
    salt = words[0] ^ ((words[1] * INVERSE) % MODULUS)
    matched = sum(
        ((words[i] ^ salt) * MULTIPLIER) % MODULUS == words[i + 1]
        for i in range(count - 1)
    )
    complete = matched == count - 1
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "endianness": endian,
        "word_count": count,
        "tail_bytes": len(data) % 4,
        "first_word": f"0x{words[0]:08X}",
        "candidate_xor_salt": f"0x{salt:08X}",
        "matching_transitions": matched,
        "total_transitions": count - 1,
        "full_recurrence_match": complete,
        "algorithm_asserted": complete,
        "algorithm": "masked Park-Miller MINSTD mod 2^31-1" if complete else None,
        "no_decryption_attempted": True,
        "protected_file_authenticity_asserted": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--endian", choices=("little", "big"), required=True)
    args = parser.parse_args(argv)
    try:
        path = args.file
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
            raise ValueError("refusing symlink, non-file, or oversized input")
        result = analyse(path.read_bytes(), args.endian)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
