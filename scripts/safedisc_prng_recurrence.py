#!/usr/bin/env python3
"""Bounded, read-only alignment-aware analysis of 31-bit masked MINSTD streams.

A recurrence match is mathematical evidence of a deterministic stream, not a
SafeDisc authenticity verdict, deciphered executable, or verified game loader.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import struct
from pathlib import Path

MAX_INPUT = 16 * 1024 * 1024
MODULUS = 2_147_483_647
MULTIPLIER = 16_807
INVERSE = pow(MULTIPLIER, -1, MODULUS)
MIN_WORDS = 256


def repeated_salt_triplets(words: tuple[int, ...]) -> int:
    """Three-word windows fitting the *same* salt in two adjacent steps."""
    if len(words) < 3:
        return 0
    previous = words[0] ^ ((words[1] * INVERSE) % MODULUS)
    count = 0
    for i in range(1, len(words) - 1):
        candidate = words[i] ^ ((words[i + 1] * INVERSE) % MODULUS)
        count += candidate == previous
        previous = candidate
    return count


def analyse(data: bytes, endian: str, offset: int = 0) -> dict:
    if endian not in ("little", "big"):
        raise ValueError("endianness must be little or big")
    if offset not in range(4):
        raise ValueError("offset must be 0, 1, 2, or 3")
    if len(data) > MAX_INPUT:
        raise ValueError("input exceeds 16 MiB")
    payload = data[offset:]
    count = len(payload) // 4
    if count < MIN_WORDS:
        raise ValueError(f"need at least {MIN_WORDS} complete 32-bit words")
    words = struct.unpack(("<" if endian == "little" else ">") + f"{count}I",
                          payload[:count * 4])
    invalid = sum(value >= MODULUS for value in words)
    base = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "endianness": endian,
        "offset_bytes": offset,
        "preserved_prefix_hex": data[:offset].hex(),
        "word_count": count,
        "tail_bytes": len(payload) % 4,
        "words_outside_modulus": invalid,
        "no_decryption_attempted": True,
        "protected_file_authenticity_asserted": False,
    }
    if invalid:
        return {**base, "full_recurrence_match": False,
                "whole_file_reconstructible_from_prefix_and_seed": False,
                "three_word_windows_examined": count - 2,
                "matching_local_three_word_windows": None}
    salt = words[0] ^ ((words[1] * INVERSE) % MODULUS)
    matched = sum(
        ((words[i] ^ salt) * MULTIPLIER) % MODULUS == words[i + 1]
        for i in range(count - 1)
    )
    complete = matched == count - 1
    full_rebuild = False
    if complete and len(payload) % 4 == 0:
        # Independent forward regeneration; compare the complete byte array
        # rather than relying on a count of consecutive equations alone.
        rebuilt = bytearray(data[:offset])
        state = words[0]
        for _ in range(count):
            rebuilt.extend(state.to_bytes(4, endian))
            state = ((state ^ salt) * MULTIPLIER) % MODULUS
        full_rebuild = rebuilt == data
    return {**base,
            "first_word": f"0x{words[0]:08X}",
            "candidate_xor_salt": f"0x{salt:08X}",
            "matching_transitions": matched,
            "total_transitions": count - 1,
            "matching_local_three_word_windows": repeated_salt_triplets(words),
            # Keep the original research field for existing callers/tests.
            "consecutive_three_word_windows_matching_a_local_salt": repeated_salt_triplets(words),
            "three_word_windows_examined": count - 2,
            "full_recurrence_match": complete,
            "whole_file_reconstructible_from_prefix_and_seed": full_rebuild,
            "algorithm": "masked Park-Miller MINSTD modulo 2^31-1" if complete else None}


def analyse_alignments(data: bytes) -> dict:
    matches = []
    checked = 0
    for offset in range(4):
        for endian in ("little", "big"):
            try:
                result = analyse(data, endian, offset)
            except ValueError as exc:
                if "need at least" in str(exc):
                    continue
                raise
            checked += 1
            if result["full_recurrence_match"]:
                matches.append(result)
    return {"tested_alignments": checked,
            "full_match_count": len(matches),
            "matches": matches,
            "automatic_file_authentication": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--endian", choices=("little", "big"))
    group.add_argument("--auto-align", action="store_true")
    parser.add_argument("--offset", type=int, choices=range(4), default=0)
    args = parser.parse_args(argv)
    try:
        path = args.file
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_INPUT:
            raise ValueError("refusing symlink, non-file, or oversized input")
        # Reject symlink substitution during opening where the platform allows.
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            import stat
            meta = os.fstat(handle.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_INPUT:
                raise ValueError("input changed type or exceeded limit")
            data = handle.read(MAX_INPUT + 1)
            if len(data) != meta.st_size:
                raise ValueError("input changed while reading")
        result = analyse_alignments(data) if args.auto_align else analyse(data, args.endian, args.offset)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
