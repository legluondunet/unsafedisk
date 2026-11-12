#!/usr/bin/env python3
"""Read-only SafeDisc-v1 PE/opaque-file research, without game-specific offsets.

Does not execute, decrypt, rewrite, or assert that an input is SafeDisc.
All measurements are descriptive; MZ sequences can occur randomly.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

MAX_BYTES = 16 * 1024 * 1024
BLOCK_SIZE = 4096


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise ValueError("truncated PE word")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise ValueError("truncated PE doubleword")
    return struct.unpack_from("<I", data, offset)[0]


def parse_embedded_pe32(data: bytes, start: int) -> dict | None:
    """Require a coherent i386 PE32 header and file-backed section table."""
    if start < 0 or data[start:start + 2] != b"MZ" or start + 64 > len(data):
        return None
    try:
        nt = start + _u32(data, start + 0x3C)
        if nt < start + 64 or nt + 24 > len(data) or data[nt:nt + 4] != b"PE\0\0":
            return None
        count = _u16(data, nt + 6)
        opt_size = _u16(data, nt + 20)
        opt = nt + 24
        if _u16(data, nt + 4) != 0x14C or not 0 < count <= 96:
            return None
        if opt_size < 0x60 or opt + opt_size > len(data) or _u16(data, opt) != 0x10B:
            return None
        section_table = opt + opt_size
        if section_table + count * 40 > len(data):
            return None
        sections = []
        for i in range(count):
            pos = section_table + 40 * i
            raw_size = _u32(data, pos + 16)
            raw_offset = _u32(data, pos + 20)
            if raw_size and start + raw_offset + raw_size > len(data):
                return None
            sections.append({
                "name": data[pos:pos + 8].split(b"\0")[0].decode("ascii", "backslashreplace"),
                "rva": f"0x{_u32(data, pos + 12):X}",
                "raw_size": raw_size
            })
        return {
            "offset": f"0x{start:X}",
            "entry_rva": f"0x{_u32(data, opt + 16):X}",
            "sections": sections
        }
    except ValueError:
        return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum(
        (n / len(data)) * math.log2(n / len(data))
        for n in Counter(data).values()
    )


def scan_pe_candidates(data: bytes) -> tuple[int, list[dict]]:
    hits = 0
    candidates: list[dict] = []
    start = 0
    while (offset := data.find(b"MZ", start)) != -1:
        hits += 1
        candidate = parse_embedded_pe32(data, offset)
        if candidate is not None:
            candidates.append(candidate)
        start = offset + 2
    return hits, candidates


def profile_bytes(data: bytes, role: str) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError("file exceeds 16 MiB limit")
    mz_hits, candidates = scan_pe_candidates(data)
    if role == "loader" and not any(
        candidate["offset"] == "0x0" for candidate in candidates
    ):
        raise ValueError("loader is not a valid x86 PE32")
    block_entropies = [
        entropy(data[i:i + BLOCK_SIZE])
        for i in range(0, len(data) - BLOCK_SIZE + 1, BLOCK_SIZE)
    ]
    return {
        "role": role,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "first_16_hex": data[:16].hex(" ").upper(),
        "entropy_bits_per_byte": round(entropy(data), 6),
        "full_4k_blocks": len(block_entropies),
        "block_entropy_min": round(min(block_entropies), 6) if block_entropies else None,
        "block_entropy_max": round(max(block_entropies), 6) if block_entropies else None,
        "mz_occurrences": mz_hits,
        "valid_pe32_candidates": candidates,
        "crpe_occurrences": data.count(b"CRPE\0\0"),
    }


def profile_file(path: Path, role: str) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"refusing symlink or non-file: {path}")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"refusing oversized file: {path}")
    with path.open("rb") as handle:
        data = handle.read(MAX_BYTES + 1)
    result = profile_bytes(data, role)
    result["input_name"] = path.name
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--icd", type=Path, required=True)
    parser.add_argument("--dplayerx", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        records = [
            profile_file(path, role)
            for role, path in (
                ("loader", args.loader),
                ("icd", args.icd),
                ("dplayerx", args.dplayerx)
            )
        ]
    except (OSError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(json.dumps({
        "read_only": True,
        "decryption_attempted": False,
        "safedisc_version_asserted": False,
        "inputs": records
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
