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


def four_byte_lane_profile(data: bytes, minimum_words: int = 256) -> dict:
    """Measure high bits in complete 4-byte groups from file offset zero.

    A missing top bit in one lane suggests 31-bit word encoding, but does
    not identify a cryptographic algorithm or prove the data are words.
    """
    if minimum_words < 1:
        raise ValueError("minimum_words must be positive")
    word_count, trailing = divmod(len(data), 4)
    high_bit_counts = [0, 0, 0, 0]
    for off in range(0, word_count * 4, 4):
        for lane in range(4):
            high_bit_counts[lane] += bool(data[off + lane] & 0x80)
    zero_high_bit_lanes = ([lane for lane, total in enumerate(high_bit_counts)
                            if total == 0] if word_count >= minimum_words else [])
    # A clear high-bit lane cannot establish the true word boundary:
    # lane 0 could be BE at offset 0 OR LE at offset 1; lane 3 could
    # be LE at offset 0 OR BE at offset 3. Verify a complete recurrence
    # over every byte offset before labeling an encoding.
    hint = ("ambiguous (lane 0: BE offset 0 or LE offset 1)"
            if zero_high_bit_lanes == [0]
            else "ambiguous (lane 3: LE offset 0 or BE offset 3)"
            if zero_high_bit_lanes == [3]
            else "none or ambiguous")
    return {
        "complete_four_byte_groups": word_count,
        "trailing_bytes_not_examined": trailing,
        "high_bit_set_counts_by_byte_lane": high_bit_counts,
        "always_clear_high_bit_lanes": zero_high_bit_lanes,
        "word_order_hint": hint,
        "note": "Descriptive only; not proof of encryption or a decoder",
    }


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
        "four_byte_lanes": four_byte_lane_profile(data),
    }


def provenance_cautions(records: list[dict]) -> dict:
    """Flag structural discrepancies without declaring inputs invalid.

    SafeDisc v1 variants differ, and installation may transform CD bytes.
    PE header absence is an observation, not a proof of corruption.
    """
    by_role = {entry["role"]: entry for entry in records}
    cautions = []
    for role, explanation in (
        ("icd", "The ICD has no directly runnable PE32 at offset zero. "
                "Historical SafeDisc v1 descriptions start the ICD as a suspended "
                "Windows process; check installed versus disc-extracted bytes."),
        ("dplayerx", "DPLAYERX.DLL has no loadable PE32 at offset zero. "
                     "A normal Windows LoadLibrary cannot directly load these "
                     "on-disk bytes; check whether they require a preparation "
                     "stage or were obtained from a different installation.")
    ):
        entry = by_role.get(role)
        if entry is None:
            continue
        root_pe = any(item["offset"] == "0x0" for item in
                      entry.get("valid_pe32_candidates", []))
        if not root_pe:
            cautions.append({"role": role, "code": "no_pe32_at_file_start",
                             "note": explanation})

    loader = by_role.get("loader")
    if loader:
        root = next((item for item in loader.get("valid_pe32_candidates", [])
                     if item["offset"] == "0x0"), None)
        if root:
            names = {section["name"] for section in root["sections"]}
            if not {".txt", ".txt2"}.issubset(names):
                cautions.append({
                    "role": "loader",
                    "code": "historical_wrapper_section_layout_differs",
                    "note": "Loader lacks .txt/.txt2 sections described in "
                            "a historical Wine SafeDisc v1 write-up; versions "
                            "and customized layouts may differ."
                })
    return {
        # File-format checks do NOT authenticate the originating disc,
        # even when all three files happen to be valid PE32 binaries.
        "provenance_not_verified": True,
        "structural_cautions_present": bool(cautions),
        "corruption_asserted": False,
        "cautions": cautions,
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
        "inputs": records,
        "structural_consistency": provenance_cautions(records)
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
