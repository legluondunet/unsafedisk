#!/usr/bin/env python3
"""Read-only input verification; writes a new Rayman 2 DAT-name diagnostic candidate.

ONLY for the owner-provided exact Rayman2-portable-test.exe prototype.
Preserves the existing PE32 fix, relative CD paths, original DAT reads,
original arithmetic, and every other original game instruction. This is a
controlled hypothesis test, not an established SafeDisc unwrapping.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

INPUT_SHA256 = "6702ff583cb0ee1f1023cc4b334ef4dab3f737a0ee7f272fe31dd13a9f23ce71"
OUTPUT_SHA256 = "35427161a5f9e109564aa00457640f4552497a6a40e28ede7a99a18f444eeb5d"
INPUT_SIZE = 676352
SITE_VA = 0x44F13A
OLD = bytes.fromhex("8B 14 9D 90 20 4A 00")
NEW = bytes.fromhex("8B 15 90 20 4A 00 90")
# This is the exact seven-byte same-address substitution in the separate GOG
# comparator (but GOG has many other independent changes).
NEXT_CALL_VA = 0x44F17D
NEXT_CALL_BYTES = bytes.fromhex("E8 9E 00 00 00 8B F8 83 FF FF 75 43")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def text_offset(data: bytes, va: int, length: int) -> int:
    """Find strict, file-backed PE32 .text VA without assuming file alignment."""
    if len(data) != INPUT_SIZE or data[:2] != b"MZ":
        raise ValueError("unexpected input size or signature")
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    if e_lfanew > 4096 or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    machine, nsections = struct.unpack_from("<HH", data, e_lfanew + 4)
    optsize = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    opt = e_lfanew + 24
    if machine != 0x14c or nsections != 3 or optsize < 0xe0 or struct.unpack_from("<H", data, opt)[0] != 0x10b:
        raise ValueError("unexpected PE32 layout")
    imagebase = struct.unpack_from("<I", data, opt + 28)[0]
    if imagebase != 0x400000:
        raise ValueError("unexpected base")
    sec = opt + optsize
    if sec + nsections*40 > len(data):
        raise ValueError("truncated PE sections")
    for i in range(nsections):
        p = sec + i*40
        name = data[p:p+8].rstrip(b"\0")
        virt, rva, rawsize, rawptr = struct.unpack_from("<IIII", data, p + 8)
        if name != b".text":
            continue
        d = va - imagebase - rva
        if d < 0 or d + length > min(virt, rawsize) or rawptr + d + length > len(data):
            raise ValueError("site lies beyond file-backed .text")
        return rawptr + d
    raise ValueError(".text not found")


def patch(data: bytes) -> tuple[bytes, dict]:
    if sha256(data) != INPUT_SHA256:
        raise ValueError("unrecognized source SHA-256: use exact Rayman2-portable-test.exe V1")
    a = text_offset(data, SITE_VA, len(OLD))
    b = text_offset(data, NEXT_CALL_VA, len(NEXT_CALL_BYTES))
    if data[a:a+7] != OLD or data[b:b+len(NEXT_CALL_BYTES)] != NEXT_CALL_BYTES:
        raise ValueError("original DAT selector or later CreateFileA check changed")
    # Validate only the current hypothesis. Unlike GOG, do not skip 512-byte
    # DAT reads, alter index math or transform source media/engine data.
    target = bytearray(data)
    target[a:a+7] = NEW
    result = bytes(target)
    changed = [i for i,(x,y) in enumerate(zip(data,result)) if x!=y]
    if not changed or not set(changed) <= set(range(a,a+7)):
        raise ValueError("unexpected changed bytes")
    if sha256(result) != OUTPUT_SHA256:
        raise ValueError("unexpected output SHA-256")
    return result, {
        "source_sha256": sha256(data),
        "candidate_sha256": sha256(result),
        "candidate_size": len(result),
        "selected_DAT_name": "LEVELS0.DAT",
        "selector_site_VA": f"0x{SITE_VA:08X}",
        "overwritten_bytes": 7,
        "different_bytes": len(changed),
        "remaining_original_DAT_reads_and_arithmetic": True,
        "CD_independence_proven": False,
        "SafeDisc_unwrapped_proven": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path, help="exact V1 Rayman2-portable-test.exe")
    p.add_argument("output", type=Path, help="new candidate name; never overwrite")
    p.add_argument("--dry-run", action="store_true", help="do not write candidate")
    args=p.parse_args()
    if args.source.is_symlink() or not args.source.is_file():
        p.error("source must be an existing regular file")
    if args.output.exists() or args.output.is_symlink() or args.output.resolve() == args.source.resolve():
        p.error("output must be a new, different file")
    try:
        new,report = patch(args.source.read_bytes())
        if not args.dry_run:
            with args.output.open("xb") as f:
                f.write(new)
        print(json.dumps(report, indent=2))
        print("Unverified, narrow DAT-filename diagnostic; original 512-byte reads preserved.")
        return 0
    except (OSError, ValueError) as e:
        p.error(str(e))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
