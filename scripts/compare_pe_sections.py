#!/usr/bin/env python3
"""Read-only comparison of two PE32 x86 files (ICD and historical TESTME.EXE).

Only structural/byte-level evidence; this does not decrypt anything.
"""
import argparse
import hashlib
import pathlib
import struct


def u16(blob, offset):
    if offset + 2 > len(blob):
        raise ValueError("truncated PE16 field")
    return struct.unpack_from("<H", blob, offset)[0]


def u32(blob, offset):
    if offset + 4 > len(blob):
        raise ValueError("truncated PE32 field")
    return struct.unpack_from("<I", blob, offset)[0]


def sections(blob):
    if blob[:2] != b"MZ":
        raise ValueError("missing MZ header")
    nt = u32(blob, 0x3C)
    if blob[nt:nt + 4] != b"PE\0\0" or u16(blob, nt + 4) != 0x14C:
        raise ValueError("expected x86 PE")
    optional = nt + 24
    if u16(blob, optional) != 0x10B:
        raise ValueError("expected PE32")
    count = u16(blob, nt + 6)
    if count == 0 or count > 96:
        raise ValueError("invalid section count")
    first = optional + u16(blob, nt + 20)
    if first + count * 40 > len(blob):
        raise ValueError("truncated section table")
    result = []
    for i in range(count):
        off = first + i * 40
        name = blob[off:off + 8].split(b"\0")[0].decode("ascii", errors="replace")
        raw_size, raw_offset = u32(blob, off + 16), u32(blob, off + 20)
        if raw_offset + raw_size > len(blob):
            raise ValueError("section extends past end of file")
        result.append((name, raw_offset, raw_size))
    return u32(blob, optional + 16), result


def compare(left, right):
    left_entry, left_sections = sections(left)
    right_entry, right_sections = sections(right)
    print(f"ICD: {len(left)} bytes SHA-256 {hashlib.sha256(left).hexdigest()}")
    print(f"EXE: {len(right)} bytes SHA-256 {hashlib.sha256(right).hexdigest()}")
    print(f"Entry RVAs: 0x{left_entry:08X} / 0x{right_entry:08X}")
    for (name_a, offset_a, size_a), (name_b, offset_b, size_b) in zip(left_sections, right_sections):
        if name_a != name_b or size_a != size_b:
            print(f"{name_a} vs {name_b}: differing layout; no positional byte comparison")
            continue
        a = left[offset_a:offset_a + size_a]
        b = right[offset_b:offset_b + size_b]
        differences = sum(x != y for x, y in zip(a, b))
        print(f"{name_a}: {differences}/{size_a} differing bytes ({100 * differences / size_a:.2f}%)")
    if len(left_sections) != len(right_sections):
        print("Different section counts; comparison incomplete")
    print("Structural comparison only. No transformation or compatibility inferred.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("icd", type=pathlib.Path)
    parser.add_argument("unwrapped", type=pathlib.Path)
    args = parser.parse_args()
    compare(args.icd.read_bytes(), args.unwrapped.read_bytes())
