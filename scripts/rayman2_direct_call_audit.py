#!/usr/bin/env python3
"""Hash-gated, read-only x86 CALL rel32 comparison of CD and GOG Rayman 2.

Requires GNU objdump. Does not execute the Windows programs or reconstruct a PE.
The GOG program is an independently modified comparison build, not an oracle.
"""
import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import struct
import subprocess

HASHES = (
    "7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3",
    "9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713",
)
LINE = re.compile(r"^\s*([0-9a-f]{6,8}):\s+((?:[0-9a-f]{2} )+)\s+(\S+)")
STUBS = (0x4478A0, 0x448DB0, 0x448D80, 0x447DE0)


def read_file(path, expected_hash):
    if pathlib.Path(path).is_symlink():
        raise ValueError("refusing symlink input")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if not 0 < before.st_size <= 16 * 1024 * 1024 or not os.path.isfile(path):
            raise ValueError("input is not a regular, bounded file")
        data = os.read(fd, before.st_size + 1)
        after = os.fstat(fd)
        if len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("file changed during read")
    finally:
        os.close(fd)
    if hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError("unrecognized executable: exact SHA-256 required")
    return data


def text_section(pe):
    if pe[:2] != b"MZ" or len(pe) < 0x100:
        raise ValueError("not MZ")
    off = struct.unpack_from("<I", pe, 0x3C)[0]
    if off + 24 > len(pe) or pe[off:off + 4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    sections, optional_size = struct.unpack_from("<HH", pe, off + 6)[0], struct.unpack_from("<H", pe, off + 20)[0]
    opt = off + 24
    if sections > 96 or opt + optional_size + sections * 40 > len(pe):
        raise ValueError("invalid section bounds")
    if struct.unpack_from("<H", pe, opt)[0] != 0x10B:
        raise ValueError("only PE32 supported")
    image_base = struct.unpack_from("<I", pe, opt + 28)[0]
    for i in range(sections):
        item = opt + optional_size + i * 40
        name, virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<8sIIII", pe, item)
        if name.rstrip(b"\0") != b".text":
            continue
        if raw_offset + raw_size > len(pe):
            raise ValueError("truncated .text")
        return image_base + rva, pe[raw_offset:raw_offset + raw_size]
    raise ValueError("missing .text")


def direct_calls(path, start, stop):
    p = subprocess.run(["objdump", "-d", "-M", "intel", "--start-address", hex(start),
                        "--stop-address", hex(stop), str(path)], capture_output=True, text=True, check=True)
    calls = {}
    for line in p.stdout.splitlines():
        m = LINE.match(line)
        if not m or m.group(3) != "call":
            continue
        site = int(m.group(1), 16)
        opcodes = bytes.fromhex(m.group(2))
        if len(opcodes) == 5 and opcodes[0] == 0xE8 and start <= site < stop:
            calls[site] = site + 5 + struct.unpack_from("<i", opcodes, 1)[0]
    return calls


def audit_code(retail_code, gog_code, start, retail_calls, gog_calls):
    end = start + min(len(retail_code), len(gog_code))
    removed = collections.defaultdict(list)
    retained = collections.defaultdict(list)
    for site, target in retail_calls.items():
        if not start <= target < end:
            continue
        if retail_code[target - start] != 0xCC and gog_code[target - start] == 0xCC:
            unchanged_source = gog_calls.get(site) == target
            (retained if unchanged_source else removed)[target].append(site)
    gog_danger = [(site, target) for site, target in gog_calls.items()
                  if start <= target < end and gog_code[target - start] == 0xCC]
    return {
        "retail_direct_calls_into_gog_int3": sum(map(len, removed.values())) + sum(map(len, retained.values())),
        "sources_modified_in_gog": sum(map(len, removed.values())),
        "sources_still_direct_calls_in_gog": sum(map(len, retained.values())),
        "gog_direct_calls_into_int3": len(gog_danger),
        "removed_target_sites": {f"0x{k:08X}": [f"0x{s:08X}" for s in v]
                                 for k, v in sorted(removed.items())},
        "still_live_target_sites": {f"0x{k:08X}": [f"0x{s:08X}" for s in v]
                                    for k, v in sorted(retained.items())},
        "gog_int3_call_sites": [[hex(a), hex(b)] for a, b in gog_danger],
        "startup_stubs_return_immediately_in_gog": {
            f"0x{va:08X}": gog_code[va-start:va-start+1] == b"\xC3"
            for va in STUBS if start <= va < end},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("retail", help="owner's exact 676352-byte CD-sourced EXE")
    parser.add_argument("gog", help="owner's exact 1468928-byte GOG reference EXE")
    args = parser.parse_args()
    r = read_file(args.retail, HASHES[0])
    g = read_file(args.gog, HASHES[1])
    start, rb = text_section(r)
    start_g, gb = text_section(g)
    if start != start_g or len(rb) < 0x9A200 or len(gb) < 0x9A200:
        raise ValueError("unexpected .text mapping")
    end = start + 0x9A200
    result = audit_code(rb[:0x9A200], gb[:0x9A200], start,
                        direct_calls(args.retail, start, end), direct_calls(args.gog, start, end))
    result.update({"retail_sha256": HASHES[0], "gog_sha256": HASHES[1],
                   "method": "GNU objdump linear disassembly; direct E8 rel32 only",
                   "runtime_reachability_proven": False,
                   "gog_is_pristine_retail": False, "decryption_performed": False})
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
