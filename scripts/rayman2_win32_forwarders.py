#!/usr/bin/env python3
"""Read-only, SHA-locked survey of Win32 forwarders in Rayman 2 CD vs GOG.

Static evidence only: GOG is not pristine retail; neither file is run or
decrypted. No proprietary data is embedded in this script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from pe_import_xrefs import parse_headers, import_entries, rva_file_offset
from rayman2_cd_io_diff import safe_read, RETAIL_SHA256, GOG_SHA256

# VA -> (API name, imported pointer VA, stdcall argument count)
EXPECTED = {
    0x00448500: ("CloseHandle", 0x0049C0E0, 1),
    0x0044E750: ("ReadFile", 0x0049C04C, 5),
    0x0044F220: ("CreateFileA", 0x0049C058, 7),
    0x0044F380: ("SetFilePointer", 0x0049C048, 4),
}
# Object-file disassembly verified these E8 rel32 instruction boundaries.
CALLS = {
    0x00448500: (0x0044E743, 0x0044F135),
    0x0044E750: (0x0044E6B0, 0x0044E6E5, 0x0044E71A, 0x0044F125, 0x0044F1EC),
    0x0044F220: (0x0044F17D, 0x0044F1C0),
    0x0044F380: (0x0044F10D, 0x0044F1D4),
}

FORWARDER = re.compile(
    rb"\x55\x8B\xEC(?P<pushes>(?:\xFF\x75[\x00-\xFF]){0,12})"
    rb"\xFF\x15(?P<iat>.{4})\x5D\xC2(?P<cleanup>.{2})", re.DOTALL
)


def get_va(data: bytes, hdr: dict, va: int, size: int) -> bytes:
    if not 0 < size <= 256 or not hdr["image_base"] <= va <= 0xFFFFFFFF:
        raise ValueError("invalid VA span")
    rva = va - hdr["image_base"]
    start = rva_file_offset(hdr, rva, size, len(data))
    return data[start:start+size]


def scan_forwarders(blob: bytes, base_va: int, imports: dict) -> list[dict]:
    """Recognize exact stack forwarding, direct IAT call, stdcall cleanup."""
    matches = []
    for m in FORWARDER.finditer(blob):
        params = list(m["pushes"][2::3])
        n = len(params)
        iat = struct.unpack("<I", m["iat"])[0]
        cleanup = struct.unpack("<H", m["cleanup"])[0]
        if params != list(range(8, 8+4*n, 4))[::-1] or cleanup != 4*n:
            continue
        if iat not in imports:
            continue
        matches.append({
            "va": base_va+m.start(), "iat_va": iat, "args": n,
            "size": m.end()-m.start(), "api": imports[iat]["name"],
            "dll": imports[iat]["dll"],
        })
    return matches


def analyze(retail: bytes, gog: bytes) -> dict:
    if hashlib.sha256(retail).hexdigest() != RETAIL_SHA256:
        raise ValueError("unexpected original retail SHA-256")
    if hashlib.sha256(gog).hexdigest() != GOG_SHA256:
        raise ValueError("unexpected GOG reference SHA-256")
    rh, gh = parse_headers(retail), parse_headers(gog)
    imports = {e["iat_va"]: e for e in import_entries(gog, gh)}
    sections = [s for s in gh["sections"] if s["name"] == ".text" and
                s["flags"] & 0x20000000]
    if len(sections) != 1 or rh["image_base"] != gh["image_base"]:
        raise ValueError("unexpected PE layout")
    s = sections[0]
    data = gog[s["raw_off"]:s["raw_off"]+s["raw_size"]]
    rows = scan_forwarders(data, gh["image_base"]+s["rva"], imports)
    found = {r["va"]: r for r in rows}
    if len(rows) != len(EXPECTED) or set(found) != set(EXPECTED):
        raise ValueError("unexpected GOG forwarding stub set")
    observations = []
    for va, (api, iat, argc) in EXPECTED.items():
        row = found[va]
        if (row["api"], row["iat_va"], row["args"], row["dll"].lower()) != (
            api, iat, argc, "kernel32.dll"
        ):
            raise ValueError(f"mismatched imported API at 0x{va:08X}")
        if get_va(retail, rh, va, 6) != bytes.fromhex("8B 0D F0 0B 51 00"):
            raise ValueError(f"missing retail PRNG state access at 0x{va:08X}")
        if bytes.fromhex("81 F1 24 D9 5B 07") not in get_va(retail, rh, va, 32):
            raise ValueError(f"missing retail PRNG XOR at 0x{va:08X}")
        callsites = []
        for site in CALLS[va]:
            rel = va - site - 5
            opcode = b"\xE8" + struct.pack("<i", rel)
            if get_va(retail, rh, site, 5) != opcode:
                raise ValueError(f"retail callsite mismatch at 0x{site:08X}")
            callsites.append({
                "site_va": f"0x{site:08X}",
                "unchanged_direct_call_in_gog": get_va(gog, gh, site, 5) == opcode,
            })
        observations.append({
            "function_va": f"0x{va:08X}", "gog_win32_api": api,
            "gog_iat_va": f"0x{iat:08X}", "stdcall_args": argc,
            "gog_stub_size": row["size"],
            "retail_prng_anchors_found": True,
            "retail_direct_calls": callsites,
        })
    return {
        "read_only": True, "exact_sha256_gate": True,
        "gog_is_not_pristine_retail": True,
        "runtime_reachability_proven": False,
        "safe_disc_decrypted": False,
        "matching_gog_forwarders": observations,
        "retail_direct_callsite_count": sum(len(r["retail_direct_calls"]) for r in observations),
        "gog_unchanged_direct_callsite_count": sum(
            sum(c["unchanged_direct_call_in_gog"] for c in r["retail_direct_calls"])
            for r in observations
        ),
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--retail", type=Path, required=True)
    p.add_argument("--gog", type=Path, required=True)
    opt = p.parse_args(argv)
    try:
        print(json.dumps(analyze(safe_read(opt.retail), safe_read(opt.gog)), indent=2))
    except (ValueError, OSError) as e:
        p.exit(1, f"ERROR: {e}\n")
    return 0


if __name__ == "__main__":
    main()
