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



# Original 16-entry CD callback vector, initialized at VA 0x467130:
# callback byte offset, original masked API index, original read VA,
# GOG new pointer expression VA, GOG replacement entry VA or None,
# retained destination-store instruction VA.
CD_CALLBACKS = (
    (0x00,11,0x467168,0x46716F,0x448F08,0x467174),
    (0x08, 8,0x46714A,0x467151,0x448F60,0x467156),
    (0x0C,28,0x467194,0x46719B,0x448ED0,0x4671A0),
    (0x10,15,0x467176,0x46717C,0x448EC4,0x467182),
    (0x14,30,0x4671B2,0x4671B9,0x448F08,0x4671BE),
    (0x1C,31,0x467159,0x467160,0x449010,0x467165),
    (0x20,18,0x4671DF,0x4671DF,0x448FD0,0x4671FB),
    (0x24,34,0x4671D0,0x4671D7,0x448F18,0x4671DC),
    (0x28,16,0x467185,0x46718C,0x448E6C,0x467191),
    (0x34,32,0x46713B,0x467141,None,   0x467147),
    (0x38,29,0x4671A3,0x4671AA,0x448F00,0x4671AF),
    (0x3C,33,0x4671C1,0x4671C8,0x448F10,0x4671CD),
)
CD_CALLBACK_LOCALS = {
    0x04: (0x4671FE,0x467050),
    0x18: (0x467134,0x45FEBC),
    0x2C: (0x4671EB,0x448DE0),
    0x30: (0x4671F4,0x448AB0),
}
CD_CALLBACK_NAMES = {
    8:"CreateFileA",11:"CloseHandle",15:"GetDriveTypeA",
    16:"GetVolumeInformationA",18:"GetFileSize",
    28:"GetDiskFreeSpaceA",29:"SetFileAttributesA",
    30:"GetFileAttributesA",31:"GetFileInformationByHandle",
    32:"SetErrorMode",33:"SetFileTime",34:"GetFileTime",
}


def inspect_cd_callback_table(retail: bytes, gog: bytes, rh: dict,
                              gh: dict, imports: dict) -> dict:
    """Prove masked original Win32 callbacks vs GOG CD-media simulation.

    Exact original/GOG hashes are verified by the caller. Only bounded,
    on-disk opcode/descriptor comparisons; no code or callbacks execute.
    """
    from pe_masked_api_inventory import decode_name

    def require(data, hdr, va, expected):
        if get_va(data,hdr,va,len(expected)) != expected:
            raise ValueError(f"Rayman 2 callback mismatch at 0x{va:08X}")

    for site in (0x4674C8,0x47B01B):
        call=b'\xe8'+struct.pack('<i',0x467130-site-5)
        for data,hdr in ((retail,rh),(gog,gh)):
            require(data,hdr,site,call)
    rows=[]
    for off,idx,read_va,gog_va,target,store_va in CD_CALLBACKS:
        desc=0x4A141C+(idx-1)*0x4C
        original_record=get_va(retail,rh,desc,0x4C)
        if get_va(gog,gh,desc,0x4C)!=original_record:
            raise ValueError("changed callback API descriptor")
        name=decode_name(original_record)
        if name != CD_CALLBACK_NAMES[idx]:
            raise ValueError("unrecognized callback API descriptor")
        if original_record[0x30:0x34]!=b'\0'*4:
            raise ValueError("API callback pointer already set on disk")
        register=0x15 if off in (0,8,0x20,0x28,0x38,0x3c) else 0x0D
        require(retail,rh,read_va,b'\x8b'+bytes([register])+struct.pack('<I',desc+0x30))
        if off==0x20:
            require(retail,rh,read_va+6,b'\x8b\x0d'+struct.pack('<I',desc))
            require(retail,rh,0x4671F2,b'\x33\xd1')
        else:
            require(retail,rh,read_va+6,b'\x33'+bytes([register])+struct.pack('<I',desc))
        original_store=get_va(retail,rh,store_va,2 if off==0 else 3)
        require(gog,gh,store_va,original_store)
        if target is None:
            if (imports.get(0x49C0C8) or {}).get("name")!="SetErrorMode":
                raise ValueError("GOG callback direct IAT does not resolve SetErrorMode")
            require(gog,gh,gog_va,bytes.fromhex("8B 0D C8 C0 49 00"))
            replacement="IAT:KERNEL32!SetErrorMode"
        else:
            opcode=0xB9 if off in (0x0c,0x10,0x14,0x1c,0x24) else 0xBA
            require(gog,gh,gog_va,bytes([opcode])+struct.pack('<I',target))
            replacement=f"local:0x{target:08X}"
        rows.append({"offset":f"0x{off:02X}","retail_api":name,
                     "descriptor_index":idx,"gog_callback":replacement})
    locals_out=[]
    for off,(site,target) in CD_CALLBACK_LOCALS.items():
        unchanged=b'\xc7\x40'+bytes([off])+struct.pack('<I',target)
        require(retail,rh,site,unchanged)
        require(gog,gh,site,unchanged)
        locals_out.append({"offset":f"0x{off:02X}",
                           "unchanged_handler_va":f"0x{target:08X}"})
    if ({int(r["offset"],16) for r in rows+locals_out}
            !=set(range(0,0x40,4))):
        raise ValueError("incomplete Rayman 2 callback vector")

    # GOG deliberately supplies CD-ROM signatures and fake media geometry.
    # The 0x51270 total-cluster immediate is separate from GOG's
    # 3,716-entry virtual filename metadata; do not conflate the sums.
    virtual_cd_signatures={
        0x448EC4:"B8 05 00 00 00 C2 04 00", # GetDriveTypeA=DRIVE_CDROM
        0x448ED6:"C7 00 01 00 00 00",       # sectors/cluster
        0x448EDF:"C7 00 00 08 00 00",       # bytes/sector 2048
        0x448EE8:"C7 00 00 00 00 00",       # free clusters
        0x448EF1:"C7 00 70 12 05 00",       # total clusters
        0x448E76:"C7 00 43 44 46 53",       # CDFS
        0x448E7C:"C6 40 04 00",
        0x448EAE:"C7 00 52 41 59 4D",       # RAYM
        0x448EB4:"C7 40 04 41 4E 32 00",    # AN2\0
        0x448EA1:"C7 00 E8 0A 38 6D",       # virtual serial
        0x448E87:"C7 00 05 00 00 00",       # volume flags
        0x448E94:"C7 00 6E 00 00 00",       # max component length
        0x448EBE:"5D C2 20 00",             # stdcall 8 arguments
        0x448F80:"BF 00 30 5B 00",          # virtual archive metadata base
        0x448FD7:"BE 00 30 5B 00",
    }
    for address,opcode in virtual_cd_signatures.items():
        require(gog,gh,address,bytes.fromhex(opcode))
    virtual_capacity=1*2048*0x51270
    if virtual_capacity!=680755200:
        raise ValueError("unexpected GOG virtual CD size")
    return {"static_read_only":True,
            "game_execution_observed":False,
            "callback_initializer_va":"0x00467130",
            "callers_unchanged_in_both":["0x004674C8","0x0047B01B"],
            "callback_count":16,"original_masked_api_entries":len(rows),
            "unchanged_local_entries":len(locals_out),
            "gog_local_compatibility_entries":11,
            "gog_direct_IAT_entries":1,
            "original_to_gog_mappings":sorted(rows,key=lambda r:int(r["offset"],16)),
            "unchanged_local_handlers":sorted(locals_out,key=lambda r:int(r["offset"],16)),
            "gog_emulated_cdrom":{"drive_type":5,"volume_label":"RAYMAN2",
                "filesystem":"CDFS","volume_serial":"0x6D380AE8",
                "sectors_per_cluster":1,"bytes_per_sector":2048,
                "free_clusters":0,"total_clusters":332400,
                "geometry_bytes":virtual_capacity,"manifest_base_va":"0x005B3000"},
            "gog_metadata_opcode_anchors":len(virtual_cd_signatures),
            "warning":"CD geometry observed only in modified GOG EXE, not original CD physical sectors or a SafeDisc key."}



# Read-only model of GOG's *virtual* CreateFileA/GetFileSize handle scheme.
# The real Win32 ABI is NOT called for these callback slots.
VIRTUAL_CD_KNOWN = {
    "DPLAYERX.DLL": (6,165888),
    "RAYMAN2.EXE": (17,676352),
    "RAYMAN2.ICD": (18,683565),
    "SECDRV.SYS": (21,14368),
    "DATA\\WORLD\\LEVELS\\LEVELS0.DAT": (43,150775808),
    "DATA\\WORLD\\LEVELS\\MAP0.DAT": (46,187087845),
    "DATA\\WORLD\\LEVELS\\SOUNDS1.DAT": (56,339690633),
}
VIRTUAL_HANDLE_ANCHORS = {
    0x448F65:"8B 45 0C A9 00 00 00 40 75 52",
    0x448F76:"66 81 7E 01 3A 5C",
    0x448F80:"BF 00 30 5B 00",
    0x448F85:"81 3F FF FF FF FF",
    0x448F8D:"56 83 C6 03 8D 57 08",
    0x448F94:"8A 06 8A 22 46 42",
    0x448F9A:"3C 61 72 06 3C 7A 77 02 2C 20",
    0x448FA4:"3A C4 75 0D 84 C0 75 E8",
    0x448FAC:"5E 8B C1 5F 5E 5D C2 1C 00",
    0x448FB5:"41 83 C7 08 03 7F FC",
    0x448FC1:"83 C8 FF",
    0x448FD4:"8B 4D 08",
    0x448FD7:"BE 00 30 5B 00",
    0x448FE0:"81 3E FF FF FF FF",
    0x448FE8:"83 C6 08 03 76 FC 49",
    0x448FF1:"33 C0 EB 02 8B 06",
    0x448FF7:"8B 4D 0C 85 C9 74 06 C7 01 00 00 00 00",
    0x449013:"8B 45 0C C7 00 01 00 00 00",
    0x44901C:"C7 40 04 00 2B 9E C6",
    0x449023:"C7 47 08 10 F9 BE 01",
    0x449046:"C7 40 1C E8 0A 38 6D",
    0x449054:"50 6A 00 FF 75 08 E8 71 FF FF FF",
    0x449060:"89 41 24 C7 41 28 01 00 00 00",
    0x449074:"89 41 30",
    0x448F00:"33 C0 C2 08 00",
    0x448F08:"B8 01 00 00 00 C2 04 00",
    0x448F10:"33 C0 C2 10 00",
    0x448F18:"55 8B EC 8B 45 0C",
    0x448F22:"C7 00 00 2B 9E C6",
    0x448F28:"C7 40 04 10 F9 BE 01",
}


def virtual_open_index(path: str, desired_access: int, entries: list[tuple[str,int]]) -> int:
    """Model *observed GOG instructions*, not general Win32 CreateFileA."""
    if (type(path) is not str or type(desired_access) is not int or
        not path.isascii() or desired_access < 0 or desired_access > 0xFFFFFFFF or
        (desired_access & 0x40000000) or len(path) < 3 or path[1:3] != ":\\"):
        return -1
    # Only ASCII a..z are converted by the GOG x86 byte comparison loop.
    key = "".join(chr(ord(c)-32) if "a" <= c <= "z" else c
                  for c in path[3:])
    for index, (name, _) in enumerate(entries):
        if key == name:
            return index
    return -1


def virtual_get_size(index: int, entries: list[tuple[str,int]]) -> int:
    """Original GetFileSizeA replacement returns 0 for unknown indices."""
    if type(index) is not int or index < 0 or index >= len(entries):
        return 0
    return entries[index][1]


def inspect_gog_virtual_handles(gog: bytes, gh: dict) -> dict:
    """Check exact GOG opcode paths *and* its 3,716 embedded records."""
    from rayman2_sample_provenance import manifest_entries
    for address, signature in VIRTUAL_HANDLE_ANCHORS.items():
        if get_va(gog,gh,address,len(bytes.fromhex(signature))) != bytes.fromhex(signature):
            raise ValueError(f"GOG virtual handle opcode mismatch at 0x{address:08X}")
    extra = [s for s in gh["sections"] if s["name"] == ".extra2"]
    if len(extra) != 1 or gh["image_base"]+extra[0]["rva"] != 0x005B3000:
        raise ValueError("unexpected virtual file manifest location")
    s=extra[0]
    records, used, total=manifest_entries(gog[s["raw_off"]:s["raw_off"]+s["raw_size"]])
    if len(records)!=3716 or used!=139366 or total!=7453062614:
        raise ValueError("unexpected virtual manifest records")
    entries=list(records.items()) # insertion order = exact on-disk record order
    known={}
    for name,(index,size) in VIRTUAL_CD_KNOWN.items():
        if entries[index]!=(name,size):
            raise ValueError(f"unexpected GOG virtual record at index {index}")
        for path in ("D:\\"+name, "x:\\"+name.lower()):
            if virtual_open_index(path,0,entries)!=index:
                raise ValueError(f"virtual handle mismatch for {name}")
        if virtual_get_size(index,entries)!=size:
            raise ValueError(f"virtual file size mismatch for {name}")
        known[name]={"zero_based_handle":index,"declared_bytes":size}
    return {
        "read_only":True, "runtime_callback_calls_observed":False,
        "bytecode_signatures_verified":len(VIRTUAL_HANDLE_ANCHORS),
        "virtual_manifest_entries":len(entries),
        "handle_semantics":"zero-based manifest record index (not native Windows HANDLE)",
        "required_path_prefix":"drive-letter followed by :\\",
        "case_comparison":"ASCII lower-case normalized to upper-case",
        "rejects_access_mask_bit":"GENERIC_WRITE (0x40000000)",
        "nonexistent_file_handle":"0xFFFFFFFF",
        "get_file_size_from_manifest":True,
        "get_file_size_high_word_zero":True,
        "out_of_range_index_returns_zero_length":True,
        "close_handle_returns_true_without_native_close":True,
        "get_file_attributes_returns_readonly_bit":True,
        "set_file_attributes_and_set_file_time_return_false":True,
        "get_file_information_volume_serial":"0x6D380AE8",
        "get_file_information_link_count":1,
        "get_file_information_file_index_is_handle":True,
        "simulated_file_time_utc":"1999-09-07T09:10:06Z",
        "unverified_register_hazard":"at 0x00449023 GetFileInformationByHandle writes [EDI+8] instead of [EAX+8]; caller register context unobserved",
        "verified_example_records":known,
        "warning":"Static GOG media compatibility only; not a functioning native handle or an observed SafeDisc media check.",
    }



def analyze(retail: bytes, gog: bytes) -> dict:
    if hashlib.sha256(retail).hexdigest() != RETAIL_SHA256:
        raise ValueError("unexpected original retail SHA-256")
    if hashlib.sha256(gog).hexdigest() != GOG_SHA256:
        raise ValueError("unexpected GOG reference SHA-256")
    rh, gh = parse_headers(retail), parse_headers(gog)
    imports = {e["iat_va"]: e for e in import_entries(gog, gh)}
    cd_callbacks=inspect_cd_callback_table(retail,gog,rh,gh,imports)
    virtual_handles=inspect_gog_virtual_handles(gog,gh)
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
        "original_to_gog_cd_callback_table":cd_callbacks,
        "gog_virtual_handle_protocol":virtual_handles,
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
