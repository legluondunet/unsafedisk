#!/usr/bin/env python3
"""Experimental Rayman 2 local-R + GOG-style DAT V4 probe.

Input: exact, owner-generated Rayman2-local-R-test.exe, descended from the
SHA256-pinned retail CD executable through the known Rust local-disc-probe
relative-folder patch. This script *proves* ancestry by reversing all Rust
local-R edits in memory, then hashing the recovered retail executable.

A/B difference: only 4 DAT code sites already established by previous V2/V3/
V4 research (fixed LEVELS0.DAT, removes offset subtraction, skips two retail
512-byte reads). The local-R volume and 5 relative formatters are unchanged.
Creates only a NEW EXE, never edits resources or the original retail binary.

This is NOT SafeDisc unwrapping, an authentication fix, or a known-working
no-CD patch. No proprietary game data is bundled. Exit codes and piracy
overlays still need owner-side Wine testing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

RETAIL_SHA = "7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3"
FILE_SIZE = 676352
PE_BASE = 0x400000
SCANNER_VA = 0x447C20
SCANNER_ORIGINAL = bytes.fromhex(
    "83 C1 18 85 C9 74 50 8B 49 60 85 C9 74 49 03 CA "
    "85 C9 74 43 8B 49 0C 03 CA")
SCANNER_PATCHED = bytes.fromhex(
    "83 C1 18 66 81 39 0B 01 75 4D 8B 49 60 85 C9 74 46 "
    "03 CA 8B 49 0C 03 CA 90")
VOLUME_VA = 0x448E5A
VOLUME_ORIGINAL = bytes.fromhex("8B 0D F0 0B 51 00 B8 5F 0B 4E 83")
VOLUME_R = bytes.fromhex("B0 52 A2 D8 6A 4A 00 8B E5 5D C3")
FORMAT_VAS = (0x49F394, 0x49F3A4, 0x4A06D8, 0x4A2264, 0x4A2688)

# All four source anchors were independently inspected in the earlier
# SHA-locked V2/V3/V4 tools. They must still be in their ORIGINAL state.
DAT_SITE_CHANGES = (
    (0x44F102,
     bytes.fromhex("8B 45 08 6A 00 6A 00 8B 08 51 57 E8 6E 02 00 00 "
                   "8D 55 F0 6A 00 52 8D 85 CC FC FF FF 68 00 02 00 00 "
                   "50 57 E8 26 F6 FF FF"),
     bytes([0x90])*40, "skip_first_512_byte_DAT_read"),
    (0x44F133, bytes.fromhex("29 0E"), bytes.fromhex("90 90"),
     "no_DAT_offset_subtraction"),
    (0x44F13A, bytes.fromhex("8B 14 9D 90 20 4A 00"),
     bytes.fromhex("8B 15 90 20 4A 00 90"), "choose_LEVELS0_DAT"),
    (0x44F1CC, bytes.fromhex("8B 0E"), bytes.fromhex("EB 23"),
     "skip_second_512_byte_DAT_read"),
)
CONTEXT = (
    (0x44F12A, bytes.fromhex("8B CB 57 0F AF CE 8B 75 08")),
    (0x44F135, bytes.fromhex("E8 C6 93 FF FF")),
    (0x44F1C0, bytes.fromhex("E8 5B 00 00 00 8B F8 83 FF FF 74 BD")),
    (0x44F1F1, bytes.fromhex("5B 8B C7 5E 5F 8B E5 5D C3")),
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def map_pe(data: bytes) -> dict[bytes, tuple[int,int,int]]:
    if len(data)!=FILE_SIZE or data[:2]!=b"MZ":
        raise ValueError("local-R candidate must be a 676352-byte MZ executable")
    nt=struct.unpack_from("<I", data, 0x3c)[0]
    if nt<0x40 or nt>0x1000 or data[nt:nt+4]!=b"PE\0\0":
        raise ValueError("invalid PE signature")
    machine, sections=struct.unpack_from("<HH",data,nt+4)
    optsz=struct.unpack_from("<H",data,nt+20)[0]
    opt=nt+24
    if (machine!=0x14c or sections!=3 or optsz<0xe0 or
        opt+optsz+sections*40>len(data) or
        struct.unpack_from("<H",data,opt)[0]!=0x10b or
        struct.unpack_from("<I",data,opt+28)[0]!=PE_BASE or
        struct.unpack_from("<I",data,opt+16)[0]!=0x5FCC0):
        raise ValueError("unknown retail PE32 layout")
    mapped={}
    for i in range(sections):
        at=opt+optsz+i*40
        name=bytes(data[at:at+8]).split(b"\0",1)[0]
        vsize,rva,rsize,offset=struct.unpack_from("<IIII",data,at+8)
        if (name in mapped or not name or offset+rsize>len(data) or
            (name==b".text" and not struct.unpack_from("<I",data,at+36)[0]&0x20000000)):
            raise ValueError("bad PE section metadata")
        mapped[name]=(rva, min(vsize,rsize), offset)
    if set(mapped)!={b".text",b".rdata",b".data"}:
        raise ValueError("unexpected three PE sections")
    return mapped


def at_va(pe: dict, va: int, n: int, section: bytes) -> int:
    if n<=0 or n>256:
        raise ValueError("invalid read size")
    rva,size,base=pe[section]
    relative=va-PE_BASE-rva
    if relative<0 or relative+n>size:
        raise ValueError(f"VA {va:08X} outside file-backed {section!r}")
    return base+relative


def require(data: bytes, pe: dict, va: int, expected: bytes,
            section: bytes=b".text") -> int:
    pos=at_va(pe,va,len(expected),section)
    if data[pos:pos+len(expected)]!=expected:
        raise ValueError(f"unknown executable byte signature at VA 0x{va:08X}")
    return pos


def reconstruct_retail(data: bytes) -> tuple[bytes,dict]:
    """Undo exactly Rust local-R code/format patches; returns original candidate.

    Does not trust any caller-supplied input digest: compares recovered full
    executable against the owner's SHA-pinned retail-CD original.
    """
    pe=map_pe(data)
    original=bytearray(data)
    scanner=require(data,pe,SCANNER_VA,SCANNER_PATCHED)
    original[scanner:scanner+len(SCANNER_ORIGINAL)]=SCANNER_ORIGINAL
    volume=require(data,pe,VOLUME_VA,VOLUME_R)
    original[volume:volume+len(VOLUME_ORIGINAL)]=VOLUME_ORIGINAL
    for va in FORMAT_VAS:
        i=require(data,pe,va,b"%c\\\\",b".data")
        original[i+2]=ord(":")
    original=bytes(original)
    if digest(original)!=RETAIL_SHA:
        raise ValueError("unknown local-R build: recovered source hash is not the pinned retail CD")
    return original,pe


def patch_bytes(data: bytes) -> tuple[bytes,dict]:
    _,pe=reconstruct_retail(data)
    for va,old,new,label in DAT_SITE_CHANGES:
        if len(old)!=len(new):
            raise ValueError("internal error: instruction length change")
        require(data,pe,va,old)
    for va,expected in CONTEXT:
        require(data,pe,va,expected)
    # Prevent accidental overlap with known original stack/frame code.
    spans=[(at_va(pe,va,len(old),b".text"),len(old)) for va,old,_,_ in DAT_SITE_CHANGES]
    for i,(at,size) in enumerate(spans):
        if any(max(at,other)<min(at+size,other+extent)
               for other,extent in spans[i+1:]):
            raise ValueError("overlapping patch regions")
    output=bytearray(data)
    changed=[]
    for va,old,new,label in DAT_SITE_CHANGES:
        pos=at_va(pe,va,len(old),b".text")
        output[pos:pos+len(old)]=new
        changed.extend(k for k in range(pos,pos+len(old)) if data[k]!=output[k])
    if not changed or any(data[i]==output[i] for i in changed):
        raise ValueError("incorrect patch delta")
    for va,old,new,label in DAT_SITE_CHANGES:
        require(output,pe,va,new)
    return bytes(output), {
        "experiment":"retail local-R + selected GOG DAT V2/V3/V4 site deltas",
        "input_sha256":digest(data),
        "verified_retail_ancestor_sha256":RETAIL_SHA,
        "output_sha256":digest(output),
        "file_size_bytes":len(data),
        "code_sites": [{"va":f"0x{va:08X}","purpose":label,"bytes":len(old)}
                       for va,old,new,label in DAT_SITE_CHANGES],
        "changed_byte_count":len(changed),
        "changed_only_four_Dat_sites":True,
        "local_R_paths_and_CD_selector_unchanged":True,
        "sna_and_dat_files_unchanged":True,
        "no_CD_functionality_unverified":True,
        "safedisc_unwrapped":False,
    }


def main(argv=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source",type=Path,
                        help="exact existing Rayman2-local-R-test.exe")
    parser.add_argument("output",type=Path,
                        help="new output EXE (will not overwrite)")
    parser.add_argument("--dry-run",action="store_true",
                        help="verify all input and output invariants, don't write")
    args=parser.parse_args(argv)
    if args.source.is_symlink() or not args.source.is_file():
        parser.error("source EXE missing or symlink")
    try:
        info=os.stat(args.source,follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size!=FILE_SIZE:
            raise ValueError("source must be a regular exact retail-sized EXE")
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists; refusing overwrite")
        content=args.source.read_bytes()
        if len(content)!=FILE_SIZE or args.source.stat().st_mtime_ns!=info.st_mtime_ns:
            raise ValueError("input file changed while reading")
        output, report=patch_bytes(content)
        if not args.dry_run:
            try:
                with args.output.open("xb") as f:
                    f.write(output)
                    f.flush()
            except OSError:
                # Leave no incomplete executable with a trusted output name.
                if args.output.exists() and not args.output.is_symlink():
                    args.output.unlink()
                raise
        print(json.dumps(report,indent=2,ensure_ascii=False))
        print("DRY RUN: no EXE written" if args.dry_run else "Created NEW test EXE; original files unchanged")
        return 0
    except (OSError,ValueError,struct.error) as error:
        parser.error(str(error))
    return 2


if __name__=="__main__":
    raise SystemExit(main())
