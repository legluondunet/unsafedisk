#!/usr/bin/env python3
"""Experimental PE32-only guard for the original Rayman 2 CD module scanner.

Creates a NEW, SHA-locked diagnostic copy. It is NOT a SafeDisc decrypter,
and is not intended for GOG or other executables. No bypass of CD checks.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import sys

EXPECTED_SHA = "7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3"
TARGET_VA = 0x447C20
RETURN_VA = 0x447C77
NEXT_VA = 0x447C39
OLD = bytes.fromhex(
    "83 C1 18 85 C9 74 50 8B 49 60 85 C9 74 49 03 CA "
    "85 C9 74 43 8B 49 0C 03 CA"
)


def relative_branch(current_va: int, instruction_size: int, target_va: int) -> bytes:
    offset = target_va - (current_va + instruction_size)
    if not -128 <= offset <= 127:
        raise ValueError("relative branch displacement outside int8 range")
    return struct.pack("b", offset)


def fixed_code() -> bytes:
    # Keep original function call contract: EDX=module base, EAX=result.
    # After PE signature check the original ECX points at the PE file header.
    # At 0x447c20 it advances to IMAGE_OPTIONAL_HEADER and verifies PE32.
    # Ignore PE32+ (0x20B), which has different data-directory offsets.
    patched = (
        bytes.fromhex("83 C1 18") +               # add ecx,0x18
        bytes.fromhex("66 81 39 0B 01") +         # cmp word ptr [ecx],0x10b
        b"\x75" + relative_branch(0x447C28,2,RETURN_VA) + # jne return
        bytes.fromhex("8B 49 60 85 C9") +        # PE32 export RVA; test ecx
        b"\x74" + relative_branch(0x447C2F,2,RETURN_VA) + # je return
        bytes.fromhex("03 CA 8B 49 0C 03 CA 90") # export name RVA; nop
    )
    assert len(OLD) == 25 and len(patched) == 25
    return patched


def exact_file_offset(data: bytes, va: int, length: int) -> int:
    if data[:2] != b"MZ" or len(data) < 0x200:
        raise ValueError("not a PE file")
    pe = struct.unpack_from("<I",data,0x3C)[0]
    if pe > len(data) - 0x120 or data[pe:pe+4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    if struct.unpack_from("<H",data,pe+4)[0] != 0x14C:
        raise ValueError("not an i386 executable")
    count = struct.unpack_from("<H",data,pe+6)[0]
    opt = pe+24
    size = struct.unpack_from("<H",data,pe+20)[0]
    if struct.unpack_from("<H",data,opt)[0] != 0x10B:
        raise ValueError("not a PE32 input")
    base = struct.unpack_from("<I",data,opt+28)[0]
    if base != 0x400000 or not 1 <= count <= 32 or not 0xE0 <= size <= 0x400:
        raise ValueError("unexpected executable PE geometry")
    table = opt+size
    if table+40*count > len(data):
        raise ValueError("truncated PE sections")
    rva=va-base
    for i in range(count):
        s=table+40*i
        name=data[s:s+8].split(b"\0",1)[0]
        section_rva,raw_len,raw_start=struct.unpack_from("<III",data,s+12)
        if name != b".text":
            continue
        if not section_rva <= rva or rva + length > section_rva+raw_len:
            continue
        if not struct.unpack_from("<I",data,s+36)[0] & 0x20000000:
            raise ValueError(".text section not executable")
        off = raw_start + (rva-section_rva)
        if off + length > len(data):
            raise ValueError("file-backed code out of range")
        return off
    raise ValueError("patch VA not in file-backed executable .text")


def patch_bytes(data:bytes, expected_sha: str = EXPECTED_SHA) -> bytes:
    if len(data) != 676352 or hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("not the exact SHA-256-verified CD executable; refusing patch")
    offset=exact_file_offset(data,TARGET_VA,len(OLD))
    if data[offset:offset+len(OLD)] != OLD:
        raise ValueError("original scanner opcodes differ; refusing patch")
    for va,check in ((0x447C0C,bytes.fromhex("66 81 3A 4D 5A")),
                     (0x447C18,bytes.fromhex("81 39 50 45 00 00")),
                     (NEXT_VA,bytes.fromhex("8B 11 81 E2 DF DF DF DF")),
                     (0x447C80,bytes.fromhex("55 8B EC 51 53"))):
        ix=exact_file_offset(data,va,len(check))
        if data[ix:ix+len(check)]!=check:
            raise ValueError(f"unexpected adjacent scanner or handler at 0x{va:08X}")
    result=bytearray(data)
    result[offset:offset+len(OLD)]=fixed_code()
    assert len(result)==len(data)
    assert sum(a!=b for a,b in zip(data,result)) <= len(OLD)
    assert result[:offset]==data[:offset] and result[offset+len(OLD):]==data[offset+len(OLD):]
    return bytes(result)


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original",type=Path,help="unmodified retail CD Rayman2.exe")
    parser.add_argument("output",type=Path,help="new diagnostic EXE path (must not exist)")
    args=parser.parse_args()
    if not args.original.is_file() or args.original.is_symlink():
        parser.error("original must be a regular non-symlink file")
    if args.output.exists() or args.output.is_symlink():
        parser.error("output exists; refusing overwrite")
    if args.original.stat().st_size > 2_000_000:
        parser.error("input too large")
    try:
        patched=patch_bytes(args.original.read_bytes())
        with args.output.open("xb") as f: f.write(patched)
    except (ValueError,OSError) as exc:
        parser.error(str(exc))
    print("Diagnostic-only PE32+ scanner guard written:",args.output)
    print("SHA-256:",hashlib.sha256(patched).hexdigest())
    print("Not decrypted; no SafeDisc, resource, or media checks removed.")

if __name__=="__main__": main()
