#!/usr/bin/env python3
"""Read-only, SHA-pinned static comparison of Rayman 2 retail/CD and GOG file I/O.

Uses exact known x86 opcode anchors, not a disassembler, decryption method,
proof of runtime execution, or a retail-only SafeDisc patch recipe.
The GOG build may contain unrelated changes: attribution is NOT implied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
from pe_import_xrefs import parse_headers, rva_file_offset, import_entries

MAX_INPUT_BYTES = 16 * 1024 * 1024
RETAIL_SHA256 = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_SHA256 = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
TABLE_VA = 0x004A2090
FORMAT_ORIGINAL_VA = 0x004A2264
FORMAT_GOG_VA = 0x004A2268

# Only short, independently inspected instruction encodings, not arbitrary
# executable blocks. A match still does not prove these paths are executed.
SITES = (
    (0x0044EB82, 'original drive-letter format argument', bytes.fromhex('51'), bytes.fromhex('90')),
    (0x0044EB89, 'original drive-letter format pointer', bytes.fromhex('68 64 22 4A 00'), bytes.fromhex('68 68 22 4A 00')),
    (0x0044EB94, 'stack-adjustment for format arguments', bytes.fromhex('83 C4 14'), bytes.fromhex('83 C4 10')),
    (0x0044EB97, 'protected branch invokes PRNG wrapper vs GOG skip', bytes.fromhex('E8 E4 98 FF FF'), bytes.fromhex('EB 72')),
    (0x0044EC24, 'dynamic file open vs direct CreateFileA IAT call', bytes.fromhex('FF D6'), bytes.fromhex('FF 15 58 C0 49 00')),
    (0x0044F133, 'retail arithmetic vs GOG NOP', bytes.fromhex('29 0E'), bytes.fromhex('90 90')),
    (0x0044F13A, 'indexed selection from 24-name table vs first entry', bytes.fromhex('8B 14 9D 90 20 4A 00'), bytes.fromhex('8B 15 90 20 4A 00 90')),
    (0x0044F155, 'drive-letter argument removed at second site', bytes.fromhex('50'), bytes.fromhex('90')),
    (0x0044F156, 'second file path format pointer', bytes.fromhex('68 64 22 4A 00'), bytes.fromhex('68 68 22 4A 00')),
    (0x0044F161, 'second stack adjustment for format arguments', bytes.fromhex('83 C4 14'), bytes.fromhex('83 C4 10')),
    (0x0044F1CC, 'retail continuation vs GOG early jump', bytes.fromhex('8B 0E'), bytes.fromhex('EB 23')),
)


def safe_read(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError('refusing symlink')
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT_BYTES:
        raise ValueError('refusing nonregular/oversized file')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as fh:
        opened = os.fstat(fh.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_INPUT_BYTES:
            raise ValueError('file changed type or size')
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('file replaced on opening')
        data = fh.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(fh.fileno())
    if (len(data) != opened.st_size or len(data) > MAX_INPUT_BYTES or
            (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise ValueError('file changed during reading')
    return data


def va_bytes(data: bytes, headers: dict, va: int, length: int) -> bytes:
    rva = va - headers['image_base']
    if not 0 <= rva <= 0xffffffff or not 0 <= length <= 512:
        raise ValueError('VA/length out of range')
    off = rva_file_offset(headers, rva, length, len(data))
    return data[off:off+length]


def va_cstr(data: bytes, headers: dict, va: int, max_len: int = 64) -> str:
    chars = bytearray()
    for i in range(max_len):
        b = va_bytes(data, headers, va + i, 1)[0]
        if b == 0:
            return chars.decode('ascii', 'strict')
        chars.append(b)
    raise ValueError('unterminated text at VA')


def read_file_table(data: bytes, headers: dict, table_va: int = TABLE_VA) -> list[str]:
    pointers = va_bytes(data, headers, table_va, 24*4)
    names=[]
    for index in range(24):
        (name_va,) = struct.unpack_from('<I', pointers, index*4)
        name = va_cstr(data, headers, name_va, 32)
        if not re.fullmatch(r'(LEVELS|MAP|TEXTURES|ANIMS|SOUNDS|MUSIC|GRAPHICS|MENU)[012]\.DAT', name):
            raise ValueError(f'unexpected file table entry {index}')
        names.append(name)
    if len(set(names)) != 24:
        raise ValueError('duplicate data table name')
    return names


def inspect_pair(retail: bytes, gog: bytes, *, verify_hashes: bool = True) -> dict:
    hashes = (hashlib.sha256(retail).hexdigest(), hashlib.sha256(gog).hexdigest())
    if verify_hashes and hashes != (RETAIL_SHA256, GOG_SHA256):
        raise ValueError('input hashes are not the two known exact Rayman 2 samples')
    h_r, h_g = parse_headers(retail), parse_headers(gog)
    names_r = read_file_table(retail, h_r)
    names_g = read_file_table(gog, h_g)
    if names_r != names_g or names_r[0] != 'LEVELS0.DAT':
        raise ValueError('asset name table mismatch between executables')
    # Same names and actual pointer values in these two builds, not just text.
    ptr_r = va_bytes(retail, h_r, TABLE_VA, 96)
    ptr_g = va_bytes(gog, h_g, TABLE_VA, 96)
    if ptr_r != ptr_g:
        raise ValueError('file path pointer table differs')
    fmt = va_cstr(retail, h_r, FORMAT_ORIGINAL_VA)
    gfmt = va_cstr(gog, h_g, FORMAT_GOG_VA)
    if fmt != '%c:\\%s\\%s' or gfmt != '%s\\%s':
        raise ValueError('unexpected original vs GOG file path formats')
    imports_r = import_entries(retail,h_r)
    imports_g = import_entries(gog,h_g)
    for entries in (imports_r,imports_g):
        if not any(e['name'] == 'CreateFileA' and e['dll'].upper() == 'KERNEL32.DLL'
                   and e['iat_va'] == 0x0049C058 for e in entries):
            raise ValueError('unverified CreateFileA import anchor')
    sites=[]
    for va, description, code_r, code_g in SITES:
        real_r = va_bytes(retail,h_r,va,len(code_r))
        real_g = va_bytes(gog,h_g,va,len(code_g))
        if real_r != code_r or real_g != code_g:
            raise ValueError(f'unsupported instruction comparison at 0x{va:08X}')
        sites.append({'va':f'0x{va:08X}', 'observation':description,
                      'bytes_checked_retail':len(code_r),'bytes_checked_gog':len(code_g)})
    return {
        'read_only':True, 'decryption_attempted':False,
        'disassembly_executed':False, 'control_flow_dynamically_verified':False,
        'both_exact_sha256_verified':hashes == (RETAIL_SHA256,GOG_SHA256),
        'reference_is_gog_not_pristine_retail':True,
        'drm_attribution_unproven':True,
        'retail_sha256':hashes[0],'gog_sha256':hashes[1],
        'file_table_va':f'0x{TABLE_VA:08X}',
        'file_table_pointers_identical':True,
        'file_table_pointer_sha256':hashlib.sha256(ptr_r).hexdigest(),
        'file_name_count':len(names_r),'file_names':names_r,
        'retail_path_format':fmt,'gog_path_format':gfmt,
        'direct_import_va':'0x0049C058','direct_import_api':'KERNEL32.dll!CreateFileA',
        'code_comparisons':sites,
        'conclusion':('Verified local static I/O code changes at exact addresses: GOG omits the drive letter, '
                      'directly calls CreateFileA at one site, selects the first of 24 DAT names at a second '
                      'site, and shortens paths through other code. Runtime reachability, intent, SafeDisc '
                      'decryption and preservation of anti-tamper behavior are not demonstrated.')
    }


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail',type=Path,required=True)
    parser.add_argument('--gog',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        print(json.dumps(inspect_pair(safe_read(args.retail),safe_read(args.gog)),indent=2))
    except (OSError,ValueError,UnicodeError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
