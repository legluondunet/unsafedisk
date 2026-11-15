#!/usr/bin/env python3
"""A/B discriminator: restore ONLY retail CD drive routing in the SHA-locked V4.

This file intentionally leaves the V4 DAT selector, offset adjustment and
512-byte-read modifications exactly unchanged. The result requires the authentic
CD to be mounted/mapped into Wine: it is not a no-CD patch or a fix claim.
Owner's V4 file is required; no proprietary binaries are included/distributed.
The source input is never changed, and output must not already exist.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

V4_SHA256 = 'ef656c7a80272726508ec20aace94ddbaed655c8e25151c87e3d520abebcbbf0'
CD_ROUTE_SHA256 = '48185e5e320c3532731c71b3ae2b2a231aab3af9e361aa531872bb7c23e9464d'
EXPECTED_SIZE = 676352
SCANNER_VA = 0x447C20
SCANNER_FIXED = bytes.fromhex('83 C1 18 66 81 39 0B 01 75 4D 8B 49 60 85 C9 74 46 03 CA 8B 49 0C 03 CA 90')
VOLUME_VA = 0x448E5A
VOLUME_V4 = bytes.fromhex('B0 2E A2 D8 6A 4A 00 8B E5 5D C3')
VOLUME_RETAIL = bytes.fromhex('8B 0D F0 0B 51 00 B8 5F 0B 4E 83')
DRIVE_FORMATS = {
    0x49F394: b'%c:\\%s/%s/%s.%s',
    0x49F3A4: b'%c:\\%s/*',
    0x4A06D8: b'%c:\\%s',
    0x4A2264: b'%c:\\%s\\%s',
    0x4A2688: b'%c:\\',
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def mapped_offset(data: bytes, va: int, length: int, section_name: str) -> int:
    if len(data) != EXPECTED_SIZE or data[:2] != b'MZ':
        raise ValueError('unexpected MZ signature or size')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if nt > 0x1000 or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('unexpected PE signature')
    machine, count = struct.unpack_from('<HH', data, nt+4)
    opt_size = struct.unpack_from('<H', data, nt+20)[0]
    opt = nt+24
    if machine != 0x14c or count != 3 or opt_size < 0xe0 or opt+opt_size+40*count > len(data):
        raise ValueError('unexpected PE32 layout')
    if struct.unpack_from('<H',data,opt)[0] != 0x10b or struct.unpack_from('<I',data,opt+28)[0] != 0x400000:
        raise ValueError('unexpected PE32 image base')
    for i in range(count):
        section = opt+opt_size+i*40
        name = data[section:section+8].split(b'\0',1)[0].decode('ascii',errors='replace')
        if name != section_name: continue
        virtual_size,rva,raw_size,raw_offset = struct.unpack_from('<IIII',data,section+8)
        r = va-0x400000-rva
        if r < 0 or r+length > min(virtual_size,raw_size) or raw_offset+r+length > len(data):
            raise ValueError('required VA not backed by expected PE section')
        return raw_offset+r
    raise ValueError('required PE section absent')


def patch(data: bytes) -> tuple[bytes, dict]:
    if sha256(data) != V4_SHA256:
        raise ValueError('unknown input: require the exact verified V4 Rayman2-portable-v4-dat-read-test.exe')
    scanner = mapped_offset(data, SCANNER_VA, len(SCANNER_FIXED), '.text')
    if data[scanner:scanner+len(SCANNER_FIXED)] != SCANNER_FIXED:
        raise ValueError('validated PE32 scanner patch differs')
    volume = mapped_offset(data, VOLUME_VA, len(VOLUME_V4), '.text')
    if data[volume:volume+len(VOLUME_V4)] != VOLUME_V4:
        raise ValueError('unknown V4 CD-volume selector bytes')
    positions = []
    for va, original in DRIVE_FORMATS.items():
        loc = mapped_offset(data, va, len(original)+1, '.data')
        patched = original[:2] + b'\\' + original[3:]
        if data[loc:loc+len(original)+1] != patched+b'\0':
            raise ValueError(f'unexpected V4 CD path pattern at 0x{va:08X}')
        positions.append((va, loc+2))
    out = bytearray(data)
    out[volume:volume+len(VOLUME_V4)] = VOLUME_RETAIL
    for _, loc in positions:
        out[loc] = ord(':')
    result = bytes(out)
    changes = [i for i,(a,b) in enumerate(zip(data,result)) if a!=b]
    allowed = set(range(volume,volume+len(VOLUME_V4))) | {p for _,p in positions}
    if len(changes) != 16 or not set(changes).issubset(allowed):
        raise ValueError('unexpected byte count or modified regions')
    if sha256(result) != CD_ROUTE_SHA256:
        raise ValueError('unexpected output SHA-256; refusing unverified candidate')
    return result, {
        'variant':'V4-CD-routing-only-control (NOT V5, NOT no-CD)',
        'input_sha256':V4_SHA256,
        'output_sha256':sha256(result),
        'bytes_different_from_v4':len(changes),
        'restored_retained_original_cd_drive_scan':True,
        'restored_retail_cd_path_formats':len(positions),
        'V4_DAT_name_offset_and_read_patches_unchanged':True,
        'requires_mounted_CD':True,
        'hypothesis':'If the pirate head disappears with CD, isolate V1 relative-routing and volume changes; if present, inspect V2-V4 DAT changes or another integrity check.'
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=Path,help='exact V4 test executable')
    ap.add_argument('output',type=Path,help='new output executable, never overwrites')
    ap.add_argument('--dry-run',action='store_true')
    args = ap.parse_args(argv)
    if args.source.is_symlink() or not args.source.is_file():
        ap.error('input must be a regular file, not a symlink')
    if args.output.exists() or args.output.is_symlink() or args.output.resolve()==args.source.resolve():
        ap.error('output already exists or equals input; refusing to overwrite')
    try:
        result, report = patch(args.source.read_bytes())
        if not args.dry_run:
            with args.output.open('xb') as f:
                f.write(result)
    except (ValueError,OSError,struct.error) as ex:
        ap.error(str(ex))
    print(json.dumps(report,indent=2))
    print('CD REQUIRED for this test; no game files, DAT, or Wine configuration changed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
