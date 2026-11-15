#!/usr/bin/env python3
"""A/B probe: retain original CD scanner, revert just five retail path separators.

Input: validated working-with-CD Rayman2-v4-cd-routes-test.exe.
Output: distinct test executable with retail scanner + V4 relative paths.
Do NOT use this executable without the original CD. No game data modified.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

INPUT_SHA256 = '48185e5e320c3532731c71b3ae2b2a231aab3af9e361aa531872bb7c23e9464d'
OUTPUT_SHA256 = '14be1a73f6cb016d0ee3ba039b92bf7f339e078bab2980c3ea887968dfe2f133'
SIZE = 676352
BASE = 0x400000
SCANNER_VA = 0x448E5A
SCANNER_ORIGINAL = bytes.fromhex('8B 0D F0 0B 51 00 B8 5F 0B 4E 83')
FORMATS = {
  0x49F394: b'%c:\\%s/%s/%s.%s',
  0x49F3A4: b'%c:\\%s/*',
  0x4A06D8: b'%c:\\%s',
  0x4A2264: b'%c:\\%s\\%s',
  0x4A2688: b'%c:\\',
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def offset(data: bytes, va: int, size: int, expected_section: str) -> int:
    if len(data) != SIZE or data[:2] != b'MZ':
        raise ValueError('unexpected input size or MZ signature')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if not 0 < nt < 4096 or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    machine, count = struct.unpack_from('<HH', data, nt+4)
    optional_size = struct.unpack_from('<H', data, nt+20)[0]
    opt = nt+24
    if machine != 0x14c or count != 3 or optional_size < 0xe0:
        raise ValueError('unexpected PE32 header layout')
    if struct.unpack_from('<H', data, opt)[0] != 0x10b or struct.unpack_from('<I', data, opt+28)[0] != BASE:
        raise ValueError('unexpected PE32 image base')
    sections = opt+optional_size
    if sections+count*40 > len(data):
        raise ValueError('truncated PE section table')
    for i in range(count):
        header = sections+i*40
        name = data[header:header+8].split(b'\x00',1)[0].decode('ascii','replace')
        if name != expected_section:
            continue
        virtual_size, rva, raw_size, raw_off = struct.unpack_from('<IIII',data,header+8)
        local=va-BASE-rva
        if 0 <= local and local+size <= min(virtual_size, raw_size) and raw_off+local+size <= len(data):
            return raw_off+local
        raise ValueError(f'VA 0x{va:X} not fully backed by {expected_section}')
    raise ValueError(f'expected {expected_section} PE section absent')


def patch(data:bytes)->tuple[bytes,dict]:
    if digest(data)!=INPUT_SHA256:
        raise ValueError('unrecognized input: requires the validated V4 CD-routes control')
    s=offset(data,SCANNER_VA,len(SCANNER_ORIGINAL),'.text')
    if data[s:s+len(SCANNER_ORIGINAL)]!=SCANNER_ORIGINAL:
        raise ValueError('not original retail CD scanner')
    out=bytearray(data)
    chars=[]
    for va,text in FORMATS.items():
        loc=offset(data,va,len(text)+1,'.data')
        if data[loc:loc+len(text)+1]!=text+b'\0':
            raise ValueError(f'unexpected CD path format at 0x{va:X}')
        if data[loc+2] != 0x3a:
            raise ValueError(f'expected colon not found at 0x{va+2:X}')
        out[loc+2]=0x5c
        chars.append(loc+2)
    result=bytes(out)
    changes=[i for i,(a,b) in enumerate(zip(data,result)) if a!=b]
    if len(changes)!=5 or set(changes)!=set(chars):
        raise ValueError('unexpected modified byte count or region')
    sha=digest(result)
    if sha!=OUTPUT_SHA256:
        raise ValueError('unverified output hash; refusing to publish experimental EXE')
    return result, {'variant':'V4 CD scanner only — restores V4 relative path formats',
                    'input_sha256':INPUT_SHA256,
                    'output_sha256':sha,
                    'size_bytes':SIZE,
                    'changed_bytes':5,
                    'original_CD_scanner_retained':True,
                    'V4_relative_path_formats_restored':True,
                    'V2_V3_V4_DAT_patches_unchanged':True,
                    'requires_mounted_original_CD':True}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path)
    p.add_argument('destination',type=Path)
    args=p.parse_args(argv)
    if not args.source.is_file() or args.source.is_symlink():
        p.error('source must be a regular existing file (not symlink)')
    if args.destination.exists() or args.destination.is_symlink() or args.destination.resolve()==args.source.resolve():
        p.error('destination already exists / symlink / same as source')
    try:
        result,info=patch(args.source.read_bytes())
        with args.destination.open('xb') as f:
            f.write(result)
    except (ValueError,OSError,struct.error) as error:
        p.error(str(error))
    print(json.dumps(info,indent=2))
    print('No CD removal: retain mounted retail disc mapped to F:. No game assets changed.')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
