#!/usr/bin/env python3
"""One-byte Rayman 2 V4 A/B: restore retail DAT file path drive colon.

Input: exact owner-built Rayman2-v4-cd-scan-only-test.exe (CD scanner original,
other five V1 path formats relative). Output restores only the DAT pathname
formatter at VA 0x4A2264; four other V1 path formats remain relative.

The original mounted RAYMAN2 CD is REQUIRED. This is a test, not a no-CD fix.
No game data, registry settings, or existing executable is changed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

INPUT_SHA = "14be1a73f6cb016d0ee3ba039b92bf7f339e078bab2980c3ea887968dfe2f133"
OUTPUT_SHA = "f09ebfc18d065eac771d4212a2c7f76bedee5a9c2e0217a8f530bfa4fb3f6d8f"
EXE_SIZE = 676352
IMAGE_BASE = 0x400000
FORMAT_VA = 0x4A2264
COLON_VA = 0x4A2266
# V1 format has two consecutive backslashes after %c. Original had ':' then '\'.
RELATIVE_FORMAT = b'%c\\\\%s\\%s\0'
ABSOLUTE_FORMAT = b'%c:\\%s\\%s\0'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def section_offset(data: bytes, va: int, size: int, name: bytes = b'.data') -> int:
    if len(data) != EXE_SIZE or data[:2] != b'MZ':
        raise ValueError('unexpected EXE size or MZ signature')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if not 0 < nt < 0x1000 or data[nt:nt + 4] != b'PE\0\0':
        raise ValueError('unexpected PE header')
    machine, section_count = struct.unpack_from('<HH', data, nt + 4)
    optional = nt + 24
    optional_len = struct.unpack_from('<H', data, nt + 20)[0]
    if (machine != 0x14c or section_count != 3 or optional_len < 0xe0 or
            data[optional:optional + 2] != b'\x0b\x01' or
            struct.unpack_from('<I', data, optional + 28)[0] != IMAGE_BASE):
        raise ValueError('unexpected PE32 sections or image base')
    section_start = optional + optional_len
    if section_start + section_count * 40 > len(data):
        raise ValueError('truncated PE section headers')
    for i in range(section_count):
        header = section_start + i * 40
        if data[header:header + 8].split(b'\0', 1)[0] != name:
            continue
        virtual_size, rva, raw_size, raw = struct.unpack_from('<IIII', data, header + 8)
        rel = va - IMAGE_BASE - rva
        if rel < 0 or rel + size > min(virtual_size, raw_size) or raw + rel + size > len(data):
            raise ValueError('target VA outside expected file-backed PE section')
        return raw + rel
    raise ValueError('target section missing')


def patch(data: bytes) -> tuple[bytes, dict]:
    if digest(data) != INPUT_SHA:
        raise ValueError('unknown input: exact Rayman2-v4-cd-scan-only-test.exe required')
    offset = section_offset(data, FORMAT_VA, len(RELATIVE_FORMAT))
    if data[offset:offset + len(RELATIVE_FORMAT)] != RELATIVE_FORMAT:
        raise ValueError('DAT path formatter is not the expected V1 relative format')
    if len(RELATIVE_FORMAT) != len(ABSOLUTE_FORMAT) or RELATIVE_FORMAT[2] != ord('\\'):
        raise ValueError('invalid patch specification')
    result = bytearray(data)
    result[offset + 2] = ord(':')
    result = bytes(result)
    differing = [i for i, (old, new) in enumerate(zip(data, result)) if old != new]
    if differing != [section_offset(data, COLON_VA, 1)]:
        raise ValueError('patch unexpectedly changed other bytes')
    if result[offset:offset + len(ABSOLUTE_FORMAT)] != ABSOLUTE_FORMAT:
        raise ValueError('DAT path formatter not restored')
    if digest(result) != OUTPUT_SHA:
        raise ValueError('output SHA mismatch; refusal to publish')
    return result, {
        'experiment': 'CD-required V4 DAT path only: restore one retail colon',
        'source_sha256': INPUT_SHA,
        'output_sha256': OUTPUT_SHA,
        'bytes_changed': 1,
        'format_va': f'0x{FORMAT_VA:08X}',
        'changed_va': f'0x{COLON_VA:08X}',
        'CD_scanner_original': True,
        'V2_V3_V4_DAT_read_patches_unchanged': True,
        'remaining_V1_path_formats_relative': 4,
        'CD_must_remain_mounted': True,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source', type=Path, help='exact validated V4 CD-scan-only EXE')
    ap.add_argument('destination', type=Path, help='new output EXE (never overwrite)')
    ap.add_argument('--dry-run', action='store_true', help='verify and show planned changes')
    a = ap.parse_args(argv)
    if a.source.is_symlink() or not a.source.is_file():
        ap.error('source must be an existing regular file (no symlinks)')
    if a.destination.is_symlink() or a.destination.exists() or a.destination.resolve() == a.source.resolve():
        ap.error('output exists or aliases source; refusing overwrite')
    try:
        result, info = patch(a.source.read_bytes())
        if not a.dry_run:
            with a.destination.open('xb') as out:
                out.write(result)
    except (OSError, ValueError, struct.error) as exc:
        ap.error(str(exc))
    print(json.dumps(info, indent=2))
    print('REQUIRES REAL RAYMAN2 CD ON F:; NOT a no-CD patch.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
