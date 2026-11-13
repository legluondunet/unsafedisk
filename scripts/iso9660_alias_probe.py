#!/usr/bin/env python3
"""Read-only ISO9660 directory metadata probe for Rayman 2's 24 pseudo-files.

Never extracts file payloads, trusts fake lengths as physical extents, or modifies
an image. Primary volume (2048-byte data sectors) only, NOT a raw 2352 BIN/CUE.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import stat
import struct

SECTOR = 2048
MAX_IMAGE_BYTES = 16 * 1024**3
MAX_DIR_BYTES = 32 * 1024**2
MAX_DIRS = 8192
MAX_RECORDS = 50000
MAX_DEPTH = 24
FAMILIES = ("LEVELS", "MAP", "TEXTURES", "ANIMS", "SOUNDS", "MUSIC", "GRAPHICS", "MENU")
EXPECTED = {f"{family}{i}.DAT" for i in range(3) for family in FAMILIES}


def _both32(data: bytes, pos: int) -> tuple[int, bool]:
    if pos < 0 or pos + 8 > len(data):
        raise ValueError("truncated both-endian 32-bit value")
    le = struct.unpack_from('<I', data, pos)[0]
    be = struct.unpack_from('>I', data, pos + 4)[0]
    return le, le == be


def _record(data: bytes, at: int) -> dict:
    if at >= len(data) or at < 0:
        raise ValueError("directory record offset outside sector")
    n = data[at]
    if n < 34 or n > 255 or at + n > len(data):
        raise ValueError("malformed ISO9660 directory record")
    rec = data[at:at+n]
    extent, valid_extent = _both32(rec, 2)
    size, valid_size = _both32(rec, 10)
    name_size = rec[32]
    if name_size < 1 or 33+name_size > n:
        raise ValueError("malformed ISO9660 filename size")
    raw = rec[33:33+name_size]
    if raw in (b'\0', b'\1'):
        name = '.' if raw == b'\0' else '..'
    else:
        # Keep a normalized filename for the known DAT names without erasing
        # the original name or ISO9660 version used for diagnostics.
        name = raw.decode('ascii','backslashreplace')
    return {'name': name, 'lba': extent, 'bytes': size, 'directory': bool(rec[25] & 2),
            'multi_extent': bool(rec[25] & 0x80),
            'valid_both_endian': valid_extent and valid_size}


def _read_at(f, size: int, offset: int, length: int) -> bytes:
    if (offset < 0 or length < 0 or offset > size or length > size - offset):
        raise ValueError("directory extent exceeds physical ISO length")
    f.seek(offset)
    data = f.read(length)
    if len(data) != length:
        raise ValueError("ISO changed during reading")
    return data


def scan_iso_file(f, physical_bytes: int) -> dict:
    pvd = _read_at(f, physical_bytes, 16 * SECTOR, SECTOR)
    if pvd[:7] != b'\x01CD001\x01':
        raise ValueError("missing primary ISO9660 descriptor (expects 2048-byte sectors)")
    declared_sectors, match_volume = _both32(pvd, 80)
    logical_sector = struct.unpack_from('<H', pvd, 128)[0]
    sector_be = struct.unpack_from('>H', pvd, 130)[0]
    if logical_sector != SECTOR or sector_be != SECTOR:
        raise ValueError('unsupported ISO9660 logical sector size')
    root = _record(pvd, 156)
    if not root['directory'] or root['name'] != '.':
        raise ValueError('invalid root directory record')
    queue = [('', root, 0)]
    visited = set()
    files = []
    directory_count = 0
    warnings = []
    while queue:
        parent, record, depth = queue.pop(0)
        key = (record['lba'], record['bytes'])
        if key in visited:
            continue
        visited.add(key)
        directory_count += 1
        if directory_count > MAX_DIRS or depth > MAX_DEPTH:
            raise ValueError('directory depth or count bound exceeded')
        if record['bytes'] > MAX_DIR_BYTES:
            warnings.append({'directory': parent or '/', 'reason': 'oversized directory', 'length': record['bytes']})
            continue
        start = record['lba'] * SECTOR
        try:
            contents = _read_at(f, physical_bytes, start, record['bytes'])
        except ValueError:
            warnings.append({'directory': parent or '/', 'reason': 'directory beyond physical image'})
            continue
        pos=0
        while pos < len(contents):
            if contents[pos] == 0:
                pos = ((pos // SECTOR) + 1) * SECTOR
                continue
            # Directory entries must not cross a sector boundary.
            n=contents[pos]
            if n < 34 or pos + n > len(contents) or (pos % SECTOR) + n > SECTOR:
                raise ValueError(f'invalid directory entry at offset {pos} within {parent or "/"}')
            rec = _record(contents,pos)
            pos+=n
            if rec['name'] in ('.','..'):
                continue
            if len(files) + len(queue) > MAX_RECORDS:
                raise ValueError('ISO9660 entry count bound exceeded')
            path = parent + '/' + rec['name'] if parent else rec['name']
            if rec['directory']:
                queue.append((path,rec,depth+1))
            else:
                name = rec['name'].split(';',1)[0].rstrip('.')
                startbyte = rec['lba'] * SECTOR
                files.append({'path':path,'base_name':name.upper(), 'lba':rec['lba'],
                              'declared_bytes':rec['bytes'],
                              'multi_extent':rec['multi_extent'],
                              'valid_both_endian':rec['valid_both_endian'],
                              'inside_declared_volume':startbyte+rec['bytes'] <= declared_sectors*SECTOR,
                              'inside_physical_image':startbyte+rec['bytes'] <= physical_bytes,
                              'start_inside_physical_image':startbyte < physical_bytes})
    dat = [r for r in files if r['base_name'] in EXPECTED]
    grouped = defaultdict(list)
    for rec in dat:
        grouped[rec['lba']].append(rec)
    shared = [{'lba':lba, 'names':sorted({r['base_name'] for r in group}),
               'declared_sizes':sorted({r['declared_bytes'] for r in group})}
              for lba,group in grouped.items() if len(set(r['base_name'] for r in group)) >= 2]
    shared.sort(key=lambda g:g['lba'])
    return {
      'read_only': True, 'file_payloads_read': False, 'cd_authentication_performed': False,
      'image_bytes': physical_bytes, 'physical_sectors_floor': physical_bytes//SECTOR,
      'pvd_declared_sectors':declared_sectors,'volume_endian_fields_consistent':match_volume,
      'directory_count':directory_count,'file_count':len(files),
      'candidate_name_count':len(set(r['base_name'] for r in dat)),
      'expected_candidate_count':len(EXPECTED),
      'candidates':dat, 'same_lba_groups':shared,
      'warnings':warnings,
      'interpretation':'Matching LBA values are metadata aliases, not proof of readable identical payloads. Oversized declared lengths are not extracted or trusted. Missing names may be in other volume descriptors or archives.'
    }


def scan(path: Path) -> dict:
    if path.is_symlink():
        raise ValueError('refusing symlink')
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_IMAGE_BYTES:
        raise ValueError('refusing nonregular or oversized image')
    fd = os.open(path, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_BINARY',0))
    with os.fdopen(fd,'rb') as f:
        state = os.fstat(f.fileno())
        if (not stat.S_ISREG(state.st_mode) or
            (state.st_ino,state.st_dev) != (info.st_ino,info.st_dev) or
            state.st_size != info.st_size):
            raise ValueError('image replaced or resized before opening')
        result = scan_iso_file(f, state.st_size)
        after = os.fstat(f.fileno())
        if (state.st_size,state.st_mtime_ns) != (after.st_size,after.st_mtime_ns):
            raise ValueError('image modified while scanning')
        return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('image',type=Path,help='2048-byte/sector ISO image (NOT CUE/BIN 2352)')
    a=p.parse_args(argv)
    try:
        print(json.dumps(scan(a.image),indent=2))
    except (OSError,ValueError) as e:
        p.exit(1, f'ERROR: {e}\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
