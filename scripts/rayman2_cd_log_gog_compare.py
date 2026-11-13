#!/usr/bin/env python3
"""Read-only comparison of original-ISO inspection log and edited GOG catalog.

Compares only explicitly logged original ISO file records to the GOG
virtual-CD table. Does not authenticate their data contents or physical CD.
No commercial bytes are emitted or saved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

GOG_SHA256 = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
DISC_RE = re.compile(r'^DISC: format=ISO9660 / 2048-byte sectors volume=RAYMAN2\b.*$', re.M)
OMIT_RE = re.compile(r'^DISC-OMIT: .+? path=(.+?) declared_bytes=(\d+) \(not copied;', re.M)


def read_catalog(gog: bytes, *, verify_hash: bool = True) -> dict[str, int]:
    if verify_hash and hashlib.sha256(gog).hexdigest() != GOG_SHA256:
        raise ValueError('GOG executable SHA-256 mismatch')
    if gog[:2] != b'MZ' or len(gog) < 0x100:
        raise ValueError('not a PE')
    pe = struct.unpack_from('<I', gog, 0x3c)[0]
    if pe < 0x40 or pe + 0x18 >= len(gog) or gog[pe:pe+4] != b'PE\0\0':
        raise ValueError('invalid PE header')
    sec_count = struct.unpack_from('<H', gog, pe+6)[0]
    opt_size = struct.unpack_from('<H', gog, pe+20)[0]
    if not 1 <= sec_count <= 24 or not 0x60 <= opt_size <= 0x400:
        raise ValueError('unsupported PE headers')
    section_table = pe + 24 + opt_size
    section = None
    for index in range(sec_count):
        off = section_table + 40 * index
        if off + 40 > len(gog):
            raise ValueError('truncated PE section table')
        if gog[off:off+8].rstrip(b'\0') == b'.extra2':
            section = struct.unpack_from('<II', gog, off+16)
            break
    if section is None:
        raise ValueError('no .extra2 virtual-CD table')
    length, offset = section
    if not length or offset + length > len(gog):
        raise ValueError('invalid .extra2 extent')
    blob = memoryview(gog)[offset:offset+length]
    pos = 0
    entries = {}
    while pos + 8 <= len(blob):
        size, n = struct.unpack_from('<II', blob, pos)
        if (size, n) == (0xffffffff, 0):
            if any(blob[pos+8:]):
                raise ValueError('nonzero after catalog sentinel')
            if verify_hash and len(entries) != 3716:
                raise ValueError('unexpected GOG record count')
            return entries
        if not 2 <= n <= 255 or pos + 8 + n > len(blob):
            raise ValueError('malformed filename record')
        raw = bytes(blob[pos+8:pos+8+n])
        if raw[-1] != 0 or b'\0' in raw[:-1]:
            raise ValueError('malformed filename termination')
        name = raw[:-1].decode('ascii').lower().replace('\\', '/')
        if not name or name in entries:
            raise ValueError('duplicate virtual-CD path')
        entries[name] = size
        pos += 8 + n
    raise ValueError('missing virtual-CD catalog sentinel')


def parse_iso_omissions(text: str) -> dict:
    matches = list(DISC_RE.finditer(text))
    if len(matches) != 1:
        raise ValueError('expected one Rayman 2 ISO9660 DISC summary')
    stats = {name: int(number) for name, number in
             re.findall(r'(\b[a-z_]+)=(\d+)', matches[0].group())}
    count = stats.get('cd_excluded_files', stats.get('lutris_cd_ignored_files'))
    total = stats.get('cd_excluded_bytes', stats.get('lutris_cd_ignored_bytes'))
    if count is None or total is None or stats.get('files', 0) < count:
        raise ValueError('missing summary omissions')
    found = {}
    for name, size in OMIT_RE.findall(text):
        lowered = name.casefold().replace('\\', '/')
        if not lowered or lowered in found:
            raise ValueError('duplicate or blank omitted ISO path')
        found[lowered] = int(size)
    if len(found) != count or sum(found.values()) != total:
        raise ValueError('ISO log omission count or byte sum is inconsistent')
    return {'stats': stats, 'omissions': found}


def compare(log_data: dict, catalog: dict[str, int]) -> dict:
    missing = []
    changed = []
    same = 0
    for name, iso_size in sorted(log_data['omissions'].items()):
        if name not in catalog:
            missing.append({'path': name, 'iso_declared_bytes': iso_size})
        elif catalog[name] != iso_size:
            changed.append({'path': name, 'iso_declared_bytes': iso_size,
                            'gog_declared_bytes': catalog[name]})
        else:
            same += 1
    stats = log_data['stats']
    return {
        'iso_logged_file_count': stats['files'],
        'iso_logged_declared_bytes': stats['declared_bytes'],
        'iso_logged_image_bytes': stats['image_bytes'],
        'iso_omitted_files_compared': len(log_data['omissions']),
        'gog_catalog_file_count': len(catalog),
        'same_path_and_declared_size': same,
        'iso_omissions_absent_from_gog': missing,
        'iso_omissions_with_different_gog_size': changed,
        'all_matching_path_sizes_identical': not changed,
        'scope': 'ISO omissions only; this is NOT an ISO filesystem reconstruction',
        'content_hashes_compared': False,
        'physical_cd_authentication': False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspection-log', type=Path, required=True)
    parser.add_argument('--gog', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        from rayman2_sample_provenance import read_bounded
        log_bytes = read_bounded(args.inspection_log)
        if len(log_bytes) > 4 * 1024 * 1024:
            raise ValueError('log too large')
        report = compare(parse_iso_omissions(log_bytes.decode('utf-8')),
                         read_catalog(read_bounded(args.gog)))
    except (ValueError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
