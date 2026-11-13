#!/usr/bin/env python3
"""Reconcile owner Rayman 2 samples with GOG virtual-CD metadata, read-only.

Four exact SHA-256 reference inputs only. Reports correlations, *not* proof
that a file was read from the original CD, safe-disc decryption, or execution.
No proprietary file bytes are emitted, patched or written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

MAX_INPUT = 16 * 1024 * 1024
M = 2147483647
A = 16807
SALT = 0x075BD924
REFS = {
    'retail': ('7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3', 676352),
    'gog': ('9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713', 1468928),
    'icd': ('4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6', 683565),
    'dplayerx': ('0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee', 165888),
}
MANIFEST_NAMES = {'retail': 'RAYMAN2.EXE', 'icd': 'RAYMAN2.ICD',
                  'dplayerx': 'DPLAYERX.DLL'}


def read_bounded(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError('refusing symlink')
    st = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_INPUT:
        raise ValueError('refusing nonregular, empty or oversized input')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                 getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as fh:
        opened = os.fstat(fh.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size) != (st.st_dev, st.st_ino, st.st_size):
            raise ValueError('file replaced before reading')
        data = fh.read(MAX_INPUT + 1)
        after = os.fstat(fh.fileno())
    if (len(data) != opened.st_size or len(data) > MAX_INPUT or
        (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise ValueError('file modified during reading')
    return data


def pe_sections(data: bytes) -> dict[str, bytes]:
    if len(data) < 0x40 or data[:2] != b'MZ':
        raise ValueError('invalid PE DOS header')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if nt < 0x40 or nt+24 > len(data) or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    machine, n = struct.unpack_from('<HH', data, nt+4)
    opt_len = struct.unpack_from('<H', data, nt+20)[0]
    opt = nt+24
    if (machine != 0x14c or not 1 <= n <= 96 or opt_len < 0x60 or
        opt+opt_len+40*n > len(data) or struct.unpack_from('<H', data, opt)[0] != 0x10b):
        raise ValueError('unsupported PE32 section table')
    sections: dict[str, bytes] = {}
    for i in range(n):
        pos = opt+opt_len+40*i
        name = data[pos:pos+8].split(b'\0')[0].decode('ascii', 'strict')
        size, offset = struct.unpack_from('<II', data, pos+16)
        if (not name or name in sections or offset+size > len(data)):
            raise ValueError('invalid or duplicate PE section')
        sections[name] = data[offset:offset+size]
    return sections


def manifest_entries(data: bytes) -> tuple[dict[str, int], int, int]:
    """GOG .extra2 named (u32 length, u32 name-size, NUL name) records.

    The metadata is *not* an authenticated ISO9660 directory and file sizes
    are not treated as physical/valid file extents. FFFFFFFF, 0 terminates.
    """
    entries: dict[str, int] = {}
    pos = 0
    for i in range(10000):
        if pos+8 > len(data):
            raise ValueError('missing virtual-CD table terminator')
        size, n = struct.unpack_from('<II', data, pos)
        if (size, n) == (0xffffffff, 0):
            if any(data[pos+8:]):
                raise ValueError('unexpected bytes after manifest sentinel')
            return entries, pos, sum(entries.values())
        if not 2 <= n <= 255 or pos+8+n > len(data):
            raise ValueError('bad virtual-CD filename record')
        raw = data[pos+8:pos+8+n]
        if not raw.endswith(b'\0') or b'\0' in raw[:-1]:
            raise ValueError('bad NUL termination in virtual-CD filename')
        name = raw[:-1].decode('ascii', 'strict')
        if not name or name in entries:
            raise ValueError('empty or duplicate virtual-CD filename')
        entries[name] = size
        pos += 8+n
    raise ValueError('too many virtual-CD manifest entries')


def check_opaque_prng(data: bytes, *, prefix: bytes, seed: int) -> bool:
    """Independently regenerate *every* byte of one known PRNG reference."""
    if not data.startswith(prefix) or (len(data)-len(prefix)) % 4:
        return False
    out = bytearray(prefix)
    state = seed
    for _ in range((len(data)-len(prefix)) // 4):
        out.extend(struct.pack('<I', state))
        state = ((state ^ SALT) * A) % M
    return out == data


def inspect(samples: dict[str, bytes]) -> dict:
    for key, (sha, size) in REFS.items():
        if key not in samples or len(samples[key]) != size or hashlib.sha256(samples[key]).hexdigest() != sha:
            raise ValueError(f'unknown or changed {key} sample')
    retail, gog = pe_sections(samples['retail']), pe_sections(samples['gog'])
    if '.text' not in retail or '.extra' not in gog or '.extra2' not in gog:
        raise ValueError('expected reference PE sections missing')
    text = retail['.text']
    extra = gog['.extra']
    copy_at = extra.find(text)
    if copy_at != 4096 or extra.count(text) != 1 or any(extra[:copy_at]) or any(extra[copy_at+len(text):]):
        raise ValueError('original retail .text not embedded as expected in GOG .extra')
    entries, used, total = manifest_entries(gog['.extra2'])
    if len(entries) != 3716 or total != 7453062614 or used != 139366:
        raise ValueError('unexpected GOG virtual-CD metadata')
    found = {}
    for key, name in MANIFEST_NAMES.items():
        expected = len(samples[key])
        observed = entries.get(name)
        if observed != expected:
            raise ValueError(f'GOG manifest size does not match {name} sample')
        found[name] = {'manifest_declared_size':observed, 'owner_sample_bytes':expected,
                       'same_length':True, 'same_file_bytes_proven':False}
    if entries.get('SECDRV.SYS') != 14368:
        raise ValueError('missing expected SafeDisc driver metadata')
    if not check_opaque_prng(samples['icd'], prefix=b'\x5b', seed=0x6EE4C08A):
        raise ValueError('ICD PRNG complete-byte reconstruction failed')
    if not check_opaque_prng(samples['dplayerx'], prefix=b'', seed=0x0030FBEC):
        raise ValueError('DLL PRNG complete-byte reconstruction failed')
    return {
        'read_only':True, 'all_four_exact_sha256_verified':True,
        'private_input_bytes_reproduced_in_report':False,
        'gog_virtual_cd_record_count':len(entries),
        'gog_manifest_end_offset':used,
        'gog_declared_file_size_total':total,
        'gog_manifest_matches_owner_lengths':found,
        'gog_secdrv_sys_declared_bytes':entries['SECDRV.SYS'],
        'secdrv_sys_sample_available':False,
        'retail_text_bytes':len(text), 'embedded_copy_offset_in_gog_extra':copy_at,
        'embedded_retail_text_exact_match':True,
        'opaque_prng':{
            'icd':{'complete_byte_regeneration':True,'prefix_bytes':1,'seed':'0x6EE4C08A'},
            'dplayerx':{'complete_byte_regeneration':True,'prefix_bytes':0,'seed':'0x0030FBEC'},
            'xor_salt':'0x075BD924', 'modulus':M, 'multiplier':A},
        'limits':('Three matching sizes and an embedded retail .text prove correlation between these exact '
                  'samples and GOG metadata, not the byte content or provenance of the physical CD files. '
                  'Neither PRNG generation nor virtual-CD metadata proves SafeDisc decryption.'),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in REFS:
        parser.add_argument('--'+key, required=True, type=Path)
    a = parser.parse_args(argv)
    try:
        print(json.dumps(inspect({key:read_bounded(getattr(a,key)) for key in REFS}), indent=2))
    except (OSError, ValueError, UnicodeError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
