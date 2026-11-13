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
        # On Windows, stat() and fstat() may disagree on inode/device for
        # an unchanged file. Keep strict POSIX checks; on Windows compare
        # common snapshot fields (best effort, not a TOCTOU guarantee).
        if ((opened.st_size, opened.st_mtime_ns) != (st.st_size, st.st_mtime_ns)
                or (os.name != 'nt' and
                    (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino))):
            raise ValueError('file replaced or changed before reading')
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



def changed_runs(a: bytes, b: bytes) -> list[tuple[int,int]]:
    """Exclusive-end spans of byte differences; reject unlike raw lengths."""
    if len(a) != len(b):
        raise ValueError('incomparable section raw lengths')
    out=[]
    start=None
    for i,(x,y) in enumerate(zip(a,b)):
        if x != y and start is None:
            start=i
        if x == y and start is not None:
            out.append((start,i))
            start=None
    if start is not None:
        out.append((start,len(a)))
    return out


def decode_masked_module(record: bytes) -> str:
    """Decode original keyed/XOR DLL-name layout; no execution."""
    if len(record) != 45:
        raise ValueError('expected 45-byte encoded DLL record')
    sub, key, delta_sub, delta_key, count = record[:5]
    if not 1 <= count <= 40:
        raise ValueError('invalid encoded DLL name length')
    letters=[]
    for value in record[5:5+count]:
        letters.append(((value-sub)&255)^key)
        sub=(sub+delta_sub)&255
        key=(key+delta_key)&255
    return bytes(letters).decode('ascii','strict')


def audit_cd_gog_data_changes(original_sections:dict[str,bytes],
                              gog_sections:dict[str,bytes]) -> dict:
    """Classify ALL of the exact 127 original/GOG .data byte edits.

    Not a generic version diff: these records and address spans are for the
    two exact SHA-256-pinned samples that inspect() validates first.
    """
    for sect in ('.data','.rdata'):
        if sect not in original_sections or sect not in gog_sections:
            raise ValueError('missing required PE section')
    if original_sections['.rdata'] != gog_sections['.rdata']:
        raise ValueError('unexpected read-only data changes')
    original=original_sections['.data']
    changed=gog_sections['.data']
    runs=changed_runs(original,changed)
    offsets_expected=((0x128,0x129),(0x134,0x135),
        (0x396,0x397),(0x3a6,0x3a7),(0x40c,0x40d),
        (0x410,0x41c),(0x16da,0x16db),
        (0x2268,0x2279),(0x2295,0x22a4),
        (0x22c2,0x22d0),(0x22ef,0x2300),
        (0x231c,0x232a),(0x2349,0x2359),
        (0x2376,0x2384),(0x3266,0x3267),(0x368a,0x368b))
    if tuple(runs) != offsets_expected:
        raise ValueError('unexpected .data edit positions or lengths')
    changed_count=sum(end-start for start,end in runs)
    if len(runs)!=16 or changed_count!=127:
        raise ValueError('unexpected .data edit count')
    base_va=0x49F000
    orig_mods=[];new_mods=[]
    for i,expected_name in enumerate(('KERNEL32.DLL','USER32.DLL','PSAPI.DLL',
          'ADVAPI32.DLL','GDI32.DLL','VERSION.DLL','WINMM.DLL')):
        off=0x2268+i*0x2d
        orig=decode_masked_module(original[off:off+45])
        gog=changed[off:off+45]
        if orig.upper()!=expected_name or gog!=expected_name.encode()+b'\0'*(45-len(expected_name)):
            raise ValueError(f'changed module name does not match original at index {i}')
        orig_mods.append(orig);new_mods.append(gog.split(b'\0',1)[0].decode('ascii'))
    api_off=0x241c
    apis=35*0x4c
    orig_api=original[api_off:api_off+apis]
    gog_api=changed[api_off:api_off+apis]
    if len(orig_api)!=apis or orig_api!=gog_api:
        raise ValueError('masked API descriptor bytes differ')
    if any(orig_api[0x30+i*0x4c:0x34+i*0x4c]!=b'\0'*4 for i in range(35)):
        raise ValueError('unexpected nonzero on-disk API pointers')
    module_changed=sum(end-start for start,end in runs[7:14])
    other_changed=changed_count-module_changed
    if module_changed!=107 or other_changed!=20:
        raise ValueError('unexpected DLL names versus file-path byte counts')
    return {'rdata_byte_identical':True,
            'data_diff_bytes':changed_count,'data_diff_runs':len(runs),
            'data_diff_va_ranges':[[f'0x{base_va+a:08X}',f'0x{base_va+b:08X}'] for a,b in runs],
            'seven_module_names_original_encoded':orig_mods,
            'gog_module_names_plaintext':new_mods,
            'module_name_diff_bytes':module_changed,
            'path_config_diff_bytes':other_changed,
            'masked_api_descriptor_records_identical':35,
            'masked_api_descriptor_sha256':hashlib.sha256(orig_api).hexdigest(),
            'all_masked_api_slots_zero_on_disk':True,
            'module_name_changes_do_not_imply_live_resolution':True}


# Exact modified GOG virtual-CD manifest ordinals and declared lengths for
# the original game's Fix resource sidecars. These are NOT physical-CD
# extent checks, and ".rtl" is a supported code suffix but absent here.
FIX_SIDECARS = (
    (34, 'DATA\\WORLD\\LEVELS\\FIX.RTB', 235995),
    (35, 'DATA\\WORLD\\LEVELS\\FIX.RTP', 547),
    (36, 'DATA\\WORLD\\LEVELS\\FIX.RTS', 2259),
    (37, 'DATA\\WORLD\\LEVELS\\FIX.RTT', 2067),
    (38, 'DATA\\WORLD\\LEVELS\\FIX.SNA', 7682868),
)


def verify_fix_sidecars(manifest: dict[str,int]) -> dict:
    """Validate five original resource names in GOG metadata, not file bytes."""
    ordered = list(manifest.items())
    for offset,name,size in FIX_SIDECARS:
        if len(ordered) <= offset or ordered[offset] != (name,size):
            raise ValueError(f'unexpected Fix resource record at ordinal {offset}')
    if 'DATA\\WORLD\\LEVELS\\FIX.RTL' in manifest:
        raise ValueError('unexpected Fix.rtl in the known GOG manifest')
    return {
        'read_only':True,
        'source':'modified GOG embedded virtual-CD filename/length manifest',
        'file_bytes_or_original_CD_extents_verified':False,
        'resources':[
            {'zero_based_manifest_index':index,
             'filename':name,
             'declared_bytes':size}
            for index,name,size in FIX_SIDECARS
        ],
        'has_Fix_rtl_manifest_entry':False,
        'code_can_construct_rtl_suffix':True,
    }


def inspect(samples: dict[str, bytes]) -> dict:
    for key, (sha, size) in REFS.items():
        if key not in samples or len(samples[key]) != size or hashlib.sha256(samples[key]).hexdigest() != sha:
            raise ValueError(f'unknown or changed {key} sample')
    retail, gog = pe_sections(samples['retail']), pe_sections(samples['gog'])
    data_delta = audit_cd_gog_data_changes(retail,gog)
    if '.text' not in retail or '.extra' not in gog or '.extra2' not in gog:
        raise ValueError('expected reference PE sections missing')
    text = retail['.text']
    # A contemporary January-2000 Rayman 2 SafeDisc study identifies an
    # entrypoint and section size matching this *on-disk* reference. Its
    # post-decryption function addresses must not be treated as static
    # protected-EXE byte signatures: these two addresses differ.
    nt = struct.unpack_from('<I', samples['retail'], 0x3c)[0]
    opt = nt+24
    entry_va = (struct.unpack_from('<I', samples['retail'], opt+28)[0]
                + struct.unpack_from('<I', samples['retail'], opt+16)[0])
    if len(text) != 0x9A200 or entry_va != 0x45FCC0:
        raise ValueError('retail entry or section size differs from historical fingerprint')
    if text[0x5ECC0:0x5ECC0+10] != bytes.fromhex('55 8B EC 6A FF 68 D0 C9 49 00'):
        raise ValueError('unexpected protected on-disk original entrypoint bytes')
    if text[0x54D0:0x54D0+7] != bytes.fromhex('53 8B 5C 24 08 55 8B'):
        raise ValueError('unexpected on-disk function at historic address 0x4064D0')
    if text[0x18FD] != 0x54:
        raise ValueError('unexpected on-disk function at historic address 0x4028FD')
    extra = gog['.extra']
    copy_at = extra.find(text)
    if copy_at != 4096 or extra.count(text) != 1 or any(extra[:copy_at]) or any(extra[copy_at+len(text):]):
        raise ValueError('original retail .text not embedded as expected in GOG .extra')
    entries, used, total = manifest_entries(gog['.extra2'])
    if len(entries) != 3716 or total != 7453062614 or used != 139366:
        raise ValueError('unexpected GOG virtual-CD metadata')
    fix_resources=verify_fix_sidecars(entries)
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
        'original_to_gog_data_changes':data_delta,
        'private_input_bytes_reproduced_in_report':False,
        'gog_virtual_cd_record_count':len(entries),
        'gog_manifest_end_offset':used,
        'gog_declared_file_size_total':total,
        'gog_manifest_matches_owner_lengths':found,
        'gog_Fix_resource_sidecars':fix_resources,
        'gog_secdrv_sys_declared_bytes':entries['SECDRV.SYS'],
        'secdrv_sys_sample_available':False,
        'retail_text_bytes':len(text), 'embedded_copy_offset_in_gog_extra':copy_at,
        'contemporary_study_crosscheck':{
            'published':'2000-01-25',
            'source':'The Twilight of Safedisc (ArthaXerXes)',
            'reported_entry_va_matches_disk':True,
            'reported_text_size_matches_disk':True,
            'runtime_decrypted_function_bytes_match_disk_at_0x4064d0':False,
            'runtime_decrypted_function_bytes_match_disk_at_0x4028fd':False,
            'interpretation':'Different execution stage or revision possible; historical patch offsets not safe for this file',
        },
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
