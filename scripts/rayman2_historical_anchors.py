#!/usr/bin/env python3
"""Read-only, SHA-256 pinned comparison with January 2000 Rayman 2 notes.

This checks specific historical addresses and opcode patterns on two owner's
on-disk EXEs. An absent pattern is NOT proof of a different game revision:
loaded-memory code, a different protection stage and editorial mistakes
are all alternative explanations. No game bytes are printed or exported.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

RETAIL_HASH = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_HASH = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
RETAIL_SIZE = 676352
GOG_SIZE = 1468928

# Source: ArthaXerXes, The Twilight of Safedisc, January 2000.
# These short published assembly signatures are *historical references*,
# not bytes derived from the protected commercial executable.
HISTORICAL = {
    'entrypoint_normal_prologue': (0x0045FCC0, bytes.fromhex('55 8B EC 6A FF 68 D0 C9 49 00')),
    'checksum_callsite_push_2': (0x004028FD, bytes.fromhex('6A 02')),
    'checksum_txt_section_push': (0x004115D9, bytes.fromhex('68')),
    'first_cd_check_stack_reserve': (0x004124F0, bytes.fromhex('81 EC 04 01 00 00')),
}

HISTORICAL_PATTERNS = {
    'early_local_file_branch': bytes.fromhex('0F 85 35 01'),
    'nasty_checksum_start': bytes.fromhex('55 8B EC 83 EC 0C 53 56 57 EB 01 EE'),
    'txt_checksum_branch_marker': bytes.fromhex('02 EB 0B EB FC D7 E1 4A 76 BA 98 05 A5 0D 8B'),
}


def pe_code(data: bytes) -> tuple[int, int, bytes]:
    """Return imagebase, entry VA, .text raw bytes after strict PE32 checks."""
    if len(data) < 0x200 or data[:2] != b'MZ':
        raise ValueError('not MZ')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if not 0x40 <= nt <= len(data) - 0x100 or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE header')
    if struct.unpack_from('<H', data, nt+4)[0] != 0x14c:
        raise ValueError('not x86 PE32')
    count = struct.unpack_from('<H', data, nt+6)[0]
    optional = struct.unpack_from('<H', data, nt+20)[0]
    if not 1 <= count <= 96 or not 0x60 <= optional <= 0x400:
        raise ValueError('invalid PE section layout')
    o = nt + 24
    if struct.unpack_from('<H', data, o)[0] != 0x10b:
        raise ValueError('not PE32')
    ep = struct.unpack_from('<I', data, o+16)[0]
    imagebase = struct.unpack_from('<I', data, o+28)[0]
    if imagebase != 0x400000:
        raise ValueError('unexpected image base')
    table = o + optional
    for i in range(count):
        at = table + 40*i
        if at + 40 > len(data):
            raise ValueError('truncated section table')
        name = data[at:at+8].rstrip(b'\0')
        if name != b'.text':
            continue
        virtual_size, rva, size, off = struct.unpack_from('<IIII', data, at+8)
        if size < virtual_size or off + size > len(data) or size > 2*1024*1024:
            raise ValueError('invalid .text physical extent')
        if not rva <= ep < rva + virtual_size:
            raise ValueError('entrypoint outside .text')
        return imagebase + rva, imagebase + ep, data[off:off+size]
    raise ValueError('missing .text')


def audit_bytes(retail: bytes, gog: bytes) -> dict:
    base_r, ep_r, code_r = pe_code(retail)
    base_g, ep_g, code_g = pe_code(gog)
    if base_r != base_g or ep_r != ep_g:
        raise ValueError('incompatible code layout')
    anchors = {}
    for name, (va, expected) in HISTORICAL.items():
        idx = va - base_r
        if idx < 0 or idx + 32 > min(len(code_r), len(code_g)):
            raise ValueError('historical anchor outside .text')
        cr, cg = code_r[idx:idx+32], code_g[idx:idx+32]
        anchors[name] = {
            'va': f'0x{va:08X}',
            'historical_prefix_matches_retail_disk': cr.startswith(expected),
            'historical_prefix_matches_gog_disk': cg.startswith(expected),
            'retail_and_gog_32_bytes_identical': cr == cg,
        }
    signatures = {
        name: {'retail_count': code_r.count(pattern), 'gog_count': code_g.count(pattern)}
        for name, pattern in HISTORICAL_PATTERNS.items()
    }
    return {
        'historical_referent': 'January 2000 reverse-engineering paper; decoded runtime, potentially different release',
        'retail_entry_va': f'0x{ep_r:08X}', 'gog_entry_va': f'0x{ep_g:08X}',
        'retail_text_raw_size': len(code_r), 'gog_text_raw_size': len(code_g),
        'anchors': anchors, 'historical_signature_occurrences': signatures,
        'matched_entry_prologue_is_not_unwrapping_proof': True,
        'mismatches_do_not_prove_version_difference': True,
        'runtime_bytes_observed': False,
        'proprietary_bytes_emitted': False,
    }


def audit(retail: bytes, gog: bytes) -> dict:
    if len(retail) != RETAIL_SIZE or hashlib.sha256(retail).hexdigest() != RETAIL_HASH:
        raise ValueError('retail exact sample hash/size mismatch')
    if len(gog) != GOG_SIZE or hashlib.sha256(gog).hexdigest() != GOG_HASH:
        raise ValueError('GOG exact sample hash/size mismatch')
    r = audit_bytes(retail, gog)
    r['sample_sha256_verified'] = True
    return r


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail', type=Path, required=True)
    parser.add_argument('--gog', type=Path, required=True)
    args = parser.parse_args(argv)
    from rayman2_sample_provenance import read_bounded
    try:
        report = audit(read_bounded(args.retail), read_bounded(args.gog))
    except (ValueError, OSError) as e:
        parser.error(str(e))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
