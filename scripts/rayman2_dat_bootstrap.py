#!/usr/bin/env python3
"""Read-only Rayman 2 DAT bootstrap metadata research (not SafeDisc decryption).

For exact owner-supplied retail and GOG PE32 samples, verifies static code
patterns that create six global DAT parameters. An independent pure helper
models a *hypothetical* first 48-byte DAT buffer for synthetic tests. It
never executes the game, authenticates media, or reads binary resource data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

RETAIL_SHA256 = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_SHA256 = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
UINT32 = 0xffffffff
# Eight 4-byte reads after a 16-byte header; first and last words have no
# direct output to the six globals in this local function.
READ_CALL_VAS = (0x44E387, 0x44E43C, 0x44E4FE, 0x44E5B8,
                 0x44E662, 0x44E6B0, 0x44E6E5, 0x44E71A)
# After each successful nominal 4-byte read, the corresponding write to a
# global; the first/last reads are not assigned one of these six globals.
OUTPUTS = ((1, 0x5117B0, 0x44E471, 0),
           (2, 0x511750, 0x44E52C, 2),
           (3, 0x5117B4, 0x44E6AA, 0),
           (4, 0x5117C0, 0x44E6CA, 0),
           (5, 0x511754, 0x44E714, 0),
           (6, 0x5117BC, 0x44E732, 0))


def decode_bootstrap_48(data: bytes) -> dict[str, int]:
    """Model x86 unsigned-32 arithmetic for first 48 bytes of a DAT stream.

    Only a *mathematical* model: read success, actual file provenance and
    the file position are not inferred. The two unconsumed words in this
    function must still be present, but should not be called encrypted data.
    """
    if len(data) != 48:
        raise ValueError('DAT bootstrap model requires exactly 48 bytes')
    a, b, c, d = struct.unpack_from('<4I', data, 0)
    result: dict[str, int] = {}
    for i in range(8):
        (word,) = struct.unpack_from('<I', data, 16+4*i)
        if 1 <= i <= 6:
            output, shift = next((addr, shift) for k, addr, _, shift in OUTPUTS if k == i)
            value = (((word - a) & UINT32) ^ b) >> shift
            result[f'0x{output:08X}'] = value
        if i != 7:
            a = (a + c) & UINT32
            b = (b + d) & UINT32
    return result


def pe_va(data: bytes, va: int, length: int) -> bytes:
    if len(data) < 0x40 or data[:2] != b'MZ' or not 0 < length <= 64:
        raise ValueError('invalid PE32 or read length')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if nt + 24 > len(data) or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE32 header')
    sections = struct.unpack_from('<H', data, nt+6)[0]
    optional_len = struct.unpack_from('<H', data, nt+20)[0]
    opt = nt+24
    if (sections > 64 or sections < 1 or opt+optional_len+40*sections > len(data)
            or struct.unpack_from('<H', data, opt)[0] != 0x10b):
        raise ValueError('unsupported PE32 layout')
    image_base = struct.unpack_from('<I', data, opt+28)[0]
    rva = va-image_base
    for i in range(sections):
        entry = opt+optional_len+i*40
        section_rva = struct.unpack_from('<I', data, entry+12)[0]
        raw_len, raw_off = struct.unpack_from('<II', data, entry+16)
        if 0 <= rva-section_rva <= raw_len-length:
            start = raw_off + rva-section_rva
            if start+length > len(data):
                raise ValueError('PE section exceeds file')
            return data[start:start+length]
    raise ValueError(f'VA 0x{va:08X} is not backed by file bytes')


def analyze_executables(retail: bytes, gog: bytes) -> dict:
    if hashlib.sha256(retail).hexdigest() != RETAIL_SHA256:
        raise ValueError('original retail sample SHA-256 mismatch')
    if hashlib.sha256(gog).hexdigest() != GOG_SHA256:
        raise ValueError('GOG sample SHA-256 mismatch')
    checks=[]
    # A 16-byte header and eight 4-byte words are read in the retail path.
    for va, n in ((0x44E289,16), (0x44E383,4), (0x44E438,4),
                  (0x44E4FA,4), (0x44E5B4,4), (0x44E65E,4),
                  (0x44E6A6,4), (0x44E6E1,4), (0x44E710,4)):
        enc = b'\x6a'+bytes([n])
        if pe_va(retail,va,2)!=enc or pe_va(gog,va,2)!=enc:
            raise ValueError(f'nonmatching DAT bootstrap length at 0x{va:08X}')
        checks.append({'va':f'0x{va:08X}','purpose':'read length'})
    if pe_va(retail,0x44E28D,2)!=b'\xff\xd6':
        raise ValueError('missing original 16-byte indirect ReadFile')
    if pe_va(gog,0x44E28D,6)!=bytes.fromhex('FF 15 4C C0 49 00'):
        raise ValueError('missing GOG direct ReadFile for 16-byte header')
    for va in READ_CALL_VAS[:5]:
        if pe_va(retail,va,2)!=b'\xff\xd6':
            raise ValueError(f'missing original 4-byte indirect call at {va:#x}')
        if pe_va(gog,va,6)!=bytes.fromhex('FF 15 4C C0 49 00'):
            raise ValueError(f'missing GOG 4-byte direct ReadFile at {va:#x}')
    # Last 3 calls route via a preserved original wrapper address, which
    # GOG supplies as a direct-IAT forwarder. Check the shared E8 bytes.
    for va in READ_CALL_VAS[5:]:
        expected=b'\xe8'+struct.pack('<i', 0x44E750-va-5)
        if pe_va(retail,va,5)!=expected or pe_va(gog,va,5)!=expected:
            raise ValueError(f'expected preserved ReadFile wrapper at {va:#x}')
    for i, address, site, shift in OUTPUTS:
        expected=b'\x89\x15'+struct.pack('<I',address)
        for binary in (retail,gog):
            if pe_va(binary,site,6)!=expected:
                raise ValueError(f'missing shared global write at 0x{site:08X}')
        checks.append({'va':f'0x{site:08X}','read_index_zero_based':i,
                       'global_va':f'0x{address:08X}','right_shift':shift})
    for binary in (retail,gog):
        if pe_va(binary,0x44E529,3)!=bytes.fromhex('C1 EA 02'):
            raise ValueError('missing two-bit shift on third read')
        if pe_va(binary,0x44E469,8)!=bytes.fromhex('2B D0 33 D1 03 C3 03 CE'):
            raise ValueError('missing shared arithmetic on second word')
    return {'read_only':True,'sha256_verified':True,'sample_pair': 'retail CD and modified GOG',
            'header_length_bytes':16,'following_4byte_reads':8,'nominal_minimum_bytes':48,
            'return_values_checked_for_full_reads':False,'global_writes':checks,
            'two_unused_read_indices':[0,7],
            'actual_cd_DAT_payload_verified':False,
            'warning':'Static read-path structure, not proof of actual data or SafeDisc decryption.'}


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--retail',type=Path,required=True)
    ap.add_argument('--gog',type=Path,required=True)
    args=ap.parse_args(argv)
    try:
        # Explicit bounded research inputs, not a generic untrusted PE parser.
        if any(p.is_symlink() or not p.is_file() or p.stat().st_size>16*1024*1024
               for p in (args.retail,args.gog)):
            raise ValueError('refuse symlinks, nonregular or oversized inputs')
        print(json.dumps(analyze_executables(args.retail.read_bytes(),
                                            args.gog.read_bytes()),indent=2))
    except (ValueError,OSError) as exc:
        ap.exit(1,f'ERROR: {exc}\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
