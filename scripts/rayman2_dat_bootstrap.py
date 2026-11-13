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
import math
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
    # Bootstrap always begins with the first DAT name; only the later
    # game-resource lookup selects among 24 names in the original edition.
    for binary, format_va in ((retail, 0x004A2264), (gog, 0x004A2268)):
        if pe_va(binary,0x44DE9D,5)!=bytes.fromhex('A1 90 20 4A 00'):
            raise ValueError('missing bootstrap first-name table lookup')
        name_va=struct.unpack('<I',pe_va(binary,0x004A2090,4))[0]
        if name_va!=0x004A221C or pe_va(binary,name_va,12)!=b'LEVELS0.DAT\0':
            raise ValueError('unexpected bootstrap DAT filename')
        if pe_va(binary,0x44DEB7,5)!=b'\x68'+struct.pack('<I',format_va):
            raise ValueError('unexpected bootstrap filename formatting')
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
    seek_report = verify_seek_selector(retail, gog)
    return {**seek_report, 'read_only':True,'sha256_verified':True,'sample_pair': 'retail CD and modified GOG',
            'bootstrap_filename':'LEVELS0.DAT','later_retail_alias_selector_independent':True,
            'header_length_bytes':16,'following_4byte_reads':8,'nominal_minimum_bytes':48,
            'return_values_checked_for_full_reads':False,'global_writes':checks,
            'two_unused_read_indices':[0,7],
            'actual_cd_DAT_payload_verified':False,
            'warning':'Static read-path structure, not proof of actual data or SafeDisc decryption.'}


# Core x87 selector instructions are identical across the two exact samples.
SELECTOR_VA = 0x0044ED8E
SELECTOR_LENGTH = 192
SELECTOR_CONSTANTS = (1.06913, 1.69314, -0.69314, -0.52658, 1000000.0, 1e-6)
SELECTOR_ANCHORS = {
    0x0044ED92:'A0 F2 16 51 00',
    0x0044ED99:'F7 35 B4 17 51 00',
    0x0044EDB2:'0F 86 42 04 00 00',
    0x0044EDC8:'DC 0D 48 C9 49 00',
    0x0044EDCE:'D9 FE D9 E1',
    0x0044EDD2:'DC 0D 50 C9 49 00',
    0x0044EDDC:'DC 25 58 C9 49 00',
    0x0044EDF7:'E8 56 11 01 00',
    0x0044EDFC:'DC 0D 60 C9 49 00',
    0x0044EE0B:'E8 3C 11 01 00',
    0x0044EE18:'DC 0D 68 C9 49 00',
    0x0044EE31:'E8 16 11 01 00',
    0x0044EE39:'E8 72 10 01 00',
    0x0044EE40:'8B 35 54 17 51 00',
    0x0044EE46:'0F AF 1D BC 17 51 00 03 DE',
}


def verify_seek_selector(retail: bytes, gog: bytes) -> dict:
    """Check retained x87 code/constants and exact CRT forwarding thunks.

    Assumes the two samples have already passed analyze_executables' exact
    SHA-256 gates. Do not use it by itself to authenticate unknown samples.
    """
    chunks = range(0, SELECTOR_LENGTH, 64)
    original = b''.join(pe_va(retail, SELECTOR_VA+i, 64) for i in chunks)
    reference = b''.join(pe_va(gog, SELECTOR_VA+i, 64) for i in chunks)
    if original != reference:
        raise ValueError('original/GOG x87 selector code mismatch')
    for binary in (retail, gog):
        if struct.unpack('<6d', pe_va(binary, 0x0049C940, 48)) != SELECTOR_CONSTANTS:
            raise ValueError('unexpected six floating-point selector constants')
        for va, bytecode in SELECTOR_ANCHORS.items():
            expected = bytes.fromhex(bytecode)
            if pe_va(binary, va, len(expected)) != expected:
                raise ValueError(f'wrong selector instruction at VA 0x{va:08X}')
        # These thunk locations correspond to imported CRT modf/floor/_ftol.
        for va, iat in ((0x45ff52, 0x49c12c), (0x45ff4c, 0x49c13c),
                        (0x45feb0, 0x49c1ac)):
            if pe_va(binary, va, 6) != b'\xff\x25'+struct.pack('<I',iat):
                raise ValueError('unexpected imported CRT forwarding thunk')
    return {'x87_selector_retained_identical':True,
            'x87_selector_verified_bytes':len(original),
            'x87_instruction_anchors_verified':len(SELECTOR_ANCHORS),
            'six_float_constants_verified':True,
            'bit_exact_x87_runtime_reproduction':False}


def approximate_dat_seek(state_byte:int, modulus:int, count:int,
                         base:int, stride:int) -> dict:
    """Binary64 mathematical approximation, NOT exact x87 FSIN/CRT behavior.

    A normal (m>0) path calculates m=state_byte%modulus, accumulates the
    sine terms, keeps the fractional part with modf, floors a 1e6 scale,
    then multiplies by count and floors again. Large counts can overflow
    the original signed 32-bit _ftol conversion, which is NOT emulated.
    """
    fields=(state_byte,modulus,count,base,stride)
    if any(type(x) is not int for x in fields) or not (
        0<=state_byte<=255 and 1<=modulus<=0xffffffff and
        0<=count<=0x7fffffff and 0<=base<=0xffffffff and
        0<=stride<=0xffffffff
    ):
        raise ValueError('invalid DAT selector parameters or unsupported _ftol width')
    m=state_byte%modulus
    if m == 0:
        return {'read_occurs':False,'m':0,'j_approximate':None,
                'position_approximate':None,'bit_exact_x87':False}
    acc=1.06913
    for i in range(m):
        acc += 0.69314*abs(math.sin(1.69314*i*i))+0.52658
    fraction=math.modf(acc)[0]
    quantized=math.floor(fraction*1000000.0)*1e-6
    j=math.floor(quantized*count)
    return {'read_occurs':True,'m':m,'j_approximate':j,
            'position_approximate':(base+j*stride)&0xffffffff,
            'quantized_fraction_approximate':quantized,
            'bit_exact_x87':False}

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
