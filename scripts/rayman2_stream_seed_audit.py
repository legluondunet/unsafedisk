#!/usr/bin/env python3
"""Rayman 2 retail/GOG SHA-gated, read-only x86 stream seed research.

Does not run, patch or decrypt a proprietary executable.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
from rayman2_stream_mode_audit import RETAIL_SHA, GOG_SHA, pe_mapper

MASK = 0xffffffff
MODULUS = 0x7fffffff
SALT = 0x075bd924
MAGIC = 0x069c16bd
MULT = 16807
DIV = 127773
ICD_SHA = '4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6'
DPLAYER_SHA = '0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee'

ANCHORS = {
    0x44ea23: '8a 15 f2 16 51 00',
    0x44ea29: '83 c4 08 f6 d2 88 15 f3 16 51 00',
    0x44ea34: '8b 0d f0 16 51 00',
    0x44ea3a: '81 f1 24 d9 5b 07',
    0x44ea41: '8b c1',
    0x44ea45: 'c1 e0 03 2b c1',
    0x44ea4c: '8d 04 80 8d 04 80 c1 e0 04 03 c1 8d 04 40 8d 14 41',
    0x44ea5d: 'b8 bd 16 9c 06',
    0x44ea62: '8b fa f7 e1',
    0x44ea66: '2b ca d1 e9 03 ca c1 e9 10',
    0x44ea6f: '8b c1 f7 d8 c1 e0 1f 2b c1 2b f8',
    0x44ea7a: '8b 45 f4 89 7e 14',
    0x44eaa0: 'e8 eb 22 00 00',
    0x450a2d: 'c7 46 14 79 cc b5 6a',
    0x4510cd: '8a 4f 15 8a 16 32 d1',
    0x4510d4: 'b8 bd 16 9c 06 88 16 8b 4f 14 81 f1 24 d9 5b 07',
    0x4510e4: 'f7 e1 8b c1 69 c9 a7 41 00 00',
    0x4510ee: '2b c2 d1 e8 03 c2 c1 e8 10 8b d0 f7 da c1 e2 1f 2b d0 2b ca',
    0x451105: '89 4f 14',
}


def require_u32(n):
    if not isinstance(n, int) or not 0 <= n <= MASK:
        raise ValueError('expected unsigned 32-bit integer')
    return n


def masked_input_from_global_before_complement(global_word):
    # 44EA23: high byte becomes bitwise NOT of byte at 0x5116F2.
    original = require_u32(global_word)
    adjusted = (original & 0xffffff) | ((((original >> 16) ^ 0xff) & 0xff) << 24)
    return adjusted ^ SALT


def native_quotient(x):
    x = require_u32(x)
    hi = (x * MAGIC) >> 32
    return (((x - hi) >> 1) + hi) >> 16


def next_state_from_masked(x):
    x = require_u32(x)
    return (MULT * x - native_quotient(x) * MODULUS) & MASK


def next_state(state):
    return next_state_from_masked(require_u32(state) ^ SALT)


def from_x86_instructions(x):
    """Independent literal 32-bit operation-by-operation emulator."""
    x = require_u32(x)
    eax = (x << 3) & MASK
    eax = (eax - x) & MASK
    eax = (eax + eax*4) & MASK
    eax = (eax + eax*4) & MASK
    eax = (eax << 4) & MASK
    eax = (eax + x) & MASK
    eax = (eax + eax*2) & MASK
    edx = (x + eax*2) & MASK
    edi = edx
    edx = (MAGIC*x) >> 32
    ecx = ((x - edx) & MASK) >> 1
    ecx = (ecx + edx) & MASK
    ecx >>= 16
    eax = ((-ecx) << 31) & MASK
    eax = (eax - ecx) & MASK
    return (edi - eax) & MASK


def quotient_boundary_proof():
    # Monotonicity of the instruction quotient is proven by both
    # x-hi(x) and hi(x) being nondecreasing for 0 <= x <= MASK.
    n = 0
    for q in range(MASK//DIV + 1):
        for x in (q*DIV, min(MASK, (q+1)*DIV-1)):
            if native_quotient(x) != q:
                raise ValueError(f'quotient mismatch at {x:#x}')
            n += 1
    return n


def negative_remainder_count():
    count = 0
    for q in range(1, MASK//DIV+1):
        last_r = min(DIV-1, MASK-q*DIV)
        count += min(last_r+1, ((2836*q-1)//MULT)+1)
    return count


def four_masks(global_snapshot):
    state = next_state_from_masked(masked_input_from_global_before_complement(global_snapshot))
    start = state
    masks = []
    for _ in range(4):
        masks.append((state >> 8) & 255)
        state = next_state(state)
    return {'initial_state':f'0x{start:08X}', 'xor_masks_hex':bytes(masks).hex(),
            'state_after_four':f'0x{state:08X}'}


def compare_auxiliary(data, prefix):
    if prefix not in (0,1,2) or (len(data)-prefix)%4:
        raise ValueError('unexpected auxiliary length')
    n = (len(data)-prefix)//4
    mismatches = 0
    normalized = 0
    first = None
    for index in range(n-1):
        before = struct.unpack_from('<I', data, prefix+4*index)[0]
        after = struct.unpack_from('<I', data, prefix+4*(index+1))[0]
        if after != (MULT*(before ^ SALT)) % MODULUS:
            normalized += 1
        if after != next_state(before):
            mismatches += 1
            if first is None: first = index
    return {'transitions':n-1,'normalized_mismatches':normalized,
            'native_stream_mismatches':mismatches,'first_native_mismatch':first}


def inspect(retail, gog):
    for name,data,sha in [('retail',retail,RETAIL_SHA),('GOG',gog,GOG_SHA)]:
        if hashlib.sha256(data).hexdigest()!=sha:
            raise ValueError(f'{name}: unknown SHA256')
    maps=[pe_mapper(retail),pe_mapper(gog)]
    for label,at in zip(('retail','GOG'),maps):
        for va,hexbytes in ANCHORS.items():
            b=bytes.fromhex(hexbytes)
            if at(va,len(b))!=b:
                raise ValueError(f'{label}: changed instruction 0x{va:X}')
    for va,length in ((0x44ea23,0x5d),(0x4510d4,0x31)):
        if maps[0](va,length)!=maps[1](va,length):
            raise ValueError(f'non-identical code at 0x{va:X}')
    return {'retail_sha256':RETAIL_SHA,'gog_sha256':GOG_SHA,
        'code_identical_between_retail_and_GOG':True,
        'stream_constructor_seed_overwritten':True,
        'modified_global_address':'0x005116F0',
        'stream_seed_store':'0x0044EA7D',
        'native_quotient_formula':'floor(x/127773)',
        'native_state_formula':'(16807*x - floor(x/127773)*2147483647) modulo 2^32',
        'mask_byte_formula':'(state >> 8) & 0xff',
        'quotient_boundary_checks':quotient_boundary_proof(),
        'negative_remainders_count':negative_remainder_count(),
        'example_masked_x':127773,
        'native_result_for_example':hex(next_state_from_masked(127773)),
        'normalized_result_for_example':hex((MULT*127773)%MODULUS),
        'game_executed':False,'retail_decrypted':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    p.add_argument('--icd',type=Path)
    p.add_argument('--dplayerx',type=Path)
    p.add_argument('--runtime-global',type=lambda v:int(v,0))
    args=p.parse_args()
    result=inspect(args.retail.read_bytes(),args.gog.read_bytes())
    if args.runtime_global is not None:
        result['runtime_snapshot_masks']=four_masks(args.runtime_global)
    for name,path,sha,prefix in (
        ('icd',args.icd,ICD_SHA,1),('dplayerx',args.dplayerx,DPLAYER_SHA,0)):
        if path is not None:
            data=path.read_bytes()
            if hashlib.sha256(data).hexdigest()!=sha:
                raise ValueError(f'{name}: unknown auxiliary SHA256')
            result[name+'_comparison']=compare_auxiliary(data,prefix)
    print(json.dumps(result,indent=2))


if __name__=='__main__': main()
