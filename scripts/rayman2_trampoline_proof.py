#!/usr/bin/env python3
"""SHA-pinned read-only proof of Rayman 2's masked Win32 call trampolines.

Inspects owner-provided protected retail PE only. Never runs, patches, or
unpacks it. This diagnostic does not infer live pointers or SafeDisc keys.
"""
import argparse
import hashlib
import json
import struct

from pathlib import Path
from rayman2_cd_io_diff import safe_read as checked_input, va_bytes as backed
from pe_import_xrefs import parse_headers as pe_headers
from pe_masked_api_inventory import decode_name

EXPECTED_SHA = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
DESCRIPTORS = 0x004A141C
BUFFER = 0x00510EA0
# Entry VA, one-based descriptor number, generator VA, flush-call VA, call-stub VA, kind
WRAPPERS = [
    (0x00448500,11,0x00448556,0x0044856E,0x0044859D,'push-ret'),
    (0x0044E750,10,0x0044E7BC,0x0044E7DD,0x0044E820,'mov-xor-push-ret'),
    (0x0044F220,8,0x0044F28C,0x0044F2AD,0x0044F2FA,'mov-xor-jmp'),
    (0x0044F380,12,0x0044F3EC,0x0044F40D,0x0044F44B,'mov-xor-push-ret'),
]


def p32(n):
    return struct.pack('<I',n)


def code_gen(base, slot, kind):
    if kind == 'push-ret':
        return (b'\xc6\x06\x68\x8b\x15'+p32(slot)+b'\x8b\x3d'+p32(base)+
                b'\xc6\x46\x05\xc3\x33\xd7\x89\x56\x01')
    if kind not in ('mov-xor-jmp','mov-xor-push-ret'):
        raise ValueError('unknown trampoline type')
    last=b'\xff\xe0' if kind == 'mov-xor-jmp' else b'\x50\xc3'
    return (b'\xc6\x06\xa1\xc7\x46\x01'+p32(slot)+
            b'\xc6\x46\x05\x33\xc6\x46\x06\x05\xc7\x46\x07'+p32(base)+
            b'\xc6\x46\x0b'+last[:1]+b'\xc6\x46\x0c'+last[1:])


def flush_pattern():
    # GetCurrentProcess (record 2), then FlushInstructionCache (record 1).
    return (b'\x8b\x0d'+p32(0x4A1498)+b'\xa1'+p32(0x4A1468)+
            b'\x33\xc1\xff\xd0\x8b\x15'+p32(0x4A144C)+
            b'\x8b\x0d'+p32(0x4A141C)+b'\x68'+p32(0x464)+
            b'\x68'+p32(BUFFER)+b'\x50\x33\xca\xff\xd1')


def assert_bytes(data, head, site, expected):
    if backed(data,head,site,len(expected)) != expected:
        raise ValueError(f'wrong opcode pattern at 0x{site:08X}')


def analyze(data):
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise ValueError('wrong exact protected Rayman 2 SHA-256')
    h=pe_headers(data)
    names=[]
    for i in range(35):
        record=backed(data,h,DESCRIPTORS+i*0x4c,0x4c)
        if record[0x30:0x34] != b'\0'*4:
            raise ValueError(f'unexpected on-disk pointer at descriptor {i+1}')
        names.append(decode_name(record))
    if names[:2] != ['FlushInstructionCache','GetCurrentProcess']:
        raise ValueError('helper API names not verified')
    wanted={8:'CreateFileA',10:'ReadFile',11:'CloseHandle',12:'SetFilePointer'}
    results=[]
    for entry,index,write,flush,call,kind in WRAPPERS:
        if names[index-1] != wanted[index]:
            raise ValueError('unexpected masked API mapping')
        assert_bytes(data,h,entry,bytes.fromhex('8B 0D F0 0B 51 00'))
        if bytes.fromhex('81 F1 24 D9 5B 07') not in backed(data,h,entry,32):
            raise ValueError('PRNG salt not verified')
        base=DESCRIPTORS+(index-1)*0x4c
        assert_bytes(data,h,write,code_gen(base,base+0x30,kind))
        assert_bytes(data,h,flush,flush_pattern())
        assert_bytes(data,h,call,b'\xff\xd6')  # CALL ESI
        results.append({'function_va':f'0x{entry:08X}','name':names[index-1],
                        'descriptor':index,'template':kind,
                        'generated_instruction_bytes':6 if kind=='push-ret' else 13,
                        'generator_va':f'0x{write:08X}',
                        'cache_flush_site_va':f'0x{flush:08X}',
                        'indirect_call_va':f'0x{call:08X}'})
    region=[]
    for section in h['sections']:
        x=BUFFER-h['image_base']-section['rva']
        if 0<=x<section['virtual_size']:
            region.append(dict(name=section['name'],zero_initial=x>=section['raw_size'],
                               executable_flag=bool(section['flags']&0x20000000),
                               write_flag=bool(section['flags']&0x80000000)))
    if region != [{'name':'.data','zero_initial':True,'executable_flag':False,'write_flag':True}]:
        raise ValueError('unexpected PE trampoline memory layout')
    nt=int.from_bytes(data[0x3C:0x40], 'little')
    nx=bool(int.from_bytes(data[nt+24+70:nt+24+72], 'little') & 0x100)
    return {'sha256_verified':True,'read_only':True,'runtime_execution_proven':False,
            'native_unwrapping_performed':False,'descriptor_count':len(names),
            'all_35_pointer_fields_zero_on_disk':True,'nx_compat_flag':nx,
            'buffer':region[0],
            'generator_offset_modulus':0x455,'maximum_offset':0x455-1,
            'largest_generated_stub_bytes':13,
            'maximum_used_span':0x455-1+13,
            'instruction_cache_flush_bytes':0x464,
            'helpers':['GetCurrentProcess','FlushInstructionCache'],
            'wrappers':results,
            'warning':'Static patterns; actual runtime memory permissions and resolved pointers unknown.'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('retail',type=Path)
    opt=p.parse_args(argv)
    try:
        print(json.dumps(analyze(checked_input(opt.retail)),indent=2))
    except (OSError,ValueError) as e:
        p.exit(1,f'ERROR: {e}\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
