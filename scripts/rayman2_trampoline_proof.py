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



GOG_SHA = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
# Original protected executable's direct masked-API slot initializer.
# GOG rewrites the entire 234-byte init routine to INT3.
SLOT_INIT = 0x00447AF0
SLOT_INIT_SIZE = 0xEA
SLOT_ANCHORS = {
    0x00447B21: '8D 0C C0 8D 34 48 C1 E6 02',  # index * 76
    0x00447B2A: '8B 8E 04 14 4A 00',           # descriptor module index
    0x00447B30: '8B 9E D0 13 4A 00',           # descriptor XOR mask
    0x00447B36: '8B 3C 8A',                    # loaded module base
    0x00447B3D: '89 BE 00 14 4A 00',           # zero if module not loaded
    0x00447B50: 'E8 DB FB FF FF',              # export resolver 0x447730
    0x00447B7B: 'E8 C0 F9 FF FF',              # import walker 0x447540
    0x00447B86: 'E8 A5 FB FF FF',              # export resolver 0x447730
    0x00447BAE: '8B 8E 00 14 4A 00',           # previous masked slot
    0x00447BB4: '33 CB',                       # unmask previous slot
    0x00447BBC: '85 C0',                       # check resolved pointer
    0x00447BC0: '33 D8',                       # EBX = mask XOR resolved EAX
    0x00447BC2: '89 9E 00 14 4A 00',           # write masked pointer
    0x00447BCD: '33 DB',                       # zero on failure
    0x00447BCF: '89 9E 00 14 4A 00',           # write zero on failure
}
SLOT_INIT_CALLS = {
    0x0044818A: 0x00447A90,
    0x00448196: SLOT_INIT,
    0x004481A2: SLOT_INIT,
    0x00448D96: SLOT_INIT,
    0x00448DC3: 0x00447A90,
}


def masked_slot(index):
    """Original x86 index is one-based; record stride is exactly 0x4C."""
    if type(index) is not int or not 1 <= index <= 35:
        raise ValueError('masked descriptor index must be 1..35')
    base = DESCRIPTORS + (index-1)*0x4C
    slot = 0x004A1400 + index*0x4C
    if slot != base+0x30:
        raise ValueError('descriptor pointer arithmetic differs')
    return base, slot


def verify_slot_initializer(retail, retail_headers, gog=None):
    """Read-only static verification; no runtime API pointer is recovered."""
    for site, hex_pattern in SLOT_ANCHORS.items():
        assert_bytes(retail,retail_headers,site,bytes.fromhex(hex_pattern))
    for site, dest in SLOT_INIT_CALLS.items():
        assert_bytes(retail,retail_headers,site,
                     b'\xe8' + struct.pack('<i',dest-site-5))
    rows=[]
    for i in range(1,36):
        base,slot=masked_slot(i)
        record=backed(retail,retail_headers,base,0x4C)
        if record[0x30:0x34] != b'\0'*4:
            raise ValueError('pointer slot unexpectedly initialized on disk')
        rows.append((base,record))
    gog_int3_verified=False
    if gog is not None:
        if hashlib.sha256(gog).hexdigest() != GOG_SHA:
            raise ValueError('wrong exact GOG reference SHA-256')
        gh=pe_headers(gog)
        if backed(gog,gh,SLOT_INIT,SLOT_INIT_SIZE) != b'\xcc'*SLOT_INIT_SIZE:
            raise ValueError('GOG retained unexpected resolver instructions')
        for va in (0x004474D0,0x00447540,0x00447730):
            if backed(gog,gh,va,8) != b'\xcc'*8:
                raise ValueError('GOG retains a removed name/import/export helper')
        for base, record in rows:
            if backed(gog,gh,base,0x4C) != record:
                raise ValueError('GOG masked API descriptor differs from retail')
        gog_int3_verified=True
    return {
        'retail_init_va':f'0x{SLOT_INIT:08X}',
        'direct_slot_init_calls_verified':3,
        'other_load_module_helper_calls_verified':2,
        'init_instruction_anchors_verified':len(SLOT_ANCHORS),
        'api_descriptors_verified':len(rows),
        'descriptor_stride_bytes':0x4C,
        'slot_formula':'0x004A1400 + index * 0x4C (index 1..35)',
        'on_success':'slot = decoded_runtime_API_VA XOR descriptor_mask',
        'zero_on_failure':True,
        'manual_PE_import_walker_va':'0x00447540',
        'manual_PE_export_resolver_va':'0x00447730',
        'gog_234_int3_resolver_bytes_verified':gog_int3_verified,
        'runtime_initialized_slot_values_unknown':True,
        'unwrapping_or_game_execution_performed':False,
    }


def analyze(data, gog=None):
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        raise ValueError('wrong exact protected Rayman 2 SHA-256')
    h=pe_headers(data)
    slot_report=verify_slot_initializer(data,h,gog)
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
            'masked_pointer_initialization':slot_report,
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
    p.add_argument('--gog',type=Path,help='optional exact GOG executable for INT3 comparison')
    opt=p.parse_args(argv)
    try:
        print(json.dumps(analyze(checked_input(opt.retail),
                                 checked_input(opt.gog) if opt.gog else None),indent=2))
    except (OSError,ValueError) as e:
        p.exit(1,f'ERROR: {e}\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
