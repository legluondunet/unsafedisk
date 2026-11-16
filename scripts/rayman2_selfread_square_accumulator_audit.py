#!/usr/bin/env python3
"""Read-only, SHA-pinned audit of Rayman 2's type-0x170 square accumulator.

Does not execute or patch a game, prove integrity validation or output copyright
binary sections. The GOG comparator is not a pristine unwrapped retail build.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from rayman2_selfread_archive_audit import locked_read, sections, by_rva, archive_relation

IMAGE_BASE = 0x400000
REGISTRY_OTHER = 0x4A43E0
TYPED_CALLBACK_TABLE = 0x4A4278

# Opcode-boundary anchors, independently selected from CD x86 disassembly.
# All these exact instructions also survive in GOG's active .text.
ANCHORS = {
    0x47010E: '81 fd 70 01 00 00',       # cmp ebp,0x170
    0x470187: '3c 01 75 6e',             # cmp al,1 ; jne to function tail
    0x4701A6: 'e8 e5 09 01 00',          # call typed parser
    0x4701BC: '8b 04 10',                # mov eax,[eax+edx]
    0x4701BA: '33 c9',                   # xor ecx,ecx (zero the high halves)
    0x4701BF: '51 50 51 50',             # push 0, value, 0, value
    0x4701C3: 'e8 08 78 02 00',          # call 0x4979D0
    0x4701C8: '03 f0',                   # add esi,eax
    0x4701CE: '13 fa',                   # adc edi,edx
    0x4701D9: '89 74 24 28',             # write accumulator low
    0x4701DD: '89 7c 24 2c',             # write accumulator high
    0x4701E1: '89 5c 24 30',             # write object payload
    0x4701E5: 'c7 44 24 34 15 00 00 00',  # tag object as type 0x15
    0x4701ED: 'e8 0e 16 01 00',          # pass to callback dispatcher
    0x4979D0: '8b 44 24 08 8b 4c 24 10 0b c8',
    0x4979E0: '8b 44 24 04 f7 e1 c2 10 00', # unsigned MUL + ret 16
    0x4979E9: '53 f7 e1 8b d8',         # general 64bit multiplication path
    0x4979FE: '03 d3 5b c2 10 00',      # 64bit multiply final carry+ret
    0x481800: '56 57 8b 7c 24 14 8b 74 24 0c',
    0x481847: 'ff d0',                    # indirect callback
    0x47B29B: '81 fd 1b 01 00 00',       # separate type 0x11b compare
    0x47B2A9: '8b 1c 32',                # simple DWORD read
    0x47B30C: '89 18 c7 40 0c 07 00 00 00',  # 0x11b returns tag 7
}
CALLS = {0x4701A6:0x480B90, 0x4701C3:0x4979D0, 0x4701ED:0x481800}

# Adjacent registry type 0x171 is a useful counterexample to assuming every
# GOG code edit removes a SafeDisc check: original ShellExecuteA call suppressed.
NEIGHBOR_TYPE = 0x171
NEIGHBOR_CALL_SITE = 0x470256
NEIGHBOR_CD = bytes.fromhex('6a 00 6a 00 6a 00 50 6a 00 6a 00 ff 15 20 c2 49 00')
NEIGHBOR_GOG = b'\x90' * len(NEIGHBOR_CD)
NEIGHBOR_COMMON = {
    0x470218:bytes.fromhex('81 7e f8 71 01 00 00'),
    0x470267:bytes.fromhex('8b c6 5e 83 c4 10 c3'),
}


def squared_sum(low: int, high: int, value: int) -> tuple[int, int]:
    """Full unsigned x86 DWORD x DWORD, add/adc into original 64bit pair."""
    for v in (low,high,value):
        if not isinstance(v,int) or not 0 <= v <= 0xFFFFFFFF:
            raise ValueError('not a DWORD')
    product = value*value
    low_part = product & 0xFFFFFFFF
    high_part = (product>>32)&0xFFFFFFFF
    tmp=low+low_part
    return tmp&0xFFFFFFFF, (high+high_part+(tmp>>32))&0xFFFFFFFF


def rel32_target(va: int, code: bytes) -> int:
    if len(code)!=5 or code[0]!=0xE8:
        raise ValueError('not a direct near call')
    return va+5+struct.unpack('<i',code[1:])[0]


def raw_dword_offsets(blob: bytes, value: int) -> list[int]:
    pattern=struct.pack('<I',value)
    return [off for off in range(len(blob)-3) if blob[off:off+4]==pattern]


def inspect(cd: bytes, gog: bytes) -> dict:
    r={}
    inputs=[]
    for kind,b in (('cd',cd),('gog',gog)):
        base,ss=sections(b)
        if base!=IMAGE_BASE or not {'.text','.data','.rdata'}.issubset(ss):
            raise ValueError('unexpected module base or sections')
        if ss['.text'].rva!=0x1000 or ss['.rdata'].rva!=0x9C000 or ss['.data'].rva!=0x9F000:
            raise ValueError('unexpected section RVA layout')
        read=lambda va,size:by_rva(b,ss,va-base,size)
        for va,op in ANCHORS.items():
            exp=bytes.fromhex(op)
            if read(va,len(exp))!=exp:
                raise ValueError(f'{kind}: changed x86 opcode 0x{va:08X}')
        for va,target in CALLS.items():
            if rel32_target(va,read(va,5))!=target:
                raise ValueError(f'{kind}: unexpected call target 0x{va:08X}')
        # 0x170 dispatch: function pointer and flag in the registered type record.
        h,flag=struct.unpack('<II',read(REGISTRY_OTHER+0x170*8,8))
        if (h,flag)!=(0x470000,1):
            raise ValueError(f'{kind}: wrong type 0x170 registry entry')
        nfn,nflag=struct.unpack('<II',read(REGISTRY_OTHER+NEIGHBOR_TYPE*8,8))
        if (nfn,nflag)!=(0x470210,0):
            raise ValueError(f'{kind}: changed neighboring type 0x171 entry')
        for va,opcode in NEIGHBOR_COMMON.items():
            if read(va,len(opcode)) != opcode:
                raise ValueError(f'{kind}: changed type 0x171 common opcode {va:#x}')
        expected=NEIGHBOR_CD if kind=='cd' else NEIGHBOR_GOG
        if read(NEIGHBOR_CALL_SITE,len(expected))!=expected:
            raise ValueError(f'{kind}: unexpected type 0x171 ShellExecuteA instructions')
        # Type 0x11B is a distinct expression handler that returns a tagged DWORD.
        h2,flag2=struct.unpack('<II',read(0x4A5460+0x11B*8,8))
        if (h2,flag2)!=(0x47B170,0):
            raise ValueError(f'{kind}: wrong type 0x11b registry entry')
        # The 0x15 record contains field metadata and two generic callback VAs.
        typed=struct.unpack('<III',read(TYPED_CALLBACK_TABLE+0x15*12,12))
        if typed!=(0x29,0x4815A0,0x4817B0):
            raise ValueError(f'{kind}: changed callback-table row 0x15')
        literal_counts={}
        for name in ('.rdata','.data'):
            sec=ss[name]
            payload=by_rva(b,ss,sec.rva,sec.raw_size)
            literal_counts[name]={f'0x{typ:X}':len(raw_dword_offsets(payload,typ))
                                  for typ in (0x170,0x11B)}
        inputs.append({'reference':kind,'typed_table_row':list(map(lambda x:f'0x{x:X}',typed)),
                       'object_type_literal_counts_in_noncode_sections':literal_counts})
    cb,cs=sections(cd);gb,gs=sections(gog)
    code=by_rva(cd,cs,cs['.text'].rva,cs['.text'].raw_size)
    extra=by_rva(gog,gs,gs['.extra'].rva,gs['.extra'].raw_size)
    copy=archive_relation(code,extra,cs['.text'].rva)
    if cs['.text'].raw_size!=0x9A200 or gb+gs['.extra'].rva!=0x517000:
        raise ValueError('unexpected archiving layout')
    # Only this RVA interval is fully backed by an exact archived .text byte copy.
    return {
        'read_only':True,
        'input_sha256_required_at_cli':True,
        'anchored_opcodes_per_sample':len(ANCHORS),
        'verified_call_targets_per_sample':len(CALLS),
        'expression_type_0x170':{'entry_va':'0x470000','module_dword_read_va':'0x4701BC',
            'unsigned_square_helper_va':'0x4979D0', 'unsigned_square_callsite_va':'0x4701C3',
            'accumulator':'EDI:ESI (unsigned 64-bit)',
            'operation':'A=(A+(x*x)) mod 2^64',
            'typed_output_tag':'0x15','downstream_callback_dispatch':'0x481800',
            'prior_conversion_check_va':'0x470187'},
        'neighbor_type_0x171':{
            'handler':'0x470210',
            'original_iat_call':'ShellExecuteA via 0x49C220',
            'gog_call_region_replaced_by_nops':len(NEIGHBOR_GOG),
            'evidence_about_drm_intent':'none; code edits cannot all be assumed SafeDisc removals',
        },
        'distinct_expression_type_0x11B':{'entry_va':'0x47B170',
            'module_dword_read_va':'0x47B2A9','output_type':7,
            'not_the_same_squared_accumulator':True},
        'gog_archive':{'base_va':'0x517000',
            'exact_original_code_rva_start':'0x1000',
            'exact_original_code_rva_end_exclusive':'0x9B200',
            'outside_exactly_mirrored_text_not_proven_equivalent':True,
            'same_code_section':copy['exact_original_text_bytes']},
        'inputs':inputs,
        'not_proven':['objects actually present in game assets','runtime reachability',
                      'sampled addresses valid/in .text','downstream compare or fail',
                      'physical SafeDisc media authentication'],
    }


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    a=p.parse_args()
    print(json.dumps(inspect(locked_read(a.retail,'cd'),locked_read(a.gog,'gog')),
                     indent=2,sort_keys=True))

if __name__=='__main__':main()
