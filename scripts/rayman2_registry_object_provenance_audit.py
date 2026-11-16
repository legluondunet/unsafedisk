#!/usr/bin/env python3
"""Read-only Rayman 2 object dispatch / selfread type-0x170 provenance audit.

This audit uses only two owner-supplied, SHA-256-locked PE32 images. It does
not execute or patch the game, claim SafeDisc bypass, or extract game data.
GOG is a separately modified comparative executable, NOT a clean unwrapping.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import struct
from pathlib import Path

from rayman2_selfread_archive_audit import locked_read, sections, by_rva
from rayman2_selfread_typed_callback_audit import disassemble_text, parse_direct_xrefs, relcall

BASE = 0x400000
REGISTRY_VA = 0x4A43E0
ROW_SIZE = 8
ROW_COUNT = 0x202  # 514 contiguous function+flag rows before non-pointer constants
NEXT_REGISTRY_VA = 0x4A5460
TRAILER_VA = REGISTRY_VA + ROW_COUNT * ROW_SIZE  # 0x4A53F0
TRAILER_REPETITIONS = 7
TRAILER_BLOCK_SIZE = 16
PARSER_TABLE_VA = 0x4A4180
PARSER_ROWS = 41
PARSER_SENTINEL_VA = PARSER_TABLE_VA + PARSER_ROWS*4
REGISTRY_SHA = "b6cbd675c8faa32c8f94631d81e6ebcb3321365893ac8adf8e3fe209075fb41a"
PARSER_SHA = "c5b610b43699e6e64e75a171968d5aa35ca20a260a1082ef4fbc0ea96543f7b3"
TRAILER_SHA = "b16f973515e4ce20338a0d7d87aff735b5786b68cc25553112dbf376ad1b75f6"
OBJECT_170 = 0x170
EXPECTED_HANDLER = 0x470000
SUBTYPE_2_HANDLER = 0x4808B0
SHARED_ANCHORS = {
    0x470032: '8b 6b f8',           # MOV EBP,[EBX-8] - object type
    0x47010E: '81 fd 70 01 00 00', # CMP EBP,0x170
    0x470114: '74 16',              # JE to the handled branch
    0x47012C: '80 7b 07 02',       # CMP BYTE [EBX+7],2
    0x470130: '75 1e',             # non-nested case
    0x47013F: '50 e8 cb 1a 01 00', # call 0x481c10, with preceding PUSH
    0x470150: '8b 4c 24 2c',
    0x47015C: '83 c3 08',          # advance object cursor by eight
    0x47017F: 'e8 6c 14 01 00',   # generic typed converter 0x4815f0
    0x470187: '3c 01 75 6e',      # requires conversion status 1
    0x4701A6: 'e8 e5 09 01 00',   # expression evaluator 0x480b90
    0x4701BC: '8b 04 10',          # read dword from base+computed offset
    0x4701ED: 'e8 0e 16 01 00',   # generic typed output dispatcher
    0x47B185: '8b 68 f8',         # other object -> type at [input-8]
    0x47B29B: '81 fd 1b 01 00 00',
    0x481C10: '8b 4c 24 08 8b 54 24 04',
    0x481C23: 'e8 68 ef ff ff',   # nested evaluation at 0x480b90
    0x481C35: 'e8 96 1a f9 ff',   # followup helper 0x4136d0
    0x480B9B: '8a 48 07',         # byte class discriminator [object+7]
    0x480BA4: 'ff 14 8d 80 41 4a 00', # indirect CALL through indexed parser table
    0x480880: '56 8b 74 24 0c 8b 06', # generic subtype3 wrapper
    0x4808B0: '56 8b 74 24 0c 8b 06', # generic subtype2 wrapper
    0x482690: '8b 44 24 04 8b 04 c5 e0 43 4a 00',
    0x482680: '8b 44 24 04 8a 04 c5 e4 43 4a 00',
}
CALL_TARGETS = {
    0x470140: 0x481C10,
    0x47017F: 0x4815F0,
    0x4701A6: 0x480B90,
    0x4701ED: 0x481800,
    0x481C23: 0x480B90,
    0x481C35: 0x4136D0,
}
GENERIC_COUNTS = {0x481C10: 15, 0x480B90: 757, 0x482680: 68, 0x482690: 1}
# The 112 bytes between the two pointer registries are seven 16-byte
# numeric-looking blocks; one word differs in the sixth block. This checks
# a deliberate non-pointer boundary, not the semantics of the constants.
TRAILER_PREFIX = bytes.fromhex('d3 17 42 ce fb ff df 3f 00 00 80 3f')


def decode_rows(payload: bytes, limit: int = ROW_COUNT) -> list[tuple[int,int]]:
    if not 1 <= limit <= 1000 or len(payload) != limit * ROW_SIZE:
        raise ValueError('invalid registry length')
    return list(struct.iter_unpack('<II', payload))


def validate_registry(rows: list[tuple[int,int]], start_va: int = 0x401000,
                      end_va: int = 0x49B200) -> dict:
    if len(rows) != ROW_COUNT or not 0 < start_va < end_va:
        raise ValueError('registry size or code range mismatch')
    if any(not (start_va <= fn < end_va) or flag not in (0,1) for fn,flag in rows):
        raise ValueError('not a contiguous function+flag registry')
    if rows[OBJECT_170] != (EXPECTED_HANDLER,1):
        raise ValueError('type 0x170 registry entry changed')
    if [i for i,(fn,_) in enumerate(rows) if fn==EXPECTED_HANDLER] != [OBJECT_170]:
        raise ValueError('0x470000 handler is not exclusive to 0x170')
    if rows[0x171] != (0x470210,0):
        raise ValueError('neighbor 0x171 registry entry changed')
    flags=Counter(flag for _,flag in rows)
    return {'row_count':len(rows),'last_index_hex':hex(len(rows)-1),
            'unique_handler_addresses':len(set(fn for fn,_ in rows)),
            'flag_zero_count':flags[0], 'flag_one_count':flags[1],
            'type_0x170_unique_handler_entry':True}


def validate_trailer(payload:bytes)->dict:
    if len(payload) != TRAILER_REPETITIONS*TRAILER_BLOCK_SIZE:
        raise ValueError('wrong trailer length')
    blocks=[payload[i*TRAILER_BLOCK_SIZE:(i+1)*TRAILER_BLOCK_SIZE]
            for i in range(TRAILER_REPETITIONS)]
    for i,b in enumerate(blocks):
        if not b.startswith(TRAILER_PREFIX) or b[12:] != struct.pack('<I',1 if i==5 else 0):
            raise ValueError('expected numeric constants absent after registry')
    return {'numeric_block_count':len(blocks),
            'trailer_bytes':len(payload),
            'not_plausible_handler_pairs':True}


def scan_dword_literals(payload:bytes, value:int)->int:
    if not 0 <= value <= 0xFFFFFFFF:raise ValueError('not a DWORD')
    return payload.count(struct.pack('<I',value))


def read_bytes(raw:bytes, sects:dict, va:int, length:int)->bytes:
    return by_rva(raw,sects,va-BASE,length)


def one(raw:bytes, disasm:str, name:str)->dict:
    base,ss=sections(raw)
    if base != BASE or not {'.text','.data','.rdata'}.issubset(ss):
        raise ValueError('wrong PE layout')
    byte_at=lambda addr,n:read_bytes(raw,ss,addr,n)
    for va, pattern in SHARED_ANCHORS.items():
        expected=bytes.fromhex(pattern)
        if byte_at(va,len(expected))!=expected:
            raise ValueError(f'{name}: opcode at {va:#x} differs')
    for va,target in CALL_TARGETS.items():
        site = va
        if relcall(site,byte_at(site,5))!=target:
            raise ValueError(f'{name}: unexpected CALL at {site:#x}')
    registry_bytes=byte_at(REGISTRY_VA,ROW_COUNT*ROW_SIZE)
    if hashlib.sha256(registry_bytes).hexdigest()!=REGISTRY_SHA:
        raise ValueError('exact original registry content changed')
    rows=decode_rows(registry_bytes)
    registry=validate_registry(rows)
    trailer_bytes=byte_at(TRAILER_VA,NEXT_REGISTRY_VA-TRAILER_VA)
    if hashlib.sha256(trailer_bytes).hexdigest()!=TRAILER_SHA:
        raise ValueError('exact numeric separator content changed')
    trailer=validate_trailer(trailer_bytes)
    parser_bytes=byte_at(PARSER_TABLE_VA,PARSER_ROWS*4)
    if hashlib.sha256(parser_bytes).hexdigest()!=PARSER_SHA:
        raise ValueError('exact 41-entry parser table content changed')
    parser=struct.unpack('<41I',parser_bytes)
    if parser[2]!=SUBTYPE_2_HANDLER or parser[3]!=0x480880:
        raise ValueError('nested parser entry changed')
    if any(not 0x401000<=addr<0x49B200 for addr in parser):
        raise ValueError('parser table points outside executable .text')
    if len(set(parser)) != 38 or byte_at(PARSER_SENTINEL_VA,4) != b'\x00'*4:
        raise ValueError('parser table lacks verified 41-entry boundary / zero sentinel')
    xrefs={}
    for target,n in GENERIC_COUNTS.items():
        sites=parse_direct_xrefs(disasm,target)
        if len(sites)!=n or any(relcall(site,byte_at(site,5))!=target for site in sites):
            raise ValueError(f'{name}: malformed generic call inventory for {target:#x}')
        xrefs[f'0x{target:08X}']=sites
    for secname in ('.rdata','.data'):
        sec=ss[secname]
        payload=by_rva(raw,ss,sec.rva,sec.raw_size)
        if scan_dword_literals(payload,OBJECT_170) or scan_dword_literals(payload,0x11B):
            raise ValueError(f'{name}: unexpected type literal in {secname}')
    return {
        'input':name,
        'registry':registry,
        'registry_trailer':trailer,
        'parser_table_count':PARSER_ROWS,
        'parser_table_unique_handlers':len(set(parser)),
        'parser_table_zero_sentinel_va':hex(PARSER_SENTINEL_VA),
        'parser_byte_class_2_handler':hex(parser[2]),
        'parser_byte_class_3_handler':hex(parser[3]),
        'handler_0x170':{
           'type_tag_location':'[object - 8]',
           'type_test_va':'0x47010E',
           'nested_class_field':'[object + 7]',
           'nested_class_value':2,
           'conditional_nested_resolver':'0x481C10',
           'generic_object_parser':'0x480B90',
           'generic_conversion':'0x4815F0',
           'square_accumulator_input_read':'0x4701BC',
           'generic_result_dispatcher':'0x481800',
        },
        'other_type_0x11B_tag_source':'[input - 8]',
        'unchanged_anchor_count':len(SHARED_ANCHORS),
        'generic_direct_calls':{addr:len(sites) for addr,sites in xrefs.items()},
        'generic_direct_caller_sites':{addr:[hex(site) for site in sites] for addr,sites in xrefs.items()},
        'type_literals_in_rdata_and_data':{'0x170':0,'0x11B':0},
    }


def inspect(cd:bytes,gog:bytes,cd_asm:str,gog_asm:str)->dict:
    a=one(cd,cd_asm,'cd')
    b=one(gog,gog_asm,'gog')
    for key in ('registry','registry_trailer','generic_direct_caller_sites','parser_table_count','parser_table_unique_handlers','parser_table_zero_sentinel_va'):
        if a[key]!=b[key]:raise ValueError(f'CD and GOG differ in {key}')
    return {
        'read_only':True,'exact_SHA256_verified_by_cli':True,
        'objects_from_game_resources_loaded':False,
        'any_0x170_object_execution_observed':False,
        'SafeDisc_integrity_verdict_proven':False,
        'inputs':[a,b],
        'interpretation':'Two data-driven dispatch levels: register type stored before object, nested parser subtype at +7. No authenticated level asset or runtime object.'
    }


def main()->None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail',required=True,type=Path)
    parser.add_argument('--gog',required=True,type=Path)
    args=parser.parse_args()
    cd=locked_read(args.retail,'cd')
    gog=locked_read(args.gog,'gog')
    cd_asm=disassemble_text(args.retail)
    gog_asm=disassemble_text(args.gog)
    if locked_read(args.retail,'cd')!=cd or locked_read(args.gog,'gog')!=gog:
        raise ValueError('input changed between hash verification and disassembly')
    print(json.dumps(inspect(cd,gog,cd_asm,gog_asm),indent=2))

if __name__=='__main__':main()
