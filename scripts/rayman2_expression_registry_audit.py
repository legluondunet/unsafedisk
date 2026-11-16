#!/usr/bin/env python3
"""Read-only, exact-hash audit of Rayman 2's type-to-handler expression registry.

The CD and GOG files are non-redistributed, exact owner-supplied PE32 samples.
No runtime reachability, DRM checksum or complete unwrapping is inferred.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from rayman2_selfread_archive_audit import locked_read, sections, by_rva

IMAGE_BASE = 0x400000
REGISTRY_BASE = 0x4A5460
REGISTRY_STRIDE = 8
OTHER_REGISTRY_BASE = 0x4A43E0
OTHER_HANDLERS = {
    0x16E:(0x46FF90,0), 0x16F:(0x472F90,0),
    0x170:(0x470000,1), 0x171:(0x470210,0), 0x172:(0x4708B0,0),
}
TYPE_MIN, TYPE_MAX = 0x110, 0x11B
HANDLERS = {
    0x110:(0x47AE10,1), 0x111:(0x47AEB0,0), 0x112:(0x47B0E0,1),
    0x113:(0x47B170,0), 0x114:(0x47B170,0), 0x115:(0x47B170,0),
    0x116:(0x47B340,0), 0x117:(0x47B170,0), 0x118:(0x47B170,0),
    0x119:(0x47B170,0), 0x11A:(0x47B170,0), 0x11B:(0x47B170,0),
}
# All instructions below are unchanged in both exact programs.
SHARED = {
    0x480B90:'8b 44 24 08',
    0x480B9B:'8a 48 07',
    0x480BA4:'ff 14 8d 80 41 4a 00',
    0x480880:'56 8b 74 24 0c 8b 06 50 e8 93 6f 00 00',
    0x48089B:'51 56 52 ff d0',
    0x487820:'8b 44 24 04 8b 04 c5 60 54 4a 00 c3',
    0x487810:'8b 44 24 04 8a 04 c5 64 54 4a 00 c3',
    0x482680:'8b 44 24 04 8a 04 c5 e4 43 4a 00 c3',
    0x482690:'8b 44 24 04 8b 04 c5 e0 43 4a 00 c3',
    0x480900:'56 8b 74 24 0c 57 8b 06 50',
    0x480909:'e8 82 1d 00 00',
    0x480926:'ff d7',
    0x47010E:'81 fd 70 01 00 00',
    0x4701BC:'8b 04 10',
    0x470187:'3c 01 75 6e',
    0x4701ED:'e8 0e 16 01 00',
    0x4815F0:'8b 44 24 0c 8b 4c 24 04 81 e1 ff 00 00 00',
    0x481623:'e8 08 00 00 00',
    0x481800:'56 57 8b 7c 24 14 8b 74 24 0c',
    0x481822:'e8 39 00 00 00',
    0x481847:'ff d0',
    0x481850:'8b 44 24 04 8d 04 40 8b 04 85 7c 42 4a 00 c3',
    0x481860:'8b 44 24 04 8d 04 40 8b 04 85 80 42 4a 00 c3',
    0x47B185:'8b 68 f8',
    0x47B29B:'81 fd 1b 01 00 00',
    0x47B2A3:'75 09',
    0x47B2A5:'8b 54 24 10 8b 1c 32',
    0x47B305:'8b 44 24 40',
    0x47B30C:'89 18 c7 40 0c 07 00 00 00',
    0x47B460:'f7 d2 5f 89 11 c7 41 0c 07 00 00 00',
}
REGULAR_GOG_REDIRECTS = {
    0x470051:'b8 00 70 51 00 eb 5b',
    0x4700B7:'eb 55',
    0x47B1C3:'b8 00 70 51 00 eb 5b',
    0x47B229:'eb 55',
    0x47B388:'e9 b4 00 00 00',
}
REGULAR_CD_AT_SITES = {
    0x470051:'99 b9 55 04 00 00',
    0x4700B7:'3b f7',
    0x47B1C3:'99 b9 55 04 00 00',
    0x47B229:'3b f7',
    0x47B388:'99 b9 55 04 00 00',
}


def decode_rows(raw: bytes, first: int = TYPE_MIN) -> list[dict]:
    """Decode bounded 8-byte records, for independent synthetic testing."""
    if not 1 <= len(raw) // 8 <= 256 or len(raw) % 8:
        raise ValueError('registry length invalid')
    return [{'type':f'0x{first+i:X}', 'handler_va':f'0x{fn:08X}', 'flag':flag}
            for i, (fn,flag) in enumerate(struct.iter_unpack('<II',raw))]


def validate_anchors(raw_read) -> None:
    for va,code in SHARED.items():
        if raw_read(va,len(bytes.fromhex(code))) != bytes.fromhex(code):
            raise ValueError(f'changed shared opcode at 0x{va:08X}')


def inspect(cd: bytes, gog: bytes) -> dict:
    registry = []
    other_registry = []
    for kind,raw in (('cd',cd),('gog',gog)):
        base,sects=sections(raw)
        if base!=IMAGE_BASE or not {'.text','.data'}.issubset(sects):
            raise ValueError('wrong PE base or missing sections')
        text_section=sects['.text']; data_section=sects['.data']
        if text_section.rva!=0x1000 or data_section.rva!=0x9f000:
            raise ValueError('unrecognized original layout')
        read=lambda va,size:by_rva(raw,sects,va-base,size)
        validate_anchors(read)
        table_start=REGISTRY_BASE+TYPE_MIN*REGISTRY_STRIDE
        rows=decode_rows(read(table_start,(TYPE_MAX-TYPE_MIN+1)*REGISTRY_STRIDE))
        for typ,row in zip(range(TYPE_MIN,TYPE_MAX+1),rows):
            fn,flag=HANDLERS[typ]
            if (int(row['handler_va'],16),row['flag'])!=(fn,flag):
                raise ValueError(f'{kind} changed handler for {typ:#x}')
        # The byte-type parser dispatches through a separate table;
        # its entry 3 uses the registry-based interpreter at 0x480880.
        if struct.unpack('<I',read(0x4A4180+3*4,4))[0]!=0x480880:
            raise ValueError(f'{kind} unexpected object parser entry 3')
        for va,pattern in (REGULAR_CD_AT_SITES if kind=='cd' else REGULAR_GOG_REDIRECTS).items():
            if read(va,len(bytes.fromhex(pattern)))!=bytes.fromhex(pattern):
                raise ValueError(f'{kind} changed branch at {va:#x}')
        registry.append(rows)
        other_rows=decode_rows(read(OTHER_REGISTRY_BASE+0x16E*REGISTRY_STRIDE,
                                    len(OTHER_HANDLERS)*REGISTRY_STRIDE),0x16E)
        for typ,row in zip(sorted(OTHER_HANDLERS),other_rows):
            fn,flag=OTHER_HANDLERS[typ]
            if (int(row['handler_va'],16),row['flag'])!=(fn,flag):
                raise ValueError(f'{kind} changed alternate handler for {typ:#x}')
        other_registry.append(other_rows)
    if registry[0]!=registry[1] or other_registry[0]!=other_registry[1]:
        raise ValueError('registry differs between original and GOG')
    return {
        'read_only':True, 'exact_sha256_inputs_mandatory_at_cli':True,
        'registry_base_va':f'0x{REGISTRY_BASE:08X}',
        'record_stride_bytes':REGISTRY_STRIDE,
        'types_checked':f'0x{TYPE_MIN:X}..0x{TYPE_MAX:X}',
        'rows':registry[0],
        'other_registry_base_va':f'0x{OTHER_REGISTRY_BASE:08X}',
        'other_registry_rows_checked':other_registry[0],
        'other_lookup_va':'0x482690',
        'other_handler_dispatch_va':'0x480900',
        'other_special_type_0x170':{'handler':'0x470000', 'module_read':'0x4701BC',
                                    'gog_original_text_archive_base':'0x517000'},
        'handler_dispatch_va':'0x480880',
        'handler_lookup_va':'0x487820',
        'parser_byte_dispatch_va':'0x480B90',
        'parser_byte_type_3_va':'0x480880',
        'special_type_0x11B':{'handler':'0x47B170', 'module_read':'0x47B2A9',
                             'gog_original_text_archive_base':'0x517000'},
        'type_0x116':{'handler':'0x47B340','operation':'bitwise NOT',
                      'gog_skips_generated_trampoline':True},
        'shared_anchors_checked':len(SHARED),
        'gog_branch_redirects_checked':len(REGULAR_GOG_REDIRECTS),
        'runtime_0x11B_reachability_observed':False,
        'first_path_secondary_callback_dispatch': {'gate_va':'0x470187',
                  'dispatcher_va':'0x481800','dispatcher_callback_va':'0x481847',
                  'callback_resolver_va':'0x481860',
                  'callback_table_va':'0x4A4280'},
        'downstream_integrity_verdict_observed':False,
        'warning':'A handler identity is not proof the object is present, executed, or used as DRM.'
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    a=p.parse_args(argv)
    output=inspect(locked_read(a.retail,'cd'),locked_read(a.gog,'gog'))
    print(json.dumps(output,indent=2))

if __name__=='__main__':main()
