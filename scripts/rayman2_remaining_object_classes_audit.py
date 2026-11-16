#!/usr/bin/env python3
"""Read-only SHA-pinned x86 audit of Rayman 2 byte classes 5..40.

Scope is limited to the original owner's CD and separately modified GOG
PE32 binaries. It does not run, decrypt or patch either game executable.
The opcode template proves a local static effect, not runtime reachability.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

from rayman2_selfread_archive_audit import locked_read, sections, by_rva
from rayman2_five_object_dispatch_audit import PARSER_TABLE, PARSER_ROWS, PARSER_HASH

BASE = 0x400000
HANDLER_LOW = 0x480220
HANDLER_HIGH = 0x480800
HANDLER_SPAN_SHA = '028b75a304843ed411f05ef284914992220d7728de3e180a078f30f82c95d69f'
PARSER_CODE_START = 0x480800
PARSER_CODE_END = 0x480BB0
PARSER_CODE_SHA = 'dcf64fe7acdbbe5493ee1823745ba07e12dddab4dc32d2563faa4f18d82efc16'
FIRST_CLASS = 6
LAST_CLASS = 40
# MOV EAX,[ESP+8]; MOV ECX,[ESP+12]; MOV EDX,[EAX];
# MOV DWORD PTR [ECX+12], <u32 literal>; MOV [ECX],EDX;
# ADD EAX,8; RET
LITERAL_PREFIX = bytes.fromhex('8b 44 24 08 8b 4c 24 0c 8b 10 c7 41 0c')
LITERAL_SUFFIX = bytes.fromhex('89 11 83 c0 08 c3')
LITERAL_SIZE = len(LITERAL_PREFIX) + 4 + len(LITERAL_SUFFIX)

# Non-literal classes: a complete, independently hash-pinned handler
# interval still guards the entire region. These specific bytes validate
# what is asserted about each special case in the report.
SPECIAL = {
    6: ('zero_typed_result', 0x4806F0),
    7: ('zero_typed_result', 0x4806F0),
    8: ('constant_16_without_cursor_advance', 0x4806D0),
    9: ('validation_helper_and_error_route', 0x4803D0),
    10: ('generic_conversion_helper', 0x480400),
    11: ('generic_conversion_helper', 0x480400),
    15: ('triple_dword_typed_0x15', 0x4805A0),
    16: ('three_nested_values_typed_0x15', 0x480510),
    17: ('u16_typed_0x1a', 0x480630),
    39: ('stateful_nested_parser', 0x480220),
    40: ('advance_8_only', 0x4807F0),
}

# Virtual-address -> bytes. All are checked against *both* binaries.
SPECIAL_ANCHORS = {
    0x4806F0: '8b 44 24 0c c7 00 00 00 00 00',
    0x4806FA: 'c7 40 0c 14 00 00 00',
    0x4806D4: 'c7 00 10 00 00 00',
    0x4806DA: 'c7 40 0c 14 00 00 00',
    0x4803EA: '84 c0 75 0c',
    0x480400: '8b 4c 24 04',
    0x4805C0: 'c7 41 0c 15 00 00 00',
    0x48058C: 'c7 46 0c 15 00 00 00',
    0x48063A: '66 8b 10',
    0x48063D: 'c7 41 0c 1a 00 00 00',
    0x480220: 'a0 1c 9c 4b 00',
    0x480249: '89 1d 20 9c 4b 00',
    0x4802C2: '80 f9 10',
    0x4807F0: '8b 44 24 08 83 c0 08 c3',
    0x480A50: 'a0 1c 9c 4b 00',
    0x480A67: '8b 0d 9c 93 4e 00',
    0x480A98: '3a d3 73 5e',
    0x480B33: '3a d3 73 34',
    0x480B6B: '6a 00 6a 18',
    0x480B7C: 'c7 00 00 00 00 00',
    0x480B82: 'c7 40 0c 14 00 00 00',
    0x480B9B: '8a 48 07',
    0x480BA4: 'ff 14 8d 80 41 4a 00',
}

DIRECT_CALLS = {
    0x4803E2: 0x487CF0,
    0x4803F2: 0x480FB0,
    0x48041C: 0x4815F0,
    0x480524: 0x480B90,
    0x480545: 0x480B90,
    0x480566: 0x480B90,
    0x48024F: 0x4826A0,
    0x4802A5: 0x480BD0,
    0x480A75: 0x4826E0,
    0x480AD0: 0x480A30,
    0x480B01: 0x482870,
    0x480B10: 0x482730,
    0x480B3F: 0x482760,
    0x480B5F: 0x4809E0,
    0x480B6F: 0x480FB0,
}


def call_target(site: int, instruction: bytes) -> int:
    if len(instruction) != 5 or instruction[0] != 0xE8:
        raise ValueError('not a direct x86 E8 rel32 CALL')
    return (site + 5 + struct.unpack('<i', instruction[1:])[0]) & 0xFFFFFFFF


def classify_handler(handler: int, at) -> dict:
    """Classify an exactly matched handler; never speculate about effects."""
    code = at(handler, LITERAL_SIZE)
    if (code[:len(LITERAL_PREFIX)] == LITERAL_PREFIX
        and code[len(LITERAL_PREFIX)+4:] == LITERAL_SUFFIX):
        value = struct.unpack_from('<I', code, len(LITERAL_PREFIX))[0]
        return {'behavior': 'literal_dword_to_typed_result',
                'output_type': value, 'consumes_bytes': 8,
                'writes_output_value_from_input_dword': True}
    return {'behavior': 'non_literal_special', 'output_type': None,
            'consumes_bytes': None, 'writes_output_value_from_input_dword': False}


def examine(raw: bytes) -> dict:
    base, ss = sections(raw)
    if base != BASE or '.text' not in ss or '.data' not in ss:
        raise ValueError('unexpected PE layout')
    at = lambda va, n: by_rva(raw, ss, va-BASE, n)
    for a, b, expected in ((HANDLER_LOW,HANDLER_HIGH,HANDLER_SPAN_SHA),
                            (PARSER_CODE_START,PARSER_CODE_END,PARSER_CODE_SHA),
                            (PARSER_TABLE,PARSER_TABLE+4*PARSER_ROWS,PARSER_HASH)):
        if hashlib.sha256(at(a,b-a)).hexdigest() != expected:
            raise ValueError(f'changed code/table span 0x{a:08X}')
    for va, hexbytes in SPECIAL_ANCHORS.items():
        exp = bytes.fromhex(hexbytes)
        if at(va,len(exp)) != exp:
            raise ValueError(f'changed instruction at 0x{va:08X}')
    for va, target in DIRECT_CALLS.items():
        if call_target(va, at(va,5)) != target:
            raise ValueError(f'changed direct-call target at 0x{va:08X}')
    dispatch = struct.unpack('<' + 'I'*PARSER_ROWS,
                             at(PARSER_TABLE,4*PARSER_ROWS))
    if dispatch[5] != 0x480A50:
        raise ValueError('class 5 handler mismatched')
    classes = []
    for i in range(FIRST_CLASS,LAST_CLASS+1):
        handler = dispatch[i]
        if not HANDLER_LOW <= handler < HANDLER_HIGH:
            raise ValueError(f'class {i} handler outside bounded region')
        mapped = classify_handler(handler,at)
        if i in SPECIAL:
            desc,expected_va = SPECIAL[i]
            if mapped['behavior'] != 'non_literal_special' or handler != expected_va:
                raise ValueError(f'class {i} special mismatch')
            mapped['behavior'] = desc
        elif mapped['behavior'] != 'literal_dword_to_typed_result':
            raise ValueError(f'class {i} no longer matches literal handler')
        classes.append({'class_id': i,'handler':f'0x{handler:08X}',**mapped})
    hist=Counter(c['behavior'] for c in classes)
    assert len(classes) == 35
    if hist['literal_dword_to_typed_result'] != 24:
        raise ValueError('literal class count changed')
    if len(set(c['handler'] for c in classes)) != 32:
        raise ValueError('unique handler count changed')
    # Two distinct class parsers, 15 & 16, produce a typed 0x15 result,
    # independent of the type-0x170 accumulator's result.
    if any(c['output_type']==0x15 for c in classes):
        raise ValueError('class 0x15 producers should be specialised, not literal')
    if [c['class_id'] for c in classes if c['behavior']=='triple_dword_typed_0x15'] != [15]:
        raise ValueError('class 15 typed route missing')
    if [c['class_id'] for c in classes if c['behavior']=='three_nested_values_typed_0x15'] != [16]:
        raise ValueError('class 16 typed route missing')
    return {
        'handler_region_sha256': HANDLER_SPAN_SHA,
        'parser_region_sha256': PARSER_CODE_SHA,
        'parser_table_sha256': PARSER_HASH,
        'classes_6_through_40': classes,
        'slot_count':len(classes),
        'unique_handler_count':len(set(c['handler'] for c in classes)),
        'literal_dword_slots':hist['literal_dword_to_typed_result'],
        'other_slots':len(classes)-hist['literal_dword_to_typed_result'],
        'class_5':{
            'handler':'0x00480A50','behavior':'stateful_nested_parser',
            'global_state_addresses':['0x004B9C1C','0x004B9C20','0x004E939C','0x004E939A'],
            'two_comparison_branches':['0x00480A9A','0x00480B35'],
            'fallback_error_path_at':'0x00480B6B',
            'fallback_returns_zero_typed_0x14':True,
        },
        'other_classes_0_to_4': 'examined in previous five-family audit',
        'runtime_calls_observed': False,
        'physical_CD_integrity_or_SafeDisc_bypass_proven': False,
    }


def audit(cd: bytes, gog: bytes) -> dict:
    retail=examine(cd)
    second=examine(gog)
    if retail != second:
        raise ValueError('CD/GOG handler families diverge')
    return {'read_only':True,'exact_samples_required':True,
            'original_and_GOG_static_regions_identical':True,
            'results':retail}


def main(argv=None) -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--retail',type=Path,required=True)
    ap.add_argument('--gog',type=Path,required=True)
    ns=ap.parse_args(argv)
    report=audit(locked_read(ns.retail,'cd'),locked_read(ns.gog,'gog'))
    print(json.dumps(report,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
