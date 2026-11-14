#!/usr/bin/env python3
"""Read-only, hash-pinned inventory of five Rayman 2 object dispatch families.

Interprets the original engine's first five class handlers and their on-disk
function-pointer registries. This does not execute untrusted functions, decrypt
SafeDisc, inspect DRM runtime decisions, or distribute proprietary bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from rayman2_selfread_archive_audit import locked_read, sections, by_rva

IMAGE_BASE = 0x400000
CODE_LOW, CODE_HIGH = 0x401000, 0x49B200
PARSER_TABLE = 0x4A4180
PARSER_ROWS = 41
PARSER_HASH = 'c5b610b43699e6e64e75a171968d5aa35ca20a260a1082ef4fbc0ea96543f7b3'
TRAILER_PREFIX = bytes.fromhex('d31742cefbffdf3f0000803f')


@dataclass(frozen=True)
class Family:
    tag: int
    first_va: int
    count: int
    stride: int
    following_va: int
    class_handler: int
    getter_va: int
    getter_call_va: int
    dispatch_call_va: int
    checksum: str
    trailer_hash: str


FAMILIES = (
    Family(0, 0x4A5E80, 20, 4, 0x4A5EE0, 0x480800, 0x487D50, 0x480808, 0x48081E,
           'fbe235969671a7655df39152c8dbda0445181b379a99253eb78e33768d5b7e1a',
           'fa286d4865350afe801f159e800db723fc7f11bda2571ef03ba551d3c79bb49f'),
    Family(1, 0x4A5EE0, 149, 8, 0x4A6398, 0x480830, 0x487D70, 0x480841, 0x480857,
           'e8f3b8fdfaf26c427d260b3ffb128aca2f34128949d17b0ccb38f367f6a6926e',
           'fa286d4865350afe801f159e800db723fc7f11bda2571ef03ba551d3c79bb49f'),
    Family(2, 0x4A6398, 28, 4, 0x4A6418, 0x4808B0, 0x487D80, 0x4808B8, 0x4808CE,
           'afc0cf5ee33337b90e28b97cd963fd0aba87c16267397af1b5e7aa04f7aed266',
           'fa286d4865350afe801f159e800db723fc7f11bda2571ef03ba551d3c79bb49f'),
    Family(3, 0x4A5460, 314, 8, 0x4A5E80, 0x480880, 0x487820, 0x480888, 0x48089E,
           'd424c142fa7c8a974e3d9b73638a8cb6864fc1e919f707cc46c94159ffa4f996',
           'e3cd7f65d01647660657814a91062f590b16ce4656534c1b765f5a308f217f0b'),
    Family(4, 0x4A43E0, 514, 8, 0x4A5460, 0x480900, 0x482690, 0x480909, 0x480926,
           'b6cbd675c8faa32c8f94631d81e6ebcb3321365893ac8adf8e3fe209075fb41a',
           'b16f973515e4ce20338a0d7d87aff735b5786b68cc25553112dbf376ad1b75f6'),
)


def decode_table(blob: bytes, family: Family) -> tuple[tuple[int, ...], tuple[int, ...]]:
    if len(blob) != family.count * family.stride:
        raise ValueError('table length inconsistent with bounded class registry')
    words = struct.unpack('<' + 'I' * (len(blob)//4), blob)
    pointers = words[::2] if family.stride == 8 else words
    flags = words[1::2] if family.stride == 8 else ()
    if any(not CODE_LOW <= p < CODE_HIGH for p in pointers):
        raise ValueError('table contains out-of-code pointer')
    if any(f not in (0, 1) for f in flags):
        raise ValueError('table contains unexpected flag')
    return tuple(pointers), tuple(flags)


def validate_trailer(trailer: bytes, family: Family) -> None:
    if len(trailer) != family.following_va - family.first_va - family.count * family.stride:
        raise ValueError('wrong trailer extent')
    if len(trailer) < 16 or trailer[:12] != TRAILER_PREFIX:
        raise ValueError('missing non-function trailer marker')
    if hashlib.sha256(trailer).hexdigest() != family.trailer_hash:
        raise ValueError('unexpected table-trailing data')
    if family.tag != 3 and trailer[12:] != b'\x00' * 4 and len(trailer) == 16:
        raise ValueError('unexpected 16-byte trailer suffix')


def target_of_call(site: int, code: bytes) -> int:
    if len(code) != 5 or code[0] != 0xE8:
        raise ValueError('expected x86 E8 rel32 call')
    displacement, = struct.unpack('<i', code[1:5])
    return (site + 5 + displacement) & 0xFFFFFFFF


def validate_getter_code(code: bytes, family: Family) -> None:
    # MOV EAX,[ESP+4] ; MOV EAX,[EAX*stride+table_va] ; RET.
    prefix = bytes.fromhex('8b4424048b04')
    scale = b'\x85' if family.stride == 4 else b'\xc5'
    expected = prefix + scale + struct.pack('<I', family.first_va) + b'\xc3'
    if code != expected:
        raise ValueError('getter does not index the expected registry')


def decode_object_header(record: bytes, class_id: int, families_data: dict[int, tuple[tuple[int,...], tuple[int,...]]]) -> dict:
    """Static single-record routing model; does NOT execute or parse level files."""
    if len(record) != 8:
        raise ValueError('record header must be exactly eight bytes')
    if record[7] != class_id or class_id not in families_data:
        raise ValueError('unknown or mismatched class ID')
    tag, = struct.unpack('<I', record[:4])
    pointers, flags = families_data[class_id]
    if tag >= len(pointers):
        raise ValueError('record tag indexes past validated table')
    return {'class_id': class_id, 'record_type': tag, 'target': f'0x{pointers[tag]:08X}',
            'flag': flags[tag] if flags else None,
            'handler_cursor_advance': 8,
            'runtime_call_performed': False}


def examine(raw: bytes) -> tuple[dict, dict[int, tuple[tuple[int,...], tuple[int,...]]]]:
    base, ss = sections(raw)
    if base != IMAGE_BASE or not {'.text', '.data'}.issubset(ss):
        raise ValueError('unsupported x86 sample PE layout')
    at = lambda va, length: by_rva(raw, ss, va-base, length)
    t = at(PARSER_TABLE, PARSER_ROWS*4)
    if hashlib.sha256(t).hexdigest() != PARSER_HASH:
        raise ValueError('41-pointer parser table modified')
    parser = struct.unpack('<41I', t)
    if at(0x480B9B, 3) != b'\x8a\x48\x07' or at(0x480BA4,7) != bytes.fromhex('ff148d80414a00'):
        raise ValueError('byte class dispatch opcode mismatch')
    result = {}
    models: dict[int, tuple[tuple[int,...], tuple[int,...]]] = {}
    for family in FAMILIES:
        if parser[family.tag] != family.class_handler:
            raise ValueError(f'class {family.tag} dispatch mismatch')
        n = family.count * family.stride
        table = at(family.first_va,n)
        if hashlib.sha256(table).hexdigest() != family.checksum:
            raise ValueError(f'class {family.tag} registry SHA mismatch')
        pointers, flags = decode_table(table, family)
        trailer = at(family.first_va+n, family.following_va-family.first_va-n)
        validate_trailer(trailer,family)
        validate_getter_code(at(family.getter_va,12),family)
        if target_of_call(family.getter_call_va,at(family.getter_call_va,5)) != family.getter_va:
            raise ValueError(f'class {family.tag} getter call mismatch')
        if at(family.dispatch_call_va,2) != (b'\xff\xd7' if family.tag==4 else b'\xff\xd0'):
            raise ValueError(f'class {family.tag} dynamic call mismatch')
        models[family.tag] = (pointers, flags)
        cnt=Counter(flags)
        result[str(family.tag)] = {
            'class_handler':f'0x{family.class_handler:08X}',
            'getter':f'0x{family.getter_va:08X}',
            'table_address':f'0x{family.first_va:08X}',
            'entry_count':len(pointers),
            'stride_bytes':family.stride,
            'distinct_targets':len(set(pointers)),
            'flag_zero':cnt[0] if flags else None,
            'flag_one':cnt[1] if flags else None,
            'table_sha256':family.checksum,
            'next_nonhandler_bytes':len(trailer),
            'next_nonhandler_sha256':family.trailer_hash,
            'trailing_region_not_interpreted_as_code_pointers':True,
        }
    if models[4][0][0x170] != 0x470000 or models[3][0][0x11B] != 0x47B170:
        raise ValueError('Rayman 2 target object mappings changed')
    cls5=parser[5]
    if cls5 != 0x480A50 or at(cls5,2) != b'\xa0\x1c':
        raise ValueError('class five is not the expected stateful parser')
    return {'families':result,
            'special_class_5_handler':'0x00480A50',
            'special_class_5_is_not_a_plain_registry_lookup':True,
            'original_tag_0x170':decode_object_header(struct.pack('<I',0x170)+b'\0\0\0\x04',4,models),
            'original_tag_0x11B':decode_object_header(struct.pack('<I',0x11B)+b'\0\0\0\x03',3,models),
            'object_bytes_from_level_data_observed':False,
            'SafeDisc_authentication_or_decryption_proven':False},models


def audit(cd:bytes,gog:bytes)->dict:
    one,_=examine(cd)
    two,_=examine(gog)
    if one!=two:
        raise ValueError('original and GOG code/table layouts differ')
    return {'read_only':True,
            'sha256_verified_by_cli':True,
            'active_sections_examined_not_gog_extra':True,
            'five_record_dispatch_tables_identical':True,
            'results':one,
            'runtime_behavior_observed':False}


def main()->None:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--retail', type=Path, required=True)
    ap.add_argument('--gog', type=Path, required=True)
    args=ap.parse_args()
    cd=locked_read(args.retail,'cd')
    gog=locked_read(args.gog,'gog')
    print(json.dumps(audit(cd,gog), indent=2))


if __name__=='__main__':
    main()
