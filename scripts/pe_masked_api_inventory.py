#!/usr/bin/env python3
"""Decode static Windows DLL/export names in a bounded PE descriptor layout.

Research only: does not execute, patch, decrypt a PE, or infer runtime API
addresses from zero-valued on-disk descriptor slots. No input bytes printed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from pe_reference_diff import parse_pe32, read_bounded


def file_backed_bytes(pe: dict, va: int, length: int) -> bytes:
    if not 0 <= va <= 0xFFFFFFFF or not 0 < length <= 4096:
        raise ValueError('unbounded VA or length')
    rva = va - pe['image_base']
    for section in pe['sections'].values():
        offset = rva - section['rva']
        if 0 <= offset and offset + length <= section['raw_len']:
            return section['contents'][offset:offset + length]
    raise ValueError(f'VA 0x{va:08X} is not backed by file data')


def decode_name(record: bytes) -> str:
    """Decode seed/deltas/length/bytes as observed in the protected loader.

    First four bytes: starting subtraction key, starting XOR key, and their
    per-character increments. Byte +4: name length. Names are ASCII.
    """
    if len(record) < 6:
        raise ValueError('truncated name descriptor')
    subtract, xor_key, sub_inc, xor_inc, count = record[:5]
    if count < 1 or count > len(record) - 5:
        raise ValueError('encoded name length outside record')
    out = bytearray()
    for value in record[5:5 + count]:
        out.append(((value - subtract) & 0xFF) ^ xor_key)
        subtract = (subtract + sub_inc) & 0xFF
        xor_key = (xor_key + xor_inc) & 0xFF
    if any(v < 0x21 or v > 0x7E for v in out):
        raise ValueError('decoded name is not printable ASCII')
    return out.decode('ascii')


def decode_plain_name(record: bytes) -> str:
    nul = record.find(b'\0')
    if nul < 1 or any(record[nul+1:]):
        raise ValueError('plaintext module name must be NUL terminated and padded')
    data = record[:nul]
    if any(v < 0x21 or v > 0x7E for v in data):
        raise ValueError('plaintext module name is not printable ASCII')
    return data.decode('ascii')


def inspect(pe: dict, module_base: int, module_stride: int, modules: int,
            api_base: int, api_stride: int, apis: int,
            module_selector_offset: int, pointer_slot_offset: int,
            module_mode: str = 'encoded') -> dict:
    if (not 1 <= modules <= 32 or not 1 <= apis <= 256
        or not 6 <= module_stride <= 4096 or not 6 <= api_stride <= 4096
        or module_selector_offset < 0 or pointer_slot_offset < 0
        or module_selector_offset + 4 > api_stride
        or pointer_slot_offset + 4 > api_stride):
        raise ValueError('invalid descriptor dimensions/offsets')
    if module_mode not in ('encoded','plain'):
        raise ValueError('invalid module-name mode')
    module_rows = []
    for index in range(modules):
        va = module_base + index*module_stride
        raw = file_backed_bytes(pe, va, module_stride)
        name = decode_name(raw) if module_mode == 'encoded' else decode_plain_name(raw)
        module_rows.append({'index_zero_based': index, 'name': name})
    api_rows = []
    for i in range(apis):
        va = api_base + i*api_stride
        raw = file_backed_bytes(pe, va, api_stride)
        module_index = int.from_bytes(raw[module_selector_offset:module_selector_offset+4], 'little')
        if module_index >= modules:
            raise ValueError(f'API record {i} references missing module index {module_index}')
        slot = int.from_bytes(raw[pointer_slot_offset:pointer_slot_offset+4], 'little')
        api_rows.append({
            'index_one_based': i+1, 'descriptor_va': f'0x{va:08X}',
            'module_index_zero_based': module_index,
            'module_name': module_rows[module_index]['name'],
            'api_name': decode_name(raw),
            'pointer_slot_va': f'0x{va + pointer_slot_offset:08X}',
            'pointer_slot_zero_on_disk': slot == 0,
        })
    return {
        'read_only': True, 'reference_sha256': pe['sha256'],
        'runtime_exports_resolved': False,
        'derived_runtime_addresses_asserted': False,
        'api_name_encoding': 'additive-byte-key + XOR',
        'module_name_encoding': module_mode,
        'module_count': modules, 'api_count': apis,
        'zero_on_disk_slots': sum(row['pointer_slot_zero_on_disk'] for row in api_rows),
        'modules': module_rows, 'apis': api_rows,
        'warning': ('Static name decoding only. Runtime module load success, '
                    'export resolution, encoded pointer writes and execution '
                    'must be established independently.'),
    }


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('pe',type=Path)
    for name in ('module-base', 'module-stride', 'module-count',
                 'api-base', 'api-stride', 'api-count',
                 'module-selector-offset', 'pointer-slot-offset'):
        parser.add_argument('--'+name, type=lambda v:int(v,0), required=True)
    parser.add_argument('--module-mode',choices=('encoded','plain'),default='encoded',
                        help='encoded retail DLL names or GOG plaintext names')
    a=parser.parse_args(argv)
    try:
        pe=parse_pe32(read_bounded(a.pe))
        result=inspect(pe, a.module_base,a.module_stride,a.module_count,
                       a.api_base,a.api_stride,a.api_count,
                       a.module_selector_offset,a.pointer_slot_offset,a.module_mode)
    except (OSError,ValueError) as exc:
        parser.exit(1,f'ERROR: {exc}\n')
    print(json.dumps(result,indent=2))
    return 0


if __name__=='__main__':
    raise SystemExit(main())
