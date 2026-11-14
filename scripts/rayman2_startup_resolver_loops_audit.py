#!/usr/bin/env python3
"""SHA-locked, read-only inventory of Rayman 2 startup descriptor loops.

No SafeDisc unwrap is attempted. Reports only control-flow metadata, never game bytes.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct

from rayman2_patch_dependency_audit import (
    pe_sections, get_bytes, sha_gate, CD_HASH, GOG_HASH,
)

REPO = 'legluondunet/unsafedisk'
CALLS = {
    0x44947C: 0x4478A0,
    0x449485: 0x448DB0,
    0x44948E: 0x448D80,
    0x44949A: 0x447DE0,
    0x44949F: 0x448E30,
}
# Complete original loop bodies, including the final RET.
LOOPS = {
    'small': {
        'va': 0x448DB0, 'counter_va': 0x5113E8, 'first_index': 0,
        'callee_va': 0x447A90, 'count': 7,
        'code': bytes.fromhex(
            'a1e81351005633f685c0761a578b7c240c5756e8c8ecffff'
            'a1e813510083c408463bf072ec5f5ec3'),
        'call_va': 0x448DC3,
    },
    'descriptors': {
        'va': 0x448D80, 'counter_va': 0x5113F0, 'first_index': 1,
        'callee_va': 0x447AF0, 'count': 36,
        'code': bytes.fromhex(
            'a1f013510056be010000003bc6761a578b7c240c5756e855edffff'
            'a1f013510083c408463bf072ec5f5ec3'),
        'call_va': 0x448D96,
    },
}
# Distinct later refreshes in the original helper 0x447DE0, *not*
# extra guaranteed iterations in the two startup loops.
REFRESH_CALLS = {
    0x44818A: (0x447A90, 2),
    0x448196: (0x447AF0, 24),
    0x4481A2: (0x447AF0, 25),
}

ANCHORS = {
    0x401EF8: '6a01e861740400',  # PUSH mode=1; CALL initializer
    0x4493FA: 'c705e813510007000000',
    0x449404: 'c705f013510024000000',
    0x4493E7: '8b5d08',
    0x4493F0: '85db',
    0x449496: '85db740a',
    0x447A90: '558beca1ec13510085c07416',
    0x447ACE: 'ffd1',  # masked GetModuleHandleA via ECX
    0x447AE4: '8904b1',  # write 7-slot runtime state
    0x447AF0: '558beca1ec13510053565785c07419',
    0x447B21: '8d0cc0',  # 9*index
    0x447B24: '8d3448',  # 19*index
    0x447B27: 'c1e602',  # 76*index
    0x447B2A: '8b8e04144a00',  # descriptor field +0x34
    0x447B30: '8b9ed0134a00',  # descriptor mask base
    0x447B3D: '89be00144a00',  # empty pointer branch
    0x447BC2: '899e00144a00',  # conditional slot write
}


def target(code: bytes, site: int) -> int:
    if len(code) != 5 or code[0] != 0xE8:
        raise ValueError('not direct CALL rel32')
    return site + 5 + struct.unpack_from('<i', code, 1)[0]


def expected_indices(initial: int, limit: int) -> list[int]:
    """Unsigned loop condition after the initial body guard (limit <= 255)."""
    if not 0 <= initial <= 255 or not 0 <= limit <= 255:
        raise ValueError('loop bounds must be byte-sized')
    return list(range(initial, limit))


def inspect(retail: bytes, gog: bytes) -> dict:
    sha_gate(retail, CD_HASH)
    sha_gate(gog, GOG_HASH)
    cp, gp = pe_sections(retail), pe_sections(gog)
    if cp['image_base'] != gp['image_base'] or cp['image_base'] != 0x400000:
        raise ValueError('unexpected image base')
    for va, op in ANCHORS.items():
        exp = bytes.fromhex(op)
        if get_bytes(retail, cp, va, len(exp)) != exp:
            raise ValueError(f'original machine-code anchor mismatch at {va:#x}')
    # This initializer is shared byte-for-byte between CD and GOG.
    same_initializer = get_bytes(retail, cp, 0x449360, 331)
    if same_initializer != get_bytes(gog, gp, 0x449360, 331):
        raise ValueError('initializer not preserved')
    graph = []
    for site, dest in CALLS.items():
        for data, pe in ((retail, cp), (gog, gp)):
            if target(get_bytes(data, pe, site, 5), site) != dest:
                raise ValueError(f'startup edge mismatch {site:#x}')
        graph.append({'call_va': hex(site), 'target_va': hex(dest)})
    result_loops = {}
    for name, d in LOOPS.items():
        va, body = d['va'], d['code']
        if get_bytes(retail, cp, va, len(body)) != body:
            raise ValueError(f'{name} original loop body mismatch')
        if get_bytes(gog, gp, va, 16) != b'\xc3' + b'\xcc'*15:
            raise ValueError(f'{name} GOG return stub mismatch')
        if target(get_bytes(retail, cp, d['call_va'], 5), d['call_va']) != d['callee_va']:
            raise ValueError(f'{name} iteration target mismatch')
        indices = expected_indices(d['first_index'], d['count'])
        result_loops[name] = {
            'original_va': hex(va),
            'count_global_va': hex(d['counter_va']),
            'original_loop_callee_va': hex(d['callee_va']),
            'first_index': indices[0],
            'last_index': indices[-1],
            'conditional_iterations_if_initializer_mode_1_completed': len(indices),
            'gog_direct_callee_is_ret_int3_stub': True,
            'call_instruction_preserved_in_gog_initializer': True,
        }
    refresh = []
    for site, (callee, idx) in REFRESH_CALLS.items():
        if idx > 0xff:
            raise ValueError('unexpected refresh index')
        push_args = bytes([0x6A, 1, 0x6A, idx])
        if get_bytes(retail, cp, site - 4, 4) != push_args:
            raise ValueError(f'refresh PUSH flags/index mismatch at {site:#x}')
        if target(get_bytes(retail, cp, site, 5), site) != callee:
            raise ValueError(f'original refresh CALL mismatch at {site:#x}')
        if get_bytes(gog, gp, site - 4, 9) != b'\xcc'*9:
            raise ValueError(f'GOG refresh still appears in active .text at {site:#x}')
        refresh.append({'call_va': hex(site), 'callee_va': hex(callee),
                        'descriptor_or_module_index': idx, 'flag_argument': 1,
                        'gog_replaced_with_int3': True})
    # On disk the pointer slots are zero, and the 36 76-byte records are
    # the bootstrap descriptor #0 followed by descriptor indices 1..35.
    masks = []
    for idx in range(36):
        addr = 0x4A13D0 + 76*idx
        orig = get_bytes(retail, cp, addr, 76)
        other = get_bytes(gog, gp, addr, 76)
        if orig != other or orig[0x30:0x34] != b'\x00'*4:
            raise ValueError(f'descriptor {idx} differs or pointer not initially zero')
        masks.append(struct.unpack_from('<I', orig, 0)[0])
    if not all(masks):
        raise ValueError('unexpected empty descriptor mask')
    return {
        'retail_sha256_verified': CD_HASH,
        'gog_sha256_verified': GOG_HASH,
        'startup_initializer_va': '0x449360',
        'startup_mode_one_callsite_va': '0x401EFA',
        'startup_initializer_bytes_identical': len(same_initializer),
        'startup_preserved_calls': graph,
        'loops': result_loops,
        'descriptor_table_va': '0x4A13D0',
        'descriptor_stride_bytes': 76,
        'descriptor_index_range': [0, 35],
        'descriptor_count_byte_identical': 36,
        'descriptor_36_pointer_slots_zero_on_disk': True,
        'original_dynamic_callee_masked_getmodulehandlea_site': '0x447ACE',
        'original_per_descriptor_pointer_writer_site': '0x447BC2',
        'original_statically_implied_callback_visits_if_mode_1': 42,
        'later_conditional_original_refresh_calls': refresh,
        'extra_refresh_calls_not_counted_as_startup_loop_iterations': 3,
        'runtime_call_count_measured': False,
        'safedisc_decryption_or_cd_authentication_proven': False,
        'executable_patched': False,
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail', type=Path, required=True)
    p.add_argument('--gog', type=Path, required=True)
    args = p.parse_args()
    for path in (args.retail, args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
            p.error('refusing symlink, missing file or >2 MB input')
    try:
        print(json.dumps(inspect(args.retail.read_bytes(), args.gog.read_bytes()), indent=2))
    except ValueError as exc:
        p.error(str(exc))


if __name__ == '__main__':
    main()
