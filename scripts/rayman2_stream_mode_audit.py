#!/usr/bin/env python3
"""Strictly read-only, hash-gated map of Rayman 2's stream-reader flags.

Only proves static calls, immediately visible 8-bit flag provenance, and
reader selection; does not execute the game or identify CD authentication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

BASE = 0x400000
RETAIL_SHA = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_SHA = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
CONSTRUCTOR = 0x450A00
OPEN_WRAPPER = 0x450A80
CALL_SITES = {
    0x44D510: ('constant', 3, 0x44D50B),
    0x44D56A: ('constant', 3, 0x44D565),
    0x44D5A3: ('constant', 3, 0x44D59E),
    0x44DADA: ('constant', 0, 0x44DACF),
    0x44DB48: ('constant', 0, 0x44DB43),
    0x44DB87: ('constant', 0, 0x44DB7C),
    0x44F782: ('conditional', None, 0x44F780),
    0x44F7E9: ('conditional', None, 0x44F7E7),
    0x44F823: ('conditional', None, 0x44F821),
}
# Both binaries must retain these exact instruction anchors.
ANCHORS = {
    0x450A0D: '89 5e 10 88 5e 0c 88 46 18',
    0x450A20: 'e8 9b 04 00 00',
    0x450A37: 'e8 94 04 00 00',
    0x450A5A: 'e8 71 04 00 00',
    0x450A4D: '89 46 24',
    0x450A70: '89 46 24',
    0x450A8D: '50 e8 6d ff ff ff',
    0x44EA1B: '56 6a 06 e8 dd 1f 00 00',
    0x450EC0: '8b 44 24 04 8a 40 18 d1 e8 83 e0 01 c3',
    0x450ED0: '8b 44 24 04 8a 40 18 c1 e8 02 83 e0 01 c3',
    0x44F76B: '8a 11 80 fa 77',
    0x44F774: '0f 95 c0 40 88 44 24 14',
    0x44F77C: '8b 5c 24 14',
    0x4510CD: '8a 4f 15 8a 16 32 d1',
    0x451105: '89 4f 14',
    0x4512DA: 'ff 15 4c c0 49 00',
}
READER_NAMES = {
    0x451090: 'direct ReadFile + XOR',
    0x451110: 'masked ReadFile + XOR',
    0x4512C0: 'direct ReadFile + raw bytes',
    0x451300: 'masked ReadFile + raw bytes',
}


def reader_for_flags(flags: int, modified: bool) -> int:
    """Model branch choices; not a claim of native runtime execution."""
    if not isinstance(flags, int) or flags < 0 or flags > 255:
        raise ValueError('flags must be a byte')
    use_xor = bool(flags & 0x02)
    use_masked_api = bool(flags & 0x04) and not modified
    if use_xor:
        return 0x451110 if use_masked_api else 0x451090
    return 0x451300 if use_masked_api else 0x4512C0


def pe_mapper(data: bytes):
    """Map a file-backed PE32 RVA to bytes, rejecting unbacked spans."""
    if data[:2] != b'MZ':
        raise ValueError('MZ absent')
    e_lfanew = struct.unpack_from('<I', data, 0x3c)[0]
    if e_lfanew > len(data) - 24 or data[e_lfanew:e_lfanew+4] != b'PE\0\0':
        raise ValueError('PE absent')
    number = struct.unpack_from('<H', data, e_lfanew+6)[0]
    opt_len = struct.unpack_from('<H', data, e_lfanew+20)[0]
    opt = e_lfanew + 24
    if (struct.unpack_from('<H', data, opt)[0] != 0x10b
            or struct.unpack_from('<I', data, opt+28)[0] != BASE):
        raise ValueError('not expected PE32')
    sections = []
    sec = opt + opt_len
    for i in range(number):
        o = sec + 40*i
        name = data[o:o+8].rstrip(b'\0').decode('ascii')
        rva, raw_size, raw_off = struct.unpack_from('<III', data, o+12)
        sections.append((name, rva, raw_off, raw_size))

    def at(va: int, n: int) -> bytes:
        for name, rva, raw_off, raw_size in sections:
            offs = va - BASE - rva
            if 0 <= offs and offs+n <= raw_size and raw_off+offs+n <= len(data):
                return data[raw_off+offs:raw_off+offs+n]
        raise ValueError(f'VA 0x{va:X} not in file-backed section')
    return at


def check_anchors(at):
    for va, hex_bytes in ANCHORS.items():
        expected = bytes.fromhex(hex_bytes)
        if at(va, len(expected)) != expected:
            raise ValueError(f'wrong x86 anchor 0x{va:X}')


def check_calls(at):
    for va, (kind, value, flag_source) in CALL_SITES.items():
        call = at(va, 5)
        if (call[0] != 0xe8
                or va + 5 + struct.unpack('<i', call[1:])[0] != OPEN_WRAPPER):
            raise ValueError(f'call at 0x{va:X} not 0x{OPEN_WRAPPER:X}')
        if kind == 'constant':
            if at(flag_source, 2) != bytes([0x6a, value]):
                raise ValueError(f'wrong constant flags at 0x{flag_source:X}')
        else:
            if at(flag_source, 1) != b'\x53':
                raise ValueError(f'wrong runtime flags push at 0x{flag_source:X}')

    # Different direct constructor invocation, present in both executables:
    # 0x44EA1C: PUSH 6; 0x44EA1E: CALL 0x450A00.
    call = at(0x44EA1E, 5)
    if (call[0] != 0xe8
            or 0x44EA23 + struct.unpack('<i', call[1:])[0] != CONSTRUCTOR):
        raise ValueError('direct flags=6 constructor call not verified')


def analyze(retail: bytes, gog: bytes) -> dict:
    for name, data, digest in (
        ('retail', retail, RETAIL_SHA),
        ('GOG', gog, GOG_SHA),
    ):
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError(f'{name} unknown SHA256')
    cd = pe_mapper(retail)
    gf = pe_mapper(gog)
    for at in (cd, gf):
        check_anchors(at)
        check_calls(at)

    if cd(0x450A46, 2) != bytes.fromhex('75 28') or cd(0x450A69, 2) != bytes.fromhex('75 05'):
        raise ValueError('retail masked-reader branches changed')
    if gf(0x450A46, 2) != bytes.fromhex('75 00') or gf(0x450A69, 2) != bytes.fromhex('75 00'):
        raise ValueError('GOG direct-reader branches changed')

    sites = []
    for va, (kind, flag, _) in CALL_SITES.items():
        values = (flag,) if kind == 'constant' else (1, 2)
        sites.append({
            'call_va': f'0x{va:08X}',
            'flag_provenance': kind,
            'possible_low_flag_values': list(values),
            'retail_readers': [
                READER_NAMES[reader_for_flags(x, False)] for x in values
            ],
            'gog_readers': [
                READER_NAMES[reader_for_flags(x, True)] for x in values
            ],
        })

    return {
        'static_only': True,
        'original_sha256': RETAIL_SHA,
        'gog_sha256': GOG_SHA,
        'direct_calls_to_open_wrapper': len(sites),
        'constant_xor_direct_calls': 3,
        'constant_raw_calls': 3,
        'conditional_mode_calls': 3,
        'conditional_rule': (
            'caller-supplied pointer first byte == ASCII w => 1 (raw); '
            'otherwise => 2 (XOR)'
        ),
        'conditional_rule_source': (
            '0x44F76B..0x44F77C; flags reused at three call sites'
        ),
        'flags_bit_1_enables_payload_xor': True,
        'flags_bit_2_selects_masked_win32': True,
        'distinct_direct_constructor_call_va': '0x0044EA1E',
        'distinct_constructor_flag_value': 6,
        'retail_flag6_reader': READER_NAMES[reader_for_flags(6, False)],
        'gog_flag6_reader': READER_NAMES[reader_for_flags(6, True)],
        'gog_preserves_payload_xor': True,
        'input_filename_or_file_role_runtime_confirmed': False,
        'safedisc_135_executable_decrypted': False,
        'sites': sites,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail', type=Path, required=True)
    p.add_argument('--gog', type=Path, required=True)
    args = p.parse_args(argv)
    print(json.dumps(
        analyze(args.retail.read_bytes(), args.gog.read_bytes()), indent=2
    ))


if __name__ == '__main__':
    main()
