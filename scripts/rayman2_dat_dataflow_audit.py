#!/usr/bin/env python3
"""Static, SHA-locked Rayman 2 DAT-buffer/selection flow audit.

Never executes, decrypts, modifies or republishes executable content.
GOG is a differently modified comparison build, NOT pristine retail.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess

EXACT = {
    'cd': ('7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3', 676352),
    'gog': ('9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713', 1468928),
}
IMAGE_BASE = 0x400000
LINE = re.compile(r'^\s*([0-9a-f]{6,8}):\s+((?:[0-9a-f]{2} )+)\s+(\S+)(?:\s+(.*))?$')
TABLE = (0x44ED8E, 0x44ED80, 0x44ED83, 0x44ED88)


def read_exact(path: Path, kind: str) -> bytes:
    sha, size = EXACT[kind]
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != size:
            raise ValueError('expected a bounded regular input file of exact known size')
        b = os.read(fd, size+1)
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError('input changed during read')
    finally:
        os.close(fd)
    if len(b) != size or hashlib.sha256(b).hexdigest() != sha:
        raise ValueError('exact input SHA-256 mismatch')
    return b


def pe_slice(data: bytes, va: int, count: int) -> bytes:
    if count < 1 or count > 0x10000 or len(data) < 0x100 or data[:2] != b'MZ':
        raise ValueError('invalid input request or DOS header')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if nt < 0x40 or nt+24 > len(data) or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE header')
    nsections = struct.unpack_from('<H', data, nt+6)[0]
    o = nt+24
    optional_size = struct.unpack_from('<H', data, nt+20)[0]
    if not 1 <= nsections <= 96 or o+optional_size+nsections*40 > len(data):
        raise ValueError('invalid PE section table')
    if struct.unpack_from('<H', data, o)[0] != 0x10b or struct.unpack_from('<I', data, o+28)[0] != IMAGE_BASE:
        raise ValueError('unexpected PE32 image')
    for i in range(nsections):
        p = o+optional_size+40*i
        name = data[p:p+8].rstrip(b'\x00')
        vs, rva, rawlen, rawoff = struct.unpack_from('<IIII',data,p+8)
        start = IMAGE_BASE+rva
        if name == b'.text' and start <= va and va+count <= start+min(vs,rawlen) and rawoff+rawlen <= len(data):
            return data[rawoff+va-start:rawoff+va-start+count]
    raise ValueError('requested VA is not backed by active .text')


def x86_lines(path: Path, start: int, end: int) -> dict[int, tuple[bytes,str,str]]:
    proc = subprocess.run(['objdump','-d','-M','intel','--start-address',hex(start),'--stop-address',hex(end),str(path)],
                          check=True, capture_output=True, text=True)
    result = {}
    for line in proc.stdout.splitlines():
        m=LINE.match(line)
        if not m:
            continue
        at=int(m.group(1),16)
        if start <= at < end:
            result[at] = (bytes.fromhex(m.group(2)),m.group(3),m.group(4) or '')
    return result


def anchor(code: dict, at: int, opcode: bytes, mnemonic: str):
    row=code.get(at)
    if row is None or row[0] != opcode or row[1] != mnemonic:
        raise ValueError(f'x86 instruction anchor mismatch at 0x{at:08X}')


def derived_probe_word(header: tuple[int,int,int,int], index: int, sample: int) -> int:
    """Math of 0x44ef82..0x44efa0 and 0x44f0c8..0x44f0d8.

    Does not model the unknown on-disc samples / random modulus.
    """
    if len(header) != 4 or not 0 <= index <= 1023:
        raise ValueError('header must be four DWORDs and initial index 0..1023')
    if any(not 0 <= v <= 0xffffffff for v in (*header, sample)):
        raise ValueError('DWORD out of range')
    w0,w1,w2,w3 = header
    modified_w0 = (w0 + w2*index) & 0xffffffff
    modified_w1 = (w1 + w3*max(index-1, 0)) & 0xffffffff
    return (((sample - modified_w0) & 0xffffffff) ^ modified_w1) & 0xffffffff


def initial_index(low_5116f0: int, byte_5116f1: int) -> int:
    """4*(global low byte)+switch(0..3), NOT the final 24-name table index."""
    if not (0 <= low_5116f0 <= 255 and 0 <= byte_5116f1 <= 255):
        raise ValueError('require two byte values')
    return 4*low_5116f0 + (byte_5116f1 & 3)


def check(data_cd: bytes, data_gog: bytes, cd: dict, gog: dict) -> dict:
    # These are *real, disassembled instruction starts*, checked with the
    # underlying active .text bytes as a second independent source.
    req = [
        # Denominator globals are *computed from file-derived local state*
        # during the earlier LEVELS0.DAT initialisation, not constants.
        *[(code, 0x44e469, bytes.fromhex('2b d0'), 'sub') for code in (cd,gog)],
        *[(code, 0x44e46b, bytes.fromhex('33 d1'), 'xor') for code in (cd,gog)],
        *[(code, 0x44e471, bytes.fromhex('89 15 b0 17 51 00'), 'mov') for code in (cd,gog)],
        *[(code, 0x44e6c1, bytes.fromhex('2b d0'), 'sub') for code in (cd,gog)],
        *[(code, 0x44e6c5, bytes.fromhex('33 d1'), 'xor') for code in (cd,gog)],
        *[(code, 0x44e6ca, bytes.fromhex('89 15 c0 17 51 00'), 'mov') for code in (cd,gog)],
        (cd, 0x44ed79, bytes.fromhex('ff 24 85 04 f2 44 00'), 'jmp'),
        (cd, 0x44ed8b, bytes.fromhex('89 4d fc'), 'mov'),
        (cd, 0x44ef59, bytes.fromhex('6a 10'), 'push'),
        (cd, 0x44ef5d, bytes.fromhex('ff d6'), 'call'),
        (cd, 0x44f00b, bytes.fromhex('8d 14 9d 00 00 00 00'), 'lea'),
        (cd, 0x44f016, bytes.fromhex('ff d6'), 'call'),
        (cd, 0x44f0a6, bytes.fromhex('6a 04'), 'push'),
        (cd, 0x44f0aa, bytes.fromhex('ff d6'), 'call'),
        (cd, 0x44f0c8, bytes.fromhex('8b 4d f8'), 'mov'),
        (cd, 0x44f0cb, bytes.fromhex('8b 5d e0'), 'mov'),
        (cd, 0x44f0ce, bytes.fromhex('8b 75 e4'), 'mov'),
        (cd, 0x44f0d4, bytes.fromhex('2b cb'), 'sub'),
        (cd, 0x44f0d6, bytes.fromhex('33 ce'), 'xor'),
        (cd, 0x44f0d8, bytes.fromhex('89 0a'), 'mov'),
        (cd, 0x44f0da, bytes.fromhex('a1 b0 17 51 00'), 'mov'),
        (cd, 0x44f0e1, bytes.fromhex('f7 35 c0 17 51 00'), 'div'),
        (cd, 0x44f0ed, bytes.fromhex('c1 e6 0b'), 'shl'),
        (cd, 0x44f0f0, bytes.fromhex('f7 f6'), 'div'),
        (cd, 0x44f102, bytes.fromhex('8b 45 08'), 'mov'),
        (cd, 0x44f109, bytes.fromhex('8b 08'), 'mov'),
        (cd, 0x44f10d, bytes.fromhex('e8 6e 02 00 00'), 'call'),
        (cd, 0x44f118, bytes.fromhex('8d 85 cc fc ff ff'), 'lea'),
        (cd, 0x44f11e, bytes.fromhex('68 00 02 00 00'), 'push'),
        (cd, 0x44f125, bytes.fromhex('e8 26 f6 ff ff'), 'call'),
        (cd, 0x44f133, bytes.fromhex('29 0e'), 'sub'),
        (cd, 0x44f13a, bytes.fromhex('8b 14 9d 90 20 4a 00'), 'mov'),
        (cd, 0x44f1cc, bytes.fromhex('8b 0e'), 'mov'),
        (cd, 0x44f1df, bytes.fromhex('8d 85 cc fa ff ff'), 'lea'),
        (cd, 0x44f1e5, bytes.fromhex('68 00 02 00 00'), 'push'),
        (cd, 0x44f1ec, bytes.fromhex('e8 5f f5 ff ff'), 'call'),
        (gog, 0x44ef59, bytes.fromhex('6a 10'), 'push'),
        (gog, 0x44f0a6, bytes.fromhex('6a 04'), 'push'),
        (gog, 0x44f0d4, bytes.fromhex('2b cb'), 'sub'),
        (gog, 0x44f0d6, bytes.fromhex('33 ce'), 'xor'),
        (gog, 0x44f0e1, bytes.fromhex('f7 35 c0 17 51 00'), 'div'),
        (gog, 0x44f102, bytes.fromhex('90'), 'nop'),
        (gog, 0x44f125, bytes.fromhex('90'), 'nop'),
        (gog, 0x44f133, bytes.fromhex('90'), 'nop'),
        (gog, 0x44f13a, bytes.fromhex('8b 15 90 20 4a 00'), 'mov'),
        (gog, 0x44f1cc, bytes.fromhex('eb 23'), 'jmp'),
        (gog, 0x44f1ec, bytes.fromhex('cc'), 'int3'),
    ]
    for code, va, raw, op in req:
        anchor(code, va, raw, op)
    for code, pe in ((cd, data_cd),(gog, data_gog)):
        for va,(raw,_,_) in code.items():
            if 0x44f100 <= va < 0x44f1fa:
                if pe_slice(pe, va, len(raw)) != raw:
                    raise ValueError('disassembly and PE bytes do not agree')
    # Four dispatch labels at actual stored, active code location.
    jump=pe_slice(data_cd,0x44f204,16)
    if jump != pe_slice(data_gog,0x44f204,16) or struct.unpack('<4I',jump)!=TABLE:
        raise ValueError('expected 4-way switch table does not match exact PE bytes')
    # Both read destinations are in disjoint 512-byte ranges. Their only
    # direct stack-offset references between first and second read/return
    # must be the LEAs used as ReadFile lpBuffer. No content-check inferred.
    # Disassembly does not prove absence of aliasing/indirect reads.
    buffer_direct_sites={
        '-0x334':[a for a,(_,_,ops) in cd.items() if 0x44f102 <= a < 0x44f1fa and 'ebp-0x334' in ops],
        '-0x534':[a for a,(_,_,ops) in cd.items() if 0x44f102 <= a < 0x44f1fa and 'ebp-0x534' in ops],
    }
    if buffer_direct_sites != {'-0x334':[0x44f118],'-0x534':[0x44f1df]}:
        raise ValueError('unexpected direct buffer references in original .text')
    return {
        'read_only':True,
        'sha256_locked_inputs':True,
        'original_table_switch_targets':[f'0x{v:08X}' for v in TABLE],
        'initial_internal_index_formula':'4 * (global[0x5116f0] & 0xFF) + (global[0x5116f1] & 3)',
        'initial_internal_index_possible_range':[0,1023],
        'not_a_24_file_table_index':True,
        'sampled_header_dword_count':4,
        'header_word_reads_from_stack':['[EBP-0x20]','[EBP-0x1C]','[EBP-0x18]','[EBP-0x14]'],
        'four_byte_sample_stack':'[EBP-0x8]',
        'derived_word_formula':'(((sample - (w0 + w2*n)) mod 2^32) XOR ((w1 + w3*max(n-1,0)) mod 2^32))',
        'derived_word_written_to_output_arg':'0x44F0D8',
        'shared_derivation_on_gog': pe_slice(data_cd,0x44f0c8,0x3a)==pe_slice(data_gog,0x44f0c8,0x3a),
        'remaining_final_index_formula':'(PRNG % (derived_word // ((global_5117b0 // global_5117c0) << 11)))',
        'final_index_bounds_unproven':True,
        'index_denominator_globals_written_during_level0_initialization':[{'global_va':'0x5117B0','instruction_va':'0x44E471'}, {'global_va':'0x5117C0','instruction_va':'0x44E6CA'}],
        'known_integer_division_zero_hazard_without_runtime_values':True,
        'original_extra_512_byte_buffers':[
            {'stack_base':'[EBP-0x334]','bytes':512,'address_instruction':'0x44F118','read_call':'0x44F125','direct_references':[f'0x{x:08X}' for x in buffer_direct_sites['-0x334']]},
            {'stack_base':'[EBP-0x534]','bytes':512,'address_instruction':'0x44F1DF','read_call':'0x44F1EC','direct_references':[f'0x{x:08X}' for x in buffer_direct_sites['-0x534']]},
        ],
        '512_byte_buffer_contents_read_directly_in_audited_function':False,
        'readfile_returns_tested_after_512byte_reads':False,
        'gog_first_seek_and_read_nopped':True,
        'gog_second_seek_and_read_jumped_over':True,
        'gog_final_filename_selector_constant':'LEVELS0.DAT',
        'dynamic_aliasing_or_runtime_modification_excluded':False,
        'retail_runtime_branch_reachability_proven':False,
        'integrity_verdict_proven':False,
        'runnable_retail_unwrapping_produced':False,
    }


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('cd',type=Path)
    ap.add_argument('gog',type=Path)
    args=ap.parse_args()
    a=read_exact(args.cd,'cd');b=read_exact(args.gog,'gog')
    c=x86_lines(args.cd,0x44e45a,0x44f21a)
    d=x86_lines(args.gog,0x44e45a,0x44f21a)
    print(json.dumps(check(a,b,c,d),indent=2,sort_keys=True))


if __name__=='__main__':
    main()
