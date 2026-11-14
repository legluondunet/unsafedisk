#!/usr/bin/env python3
"""Rayman 2 original/GOG CD volume branch audit, exact SHA-gated, read-only.

Disassembles only user-provided PE32 executables. Verifies actual branch bytes,
masked API descriptor names and import thunk without executing either binary.
A linear static disassembly is not a proof of dynamic reachability.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from rayman2_direct_call_audit import HASHES, read_file, text_section
from rayman2_trampoline_audit import disassemble, imports, pe_regions
from rayman2_indirect_taxonomy import classify_sites

EXPECTED_LABEL = 'RAYMAN2'
LABEL_COMPARISON_VAS = (0x4491EA, 0x4491B4, 0x4491BD,
                        0x4491CF, 0x4491D8, 0x4491C6, 0x4491E1)
API_SITES = {0x448F02: 'GetLogicalDrives',
             0x449037: 'GetDriveTypeA',
             0x449158: 'GetVolumeInformationA'}


def require(insns: dict, va: int, raw: bytes):
    row = insns.get(va)
    if row is None or row[0] != raw:
        raise ValueError(f'opcode mismatch at {va:#x}; refusing unverified pattern')
    return row


def decode_relative_branch(va: int, raw: bytes) -> int:
    """Accept only 2-byte conditional branches, 6-byte Jcc, 2-byte jmp, or E8."""
    if len(raw) == 2 and (raw[0] in (0x74, 0x75, 0xEB)):
        disp = struct.unpack('b', raw[1:2])[0]
    elif len(raw) == 6 and raw[:2] in (b'\x0f\x84', b'\x0f\x85'):
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif len(raw) == 5 and raw[0] in (0xE8, 0xE9):
        disp = struct.unpack_from('<i', raw, 1)[0]
    else:
        raise ValueError('unsupported branch form')
    return va + len(raw) + disp


def check_edge(insns, site, expected_dst, raw):
    require(insns, site, raw)
    if decode_relative_branch(site, raw) != expected_dst:
        raise ValueError(f'branch at {site:#x} does not reach {expected_dst:#x}')


def decode_label_comparisons(insns):
    """Reorder seven independent byte comparisons by their actual EBP offsets."""
    by_offset = {}
    for va in LABEL_COMPARISON_VAS:
        if va not in insns:
            raise ValueError(f'missing label byte comparison at {va:#x}')
        raw, mnemonic, args = insns[va]
        if mnemonic != 'cmp' or len(raw) != 7 or raw[:2] != b'\x80\xbd':
            raise ValueError(f'not a byte comparison at {va:#x}')
        offset = struct.unpack_from('<i', raw, 2)[0]
        byte = raw[-1]
        if offset in by_offset or not 32 <= byte < 127:
            raise ValueError('duplicate label offset or non-ASCII comparison')
        by_offset[offset] = chr(byte)
    if sorted(by_offset) != list(range(-0xEC, -0xE5)):
        raise ValueError('comparison offsets are not contiguous seven-byte label')
    label = ''.join(by_offset[i] for i in sorted(by_offset))
    if label != EXPECTED_LABEL:
        raise ValueError(f'unexpected volume label {label!r}')
    return label


def scan_drive_letter_refs(insns):
    """Match only decoded absolute x86 byte load/store forms at VA 0x4A6AD8.

    Linear-disassembly bounded: this cannot see indexed stores or dynamically
    constructed references; it is a direct-reference inventory only.
    """
    reads, writes = {}, {}
    for va, row in insns.items():
        raw = row[0]
        if '0x4a6ad8' not in row[2].lower():
            continue
        if raw == b'\xa2\xd8\x6a\x4a\x00':
            writes[va] = raw
        elif (raw == b'\xa0\xd8\x6a\x4a\x00'
              or raw.startswith((b'\x8a\x0d\xd8\x6a\x4a\x00',
                                 b'\x0f\xbe\x05\xd8\x6a\x4a\x00',
                                 b'\x0f\xbe\x0d\xd8\x6a\x4a\x00',
                                 b'\x0f\xbe\x15\xd8\x6a\x4a\x00'))):
            reads[va] = raw
        else:
            raise ValueError(f'unknown direct x86 reference to drive letter at {va:#x}')
    return reads, writes


def reconstruct_dialog_strings(insns):
    """Recover two literal stack strings, with BL proven to equal ASCII space.

    Decoding local x86 MOV byte writes is intentionally constrained to this one
    verified source interval, not an unconstrained executable-string scan.
    """
    require(insns, 0x448F73, b'\xbb\x20\x00\x00\x00')
    values = {}
    for va, (raw, _, _) in insns.items():
        if not 0x449240 <= va < 0x449339:
            continue
        if len(raw) == 4 and raw[:2] == b'\xc6\x45':
            offset = struct.unpack('b', raw[2:3])[0]
            value = raw[3]
        elif len(raw) == 3 and raw[:2] == b'\x88\x5d':
            offset = struct.unpack('b', raw[2:3])[0]
            value = ord(' ')
        else:
            continue
        if offset in values:
            raise ValueError('duplicate stack string byte write')
        values[offset] = value
    def string_from(start, text):
        stop = start + len(text)
        expected = text.encode('ascii') + b'\0'
        try:
            actual = bytes(values[i] for i in range(start, stop+1))
        except KeyError as exc:
            raise ValueError('truncated stack string') from exc
        if actual != expected:
            raise ValueError('stack-constructed dialog string differs from expected')
        return actual[:-1].decode('ascii')
    return {
        'prompt': string_from(-0x5C, 'Please, insert Rayman II CD in CDROM Drive'),
        'title': string_from(-0x28, 'Rayman 2 CD not found'),
    }


def audit(retail_insns, gog_insns, exports, classified_sites):
    # Calls into the routine are retained, not proof that both bodies execute.
    check_edge(retail_insns, 0x44949F, 0x448E30, b'\xe8\x8c\xf9\xff\xff')
    check_edge(gog_insns, 0x44949F, 0x448E30, b'\xe8\x8c\xf9\xff\xff')
    for insns in (retail_insns, gog_insns):
        require(insns, 0x448E39, b'\xa1\xec\x13\x51\x00')
        check_edge(insns, 0x448E40, 0x448E5A, b'\x74\x18')

    sites = {int(row['site'], 16):row for row in classified_sites}
    for va, name in API_SITES.items():
        row = sites.get(va)
        if row is None or row.get('name') != name or row.get('retail_call_reg') != 'esi':
            raise ValueError(f'could not verify generated {name} API call at {va:#x}')
        require(retail_insns, va, b'\xff\xd6')

    require(retail_insns, 0x449096, b'\x83\x7d\x9c\x05')
    check_edge(retail_insns, 0x44909A, 0x449208, b'\x0f\x85\x68\x01\x00\x00')
    label = decode_label_comparisons(retail_insns)
    require(retail_insns, 0x449203, b'\x83\xf9\x07')
    check_edge(retail_insns, 0x449206, 0x449219, b'\x74\x11')
    require(retail_insns, 0x44921C, b'\xc7\x45\xa0\x01\x00\x00\x00')
    require(retail_insns, 0x449225, b'\xa2\xd8\x6a\x4a\x00')
    check_edge(retail_insns, 0x44922F, 0x449351, b'\x0f\x85\x1c\x01\x00\x00')
    require(retail_insns, 0x449238, b'\x6a\x05')
    require(retail_insns, 0x449339, b'\xff\x15\x70\xc2\x49\x00')
    if exports.get(0x49C270) != 'MessageBoxA':
        raise ValueError('message/error import not verified')
    require(retail_insns, 0x44933F, b'\x83\xf8\x02')
    check_edge(retail_insns, 0x449342, 0x449349, b'\x75\x05')
    check_edge(retail_insns, 0x449344, 0x4011C0, b'\xe8\x77\x7e\xfb\xff')

    # GOG replaces original CD probing by direct '.' write. Both preserved
    # entry guard and different successful body are explicitly checked.
    check_edge(retail_insns, 0x44934B, 0x448F78, b'\x0f\x84\x27\xfc\xff\xff')
    require(gog_insns, 0x448E5A, b'\xb0\x2e')
    require(gog_insns, 0x448E5C, b'\xa2\xd8\x6a\x4a\x00')
    require(gog_insns, 0x448E61, b'\x8b\xe5')
    require(gog_insns, 0x448E64, b'\xc3')
    require(gog_insns, 0x449096, b'\xcc')
    require(gog_insns, 0x449219, b'\xcc')
    require(gog_insns, 0x449339, b'\xcc')
    reads_r, writes_r = scan_drive_letter_refs(retail_insns)
    reads_g, writes_g = scan_drive_letter_refs(gog_insns)
    if (len(reads_r),len(writes_r),len(reads_g),len(writes_g)) != (17,1,17,1):
        raise ValueError('unexpected direct drive-letter xref count')
    if reads_r != reads_g or set(writes_r) != {0x449225} or set(writes_g) != {0x448E5C}:
        raise ValueError('drive-letter read references changed or write sites unknown')
    return {
        'entry_call_identical_cd_gog': '0x44949F -> 0x448E30',
        'zero_guard': 'DWORD [0x5113EC] == 0 enters body at 0x448E5A',
        'original_cd_api_sequence': [API_SITES[k] for k in sorted(API_SITES)],
        'original_drive_type_required': {'value':5,'api':'GetDriveTypeA', 'comparison_va':'0x449096'},
        'volume_label_7_bytes':label,
        'label_success_branch': '0x449206 -> 0x449219',
        'drive_letter_written_at': '0x004A6AD8',
        'drive_letter_direct_read_count':len(reads_r),
        'drive_letter_same_instruction_reads_gog':len(reads_g),
        'drive_letter_direct_retail_write':'0x449225',
        'drive_letter_direct_gog_write':'0x448E5C',
        'drive_letter_read_site_vas':[f'0x{va:08X}' for va in sorted(reads_r)],
        'error_dialog_import': {'name':'MessageBoxA','iat_slot':'0x0049C270', 'call_va':'0x449339'},
        'error_dialog_strings':reconstruct_dialog_strings(retail_insns),
        'messagebox_style':{'value':5,'win32_constant':'MB_RETRYCANCEL'},
        'retry_branch':'0x44934B -> 0x448F78',
        'dialog_return_2_calls': '0x004011C0',
        'gog_body': "writes '.' directly to 0x004A6AD8; original volume-scan block neutralised",
        'runtime_execution_observed': False,
        'physical_safedisc_authentication_proven': False,
        'decryption_performed': False,
    }


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('retail', type=Path)
    p.add_argument('gog', type=Path)
    args=p.parse_args(argv)
    r=read_file(args.retail,HASHES[0]); g=read_file(args.gog,HASHES[1])
    start_r,text_r=text_section(r);start_g,text_g=text_section(g)
    if start_r != start_g or len(text_r) < 0x9A200 or len(text_g) < 0x9A200:
        p.error('unexpected PE .text mapping')
    ins_r=disassemble(args.retail);ins_g=disassemble(args.gog)
    rows=classify_sites(ins_r,ins_g,pe_regions(r))
    try:
        result=audit(ins_r,ins_g,imports(args.retail),rows)
    except ValueError as exc:
        p.error(str(exc))
    result.update({'read_only':True,'retail_sha256':HASHES[0],'gog_sha256':HASHES[1],
                   'disassembler':'GNU objdump, linear x86 decode',
                   'gog_not_pristine_retail':True})
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
