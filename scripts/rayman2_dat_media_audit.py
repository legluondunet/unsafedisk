#!/usr/bin/env python3
"""Rayman 2 CD/GOG .DAT media-read flow audit (SHA-gated, read-only).

This checks a bounded set of independently disassembled x86 instruction sites,
PE-backed pointer-table contents and Win32 imports. Does not decrypt, patch,
load or execute the game. Linear static disassembly is not runtime reachability.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from rayman2_direct_call_audit import read_file, HASHES
from rayman2_trampoline_audit import disassemble, pe_regions, at_va, imports

FAMILIES = ('LEVELS', 'MAP', 'TEXTURES', 'ANIMS', 'SOUNDS', 'MUSIC', 'GRAPHICS', 'MENU')
TABLE_VA = 0x4A2090


def require(insns, va, raw):
    if va not in insns or insns[va][0] != raw:
        raise ValueError(f'expected opcode does not match at 0x{va:08X}')
    return insns[va]


def rel_target(va: int, raw: bytes) -> int:
    if len(raw) == 5 and raw[0] in (0xE8, 0xE9):
        disp = struct.unpack_from('<i', raw, 1)[0]
    elif len(raw) == 6 and raw[:2] in (b'\x0f\x84', b'\x0f\x85'):
        disp = struct.unpack_from('<i', raw, 2)[0]
    elif len(raw) == 2 and raw[0] in (0x74, 0x75, 0xEB):
        disp = struct.unpack_from('<b', raw, 1)[0]
    else:
        raise ValueError('not a supported static relative branch')
    return va + len(raw) + disp


def edge(insns, va, raw, target):
    require(insns, va, raw)
    if rel_target(va, raw) != target:
        raise ValueError(f'unexpected control-flow target at 0x{va:08X}')


def parse_table(regions):
    """Validate *each* pointer as file-backed PE data, never execute dereferences."""
    contents = at_va(regions, TABLE_VA, 24*4)
    pointers = struct.unpack('<24I', contents)
    names = []
    for i, pointer in enumerate(pointers):
        if not 0x4A20F0 <= pointer <= 0x4A2224:
            raise ValueError(f'out-of-bounds DAT pointer at index {i}')
        raw = at_va(regions, pointer, 17)
        if b'\x00' not in raw:
            raise ValueError(f'unterminated DAT name at index {i}')
        name = raw.split(b'\x00', 1)[0]
        try:
            decoded = name.decode('ascii')
        except UnicodeDecodeError as e:
            raise ValueError('DAT name is not ASCII') from e
        expected = f'{FAMILIES[i % 8]}{i//8}.DAT'
        if decoded != expected:
            raise ValueError(f'DAT name or ordering mismatch at index {i}: {decoded!r}')
        names.append(decoded)
    if len(set(names)) != 24 or len(set(pointers)) != 24:
        raise ValueError('duplicate DAT names or pointers')
    return {'names':names, 'pointers':[f'0x{p:08X}' for p in pointers],
            'table_sha256':hashlib.sha256(contents).hexdigest()}


def c_string(regions, address, limit=96):
    buf=at_va(regions,address,limit)
    if b'\x00' not in buf:raise ValueError(f'unterminated string at {address:#x}')
    return buf.split(b'\x00',1)[0].decode('ascii')


def audit(cd, gog, cd_ins, gog_ins, cd_imports, gog_imports):
    cd_regions=pe_regions(cd); gog_regions=pe_regions(gog)
    old_table=parse_table(cd_regions)
    new_table=parse_table(gog_regions)
    if old_table != new_table:
        raise ValueError('GOG and CD DAT tables differ unexpectedly')
    # 0x418960 returns AL=1 *on disk*, not an assertion about runtime patching.
    for inst in (cd_ins,gog_ins):
        require(inst, 0x418960, b'\xB0\x01')
        require(inst, 0x418962, b'\xC3')
        edge(inst,0x44D9EA,b'\xE8\x71\xAF\xFC\xFF',0x418960)
        require(inst, 0x44D9EF, b'\x84\xC0')
        edge(inst,0x44D9F1,b'\x74\x16',0x44DA09)
        edge(inst,0x44D9F4,b'\xE8\xA7\x0E\x00\x00',0x44E8A0)
        require(inst,0x44D9FC,b'\x84\xC0')
        edge(inst,0x44DE90,b'\xE8\xCB\xAA\xFC\xFF',0x418960)
        edge(inst,0x44DE97,b'\x0F\x84\xAB\x08\x00\x00',0x44E748)
        require(inst,0x44DE9D,b'\xA1\x90\x20\x4A\x00')
        edge(inst,0x44E8D3,b'\xE8\x68\x02\x00\x00',0x44EB40)
        require(inst,0x44EB49,b'\xA1\xEC\x13\x51\x00')
        require(inst,0x44EB6C,b'\xA1\x90\x20\x4A\x00')
        require(inst,0x44EC44,b'\x83\xFF\xFF')
        require(inst,0x44EF59,b'\x6A\x10')
        require(inst,0x44F0A6,b'\x6A\x04')
        edge(inst,0x44F135,b'\xE8\xC6\x93\xFF\xFF',0x448500)
        edge(inst,0x44F17D,b'\xE8\x9E\x00\x00\x00',0x44F220)
        require(inst,0x44F184,b'\x83\xFF\xFF')
        require(inst,0x44F189,b'\x6A\x05')
        edge(inst,0x44F195,b'\xE8\x56\x37\xFB\xFF',0x4028F0)
        require(inst,0x44F19D,b'\x83\xF8\x02')
        edge(inst,0x44F1A0,b'\x75\x05',0x44F1A7)
        edge(inst,0x44F1C0,b'\xE8\x5B\x00\x00\x00',0x44F220)
        require(inst,0x44F1F1,b'\x5B')
    # An earlier second consumer of the same first DAT table element
    # also has a GOG direct-OpenFile substitution. No runtime trace assumed.
    require(cd_ins,0x44DEB0,b'\x51')
    require(gog_ins,0x44DEB0,b'\x90')
    require(cd_ins,0x44DEB7,b'\x68\x64\x22\x4A\x00')
    require(gog_ins,0x44DEB7,b'\x68\x68\x22\x4A\x00')
    require(cd_ins,0x44DEC2,b'\x83\xC4\x14')
    require(gog_ins,0x44DEC2,b'\x83\xC4\x10')
    edge(cd_ins,0x44DEC5,b'\xE8\xB6\xA5\xFF\xFF',0x448480)
    edge(gog_ins,0x44DEC5,b'\xEB\x72',0x44DF39)
    require(cd_ins,0x44DF52,b'\xFF\xD6')
    require(gog_ins,0x44DF52,b'\xFF\x15\x58\xC0\x49\x00')
    require(cd_ins,0x44EC24,b'\xFF\xD6')
    require(gog_ins,0x44EC24,b'\xFF\x15\x58\xC0\x49\x00')
    for site in (0x44EF5D,0x44F0AA):
        require(cd_ins,site,b'\xFF\xD6')
        require(gog_ins,site,b'\xFF\x15\x4C\xC0\x49\x00')
    if cd_imports.get(0x49C04C)!='ReadFile' or gog_imports.get(0x49C04C)!='ReadFile' or gog_imports.get(0x49C058)!='CreateFileA':
        raise ValueError('Win32 PE IAT imports do not match')

    # Phase two: CD performs additional seek/read, changes argument-based
    # offset, and selects a variable DAT pathname. GOG removes both 512-byte
    # reads and fixes the selection. These are instruction facts, not DRM proof.
    edge(cd_ins,0x44F10D,b'\xE8\x6E\x02\x00\x00',0x44F380)
    require(cd_ins,0x44F11E,b'\x68\x00\x02\x00\x00')
    edge(cd_ins,0x44F125,b'\xE8\x26\xF6\xFF\xFF',0x44E750)
    require(cd_ins,0x44F133,b'\x29\x0E')
    require(cd_ins,0x44F13A,b'\x8B\x14\x9D\x90\x20\x4A\x00')
    require(gog_ins,0x44F13A,b'\x8B\x15\x90\x20\x4A\x00')
    require(gog_ins,0x44F140,b'\x90')
    for i in range(0x44F102,0x44F12A):
        require(gog_ins,i,b'\x90')
    require(gog_ins,0x44F133,b'\x90')
    require(gog_ins,0x44F134,b'\x90')
    require(cd_ins,0x44F156,b'\x68\x64\x22\x4A\x00')
    require(gog_ins,0x44F156,b'\x68\x68\x22\x4A\x00')
    require(cd_ins,0x44F161,b'\x83\xC4\x14')
    require(gog_ins,0x44F161,b'\x83\xC4\x10')
    if (c_string(cd_regions,0x4A2264) != '%c:\\%s\\%s'
        or c_string(gog_regions,0x4A2268) != '%s\\%s'):
        raise ValueError('unexpected retail/GOG pathname format')
    require(cd_ins,0x44F1CC,b'\x8B\x0E')
    edge(gog_ins,0x44F1CC,b'\xEB\x23',0x44F1F1)
    edge(cd_ins,0x44F1D4,b'\xE8\xA7\x01\x00\x00',0x44F380)
    require(cd_ins,0x44F1E5,b'\x68\x00\x02\x00\x00')
    edge(cd_ins,0x44F1EC,b'\xE8\x5F\xF5\xFF\xFF',0x44E750)
    for i in range(0x44F1CE,0x44F1F1):
        require(gog_ins,i,b'\xCC')
    # The error/retry dialog remains identical in both, *separate* from the
    # earlier logical 'RAYMAN2' volume-label dialog.
    for r in (cd_regions,gog_regions):
        if c_string(r,0x4A06C0)!='Please insert the CD' or c_string(r,0x4A2270)!='CDROM not found!':
            raise ValueError('expected DAT file-open retry message differs')
    result={
        'hashes_locked':True, 'read_only':True,
        'caller_chain': ['0x44D990','0x44D9F4 -> 0x44E8A0','0x44E8D3 -> 0x44EB40'],
        'caller_true_stub':'0x418960 MOV AL,1; RET in both on-disk binaries',
        'guard':'0x5113EC != 0 early return from file-opening helper; runtime value unknown',
        'table_va':'0x004A2090', 'table_size':24, 'table_sha256':old_table['table_sha256'],
        'table_names':old_table['names'], 'table_bitwise_identical':True,
        'other_level0_path':{'table_ref':'0x44DE9D','original_generator':'0x44DEC5 -> 0x448480','gog_skips_generator':'0x44DEC5 -> 0x44DF39', 'original_dynamic_open':'0x44DF52 CALL ESI', 'gog_direct_createfile':'0x44DF52 CALL [0x49C058]'},
        'common_initial_read_sizes_bytes':[16,4],
        'cd_extra_read_sizes_bytes':[512,512],
        'gog_extra_read_blocks_neutralised':True,
        'retail_indexed_selection_va':'0x0044F13A',
        'gog_fixed_selection_va':'0x0044F13A','gog_fixed_filename':'LEVELS0.DAT',
        'retail_file_path_format':'%c:\\%s\\%s',
        'gog_file_path_format':'%s\\%s',
        'retail_offset_mutation_va':'0x0044F133',
        'gog_offset_mutation_nopped':True,
        'gog_second_followup_read_skipped_by_jump':'0x44F1CC -> 0x44F1F1',
        'file_open_error_strings':['Please insert the CD','CDROM not found!'],
        'file_open_retry_still_in_gog':True,
        'runtime_execution_observed':False,
        'original_media_content_authenticated':False,
        'anti_tamper_predicate_proven':False,
        'safedisc_driver_io_proven':False,
        'decrypted_game_executable':False,
    }
    return result


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('retail',type=Path)
    p.add_argument('gog',type=Path)
    a=p.parse_args(argv)
    retail=read_file(a.retail,HASHES[0]); gog=read_file(a.gog,HASHES[1]);
    result=audit(retail,gog,disassemble(a.retail),disassemble(a.gog),imports(a.retail),imports(a.gog))
    result['retail_sha256'],result['gog_sha256']=HASHES
    print(json.dumps(result,indent=2))

if __name__ == '__main__':
    main()
