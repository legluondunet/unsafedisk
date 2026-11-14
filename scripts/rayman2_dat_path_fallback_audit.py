#!/usr/bin/env python3
"""Read-only audit of Rayman 2 DAT fallback paths and binary path-record parser.

Two exact SHA-256 owner-owned PE32 executables only; no game execution or patching.
The GOG file is a separately modified reference, not a pristine retail-unwrapped copy.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from rayman2_dat_dataflow_audit import read_exact, pe_slice, x86_lines, anchor

# The 0x1e dispatcher tag invokes the path list loader; 0x1f is a
# record tag consumed *inside* that loader. Both are data-stream tags.
DISPATCH_TAG = 0x1e
RECORD_TAG = 0x1f
DISPATCH_TABLE_VA = 0x45097c
DISPATCH_JUMPS_VA = 0x45094c
PATH_BASE = 0x500642
PATH_COUNTER = 0x500fa2
PATH_STRIDE = 30
PATH_EXTENSION_TABLE = 0x44dbcc
PATH_EXTENSIONS = ('.rtb', '.rtp', '.rts', '.rtt', '.rtl')
PATH_EXTENSION_VA = (0x4a2248, 0x4a2240, 0x4a2230, 0x4a2238, 0x4a2228)
FALLBACK_SPAN = (0x44d990, 0x44dc40)
LOADER_SPAN = (0x44f9a0, 0x44fa7c)
LOADERS = ((0x44f8b0, 0x44f928), (0x4508a0, 0x45093b))

ANCHORS = {
    0x44d9c2: ('a0 f0 16 51 00','mov'),
    0x44d9ca: ('3c ff','cmp'),
    0x44d9f4: ('e8 a7 0e 00 00','call'),
    0x44d9fe: ('74 09','je'),
    0x44da09: ('a1 f0 16 51 00','mov'),
    0x44da1b: ('8d 3c 4d 42 06 50 00','lea'),
    0x44da5e: ('83 f8 04','cmp'),
    0x44da63: ('ff 24 85 cc db 44 00','jmp'),
    0x44dace: ('53','push'),
    0x44dad9: ('50','push'),
    0x44dada: ('e8 a1 2f 00 00','call'),
    0x44dbf1: ('8a 1d a2 0f 50 00','mov'),
    0x44dc0b: ('8d 34 4d 42 06 50 00','lea'),
    0x44f8b0: ('8b 44 24 04','mov'),
    0x44f8bb: ('6a 04','push'),
    0x44f8be: ('e8 cd 14 00 00','call'),
    0x44f8f0: ('51','push'),
    0x44f8fc: ('6a 02','push'),
    0x44f91e: ('e8 6d 14 00 00','call'),
    0x44f9a0: ('83 ec 3c','sub'),
    0x44f9b8: ('c6 05 a2 0f 50 00 00','mov'),
    0x44f9d2: ('3d ff ff 00 00','cmp'),
    0x44f9df: ('83 f8 1f','cmp'),
    0x44f9e9: ('e8 02 ff ff ff','call'),
    0x44fa1a: ('8a 0d a2 0f 50 00','mov'),
    0x44fa24: ('fe c1','inc'),
    0x44fa26: ('88 0d a2 0f 50 00','mov'),
    0x44fa41: ('8d 14 55 42 06 50 00','lea'),
    0x44fa51: ('f3 a5','rep'),
    0x44fa58: ('f3 a4','rep'),
    0x4508b7: ('e8 94 f0 ff ff','call'),
    0x4508bc: ('83 f8 78','cmp'),
    0x4508c7: ('8a 88 7c 09 45 00','mov'),
    0x4508cd: ('ff 24 8d 4c 09 45 00','jmp'),
    0x4508db: ('e8 c0 f0 ff ff','call'),
}


def file_backed_va(data: bytes, va: int, length: int) -> bytes:
    """Safe PE32 mapping for the original .data strings, not just active .text."""
    if length < 1 or length > 128 or len(data) < 0x100 or data[:2] != b'MZ':
        raise ValueError('invalid section request')
    nt = struct.unpack_from('<I', data, 0x3c)[0]
    if nt < 0x40 or nt+24 > len(data) or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE header')
    sizeopt, num = struct.unpack_from('<HH',data,nt+20)[0],struct.unpack_from('<H',data,nt+6)[0]
    if not 1 <= num <= 96 or nt+24+sizeopt+40*num > len(data):
        raise ValueError('invalid section table')
    for i in range(num):
        p=nt+24+sizeopt+i*40
        name=data[p:p+8].rstrip(b'\0')
        vsize,rva,rsize,roff=struct.unpack_from('<IIII',data,p+8)
        s=0x400000+rva
        if name == b'.data' and s <= va and va+length <= s+min(vsize,rsize) and roff+rsize<=len(data):
            return data[roff+va-s:roff+va-s+length]
    raise ValueError('not backed by original PE .data section')


def path_slot(index: int) -> int:
    if not isinstance(index,int) or not 0 <= index <= 255:
        raise ValueError('path index must be byte')
    return PATH_BASE + PATH_STRIDE * index


def dispatch_target(table: bytes, jumps: bytes, tag: int) -> int:
    if len(table) != 0x79 or len(jumps) != 12*4 or not 0 <= tag < 0x79:
        raise ValueError('invalid bounded dispatcher table or tag')
    slot=table[tag]
    if not slot < 12:
        raise ValueError('dispatcher slot out of range')
    return struct.unpack_from('<I',jumps,slot*4)[0]


def extension_targets(table: bytes) -> tuple[int,...]:
    if len(table) != 20:
        raise ValueError('invalid extension switch')
    return struct.unpack('<5I',table)


def audit(cdpath: Path, gogpath: Path) -> dict:
    cd=read_exact(cdpath,'cd'); gog=read_exact(gogpath,'gog')
    dis={kind:x86_lines(path,0x44d990,0x4509a0)
         for kind,path in [('cd',cdpath),('gog',gogpath)]}
    for kind,b in [('cd',cd),('gog',gog)]:
        for va,(code,mnemonic) in ANCHORS.items():
            op=bytes.fromhex(code)
            anchor(dis[kind],va,op,mnemonic)
            if pe_slice(b,va,len(op)) != op:
                raise ValueError(f'{kind} PE source bytes drifted at 0x{va:X}')

    span_status = {}
    for name,(begin,end) in {
        'fallback_function_688_bytes':FALLBACK_SPAN,
        'path_list_loader_220_bytes':LOADER_SPAN,
        'path_record_readers_120_bytes':LOADERS[0],
        'binary_dispatch_function_155_bytes':LOADERS[1],
    }.items():
        r=pe_slice(cd,begin,end-begin);g=pe_slice(gog,begin,end-begin)
        if r!=g:
            raise ValueError(f'important {name} code span differs between CD/GOG')
        span_status[name]={'identical':True,'bytes':len(r),'sha256':hashlib.sha256(r).hexdigest()}

    dispatch=pe_slice(cd,DISPATCH_TABLE_VA,121)
    jumps=pe_slice(cd,DISPATCH_JUMPS_VA,48)
    if dispatch != pe_slice(gog,DISPATCH_TABLE_VA,121) or jumps != pe_slice(gog,DISPATCH_JUMPS_VA,48):
        raise ValueError('binary dispatcher differs unexpectedly')
    if dispatch_target(dispatch,jumps,DISPATCH_TAG) != 0x4508db:
        raise ValueError('tag 0x1e does not route to path parser')
    paths=pe_slice(cd,PATH_EXTENSION_TABLE,20)
    if paths != pe_slice(gog,PATH_EXTENSION_TABLE,20):
        raise ValueError('filename extension selection differs')
    expected_targets=(0x44da6a,0x44da77,0x44da91,0x44da84,0x44da9e)
    if extension_targets(paths)!=expected_targets:
        raise ValueError('unrecognized 5-way filename extension switch')
    extensions=[]
    for va,ext in zip(PATH_EXTENSION_VA,PATH_EXTENSIONS):
        a=file_backed_va(cd,va,len(ext)+1)
        b=file_backed_va(gog,va,len(ext)+1)
        if a!=ext.encode()+b'\0' or a!=b:
            raise ValueError(f'original extension string drifted at 0x{va:X}')
        extensions.append({'literal':ext,'string_va':f'0x{va:08X}'})
    # The two source-format strings differ by one byte, a CD-drive
    # colon replaced by a second backslash in the GOG relative path. GOG also seeds the shared drive byte with '.'
    # at the shortened 0x448E5A entry.
    format_strings=[]
    for va,retail_fmt,gog_fmt in (
        (0x4a06d8,b'%c:\\%s',b'%c\\\\%s'),
        (0x4a2264,b'%c:\\%s\\%s',b'%c\\\\%s\\%s'),
    ):
        rs=file_backed_va(cd,va,len(retail_fmt)+1)
        gs=file_backed_va(gog,va,len(gog_fmt)+1)
        if rs!=retail_fmt+b'\0' or gs!=gog_fmt+b'\0':
            raise ValueError(f'unexpected CD/GOG format string at VA 0x{va:x}')
        format_strings.append({'va':f'0x{va:08X}',
                               'original_ascii':retail_fmt.decode('ascii'),
                               'gog_ascii':gog_fmt.decode('ascii')})
    if pe_slice(gog,0x448e5a,7) != bytes.fromhex('b0 2e a2 d8 6a 4a 00'):
        raise ValueError('GOG drive-byte initialiser has changed')
    if pe_slice(cd,0x448e5a,6) != bytes.fromhex('8b 0d f0 0b 51 00'):
        raise ValueError('original CD drive search did not match known entry')
    # IMPORTANT: this is a calculated memory interval before the counter,
    # NOT proof of a validated runtime capacity. The parser shows no check.
    space=PATH_COUNTER-PATH_BASE
    if space != 2400 or space%PATH_STRIDE:
        raise ValueError('unexpected distance to adjacent byte counter')
    return {
        'read_only':True,'exact_sha256_gated':True,'gog_pristine_retail':False,
        'matching_code_spans':span_status,
        'binary_resource_tag_0x1E_routes_to_path_parser':'0x004508DB -> 0x0044F9A0',
        'parser_path_record_tag':'0x1F',
        'reader':'0x44F8B0 -> 0x450D90 (4-byte records); 0x44F8F0 (2-byte length and contents)',
        'path_list_source':'binary data stream accessed through file handle 0x5116C0',
        'path_stride_bytes':PATH_STRIDE,
        'path_base_va':f'0x{PATH_BASE:08X}',
        'counter_va':f'0x{PATH_COUNTER:08X}',
        'slots_between_path_base_and_adjacent_counter':space//PATH_STRIDE,
        'runtime_record_count_proven':False,
        'runtime_input_length_validated':False,
        'fallback_extension_strings':extensions,
        'selector_switch_targets':[f'0x{a:08X}' for a in expected_targets],
        'fallback_preserved_in_gog':True,
        'original_cd_vs_gog_path_formats':format_strings,
        'gog_drive_prefix_seed_va':'0x00448E5A',
        'gog_drive_prefix_seed_character':'.',
        'path_change_mechanism':'GOG replaces the colon with an additional backslash and uses dot as the prefix character, converting absolute drive paths to dot-prefixed relative paths',
        'part_of_resource_loading_inferred_from_code':True,
        'physical_cd_authentication_proven':False,
        'program_executed':False,
    }


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(audit(a.retail,a.gog),indent=2,sort_keys=True))

if __name__=='__main__':main()