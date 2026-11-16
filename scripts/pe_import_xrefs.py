#!/usr/bin/env python3
"""Bounded read-only x86 PE32 import/IAT callsite research (not disassembly).

Does not execute game code, interpret crypto, or assert SafeDisc.
Xrefs are byte-pattern candidates; they may include non-instructions.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct
import sys

MAX_INPUT = 16 * 1024 * 1024


def u16(data: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        raise ValueError('truncated u16')
    return struct.unpack_from('<H', data, off)[0]


def u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise ValueError('truncated u32')
    return struct.unpack_from('<I', data, off)[0]


def parse_headers(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b'MZ':
        raise ValueError('not an MZ executable')
    nt = u32(data, 0x3c)
    if nt < 0x40 or nt + 24 > len(data) or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    n = u16(data, nt + 6)
    optlen = u16(data, nt + 20)
    opt = nt + 24
    if u16(data, nt + 4) != 0x14c or not (1 <= n <= 96):
        raise ValueError('expected bounded x86 PE')
    if optlen < 0x70 or opt + optlen > len(data) or u16(data, opt) != 0x10b:
        raise ValueError('expected PE32 data directories')
    directories = u32(data, opt + 92)
    rva_import = u32(data, opt + 104) if directories > 1 else 0
    sections=[]
    table = opt + optlen
    if table + 40*n > len(data):
        raise ValueError('truncated section table')
    for i in range(n):
        pos = table + i*40
        raw_size, raw_off = u32(data, pos+16), u32(data, pos+20)
        if raw_off + raw_size > len(data):
            raise ValueError('section outside file')
        sections.append({
            'name': data[pos:pos+8].split(b'\0')[0].decode('ascii','backslashreplace'),
            'rva': u32(data,pos+12),
            'virtual_size': u32(data,pos+8),
            'raw_size': raw_size,
            'raw_off': raw_off,
            'flags': u32(data,pos+36)
        })
    return {'image_base': u32(data,opt+28), 'import_rva':rva_import,'sections':sections}


def rva_file_offset(headers:dict, rva:int, length:int, data_len:int) -> int:
    for section in headers['sections']:
        delta = rva-section['rva']
        if 0 <= delta and delta + length <= section['raw_size']:
            off = section['raw_off'] + delta
            if off + length <= data_len:
                return off
    raise ValueError(f'RVA 0x{rva:X} not backed by file')


def cstr(data:bytes, headers:dict, rva:int, limit:int=256) -> str:
    b=bytearray()
    for i in range(limit):
        # Adjacent RVAs may map to disjoint raw file ranges when the
        # string crosses a section boundary.
        off = rva_file_offset(headers, rva+i, 1, len(data))
        ch = data[off]
        if ch == 0:
            return b.decode('ascii','backslashreplace')
        b.append(ch)
    raise ValueError('unterminated/oversized imported name')


def import_entries(data:bytes, headers:dict) -> list[dict]:
    if not headers['import_rva']:
        return []
    imports=[]
    terminated=False
    for desc_index in range(64):
        at = rva_file_offset(headers, headers['import_rva']+desc_index*20,20,len(data))
        original,timestamp,forward,name,iat=struct.unpack_from('<5I',data,at)
        if not any((original,timestamp,forward,name,iat)):
            terminated=True
            break
        if not name or not iat:
            raise ValueError('invalid import descriptor')
        dll=cstr(data,headers,name)
        ilt=original or iat
        thunk_terminated=False
        for idx in range(4096):
            src=rva_file_offset(headers,ilt+4*idx,4,len(data))
            value=u32(data,src)
            if value == 0:
                thunk_terminated=True
                break
            name_str=(f'ordinal:{value & 0xFFFF}' if value & 0x80000000
                      else cstr(data,headers,value+2))
            imports.append({'dll':dll,'name':name_str,'iat_va':headers['image_base']+iat+4*idx})
        if not thunk_terminated:
            raise ValueError('unterminated import thunk table')
    if not terminated:
        raise ValueError('unterminated import directory')
    return imports


def direct_iat_sites(data:bytes, headers:dict, address:int) -> list[dict]:
    results=[]
    ptr=struct.pack('<I',address)
    for s in headers['sections']:
        if not (s['flags'] & 0x20000000):
            continue
        chunk=data[s['raw_off']:s['raw_off']+s['raw_size']]
        for opcode,kind in ((b'\xff\x15','call'),(b'\xff\x25','jmp')):
            pattern=opcode+ptr
            start=0
            while (off:=chunk.find(pattern,start))!=-1:
                va=headers['image_base']+s['rva']+off
                results.append({'va':f'0x{va:08X}','kind':kind})
                start=off+1
    return sorted(results,key=lambda r:int(r['va'],16))


def profile(data:bytes, top:int=100) -> dict:
    if len(data)>MAX_INPUT:
        raise ValueError('oversized file')
    headers=parse_headers(data)
    imports=import_entries(data,headers)
    summary=[]
    for entry in imports:
        sites=direct_iat_sites(data,headers,entry['iat_va'])
        if sites:
            summary.append({'dll':entry['dll'],'api':entry['name'],
                            'iat_va':f"0x{entry['iat_va']:08X}",
                            'candidate_sites':sites[:top], 'site_count':len(sites)})
    return {'read_only':True,'signature_heuristic_not_disassembly':True,
            'import_count':len(imports), 'import_dlls':sorted(set(x['dll'] for x in imports)),
            'direct_call_targets_with_sites':len(summary),
            'direct_callsite_candidates':sum(x['site_count'] for x in summary),
            'references':summary}


def main(argv=None)->int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file',type=Path)
    args=parser.parse_args(argv)
    try:
        path=args.file
        if not path.is_file() or path.is_symlink() or path.stat().st_size>MAX_INPUT:
            raise ValueError('refusing non-regular/symlink/oversized file')
        print(json.dumps(profile(path.read_bytes()),indent=2))
    except (OSError,ValueError) as exc:
        parser.exit(1,f'ERROR: {exc}\n')
    return 0


if __name__=='__main__':
    sys.exit(main())
