#!/usr/bin/env python3
"""Read-only, exact-SHA Rayman 2 startup guard census, not a decoder."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

RETAIL_SHA = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_SHA = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
BASE = 0x400000
GUARD = 0x5113EC
STARTUP_CALLS = {0x44947C: 0x4478A0, 0x449485: 0x448DB0,
                 0x44948E: 0x448D80, 0x44949A: 0x447DE0}


def sections(data: bytes) -> dict:
    if len(data) < 0x100 or data[:2] != b'MZ':
        raise ValueError('not a bounded MZ file')
    nt = struct.unpack_from('<I', data, 0x3C)[0]
    if nt+24 > len(data) or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('missing PE header')
    count = struct.unpack_from('<H', data, nt+6)[0]
    optional_len = struct.unpack_from('<H', data, nt+20)[0]
    optional = nt+24
    if optional+optional_len > len(data) or optional_len < 96:
        raise ValueError('truncated optional PE header')
    if struct.unpack_from('<H', data, optional)[0] != 0x10B:
        raise ValueError('expected x86 PE32')
    if struct.unpack_from('<I', data, optional+28)[0] != BASE:
        raise ValueError('unexpected PE image base')
    sh = optional+optional_len
    if count < 3 or sh+count*40 > len(data):
        raise ValueError('malformed PE section headers')
    out = {}
    for i in range(count):
        o = sh+i*40
        name = data[o:o+8].split(b'\0')[0].decode('ascii')
        vs, rva, rs, pos = struct.unpack_from('<IIII', data, o+8)
        attrs = struct.unpack_from('<I', data, o+36)[0]
        if not name or (rs and pos+rs > len(data)):
            raise ValueError('invalid section extents')
        if name in out:
            raise ValueError('duplicate section')
        out[name] = {'virtual_size':vs, 'rva':rva, 'raw_size':rs,
                     'file_offset':pos, 'flags':attrs}
    return out


def bytes_at(data: bytes, sections_map: dict, va: int, n: int) -> bytes:
    for sec in sections_map.values():
        off = va-BASE-sec['rva']
        if 0 <= off and 0 < n <= sec['raw_size']-off:
            pos = sec['file_offset']+off
            return data[pos:pos+n]
    raise ValueError(f'VA 0x{va:X} is not file-backed')


def direct_references(raw: bytes, text_va: int, target: int) -> list[dict]:
    """Only recognize direct reads and zero-comparisons; fail closed otherwise."""
    needle = struct.pack('<I', target)
    hits = []
    start = 0
    while True:
        i = raw.find(needle, start)
        if i < 0:
            break
        start = i+1
        if i>=2 and raw[i-2:i]==b'\x83\x3d' and i+4 < len(raw) and raw[i+4]==0:
            va = text_va+i-2
            op = 'CMP [guard],0'
        elif i>=2 and raw[i-2:i]==b'\x8b\x0d':
            va = text_va+i-2
            op = 'MOV ECX,[guard]'
        elif i>=1 and raw[i-1]==0xA1:
            va = text_va+i-1
            op = 'MOV EAX,[guard]'
        else:
            raise ValueError(f'unclassified direct guard reference at 0x{text_va+i:X}')
        hits.append({'va':f'0x{va:08X}', 'op':op})
    return hits


def one(data: bytes, expected_sha: str) -> tuple[dict,dict]:
    if hashlib.sha256(data).hexdigest()!=expected_sha:
        raise ValueError('unapproved original/GOG executable SHA256')
    s=sections(data)
    if '.data' not in s or '.text' not in s:
        raise ValueError('missing expected sections')
    bss=s['.data']
    at=GUARD-BASE-bss['rva']
    if not (bss['raw_size']<=at and at+4<=bss['virtual_size']):
        raise ValueError('guard unexpectedly not in zero-filled data region')
    code=s['.text']
    if not (code['flags'] & 0x20000000):
        raise ValueError('text not executable')
    raw=data[code['file_offset']:code['file_offset']+code['raw_size']]
    refs=direct_references(raw,BASE+code['rva'],GUARD)
    return s, {'active_refs':refs, 'direct_writes':0,
               'initial_guard':0,'guard_va':f'0x{GUARD:08X}',
               'guard_section':'.data','guard_is_zero_filled':True}


def inspect(retail: bytes, gog: bytes) -> dict:
    rs,cd=one(retail,RETAIL_SHA)
    gs,gw=one(gog,GOG_SHA)
    old={x['va']:x['op'] for x in cd['active_refs']}
    new={x['va']:x['op'] for x in gw['active_refs']}
    if len(old)!=28 or len(new)!=16:
        raise ValueError('unexpected approved direct-reference census')
    if any(old.get(k)!=v for k,v in new.items()):
        raise ValueError('GOG introduced or modified a direct guard read')
    removed=sorted(set(old)-set(new))
    if len(removed)!=12:
        raise ValueError('unexpected count of removed direct reads')
    for va,dest in STARTUP_CALLS.items():
        a=bytes_at(retail,rs,va,5)
        b=bytes_at(gog,gs,va,5)
        if a!=b or a[0]!=0xE8 or va+5+struct.unpack('<i',a[1:])[0]!=dest:
            raise ValueError('startup direct call altered')
    # Non-executable GOG .extra mirrors original .text at +0x1000.
    text_rs=rs['.text']
    ex=gs.get('.extra')
    if ex is None or ex['flags'] & 0x20000000:
        raise ValueError('missing or executable GOG archival section')
    size=text_rs['raw_size']
    original=retail[text_rs['file_offset']:text_rs['file_offset']+size]
    archive=gog[ex['file_offset']+0x1000:ex['file_offset']+0x1000+size]
    if archive!=original:
        raise ValueError('non-identical original code archive')
    return {'strict_sha256':True,'retail':cd,'gog':gw,
            'unchanged_guard_refs':len(new),'removed_guard_ref_sites':removed,
            'retail_active_read_count':len(old),'gog_active_read_count':len(new),
            'no_direct_guard_write_proven':True,
            'indirect_or_runtime_guard_writes_ruled_out':False,
            'unchanged_startup_calls':{f'0x{k:08X}':f'0x{v:08X}' for k,v in STARTUP_CALLS.items()},
            'archival_text_bytes_equal_original':size,
            'gog_archive_not_executable':True,
            'actual_protection_semantics_proven':False,
            'decrypted_executable_generated':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    a=p.parse_args()
    for path in (a.retail,a.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('refusing nonregular, symlink or oversized input')
    print(json.dumps(inspect(a.retail.read_bytes(),a.gog.read_bytes()),indent=2))


if __name__=='__main__':
    main()
