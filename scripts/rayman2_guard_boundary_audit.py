#!/usr/bin/env python3
"""Read-only, SHA-locked Rayman 2 guard/table boundary audit.

Checks original and GOG active PE sections separately from the archived
retail .text copy. Literal-address absence does not exclude runtime
or calculated pointers; no decryption or executable patch is performed.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from rayman2_guard_provenance_audit import (
    BASE, GUARD, RETAIL_SHA, GOG_SHA, one, bytes_at)
from rayman2_guarded_ranges_audit import inspect as inspect_ranges

HISTORICAL_SITES = (0x405856, 0x448E39)


def pe_loader_fields(data: bytes) -> dict:
    if len(data) < 0x100 or data[:2] != b'MZ':
        raise ValueError('not an MZ input')
    nt = struct.unpack_from('<I', data, 0x3C)[0]
    if nt + 24 > len(data) or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    optional = nt + 24
    length = struct.unpack_from('<H', data, nt + 20)[0]
    if length < 224 or optional + length > len(data):
        raise ValueError('truncated PE32 optional header')
    if struct.unpack_from('<H', data, optional)[0] != 0x10B:
        raise ValueError('not PE32')
    n = struct.unpack_from('<I', data, optional + 92)[0]
    if n < 16:
        raise ValueError('missing PE directories')
    def directory(i):
        return struct.unpack_from('<II', data, optional + 96 + i*8)
    flags = struct.unpack_from('<H', data, nt + 22)[0]
    return {
        'entrypoint_rva':struct.unpack_from('<I', data, optional + 16)[0],
        'image_base':struct.unpack_from('<I', data, optional + 28)[0],
        'relocations_stripped':bool(flags & 1),
        'relocation_directory':directory(5),
        'tls_directory':directory(9),
    }


def pointer_occurrences(data:bytes, sections:dict, pointers:set[int]) -> dict:
    """List byte-offset literal occurrences by PE section, not by reachability."""
    result={}
    for name,s in sections.items():
        raw=data[s['file_offset']:s['file_offset']+s['raw_size']]
        hits=[]
        for pointer in sorted(pointers):
            needle=struct.pack('<I', pointer)
            start=0
            while True:
                idx=raw.find(needle,start)
                if idx<0: break
                hits.append((BASE+s['rva']+idx,pointer))
                start=idx+1
        result[name]=sorted(hits)
    return result


def verify_registration_writes(data:bytes, sections:dict,
                               rows:list, guards:set[int]) -> int:
    count=0
    for row in rows:
        if row['guard_va'] not in guards:
            continue
        raw=bytes_at(data, sections, row['guard_va'], 72)
        for pointer,value in (
            (row['begin_slot_va'],row['begin']),
            (row['end_slot_va'],row['end']),
        ):
            needle=b'\xC7\x05'+struct.pack('<II',pointer,value)
            if raw.count(needle)!=1:
                raise ValueError('unexpected protected-region registration')
            count+=1
    return count


def inspect(retail:bytes,gog:bytes) -> dict:
    rs,old=one(retail,RETAIL_SHA)
    gs,new=one(gog,GOG_SHA)
    span_report=inspect_ranges(retail,gog)
    spans=span_report.get('ranges',span_report.get('guarded_code_ranges'))
    if spans is None or len(spans)!=28:
        raise ValueError('expected exactly 28 audited regions')
    slots={x for span in spans for x in (
        span['begin_slot_va'],span['end_slot_va'])}
    if len(slots)!=56:
        raise ValueError('expected 56 distinct table slots')
    pointers=slots|{GUARD}
    a=pointer_occurrences(retail,rs,pointers)
    b=pointer_occurrences(gog,gs,pointers)
    if not all(not a[name] and not b[name] for name in ('.rdata','.data')):
        raise ValueError('unexpected noncode literal')
    if any(b[name] for name in ('.extra2','.rsrc')):
        raise ValueError('unexpected GOG noncode pointer')
    if (len(a['.text']),len(b['.text']),len(b['.extra']))!=(85,49,85):
        raise ValueError('source pointer census changed')
    if {ptr for _,ptr in a['.text']} != pointers:
        raise ValueError('missing original pointer operand')
    original_text=rs['.text']
    data=retail[original_text['file_offset']:
                original_text['file_offset']+original_text['raw_size']]
    extra=gs['.extra']
    archived=gog[extra['file_offset']+0x1000:
                 extra['file_offset']+0x1000+len(data)]
    if archived!=data or extra['flags'] & 0x20000000:
        raise ValueError('unexpected executable/changed GOG archival .text')
    old_guards={int(x['va'],16) for x in old['active_refs']}
    new_guards={int(x['va'],16) for x in new['active_refs']}
    if len(old_guards)!=28 or len(new_guards)!=16:
        raise ValueError('unknown active guarded entry count')
    originals=verify_registration_writes(retail,rs,spans,old_guards)
    gog_writes=verify_registration_writes(gog,gs,spans,new_guards)
    if (originals,gog_writes)!=(56,32):
        raise ValueError('registration writes mismatch')
    for va in HISTORICAL_SITES:
        for data_,sections_ in ((retail,rs),(gog,gs)):
            if bytes_at(data_,sections_,va,5)!=b'\xA1\xEC\x13\x51\x00':
                raise ValueError(f'historical guard site changed: 0x{va:X}')
    for pe in (pe_loader_fields(retail),pe_loader_fields(gog)):
        if not (pe['image_base']==BASE
                and pe['entrypoint_rva']==0x5FCC0
                and pe['relocations_stripped']
                and pe['relocation_directory']==(0,0)
                and pe['tls_directory']==(0,0)):
            raise ValueError('nonmatching PE loader metadata')
    for label,counts in (('retail',a),('GOG',b)):
        for name,hits in counts.items():
            if name not in ('.text','.extra') and hits:
                raise ValueError(f'{label} has unexpected literal in {name}')
    if [sum(ptr==GUARD for _,ptr in arr) for arr in
        (a['.text'],b['.text'],b['.extra'])]!=[28,16,28]:
        raise ValueError('guard address counts differ')
    return {
        'retail_sha256':RETAIL_SHA, 'gog_sha256':GOG_SHA,
        'original_guard_reference_sites':28,
        'gog_active_guard_reference_sites':16,
        'original_registration_writes':originals,
        'gog_registration_writes':gog_writes,
        'unique_table_slot_addresses':56,
        'retail_section_pointer_literals':
            {name:len(hits) for name,hits in a.items()},
        'gog_section_pointer_literals':
            {name:len(hits) for name,hits in b.items()},
        'historical_2006_guard_sites':
            [f'0x{va:08X}' for va in HISTORICAL_SITES],
        'historical_reported_packed_executable_bytes':676397,
        'owner_sample_bytes':len(retail),
        'historical_sample_size_difference_bytes':676397-len(retail),
        'historical_sample_same_binary_proven':False,
        'archival_text_is_nonexecutable':True,
        'guard_bss_initialized_zero':True,
        'loader_has_static_reloc_or_tls_directory':False,
        'indirect_or_runtime_writes_excluded':False,
        'external_guard_or_table_consumer_identified':False,
        'decrypted_retail_executable_created':False,
    }


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    args=p.parse_args()
    for path in (args.retail,args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('refusing symlink, nonregular or oversized input')
    print(json.dumps(inspect(args.retail.read_bytes(),args.gog.read_bytes()),
                     indent=2))


if __name__=='__main__':main()
