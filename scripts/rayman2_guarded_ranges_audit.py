#!/usr/bin/env python3
"""Exact-SHA read-only Rayman 2 guarded code-range and GOG delta census.

Emits only metadata. Does not execute, patch, decrypt or distribute game bytes.
GOG is a modified comparison build, not a pristine unwrapped retail EXE.
"""
from __future__ import annotations
import argparse
import json
import re
import struct
from pathlib import Path

from rayman2_guard_provenance_audit import one, bytes_at, RETAIL_SHA, GOG_SHA

PRIMARY_END = range(0x510C00, 0x510C60, 4)
PRIMARY_BEGIN = range(0x510DC0, 0x510E20, 4)
SECOND_END = range(0x511320, 0x511338, 4)
SECOND_BEGIN = range(0x511400, 0x511418, 4)
WRITE = re.compile(b'\xc7\x05(.{4})(.{4})', re.DOTALL)


def extract_entry(retail: bytes, rsections: dict, guard_va: int) -> dict:
    """Read two exact guarded register writes and a validated zero-guard JZ."""
    window = bytes_at(retail, rsections, guard_va, 72)
    matches = []
    for match in WRITE.finditer(window):
        ptr = int.from_bytes(match.group(1), 'little')
        val = int.from_bytes(match.group(2), 'little')
        if (ptr in PRIMARY_BEGIN or ptr in SECOND_BEGIN
                or ptr in PRIMARY_END or ptr in SECOND_END):
            matches.append((match.start(), ptr, val))
    if len(matches) != 2:
        raise ValueError(f'0x{guard_va:X}: expected two range writes')
    (startpos, start_ptr, begin), (endpos, end_ptr, end) = matches
    if endpos <= startpos:
        raise ValueError('range writes in unexpected instruction order')
    if start_ptr in PRIMARY_BEGIN:
        if end_ptr != start_ptr - 0x1C0:
            raise ValueError('wrong primary pointer-table pairing')
        family, slot = 'primary', (end_ptr - 0x510C00)//4
    elif start_ptr in SECOND_BEGIN:
        if end_ptr != start_ptr - 0xE0:
            raise ValueError('wrong secondary pointer-table pairing')
        family, slot = 'secondary', (end_ptr - 0x511320)//4
    else:
        raise ValueError('unknown range family')
    txt = rsections['.text']
    lo = 0x400000 + txt['rva']
    hi = lo + txt['raw_size']
    if not lo <= begin < end <= hi:
        raise ValueError('range outside original active .text')

    # All 28 callers guard their ordinary body with a short JZ.
    # 27 land on the recorded begin; one 0x405856 path begins 8 B
    # earlier, performing additional setup before the range.
    jumps = []
    for i in range(startpos-1):
        if window[i] == 0x74:
            target = guard_va + i + 2 + int.from_bytes(
                window[i+1:i+2], 'little', signed=True)
            if 0 <= begin - target <= 8:
                jumps.append((i, target))
    if len(jumps) != 1:
        raise ValueError('zero-guard JZ not connected to registered begin')
    return {
        'guard_va':guard_va,'begin':begin,'end':end,'length':end-begin,
        'family':family,'slot':slot,
        'begin_slot_va':start_ptr,'end_slot_va':end_ptr,
        'zero_guard_jump_va':guard_va+jumps[0][0],
        'zero_guard_branch_target_va':jumps[0][1],
    }


def disjoint_entries(rows):
    ordered=sorted(rows,key=lambda row:row['begin'])
    for left,right in zip(ordered,ordered[1:]):
        if left['end'] > right['begin']:
            raise ValueError('overlapping guarded ranges')


def section_text(data:bytes, sections:dict)->bytes:
    s=sections['.text']
    return data[s['file_offset']:s['file_offset']+s['raw_size']]


def inspect(retail:bytes,gog:bytes)->dict:
    rs,rg=one(retail,RETAIL_SHA)
    gs,gg=one(gog,GOG_SHA)
    if rs['.text']['rva']!=gs['.text']['rva']:
        raise ValueError('nonaligned original and GOG code RVAs')
    original=section_text(retail,rs)
    modified=section_text(gog,gs)
    if len(modified)<len(original):
        raise ValueError('short GOG active code')
    rows=[extract_entry(retail,rs,int(x['va'],16))
          for x in rg['active_refs']]
    disjoint_entries(rows)
    primary={r['slot'] for r in rows if r['family']=='primary'}
    secondary={r['slot'] for r in rows if r['family']=='secondary'}
    if len(rows)!=28 or primary!=set(range(24)) or secondary!={0,1,2,5}:
        raise ValueError('unexpected 24 primary / four secondary registrations')
    covered=bytearray(len(original))
    for row in rows:
        lo=row['begin']-0x400000-rs['.text']['rva']
        hi=row['end']-0x400000-rs['.text']['rva']
        row['gog_changed_bytes']=sum(a!=b for a,b in zip(
            original[lo:hi], modified[lo:hi]))
        row['gog_changed_fraction']=round(
            row['gog_changed_bytes']/row['length'],6)
        covered[lo:hi]=b'\x01'*(hi-lo)
    changed=inside=0
    for i,(a,b) in enumerate(zip(original,modified)):
        if a!=b:
            changed+=1
            inside+=bool(covered[i])
    total_span=sum(r['length'] for r in rows)
    if (changed,inside,total_span)!=(13269,8669,14757):
        raise ValueError('changed code or range fingerprint not approved')
    if inside!=sum(r['gog_changed_bytes'] for r in rows):
        raise ValueError('overlap / range delta double count')

    # Count literal operands, not calls. One additional apparent pointer
    # at 0x497FE7 resides in an embedded descriptor/data region of .text.
    slot_addresses={p for r in rows for p in
                    (r['begin_slot_va'],r['end_slot_va'])}
    if len(slot_addresses)!=56:
        raise ValueError('expected 56 distinct paired slots')
    extra_literals=[]
    for ptr in sorted(slot_addresses):
        pattern=struct.pack('<I',ptr)
        hits=[]
        offset=0
        while True:
            index=original.find(pattern,offset)
            if index<0:
                break
            hits.append(0x400000+rs['.text']['rva']+index)
            offset=index+1
        if ptr==0x510C00:
            if hits!=[0x44D9B1,0x497FE7]:
                raise ValueError('extra table literal mismatch')
            extra_literals.append({'slot_va':'0x00510C00',
                                   'other_literal_va':'0x00497FE7'})
        elif len(hits)!=1:
            raise ValueError('unexpected direct slot pointer appearance')
    preserved={x['va'] for x in gg['active_refs']}
    active=sum(f'0x{r["guard_va"]:08X}' in preserved for r in rows)
    if active!=16:
        raise ValueError('unexpected number of GOG guard reads')
    rows.sort(key=lambda r:(r['family'],r['slot']))
    return {
        'original_sha256':RETAIL_SHA,'gog_sha256':GOG_SHA,
        'sha256_gated':True,'original_text_bytes':len(original),
        'active_text_changed_bytes':changed,
        'guarded_regions':len(rows),'primary_slots':len(primary),
        'secondary_slots':sorted(secondary),'total_guarded_bytes':total_span,
        'changed_bytes_inside_guarded_regions':inside,
        'changed_bytes_outside_guarded_regions':changed-inside,
        'fraction_of_changed_code_inside':round(inside/changed,8),
        'fraction_of_text_covered':round(total_span/len(original),8),
        'gog_preserved_guard_sites':active,
        'paired_slot_addresses':len(slot_addresses),
        'other_embedded_pointer_literals':extra_literals,
        'ranges':rows,
        'runtime_execution_observed':False,
        'all_regions_proven_to_be_safedisc':False,
        'decrypted_executable_written':False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail',type=Path,required=True)
    parser.add_argument('--gog',type=Path,required=True)
    args=parser.parse_args()
    for name in ('retail','gog'):
        path=getattr(args,name)
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            parser.error('requires regular, bounded, non-symlink executable inputs')
    print(json.dumps(inspect(args.retail.read_bytes(),args.gog.read_bytes()),
                     indent=2))


if __name__=='__main__':
    main()
