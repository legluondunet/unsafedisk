#!/usr/bin/env python3
"""Rayman2: exact-SHA static graph of 11 removed guarded functions.

Read-only. Raw E8 rel32 candidates are byte patterns, not a claim to
complete disassembly or dynamic reachability. Does not emit binary code.
"""
from __future__ import annotations
import argparse
import json
import struct
from pathlib import Path
from rayman2_guard_provenance_audit import RETAIL_SHA,GOG_SHA,one,bytes_at,BASE
from rayman2_guarded_ranges_audit import inspect as guarded_inspect

# Function entry VAs derived from genuine original prologues. Their spans
# are independently checked against the 28-range guard-table audit.
REMOVED={
    4:(0x4481B0,'int3'),
    5:(0x448610,'int3'),
    6:(0x447DE0,'ret'),
    7:(0x447D10,'int3'),
    8:(0x4478A0,'ret'),
    9:(0x448AB0,'xor-eax-ret'),
    13:(0x447540,'int3'),
    14:(0x447730,'int3'),
    15:(0x447A90,'int3'),
    16:(0x447AF0,'int3'),
    17:(0x447BE0,'int3'),
}
EXPECTED_CALLS={
    4:(0x448E11,),
    5:(0x448E1F,),
    6:(0x44949A,),
    7:(0x4478D4,),
    8:(0x44947C,),
    9:(),
    13:(0x44792C,0x447B7B),
    14:(0x4478E3,0x447B50,0x447B86),
    15:(0x44818A,0x448DC3),
    16:(0x448196,0x4481A2,0x448D96),
    17:(0x447CD7,),
}
PRESERVED_CALLS={6:EXPECTED_CALLS[6],8:EXPECTED_CALLS[8]}
STUB_PREFIX={
    'int3':b'\xCC'*16,
    'ret':b'\xC3'+b'\xCC'*15,
    'xor-eax-ret':b'\x33\xC0\xC3'+b'\xCC'*13,
}


def text_view(data:bytes,sections:dict)->tuple[int,bytes]:
    s=sections['.text']
    return BASE+s['rva'], data[s['file_offset']:s['file_offset']+s['raw_size']]


def raw_relative_calls(text_va:int,section_bytes:bytes,targets:set[int]):
    """Enumerate *all raw candidate* E8 rel32 bytes targeting a known VA.

    No disassembler dependency, therefore this is an opcode pattern census;
    actual instruction boundaries require independent verification.
    """
    found={va:[] for va in targets}
    for index in range(len(section_bytes)-4):
        if section_bytes[index]!=0xE8:
            continue
        target=text_va+index+5+struct.unpack_from('<i',section_bytes,index+1)[0]
        if target in found:
            found[target].append(text_va+index)
    return found


def instruction_stub(data:bytes,sections:dict,va:int,expected_kind:str):
    prefix=STUB_PREFIX[expected_kind]
    if bytes_at(data,sections,va,len(prefix))!=prefix:
        raise ValueError(f'GOG stub changed at 0x{va:X}')


def audit(retail:bytes,gog:bytes):
    rs,_=one(retail,RETAIL_SHA)
    gs,_=one(gog,GOG_SHA)
    original=guarded_inspect(retail,gog)
    rows=original.get('ranges',original.get('guarded_code_ranges'))
    if rows is None or len(rows)!=28:
        raise ValueError('guarded-region census changed')
    relevant={r['slot']:r for r in rows if r['family']=='primary'
              and r.get('gog_fully_int3_filled')}
    if set(relevant)!=set(REMOVED):
        raise ValueError('not the same eleven INT3 filled guarded spans')
    cv,cd=text_view(retail,rs)
    gv,gd=text_view(gog,gs)
    if cv!=gv or len(cd)!=0x9A200:
        raise ValueError('unexpected active text base or size')
    targets={va for va,_ in REMOVED.values()}
    cd_calls=raw_relative_calls(cv,cd,targets)
    gog_calls=raw_relative_calls(gv,gd[:len(cd)],targets)
    sources=[]
    for slot,(va,kind) in sorted(REMOVED.items()):
        if not relevant[slot]['begin']>va:
            raise ValueError('entry must precede registered body')
        if cd_calls[va]!=list(EXPECTED_CALLS[slot]):
            raise ValueError(f'original CALL rel32 target census changed for {slot}')
        wanted=list(PRESERVED_CALLS.get(slot,()))
        if gog_calls[va]!=wanted:
            raise ValueError(f'GOG CALL rel32 target census changed for {slot}')
        instruction_stub(gog,gs,va,kind)
        for site in cd_calls[va]:
            op=bytes_at(retail,rs,site,5)
            if op[0]!=0xE8 or site+5+struct.unpack_from('<i',op,1)[0]!=va:
                raise ValueError('original CALL rel32 malformed')
            actual=bytes_at(gog,gs,site,5)
            preserved=site in wanted
            if actual != (op if preserved else b'\xCC'*5):
                raise ValueError(f'GOG not preserving or pruning CALL at {site:X}')
            parent=next((r for r in rows if r['begin']<=site<r['end']),None)
            sources.append({'source_va':f'0x{site:08X}',
                            'target_va':f'0x{va:08X}',
                            'target_slot':slot,
                            'gog_call_preserved':preserved,
                            'source_inside_guarded_span':None if parent is None else {
                                'family':parent['family'],'slot':parent['slot']}})
    if len(sources)!=16 or sum(x['gog_call_preserved'] for x in sources)!=2:
        raise ValueError('unexpected number of direct CALLs')
    classes={kind:sum(1 for _,k in REMOVED.values() if k==kind)
             for kind in STUB_PREFIX}
    if classes!={'int3':8,'ret':2,'xor-eax-ret':1}:
        raise ValueError('unexpected stub classes')
    # A zero direct-E8 count does NOT imply no consumer. This engine-
    # created function-vector retains an address to the zero-return stub;
    # the other retained slot points at a one-return stub.
    address_taken={
        0x4671EB:(0x2C,0x448DE0),
        0x4671F4:(0x30,0x448AB0),
    }
    for site,(field,target) in address_taken.items():
        literal=b'\xC7\x40'+bytes((field,))+struct.pack('<I',target)
        if bytes_at(retail,rs,site,7)!=literal or bytes_at(gog,gs,site,7)!=literal:
            raise ValueError(f'function pointer store altered at {site:#x}')
    if bytes_at(gog,gs,0x448DE0,16)!=b'\x33\xC0\x40\xC3'+b'\xCC'*12:
        raise ValueError('GOG nonzero-success callback changed')
    for site in (0x4674C8,0x47B01B):
        call=bytes_at(retail,rs,site,5)
        if (call!=bytes_at(gog,gs,site,5) or call[0]!=0xE8
                or site+5+struct.unpack('<i',call[1:])[0]!=0x467130):
            raise ValueError('function-vector builder call changed')
    indirect_candidates={0x42E087:bytes.fromhex('ff5130'),
                         0x45224F:bytes.fromhex('ff543a30')}
    for site,code in indirect_candidates.items():
        if bytes_at(retail,rs,site,len(code))!=code or bytes_at(gog,gs,site,len(code))!=code:
            raise ValueError('offset +0x30 indirect CALL changed')
    return {'original_sha256':RETAIL_SHA, 'gog_sha256':GOG_SHA,
        'sha256_strict':True,'pure_static_call_patterns':True,
        'full_int3_body_count':len(relevant),
        'gog_entrypoint_classes':classes,
        'original_direct_E8_calls':len(sources),
        'gog_preserved_E8_calls':2,
        'gog_removed_E8_calls':14,
        'gog_removed_calls_are_CC_filled':True,
        'direct_incoming_calls_to_eight_cc_entrypoints_on_gog':0,
        'preserved_function_pointer_store_sites':{'0x004671EB':'0x00448DE0','0x004671F4':'0x00448AB0'},
        'gog_function_pointer_stub_returns':{'0x00448DE0':1,'0x00448AB0':0},
        'function_vector_builder_calls':['0x004674C8','0x0047B01B'],
        'possible_plus30_indirect_call_sites':['0x0042E087','0x0045224F'],
        'indirect_call_to_this_specific_vector_proven':False,
        'indirect_or_self_modified_calls_ruled_out':False,
        'static_sites':sources,
        'decrypted_retail_executable_generated':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    args=p.parse_args()
    for path in (args.retail,args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('expected bounded, nonsymlink regular PE input')
    print(json.dumps(audit(args.retail.read_bytes(),args.gog.read_bytes()),indent=2))

if __name__=='__main__':main()
