#!/usr/bin/env python3
"""Exact-SHA read-only Rayman2 two-span in-memory XOR executor study.

No proprietary bytes, payloads, or decrypted EXE are generated or emitted.
The arithmetic helper is for synthetic test data only.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from rayman2_guard_provenance_audit import one, bytes_at, RETAIL_SHA, GOG_SHA

C=0x00EC8B55
SIZE_MAIN=0x24E
SIZE_EXPR=0x207

# x86 instruction anchors expected at exact original program VAs.
# All values below were independently located in GNU objdump output.
ANCHORS={
0x4673f3:'8b5010', 0x4673f6:'8d441108', 0x4673fa:'894584',
0x467413:'8b5030', 0x467416:'8d441108', 0x46741a:'894588',
0x467433:'034820',0x467436:'894dd8',
0x46744f:'035140',0x467452:'8955dc',
0x467477:'c74594558bec00',0x467484:'8b45e0',
0x467487:'8b08',0x467489:'0b4d94',0x46748f:'8b02',
0x467491:'33c1',0x467493:'8945e4',
0x467496:'8b4de0',0x467499:'3b4dd8',0x46749c:'7326',
0x4674a1:'8b02',0x4674ab:'3355e4',0x4674b1:'8910',
0x4674b6:'894de4',0x4674c2:'ebd2',
0x4674c4:'8d4598',0x4674c8:'e863fcffff',
0x4674d0:'8b4d88',0x4674d6:'8b55e0',
0x4674d9:'3b55dc',0x4674dc:'732c',
0x4674e1:'8b08',0x4674ee:'3345e4',0x4674f4:'8901',
0x4674fc:'8955e4',0x467508:'ebcc',
0x467525:'8a0dd86a4a00',0x46752d:'8d5598',
0x467535:'ff5584',0x46753b:'89458c',
0x46753e:'8b4d84',0x467541:'3b4dd8',0x467544:'7315',
0x467546:'e8350ffeff',0x46754e:'8802',0x467559:'ebe3',
0x467568:'8b5588',0x46756b:'3b55dc',0x46756e:'7315',
0x467570:'e80b0ffeff',0x467578:'8801',0x467583:'ebe3',
0x467561:'c745fc06000000',0x46758f:'e8dca10100',
# Separate typed-expression path, type 0x111 in registry table.
0x47aeed:'817df811010000',0x47af7a:'8d540808',
0x47af7e:'8955ac',0x47b010:'8d540808',0x47b014:'8955a4',
0x47b017:'8d45b0',0x47b01b:'e810c1feff',
0x47b06a:'8d4db0',0x47b072:'ff55ac',
0x47b0a6:'c7410c06000000',
# PRNG byte source called by *both* scrub loops.
0x448480:'8b0df00b5100',0x4484b2:'a3f00b5100',
}

BRANCHES={
    0x46749c:0x4674c4,0x4674c2:0x467496,
    0x4674dc:0x46750a,0x467508:0x4674d6,
    0x467544:0x46755b,0x467559:0x46753e,
    0x46756e:0x467585,0x467583:0x467568,
    0x4674c8:0x467130,0x467546:0x448480,
    0x467570:0x448480,0x46758f:0x481770,
    0x47b01b:0x467130,
}


def branch_target(va:int,code:bytes)->int:
    if len(code)==2 and code[0] in (0x73,0xeb):
        return va+2+struct.unpack('<b',code[1:])[0]
    if len(code)==5 and code[0]==0xe8:
        return va+5+struct.unpack('<i',code[1:])[0]
    raise ValueError('not an accepted direct branch')


def x86_literal_model(first:list[int],second:list[int])->tuple[list[int],list[int]]:
    """Independent x86 DWORD-level replay of the two loops (synthetics)."""
    if not first or not all(0<=x<2**32 for x in first+second):
        raise ValueError('invalid synthetic DWORD sequence')
    word0=first[0]
    eax=word0
    ecx=word0 | C
    eax ^= ecx
    prior=eax
    left=[];right=[]
    for source,out in ((first,left),(second,right)):
        for word in source:
            old=word
            edx=word^prior
            out.append(edx&0xffffffff)
            prior=old
    return left,right


def compact_model(first:list[int],second:list[int])->tuple[list[int],list[int]]:
    if not first or not all(isinstance(x,int) and 0<=x<2**32 for x in first+second):
        raise ValueError('requires a nonempty first span, each element a uint32')
    previous=C & ~first[0]
    out=[]
    for run in (first,second):
        decoded=[]
        for enc in run:
            decoded.append((enc ^ previous)&0xffffffff)
            previous=enc
        out.append(decoded)
    return out[0],out[1]


def inspect(retail:bytes,gog:bytes)->dict:
    rs,_=one(retail,RETAIL_SHA);gs,_=one(gog,GOG_SHA)
    main=bytes_at(retail,rs,0x467350,SIZE_MAIN)
    if main!=bytes_at(gog,gs,0x467350,SIZE_MAIN):
        raise ValueError('xor-executor body differs between editions')
    expr=bytes_at(retail,rs,0x47aeb0,SIZE_EXPR)
    if expr!=bytes_at(gog,gs,0x47aeb0,SIZE_EXPR):
        raise ValueError('expression executor body differs between editions')
    for va,hexdump in ANCHORS.items():
        expected=bytes.fromhex(hexdump)
        for name,program,sects in (('retail',retail,rs),('GOG',gog,gs)):
            if bytes_at(program,sects,va,len(expected))!=expected:
                raise ValueError(f'{name} x86 anchor mismatch at {va:#x}')
    for va,target in BRANCHES.items():
        b=bytes.fromhex(ANCHORS[va])
        if branch_target(va,b)!=target:
            raise ValueError(f'direct branch mismatch at {va:#x}')
    # Handler type 0x111 lives in the expression engine's dispatch table:
    # 0x4A5460 + 8*0x111, followed by a zero flag.
    registry=0x4a5460+0x111*8
    rec=struct.pack('<II',0x47aeb0,0)
    if registry!=0x4a5ce8:
        raise AssertionError('incorrect expression record computation')
    for program,sects in ((retail,rs),(gog,gs)):
        if bytes_at(program,sects,registry,len(rec))!=rec:
            raise ValueError('type 0x111 registry entry changed')
    return {
        'retail_sha256':RETAIL_SHA,'gog_sha256':GOG_SHA,
        'main_executor_va':'0x00467350','main_equal_code_bytes':SIZE_MAIN,
        'main_code_sha256':hashlib.sha256(main).hexdigest(),
        'expression_handler_va':'0x0047AEB0',
        'expression_handler_equal_code_bytes':SIZE_EXPR,
        'expression_handler_sha256':hashlib.sha256(expr).hexdigest(),
        'expression_registry_type':'0x111',
        'expression_registry_va':f'0x{registry:08X}',
        'xor_span_count':2,'xor_word_width_bytes':4,
        'first_seed_formula':'(~first_ciphertext_dword) & 0x00EC8B55',
        'subsequent_mask_source':'previous original ciphertext DWORD; carries across both spans',
        'main_indirect_call_va':'0x00467535',
        'main_indirect_call_args':'(second_span_base, pointer_to_16_slot_callback_vector)',
        'scrub_after_call_bytes':'both source ranges, one byte per 0x448480 pseudo-random call',
        'expression_indirect_call_va':'0x0047B072',
        'expression_indirect_call_args':'(data_derived_span_ptr, pointer_to_16_slot_callback_vector)',
        'branch_targets_verified':len(BRANCHES),
        'instruction_anchors_verified':len(ANCHORS),
        'actual_executable_target_resolved':False,
        'runtime_memory_dump_available':False,
        'physical_safedisc_verdict_observed':False,
        'retail_executable_decrypted':False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    args=p.parse_args()
    for path in (args.retail,args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('refusing symlink, nonregular or oversized file')
    print(json.dumps(inspect(args.retail.read_bytes(),args.gog.read_bytes()),indent=2))


if __name__=='__main__':main()
