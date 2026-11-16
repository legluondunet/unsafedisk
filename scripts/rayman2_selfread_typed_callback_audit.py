#!/usr/bin/env python3
"""Rayman 2 CD/GOG: independent, read-only audit of 0x170 typed-result dispatch.

Static x86 only, SHA-256 pinned by the existing ``locked_read`` reader.
Does not execute or patch commercial binaries; does not infer SafeDisc verdict.
Requires GNU objdump for instruction-boundary inventory.
"""
from __future__ import annotations
import argparse
import json
import re
import struct
import subprocess
from pathlib import Path
from rayman2_selfread_archive_audit import locked_read, sections, by_rva

BASE=0x400000
ROW_BASE=0x4A4278
ROW_FIRST=0x12
ROW_LAST=0x17
ROW_BYTES=12
TRIPLE=(0x29,0x4815A0,0x4817B0)
DESTINATION=0x481800
# Generic parser / field converter / nested type handler and result dispatcher.
# Counts were independently discovered in GNU objdump active .text and subsequently
# verified against raw E8 rel32 bytes at every instruction boundary.
GENERIC_HELPERS={0x480B90:757, 0x4815F0:7, 0x4817B0:2, 0x481800:16}
EXPECTED_CALLS=(
    0x46790D,0x46BBAA,0x46BBFE,0x46F8D7,0x46F95A,0x46FD5C,
    0x4701ED,0x475AEF,0x475EB9,0x478F66,0x478F91,0x478FC7,
    0x48243C,0x48AB81,0x48AF49,0x48B543,
)
SHARED_ANCHORS={
    0x4701E1:'89 5c 24 30',                  # temp typed object payload
    0x4701E5:'c7 44 24 34 15 00 00 00',     # type tag 0x15, immediately before call
    0x4701ED:'e8 0e 16 01 00',              # dispatch typed result
    0x4701F2:'8b 5c 24 40',                 # restore old EBX
    0x4701F9:'5f 5e 8b c3 5d 5b 83 c4 18 c3', # no direct verdict in tail
    0x481800:'56 57 8b 7c 24 14 8b 74 24 0c',
    0x481816:'8b 08 8b 11 8b 42 04',     # pointer chasing, not comparing the value
    0x481822:'e8 39 00 00 00',             # lookup generic callback in third row field
    0x481847:'ff d0',                       # indirect callback invocation
    0x48184C:'5f 5e c3',                    # generic dispatch epilogue
    0x481860:'8b 44 24 04 8d 04 40 8b 04 85 80 42 4a 00 c3',
    0x4817B0:'56 8b 74 24 08 8b 06 50 e8 a3 00 00 00',
    0x4817E0:'ff d0',                       # nested type callback
    0x4817F9:'ff d0',                       # nested type callback, second branch
}
OBJDUMP_CALL=re.compile(r'^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+call\s+0x([0-9a-fA-F]+)(?:\s|$)',re.M)


def relcall(va:int, op:bytes)->int:
    if len(op)!=5 or op[0]!=0xE8: raise ValueError('not E8 rel32')
    return va+5+struct.unpack('<i',op[1:])[0]


def callbacks_at(raw:bytes, sec:dict, first:int=ROW_FIRST, last:int=ROW_LAST)->tuple[tuple[int,int,int],...]:
    if not 0<=first<=last<=0xFF:raise ValueError('invalid callback range')
    b=by_rva(raw,sec,ROW_BASE+first*ROW_BYTES-BASE,(last-first+1)*ROW_BYTES)
    return tuple(struct.iter_unpack('<III',b))


def parse_direct_xrefs(objdump_text:str,callee:int=DESTINATION)->list[int]:
    return sorted(int(m.group(1),16) for m in OBJDUMP_CALL.finditer(objdump_text) if int(m.group(2),16)==callee)


def disassemble_text(exe:Path)->str:
    p=subprocess.run(['objdump','-d','-M','intel','-j','.text',str(exe)],
                     capture_output=True,text=True,timeout=40,check=True)
    if len(p.stdout)>30_000_000:raise ValueError('unbounded disassembly')
    return p.stdout


def inspect_one(raw:bytes, objdump_text:str, kind:str)->dict:
    base,sects=sections(raw)
    if base!=BASE or not {'.text','.data'}.issubset(sects):raise ValueError('unknown PE layout')
    read=lambda va,n:by_rva(raw,sects,va-BASE,n)
    for va,op in SHARED_ANCHORS.items():
        b=bytes.fromhex(op)
        if read(va,len(b))!=b:raise ValueError(f'{kind}: anchor mismatch at {va:#x}')
    rows=callbacks_at(raw,sects)
    if rows!=(TRIPLE,)*(ROW_LAST-ROW_FIRST+1):raise ValueError(f'{kind}: callback family changed')
    left=callbacks_at(raw,sects,ROW_FIRST-1,ROW_FIRST-1)[0]
    right=callbacks_at(raw,sects,ROW_LAST+1,ROW_LAST+1)[0]
    if left==TRIPLE or right==TRIPLE:raise ValueError('not bounded six-row family')
    calls=parse_direct_xrefs(objdump_text)
    if calls!=list(EXPECTED_CALLS):
        raise ValueError(f'{kind}: expected 16 boundaries; got {len(calls)} at {calls}')
    for va in calls:
        if relcall(va,read(va,5))!=DESTINATION:
            raise ValueError(f'{kind}: bad raw rel32 at {va:#x}')
    if relcall(0x481822,read(0x481822,5))!=0x481860:
        raise ValueError('callback resolver changed')
    helper_sites={}
    for target,expected_count in GENERIC_HELPERS.items():
        xs=parse_direct_xrefs(objdump_text,target)
        if len(xs)!=expected_count:
            raise ValueError(f'{kind}: wrong direct E8 count for helper {target:#x}: {len(xs)}')
        for va in xs:
            if relcall(va,read(va,5))!=target:
                raise ValueError(f'{kind}: wrong raw E8 to helper {target:#x} at {va:#x}')
        helper_sites[f'0x{target:08X}']=len(xs)
    return {'sample':kind,'generic_helper_direct_call_counts':helper_sites,
            'row_type_range':'0x12..0x17',
            'six_identical_row_fields':[hex(x) for x in TRIPLE],
            'neighbor_rows_distinct':True,
            'shared_opcodes_checked':len(SHARED_ANCHORS),
            'direct_caller_sites':[f'0x{x:08X}' for x in calls],
            'ordinary_callers_outside_0x170':len(calls)-1,
            'unique_0x170_caller_va':'0x004701ED',
            'nested_callback_functions':['0x481800','0x4817B0','0x481860'],
            'runtime_objects_inspected':False}


def inspect(cd:bytes,gog:bytes,cd_asm:str,gog_asm:str)->dict:
    a=inspect_one(cd,cd_asm,'cd')
    b=inspect_one(gog,gog_asm,'gog')
    if a['direct_caller_sites']!=b['direct_caller_sites']:
        raise ValueError('caller inventory changed between CD and GOG')
    # Check all generic helpers have the same instruction-site xrefs in both builds.
    for target in GENERIC_HELPERS:
        if parse_direct_xrefs(cd_asm,target)!=parse_direct_xrefs(gog_asm,target):
            raise ValueError(f'helper {target:#x} call-site inventory changed in GOG')
    return {'read_only':True, 'verified_samples':[a,b],
            'typed_output_0x15_has_specialized_callback':False,
            'type_0x15_shares_conversion_callbacks_with_six_types':True,
            '0x481800_is_a_generic_dynamic_callback_dispatch':True,
            '0x170_accumulator_compared_to_expected_literal_here':False,
            'integrity_verdict_or_gameplay_execution_proven':False,
            'caution':'No object payloads or runtime traces; absent comparison here does not prove absent downstream checks.'}


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    args=p.parse_args()
    retail=locked_read(args.retail,'cd')
    gog=locked_read(args.gog,'gog')
    asm_retail=disassemble_text(args.retail)
    asm_gog=disassemble_text(args.gog)
    # Ensure objdump did not read a different revision than the SHA-gated bytes.
    if locked_read(args.retail,'cd')!=retail or locked_read(args.gog,'gog')!=gog:
        raise ValueError('input changed between hashing and disassembly')
    report=inspect(retail,gog,asm_retail,asm_gog)
    print(json.dumps(report,sort_keys=True,indent=2))

if __name__=='__main__':main()
