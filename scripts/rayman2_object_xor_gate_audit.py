#!/usr/bin/env python3
"""Read-only Rayman2 object-gate -> runtime XOR call chain, exact-owner SHA gated.

Emits structural metadata only; no game bytes, decryption or patching.
All branch claims are static; object data comes from the game at runtime.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from rayman2_guard_provenance_audit import one, bytes_at, RETAIL_SHA, GOG_SHA

# Full byte-identity checks of relevant routines, from independent owner samples.
BODIES={
  0x404550:(0x99,'4cef57faf6969059bd1732ad13eee6aecee8e845cbd6ba08df47610a7c95692b'),
  0x4045f0:(0xcc,'821263233d13affb1d623465d08e7c244ec4e7a5cc35cfe68b5ac1a7cb2b6263'),
  0x467210:(0x134,'b9721ba2595f392b1f306c0908bac5794f02e64a3f9003c64e45d3eddd280c7b'),
  0x467350:(0x24e,'b33fb63041764dfbd2a35ae1d591e7ad61b21484b4e6594053cf626d2ce37dc3'),
}
CALLS={
    0x4042a8:0x4045f0,
    0x4045f4:0x404550,
    0x404588:0x467210,
    0x404591:0x467350,
    0x4045cc:0x467210,
    0x4045d5:0x467350,
    0x4673b7:0x481550,
    0x4674c8:0x467130,
}
ANCHORS={
  0x4045f2:'6a 00', # zero mode to outer list walk
  0x404558:'8b 3d 1c 6b 4a 00', # first global list head
  0x404560:'bd 00 00 00 01', # object flag = 0x01000000
  0x404567:'8b 47 10',
  0x40456a:'8b 48 04',
  0x404571:'85 69 24',
  0x404576:'8b 40 0c',
  0x40457d:'8b 30',
  0x404583:'85 db', 0x404585:'75 12',
  0x404587:'56', 0x404590:'56',
  0x404599:'8b 3f', # first list next node
  0x40459f:'a1 d0 0f 50 00', # second list owns a root object
  0x4045a4:'8b 78 08',
  0x4045ab:'8b 47 04',
  0x4045ae:'8b 48 04',
  0x4045b5:'85 69 24',
  0x4045ba:'8b 40 0c',
  0x4045c1:'8b 30',
  0x4045c7:'85 db', 0x4045c9:'75 12',
  0x4045cb:'56',0x4045d4:'56',
  0x4045dd:'8b 7f 14', # second list next node
  0x46723d:'8b 75 08',
  0x467248:'8b 0e',
  0x46725f:'03 11',
  0x46729f:'a1 c4 17 51 00', # prehelper's separate typed-value stage
  0x467350:'55 8b ec',
  0x46737e:'83 7d 08 00', # non-null input object required
  0x4673a3:'83 7d ec 00', # required computed value
  0x4673bf:'25 ff 00 00 00', # type conversion requires AL=1
  0x4673c4:'83 f8 01',
  0x4673cd:'8b 45 f0',
  0x4673d3:'83 7d e8 02', # expected typed property = 2
  0x4673f3:'8b 50 10',0x467413:'8b 50 30',
  0x467433:'03 48 20',0x46744f:'03 51 40',
  0x467477:'c7 45 94 55 8b ec 00',
  0x467535:'ff 55 84',
  0x46753b:'89 45 8c',
}
EXPECTED_PATHS={
    'entry_to_walker':['0x004042A8','0x004045F0','0x00404550'],
    'first_list':['0x004A6B1C','[node+0x10]','[node]'],
    'second_list':['0x00500FD0','[root+0x08]','[node+0x14]'],
    'preprocess':'0x00467210',
    'execute':'0x00467350',
    'call_decrypted_A':'0x00467535',
}

def relative_call_target(site:int,opcode:bytes)->int:
    if len(opcode)!=5 or opcode[0]!=0xe8:
        raise ValueError('not E8 rel32')
    return site+5+struct.unpack_from('<i',opcode,1)[0]

def geometry(a_begin:int,a_end:int,b_begin:int,b_end:int)->dict:
    """Safe metadata-only assessment of a prospective runtime snapshot."""
    vals=(a_begin,a_end,b_begin,b_end)
    if any(not isinstance(x,int) or x<0 or x>0xffffffff for x in vals):
        raise ValueError('all addresses must be 32-bit nonnegative integers')
    if not a_begin<a_end or not b_begin<=b_end:
        raise ValueError('first region must be nonempty; second cannot invert')
    if a_end-a_begin>32*1024*1024 or b_end-b_begin>32*1024*1024:
        raise ValueError('unbounded trace input')
    if not (a_end<=b_begin or b_end<=a_begin):
        raise ValueError('overlapping ranges: static decoder may self-corrupt')
    a_len=a_end-a_begin;b_len=b_end-b_begin
    return {
        'first_range_bytes':a_len, 'second_range_bytes':b_len,
        'first_dword_loop_iterations':(a_len+3)//4,
        'second_dword_loop_iterations':(b_len+3)//4,
        'first_dword_overrun_risk_bytes':(-a_len)%4,
        'second_dword_overrun_risk_bytes':(-b_len)%4,
        'scrub_loop_byte_iterations':a_len+b_len,
        'range_alignment_confirmed':a_begin%4==0 and b_begin%4==0,
        'memory_values_were_not_read':True,
    }

def inspect(retail:bytes,gog:bytes)->dict:
    rs,_=one(retail,RETAIL_SHA);gs,_=one(gog,GOG_SHA)
    for va,(length,sha) in BODIES.items():
        original=bytes_at(retail,rs,va,length)
        if hashlib.sha256(original).hexdigest()!=sha:
            raise ValueError(f'original routine changed at 0x{va:X}')
        if bytes_at(gog,gs,va,length)!=original:
            raise ValueError(f'GOG routine changed at 0x{va:X}')
    for va,code in ANCHORS.items():
        expected=bytes.fromhex(code)
        if (bytes_at(retail,rs,va,len(expected))!=expected or
            bytes_at(gog,gs,va,len(expected))!=expected):
            raise ValueError(f'instruction anchor changed at 0x{va:X}')
    for site,target in CALLS.items():
        original=bytes_at(retail,rs,site,5)
        if (original!=bytes_at(gog,gs,site,5)
                or relative_call_target(site,original)!=target):
            raise ValueError(f'call chain changed at 0x{site:X}')
    # Root 1 lives in file-backed .data and is zero on disk.
    if bytes_at(retail,rs,0x4a6b1c,4)!=b'\0'*4 or bytes_at(gog,gs,0x4a6b1c,4)!=b'\0'*4:
        raise ValueError('first list not initially null')
    # Root 2 is in PE zero-filled .data, not any on-disk pointer table.
    for sections in (rs,gs):
        sec=sections['.data']
        offset=0x500fd0-0x400000-sec['rva']
        if not sec['raw_size']<=offset and offset+4<=sec['virtual_size']:
            raise ValueError('second head not loader-zero-filled .data')
    return {
        'retail_sha256':RETAIL_SHA,'gog_sha256':GOG_SHA,
        'exact_unmodified_bodies':{f'0x{va:08X}':n for va,(n,_) in BODIES.items()},
        'exact_preserved_direct_calls':len(CALLS),
        'opcode_anchors':len(ANCHORS),
        'outer_known_call_mode':0,
        'required_object_flag_mask':'0x01000000',
        'object_flag_field_offset':'0x24',
        'two_linked_lists':True,'first_head_initial_value':0,
        'second_root_zero_initialized_by_PE_loader':True,
        'prehelper_return_checked_before_decoder':False,
        'main_decoder_requires_type_result':2,
        'main_decoder_requires_type_call_success':True,
        'input_runtime_object_bytes_available':False,
        'code_fragment_ciphertext_recovered':False,
        'all_paths_proven_to_be_SafeDisc':False,
        'call_chain':EXPECTED_PATHS,
    }

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail',required=True,type=Path)
    parser.add_argument('--gog',required=True,type=Path)
    parser.add_argument('--range-geometry',nargs=4,type=lambda x:int(x,0),
                        metavar=('A_START','A_END','B_START','B_END'))
    args=parser.parse_args()
    for path in (args.retail,args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            parser.error('refusing nonregular, symlink or oversized original input')
    report=inspect(args.retail.read_bytes(),args.gog.read_bytes())
    if args.range_geometry is not None:
        report['optional_runtime_geometry_only']=geometry(*args.range_geometry)
    print(json.dumps(report,indent=2))

if __name__=='__main__':
    main()
