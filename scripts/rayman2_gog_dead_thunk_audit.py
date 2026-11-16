#!/usr/bin/env python3
"""Rayman 2 exact-file, read-only static census of dynamic API thunks.

Never executes, rewrites, unpacks or distributes commercial game bytes.
Original opcode VAs were checked independently using GNU objdump;
byte-pattern counts do NOT establish runtime reachability or a full CFG.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

CD_SHA = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_SHA = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
VA_BASE = 0x400000
STUB_BASE = 0x510EA0
STUB_CACHE_BYTES = 0x464

# Actual instruction-boundary writer sites, no assumption about other forms.
CD_SITES = {
    'esi-movxor': (0x447E98,0x447FB6,0x4480DE,0x448254,0x448B45,
                   0x448EB7,0x448FE8,0x4490F3,0x44E7BC,0x44E954,
                   0x44F28C,0x44F3EC,0x450B42,0x450FC3,0x451185,
                   0x45135E,0x470061,0x47B1D3,0x47B398),
    'esi-push': (0x448556,0x450CB3),
    'edx-movxor': (0x448653,0x44DED2,0x44E0F8,0x44E219,0x44E313,
                   0x44E3C8,0x44E48A,0x44E554,0x44E5FE,0x44EBA4,
                   0x44EC78,0x44EE5C,0x44EEF9,0x44EFB2,0x44F046),
    'edx-jmp': (0x448736,0x44882E),
    'edx-push': (0x4488F9,),
}
GOG_RETAINED = (0x470061,0x47B1D3,0x47B398)

TEMPLATES = {
    'esi-movxor': b'\xc6\x06\xa1',
    'esi-push': b'\xc6\x06\x68',
    'edx-movxor': b'\xc6\x82'+struct.pack('<I',STUB_BASE)+b'\xa1',
    'edx-jmp': b'\xc6\x82'+struct.pack('<I',STUB_BASE)+b'\xe9',
    'edx-push': b'\xc6\x82'+struct.pack('<I',STUB_BASE)+b'\x68',
}

# For all three physically retained GOG instructions, an actual branch
# immediately preceding the code-generation block jumps past it. This is
# entry-path evidence, not an unqualified unreachable-code proof.
GOG_BRANCHES = (
    {'writer':0x470061,'primary':(0x470056,0x4700B3),
     'secondary':(0x4700B7,0x47010E),
     'retail_start':0x470051,'retail_scrub_tail':0x47010C,'retail_scrub_start':0x4700BB,
     'retail_scrub_preamble':0x4700B0,
     'gog_preserved_value':0x517000},
    {'writer':0x47B1D3,'primary':(0x47B1C8,0x47B225),
     'secondary':(0x47B229,0x47B280),
     'retail_start':0x47B1C3,'retail_scrub_tail':0x47B27E,'retail_scrub_start':0x47B22D,
     'retail_scrub_preamble':0x47B222,
     'gog_preserved_value':0x517000},
    {'writer':0x47B398,'primary':(0x47B388,0x47B441),
     'secondary':None,
     'retail_start':0x47B388,'retail_scrub_tail':0x47B43F,'retail_scrub_start':0x47B3EE,
     'retail_scrub_preamble':0x47B3E7,
     'gog_preserved_value':None},
)


def sections(data:bytes)->dict:
    if len(data)<0x400 or data[:2]!=b'MZ': raise ValueError('Missing DOS header')
    pe=struct.unpack_from('<I',data,0x3c)[0]
    if pe+24>len(data) or data[pe:pe+4]!=b'PE\0\0':
        raise ValueError('Missing PE signature')
    if struct.unpack_from('<H',data,pe+4)[0]!=0x14c:
        raise ValueError('Not x86 PE')
    n=struct.unpack_from('<H',data,pe+6)[0]
    opt=pe+24
    size=struct.unpack_from('<H',data,pe+20)[0]
    if size<0xE0 or struct.unpack_from('<H',data,opt)[0]!=0x10b:
        raise ValueError('Not PE32')
    if not 2<=n<=16 or opt+size+40*n>len(data):
        raise ValueError('Truncated PE sections')
    if struct.unpack_from('<I',data,opt+28)[0]!=VA_BASE:
        raise ValueError('Unknown image base')
    output={}
    for k in range(n):
        pos=opt+size+40*k
        name=data[pos:pos+8].split(b'\0')[0].decode('ascii')
        virtual,rva,raw_size,file_pos=struct.unpack_from('<IIII',data,pos+8)
        flags=struct.unpack_from('<I',data,pos+36)[0]
        if raw_size and file_pos+raw_size>len(data):
            raise ValueError('Section content truncated')
        if name in output or not virtual or rva&0xfff:
            raise ValueError('Duplicate, empty, or misaligned section')
        output[name]=(virtual,rva,raw_size,file_pos,flags)
    return output


def backed(data:bytes,sec:dict,va:int,n:int)->bytes:
    if n<1 or n>8192: raise ValueError('Out-of-bounds byte request')
    rva=va-VA_BASE
    for _,(virtual,section_rva,raw_size,file_pos,_) in sec.items():
        delta=rva-section_rva
        if 0<=delta and delta+n<=min(virtual,raw_size):
            return data[file_pos+delta:file_pos+delta+n]
    raise ValueError(f'VA {va:#x} is not file-backed')


def matches(raw:bytes,section_rva:int,needle:bytes)->tuple[int,...]:
    if not needle:raise ValueError('Empty opcode signature')
    found=[]; offset=0
    while True:
        k=raw.find(needle,offset)
        if k<0:break
        found.append(VA_BASE+section_rva+k)
        offset=k+1
    return tuple(found)


def relative_branch(code:bytes,site:int)->tuple[int,int]:
    """Decode a single E9 rel32 or EB rel8 branch; reject all other opcodes."""
    if not code:raise ValueError('No opcode')
    if code[0]==0xeb:
        if len(code)<2:raise ValueError('Truncated rel8')
        size=2; delta=struct.unpack_from('<b',code,1)[0]
    elif code[0]==0xe9:
        if len(code)<5:raise ValueError('Truncated rel32')
        size=5; delta=struct.unpack_from('<i',code,1)[0]
    else:raise ValueError('Not an unconditional near jump')
    return size,(site+size+delta)&0xffffffff


def check(cd:bytes,gog:bytes,strict_sha:bool=True)->dict:
    if strict_sha and ((len(cd)!=676352 or hashlib.sha256(cd).hexdigest()!=CD_SHA)
                      or (len(gog)!=1468928 or hashlib.sha256(gog).hexdigest()!=GOG_SHA)):
        raise ValueError('Not the two exact owner-provided Rayman 2 samples')
    a,b=sections(cd),sections(gog)
    if len(a)!=3 or len(b)!=6:raise ValueError('Unexpected section count')
    for label,sec in (('retail',a),('gog',b)):
        v,r,raw_size,off,flags=sec['.data']
        if (r,v,raw_size,flags)!=(0x9f000,0x776d0,0x7c00,0xc0000040):
            raise ValueError(f'{label} data section changed')
        offset=STUB_BASE-(VA_BASE+r)
        if not(raw_size<offset and offset+STUB_CACHE_BYTES<=v):
            raise ValueError('Transient code buffer no longer in zero-filled .data')
        dll=struct.unpack_from('<H',(cd if label=='retail' else gog),struct.unpack_from('<I',(cd if label=='retail' else gog),0x3c)[0]+24+70)[0]
        if dll!=0:raise ValueError(f'{label} DLL characteristics changed')
    if b['.extra'][4]&0x20000000:
        raise ValueError('GOG .extra archive unexpectedly executable')

    old, new={},{}
    for label,data,sec,out in (('retail',cd,a,old),('gog',gog,b,new)):
        v,r,raw_size,foff,flags=sec['.text']
        raw=data[foff:foff+min(v,raw_size)]
        if flags!=0x60000020: raise ValueError(f'{label} active .text permissions changed')
        for name,signature in TEMPLATES.items():
            found=matches(raw,r,signature)
            expected=CD_SITES[name] if label=='retail' else (GOG_RETAINED if name=='esi-movxor' else ())
            if found!=expected:
                raise ValueError(f'{label} {name} signature list differs')
            out[name]=found
    # All three preserved GOG sequences are byte-identical over the 13-byte
    # generator, but on a normal function entry path branches skip them.
    bypass=[]
    for entry in GOG_BRANCHES:
        writer=entry['writer']
        if backed(cd,a,writer,3)!=backed(gog,b,writer,3):
            raise ValueError('Retained writer changed')
        site,dest=entry['primary']
        size,target=relative_branch(backed(gog,b,site,5),site)
        if target!=dest or not site+size <= writer < dest:
            raise ValueError(f'Primary jump does not bypass writer {writer:#x}')
        secondary=entry['secondary']
        if secondary:
            site2,dest2=secondary
            size2,target2=relative_branch(backed(gog,b,site2,5),site2)
            if target2!=dest2 or not dest<=site2<dest2:
                raise ValueError('Secondary jump does not bypass scrub')
            if backed(cd,a,site2,2)!=b'\x3b\xf7':
                raise ValueError('Retail scrub comparison not established')
        if backed(cd,a,entry['retail_scrub_preamble'],3)!=b'\x8d\x7e\x0f':
            raise ValueError('Retail transient scrub bound is not 15 bytes')
        if backed(cd,a,entry['retail_scrub_tail'],2)!=b'\x72\xad':
            raise ValueError('Retail back edge changed')
        if entry['gog_preserved_value'] is not None:
            start=entry['retail_start']
            if backed(gog,b,start,5)!=b'\xb8'+struct.pack('<I',entry['gog_preserved_value']):
                raise ValueError('Changed GOG code-archive pointer')
        bypass.append({'retained_writer_va':hex(writer),
                       'skip_dynamic_code_site':hex(entry['primary'][0]),
                       'first_skip_target':hex(entry['primary'][1]),
                       'skip_scrub_site':hex(secondary[0]) if secondary else None,
                       'scrub_skip_target':hex(secondary[1]) if secondary else None,
                       'retail_pseudorandom_scrub_bytes_on_loop_entry':15,
                       'gog_entry_path_bypasses_scrub':True,
                       'entry_path_bypasses_code_generation':True,
                       'unconditional_global_unreachability_proven':False})
    # GOG inactive .extra is an old .text copy, not active executable code.
    oldstart=a['.text'];ex=b['.extra']
    copied=gog[ex[3]+0x1000:ex[3]+0x1000+oldstart[2]]
    if copied!=cd[oldstart[3]:oldstart[3]+oldstart[2]]:
        raise ValueError('Original retail .text archive mismatches')
    return {
        'retail_sha256':CD_SHA,'gog_sha256':GOG_SHA,
        'read_only':True,
        'retail_pattern_counts':{k:len(v) for k,v in old.items()},
        'retail_total_bounded_writer_patterns':sum(map(len,old.values())),
        'gog_active_pattern_counts':{k:len(v) for k,v in new.items()},
        'gog_active_total_bounded_writer_patterns':sum(map(len,new.values())),
        'gog_preserved_but_entry_path_bypassed_writers':bypass,
        'gog_archival_original_text_executable':False,
        'transient_region_va':hex(STUB_BASE),
        'transient_region_section':'.data',
        'transient_region_section_flags':hex(a['.data'][4]),
        'section_exec_flag':False,
        'actual_process_page_executable':None,
        'image_nx_compat_opt_in':False,
        'runtime_executions_observed':False,
        'safe_disc_driver_transaction_observed':False,
        'decrypted_game_executable_created':False,
        'scope_note':'Exact writer opcodes and direct entry-path jumps only; no full CFG or DEP conclusion.'
    }


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    args=p.parse_args()
    for filename in (args.retail,args.gog):
        if filename.is_symlink() or not filename.is_file() or filename.stat().st_size>2000000:
            p.error('Refusing symlink, oversized or nonregular game file')
    try:
        print(json.dumps(check(args.retail.read_bytes(),args.gog.read_bytes()),indent=2,sort_keys=True))
    except (OSError,ValueError) as e:
        p.error(str(e))


if __name__=='__main__':main()
