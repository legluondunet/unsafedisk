#!/usr/bin/env python3
"""Read-only Rayman 2 CD/GOG patch-dependency preflight; NOT an unwrapper.

Whole-file SHA-256 gates, RVA-aligned active .text comparison, exact opcode
anchors and PE section bounds. Never emits commercial bytes or patches a game.
"""
from __future__ import annotations
import argparse,hashlib,json,struct
from pathlib import Path

CD_HASH='7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_HASH='9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
BASE=0x400000
RVA_TEXT=0x1000
TEXT_BYTES=0x9a200
SMALL={
 (0x401d8e,0x401dee):94,(0x402532,0x402595):6,
 (0x40593d,0x405a4c):33,(0x4500b0,0x4500b2):2,
 (0x46713b,0x4671f4):135,(0x470051,0x470267):25,
 (0x47b1c3,0x47b38c):12,
}
MAJOR={
 (0x4474b0,0x449360):7704,(0x44deb0,0x44f4c9):3646,
 (0x450a47,0x451440):1612,
}


def sha_gate(data:bytes,expected:str):
    if hashlib.sha256(data).hexdigest()!=expected:
        raise ValueError('Unknown Rayman2 executable SHA256')


def u32(data:bytes,pos:int):
    if pos<0 or pos+4>len(data):raise ValueError('unbounded DWORD')
    return struct.unpack_from('<I',data,pos)[0]


def pe_sections(data:bytes):
    if len(data)<0x100 or data[:2]!=b'MZ':raise ValueError('not MZ')
    p=u32(data,0x3c)
    if p+24>len(data) or data[p:p+4]!=b'PE\0\0':raise ValueError('not PE')
    cnt=struct.unpack_from('<H',data,p+6)[0]
    opt_len=struct.unpack_from('<H',data,p+20)[0]
    o=p+24
    if o+opt_len>len(data) or opt_len<224 or data[o:o+2]!=b'\x0b\x01':
        raise ValueError('unknown PE32 layout')
    image_base=u32(data,o+28)
    image_size=u32(data,o+56)
    sh=o+opt_len
    if cnt<3 or cnt>16 or sh+cnt*40>len(data):raise ValueError('bad section count')
    regions={}
    for idx in range(cnt):
        s=sh+idx*40
        label=data[s:s+8].split(b'\0')[0].decode('ascii')
        vs,rva,rs,raw=struct.unpack_from('<IIII',data,s+8)
        flags=u32(data,s+36)
        if not label or label in regions or raw+rs>len(data):
            raise ValueError('bad section extents')
        regions[label]={'va':image_base+rva,'virtual_size':vs,'raw_size':rs,
                        'file_offset':raw,'flags':flags}
    return {'image_base':image_base,'image_size':image_size,'sections':regions}


def is_mapped(pe:dict,va:int)->bool:
    if not pe['image_base']<=va<pe['image_base']+pe['image_size']:
        return False
    return any(s['va']<=va<s['va']+max(s['virtual_size'],s['raw_size'])
               for s in pe['sections'].values())


def get_bytes(data:bytes,pe:dict,va:int,n:int)->bytes:
    if n<1 or n>TEXT_BYTES:raise ValueError('unbounded read')
    for s in pe['sections'].values():
        at=va-s['va']
        if 0<=at and at+n<=s['raw_size']:
            offset=s['file_offset']+at
            return data[offset:offset+n]
    raise ValueError('VA not backed by file data')


def diff_runs(a:bytes,b:bytes):
    if len(a)!=len(b):raise ValueError('unaligned image')
    ans=[];start=None
    for i,(x,y) in enumerate(zip(a,b)):
        if x!=y and start is None:start=i
        if x==y and start is not None:
            ans.append((start,i));start=None
    if start is not None:ans.append((start,len(a)))
    return ans


def grouped_diff(a:bytes,b:bytes,gap:int=512):
    if gap<0:raise ValueError('negative gap')
    group=[]
    for start,end in diff_runs(a,b):
        if group and start-group[-1][1]<=gap:
            group[-1]=(group[-1][0],end)
        else:group.append((start,end))
    return [(start+BASE+RVA_TEXT,end+BASE+RVA_TEXT,
             sum(x!=y for x,y in zip(a[start:end],b[start:end])))
            for start,end in group]


def rel32_target(insn:bytes,at:int)->int:
    if len(insn)!=5 or insn[0]!=0xE8:raise ValueError('not a direct CALL')
    return at+5+struct.unpack_from('<i',insn,1)[0]


def verify_known_sites(cd:bytes,gog:bytes,cp:dict,gp:dict)->dict:
    def exact(at,cd_hex,gog_hex):
        orig=bytes.fromhex(cd_hex);patch=bytes.fromhex(gog_hex)
        if get_bytes(cd,cp,at,len(orig))!=orig or get_bytes(gog,gp,at,len(patch))!=patch:
            raise ValueError(f'differing opcode at VA 0x{at:X}')
    iat=0x49c0b4
    directory_sites=[0x401d8e,0x40593d,0x4059bd,0x405a40]
    exact(0x401d8e,'680401000050ff15b4c04900','c7002e000000eb58cccccccc')
    for site in directory_sites[1:]:
        exact(site,'680401000050ff15b4c04900','66c7002e0090909090909090')
    for site in directory_sites:
        if get_bytes(cd,cp,site+6,6)!=b'\xff\x15'+struct.pack('<I',iat):
            raise ValueError('original directory import call changed')

    exact(0x402532,'e819f6ffff','9090909090')
    exact(0x402594,'7528','eb28')
    if rel32_target(get_bytes(cd,cp,0x402532,5),0x402532)!=0x401b50:
        raise ValueError('unexpected original message callback')

    exact(0x4500af,'e81cf8ffff','e8cc8fffff')
    if rel32_target(get_bytes(cd,cp,0x4500af,5),0x4500af)!=0x44f8d0:
        raise ValueError('original function pointer changed')
    if rel32_target(get_bytes(gog,gp,0x4500af,5),0x4500af)!=0x449080:
        raise ValueError('GOG call no longer targets added helper')
    # The *same VA* is an immediate-byte interior of original code,
    # but executable helper code in GOG's rewritten CD-search region.
    exact(0x449080,'7f','e84b6800003da02e630075050500000002c3')
    helper=get_bytes(gog,gp,0x449080,18)
    if rel32_target(helper[:5],0x449080)!=0x44f8d0:
        raise ValueError('GOG helper does not delegate to original')
    if (helper[5:10]!=b'\x3d\xa0\x2e\x63\x00'
            or helper[10:12]!=b'\x75\x05'
            or helper[12:17]!=b'\x05\x00\x00\x00\x02'
            or helper[17]!=0xc3):
        raise ValueError('GOG magic selector changed')

    exact(0x470051,'99b9550400','b800705100')
    exact(0x470056,'00f7','eb5b')
    exact(0x47b1c3,'99b9550400','b800705100')
    exact(0x47b1c8,'00f7','eb5b')
    exact(0x470256,'6a006a006a00506a006a00ff1520c24900','90'*17)
    return {
      'get_windows_directory_call_sites':[hex(x) for x in directory_sites],
      'window_callback_original_va':'0x00401B50',
      'gog_noop_window_callback_va':'0x00402532',
      'gog_unconditional_message_skip_va':'0x00402594',
      'isolated_call_va':'0x004500AF',
      'isolated_original_target_va':'0x0044F8D0',
      'isolated_gog_target_va':'0x00449080',
      'gog_helper_delegates_to_va':'0x0044F8D0',
      'gog_helper_compared_result_constant':'0x00632EA0',
      'gog_helper_conditional_add':'0x02000000',
      'gog_selfread_archive_base':'0x00517000',
      'gog_shell_execute_neutralized_va':'0x00470256',
    }


def audit(cd:bytes,gog:bytes):
    sha_gate(cd,CD_HASH);sha_gate(gog,GOG_HASH)
    cp=pe_sections(cd);gp=pe_sections(gog)
    if cp['image_base']!=BASE or gp['image_base']!=BASE:
        raise ValueError('unexpected PE base')
    ca=get_bytes(cd,cp,BASE+RVA_TEXT,TEXT_BYTES)
    ga=get_bytes(gog,gp,BASE+RVA_TEXT,TEXT_BYTES)
    groups=grouped_diff(ca,ga)
    observed={(a,b):cnt for a,b,cnt in groups}
    if len(groups)!=10 or observed!={**SMALL,**MAJOR}:
        raise ValueError('unexpected original/GOG delta clusters')
    note=verify_known_sites(cd,gog,cp,gp)
    extra=gp['sections'].get('.extra');extra2=gp['sections'].get('.extra2')
    if not extra or not extra2 or extra['va']!=0x517000 or extra2['va']!=0x5b3000:
        raise ValueError('missing GOG-only virtual structures')
    if extra['flags']&0x20000000 or extra2['flags']&0x20000000:
        raise ValueError('unexpected executable GOG virtual structures')
    if cp['image_size']!=0x117000 or gp['image_size']!=0x1d7000:
        raise ValueError('retail/GOG PE image sizes changed')
    for va in (0x517000,0x518000,0x5b3000):
        if is_mapped(cp,va) or not is_mapped(gp,va):
            raise ValueError('GOG-only section address no longer exclusive')
    if get_bytes(gog,gp,0x518000,TEXT_BYTES)!=ca:
        raise ValueError('GOG archived code copy differs from original .text')
    note.update({
       'retail_sha256':CD_HASH,'gog_sha256':GOG_HASH,
       'retail_size_of_image':cp['image_size'],
       'gog_size_of_image':gp['image_size'],
       'gog_only_section_address_mapping_confirmed':True,
       'archived_original_text_verified':True,
       'seven_minor_changed_bytes':sum(SMALL.values()),
       'major_changed_bytes':sum(MAJOR.values()),
       'total_changed_bytes':sum(x[2] for x in groups),
       'nonportable_selfread_base':True,
       'nonportable_retargeted_helper':True,
       'not_mapped_in_retail':['0x00517000','0x00518000','0x005B3000'],
       'reconstructed_executable_created':False,
       'safedisc_verdict_observed':False,
       'minor_clusters':[
          {'start':hex(a),'end_exclusive':hex(b),'changed_bytes':n}
          for (a,b),n in SMALL.items()],
    })
    return note


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    args=p.parse_args()
    for path in (args.retail,args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('refusing symlinks, nonregular files or >2MB input')
    print(json.dumps(audit(args.retail.read_bytes(),args.gog.read_bytes()),indent=2))

if __name__=='__main__':
    main()
