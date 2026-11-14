#!/usr/bin/env python3
"""Read-only, exact-SHA audit of Rayman 2 selector 5 and GlobalAlloc.

Does not patch, decrypt or run the game. Only reports numeric metadata.
"""
import argparse
import json
import struct
from pathlib import Path
from rayman2_patch_dependency_audit import (
    CD_HASH,GOG_HASH,sha_gate,pe_sections,get_bytes,rel32_target)

DISPATCH=0x4501F0
MAGIC=0x00632EA0 # decimal 6,500,000
EXTRA=0x02000000 # 32 MiB
TABLE=(0x45002E,0x450063,0x450082,0x450097,
       0x4500AF,0x4500ED,0x4500D5,0x450100,
       0x4501C0,0x4501C0,0x450122,0x45015E,
       0x45017D,0x4501A3,0x4500C2,0x450113)

COMMON={
 0x44F8D0:'51',0x44F8D1:'68 c0 16 51 00',0x44F8D6:'6a 01',
 0x44F8D8:'8d 44 24 08',0x44F8DC:'6a 04',0x44F8DE:'50',
 0x44F8DF:'e8 ac 14 00 00',0x44F8E4:'8b 44 24 10',
 0x44F8E8:'83 c4 10',0x44F8EB:'59',0x44F8EC:'c3',
 0x4500B4:'50',0x4500B5:'e8 26 db 00 00',0x4500BA:'83 c4 04',
 0x45DBE0:'8b 44 24 04',0x45DBE4:'6a 00',0x45DBE6:'6a 01',
 0x45DBE8:'68 a0 86 01 00',0x45DBED:'50',
 0x45DBEE:'a0 d4 3f 4a 00',0x45DBF3:'33 c9',0x45DBF5:'8a c8',
 0x45DBF7:'8b 14 8d c0 ac 50 00',0x45DBFE:'52',
 0x45DBFF:'50',0x45DC00:'6a 00',0x45DC02:'e8 19 48 fe ff',
 0x45DC07:'83 c4 1c',0x45DC0A:'c6 05 48 61 51 00 00',
 0x45DC11:'c3',0x442420:'53',0x442421:'8b 54 24 10',
 0x442426:'8a 44 24 24',0x44242C:'8b 7c 24 14',
 0x442430:'81 e7 ff 00 00 00',0x442436:'c1 e7 04',
 0x442439:'03 fa',0x44243B:'24 01',0x442441:'75 0b',
 0x442443:'8b 74 24 20',0x442447:'c6 44 24 1c 04',
 0x44244C:'eb 21',0x44246F:'8b 44 24 1c',
 0x442473:'25 ff 00 00 00',0x44247C:'8d 58 ff',
 0x44247F:'85 f3',0x44248B:'56',0x44248C:'6a 00',
 0x44248E:'ff 15 7c c0 49 00',0x442494:'8b e8',
 0x442504:'89 2f',0x442506:'89 47 04',
 0x4500C2:'e8 09 f8 ff ff',0x4500C7:'50',
 0x4500C8:'e8 53 db 00 00',0x45DC20:'8b 44 24 04',
 0x45DC42:'e8 d9 47 fe ff',0x45DC4A:'c6 05 48 61 51 00 01',
}
CD_ONLY={0x4500AF:'e8 1c f8 ff ff'}
GOG_ONLY={0x449080:'e8 4b 68 00 00',0x449085:'3d a0 2e 63 00',
          0x44908A:'75 05',0x44908C:'05 00 00 00 02',
          0x449091:'c3',0x4500AF:'e8 cc 8f ff ff'}


def transform(value):
    if not isinstance(value,int) or value<0 or value>0xffffffff:
        raise ValueError('requires unsigned DWORD')
    return value+EXTRA if value==MAGIC else value


def aligned_size(value):
    if not isinstance(value,int) or value<0 or value>0xfffffffc:
        raise ValueError('cannot safely round unbounded DWORD size')
    return (value+3)&~3


def check(data,pe,anchors,label):
    for va,hexbytes in anchors.items():
        raw=bytes.fromhex(hexbytes)
        if get_bytes(data,pe,va,len(raw))!=raw:
            raise ValueError(f'{label} unexpected x86 at 0x{va:08X}')


def audit(cd,gog):
    sha_gate(cd,CD_HASH);sha_gate(gog,GOG_HASH)
    c=pe_sections(cd);g=pe_sections(gog)
    for label,data,pe in [('CD',cd,c),('GOG',gog,g)]:
        check(data,pe,COMMON,label)
        expected=b''.join(struct.pack('<I',v) for v in TABLE)
        if get_bytes(data,pe,DISPATCH,64)!=expected:
            raise ValueError('16-entry switch table changed')
    check(cd,c,CD_ONLY,'CD');check(gog,g,GOG_ONLY,'GOG')
    for va,target in ((0x44F8DF,0x450D90),(0x4500B5,0x45DBE0),
                      (0x45DC02,0x442420),(0x4500C2,0x44F8D0),
                      (0x4500C8,0x45DC20),(0x45DC42,0x442420)):
        for data,pe in [(cd,c),(gog,g)]:
            if rel32_target(get_bytes(data,pe,va,5),va)!=target:
                raise ValueError(f'changed call edge 0x{va:08X}')
    for va,target,data,pe in ((0x4500AF,0x44F8D0,cd,c),
                               (0x4500AF,0x449080,gog,g),
                               (0x449080,0x44F8D0,gog,g)):
        if rel32_target(get_bytes(data,pe,va,5),va)!=target:
            raise ValueError('incorrect selector 5 call edge')
    if not TABLE[4]==0x4500AF or not TABLE[14]==0x4500C2:
        raise ValueError('changed selector mapping')
    return {
      'retail_sha256':CD_HASH,'gog_sha256':GOG_HASH,
      'selector':5,'dispatch_va':'0x004501F0','stream_va':'0x005116C0',
      'read_dword_function_va':'0x0044F8D0','read_dispatch_va':'0x00450D90',
      'read_width_bytes':4,'gog_helper_va':'0x00449080',
      'allocation_mode_initializer_va':'0x0045DBE0',
      'allocation_manager_va':'0x00442420',
      'win32_api':'KERNEL32!GlobalAlloc','win32_import_va':'0x0049C07C',
      'globalalloc_flag':0,'allocation_selector_slot':0,
      'trigger_input_bytes':MAGIC,'extra_bytes':EXTRA,'extra_mib':32,
      'retail_requested_bytes':aligned_size(MAGIC),
      'gog_requested_bytes':aligned_size(transform(MAGIC)),
      'separate_unmodified_selector_15':'0x004500C2 -> 0x0045DC20',
      'original_real_world_size_observed':False,
      'safedisc_authentication_proven':False,'decrypted_exe_written':False,
      'verified_opcode_sites':len(COMMON)+len(CD_ONLY)+len(GOG_ONLY),
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    a=p.parse_args()
    for path in (a.retail,a.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('nonregular, symlink, missing, or oversized PE')
    print(json.dumps(audit(a.retail.read_bytes(),a.gog.read_bytes()),indent=2))

if __name__=='__main__':main()
