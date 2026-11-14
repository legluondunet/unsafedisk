#!/usr/bin/env python3
"""Read-only SHA-locked Rayman2 startup call-chain audit; no game writes."""
from __future__ import annotations
import argparse, json, struct
from pathlib import Path
from rayman2_guard_provenance_audit import one, bytes_at, RETAIL_SHA, GOG_SHA

START_CALLS = ((0x44947c,0x4478a0),(0x449485,0x448db0),
               (0x44948e,0x448d80),(0x44949a,0x447de0),
               (0x44949f,0x448e30))
RET_STUBS = (0x4478a0,0x448db0,0x448d80,0x447de0)
ORIGINAL_STUB_STARTS = {
  0x4478a0:bytes.fromhex('55 8b ec 83 ec 20'),
  0x448db0:bytes.fromhex('a1 e8 13 51 00'),
  0x448d80:bytes.fromhex('a1 f0 13 51 00'),
  0x447de0:bytes.fromhex('a1 ec 13 51 00'),
}
UNCHANGED = {
  0x401ef8:'6a 01', # WinMain pushes 1, not an inferred argument
  0x449366:'a1 ec 13 51 00', # BSS guard
  0x449370:'74 1b', # zero takes executable code, not registration
  0x4493a8:'bf 19 01 00 00', # 281 PRNG states
  0x4493e7:'8b 5d 08', # EBX = incoming argument
  0x4493f0:'85 db', # test EBX
  0x4493f2:'0f 84 83 00 00 00', # flag=0 skips allocation
  0x4493f8:'6a 1c', # flag=1 allocates 28-byte buffer
  0x4493fa:'c7 05 e8 13 51 00 07 00 00 00',
  0x449404:'c7 05 f0 13 51 00 24 00 00 00',
  0x449496:'85 db', # test EBX again
  0x449498:'74 0a', # flag=0 skips 2 further routines
}
GOG_VOLUME = bytes.fromhex('b0 2e a2 d8 6a 4a 00 8b e5 5d c3')
GOG_NOOP = b'\xc3' + b'\xcc'*15


def rel_target(code,va):
    if len(code)!=5 or code[0]!=0xe8:
        raise ValueError(f'not CALL rel32 at 0x{va:X}')
    return va+5+struct.unpack_from('<i',code,1)[0]


def inspect(retail:bytes,gog:bytes):
    sr,_=one(retail,RETAIL_SHA)
    sg,_=one(gog,GOG_SHA)
    for va,hexbytes in UNCHANGED.items():
        b=bytes.fromhex(hexbytes)
        if bytes_at(retail,sr,va,len(b))!=b or bytes_at(gog,sg,va,len(b))!=b:
            raise ValueError(f'unchanged anchor failed at 0x{va:X}')
    if bytes_at(retail,sr,0x401efa,5)!=bytes_at(gog,sg,0x401efa,5):
        raise ValueError('initial CALL changed')
    if rel_target(bytes_at(retail,sr,0x401efa,5),0x401efa)!=0x449360:
        raise ValueError('wrong boot initializer target')
    edges=[]
    for va,target in START_CALLS:
        orig=bytes_at(retail,sr,va,5)
        if orig!=bytes_at(gog,sg,va,5) or rel_target(orig,va)!=target:
            raise ValueError(f'changed / incorrect call edge at {va:#x}')
        edges.append({'site':f'0x{va:08X}','target':f'0x{target:08X}'})
    for va in RET_STUBS:
        expected=ORIGINAL_STUB_STARTS[va]
        if bytes_at(retail,sr,va,len(expected))!=expected:
            raise ValueError(f'retail opcode changed at {va:#x}')
        if bytes_at(gog,sg,va,16)!=GOG_NOOP:
            raise ValueError(f'GOG no-op stub changed at {va:#x}')
    if bytes_at(gog,sg,0x448e5a,len(GOG_VOLUME))!=GOG_VOLUME:
        raise ValueError('GOG local path substitution changed')
    if bytes_at(retail,sr,0x448e5a,len(GOG_VOLUME))==GOG_VOLUME:
        raise ValueError('no retail/GOG CD-volume difference')
    return {'retail_sha256':RETAIL_SHA,'gog_sha256':GOG_SHA,
      'initial_call_va':'0x00401EFA','initial_argument':1,
      'initializer_va':'0x00449360','guard_bss_zero_on_pe_load':True,
      'pseudo_random_bootstrap_state_count':281,
      'peripheral_state_count':7,'secondary_state_count':36,
      'unchanged_direct_calls':edges,
      'gog_ret_only_targets':[f'0x{va:08X}' for va in RET_STUBS],
      'gog_volume_probe_replaced_by_dot':True,
      'gog_drive_selector_va':'0x004A6AD8',
      'retail_drive_volume_authentication_proven':False,
      'physical_safedisc_authentication_proven':False,
      'runtime_guard_nonzero_proven':False,
      'decrypted_retail_executable_written':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    a=p.parse_args()
    for path in (a.retail,a.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
            p.error('refusing symlink, nonregular or oversized PE')
    print(json.dumps(inspect(a.retail.read_bytes(),a.gog.read_bytes()),indent=2))

if __name__=='__main__':
    main()
