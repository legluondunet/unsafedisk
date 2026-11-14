#!/usr/bin/env python3
"""Read-only, hash-locked original/GOG Rayman 2 DAT caller-chain audit.

Identifies direct x86 CALL edges and selected exact branch anchors.
Not a dynamic graph or anti-copy decoder. Does not execute the game.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from rayman2_dat_dataflow_audit import read_exact, pe_slice, x86_lines, anchor

LOADER = 0x44DC40
CALLERS = (
    0x402A34, 0x402B32, 0x402EF2, 0x403044,
    0x403964, 0x403A41, 0x404186, 0x404294,
    0x44CE78, 0x44CF2C, 0x44D2D8, 0x44D619,
)
EDGES = {0x44DC80:0x44D990, 0x44D9F4:0x44E8A0, 0x44E8D3:0x44EB40}
CODE = {
    0x44DC88:('84 c0','test'),
    0x44DC8A:('75 09','jne'),  # the loader continues only for a nonzero AL
    0x44DC8C:('33 c0','xor'),
    0x44DC95:('8d 4d c0','lea'),
    0x44D9FC:('84 c0','test'),
    0x44D9FE:('74 09','je'),   # fallback when 0x44E8A0 says false
    0x44DA09:('a1 f0 16 51 00','mov'),
    0x44E8DD:('83 fb ff','cmp'),
    0x44E8E3:('0f 84 4a 02 00 00','je'), # invalid handle -> return zero
    0x44EB2A:('b0 01','mov'),
    0x44EB33:('32 c0','xor'),
    0x44DCA1:('e8 ea 30 00 00','call'), # sample of structured reads
    0x44DCAB:('e8 b0 ff 00 00','call'), # allocation
    0x44DCBB:('88 46 04','mov'),
    0x44DDAC:('88 50 01','mov'),
    0x44DDB2:('89 48 04','mov'),
    0x44DDB5:('89 70 08','mov'),
}


def target_at(site: int, opcode: bytes) -> int:
    if len(opcode)!=5 or opcode[0]!=0xe8:
        raise ValueError('only 5-byte x86 CALL rel32 is supported')
    return site+5+int.from_bytes(opcode[1:], 'little', signed=True)


def direct_callers(code: dict, callee: int) -> list[int]:
    result=[]
    for site,(raw,mnemonic,_) in code.items():
        if mnemonic=='call' and len(raw)==5 and raw[:1]==b'\xe8':
            if target_at(site,raw)==callee:
                result.append(site)
    return sorted(result)


def short_jcc_target(site: int, op: bytes, expected: int) -> int:
    if len(op)!=2 or op[0]!=expected:
        raise ValueError('expected 2-byte conditional jump')
    return site+2+int.from_bytes(op[1:2], 'little', signed=True)


def near_jcc_target(site: int, op: bytes, expected: bytes) -> int:
    if len(op)!=6 or not op.startswith(expected):
        raise ValueError('expected six-byte near conditional jump')
    return site+6+int.from_bytes(op[2:], 'little', signed=True)


def audit(cdpath: Path, gogpath: Path) -> dict:
    result=[]
    for kind,path in [('cd',cdpath),('gog',gogpath)]:
        data=read_exact(path,kind)
        full=x86_lines(path,0x401000,0x49B200)
        sites=direct_callers(full,LOADER)
        if tuple(sites)!=CALLERS:
            raise ValueError(f'{kind} original 12-caller inventory drifted')
        for site in sites:
            if pe_slice(data,site,5)!=full[site][0]:
                raise ValueError(f'{kind} bad PE CALL bytes at {site:x}')
        for site,dest in EDGES.items():
            if target_at(site,pe_slice(data,site,5)) != dest:
                raise ValueError(f'{kind} indirect stage unexpectedly changed at {site:x}')
            anchor(full,site,pe_slice(data,site,5),'call')
        for site,(hexbytes,mnemonic) in CODE.items():
            op=bytes.fromhex(hexbytes)
            anchor(full,site,op,mnemonic)
            if pe_slice(data,site,len(op)) != op:
                raise ValueError(f'{kind} PE code anchor drifted at {site:x}')
        if short_jcc_target(0x44DC8A,full[0x44DC8A][0],0x75) != 0x44DC95:
            raise ValueError('failed nonzero loader result route')
        if short_jcc_target(0x44D9FE,full[0x44D9FE][0],0x74) != 0x44DA09:
            raise ValueError('failed fallback route')
        if near_jcc_target(0x44E8E3,full[0x44E8E3][0],b'\x0f\x84') != 0x44EB33:
            raise ValueError('failed invalid-handle route')
        for site,callee in ((0x44DCA1,0x450D90),(0x44DCAB,0x45DC60)):
            if target_at(site,full[site][0])!=callee:
                raise ValueError('structured-data reader/allocation target drifted')
        result.append({'build':kind,'direct_loader_callers':len(sites),'caller_sites':[f'0x{s:08X}' for s in sites],
                       'chain_unchanged':True})
    return {
        'inputs_exact_sha256_verified':True,'read_only':True,'statically_observed':result,
        'direct_edges':[{ 'from':f'0x{x:08X}', 'to':f'0x{y:08X}'} for x,y in EDGES.items()],
        'loader_caller_0x44DC40_result_check':'0x44DC88 TEST AL,AL; 0x44DC8A JNE 0x44DC95',
        'alternate_dat_lookup_on_failure':'0x44D9FE JE 0x44DA09 when 0x44E8A0 returns AL=0',
        'first_open_invalid_handle_branch':'0x44E8E3 JE 0x44EB33 => AL=0',
        'parser_read_call':'0x44DCA1 CALL 0x450D90',
        'parser_allocation_call':'0x44DCAB CALL 0x45DC60',
        'integrity_verdict_established':False,
        'runtime_reachability_established':False,
        'gog_is_pristine_unwrapped_retail':False,
    }


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(audit(a.retail,a.gog),indent=2,sort_keys=True))

if __name__=='__main__':main()
