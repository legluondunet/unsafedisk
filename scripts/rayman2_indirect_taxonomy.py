#!/usr/bin/env python3
"""Exact-SHA, read-only static taxonomy of changed Rayman 2 CALL reg sites.

GNU objdump linear disassembly only: *not* a runtime reachability graph, SafeDisc
unwrapper, executable patcher, or proof about why GOG made each modification.
"""
from __future__ import annotations

import argparse
import collections
import json
import struct

from rayman2_trampoline_audit import (
    CD_SHA256, GOG_SHA256, BASE, STRIDE, WRITE, api_name, at_va,
    disassemble, hash_gated, pe_regions, tail_from_builder,
)

MOV_EDX_ABS = b'\x8b\x15'
MOV_ECX_ABS = b'\x8b\x0d'
MOV_EAX_ABS = b'\xa1'
XOR_EAX_ECX = b'\x33\xc1'
XOR_ECX_EDX = b'\x33\xca'


def bootstrap_name(regions):
    """The preceding stride-76 record is descriptor index zero, not padding.

    Its encoded name is derived using the same subtract/XOR recurrence as
    the 35 following records. The runtime function pointer is **not** read
    from disk, where the pointer slot is initially zero.
    """
    record = at_va(regions, BASE-STRIDE, STRIDE)
    subtract, xor_key, sub_inc, xor_inc, length = record[:5]
    if not 1 <= length <= 40 or record[0x30:0x34] != b'\0'*4:
        raise ValueError('invalid bootstrap descriptor shape')
    decoded=bytearray()
    for encoded in record[5:5+length]:
        decoded.append(((encoded - subtract)&0xff) ^ xor_key)
        subtract=(subtract+sub_inc)&0xff
        xor_key=(xor_key+xor_inc)&0xff
    if any(v < 33 or v > 126 for v in decoded):
        raise ValueError('bootstrap export name is not printable')
    return decoded.decode('ascii')


def find_prior(insns, site, op, *, horizon, end=None):
    """Return most recent *decoded instruction start* with exact opcode bytes."""
    stop = site if end is None else end
    hits = [va for va, (raw, _, _) in insns.items()
            if site-horizon <= va < stop and raw == op]
    return max(hits) if hits else None


def decode_register_call(insns, site, reg, regions):
    """Recognise only a same-register XOR and two file-backed absolute loads."""
    if reg == 'eax':
        xor = find_prior(insns, site, XOR_EAX_ECX, horizon=24)
        if xor is None:
            return None
        # Latest absolute-load instruction of each exact 32-bit encoding.
        eax_rows = [(va, struct.unpack_from('<I', raw, 1)[0])
                    for va, (raw, _, _) in insns.items()
                    if xor-40 <= va < xor and len(raw)==5 and raw.startswith(MOV_EAX_ABS)]
        ecx_rows = [(va, struct.unpack_from('<I', raw, 2)[0])
                    for va, (raw, _, _) in insns.items()
                    if xor-40 <= va < xor and len(raw)==6 and raw.startswith(MOV_ECX_ABS)]
        for eax_va, mask in sorted(eax_rows, reverse=True):
            for ecx_va, ptr in sorted(ecx_rows, reverse=True):
                if ecx_va >= eax_va:
                    continue
                try:
                    idx, name = api_name(regions, ptr, mask)
                except ValueError:
                    continue
                return {'category':'descriptor-register-call', 'name':name,
                        'descriptor_index_one_based':idx,
                        'masked_pointer_va':f'0x{ptr:08X}',
                        'mask_va':f'0x{mask:08X}',
                        'load_sites':[f'0x{ecx_va:08X}', f'0x{eax_va:08X}'],
                        'xor_site':f'0x{xor:08X}'}
    elif reg == 'ecx':
        xor = find_prior(insns, site, XOR_ECX_EDX, horizon=12)
        if xor is None:
            return None
        edx_rows=[(va,struct.unpack_from('<I',raw,2)[0])
                  for va,(raw,_,_) in insns.items()
                  if xor-48<=va<xor and len(raw)==6 and raw.startswith(MOV_EDX_ABS)]
        ecx_rows=[(va,struct.unpack_from('<I',raw,2)[0])
                  for va,(raw,_,_) in insns.items()
                  if xor-48<=va<xor and len(raw)==6 and raw.startswith(MOV_ECX_ABS)]
        for ecx_va, mask in sorted(ecx_rows, reverse=True):
            for edx_va, ptr in sorted(edx_rows, reverse=True):
                if edx_va >= ecx_va:
                    continue
                try:
                    idx, name = api_name(regions,ptr,mask)
                except ValueError:
                    if (ptr,mask)==(BASE-STRIDE+0x30, BASE-STRIDE):
                        return {'category':'bootstrap-descriptor-register-call',
                                'name':bootstrap_name(regions),
                                'descriptor_index_zero_based':0, 'masked_pointer_va':f'0x{ptr:08X}',
                                'mask_va':f'0x{mask:08X}',
                                'load_sites':[f'0x{edx_va:08X}', f'0x{ecx_va:08X}'],
                                'xor_site':f'0x{xor:08X}'}
                    continue
                return {'category':'descriptor-register-call', 'name':name,
                        'descriptor_index_one_based':idx,
                        'masked_pointer_va':f'0x{ptr:08X}',
                        'mask_va':f'0x{mask:08X}',
                        'load_sites':[f'0x{edx_va:08X}', f'0x{ecx_va:08X}'],
                        'xor_site':f'0x{xor:08X}'}
    return None


def esi_descriptor_call(insns, site, regions):
    """Require a complete generated 13-byte MOV/XOR/JMP or PUSH/RET stub."""
    writes=[]
    for va,(raw,mn,args) in insns.items():
        if site-160 <= va < site and mn=='mov' and (m:=WRITE.fullmatch(args)):
            writes.append((va,m[1],m[2],int(m[3],16)))
    writes.sort()
    for ptrrow, maskrow in reversed(list(zip(writes, writes[1:]))):
        if ptrrow[2]!='1' or maskrow[2]!='7' or ptrrow[1]!=maskrow[1]:
            continue
        try:
            idx,name=api_name(regions,ptrrow[3],maskrow[3])
            transfer,_=tail_from_builder(insns,ptrrow[0],maskrow[0],ptrrow[1])
        except ValueError:
            continue
        return {'category':'generated-descriptor-trampoline',
                'name':name,'descriptor_index_one_based':idx,
                'transfer':transfer, 'masked_pointer_va':f'0x{ptrrow[3]:08X}',
                'mask_va':f'0x{maskrow[3]:08X}',
                'builder_sites':[f'0x{ptrrow[0]:08X}',f'0x{maskrow[0]:08X}']}
    return None


def classify_non_descriptor_transfer(insns, site, regions):
    """Decode opcode-only builders and verify any embedded masked API pair."""
    recent = [(va, raw, mn, args) for va, (raw, mn, args) in insns.items()
              if site - 160 <= va < site]
    recent.sort()
    ops = {raw for _, raw, _, _ in recent}
    # Push literal target then RET. The literal is the XOR of two descriptor
    # fields; verify each source load and register pairing, not just the shape.
    if ((b'\xc6\x06\x68' in ops or b'\xc6\x82\xa0\x0e\x51\x00\x68' in ops)
            and b'\xc6\x46\x05\xc3' in ops and b'\x89\x56\x01' in ops):
        for mask_register, load_prefix, xor in (
            ('edi', b'\x8b\x3d', b'\x33\xd7'),
            ('ebx', b'\x8b\x1d', b'\x33\xd3'),
        ):
            xor_site = find_prior(insns, site, xor, horizon=100)
            if xor_site is None:
                continue
            masks = [(va, struct.unpack_from('<I', raw, 2)[0])
                     for va, raw, _, _ in recent if va < xor_site
                     and len(raw) == 6 and raw.startswith(load_prefix)]
            ptrs = [(va, struct.unpack_from('<I', raw, 2)[0])
                    for va, raw, _, _ in recent if va < xor_site
                    and len(raw) == 6 and raw.startswith(MOV_EDX_ABS)]
            for maskva, mask in sorted(masks, reverse=True):
                for ptrva, ptr in sorted(ptrs, reverse=True):
                    try:
                        idx, name = api_name(regions, ptr, mask)
                    except ValueError:
                        continue
                    return {'category': 'generated-push-immediate-ret',
                            'name': name, 'descriptor_index_one_based': idx,
                            'masked_pointer_va': f'0x{ptr:08X}',
                            'mask_va': f'0x{mask:08X}',
                            'load_sites': [f'0x{ptrva:08X}', f'0x{maskva:08X}'],
                            'xor_site': f'0x{xor_site:08X}',
                            'transfer': 'PUSH runtime_imm32; RET',
                            'runtime_destination_proven': False}
        return None
    # E9 rel32, where the displacement is the decoded API address minus the
    # dynamic trampoline base and the five-byte instruction width.
    if (b'\xc6\x82\xa0\x0e\x51\x00\xe9' in ops
            and b'\x89\x56\x01' in ops
            and b'\x33\xd1' in ops and b'\x2b\xd6' in ops
            and b'\x83\xea\x05' in ops):
        xor_site = find_prior(insns, site, b'\x33\xd1', horizon=100)
        if xor_site is None:
            return None
        ptrs = [(va, struct.unpack_from('<I', raw, 2)[0])
                for va, raw, _, _ in recent if va < xor_site
                and len(raw) == 6 and raw.startswith(MOV_EDX_ABS)]
        masks = [(va, struct.unpack_from('<I', raw, 2)[0])
                 for va, raw, _, _ in recent if va < xor_site
                 and len(raw) == 6 and raw.startswith(MOV_ECX_ABS)]
        for ptrva, ptr in sorted(ptrs, reverse=True):
            for maskva, mask in sorted(masks, reverse=True):
                if maskva >= ptrva:
                    continue
                try:
                    idx, name = api_name(regions, ptr, mask)
                except ValueError:
                    continue
                return {'category': 'generated-rel32-jump', 'name': name,
                        'descriptor_index_one_based': idx,
                        'masked_pointer_va': f'0x{ptr:08X}',
                        'mask_va': f'0x{mask:08X}',
                        'load_sites': [f'0x{maskva:08X}', f'0x{ptrva:08X}'],
                        'xor_site': f'0x{xor_site:08X}',
                        'transfer': 'JMP runtime_rel32',
                        'runtime_destination_proven': False}
        return None
    # A1 [0x4A1400]; XOR EAX,[EDI]; JMP EAX. EDI is explicitly loaded
    # with 0x4A13D0 by the function prologue, outside this short builder.
    if (b'\xc6\x06\xa1' in ops
            and b'\xc7\x46\x01\x00\x14\x4a\x00' in ops
            and b'\x89\x7e\x07' in ops
            and b'\xc6\x46\x0b\xff' in ops
            and b'\xc6\x46\x0c\xe0' in ops
            and find_prior(insns, site, b'\xbf\xd0\x13\x4a\x00', horizon=320) is not None):
        return {'category': 'generated-bootstrap-trampoline',
                'name': bootstrap_name(regions), 'descriptor_index_zero_based': 0,
                'masked_pointer_va': '0x004A1400', 'mask_va': '0x004A13D0',
                'transfer': 'MOV EAX,[0x4A1400]; XOR EAX,[0x4A13D0]; JMP EAX',
                'runtime_destination_proven': False}
    return None


def classify_sites(retail_insns,gog_insns,regions):
    results=[]
    for site,(raw,mn,args) in sorted(retail_insns.items()):
        if mn != 'call' or len(raw)!=2 or raw[0]!=0xFF or not (0xD0<=raw[1]<=0xD7):
            continue
        new=gog_insns.get(site)
        if new is not None and raw==new[0]:
            continue
        if args in ('eax','ecx'):
            match=decode_register_call(retail_insns,site,args,regions)
        elif args=='esi':
            match=(esi_descriptor_call(retail_insns,site,regions)
                   or classify_non_descriptor_transfer(retail_insns,site,regions))
        else:
            match=None
        gog_state = ('absent-in-linear-disassembly' if new is None else new[1])
        rec={'site':f'0x{site:08X}','retail_call_reg':args,
             'gog_instruction_at_same_site':gog_state,
             'same_site_bytes_preserved':False}
        if match:
            rec.update(match)
        else:
            rec.update({'category':'unclassified', 'name':None})
        results.append(rec)
    return results


def summarize(rows):
    return {'total_changed_indirect_register_call_sites':len(rows),
            'category_counts':dict(sorted(collections.Counter(x['category'] for x in rows).items())),
            'known_export_counts':dict(sorted(collections.Counter(x['name'] for x in rows if x.get('name')).items())),
            'gog_same_site_opcode_counts':dict(sorted(collections.Counter(x['gog_instruction_at_same_site'] for x in rows).items())),
            'unclassified_sites':[x['site'] for x in rows if x['category']=='unclassified']}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('retail')
    p.add_argument('gog')
    p.add_argument('--strict',action='store_true',help='fail if any changed register call cannot be classified')
    a=p.parse_args(argv)
    retail=hash_gated(a.retail,CD_SHA256)
    hash_gated(a.gog,GOG_SHA256)
    regions=pe_regions(retail)
    rows=classify_sites(disassemble(a.retail),disassemble(a.gog),regions)
    out={'read_only':True,'CD_SHA256':CD_SHA256,'GOG_SHA256':GOG_SHA256,
         'disassembler':'GNU objdump -d -M intel (linear, not CFG)',
         'gog_is_pristine_retail':False,'runtime_reachability_proven':False,
         'disc_decryption_performed':False,'summary':summarize(rows),'sites':rows}
    print(json.dumps(out,indent=2))
    if a.strict and out['summary']['unclassified_sites']:
        p.exit(2,'ERROR: at least one call site not classified\n')
    return 0

if __name__=='__main__':
    raise SystemExit(main())
