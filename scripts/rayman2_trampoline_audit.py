#!/usr/bin/env python3
"""Read-only original/GOG comparison of Rayman 2's generated x86 API trampolines.

SHA-256 pins both known user-supplied files. Never runs, patches, or redistributes
protected binaries. Only shows connections that both PE descriptors and IAT prove.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import subprocess

CD_SHA256 = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_SHA256 = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
BASE = 0x4A141C
STRIDE = 0x4C
LINE = re.compile(r'^\s*([0-9a-f]{6,8}):\s+((?:[0-9a-f]{2} )+)\s+(\S+)\s*(.*)')
WRITE = re.compile(r'^DWORD PTR \[(edx\+0x510ea|esi\+0x)([17])\],0x([0-9a-f]+)$')
IMPORT = re.compile(r'^\s*([0-9a-f]{8})\s+<none>\s+([0-9a-f]{4})\s+([A-Za-z_][A-Za-z_0-9@]*)\s*$')


def hash_gated(path, expected):
    p = pathlib.Path(path)
    if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size < 16 * 1024 * 1024:
        raise ValueError('input is not a bounded regular file')
    content = p.read_bytes()
    if hashlib.sha256(content).hexdigest() != expected:
        raise ValueError('unrecognized binary SHA-256')
    return content


def pe_regions(data):
    if len(data) < 256 or data[:2] != b'MZ':
        raise ValueError('MZ signature required')
    peoff = struct.unpack_from('<I', data, 0x3C)[0]
    if peoff + 24 > len(data) or data[peoff:peoff+4] != b'PE\0\0':
        raise ValueError('invalid PE signature')
    count = struct.unpack_from('<H', data, peoff+6)[0]
    optlen = struct.unpack_from('<H', data, peoff+20)[0]
    opt = peoff+24
    if not 1 <= count <= 96 or optlen < 96 or opt+optlen+40*count > len(data):
        raise ValueError('invalid sections')
    if struct.unpack_from('<H', data, opt)[0] != 0x10B:
        raise ValueError('PE32 only')
    base = struct.unpack_from('<I', data, opt+28)[0]
    regions = {}
    for i in range(count):
        off=opt+optlen+i*40
        name,virt,rva,rawsize,rawpos = struct.unpack_from('<8sIIII',data,off)
        if rawpos+rawsize > len(data):
            raise ValueError('section outside file')
        regions[name.rstrip(b'\0').decode('ascii')] = (base+rva, data[rawpos:rawpos+rawsize])
    return regions


def at_va(regions, va, count):
    for start, content in regions.values():
        if start <= va and va+count <= start+len(content):
            return content[va-start:va-start+count]
    raise ValueError(f'unmapped RVA at {va:#x}')


def api_name(regions, ptr, mask):
    if ptr-mask != 0x30 or (mask-BASE) % STRIDE != 0:
        raise ValueError('not matching a paired descriptor pointer and mask')
    index = (mask-BASE) // STRIDE + 1
    if not 1 <= index <= 35:
        raise ValueError('descriptor index outside authenticated layout')
    data = at_va(regions, mask, STRIDE)
    minus, key, plusminus, pluskey, n = data[:5]
    if not 0 < n <= 40:
        raise ValueError('invalid export name length')
    result = []
    for val in data[5:5+n]:
        result.append(((val-minus)&255)^key)
        minus = (minus+plusminus)&255
        key = (key+pluskey)&255
    if not all(33<=c<=126 for c in result):
        raise ValueError('invalid export name encoding')
    return index, bytes(result).decode('ascii')


def disassemble(path):
    output = subprocess.run(['objdump','-d','-M','intel',str(path)],check=True,capture_output=True,text=True).stdout
    entries = {}
    for line in output.splitlines():
        m=LINE.match(line)
        if m:
            entries[int(m[1],16)] = (bytes.fromhex(m[2]),m[3],m[4])
    return entries


def imports(path, image_base=0x400000):
    output = subprocess.run(['objdump','-p',str(path)],check=True,capture_output=True,text=True).stdout
    return {image_base+int(m[1],16):m[3] for line in output.splitlines()
            if (m:=IMPORT.match(line))}



def tail_from_builder(cd_ins, pointer_write, mask_write, regclass):
    """Verify every single-byte opcode write in the 13-byte generator template.

    The two operand DWORD writes have already been decoded independently.
    Templates end either in JMP EAX or the equivalent PUSH EAX; RET.
    """
    if regclass == 'edx+0x510ea':
        def operand(offset):
            return f'BYTE PTR [edx+{0x510EA0+offset:#x}]'
    elif regclass == 'esi+0x':
        def operand(offset):
            return 'BYTE PTR [esi]' if offset == 0 else f'BYTE PTR [esi+{offset:#x}]'
    else:
        raise ValueError('unsupported generator write base register')
    found = {}
    for va, (_, mn, args) in cd_ins.items():
        if not pointer_write-25 <= va <= mask_write+40 or mn != 'mov':
            continue
        for offset in (0, 5, 6, 11, 12):
            prefix = operand(offset) + ',0x'
            if args.startswith(prefix):
                found[offset] = int(args[len(prefix):], 16)
    if any(found.get(i) != byte for i, byte in {0:0xA1, 5:0x33, 6:0x05}.items()):
        raise ValueError('generated MOV/XOR opcode bytes are not complete')
    if (found.get(11), found.get(12)) == (0xFF, 0xE0):
        return 'JMP EAX', b'\xFF\xE0'
    if (found.get(11), found.get(12)) == (0x50, 0xC3):
        return 'PUSH EAX; RET', b'\x50\xC3'
    raise ValueError('missing/invalid generated transfer opcode bytes')


def bridge_targets(cd_ins, gog_ins, regions, iat_imports):
    """Exact same-site replacement: original CALL reg -> GOG CALL [IAT].

    Candidate builder must precede the call within 160 VA bytes and contain
    paired writes to offsets +1/+7 of a 13-byte generated trampoline.
    """
    rows=[]
    bad=[]
    changed_indirect=collections.Counter()
    # Preserve only decoded instructions, not arbitrary bytes matching FF Dn.
    for site,(old,mn,ops) in sorted(cd_ins.items()):
        if not (mn=='call' and len(old)==2 and old[0]==0xFF and 0xD0<=old[1]<=0xD7):
            continue
        new = gog_ins.get(site)
        if new is not None and new[0] == old:
            changed_indirect['preserved'] += 1
            continue
        changed_indirect['changed'] += 1
        if new is None or len(new[0])!=6 or new[0][:2]!=b'\xFF\x15':
            continue
        iat=struct.unpack_from('<I',new[0],2)[0]
        imp=iat_imports.get(iat)
        writes=[]
        for addr,(raw,mn2,op2) in cd_ins.items():
            if not site-160<=addr<site or mn2 != 'mov':
                continue
            match=WRITE.fullmatch(op2)
            if match:
                writes.append((addr,match[1],match[2],int(match[3],16)))
        writes.sort()
        if len(writes)<2 or (writes[-2][2],writes[-1][2]) != ('1','7') or writes[-2][1]!=writes[-1][1]:
            bad.append(f'{site:#x}: missing generated-code descriptor pair')
            continue
        addrptr,regclass,_,ptr=writes[-2]
        addrmask,_,_,mask=writes[-1]
        try:
            index,name=api_name(regions,ptr,mask)
        except ValueError as exc:
            bad.append(f'{site:#x}: {exc}')
            continue
        try:
            transfer, tail = tail_from_builder(cd_ins, addrptr, addrmask, regclass)
        except ValueError as exc:
            bad.append(f'{site:#x}: {exc}')
            continue
        if imp != name:
            bad.append(f'{site:#x}: descriptor {name} mismatches IAT {imp}')
            continue
        # This is a *static* generator template, not a memory dump.
        template=(b'\xA1'+struct.pack('<I',ptr)+b'\x33\x05'+struct.pack('<I',mask)+tail)
        if len(template)!=13:
            raise AssertionError('unexpected generated trampoline width')
        rows.append({'call_site': f'0x{site:08X}', 'retail_indirect_call':ops,
                     'gog_iat_slot':f'0x{iat:08X}', 'win32_api':name,
                     'descriptor_index_one_based':index,
                     'descriptor_pointer_field':f'0x{ptr:08X}',
                     'descriptor_mask_field':f'0x{mask:08X}',
                     'builder_pointer_write':f'0x{addrptr:08X}',
                     'builder_mask_write':f'0x{addrmask:08X}',
                     'template_transfer':transfer,
                     'template_opcode_shape':('A1 <ptr> 33 05 <mask> FF E0' if transfer == 'JMP EAX'
                                              else 'A1 <ptr> 33 05 <mask> 50 C3')})
    return rows,bad,dict(changed_indirect)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('cd')
    ap.add_argument('gog')
    args=ap.parse_args()
    rawcd=hash_gated(args.cd,CD_SHA256)
    hash_gated(args.gog,GOG_SHA256)
    cdregions=pe_regions(rawcd)
    rows,bad,counts=bridge_targets(disassemble(args.cd),disassemble(args.gog),cdregions,imports(args.gog))
    if bad:
        raise RuntimeError('; '.join(bad))
    print(json.dumps({'read_only':True,'CD_SHA256':CD_SHA256,'GOG_SHA256':GOG_SHA256,
                      'gog_is_pristine_retail':False,'runtime_execution_observed':False,
                      'working_retail_unwrapper':False,'original_indirect_call_counts':counts,
                      'verified_gog_iat_bridge_count':len(rows),
                      'api_bridge_histogram':dict(collections.Counter(x['win32_api'] for x in rows)),
                      'template_transfer_histogram':dict(collections.Counter(x['template_transfer'] for x in rows)),
                      'bridges':rows,
                      'limitations':'Linear disassembly and static opcode pairs; no runtime call graph or proof of disc decryption.'},indent=2))


if __name__=='__main__':
    main()
