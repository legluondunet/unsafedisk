#!/usr/bin/env python3
"""Read-only *candidate* callback-table assignment map from objdump Intel output.

Only a narrowly chosen initializer may be analyzed. MOV instructions are
recognized, but no control-flow or register-alias analysis is done;
verify the table-base register and each instruction with a disassembler.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

LINE = re.compile(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)([a-z]+)\s*(.*?)\s*$', re.I)
STORE = re.compile(r'^(?:DWORD PTR )?\[eax(?:\+0x([0-9a-f]+))?\],(.*)$', re.I)
REGISTER = re.compile(r'^(ecx|edx),(.+)$', re.I)
HEX = re.compile(r'^0x[0-9a-f]+$', re.I)
MEMORY = re.compile(r'^DWORD PTR ds:0x([0-9a-f]+)$', re.I)


def extract(lines, start_va: int, end_va: int, expected_slots: int | None = None):
    if not 0 <= start_va < end_va <= 0x100000000 or end_va-start_va > 4096:
        raise ValueError('invalid bounded initializer VA range')
    if expected_slots is not None and not 1 <= expected_slots <= 64:
        raise ValueError('expected slot count must be 1..64')
    registers = {}
    slots = {}
    scanned = 0
    for line in lines:
        m = LINE.match(line)
        if not m: continue
        va, _, op, args = m.groups()
        va = int(va, 16)
        if not start_va <= va < end_va: continue
        scanned += 1
        op = op.lower(); args = args.split('#', 1)[0].strip()
        if op not in ('mov', 'nop', 'ret'):
            raise ValueError(f'unsupported instruction {op} at 0x{va:08X}: inspect manually')
        if op != 'mov': continue
        load = REGISTER.match(args)
        if load:
            reg, src = load.groups(); reg = reg.lower(); src=src.strip()
            if HEX.fullmatch(src): registers[reg] = ('literal_va', int(src,16))
            elif (mm:=MEMORY.fullmatch(src)):
                registers[reg] = ('loaded_pointer', int(mm.group(1),16))
            else: registers.pop(reg, None)
        store = STORE.match(args)
        if not store: continue
        off, src = store.groups(); off=int(off or '0',16); src=src.strip()
        if off%4 or off>=256:
            raise ValueError('unexpected callback offset or alignment')
        if HEX.fullmatch(src): value=('literal_va',int(src,16))
        else: value=registers.get(src.lower())
        if value is None:raise ValueError(f'unresolved callback value at 0x{va:08X}')
        if off in slots:raise ValueError(f'duplicate callback slot +0x{off:02X}')
        slots[off] = {'offset':f'+0x{off:02X}','store_va':f'0x{va:08X}',
                      'source_kind':value[0], 'source_or_value':f'0x{value[1]:08X}'}
    ordered=[slots[k] for k in sorted(slots)]
    if expected_slots is not None:
        if sorted(slots) != list(range(0,expected_slots*4,4)):
            raise ValueError('callback slots incomplete or noncontiguous')
    return {'read_only':True, 'control_flow_verified':False,
            'base_register_verified':False, 'instructions_scanned':scanned,
            'slot_count':len(ordered),'literal_assignments':sum(x['source_kind']=='literal_va' for x in ordered),
            'runtime_import_assignments':sum(x['source_kind']=='loaded_pointer' for x in ordered),
            'slots':ordered}


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--objdump',required=True,type=Path)
    ap.add_argument('--start-va',required=True,type=lambda s:int(s,0))
    ap.add_argument('--end-va',required=True,type=lambda s:int(s,0))
    ap.add_argument('--expected-slots',type=int)
    opt=ap.parse_args(argv)
    try:
        if opt.objdump.is_symlink() or not opt.objdump.is_file() or opt.objdump.stat().st_size>64*1024*1024:
            raise ValueError('refusing nonregular, symlink or >64 MiB text input')
        with opt.objdump.open('rb') as handle:data=handle.read(64*1024*1024+1)
        if len(data)>64*1024*1024:raise ValueError('disassembly grew above 64 MiB')
        result=extract(data.decode('utf-8','replace').splitlines(),opt.start_va,opt.end_va,opt.expected_slots)
    except (ValueError,OSError) as exc:
        ap.exit(1,f'ERROR: {exc}\n')
    print(json.dumps(result,indent=2))
    return 0


if __name__=='__main__':raise SystemExit(main())
