#!/usr/bin/env python3
"""Read-only static classification of descriptor references in objdump -d output.

This scans rendered instructions, NOT verified control flow. It cannot detect
computed-address stores, dynamically generated code or excluded sections.
No original disassembly bytes are included in JSON.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re

ASM = re.compile(r'^\s*([0-9A-Fa-f]+):\s+((?:[0-9A-Fa-f]{2}\s+)+)([A-Za-z][\w.]*)\s*(.*?)\s*$')
ADDRESS = re.compile(r'0x([0-9a-f]+)(?![a-f0-9])', re.I)
MEMORY = re.compile(r'(?:\bPTR\b|\b(?:ds|es|ss|fs|gs|cs):|\[[^]]*\])', re.I)
READ_ONLY = {'cmp','test','push','bt','movzx','movsx','lea','prefetchnta','prefetcht0','prefetcht1'}


def inspect_asm(lines: list[str], base: int, stride: int, count: int, slot_offset: int) -> dict:
    if not 0 <= base <= 0xFFFFFFFF or not 1 <= count <= 256 or not 4 <= stride <= 8192:
        raise ValueError('invalid base/count/stride')
    if not 0 <= slot_offset <= stride - 4 or base + (count - 1) * stride + slot_offset > 0xFFFFFFFF:
        raise ValueError('out-of-range slot')
    targets = {base + i * stride + slot_offset: i for i in range(count)}
    rows = [{'index': i, 'slot_va': f'0x{va:08X}',
             'direct_read': [], 'possible_direct_write': [],
             'address_literal': [], 'other': []} for va, i in targets.items()]
    instructions = 0
    for line in lines:
        found = ASM.match(line)
        if not found:
            continue
        instructions += 1
        va, _, mnemonic, operands = found.groups()
        operands = operands.split('#', 1)[0].strip()
        mnemonic = mnemonic.lower()
        first_operand = operands.split(',', 1)[0]
        for candidate in ADDRESS.findall(operands):
            value = int(candidate, 16)
            if value not in targets:
                continue
            row = rows[targets[value]]
            addr_text = f'0x{candidate.lower()}'
            at_destination = bool(re.search(re.escape(addr_text) + r'(?![0-9a-f])',
                                            first_operand, re.I))
            source = (first_operand if at_destination
                      else operands.split(',', 1)[1] if ',' in operands
                      else operands)
            memory = bool(MEMORY.search(source))
            if mnemonic == 'lea':
                category = 'address_literal'
            elif at_destination and memory and mnemonic not in READ_ONLY:
                category = 'possible_direct_write'
            elif memory:
                category = 'direct_read'
            elif not at_destination and not memory:
                category = 'address_literal'
            else:
                category = 'other'
            entry = {'instruction_va': f'0x{int(va,16):08X}',
                     'mnemonic': mnemonic}
            if entry not in row[category]:
                row[category].append(entry)
    categories = ['direct_read','possible_direct_write','address_literal','other']
    totals = {cat: sum(len(row[cat]) for row in rows) for cat in categories}
    return {
        'read_only': True, 'code_execution_performed': False,
        'decoded_control_flow_verified': False,
        'linearly_disassembled_text_only': True,
        'computed_address_writes_excluded': True,
        'dynamically_generated_code_excluded': True,
        'instructions_parsed': instructions, 'descriptor_count': count,
        'slot_offset_bytes': slot_offset,
        'total_references_by_category': totals,
        'referenced_descriptor_count':
            sum(any(row[cat] for cat in categories) for row in rows),
        'rows': rows,
    }


def main(argv=None) -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--objdump', type=Path, required=True,
                    help='existing objdump -d -M intel text output')
    ap.add_argument('--base', type=lambda s:int(s,0), required=True)
    ap.add_argument('--stride', type=lambda s:int(s,0), required=True)
    ap.add_argument('--count', type=int, required=True)
    ap.add_argument('--slot-offset', type=lambda s:int(s,0), required=True)
    opt=ap.parse_args(argv)
    try:
        if (opt.objdump.is_symlink() or not opt.objdump.is_file()
                or opt.objdump.stat().st_size > 64*1024*1024):
            raise ValueError('refusing symlink, nonfile or oversized disassembly')
        lines=opt.objdump.read_text(encoding='utf8',errors='replace').splitlines()
        print(json.dumps(inspect_asm(lines,opt.base,opt.stride,opt.count,opt.slot_offset),indent=2))
    except (OSError,ValueError) as exc:
        ap.exit(1,f'ERROR: {exc}\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
