#!/usr/bin/env python3
"""Rayman 2 exact-file, read-only audit of in-process module scans.

Cross-validates the PSAPI current-process and Toolhelp snapshot scopes,
and the six-to-one original/GOG direct literal references to a BSS flag.
Does not run protected code, patch EXEs, infer a SafeDisc decision, or claim
that indirect or dynamically generated writers are absent.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import struct

from rayman2_callback2c_branch_audit import (
    audit as audit_callback, inspect_structure as inspect_callback,
    layout, raw_at, require, IMGBASE,
)

FLAG=0x510BF4
ORIGINAL_OPERANDS={
    0x447B98: ('read', '8b0df40b5100'),
    0x447F4F: ('write_one', 'c705f40b510001000000'),
    0x448067: ('write_zero', 'c705f40b510000000000'),
    0x448077: ('write_one', 'c705f40b510001000000'),
    0x448E04: ('read', 'a1f40b5100'),
    0x4494C7: ('read', '8b0df40b5100'),
}
GOG_OPERANDS={0x4494C7: ORIGINAL_OPERANDS[0x4494C7]}

# All 8 verified below are precise opcode locations of *live* retail code.
# GOG replaced their scanner bodies, and must not be assigned the same roles.
SCOPE_ANCHORS={
    'psapi_get_current_process_masked_call': (0x4481ED, '8b0d98144a00a168144a0033c1ffd0'),
    'psapi_store_current_process_handle': (0x448202, '8bf8'),
    'psapi_enumprocessmodules_argument_order': (0x4482A8, '5268001000005057ffd6'),
    'psapi_one_module_skip_condition': (0x44831E, '8b45e4c1e80283f8017509'),
    'psapi_one_module_immediate_zero_result': (0x448329, '33c05f5e5b8be55dc3'),
    'psapi_export_name_walk': (0x44836F, '8b51208b791c8b71248b4918'),
    'toolhelp_current_process_module_snapshot': (0x4486BA, '6a006a08ffd6'),
    'toolhelp_pe_module_base_from_record': (0x4487F5, '8b85ecfdffff'),
}


def active_text(data:bytes, sections:dict) -> bytes:
    rva, vsize, raw, at, flags=sections['.text']
    if rva!=0x1000 or not (flags & 0x20000000):
        raise ValueError('Unrecognized executable section')
    return data[at:at+min(raw,vsize)]


def literal_hits(data:bytes, sections:dict, target:int=FLAG) -> list[int]:
    """Byte-level 4-byte operand matches: not by itself instruction proof."""
    code=active_text(data,sections)
    target_bytes=struct.pack('<I',target)
    pos=0
    out=[]
    while True:
        index=code.find(target_bytes,pos)
        if index<0:
            break
        out.append(IMGBASE+sections['.text'][0]+index)
        pos=index+1
    return out


def bss_flag(sections:dict) -> bool:
    rva,virt,raw,_,_=sections['.data']
    rel=(FLAG-IMGBASE)-rva
    return rel>=raw and rel+4<=virt


def inspect_structure(cd:bytes,gog:bytes) -> dict:
    # Inherited, exact opcode-by-opcode callback audit is part of the proof.
    inherited=inspect_callback(cd,gog)
    a,b=layout(cd),layout(gog)
    if not all(bss_flag(pe) for pe in (a,b)):
        raise ValueError('backend flag not zero-initialized BSS')
    # The exact operand starts at instruction VA+2 for ModRM 0D/05; at
    # VA+1 for the 5-byte A1 MOV EAX,[abs32].
    expected_original=sorted(va+(1 if va==0x448E04 else 2)
                             for va in ORIGINAL_OPERANDS)
    expected_gog=[0x4494C9]
    for site,(role,encoding) in ORIGINAL_OPERANDS.items():
        require(cd,a,site,bytes.fromhex(encoding))
    for site,(role,encoding) in GOG_OPERANDS.items():
        require(gog,b,site,bytes.fromhex(encoding))
    actual_original=literal_hits(cd,a)
    actual_gog=literal_hits(gog,b)
    if actual_original!=expected_original or actual_gog!=expected_gog:
        raise ValueError('unexpected direct-literal flag operand census')
    # The *archived* old .text in GOG is explicitly not active code.
    extra=b.get('.extra')
    if not extra or extra[4]&0x20000000:
        raise ValueError('GOG inactive text archive unavailable or executable')
    archival=gog[extra[3]+0x1000:extra[3]+0x1000+len(active_text(cd,a))]
    if archival!=active_text(cd,a):
        raise ValueError('GOG archive no longer exact original code copy')
    # Check raw machine opcodes and the dynamic-call argument order.
    for name,(va,hexed) in SCOPE_ANCHORS.items():
        require(cd,a,va,bytes.fromhex(hexed))
    # These dynamically constructed imports are independently named in
    # the inherited 36-descriptor resolver audit.
    expected={"25":"EnumProcessModules"}
    for index,name in expected.items():
        if inherited['other_process_exports'].get(index)!=name:
            raise ValueError('unexpected PSAPI descriptor export')
    if inherited['gog_0x448DE0_returns_constant']!=1:
        raise ValueError('GOG callback not a constant-one return')
    # GOG's shared cleanup read still exists, while provider/mode writers
    # are replaced: direct literal statements only, not a runtime trace.
    return {
        'retail_direct_flag_instruction_count':len(ORIGINAL_OPERANDS),
        'retail_direct_flag_reads':sum(role=='read' for role,_ in ORIGINAL_OPERANDS.values()),
        'retail_direct_flag_writes':sum(role.startswith('write_') for role,_ in ORIGINAL_OPERANDS.values()),
        'gog_active_direct_flag_instruction_count':len(GOG_OPERANDS),
        'gog_active_direct_flag_reads':1,
        'gog_active_direct_flag_writes':0,
        'retail_literal_operand_vas':[hex(va) for va in actual_original],
        'gog_active_literal_operand_vas':[hex(va) for va in actual_gog],
        'gog_archival_text_original_literal_count':len(actual_original),
        'flag_zero_initialized_in_both_pe_loaders':True,
        'retail_psapi_module_scope':'GetCurrentProcess -> EnumProcessModules',
        'retail_psapi_module_list_capacity_bytes':0x1000,
        'retail_psapi_one_module_short_circuit_zero':True,
        'retail_toolhelp_module_scope':'CreateToolhelp32Snapshot(TH32CS_SNAPMODULE=8, th32ProcessID=0)',
        'retail_toolhelp_uses_module_entry_pe_base':True,
        'both_scanners_seek_masked_pe_export_name':True,
        'gog_callback_replacement_returns_one':1,
        'gog_preserved_cleanup_flag_read_va':'0x4494C7',
        'calculated_or_external_flag_writers_excluded':False,
        'callback_invocation_observed':False,
        'safedisc_export_name_identified':False,
        'unprotected_retail_exe_created':False,
    }


def audit(cd:bytes,gog:bytes)->dict:
    # The inherited audit verifies both full sample SHA-256s, before any
    # derived claim or file data is read via the PE mapping.
    verification=audit_callback(cd,gog)
    data=inspect_structure(cd,gog)
    data['exact_sample_hashes_verified']=verification['sample_sha256_pinned']
    return data


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    a=p.parse_args()
    for path in [a.retail,a.gog]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('refusing symlink, nonregular or oversized input')
    try:
        print(json.dumps(audit(a.retail.read_bytes(),a.gog.read_bytes()), indent=2,
                         sort_keys=True))
    except (ValueError,OSError) as exc:
        p.error(str(exc))

if __name__=='__main__':
    main()
