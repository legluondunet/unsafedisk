#!/usr/bin/env python3
"""Rayman 2 read-only callback +0x30 imported-function-pointer check.

Strictly bounded to two SHA256-pinned, owner-supplied PE32 binaries. This
proves a *static instruction dependency*, not reachability, physical disc
DRM, decryptability or the outcome of the check during a real game run.
The GOG build is NOT a pristine unwrapped retail reference.
No game bytes are printed, exported or modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from rayman2_callback2c_branch_audit import (
    CD_HASH, GOG_HASH, CD_SIZE, GOG_SIZE, layout, raw_at, require,
    call_target, encoded_export,
)

CALLBACK_SLOT = 0x30
CALLBACK_INSTALL_VA = 0x4671F4
HANDLER_VA = 0x448AB0
HANDLER_END = 0x448D78
RETAIL_HANDLER_SHA256 = '2709650e3632600e4c1e0ddfef3df51b304a060ecc8606c6dbd2bd59ef9c3fe3'
GOG_HANDLER_SHA256 = '50ab7969a95ddfaa58fc08279448f6884f2bb10c0af68d8f55c2fe181aef6afc'
RECORD_BASE = 0x4A13D0
RECORD_STRIDE = 0x4C
RECORD_COUNT = 36

# All addresses are the beginning of genuine instructions in retail active
# .text (independently checked using GNU objdump). Minimal signatures protect
# both the static data-flow proof and the comparison against an inert GOG stub.
SOURCE_INSTRUCTIONS = {
    0x448AB0: '55 8b ec 83 ec 24',           # ordinary function prologue
    0x448AB6: 'a1 ec 13 51 00',              # same zero-filled guard
    0x448AE7: '8b 45 08 8b 08',              # saved encoded descriptor key
    0x448AF1: '89 4d dc',                    # [ebp-0x24]=input DWORD key
    0x448B45: 'c6 06 a1',                    # generated API trampoline
    0x448B48: 'c7 46 01 00 14 4a 00',      # bootstrap descriptor #0 ptr
    0x448B4F: 'c6 46 05 33',
    0x448B53: 'c6 46 06 05',
    0x448B57: '89 7e 07',                    # mask descriptor base in EDI
    0x448B5A: 'c6 46 0b ff',
    0x448B5E: 'c6 46 0c e0',
    0x448B8C: '6a 00',                       # GetModuleHandleA(NULL)
    0x448B8E: 'ff d6',                       # indirect call to masked API
    0x448BF2: '8b 57 3c',                    # PE e_lfanew
    0x448BF5: '8b b4 3a 80 00 00 00',     # import directory RVA
    0x448C19: '8b 06',                       # IMAGE_IMPORT_DESCRIPTOR.OriginalFirstThunk
    0x448C23: '8d 14 38',                    # OriginalFirstThunk + ImageBase
    0x448C26: '8b 46 10',                    # IMAGE_IMPORT_DESCRIPTOR.FirstThunk
    0x448C29: '8d 0c 38',                    # FirstThunk + ImageBase
    0x448C2C: '8b 02',                       # first original thunk
    0x448C40: 'a9 00 00 00 80',           # imported-by-ordinal flag
    0x448C4B: '8b 14 19',                    # import-name thunk from adjusted pointer
    0x448C4E: '8b 75 08',                    # encoded input again
    0x448C53: '83 c6 05',                    # skip descriptor's 5-byte header
    0x448C56: '8d 7c 3a 02',                 # skip 2-byte import-name hint
    0x448C6A: '8a 4d f8',                    # encoded key0
    0x448C6D: '8a 1e',                       # encoded byte
    0x448C6F: '8a 45 f9',                    # encoded key1
    0x448C72: '2a d9',                       # subtract key
    0x448C74: '32 d8',                       # xor key
    0x448C7A: '8a 5d fa',                    # increment key0
    0x448C7F: '8a 5d fb',                    # increment key1
    0x448C8C: '8a 07',                       # actual import-name char
    0x448C94: '2b c3',                       # compare to decoded byte
    0x448CC7: '74 2b',                       # matching import name -> use IAT
    0x448CF4: '8b c1',                       # EAX = address of IAT slot
    0x448CFA: '85 c0',
    0x448CFE: '8b 00',                       # EAX = actual address in IAT
    0x448D04: '85 c0',
    0x448D08: '8a 0d d0 13 4a 00',        # first byte of encoded descriptor #0
    0x448D15: '8b 75 08',                    # caller's encoded descriptor
    0x448D1E: '3a 1e',                       # compare to descriptor table raw bytes
    0x448D47: '8a 4f 4c',                    # pointer stride 76 (next record)
    0x448D4A: '83 c7 4c',                    # advance to next record
    0x448D5E: '8b 4f 30',                    # pointer from descriptor+0x30
    0x448D61: '8b 75 dc',                    # caller's saved first DWORD / mask
    0x448D64: '33 ce',                       # decode expected pointer
    0x448D66: '2b c1',                       # actual IAT pointer - expected pointer
    0x448D6F: '33 c0',                       # no-match -> zero
}


def checked_layout_pair(cd: bytes, gog: bytes):
    a, b = layout(cd), layout(gog)
    if (a['.text'][:4], b['.text'][:4]) != (
        (0x1000, 0x9A1D0, 0x9A200, 0x400),
        (0x1000, 0x9B000, 0x9B000, 0x1000),
    ):
        raise ValueError('Unexpected original/GOG active .text placement')
    if a['.text'][4] & 0x20000000 == 0 or b['.text'][4] & 0x20000000 == 0:
        raise ValueError('Missing executable .text')
    return a, b


def raw_rel32_call_sites(section: bytes, base_va: int, target_va: int) -> list[int]:
    """Exhaustive raw E8 rel32 matches. Zero matches is a strong negative;
    positive matches still require instruction-boundary disassembly.
    """
    if not 0 <= base_va <= 0xffffffff or not 0 <= target_va <= 0xffffffff:
        raise ValueError('Invalid 32-bit VA')
    matches=[]
    for i in range(len(section)-4):
        if section[i] != 0xe8:
            continue
        delta=struct.unpack_from('<i',section,i+1)[0]
        if (base_va+i+5+delta)&0xffffffff == target_va:
            matches.append(base_va+i)
    return matches


def pe_imports(data: bytes, sections: dict) -> dict[str, dict[str, int]]:
    """Bounded PE32 import-name/IAT-RVA inventory, no runtime dereferencing."""
    nt=struct.unpack_from('<I',data,0x3c)[0]
    o=nt+24
    count=struct.unpack_from('<I',data,o+92)[0]
    if count < 2:
        raise ValueError('Missing import data directory')
    directory_rva,directory_size=struct.unpack_from('<II',data,o+96+8)
    if not directory_rva or not 20<=directory_size<=4096:
        raise ValueError('Bad import directory bounds')
    def at(rva: int, n: int) -> bytes:
        if not 0<rva<=0xFFFFFFFF:
            raise ValueError('Bad import RVA')
        return raw_at(data,sections,0x400000+rva,n)
    def zstring(rva: int, limit=128) -> str:
        b=bytearray()
        for j in range(limit):
            v=at(rva+j,1)[0]
            if v==0:
                if not b:
                    raise ValueError('Empty imported name')
                return b.decode('ascii')
            if not 0x21<=v<=0x7e:
                raise ValueError('Nonprintable imported name')
            b.append(v)
        raise ValueError('Unterminated imported name')
    imports={}
    terminator=False
    for di in range(min(directory_size//20,64)):
        row=at(directory_rva+20*di,20)
        if row == bytes(20):
            terminator=True
            break
        oft,timestamp,forwarder,dllname,ft=struct.unpack('<IIIII',row)
        if not (dllname and ft):
            raise ValueError('Truncated import descriptor')
        module=zstring(dllname)
        thunks=oft or ft
        for i in range(1024):
            entry=struct.unpack('<I',at(thunks+4*i,4))[0]
            if not entry:
                break
            if entry&0x80000000:
                continue  # imported by ordinal, cannot compare to encoded name
            name=zstring(entry+2)
            if name in imports:
                raise ValueError('Unexpected duplicated imported export name')
            imports[name]={'iat_va':0x400000+ft+4*i,'module':module}
        else:
            raise ValueError('Unterminated import thunk list')
    if not terminator:
        raise ValueError('Missing PE import directory terminator')
    return imports


def pointer_delta(actual: int | None, expected: int | None,
                  encoded_descriptor_found: bool) -> int:
    """Simplified, explicitly conservative *post-lookup* return model.

    The original function has additional early failures, so this is not an
    emulator of the full function. Input is synthetic, never game memory.
    """
    if not encoded_descriptor_found or actual is None or expected is None:
        return 0
    if not 0 <= actual <= 0xFFFFFFFF or not 0 <= expected <= 0xFFFFFFFF:
        raise ValueError('Only unsigned 32-bit addresses are supported')
    return (actual - expected) & 0xFFFFFFFF


def inspect_structure(cd: bytes, gog: bytes) -> dict:
    a, b = checked_layout_pair(cd, gog)
    for raw, pe in ((cd, a), (gog, b)):
        require(raw, pe, CALLBACK_INSTALL_VA,
                bytes.fromhex('c7 40 30 b0 8a 44 00'))
        call_target(raw, pe, 0x4674C8, 0x467130)
        call_target(raw, pe, 0x47B01B, 0x467130)
    # The old routine and its registration entrypoint are separate facts.
    for va, opcode in SOURCE_INSTRUCTIONS.items():
        require(cd, a, va, bytes.fromhex(opcode))
    retail_body = raw_at(cd, a, HANDLER_VA, HANDLER_END-HANDLER_VA)
    gog_body = raw_at(gog, b, HANDLER_VA, HANDLER_END-HANDLER_VA)
    if hashlib.sha256(retail_body).hexdigest() != RETAIL_HANDLER_SHA256:
        raise ValueError('Unexpected original IAT verifier body')
    if hashlib.sha256(gog_body).hexdigest() != GOG_HANDLER_SHA256:
        raise ValueError('Unexpected GOG replacement body')
    if gog_body != b'\x33\xc0\xc3' + b'\xcc'*(len(gog_body)-3):
        raise ValueError('GOG IAT check does not reduce to return 0')
    names = {}
    for idx in range(RECORD_COUNT):
        addr = RECORD_BASE + RECORD_STRIDE*idx
        cd_rec = raw_at(cd, a, addr, RECORD_STRIDE)
        gog_rec = raw_at(gog, b, addr, RECORD_STRIDE)
        if cd_rec != gog_rec:
            raise ValueError(f'Descriptor #{idx} changed in GOG')
        name = encoded_export(cd_rec)
        names[idx] = name
    unique_references={}
    for label,data,pe in (('retail',cd,a),('gog',gog,b)):
        start,vsize,rsize,roff,flags=pe['.text']
        active=data[roff:roff+rsize]
        ptr=struct.pack('<I',HANDLER_VA)
        refs=[];pos=0
        while True:
            found=active.find(ptr,pos)
            if found<0:break
            refs.append(0x400000+start+found)
            pos=found+1
        if refs != [0x4671F7]:
            raise ValueError(f'Unexpected {label} direct callback pointer literals')
        direct=raw_rel32_call_sites(active,0x400000+start,HANDLER_VA)
        if direct:
            raise ValueError(f'New raw E8 direct call to handler in {label}')
        unique_references[label]={'callback_pointer_operand_va':'0x4671F7',
                                  'direct_rel32_call_sites':0,
                                  'exact_literal_occurrences_in_active_text':len(refs)}
    imported={}
    for label,data,pe in (('retail',cd,a),('gog',gog,b)):
        imports=pe_imports(data,pe)
        if len(imports)!=163:
            raise ValueError(f'Unexpected {label} import-name count')
        relevant={i:name for i,name in names.items() if name in imports}
        if len(relevant)!=18:
            raise ValueError(f'Unexpected {label} potentially checked IAT functions')
        if {imports[name]['module'].lower() for name in relevant.values()} != {'kernel32.dll'}:
            raise ValueError('Expected candidate IAT descriptor subset to be KERNEL32')
        # This is a *static input restriction*, not which descriptor an
        # actual protected script will ask about at runtime.
        imported[label]={'named_import_count':len(imports),
                         'descriptor_names_also_present_in_IAT':len(relevant),
                         'candidate_imports_only_kernel32':True,
                         'descriptor_indices_with_named_IAT_entries':sorted(relevant),
                         'possible_named_iat_targets':[
                             {'descriptor_index':i, 'api':name,
                              'iat_va':f"0x{imports[name]['iat_va']:08X}"}
                             for i,name in sorted(relevant.items())]}
    if pe_imports(cd,a) != pe_imports(gog,b):
        raise ValueError('Original and GOG import directory contents diverge')
    if names[0] != 'GetModuleHandleA':
        raise ValueError('Unexpected bootstrap export descriptor')
    if raw_at(cd, a, 0x4A1E7C, 4) != b'\x00'*4:
        raise ValueError('Descriptor terminator changed')
    # Negative control: no runtime pointers are known from these zero-on-disk slots.
    return {
        'mode':'read_only_static',
        'exact_samples_verified_by_wrapper':False,
        'callback_slot_offset_hex':'0x30',
        'install_va':'0x4671F4',
        'original_handler_va':'0x448AB0',
        'gog_handler_va':'0x448AB0',
        'body_span_length_bytes':HANDLER_END-HANDLER_VA,
        'original_handler_sha256':RETAIL_HANDLER_SHA256,
        'gog_handler_sha256':GOG_HANDLER_SHA256,
        'gog_handler_returns_zero':True,
        'gog_retains_original_callback_slot':True,
        'original_reads_pe_import_directory':True,
        'original_decodes_input_export_name_before_import_lookup':True,
        'original_checks_matched_import_against_encoded_masked_descriptor_pointer':True,
        'original_result_formula_if_both_lookups_succeed':'(actual_iat_pointer - expected_decoded_pointer) mod 2^32',
        'original_returns_zero_on_some_missing_lookup_paths':True,
        'runtime_target_export_name_known':False,
        'runtime_expected_pointer_known':False,
        'runtime_callback_execution_observed':False,
        'safedisc_driver_or_media_verdict_observed':False,
        'game_executable_modified':False,
        'direct_pointer_and_call_census':unique_references,
        'iat_name_intersection':imported,
        'record_count':RECORD_COUNT,
        'descriptor_stride_bytes':RECORD_STRIDE,
        'bootstrap_descriptor_zero_name':names[0],
        'module_descriptor_names_published':False,
        'proprietary_bytes_emitted':False,
    }


def audit(cd: bytes, gog: bytes) -> dict:
    if len(cd) != CD_SIZE or hashlib.sha256(cd).hexdigest() != CD_HASH:
        raise ValueError('Unknown original CD sample')
    if len(gog) != GOG_SIZE or hashlib.sha256(gog).hexdigest() != GOG_HASH:
        raise ValueError('Unknown GOG sample')
    report = inspect_structure(cd, gog)
    report['exact_samples_verified_by_wrapper'] = True
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail', type=Path, required=True)
    p.add_argument('--gog', type=Path, required=True)
    args = p.parse_args(argv)
    for path in (args.retail, args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
            p.error('Use a regular, bounded, non-symlink owner input')
    try:
        result = audit(args.retail.read_bytes(), args.gog.read_bytes())
    except (OSError, ValueError) as e:
        p.error(str(e))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())