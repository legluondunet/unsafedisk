#!/usr/bin/env python3
"""Exact-hash, read-only inspection of Rayman 2 CD/GOG DAT file-read paths.

Code signatures are static observations, not execution traces, DRM attribution,
or proof that resource data is identical across editions. Does not patch files.
"""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path
from pe_import_xrefs import parse_headers, rva_file_offset, import_entries
from rayman2_cd_io_diff import safe_read
CD_HASH='7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_HASH='9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'


def region(data:bytes, head:dict, va:int, n:int)->bytes:
    if n < 1 or n > 256 or va < head['image_base']:
        raise ValueError('invalid VA span')
    off=rva_file_offset(head,va-head['image_base'],n,len(data))
    return data[off:off+n]


def want(data,head,va,expected:bytes):
    if region(data,head,va,len(expected)) != expected:
        raise ValueError(f'code signature mismatch at 0x{va:08X}')


def rel_call(site,target):
    return b'\xe8'+struct.pack('<i',target-site-5)


def derive_dat_word(header:bytes, indexed_word:int, index:int)->int:
    """Reconstruct the shared x86 arithmetic, not a SafeDisc key decoder.

    header: four little-endian unsigned DWORDs read from the chosen DAT
    at the prior (possibly nonzero) file position. The separate indexed
    word comes from 16 + 4*index bytes after that prior position, but
    only if both Win32 reads and both seeks succeed.
    """
    if len(header)!=16 or not 0<=indexed_word<2**32 or not 0<=index<65536:
        raise ValueError('invalid DAT header/index/word')
    a,b,c,d=struct.unpack('<4I',header)
    aa=(a+c*index)&0xffffffff
    bb=(b+d*index)&0xffffffff
    return ((indexed_word-aa)&0xffffffff)^bb


def analyze(cd:bytes,gog:bytes)->dict:
    if hashlib.sha256(cd).hexdigest() != CD_HASH:
        raise ValueError('retail executable hash mismatch')
    if hashlib.sha256(gog).hexdigest() != GOG_HASH:
        raise ValueError('GOG executable hash mismatch')
    ch,gh=parse_headers(cd),parse_headers(gog)
    for data,head in ((cd,ch),(gog,gh)):
        if not any(x['iat_va']==0x0049C04C and x['name']=='ReadFile'
                   and x['dll'].lower()=='kernel32.dll'
                   for x in import_entries(data,head)):
            raise ValueError('ReadFile import pointer not confirmed')
    # Both binaries retain an initial FILE_BEGIN seek to a runtime-computed
    # offset, a 16-byte read into four local DWORDs, then a FILE_CURRENT
    # seek of 4*index before the following 4-byte indexed read.
    for data,head,is_gog in ((cd,ch,False),(gog,gh,True)):
        want(data,head,0x44EE39,bytes.fromhex(
            'E8 72 10 01 00 8B D8 8B 35 54 17 51 00 0F AF 1D BC 17 51 00 03 DE'))
        want(data,head,0x44EEC3,bytes.fromhex('6A 00 6A 00 53 57'))
        want(data,head,0x44EEC9,(bytes.fromhex('FF 15 48 C0 49 00')
                                if is_gog else bytes.fromhex('FF D6')))
        want(data,head,0x44EF53,bytes.fromhex('6A 00 52 8D 45 E0 6A 10 50 57'))
        want(data,head,0x44EF5D,(bytes.fromhex('FF 15 4C C0 49 00')
                                if is_gog else bytes.fromhex('FF D6')))
        want(data,head,0x44EF7B,bytes.fromhex(
            '8B 5D FC 85 DB 76 1E 8B 55 E8 8B 4D E0 0F AF D3 '
            '03 CA 8B 55 EC 89 4D E0 8B 4D E4 8B C3 03 CA '
            '48 75 FB 89 4D E4'))
        want(data,head,0x44F009,bytes.fromhex(
            '6A 01 8D 14 9D 00 00 00 00 6A 00 52 57'))
        want(data,head,0x44F016,(bytes.fromhex('FF 15 48 C0 49 00')
                                if is_gog else bytes.fromhex('FF D6')))
    if not any(x['iat_va']==0x0049C048 and x['name']=='SetFilePointer'
               and x['dll'].lower()=='kernel32.dll'
               for x in import_entries(cd,ch)):
        raise ValueError('SetFilePointer import pointer not confirmed')
    # 4-byte extraction and transformation (common to both).
    want(cd,ch,0x44F0A6,b'\x6a\x04')
    want(gog,gh,0x44F0A6,b'\x6a\x04')
    want(cd,ch,0x44F0AA,b'\xff\xd6')
    want(gog,gh,0x44F0AA,bytes.fromhex('FF 15 4C C0 49 00'))
    common=region(cd,ch,0x44F0C8,0x3A)
    if common != region(gog,gh,0x44F0C8,0x3A):
        raise ValueError('unexpected 4-byte data transformation mismatch')
    want(cd,ch,0x44F0D4,bytes.fromhex('2B CB 33 CE 89 0A'))
    # First 512-byte read and seek are present in retail, 40 bytes of
    # ordinary NOP fill in GOG, with continuation to retained logic.
    want(cd,ch,0x44F11E,bytes.fromhex('68 00 02 00 00'))
    want(cd,ch,0x44F10D,rel_call(0x44F10D,0x44F380))
    want(cd,ch,0x44F125,rel_call(0x44F125,0x44E750))
    want(gog,gh,0x44F102,b'\x90'*0x28)
    # Original code adjusts a caller-owned word, GOG suppresses that store.
    want(cd,ch,0x44F133,bytes.fromhex('29 0E'))
    want(gog,gh,0x44F133,bytes.fromhex('90 90'))
    # 24-name selection vs LEVELS0.DAT, as previously confirmed.
    want(cd,ch,0x44F13A,bytes.fromhex('8B 14 9D 90 20 4A 00'))
    want(gog,gh,0x44F13A,bytes.fromhex('8B 15 90 20 4A 00 90'))
    # Second 512-byte read is bypassed after successful file open in GOG.
    want(cd,ch,0x44F1E5,bytes.fromhex('68 00 02 00 00'))
    want(cd,ch,0x44F1D4,rel_call(0x44F1D4,0x44F380))
    want(cd,ch,0x44F1EC,rel_call(0x44F1EC,0x44E750))
    want(gog,gh,0x44F1CC,bytes.fromhex('EB 23')+b'\xcc'*0x23)
    # These two caller-stack buffers are passed to ReadFile, but no
    # *additional direct EBP-displacement reference* occurs within this
    # function. This byte-level count is not a dynamic dataflow proof.
    start=rva_file_offset(ch,0x44EB40-ch['image_base'],1,len(cd))
    finish=rva_file_offset(ch,0x44F1FA-ch['image_base']-1,1,len(cd))+1
    function_code=cd[start:finish]
    for displacement in (0x334,0x534):
        if function_code.count(struct.pack('<i',-displacement)) != 1:
            raise ValueError('unexplained direct local-buffer displacement')
    return {
      'read_only':True,'exact_retail_gog_sha256':True,
      'runtime_flow_verified':False,'safedisc_removal_attributed':False,
      'initial_dat_seek':{'va':'0x0044EEC9','move_method':'FILE_BEGIN',
                          'offset':'runtime-computed base, not necessarily 0'},
      'preceding_header_read':{'va':'0x0044EF5D','requested_bytes':16,
                               'local_buffer':'[EBP-0x20]','four_dwords':'A,B,C,D',
                               'original':'generated indirect ReadFile',
                               'gog':'direct ReadFile IAT'},
      'indexed_word_seek':{'va':'0x0044F016','move_method':'FILE_CURRENT',
                           'distance':'4 * index',
                           'file_offset_if_successful':'base + 16 + 4 * index'},
      'indexed_word_decode':{'header_update':'A=(A+index*C) mod 2^32; B=(B+index*D) mod 2^32',
                             'result':'((indexed_word - A) mod 2^32) XOR B',
                             'semantics':'data decoding preserved identically in both EXEs, not established as SafeDisc cryptography'},
      'retail_512_read_buffers':{'first':'[EBP-0x334]','second':'[EBP-0x534]',
                                 'direct_encoded_stack_refs_each':1,
                                 'readfile_returns_explicitly_checked':False,
                                 'warning':'No further direct encoded references; indirect side effects and runtime behavior unverified'},
      'indexed_read':{'va':'0x0044F0AA','requested_bytes':4,
                    'retail':'generated ReadFile pointer','gog':'direct ReadFile IAT',
                    'following_58_bytes_identical':True,
                    'local_transform':'value=(indexed_word - corrected_A) XOR corrected_B; stored through caller pointer'},
      'retail_only_additional_reads':[
         {'va':'0x0044F125','requested_bytes':512,'corresponding_gog':'NOP span 0x0044F102..0x0044F129'},
         {'va':'0x0044F1EC','requested_bytes':512,'corresponding_gog':'bypassed by JMP 0x0044F1CC -> 0x0044F1F1'}],
      'retail_caller_word_subtraction_removed_by_gog':True,
      'gog_selects_first_dat_name':True,
      'not_proven':'Actual dynamic call path, file values, success of ReadFile, SafeDisc attribution, game-copy integrity semantics are unknown.'}


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--retail',type=Path,required=True)
    ap.add_argument('--gog',type=Path,required=True)
    args=ap.parse_args(argv)
    try: print(json.dumps(analyze(safe_read(args.retail),safe_read(args.gog)),indent=2))
    except (OSError,ValueError) as e: ap.exit(1,f'ERROR: {e}\n')
    return 0

if __name__=='__main__':raise SystemExit(main())
