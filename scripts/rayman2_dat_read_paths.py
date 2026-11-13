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
    return {
      'read_only':True,'exact_retail_gog_sha256':True,
      'runtime_flow_verified':False,'safedisc_removal_attributed':False,
      'first_read':{'va':'0x0044F0AA','requested_bytes':4,
                    'retail':'generated ReadFile pointer','gog':'direct ReadFile IAT',
                    'following_58_bytes_identical':True,
                    'local_transform':'value=(first_u32 - local_u32) XOR another_local_u32; stored through caller pointer'},
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
