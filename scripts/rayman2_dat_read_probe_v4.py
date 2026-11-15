#!/usr/bin/env python3
"""Experimental Rayman 2 V4: isolate two original 512-byte DAT probe reads.

Source must be the exact SHA-locked V3 candidate. Create a NEW output file,
changing ONLY two code sites at VA 0x44F102 and 0x44F1CC. The first stage
neutralizes the original first SetFilePointer/ReadFile call sequence with NOPs;
the second adds a short jump over the original second SetFilePointer/ReadFile
sequence. This models two independently verified GOG modifications while
preserving the V3 path/selector/offset changes. GOG is not an unmodified retail
binary, and this V4 is a test hypothesis, not proven no-CD functionality.
"""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path

INPUT_SHA256 = '6df04e1c18d9318c9f8566a14018abc6f0e8dd84f7649eb4c411e81fabeb61f7'
OUTPUT_SHA256 = 'ef656c7a80272726508ec20aace94ddbaed655c8e25151c87e3d520abebcbbf0'
INPUT_SIZE=676352
FIRST_VA=0x44F102
FIRST_OLD=bytes.fromhex('8B 45 08 6A 00 6A 00 8B 08 51 57 E8 6E 02 00 00 8D 55 F0 6A 00 52 8D 85 CC FC FF FF 68 00 02 00 00 50 57 E8 26 F6 FF FF')
FIRST_NEW=b'\x90'*len(FIRST_OLD)
SECOND_VA=0x44F1CC
SECOND_OLD=bytes.fromhex('8B 0E')
SECOND_NEW=bytes.fromhex('EB 23')
TAIL_VA=0x44F1F1
TAIL_EXPECTED=bytes.fromhex('5B 8B C7 5E 5F 8B E5 5D C3')
FIRST_FOLLOW_VA=0x44F12A
FIRST_FOLLOW=bytes.fromhex('8B CB 57 0F AF CE 8B 75 08 90 90 E8 C6 93 FF FF 8B 15 90 20 4A 00 90')
SECOND_CALL_VA=0x44F1C0
SECOND_CALL=bytes.fromhex('E8 5B 00 00 00 8B F8 83 FF FF 74 BD')


def sha256(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()


def text_offset(data:bytes,va:int,n:int)->int:
    if len(data)!=INPUT_SIZE or data[:2]!=b'MZ': raise ValueError('source size or MZ invalid')
    nt=struct.unpack_from('<I',data,0x3c)[0]
    if nt>0x1000 or data[nt:nt+4]!=b'PE\0\0': raise ValueError('PE signature invalid')
    machine,count=struct.unpack_from('<HH',data,nt+4)
    optional_size=struct.unpack_from('<H',data,nt+20)[0]; opt=nt+24
    if machine!=0x14c or count!=3 or optional_size<0xe0 or opt+optional_size+count*40>len(data):
        raise ValueError('unexpected PE32 section structure')
    if struct.unpack_from('<H',data,opt)[0]!=0x10b or struct.unpack_from('<I',data,opt+28)[0]!=0x400000:
        raise ValueError('unexpected PE32 image base')
    for i in range(count):
        p=opt+optional_size+40*i
        if data[p:p+8].split(b'\0')[0]!=b'.text': continue
        virtual_size,rva,raw_size,raw=struct.unpack_from('<IIII',data,p+8)
        offset=va-0x400000-rva
        if offset<0 or offset+n>min(virtual_size,raw_size) or raw+offset+n>len(data):
            raise ValueError('patch beyond file-backed text section')
        return raw+offset
    raise ValueError('missing text section')


def anchored(data:bytes,va:int,want:bytes,label:str)->int:
    start=text_offset(data,va,len(want))
    if data[start:start+len(want)]!=want:
        raise ValueError('unexpected '+label+' code bytes')
    return start


def patch(data:bytes)->tuple[bytes,dict]:
    if sha256(data)!=INPUT_SHA256:
        raise ValueError('unknown input: V4 requires exact SHA-pinned Rayman2-portable-v3-offset-test.exe')
    first=anchored(data,FIRST_VA,FIRST_OLD,'first DAT read')
    second=anchored(data,SECOND_VA,SECOND_OLD,'second DAT read')
    anchored(data,FIRST_FOLLOW_VA,FIRST_FOLLOW,'V3 arithmetic and selector')
    anchored(data,SECOND_CALL_VA,SECOND_CALL,'second DAT open guard')
    anchored(data,TAIL_VA,TAIL_EXPECTED,'second DAT epilogue')
    if SECOND_VA+len(SECOND_NEW)+0x23 != TAIL_VA:
        raise ValueError('short jump does not end at original epilogue')
    if first+len(FIRST_OLD)>text_offset(data,FIRST_FOLLOW_VA,1):
        raise ValueError('first block reaches live arithmetic')
    out=bytearray(data)
    out[first:first+len(FIRST_OLD)]=FIRST_NEW
    out[second:second+len(SECOND_OLD)]=SECOND_NEW
    out=bytes(out)
    delta=[i for i,(a,b) in enumerate(zip(data,out)) if a!=b]
    if delta!=[i for i in range(first,first+len(FIRST_OLD)) if data[i]!=0x90]+[second,second+1]:
        raise ValueError('V4 touches bytes outside two DAT-read sites')
    if sha256(out)!=OUTPUT_SHA256:
        raise ValueError('unexpected V4 output SHA-256')
    report={
        'experiment':'V4: isolate two extra retail 512-byte DAT reads, as skipped in modified GOG',
        'source_sha256':sha256(data),'output_sha256':sha256(out),
        'file_size':len(out),'changed_byte_count':len(delta),
        'first_site_va':hex(FIRST_VA),'first_bytes':len(FIRST_OLD),
        'second_site_va':hex(SECOND_VA),'second_bytes':len(SECOND_OLD),
        'jump_target_va':hex(TAIL_VA),
        'v3_relative_paths_and_PE32_fix_preserved':True,
        'v3_fixed_DAT_name_and_offset_subtraction_NOPS_preserved':True,
        'original_sixteen_and_four_byte_header_reads_preserved':True,
        'second_DAT_CreateFileA_and_error_handling_preserved':True,
        'no_cd_gameplay_not_yet_verified':True,
        'physical_SafeDisc_decryption_not_demonstrated':True,
    }
    return out,report


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=Path,help='exact Rayman2-portable-v3-offset-test.exe')
    ap.add_argument('output',type=Path,help='new output filename (will not overwrite)')
    ap.add_argument('--dry-run',action='store_true',help='check input and candidate without writing')
    args=ap.parse_args(argv)
    if args.source.is_symlink() or not args.source.is_file():
        ap.error('input must be a regular file, not a symlink')
    if args.output.exists() or args.output.is_symlink() or args.source.resolve()==args.output.resolve():
        ap.error('refusing to overwrite existing file or original')
    try:
        out,report=patch(args.source.read_bytes())
        if not args.dry_run:
            with args.output.open('xb') as f:f.write(out)
    except (ValueError,OSError) as ex:
        ap.error(str(ex))
    print(json.dumps(report,indent=2))
    print('V4 remains experimental. Retain PE32 CD original and V3 unchanged.')
    return 0

if __name__=='__main__': raise SystemExit(main())
