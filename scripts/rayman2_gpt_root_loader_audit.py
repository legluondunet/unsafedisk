#!/usr/bin/env python3
"""Read-only Rayman2 GPT root pointer loader & GOG declared catalog audit.

Commercial game bytes are never emitted, decrypted or modified.
The manifest describes declared file sizes, not file contents.
"""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path
from rayman2_guard_provenance_audit import one, bytes_at, RETAIL_SHA, GOG_SHA

REGIONS = {
    0x403A64: (42, 'b98021fef241c8705ad7f2a35c0d99b1d2cdad762e4cc7f8b72eafc50d29cd08'),
    0x403B66: (103, '6ebb427b4b9487959a3d9d46958b0db019919962bee14715b9997d10052ec48f'),
    0x44CD60: (341, 'e739cba587ec2a36d67d8399df8936a8c9b4bfe04270fd002488cef16872b6db'),
    0x44CFA0: (30, '0df79c80faa9d7a5a3384756e67bbb0d1555fe59f555dc19a2a336d69826fd93'),
    0x44CFC0: (115, '253047a3e9accd8c52491ab9cd53b105f65f1ff19ee8eb1b2155c7d2a0cb0e3c'),
}
CALLS = {
    0x403A64: 0x492770, 0x403A74: 0x45FE70,
    0x403A81: 0x44CD60, 0x403A89: 0x44CFC0,
    0x403B66: 0x44CFC0, 0x403B70: 0x44CFC0,
    0x403BAC: 0x44CFC0, 0x403BB6: 0x44CFC0,
    0x44CFCC: 0x44CFA0,
}
ANCHORS = {
    0x403B75:'a3 d0 0f 50 00',
    0x403BB1:'a3 1c 6b 4a 00',
    0x44CD94:'a3 bc 49 51 00',
    0x44CFAF:'a1 bc 49 51 00',
    0x44CFB7:'ff 15 4c c0 49 00',
    0x44CFE7:'3b 02',
    0x44D01D:'03 04 8d e0 21 51 00',
    0x44D024:'83 c2 08',
    0x44D013:'8a 99 e0 17 51 00',
}
PATH_FORMAT = b'%s\\%s\\%s.gpt\0'


def rel32_target(site:int, op:bytes)->int:
    if len(op)!=5 or op[0]!=0xe8:
        raise ValueError('expected CALL E8 rel32')
    return site+5+struct.unpack_from('<i',op,1)[0]


def resolve_word(raw:int, entry:tuple[int,int,int]|None, enabled:dict[int,bool], bases:dict[int,int]):
    """Synthetic model for one matching eight-byte fixup record.

    entry=(matched_word, key_byte_4, key_byte_5). Actual tables come
    from loaded runtime resources and are NOT present in owner EXE files.
    """
    if not isinstance(raw,int) or not 0<=raw<2**32:
        raise ValueError('raw must be a uint32')
    if entry is None:
        return raw,False
    if not isinstance(entry,tuple) or len(entry)!=3:
        raise ValueError('expected (tag,group,subindex) tuple')
    tag,a,b=entry
    if not all(isinstance(v,int) for v in entry) or not (0<=tag<2**32 and 0<=a<256 and 0<=b<256):
        raise ValueError('fixup record malformed')
    if tag!=raw:
        return raw,False
    i=a*10+b
    # Runtime code has no checked bound. This analysis helper deliberately
    # rejects indices that would pass the observed 2560-byte flag array.
    if i>=0xA00:
        raise ValueError('potentially out-of-range relocation flag index')
    if enabled.get(i,False):
        if i not in bases or not isinstance(bases[i],int) or not 0<=bases[i]<2**32:
            raise ValueError('active relocation base unknown')
        raw=(raw+bases[i])&0xffffffff
    return raw,True


def catalog(gog:bytes,s:dict):
    sec=s['.extra2'];pos=sec['file_offset'];end=pos+sec['raw_size'];files={};count=0
    while True:
        if pos+8>end:raise ValueError('missing manifest sentinel')
        length,n=struct.unpack_from('<II',gog,pos)
        if (length,n)==(0xffffffff,0):break
        if not 1<=n<=256 or pos+8+n>end:
            raise ValueError('invalid virtual manifest record size')
        name=gog[pos+8:pos+8+n]
        if name[-1:]!=b'\0' or b'\0' in name[:-1]:
            raise ValueError('malformed null-terminated filename')
        try:key=name[:-1].decode('ascii')
        except UnicodeDecodeError as ex:raise ValueError('non-ASCII filename') from ex
        if key in files:raise ValueError('duplicate file name')
        files[key]=(count,length)
        pos+=8+n;count+=1
        if count>4000:raise ValueError('too many virtual records')
    return files


def inspect(retail:bytes,gog:bytes)->dict:
    rs,_=one(retail,RETAIL_SHA);gs,_=one(gog,GOG_SHA)
    for va,(n,digest) in REGIONS.items():
        a=bytes_at(retail,rs,va,n)
        if hashlib.sha256(a).hexdigest()!=digest or a!=bytes_at(gog,gs,va,n):
            raise ValueError(f'changed original/GOG loader region {va:#x}')
    for va,target in CALLS.items():
        for program,sections in ((retail,rs),(gog,gs)):
            if rel32_target(va,bytes_at(program,sections,va,5))!=target:
                raise ValueError(f'changed loader call {va:#x}')
    for va,hexbytes in ANCHORS.items():
        expected=bytes.fromhex(hexbytes)
        for program,sections in ((retail,rs),(gog,gs)):
            if bytes_at(program,sections,va,len(expected))!=expected:
                raise ValueError(f'changed instruction {va:#x}')
    for program,sections in ((retail,rs),(gog,gs)):
        if bytes_at(program,sections,0x49F334,len(PATH_FORMAT))!=PATH_FORMAT:
            raise ValueError('unexpected GPT path pattern')
    files=catalog(gog,gs)
    groups={ext:{name[:-4]:(index,length) for name,(index,length) in files.items() if name.endswith('.'+ext)}
            for ext in ('GPT','PTX','SNA','SND','DSB')}
    if len(files)!=3716 or [len(groups[k]) for k in ('GPT','PTX','SNA','SND','DSB')]!=[71]*5:
        raise ValueError('changed GOG virtual catalog counts')
    gpts=groups['GPT'];stems=set(gpts)
    if any(length%4 for index,length in gpts.values()):
        raise ValueError('unexpected non-DWORD-aligned declared GPT size')
    if sum(n for i,n in gpts.values())!=59428300:
        raise ValueError('unexpected declared GPT size total')
    for ext in ('PTX','SNA','SND'):
        if set(groups[ext])!=stems:raise ValueError('GPT companion discrepancy')
    dsb_missing=sorted(stems-set(groups['DSB']))
    dsb_extra=sorted(set(groups['DSB'])-stems)
    if dsb_missing!=['DATA\\WORLD\\LEVELS\\FIX'] or dsb_extra!=['DATA\\GAME']:
        raise ValueError('unexpected DSB exception')
    return {
        'retail_sha256':RETAIL_SHA,'gog_sha256':GOG_SHA,
        'identical_original_and_GOG_loader_regions':len(REGIONS),
        'identical_original_and_GOG_rel32_calls':len(CALLS),
        'raw_gpt_filename_pattern':'%s\\%s\\%s.gpt',
        'file_reading_function':'0x0044CFA0',
        'file_stream_handle_global':'0x005149BC',
        'relocation_reader_va':'0x0044CFC0',
        'runtime_list_root_writes':{'0x004A6B1C':'0x00403BB1','0x00500FD0':'0x00403B75'},
        'conditional_fixup_word_match':True,
        'fixup_index_formula':'10*byte4 + byte5',
        'fixup_flag_array':'0x005117E0',
        'fixup_base_array':'0x005121E0',
        'gog_manifest_records':len(files),
        'gpt_declared_file_count':len(gpts),
        'gpt_declared_total_bytes':sum(n for i,n in gpts.values()),
        'all_gpt_declared_sizes_multiple_of_four':True,
        'companion_counts':{k:len(v) for k,v in groups.items()},
        'dsb_missing_gpt_stems':dsb_missing,
        'dsb_without_gpt_stems':dsb_extra,
        'example_files':[
            {'name':name+'.GPT','manifest_record_index':index,'declared_size':length}
            for name,(index,length) in list(gpts.items())[:5]],
        'actual_gpt_bytes_available':False,
        'authenticated_safedisc_decryption_proven':False,
        'retail_executable_decrypted':False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    a=p.parse_args()
    for path in (a.retail,a.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size>2_000_000:
            p.error('expected bounded regular, non-symlink input')
    print(json.dumps(inspect(a.retail.read_bytes(),a.gog.read_bytes()),indent=2))


if __name__=='__main__':main()
