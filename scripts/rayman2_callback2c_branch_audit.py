#!/usr/bin/env python3
"""Verify Rayman 2 callback +0x2c's Toolhelp-vs-PSAPI bridge.

Owner exact-SHA samples only. Static read-only *code provenance*, NOT a
SafeDisc verdict, unpacker, runtime execution, or patch recipe. Emits JSON
metadata only and never game bytes. GOG is a modified edition, not a
pristine decrypted retail reference.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

CD_HASH = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_HASH = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
CD_SIZE = 676352
GOG_SIZE = 1468928
IMGBASE = 0x400000
GUARD = 0x5113EC
BACKEND_FLAG = 0x510BF4
EXPORTS = {
    2:'GetCurrentProcess', 19:'CreateToolhelp32Snapshot',
    20:'Process32First', 21:'Process32Next',
    22:'Module32First', 23:'Module32Next',
    24:'EnumProcesses', 25:'EnumProcessModules',
}


def layout(b: bytes) -> dict:
    if len(b)<0x300 or b[:2]!=b'MZ':
        raise ValueError('Not a PE32 file')
    nt=struct.unpack_from('<I',b,0x3c)[0]
    if nt<0x40 or nt+24>len(b) or b[nt:nt+4]!=b'PE\0\0':
        raise ValueError('Truncated/invalid PE header')
    if struct.unpack_from('<H',b,nt+4)[0]!=0x14c:
        raise ValueError('Not PE x86')
    n=struct.unpack_from('<H',b,nt+6)[0]
    opt=struct.unpack_from('<H',b,nt+20)[0]
    if not 2<=n<=24 or opt<0xe0 or nt+24+opt+40*n>len(b):
        raise ValueError('Unexpected PE section table')
    o=nt+24
    if struct.unpack_from('<H',b,o)[0]!=0x10b or struct.unpack_from('<I',b,o+28)[0]!=IMGBASE:
        raise ValueError('Not fixed-imagebase PE32')
    ep=struct.unpack_from('<I',b,o+16)[0]
    if ep!=0x5fcc0:
        raise ValueError('Unexpected executable entrypoint')
    sections={}
    for i in range(n):
        at=o+opt+40*i
        name=b[at:at+8].rstrip(b'\0').decode('ascii','strict')
        vsize,rva,rsize,roff=struct.unpack_from('<IIII',b,at+8)
        flags=struct.unpack_from('<I',b,at+36)[0]
        if name in sections or roff+rsize>len(b) or vsize==0:
            raise ValueError('Overlapping/unbacked section')
        sections[name]=(rva,vsize,rsize,roff,flags)
    if '.text' not in sections or '.data' not in sections:
        raise ValueError('Missing active executable/data section')
    if not sections['.text'][4] & 0x20000000:
        raise ValueError('Non-executable .text')
    return sections


def raw_at(data:bytes, sections:dict, va:int, size:int) -> bytes:
    if not 0<size<4096:
        raise ValueError('Bad read length')
    rva=va-IMGBASE
    for name,(start,vsize,rsize,roff,flags) in sections.items():
        off=rva-start
        if 0<=off and off+size<=min(vsize,rsize):
            return data[roff+off:roff+off+size]
    raise ValueError(f'Non-file-backed VA 0x{va:x}')


def require(data:bytes, sections:dict, va:int, expected:bytes):
    if raw_at(data,sections,va,len(expected))!=expected:
        raise ValueError(f'Unexpected opcode/data at VA 0x{va:08x}')


def call_target(data:bytes, sections:dict, site:int, target:int):
    expected=b'\xe8'+struct.pack('<i',target-site-5)
    require(data,sections,site,expected)


def encoded_export(b:bytes) -> str:
    if len(b)!=76:
        raise ValueError('Invalid 76-byte record')
    sub,key,dsub,dkey,n=b[:5]
    if not 1<=n<=43:
        raise ValueError('Bad masked name length')
    out=bytearray()
    for v in b[5:5+n]:
        out.append(((v-sub)&255)^key)
        sub=(sub+dsub)&255; key=(key+dkey)&255
    if any(not 0x21<=x<=0x7e for x in out):
        raise ValueError('Bad export name encoding')
    if b[0x30:0x34]!=b'\0'*4:
        raise ValueError('On-disk runtime API pointer unexpectedly nonzero')
    return out.decode('ascii')


def inspect_structure(cd:bytes,gog:bytes) -> dict:
    a,b=layout(cd),layout(gog)
    if (a['.text'][:3],b['.text'][:3])!=((0x1000,0x9a1d0,0x9a200),(0x1000,0x9b000,0x9b000)):
        raise ValueError('Unexpected original or GOG active text span')
    if (a['.text'][3],b['.text'][3])!=(0x400,0x1000):
        raise ValueError('Unexpected PE raw section mapping')
    # The caller is not direct: an unmodified 16-entry callback vector
    # installs local function VA at slot 0x2C for both build variants.
    for data,pe in ((cd,a),(gog,b)):
        require(data,pe,0x4671EB,bytes.fromhex('c7 40 2c e0 8d 44 00'))
        call_target(data,pe,0x4674C8,0x467130)
        call_target(data,pe,0x47B01B,0x467130)
    # GOG's callback is not a normal PE import translation: it always
    # returns 1. The pointer in the vector itself is unchanged.
    require(gog,b,0x448DE0,bytes.fromhex('33 c0 40 c3'))
    require(cd,a,0x448DE0,bytes.fromhex('55 8b ec a1 ec 13 51 00 85 c0 74 18'))
    require(cd,a,0x448E04,bytes.fromhex('a1 f4 0b 51 00 85 c0 74 0e'))
    require(cd,a,0x448E0D,bytes.fromhex('8b 45 08 50'))
    call_target(cd,a,0x448E11,0x4481B0)
    require(cd,a,0x448E1B,bytes.fromhex('8b 4d 08 51'))
    call_target(cd,a,0x448E1F,0x448610)
    # A preserved cleanup path reads the same mode flag, then uses
    # the *normal* FreeLibrary IAT entry only if that flag is set.
    cleanup=bytes.fromhex('8b 0d f4 0b 51 00 85 c9 74 0a 8b 40 08 50 ff 15 80 c0 49 00')
    for data,pe in ((cd,a),(gog,b)):
        require(data,pe,0x4494C7,cleanup)
    # Startup's original 'choose provider' routine is GOG-nooped, while
    # no proof is claimed about its runtime conditions.
    require(cd,a,0x447DE0,bytes.fromhex('a1 ec 13 51 00 53 56 57 85 c0'))
    require(gog,b,0x447DE0,b'\xc3')
    flag_writes={0x447F4F:1,0x448067:0,0x448077:1}
    for va,value in flag_writes.items():
        require(cd,a,va,b'\xc7\x05'+struct.pack('<II',BACKEND_FLAG,value))
    # Verify all 5 guarded prerequisites at the exact original instruction
    # sites, including branches to the same fallback entry.
    checks=[(0x447E04,0x447E0B,19),(0x447E11,0x447E18,20),
            (0x447E1E,0x447E25,21),(0x447E2B,0x447E32,22),
            (0x447E38,0x447E3F,23)]
    for read,branch,idx in checks:
        ptr=0x4A13D0+76*idx+48
        require(cd,a,read,b'\xa1'+struct.pack('<I',ptr)+b'\x85\xc0')
        disp=0x448075-(branch+6)
        require(cd,a,branch,b'\x0f\x84'+struct.pack('<i',disp))
    names={}
    for idx,name in EXPORTS.items():
        ptr=0x4A13D0+76*idx
        raw=raw_at(cd,a,ptr,76)
        if raw!=raw_at(gog,b,ptr,76):
            raise ValueError('GOG descriptor differs from original')
        got=encoded_export(raw)
        if got!=name:
            raise ValueError(f'Unexpected API name index {idx}: {got}')
        names[str(idx)]=got
    # Distinguish backend *provenances*, not their runtime success.
    require(cd,a,0x448257,bytes.fromhex('c7 46 01 6c 1b 4a 00'))  # pointer for #25
    require(cd,a,0x448266,bytes.fromhex('c7 46 07 3c 1b 4a 00'))  # mask #25
    require(cd,a,0x448653,bytes.fromhex('c6 82 a0 0e 51 00 a1'))  # toolhelp stub
    require(cd,a,0x44865A,bytes.fromhex('c7 82 a1 0e 51 00 a4 19 4a 00'))
    require(cd,a,0x44873D,bytes.fromhex('8b 0d 58 1a 4a 00'))  # #22 mask
    require(cd,a,0x448749,bytes.fromhex('8b 15 88 1a 4a 00'))  # #22 ptr
    require(cd,a,0x448835,bytes.fromhex('8b 0d a4 1a 4a 00'))  # #23 mask
    require(cd,a,0x448841,bytes.fromhex('8b 15 d4 1a 4a 00'))  # #23 ptr
    # Original backends walk PE export directories and count matches of
    # a decoded descriptor against each module's exported names. This is
    # not just an enumeration of PID strings, nor a proved DRM verdict.
    export_walker = {
        0x44834E:'8b 48 3c',             # PE e_lfanew
        0x448351:'8b 4c 01 78',          # PE export RVA
        0x44836F:'8b 51 20',             # AddressOfNames
        0x448372:'8b 79 1c',             # AddressOfFunctions
        0x448375:'8b 71 24',             # AddressOfNameOrdinals
        0x448378:'8b 49 18',             # NumberOfNames
        0x4483D7:'8a 1f',                # input encoded name byte
        0x4483DC:'2a d9',                # SUB BL, CL
        0x4483DE:'32 d8',                # XOR BL, AL
        0x4483F6:'8a 06',                # exported ASCII name byte
        0x4483FE:'2b c3',                # signed/equality difference
        0x448456:'ff 45 f0',             # PSAPI backend: matches++
        0x44846F:'8b 45 f0',             # PSAPI backend: return matches
        0x44881E:'ff 45 fc',             # Toolhelp backend: matches++
        0x448964:'8b 45 fc',             # Toolhelp backend: return matches
    }
    for site,raw in export_walker.items():
        require(cd,a,site,bytes.fromhex(raw))
    call_target(cd,a,0x44880E,0x448970)  # Toolhelp invokes export scanner
    return {
        'callback_pointer_slot_in_16_entry_vector':'0x2C',
        'vector_install_site':'0x4671EB',
        'retail_handler':'0x448DE0',
        'gog_handler':'0x448DE0',
        'original_0x448DE0_dispatch':{
            'guard_address':'0x5113EC','backend_flag_address':'0x510BF4',
            'flag_nonzero_calls':'0x4481B0',
            'flag_zero_calls':'0x448610',
        },
        'gog_0x448DE0_returns_constant':1,
        'flag_writes_in_original':{f'0x{va:08X}':v for va,v in flag_writes.items()},
        'five_toolhelp_export_presences_tested':[names[str(i)] for i in range(19,24)],
        'other_process_exports':{str(i):names[str(i)] for i in (2,24,25)},
        'flag_nonzero_backend_has_enumprocessmodules_stub':True,
        'flag_zero_backend_has_toolhelp_snapshot_and_module_walk':True,
        'retail_checks_masked_pe_export_names_across_loaded_modules':True,
        'retail_backend_result_is_match_count_not_constant':True,
        'gog_replaces_match_count_with_constant_one':True,
        'cleanup_free_library_import_slot':'0x49C080',
        'runtime_process_examination_witnessed':False,
        'safedisc_verdict_identified':False,
        'unprotected_exe_created':False,
    }


def audit(cd:bytes,gog:bytes)->dict:
    if len(cd)!=CD_SIZE or hashlib.sha256(cd).hexdigest()!=CD_HASH:
        raise ValueError('Unknown retail CD sample')
    if len(gog)!=GOG_SIZE or hashlib.sha256(gog).hexdigest()!=GOG_HASH:
        raise ValueError('Unknown GOG comparison sample')
    report=inspect_structure(cd,gog)
    report['sample_sha256_pinned']=True
    return report


def main()->None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    args=p.parse_args()
    for f in [args.retail,args.gog]:
        if f.is_symlink() or not f.is_file() or f.stat().st_size>2_000_000:
            p.error('Input must be a bounded ordinary file, not a symlink')
    try:
        print(json.dumps(audit(args.retail.read_bytes(),args.gog.read_bytes()),indent=2,sort_keys=True))
    except (OSError, ValueError) as exc:
        p.error(str(exc))

if __name__=='__main__':
    main()
