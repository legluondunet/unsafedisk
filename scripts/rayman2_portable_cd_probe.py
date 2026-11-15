#!/usr/bin/env python3
"""Build a narrowly scoped, experimental Rayman 2 CD *path* diagnostic EXE.

The user must supply the ORIGINAL, SHA-locked CD Rayman2.exe, or the known
25-byte PE32-scanner-only derivative. No commercial EXE is distributed.

This is NOT a SafeDisc decoder, an authentication bypass guarantee, or a
playability claim. A real test may expose further game/DRM dependencies.
The program never writes to its input file and refuses existing output.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct

ORIGINAL_SHA = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
PE32_ONLY_SHA = 'f32133d9add18b37adf47ce4b3e475b641b697e2b7db77cfe7b47063da468703'
SIZE = 676352
PROBE_SHA = '6702ff583cb0ee1f1023cc4b334ef4dab3f737a0ee7f272fe31dd13a9f23ce71'

# Exact verified 25-byte original source and standalone PE32-only correction.
SCANNER_VA = 0x447C20
SCANNER_OLD = bytes.fromhex('83 C1 18 85 C9 74 50 8B 49 60 85 C9 74 49 03 CA 85 C9 74 43 8B 49 0C 03 CA')
SCANNER_FIXED = bytes.fromhex('83 C1 18 66 81 39 0B 01 75 4D 8B 49 60 85 C9 74 46 03 CA 8B 49 0C 03 CA 90')

# The zero-guard path enters this function at 0x448E5A. Preserve its
# prologue and guard at 0x448E30..0x448E59. New bytes explicitly write the
# relative-directory selector and restore EBP/ESP before RET.
VOLUME_BODY_VA = 0x448E5A
VOLUME_OLD = bytes.fromhex('8B 0D F0 0B 51 00 B8 5F 0B 4E 83')
VOLUME_RELATIVE = bytes.fromhex('B0 2E A2 D8 6A 4A 00 8B E5 5D C3')
VOLUME_SUCCESS_SELECTOR = 0x4A6AD8

# Five, not merely two: all original .data %-format strings with '%c:\\'.
# Changing just ':' -> '\\' yields a relative `.\\` prefix when the
# selector is '.', while preserving the original vararg arity and byte length.
# In particular, this diagnostic does NOT import GOG's different DAT code.
FORMATS = {
    0x49F394: b'%c:\\%s/%s/%s.%s',
    0x49F3A4: b'%c:\\%s/*',
    0x4A06D8: b'%c:\\%s',
    0x4A2264: b'%c:\\%s\\%s',
    0x4A2688: b'%c:\\',
}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def parse_sections(data: bytes) -> tuple[int, dict[str, dict]]:
    """Parse bounded, file-backed sections of a specific 32-bit PE image."""
    if len(data) != SIZE or data[:2] != b'MZ':
        raise ValueError('wrong size or DOS signature')
    nt = struct.unpack_from('<I', data, 0x3C)[0]
    if nt >= len(data)-256 or data[nt:nt+4] != b'PE\0\0':
        raise ValueError('bad PE signature')
    machine, count = struct.unpack_from('<HH', data, nt+4)
    opt_size = struct.unpack_from('<H', data, nt+20)[0]
    opt = nt + 24
    if machine != 0x14c or count != 3 or opt_size < 0xE0 or opt+opt_size > len(data):
        raise ValueError('unexpected architecture, sections or optional header')
    if struct.unpack_from('<H', data, opt)[0] != 0x10B:
        raise ValueError('not PE32')
    image_base = struct.unpack_from('<I', data, opt+28)[0]
    if image_base != 0x400000:
        raise ValueError('unexpected image base')
    sections = {}
    for i in range(count):
        o = opt+opt_size+40*i
        if o+40>len(data):
            raise ValueError('truncated section table')
        name = data[o:o+8].split(b'\0',1)[0].decode('ascii')
        virt_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', data, o+8)
        flags = struct.unpack_from('<I', data, o+36)[0]
        if name in sections or raw_offset+raw_size>len(data):
            raise ValueError('duplicate or out-of-range section')
        sections[name] = dict(rva=rva, virtual_size=virt_size, raw_size=raw_size,
                              raw_offset=raw_offset, flags=flags)
    if set(sections) != {'.text','.rdata','.data'}:
        raise ValueError('unexpected PE sections')
    if not sections['.text']['flags'] & 0x20000000 or not sections['.data']['flags'] & 0x80000000:
        raise ValueError('unexpected section permissions')
    return image_base, sections


def mapped_offset(data: bytes, va: int, length: int, section: str) -> int:
    if not isinstance(length, int) or length<=0:
        raise ValueError('invalid mapped length')
    base, sections = parse_sections(data)
    s = sections[section]
    rva = va-base
    if rva < s['rva'] or rva + length > s['rva'] + min(s['raw_size'],s['virtual_size']):
        raise ValueError(f'VA 0x{va:08X} not file-backed in {section}')
    return s['raw_offset'] + rva-s['rva']


def changed_bytes(old: bytes, new: bytes) -> int:
    if len(old)!=len(new):
        raise ValueError('changed PE size')
    return sum(a!=b for a,b in zip(old,new))


def ensure_original_patterns(original: bytes, pe32_only: bool) -> None:
    old_scanner = SCANNER_FIXED if pe32_only else SCANNER_OLD
    o = mapped_offset(original,SCANNER_VA,25,'.text')
    if original[o:o+25] != old_scanner:
        raise ValueError('PE32 module-scan pattern mismatch')
    o = mapped_offset(original,VOLUME_BODY_VA,11,'.text')
    if original[o:o+11] != VOLUME_OLD:
        raise ValueError('CD volume-init pattern mismatch')
    # Adjacent prologue and guard remain the retail originals.
    o = mapped_offset(original,0x448E30,17,'.text')
    if original[o:o+17] != bytes.fromhex('55 8B EC 81 EC EC 00 00 00 A1 EC 13 51 00 85 C0 74'):
        raise ValueError('CD scanner prologue or guard changed')
    o = mapped_offset(original,0x448E56,4,'.text')
    if original[o:o+4] != bytes.fromhex('8B E5 5D C3'):
        raise ValueError('CD volume function early-return epilogue differs')
    # Require EXACTLY five drive-root format strings in the original file-backed
    # .data, to avoid a silent failure caused by an unpatched sixth consumer.
    _,sects = parse_sections(original)
    s=sects['.data']; raw=original[s['raw_offset']:s['raw_offset']+s['raw_size']]
    expected=set(FORMATS)
    starts=[];cursor=0
    while (idx:=raw.find(b'%c:\\',cursor))!=-1:
        starts.append(0x400000 + s['rva'] + idx)
        cursor=idx+1
    if set(starts)!=expected or len(starts)!=5:
        raise ValueError(f'unexpected CD path pattern census: {starts!r}')
    for va,fmt in FORMATS.items():
        o = mapped_offset(original,va,len(fmt)+1,'.data')
        if original[o:o+len(fmt)+1] != fmt+b'\0':
            raise ValueError(f'unexpected format string at 0x{va:08X}')


def output_audit(original: bytes, patched: bytes, input_kind: str) -> dict:
    diffs=[]
    for i,(a,b) in enumerate(zip(original,patched)):
        if a!=b: diffs.append(i)
    if not diffs:
        raise ValueError('empty patch')
    allowed=set()
    for va,length,section in ([(SCANNER_VA,25,'.text')] if input_kind=='original' else []) + [
            (VOLUME_BODY_VA,11,'.text')]:
        off=mapped_offset(original,va,length,section)
        allowed.update(range(off,off+length))
    for va,fmt in FORMATS.items():
        allowed.add(mapped_offset(original,va+2,1,'.data'))
    if not set(diffs).issubset(allowed):
        raise ValueError('modification outside verified patch sites')
    return {
        'source_sha256':sha256(original),
        'source_kind':input_kind,
        'output_sha256':sha256(patched),
        'modified_byte_count':len(diffs),
        'modified_regions':[{'va':f'0x{va:08X}','length':length,'section':section} for
            va,length,section in ([(SCANNER_VA,25,'.text')] if input_kind=='original' else []) +
            [(VOLUME_BODY_VA,11,'.text')] + [(va+2,1,'.data') for va in FORMATS]],
        'format_count':len(FORMATS),
        'CD_DAT_readers_modified':False,
        'SafeDisc_authentication_removed_proven':False,
        'playability_without_CD_proven':False,
    }


def patch(data: bytes) -> tuple[bytes, dict]:
    if len(data)!=SIZE:
        raise ValueError('wrong source file size')
    digest=sha256(data)
    if digest not in (ORIGINAL_SHA,PE32_ONLY_SHA):
        raise ValueError('source SHA-256 not recognized; refusing modify')
    kind = 'original' if digest==ORIGINAL_SHA else 'PE32-scanner-only'
    ensure_original_patterns(data, kind!='original')
    b=bytearray(data)
    if kind=='original':
        o = mapped_offset(data,SCANNER_VA,25,'.text')
        b[o:o+25] = SCANNER_FIXED
    o = mapped_offset(data,VOLUME_BODY_VA,11,'.text')
    b[o:o+11] = VOLUME_RELATIVE
    for va in FORMATS:
        o = mapped_offset(data,va+2,1,'.data')
        b[o] = ord('\\')
    result=bytes(b)
    if sha256(result)!=PROBE_SHA:
        raise ValueError('unexpected candidate output fingerprint')
    return result,output_audit(data,result,kind)


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('source',type=Path,help='exact original CD EXE or known PE32-only copy')
    p.add_argument('output',type=Path,help='NEW experimental output EXE path')
    p.add_argument('--dry-run',action='store_true',help='only verify input and report; do not write an EXE')
    args=p.parse_args()
    if args.source.is_symlink() or not args.source.is_file():
        p.error('source must be an existing regular file, not a symlink')
    if args.output.exists() or args.output.is_symlink():
        p.error('refusing to overwrite existing output or symlink')
    if args.source.stat().st_size!=SIZE:
        p.error('not a supported file size')
    try:
        data=args.source.read_bytes()
        binary,report=patch(data)
        if not args.dry_run:
            with args.output.open('xb') as f:
                f.write(binary)
    except (ValueError,OSError) as e:
        p.error(str(e))
    import json
    print(json.dumps(report,indent=2))
    print('Experimental logical-CD path diagnostic ONLY; no confirmed SafeDisc decryption.')

if __name__=='__main__':
    main()
