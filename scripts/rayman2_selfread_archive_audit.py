#!/usr/bin/env python3
"""Static, read-only analysis of GOG's archived CD code and two module-base redirects.

Inputs are exact owner-supplied Rayman 2 PE32 files; this tool does not execute,
patch, decrypt, or export portions of the game executable. GOG is not a clean
retail-unwrapped binary, and observed patterns do not prove runtime reachability.
"""
import argparse
import hashlib
import json
import os
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

EXPECTED = {
    'cd': (676352, '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'),
    'gog': (1468928, '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'),
}


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    vsize: int
    raw_offset: int
    raw_size: int
    flags: int


def locked_read(path: Path, kind: str) -> bytes:
    size, sha = EXPECTED[kind]
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        pre = os.fstat(fd)
        if not stat.S_ISREG(pre.st_mode) or pre.st_size != size:
            raise ValueError('unrecognized size or nonregular file')
        b = os.read(fd, size + 1)
        post = os.fstat(fd)
        if (len(b) != size or (pre.st_dev, pre.st_ino, pre.st_size, pre.st_mtime_ns)
                != (post.st_dev, post.st_ino, post.st_size, post.st_mtime_ns)):
            raise ValueError('file changed while reading')
    finally:
        os.close(fd)
    if hashlib.sha256(b).hexdigest() != sha:
        raise ValueError('unrecognized SHA-256 input')
    return b


def sections(pe: bytes) -> tuple[int, dict[str, Section]]:
    if len(pe) < 0x100 or pe[:2] != b'MZ':
        raise ValueError('not MZ')
    nt, = struct.unpack_from('<I', pe, 0x3c)
    if nt < 0x40 or nt + 24 > len(pe) or pe[nt:nt+4] != b'PE\0\0':
        raise ValueError('invalid PE header')
    machine, count = struct.unpack_from('<HH', pe, nt + 4)
    opt_size, = struct.unpack_from('<H', pe, nt + 20)
    optional = nt + 24
    end_table = optional + opt_size + 40 * count
    if machine != 0x14c or not 1 <= count <= 32 or not 0x60 <= opt_size <= 0x400 or end_table > len(pe):
        raise ValueError('invalid x86 section table')
    magic, = struct.unpack_from('<H', pe, optional)
    base, = struct.unpack_from('<I', pe, optional + 28)
    if magic != 0x10b:
        raise ValueError('not PE32')
    result = {}
    for i in range(count):
        off = optional + opt_size + i * 40
        name = pe[off:off+8].split(b'\0',1)[0].decode('ascii')
        vsize,rva,rsize,roff = struct.unpack_from('<IIII',pe,off+8)
        flags, = struct.unpack_from('<I',pe,off+36)
        if not name or name in result or roff + rsize > len(pe):
            raise ValueError('duplicate section or malformed raw extent')
        result[name] = Section(name,rva,vsize,roff,rsize,flags)
    return base, result


def by_rva(data: bytes, table: dict[str,Section], rva: int, size: int) -> bytes:
    if not 0 < size <= 2_000_000:
        raise ValueError('invalid requested length')
    matches=[s for s in table.values() if s.rva <= rva and rva+size <= s.rva+s.raw_size]
    if len(matches) != 1:
        raise ValueError('requested RVA not uniquely backed by a section')
    s=matches[0]
    o=s.raw_offset+rva-s.rva
    return data[o:o+size]


def archive_relation(cd_code: bytes, extra: bytes, text_rva: int) -> dict:
    if text_rva <= 0 or len(extra) < text_rva + len(cd_code):
        raise ValueError('missing aligned archival region')
    if any(extra[:text_rva]):
        raise ValueError('unexpected nonzero archive prefix')
    if extra[text_rva:text_rva+len(cd_code)] != cd_code:
        raise ValueError('GOG archive is not an exact copy of CD .text')
    if any(extra[text_rva+len(cd_code):]):
        raise ValueError('unexpected nonzero archive trailer')
    return {'original_code_length':len(cd_code),
            'original_code_sha256':hashlib.sha256(cd_code).hexdigest(),
            'archive_padding_prefix':text_rva,
            'archive_padding_suffix':len(extra)-text_rva-len(cd_code),
            'exact_original_text_bytes':True}


def assess(cd: bytes, gog: bytes) -> dict:
    cb,cs=sections(cd); gb,gs=sections(gog)
    if cb != gb or cb != 0x400000:
        raise ValueError('unexpected different image base')
    t=cs['.text']; extra=gs['.extra']
    if t.rva != 0x1000 or t.raw_size != 0x9a200:
        raise ValueError('unexpected original text mapping')
    if extra.rva != 0x117000 or extra.raw_size != 0x9c000 or extra.flags & 0x20000000:
        raise ValueError('unexpected GOG nonexecutable .extra mapping')
    code=by_rva(cd,cs,t.rva,t.raw_size)
    ext=by_rva(gog,gs,extra.rva,extra.raw_size)
    relationship=archive_relation(code,ext,t.rva)
    # Search only active GOG .text; the non-executable archival copy must not count.
    active=by_rva(gog,gs,gs['.text'].rva,gs['.text'].raw_size)
    module_literal=struct.pack('<I', gb+extra.rva)
    occurrences=[gb+gs['.text'].rva+i for i in range(len(active)-3)
                 if active[i:i+4] == module_literal]
    if occurrences != [0x470052, 0x47b1c4]:
        raise ValueError('unexpected archive base references in active GOG code')
    redirects=[]
    for va,call_va,continuation,storage,reader in [
        (0x470051, 0x4700ae, 0x4700b3, 0x4700b3, None),
        (0x47b1c3, 0x47b220, 0x47b225, 0x47b225, 0x47b2a9),
    ]:
        rva=va-cb
        if by_rva(cd,cs,rva,6)!=bytes.fromhex('99 b9 55 04 00 00'):
            raise ValueError(f'unexpected original IDIV generator at {hex(va)}')
        patch=by_rva(gog,gs,rva,7)
        if patch != b'\xb8'+struct.pack('<I',gb+extra.rva)+b'\xeb\x5b':
            raise ValueError(f'unexpected GOG archive redirect at {hex(va)}')
        if va+7+struct.unpack('<b',patch[-1:])[0]!=continuation:
            raise ValueError('GOG short jump does not reach expected continuation')
        if by_rva(cd,cs,call_va-cb,2)!=b'\xff\xd6' or by_rva(cd,cs,call_va-2-cb,2)!=b'\x6a\x00':
            raise ValueError('original does not call generated module lookup with null argument')
        storage_opcode=bytes.fromhex('89 44 24 14' if storage==0x4700b3 else '89 44 24 10')
        if by_rva(cd,cs,storage-cb,4)!=storage_opcode or by_rva(gog,gs,storage-gb,4)!=storage_opcode:
            raise ValueError('module-base save not preserved across builds')
        if reader is not None:
            # Four-byte load of stored module base, followed by three-byte base-index read.
            if by_rva(cd,cs,0x47b2a5-cb,7)!=bytes.fromhex('8b 54 24 10 8b 1c 32'):
                raise ValueError('unknown base-index read sequence')
            if by_rva(gog,gs,0x47b2a5-gb,7)!=bytes.fromhex('8b 54 24 10 8b 1c 32'):
                raise ValueError('GOG base-index read sequence changed')
        redirects.append({'site_va':hex(va),
                          'original_obfuscated_call_va':hex(call_va),
                          'gog_archive_virtual_base':hex(gb+extra.rva),
                          'continuation_va':hex(continuation),
                          'same_module_base_saved_in_both':True,
                          'following_indexed_read_va':hex(reader) if reader else None})
    # The second, conditionally reached base+ESI read uses an offset returned by
    # the unchanged, type-dispatched object reader at 0x480B90. This prevents us
    # from assuming the index is statically known or a verified in-.text RVA.
    origin_opcodes={
        0x47b288:'8d 54 24 24', 0x47b28c:'52', 0x47b28d:'50',
        0x47b28e:'57', 0x47b28f:'e8 fc 58 00 00',
        0x47b294:'8b 74 24 30', 0x47b298:'83 c4 0c',
        0x47b29b:'81 fd 1b 01 00 00', 0x47b2a3:'75 09',
        0x47b2a5:'8b 54 24 10 8b 1c 32',
        0x480b90:'8b 44 24 08', 0x480b94:'8b 54 24 0c',
        0x480b9b:'8a 48 07', 0x480ba4:'ff 14 8d 80 41 4a 00',
        0x47b305:'8b 44 24 40', 0x47b309:'5f',
        0x47b30a:'5e', 0x47b30b:'5d',
        0x47b30c:'89 18', 0x47b30e:'c7 40 0c 07 00 00 00',
        0x47b315:'8b c1', 0x47b317:'5b', 0x47b318:'83 c4 24',
        0x47b31b:'c3',
    }
    for data,table in ((cd,cs),(gog,gs)):
        for va,opcode in origin_opcodes.items():
            if by_rva(data,table,va-cb,len(bytes.fromhex(opcode)))!=bytes.fromhex(opcode):
                raise ValueError(f'changed type-dispatch dataflow at 0x{va:X}')
    table_va=0x4a4180
    tab_cd=by_rva(cd,cs,table_va-cb,64)
    tab_gog=by_rva(gog,gs,table_va-gb,64)
    if tab_cd!=tab_gog:
        raise ValueError('type dispatcher table changed across builds')
    handlers=struct.unpack('<16I',tab_cd)
    if any(not cb+t.rva <= va < cb+t.rva+t.raw_size for va in handlers):
        raise ValueError('type-dispatch target outside original code')
    offset_origin={
        'branch_kind':'0x11B conditional after type dispatch',
        'helper_va':'0x480B90',
        'helper_source_pointer':'byte at [object+7]',
        'handler_table_va':hex(table_va),
        'first_16_handler_entries_sha256':hashlib.sha256(tab_cd).hexdigest(),
        'first_16_handler_entries_identical_across_builds':True,
        'first_16_entries_distinct_targets':len(set(handlers)),
        'offset_written_via_helper_out_parameter':True,
        'offset_runtime_range_proven':False,
        'read_value_output_va':'0x47B30C',
        'read_value_output_type_code':7,
        'direct_checksum_comparison_in_this_tail':False,
    }
    samples=[]
    for old_va in (0x470051, 0x47b1c3, 0x44e8a0):
        rva=old_va-cb
        transformed=gb+extra.rva+rva
        b1=by_rva(cd,cs,rva,16)
        b2=by_rva(gog,gs,extra.rva+rva,16)
        if b1!=b2:
            raise ValueError('RVA mirror mismatch')
        samples.append({'original_va':hex(old_va),'gog_archive_va':hex(transformed),
                        'same_16_bytes':True})
    return {'read_only':True,'exact_input_sha256_required':True,
            'original_sha256':EXPECTED['cd'][1],'gog_sha256':EXPECTED['gog'][1],
            'gog_is_pristine_retail':False,
            'original_image_base':hex(cb),'gog_active_image_base':hex(gb),
            'gog_archive_section_virtual_base':hex(gb+extra.rva),
            'gog_extra_nonexecuting':not bool(extra.flags & 0x20000000),
            'archive_mapping':relationship,
            'archive_base_little_endian_occurrence_sites_in_active_gog':
                [hex(va) for va in occurrences],
            'active_gog_code_differs_from_original_at_bytes':
                sum(x!=y for x,y in zip(code, active[:len(code)])),
            'two_redirects':redirects,
            'indexed_read_offset_origin':offset_origin,
            'source_rva_matches_archive_rva':samples,
            'runtime_execution_observed':False,
            'antitamper_purpose_proven':False,
            'game_executable_unwrapped':False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    a=p.parse_args()
    print(json.dumps(assess(locked_read(a.retail,'cd'),locked_read(a.gog,'gog')),indent=2))

if __name__ == '__main__':main()
