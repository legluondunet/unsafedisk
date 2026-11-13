#!/usr/bin/env python3
"""Read-only, SHA-pinned static comparison of Rayman 2 retail/CD and GOG file I/O.

Uses exact known x86 opcode anchors, not a disassembler, decryption method,
proof of runtime execution, or a retail-only SafeDisc patch recipe.
The GOG build may contain unrelated changes: attribution is NOT implied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
from pe_import_xrefs import parse_headers, rva_file_offset, import_entries

MAX_INPUT_BYTES = 16 * 1024 * 1024
RETAIL_SHA256 = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG_SHA256 = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
TABLE_VA = 0x004A2090
FORMAT_ORIGINAL_VA = 0x004A2264
FORMAT_GOG_VA = 0x004A2268

# Only short, independently inspected instruction encodings, not arbitrary
# executable blocks. A match still does not prove these paths are executed.
SITES = (
    (0x0044EB82, 'original drive-letter format argument', bytes.fromhex('51'), bytes.fromhex('90')),
    (0x0044EB89, 'original drive-letter format pointer', bytes.fromhex('68 64 22 4A 00'), bytes.fromhex('68 68 22 4A 00')),
    (0x0044EB94, 'stack-adjustment for format arguments', bytes.fromhex('83 C4 14'), bytes.fromhex('83 C4 10')),
    (0x0044EB97, 'protected branch invokes PRNG wrapper vs GOG skip', bytes.fromhex('E8 E4 98 FF FF'), bytes.fromhex('EB 72')),
    (0x0044EC24, 'dynamic file open vs direct CreateFileA IAT call', bytes.fromhex('FF D6'), bytes.fromhex('FF 15 58 C0 49 00')),
    (0x0044F133, 'retail arithmetic vs GOG NOP', bytes.fromhex('29 0E'), bytes.fromhex('90 90')),
    (0x0044F13A, 'indexed selection from 24-name table vs first entry', bytes.fromhex('8B 14 9D 90 20 4A 00'), bytes.fromhex('8B 15 90 20 4A 00 90')),
    (0x0044F155, 'drive-letter argument removed at second site', bytes.fromhex('50'), bytes.fromhex('90')),
    (0x0044F156, 'second file path format pointer', bytes.fromhex('68 64 22 4A 00'), bytes.fromhex('68 68 22 4A 00')),
    (0x0044F161, 'second stack adjustment for format arguments', bytes.fromhex('83 C4 14'), bytes.fromhex('83 C4 10')),
    (0x0044F1CC, 'retail continuation vs GOG early jump', bytes.fromhex('8B 0E'), bytes.fromhex('EB 23')),
)


def safe_read(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError('refusing symlink')
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_INPUT_BYTES:
        raise ValueError('refusing nonregular/oversized file')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as fh:
        opened = os.fstat(fh.fileno())
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > MAX_INPUT_BYTES:
            raise ValueError('file changed type or size')
        # DirEntry.stat / fstat file IDs can disagree for the same file on
        # Windows. Keep strict device+inode checks on POSIX; on Windows the
        # common snapshot fields provide a best-effort check, not immunity
        # to every concurrent path replacement (TOCTOU).
        if ((opened.st_size, opened.st_mtime_ns) !=
                (before.st_size, before.st_mtime_ns) or
                (os.name != 'nt' and (opened.st_dev, opened.st_ino) !=
                 (before.st_dev, before.st_ino))):
            raise ValueError('file changed or replaced on opening')
        data = fh.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(fh.fileno())
    if (len(data) != opened.st_size or len(data) > MAX_INPUT_BYTES or
            (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise ValueError('file changed during reading')
    return data


def va_bytes(data: bytes, headers: dict, va: int, length: int) -> bytes:
    rva = va - headers['image_base']
    if not 0 <= rva <= 0xffffffff or not 0 <= length <= 512:
        raise ValueError('VA/length out of range')
    off = rva_file_offset(headers, rva, length, len(data))
    return data[off:off+length]


def va_cstr(data: bytes, headers: dict, va: int, max_len: int = 64) -> str:
    chars = bytearray()
    for i in range(max_len):
        b = va_bytes(data, headers, va + i, 1)[0]
        if b == 0:
            return chars.decode('ascii', 'strict')
        chars.append(b)
    raise ValueError('unterminated text at VA')


def read_file_table(data: bytes, headers: dict, table_va: int = TABLE_VA) -> list[str]:
    pointers = va_bytes(data, headers, table_va, 24*4)
    names=[]
    for index in range(24):
        (name_va,) = struct.unpack_from('<I', pointers, index*4)
        name = va_cstr(data, headers, name_va, 32)
        if not re.fullmatch(r'(LEVELS|MAP|TEXTURES|ANIMS|SOUNDS|MUSIC|GRAPHICS|MENU)[012]\.DAT', name):
            raise ValueError(f'unexpected file table entry {index}')
        names.append(name)
    if len(set(names)) != 24:
        raise ValueError('duplicate data table name')
    return names



# Paired original file-stream readers. The retail-only versions use masked
# ReadFile pointer trampolines; GOG preserves the direct-IAT counterparts.
STREAM_BRANCH_BYTES = {0x00450A47:(0x28,0x00), 0x00450A6A:(0x05,0x00)}
STREAM_PRESERVED = (
    (0x00451090,0x00451110,'direct ReadFile plus per-byte XOR'),
    (0x004512C0,0x00451300,'direct ReadFile without data XOR'),
)
STREAM_REMOVED = (
    (0x00451110,0x004512C0,'masked ReadFile plus per-byte XOR'),
    (0x00451300,0x00451431,'masked ReadFile without data XOR'),
)


# Actual x86 update in the real-data ReadFile+XOR stream reader, not the
# SafeDisc PE unwrapping cipher. This is NOT equivalent to a Park-Miller
# modulo operation for every possible state (including from game's seed).
STREAM_XOR_SEED = 0x6AB5CC79
STREAM_XOR_SALT = 0x075BD924
STREAM_XOR_MAGIC = 0x069C16BD
STREAM_XOR_MULTIPLIER = 16807
STREAM_XOR_MASK = 0xFFFFFFFF
STREAM_XOR_DIRECT_ANCHORS = {
    0x00450EC0: '8B 44 24 04 8A 40 18 D1 E8 83 E0 01 C3', # flag bit 1: enable XOR
    0x00450ED0: '8B 44 24 04 8A 40 18 C1 E8 02 83 E0 01 C3', # flag bit 2: masked I/O
    0x00450A20: 'E8 9B 04 00 00',             # check XOR bit 1
    0x00450A37: 'E8 94 04 00 00',             # check masked-I/O bit 2
    0x004510B8: '89 47 04 8B 44 24 14 3B C8 74 06 32 C0 5F 5E 5B C3', # no XOR if short read
    0x00450A2D: 'C7 46 14 79 CC B5 6A',       # when mode bit 1 is set
    0x004510CD: '8A 4F 15 8A 16 32 D1',       # key = state byte +1
    0x004510D4: 'B8 BD 16 9C 06',
    0x004510DB: '8B 4F 14',
    0x004510DE: '81 F1 24 D9 5B 07',
    0x004510E4: 'F7 E1',                       # unsigned 64-bit MUL
    0x004510E6: '8B C1',
    0x004510E8: '69 C9 A7 41 00 00',         # IMUL low DWORD only
    0x004510EE: '2B C2 D1 E8 03 C2 C1 E8 10',
    0x004510F7: '8B D0 F7 DA C1 E2 1F 2B D0 2B CA',
    0x00451102: '46 3B F3 89 4F 14 72 C3',
}
STREAM_XOR_RETAIL_MASKED_ANCHORS = {
    0x0045126B: '8A 4B 15 8A 17 32 D1',
    0x00451272: 'B8 BD 16 9C 06',
    0x00451279: '8B 4B 14',
    0x0045127C: '81 F1 24 D9 5B 07',
    0x00451282: 'F7 E1',
    0x00451286: '69 C9 A7 41 00 00',
    0x0045128C: '2B C2 D1 E8 03 C2 C1 E8 10',
    0x00451295: '8B D0 F7 DA C1 E2 1F 2B D0 2B CA',
    0x004512A0: '47 3B FE 89 4B 14 72 C3',
}


def stream_xor_step32(state: int) -> int:
    """Byte-exact x86 arithmetic in VA 0x4510D4..0x451101.

    Unlike the tempting ((state XOR salt)*16807) % 2147483647,
    the original x86 MUL/SHR and 32-bit wrap sometimes produce
    a different result. Do NOT normalize intermediate arithmetic.
    """
    if type(state) is not int or not 0 <= state <= STREAM_XOR_MASK:
        raise ValueError('state must be an unsigned 32-bit integer')
    v = state ^ STREAM_XOR_SALT
    high = (v * STREAM_XOR_MAGIC) >> 32
    low_product = (v * STREAM_XOR_MULTIPLIER) & STREAM_XOR_MASK
    quotient = (v - high) & STREAM_XOR_MASK
    quotient >>= 1
    quotient = (quotient + high) & STREAM_XOR_MASK
    quotient >>= 16
    edx = (-quotient) & STREAM_XOR_MASK
    edx = (edx << 31) & STREAM_XOR_MASK
    edx = (edx - quotient) & STREAM_XOR_MASK
    return (low_product - edx) & STREAM_XOR_MASK


def stream_xor_transform(data: bytes, state: int = STREAM_XOR_SEED) -> tuple[bytes, int]:
    """Model XOR only after a complete-length successful ReadFile.

    The game checks its requested and returned byte counts before
    entering the XOR loop. Caller must not use this helper to claim
    a partial/failed read would advance the state; that case skips
    the native XOR loop.
    """
    if not isinstance(data, bytes) or len(data) > MAX_INPUT_BYTES:
        raise ValueError('input must be bytes of at most 16 MiB')
    if type(state) is not int or not 0 <= state <= STREAM_XOR_MASK:
        raise ValueError('state must be an unsigned 32-bit integer')
    out = bytearray(len(data))
    for pos, byte in enumerate(data):
        out[pos] = byte ^ ((state >> 8) & 255)  # [stream+0x15]
        state = stream_xor_step32(state)
    return bytes(out), state


def inspect_stream_xor_x86(retail: bytes, gog: bytes, rh: dict, gh: dict) -> dict:
    """Verify x86 opcode source on both authenticated samples; never run it."""
    for binary, hdr in ((retail, rh), (gog, gh)):
        for va, raw in STREAM_XOR_DIRECT_ANCHORS.items():
            expected = bytes.fromhex(raw)
            if va_bytes(binary, hdr, va, len(expected)) != expected:
                raise ValueError(f'unexpected direct stream XOR opcode at 0x{va:08X}')
    for va, raw in STREAM_XOR_RETAIL_MASKED_ANCHORS.items():
        expected = bytes.fromhex(raw)
        if va_bytes(retail, rh, va, len(expected)) != expected:
            raise ValueError(f'unexpected original masked XOR opcode at 0x{va:08X}')
        if va_bytes(gog, gh, va, len(expected)) != b'\xcc' * len(expected):
            raise ValueError(f'GOG retained masked XOR code at 0x{va:08X}')
    keystream, state256 = stream_xor_transform(bytes(256))
    digest = hashlib.sha256(keystream).hexdigest()
    if digest != '8eeed8d4e85f19dd1a78d818003c41056e15755dd1bff524afb49c8cda0bc957':
        raise ValueError('x86 stream XOR synthetic 256-byte golden mismatch')
    naive = actual = STREAM_XOR_SEED
    first_state_diff = first_key_diff = None
    for i in range(256):
        if first_state_diff is None and actual != naive:
            first_state_diff = i
        if first_key_diff is None and ((actual >> 8) & 255) != ((naive >> 8) & 255):
            first_key_diff = i
        actual = stream_xor_step32(actual)
        naive = ((naive ^ STREAM_XOR_SALT) * STREAM_XOR_MULTIPLIER) % 0x7FFFFFFF
    if first_state_diff != 70 or first_key_diff != 71:
        raise ValueError('original XOR reducer unexpectedly equals simplified modulo')
    return {
        'read_only': True, 'actual_file_read_traced': False,
        'seed_when_stream_flag_bit_1_set':f'0x{STREAM_XOR_SEED:08X}',
        'key_byte':'(state >> 8) & 0xFF',
        'XOR_enabled_only_with_stream_flag_bit_1':True,
        'masked_ReadFile_choice_controlled_by_stream_flag_bit_2_original':True,
        'short_ReadFile_byte_count_skips_XOR_loop':True,
        'direct_reader_opcodes_verified_per_executable':len(STREAM_XOR_DIRECT_ANCHORS),
        'original_masked_reader_opcodes_verified':len(STREAM_XOR_RETAIL_MASKED_ANCHORS),
        'original_masked_XOR_bytes_disabled_in_gog':True,
        'first_16_keystream_bytes':keystream[:16].hex(),
        'keystream_256_sha256':digest,
        'state_after_256_bytes':f'0x{state256:08X}',
        'naive_modulo_first_state_divergence_offset':first_state_diff,
        'naive_modulo_first_key_divergence_offset':first_key_diff,
        'safe_disc_loader_decryption_proven':False,
    }


# Unlike stream_xor_transform, this separate bit-0 mode does not modify
# file data: it maintains a 32-bit XOR of completed little-endian DWORDs.
# An incomplete 1..3-byte DWORD persists at stream+8 across read calls.
STREAM_WORD_CHECK_ANCHORS = {
    0x450A0C:'56 89 5E 10 88 5E 0C 88 46 18', # initialize zero accumulator/pending
    0x450EB0:'8B 44 24 04 8A 40 18 83 E0 01 C3', # mode bit 0: checksum
    0x450EC0:'8B 44 24 04 8A 40 18 D1 E8 83 E0 01 C3', # mode bit 1: byte XOR
    0x450ED0:'8B 44 24 04 8A 40 18 C1 E8 02 83 E0 01 C3', # bit 2: API mask
    0x450DBA:'8B 7D 10 0F AF 7D 0C 85 FF',
    0x450DD2:'53 57 56 FF 53 24', # selected read handler
    0x450DE6:'53 E8 C4 00 00 00', # bit-0 mode query
    0x450DF7:'8A 43 0C 8B CF 84 C0',
    0x450E19:'8B 45 0C 33 D2 8A 53 0C',
    0x450E28:'8D 7C 13 08',
    0x450E2E:'C1 E9 02 F3 A5 8B CA 83 E1 03 F3 A4',
    0x450E40:'02 D1 8B 4D 08 88 53 0C',
    0x450E50:'80 FA 04 75 0F',
    0x450E55:'8B 53 08 8B 43 10 33 C2', # XOR completed pending DWORD
    0x450E5D:'C6 43 0C 00 89 43 10',
    0x450E64:'8A C1 24 03 C1 E9 02',
    0x450E70:'8B 16 8B 7B 10 33 FA', # XOR one complete data DWORD
    0x450E7B:'89 7B 10 75 F0',
    0x450E80:'84 C0 74 23',
    0x450E92:'8D 7C 13 08', # store 1..3 pending bytes
    0x450EA4:'00 43 0C',
    0x450EA7:'8B 45 10 5F 5E 5B 5D C3', # return item count
    0x44D50B:'6A 03 6A 02 53 E8 6B 35 00 00', # mode 3 call
    0x44DACF:'6A 00 8D 85 00 FF FF FF 6A 02', # mode 0 call
    0x44EA1B:'56 6A 06 E8 DD 1F 00 00', # mode 6 DAT-specific init
    0x44F769:'6A 02', # mode 2 call
}


# File-supplied expected DWORD versus rolling stream XOR: another shared
# original/GOG static path that can invert an indexed global on mismatch.
# The specific SafeDisc ownership/purpose of this condition is NOT proven.
STREAM_WORD_CHECK_COMPARE_ANCHORS = {
    0x0044D93E:'8B 54 24 44 A1 B8 17 51 00 3B D0',
    0x0044D94F:'74 1E',                # no mismatch -> skip the inversion
    0x0044D951:'E8 0A B0 FC FF',       # conditional gate 0x418960
    0x0044D956:'84 C0 74 15',
    0x0044D95A:'A1 C4 17 51 00 8B 0C 85 FC 16 51 00 F7 D1 89 0C 85 FC 16 51 00',
    0x00418960:'B0 01 C3',             # this disk implementation returns TRUE
    0x0044DC80:'E8 0B FD FF FF',       # caller that opens stream then gets expected
    0x0044DCDB:'6A 01 6A 04 68 B8 17 51 00',  # read DWORD to global
    0x0044DCE6:'E8 A5 30 00 00',       # call stream fread 0x450D90
}


# Provenance of the rolling-DWORD checksum comparison: two callers feed
# .sna snapshot paths into a mode-0x03 loader. A *different* stream
# supplies the comparison DWORD through 0x44DC40 -> 0x44D990; its
# resource filename can be an .rt* variant or a special Fix path.
# This is NOT equivalent to saying that LEVELS*.DAT is a .sna file.
SNAPSHOT_CHECKSUM_ANCHORS = {
    0x00402A4E:'68 D8 F2 49 00',  # %s\Fix.sna
    0x00402A71:'E8 7A AA 04 00',  # CALL 0x44D4F0
    0x0040380D:'68 44 F3 49 00',  # %s\%s\%s.sna
    0x00403983:'E8 68 9B 04 00',  # CALL 0x44D4F0
    0x0044D4FF:'8B 9C 24 7C 01 00 00', # snapshot filepath arg
    0x0044D50B:'6A 03 6A 02 53 E8 6B 35 00 00', # mode 3 reader
    0x0044D619:'E8 22 06 00 00', # acquire separate expected-data stream
    0x0044DC80:'E8 0B FD FF FF', # call 0x44D990 reference opener
    0x0044DCDB:'6A 01 6A 04 68 B8 17 51 00', # expected DWORD destination
    0x0044DCE6:'E8 A5 30 00 00', # fread expected DWORD
    0x0044D93E:'8B 54 24 44 A1 B8 17 51 00 3B D0',
    0x0044D94F:'74 1E',          # equal -> don't invert
    0x0044D95A:'A1 C4 17 51 00 8B 0C 85 FC 16 51 00 F7 D1 89 0C 85 FC 16 51 00',
    0x0044D990:'55 8B EC 81 EC 00 02 00 00',
    0x0044D9C2:'A0 F0 16 51 00', # selector byte
    0x0044D9CA:'3C FF 75 1C',    # special Fix path
    0x0044D9F4:'E8 A7 0E 00 00', # alternate access path
    0x0044DA5E:'83 F8 04 77 6B', # 0..4 suffix selection
    0x0044DA63:'FF 24 85 CC DB 44 00', # suffix target switch
    0x0044DACF:'6A 00 8D 85 00 FF FF FF 6A 02', # reference mode 0
    0x004038A8:'89 3D C4 17 51 00', # index from EDI
    0x00404317:'89 35 C4 17 51 00', # index from ESI
    0x0040484C:'C7 05 C4 17 51 00 00 00 00 00', # clear index
    0x0044EABD:'40 81 F1 24 D9 5B 07 A3 C4 17 51 00', # increment
}
SNAPSHOT_TEMPLATES = {
    0x0049F2D8: '%s\\Fix.sna',
    0x0049F344: '%s\\%s\\%s.sna',
}
REFERENCE_SUFFIXES = (
    (0x0044DA6A,0x004A2248,'.rtb'),
    (0x0044DA77,0x004A2240,'.rtp'),
    (0x0044DA91,0x004A2230,'.rts'),
    (0x0044DA84,0x004A2238,'.rtt'),
    (0x0044DA9E,0x004A2228,'.rtl'),
)


def inspect_snapshot_checksum_provenance(retail: bytes, gog: bytes,
                                         rh: dict, gh: dict) -> dict:
    """Cross-resource static evidence, not a disk decryption or runtime trace.

    Both EXE hashes are checked by inspect_pair before calling this helper.
    The snapshot stream (mode 0x03) and reference/expected-value stream
    (mode 0x00 or alternate caller) have separate opens; do not claim
    the expected value comes from the .sna file being checked.
    """
    for img,hdr in ((retail,rh),(gog,gh)):
        for va, hexbytes in SNAPSHOT_CHECKSUM_ANCHORS.items():
            expected=bytes.fromhex(hexbytes)
            if va_bytes(img,hdr,va,len(expected)) != expected:
                raise ValueError(f'snapshot/checksum provenance mismatch at 0x{va:08X}')
        for va,text in SNAPSHOT_TEMPLATES.items():
            if va_cstr(img,hdr,va) != text:
                raise ValueError(f'unknown .sna snapshot filename format at 0x{va:08X}')
        expected_targets=tuple(target for target,_,_ in REFERENCE_SUFFIXES)
        targets=struct.unpack('<5I',va_bytes(img,hdr,0x0044DBCC,20))
        if targets!=expected_targets:
            raise ValueError('changed .rt* reference suffix switch')
        for target,string_va,suffix in REFERENCE_SUFFIXES:
            if va_cstr(img,hdr,string_va) != suffix:
                raise ValueError('unexpected expected-data stream suffix')
            # All switch targets load the correct suffix string address
            # into EDI, then share the suffix append operation.
            # All five dispatch entries begin with a six-byte LEA EDX,
            # followed by five-byte MOV EDI, <suffix string VA>.
            if va_bytes(img,hdr,target,6) != bytes.fromhex('8D 95 00 FF FF FF'):
                raise ValueError(f'unknown reference stream branch at 0x{target:08X}')
            if va_bytes(img,hdr,target+6,5) != b'\xbf'+struct.pack('<I',string_va):
                raise ValueError(f'wrong .rt suffix pointer at 0x{target:08X}')
    return {
        'read_only':True,'runtime_execution_observed':False,
        'verified_common_opcode_anchors':len(SNAPSHOT_CHECKSUM_ANCHORS),
        'snapshot_loader_va':'0x0044D4F0',
        'snapshot_loader_direct_callers':['0x00402A71','0x00403983'],
        'snapshot_path_formats':list(SNAPSHOT_TEMPLATES.values()),
        'snapshot_stream_mode':'0x03',
        'reference_stream_builder_va':'0x0044DC40',
        'reference_stream_opener_va':'0x0044D990',
        'reference_stream_normal_mode':'0x00',
        'expected_value_read_call_va':'0x0044DCE6',
        'expected_value_destination_va':'0x005117B8',
        'rolling_checksum_compare_va':'0x0044D947',
        'reference_suffix_switch':[
            {'ordinal':i,'branch_va':f'0x{entry:08X}',
             'suffix':suffix} for i,(entry,_,suffix) in enumerate(REFERENCE_SUFFIXES)],
        'special_Fix_reference_path_possible':True,
        'alternate_reference_open_path_possible':True,
        'inversion_memory_index_global_va':'0x005117C4',
        'sample_global_index_write_sites':[
            '0x004038A8','0x00404317','0x0040484C','0x0044EABD'],
        'no_index_bound_verified_at_inversion_site':True,
        'snapshot_payload_or_original_CD_checked':False,
        'SafeDisc_integrity_attribution_proven':False,
    }


# Two adjacent original/GOG runtime-only global tables, plus an index
# also reused by the .sna checksum mismatch branch. The first inversion
# address is 1 DWORD before the ordinary first table. Not a patch recipe.
INDEX_GLOBAL_VA = 0x005117C4
INDEX_INVERT_BASE_VA = 0x005116FC
INDEX_FIRST_TABLE_VA = 0x00511700
INDEX_SECOND_TABLE_VA = 0x00511760
INDEX_NEXT_GLOBAL_VA = 0x005117C0
SNAPSHOT_INDEX_ANCHORS = {
    0x0040373F:'33 FF',
    0x004038A8:'89 3D C4 17 51 00', # EDI=0 in current straight-line path
    0x00404303:'89 35 F0 0B 51 00', # PRNG state write
    0x00404309:'79 0C',
    0x0040430B:'81 C6 FF FF FF 7F', # negative-state correction
    0x00404317:'89 35 C4 17 51 00', # PRNG-derived index, not reduced to 0..23
    0x0040484C:'C7 05 C4 17 51 00 00 00 00 00', # clear
    0x004045F9:'8B 1D C4 17 51 00', # loop bound is this index
    0x00404604:'85 DB 0F 86 AD 00 00 00',
    0x00404657:'89 0C BD 60 17 51 00', # second table indexed store
    0x004046A2:'89 34 BD 00 17 51 00', # first table indexed store
    0x004046A9:'47',
    0x004046AA:'3B FB 0F 82 61 FF FF FF', # no 24 check in loop block
    0x0046729F:'A1 C4 17 51 00',
    0x004672AD:'8B 04 B5 60 17 51 00', # second table indexed read
    0x004672CC:'8B 14 B5 00 17 51 00', # first table indexed read
    0x004672F1:'FE C0 88 45 FC',
    0x00467300:'81 E6 FF 00 00 00', # consumer local counter max 255
    0x00467306:'3B F0 72 A3',
    0x0044D95A:'A1 C4 17 51 00',
    0x0044D95F:'8B 0C 85 FC 16 51 00', # starts one DWORD before first table
    0x0044D966:'F7 D1', # bitwise NOT
    0x0044D968:'89 0C 85 FC 16 51 00',
    0x0044EA80:'8B 0D C4 17 51 00',
    0x0044EA8C:'89 14 8D 60 17 51 00',
    0x0044EAA5:'A1 C4 17 51 00',
    0x0044EAB6:'89 14 85 00 17 51 00',
    0x0044EABD:'40',
    0x0044EAC4:'A3 C4 17 51 00',
}


def snapshot_inversion_address(index: int) -> int:
    """Compute x86 32-bit scaled-index address; not a safe array index."""
    if type(index) is not int or not 0 <= index <= 0xFFFFFFFF:
        raise ValueError('index must be an unsigned DWORD')
    return (INDEX_INVERT_BASE_VA + 4*index) & 0xFFFFFFFF


def inspect_snapshot_index_alias(retail: bytes, gog: bytes,
                                 rh: dict, gh: dict) -> dict:
    """Exact protected/GOG opcode and BSS layout audit, no runtime trace.

    PE .data virtual-size > raw-size means these globals are zero-fill
    on load. That does not establish their values at any later branch.
    """
    for img,hdr in ((retail,rh),(gog,gh)):
        for va,signature in SNAPSHOT_INDEX_ANCHORS.items():
            raw=bytes.fromhex(signature)
            if va_bytes(img,hdr,va,len(raw)) != raw:
                raise ValueError(f'index source/table opcode differs at 0x{va:08X}')
    zero_filled=[]
    for hdr in (rh,gh):
        sections=[s for s in hdr['sections'] if s['name']=='.data']
        if len(sections)!=1:
            raise ValueError('expected one .data section')
        sec=sections[0]
        phys_end=hdr['image_base']+sec['rva']+sec['raw_size']
        virt_end=hdr['image_base']+sec['rva']+sec['virtual_size']
        if not all(phys_end <= va < virt_end for va in
                   (INDEX_INVERT_BASE_VA,INDEX_FIRST_TABLE_VA,
                    INDEX_SECOND_TABLE_VA,INDEX_NEXT_GLOBAL_VA,INDEX_GLOBAL_VA)):
            raise ValueError('index/table globals are not in PE zero-filled .data')
        zero_filled.append((phys_end,virt_end))
    if zero_filled[0]!=zero_filled[1]:
        raise ValueError('different PE .data virtual/raw boundaries')
    if (INDEX_SECOND_TABLE_VA-INDEX_FIRST_TABLE_VA != 24*4 or
            INDEX_NEXT_GLOBAL_VA-INDEX_SECOND_TABLE_VA != 24*4):
        raise ValueError('adjacent table base intervals differ')
    examples={str(i):f'0x{snapshot_inversion_address(i):08X}'
              for i in (0,1,23,24,25,48,49,50)}
    if (snapshot_inversion_address(0)!=INDEX_FIRST_TABLE_VA-4 or
            snapshot_inversion_address(50)!=INDEX_GLOBAL_VA):
        raise ValueError('unexpected first-table/index-global address alias')
    return {
        'read_only':True,'runtime_reachability_observed':False,
        'identical_cd_gog_opcode_anchors':len(SNAPSHOT_INDEX_ANCHORS),
        'index_global_va':f'0x{INDEX_GLOBAL_VA:08X}',
        'index_writers':[
            {'at':'0x004038A8','kind':'register EDI (zeroed at 0x40373F in this path)'},
            {'at':'0x00404317','kind':'PRNG-derived ESI without local 24-entry clamp'},
            {'at':'0x0040484C','kind':'constant zero'},
            {'at':'0x0044EAC4','kind':'previous index incremented, no local 24-entry clamp'},
        ],
        'array_addresses':{
            'first_base':'0x00511700','second_base':'0x00511760',
            'each_adjacent_base_interval_dwords':24,
            'each_array_actual_allocated_length_proven':False},
        'two_table_store_sites':{
            'first':['0x004046A2','0x0044EAB6'],
            'second':['0x00404657','0x0044EA8C']},
        'two_table_load_sites':{
            'first':'0x004672CC','second':'0x004672AD'},
        'inversion_base_is_one_dword_before_first_table':True,
        'inversion_address_examples':examples,
        'index_49_aliases_adjacent_global_0x5117c0':True,
        'index_50_aliases_index_global_itself':True,
        'on_disk_globals_zero_filled_by_PE_loader_initially':True,
        'data_raw_backed_end_exclusive':f'0x{zero_filled[0][0]:08X}',
        'data_virtual_end_exclusive':f'0x{zero_filled[0][1]:08X}',
        'init_table_loop_0x4045F0_bounds_by_global_index_only':True,
        'array_consumer_0x467210_uses_8bit_index_vs_global':True,
        'local_mismatch_branch_has_explicit_array_bound':False,
        'runtime_index_values_or_bad_memory_access_proven':False,
        'SafeDisc_origin_proven':False,
    }


def stream_word_xor_checksum(data: bytes, checksum: int = 0,
                             pending: bytes = b'',
                             *, callback_success: bool = True) -> tuple[int, bytes]:
    """Exact logical checksum over *already-transformed* successful read bytes.

    The real 0x450D90 call first invokes the selected read callback, then
    (only if callback succeeds and stream bit 0 is set) folds completed
    little-endian DWORDs into [stream+0x10]. It leaves 1..3 pending bytes
    in [stream+0x08] with their count in [stream+0x0C]. The pending
    bytes are NOT zero-padded or folded on their own.
    """
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        raise ValueError('data must be bytes of at most 16 MiB')
    if type(checksum) is not int or not 0 <= checksum <= 0xffffffff:
        raise ValueError('checksum must be an unsigned DWORD')
    if type(pending) is not bytes or len(pending) > 3:
        raise ValueError('pending must contain at most three bytes')
    if type(callback_success) is not bool:
        raise ValueError('callback_success must be boolean')
    if not callback_success:
        return checksum, pending
    pos = 0
    if pending:
        take = min(4 - len(pending), len(data))
        pending += data[:take]
        pos += take
        if len(pending) == 4:
            checksum ^= struct.unpack('<I', pending)[0]
            pending = b''
    whole = (len(data) - pos) // 4
    for idx in range(whole):
        checksum ^= struct.unpack_from('<I', data, pos + idx*4)[0]
    pos += 4*whole
    return checksum, pending + data[pos:]


def inspect_stream_word_checksum(retail: bytes, gog: bytes,
                                 rh: dict, gh: dict) -> dict:
    """Opcode-audited third stream mode and original/GOG open-call contrast."""
    for data, headers in ((retail,rh),(gog,gh)):
        for va, pattern in STREAM_WORD_CHECK_ANCHORS.items():
            expected = bytes.fromhex(pattern)
            if va_bytes(data,headers,va,len(expected)) != expected:
                raise ValueError(f'stream DWORD checksum anchor mismatch at 0x{va:08X}')
    for data, headers in ((retail,rh),(gog,gh)):
        for va, pattern in STREAM_WORD_CHECK_COMPARE_ANCHORS.items():
            expected = bytes.fromhex(pattern)
            if va_bytes(data,headers,va,len(expected)) != expected:
                raise ValueError(f'stream XOR checksum compare mismatch at 0x{va:08X}')
    for begin, end in ((0x450D90,0x450EB0), (0x450EB0,0x450EE0)):
        for va in range(begin,end,64):
            n = min(64,end-va)
            if va_bytes(retail,rh,va,n) != va_bytes(gog,gh,va,n):
                raise ValueError('original/GOG checksum implementation differs')
    if va_bytes(retail,rh,0x450ADE,11) != bytes.fromhex(
            '56 E8 EC 03 00 00 83 C4 04 84 C0'):
        raise ValueError('missing original masked CreateFileA option guard')
    if va_bytes(retail,rh,0x450B9E,2) != b'\xff\xd6':
        raise ValueError('missing original generated CreateFileA call')
    if va_bytes(gog,gh,0x450ADE,5) != bytes.fromhex('E9 22 01 00 00'):
        raise ValueError('GOG does not bypass original masked CreateFileA')
    for va in range(0x450AE3,0x450C05,64):
        n = min(64,0x450C05-va)
        if va_bytes(gog,gh,va,n) != b'\xcc' * n:
            raise ValueError('masked stream-open branch remains in GOG')
    for va in range(0x450C05,0x450C33,32):
        n = min(32,0x450C33-va)
        if va_bytes(retail,rh,va,n) != va_bytes(gog,gh,va,n):
            raise ValueError('modified native CreateFileA path in GOG')
    test_bytes = bytes(range(256))
    whole = stream_word_xor_checksum(test_bytes)
    result = (0,b'')
    for i in range(0,256,7):
        result = stream_word_xor_checksum(test_bytes[i:i+7], *result)
    if result != whole:
        raise ValueError('stream checksum differs across chunk boundaries')
    return {
        'read_only':True,'runtime_checksum_calls_observed':False,
        'common_opcode_anchors_checked':len(STREAM_WORD_CHECK_ANCHORS),
        'checksum_compare_anchors_checked':len(STREAM_WORD_CHECK_COMPARE_ANCHORS),
        'expected_checksum_global_va':'0x005117B8',
        'expected_checksum_stream_read_call_va':'0x0044DCE6',
        'roll_vs_expected_compare_va':'0x0044D947',
        'mismatch_gate_va':'0x00418960',
        'mismatch_gate_returns_true_on_disk':True,
        'on_mismatch_bitwise_invert':'global[0x005116FC + 4*global_0x005117C4]',
        'looks_like_game_data_integrity_check':True,
        'safedisc_origin_not_proven':True,
        'checksum_stream_function_byte_identical_count':288,
        'three_stream_flag_extractors_identical_byte_count':48,
        'bit_0':'rolling XOR of completed little-endian 32-bit words',
        'bit_1':'per-byte XOR payload transform',
        'bit_2':'original masked API call selection',
        'checksum_accumulator_offset':'stream+0x10',
        'checksum_pending_bytes_offset':'stream+0x08',
        'checksum_pending_count_offset':'stream+0x0C',
        'bit0_checksum_does_not_modify_read_buffer':True,
        'partially_received_DWORD_not_folded_until_complete':True,
        'stream_open_masked_CreateFileA_call_va':'0x00450B9E',
        'gog_direct_stream_open_jump_va':'0x00450ADE',
        'gog_disabled_stream_open_INT3_bytes':290,
        'direct_CreateFileA_open_bytes_retained':46,
        'example_mode_values':{
            '0x0044D50B':3,'0x0044DACF':0,
            '0x0044EA1C':6,'0x0044F769':2},
        'synthetic_256_bytes_chunked_checksum_equal':True,
        'retail_CD_physical_data_verified':False,
        'safedisc_decryption_proven':False,
    }


def inspect_stream_read_variants(retail: bytes, gog: bytes,
                                 hr: dict, hg: dict) -> dict:
    """Account for the *exact two changed bytes* selecting file readers.

    This is static PE code evidence on the two SHA-locked samples; it
    cannot prove runtime equivalence or how DAT bytes are supplied.
    """
    original=va_bytes(retail,hr,0x00450A00,0x76)
    patched=va_bytes(gog,hg,0x00450A00,0x76)
    diff={0x00450A00+i:(a,b) for i,(a,b) in enumerate(zip(original,patched))
          if a!=b}
    if diff!=STREAM_BRANCH_BYTES:
        raise ValueError('unexpected file-stream callback selection edits')
    # Four reader addresses are still encoded in both on-disk initializers.
    shared_anchors={
        0x00450A41:'B8 10 11 45 00', # masked XOR reader
        0x00450A46:'75',                # short JNE, GOG patches displacement only
        0x00450A48:'B8 90 10 45 00', # direct-IAT XOR reader
        0x00450A64:'B8 00 13 45 00', # masked raw reader
        0x00450A69:'75',                # short JNE, GOG patches displacement only
        0x00450A6B:'B8 C0 12 45 00', # direct-IAT raw reader
        0x00450A4D:'89 46 24',       # structure->reader at +0x24
        0x00450A70:'89 46 24',
        0x00450A8E:'E8 6D FF FF FF', # stream setup -> 0x450A00
        0x00450DD5:'FF 53 24',       # later CALL [EBX+0x24]
        0x00450C16:'FF 15 58 C0 49 00', # CreateFileA real OS handle
        0x00450C1C:'89 06',         # store real OS HANDLE
        0x004510AE:'FF 15 4C C0 49 00', # direct ReadFile
        0x004512DA:'FF 15 4C C0 49 00', # direct ReadFile
        0x004510CD:'8A 4F 15 8A 16 32 D1', # per-byte XOR
    }
    for code,head in ((retail,hr),(gog,hg)):
        for va,hex_signature in shared_anchors.items():
            expected=bytes.fromhex(hex_signature)
            if va_bytes(code,head,va,len(expected))!=expected:
                raise ValueError(f'mismatched stream instruction at 0x{va:08X}')
    # Obfuscated originals generate a local call stub before ReadFile.
    retail_only={
        0x004511E2:'FF D6',  # masked + per-byte XOR
        0x004513BB:'FF D6',  # masked + raw
        0x0045126B:'8A 4B 15 8A 17 32 D1', # same kind of XOR after read
    }
    for va,hex_signature in retail_only.items():
        expected=bytes.fromhex(hex_signature)
        if va_bytes(retail,hr,va,len(expected))!=expected:
            raise ValueError(f'missing masked original reader at 0x{va:08X}')
    same=[]
    for start,end,description in STREAM_PRESERVED:
        if va_bytes(retail,hr,start,end-start)!=va_bytes(gog,hg,start,end-start):
            raise ValueError(f'changed preserved stream reader at 0x{start:08X}')
        same.append({'original_va':f'0x{start:08X}','byte_length':end-start,
                     'description':description})
    removed=[]
    for start,end,description in STREAM_REMOVED:
        if va_bytes(gog,hg,start,end-start)!=b'\xCC'*(end-start):
            raise ValueError(f'GOG retained masked reader at 0x{start:08X}')
        removed.append({'original_va':f'0x{start:08X}','gog_INT3_count':end-start,
                        'description':description})
    return {
        'read_only':True,'sample_hashes_validated_by_parent':True,
        'initializer_va':'0x00450A00','initializer_bytes_compared':0x76,
        'changed_initializer_byte_count':len(diff),
        'changed_branch_displacements':[
           {'va':f'0x{address:08X}','retail':pair[0],'gog':pair[1]}
           for address,pair in sorted(diff.items())],
        'reader_field_offset':'0x24','reader_call_va':'0x00450DD5',
        'native_CreateFileA_IAT_call_va':'0x00450C16',
        'native_file_handle_store_va':'0x00450C1C',
        'preserved_direct_ReadFile_variants':same,
        'gog_disabled_masked_ReadFile_variants':removed,
        'shared_instruction_anchors_checked':len(shared_anchors),
        'original_only_instruction_anchors_checked':len(retail_only),
        'data_XOR_retained':True,
        'behavioral_equivalence_not_runtime_proven':True,
        'original_CD_sector_reads_not_proven':True,
    }


def inspect_pair(retail: bytes, gog: bytes, *, verify_hashes: bool = True) -> dict:
    hashes = (hashlib.sha256(retail).hexdigest(), hashlib.sha256(gog).hexdigest())
    if verify_hashes and hashes != (RETAIL_SHA256, GOG_SHA256):
        raise ValueError('input hashes are not the two known exact Rayman 2 samples')
    h_r, h_g = parse_headers(retail), parse_headers(gog)
    stream_report = inspect_stream_read_variants(retail,gog,h_r,h_g)
    xor_report = inspect_stream_xor_x86(retail,gog,h_r,h_g)
    word_checksum_report = inspect_stream_word_checksum(retail,gog,h_r,h_g)
    snapshot_provenance = inspect_snapshot_checksum_provenance(retail,gog,h_r,h_g)
    index_alias_report = inspect_snapshot_index_alias(retail,gog,h_r,h_g)
    names_r = read_file_table(retail, h_r)
    names_g = read_file_table(gog, h_g)
    if names_r != names_g or names_r[0] != 'LEVELS0.DAT':
        raise ValueError('asset name table mismatch between executables')
    # Same names and actual pointer values in these two builds, not just text.
    ptr_r = va_bytes(retail, h_r, TABLE_VA, 96)
    ptr_g = va_bytes(gog, h_g, TABLE_VA, 96)
    if ptr_r != ptr_g:
        raise ValueError('file path pointer table differs')
    fmt = va_cstr(retail, h_r, FORMAT_ORIGINAL_VA)
    gfmt = va_cstr(gog, h_g, FORMAT_GOG_VA)
    if fmt != '%c:\\%s\\%s' or gfmt != '%s\\%s':
        raise ValueError('unexpected original vs GOG file path formats')
    imports_r = import_entries(retail,h_r)
    imports_g = import_entries(gog,h_g)
    for entries in (imports_r,imports_g):
        if not any(e['name'] == 'CreateFileA' and e['dll'].upper() == 'KERNEL32.DLL'
                   and e['iat_va'] == 0x0049C058 for e in entries):
            raise ValueError('unverified CreateFileA import anchor')
    sites=[]
    for va, description, code_r, code_g in SITES:
        real_r = va_bytes(retail,h_r,va,len(code_r))
        real_g = va_bytes(gog,h_g,va,len(code_g))
        if real_r != code_r or real_g != code_g:
            raise ValueError(f'unsupported instruction comparison at 0x{va:08X}')
        sites.append({'va':f'0x{va:08X}', 'observation':description,
                      'bytes_checked_retail':len(code_r),'bytes_checked_gog':len(code_g)})
    return {
        'read_only':True, 'decryption_attempted':False,
        'disassembly_executed':False, 'control_flow_dynamically_verified':False,
        'both_exact_sha256_verified':hashes == (RETAIL_SHA256,GOG_SHA256),
        'reference_is_gog_not_pristine_retail':True,
        'drm_attribution_unproven':True,
        'retail_sha256':hashes[0],'gog_sha256':hashes[1],
        'file_table_va':f'0x{TABLE_VA:08X}',
        'file_table_pointers_identical':True,
        'file_table_pointer_sha256':hashlib.sha256(ptr_r).hexdigest(),
        'file_name_count':len(names_r),'file_names':names_r,
        'retail_path_format':fmt,'gog_path_format':gfmt,
        'direct_import_va':'0x0049C058','direct_import_api':'KERNEL32.dll!CreateFileA',
        'code_comparisons':sites,
        'stream_reader_variants':stream_report,
        'stream_read_xor_exact_x86':xor_report,
        'stream_postread_DWORD_checksum':word_checksum_report,
        'snapshot_checksum_resource_provenance':snapshot_provenance,
        'snapshot_checksum_index_alias_provenance':index_alias_report,
        'conclusion':('Verified local static I/O code changes at exact addresses: GOG omits the drive letter, '
                      'directly calls CreateFileA at one site, selects the first of 24 DAT names at a second '
                      'site, and shortens paths through other code. Runtime reachability, intent, SafeDisc '
                      'decryption and preservation of anti-tamper behavior are not demonstrated.')
    }


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail',type=Path,required=True)
    parser.add_argument('--gog',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        print(json.dumps(inspect_pair(safe_read(args.retail),safe_read(args.gog)),indent=2))
    except (OSError,ValueError,UnicodeError) as exc:
        parser.exit(1, f'ERROR: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
