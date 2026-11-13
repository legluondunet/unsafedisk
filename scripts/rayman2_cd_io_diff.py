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
