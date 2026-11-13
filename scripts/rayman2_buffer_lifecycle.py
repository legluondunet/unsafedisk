#!/usr/bin/env python3
"""Read-only Rayman 2 CD/GOG PRNG buffer lifetime check on pinned PE32 files.

No PE execution, writing to game files, decrypting, or SafeDisc conclusions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from pe_import_xrefs import parse_headers, import_entries, rva_file_offset
from rayman2_cd_io_diff import safe_read

RETAIL = '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
GOG = '9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
BUFFER_VA = 0x00510EA0
INITIAL_WORDS = 0x119
OFFSET_DIVISOR = 0x455
FLUSH_BYTES = 0x464
SCRUB_BYTES = 15
# (wrapper, indirect-call VA, scrub-loop first VA, loop-tail VA, returned function)
WRAPPERS = (
    (0x00448500, 0x0044859D, 0x004485A8, 0x004485F3, 'CloseHandle'),
    (0x0044E750, 0x0044E820, 0x0044E82D, 0x0044E88D, 'ReadFile'),
    (0x0044F220, 0x0044F2FA, 0x0044F307, 0x0044F367, 'CreateFileA'),
    (0x0044F380, 0x0044F44B, 0x0044F458, 0x0044F4B8, 'SetFilePointer'),
)


def at(data: bytes, headers: dict, va: int, length: int) -> bytes:
    if not 1 <= length <= 256 or va < headers['image_base']:
        raise ValueError('invalid PE VA span')
    off = rva_file_offset(headers, va - headers['image_base'], length, len(data))
    return data[off:off+length]


def expect(data: bytes, headers: dict, va: int, hexbytes: str) -> None:
    expected = bytes.fromhex(hexbytes)
    if at(data, headers, va, len(expected)) != expected:
        raise ValueError(f'unexpected opcode at VA 0x{va:08X}')


def check_loop_tail(data: bytes, headers: dict, tail: int, start: int, close: bool) -> None:
    # INC pointer; CMP pointer with end; store PRNG remainder DL; JB loop.
    pattern = bytes.fromhex('46 3B F7 88 56 FF 72 AD' if close
                            else '47 3B FB 88 57 FF 72 98')
    if at(data, headers, tail, len(pattern)) != pattern:
        raise ValueError(f'unexpected scrub-loop tail at 0x{tail:08X}')
    displacement = int.from_bytes(pattern[-1:], 'little', signed=True)
    if tail+len(pattern)+displacement != start:
        raise ValueError('scrub branch does not target verified PRNG loop')


def inspect(retail: bytes, gog: bytes) -> dict:
    if hashlib.sha256(retail).hexdigest() != RETAIL:
        raise ValueError('unexpected retail SHA-256')
    if hashlib.sha256(gog).hexdigest() != GOG:
        raise ValueError('unexpected GOG SHA-256')
    rh, gh = parse_headers(retail), parse_headers(gog)
    for h, data in ((rh, retail), (gh, gog)):
        imports = import_entries(data, h)
        if not any(e['name'] == 'QueryPerformanceCounter'
                   and e['dll'].lower() == 'kernel32.dll'
                   and e['iat_va'] == 0x0049C060 for e in imports):
            raise ValueError('missing exact QueryPerformanceCounter import at 0x49C060')
    # Shared by the two exact builds: QPC, fallback, buffer fill, and save PRNG state.
    anchors = (
        (0x44938D, '8D 45 F8 50 FF 15 60 C0 49 00'),
        (0x44939E, 'B9 78 56 34 12'),
        (0x4493A3, 'BE A0 0E 51 00 BF 19 01 00 00'),
        (0x4493AD, '81 F1 24 D9 5B 07'),
        (0x4493DF, '89 0E 83 C6 04 4F 75 C6'),
        (0x4493EA, '89 0D F0 0B 51 00'),
    )
    for va, signature in anchors:
        expect(retail, rh, va, signature)
        expect(gog, gh, va, signature)
    if at(retail, rh, 0x44938D, 0x63) != at(gog, gh, 0x44938D, 0x63):
        raise ValueError('buffer-initialization code differs')
    sections = [s for s in rh['sections'] if (
        0 <= BUFFER_VA-rh['image_base']-s['rva'] < s['virtual_size'])]
    if (len(sections) != 1 or sections[0]['name'] != '.data' or
        BUFFER_VA-rh['image_base']-sections[0]['rva'] < sections[0]['raw_size']):
        raise ValueError('unexpected virtual buffer location')
    if (sections[0]['flags'] & 0xE0000000) != 0xC0000000:
        raise ValueError('unexpected non-executable read/write section flags')
    rows=[]
    for wrapper, indirect, loop, tail, api in WRAPPERS:
        expect(retail, rh, indirect, 'FF D6 8D 7E 0F' if api == 'CloseHandle'
               else 'FF D6 8D 5E 0F')
        expect(retail, rh, loop, '8B 0D F0 0B 51 00')
        # The original code draws new pseudo-random values and stores the low
        # remainder byte at each of 15 consecutive stub locations.
        check_loop_tail(retail, rh, tail, loop, api == 'CloseHandle')
        if at(gog, gh, indirect, 5) != b'\xcc'*5:
            raise ValueError('GOG has not removed expected original indirect stub')
        rows.append({'wrapper_va':f'0x{wrapper:08X}', 'api':api,
                     'scrub_loop_va':f'0x{loop:08X}', 'tail_va':f'0x{tail:08X}',
                     'scrub_bytes':SCRUB_BYTES,
                     'gog_original_callsite_int3':True})
    if (INITIAL_WORDS*4 != FLUSH_BYTES or
        (OFFSET_DIVISOR - 1) + SCRUB_BYTES > FLUSH_BYTES):
        raise ValueError('PRNG buffer arithmetic mismatch')
    return {'read_only':True,'no_game_execution':True,'hashes_verified':True,
            'source_original_and_gog':'two exact known binaries, not pristine no-DRM retail',
            'boot_seed':'QueryPerformanceCounter low DWORD if API succeeds, else 0x12345678',
            'boot_seed_runtime_value_unknown':True,
            'shared_initializer_identical_99_bytes':True,
            'buffer_va':f'0x{BUFFER_VA:08X}',
            'initial_prng_words':INITIAL_WORDS,
            'initial_prng_bytes':INITIAL_WORDS*4,
            'prng_offset_divisor':OFFSET_DIVISOR,
            'maximum_offset_for_nonnegative_state':OFFSET_DIVISOR-1,
            'flush_bytes':FLUSH_BYTES,'scrub_bytes_after_each_call':SCRUB_BYTES,
            'maximum_scrub_span':OFFSET_DIVISOR-1+SCRUB_BYTES,
            'four_obfuscated_original_wrappers':rows,
            'warning':'Static code consistency only. No runtime execution, DRM decryption, or actual NX page permissions established.'}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',type=Path,required=True)
    p.add_argument('--gog',type=Path,required=True)
    args=p.parse_args()
    try: print(json.dumps(inspect(safe_read(args.retail),safe_read(args.gog)),indent=2))
    except (OSError,ValueError) as exc:p.exit(1,f'ERROR: {exc}\n')


if __name__=='__main__':main()
