#!/usr/bin/env python3
"""Read-only, SHA-locked audit of two GOG Windows-message changes in Rayman 2.

The GOG binary is not a pristine SafeDisc-unwrapped reference. This script
never patches, executes or exports any proprietary bytes from either image.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

SAMPLES = {
    "retail": (676352, "7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3"),
    "gog": (1468928, "9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713"),
}
BASE = 0x400000


def checked_sample(path: str | Path, kind: str) -> bytes:
    blob = Path(path).read_bytes()
    n, digest = SAMPLES[kind]
    if len(blob) != n or hashlib.sha256(blob).hexdigest() != digest:
        raise ValueError(f"{kind}: refusing input not matching exact owner sample")
    return blob


class PE32:
    def __init__(self, blob: bytes):
        self.blob = blob
        if len(blob) < 0x100 or blob[:2] != b"MZ":
            raise ValueError("not an MZ executable")
        pe = struct.unpack_from('<I', blob, 0x3C)[0]
        if pe + 0x18 + 0x60 > len(blob) or blob[pe:pe+4] != b"PE\0\0":
            raise ValueError("invalid PE header")
        machine, sections, _, _, _, opts, _ = struct.unpack_from('<HHIIIHH', blob, pe + 4)
        opt = pe + 24
        if machine != 0x14C or struct.unpack_from('<H', blob, opt)[0] != 0x10B or opts < 0x60:
            raise ValueError("only PE32 i386 supported")
        self.base = struct.unpack_from('<I', blob, opt + 0x1C)[0]
        self.sections = []
        offset = opt + opts
        for i in range(sections):
            s = offset + i * 40
            if s+40 > len(blob):
                raise ValueError("truncated section table")
            name = blob[s:s+8].rstrip(b'\0').decode('ascii', 'replace')
            virtual_size, rva, raw_size, raw_offset = struct.unpack_from('<IIII', blob, s+8)
            if raw_offset+raw_size > len(blob):
                raise ValueError("file-backed section extends beyond file")
            self.sections.append((name, rva, virtual_size, raw_size, raw_offset))
        if self.base != BASE:
            raise ValueError("wrong ImageBase")

    def at(self, va: int, size: int) -> bytes:
        if size < 0 or va < self.base:
            raise ValueError('invalid mapped range')
        rva = va - self.base
        for _, start, _, raw_size, raw_offset in self.sections:
            if start <= rva and rva + size <= start+raw_size:
                return self.blob[raw_offset+rva-start:raw_offset+rva-start+size]
        raise ValueError(f"unmapped VA 0x{va:X} size={size}")


def expect(pe: PE32, va: int, raw: bytes, label: str) -> None:
    if pe.at(va, len(raw)) != raw:
        raise ValueError(f"{label}: x86 bytes mismatch at 0x{va:X}")


def rel32_target(va: int, instruction: bytes) -> int:
    if len(instruction) != 5 or instruction[0] != 0xE8:
        raise ValueError('not CALL rel32')
    return va + 5 + struct.unpack('<i', instruction[1:])[0]


def short_target(va: int, instruction: bytes, opcode: int) -> int:
    if len(instruction) != 2 or instruction[0] != opcode:
        raise ValueError(f'not short opcode 0x{opcode:02X}')
    return va + 2 + struct.unpack('<b', instruction[1:])[0]


def audit_images(retail: PE32, gog: PE32) -> dict:
    # Prologue is common, and the two Windows message discriminators are
    # unchanged in both files. All offsets are VAs, not file offsets.
    same = {
        0x401B50: bytes.fromhex('8B 4C 24 04 53 83 C1 DF'),
        0x402039: bytes.fromhex('C7 44 24 18 D0 22 40 00'),
        0x4022DD: bytes.fromhex('8B 7C 24 1C'),
        0x401B5C: bytes.fromhex('83 F9 04'),
        0x401C30: bytes.fromhex('6D 1B 40 00 06 1C 40 00 2A 1C 40 00 9A 1B 40 00 20 1C 40 00'),
        0x402520: bytes.fromhex('81 FF 18 02 00 00'),
        0x402528: bytes.fromhex('81 FF 00 04 00 00'),
        0x40252E: bytes.fromhex('75 1D 55 53'),
        0x402537: bytes.fromhex('83 C4 08 EB 0F'),
        0x40254B: bytes.fromhex('8B F0 85 F6'),
        0x402580: bytes.fromhex('8B 4C 24 04 33 C0 8B 51 04'),
        0x402589: bytes.fromhex('83 FA 1C 74 19'),
        0x40258E: bytes.fromhex('81 FA 00 04 00 00'),
        0x402596: bytes.fromhex('8B 41 0C 8B 49 08 50 51'),
        0x4025A3: bytes.fromhex('83 C4 08 C3'),
        0x4025A7: bytes.fromhex('8B 41 08 85 C0'),
        0x4025BE: bytes.fromhex('C3'),
    }
    for va, raw in same.items():
        expect(retail, va, raw, 'retail common')
        expect(gog, va, raw, 'gog common')
    # At 0x401B50, the first argument is reduced by 0x21 and dispatched
    # through the five-target table at 0x401C30 (0x21..0x25).
    # Callback VA 0x4022D0 is stored in WNDCLASS, and its second argument
    # (the Win32 message ID) is loaded into EDI at 0x4022DD.
    # An original call handling WM_USER has been NOPed in GOG.
    call = retail.at(0x402532, 5)
    if rel32_target(0x402532, call) != 0x401B50:
        raise ValueError('retail WM_USER call target mismatch')
    expect(gog, 0x402532, b'\x90'*5, 'GOG WM_USER call disabled')
    # A second helper bypasses only the WM_USER handling branch in GOG.
    rbranch, gbranch = retail.at(0x402594, 2), gog.at(0x402594, 2)
    if short_target(0x402594, rbranch, 0x75) != 0x4025BE:
        raise ValueError('retail JNE target mismatch')
    if short_target(0x402594, gbranch, 0xEB) != 0x4025BE:
        raise ValueError('GOG JMP target mismatch')
    if rel32_target(0x40259E, retail.at(0x40259E, 5)) != 0x401B50:
        raise ValueError('second retail call target mismatch')
    expect(gog, 0x40259E, retail.at(0x40259E, 5), 'secondary call preserved')
    # The branches that test message IDs 0x218 and 0x1C are also preserved.
    if short_target(0x40258C, retail.at(0x40258C, 2), 0x74) != 0x4025A7:
        raise ValueError('WM_ACTIVATEAPP branch mismatch')
    if short_target(0x40253A, retail.at(0x40253A, 2), 0xEB) != 0x40254B:
        raise ValueError('common call-result branch mismatch')
    return {
        'sample_ids': {k: {'bytes': n, 'sha256': h} for k,(n,h) in SAMPLES.items()},
        'known_windows_messages': {
            '0x400': 'WM_USER (application-defined message base)',
            '0x218': 'WM_POWERBROADCAST',
            '0x1C': 'WM_ACTIVATEAPP',
        },
        'changes': [
            {'va': '0x402532', 'retail': 'CALL 0x401B50', 'gog': '5 NOP',
             'condition': 'EDI == 0x400 inside first message handler',
             'effect': 'original message-specific dispatch no longer called'},
            {'va': '0x402594', 'retail': 'JNE 0x4025BE', 'gog': 'JMP 0x4025BE',
             'condition': 'EDX != 0x1C inside second handler',
             'effect': 'original 0x400-specific callback branch bypassed'},
        ],
        'unchanged': ['WNDCLASS uses WndProc 0x4022D0 (0x402039)',
                      'command dispatch 0x21..0x25 at 0x401C30',
                      '0x401B50 message dispatch function',
                      '0x40259E secondary CALL 0x401B50',
                      '0x402589 compare against 0x1C',
                      '0x402520 compare against 0x218'],
        'interpretation': 'Windows message-handling change; not an established SafeDisc check',
    }


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail', required=True)
    p.add_argument('--gog', required=True)
    a = p.parse_args()
    report = audit_images(PE32(checked_sample(a.retail,'retail')),
                          PE32(checked_sample(a.gog,'gog')))
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()