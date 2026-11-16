#!/usr/bin/env python3
"""Exact-owner, read-only Rayman 2 encoded-descriptor NUL boundary audit.

No protected bytes emitted, no binary patch, no runtime DRM verdict.
GOG is a modified comparator, not a pristine retail plaintext reference.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from rayman2_callback2c_branch_audit import (
    CD_HASH, GOG_HASH, CD_SIZE, GOG_SIZE, layout, raw_at, require, encoded_export
)
from rayman2_callback30_iat_audit import pe_imports

BASE, STRIDE, COUNT = 0x4A13D0, 76, 36
# Original code checks the input's decoded name as an IMPORT prefix.
PREFIX_OPCODES = {
    0x448C60: '8a 56 ff', 0x448C6D: '8a 1e',
    0x448C72: '2a d9', 0x448C74: '32 d8',
    0x448C94: '2b c3', 0x448CA0: '3a da',
    0x448CA5: '72 c6',
}
# A separate loop searches encoded descriptor records until equal NUL.
NUL_OPCODES = {
    0x448D15: '8b 75 08', 0x448D1A: '8a 19',
    0x448D1E: '3a 1e', 0x448D22: '84 d2',
    0x448D24: '74 14', 0x448D2B: '3a 5e 01',
    0x448D30: '83 c1 02', 0x448D33: '83 c6 02',
    0x448D36: '84 d2', 0x448D38: '75 e0',
    0x448D43: '85 c9', 0x448D45: '74 12',
    0x448D47: '8a 4f 4c', 0x448D4A: '83 c7 4c',
    0x448D52: '75 be', 0x448D5E: '8b 4f 30',
    0x448D61: '8b 75 dc', 0x448D64: '33 ce',
    0x448D66: '2b c1',
}

def nul_equal(a: bytes, b: bytes) -> bool:
    """Equality of the two-byte-loop comparison, not strcmp ordering."""
    for x, y in zip(a, b):
        if x != y:
            return False
        if x == 0:
            return True
    return False

def inspect(cd: bytes, gog: bytes) -> dict:
    ca, ga = layout(cd), layout(gog)
    if (ca['.text'][:4], ga['.text'][:4]) != (
            (0x1000, 0x9A1D0, 0x9A200, 0x400),
            (0x1000, 0x9B000, 0x9B000, 0x1000)):
        raise ValueError('unexpected active PE .text layout')
    for va, opcode in {**PREFIX_OPCODES, **NUL_OPCODES}.items():
        require(cd, ca, va, bytes.fromhex(opcode))
    require(gog, ga, 0x448AB0, b'\x33\xc0\xc3')
    if ga['.extra'][4] & 0x20000000:
        raise ValueError('GOG archival section unexpectedly executable')
    old_imports, gog_imports = pe_imports(cd, ca), pe_imports(gog, ga)
    if len(old_imports) != 163 or old_imports != gog_imports:
        raise ValueError('unexpected original/GOG IAT identity')
    rows = []
    prefix_candidates = []
    for index in range(COUNT):
        va = BASE + STRIDE * index
        record = raw_at(cd, ca, va, STRIDE)
        if record != raw_at(gog, ga, va, STRIDE):
            raise ValueError('changed encoded record')
        name = encoded_export(record)
        first_nul = record.find(b'\x00')
        encoded_end = 5 + record[4]
        if not 0 <= first_nul <= encoded_end:
            raise ValueError('invalid descriptor end')
        if any(imported.startswith(name) for imported in old_imports):
            prefix_candidates.append(index)
        # An early NUL can truncate this *second* comparison even when
        # the first-stage decoded name matches an actual IAT import.
        if first_nul < encoded_end:
            rows.append({'index': index, 'name': name,
                         'first_nul_offset': first_nul,
                         'encoded_end_offset': encoded_end,
                         'compared_bytes_including_nul': first_nul + 1})
        # The full encoded name signature must have exactly one file-backed
        # copy at the expected .data VA in each sample; .extra is inert.
        sig = record[:encoded_end]
        for source, sections in ((cd, ca), (gog, ga)):
            appearances = []
            for section_name, (rva, virtual, raw_len, file_off, _) in sections.items():
                chunk = source[file_off:file_off+min(virtual, raw_len)]
                start = 0
                while True:
                    offset = chunk.find(sig, start)
                    if offset < 0:
                        break
                    appearances.append((section_name, 0x400000+rva+offset))
                    start = offset + 1
            if appearances != [('.data', va)]:
                raise ValueError('encoded export signature changed/duplicated')
    if [(r['index'], r['first_nul_offset']) for r in rows] != [(3,5),(26,3)]:
        raise ValueError('unexpected early-NUL descriptor census')
    if [r['name'] for r in rows] != ['QueryPerformanceFrequency','LoadLibraryA']:
        raise ValueError('unexpected early-NUL API names')
    if len(prefix_candidates) != 18:
        raise ValueError('unexpected IAT candidate count')
    return {
        'read_only': True, 'sha256_exact_samples_verified': False,
        'records': COUNT, 'normal_records': COUNT-len(rows),
        'first_stage_matches_decoded_name_prefix': True,
        'second_stage_stops_at_equal_nul_byte': True,
        'early_nul_records': rows, 'iat_import_count': len(old_imports),
        'iat_prefix_candidate_count': len(prefix_candidates),
        'runtime_export_input_known': False, 'safe_disc_check_observed': False,
        'unprotected_exe_created': False, 'proprietary_bytes_emitted': False,
    }

def audit(cd: bytes, gog: bytes) -> dict:
    if len(cd) != CD_SIZE or hashlib.sha256(cd).hexdigest() != CD_HASH:
        raise ValueError('unknown CD sample')
    if len(gog) != GOG_SIZE or hashlib.sha256(gog).hexdigest() != GOG_HASH:
        raise ValueError('unknown GOG sample')
    result = inspect(cd, gog)
    result['sha256_exact_samples_verified'] = True
    return result

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--retail', type=Path, required=True)
    ap.add_argument('--gog', type=Path, required=True)
    args = ap.parse_args()
    for path in (args.retail, args.gog):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
            ap.error('need a regular bounded original owner file')
    try:
        print(json.dumps(audit(args.retail.read_bytes(),args.gog.read_bytes()),
                         indent=2, sort_keys=True))
    except (OSError, ValueError) as e:
        ap.error(str(e))

if __name__ == '__main__':
    main()
