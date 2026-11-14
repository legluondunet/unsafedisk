"""Synthetic regression tests for read-only Rayman 2 resource-path fallback audit."""
from __future__ import annotations
import os
from pathlib import Path
import struct
import tempfile
import unittest
from rayman2_dat_path_fallback_audit import (
    PATH_BASE, PATH_STRIDE, PATH_COUNTER, DISPATCH_TAG,
    file_backed_va, path_slot, dispatch_target, extension_targets, audit,
)


class PathFallbackTests(unittest.TestCase):
    def test_stride_first_and_last_80th(self):
        self.assertEqual(path_slot(0), PATH_BASE)
        self.assertEqual(path_slot(79), PATH_COUNTER - PATH_STRIDE)
        self.assertEqual(path_slot(80), PATH_COUNTER)

    def test_byte_index_limit(self):
        for x in (-1, 256, 2**40, 2.5, None):
            with self.subTest(value=x), self.assertRaises(ValueError):
                path_slot(x)

    def test_dispatch_positive(self):
        table = bytearray([11]*121)
        table[DISPATCH_TAG] = 1
        jump = struct.pack('<12I',*[0x401000 + i*0x10 for i in range(12)])
        self.assertEqual(dispatch_target(table,jump,DISPATCH_TAG), 0x401010)

    def test_dispatch_ignores_neighbor_tag(self):
        table = bytearray([11]*121)
        table[0x1f] = 2
        jump = struct.pack('<12I',*[0x401000 + i*0x10 for i in range(12)])
        self.assertEqual(dispatch_target(table,jump,0x1f), 0x401020)
        self.assertEqual(dispatch_target(table,jump,0x1e), 0x4010b0)

    def test_dispatch_bounds(self):
        table=bytes(121); jumps=bytes(48)
        for idx in (-1,121,2000):
            with self.subTest(tag=idx), self.assertRaises(ValueError):
                dispatch_target(table,jumps,idx)

    def test_dispatch_rejects_truncated(self):
        for table,jumps in [(bytes(120),bytes(48)),(bytes(121),bytes(44)),(bytes(122),bytes(48))]:
            with self.subTest(lengths=(len(table),len(jumps))), self.assertRaises(ValueError):
                dispatch_target(table,jumps,0)

    def test_dispatch_rejects_invalid_slot(self):
        table=bytes([12])+bytes(120)
        with self.assertRaises(ValueError):
            dispatch_target(table,bytes(48),0)

    def test_extensions_switch_exact(self):
        targets=(0x11,0x22,0x33,0x44,0x55)
        self.assertEqual(extension_targets(struct.pack('<5I',*targets)),targets)

    def test_extensions_switch_truncation(self):
        for size in (0,19,21,255):
            with self.subTest(size=size),self.assertRaises(ValueError):
                extension_targets(bytes(size))

    def test_file_backed_mapping_rejects_invalid_headers(self):
        for raw in (b'',b'PE'*80,b'MZ', b'MZ'+b'\0'*64):
            with self.subTest(length=len(raw)),self.assertRaises(ValueError):
                file_backed_va(raw,0x4a2228,5)

    def test_file_backed_mapping_rejects_invalid_lengths(self):
        for length in (0,-1,129):
            with self.subTest(length=length),self.assertRaises(ValueError):
                file_backed_va(bytes(256),0x4a2228,length)

    def test_no_live_code_claim_in_metadata(self):
        self.assertEqual(PATH_COUNTER - PATH_BASE, 30*80)
        self.assertEqual(PATH_STRIDE,30)

    def test_live_integration_on_exact_owner_samples(self):
        root=Path(__file__).parent
        a=root/'Rayman2(3).exe'
        b=root/'Rayman2.exe'
        if not (a.exists() and b.exists()):
            self.skipTest('owner binaries not available in this checkout')
        report=audit(a,b)
        self.assertTrue(report['fallback_preserved_in_gog'])
        self.assertEqual(report['parser_path_record_tag'],'0x1F')
        self.assertEqual(report['slots_between_path_base_and_adjacent_counter'],80)
        self.assertEqual(len(report['fallback_extension_strings']),5)
        a,b=report['original_cd_vs_gog_path_formats']
        self.assertEqual(a['original_ascii'],r'%c:\%s')
        self.assertEqual(a['gog_ascii'],r'%c\\%s')
        self.assertEqual(b['original_ascii'],r'%c:\%s\%s')
        self.assertEqual(b['gog_ascii'],r'%c\\%s\%s')
        self.assertEqual(report['gog_drive_prefix_seed_character'],'.')
        self.assertFalse(report['physical_cd_authentication_proven'])

    def test_hash_gate_rejects_modified_owner_copy(self):
        root=Path(__file__).parent
        a=root/'Rayman2(3).exe'
        b=root/'Rayman2.exe'
        if not (a.exists() and b.exists()):
            self.skipTest('owner binaries not available in this checkout')
        with tempfile.TemporaryDirectory() as d:
            corrupted=Path(d)/'bad.exe'
            payload=bytearray(a.read_bytes());payload[0x200] ^= 1
            corrupted.write_bytes(payload)
            with self.assertRaises(ValueError):
                audit(corrupted,b)


if __name__=='__main__':unittest.main()