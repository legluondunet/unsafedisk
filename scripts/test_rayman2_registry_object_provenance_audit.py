"""Synthetic tests, plus optional real SHA-locked integration when local owner PE files exist.

No commercial files are distributed; optional inputs are read-only. An absent
original/GOG pair skips the integration tests (the synthetic tests still run).
"""
import os
import struct
import unittest
from pathlib import Path

from rayman2_selfread_archive_audit import locked_read, sections
from rayman2_registry_object_provenance_audit import (
    BASE, REGISTRY_VA, ROW_COUNT, ROW_SIZE, TRAILER_VA, TRAILER_PREFIX,
    PARSER_TABLE_VA, PARSER_SENTINEL_VA, decode_rows, validate_registry, validate_trailer,
    scan_dword_literals, inspect, one, GENERIC_COUNTS,
)
from rayman2_selfread_typed_callback_audit import disassemble_text


def rows_fixture():
    rows=[(0x470210,0)]*ROW_COUNT
    rows[0x170]=(0x470000,1)
    return rows


def trailer_fixture():
    return b''.join(TRAILER_PREFIX + struct.pack('<I',1 if i==5 else 0)
                    for i in range(7))


class SyntheticTests(unittest.TestCase):
    def test_unpack_registry(self):
        rows=rows_fixture()
        self.assertEqual(decode_rows(b''.join(struct.pack('<II',*r) for r in rows)),rows)

    def test_registry_stats(self):
        r=validate_registry(rows_fixture())
        self.assertEqual(r['row_count'],514)
        self.assertEqual(r['last_index_hex'],'0x201')
        self.assertTrue(r['type_0x170_unique_handler_entry'])

    def test_registry_reject_wrong_length(self):
        with self.assertRaises(ValueError):decode_rows(b'\0'*4096)

    def test_registry_reject_zero_limit(self):
        with self.assertRaises(ValueError):decode_rows(b'',0)

    def test_registry_reject_duplicate_handler(self):
        rows=rows_fixture();rows[0x162]=(0x470000,1)
        with self.assertRaises(ValueError):validate_registry(rows)

    def test_registry_reject_modified_special_handler(self):
        rows=rows_fixture();rows[0x170]=(0x470210,1)
        with self.assertRaises(ValueError):validate_registry(rows)

    def test_registry_reject_invalid_flag(self):
        rows=rows_fixture();rows[0x160]=(0x470210,3)
        with self.assertRaises(ValueError):validate_registry(rows)

    def test_registry_reject_noncode_address(self):
        rows=rows_fixture();rows[0x160]=(0x3f800000,0)
        with self.assertRaises(ValueError):validate_registry(rows)

    def test_registry_reject_bad_neighbor(self):
        rows=rows_fixture();rows[0x171]=(0x470000,0)
        with self.assertRaises(ValueError):validate_registry(rows)

    def test_trailer_exact(self):
        r=validate_trailer(trailer_fixture())
        self.assertEqual(r['numeric_block_count'],7)
        self.assertEqual(r['trailer_bytes'],112)

    def test_trailer_bad_length(self):
        with self.assertRaises(ValueError):validate_trailer(trailer_fixture()[:-1])

    def test_trailer_modified_constant(self):
        raw=bytearray(trailer_fixture());raw[11]=0x42
        with self.assertRaises(ValueError):validate_trailer(bytes(raw))

    def test_trailer_modified_sixth_flag(self):
        raw=bytearray(trailer_fixture());raw[5*16+12]=0
        with self.assertRaises(ValueError):validate_trailer(bytes(raw))

    def test_dword_search(self):
        raw=b'\xaa'+struct.pack('<I',0x170)+b'\xbb'+struct.pack('<I',0x170)
        self.assertEqual(scan_dword_literals(raw,0x170),2)

    def test_dword_search_invalid_input(self):
        with self.assertRaises(ValueError):scan_dword_literals(b'',-1)


class OptionalRealInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('RAYMAN2_OWNER_SAMPLES','/mnt/data/rayman2_research'))
        retail,gog=root/'Rayman2(3).exe',root/'Rayman2.exe'
        if not retail.is_file() or not gog.is_file():
            raise unittest.SkipTest('owner-supplied exact binaries absent; integration optional')
        cls.cd=locked_read(retail,'cd')
        cls.gog=locked_read(gog,'gog')
        cls.cd_asm=disassemble_text(retail)
        cls.gog_asm=disassemble_text(gog)
        _,cls.cd_sec=sections(cls.cd)

    def mutated(self,va,byte):
        sec=self.cd_sec['.data'] if va>=0x49f000 else self.cd_sec['.text']
        off=sec.raw_offset + va-BASE-sec.rva
        blob=bytearray(self.cd);blob[off]=byte
        return bytes(blob)

    def test_real_inputs_match_and_514_rows(self):
        r=inspect(self.cd,self.gog,self.cd_asm,self.gog_asm)
        self.assertEqual(r['inputs'][0]['registry']['row_count'],514)
        self.assertEqual(r['inputs'][0]['registry']['unique_handler_addresses'],159)
        self.assertEqual(r['inputs'][0]['registry']['flag_one_count'],299)
        self.assertEqual(r['inputs'][0]['registry']['flag_zero_count'],215)

    def test_real_nested_parser_sites(self):
        r=one(self.cd,self.cd_asm,'cd')
        self.assertEqual(r['parser_byte_class_2_handler'],'0x4808b0')
        self.assertEqual(r['parser_table_count'],41)
        self.assertEqual(r['parser_table_unique_handlers'],38)
        self.assertEqual(r['generic_direct_calls']['0x00481C10'],15)
        self.assertEqual(r['generic_direct_calls']['0x00480B90'],757)

    def test_real_registry_flag_lookup_is_generic(self):
        r=one(self.cd,self.cd_asm,'cd')
        self.assertEqual(r['generic_direct_calls']['0x00482680'],68)
        self.assertEqual(r['generic_direct_calls']['0x00482690'],1)
        self.assertEqual(r['registry']['flag_one_count'],299)

    def test_real_changed_registry_fails(self):
        with self.assertRaises(ValueError):
            one(self.mutated(REGISTRY_VA+0x170*ROW_SIZE,0x42),self.cd_asm,'mutated')

    def test_real_changed_end_of_registry_fails(self):
        with self.assertRaises(ValueError):
            one(self.mutated(TRAILER_VA,0),self.cd_asm,'mutated')

    def test_real_changed_parser_target_fails(self):
        with self.assertRaises(ValueError):
            one(self.mutated(PARSER_TABLE_VA+2*4,0),self.cd_asm,'mutated')

    def test_real_changed_parser_end_fails(self):
        with self.assertRaises(ValueError):
            one(self.mutated(PARSER_TABLE_VA+40*4,0x42),self.cd_asm,'mutated')

    def test_real_changed_parser_sentinel_fails(self):
        with self.assertRaises(ValueError):
            one(self.mutated(PARSER_SENTINEL_VA,0x42),self.cd_asm,'mutated')

    def test_real_changed_type_test_fails(self):
        with self.assertRaises(ValueError):
            one(self.mutated(0x47010E,0x90),self.cd_asm,'mutated')


if __name__=='__main__':unittest.main()
