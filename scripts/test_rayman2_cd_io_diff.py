"""Synthetic PE-data tests; exact commercial samples are never fixtures."""
import os
from pathlib import Path
import struct
import tempfile
import unittest

from rayman2_cd_io_diff import (
    GOG_SHA256, RETAIL_SHA256, SITES, TABLE_VA,
    inspect_pair, read_file_table, safe_read, va_bytes, va_cstr,
)


class FileIoDiffTests(unittest.TestCase):
    def test_hash_gate_rejects_wrong_inputs(self):
        with self.assertRaisesRegex(ValueError, 'input hashes'):
            inspect_pair(b'not a retail file', b'not a GOG file')

    def test_known_hashes_are_distinct(self):
        self.assertEqual(len(RETAIL_SHA256), 64)
        self.assertEqual(len(GOG_SHA256), 64)
        self.assertNotEqual(RETAIL_SHA256, GOG_SHA256)

    def test_byte_mapping_for_shifted_sections(self):
        image = b'x' * 9 + b'xyz' + b'x' * 10
        h = {'image_base': 0x400000,
             'sections':[{'rva':0x1000,'raw_off':4,'raw_size':15}]}
        self.assertEqual(va_bytes(image,h,0x401005,3), b'xyz')

    def test_out_of_bounds_va_refused(self):
        h = {'image_base': 0x400000,
             'sections':[{'rva':0x1000,'raw_off':0,'raw_size':10}]}
        with self.assertRaises(ValueError):
            va_bytes(b'1234567890',h,0x401009,3)
        with self.assertRaises(ValueError):
            va_bytes(b'1234567890',h,0x401000,513)

    def table_fixture(self, duplicate=False, corrupt=False):
        h = {'image_base':0x400000,'sections':[{'rva':0xA0000,
              'raw_off':0x1000,'raw_size':0x3000}]}
        data = bytearray(0x4000)
        groups = ['LEVELS','MAP','TEXTURES','ANIMS','SOUNDS','MUSIC','GRAPHICS','MENU']
        names = [f'{group}{level}.DAT' for level in range(3) for group in groups]
        for i,name in enumerate(names):
            name_va = 0x4A2300 + i*24
            if duplicate and i == 1:
                name_va = 0x4A2300
            struct.pack_into('<I',data,0x1000+TABLE_VA-0x4A0000+i*4,name_va)
            if corrupt and i == 7:
                name='BAD.PRG'
            if not (duplicate and i == 1):
                encoded = name.encode() + b'\0'
                start=0x1000+name_va-0x4A0000
                data[start:start+len(encoded)] = encoded
        return bytes(data),h,names

    def test_extract_exact_twenty_four_unique_names(self):
        data,h,names = self.table_fixture()
        self.assertEqual(read_file_table(data,h), names)

    def test_reject_duplicate_table_name(self):
        data,h,_=self.table_fixture(duplicate=True)
        with self.assertRaisesRegex(ValueError,'duplicate'):
            read_file_table(data,h)

    def test_reject_non_data_table_name(self):
        data,h,_=self.table_fixture(corrupt=True)
        with self.assertRaisesRegex(ValueError,'unexpected'):
            read_file_table(data,h)

    def test_unterminated_va_string(self):
        h={'image_base':0x400000,'sections':[{'rva':0x1000,'raw_off':0,'raw_size':5}]}
        with self.assertRaisesRegex(ValueError,'unterminated'):
            va_cstr(b'ABCDE',h,0x401000,max_len=5)

    def test_site_variants_all_different(self):
        for va,description,retail,gog in SITES:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(retail,gog)
                self.assertTrue(description)
                self.assertLessEqual(max(len(retail),len(gog)),7)

    def test_safe_read_rejects_symlink(self):
        if not hasattr(os,'symlink'):self.skipTest('no symlink support')
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'sample'
            path.write_bytes(b'fake')
            link = Path(root) / 'link'
            try:link.symlink_to(path)
            except OSError:self.skipTest('symlink unsupported')
            with self.assertRaisesRegex(ValueError,'symlink'):
                safe_read(link)

    def test_safe_read_regular(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'sample'
            path.write_bytes(b'ordinary synthetic data')
            self.assertEqual(safe_read(path),b'ordinary synthetic data')


if __name__ == '__main__':unittest.main()
