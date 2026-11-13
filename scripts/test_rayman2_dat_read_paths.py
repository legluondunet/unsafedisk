"""No proprietary game data in tests: static helper checks only."""
from __future__ import annotations
import struct
import unittest
from rayman2_dat_read_paths import analyze,rel_call,region,want,derive_dat_word

class DatReadPathTests(unittest.TestCase):
    def test_retail_hash_gate(self):
        with self.assertRaisesRegex(ValueError,'retail executable hash'):
            analyze(b'dummy original',b'dummy reference')

    def test_relative_call_calculation(self):
        site,target=0x44F125,0x44E750
        expected=b'\xe8'+struct.pack('<i',target-site-5)
        self.assertEqual(rel_call(site,target),expected)

    def test_relative_call_forward(self):
        self.assertEqual(rel_call(0x401000,0x401006),b'\xe8\x01\0\0\0')

    def test_mapped_va(self):
        h={'image_base':0x400000,
           'sections':[{'rva':0x1000,'raw_off':5,'raw_start':5,'raw_size':20}]}
        self.assertEqual(region(b'_____' + b'abcdefgh' + b'\0'*12,h,0x401002,3),b'cde')

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            region(b'\0',{'image_base':0x400000},0x401000,257)

    def test_derive_zero_index(self):
        h=struct.pack('<4I',10,20,3,4)
        self.assertEqual(derive_dat_word(h,30,0),((30-10)&0xffffffff)^20)

    def test_derive_positive_index(self):
        h=struct.pack('<4I',10,20,3,4)
        self.assertEqual(derive_dat_word(h,30,2),((30-16)&0xffffffff)^28)

    def test_derive_u32_wrap(self):
        h=struct.pack('<4I',0xfffffff0,0xfffffff0,0x22,0x30)
        self.assertEqual(derive_dat_word(h,0,1),((0-0x12)&0xffffffff)^0x20)

    def test_bad_header_length(self):
        with self.assertRaisesRegex(ValueError,'invalid DAT'):
            derive_dat_word(b'no',0,0)

    def test_negative_index(self):
        with self.assertRaisesRegex(ValueError,'invalid DAT'):
            derive_dat_word(b'\0'*16,0,-1)

    def test_index_limit(self):
        with self.assertRaisesRegex(ValueError,'invalid DAT'):
            derive_dat_word(b'\0'*16,0,65536)

    def test_non_uint32_word(self):
        with self.assertRaisesRegex(ValueError,'invalid DAT'):
            derive_dat_word(b'\0'*16,0,2**32)

    def test_disallowed_bytes(self):
        h={'image_base':0x400000,
           'sections':[{'rva':0x1000,'raw_off':0,'raw_start':0,'raw_size':10}]}
        with self.assertRaisesRegex(ValueError,'code signature mismatch'):
            want(b'abcdefghij',h,0x401001,b'\xff\xfe')

if __name__=='__main__':unittest.main()
