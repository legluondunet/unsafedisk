"""No proprietary game data in tests: static helper checks only."""
from __future__ import annotations
import struct
import unittest
from rayman2_dat_read_paths import analyze,rel_call,region,want

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

    def test_disallowed_bytes(self):
        h={'image_base':0x400000,
           'sections':[{'rva':0x1000,'raw_off':0,'raw_start':0,'raw_size':10}]}
        with self.assertRaisesRegex(ValueError,'code signature mismatch'):
            want(b'abcdefghij',h,0x401001,b'\xff\xfe')

if __name__=='__main__':unittest.main()
