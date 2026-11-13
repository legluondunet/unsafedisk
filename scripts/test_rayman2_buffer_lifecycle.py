"""Synthetic, no game-file fixtures. Test the static buffer lifecycle verifier."""
import unittest
from rayman2_buffer_lifecycle import (at, expect, check_loop_tail, inspect, WRAPPERS,
                                     INITIAL_WORDS, FLUSH_BYTES, OFFSET_DIVISOR, SCRUB_BYTES)

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.h = {'image_base':0x400000,'sections':[{'rva':0x1000,'raw_size':1000,
                                                   'raw_start':0}]}

    def test_bad_hashes_refused(self):
        with self.assertRaisesRegex(ValueError,'retail SHA-256'):
            inspect(b'synthetic source',b'synthetic reference')

    def test_mapping_works(self):
        self.assertEqual(at(b'abcdefghij', self.h, 0x401002, 3), b'cde')

    def test_bad_range_refused(self):
        with self.assertRaises(ValueError): at(b'ab', self.h, 0x401000, 257)

    def test_expected_pattern(self):
        expect(b'abc\x90\x90xyz', self.h, 0x401003,'90 90')
        with self.assertRaisesRegex(ValueError,'unexpected opcode'):
            expect(b'abc\x90\x90xyz',self.h,0x401003,'90 91')

    def test_scrub_close_branch_valid(self):
        base=0x400000
        data=bytearray(1000)
        tail=0x401050; start=tail+8-83
        data[0x50:0x58]=bytes.fromhex('46 3B F7 88 56 FF 72 AD')
        check_loop_tail(bytes(data),self.h,tail,start,True)

    def test_scrub_read_branch_valid(self):
        data=bytearray(1000)
        tail=0x4010A0; start=tail+8-104
        data[0xA0:0xA8]=bytes.fromhex('47 3B FB 88 57 FF 72 98')
        check_loop_tail(bytes(data),self.h,tail,start,False)

    def test_bad_tail_refused(self):
        with self.assertRaisesRegex(ValueError,'scrub-loop tail'):
            check_loop_tail(b'\x90'*1000, self.h,0x401100,0x401000,False)

    def test_tail_incorrect_target_refused(self):
        data=bytearray(1000)
        data[0xA0:0xA8]=bytes.fromhex('47 3B FB 88 57 FF 72 98')
        with self.assertRaisesRegex(ValueError,'scrub branch'):
            check_loop_tail(bytes(data),self.h,0x4010A0,0x4010A0,False)

    def test_unique_wrappers(self):
        self.assertEqual(len(WRAPPERS),4)
        self.assertEqual(len(set(row[1] for row in WRAPPERS)),4)
        self.assertEqual({row[-1] for row in WRAPPERS},
                         {'CloseHandle','ReadFile','CreateFileA','SetFilePointer'})

    def test_buffer_exact_word_count(self):
        self.assertEqual(INITIAL_WORDS*4,FLUSH_BYTES)

    def test_scrub_can_fit_at_largest_offset(self):
        self.assertEqual((OFFSET_DIVISOR-1)+SCRUB_BYTES,1123)
        self.assertEqual(FLUSH_BYTES,1124)
        self.assertGreater(FLUSH_BYTES,1123)

if __name__ == '__main__': unittest.main()
