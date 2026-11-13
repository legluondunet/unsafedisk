"""Synthetic-only regression suite, plus optional exact private-bin integration."""
import os
from pathlib import Path
import struct
import unittest
from rayman2_dat_bootstrap import (decode_bootstrap_48, analyze_executables,
                                   OUTPUTS, pe_va, READ_CALL_VAS)


def fixture(a=100, b=200, c=7, d=9, words=None):
    if words is None:
        words=[(1000+i*123)&0xffffffff for i in range(8)]
    return struct.pack('<12I',a,b,c,d,*words)

class DatBootstrapTests(unittest.TestCase):
    def test_synthetic_known_globals(self):
        data=fixture()
        result=decode_bootstrap_48(data)
        self.assertEqual(len(result),6)
        words=struct.unpack_from('<8I',data,16)
        for idx, address, _, shift in OUTPUTS:
            expected=(((words[idx]-(100+7*idx)) & 0xffffffff) ^ (200+9*idx)) >> shift
            self.assertEqual(result[f'0x{address:08X}'],expected)

    def test_two_dummy_words_do_not_change_globals(self):
        a=decode_bootstrap_48(fixture(words=[1,2,3,4,5,6,7,8]))
        b=decode_bootstrap_48(fixture(words=[0xffffffff,2,3,4,5,6,7,0xffffffff]))
        self.assertEqual(a,b)

    def test_wrap_unsigned_a_b(self):
        out=decode_bootstrap_48(fixture(a=0xfffffff0,b=0xfffffff0,c=0x15,d=0x25))
        self.assertEqual(len(out),6)
        self.assertGreaterEqual(out['0x00511750'],0)
        self.assertLessEqual(out['0x00511750'],0x3fffffff)

    def test_invalid_short(self):
        for data in (b'',b'\0'*16,b'\0'*47,b'\0'*49):
            with self.subTest(n=len(data)),self.assertRaisesRegex(ValueError,'exactly 48 bytes'):
                decode_bootstrap_48(data)

    def test_correct_zero_output(self):
        self.assertEqual(set(decode_bootstrap_48(b'\0'*48).values()),{0})

    def test_all_one_bits(self):
        self.assertEqual(len(decode_bootstrap_48(b'\xff'*48)),6)

    def test_sequential_word_stepping(self):
        vals=decode_bootstrap_48(fixture(a=0,b=0,c=1,d=0,words=[0]*8))
        self.assertEqual(vals['0x005117B0'],0xffffffff)
        self.assertEqual(vals['0x00511750'],0x3fffffff)

    def test_wrong_binary_hashes(self):
        with self.assertRaisesRegex(ValueError,'retail sample SHA-256'):
            analyze_executables(b'wrong',b'wrong')

    def test_wrong_pe_header(self):
        with self.assertRaisesRegex(ValueError,'invalid PE32'):
            pe_va(b'no',0x401000,4)

    def test_read_callsite_count(self):
        self.assertEqual(len(READ_CALL_VAS),8)
        self.assertEqual(len(set(READ_CALL_VAS)),8)

    def test_exact_private_samples_when_available(self):
        folder=Path(os.environ.get('UNSAFEDISK_SAMPLES','/no/samples'))
        retail=folder/'Rayman2(3).exe'
        gog=folder/'rayman2(4).exe'
        if not retail.is_file() or not gog.is_file():
            self.skipTest('private game data not available; no fixtures committed')
        report=analyze_executables(retail.read_bytes(),gog.read_bytes())
        self.assertEqual(len([x for x in report['global_writes'] if 'global_va' in x]),6)
        self.assertEqual(report['nominal_minimum_bytes'],48)

if __name__ == '__main__':
    unittest.main()
