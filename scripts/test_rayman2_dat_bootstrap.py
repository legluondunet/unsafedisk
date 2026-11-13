"""Synthetic-only regression suite, plus optional exact private-bin integration."""
import os
import math
from pathlib import Path
import struct
import unittest
from rayman2_dat_bootstrap import (decode_bootstrap_48, analyze_executables,
                                   OUTPUTS, pe_va, READ_CALL_VAS,
                                   approximate_dat_seek, SELECTOR_CONSTANTS, SELECTOR_ANCHORS)


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

    def test_selector_zero_remainder_does_not_read(self):
        for v in (0, 4, 20, 252):
            with self.subTest(v=v):
                result=approximate_dat_seek(v,4,100,21,57)
                self.assertFalse(result['read_occurs'])
                self.assertIsNone(result['j_approximate'])

    def test_selector_single_round(self):
        result=approximate_dat_seek(1,256,101,21,57)
        acc=1.06913+0.52658
        ticks=math.floor(math.modf(acc)[0]*1000000.0)
        j=math.floor(ticks*1e-6*101)
        self.assertEqual(result['j_approximate'],j)
        self.assertEqual(result['position_approximate'],(21+j*57)&0xffffffff)

    def test_selector_maximum_remainder(self):
        result=approximate_dat_seek(255,256,3000,0,1)
        self.assertEqual(result['m'],255)
        self.assertTrue(0<=result['j_approximate']<3000)

    def test_selector_many_states_bound(self):
        for modulus in (1,2,3,5,13,256,0xffffffff):
            for b in range(256):
                r=approximate_dat_seek(b,modulus,103,100,307)
                if r['read_occurs']:
                    self.assertTrue(0<=r['j_approximate']<103)
                else:self.assertEqual(r['m'],0)

    def test_selector_modulo_width(self):
        r=approximate_dat_seek(15,16,12345,0xfffffff0,0xfffff000)
        self.assertTrue(0<=r['position_approximate']<=0xffffffff)

    def test_selector_bad_domains_rejected(self):
        for args in ((-1,4,100,0,1),(256,4,100,0,1),
                     (1,0,100,0,1),(1,4,-1,0,1),(1,4,100,2**32,1),
                     (1,4,100,0,2**32),(1,4,2**31,0,1),
                     (1,4,100.2,0,1),(True,4,100,0,1)):
            with self.subTest(args=args),self.assertRaises(ValueError):
                approximate_dat_seek(*args)

    def test_selector_float_constants_and_anchors(self):
        self.assertEqual(SELECTOR_CONSTANTS,
                         (1.06913,1.69314,-0.69314,-0.52658,1e6,1e-6))
        self.assertEqual(len(SELECTOR_ANCHORS),15)

    def test_selector_not_bit_exact(self):
        self.assertFalse(approximate_dat_seek(33,100,200,1000,4)['bit_exact_x87'])

    def test_exact_private_samples_when_available(self):
        folder=Path(os.environ.get('UNSAFEDISK_SAMPLES','/no/samples'))
        retail=folder/'Rayman2(3).exe'
        gog=folder/'rayman2(4).exe'
        if not retail.is_file() or not gog.is_file():
            self.skipTest('private game data not available; no fixtures committed')
        report=analyze_executables(retail.read_bytes(),gog.read_bytes())
        self.assertEqual(len([x for x in report['global_writes'] if 'global_va' in x]),6)
        self.assertEqual(report['nominal_minimum_bytes'],48)
        self.assertTrue(report['x87_selector_retained_identical'])
        self.assertEqual(report['x87_selector_verified_bytes'],192)
        self.assertEqual(report['x87_instruction_anchors_verified'],15)

if __name__ == '__main__':
    unittest.main()
