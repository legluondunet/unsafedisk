"""Synthetic test models and optional CD/GOG exact-input integration."""
import hashlib
import os
import random
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
import rayman2_selector5_allocation_audit as m


class SelectorFiveTests(unittest.TestCase):
    def test_sentinel_and_extra_megabytes(self):
        self.assertEqual(m.MAGIC,6_500_000)
        self.assertEqual(m.EXTRA,32*1024*1024)
        self.assertEqual(m.transform(m.MAGIC),40_054_432)

    def test_all_other_values_unchanged(self):
        for x in [0,1,6_499_999,6_500_001,32*1024*1024,0xFFFFFFFF]:
            self.assertEqual(m.transform(x),x)

    def test_100k_synthetic_random_values(self):
        rng=random.Random(0x4500af)
        for _ in range(100000):
            x=rng.getrandbits(32)
            self.assertEqual(m.transform(x),x+m.EXTRA if x==m.MAGIC else x)

    def test_globalalloc_word_alignment(self):
        self.assertEqual(m.aligned_size(m.MAGIC),m.MAGIC)
        self.assertEqual(m.aligned_size(m.transform(m.MAGIC)),40_054_432)
        self.assertEqual(m.aligned_size(5),8)
        self.assertEqual(m.aligned_size(8),8)

    def test_invalid_sizes_rejected(self):
        for x in (-1,2**32,None,'6500000',1.5):
            with self.subTest(value=x):
                with self.assertRaises(ValueError):m.transform(x)
                with self.assertRaises(ValueError):m.aligned_size(x)
        with self.assertRaises(ValueError):m.aligned_size(0xFFFFFFFF)

    def test_switch_and_two_modes(self):
        self.assertEqual(len(m.TABLE),16)
        self.assertEqual(m.TABLE[4],0x4500af)
        self.assertEqual(m.TABLE[14],0x4500c2)
        self.assertEqual(m.COMMON[0x45DC0A],'c6 05 48 61 51 00 00')
        self.assertEqual(m.COMMON[0x45DC4A],'c6 05 48 61 51 00 01')

    def test_read_and_alloc_import_stores(self):
        self.assertEqual(m.COMMON[0x44F8DC],'6a 04')
        self.assertEqual(m.COMMON[0x44F8D1],'68 c0 16 51 00')
        self.assertEqual(m.COMMON[0x44248E],'ff 15 7c c0 49 00')
        self.assertEqual(m.COMMON[0x45DBED],'50')
        self.assertGreaterEqual(len(m.COMMON),50)

    def test_relative_call_rejected_if_unknown(self):
        with self.assertRaises(ValueError):m.rel32_target(b'\x90'*5,0x400000)
        x=0x4500af;y=0x44f8d0
        self.assertEqual(m.rel32_target(b'\xe8'+struct.pack('<i',y-x-5),x),y)

    def test_bad_sha_refused(self):
        with self.assertRaisesRegex(ValueError,'SHA256'):m.audit(b'',b'')

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'private original/GOG EXE omitted from GitHub Actions')
    def test_real_sample_integration(self):
        x=m.audit(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
                  Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(x['retail_requested_bytes'],6_500_000)
        self.assertEqual(x['gog_requested_bytes'],40_054_432)
        self.assertEqual(x['read_width_bytes'],4)
        self.assertEqual(x['globalalloc_flag'],0)
        self.assertFalse(x['safedisc_authentication_proven'])

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'private original/GOG EXE omitted from GitHub Actions')
    def test_corrupted_opcode_detected_even_with_new_hash(self):
        cd=Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes()
        gog=Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes()
        pe=m.pe_sections(gog);section=pe['sections']['.text']
        for va in (0x449085,0x4500B5,0x44248E,0x45DBED,0x4501F0):
            b=bytearray(gog)
            b[section['file_offset']+va-section['va']]^=1
            with self.subTest(address=hex(va)):
                with patch.object(m,'GOG_HASH',hashlib.sha256(b).hexdigest()):
                    with self.assertRaises(ValueError):m.audit(cd,bytes(b))


if __name__=='__main__':unittest.main()
