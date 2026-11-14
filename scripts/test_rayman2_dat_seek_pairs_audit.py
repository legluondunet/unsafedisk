"""Synthetic and optional owner-sample checks for Rayman 2 DAT seek/pair audit."""
import os
import struct
import unittest
from pathlib import Path
import rayman2_dat_seek_pairs_audit as m


class DatSeekPairTests(unittest.TestCase):
    def test_positive_relative_call(self):
        site=0x450000
        code=b'\xe8'+struct.pack('<i',0x4817B0-site-5)
        self.assertEqual(m.rel32(lambda a,n:code,site),0x4817B0)

    def test_negative_relative_jump(self):
        site=0x450000
        code=b'\xe9'+struct.pack('<i',0x44E99F-site-5)
        self.assertEqual(m.rel32(lambda a,n:code,site),0x44E99F)

    def test_relative_call_bad_opcode(self):
        with self.assertRaises(ValueError):
            m.rel32(lambda a,n:b'\x90'*5,0x400000)

    def test_anchor_check(self):
        at=lambda a,n:b'\x6a\x06'[:n]
        m.check(at,{0x400000:'6a 06'},'synthetic')
        with self.assertRaises(ValueError):
            m.check(at,{0x400000:'6a 07'},'synthetic')

    def test_two_pair_tables(self):
        self.assertIn(0x44EA8C,m.SHARED)
        self.assertIn(0x44EAB6,m.SHARED)
        self.assertIn(0x4672AD,m.SHARED)
        self.assertIn(0x4672CC,m.SHARED)
        self.assertNotEqual(m.CD[0x44E9A5],m.GOG[0x44E9A5])

    def test_template_length(self):
        self.assertEqual(len(bytes.fromhex('a1 90 17 4a 00 33 05 60 17 4a 00 50 c3')),13)

    def test_unknown_hash_refused(self):
        with self.assertRaisesRegex(ValueError,'SHA256'):
            m.audit(b'',b'')

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'private exact-SHA inputs not provided')
    def test_exact_owner_executables(self):
        x=m.audit(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
                  Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(x['original_stub_bytes'],13)
        self.assertEqual(x['saved_seed_snapshot_table'],'0x00511760')
        self.assertFalse(x['safeDisc_decryption_proven'])


if __name__=='__main__':
    unittest.main()
