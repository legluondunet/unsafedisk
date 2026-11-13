"""Synthetic-only tests; no protected game data distributed."""
import unittest
from rayman2_trampoline_proof import analyze, code_gen, flush_pattern, p32, WRAPPERS


class TrampolineProofTests(unittest.TestCase):
    def test_reject_unknown_hash(self):
        with self.assertRaisesRegex(ValueError,'protected Rayman 2 SHA-256'):
            analyze(b'synthetic')

    def test_four_wrappers_distinct(self):
        self.assertEqual(len(WRAPPERS),4)
        self.assertEqual(len({w[0] for w in WRAPPERS}),4)
        self.assertEqual({w[1] for w in WRAPPERS},{8,10,11,12})

    def test_push_ret_template_uses_masked_pointer_pair(self):
        b=code_gen(0x4A1714,0x4A1744,'push-ret')
        self.assertEqual(b[:3],b'\xc6\x06\x68')
        self.assertEqual(b[5:9],p32(0x4A1744))
        self.assertIn(p32(0x4A1714),b)
        self.assertTrue(b.endswith(b'\x89\x56\x01'))

    def test_mov_xor_jmp_uses_masked_pointer_pair(self):
        b=code_gen(0x4A1630,0x4A1660,'mov-xor-jmp')
        self.assertIn(p32(0x4A1630),b)
        self.assertIn(p32(0x4A1660),b)
        self.assertTrue(b.endswith(b'\xc6\x46\x0c\xe0'))

    def test_mov_xor_push_ret(self):
        b=code_gen(0x4A16C8,0x4A16F8,'mov-xor-push-ret')
        self.assertTrue(b.endswith(b'\xc6\x46\x0c\xc3'))

    def test_wrong_kind_rejected(self):
        with self.assertRaisesRegex(ValueError,'unknown trampoline'):
            code_gen(0,0,'jmp-nop')

    def test_cache_flush_sequence(self):
        b=flush_pattern()
        self.assertIn(p32(0x4A1498),b)
        self.assertIn(p32(0x4A144C),b)
        self.assertIn(p32(0x464),b)
        self.assertIn(p32(0x510EA0),b)
        self.assertTrue(b.endswith(b'\x50\x33\xca\xff\xd1'))

    def test_flush_span_covers_all_generated_code(self):
        self.assertGreaterEqual(0x464,0x455-1+13)


if __name__=='__main__':
    unittest.main()
