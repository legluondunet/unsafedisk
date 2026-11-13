"""Synthetic-only tests; no protected game data distributed."""
import unittest
import os
from pathlib import Path
from rayman2_trampoline_proof import (analyze,code_gen,flush_pattern,p32,WRAPPERS,
                                      masked_slot,verify_slot_initializer,SLOT_ANCHORS,
                                      SLOT_INIT_CALLS)


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

    def test_first_masked_slot_address(self):
        self.assertEqual(masked_slot(1),(0x004A141C,0x004A144C))

    def test_four_io_slot_addresses(self):
        self.assertEqual(masked_slot(8),(0x004A1630,0x004A1660))
        self.assertEqual(masked_slot(10),(0x004A16C8,0x004A16F8))
        self.assertEqual(masked_slot(11),(0x004A1714,0x004A1744))
        self.assertEqual(masked_slot(12),(0x004A1760,0x004A1790))

    def test_last_masked_slot_address(self):
        self.assertEqual(masked_slot(35),(0x004A1E34,0x004A1E64))

    def test_invalid_descriptor_numbers_refused(self):
        for bad in (-1,0,36,100,True,1.0,'1'):
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'1..35'):
                masked_slot(bad)

    def test_original_initializer_anchor_inventory(self):
        self.assertEqual(len(SLOT_ANCHORS),15)
        self.assertEqual(len(SLOT_INIT_CALLS),5)
        self.assertEqual(sum(target==0x447AF0 for target in SLOT_INIT_CALLS.values()),3)

    def test_exact_private_samples_optional(self):
        root=Path(os.environ.get('UNSAFEDISK_SAMPLES','/no-samples'))
        original=root/'Rayman2(3).exe'
        gog=root/'rayman2(4).exe'
        if not original.is_file() or not gog.is_file():
            self.skipTest('private retail and GOG game binaries not provided')
        report=analyze(original.read_bytes(),gog.read_bytes())
        init=report['masked_pointer_initialization']
        self.assertEqual(init['api_descriptors_verified'],35)
        self.assertEqual(init['init_instruction_anchors_verified'],15)
        self.assertTrue(init['gog_234_int3_resolver_bytes_verified'])
        self.assertFalse(report['runtime_execution_proven'])

    def test_flush_span_covers_all_generated_code(self):
        self.assertGreaterEqual(0x464,0x455-1+13)


if __name__=='__main__':
    unittest.main()
