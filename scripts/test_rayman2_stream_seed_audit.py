"""Deterministic, no-binary-required tests of Rayman 2 stream seed audit."""
import os
import random
import struct
import unittest
from pathlib import Path

import rayman2_stream_seed_audit as m


class StreamSeedTest(unittest.TestCase):
    def test_exact_quotient_boundary_proof(self):
        self.assertEqual(m.quotient_boundary_proof(), 67230)

    def test_source_global_byte_complement(self):
        self.assertEqual(
            m.masked_input_from_global_before_complement(0x11223344),
            0xdd223344 ^ m.SALT,
        )
        self.assertEqual(
            m.masked_input_from_global_before_complement(0),
            0xff000000 ^ m.SALT,
        )

    def test_unnormalized_negative_result(self):
        self.assertEqual(m.next_state_from_masked(127773), 0xfffff4ec)
        self.assertEqual((m.MULT*127773)%m.MODULUS, 0x7ffff4eb)

    def test_direct_x86_instruction_model(self):
        for x in range(130000):
            self.assertEqual(
                m.next_state_from_masked(x), m.from_x86_instructions(x)
            )

    def test_full_range_random(self):
        rng = random.Random(20261114)
        for _ in range(100000):
            x = rng.getrandbits(32)
            self.assertEqual(m.native_quotient(x), x//m.DIV)
            self.assertEqual(
                m.next_state_from_masked(x), m.from_x86_instructions(x)
            )
            self.assertEqual(
                m.next_state(x ^ m.SALT), m.next_state_from_masked(x)
            )

    def test_negative_count_exact(self):
        self.assertEqual(m.negative_remainder_count(),95348946)

    def test_four_byte_mask_generation(self):
        result = m.four_masks(0x11223344)
        self.assertEqual(result['xor_masks_hex'],'b4bf6d6a')
        self.assertEqual(result['initial_state'],'0x7A0AB4AE')
        self.assertEqual(result['state_after_four'],'0x679468BC')

    def test_auxiliary_different_recurrence(self):
        x=127773
        data=struct.pack('<II',x^m.SALT,(m.MULT*x)%m.MODULUS)
        result=m.compare_auxiliary(data,0)
        self.assertEqual(result['normalized_mismatches'],0)
        self.assertEqual(result['native_stream_mismatches'],1)

    def test_reject_bad_inputs(self):
        for x in (-1,2**32):
            with self.assertRaises(ValueError):
                m.native_quotient(x)
            with self.assertRaises(ValueError):
                m.masked_input_from_global_before_complement(x)
        with self.assertRaises(ValueError):
            m.inspect(b'',b'')

    @unittest.skipUnless(
        os.environ.get('RAYMAN2_RETAIL_EXE')
        and os.environ.get('RAYMAN2_GOG_EXE'),
        'private executable paths not configured',
    )
    def test_exact_private_executables(self):
        result=m.inspect(
            Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
            Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes(),
        )
        self.assertEqual(result['quotient_boundary_checks'],67230)
        self.assertFalse(result['retail_decrypted'])

    @unittest.skipUnless(
        os.environ.get('RAYMAN2_ICD')
        and os.environ.get('RAYMAN2_DPLAYERX'),
        'private auxiliary sample paths not configured',
    )
    def test_exact_private_auxiliary_streams(self):
        for pathvar,hashval,prefix,expected,first in (
            ('RAYMAN2_ICD',m.ICD_SHA,1,1957,428),
            ('RAYMAN2_DPLAYERX',m.DPLAYER_SHA,0,474,8),
        ):
            data=Path(os.environ[pathvar]).read_bytes()
            import hashlib
            self.assertEqual(hashlib.sha256(data).hexdigest(),hashval)
            found=m.compare_auxiliary(data,prefix)
            self.assertEqual(found['normalized_mismatches'],0)
            self.assertEqual(found['native_stream_mismatches'],expected)
            self.assertEqual(found['first_native_mismatch'],first)


if __name__=='__main__':
    unittest.main()
