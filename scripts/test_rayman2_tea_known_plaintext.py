#!/usr/bin/env python3
"""Synthetic known-plaintext matching tests; no proprietary fixture data."""
import struct
import unittest

from rayman2_tea_known_plaintext import (
    compare_raw, sliding_words, encrypt_block, historical_vector_valid,
)


class KnownPlaintextTests(unittest.TestCase):
    def test_historical_tea_known_vector(self):
        self.assertTrue(historical_vector_valid())

    def test_sliding_is_all_alignments(self):
        self.assertEqual(len(sliding_words(b'abcdefghij')), 3)
        self.assertEqual(sliding_words(b'abcdefg'), set())

    def test_historical_tea_known_match_on_unaligned_ciphertext(self):
        source = b'prefix-123' + b'ABCDEFGH' + b'suffix'
        needle = encrypt_block(b'ABCDEFGH', key=0xC15CF2E5)
        opaque = b'noise!' + needle + b'data follows'
        result = compare_raw(source, {'SYNTH': opaque})
        self.assertGreaterEqual(result['keys']['0xC15CF2E5']['distinct_matches']['SYNTH'], 1)
        self.assertEqual(result['candidate_windows']['SYNTH'], len(opaque)-7)
        self.assertFalse(result['input_data_emitted'])

    def test_different_key_no_match_for_synthetic_needle(self):
        source = b'ABCDEFGH'
        target = encrypt_block(source, key=0xC15CF2E5)
        result = compare_raw(source, {'SYNTH': target})
        self.assertEqual(result['keys']['0xC15CF2E5']['distinct_matches']['SYNTH'], 1)
        self.assertEqual(result['keys']['0xC1552FE5']['distinct_matches']['SYNTH'], 0)

    def test_negative_and_validation(self):
        for source,samples in ((b'abc',{'X':b'12345678'}),
                               (b'12345678',{}),
                               (b'12345678',{'X':b'abc'})):
            with self.assertRaises(ValueError):
                compare_raw(source,samples)
        with self.assertRaises(ValueError):
            compare_raw(b'12345678', {'X':b'12345678'}, keys=(1,1))
        with self.assertRaises(ValueError):
            compare_raw(b'12345678', {'X':b'12345678'}, keys=(-1,))


if __name__ == '__main__':
    unittest.main()
