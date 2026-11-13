#!/usr/bin/env python3
"""Synthetic-only tests for the Rayman 2 masked-PRNG auxiliary audit."""
from __future__ import annotations

import hashlib
import struct
import unittest

from rayman2_auxiliary_stream_audit import (
    KNOWN, MASKED_SALT, MULTIPLIER, MODULUS,
    verify_stream, inspect_pinned, compare_gog_manifest, inspect,
)


def synthetic_stream(seed: int, words: int, prefix: bytes = b"") -> bytes:
    output = bytearray(prefix)
    state = seed
    for _ in range(words):
        output.extend(struct.pack("<I", state))
        state = ((state ^ MASKED_SALT) * MULTIPLIER) % MODULUS
    return bytes(output)


class AuxiliaryStreamAuditTests(unittest.TestCase):
    def test_exact_known_metadata_complete(self):
        self.assertEqual(set(KNOWN), {
            "RAYMAN2.ICD", "DPLAYERX.DLL", "CLOKSPL.EXE",
            "CLCD32.DLL", "DRVMGT.DLL"})
        self.assertEqual([KNOWN[name][0] for name in KNOWN],
                         [683565, 165888, 177152, 27648, 32256])
        for size, seed, prefix, digest in KNOWN.values():
            self.assertEqual((size - len(prefix)) % 4, 0)
            self.assertGreater((size - len(prefix)) // 4, 256)
            self.assertLess(seed, MODULUS)
            self.assertEqual(len(digest), 64)
        self.assertEqual(KNOWN["RAYMAN2.ICD"][2], bytes.fromhex("5b"))

    def test_generator_with_prefix_and_full_byte_coverage(self):
        data = synthetic_stream(0x6EE4C08A, 400, bytes.fromhex("5b"))
        self.assertEqual(verify_stream(
            data, seed=0x6EE4C08A, prefix=bytes.fromhex("5b")), 400)
        self.assertEqual(verify_stream(
            synthetic_stream(0x0030FBEC, 40), seed=0x0030FBEC), 40)

    def test_bitflip_prefix_and_partial_tail_fail(self):
        data = synthetic_stream(0x4F2BFCA6, 400)
        wrong = bytearray(data)
        wrong[37] ^= 1
        with self.assertRaises(ValueError):
            verify_stream(bytes(wrong), seed=0x4F2BFCA6)
        with self.assertRaises(ValueError):
            verify_stream(data + bytes.fromhex("ab"), seed=0x4F2BFCA6)
        with self.assertRaises(ValueError):
            verify_stream(data, seed=0x4F2BFCA7)
        with self.assertRaises(ValueError):
            verify_stream(bytes.fromhex("00") + data, seed=0x4F2BFCA6,
                          prefix=bytes.fromhex("5b"))

    def test_rejects_unverified_pseudo_files(self):
        with self.assertRaises(ValueError):
            inspect_pinned("CLOKSPL.EXE", synthetic_stream(0x67EC2AF6, 400))
        with self.assertRaises(ValueError):
            inspect_pinned("not-a-game.dll", bytes(20))
        with self.assertRaises(ValueError):
            inspect({})

    def test_gog_metadata_is_size_only(self):
        mock_results = {
            "DPLAYERX.DLL": {"size": 165888},
            "CLOKSPL.EXE": {"size": 177152},
        }
        good = compare_gog_manifest({
            "DPLAYERX.DLL": 165888, "CLOKSPL.EXE": 177152}, mock_results)
        self.assertTrue(good["all_checked_sizes_match"])
        self.assertFalse(good["gog_manifest_is_original_disc_authentication"])
        bad = compare_gog_manifest({"DPLAYERX.DLL": 100}, mock_results)
        self.assertFalse(bad["all_checked_sizes_match"])
        self.assertIsNone(bad["checked_names"]["CLOKSPL.EXE"]["declared_size"])


if __name__ == "__main__":
    unittest.main()
