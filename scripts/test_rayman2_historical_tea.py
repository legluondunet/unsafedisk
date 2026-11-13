#!/usr/bin/env python3
"""Synthetic, no-commercial-payload tests of the historical TEA probe."""
from __future__ import annotations

import struct
import unittest

from rayman2_historical_tea import (
    DELTA, KEY, ROUNDS, ZERO_CIPHER, PUBLISHED_SUFFIX,
    encrypt_block, decrypt_block, historical_vector, scan_known_zero,
    verify_known_prng_samples, scan_fixed_tea_for_pe32,
)


class HistoricalRayman2TEATests(unittest.TestCase):
    def test_paper_zero_ciphertext_suffix(self):
        self.assertEqual(encrypt_block(b"\0" * 8), ZERO_CIPHER)
        self.assertEqual(ZERO_CIPHER[1:], PUBLISHED_SUFFIX)

    def test_paper_round_count(self):
        self.assertEqual(ROUNDS, 32)
        self.assertEqual(DELTA, 0x9E3779B9)
        self.assertEqual(KEY, 0xC15CF2E5)

    def test_inverse(self):
        self.assertEqual(decrypt_block(ZERO_CIPHER), bytes(8))
        for i in range(256):
            block = struct.pack("<II", i * 123457, (i * 76543) ^ 0xDEADBEEF)
            self.assertEqual(decrypt_block(encrypt_block(block)), block)

    def test_transcribed_byte_sequence_is_not_the_key(self):
        # The essay's prose key and its later printed LE byte sequence disagree.
        self.assertNotEqual(encrypt_block(bytes(8), key=0xC1552FE5), ZERO_CIPHER)

    def test_invalid_inputs(self):
        for value in (b"", b"x" * 7, b"x" * 9):
            with self.assertRaises(ValueError):
                decrypt_block(value)
            with self.assertRaises(ValueError):
                encrypt_block(value)
        for key in (-1, 0x100000000):
            with self.assertRaises(ValueError):
                encrypt_block(bytes(8), key=key)

    def test_signature_scan_at_all_alignments(self):
        data = b"\x5B" + ZERO_CIPHER + b"not a section" + ZERO_CIPHER
        found = scan_known_zero(data)
        self.assertEqual(found["candidate_zero_block_count"], 2)
        self.assertEqual(found["candidate_offsets_first_16"],
                         [1, 1 + 8 + len(b"not a section")])

    def test_naive_scan_recovers_synthetic_pe_only_at_correct_alignment(self):
        # Synthetic 1-section PE32 with a complete header, no commercial bytes.
        import hashlib
        plain = bytearray(4096)
        base = 13
        plain[base:base+2] = b"MZ"
        struct.pack_into("<I", plain, base + 0x3C, 0x80)
        nt = base + 0x80
        plain[nt:nt+4] = b"PE\\0\\0"
        struct.pack_into("<H", plain, nt+4, 0x14C)
        struct.pack_into("<H", plain, nt+6, 1)
        struct.pack_into("<H", plain, nt+20, 0xE0)
        struct.pack_into("<H", plain, nt+24, 0x10B)
        enc = bytearray(plain)
        for at in range(5, len(plain)-7, 8):
            enc[at:at+8] = encrypt_block(bytes(plain[at:at+8]))
        report = scan_fixed_tea_for_pe32(bytes(enc))
        self.assertEqual(report["input_sha256"], hashlib.sha256(enc).hexdigest())
        self.assertEqual(report["tested_alignments"], 8)
        self.assertEqual(report["alignments"][5]["plausible_pe32_offsets_first_16"], [base])
        for item in report["alignments"]:
            if item["alignment"] != 5:
                self.assertEqual(item["plausible_pe32_header_count"], 0)
        self.assertTrue(report["absence_does_not_rule_out_section_only_or_runtime_stage"])

    def test_naive_pe_scan_rejects_malformed_and_wrong_types(self):
        for payload in (b"", b"x" * 7, b"x" * (2*1024*1024+1)):
            with self.assertRaises(ValueError):
                scan_fixed_tea_for_pe32(payload)
        with self.assertRaises(ValueError):
            scan_fixed_tea_for_pe32(bytearray(24))
        self.assertEqual(sum(
            item["plausible_pe32_header_count"]
            for item in scan_fixed_tea_for_pe32(b"zero" * 200)["alignments"]
        ), 0)

    def test_known_owner_prng_regeneration_not_tea_ciphertext(self):
        report = verify_known_prng_samples()
        self.assertEqual(set(report), {"RAYMAN2.ICD", "DPLAYERX.DLL"})
        self.assertEqual(report["RAYMAN2.ICD"]["byte_length"], 683565)
        self.assertEqual(report["DPLAYERX.DLL"]["byte_length"], 165888)
        self.assertEqual(
            report["RAYMAN2.ICD"]["reconstructed_sha256"],
            "4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6"
        )
        self.assertEqual(
            report["DPLAYERX.DLL"]["reconstructed_sha256"],
            "0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee"
        )
        for result in report.values():
            self.assertTrue(result["sha256_matches_owner_sample"])
            self.assertEqual(result["historical_complete_zero_block_hits"], 0)
            self.assertEqual(result["historical_seven_byte_suffix_hits"], 0)
            self.assertTrue(result["no_decrypted_payload_recovered"])

    def test_no_false_claim_without_signature(self):
        self.assertEqual(scan_known_zero(b"\x00" * 128)["candidate_zero_block_count"], 0)
        self.assertFalse(historical_vector()["verified_for_owner_retail_icd"])
        self.assertFalse(historical_vector()["cipher_params_from_runtime_dplayerx_verified"])
        self.assertTrue(historical_vector()["published_seven_byte_suffix_match"])


if __name__ == "__main__":
    unittest.main()
