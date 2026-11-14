#!/usr/bin/env python3
"""Synthetic-only tests for the Rayman 2 masked-PRNG auxiliary audit."""
from __future__ import annotations

import hashlib
import struct
import unittest

from rayman2_auxiliary_stream_audit import (
    KNOWN, MASKED_SALT, MULTIPLIER, MODULUS,
    verify_stream, inspect_pinned, compare_gog_manifest, inspect, observed_stream_state_overlap, literal_name_hits,
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
            "CLCD32.DLL", "DRVMGT.DLL", "00000001.TMP",
            "0000040C.016", "0000040C.256"})
        self.assertEqual([KNOWN[name][0] for name in KNOWN],
                         [683565, 165888, 177152, 27648, 32256,
                          20, 153718, 308278])
        for size, seed, prefix, digest in KNOWN.values():
            self.assertEqual((size - len(prefix)) % 4, 0)
            self.assertGreaterEqual((size - len(prefix)) // 4, 5)
            self.assertLess(seed, MODULUS)
            self.assertEqual(len(digest), 64)
        self.assertEqual(KNOWN["RAYMAN2.ICD"][2], bytes.fromhex("5b"))
        self.assertEqual(KNOWN["0000040C.016"][2], bytes.fromhex("abde"))
        self.assertEqual(KNOWN["0000040C.256"][2], bytes.fromhex("4dc7"))
        self.assertEqual(KNOWN["00000001.TMP"][2], b"")

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

    def test_complete_eight_file_golden_shas_and_finite_overlap(self):
        # All material is deterministic and generated exclusively in RAM.
        # This asserts exact hash/size against the owner's *already*
        # independently identified inputs; no commercial file is embedded.
        samples = {}
        for name, (size, seed, prefix, expected_digest) in KNOWN.items():
            words = (size - len(prefix)) // 4
            generated = synthetic_stream(seed, words, prefix)
            self.assertEqual(len(generated), size)
            self.assertEqual(hashlib.sha256(generated).hexdigest(), expected_digest)
            samples[name] = generated
        report = inspect(samples)
        self.assertEqual(len(report["samples"]), 8)
        overlap = report["finite_stream_overlap"]
        self.assertEqual(overlap["observed_words"], 387130)
        self.assertEqual(overlap["distinct_observed_states"], 387130)
        self.assertEqual(overlap["observed_state_collisions"], 0)
        self.assertTrue(overlap["no_state_overlap_in_observed_intervals"])
        self.assertFalse(overlap["global_seed_independence_proven"])
        self.assertFalse(report["decrypted_pe_recovered"])

    def test_two_byte_prefix_alignment_on_synthetic_data(self):
        for name in ("0000040C.016", "0000040C.256"):
            _, seed, prefix, _ = KNOWN[name]
            raw = synthetic_stream(seed, 300, prefix)
            self.assertEqual(verify_stream(raw, seed=seed, prefix=prefix), 300)
            with self.assertRaises(ValueError):
                verify_stream(raw, seed=seed, prefix=b"")
            with self.assertRaises(ValueError):
                verify_stream(raw + b"x", seed=seed, prefix=prefix)
            corrupt = bytearray(raw)
            corrupt[len(prefix) + 17] ^= 1
            with self.assertRaises(ValueError):
                verify_stream(bytes(corrupt), seed=seed, prefix=prefix)

    def test_five_word_tmp_short_stream_is_not_one_step_fit(self):
        _, seed, prefix, digest = KNOWN["00000001.TMP"]
        data = synthetic_stream(seed, 5, prefix)
        self.assertEqual(len(data), 20)
        self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        self.assertEqual(verify_stream(data, seed=seed), 5)
        corrupt = data[:15] + bytes([data[15] ^ 1]) + data[16:]
        with self.assertRaises(ValueError):
            verify_stream(corrupt, seed=seed)

    def test_literal_ascii_and_utf16le_filename_match_are_only_static_evidence(self):
        raw = (b"prefix-rayman2.icd--" + "DPLAYERX.DLL".encode("utf-16le") +
               b"-suffix-rayman2.icd")
        got = literal_name_hits(raw, ["RAYMAN2.ICD", "DPLAYERX.DLL", "CLCD32.DLL"])
        self.assertEqual(got["RAYMAN2.ICD"]["ascii_case_insensitive_occurrences"], 2)
        self.assertEqual(got["RAYMAN2.ICD"]["utf16le_ascii_case_insensitive_occurrences"], 0)
        self.assertEqual(got["DPLAYERX.DLL"]["utf16le_ascii_case_insensitive_occurrences"], 1)
        self.assertEqual(got["DPLAYERX.DLL"]["ascii_case_insensitive_occurrences"], 0)
        self.assertEqual(got["CLCD32.DLL"]["ascii_case_insensitive_occurrences"], 0)
        with self.assertRaises(ValueError):
            literal_name_hits(b"test", [""])

    def test_retail_original_hash_gate_rejects_fake_binary(self):
        size, seed, prefix, expected_sha = KNOWN["DPLAYERX.DLL"]
        raw = synthetic_stream(seed, (size - len(prefix)) // 4, prefix)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), expected_sha)
        # A valid auxiliary file MUST NOT bypass the separate EXE SHA gate.
        with self.assertRaisesRegex(ValueError, "original retail EXE"):
            inspect({"DPLAYERX.DLL": raw}, retail=raw)

    def test_gog_checks_all_eight_selected_lengths_only(self):
        mocked = {name: {"size": info[0]} for name, info in KNOWN.items()}
        original_claims = {name: info[0] for name, info in KNOWN.items()}
        self.assertTrue(compare_gog_manifest(original_claims, mocked)["all_checked_sizes_match"])
        altered = dict(original_claims)
        altered["0000040C.256"] += 1
        self.assertFalse(compare_gog_manifest(altered, mocked)["all_checked_sizes_match"])
        self.assertFalse(compare_gog_manifest(original_claims, mocked)
                         ["gog_manifest_is_original_disc_authentication"])

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
