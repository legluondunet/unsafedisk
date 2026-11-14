"""Synthetic alignment and independent-regeneration tests. No game bytes."""
import random
import unittest
from safedisc_prng_recurrence import analyse, analyse_alignments, MODULUS, MULTIPLIER


def make_stream(seed=0x0030FBEC, salt=0x075BD924, n=512,
                order="little", prefix=b""):
    result = bytearray(prefix)
    state = seed
    for _ in range(n):
        result.extend(state.to_bytes(4, order))
        state = ((state ^ salt) * MULTIPLIER) % MODULUS
    return bytes(result)


class AlignmentTests(unittest.TestCase):
    def test_owner_reference_sha256_from_generators_only(self):
        # Hashes are reference diagnostics; all bytes are generated
        # in memory from seeds, not copied from proprietary files.
        import hashlib

        samples = [
            (
                make_stream(seed=0x6EE4C08A, n=170_891, prefix=b"\x5b"),
                "4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6",
                1,
            ),
            (
                make_stream(seed=0x0030FBEC, n=41_472),
                "0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee",
                0,
            ),
        ]
        for blob, expected_sha, expected_offset in samples:
            self.assertEqual(hashlib.sha256(blob).hexdigest(), expected_sha)
            matches = analyse_alignments(blob)["matches"]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["offset_bytes"], expected_offset)
            self.assertEqual(matches[0]["endianness"], "little")
            self.assertTrue(matches[0]["whole_file_reconstructible_from_prefix_and_seed"])

    def test_dll_offset_zero(self):
        result = analyse(make_stream(), "little", 0)
        self.assertTrue(result["whole_file_reconstructible_from_prefix_and_seed"])
        self.assertEqual(result["matching_local_three_word_windows"], 510)
        self.assertEqual(result["candidate_xor_salt"], "0x075BD924")

    def test_icd_one_byte_prefix(self):
        blob = make_stream(seed=0x6EE4C08A, prefix=b"\x5b")
        result = analyse(blob, "little", 1)
        self.assertTrue(result["whole_file_reconstructible_from_prefix_and_seed"])
        self.assertEqual(result["preserved_prefix_hex"], "5b")
        self.assertEqual(result["matching_local_three_word_windows"], 510)
        self.assertFalse(analyse(blob, "big", 0)["full_recurrence_match"])

    def test_auto_detects_shifted_stream(self):
        result = analyse_alignments(make_stream(prefix=b"\x5b"))
        self.assertEqual(result["tested_alignments"], 8)
        self.assertEqual(result["full_match_count"], 1)
        self.assertEqual(
            (result["matches"][0]["offset_bytes"], result["matches"][0]["endianness"]),
            (1, "little"))

    def test_bit_flip(self):
        blob = bytearray(make_stream(prefix=b"\x5b"))
        blob[211] ^= 1
        result = analyse(bytes(blob), "little", 1)
        self.assertFalse(result["full_recurrence_match"])
        self.assertFalse(result["whole_file_reconstructible_from_prefix_and_seed"])

    def test_extra_tail_disables_whole_file(self):
        result = analyse(make_stream() + b"\x29", "little", 0)
        self.assertTrue(result["full_recurrence_match"])
        self.assertFalse(result["whole_file_reconstructible_from_prefix_and_seed"])

    def test_auto_alignment_requires_every_byte_accounted_for(self):
        complete = make_stream()
        extra = complete + b"\x29"
        report = analyse(extra, "little", 0)
        self.assertTrue(report["full_recurrence_match"])
        self.assertFalse(report["whole_file_reconstructible_from_prefix_and_seed"])
        scan = analyse_alignments(extra)
        self.assertEqual(scan["tested_alignments"], 8)
        self.assertEqual(scan["full_match_count"], 0)
        self.assertEqual(scan["match_definition"], "exact complete-file in-memory regeneration")

    def test_short_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least 256"):
            analyse(make_stream(n=255), "little")

    def test_other_byte_order(self):
        blob = make_stream(order="big", prefix=b"\x5b\x00")
        result = analyse_alignments(blob)
        self.assertEqual(result["full_match_count"], 1)
        self.assertEqual(result["matches"][0]["offset_bytes"], 2)
        self.assertEqual(result["matches"][0]["endianness"], "big")

    def test_random_opaque_no_match(self):
        generator = random.Random(991)
        blob = bytes(generator.randrange(256) for _ in range(4 * 512 + 1))
        self.assertEqual(analyse_alignments(blob)["full_match_count"], 0)


if __name__ == "__main__":
    unittest.main()
