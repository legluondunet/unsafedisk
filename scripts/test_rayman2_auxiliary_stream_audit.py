#!/usr/bin/env python3
"""Synthetic-only tests for the Rayman 2 masked-PRNG auxiliary audit."""
from __future__ import annotations

import hashlib
import struct
import unittest

from rayman2_auxiliary_stream_audit import (
    KNOWN, MASKED_SALT, MULTIPLIER, MODULUS,
    verify_stream, inspect_pinned, compare_gog_manifest, inspect,
    observed_stream_state_overlap, literal_name_hits,
    count_prng_code_literals, original_vs_gog_rng_code,
    signed_x86_masked_prng_step, inspect_runtime_rng_initializer,
    compare_masked_mov_ecx_sites,
)


def synthetic_stream(seed: int, words: int, prefix: bytes = b"") -> bytes:
    output = bytearray(prefix)
    state = seed
    for _ in range(words):
        output.extend(struct.pack("<I", state))
        state = ((state ^ MASKED_SALT) * MULTIPLIER) % MODULUS
    return bytes(output)


def synthetic_owner_rng_code_pair() -> tuple[bytes, bytes]:
    """Only synthetic bytes: exact reference histograms, no original code."""
    retained = {
        "state": {
            0x2000: 11, 0x3000: 7, 0x4000: 15, 0xC000: 3,
            0x48000: 3, 0x49000: 4, 0x4E000: 4,
            0x67000: 3, 0x70000: 6, 0x7B000: 12,
        },
        "salt": {
            0x2000: 4, 0x3000: 2, 0x4000: 8, 0xC000: 1,
            0x48000: 1, 0x49000: 2, 0x4E000: 2,
            0x51000: 1, 0x67000: 1, 0x70000: 2, 0x7B000: 5,
        },
    }
    removed = {
        "state": {
            0x47000: 12, 0x48000: 45, 0x49000: 9,
            0x4D000: 3, 0x4E000: 17, 0x4F000: 12,
            0x50000: 15, 0x51000: 15,
        },
        "salt": {
            0x47000: 4, 0x48000: 15, 0x49000: 3,
            0x4D000: 1, 0x4E000: 6, 0x4F000: 4,
            0x50000: 5, 0x51000: 6,
        },
    }
    original = bytearray(b"\x90" * 631296)
    active = bytearray(b"\x90" * 634880)
    for family, word, location_start in (
        ("state", 0x00510BF0, 0x100),
        ("salt", MASKED_SALT, 0x800),
    ):
        used: dict[int, int] = {}
        for is_retained, group in ((True, retained[family]),
                                   (False, removed[family])):
            for page, count in group.items():
                for _ in range(count):
                    slot = used.get(page, 0)
                    used[page] = slot + 1
                    at = page - 0x1000 + location_start + slot*16
                    word_bytes = struct.pack("<I", word)
                    original[at:at+4] = word_bytes
                    if is_retained:
                        active[at:at+4] = word_bytes
    return bytes(original), bytes(active)


def synthetic_pe(sections: list[tuple[str, bytes, bool]]) -> bytes:
    """Minimal structurally valid PE32, no genuine program bytes."""
    result = bytearray(b"\x00" * 0x400)
    result[:2] = b"MZ"
    struct.pack_into("<I", result, 0x3c, 0x80)
    result[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", result, 0x84, 0x14c)
    struct.pack_into("<H", result, 0x86, len(sections))
    struct.pack_into("<H", result, 0x94, 0xe0)
    struct.pack_into("<H", result, 0x98, 0x10b)
    for i, (name, data, executable) in enumerate(sections):
        entry = 0x178 + 40*i
        result[entry:entry+8] = name.encode("ascii").ljust(8, b"\0")
        struct.pack_into("<IIII", result, entry+8,
                         len(data), 0x1000+i*0xB0000, len(data), len(result))
        struct.pack_into("<I", result, entry+36,
                         0x60000020 if executable else 0x40000040)
        result.extend(data)
    return bytes(result)


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

    def test_independent_section_prng_fingerprints(self):
        original, live = synthetic_owner_rng_code_pair()
        self.assertEqual(count_prng_code_literals(original),
                         {"state_global_pointer_le": 196,
                          "masked_prng_xor_salt_le": 73})
        self.assertEqual(count_prng_code_literals(live),
                         {"state_global_pointer_le": 68,
                          "masked_prng_xor_salt_le": 29})
        archive = b"\x00"*4096 + original + b"\x00"*3584
        retail = synthetic_pe([(".text", original, True)])
        gog = synthetic_pe([(".text", live, True),
                            (".extra", archive, False)])
        verified = original_vs_gog_rng_code(retail, gog)
        self.assertTrue(verified["archived_original_text_identical"])
        self.assertTrue(verified["gog_extra_is_non_executable"])
        self.assertTrue(verified["all_eight_seed_literals_absent_from_retail"])
        self.assertTrue(verified["all_eight_seed_literals_absent_from_gog"])
        self.assertEqual(verified["per_section_raw_dword_occurrences"]
                         ["gog_active_text"]["state_global_pointer_le"], 68)
        delta = verified["original_vs_active_gog_dword_offset_diff"]
        self.assertEqual(delta["state_global_pointer_le"]["removed_in_gog"], 128)
        self.assertEqual(delta["masked_prng_xor_salt_le"]["removed_in_gog"], 44)
        self.assertEqual(delta["state_global_pointer_le"]["introduced_in_gog"], 0)
        self.assertEqual(delta["state_global_pointer_le"]
                         ["removed_rva_pages"]["0x48000"], 45)

    def test_archived_copy_and_nonexecutability_are_required(self):
        original, live = synthetic_owner_rng_code_pair()
        retail = synthetic_pe([(".text", original, True)])
        archive = b"\x00"*4096 + original + b"\x00"*3584
        corrupted = bytearray(archive)
        corrupted[4096+51] ^= 1
        for bad_gog in [
            synthetic_pe([(".text", live, True),
                          (".extra", bytes(corrupted), False)]),
            synthetic_pe([(".text", live, True),
                          (".extra", archive, True)]),
            synthetic_pe([(".text", b"\x90"*634880, True),
                          (".extra", archive, False)]),
        ]:
            with self.assertRaises(ValueError):
                original_vs_gog_rng_code(retail, bad_gog)

    def test_signed_runtime_qpc_seed_vs_unsigned_disc_prng(self):
        golden = {
            0: 0x1F0CCE42,
            0x12345678: 0x4F2CEC02,
            0x80000000: 0x1F0C8C9B,
            0xFFFFFFFF: 0x60F2F016,
        }
        for seed, known in golden.items():
            self.assertEqual(signed_x86_masked_prng_step(seed), known)
        # Only the first step from a full 32-bit timer word can differ.
        for seed in (0, 1, 0x12345678, 0x7FFFFFFF,
                     0x80000000, 0x80000001, 0xFFFFFFFF):
            value = signed_x86_masked_prng_step(seed)
            self.assertLess(value, MODULUS)
            self.assertGreaterEqual(value, 0)
            unsigned = ((seed ^ MASKED_SALT) * MULTIPLIER) % MODULUS
            if seed < 0x80000000:
                self.assertEqual(value, unsigned)
            else:
                self.assertEqual((unsigned-value) % MODULUS, 2*MULTIPLIER)

    def test_signed_runtime_fallback_281_seed_words_and_rejections(self):
        word = 0x12345678
        for _ in range(281):
            word = signed_x86_masked_prng_step(word)
        self.assertEqual(word, 0x7A833570)
        for invalid in (-1, 0x100000000, True, 1.5, "0x12345678", None):
            with self.assertRaises(ValueError):
                signed_x86_masked_prng_step(invalid)

    def test_masked_x86_mov_site_classifier(self):
        op = b"\x8b\x0d" + struct.pack("<I", 0x00510BF0)
        original = bytearray(b"\x90"*120)
        sites = (8, 24, 40, 56, 72)
        for pos in sites:
            original[pos:pos+len(op)] = op
        active = bytearray(original)
        active[24:30] = b"\xcc"*6  # old PRNG routine erased
        active[40:46] = b"\x90"*6  # former routine NOPed
        active[56:62] = b"\x55\x8b\xec\x90\x90\x90"  # normal prologue
        active[72:78] = b"\x40"*6  # another edit
        report = compare_masked_mov_ecx_sites(bytes(original), bytes(active))
        self.assertEqual(report["original_mov_ecx_global_sites"], 5)
        self.assertEqual(report["gog_mov_ecx_global_sites"], 1)
        self.assertEqual(report["retained_at_identical_offsets"], 1)
        self.assertEqual(report["removed_or_replaced_in_gog"], 4)
        self.assertEqual(report["introduced_at_new_offsets"], 0)
        self.assertEqual(report["replacement_starts"], {
            "int3_at_old_site": 1, "nop_at_old_site": 1,
            "plain_prologue_at_old_site": 1,
            "other_replacement_at_old_site": 1,
        })
        self.assertEqual(report["plain_prologue_replacement_vas"],
                         ["0x00401038"])
        self.assertTrue(report["no_attribution_to_safedisc_alone"])

    def test_runtime_initializer_rejects_wrong_binary(self):
        # No proprietary executable fixtures are present in test suite.
        fake = synthetic_pe([(".text", b"\x90"*631296, True)])
        with self.assertRaises(ValueError):
            inspect_runtime_rng_initializer(fake, fake)

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
