"""Synthetic fixtures only. No proprietary games or SafeDisc data."""
import unittest
from pathlib import Path
import tempfile

try:
    from scripts import safedisc_v1_probe as probe
except ImportError:
    import safedisc_v1_probe as probe


def fixture() -> bytes:
    b = bytearray(0x400)
    b[:2] = b"MZ"
    b[0x3C:0x40] = (0x80).to_bytes(4, "little")
    b[0x80:0x84] = b"PE\0\0"
    b[0x84:0x86] = (0x14C).to_bytes(2, "little")
    b[0x86:0x88] = (1).to_bytes(2, "little")
    b[0x94:0x96] = (0xE0).to_bytes(2, "little")
    b[0x98:0x9A] = (0x10B).to_bytes(2, "little")
    b[0xA8:0xAC] = (0x1000).to_bytes(4, "little")
    b[0x178:0x17D] = b".text"
    b[0x184:0x188] = (0x1000).to_bytes(4, "little")
    b[0x188:0x18C] = (0x200).to_bytes(4, "little")
    b[0x18C:0x190] = (0x200).to_bytes(4, "little")
    return bytes(b)


class ProbeTests(unittest.TestCase):
    def test_entropy_bounds(self):
        self.assertEqual(probe.entropy(b""), 0.0)
        self.assertEqual(probe.entropy(b"A" * 4096), 0.0)
        self.assertAlmostEqual(probe.entropy(bytes(range(256))), 8.0)

    def test_mz_noise_is_not_pe(self):
        count, found = probe.scan_pe_candidates(b"randomMZpaddingMZmore")
        self.assertEqual(count, 2)
        self.assertEqual(found, [])

    def test_valid_pe_and_embedded_pe(self):
        b = fixture()
        count, found = probe.scan_pe_candidates(b)
        self.assertEqual(count, 1)
        self.assertEqual(found[0]["offset"], "0x0")
        embedded = b"prefix" + b
        self.assertEqual(probe.scan_pe_candidates(embedded)[1][0]["offset"], "0x6")
        self.assertEqual(
            probe.profile_bytes(b, "loader")["valid_pe32_candidates"][0]["entry_rva"],
            "0x1000"
        )

    def test_loader_required_but_opaque_icd_allowed(self):
        with self.assertRaisesRegex(ValueError, "loader"):
            probe.profile_bytes(b"opaque", "loader")
        self.assertEqual(
            probe.profile_bytes(b"opaque", "icd")["valid_pe32_candidates"], []
        )

    def test_block_entropy_ignores_partial_tail(self):
        data = bytes([0] * 4096 + list(range(256)) * 16 + [255] * 99)
        profile = probe.profile_bytes(data, "icd")
        self.assertEqual(profile["full_4k_blocks"], 2)
        self.assertEqual(profile["block_entropy_min"], 0)
        self.assertEqual(profile["block_entropy_max"], 8)

    def test_refuse_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / "original"
            original.write_bytes(b"opaque")
            link = Path(d) / "link"
            try:
                link.symlink_to(original)
            except (OSError, NotImplementedError):
                self.skipTest("creating symlinks is not permitted on this Windows runner")
            with self.assertRaisesRegex(ValueError, "symlink"):
                probe.profile_file(link, "icd")

    def test_31bit_byte_lane_orders(self):
        words = [((i * 0x10203041) & 0x7FFFFFFF) for i in range(256)]
        be = b"".join(w.to_bytes(4, "big") for w in words)
        le = b"".join(w.to_bytes(4, "little") for w in words)
        self.assertEqual(probe.four_byte_lane_profile(be)["always_clear_high_bit_lanes"], [0])
        self.assertEqual(probe.four_byte_lane_profile(le)["always_clear_high_bit_lanes"], [3])
        self.assertEqual(probe.four_byte_lane_profile(be)["word_order_hint"], "31-bit big-endian candidate")
        self.assertEqual(probe.four_byte_lane_profile(le)["word_order_hint"], "31-bit little-endian candidate")

    def test_stray_high_bit_disproves_candidate(self):
        words = [((i * 0x10203041) & 0x7FFFFFFF) for i in range(256)]
        data = bytearray(b"".join(w.to_bytes(4, "little") for w in words))
        data[3] |= 0x80
        self.assertNotIn(3, probe.four_byte_lane_profile(data)["always_clear_high_bit_lanes"])

    def test_lane_profile_ignores_trailing_byte(self):
        words = [((i * 0x10203041) & 0x7FFFFFFF) for i in range(256)]
        data = b"".join(w.to_bytes(4, "little") for w in words) + b"\xff"
        profile = probe.four_byte_lane_profile(data)
        self.assertEqual(profile["trailing_bytes_not_examined"], 1)
        self.assertEqual(profile["complete_four_byte_groups"], 256)
        self.assertEqual(profile["always_clear_high_bit_lanes"], [3])

    def test_short_and_zero_data_do_not_infer_word_order(self):
        self.assertEqual(probe.four_byte_lane_profile(b"")["word_order_hint"], "none or ambiguous")
        self.assertEqual(probe.four_byte_lane_profile(bytes(100))["word_order_hint"], "none or ambiguous")
        with self.assertRaisesRegex(ValueError, "minimum_words"):
            probe.four_byte_lane_profile(bytes(16), 0)

    def test_provenance_warns_for_opaque_icd_and_dll(self):
        loader = probe.profile_bytes(fixture(), "loader")
        icd = probe.profile_bytes(b"opaque ICD bytes", "icd")
        dll = probe.profile_bytes(b"opaque DLL bytes", "dplayerx")
        result = probe.provenance_cautions([loader, icd, dll])
        self.assertTrue(result["provenance_not_verified"])
        self.assertFalse(result["corruption_asserted"])
        codes = [(item["role"], item["code"]) for item in result["cautions"]]
        self.assertIn(("icd", "no_pe32_at_file_start"), codes)
        self.assertIn(("dplayerx", "no_pe32_at_file_start"), codes)
        self.assertIn(("loader", "historical_wrapper_section_layout_differs"), codes)

    def test_provenance_does_not_flag_root_pe_as_opaque(self):
        loader = probe.profile_bytes(fixture(), "loader")
        icd = probe.profile_bytes(fixture(), "icd")
        dll = probe.profile_bytes(fixture(), "dplayerx")
        result = probe.provenance_cautions([loader, icd, dll])
        self.assertFalse(any(item["code"] == "no_pe32_at_file_start"
                             for item in result["cautions"]))
        self.assertFalse(result["corruption_asserted"])
        self.assertTrue(result["provenance_not_verified"])
        self.assertTrue(result["structural_cautions_present"])

    def test_limit(self):
        with self.assertRaisesRegex(ValueError, "16 MiB"):
            probe.profile_bytes(b"X" * (probe.MAX_BYTES + 1), "icd")


if __name__ == "__main__":
    unittest.main()
