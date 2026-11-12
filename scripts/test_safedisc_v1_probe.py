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
            link.symlink_to(original)
            with self.assertRaisesRegex(ValueError, "symlink"):
                probe.profile_file(link, "icd")

    def test_limit(self):
        with self.assertRaisesRegex(ValueError, "16 MiB"):
            probe.profile_bytes(b"X" * (probe.MAX_BYTES + 1), "icd")


if __name__ == "__main__":
    unittest.main()
