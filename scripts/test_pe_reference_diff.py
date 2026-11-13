"""Synthetic PE32/manifest fixtures only; no copyrighted game bytes."""
from __future__ import annotations
import contextlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

import pe_reference_diff as tool


def manifest_fixture() -> bytes:
    data = bytearray()
    for size, name in ((17, "FILE.EXE"), (128, r"SUB\TEXT.TXT")):
        raw = name.encode("cp1252") + b"\0"
        data.extend(struct.pack("<II", size, len(raw)))
        data.extend(raw)
    data.extend(struct.pack("<II", 0xFFFFFFFF, 0))
    return bytes(data)


def pe_fixture(text_offset: int = 0x400, change: int | None = None,
               manifest: bool = False) -> bytes:
    data = bytearray(0x1000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x14C)
    struct.pack_into("<H", data, 0x86, 2 if manifest else 1)
    struct.pack_into("<H", data, 0x94, 0xE0)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0xA8, 0x1000)
    struct.pack_into("<I", data, 0xB4, 0x400000)
    struct.pack_into("<I", data, 0xF4, 16)
    pos = 0x178
    data[pos:pos+5] = b".text"
    for off, value in ((8, 512), (12, 0x1000), (16, 512),
                       (20, text_offset), (36, 0x60000020)):
        struct.pack_into("<I", data, pos+off, value)
    data[text_offset:text_offset+512] = b"Q"*512
    if change is not None:
        data[text_offset+change] = ord("R")
    if manifest:
        pos += 40
        data[pos:pos+7] = b".extra2"
        for off, value in ((8, 512), (12, 0x3000), (16, 512),
                           (20, 0xC00), (36, 0x40000040)):
            struct.pack_into("<I", data, pos+off, value)
        fake = manifest_fixture()
        data[0xC00:0xC00+len(fake)] = fake
    return bytes(data)


class ReferenceDiffTests(unittest.TestCase):
    def test_sections_are_compared_by_rva_not_raw_offset(self):
        a = tool.parse_pe32(pe_fixture(text_offset=0x400))
        b = tool.parse_pe32(pe_fixture(text_offset=0x800))
        result = tool.compare_pe32(a, b)
        self.assertTrue(result["same_entry_rva"])
        self.assertTrue(result["same_image_base"])
        self.assertEqual(result["section_comparison"][0]["identical_percent"], 100.0)

    def test_single_patch_reports_true_rva(self):
        a = tool.parse_pe32(pe_fixture(text_offset=0x400))
        b = tool.parse_pe32(pe_fixture(text_offset=0x800, change=14))
        diff = tool.compare_pe32(a, b)["section_comparison"][0]
        self.assertEqual(diff["different_bytes"], 1)
        self.assertEqual(diff["first_difference_rvas"], ["0x0000100E"])
        self.assertEqual(diff["changed_4k_pages"], 1)

    def test_extra_section_report_contains_no_original_bytes(self):
        a = tool.parse_pe32(pe_fixture())
        b = tool.parse_pe32(pe_fixture(manifest=True))
        report = tool.compare_pe32(a, b)
        self.assertEqual(report["section_comparison"][-1]["status"], "reference_only")
        self.assertEqual(report["section_comparison"][-1]["name"], ".extra2")
        self.assertNotIn("contents", report["reference"]["sections"][0])

    def test_manifest_records_and_sentinel(self):
        report = tool.scan_manifest(manifest_fixture()+bytes(40))
        self.assertEqual(report["count"], 2)
        self.assertEqual(report["claimed_total_bytes"], 145)
        self.assertEqual(report["entries"][1]["name"], r"SUB\TEXT.TXT")
        self.assertGreater(report["manifest_bytes_before_sentinel"], 0)

    def test_malformed_manifest_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "sentinel"):
            tool.scan_manifest(manifest_fixture()[:-8])
        with self.assertRaisesRegex(ValueError, "filename length"):
            tool.scan_manifest(struct.pack("<II", 100, 99)+b"X\0")
        with self.assertRaisesRegex(ValueError, "trailing NUL"):
            tool.scan_manifest(struct.pack("<II", 100, 4)+b"bad!")

    def test_non_pe_and_overflowing_sections_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "MZ"):
            tool.parse_pe32(b"not a PE")
        data = bytearray(pe_fixture())
        struct.pack_into("<I", data, 0x178+20, 0xF00)
        with self.assertRaisesRegex(ValueError, "extends beyond EOF"):
            tool.parse_pe32(bytes(data))

    def test_data_directories_must_fit_optional_header(self):
        data = bytearray(pe_fixture())
        struct.pack_into("<H", data, 0x94, 0x70)
        with self.assertRaisesRegex(ValueError, "data directory exceeds optional header"):
            tool.parse_pe32(bytes(data))

    def test_int3_neutralization_is_counted_separately(self):
        a = bytearray(pe_fixture())
        b = bytearray(pe_fixture(text_offset=0x800))
        b[0x800+14] = 0xCC
        diff = tool.compare_pe32(
            tool.parse_pe32(bytes(a)), tool.parse_pe32(bytes(b))
        )["section_comparison"][0]
        self.assertEqual(diff["changed_to_int3_bytes"], 1)
        self.assertEqual(diff["different_bytes"], 1)

    def test_exact_full_section_copy_with_zero_padding(self):
        protected = tool.parse_pe32(pe_fixture())
        reference = tool.parse_pe32(pe_fixture(manifest=True))
        sample = protected["sections"][".text"]["contents"]
        # Distinct byte patterns prevent trivial all-zero false positives.
        sample = bytes(((i * 73) ^ (i >> 1) ^ (i >> 4)) % 256 for i in range(512))
        protected["sections"][".text"]["contents"] = sample
        extra = reference["sections"][".extra2"]
        extra["contents"] = bytes(64) + sample + bytes(96)
        extra["raw_len"] = len(extra["contents"])
        copies = tool.find_embedded_section_copies(protected, reference, min_bytes=256)
        self.assertEqual(len(copies), 1)
        result = copies[0]
        self.assertEqual(result["protected_section"], ".text")
        self.assertEqual(result["reference_section"], ".extra2")
        self.assertEqual(result["reference_section_offset"], "0x40")
        self.assertEqual(result["matched_bytes"], 512)
        self.assertEqual(result["prefix_bytes"], 64)
        self.assertEqual(result["suffix_bytes"], 96)
        self.assertTrue(result["prefix_all_zero"])
        self.assertTrue(result["suffix_all_zero"])
        self.assertFalse(result["reference_section_header_marks_executable"])
        self.assertEqual(result["reference_section_characteristics"], "0x40000040")

    def test_copy_detection_requires_exact_full_nonconstant_content(self):
        protected = tool.parse_pe32(pe_fixture())
        reference = tool.parse_pe32(pe_fixture(manifest=True))
        sample = bytes(((i * 73) ^ (i >> 1) ^ (i >> 4)) % 256 for i in range(512))
        protected["sections"][".text"]["contents"] = sample
        extra = reference["sections"][".extra2"]
        damaged = bytearray(sample)
        damaged[201] ^= 1
        extra["contents"] = bytes(64) + damaged + bytes(96)
        self.assertEqual(
            tool.find_embedded_section_copies(protected, reference, min_bytes=256), []
        )
        protected["sections"][".text"]["contents"] = bytes(512)
        extra["contents"] = bytes(64) + bytes(512) + bytes(96)
        self.assertEqual(
            tool.find_embedded_section_copies(protected, reference, min_bytes=256), []
        )
        with self.assertRaisesRegex(ValueError, "minimum section size"):
            tool.find_embedded_section_copies(protected, reference, min_bytes=0)

    def test_cli_rejects_self_comparison(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/"fixture.exe"
            path.write_bytes(pe_fixture())
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                with self.assertRaises(SystemExit) as raised:
                    tool.main(["--protected", str(path), "--reference", str(path)])
            self.assertEqual(raised.exception.code, 1)
            self.assertIn("same file", errors.getvalue())

    def test_cli_exposes_only_focused_entries(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder)/"protected.exe", Path(folder)/"reference.exe"
            a.write_bytes(pe_fixture())
            b.write_bytes(pe_fixture(manifest=True))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(tool.main([
                    "--protected", str(a), "--reference", str(b),
                    "--reference-origin", "GOG",
                    "--manifest-section", ".extra2",
                    "--focus-name", "file.exe",
                ]), 0)
            result = json.loads(buf.getvalue())
            self.assertEqual(result["reference_origin_label"], "GOG")
            self.assertFalse(result["reference_is_pristine_retail_verified"])
            self.assertIn("No difference is attributed to SafeDisc",
                          result["difference_attribution"])
            self.assertFalse(result["embedded_manifest"]["original_cd_manifest_authenticated"])
            self.assertEqual(result["embedded_manifest"]["count"], 2)
            self.assertEqual(len(result["embedded_manifest"]["focus_entries"]), 1)
            self.assertTrue(result["embedded_manifest"]["unique_names_casefold"])
            self.assertLess(len(buf.getvalue()), 6000)


if __name__ == "__main__":
    unittest.main()
