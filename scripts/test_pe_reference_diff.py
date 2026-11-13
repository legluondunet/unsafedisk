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
        self.assertEqual(report["bytes_after_sentinel"], 40)
        self.assertTrue(report["remaining_bytes_all_zero"])
        self.assertFalse(tool.scan_manifest(manifest_fixture()+bytes(4)+b"X")["remaining_bytes_all_zero"])

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

    def test_added_section_base_literal_addresses(self):
        protected = tool.parse_pe32(pe_fixture())
        binary = bytearray(pe_fixture(manifest=True))
        # GOG-style absolute VA 0x00403000, located in the synthetic .text.
        binary[0x400+42:0x400+46] = (0x00403000).to_bytes(4, "little")
        reference = tool.parse_pe32(bytes(binary))
        refs = tool.find_added_section_base_literals(protected, reference)
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["reference_only_section"], ".extra2")
        self.assertEqual(refs[0]["section_base_va"], "0x00403000")
        self.assertEqual(refs[0]["literal_candidates"], [
            {"source_section": ".text", "immediate_va": "0x0040102A"}
        ])
        reference["sections"][".text"]["contents"] = bytes(512)
        self.assertEqual(tool.find_added_section_base_literals(protected, reference), [])

    def test_x86_rel32_and_mov_imm32_reference_candidates(self):
        # Two identical relative CALLs at the same virtual address can
        # live at different raw file offsets. GOG adds an explicit
        # MOV r32,imm32 pointer where the retail image does not.
        target = 0x004011A0
        retail = bytearray(pe_fixture(text_offset=0x400))
        gog = bytearray(pe_fixture(text_offset=0x800))
        site = 0x00401040
        call_bytes = b"\xE8" + struct.pack("<i", target - (site + 5))
        retail[0x400+0x40:0x400+0x45] = call_bytes
        gog[0x800+0x40:0x800+0x45] = call_bytes
        gog[0x800+0x90:0x800+0x95] = b"\xBA" + struct.pack("<I", target)
        a = tool.find_x86_reference_candidates(tool.parse_pe32(bytes(retail)), target)
        b = tool.find_x86_reference_candidates(tool.parse_pe32(bytes(gog)), target)
        self.assertEqual(a["direct_call_candidates"], b["direct_call_candidates"])
        self.assertEqual(a["direct_call_candidates"][0]["site_va"], "0x00401040")
        self.assertEqual(a["mov_immediate_candidates"], [])
        self.assertEqual(b["mov_immediate_candidates"][0]["site_va"], "0x00401090")
        self.assertEqual(b["mov_immediate_candidates"][0]["register_code"], 2)

    def test_x86_reference_scan_handles_negative_displacements(self):
        target = 0x00401008
        sample = bytearray(pe_fixture())
        site = 0x00401110
        sample[0x400+0x110:0x400+0x115] = b"\xE8" + struct.pack("<i", target-(site+5))
        pe = tool.parse_pe32(bytes(sample))
        result = tool.find_x86_reference_candidates(pe, target)
        self.assertEqual(
            result["direct_call_candidates"],
            [{"site_va": "0x00401110", "section": ".text",
              "candidate_opcode": "E8 rel32"}]
        )
        with self.assertRaisesRegex(ValueError, "32 bits"):
            tool.find_x86_reference_candidates(pe, 1<<32)

    def test_cli_optional_x86_trace_identifies_labeled_reference(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder)/"retail.exe", Path(folder)/"gog.exe"
            a.write_bytes(pe_fixture())
            sample = bytearray(pe_fixture(text_offset=0x800))
            sample[0x800+0x10:0x800+0x15] = b"\xBA" + struct.pack("<I", 0x004011A0)
            b.write_bytes(sample)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(tool.main([
                    "--protected", str(a), "--reference", str(b),
                    "--reference-origin", "GOG",
                    "--trace-va", "0x4011a0"
                ]), 0)
            report = json.loads(out.getvalue())
            self.assertFalse(report["reference_is_pristine_retail_verified"])
            traced = report["x86_reference_candidates"][0]
            self.assertEqual(traced["target"], "0x004011A0")
            self.assertEqual(traced["protected"]["mov_immediate_candidates"], [])
            self.assertEqual(traced["reference"]["mov_immediate_candidates"][0]["site_va"], "0x00401010")

    def test_masked_globals_are_compared_by_file_backed_va(self):
        protected_raw = bytearray(pe_fixture(text_offset=0x400))
        gog_raw = bytearray(pe_fixture(text_offset=0x800))
        first, second = 0x00401060, 0x00401070
        for blob, raw_off in ((protected_raw, 0x400), (gog_raw, 0x800)):
            struct.pack_into("<I", blob, raw_off+0x60, 0)
            struct.pack_into("<I", blob, raw_off+0x70, 0x5A151926)
        protected = tool.parse_pe32(bytes(protected_raw))
        gog = tool.parse_pe32(bytes(gog_raw))
        pair = tool.compare_masked_pointer_pairs(protected, gog, [(first, second)])[0]
        self.assertEqual(pair["retail_file_values"], ["0x00000000", "0x5A151926"])
        self.assertEqual(pair["reference_file_values"], pair["retail_file_values"])
        self.assertEqual(pair["retail_on_disk_xor"], "0x5A151926")
        self.assertTrue(pair["same_bytes_at_both_vas"])
        self.assertTrue(pair["retail_first_operand_zero_on_disk"])
        self.assertFalse(pair["runtime_pointer_known"])

    def test_masked_globals_expose_divergent_retail_and_gog_values(self):
        a = bytearray(pe_fixture())
        b = bytearray(pe_fixture(text_offset=0x800))
        struct.pack_into("<I", a, 0x400+0x30, 0x12)
        struct.pack_into("<I", a, 0x400+0x40, 0x5678)
        struct.pack_into("<I", b, 0x800+0x30, 0x12)
        struct.pack_into("<I", b, 0x800+0x40, 0x5679)
        result = tool.compare_masked_pointer_pairs(
            tool.parse_pe32(bytes(a)), tool.parse_pe32(bytes(b)),
            [(0x00401030, 0x00401040)]
        )[0]
        self.assertFalse(result["same_bytes_at_both_vas"])
        self.assertEqual(result["retail_on_disk_xor"], "0x0000566A")
        self.assertEqual(result["reference_on_disk_xor"], "0x0000566B")
        self.assertFalse(result["retail_first_operand_zero_on_disk"])

    def test_masked_global_probe_rejects_unbacked_and_invalid_vas(self):
        a = tool.parse_pe32(pe_fixture())
        with self.assertRaisesRegex(ValueError, "not backed"):
            tool.read_section_u32_va(a, 0x00401999)
        with self.assertRaisesRegex(ValueError, "32-bit range"):
            tool.read_section_u32_va(a, 1 << 32)
        with self.assertRaisesRegex(ValueError, "at most 64"):
            tool.compare_masked_pointer_pairs(a, a, [(0, 0)]*65)

    def test_masked_global_probe_cli_parsing(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder)/"retail.exe", Path(folder)/"gog.exe"
            a.write_bytes(pe_fixture())
            b.write_bytes(pe_fixture(text_offset=0x800))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(tool.main([
                    "--protected", str(a), "--reference", str(b),
                    "--reference-origin", "GOG",
                    "--masked-pair", "0x401030:0x401040"
                ]), 0)
            result = json.loads(out.getvalue())
            pairs = result["masked_pointer_pair_observations"]
            self.assertEqual(len(pairs["pairs"]), 1)
            self.assertFalse(pairs["pairs"][0]["runtime_pointer_known"])
            self.assertIn("On-disk pairs", pairs["runtime_inference"])

    def test_descriptor_layout_compares_full_file_backed_records(self):
        retail = bytearray(pe_fixture(text_offset=0x400))
        gog = bytearray(pe_fixture(text_offset=0x800))
        stride = 0x4C
        for binary, raw in ((retail, 0x400), (gog, 0x800)):
            for index in range(3):
                off = raw+0x20+index*stride
                binary[off:off+stride] = bytes(stride)
            struct.pack_into("<I", binary, raw+0x20, 0x5A151926)
            struct.pack_into("<I", binary, raw+0x20+stride, 0x0E6AA5E6)
        retail_pe = tool.parse_pe32(bytes(retail))
        gog_pe = tool.parse_pe32(bytes(gog))
        profile = tool.compare_descriptor_layout(
            retail_pe, gog_pe, 0x00401020, stride, 3, 0, 0x30
        )
        self.assertEqual(profile["identical_records"], 3)
        self.assertEqual(profile["retail_nonzero_records"], 2)
        self.assertEqual(profile["retail_zero_pointer_slots"], 3)
        self.assertTrue(profile["entries"][-1]["retail_record_all_zero"])
        self.assertFalse(profile["runtime_pointer_values_inferred"])
        self.assertEqual(profile["entries"][0]["retail_mask_candidate"], "0x5A151926")

    def test_descriptor_layout_identifies_different_record_bytes(self):
        retail = bytearray(pe_fixture())
        gog = bytearray(pe_fixture(text_offset=0x800))
        for binary, raw in ((retail, 0x400), (gog, 0x800)):
            binary[raw+0x20:raw+0x20+0x4C] = bytes(0x4C)
        gog[0x800+0x20+8] = 7
        profile = tool.compare_descriptor_layout(
            tool.parse_pe32(bytes(retail)),
            tool.parse_pe32(bytes(gog)),
            0x00401020, 0x4C, 1, 0, 0x30
        )
        self.assertFalse(profile["entries"][0]["both_full_record_bytes_equal"])
        self.assertEqual(profile["identical_records"], 0)

    def test_descriptor_layout_rejects_unbacked_and_large_inputs(self):
        pe = tool.parse_pe32(pe_fixture())
        for kwargs in [(0x401000, 0x4C, 0, 0, 0x30),
                       (0x401000, 0x4C, 257, 0, 0x30),
                       (0x401000, 0x4C, 1, 0, 0x4B)]:
            with self.assertRaisesRegex(ValueError, "invalid bounded"):
                tool.compare_descriptor_layout(pe, pe, *kwargs)
        with self.assertRaisesRegex(ValueError, "file bytes unavailable"):
            tool.compare_descriptor_layout(pe, pe, 0x403000, 0x4C, 1, 0, 0x30)

    def test_cli_descriptor_layout_metadata_only(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder)/"retail.exe", Path(folder)/"gog.exe"
            a.write_bytes(pe_fixture())
            b.write_bytes(pe_fixture(text_offset=0x800))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(tool.main([
                    "--protected", str(a), "--reference", str(b),
                    "--reference-origin", "GOG",
                    "--descriptor-layout", "0x401020:0x4c:2:0:0x30"
                ]), 0)
            report = json.loads(out.getvalue())["file_backed_descriptor_observations"]
            self.assertEqual(report["records"], 2)
            self.assertEqual(report["stride_bytes"], 0x4C)
            self.assertFalse(report["source_code_execution_asserted"])
            self.assertEqual(len(report["entries"]), 2)

    def test_whole_function_int3_neutralization_at_matching_va(self):
        protected = bytearray(pe_fixture(text_offset=0x400))
        reference = bytearray(pe_fixture(text_offset=0x800))
        reference[0x800+0x30:0x800+0x30+80] = bytes([0xCC])*80
        report = tool.compare_code_spans(
            tool.parse_pe32(bytes(protected)),
            tool.parse_pe32(bytes(reference)),
            [(0x00401030, 80)]
        )[0]
        self.assertEqual(report["length_bytes"], 80)
        self.assertEqual(report["bytes_changed_to_int3"], 80)
        self.assertTrue(report["reference_all_int3_bytes"])
        self.assertEqual(report["identical_bytes"], 0)
        self.assertFalse(report["protection_change_asserted"])
        self.assertFalse(report["runtime_reachability_asserted"])

    def test_partial_code_span_change_and_nop_are_distinguished(self):
        protected = bytearray(pe_fixture())
        reference = bytearray(pe_fixture(text_offset=0x800))
        reference[0x800+0x30:0x800+0x40] = bytes([0x90])*16
        report = tool.compare_code_spans(
            tool.parse_pe32(bytes(protected)),
            tool.parse_pe32(bytes(reference)),
            [(0x00401020, 64)]
        )[0]
        self.assertEqual(report["identical_bytes"], 48)
        self.assertEqual(report["bytes_changed_to_nop"], 16)
        self.assertFalse(report["reference_all_nop_bytes"])
        self.assertFalse(report["reference_all_int3_bytes"])

    def test_code_span_rejects_oversize_and_unbacked_ranges(self):
        pe = tool.parse_pe32(pe_fixture())
        with self.assertRaisesRegex(ValueError, "between 1 and 65536"):
            tool.compare_code_spans(pe, pe, [(0x00401000, 65537)])
        with self.assertRaisesRegex(ValueError, "at most 64"):
            tool.compare_code_spans(pe, pe, [(0x00401000, 1)]*65)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            tool.compare_code_spans(pe, pe, [(0x00401200, 8)])

    def test_cli_code_span_read_only_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            a, b = Path(folder)/"retail.exe", Path(folder)/"gog.exe"
            a.write_bytes(pe_fixture())
            ref = bytearray(pe_fixture(text_offset=0x800))
            ref[0x800+0x80:0x800+0x88] = bytes([0xCC])*8
            b.write_bytes(ref)
            import contextlib, io, json
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(tool.main([
                    "--protected", str(a), "--reference", str(b),
                    "--reference-origin", "GOG",
                    "--code-span", "0x401080:8",
                ]), 0)
            report = json.loads(out.getvalue())
            self.assertEqual(report["reference_origin_label"], "GOG")
            self.assertTrue(report["on_disk_code_span_comparison"][0]["reference_all_int3_bytes"])
            self.assertFalse(report["on_disk_code_span_comparison"][0]["protection_change_asserted"])

    def test_minimal_x86_function_stub_classification(self):
        cases = [
            (bytes.fromhex("c3") + bytes(11), "ret"),
            (bytes.fromhex("33 c0 c3") + bytes(9), "returns_zero"),
            (bytes.fromhex("33 c0 40 c3") + bytes(8), "returns_one"),
            (bytes.fromhex("b8 2a 00 00 00 c3") + bytes(6), "returns_constant"),
            (bytes.fromhex("b8 05 00 00 00 c2 04 00") + bytes(4),
             "returns_constant_ret_imm16"),
            (bytes.fromhex("c2 08 00") + bytes(9), "ret_imm16"),
            (bytes.fromhex("cc") + bytes(11), "int3_at_entry"),
            (bytes.fromhex("55 8b ec") + bytes(9), "other_or_longer_function"),
        ]
        for blob, expected in cases:
            with self.subTest(expected=expected):
                r = tool.classify_x86_entry_stub(blob)
                self.assertEqual(r["kind"], expected)
        self.assertEqual(tool.classify_x86_entry_stub(cases[3][0])["value"], "0x0000002A")
        self.assertEqual(tool.classify_x86_entry_stub(cases[4][0])["value"], "0x00000005")
        self.assertEqual(tool.classify_x86_entry_stub(cases[4][0])["stack_pop_bytes"], 4)
        self.assertEqual(tool.classify_x86_entry_stub(cases[5][0])["stack_pop_bytes"], 8)

    def test_entry_stub_comparison_matches_virtual_addresses_not_file_offsets(self):
        retail = bytearray(pe_fixture())
        gog = bytearray(pe_fixture(text_offset=0x800))
        gog[0x800+0x80] = 0xC3
        gog[0x800+0x90:0x800+0x94] = bytes.fromhex("33 c0 40 c3")
        a = tool.parse_pe32(bytes(retail))
        b = tool.parse_pe32(bytes(gog))
        out = tool.compare_entry_stubs(a, b, [0x00401080, 0x00401090])
        self.assertEqual([x["reference"]["kind"] for x in out],
                         ["ret", "returns_one"])
        self.assertTrue(all(not x["runtime_execution_asserted"] for x in out))
        self.assertTrue(all(not x["safe_disc_only_change_asserted"] for x in out))

    def test_entry_stub_invalid_addresses_and_limits(self):
        pe = tool.parse_pe32(pe_fixture())
        with self.assertRaisesRegex(ValueError, "at most 64"):
            tool.compare_entry_stubs(pe, pe, [0x401000]*65)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            tool.compare_entry_stubs(pe, pe, [0x4011ff])

    def test_cli_entry_stubs_preserve_gog_origin_warning(self):
        with tempfile.TemporaryDirectory() as folder:
            retail = Path(folder)/"retail.exe"
            gog = Path(folder)/"gog.exe"
            retail.write_bytes(pe_fixture())
            raw = bytearray(pe_fixture(text_offset=0x800))
            raw[0x800+0x80] = 0xC3
            gog.write_bytes(raw)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(tool.main([
                    "--protected", str(retail),
                    "--reference", str(gog), "--reference-origin", "GOG",
                    "--entry-va", "0x401080",
                ]), 0)
            item = json.loads(out.getvalue())
            self.assertEqual(item["reference_origin_label"], "GOG")
            self.assertFalse(item["reference_is_pristine_retail_verified"])
            self.assertEqual(item["entrypoint_stub_comparison"][0]["reference"]["kind"], "ret")

    def test_virtual_pe_tail_is_not_stored_in_the_file(self):
        pe = tool.parse_pe32(pe_fixture())
        pe["sections"][".text"]["virtual_size"] = 768
        backed = tool.describe_virtual_address(pe, 0x4011F0)
        tail = tool.describe_virtual_address(pe, 0x401200)
        self.assertEqual(backed["storage"], "file_backed")
        self.assertEqual(tail["storage"], "virtual_zero_fill_at_load")
        self.assertFalse(tail["runtime_value_inferred"])
        self.assertEqual(tail["section_delta"], "0x200")

    def test_section_boundary_and_unmapped_addresses(self):
        pe = tool.parse_pe32(pe_fixture())
        pe["sections"][".text"]["virtual_size"] = 768
        self.assertEqual(
            tool.describe_virtual_address(pe, 0x4011FE, 4)["storage"],
            "crosses_file_and_zero_fill"
        )
        self.assertEqual(
            tool.describe_virtual_address(pe, 0x402FFF)["storage"],
            "not_in_any_section"
        )
        with self.assertRaisesRegex(ValueError, "invalid address or length"):
            tool.describe_virtual_address(pe, 0x401100, 0)

    def test_cli_virtual_storage_comparison(self):
        with tempfile.TemporaryDirectory() as folder:
            retail = Path(folder)/"retail.exe"
            gog = Path(folder)/"gog.exe"
            sample = bytearray(pe_fixture())
            # VirtualSize 0x300 exceeds RawSize 0x200 by 256.
            import struct
            struct.pack_into("<I", sample, 0x178+8, 0x300)
            retail.write_bytes(sample)
            sample2 = bytearray(pe_fixture(text_offset=0x800))
            struct.pack_into("<I", sample2, 0x178+8, 0x300)
            gog.write_bytes(sample2)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(tool.main([
                    "--protected", str(retail), "--reference", str(gog),
                    "--reference-origin", "GOG", "--map-va", "0x401204"
                ]), 0)
            result = json.loads(buf.getvalue())
            record = result["virtual_address_storage"][0]
            self.assertEqual(record["protected"]["storage"], "virtual_zero_fill_at_load")
            self.assertEqual(record["reference"]["storage"], "virtual_zero_fill_at_load")
            self.assertFalse(record["reference"]["runtime_value_inferred"])

    def test_reader_rejects_symlinks_and_oversized_sparse_files(self):
        import os
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.exe"
            original.write_bytes(pe_fixture())
            self.assertEqual(tool.read_bounded(original), original.read_bytes())
            large = root / "oversize.exe"
            with large.open("wb") as handle:
                handle.truncate(tool.MAX_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "16 MiB"):
                tool.read_bounded(large)
            link = root / "link.exe"
            try:
                link.symlink_to(original)
            except (OSError, NotImplementedError):
                # Symlink creation may require extra privileges on Windows.
                pass
            else:
                with self.assertRaises((ValueError, OSError)):
                    tool.read_bounded(link)

    def test_reader_detects_file_replacement_during_open(self):
        from unittest.mock import patch
        import os
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "game.exe"
            path.write_bytes(pe_fixture())
            actual_open = os.open
            def replace_file_during_open(target, flags, *args, **kwargs):
                if Path(target) == path:
                    # Keep the old inode alive: unlink/recreate can reuse
                    # the same inode immediately and make this test flaky.
                    path.rename(path.with_name("old-game.exe"))
                    path.write_bytes(pe_fixture())
                return actual_open(target, flags, *args, **kwargs)
            with patch.object(tool.os, "open", side_effect=replace_file_during_open):
                with self.assertRaisesRegex(ValueError, "replaced"):
                    tool.read_bounded(path)

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
