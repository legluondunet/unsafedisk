"""No retail game data in tests; synthetic PE32 with optional owner-only SHA check."""
import hashlib
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

import rayman2_v4_cd_dat_path_probe as probe


def fixture() -> bytes:
    b = bytearray(probe.EXE_SIZE)
    b[:2] = b'MZ'
    struct.pack_into('<I', b, 0x3c, 0x80)
    b[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HH', b, 0x84, 0x14c, 3)
    struct.pack_into('<H', b, 0x94, 0xe0)
    struct.pack_into('<H', b, 0x98, 0x10b)
    struct.pack_into('<I', b, 0x98 + 28, probe.IMAGE_BASE)
    # Three non-overlapping, file-backed sections.
    for n, (name, virt, rva, raw_size, file_offset) in enumerate([
        (b'.text', 0x99000, 0x1000, 0x99000, 0x400),
        (b'.rdata', 0x3000, 0x9c000, 0x3000, 0x99a00),
        (b'.data', 0x776d0, 0x9f000, 0x7c00, 0x9d600),
    ]):
        p = 0x98 + 0xe0 + 40*n
        b[p:p+len(name)] = name
        struct.pack_into('<IIII', b, p+8, virt, rva, raw_size, file_offset)
    p = probe.section_offset(b, probe.FORMAT_VA, len(probe.RELATIVE_FORMAT))
    b[p:p+len(probe.RELATIVE_FORMAT)] = probe.RELATIVE_FORMAT
    return bytes(b)


def expect_success(data):
    out = bytearray(data)
    out[probe.section_offset(data, probe.COLON_VA, 1)] = ord(':')
    with patch.object(probe, 'INPUT_SHA', probe.digest(data)), \
         patch.object(probe, 'OUTPUT_SHA', probe.digest(bytes(out))):
        result, info = probe.patch(data)
    return result, info


class TestCDDatPathOnly(TestCase):
    def test_va_mapping(self):
        self.assertEqual(probe.section_offset(fixture(), probe.COLON_VA, 1), 0xA0866)

    def test_one_byte_only(self):
        data = fixture()
        output, info = expect_success(data)
        self.assertEqual(len(data), len(output))
        changes = [i for i, (a,b) in enumerate(zip(data, output)) if a != b]
        self.assertEqual(changes, [0xA0866])
        self.assertEqual(info['bytes_changed'], 1)

    def test_exact_formatter(self):
        data = fixture()
        output, _ = expect_success(data)
        start = probe.section_offset(data, probe.FORMAT_VA, len(probe.ABSOLUTE_FORMAT))
        self.assertEqual(output[start:start+len(probe.ABSOLUTE_FORMAT)], probe.ABSOLUTE_FORMAT)
        self.assertTrue(probe.ABSOLUTE_FORMAT.startswith(b'%c:\\'))

    def test_unchanged_other_formats(self):
        data = fixture()
        output, _ = expect_success(data)
        for va in (0x49F396, 0x49F3A6, 0x4A06DA, 0x4A268A):
            i = probe.section_offset(data, va, 1)
            self.assertEqual(output[i], data[i])

    def test_unrecognized_input(self):
        with self.assertRaisesRegex(ValueError, 'unknown input'):
            probe.patch(fixture())

    def test_wrong_anchor(self):
        b = bytearray(fixture())
        i = probe.section_offset(b, probe.FORMAT_VA, 1)
        b[i] = 0x1
        with patch.object(probe, 'INPUT_SHA', probe.digest(b)):
            with self.assertRaisesRegex(ValueError, 'DAT path formatter'):
                probe.patch(bytes(b))

    def test_wrong_output_hash(self):
        b = fixture()
        with patch.object(probe, 'INPUT_SHA', probe.digest(b)), patch.object(probe, 'OUTPUT_SHA', '0'*64):
            with self.assertRaisesRegex(ValueError, 'output SHA mismatch'):
                probe.patch(b)

    def test_wrong_length(self):
        b = fixture()[:-1]
        with self.assertRaisesRegex(ValueError, 'unexpected EXE size'):
            probe.section_offset(b, probe.FORMAT_VA, 1)

    def test_bad_pe_signature(self):
        b = bytearray(fixture())
        b[0x80:0x84] = b'BAD!'
        with self.assertRaisesRegex(ValueError, 'unexpected PE header'):
            probe.section_offset(b, probe.FORMAT_VA, 1)

    def test_wrong_machine(self):
        b = bytearray(fixture())
        struct.pack_into('<H', b, 0x84, 0x8664)
        with self.assertRaisesRegex(ValueError, 'unexpected PE32'):
            probe.section_offset(b, probe.FORMAT_VA, 1)

    def test_wrong_section_name(self):
        b = bytearray(fixture())
        i = 0x98 + 0xe0 + 80
        b[i:i+5] = b'.DATA'
        with self.assertRaisesRegex(ValueError, 'target section missing'):
            probe.section_offset(b, probe.FORMAT_VA, 1)

    def test_out_of_bounds(self):
        with self.assertRaisesRegex(ValueError, 'outside expected'):
            probe.section_offset(fixture(), 0x4FFFFF, 1024)

    def test_existing_output_is_untouched(self):
        with TemporaryDirectory() as d:
            source = Path(d)/'source.exe'; source.write_bytes(fixture())
            output = Path(d)/'output.exe'; output.write_bytes(b'keep')
            with self.assertRaises(SystemExit) as err:
                probe.main([str(source), str(output)])
            self.assertEqual(err.exception.code, 2)
            self.assertEqual(output.read_bytes(), b'keep')

    def test_source_symlink_rejected(self):
        with TemporaryDirectory() as d:
            source = Path(d)/'source.exe'; source.write_bytes(fixture())
            link = Path(d)/'link.exe'; link.symlink_to(source)
            with self.assertRaises(SystemExit):
                probe.main([str(link), str(Path(d)/'new.exe')])

    def test_dry_run_only(self):
        with TemporaryDirectory() as d:
            source = Path(d)/'source.exe'
            data = fixture(); source.write_bytes(data)
            output = Path(d)/'new.exe'
            expected=bytearray(data)
            expected[probe.section_offset(data, probe.COLON_VA, 1)] = ord(':')
            with patch.object(probe, 'INPUT_SHA', probe.digest(data)), \
                 patch.object(probe, 'OUTPUT_SHA', probe.digest(bytes(expected))):
                self.assertEqual(probe.main([str(source), str(output), '--dry-run']), 0)
            self.assertFalse(output.exists())
            self.assertEqual(source.read_bytes(), data)

    def test_actual_user_exe_optional(self):
        source = Path('/mnt/data/rayman2_test_cd_alias_fixture/Rayman2-v4-cd-scan-only-test.exe')
        if not source.exists():
            self.skipTest('private owner input missing in CI')
        data = source.read_bytes()
        result, report = probe.patch(data)
        self.assertEqual(probe.digest(result), probe.OUTPUT_SHA)
        self.assertEqual(report['changed_va'], '0x004A2266')


if __name__ == '__main__':
    main()
