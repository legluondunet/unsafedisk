"""Synthetic-only unit tests: no commercial executable bytes or execution."""
import hashlib
import struct
import unittest

from rayman2_win32_forwarders import EXPECTED, FORWARDER, analyze, get_va, scan_forwarders


def sample_stub(n=2, iat=0x49C058, cleanup=None, ascending=False):
    if cleanup is None:
        cleanup = n * 4
    values = list(range(8, 8 + n*4, 4))
    if not ascending:
        values.reverse()
    return (b"\x55\x8B\xEC" +
            b"".join(b"\xFF\x75" + bytes([v]) for v in values) +
            b"\xFF\x15" + struct.pack("<I", iat) +
            b"\x5D\xC2" + struct.pack("<H", cleanup))


class ForwarderTests(unittest.TestCase):
    def test_detect_valid_forwarder(self):
        calls = {0x49C058: {"dll": "KERNEL32.dll", "name": "CreateFileA"}}
        rows = scan_forwarders(b"\xCC" + sample_stub() + b"\xCC", 0x400000, calls)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["va"], rows[0]["args"]), (0x400001, 2))

    def test_missing_import_refused(self):
        self.assertEqual(scan_forwarders(sample_stub(), 0x400000, {}), [])

    def test_stack_cleanup_mismatch_refused(self):
        imports = {0x49C058: {"dll": "KERNEL32.dll", "name": "CreateFileA"}}
        self.assertEqual(scan_forwarders(sample_stub(cleanup=4), 0x400000, imports), [])

    def test_argument_order_mismatch_refused(self):
        imports = {0x49C058: {"dll": "KERNEL32.dll", "name": "CreateFileA"}}
        self.assertEqual(scan_forwarders(sample_stub(ascending=True), 0x400000, imports), [])

    def test_non_import_call_refused(self):
        imports = {0x49C058: {"dll": "KERNEL32.dll", "name": "CreateFileA"}}
        self.assertEqual(scan_forwarders(sample_stub().replace(b"\xFF\x15", b"\xFF\xD6"),
                                         0x400000, imports), [])

    def test_random_unrelated_bytes_refused(self):
        self.assertEqual(scan_forwarders(b"\x55\x8B\xEC\x00" * 128, 0x400000, {}), [])

    def test_hash_lock_rejects_non_retail(self):
        with self.assertRaisesRegex(ValueError, "retail SHA-256"):
            analyze(b"synthetic retail", b"synthetic gog")

    def test_expected_four_distinct_apis(self):
        self.assertEqual(set(r[0] for r in EXPECTED.values()),
                         {"CloseHandle", "ReadFile", "CreateFileA", "SetFilePointer"})
        self.assertEqual(len(set(EXPECTED)), 4)

    def test_bad_va_length_refused(self):
        with self.assertRaisesRegex(ValueError, "invalid VA"):
            get_va(b"foo", {"image_base": 0x400000}, 0x400000, 257)


if __name__ == "__main__":
    unittest.main()
