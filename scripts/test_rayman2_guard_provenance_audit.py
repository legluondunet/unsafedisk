"""Synthetic guard-reference tests and optional exact private sample checks."""
import os
import struct
import unittest
from pathlib import Path
import rayman2_guard_provenance_audit as m


class GuardAuditTest(unittest.TestCase):
    def test_synthetic_read_census(self):
        raw=(b'\xa1'+struct.pack('<I',m.GUARD)+b'\x90'
             +b'\x8b\x0d'+struct.pack('<I',m.GUARD)
             +b'\x83\x3d'+struct.pack('<I',m.GUARD)+b'\x00')
        hits=m.direct_references(raw,0x401000,m.GUARD)
        self.assertEqual([x['op'] for x in hits],
            ['MOV EAX,[guard]','MOV ECX,[guard]','CMP [guard],0'])
        self.assertEqual([x['va'] for x in hits],
            ['0x00401000','0x00401006','0x0040100C'])

    def test_unknown_write_rejected(self):
        with self.assertRaisesRegex(ValueError,'unclassified'):
            m.direct_references(b'\xa3'+struct.pack('<I',m.GUARD),0x401000,m.GUARD)

    def test_unknown_other_pointer_rejected(self):
        with self.assertRaisesRegex(ValueError,'unclassified'):
            m.direct_references(b'\x68'+struct.pack('<I',m.GUARD),0x401000,m.GUARD)

    def test_no_reference_synthetic(self):
        self.assertEqual(m.direct_references(b'\0'*100,0x401000,m.GUARD),[])

    def test_sha_guard(self):
        with self.assertRaisesRegex(ValueError,'SHA256'):
            m.inspect(b'',b'')

    def test_invalid_pe(self):
        for data in (b'',b'MZ'+b'\0'*128):
            with self.assertRaises(ValueError):m.sections(data)

    def test_known_startup_sites(self):
        self.assertEqual(m.STARTUP_CALLS[0x44947C],0x4478A0)
        self.assertEqual(len(m.STARTUP_CALLS),4)

    @unittest.skipUnless(
        os.environ.get('RAYMAN2_RETAIL_EXE') and os.environ.get('RAYMAN2_GOG_EXE'),
        'private original/GOG files are not bundled in CI')
    def test_exact_owner_inputs(self):
        data=m.inspect(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
                       Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(data['retail_active_read_count'],28)
        self.assertEqual(data['gog_active_read_count'],16)
        self.assertEqual(len(data['removed_guard_ref_sites']),12)
        self.assertEqual(data['archival_text_bytes_equal_original'],631296)
        self.assertFalse(data['indirect_or_runtime_guard_writes_ruled_out'])


if __name__=='__main__':
    unittest.main()
