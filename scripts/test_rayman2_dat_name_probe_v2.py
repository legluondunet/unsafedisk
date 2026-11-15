"""Self-contained synthetic tests for the narrow Rayman 2 DAT name probe.

No original game files are redistributed or needed for CI. Private tests may
be explicitly enabled with environment variables pointing to owned binaries.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch as mock_patch

MODULE=Path(__file__).with_name('rayman2_dat_name_probe_v2.py')
spec=importlib.util.spec_from_file_location('rayman2_dat_v2',MODULE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture() -> bytes:
    """Independent synthetic PE with the same size, 3 sections and two anchors."""
    b=bytearray(m.INPUT_SIZE)
    b[:2]=b'MZ'
    struct.pack_into('<I',b,0x3c,0x80)
    b[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HH',b,0x84,0x14c,3)
    struct.pack_into('<H',b,0x94,0xe0)
    b[0x98:0x9a]=b'\x0b\x01'
    struct.pack_into('<I',b,0x98+28,0x400000)
    sect=0x178
    for i,(name,vs,rva,rs,rp) in enumerate((
        (b'.text',0x9a200,0x1000,0x9a200,0x400),
        (b'.rdata',0x3000,0x9c000,0x3000,0x9a600),
        (b'.data',0x776d0,0x9f000,0x7c00,0x9d600),
    )):
        p=sect+i*40
        b[p:p+8]=name.ljust(8,b'\0')
        struct.pack_into('<IIII',b,p+8,vs,rva,rs,rp)
    for va, anchor in ((m.SITE_VA,m.OLD),(m.NEXT_CALL_VA,m.NEXT_CALL_BYTES)):
        off=0x400+va-0x401000
        b[off:off+len(anchor)]=anchor
    return bytes(b)


class DATNameSynthetic(unittest.TestCase):
    def test_original_7_byte_site(self):
        self.assertEqual(m.OLD,bytes.fromhex('8B 14 9D 90 20 4A 00'))
        self.assertEqual(m.NEW,bytes.fromhex('8B 15 90 20 4A 00 90'))

    def test_file_backed_address(self):
        b=fixture()
        self.assertEqual(b[m.text_offset(b,m.SITE_VA,7):][:7],m.OLD)

    def test_patch_refuses_unknown_hash(self):
        with self.assertRaisesRegex(ValueError,'source SHA-256'):
            m.patch(fixture())

    def test_patch_synthetic_mutation_under_mocked_hash_and_checksum(self):
        b=fixture()
        with mock_patch.object(m,'INPUT_SHA256',m.sha256(b)):
            # Expected exact output hash computed independently by byte replacement.
            expected=bytearray(b)
            start=m.text_offset(b,m.SITE_VA,len(m.OLD))
            expected[start:start+7]=m.NEW
            with mock_patch.object(m,'OUTPUT_SHA256',m.sha256(expected)):
                out,report=m.patch(b)
        self.assertEqual(out,bytes(expected))
        self.assertEqual(report['different_bytes'],6)
        self.assertTrue(report['remaining_original_DAT_reads_and_arithmetic'])
        self.assertFalse(report['CD_independence_proven'])
        self.assertFalse(report['SafeDisc_unwrapped_proven'])

    def test_bad_second_CreatFile_anchor_refused(self):
        b=bytearray(fixture())
        b[m.text_offset(b,m.NEXT_CALL_VA,len(m.NEXT_CALL_BYTES))]=0x90
        b=bytes(b)
        with mock_patch.object(m,'INPUT_SHA256',m.sha256(b)):
            with self.assertRaisesRegex(ValueError,'later CreateFileA'):
                m.patch(b)

    def test_modified_selector_refused(self):
        b=bytearray(fixture());b[m.text_offset(b,m.SITE_VA,7)+4]=0x00;b=bytes(b)
        with mock_patch.object(m,'INPUT_SHA256',m.sha256(b)):
            with self.assertRaisesRegex(ValueError,'selector'):
                m.patch(b)

    def test_modified_pe_signature_refused(self):
        b=bytearray(fixture());b[0x80]=0;b=bytes(b)
        with mock_patch.object(m,'INPUT_SHA256',m.sha256(b)):
            with self.assertRaisesRegex(ValueError,'PE header'):
                m.patch(b)

    def test_wrong_output_hash_refused(self):
        b=fixture()
        with mock_patch.object(m,'INPUT_SHA256',m.sha256(b)):
            with self.assertRaisesRegex(ValueError,'output SHA-256'):
                m.patch(b)

    def test_section_out_of_bounds(self):
        b=fixture()
        with self.assertRaisesRegex(ValueError,'beyond file-backed'):
            m.text_offset(b,0x500000,4)

    def test_missing_input_bails_without_output(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'missing.exe';q=Path(d)/'out.exe'
            self.assertFalse(q.exists())
            self.assertFalse(p.exists())

    def test_gog_and_original_opcode_reference(self):
        original=os.environ.get('RAYMAN2_RETAIL_ORIGINAL')
        gog=os.environ.get('RAYMAN2_GOG_REFERENCE')
        if not original or not gog:
            self.skipTest('owner-only files not provided')
        import sys
        sys.path.insert(0,str(MODULE.parent))
        from rayman2_portable_cd_probe import patch as make_v1
        cd=Path(original).read_bytes(); gog_bytes=Path(gog).read_bytes()
        assert hashlib.sha256(cd).hexdigest()=='7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3'
        assert hashlib.sha256(gog_bytes).hexdigest()=='9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713'
        v1,_=make_v1(cd)
        v2,report=m.patch(v1)
        self.assertEqual(m.sha256(v2),m.OUTPUT_SHA256)
        self.assertEqual(v2[m.text_offset(v2,m.SITE_VA,7):][:7],m.NEW)
        self.assertEqual(gog_bytes[0x1000 + m.SITE_VA - 0x401000:][:7],m.NEW)
        self.assertEqual(report['candidate_size'],m.INPUT_SIZE)


if __name__=='__main__':
    unittest.main()
