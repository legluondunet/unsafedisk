"""Synthetic, independent verification of the two-byte V3 hypothesis."""
from __future__ import annotations
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch as replace

SOURCE=Path(__file__).with_name('rayman2_dat_offset_probe_v3.py')
spec=importlib.util.spec_from_file_location('v3',SOURCE)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture() -> bytes:
    x=bytearray(m.INPUT_SIZE)
    x[:2]=b'MZ'
    struct.pack_into('<I',x,0x3c,0x80)
    x[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HH',x,0x84,0x14c,3)
    struct.pack_into('<H',x,0x94,0xe0)
    struct.pack_into('<H',x,0x98,0x10b)
    struct.pack_into('<I',x,0x98+28,0x400000)
    sect=0x178
    for i,(name,vs,rva,rs,rp) in enumerate(((b'.text',0x9a200,0x1000,0x9a200,0x400),
        (b'.rdata',0x3000,0x9c000,0x3000,0x9a600),
        (b'.data',0x776d0,0x9f000,0x7c00,0x9d600))):
        p=sect+i*40
        x[p:p+8]=name.ljust(8,b'\0')
        struct.pack_into('<IIII',x,p+8,vs,rva,rs,rp)
    for va,b in ((m.PREVIOUS_VA,m.PREVIOUS_BYTES),
                 (m.SITE_VA,m.OLD),(m.NEXT_VA,m.NEXT_BYTES)):
        o=0x400+va-0x401000
        x[o:o+len(b)]=b
    return bytes(x)


class Tests(unittest.TestCase):
    def test_byte_patterns(self):
        self.assertEqual(m.OLD,b'\x29\x0e')
        self.assertEqual(m.NEW,b'\x90\x90')
    def test_file_backed_mapping(self):
        f=fixture();i=m.text_offset(f,m.SITE_VA,2)
        self.assertEqual(f[i:i+2],m.OLD)
    def test_only_two_bytes_changed(self):
        f=fixture()
        expect=bytearray(f);p=m.text_offset(f,m.SITE_VA,2);expect[p:p+2]=m.NEW
        with replace.object(m,'INPUT_SHA256',m.sha256(f)),replace.object(m,'OUTPUT_SHA256',m.sha256(expect)):
            out,r=m.patch(f)
        self.assertEqual(out,bytes(expect))
        self.assertEqual(r['changed_byte_count'],2)
        self.assertTrue(r['original_512_byte_DAT_reads_preserved'])
        self.assertFalse(r['CD_independence_proven'])
    def test_wrong_source_sha(self):
        with self.assertRaisesRegex(ValueError,'unknown source'):m.patch(fixture())
    def test_wrong_output_sha(self):
        f=fixture()
        with replace.object(m,'INPUT_SHA256',m.sha256(f)):
            with self.assertRaisesRegex(ValueError,'candidate bytes or SHA'):m.patch(f)
    def test_site_corruption_fails_anchor(self):
        x=bytearray(fixture());x[m.text_offset(x,m.SITE_VA,2)]=0xCC
        with replace.object(m,'INPUT_SHA256',m.sha256(x)):
            with self.assertRaisesRegex(ValueError,'subtraction'):m.patch(bytes(x))
    def test_prior_corruption_fails_anchor(self):
        x=bytearray(fixture());x[m.text_offset(x,m.PREVIOUS_VA,9)]=0xCC
        with replace.object(m,'INPUT_SHA256',m.sha256(x)):
            with self.assertRaisesRegex(ValueError,'earlier offset'):m.patch(bytes(x))
    def test_later_corruption_fails_anchor(self):
        x=bytearray(fixture());x[m.text_offset(x,m.NEXT_VA,12)]=0xCC
        with replace.object(m,'INPUT_SHA256',m.sha256(x)):
            with self.assertRaisesRegex(ValueError,'later call'):m.patch(bytes(x))
    def test_wrong_dos_magic(self):
        f=bytearray(fixture());f[:2]=b'XX'
        with self.assertRaisesRegex(ValueError,'invalid MZ'):m.text_offset(bytes(f),m.SITE_VA,2)
    def test_wrong_nt_magic(self):
        f=bytearray(fixture());f[0x80:0x84]=b'BAD!'
        with self.assertRaisesRegex(ValueError,'PE signature'):m.text_offset(bytes(f),m.SITE_VA,2)
    def test_beyond_section(self):
        with self.assertRaisesRegex(ValueError,'outside file-backed'):m.text_offset(fixture(),0x501000,2)
    def test_input_output_not_touched_on_dry_run(self):
        f=fixture()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fake-v2.exe';p.write_bytes(f)
            q=Path(d)/'v3.exe'
            with replace.object(m,'INPUT_SHA256',m.sha256(f)):
                expect=bytearray(f);i=m.text_offset(f,m.SITE_VA,2);expect[i:i+2]=m.NEW
                with replace.object(m,'OUTPUT_SHA256',m.sha256(expect)):
                    self.assertEqual(m.main([str(p),str(q),'--dry-run']),0)
            self.assertEqual(p.read_bytes(),f)
            self.assertFalse(q.exists())
    def test_candidate_from_exact_known_original(self):
        # Integration is private owner-only and not required for CI.
        orig=Path('/mnt/data/rayman2_research/Rayman2(3).exe')
        v1src=SOURCE.with_name('rayman2_portable_cd_probe.py')
        v2src=SOURCE.with_name('rayman2_dat_name_probe_v2.py')
        if not(orig.exists() and v1src.exists() and v2src.exists()):
            self.skipTest('private original and V1/V2 tools absent')
        import sys
        sys.path.insert(0,str(SOURCE.parent))
        from rayman2_portable_cd_probe import patch as make_v1
        from rayman2_dat_name_probe_v2 import patch as make_v2
        b=orig.read_bytes()
        self.assertEqual(hashlib.sha256(b).hexdigest(),
           '7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3')
        a,_=make_v1(b)
        v2,_=make_v2(a)
        out,report=m.patch(v2)
        self.assertEqual(report['output_sha256'],m.OUTPUT_SHA256)
        self.assertEqual(len(out),m.INPUT_SIZE)
        delta=[i for i,(a,b) in enumerate(zip(v2,out)) if a!=b]
        self.assertEqual(delta,[m.text_offset(v2,m.SITE_VA,2),m.text_offset(v2,m.SITE_VA,2)+1])


if __name__=='__main__':unittest.main()
