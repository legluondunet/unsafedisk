"""Tests for V4-CD-routes -> V4-CD-scan-only control; synthetic PE and owner-only integration."""
from __future__ import annotations
import hashlib
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import rayman2_v4_cd_scan_only as m


def fixture() -> bytes:
    data=bytearray(m.SIZE)
    data[:2]=b'MZ';struct.pack_into('<I',data,0x3c,0x80)
    data[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HH',data,0x84,0x14c,3)
    struct.pack_into('<H',data,0x94,0xe0)
    struct.pack_into('<H',data,0x98,0x10b)
    struct.pack_into('<I',data,0x98+28,0x400000)
    for i,(name,vsize,rva,rsize,roff) in enumerate([
        (b'.text',0x50000,0x1000,0x50000,0x400),
        (b'.rdata',0x1000,0x51000,0x1000,0x50400),
        (b'.data',0x9000,0x9e000,0x9000,0x54000),
    ]):
        p=0x98+0xe0+i*40;data[p:p+len(name)]=name
        struct.pack_into('<IIII',data,p+8,vsize,rva,rsize,roff)
    scanner=m.offset(data,m.SCANNER_VA,len(m.SCANNER_ORIGINAL),'.text')
    data[scanner:scanner+len(m.SCANNER_ORIGINAL)]=m.SCANNER_ORIGINAL
    for va,t in m.FORMATS.items():
        p=m.offset(data,va,len(t)+1,'.data')
        data[p:p+len(t)+1]=t+b'\0'
    return bytes(data)


def expected(data:bytes) -> bytes:
    out=bytearray(data)
    for va in m.FORMATS:
        out[m.offset(data,va+2,1,'.data')]=0x5c
    return bytes(out)


def patched_fixture(data=None):
    data=fixture() if data is None else data
    with patch.object(m,'INPUT_SHA256',m.digest(data)),patch.object(m,'OUTPUT_SHA256',m.digest(expected(data))):
        return m.patch(data)


class TestScanOnly(unittest.TestCase):
    def test_exact_five_changes(self):
        a=fixture();b,meta=patched_fixture(a)
        self.assertEqual(b,expected(a));self.assertEqual(meta['changed_bytes'],5)
        self.assertEqual(sum(c!=d for c,d in zip(a,b)),5)
    def test_volume_scanner_intact(self):
        a=fixture();b,_=patched_fixture(a)
        p=m.offset(a,m.SCANNER_VA,11,'.text')
        self.assertEqual(a[p:p+11],b[p:p+11])
    def test_all_five_original_formats_covered(self):
        a=fixture();b,_=patched_fixture(a)
        for va,t in m.FORMATS.items():
            p=m.offset(a,va,len(t)+1,'.data')
            self.assertEqual(a[p:p+len(t)+1],t+b'\0')
            self.assertEqual(b[p:p+len(t)+1],t[:2]+b'\\'+t[3:]+b'\0')
    def test_unknown_source_sha_rejected(self):
        with self.assertRaisesRegex(ValueError,'unrecognized input'):m.patch(fixture())
    def test_wrong_output_hash_rejected(self):
        a=fixture()
        with patch.object(m,'INPUT_SHA256',m.digest(a)),patch.object(m,'OUTPUT_SHA256','f'*64):
            with self.assertRaisesRegex(ValueError,'unverified output'):m.patch(a)
    def test_missing_scanner_anchor(self):
        a=bytearray(fixture());p=m.offset(a,m.SCANNER_VA,11,'.text');a[p]=0
        with patch.object(m,'INPUT_SHA256',m.digest(a)):
            with self.assertRaisesRegex(ValueError,'retail CD scanner'):m.patch(bytes(a))
    def test_missing_path_anchor(self):
        a=bytearray(fixture());p=m.offset(a,0x4A06D8,1,'.data');a[p]=0
        with patch.object(m,'INPUT_SHA256',m.digest(a)):
            with self.assertRaisesRegex(ValueError,'path format'):m.patch(bytes(a))
    def test_bad_mz(self):
        a=bytearray(fixture());a[:2]=b'AZ'
        with self.assertRaisesRegex(ValueError,'MZ'):m.offset(bytes(a),0x4A06D8,1,'.data')
    def test_bad_pe_magic(self):
        a=bytearray(fixture());a[0x80:0x84]=b'FAIL'
        with self.assertRaisesRegex(ValueError,'PE signature'):m.offset(bytes(a),0x4A06D8,1,'.data')
    def test_missing_section(self):
        a=bytearray(fixture());p=0x98+0xe0+2*40;a[p:p+5]=b'.gone'
        with self.assertRaisesRegex(ValueError,'section absent'):m.offset(bytes(a),0x4A06D8,1,'.data')
    def test_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'in.exe';dst=root/'out.exe'
            src.write_bytes(fixture());dst.write_bytes(b'keep')
            with self.assertRaises(SystemExit) as x:m.main([str(src),str(dst)])
            self.assertEqual(x.exception.code,2)
            self.assertEqual(dst.read_bytes(),b'keep')
    def test_refuses_symlink_source(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'in.exe';link=root/'link.exe'
            src.write_bytes(fixture());link.symlink_to(src)
            with self.assertRaises(SystemExit) as x:m.main([str(link),str(root/'out.exe')])
            self.assertEqual(x.exception.code,2)
    def test_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'in.exe';link=root/'link.exe'
            src.write_bytes(fixture());link.symlink_to(root/'absent.exe')
            with self.assertRaises(SystemExit) as x:m.main([str(src),str(link)])
            self.assertEqual(x.exception.code,2)
    def test_private_owner_full_reconstruction(self):
        orig=Path('/mnt/data/rayman2_research/Rayman2(3).exe')
        if not orig.exists():self.skipTest('Original CD binary not in CI')
        v=orig.read_bytes()
        modules=['unsafedisk_v3/rayman2_portable_cd_probe.py',
                 'unsafedisk_v3/rayman2_dat_name_probe_v2.py',
                 'unsafedisk_v3/rayman2_dat_offset_probe_v3.py',
                 'unsafedisk_v4/rayman2_dat_read_probe_v4.py',
                 'unsafedisk_cdroute_control/rayman2_v4_cd_route_control.py']
        for i,item in enumerate(modules):
            p=Path('/mnt/data')/item
            if not p.exists():self.skipTest('Private full-pipeline source missing')
            spec=importlib.util.spec_from_file_location(f'owner_stage_{i}',p)
            code=importlib.util.module_from_spec(spec);spec.loader.exec_module(code)
            v,_=code.patch(v)
        b,info=m.patch(v)
        self.assertEqual(hashlib.sha256(b).hexdigest(),m.OUTPUT_SHA256)
        self.assertEqual(info['changed_bytes'],5)


if __name__=='__main__':unittest.main()
