"""Synthetic-only tests; no commercial EXEs or game assets bundled."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch
import struct
import hashlib
import rayman2_v4_cd_route_control as m


def fixture() -> bytes:
    b = bytearray(m.EXPECTED_SIZE)
    b[:2] = b'MZ'
    struct.pack_into('<I',b,0x3c,0x80)
    b[0x80:0x84] = b'PE\x00\x00'
    struct.pack_into('<HH',b,0x84,0x14c,3)
    struct.pack_into('<H',b,0x94,0xe0)
    struct.pack_into('<H',b,0x98,0x10b)
    struct.pack_into('<I',b,0x98+28,0x400000)
    sects=[(b'.text',0x50000,0x1000,0x50000,0x400),
           (b'.rdata',0x1000,0x51000,0x1000,0x50400),
           (b'.data',0x9000,0x9e000,0x9000,0x54000)]
    for i,(name,virtual,rva,rawsize,rawpos) in enumerate(sects):
        off=0x98+0xe0+i*40
        b[off:off+len(name)]=name
        struct.pack_into('<IIII',b,off+8,virtual,rva,rawsize,rawpos)
    pos=m.mapped_offset(b,m.SCANNER_VA,len(m.SCANNER_FIXED),'.text')
    b[pos:pos+len(m.SCANNER_FIXED)]=m.SCANNER_FIXED
    pos=m.mapped_offset(b,m.VOLUME_VA,len(m.VOLUME_V4),'.text')
    b[pos:pos+len(m.VOLUME_V4)]=m.VOLUME_V4
    for va,fmt in m.DRIVE_FORMATS.items():
        pos=m.mapped_offset(b,va,len(fmt)+1,'.data')
        b[pos:pos+len(fmt)+1] = fmt[:2]+b'\\'+fmt[3:]+b'\0'
    return bytes(b)


def reference_transform(b):
    out=bytearray(b)
    off=m.mapped_offset(b,m.VOLUME_VA,len(m.VOLUME_RETAIL),'.text')
    out[off:off+len(m.VOLUME_RETAIL)]=m.VOLUME_RETAIL
    for va in m.DRIVE_FORMATS:
        out[m.mapped_offset(b,va+2,1,'.data')]=ord(':')
    return bytes(out)


def run_fixture(b):
    target=reference_transform(b)
    with patch.object(m,'V4_SHA256',m.sha256(b)),patch.object(m,'CD_ROUTE_SHA256',m.sha256(target)):
        return m.patch(b)


class TestCDRouteControl(TestCase):
    def test_fixture_sections(self):
        b=fixture()
        self.assertEqual(m.mapped_offset(b,m.VOLUME_VA,11,'.text'),0x400+0x48e5a-0x1000)
    def test_target_hash_and_exact_16(self):
        b=fixture();out,report=run_fixture(b)
        self.assertEqual(out,reference_transform(b))
        self.assertEqual(report['bytes_different_from_v4'],16)
        self.assertEqual(report['restored_retail_cd_path_formats'],5)
    def test_original_cd_routing_restored(self):
        b=fixture();out,_=run_fixture(b)
        p=m.mapped_offset(b,m.VOLUME_VA,len(m.VOLUME_RETAIL),'.text')
        self.assertEqual(out[p:p+11],m.VOLUME_RETAIL)
        for va,fmt in m.DRIVE_FORMATS.items():
            p=m.mapped_offset(b,va,len(fmt)+1,'.data')
            self.assertEqual(out[p:p+len(fmt)+1],fmt+b'\0')
    def test_no_other_changes(self):
        b=fixture();out,_=run_fixture(b)
        changed={i for i,(a,c) in enumerate(zip(b,out)) if a!=c}
        vol=m.mapped_offset(b,m.VOLUME_VA,11,'.text')
        expected={i for i in range(vol,vol+11) if b[i]!=m.VOLUME_RETAIL[i-vol]}
        expected|={m.mapped_offset(b,va+2,1,'.data') for va in m.DRIVE_FORMATS}
        self.assertEqual(changed,expected)
    def test_wrong_sha(self):
        with self.assertRaisesRegex(ValueError,'unknown input'):
            m.patch(fixture())
    def test_wrong_output_sha(self):
        b=fixture()
        with patch.object(m,'V4_SHA256',m.sha256(b)),patch.object(m,'CD_ROUTE_SHA256','0'*64):
            with self.assertRaisesRegex(ValueError,'output SHA'):m.patch(b)
    def test_corrupt_volume_anchor(self):
        b=bytearray(fixture());p=m.mapped_offset(b,m.VOLUME_VA,11,'.text');b[p]=0x90
        with patch.object(m,'V4_SHA256',m.sha256(b)):
            with self.assertRaisesRegex(ValueError,'CD-volume'):m.patch(bytes(b))
    def test_corrupt_one_format(self):
        b=bytearray(fixture());p=m.mapped_offset(b,0x4A06D8,1,'.data');b[p]=0x20
        with patch.object(m,'V4_SHA256',m.sha256(b)):
            with self.assertRaisesRegex(ValueError,'path pattern'):m.patch(bytes(b))
    def test_corrupt_scanner(self):
        b=bytearray(fixture());p=m.mapped_offset(b,m.SCANNER_VA,1,'.text');b[p]=0x40
        with patch.object(m,'V4_SHA256',m.sha256(b)):
            with self.assertRaisesRegex(ValueError,'scanner'):m.patch(bytes(b))
    def test_bad_mz(self):
        b=bytearray(fixture());b[:2]=b'!!'
        with self.assertRaisesRegex(ValueError,'MZ'):m.mapped_offset(bytes(b),m.VOLUME_VA,1,'.text')
    def test_missing_section(self):
        b=bytearray(fixture());p=0x98+0xe0+2*40;b[p:p+5]=b'.lost'
        with self.assertRaisesRegex(ValueError,'section absent'):m.mapped_offset(bytes(b),0x49F394,1,'.data')
    def test_outside_section(self):
        with self.assertRaisesRegex(ValueError,'not backed'):m.mapped_offset(fixture(),0x4FFFFF,4,'.data')
    def test_executable_only_and_output_collision(self):
        with TemporaryDirectory() as d:
            path=Path(d)/'v4.exe';path.write_bytes(fixture())
            out=Path(d)/'control.exe';out.write_bytes(b'existing')
            with self.assertRaises(SystemExit) as error:m.main([str(path),str(out)])
            self.assertEqual(error.exception.code,2)
            self.assertEqual(out.read_bytes(),b'existing')
    def test_reject_source_symlink(self):
        with TemporaryDirectory() as d:
            p=Path(d)/'v4.exe';p.write_bytes(fixture());link=Path(d)/'link.exe';link.symlink_to(p)
            with self.assertRaises(SystemExit) as error:m.main([str(link),str(Path(d)/'new.exe')])
            self.assertEqual(error.exception.code,2)
    def test_real_owner_input_if_available(self):
        # Private, optional integration; CI can run this without owner files.
        p=Path('/mnt/data/rayman2_research/Rayman2(3).exe')
        if not p.exists():self.skipTest('owner binary not available in CI')
        import importlib.util
        root=Path('/mnt/data')
        files=['unsafedisk_v3/rayman2_portable_cd_probe.py','unsafedisk_v3/rayman2_dat_name_probe_v2.py','unsafedisk_v3/rayman2_dat_offset_probe_v3.py','unsafedisk_v4/rayman2_dat_read_probe_v4.py']
        data=p.read_bytes()
        for i,file in enumerate(files):
            spec=importlib.util.spec_from_file_location(f'local_own_patch_{i}',root/file)
            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            data,_=module.patch(data)
        result,report=m.patch(data)
        self.assertEqual(report['output_sha256'],m.CD_ROUTE_SHA256)
        self.assertEqual(m.sha256(result),m.CD_ROUTE_SHA256)


if __name__=='__main__':main()
