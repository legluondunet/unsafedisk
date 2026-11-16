"""Synthetic independent tests for the retail-ancestry-gated local-R DAT V4 probe.

No commercial EXE bytes and no CD or DAT resources are used in these tests.
"""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).with_name("rayman2_local_r_dat_v4_probe.py")
spec=importlib.util.spec_from_file_location("rayman2_local_r_dat_v4_probe",SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture() -> tuple[bytes,bytes]:
    retail=bytearray(m.FILE_SIZE)
    retail[:2]=b"MZ"
    struct.pack_into("<I",retail,0x3c,0xe0)
    retail[0xe0:0xe4]=b"PE\0\0"
    struct.pack_into("<HH",retail,0xe4,0x14c,3)
    struct.pack_into("<H",retail,0xf4,0xe0)
    opt=0xf8
    struct.pack_into("<H",retail,opt,0x10b)
    struct.pack_into("<I",retail,opt+16,0x5fcc0)
    struct.pack_into("<I",retail,opt+28,0x400000)
    for idx,(name,rva,raw,size,vsize,flags) in enumerate((
          (b".text",0x1000,0x400,0x9A200,0x9A200,0x60000020),
          (b".rdata",0x9C000,0x9A600,0x3000,0x3000,0x40000040),
          (b".data",0x9F000,0x9D600,0x7C00,0x776D0,0xC0000040))):
        at=0x1d8+idx*40
        retail[at:at+len(name)]=name
        struct.pack_into("<IIII",retail,at+8,vsize,rva,size,raw)
        struct.pack_into("<I",retail,at+36,flags)
    pe=m.map_pe(retail)
    def fill(va,data,sect=b".text"):
        at=m.at_va(pe,va,len(data),sect)
        retail[at:at+len(data)]=data
    fill(m.SCANNER_VA,m.SCANNER_ORIGINAL)
    fill(m.VOLUME_VA,m.VOLUME_ORIGINAL)
    for va in m.FORMAT_VAS:
        fill(va,b"%c:\\",b".data")
    for va,old,_,_ in m.DAT_SITE_CHANGES:
        fill(va,old)
    for va,data in m.CONTEXT:
        fill(va,data)
    original=bytes(retail)
    local=bytearray(retail)
    for va,binary in [(m.SCANNER_VA,m.SCANNER_PATCHED),
                      (m.VOLUME_VA,m.VOLUME_R)]:
        i=m.at_va(pe,va,len(binary),b".text")
        local[i:i+len(binary)]=binary
    for va in m.FORMAT_VAS:
        i=m.at_va(pe,va,4,b".data")
        local[i+2]=ord("\\")
    return original, bytes(local)


class Hybrid(unittest.TestCase):
    def setUp(self):
        self.original,self.local=fixture()
        self.patch_hash=patch.object(m,"RETAIL_SHA",m.digest(self.original))
        self.patch_hash.start()
        self.addCleanup(self.patch_hash.stop)

    def test_reconstruct_recovers_exact_original_pe32(self):
        old,_=m.reconstruct_retail(self.local)
        self.assertEqual(old,self.original)

    def test_only_four_DAT_sites_are_modified_and_all_expected(self):
        result,report=m.patch_bytes(self.local)
        self.assertEqual(report["changed_only_four_Dat_sites"],True)
        self.assertEqual(report["local_R_paths_and_CD_selector_unchanged"],True)
        self.assertEqual(report["verified_retail_ancestor_sha256"],m.digest(self.original))
        self.assertEqual(report["file_size_bytes"],m.FILE_SIZE)
        self.assertEqual(len(report["code_sites"]),4)
        pe=m.map_pe(self.local)
        allowed=set()
        for va,old,new,label in m.DAT_SITE_CHANGES:
            pos=m.at_va(pe,va,len(old),b".text")
            allowed.update(range(pos,pos+len(old)))
            self.assertEqual(result[pos:pos+len(new)],new)
        actual={i for i,(before,after) in enumerate(zip(self.local,result))
                if before!=after}
        self.assertTrue(actual)
        self.assertTrue(actual<=allowed)
        # This is an independent check that no local-R path or scanner reverts.
        for va,expected in ((m.SCANNER_VA,m.SCANNER_PATCHED),
                            (m.VOLUME_VA,m.VOLUME_R)):
            i=m.at_va(pe,va,len(expected),b".text")
            self.assertEqual(result[i:i+len(expected)],expected)
        for va in m.FORMAT_VAS:
            i=m.at_va(pe,va,4,b".data")
            self.assertEqual(result[i:i+4],b"%c\\\\")

    def test_unknown_local_R_revision_refused(self):
        bad=bytearray(self.local)
        bad[900]=1
        with self.assertRaisesRegex(ValueError,"source hash"):
            m.patch_bytes(bytes(bad))

    def test_wrong_input_volume_provenance_refused(self):
        bad=bytearray(self.local)
        pe=m.map_pe(bad)
        at=m.at_va(pe,m.VOLUME_VA,len(m.VOLUME_R),b".text")
        bad[at]=0x90
        with self.assertRaisesRegex(ValueError,"signature"):
            m.patch_bytes(bytes(bad))

    def test_DAT_already_patched_refused(self):
        out,_=m.patch_bytes(self.local)
        with self.assertRaises(ValueError):
            m.patch_bytes(out)

    def test_site_overlap_refused(self):
        with patch.object(m,"DAT_SITE_CHANGES",m.DAT_SITE_CHANGES+
                          ((0x44F13B,b"\x14",b"\x90","unexpected overlap"),)):
            with self.assertRaises(ValueError):
                m.patch_bytes(self.local)

    def test_write_fresh_exe_and_refuse_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/"Rayman2-local-R-test.exe"
            dest=Path(folder)/"Rayman2-local-R-DAT-V4-test.exe"
            source.write_bytes(self.local)
            self.assertEqual(m.main([str(source),str(dest)]),0)
            expected,_=m.patch_bytes(self.local)
            self.assertEqual(dest.read_bytes(),expected)
            self.assertEqual(source.read_bytes(),self.local)
            with self.assertRaises(SystemExit):
                m.main([str(source),str(dest)])
            self.assertEqual(dest.read_bytes(),expected)

    def test_dry_run_does_not_write_exe(self):
        with tempfile.TemporaryDirectory() as folder:
            source=Path(folder)/"source.exe"
            dest=Path(folder)/"not_created.exe"
            source.write_bytes(self.local)
            self.assertEqual(m.main([str(source),str(dest),"--dry-run"]),0)
            self.assertFalse(dest.exists())

    def test_symlink_source_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            a=Path(folder)/"a.exe"
            b=Path(folder)/"b.exe"
            c=Path(folder)/"c.exe"
            a.write_bytes(self.local)
            try:
                b.symlink_to(a)
            except OSError:
                self.skipTest("no symlink privilege")
            with self.assertRaises(SystemExit):
                m.main([str(b),str(c)])
            self.assertFalse(c.exists())


if __name__=="__main__":
    unittest.main()
