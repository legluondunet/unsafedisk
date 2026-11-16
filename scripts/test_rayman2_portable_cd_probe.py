"""Synthetic tests and optional exact-owner integration for the CD path probe."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('rayman2_portable_cd_probe.py')
spec=importlib.util.spec_from_file_location('ray2_portable',SCRIPT)
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def make_fixture():
    """Fake PE with the known section geometry; no commercial bytes."""
    b=bytearray(m.SIZE)
    b[:2]=b'MZ'; struct.pack_into('<I',b,0x3c,0xE0)
    nt=0xE0; b[nt:nt+4]=b'PE\0\0'
    struct.pack_into('<HH',b,nt+4,0x14C,3)
    struct.pack_into('<H',b,nt+20,0xE0)
    opt=nt+24
    struct.pack_into('<H',b,opt,0x10B)
    struct.pack_into('<I',b,opt+28,0x400000)
    section_table=opt+0xE0
    sections=[('.text',0x1000,0x9A200,0x400,0x9A170,0x60000020),
              ('.rdata',0x9C000,0x3000,0x9A600,0x2E49,0x40000040),
              ('.data',0x9F000,0x7C00,0x9D600,0x776D0,0xC0000040)]
    for i,(name,rva,raw,ptr,vsize,flags) in enumerate(sections):
        st=section_table+i*40
        b[st:st+len(name)]=name.encode()
        struct.pack_into('<IIII',b,st+8,vsize,rva,raw,ptr)
        struct.pack_into('<I',b,st+36,flags)
    # Plant only the few verified opcodes/format strings.
    for va,raw in ((m.SCANNER_VA,m.SCANNER_OLD),
                   (m.VOLUME_BODY_VA,m.VOLUME_OLD),
                   (0x448E30,bytes.fromhex('55 8B EC 81 EC EC 00 00 00 A1 EC 13 51 00 85 C0 74')),
                   (0x448E56,bytes.fromhex('8B E5 5D C3'))):
        pos=m.mapped_offset(bytes(b),va,len(raw),'.text');b[pos:pos+len(raw)]=raw
    for va,fmt in m.FORMATS.items():
        off=m.mapped_offset(bytes(b),va,len(fmt)+1,'.data')
        b[off:off+len(fmt)+1]=fmt+b'\0'
    return bytes(b)


class PureSynthetic(unittest.TestCase):
    def test_pe_parsing(self):
        base,sections=m.parse_sections(make_fixture())
        self.assertEqual(base,0x400000)
        self.assertEqual(set(sections),{'.text','.rdata','.data'})
        self.assertEqual(sections['.text']['raw_offset'],0x400)

    def test_mapped_code(self):
        b=make_fixture()
        ix=m.mapped_offset(b,m.SCANNER_VA,25,'.text')
        self.assertEqual(b[ix:ix+25],m.SCANNER_OLD)

    def test_mapped_data(self):
        b=make_fixture()
        for va,fmt in m.FORMATS.items():
            ix=m.mapped_offset(b,va,len(fmt)+1,'.data')
            self.assertEqual(b[ix:ix+len(fmt)+1],fmt+b'\0')

    def test_patterns_accepted(self):
        m.ensure_original_patterns(make_fixture(),False)

    def test_scanner_fixed_pattern_recognized(self):
        b=bytearray(make_fixture());off=m.mapped_offset(b,m.SCANNER_VA,25,'.text')
        b[off:off+25]=m.SCANNER_FIXED
        m.ensure_original_patterns(bytes(b),True)

    def test_swapped_scanner_variant_rejected(self):
        with self.assertRaisesRegex(ValueError,'PE32 module-scan pattern'):
            m.ensure_original_patterns(make_fixture(),True)

    def test_unknown_source_rejected_before_mutation(self):
        with self.assertRaisesRegex(ValueError,'source SHA-256'):
            m.patch(make_fixture())

    def test_unexpected_sixth_format_rejected(self):
        b=bytearray(make_fixture());off=m.mapped_offset(b,0x4A2A00,4,'.data')
        b[off:off+4]=b'%c:\\'
        with self.assertRaisesRegex(ValueError,'pattern census'):
            m.ensure_original_patterns(bytes(b),False)

    def test_mutated_format_rejected(self):
        b=bytearray(make_fixture());off=m.mapped_offset(b,0x4A06D8,4,'.data')
        b[off+3]=ord('/')
        with self.assertRaisesRegex(ValueError,'pattern census'):
            m.ensure_original_patterns(bytes(b),False)

    def test_nul_terminator_required(self):
        b=bytearray(make_fixture());fmt=m.FORMATS[0x49F394]
        off=m.mapped_offset(b,0x49F394,len(fmt)+1,'.data')
        b[off+len(fmt)]=ord('X')
        with self.assertRaisesRegex(ValueError,'format string'):
            m.ensure_original_patterns(bytes(b),False)

    def test_guard_prologue_required(self):
        b=bytearray(make_fixture());off=m.mapped_offset(b,0x448E30,17,'.text')
        b[off]^=1
        with self.assertRaisesRegex(ValueError,'prologue'):
            m.ensure_original_patterns(bytes(b),False)

    def test_old_cd_volume_required(self):
        b=bytearray(make_fixture());off=m.mapped_offset(b,m.VOLUME_BODY_VA,11,'.text')
        b[off]^=0xff
        with self.assertRaisesRegex(ValueError,'volume-init'):
            m.ensure_original_patterns(bytes(b),False)

    def test_invalid_pe(self):
        b=bytearray(make_fixture());b[:2]=b'XX'
        with self.assertRaisesRegex(ValueError,'DOS signature'):
            m.parse_sections(bytes(b))

    def test_wrong_machine(self):
        b=bytearray(make_fixture());struct.pack_into('<H',b,0xE4,0x8664)
        with self.assertRaisesRegex(ValueError,'architecture'):
            m.parse_sections(bytes(b))

    def test_data_out_of_range(self):
        with self.assertRaisesRegex(ValueError,'not file-backed'):
            m.mapped_offset(make_fixture(),0x512020,4,'.data')

    def test_text_out_of_range(self):
        with self.assertRaisesRegex(ValueError,'not file-backed'):
            m.mapped_offset(make_fixture(),0x49b210,4,'.text')

    def test_zero_length_rejected(self):
        with self.assertRaisesRegex(ValueError,'invalid mapped length'):
            m.mapped_offset(make_fixture(),0x447c20,0,'.text')

    def test_malformed_section_rejected(self):
        b=bytearray(make_fixture()); off=0xE0+24+0xE0
        struct.pack_into('<I',b,off+20,len(b))
        with self.assertRaisesRegex(ValueError,'out-of-range'):
            m.parse_sections(bytes(b))

    def test_modified_byte_count(self):
        self.assertEqual(m.changed_bytes(b'abc',b'bbc'),1)
        with self.assertRaisesRegex(ValueError,'changed PE size'):
            m.changed_bytes(b'ab',b'abc')

    def test_format_simulation(self):
        # A leading '.' is portable relative path syntax in common Win32 paths.
        # It is NOT an assertion about actual Wine file-open success.
        for fmt in m.FORMATS.values():
            self.assertTrue(fmt.startswith(b'%c:\\'))
            self.assertEqual(fmt.replace(b':',b'\\',1)[:4],b'%c\\\\')
        self.assertEqual(len(m.FORMATS),5)

    def test_volume_epilogue_stack_convention(self):
        self.assertEqual(len(m.VOLUME_RELATIVE),11)
        self.assertEqual(m.VOLUME_RELATIVE[:7],bytes.fromhex('B0 2E A2 D8 6A 4A 00'))
        self.assertEqual(m.VOLUME_RELATIVE[-4:],bytes.fromhex('8B E5 5D C3'))

    def test_modified_region_detector_rejects_outside(self):
        old=make_fixture();new=bytearray(old);new[-1]=1
        with self.assertRaisesRegex(ValueError,'outside'):
            m.output_audit(old,bytes(new),'PE32-scanner-only')


RETAIL=Path(os.environ.get('RAYMAN2_RETAIL_EXE','/mnt/data/rayman2_research/Rayman2(3).exe'))
GOG=Path(os.environ.get('RAYMAN2_GOG_EXE','/mnt/data/rayman2_research/rayman2(4).exe'))


@unittest.skipUnless(RETAIL.is_file(),'private retail sample absent')
class PrivateRetailIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=RETAIL.read_bytes()
        if m.sha256(cls.original)!=m.ORIGINAL_SHA:
            raise unittest.SkipTest('source not matching pinned owner SHA')
        cls.patched,cls.report=m.patch(cls.original)

    def test_exact_original_sha_and_output_sha(self):
        self.assertEqual(m.sha256(self.original),m.ORIGINAL_SHA)
        self.assertEqual(m.sha256(self.patched),m.PROBE_SHA)

    def test_exact_delta_count(self):
        self.assertEqual(m.changed_bytes(self.original,self.patched),38)
        self.assertEqual(self.report['format_count'],5)

    def test_full_pe32_secondary_roundtrip(self):
        b=bytearray(self.original)
        off=m.mapped_offset(b,m.SCANNER_VA,25,'.text')
        b[off:off+25]=m.SCANNER_FIXED
        self.assertEqual(m.sha256(bytes(b)),m.PE32_ONLY_SHA)
        patched_again,report=m.patch(bytes(b))
        self.assertEqual(patched_again,self.patched)
        self.assertEqual(report['source_kind'],'PE32-scanner-only')
        self.assertEqual(report['modified_byte_count'],16)

    def test_other_retail_data_unchanged(self):
        for va,length in [(0x44F10D,0x1F5),(0x467350,0x24E),(0x44EB40,0x100)]:
            off=m.mapped_offset(self.original,va,length,'.text')
            self.assertEqual(self.original[off:off+length],self.patched[off:off+length])

    def test_cli_dry_run_creates_no_output(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'not-produced.exe'
            r=subprocess.run([sys.executable,str(SCRIPT),str(RETAIL),str(out),'--dry-run'],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertFalse(out.exists())
            self.assertEqual(json.loads(r.stdout.split('\nExperimental')[0])['output_sha256'],m.PROBE_SHA)

    def test_cli_creates_new_exe_only(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'only-private.exe'
            r=subprocess.run([sys.executable,str(SCRIPT),str(RETAIL),str(out)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(out.read_bytes(),self.patched)
            r2=subprocess.run([sys.executable,str(SCRIPT),str(RETAIL),str(out)],capture_output=True,text=True)
            self.assertNotEqual(r2.returncode,0)
            self.assertIn('refusing to overwrite',r2.stderr)

    def test_original_file_not_mutated(self):
        self.assertEqual(RETAIL.read_bytes(),self.original)


def gog_offset(data: bytes, va: int, n: int, section: str) -> int:
    """Read-only test helper: GOG has DIFFERENT PE geometry from CD."""
    nt=struct.unpack_from('<I',data,0x3c)[0]
    base=struct.unpack_from('<I',data,nt+24+28)[0]
    count=struct.unpack_from('<H',data,nt+6)[0]
    s0=nt+24+struct.unpack_from('<H',data,nt+20)[0]
    for i in range(count):
        off=s0+i*40
        name=data[off:off+8].split(b'\0',1)[0].decode('ascii')
        vsz,rva,raw,ptr=struct.unpack_from('<IIII',data,off+8)
        if name==section and rva<=va-base and va-base+n<=rva+min(raw,vsz):
            return ptr+(va-base-rva)
    raise ValueError('not mapped in expected GOG file-backed section')


@unittest.skipUnless(RETAIL.is_file() and GOG.is_file(),'private owner pair absent')
class PrivateGogCrosscheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original=RETAIL.read_bytes();cls.gog=GOG.read_bytes()
        if m.sha256(cls.original)!=m.ORIGINAL_SHA or m.sha256(cls.gog)!='9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713':
            raise unittest.SkipTest('not the exact known pair')
        cls.patched,_=m.patch(cls.original)

    def test_no_cd_branch_matches_independently_modified_gog(self):
        o=m.mapped_offset(self.patched,m.VOLUME_BODY_VA,11,'.text')
        g=gog_offset(self.gog,m.VOLUME_BODY_VA,11,'.text')
        self.assertEqual(self.patched[o:o+11],self.gog[g:g+11])

    def test_all_five_relative_formats_match_gog(self):
        for va,fmt in m.FORMATS.items():
            o=m.mapped_offset(self.patched,va,len(fmt)+1,'.data')
            g=gog_offset(self.gog,va,len(fmt)+1,'.data')
            self.assertEqual(self.patched[o:o+len(fmt)+1],self.gog[g:g+len(fmt)+1])

    def test_unmodified_indexed_dat_selection(self):
        va=0x44F13A
        o=m.mapped_offset(self.patched,va,7,'.text')
        self.assertEqual(self.patched[o:o+7],bytes.fromhex('8B 14 9D 90 20 4A 00'))
        g=gog_offset(self.gog,va,7,'.text')
        self.assertNotEqual(self.patched[o:o+7],self.gog[g:g+7])


if __name__=='__main__':
    unittest.main()
