"""Rayman2 GOG patch-dependency audit: synthetic and optional owner-PE tests."""
import hashlib
import os
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
import rayman2_patch_dependency_audit as m


class PatchDependencyTest(unittest.TestCase):
    def test_total_changed_bytes(self):
        self.assertEqual(sum(m.SMALL.values()),307)
        self.assertEqual(sum(m.MAJOR.values()),12962)
        self.assertEqual(sum(m.SMALL.values())+sum(m.MAJOR.values()),13269)

    def test_diff_groups(self):
        a=bytearray(b'\0'*1024);b=bytearray(a)
        b[2]=1;b[10]=1;b[1000]=1
        self.assertEqual(m.grouped_diff(bytes(a),bytes(b),gap=10),
                         [(0x401002,0x40100b,2),(0x4013e8,0x4013e9,1)])

    def test_diff_rejects_unaligned(self):
        with self.assertRaises(ValueError):m.diff_runs(b'a',b'')
        with self.assertRaises(ValueError):m.grouped_diff(b'',b'',gap=-1)

    def test_relative_calls(self):
        for site,target in ((0x4500af,0x449080),(0x4500af,0x44f8d0),
                            (0x449080,0x44f8d0)):
            op=b'\xe8'+struct.pack('<i',target-site-5)
            self.assertEqual(m.rel32_target(op,site),target)

    def test_relative_rejects_bad_opcode(self):
        for raw in (b'',b'\x90'*5,b'\xe8\0\0',b'\xe9\0\0\0\0'):
            with self.assertRaises(ValueError):m.rel32_target(raw,0x400000)

    def test_original_image_unmapped_extra(self):
        pe={'image_base':0x400000,'image_size':0x117000,
            'sections':{'.text':{'va':0x401000,'virtual_size':0x9a1d0,
                                  'raw_size':0x9a200,'file_offset':0}}}
        self.assertTrue(m.is_mapped(pe,0x401000))
        self.assertFalse(m.is_mapped(pe,0x517000))
        self.assertFalse(m.is_mapped(pe,0x5b3000))
        self.assertFalse(m.is_mapped(pe,0x400000))

    def test_section_file_bounds(self):
        pe={'sections':{'.text':{'va':0x401000,'virtual_size':4,
                                 'raw_size':4,'file_offset':0}}}
        self.assertEqual(m.get_bytes(b'abcd',pe,0x401000,4),b'abcd')
        with self.assertRaises(ValueError):m.get_bytes(b'abcd',pe,0x401002,4)
        with self.assertRaises(ValueError):m.get_bytes(b'abcd',pe,0x401000,0)

    def test_reject_bad_pe_and_bad_hash(self):
        with self.assertRaises(ValueError):m.pe_sections(b'')
        with self.assertRaisesRegex(ValueError,'SHA256'):m.audit(b'',b'')
        with self.assertRaisesRegex(ValueError,'SHA256'):m.sha_gate(b'',m.CD_HASH)

    def test_seven_minor_groups(self):
        self.assertEqual(len(m.SMALL),7)
        self.assertEqual(m.SMALL[(0x4500b0,0x4500b2)],2)

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'owner executables never bundled in GitHub Actions')
    def test_private_exact_sources(self):
        cd=Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes()
        gog=Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes()
        report=m.audit(cd,gog)
        self.assertEqual(report['total_changed_bytes'],13269)
        self.assertEqual(report['seven_minor_changed_bytes'],307)
        self.assertEqual(report['gog_helper_compared_result_constant'],'0x00632EA0')
        self.assertTrue(report['nonportable_retargeted_helper'])
        self.assertTrue(report['nonportable_selfread_base'])
        self.assertFalse(report['reconstructed_executable_created'])

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'owner executables never bundled in GitHub Actions')
    def test_mutation_rejected_even_when_hash_gate_is_adjusted(self):
        cd=Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes()
        gog=bytearray(Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        gp=m.pe_sections(gog)
        for va in (0x401d8e,0x449080,0x470051):
            with self.subTest(va=hex(va)):
                changed=bytearray(gog)
                offset=gp['sections']['.text']['file_offset']+va-0x401000
                changed[offset]^=1
                with patch.object(m,'GOG_HASH',hashlib.sha256(changed).hexdigest()):
                    with self.assertRaises(ValueError):m.audit(cd,bytes(changed))


if __name__=='__main__':unittest.main()
