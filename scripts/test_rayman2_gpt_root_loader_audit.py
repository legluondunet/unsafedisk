"""Read-only Rayman2 GPT loader audit, synthetic and optional private tests."""
import os
import struct
import unittest
from pathlib import Path
import rayman2_gpt_root_loader_audit as m

class GPTLoaderAuditTests(unittest.TestCase):
    def test_rel32_forward_and_back(self):
        for site,target in m.CALLS.items():
            code=b'\xe8'+struct.pack('<i',target-site-5)
            self.assertEqual(m.rel32_target(site,code),target)

    def test_bad_call(self):
        for code in (b'',b'\xe8',b'\x90'*5,b'\xe9'+b'\0'*4):
            with self.assertRaises(ValueError):m.rel32_target(0x400000,code)

    def test_raw_unmatched_fixup(self):
        self.assertEqual(m.resolve_word(123,None,{},{}),(123,False))
        self.assertEqual(m.resolve_word(123,(124,1,2),{},{}),(123,False))

    def test_matched_but_disabled_fixup_advances(self):
        self.assertEqual(m.resolve_word(123,(123,1,2),{12:False},{}),(123,True))

    def test_matched_relocation(self):
        self.assertEqual(m.resolve_word(123,(123,1,2),{12:True},{12:0x100000}),
                         (0x10007b,True))

    def test_fixup_u32_overflow(self):
        self.assertEqual(m.resolve_word(0xfffffffe,(0xfffffffe,0,1),{1:True},{1:20}),
                         (18,True))

    def test_unavailable_relocation_base_rejected(self):
        with self.assertRaises(ValueError):m.resolve_word(200,(200,0,3),{3:True},{})

    def test_invalid_fixup_fields_rejected(self):
        for entry in ((1,-1,1),(1,0,256),(1,255,255),(1,2),(1,1,'a')):
            with self.assertRaises(ValueError):m.resolve_word(1,entry,{}, {})

    def test_invalid_u32_rejected(self):
        for value in (-1,2**32,'n'):
            with self.assertRaises(ValueError):m.resolve_word(value,None,{}, {})

    def test_known_provenance_anchors(self):
        self.assertEqual(m.ANCHORS[0x44CFB7],'ff 15 4c c0 49 00')
        self.assertEqual(m.ANCHORS[0x44D01D],'03 04 8d e0 21 51 00')
        self.assertEqual(m.PATH_FORMAT,b'%s\\%s\\%s.gpt\0')
        self.assertEqual(len(m.REGIONS),5)
        self.assertEqual(len(m.CALLS),9)

    def test_manifest_bad_record_rejected(self):
        fake=bytes(32)
        sections={'.extra2':{'file_offset':0,'raw_size':len(fake)}}
        with self.assertRaises(ValueError):m.catalog(fake,sections)

    def test_wrong_sha_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA256'):m.inspect(b'',b'')

    @unittest.skipUnless(os.environ.get('RAYMAN2_RETAIL_EXE') and os.environ.get('RAYMAN2_GOG_EXE'),
                         'private owner files are not bundled in GitHub CI')
    def test_real_provenance(self):
        report=m.inspect(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
                         Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(report['identical_original_and_GOG_loader_regions'],5)
        self.assertEqual(report['identical_original_and_GOG_rel32_calls'],9)
        self.assertEqual(report['gpt_declared_file_count'],71)
        self.assertEqual(report['gpt_declared_total_bytes'],59428300)
        self.assertEqual(report['dsb_missing_gpt_stems'],['DATA\\WORLD\\LEVELS\\FIX'])
        self.assertEqual(report['dsb_without_gpt_stems'],['DATA\\GAME'])
        self.assertFalse(report['actual_gpt_bytes_available'])

if __name__=='__main__':unittest.main()
