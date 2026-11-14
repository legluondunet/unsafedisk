"""Read-only synthetic/mutated-byte tests of Rayman 2 generic type callbacks."""
import unittest
import struct
import sys
from pathlib import Path

HERE=Path(__file__).parent
sys.path.insert(0,str(HERE))
from rayman2_selfread_archive_audit import locked_read,sections
from rayman2_selfread_typed_callback_audit import (
    BASE,ROW_BASE,ROW_FIRST,ROW_BYTES,TRIPLE,EXPECTED_CALLS,GENERIC_HELPERS,
    relcall,parse_direct_xrefs,callbacks_at,inspect_one,inspect,disassemble_text,
)


class CallbackAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cd_path=HERE/'Rayman2(3).exe'
        cls.gog_path=HERE/'Rayman2.exe'
        cls.cd=locked_read(cls.cd_path,'cd')
        cls.gog=locked_read(cls.gog_path,'gog')
        cls.cd_asm=disassemble_text(cls.cd_path)
        cls.gog_asm=disassemble_text(cls.gog_path)
        _,cls.cs=sections(cls.cd)

    @staticmethod
    def changed(raw:bytes,sects,va:int,change:bytes)->bytes:
        x=bytearray(raw)
        s=next(z for z in sects.values() if z.rva <= va-BASE < z.rva+z.raw_size)
        off=s.raw_offset+va-BASE-s.rva
        x[off:off+len(change)]=change
        return bytes(x)

    def test_parser_synthetic_call_sites(self):
        text='  004701ed: e8 0e 16 01 00     call   0x481800\n'
        self.assertEqual(parse_direct_xrefs(text),[0x4701ED])

    def test_parser_ignores_unrelated_target(self):
        self.assertEqual(parse_direct_xrefs('  4701ed: e8 0e 16 01 00 call 0x481801\n'),[])

    def test_parser_ignores_noncall_mnemonic(self):
        self.assertEqual(parse_direct_xrefs('  4701ed: e8 0e 16 01 00 jmp 0x481800\n'),[])

    def test_parser_normalizes_nonmonotonic_addresses(self):
        lines='  4701ed: e8 0e 16 01 00 call 0x481800\n  46790d: e8 ee 9e 01 00 call 0x481800\n'
        self.assertEqual(parse_direct_xrefs(lines),[0x46790D,0x4701ED])

    def test_relcall_positive(self):
        self.assertEqual(relcall(0x4701ED,bytes.fromhex('e8 0e 16 01 00')),0x481800)

    def test_relcall_negative(self):
        self.assertEqual(relcall(0x1000,bytes.fromhex('e8 fb ff ff ff')),0x1000)

    def test_relcall_invalid(self):
        for raw in (b'\xff\xd0', b'',b'\xe8\x00',b'\x90\x00\x00\x00\x00'):
            with self.assertRaises(ValueError):relcall(0x1000,raw)

    def test_family_rows_all_six_identical(self):
        self.assertEqual(callbacks_at(self.cd,self.cs), (TRIPLE,)*6)

    def test_type_0x15_is_not_unique(self):
        self.assertIn(0x15,range(ROW_FIRST,ROW_FIRST+6))
        self.assertEqual(callbacks_at(self.cd,self.cs,0x14,0x16),(TRIPLE,)*3)

    def test_family_negative_neighbor(self):
        self.assertNotEqual(callbacks_at(self.cd,self.cs,0x11,0x11)[0],TRIPLE)
        self.assertNotEqual(callbacks_at(self.cd,self.cs,0x18,0x18)[0],TRIPLE)

    def test_row_bounds(self):
        for first,last in ((0,-1),(256,256),(12,11)):
            with self.assertRaises(ValueError):callbacks_at(self.cd,self.cs,first,last)

    def test_exact_two_sample_audit(self):
        x=inspect(self.cd,self.gog,self.cd_asm,self.gog_asm)
        self.assertEqual(len(x['verified_samples']),2)
        self.assertEqual(x['verified_samples'][0]['ordinary_callers_outside_0x170'],15)
        self.assertFalse(x['integrity_verdict_or_gameplay_execution_proven'])

    def test_expected_16_live_direct_calls(self):
        self.assertEqual(parse_direct_xrefs(self.cd_asm), list(EXPECTED_CALLS))
        self.assertEqual(parse_direct_xrefs(self.gog_asm), list(EXPECTED_CALLS))

    def test_generic_helper_call_counts(self):
        self.assertEqual(GENERIC_HELPERS,{0x480B90:757,0x4815F0:7,0x4817B0:2,0x481800:16})
        for target,count in GENERIC_HELPERS.items():
            self.assertEqual(len(parse_direct_xrefs(self.cd_asm,target)),count)
            self.assertEqual(parse_direct_xrefs(self.cd_asm,target),parse_direct_xrefs(self.gog_asm,target))

    def test_already_generic_field_converter_is_used_elsewhere(self):
        calls=parse_direct_xrefs(self.cd_asm,0x4815F0)
        self.assertEqual(len(calls),7)
        self.assertIn(0x47017F,calls)
        self.assertIn(0x481CCC,calls)

    def test_generic_parser_has_many_direct_calls(self):
        self.assertEqual(len(parse_direct_xrefs(self.cd_asm,0x480B90)),757)
        self.assertEqual(parse_direct_xrefs(self.cd_asm,0x480B90),
                         parse_direct_xrefs(self.gog_asm,0x480B90))

    def test_wrong_anchor_detected(self):
        broken=self.changed(self.cd,self.cs,0x4701E5,b'\x90')
        with self.assertRaisesRegex(ValueError,'anchor mismatch'):
            inspect_one(broken,self.cd_asm,'mutated')

    def test_wrong_0x15_callback_detected(self):
        slot=ROW_BASE+0x15*ROW_BYTES+8
        broken=self.changed(self.cd,self.cs,slot,struct.pack('<I',0x481730))
        with self.assertRaisesRegex(ValueError,'callback family changed'):
            inspect_one(broken,self.cd_asm,'mutated')

    def test_wrong_0x12_callback_detected(self):
        slot=ROW_BASE+0x12*ROW_BYTES+4
        broken=self.changed(self.cd,self.cs,slot,struct.pack('<I',0x481430))
        with self.assertRaisesRegex(ValueError,'callback family changed'):
            inspect_one(broken,self.cd_asm,'mutated')

    def test_wrong_direct_site_detected(self):
        broken=self.changed(self.cd,self.cs,EXPECTED_CALLS[0],b'\x90')
        with self.assertRaisesRegex(ValueError,'not E8 rel32'):
            inspect_one(broken,self.cd_asm,'mutated')

    def test_missing_disassembly_caller_detected(self):
        truncated='\n'.join(line for line in self.cd_asm.splitlines()
                            if not line.lstrip().startswith('4701ed:'))
        with self.assertRaisesRegex(ValueError,'expected 16 boundaries'):
            inspect_one(self.cd,truncated,'mutated')

    def test_wrong_0x481800_callback_resolver_detected(self):
        broken=self.changed(self.cd,self.cs,0x481822,b'\x90')
        with self.assertRaisesRegex(ValueError,'anchor mismatch'):
            inspect_one(broken,self.cd_asm,'mutated')

    def test_typed_tag_mutation_detected(self):
        broken=self.changed(self.cd,self.cs,0x4701E9,b'\x16')
        with self.assertRaisesRegex(ValueError,'anchor mismatch'):
            inspect_one(broken,self.cd_asm,'mutated')


if __name__=='__main__':unittest.main()
