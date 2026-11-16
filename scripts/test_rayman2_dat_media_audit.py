"""Synthetic rejection tests, plus pinned-binary local integration.

Tests do not execute or write to the two original game executables.
"""
import struct
import unittest
from pathlib import Path
from rayman2_dat_media_audit import (
    FAMILIES, TABLE_VA, parse_table, require, edge, rel_target, audit,
)
from rayman2_direct_call_audit import read_file, HASHES
from rayman2_trampoline_audit import disassemble, pe_regions, imports

ROOT = Path(__file__).resolve().parent


def fake_region():
    b = bytearray(0x300)
    pos = 0xF0
    pointers=[]
    for n in range(3):
        for family in FAMILIES:
            pointers.append(0x4A2000 + pos)
            string = f'{family}{n}.DAT'.encode('ascii') + b'\0'
            b[pos:pos+len(string)] = string
            pos += len(string)
    struct.pack_into('<24I',b, TABLE_VA-0x4A2000,*pointers)
    return {'.data':(0x4A2000,bytes(b))}


class UnitTests(unittest.TestCase):
    def test_rel32(self):
        self.assertEqual(rel_target(0x44D9F4,b'\xe8\xa7\x0e\x00\x00'),0x44E8A0)

    def test_jcc_near(self):
        self.assertEqual(rel_target(0x44DE97, b'\x0f\x84\xab\x08\x00\x00'), 0x44E748)

    def test_short_relative(self):
        self.assertEqual(rel_target(0x44F1CC,b'\xeb\x23'),0x44F1F1)

    def test_reject_non_branch(self):
        with self.assertRaises(ValueError):rel_target(0x5000,b'\xc3')

    def test_edge_rejects_wrong_target(self):
        with self.assertRaises(ValueError):edge({0x1000:(b'\xeb\x10','jmp','')},0x1000,b'\xeb\x10',0x2000)

    def test_reject_wrong_instruction(self):
        with self.assertRaises(ValueError):require({0x1000:(b'\x90','nop','')},0x1000,b'\x55')

    def test_table_24_names(self):
        obj = parse_table(fake_region())
        self.assertEqual(len(obj['names']),24)
        self.assertEqual(obj['names'][0], 'LEVELS0.DAT')
        self.assertEqual(obj['names'][-1], 'MENU2.DAT')

    def test_table_bad_name(self):
        regions=fake_region()
        b=bytearray(regions['.data'][1]);b[0xF0]=ord('Q')
        with self.assertRaises(ValueError):parse_table({'.data':(0x4A2000,bytes(b))})

    def test_table_bad_pointer(self):
        regions=fake_region()
        b=bytearray(regions['.data'][1]);struct.pack_into('<I',b,0x90,0xFFFFFFFF)
        with self.assertRaises(ValueError):parse_table({'.data':(0x4A2000,bytes(b))})

    def test_table_duplicate(self):
        regions=fake_region()
        b=bytearray(regions['.data'][1]);struct.pack_into('<I',b,0x94,0x4A20F0)
        with self.assertRaises(ValueError):parse_table({'.data':(0x4A2000,bytes(b))})

    def test_table_truncated(self):
        regions=fake_region()
        b=regions['.data'][1][:0x98]
        with self.assertRaises(ValueError):parse_table({'.data':(0x4A2000,b)})


class OriginalFileIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cd_path=ROOT/'Rayman2(3).exe'
        cls.gog_path=ROOT/'Rayman2.exe'
        if not(cls.cd_path.is_file() and cls.gog_path.is_file()):
            raise unittest.SkipTest('Original owner binaries not present; synthetic tests still run')
        cls.cd=read_file(cls.cd_path,HASHES[0]);cls.gog=read_file(cls.gog_path,HASHES[1])
        cls.a=disassemble(cls.cd_path);cls.b=disassemble(cls.gog_path)
        cls.i=imports(cls.cd_path);cls.j=imports(cls.gog_path)

    def run_audit(self,a=None,b=None,cd=None,gog=None,i=None,j=None):
        return audit(cd or self.cd, gog or self.gog,a or self.a,b or self.b,i or self.i,j or self.j)

    def test_integration_positive(self):
        result=self.run_audit()
        self.assertEqual(result['table_size'],24)
        self.assertEqual(result['cd_extra_read_sizes_bytes'],[512,512])
        self.assertEqual(result['common_initial_read_sizes_bytes'],[16,4])
        self.assertFalse(result['anti_tamper_predicate_proven'])

    def test_reject_changed_read_length(self):
        modified=dict(self.a);modified[0x44F11E]=(b'\x68\x00\x01\x00\x00','push','0x100')
        with self.assertRaises(ValueError):self.run_audit(a=modified)

    def test_reject_changed_selector_opcode(self):
        modified=dict(self.a);modified[0x44F13A]=(b'\x90','nop','')
        with self.assertRaises(ValueError):self.run_audit(a=modified)

    def test_reject_missing_gog_nop(self):
        modified=dict(self.b);modified[0x44F125]=(b'\xCC','int3','')
        with self.assertRaises(ValueError):self.run_audit(b=modified)

    def test_reject_changed_other_level0_generator_branch(self):
        modified=dict(self.b);modified[0x44DEC5]=(b'\x90','nop','')
        with self.assertRaises(ValueError):self.run_audit(b=modified)

    def test_reject_changed_other_level0_iat(self):
        modified=dict(self.b);modified[0x44DF52]=(b'\xFF\x15\x50\xC0\x49\x00','call','DWORD PTR ds:0x49c050')
        with self.assertRaises(ValueError):self.run_audit(b=modified)

    def test_reject_changed_gog_jump(self):
        modified=dict(self.b);modified[0x44F1CC]=(b'\xEB\x22','jmp','0x44f1f0')
        with self.assertRaises(ValueError):self.run_audit(b=modified)

    def test_reject_wrong_import(self):
        modified=dict(self.j);modified[0x49C04C]='WriteFile'
        with self.assertRaises(ValueError):self.run_audit(j=modified)

    def test_reject_changed_message(self):
        r=pe_regions(self.cd);base,old=r['.data'];b=bytearray(old)
        idx=0x4A06C0-base;b[idx]=ord('Q')
        # Build a minimal PE mutation at its file-offset, preserving PE geometry;
        # this is only in local test memory (not written back to original file).
        pe=bytearray(self.cd)
        peoff=struct.unpack_from('<I',pe,0x3c)[0]
        table=peoff+24+struct.unpack_from('<H',pe,peoff+20)[0]
        for n in range(struct.unpack_from('<H',pe,peoff+6)[0]):
            at=table+n*40
            if pe[at:at+8].rstrip(b'\0')==b'.data':
                raw=struct.unpack_from('<I',pe,at+20)[0]
                pe[raw+idx]=ord('Q')
                break
        with self.assertRaises(ValueError):self.run_audit(cd=bytes(pe))

    def test_reject_mutated_initial_guard(self):
        modified=dict(self.a);modified[0x44EB49]=(b'\x90','nop','')
        with self.assertRaises(ValueError):self.run_audit(a=modified)


if __name__ == '__main__':
    unittest.main()
