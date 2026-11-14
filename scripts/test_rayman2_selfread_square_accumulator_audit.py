"""Focused, read-only x86 helper tests and exact owner-file integration checks."""
import random
import struct
import unittest
from pathlib import Path
from rayman2_selfread_archive_audit import sections
from rayman2_selfread_square_accumulator_audit import (
    squared_sum, rel32_target, raw_dword_offsets, inspect, IMAGE_BASE, ANCHORS,
)
ROOT=Path(__file__).resolve().parent


def patch_va(executable:bytes,va:int,payload:bytes)->bytes:
    base,s=sections(executable)
    for sect in s.values():
        if sect.rva <= va-base and va-base+len(payload) <= sect.rva+sect.raw_size:
            offset=sect.raw_offset+va-base-sect.rva
            return executable[:offset]+payload+executable[offset+len(payload):]
    raise ValueError('VA outside raw sections')


class MathChecks(unittest.TestCase):
    def test_zero(self): self.assertEqual(squared_sum(0,0,0),(0,0))
    def test_one(self): self.assertEqual(squared_sum(10,100,1),(11,100))
    def test_32bit_carry(self): self.assertEqual(squared_sum(0xffffffff,0,1),(0,1))
    def test_64bit_wrap(self): self.assertEqual(squared_sum(0xffffffff,0xffffffff,1),(0,0))
    def test_64bit_high_product(self):
        x=(0x80000000**2)
        self.assertEqual(squared_sum(0,0,0x80000000),(x&0xffffffff,x>>32))
    def test_64bit_max_square(self):
        x=(0xffffffff**2)
        self.assertEqual(squared_sum(0,0,0xffffffff),(x&0xffffffff,x>>32))
    def test_invalid_dword(self):
        for triple in [(0,0,-1),(0,0,0x100000000),(0,-1,0),('a',0,0)]:
            with self.subTest(triple=triple), self.assertRaises(ValueError):
                squared_sum(*triple)
    def test_10000_independent_modulo_cases(self):
        r=random.Random(0x4701bc)
        for _ in range(10000):
            lo,hi,x=[r.getrandbits(32) for _ in range(3)]
            actual=squared_sum(lo,hi,x)
            expected=(((hi<<32)|lo)+x*x)&0xffffffffffffffff
            self.assertEqual(actual,(expected&0xffffffff,expected>>32))


class PeAnchors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cd=(ROOT/'Rayman2(3).exe').read_bytes()
        cls.gog=(ROOT/'Rayman2.exe').read_bytes()

    def test_rel32(self):
        self.assertEqual(rel32_target(0x4701c3,bytes.fromhex('e8 08 78 02 00')),0x4979d0)
        self.assertEqual(rel32_target(0x4701ed,bytes.fromhex('e8 0e 16 01 00')),0x481800)
    def test_rel32_rejects_bad_opcode(self):
        for b in [b'\x90'*5,b'\xe8\x00',b'']:
            with self.assertRaises(ValueError):rel32_target(0,b)
    def test_literal_scan(self):
        self.assertEqual(raw_dword_offsets(b'\x70\x01\x00\x00\x70\x01\x00\x00',0x170),[0,4])
        self.assertEqual(raw_dword_offsets(b'\x00\x1b\x01\x00\x00',0x11b),[1])
    def test_real_owners_both(self):
        out=inspect(self.cd,self.gog)
        self.assertEqual(out['anchored_opcodes_per_sample'],23)
        self.assertTrue(out['gog_archive']['same_code_section'])
        self.assertEqual(out['expression_type_0x170']['typed_output_tag'],'0x15')
    def test_original_opcode_mutation_rejected(self):
        mutated=patch_va(self.cd,0x4701bf,b'\x90')
        with self.assertRaisesRegex(ValueError,'4701BF'):
            inspect(mutated,self.gog)
    def test_gog_opcode_mutation_rejected(self):
        mutated=patch_va(self.gog,0x4979e0,b'\x90')
        with self.assertRaisesRegex(ValueError,'4979E0'):
            inspect(self.cd,mutated)
    def test_output_tag_mutation_rejected(self):
        mutated=patch_va(self.cd,0x4701e5,b'\x90')
        with self.assertRaisesRegex(ValueError,'4701E5'):
            inspect(mutated,self.gog)
    def test_registry_type170_mutation_rejected(self):
        mutated=patch_va(self.gog,0x4a43e0+0x170*8+2,b'\x00')
        with self.assertRaisesRegex(ValueError,'0x170'):
            inspect(self.cd,mutated)
    def test_archive_copy_mutation_rejected(self):
        mutated=patch_va(self.gog,0x517000+0x4701c3-IMAGE_BASE,b'\x00')
        with self.assertRaisesRegex(ValueError,'archive'):
            inspect(self.cd,mutated)
    def test_noncode_dword_types_not_asserted_absent_from_assets(self):
        out=inspect(self.cd,self.gog)
        self.assertIn('objects actually present in game assets',out['not_proven'])
        for row in out['inputs']:
            self.assertEqual(row['object_type_literal_counts_in_noncode_sections']['.data'],{'0x170':0,'0x11B':0})
            self.assertEqual(row['object_type_literal_counts_in_noncode_sections']['.rdata'],{'0x170':0,'0x11B':0})


if __name__=='__main__':unittest.main()
