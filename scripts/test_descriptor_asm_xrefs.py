"""Synthetic objdump text fixtures, independent of game bytes."""
import unittest
from descriptor_asm_xrefs import inspect_asm


class ReferenceScanTests(unittest.TestCase):
    def fixture(self):
        return [
            '  401000:\ta1 4c 14 4a 00       \tmov    eax,ds:0x4a144c',
            '  401005:\ta3 4c 14 4a 00       \tmov    ds:0x4a144c,eax',
            '  40100a:\tc7 46 01 4c 14 4a 00\tmov    DWORD PTR [esi+0x1],0x4a144c',
            '  401011:\t8d 05 4c 14 4a 00\tlea    eax,ds:0x4a144c',
            '  401017:\t83 3d 4c 14 4a 00 01\tcmp    DWORD PTR ds:0x4a144c,0x1',
            '  40101e:\t89 0d 4c 14 4a 00\tmov    DWORD PTR ds:0x4a144c,ecx',
            '  401024:\t90\tnop',
            '  401025:\t90\tnop # 0x4a144c',
        ]

    def test_classify_read_write_literals(self):
        result=inspect_asm(self.fixture(),0x4a141c,0x4c,2,0x30)
        counts=result['total_references_by_category']
        self.assertEqual(counts['direct_read'],2)
        self.assertEqual(counts['possible_direct_write'],2)
        self.assertEqual(counts['address_literal'],2)
        self.assertEqual(counts['other'],0)

    def test_empty_or_no_match(self):
        result=inspect_asm(['invalid','  123456: 90 nop'],0x4a141c,0x4c,2,0x30)
        self.assertEqual(result['referenced_descriptor_count'],0)

    def test_multiple_slots(self):
        data=[
            '  401000:\ta1 4c 14 4a 00\tmov    eax,ds:0x4a144c',
            '  401005:\ta1 98 14 4a 00\tmov    eax,ds:0x4a1498',
        ]
        result=inspect_asm(data,0x4a141c,0x4c,2,0x30)
        self.assertEqual(result['referenced_descriptor_count'],2)

    def test_validation(self):
        for args in ((0x4a141c,0x4c,0,0x30),
                     (0x4a141c,0x4c,2,0x4a),
                     (0xffffffff,0x4c,2,0x30),
                     (-1,0x4c,2,0x30)):
            with self.assertRaises(ValueError):
                inspect_asm([], *args)


if __name__=='__main__':
    unittest.main()
