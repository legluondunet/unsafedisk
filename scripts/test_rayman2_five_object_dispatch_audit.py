"""Synthetic and optional exact-SHA integration tests for 5 object-dispatch families."""
import os
import struct
import unittest
from dataclasses import replace
from pathlib import Path

from rayman2_five_object_dispatch_audit import (
    FAMILIES, PARSER_TABLE, Family, audit, decode_object_header,
    decode_table, examine, target_of_call, validate_getter_code, validate_trailer,
)
from rayman2_selfread_archive_audit import by_rva, locked_read, sections


def toy_family(stride=4, count=2):
    f=FAMILIES[0]
    return replace(f, count=count,stride=stride)


class SyntheticTests(unittest.TestCase):
    def test_decode_two_pointer_entries(self):
        f=toy_family(stride=4)
        self.assertEqual(decode_table(struct.pack('<II',0x480900,0x470000),f),((0x480900,0x470000),()))

    def test_decode_two_flagged_entries(self):
        f=toy_family(stride=8)
        self.assertEqual(decode_table(struct.pack('<IIII',0x470000,1,0x480900,0),f),((0x470000,0x480900),(1,0)))

    def test_wrong_length(self):
        with self.assertRaises(ValueError): decode_table(b'\0'*5,toy_family())

    def test_noncode_pointer_rejected(self):
        with self.assertRaises(ValueError):decode_table(struct.pack('<II',0x470000,0x3f800000),toy_family())

    def test_invalid_flag_rejected(self):
        with self.assertRaises(ValueError):decode_table(struct.pack('<IIII',0x470000,1,0x480900,2),toy_family(stride=8))

    def test_direct_call_target_signed_backwards(self):
        displacement=0x480800-(0x487d50+5)
        self.assertEqual(target_of_call(0x487d50,b'\xe8'+struct.pack('<i',displacement)),0x480800)

    def test_direct_call_reject_short(self):
        with self.assertRaises(ValueError): target_of_call(0x480808,b'\xe8\x00')

    def test_direct_call_reject_wrong_opcode(self):
        with self.assertRaises(ValueError): target_of_call(0x480808,b'\xe9\0\0\0\0')

    def test_getter_all_five_reconstructed(self):
        for f in FAMILIES:
            idx=b'\x85' if f.stride==4 else b'\xc5'
            with self.subTest(f=f.tag):
                validate_getter_code(bytes.fromhex('8b4424048b04')+idx+struct.pack('<I',f.first_va)+b'\xc3',f)

    def test_getter_reject_wrong_address(self):
        f=FAMILIES[4]
        raw=bytes.fromhex('8b4424048b04c5')+struct.pack('<I',f.first_va+4)+b'\xc3'
        with self.assertRaises(ValueError):validate_getter_code(raw,f)

    def test_getter_reject_wrong_scale(self):
        f=FAMILIES[4]
        raw=bytes.fromhex('8b4424048b0485')+struct.pack('<I',f.first_va)+b'\xc3'
        with self.assertRaises(ValueError):validate_getter_code(raw,f)

    def test_class4_record_target(self):
        records={4:((0x470210,0x470000),(0,1))}
        out=decode_object_header(struct.pack('<I',1)+b'\x00\x00\x00\x04',4,records)
        self.assertEqual(out['target'],'0x00470000')
        self.assertEqual(out['handler_cursor_advance'],8)
        self.assertFalse(out['runtime_call_performed'])

    def test_class3_record_target(self):
        records={3:((0x47B170,), (1,))}
        out=decode_object_header(struct.pack('<I',0)+b'\x00\x00\x00\x03',3,records)
        self.assertEqual(out['target'],'0x0047B170')

    def test_record_short_rejected(self):
        with self.assertRaises(ValueError):decode_object_header(b'\0'*7,4,{4:((0x470000,),(1,))})

    def test_record_invalid_class(self):
        with self.assertRaises(ValueError):decode_object_header(b'\0'*7+b'\x29',41,{4:((0x470000,),(1,))})

    def test_record_class_mismatch(self):
        with self.assertRaises(ValueError):decode_object_header(b'\0'*7+b'\x03',4,{4:((0x470000,),(1,))})

    def test_record_index_out_of_range(self):
        with self.assertRaises(ValueError):decode_object_header(struct.pack('<I',2)+b'\0\0\0\x04',4,{4:((0x470000,),(1,))})

    def test_trailer_bytes_are_not_registry_pointers(self):
        f=FAMILIES[0]
        raw=bytes.fromhex('d31742cefbffdf3f0000803f00000000')
        validate_trailer(raw,f)
        with self.assertRaises(ValueError):validate_trailer(raw[:-1]+b'\x10',f)

    def test_numeric_separator_first_four_words_not_functions(self):
        buf=bytes.fromhex('d31742cefbffdf3f0000803f00000000')
        with self.assertRaises(ValueError):decode_table(buf,replace(FAMILIES[0],count=4,stride=4))

    def test_changed_trailer_invalid(self):
        raw=bytearray(bytes.fromhex('d31742cefbffdf3f0000803f00000000'))
        raw[3]^=1
        with self.assertRaises(ValueError):validate_trailer(bytes(raw),FAMILIES[0])


class RealFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        home=Path(os.environ.get('RAYMAN2_OWNER_SAMPLES','/mnt/data/rayman2_research'))
        c,g=home/'Rayman2(3).exe',home/'Rayman2.exe'
        if not c.is_file() or not g.is_file():
            raise unittest.SkipTest('owner-owned exact binaries not accessible; synthetic tests still run')
        cls.cd=locked_read(c,'cd')
        cls.gog=locked_read(g,'gog')
        _,cls.sec=sections(cls.cd)

    def changed(self,va:int,delta=1)->bytes:
        sec=self.sec['.text'] if va<0x49B200 else self.sec['.data']
        off=sec.raw_offset + (va-0x400000)-sec.rva
        raw=bytearray(self.cd)
        raw[off]^=delta
        return bytes(raw)

    def test_exact_five_tables(self):
        a=audit(self.cd,self.gog)
        self.assertTrue(a['five_record_dispatch_tables_identical'])
        self.assertEqual([a['results']['families'][str(i)]['entry_count'] for i in range(5)], [20,149,28,314,514])
        self.assertEqual(a['results']['original_tag_0x170']['target'],'0x00470000')
        self.assertEqual(a['results']['original_tag_0x11B']['target'],'0x0047B170')

    def test_original_and_gog_individually(self):
        a,_=examine(self.cd)
        b,_=examine(self.gog)
        self.assertEqual(a,b)
        self.assertEqual(a['special_class_5_handler'],'0x00480A50')

    def test_mutated_class1_table(self):
        with self.assertRaises(ValueError):examine(self.changed(FAMILIES[1].first_va))

    def test_mutated_class3_table(self):
        with self.assertRaises(ValueError):examine(self.changed(FAMILIES[3].first_va))

    def test_mutated_class2_trailer(self):
        f=FAMILIES[2]
        with self.assertRaises(ValueError):examine(self.changed(f.first_va+f.count*f.stride))

    def test_mutated_dispatch_call(self):
        with self.assertRaises(ValueError):examine(self.changed(FAMILIES[4].getter_call_va))

    def test_mutated_getter_pointer(self):
        with self.assertRaises(ValueError):examine(self.changed(FAMILIES[4].getter_va+7))

    def test_mutated_class5_opcode(self):
        with self.assertRaises(ValueError):examine(self.changed(0x480A50))

    def test_mutated_parser_table(self):
        with self.assertRaises(ValueError):examine(self.changed(PARSER_TABLE))


if __name__=='__main__':
    unittest.main()
