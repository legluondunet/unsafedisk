"""Synthetic and optional exact-binary tests for Rayman 2 classes 5..40."""
import os
from pathlib import Path
import struct
import unittest

from rayman2_remaining_object_classes_audit import (
    FIRST_CLASS, LAST_CLASS, LITERAL_PREFIX, LITERAL_SUFFIX,
    LITERAL_SIZE, SPECIAL, SPECIAL_ANCHORS, DIRECT_CALLS,
    audit, call_target, classify_handler, examine,
)
from rayman2_selfread_archive_audit import locked_read, sections


class SyntheticControls(unittest.TestCase):
    @staticmethod
    def literal_code(value=0x15):
        return LITERAL_PREFIX + struct.pack('<I', value) + LITERAL_SUFFIX

    def test_literal_23_byte_template(self):
        self.assertEqual(len(self.literal_code()), LITERAL_SIZE)
        self.assertEqual(LITERAL_SIZE,23)

    def test_literal_matches_known_value(self):
        raw=self.literal_code(0x25)
        record=classify_handler(0x480390,lambda _addr,n:raw[:n])
        self.assertEqual(record['output_type'],0x25)
        self.assertEqual(record['consumes_bytes'],8)

    def test_literal_accepts_full_u32(self):
        raw=self.literal_code(0xDEADBEEF)
        record=classify_handler(0x480390,lambda _addr,n:raw[:n])
        self.assertEqual(record['output_type'],0xDEADBEEF)

    def test_bad_input_load_is_not_literal(self):
        buf=bytearray(self.literal_code());buf[8]^=1
        self.assertEqual(classify_handler(0x480390,lambda _addr,n:bytes(buf[:n]))['behavior'],'non_literal_special')

    def test_bad_output_type_store_is_not_literal(self):
        buf=bytearray(self.literal_code());buf[10]^=1
        self.assertEqual(classify_handler(0x480390,lambda _addr,n:bytes(buf[:n]))['behavior'],'non_literal_special')

    def test_bad_end_sequence_is_not_literal(self):
        buf=bytearray(self.literal_code());buf[-1]=0x90
        self.assertEqual(classify_handler(0x480390,lambda _addr,n:bytes(buf[:n]))['behavior'],'non_literal_special')

    def test_no_assumption_about_special_function(self):
        out=classify_handler(0x480510,lambda _addr,n:b'\x90'*n)
        self.assertEqual(out['behavior'],'non_literal_special')
        self.assertIsNone(out['output_type'])

    def test_special_class_inventory_exact(self):
        self.assertEqual(sorted(SPECIAL),[6,7,8,9,10,11,15,16,17,39,40])

    def test_separate_class_5(self):
        self.assertEqual((FIRST_CLASS,LAST_CLASS),(6,40))
        self.assertNotIn(5,SPECIAL)

    def test_synthetic_positive_relative_call(self):
        at=0x4803E2;to=0x487CF0
        b=b'\xe8'+struct.pack('<i',to-(at+5))
        self.assertEqual(call_target(at,b),to)

    def test_synthetic_negative_relative_call(self):
        with self.assertRaises(ValueError):call_target(0x4803E2,b'\xe9'+b'\0'*4)

    def test_synthetic_short_relative_call(self):
        with self.assertRaises(ValueError):call_target(0x4803E2,b'\xe8\0')

    def test_known_special_opcode_anchors(self):
        self.assertEqual(len(SPECIAL_ANCHORS),23)
        self.assertEqual(bytes.fromhex(SPECIAL_ANCHORS[0x480B6B]),bytes.fromhex('6a 00 6a 18'))

    def test_known_direct_call_sites(self):
        self.assertEqual(len(DIRECT_CALLS),15)
        self.assertEqual(DIRECT_CALLS[0x480545],0x480B90)


class OptionalExactSourceControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root=Path(os.environ.get('RAYMAN2_OWNER_SAMPLES','/mnt/data/rayman2_research'))
        a,b=root/'Rayman2(3).exe',root/'Rayman2.exe'
        if not (a.is_file() and b.is_file()):
            raise unittest.SkipTest('Exact private owner samples absent; synthetic tests remain active')
        cls.cd=locked_read(a,'cd');cls.gog=locked_read(b,'gog')
        _,cls.ss=sections(cls.cd)

    def change(self,va,mask=1):
        # Strictly in-memory mutation: never write to the original EXE.
        item=self.ss['.text'] if va < 0x49B200 else self.ss['.data']
        offset=item.raw_offset + (va-0x400000) - item.rva
        changed=bytearray(self.cd)
        changed[offset]^=mask
        return bytes(changed)

    def test_exact_35_slot_inventory(self):
        r=audit(self.cd,self.gog)
        self.assertTrue(r['original_and_GOG_static_regions_identical'])
        summary=r['results']
        self.assertEqual((summary['slot_count'],summary['unique_handler_count']), (35,32))
        self.assertEqual((summary['literal_dword_slots'],summary['other_slots']),(24,11))
        self.assertFalse(summary['runtime_calls_observed'])

    def test_dual_binary_identical(self):
        self.assertEqual(examine(self.cd),examine(self.gog))

    def test_classes_15_and_16_result_type_shared(self):
        rows={x['class_id']:x for x in examine(self.cd)['classes_6_through_40']}
        self.assertEqual(rows[15]['behavior'],'triple_dword_typed_0x15')
        self.assertEqual(rows[16]['behavior'],'three_nested_values_typed_0x15')
        self.assertNotEqual(rows[15]['handler'],rows[16]['handler'])

    def test_24_literal_rows(self):
        rows=examine(self.cd)['classes_6_through_40']
        self.assertEqual(len([r for r in rows if r['behavior']=='literal_dword_to_typed_result']),24)
        self.assertEqual([r['output_type'] for r in rows if r['class_id'] in (34,35,36,37,38)],
                         [0x27,0x28,0x2A,0x2B,0x2C])

    def test_class_5_is_stateful(self):
        r=examine(self.cd)['class_5']
        self.assertEqual(r['handler'],'0x00480A50')
        self.assertEqual(r['fallback_error_path_at'],'0x00480B6B')
        self.assertTrue(r['fallback_returns_zero_typed_0x14'])

    def test_mutated_literal_handler_rejected(self):
        with self.assertRaisesRegex(ValueError,'changed code/table span'):
            examine(self.change(0x480390))

    def test_mutated_complex_handler_rejected(self):
        with self.assertRaisesRegex(ValueError,'changed code/table span'):
            examine(self.change(0x4805A0))

    def test_mutated_stateful_class5_rejected(self):
        with self.assertRaisesRegex(ValueError,'changed code/table span'):
            examine(self.change(0x480A50))

    def test_mutated_parser_table_rejected(self):
        with self.assertRaisesRegex(ValueError,'changed code/table span'):
            examine(self.change(0x4A4180))


if __name__ == '__main__':
    unittest.main()
