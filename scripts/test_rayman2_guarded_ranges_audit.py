"""Rayman 2 guarded ranges: synthetic tests, optional exact-owner integration."""
import os
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
import rayman2_guarded_ranges_audit as m


def synthetic_window(va=0x401100, first_ptr=0x510DC0,
                     second_ptr=0x510C00, branch_delta=0, end_delta=40):
    begin=va+30+branch_delta
    end=begin+end_delta
    raw=bytearray(bytes.fromhex('a1 ec 13 51 00 85 c0 74'))
    raw.append(21) # JZ at +7 lands at +30 when zero
    raw+=b'\xc7\x05'+struct.pack('<II',first_ptr,begin)
    raw+=b'\xc7\x05'+struct.pack('<II',second_ptr,end)
    raw+=b'\xc3'+b'\x90'*80
    return bytes(raw[:72])


class GuardedRangeTests(unittest.TestCase):
    def setUp(self):
        self.va=0x401100
        self.sections={'.text':{'rva':0x1000,'raw_size':0x9A200}}

    def extract(self,raw):
        with patch.object(m,'bytes_at',return_value=raw):
            return m.extract_entry(b'',self.sections,self.va)

    def test_valid_primary_region(self):
        v=self.extract(synthetic_window())
        self.assertEqual((v['family'],v['slot'],v['length']),
                         ('primary',0,40))
        self.assertEqual(v['begin'],self.va+30)
        self.assertEqual(v['zero_guard_branch_target_va'],v['begin'])

    def test_final_primary_slot(self):
        v=self.extract(synthetic_window(first_ptr=0x510E1C,
                                        second_ptr=0x510C5C))
        self.assertEqual(v['slot'],23)

    def test_secondary_pair(self):
        v=self.extract(synthetic_window(first_ptr=0x511408,
                                        second_ptr=0x511328))
        self.assertEqual((v['family'],v['slot']),('secondary',2))

    def test_unpaired_ranges_refused(self):
        for first,last in ((0x510DC0,0x510C04),
                           (0x511400,0x510C00),
                           (0x510DC0,0x511320)):
            with self.subTest(first=first,last=last):
                with self.assertRaises(ValueError):
                    self.extract(synthetic_window(first_ptr=first,
                                                 second_ptr=last))

    def test_wrong_zero_guard_branch_refused(self):
        with self.assertRaisesRegex(ValueError,'zero-guard'):
            self.extract(synthetic_window(branch_delta=10))

    def test_reversed_code_bounds_refused(self):
        with self.assertRaises(ValueError):
            self.extract(synthetic_window(end_delta=-2))

    def test_absent_second_store_refused(self):
        raw=synthetic_window()
        with self.assertRaisesRegex(ValueError,'two range writes'):
            self.extract(raw[:19]+b'\x90'*53)

    def test_disjoint_regions(self):
        m.disjoint_entries([{'begin':10,'end':20},{'begin':20,'end':30}])
        with self.assertRaisesRegex(ValueError,'overlap'):
            m.disjoint_entries([{'begin':10,'end':21},{'begin':20,'end':30}])

    def test_wrong_executable_rejected(self):
        with self.assertRaises(ValueError):
            m.inspect(b'',b'')

    @unittest.skipUnless(
        os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
        'private owner executables are not bundled into GitHub Actions')
    def test_exact_private_inputs(self):
        report=m.inspect(
            Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
            Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(report['guarded_regions'],28)
        self.assertEqual(report['total_guarded_bytes'],14757)
        self.assertEqual(report['changed_bytes_inside_guarded_regions'],8669)
        self.assertEqual(report['changed_bytes_outside_guarded_regions'],4600)
        self.assertEqual(report['secondary_slots'],[0,1,2,5])
        self.assertEqual(report['paired_slot_addresses'],56)
        self.assertEqual(report['gog_int3_filled_region_count'],11)
        self.assertEqual(report['gog_int3_filled_region_bytes'],4738)
        self.assertEqual(report['gog_unchanged_region_count'],12)
        self.assertEqual(sum(r['begin']-r['zero_guard_branch_target_va']==8
                             for r in report['ranges']),1)
        self.assertFalse(report['all_regions_proven_to_be_safedisc'])


if __name__ == '__main__':
    unittest.main()
