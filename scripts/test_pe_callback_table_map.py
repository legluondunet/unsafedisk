"""Synthetic x86 objdump text only; no commercial game bytes."""
import unittest
from pe_callback_table_map import extract

class TestCallbackMapping(unittest.TestCase):
    def test_two_literals_and_one_import(self):
        rows = [
            '  401000: ba 20 10 40 00  mov edx,0x401020',
            '  401005: 89 50 04  mov DWORD PTR [eax+0x4],edx',
            '  401008: b9 30 10 40 00  mov ecx,0x401030',
            '  40100d: 89 08  mov DWORD PTR [eax],ecx',
            '  40100f: 8b 0d 20 30 40 00  mov ecx,DWORD PTR ds:0x403020',
            '  401015: 89 48 08  mov DWORD PTR [eax+0x8],ecx',
        ]
        r=extract(rows,0x401000,0x401020,3)
        self.assertEqual(r['slot_count'],3)
        self.assertEqual(r['literal_assignments'],2)
        self.assertEqual(r['runtime_import_assignments'],1)
        self.assertEqual(r['slots'][2]['source_or_value'],'0x00403020')
        self.assertFalse(r['control_flow_verified'])

    def test_reject_duplicate(self):
        rows=['  401000: c7 00 40 10 40 00  mov DWORD PTR [eax],0x401040',
              '  401006: c7 00 44 10 40 00  mov DWORD PTR [eax],0x401044']
        with self.assertRaisesRegex(ValueError,'duplicate'):
            extract(rows,0x401000,0x401010)

    def test_reject_unresolved(self):
        with self.assertRaisesRegex(ValueError,'unresolved'):
            extract(['  401000: 89 50 04 mov DWORD PTR [eax+0x4],edx'],0x401000,0x401008)

    def test_reject_unknown_opcode(self):
        with self.assertRaisesRegex(ValueError,'unsupported'):
            extract(['  401000: 31 d2 xor edx,edx'],0x401000,0x401008)

    def test_range_and_completion(self):
        with self.assertRaisesRegex(ValueError,'incomplete'):
            extract(['  401000: c7 40 04 40 10 40 00 mov DWORD PTR [eax+0x4],0x401040'],0x401000,0x401008,2)
        with self.assertRaises(ValueError):extract([],0x401000,0x402001)

if __name__=='__main__': unittest.main()
