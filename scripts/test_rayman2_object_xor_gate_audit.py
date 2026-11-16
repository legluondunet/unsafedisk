"""Rayman2 object-gate static calls, runtime geometry and fail-closed tests."""
from __future__ import annotations
import os
import struct
import unittest
from pathlib import Path
import rayman2_object_xor_gate_audit as m

class ObjectGateTests(unittest.TestCase):
    def test_e8_forward(self):
        va=0x4042a8;target=0x4045f0
        self.assertEqual(m.relative_call_target(va,b'\xe8'+struct.pack('<i',target-va-5)),target)

    def test_e8_backward(self):
        va=0x4674c8;target=0x467130
        self.assertEqual(m.relative_call_target(va,b'\xe8'+struct.pack('<i',target-va-5)),target)

    def test_bad_relative_call(self):
        for b in (b'',b'\xe8',b'\xe9'+bytes(4),b'\x90'*5):
            with self.assertRaises(ValueError):m.relative_call_target(0x400000,b)

    def test_static_linked_list_branches(self):
        self.assertIn(0x404588,m.CALLS)
        self.assertIn(0x404591,m.CALLS)
        self.assertIn(0x4045cc,m.CALLS)
        self.assertIn(0x4045d5,m.CALLS)
        self.assertEqual(m.ANCHORS[0x4045f2],'6a 00')
        self.assertEqual(m.ANCHORS[0x404560],'bd 00 00 00 01')
        self.assertEqual(m.ANCHORS[0x404571],'85 69 24')
        self.assertEqual(m.ANCHORS[0x4045b5],'85 69 24')

    def test_bodies_expected_sha_are_proper(self):
        self.assertEqual(len(m.BODIES),4)
        for va,(length,digest) in m.BODIES.items():
            self.assertGreater(length,0)
            self.assertEqual(len(digest),64)

    def test_geometry_aligned(self):
        g=m.geometry(0x400000,0x400008,0x401000,0x40100c)
        self.assertEqual(g['first_range_bytes'],8)
        self.assertEqual(g['second_range_bytes'],12)
        self.assertEqual(g['first_dword_loop_iterations'],2)
        self.assertEqual(g['second_dword_loop_iterations'],3)
        self.assertEqual(g['scrub_loop_byte_iterations'],20)
        self.assertEqual(g['first_dword_overrun_risk_bytes'],0)
        self.assertTrue(g['range_alignment_confirmed'])

    def test_geometry_misaligned_end(self):
        g=m.geometry(0x400000,0x400005,0x401000,0x401009)
        self.assertEqual(g['first_dword_loop_iterations'],2)
        self.assertEqual(g['second_dword_loop_iterations'],3)
        self.assertEqual(g['first_dword_overrun_risk_bytes'],3)
        self.assertEqual(g['second_dword_overrun_risk_bytes'],3)
        self.assertEqual(g['scrub_loop_byte_iterations'],14)

    def test_geometry_empty_b_allowed(self):
        g=m.geometry(0x1000,0x1008,0x2000,0x2000)
        self.assertEqual(g['second_dword_loop_iterations'],0)

    def test_geometry_invalid_rejected(self):
        for fields in ((0,0,4,8),(-1,4,5,6),(8,4,20,24),
                       (0x1000,0x1010,0x1008,0x1020),
                       (1,2,2**32,2**32),
                       (0,32*1024*1024+1,0x30000000,0x30000004)):
            with self.subTest(fields=fields),self.assertRaises(ValueError):
                m.geometry(*fields)

    def test_unknown_exe_refused(self):
        with self.assertRaises(ValueError):m.inspect(b'',b'')

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'owner-provided executables not included in GitHub CI')
    def test_real_owner_pe_strict_gates(self):
        out=m.inspect(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
                      Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(out['exact_preserved_direct_calls'],8)
        self.assertEqual(out['required_object_flag_mask'],'0x01000000')
        self.assertTrue(out['second_root_zero_initialized_by_PE_loader'])
        self.assertFalse(out['prehelper_return_checked_before_decoder'])
        self.assertFalse(out['input_runtime_object_bytes_available'])

if __name__=='__main__':unittest.main()
