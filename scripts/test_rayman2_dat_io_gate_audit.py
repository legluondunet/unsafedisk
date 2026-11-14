"""Synthetic, source-only regression tests for the I/O gate audit."""
import unittest
from rayman2_dat_io_gate_audit import (
    near_target, relative_jump_target, dat_selector_model,
    assert_no_status_consumer, validate_anchors,
)

class DatGateTests(unittest.TestCase):
    def test_call_rel32_forward(self):
        self.assertEqual(near_target(0x1000,bytes.fromhex('e8 05 00 00 00')),0x100a)
    def test_call_rel32_backward(self):
        self.assertEqual(near_target(0x2000,bytes.fromhex('e8 fb ff ff ff')),0x2000)
    def test_reject_non_call(self):
        with self.assertRaises(ValueError): near_target(0x2000,b'\x90')
    def test_short_jump(self):
        self.assertEqual(relative_jump_target(0x44f1cc,bytes.fromhex('eb 23')),0x44f1f1)
    def test_reject_non_jump(self):
        with self.assertRaises(ValueError): relative_jump_target(0,b'\x90\x01')
    def test_selector_zero(self):
        self.assertEqual(dat_selector_model(0,1,1,55)['final_index'],0)
    def test_selector_remainder(self):
        # count=100; random=82 -> index 82: above 24-name table bounds.
        r=dat_selector_model(204800,1,1,82)
        self.assertEqual(r['quotient_before_rng'],100)
        self.assertEqual(r['final_index'],82)
        self.assertFalse(r['in_24_entry_table'])
    def test_selector_safe_boundary(self):
        self.assertEqual(dat_selector_model(2048*24,1,1,23)['final_index'],23)
    def test_selector_zero_denominator(self):
        with self.assertRaises(ZeroDivisionError): dat_selector_model(33,1,0,1)
    def test_selector_zero_quotient(self):
        with self.assertRaises(ZeroDivisionError): dat_selector_model(33,1,2,1)
    def test_selector_shift_overflow(self):
        with self.assertRaises(ZeroDivisionError): dat_selector_model(1,0x200000,1,1)
    def test_selector_reject_negative_rng(self):
        with self.assertRaises(ValueError): dat_selector_model(1,1,1,-2)
    def test_selector_reject_bad_dword(self):
        with self.assertRaises(ValueError): dat_selector_model(2**32,1,1,1)
    def test_status_guard_accepts_exact_non_consuming_span(self):
        code={0x10:(b'','mov','ecx,ebx'), 0x12:(b'','push','edi')}
        self.assertTrue(assert_no_status_consumer(code,0x10,0x14,
                         [(0x10,'mov','ecx,ebx'),(0x12,'push','edi')]))
    def test_status_guard_rejects_new_test_eax(self):
        code={0x10:(b'','mov','ecx,ebx'), 0x12:(b'','test','eax,eax')}
        with self.assertRaises(ValueError): assert_no_status_consumer(
            code,0x10,0x14,[(0x10,'mov','ecx,ebx'),(0x12,'push','edi')])
    def test_status_guard_rejects_unexpected_branch(self):
        code={0x10:(b'','je','0x20')}
        with self.assertRaises(ValueError): assert_no_status_consumer(code,0x10,0x14,[])

if __name__ == '__main__':
    unittest.main()
