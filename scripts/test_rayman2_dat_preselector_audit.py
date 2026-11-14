"""Synthetic x86-width regression tests; no commercial DAT input required."""
import random
import unittest
from rayman2_dat_preselector_audit import (
    normalized_initial_index, normalized_iteration_count, signed_rel32,
)


def x86_register_model(first, second, divisor):
    """Independent register/byte-store emulator of 0x44ED2C..0x44ED8B."""
    original_dword = (0xABCDEF00 | first)  # upper 24 bits need not be zero
    eax=original_dword & 0xff
    edx=0
    eax, edx = divmod((edx<<32)|eax, divisor)
    # MOV byte [0x5116F0],DL keeps the other 24 bits intact
    original_dword = (original_dword & 0xffffff00) | (edx & 255)
    eax = second  # XOR EAX,EAX followed by MOV AL, byte
    edx = (0xffffffff if eax & 0x80000000 else 0)  # CDQ
    eax=(eax^edx)&0xffffffff
    eax=(eax-edx)&0xffffffff
    eax &= 3
    eax=(eax^edx)&0xffffffff
    eax=(eax-edx)&0xffffffff
    edx=0  # XOR EDX,EDX
    edx = (edx & 0xffffff00) | (eax & 0xff)  # MOV DL,AL
    ecx = original_dword & 0xff  # MOV ECX,[0x5116F0]; AND ECX,255
    ecx=(ecx<<2)&0xffffffff
    eax=edx
    # Four-way original jump table (first target adds 0).
    if eax == 1: ecx+=1
    elif eax == 2: ecx+=2
    elif eax == 3: ecx+=3
    elif eax > 3: raise ValueError('impossible route')
    return ecx


class PreselectorTests(unittest.TestCase):
    def test_first_divisor_one(self):
        self.assertEqual(normalized_initial_index(255,255,1)['index_n'],3)
        self.assertEqual(normalized_initial_index(255,255,1)['index_range_at_this_divisor'],[0,3])
    def test_first_divisor_four(self):
        self.assertEqual(normalized_initial_index(255,255,4)['index_n'],15)
        self.assertEqual(normalized_initial_index(255,255,4)['index_range_at_this_divisor'],[0,15])
    def test_first_divisor_six(self):
        self.assertEqual(normalized_initial_index(255,255,6)['index_range_at_this_divisor'],[0,23])
    def test_first_divisor_256(self):
        self.assertEqual(normalized_initial_index(255,255,256)['index_n'],1023)
    def test_first_divisor_greater_than_byte(self):
        self.assertEqual(normalized_initial_index(255,255,0xffffffff)['index_n'],1023)
    def test_general_range_1024(self):
        for first in range(256):
            for second in range(4):
                self.assertEqual(normalized_initial_index(first,second,256)['index_n'],4*first+second)
    def test_independent_x86_interpreter_10000(self):
        rng=random.Random(20261114)
        for _ in range(10000):
            x=rng.randrange(256); y=rng.randrange(256); d=rng.randrange(1,2**32)
            self.assertEqual(normalized_initial_index(x,y,d)['index_n'], x86_register_model(x,y,d))
    def test_invalid_first_zero(self):
        with self.assertRaises(ValueError): normalized_initial_index(2,0,0)
    def test_invalid_first_not_byte(self):
        for x in (-1,256):
            with self.assertRaises(ValueError): normalized_initial_index(x,3,3)
    def test_invalid_large_divisor(self):
        with self.assertRaises(ValueError): normalized_initial_index(255,3,2**32)
    def test_third_zero_remainder_skips_fpu_loop(self):
        self.assertTrue(normalized_iteration_count(18,6)['zero_remainder_uses_branch_to_0x44F1FA'])
    def test_third_nonzero_enters_fpu_loop(self):
        self.assertFalse(normalized_iteration_count(19,6)['zero_remainder_uses_branch_to_0x44F1FA'])
        self.assertEqual(normalized_iteration_count(19,6)['fpu_loop_requested_iterations'],1)
    def test_third_divisor_one_always_skips(self):
        self.assertTrue(all(normalized_iteration_count(v,1)['zero_remainder_uses_branch_to_0x44F1FA'] for v in range(256)))
    def test_third_divisor_larger_than_byte(self):
        self.assertEqual(normalized_iteration_count(255,65535)['fpu_loop_requested_iterations'],255)
    def test_third_zero_divisor_rejected(self):
        with self.assertRaises(ValueError): normalized_iteration_count(7,0)
    def test_branch_relative_targets(self):
        self.assertEqual(signed_rel32(0x44edb2,bytes.fromhex('0f 86 42 04 00 00'),b'\x0f\x86'),0x44f1fa)
        self.assertEqual(signed_rel32(0x44f1fc,bytes.fromhex('e9 ea fb ff ff'),b'\xe9'),0x44edeb)
    def test_wrong_relative_branch(self):
        with self.assertRaises(ValueError): signed_rel32(0x44edb2,b'\x90\x90',b'\x0f\x86')

if __name__=='__main__': unittest.main()
