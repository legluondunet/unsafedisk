"""Isolated synthetic tests for bounded x86 direct-call and branch decoding."""
import unittest
from rayman2_dat_caller_chain_audit import target_at, direct_callers, short_jcc_target, near_jcc_target

class CallerChainTests(unittest.TestCase):
    def test_forward_call(self):
        self.assertEqual(target_at(0x1000,bytes.fromhex('e8 05 00 00 00')),0x100A)
    def test_backward_call(self):
        self.assertEqual(target_at(0x1000,bytes.fromhex('e8 f6 ff ff ff')),0x0FFB)
    def test_invalid_call(self):
        with self.assertRaises(ValueError):target_at(0x1000,b'\xff\xd0')
    def test_direct_call_match_only(self):
        code={0x1000:(bytes.fromhex('e8 05 00 00 00'),'call','0x100a'),
              0x1010:(b'\xff\xd0','call','eax'),
              0x1020:(bytes.fromhex('e8 e5 ff ff ff'),'call','0x100a'),
              0x1030:(bytes.fromhex('e8 d5 ff ff ff'),'mov','fake')}
        self.assertEqual(direct_callers(code,0x100a),[0x1000,0x1020])
    def test_other_target_empty(self):
        self.assertEqual(direct_callers({0x1000:(b'\x90','nop','')},0x100a),[])
    def test_true_loader_branch(self):
        self.assertEqual(short_jcc_target(0x44dc8a,b'\x75\x09',0x75),0x44dc95)
    def test_fallback_branch(self):
        self.assertEqual(short_jcc_target(0x44d9fe,b'\x74\x09',0x74),0x44da09)
    def test_invalid_handle_branch(self):
        self.assertEqual(near_jcc_target(0x44e8e3,bytes.fromhex('0f 84 4a 02 00 00'),b'\x0f\x84'),0x44eb33)
    def test_reject_short_branch_opcode(self):
        with self.assertRaises(ValueError):short_jcc_target(0,b'\x74\x09',0x75)
    def test_reject_near_branch_opcode(self):
        with self.assertRaises(ValueError):near_jcc_target(0,b'\x0f\x85\x00\x00\x00\x00',b'\x0f\x84')
    def test_signed_near_branch(self):
        self.assertEqual(near_jcc_target(0x1050,bytes.fromhex('0f 84 fa ff ff ff'),b'\x0f\x84'),0x1050)

if __name__=='__main__':unittest.main()
