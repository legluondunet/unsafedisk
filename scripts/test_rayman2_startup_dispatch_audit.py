"""Synthetic and private optional checks of original/GOG startup relay."""
import os,struct,unittest
from pathlib import Path
import rayman2_startup_dispatch_audit as m

class StartupTests(unittest.TestCase):
    def test_forward(self):
        at=0x400000;dst=0x4f1234
        self.assertEqual(m.rel_target(b'\xe8'+struct.pack('<i',dst-at-5),at),dst)
    def test_backward(self):
        at=0x44947c;dst=0x4478a0
        self.assertEqual(m.rel_target(b'\xe8'+struct.pack('<i',dst-at-5),at),dst)
    def test_reject_not_call(self):
        for raw in (b'',b'\xe8',b'\xe9\0\0\0\0',b'\x90'*5):
            with self.assertRaises(ValueError):m.rel_target(raw,0x400000)
    def test_wanted_five_targets(self):
        self.assertEqual(len(m.START_CALLS),5)
        self.assertEqual(len(m.RET_STUBS),4)
        self.assertIn((0x44949f,0x448e30),m.START_CALLS)
    def test_guard_and_prng_anchors(self):
        self.assertEqual(m.UNCHANGED[0x4493a8],'bf 19 01 00 00')
        self.assertEqual(m.UNCHANGED[0x401ef8],'6a 01')
        self.assertEqual(m.UNCHANGED[0x449370],'74 1b')
    def test_gog_opcode(self):
        self.assertEqual(len(m.GOG_NOOP),16)
        self.assertEqual(m.GOG_NOOP,bytes.fromhex('c3')+bytes([0xcc]*15))
        self.assertEqual(m.GOG_VOLUME[:2],b'\xb0\x2e')
    def test_strict_sha_gate(self):
        with self.assertRaises(ValueError):m.inspect(b'',b'')
    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),'private samples absent')
    def test_exact_owner_inputs(self):
        report=m.inspect(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
                         Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(report['initial_argument'],1)
        self.assertEqual(report['pseudo_random_bootstrap_state_count'],281)
        self.assertEqual(len(report['unchanged_direct_calls']),5)
        self.assertEqual(len(report['gog_ret_only_targets']),4)
        self.assertFalse(report['physical_safedisc_authentication_proven'])

if __name__=='__main__':unittest.main()
