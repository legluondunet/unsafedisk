"""Self-contained synthetic checks plus optional owner-binary integration."""
from __future__ import annotations
import os
import struct
import unittest
from pathlib import Path
import rayman2_removed_callgraph_audit as m


class DeletedCallgraphTests(unittest.TestCase):
    def test_raw_call_forward_and_backward(self):
        raw=bytearray(100)
        base=0x401000
        raw[1:6]=b'\xE8'+struct.pack('<i',0x501000-(base+1+5))
        raw[50:55]=b'\xE8'+struct.pack('<i',0x400000-(base+50+5))
        self.assertEqual(m.raw_relative_calls(base,bytes(raw),{0x501000,0x400000}),
                         {0x501000:[base+1],0x400000:[base+50]})

    def test_raw_call_is_not_jmp(self):
        raw=b'\xE9'+struct.pack('<i',0x1000-5)
        self.assertEqual(m.raw_relative_calls(0,raw,{0x1000}),{0x1000:[]})

    def test_truncated_call_not_counted(self):
        self.assertEqual(m.raw_relative_calls(0,b'\xe8\x00', {5}),{5:[]})

    def test_repeated_same_target(self):
        base=0x401000
        target=0x401024
        raw=(b'\xE8'+struct.pack('<i',target-(base+5))
             +b'\xE8'+struct.pack('<i',target-(base+10)))
        self.assertEqual(m.raw_relative_calls(base,raw,{target})[target],[base,base+5])

    def test_stubs(self):
        self.assertEqual(set(m.STUB_PREFIX),{'int3','ret','xor-eax-ret'})
        self.assertTrue(all(len(b)==16 for b in m.STUB_PREFIX.values()))
        self.assertEqual(m.STUB_PREFIX['xor-eax-ret'][:3],b'\x33\xc0\xc3')

    def test_original_16_expected_calls(self):
        self.assertEqual(len(m.REMOVED),11)
        self.assertEqual(sum(map(len,m.EXPECTED_CALLS.values())),16)
        self.assertEqual({i for i,sites in m.EXPECTED_CALLS.items() if not sites},{9})
        self.assertEqual(set(m.PRESERVED_CALLS),{6,8})

    def test_sha_fails_closed(self):
        with self.assertRaises(ValueError):m.audit(b'',b'')

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'owner executables not distributed to GitHub Actions')
    def test_real_executables(self):
        report=m.audit(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
                       Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(report['original_direct_E8_calls'],16)
        self.assertEqual(report['gog_removed_E8_calls'],14)
        self.assertEqual(report['gog_preserved_E8_calls'],2)
        self.assertEqual(report['gog_entrypoint_classes']['int3'],8)
        self.assertFalse(report['indirect_or_self_modified_calls_ruled_out'])

if __name__=='__main__': unittest.main()
