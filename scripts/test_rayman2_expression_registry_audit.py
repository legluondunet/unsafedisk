"""Synthetic and exact-owned-sample tests of the expression registry audit."""
import struct
import unittest
from pathlib import Path
from rayman2_expression_registry_audit import (
    HANDLERS, SHARED, REGISTRY_BASE, REGISTRY_STRIDE, TYPE_MIN, TYPE_MAX,
    OTHER_HANDLERS, OTHER_REGISTRY_BASE,
    decode_rows, validate_anchors, inspect
)
from rayman2_selfread_archive_audit import locked_read, sections

ROOT=Path(__file__).resolve().parent

class RegistryAuditTests(unittest.TestCase):
    def test_synthetic_rows(self):
        raw=struct.pack('<IIII',0x401234,1,0x405678,0)
        result=decode_rows(raw,0x90)
        self.assertEqual(result,[
            {'type':'0x90','handler_va':'0x00401234','flag':1},
            {'type':'0x91','handler_va':'0x00405678','flag':0}])
    def test_bad_row_lengths(self):
        for raw in (b'',b'\x00'*7,b'\x00'*9,b'\x00'*8*257):
            with self.assertRaises(ValueError):decode_rows(raw)
    def test_registry_offset(self):
        self.assertEqual(REGISTRY_BASE+REGISTRY_STRIDE*0x11B,0x4A5D38)
        self.assertEqual(REGISTRY_BASE+REGISTRY_STRIDE*0x116,0x4A5D10)
    def test_other_registry_offsets(self):
        self.assertEqual(OTHER_REGISTRY_BASE+0x170*8,0x4A4F60)
        self.assertEqual(OTHER_HANDLERS[0x170],(0x470000,1))
        self.assertNotEqual(HANDLERS.get(0x170),(0x470000,1))
    def test_other_registry_separate_dispatch(self):
        self.assertEqual(len(OTHER_HANDLERS),5)
        self.assertEqual(OTHER_HANDLERS[0x171],(0x470210,0))
    def test_type_116_separate_handler(self):
        self.assertEqual(HANDLERS[0x116],(0x47B340,0))
        self.assertEqual(HANDLERS[0x11B],(0x47B170,0))
    def test_other_types(self):
        self.assertEqual([k for k,(fn,_) in HANDLERS.items() if fn==0x47B170],
                         [0x113,0x114,0x115,0x117,0x118,0x119,0x11A,0x11B])
    def test_shared_anchor_positive_synthetic(self):
        mapping={va:bytes.fromhex(code) for va,code in SHARED.items()}
        validate_anchors(lambda a,n: mapping[a][:n])
    def test_shared_anchor_negative_synthetic(self):
        mapping={va:bytes.fromhex(code) for va,code in SHARED.items()}
        mapping[0x480880]=b'\x00'+mapping[0x480880][1:]
        with self.assertRaisesRegex(ValueError,'shared opcode'):
            validate_anchors(lambda a,n:mapping[a][:n])
    def test_secondary_callback_dispatch_sites(self):
        for address in (0x470187,0x4701ED,0x4815F0,0x481623,
                        0x481800,0x481822,0x481847,0x481850,0x481860):
            self.assertIn(address,SHARED)
        self.assertIn(b'\xff\xd0',bytes.fromhex(SHARED[0x481847]))
    def test_sample_readonly(self):
        cd=locked_read(ROOT/'Rayman2(3).exe','cd')
        gog=locked_read(ROOT/'Rayman2.exe','gog')
        result=inspect(cd,gog)
        self.assertEqual(len(result['rows']),TYPE_MAX-TYPE_MIN+1)
        self.assertFalse(result['downstream_integrity_verdict_observed'])
        self.assertEqual(result['other_special_type_0x170']['handler'],'0x470000')
        self.assertEqual(len(result['other_registry_rows_checked']),5)
    def test_sample_corrupt_data_row(self):
        cd=locked_read(ROOT/'Rayman2(3).exe','cd')
        gog=bytearray(locked_read(ROOT/'Rayman2.exe','gog'))
        base,sects=sections(gog); sec=sects['.data']
        va=0x4A5D38
        off=sec.raw_offset+(va-base)-sec.rva
        gog[off]^=0x01
        with self.assertRaisesRegex(ValueError,'changed handler'):
            inspect(cd,bytes(gog))
    def test_sample_corrupt_gog_branch(self):
        cd=locked_read(ROOT/'Rayman2(3).exe','cd')
        gog=bytearray(locked_read(ROOT/'Rayman2.exe','gog'))
        base,sects=sections(gog); sec=sects['.text']
        va=0x47B388
        off=sec.raw_offset+(va-base)-sec.rva
        gog[off]^=1
        with self.assertRaisesRegex(ValueError,'changed branch'):
            inspect(cd,bytes(gog))

if __name__=='__main__':unittest.main()
