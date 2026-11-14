"""Self-contained synthetic XOR tests and optional owner-PE integration."""
from __future__ import annotations
import hashlib
import os
import random
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
import rayman2_inplace_xor_executor_audit as m
from rayman2_guard_provenance_audit import one, BASE


class XorExecutorTests(unittest.TestCase):
    def test_first_cipherword_forces_prologue_mask(self):
        c0=0xA3510240
        first,second=m.compact_model([c0],[])
        self.assertEqual(first[0],c0 | m.C)
        self.assertEqual(m.C & ~c0,c0 ^ (c0 | m.C))
        self.assertEqual(second,[])

    def test_mask_uses_previous_cipher_not_plain(self):
        f=[0,0x11001100,0xFFFF5555]
        s=[0xDEADBEEF,0x13572468]
        out1,out2=m.compact_model(f,s)
        self.assertEqual(out1,[m.C,f[1]^f[0],f[2]^f[1]])
        self.assertEqual(out2,[s[0]^f[-1],s[1]^s[0]])
        self.assertNotEqual(out2[0],s[0]^out1[-1])

    def test_simulated_x86_matches_optimised_xor(self):
        rng=random.Random(0x467350)
        for _ in range(100000):
            a=[rng.getrandbits(32) for i in range(rng.randrange(1,8))]
            b=[rng.getrandbits(32) for i in range(rng.randrange(0,8))]
            self.assertEqual(m.x86_literal_model(a,b),m.compact_model(a,b))

    def test_synthetic_known_plaintext_two_spans(self):
        plain_a=[m.C,0x90909090,0xC3C3C3C3]
        plain_b=[0xCAFEBABE,0x01020304]
        c0=0  # synthetic, NOT commercial game ciphertext
        enc_a=[c0]
        for word in plain_a[1:]:enc_a.append(word ^ enc_a[-1])
        enc_b=[]
        prev=enc_a[-1]
        for word in plain_b:
            prev=word^prev
            enc_b.append(prev)
        self.assertEqual(m.compact_model(enc_a,enc_b),(plain_a,plain_b))

    def test_reject_invalid_synthetic_ranges(self):
        for first,second in (([],[]),([2**32],[]),([-1],[]),([0],[-1]),(['z'],[])):
            with self.assertRaises((ValueError,TypeError)):
                m.compact_model(first,second)

    def test_x86_jump_forward_backward(self):
        for origin,target in m.BRANCHES.items():
            with self.subTest(source=hex(origin)):
                self.assertEqual(m.branch_target(origin,bytes.fromhex(m.ANCHORS[origin])),target)

    def test_non_branch_rejected(self):
        for code in (b'',b'\x90\x90',b'\xE9\x00\x00\x00\x00',b'\xE8\x00'):
            with self.assertRaises(ValueError):m.branch_target(0x401000,code)

    def test_exact_anchors_have_expected_count(self):
        self.assertGreaterEqual(len(m.ANCHORS),60)
        self.assertEqual(len(m.BRANCHES),13)
        self.assertEqual(m.ANCHORS[0x467477],'c74594558bec00')
        self.assertEqual(m.ANCHORS[0x467535],'ff5584')
        self.assertEqual(m.ANCHORS[0x47b072],'ff55ac')

    def test_invalid_sha_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA256'):
            m.inspect(b'',b'')

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'private owner binaries not included in GitHub Actions')
    def test_owner_inputs_end_to_end(self):
        retail=Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes()
        gog=Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes()
        report=m.inspect(retail,gog)
        self.assertEqual(report['main_equal_code_bytes'],590)
        self.assertEqual(report['expression_handler_equal_code_bytes'],519)
        self.assertEqual(report['branch_targets_verified'],13)
        self.assertEqual(report['expression_registry_type'],'0x111')
        self.assertFalse(report['actual_executable_target_resolved'])
        self.assertFalse(report['retail_executable_decrypted'])

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'private owner binaries not included in GitHub Actions')
    def test_mutated_executor_anchor_rejected(self):
        retail=bytearray(Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes())
        gog=Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes()
        section,_=one(bytes(retail),m.RETAIL_SHA)
        va=0x467477
        off=section['.text']['file_offset']+va-BASE-section['.text']['rva']
        retail[off]^=1
        fakehash=hashlib.sha256(retail).hexdigest()
        with patch.object(m,'RETAIL_SHA',fakehash):
            with self.assertRaises(ValueError):m.inspect(bytes(retail),gog)

    @unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                         'private owner binaries not included in GitHub Actions')
    def test_mutated_registry_record_rejected(self):
        retail=Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes()
        gog=bytearray(Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        section,_=one(bytes(gog),m.GOG_SHA)
        va=0x4a5ce8
        off=section['.data']['file_offset']+va-BASE-section['.data']['rva']
        gog[off]^=1
        fakehash=hashlib.sha256(gog).hexdigest()
        with patch.object(m,'GOG_SHA',fakehash):
            with self.assertRaisesRegex(ValueError,'registry'):
                m.inspect(retail,bytes(gog))


if __name__=='__main__':unittest.main()
