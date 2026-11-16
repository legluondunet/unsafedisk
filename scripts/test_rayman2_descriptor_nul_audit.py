"""Pure synthetic and optional private exact-SHA Rayman 2 NUL audit tests."""
import os
from pathlib import Path
import unittest

import rayman2_descriptor_nul_audit as m
from rayman2_callback2c_branch_audit import layout, raw_at, encoded_export


def synthetic_record(head, name):
    """Invent a 76-byte encoded descriptor; no game data."""
    sub, key, ds, dk = head
    b = bytearray(head + bytes([len(name)]))
    for val in name.encode('ascii'):
        b.append(((val ^ key) + sub) & 255)
        sub = (sub + ds) & 255
        key = (key + dk) & 255
    b.extend(bytes(76-len(b)))
    return bytes(b)


class Synthetic(unittest.TestCase):
    def test_equal_until_null(self):
        self.assertTrue(m.nul_equal(b'abc\x00old', b'abc\x00new'))
        self.assertTrue(m.nul_equal(b'\x00x', b'\x00y'))

    def test_mismatch_before_null_rejected(self):
        self.assertFalse(m.nul_equal(b'abx\x00', b'aby\x00'))
        self.assertFalse(m.nul_equal(b'ab\x00', b'abc\x00'))

    def test_missing_null_not_proven_equal(self):
        self.assertFalse(m.nul_equal(b'ab', b'ab'))

    def test_nul_in_seed_allows_two_distinct_names(self):
        seed=bytes([7,23,3,0])
        a=synthetic_record(seed,'LoadLibraryA')
        b=synthetic_record(seed,'ReadFile')
        self.assertEqual(encoded_export(a), 'LoadLibraryA')
        self.assertEqual(encoded_export(b), 'ReadFile')
        self.assertNotEqual(a,b)
        self.assertTrue(m.nul_equal(a,b))

    def test_changing_nul_seed_byte_rejected(self):
        a=synthetic_record(bytes([7,23,3,0]),'ReadFile')
        b=synthetic_record(bytes([7,23,3,1]),'ReadFile')
        self.assertFalse(m.nul_equal(a,b))
        self.assertEqual(encoded_export(a),encoded_export(b))

    def test_early_nul_in_first_encoded_name_byte(self):
        a=b'\x21\x22\x23\x24\x05\x00ABCDE'
        b=b'\x21\x22\x23\x24\x05\x00VWXYZ'
        self.assertTrue(m.nul_equal(a,b))

    def test_opcode_tables_do_not_conflict(self):
        self.assertFalse(set(m.PREFIX_OPCODES)&set(m.NUL_OPCODES))
        self.assertGreater(len(m.PREFIX_OPCODES)+len(m.NUL_OPCODES),20)

    def test_audit_rejects_invalid_sha(self):
        with self.assertRaisesRegex(ValueError,'unknown CD'):
            m.audit(b'x',b'y')


class OwnerExactFiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cd=os.getenv('RAYMAN2_RETAIL_EXE')
        gog=os.getenv('RAYMAN2_GOG_EXE')
        if not cd or not gog or not Path(cd).is_file() or not Path(gog).is_file():
            raise unittest.SkipTest('Private owner files not distributed in CI')
        cls.cd=Path(cd).read_bytes()
        cls.gog=Path(gog).read_bytes()

    def test_owner_pair(self):
        r=m.audit(self.cd,self.gog)
        self.assertEqual(r['records'],36)
        self.assertEqual(r['normal_records'],34)
        self.assertEqual([x['index'] for x in r['early_nul_records']],[3,26])
        self.assertEqual([x['first_nul_offset'] for x in r['early_nul_records']],[5,3])
        self.assertTrue(r['sha256_exact_samples_verified'])
        self.assertFalse(r['runtime_export_input_known'])

    def test_real_record_26_synthetic_alt_name(self):
        rec=raw_at(self.cd,layout(self.cd),m.BASE+26*m.STRIDE,76)
        alt=synthetic_record(rec[:4],'ReadFile')
        self.assertTrue(m.nul_equal(rec,alt))
        self.assertEqual(encoded_export(alt),'ReadFile')

    def test_mutated_branch_rejected(self):
        data=bytearray(self.cd)
        sections=layout(self.cd)
        rva,_,_,offset,_=sections['.text']
        data[offset + 0x448D24-(0x400000+rva)] ^= 1
        with self.assertRaises(ValueError):
            m.inspect(bytes(data),self.gog)

    def test_mutated_record_rejected(self):
        data=bytearray(self.cd)
        sections=layout(self.cd)
        rva,_,_,offset,_=sections['.data']
        data[offset + (m.BASE+26*m.STRIDE)-(0x400000+rva)+3] ^= 1
        with self.assertRaises(ValueError):
            m.inspect(bytes(data),self.gog)

    def test_file_hash_rejects_unrelated_mutation(self):
        data=bytearray(self.cd)
        data[0x220] ^= 1
        with self.assertRaisesRegex(ValueError,'unknown CD'):
            m.audit(bytes(data),self.gog)


if __name__=='__main__':
    unittest.main()
