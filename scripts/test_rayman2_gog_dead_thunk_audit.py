"""Synthetic PE/branch/census tests plus opt-in private exact-file integration."""
import importlib.util
import os
import struct
import unittest
from pathlib import Path

SCRIPT=Path(__file__).with_name('rayman2_gog_dead_thunk_audit.py')
spec=importlib.util.spec_from_file_location('dead_thunk',SCRIPT)
a=importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def mini_pe():
    raw=bytearray(0x800)
    raw[:2]=b'MZ';struct.pack_into('<I',raw,0x3c,0x80)
    raw[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<H',raw,0x84,0x14c)
    struct.pack_into('<H',raw,0x86,2)
    struct.pack_into('<H',raw,0x94,0xE0)
    opt=0x98
    struct.pack_into('<H',raw,opt,0x10b)
    struct.pack_into('<I',raw,opt+28,0x400000)
    table=0x178
    for k,(name,rva,foff) in enumerate((('.text',0x1000,0x200),('.data',0x2000,0x400))):
        off=table+k*40
        raw[off:off+8]=name.encode().ljust(8,b'\0')
        struct.pack_into('<IIII',raw,off+8,0x200,rva,0x200,foff)
        struct.pack_into('<I',raw,off+36,0x60000020 if k==0 else 0xc0000040)
    return raw


class DecoderTests(unittest.TestCase):
    def test_rel8_forward(self):
        self.assertEqual(a.relative_branch(b'\xeb\x05',0x401000),(2,0x401007))
    def test_rel8_backward(self):
        self.assertEqual(a.relative_branch(b'\xeb\xfa',0x401000),(2,0x400ffc))
    def test_rel32_forward(self):
        self.assertEqual(a.relative_branch(b'\xe9\x45\x01\x00\x00',0x401000),(5,0x40114a))
    def test_rel32_backward(self):
        self.assertEqual(a.relative_branch(b'\xe9\xf6\xff\xff\xff',0x401000),(5,0x400ffb))
    def test_not_jump(self):
        with self.assertRaises(ValueError):a.relative_branch(b'\xe8\0\0\0\0',0x401000)
    def test_truncated_jumps(self):
        for op in (b'',b'\xeb',b'\xe9',b'\xe9\xff'):
            with self.subTest(op=op),self.assertRaises(ValueError):a.relative_branch(op,0x401000)
    def test_find_all_patterns(self):
        self.assertEqual(a.matches(b'\xc6\x06\xa1\x00\xc6\x06\xa1',0x1000,a.TEMPLATES['esi-movxor']),
                         (0x401000,0x401004))
    def test_find_ansi_overlaps(self):
        self.assertEqual(a.matches(b'aaaa',0x1000,b'aa'),
                         (0x401000,0x401001,0x401002))
    def test_empty_signature(self):
        with self.assertRaises(ValueError):a.matches(b'aaa',0,b'')
    def test_mini_pe_two_sections(self):
        s=a.sections(mini_pe())
        self.assertEqual(set(s),{'.text','.data'})
        self.assertEqual(a.backed(mini_pe(),s,0x401000,2),b'\0\0')
    def test_reject_truncated(self):
        with self.assertRaises(ValueError):a.sections(b'MZ')
    def test_reject_non_pe(self):
        b=mini_pe();b[0x80:0x84]=b'NONE'
        with self.assertRaises(ValueError):a.sections(b)
    def test_reject_non_x86(self):
        b=mini_pe();struct.pack_into('<H',b,0x84,0x8664)
        with self.assertRaises(ValueError):a.sections(b)
    def test_reject_other_image_base(self):
        b=mini_pe();struct.pack_into('<I',b,0x98+28,0x500000)
        with self.assertRaises(ValueError):a.sections(b)
    def test_reject_unbacked_memory(self):
        b=mini_pe()
        with self.assertRaises(ValueError):a.backed(b,a.sections(b),0x420000,4)
    def test_no_out_of_bounds_read(self):
        b=mini_pe()
        with self.assertRaises(ValueError):a.backed(b,a.sections(b),0x401000,8193)
    def test_signature_classes_are_disjoint(self):
        groups=list(a.CD_SITES.values())
        sites=[site for group in groups for site in group]
        self.assertEqual((len(sites),len(set(sites))), (39,39))


class PrivateIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        x,y=os.environ.get('RAYMAN2_RETAIL_EXE'),os.environ.get('RAYMAN2_GOG_EXE')
        if not(x and y):raise unittest.SkipTest('Exact user-owned EXEs not present in CI')
        cls.cd=Path(x).read_bytes();cls.gog=Path(y).read_bytes()
    def test_exact_inputs(self):
        result=a.check(self.cd,self.gog)
        self.assertEqual((result['retail_total_bounded_writer_patterns'],
                          result['gog_active_total_bounded_writer_patterns']),(39,3))
        self.assertEqual(len(result['gog_preserved_but_entry_path_bypassed_writers']),3)
        self.assertTrue(all(row['gog_entry_path_bypasses_scrub']
                            for row in result['gog_preserved_but_entry_path_bypassed_writers']))
    def test_mutated_retail_writer_rejected(self):
        b=bytearray(self.cd);s=a.sections(b)
        off=s['.text'][3]+(0x448B45-0x401000)
        b[off]^=1
        with self.assertRaisesRegex(ValueError,'retail esi-movxor'):
            a.check(bytes(b),self.gog,strict_sha=False)
    def test_mutated_gog_bypass_rejected(self):
        b=bytearray(self.gog);s=a.sections(b)
        off=s['.text'][3]+(0x47B388-0x401000)
        b[off]=0x90
        with self.assertRaisesRegex(ValueError,'unconditional near jump'):
            a.check(self.cd,bytes(b),strict_sha=False)
    def test_mutated_gog_archive_rejected(self):
        b=bytearray(self.gog);s=a.sections(b)
        b[s['.extra'][3]+0x1000+10]^=1
        with self.assertRaisesRegex(ValueError,'archive mismatches'):
            a.check(self.cd,bytes(b),strict_sha=False)
    def test_gog_section_exec_flag_rejected(self):
        b=bytearray(self.gog)
        n=struct.unpack_from('<I',b,0x3c)[0]
        o=n+24+struct.unpack_from('<H',b,n+20)[0]
        struct.pack_into('<I',b,o+3*40+36,0x60000040)
        with self.assertRaisesRegex(ValueError,'unexpectedly executable'):
            a.check(self.cd,bytes(b),strict_sha=False)
    def test_hash_gate(self):
        with self.assertRaisesRegex(ValueError,'exact owner'):
            a.check(self.cd[:-1],self.gog)


if __name__=='__main__':unittest.main()
