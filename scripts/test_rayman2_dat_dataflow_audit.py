"""Synthetic controls for exact-SHA read-only DAT arithmetic and provenance."""
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rayman2_dat_dataflow_audit import (
    read_exact, pe_slice, x86_lines, anchor, initial_index, derived_probe_word,
)


class DataflowAuditTests(unittest.TestCase):
    @staticmethod
    def synthetic_pe():
        x=bytearray(0x300)
        x[:2]=b'MZ'
        struct.pack_into('<I',x,0x3c,0x80)
        x[0x80:0x84]=b'PE\0\0'
        struct.pack_into('<H',x,0x84,0x14c)
        struct.pack_into('<H',x,0x86,1)
        struct.pack_into('<H',x,0x94,0xe0)
        struct.pack_into('<H',x,0x98,0x10b)
        struct.pack_into('<I',x,0x98+28,0x400000)
        x[0x178:0x17d]=b'.text'
        struct.pack_into('<IIII',x,0x178+8,0x60,0x1000,0x80,0x200)
        x[0x200:0x280]=bytes(range(0x80))
        return x

    def test_start_index_boundary(self):
        self.assertEqual(initial_index(0,0),0)
        self.assertEqual(initial_index(255,3),1023)
        self.assertEqual(initial_index(1,255),7)
        self.assertEqual(initial_index(128,0xfc),512)

    def test_start_index_bijection(self):
        values={initial_index(i,j) for i in range(256) for j in range(4)}
        self.assertEqual(values,set(range(1024)))

    def test_start_index_strips_upper_selector_bits(self):
        for high in range(0,256,4):
            self.assertEqual(initial_index(7,high+2),30)

    def test_start_index_rejects_invalid(self):
        for a,b in [(-1,0),(256,0),(0,256),(0,-2)]:
            with self.assertRaises(ValueError):initial_index(a,b)

    def test_derived_value_no_loop_for_zero_index(self):
        self.assertEqual(derived_probe_word((3,4,5,6),0,17),(17-3)^4)

    def test_derived_value_one_iteration(self):
        self.assertEqual(derived_probe_word((3,4,5,6),1,17),(17-8)^(4+6))

    def test_derived_value_overflow(self):
        self.assertEqual(derived_probe_word((0xffffffff,0xffffffff,0xffffffff,0xffffffff),1023,0xffffffff),
                         (((0xffffffff-(0xffffffff+0xffffffff*1023))&0xffffffff)^((0xffffffff+0xffffffff*1023)&0xffffffff))&0xffffffff)

    def test_derived_against_independent_loop(self):
        rng=random.Random(20261114)
        for _ in range(8000):
            w=[rng.getrandbits(32) for __ in range(4)]
            sample=rng.getrandbits(32)
            n=rng.randrange(1024)
            a,b,c,d=w
            a=(a+c*n)&0xffffffff
            for _j in range(n):
                b=(b+d)&0xffffffff
            expected=((sample-a)&0xffffffff)^b
            self.assertEqual(derived_probe_word(tuple(w),n,sample),expected)

    def test_derived_invalid_width(self):
        for words,n,sample in [((1,2,3),1,4),((1,2,3,4),1024,4),((1,2,3,4),-1,4),((1,2,3,4),1,-1),((1,2,3,2**32),1,4)]:
            with self.assertRaises(ValueError):derived_probe_word(words,n,sample)

    def test_pe_slice_synthetic_valid(self):
        b=self.synthetic_pe()
        self.assertEqual(pe_slice(b,0x401000,10),bytes(range(10)))
        self.assertEqual(pe_slice(b,0x401040,10),bytes(range(0x40,0x4a)))

    def test_pe_reject_out_of_section_and_bad_dos(self):
        b=self.synthetic_pe()
        for v,n in [(0x400ff0,4),(0x40105f,2),(0x401100,1),(0x401040,0)]:
            with self.assertRaises(ValueError):pe_slice(b,v,n)
        b[:2]=b'??'
        with self.assertRaises(ValueError):pe_slice(b,0x401000,1)

    def test_pe_reject_bad_nt_header(self):
        b=self.synthetic_pe()
        b[0x80:0x84]=b'BAD!'
        with self.assertRaises(ValueError):pe_slice(b,0x401000,1)

    def test_asm_anchor_wrong_opcode(self):
        m={0x441234:(b'\x90','nop','')}
        anchor(m,0x441234,b'\x90','nop')
        with self.assertRaises(ValueError):anchor(m,0x441234,b'\xcc','int3')
        with self.assertRaises(ValueError):anchor(m,0x441235,b'\x90','nop')

    def test_objdump_line_decoder(self):
        class P:
            stdout='  44f0d4:\t2b cb \t\tsub ecx,ebx\n  44f0d6:\t33 ce \t\txor ecx,esi\n'
        with patch('rayman2_dat_dataflow_audit.subprocess.run',return_value=P()):
            got=x86_lines(Path('/dev/null'),0x44f0d4,0x44f0d8)
        self.assertEqual(got[0x44f0d4],(b'\x2b\xcb','sub','ecx,ebx'))
        self.assertEqual(got[0x44f0d6][1],'xor')

    def test_size_and_symlink_refused_before_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'sample'
            p.write_bytes(b'MZ')
            with self.assertRaises(ValueError):read_exact(p,'cd')
            link=Path(temp)/'link'
            link.symlink_to(p)
            with self.assertRaises(OSError):read_exact(link,'cd')


if __name__ == '__main__':
    unittest.main()
