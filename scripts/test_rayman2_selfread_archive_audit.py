"""Synthetic and real-input controls of the archive-mapping logic, no game bytes committed."""
import importlib
import pathlib
import struct
import tempfile
import unittest
from rayman2_selfread_archive_audit import (
    locked_read, sections, by_rva, archive_relation, assess, EXPECTED,
)

BASE=0x400000
TEXT_RVA=0x1000
TEXT_SIZE=0x9A200
EXTRA_RVA=0x117000
EXTRA_SIZE=0x9C000


def pe32(secs):
    """Construct synthetic PE32 sections (name, RVA, bytes, file_offset, flags)."""
    end=max(off+len(payload) for _,_,payload,off,_ in secs)
    out=bytearray(max(end,0x400))
    out[0:2]=b'MZ'
    struct.pack_into('<I',out,0x3c,0x80)
    out[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<H',out,0x84,0x14c)
    struct.pack_into('<H',out,0x86,len(secs))
    struct.pack_into('<H',out,0x94,0xe0)
    struct.pack_into('<H',out,0x98,0x10b)
    struct.pack_into('<I',out,0x98+28,BASE)
    for i,(name,rva,payload,off,flags) in enumerate(secs):
        p=0x178+40*i
        out[p:p+8]=name.encode().ljust(8,b'\0')
        struct.pack_into('<IIII',out,p+8,len(payload),rva,len(payload),off)
        struct.pack_into('<I',out,p+36,flags)
        out[off:off+len(payload)]=payload
    return bytes(out)


def make_pair():
    code=bytearray(b'\x90'*TEXT_SIZE)
    def put(va,b):code[va-(BASE+TEXT_RVA):va-(BASE+TEXT_RVA)+len(b)]=b
    for va in (0x470051,0x47b1c3):put(va,bytes.fromhex('99 b9 55 04 00 00'))
    for va in (0x4700ae,0x47b220):put(va,b'\xff\xd6');put(va-2,b'\x6a\x00')
    put(0x4700b3,bytes.fromhex('89 44 24 14'))
    put(0x47b225,bytes.fromhex('89 44 24 10'))
    put(0x47b2a5,bytes.fromhex('8b 54 24 10 8b 1c 32'))
    g=bytearray(code)
    for va in (0x470051,0x47b1c3):
        i=va-(BASE+TEXT_RVA)
        g[i:i+7]=b'\xb8'+struct.pack('<I',BASE+EXTRA_RVA)+b'\xeb\x5b'
    archive=b'\0'*TEXT_RVA+code+b'\0'*(EXTRA_SIZE-TEXT_RVA-len(code))
    cd=pe32([('.text',TEXT_RVA,code,0x400,0x60000020)])
    gog=pe32([('.text',TEXT_RVA,g,0x1000,0x60000020),
              ('.extra',EXTRA_RVA,archive,0xc0000,0x40000040)])
    return cd,gog


class SelfReadArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.cd,cls.gog=make_pair()

    def test_synthetic_success(self):
        r=assess(self.cd,self.gog)
        self.assertTrue(r['archive_mapping']['exact_original_text_bytes'])
        self.assertEqual(len(r['two_redirects']),2)

    def test_exact_archival_layout(self):
        r=assess(self.cd,self.gog)
        self.assertEqual(r['archive_mapping']['archive_padding_prefix'],4096)
        self.assertEqual(r['archive_mapping']['archive_padding_suffix'],3584)

    def test_fake_va_translations(self):
        r=assess(self.cd,self.gog)
        self.assertEqual(r['source_rva_matches_archive_rva'][0]['gog_archive_va'],'0x587051')

    def test_nonexec_required(self):
        b=bytearray(self.gog)
        # The second section flags are at 0x178 + 40 + 36.
        struct.pack_into('<I',b,0x178+40+36,0x60000040)
        with self.assertRaisesRegex(ValueError,'nonexecutable'):
            assess(self.cd,b)

    def test_corrupted_archive_rejected(self):
        b=bytearray(self.gog);b[0xc0000+0x3000]^=1
        with self.assertRaisesRegex(ValueError,'not an exact copy'):
            assess(self.cd,b)

    def test_prefix_rejected(self):
        b=bytearray(self.gog);b[0xc0000]^=1
        with self.assertRaisesRegex(ValueError,'nonzero archive prefix'):
            assess(self.cd,b)

    def test_trailer_rejected(self):
        b=bytearray(self.gog);b[0xc0000+EXTRA_SIZE-1]^=1
        with self.assertRaisesRegex(ValueError,'nonzero archive trailer'):
            assess(self.cd,b)

    def test_redirect_byte_rejected(self):
        b=bytearray(self.gog);b[0x1000+0x470051-(BASE+TEXT_RVA)]^=1
        with self.assertRaisesRegex(ValueError,'archive redirect'):
            assess(self.cd,b)

    def test_archive_base_literal_scan_rejects_extra_reference(self):
        b=bytearray(self.gog);b[0x1000+0x4000:0x1000+0x4004]=struct.pack('<I', BASE+EXTRA_RVA)
        with self.assertRaisesRegex(ValueError,'archive base references'):
            assess(self.cd,b)

    def test_module_base_indexed_reader_required(self):
        b=bytearray(self.gog);b[0x1000+0x47b2a9-(BASE+TEXT_RVA)]^=1
        with self.assertRaisesRegex(ValueError,'base-index'):
            assess(self.cd,b)

    def test_by_rva_bounds(self):
        _,s=sections(self.cd)
        with self.assertRaisesRegex(ValueError,'uniquely'):
            by_rva(self.cd,s,0x1000-20,2)
        with self.assertRaisesRegex(ValueError,'invalid'):
            by_rva(self.cd,s,0x1000,0)

    def test_short_section_table(self):
        with self.assertRaisesRegex(ValueError,'invalid'):
            sections(self.cd[:0x170])

    def test_no_header(self):
        with self.assertRaisesRegex(ValueError,'not MZ'):
            sections(b'not a PE')

    def test_archive_relation_reject_short(self):
        with self.assertRaisesRegex(ValueError,'missing aligned'):
            archive_relation(b'\x90'*8,b'\0'*16,0x1000)

    def test_locked_read_wrong_sample(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'x.exe';p.write_bytes(b'MZ')
            with self.assertRaisesRegex(ValueError,'unrecognized size'):
                locked_read(p,'cd')

    def test_locked_read_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'x.exe';p.write_bytes(b'MZ')
            q=pathlib.Path(d)/'y.exe';q.symlink_to(p)
            with self.assertRaises(OSError):
                locked_read(q,'cd')


if __name__=='__main__':unittest.main()
