"""Reversible V4 42-byte DAT read-skip experiment tests; no game distributed."""
import hashlib, importlib.util, pathlib, struct, tempfile, unittest
from unittest.mock import patch as setmock

SRC=pathlib.Path(__file__).with_name('rayman2_dat_read_probe_v4.py')
spec=importlib.util.spec_from_file_location('v4',SRC)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fixture():
    b=bytearray(m.INPUT_SIZE)
    b[:2]=b'MZ';struct.pack_into('<I',b,0x3c,0x80)
    b[0x80:0x84]=b'PE\0\0'
    struct.pack_into('<HH',b,0x84,0x14c,3)
    struct.pack_into('<H',b,0x94,0xe0)
    struct.pack_into('<H',b,0x98,0x10b)
    struct.pack_into('<I',b,0x98+28,0x400000)
    for i,(name,vs,rva,rs,raw) in enumerate(((b'.text',0x9a200,0x1000,0x9a200,0x400),
                           (b'.rdata',0x3000,0x9c000,0x3000,0x9a600),
                           (b'.data',0x776d0,0x9f000,0x7c00,0x9d600))):
        p=0x178+i*40
        b[p:p+8]=name.ljust(8,b'\0')
        struct.pack_into('<IIII',b,p+8,vs,rva,rs,raw)
    for va,pat in ((m.FIRST_VA,m.FIRST_OLD),(m.SECOND_VA,m.SECOND_OLD),
                   (m.FIRST_FOLLOW_VA,m.FIRST_FOLLOW),
                   (m.SECOND_CALL_VA,m.SECOND_CALL),
                   (m.TAIL_VA,m.TAIL_EXPECTED)):
        off=m.text_offset(b,va,len(pat));b[off:off+len(pat)]=pat
    return bytes(b)


def expected(data):
    b=bytearray(data)
    for va,new in ((m.FIRST_VA,m.FIRST_NEW),(m.SECOND_VA,m.SECOND_NEW)):
        off=m.text_offset(b,va,len(new));b[off:off+len(new)]=new
    return bytes(b)


class Tests(unittest.TestCase):
    def test_first_40_bytes_no_longer_read(self):
        self.assertEqual(len(m.FIRST_OLD),40)
        self.assertEqual(m.FIRST_NEW,b'\x90'*40)
    def test_second_jump_target(self):
        self.assertEqual(m.SECOND_NEW,b'\xeb\x23')
        self.assertEqual(m.SECOND_VA+2+0x23,m.TAIL_VA)
    def test_fixture_pe_offsets(self):
        f=fixture()
        self.assertEqual(m.anchored(f,m.FIRST_VA,m.FIRST_OLD,'test'),0x4e502)
        self.assertEqual(m.anchored(f,m.SECOND_VA,m.SECOND_OLD,'test'),0x4e5cc)
    def test_synthetic_exact_delta(self):
        f=fixture();out=expected(f)
        with setmock.object(m,'INPUT_SHA256',m.sha256(f)),setmock.object(m,'OUTPUT_SHA256',m.sha256(out)):
            result,report=m.patch(f)
        self.assertEqual(result,out)
        self.assertEqual(report['changed_byte_count'],42)
        self.assertTrue(report['second_DAT_CreateFileA_and_error_handling_preserved'])
    def test_source_unchanged(self):
        f=fixture();orig=bytes(f)
        out=expected(f)
        with setmock.object(m,'INPUT_SHA256',m.sha256(f)),setmock.object(m,'OUTPUT_SHA256',m.sha256(out)):
            m.patch(f)
        self.assertEqual(f,orig)
    def test_wrong_source_sha(self):
        with self.assertRaisesRegex(ValueError,'unknown input'):m.patch(fixture())
    def test_wrong_output_sha(self):
        f=fixture()
        with setmock.object(m,'INPUT_SHA256',m.sha256(f)):
            with self.assertRaisesRegex(ValueError,'unexpected V4 output SHA'):m.patch(f)
    def check_anchor(self,va,label):
        f=bytearray(fixture());f[m.text_offset(f,va,1)]=0xff
        with setmock.object(m,'INPUT_SHA256',m.sha256(f)):
            with self.assertRaisesRegex(ValueError,label):m.patch(bytes(f))
    def test_first_anchor(self): self.check_anchor(m.FIRST_VA,'first DAT read')
    def test_second_anchor(self): self.check_anchor(m.SECOND_VA,'second DAT read')
    def test_v3_selector_anchor(self): self.check_anchor(m.FIRST_FOLLOW_VA,'V3 arithmetic')
    def test_open_guard_anchor(self): self.check_anchor(m.SECOND_CALL_VA,'second DAT open guard')
    def test_epilogue_anchor(self): self.check_anchor(m.TAIL_VA,'second DAT epilogue')
    def test_non_pe_invalid(self):
        x=bytearray(fixture());x[:2]=b'??'
        with self.assertRaisesRegex(ValueError,'MZ'):m.text_offset(x,m.FIRST_VA,40)
    def test_wrong_arch_invalid(self):
        x=bytearray(fixture());x[0x84:0x86]=b'\x64\x86'
        with self.assertRaisesRegex(ValueError,'PE32 section'):m.text_offset(x,m.FIRST_VA,40)
    def test_outside_section_invalid(self):
        with self.assertRaisesRegex(ValueError,'beyond file-backed text'):m.text_offset(fixture(),0x501000,40)
    def test_no_output_on_dry_run(self):
        f=fixture();out=expected(f)
        with tempfile.TemporaryDirectory() as t:
            a=pathlib.Path(t)/'in.exe';b=pathlib.Path(t)/'out.exe';a.write_bytes(f)
            with setmock.object(m,'INPUT_SHA256',m.sha256(f)),setmock.object(m,'OUTPUT_SHA256',m.sha256(out)):
                self.assertEqual(m.main([str(a),str(b),'--dry-run']),0)
            self.assertFalse(b.exists());self.assertEqual(a.read_bytes(),f)
    def test_refuse_existing_output(self):
        with tempfile.TemporaryDirectory() as t:
            a=pathlib.Path(t)/'in.exe';b=pathlib.Path(t)/'out.exe'
            a.write_bytes(fixture());b.write_text('not touched')
            with self.assertRaises(SystemExit):m.main([str(a),str(b)])
            self.assertEqual(b.read_text(),'not touched')
    def test_refuse_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            a=pathlib.Path(t)/'in.exe';b=pathlib.Path(t)/'link.exe';c=pathlib.Path(t)/'out.exe'
            a.write_bytes(fixture());b.symlink_to(a)
            with self.assertRaises(SystemExit):m.main([str(b),str(c)])
    def test_real_original_cd_chain_and_gog_reference(self):
        private=pathlib.Path('/mnt/data/rayman2_research/Rayman2(3).exe')
        gog=pathlib.Path('/mnt/data/rayman2_research/rayman2(4).exe')
        tools=pathlib.Path('/mnt/data/unsafedisk_v3')
        if not private.exists() or not gog.exists() or not tools.is_dir():
            self.skipTest('exact owner-owned CD and GOG comparison absent from public CI')
        import sys
        sys.path.insert(0,str(tools))
        from rayman2_portable_cd_probe import patch as v1
        from rayman2_dat_name_probe_v2 import patch as v2
        from rayman2_dat_offset_probe_v3 import patch as v3
        orig=private.read_bytes()
        self.assertEqual(m.sha256(orig),'7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3')
        one,_=v1(orig);two,_=v2(one);three,_=v3(two)
        result,meta=m.patch(three)
        self.assertEqual(meta['output_sha256'],m.OUTPUT_SHA256)
        self.assertEqual(result,expected(three))
        self.assertEqual(m.sha256(three),m.INPUT_SHA256)
        # Independently compare just two *active* GOG code spans; not data, not .extra.
        modified=gog.read_bytes()
        self.assertEqual(m.sha256(modified),'9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713')
        for va,pat in ((m.FIRST_VA,m.FIRST_NEW),(m.SECOND_VA,m.SECOND_NEW)):
            offset=va-0x400000 # only the active GOG .text maps file-offset RVA
            self.assertEqual(modified[offset:offset+len(pat)],pat)
        offsets=[i for i,(a,b) in enumerate(zip(three,result)) if a!=b]
        self.assertEqual(len(offsets),42)
        self.assertEqual(offsets[:40],list(range(0x4e502,0x4e52a)))
        self.assertEqual(offsets[40:],[0x4e5cc,0x4e5cd])

if __name__=='__main__':unittest.main()
