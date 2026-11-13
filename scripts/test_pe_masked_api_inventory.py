"""Synthetic obfuscated-name fixtures; no original game data."""
import unittest
from pe_masked_api_inventory import decode_name, file_backed_bytes, inspect


def encode_name(name, a=0x18,b=0xBC,da=0x14,db=0x05, stride=45):
    src=name.encode('ascii')
    assert len(src) <= stride-5
    out=bytearray((a,b,da,db,len(src)))
    for ch in src:
        out.append(((ch ^ b)+a)&0xff)
        a=(a+da)&0xff;b=(b+db)&0xff
    return bytes(out).ljust(stride,b'\0')


def fake_pe():
    blob=bytearray(0x500)
    modules=[encode_name('KERNEL32.dll'),encode_name('PSAPI.dll')]
    apis=[('ReadFile',0),('EnumProcesses',1),('GetFileSize',0)]
    for i, name in enumerate(modules):
        blob[0x20+i*45:0x20+(i+1)*45]=name
    for i,(name,mod) in enumerate(apis):
        raw=bytearray(encode_name(name,stride=76))
        raw[0x34:0x38]=mod.to_bytes(4,'little')
        blob[0x120+i*76:0x120+(i+1)*76]=raw
    return {'image_base':0x400000,'sha256':'synthetic','sections':{
        '.data':{'rva':0x1000,'raw_len':len(blob),'contents':bytes(blob)}}}


class DecoderTests(unittest.TestCase):
    def test_key_deltas_recover_name(self):
        self.assertEqual(decode_name(encode_name('Kernel32.dll')), 'Kernel32.dll')
        self.assertEqual(
            decode_name(encode_name('EnumProcessModules',0xff,0xfe,0x37,0xa9,76)),
            'EnumProcessModules')

    def test_reject_bad_length_and_controls(self):
        for invalid in (b'\0'*5,b'\0'*6,bytes([0,0,0,0,40,0])):
            with self.assertRaises(ValueError):
                decode_name(invalid)

    def test_bounded_va_mapping(self):
        p=fake_pe()
        self.assertEqual(file_backed_bytes(p,0x401020,45),encode_name('KERNEL32.dll'))
        with self.assertRaises(ValueError):
            file_backed_bytes(p,0x501020,45)

    def test_api_names_module_indexes_and_zero_slots(self):
        r=inspect(fake_pe(),0x401020,45,2,0x401120,76,3,0x34,0x30)
        self.assertEqual(
            [x['api_name'] for x in r['apis']],
            ['ReadFile','EnumProcesses','GetFileSize'])
        self.assertEqual(
            [x['module_name'] for x in r['apis']],
            ['KERNEL32.dll','PSAPI.dll','KERNEL32.dll'])
        self.assertEqual(r['zero_on_disk_slots'],3)
        self.assertFalse(r['runtime_exports_resolved'])

    def test_invalid_module_reference(self):
        p=fake_pe()
        blob=bytearray(p['sections']['.data']['contents'])
        blob[0x120+0x34:0x120+0x38]=(9).to_bytes(4,'little')
        p['sections']['.data']['contents']=bytes(blob)
        with self.assertRaisesRegex(ValueError,'missing module'):
            inspect(p,0x401020,45,2,0x401120,76,3,0x34,0x30)

    def test_reject_excessive_config(self):
        with self.assertRaises(ValueError):
            inspect(fake_pe(),0x401020,45,0,0x401120,76,3,0x34,0x30)
        with self.assertRaises(ValueError):
            inspect(fake_pe(),0x401020,45,2,0x401120,76,257,0x34,0x30)
        with self.assertRaises(ValueError):
            inspect(fake_pe(),0x401020,45,2,0x401120,76,3,76,0x30)


if __name__=='__main__':
    unittest.main()
