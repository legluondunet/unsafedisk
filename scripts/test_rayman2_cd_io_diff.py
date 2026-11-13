"""Synthetic PE-data tests; exact commercial samples are never fixtures."""
import os
from pathlib import Path
import struct
import tempfile
import unittest

from rayman2_cd_io_diff import (
    GOG_SHA256, RETAIL_SHA256, SITES, TABLE_VA,
    inspect_pair, inspect_stream_read_variants, read_file_table, safe_read,
    va_bytes, va_cstr, STREAM_BRANCH_BYTES, STREAM_PRESERVED, STREAM_REMOVED,
)


class FileIoDiffTests(unittest.TestCase):
    def test_hash_gate_rejects_wrong_inputs(self):
        with self.assertRaisesRegex(ValueError, 'input hashes'):
            inspect_pair(b'not a retail file', b'not a GOG file')

    def test_known_hashes_are_distinct(self):
        self.assertEqual(len(RETAIL_SHA256), 64)
        self.assertEqual(len(GOG_SHA256), 64)
        self.assertNotEqual(RETAIL_SHA256, GOG_SHA256)

    def test_byte_mapping_for_shifted_sections(self):
        image = b'x' * 9 + b'xyz' + b'x' * 10
        h = {'image_base': 0x400000,
             'sections':[{'rva':0x1000,'raw_off':4,'raw_size':15}]}
        self.assertEqual(va_bytes(image,h,0x401005,3), b'xyz')

    def test_out_of_bounds_va_refused(self):
        h = {'image_base': 0x400000,
             'sections':[{'rva':0x1000,'raw_off':0,'raw_size':10}]}
        with self.assertRaises(ValueError):
            va_bytes(b'1234567890',h,0x401009,3)
        with self.assertRaises(ValueError):
            va_bytes(b'1234567890',h,0x401000,513)

    def table_fixture(self, duplicate=False, corrupt=False):
        h = {'image_base':0x400000,'sections':[{'rva':0xA0000,
              'raw_off':0x1000,'raw_size':0x3000}]}
        data = bytearray(0x4000)
        groups = ['LEVELS','MAP','TEXTURES','ANIMS','SOUNDS','MUSIC','GRAPHICS','MENU']
        names = [f'{group}{level}.DAT' for level in range(3) for group in groups]
        for i,name in enumerate(names):
            name_va = 0x4A2300 + i*24
            if duplicate and i == 1:
                name_va = 0x4A2300
            struct.pack_into('<I',data,0x1000+TABLE_VA-0x4A0000+i*4,name_va)
            if corrupt and i == 7:
                name='BAD.PRG'
            if not (duplicate and i == 1):
                encoded = name.encode() + b'\0'
                start=0x1000+name_va-0x4A0000
                data[start:start+len(encoded)] = encoded
        return bytes(data),h,names

    def test_extract_exact_twenty_four_unique_names(self):
        data,h,names = self.table_fixture()
        self.assertEqual(read_file_table(data,h), names)

    def test_reject_duplicate_table_name(self):
        data,h,_=self.table_fixture(duplicate=True)
        with self.assertRaisesRegex(ValueError,'duplicate'):
            read_file_table(data,h)

    def test_reject_non_data_table_name(self):
        data,h,_=self.table_fixture(corrupt=True)
        with self.assertRaisesRegex(ValueError,'unexpected'):
            read_file_table(data,h)

    def test_unterminated_va_string(self):
        h={'image_base':0x400000,'sections':[{'rva':0x1000,'raw_off':0,'raw_size':5}]}
        with self.assertRaisesRegex(ValueError,'unterminated'):
            va_cstr(b'ABCDE',h,0x401000,max_len=5)

    def test_site_variants_all_different(self):
        for va,description,retail,gog in SITES:
            with self.subTest(va=hex(va)):
                self.assertNotEqual(retail,gog)
                self.assertTrue(description)
                self.assertLessEqual(max(len(retail),len(gog)),7)

    def stream_fixture(self):
        """Synthetic x86 layouts only: no original game code in fixtures."""
        size=0x51000
        retail=bytearray(b'\x90'*size)
        gog=bytearray(b'\x90'*size)
        hdr={'image_base':0x400000,'sections':[{'rva':0x1000,
                 'raw_off':0,'raw_size':size}]}
        def store(buf,va,raw):
            offset=va-0x401000
            buf[offset:offset+len(raw)] = raw
        for begin,end,_ in STREAM_REMOVED:
            store(gog,begin,b'\xcc'*(end-begin))
        for addr,(before,after) in STREAM_BRANCH_BYTES.items():
            store(retail,addr,bytes([before]))
            store(gog,addr,bytes([after]))
        common={
            0x450A41:'B8 10 11 45 00',
            0x450A46:'75',
            0x450A48:'B8 90 10 45 00',
            0x450A64:'B8 00 13 45 00',
            0x450A69:'75',
            0x450A6B:'B8 C0 12 45 00',
            0x450A4D:'89 46 24',
            0x450A70:'89 46 24',
            0x450A8E:'E8 6D FF FF FF',
            0x450DD5:'FF 53 24',
            0x450C16:'FF 15 58 C0 49 00',
            0x450C1C:'89 06',
            0x4510AE:'FF 15 4C C0 49 00',
            0x4512DA:'FF 15 4C C0 49 00',
            0x4510CD:'8A 4F 15 8A 16 32 D1',
        }
        for addr,code in common.items():
            for buf in (retail,gog):
                store(buf,addr,bytes.fromhex(code))
        for addr,code in {
            0x4511E2:'FF D6',0x4513BB:'FF D6',
            0x45126B:'8A 4B 15 8A 17 32 D1',
        }.items():
            store(retail,addr,bytes.fromhex(code))
        return retail,gog,hdr

    def test_stream_synthetic_two_selector_byte_changes(self):
        r,g,h=self.stream_fixture()
        report=inspect_stream_read_variants(bytes(r),bytes(g),h,h)
        self.assertEqual(report['changed_initializer_byte_count'],2)
        self.assertEqual([p['retail'] for p in report['changed_branch_displacements']],
                         [0x28,0x05])
        self.assertEqual(len(report['preserved_direct_ReadFile_variants']),2)
        self.assertEqual(len(report['gog_disabled_masked_ReadFile_variants']),2)

    def test_stream_rejects_non_Int3_gog_masked_reader(self):
        r,g,h=self.stream_fixture()
        at=0x451110-0x401000
        g[at]=0x90
        with self.assertRaisesRegex(ValueError,'retained masked reader'):
            inspect_stream_read_variants(bytes(r),bytes(g),h,h)

    def test_stream_rejects_unexpected_branch_change(self):
        r,g,h=self.stream_fixture()
        at=0x450A47-0x401000
        g[at]=0x03
        with self.assertRaisesRegex(ValueError,'selection edits'):
            inspect_stream_read_variants(bytes(r),bytes(g),h,h)

    def test_stream_rejects_bad_plain_ReadFile_IAT_call(self):
        r,g,h=self.stream_fixture()
        at=0x4512DA-0x401000
        g[at]=0x90
        with self.assertRaisesRegex(ValueError,'mismatched stream instruction'):
            inspect_stream_read_variants(bytes(r),bytes(g),h,h)

    def test_stream_exact_real_pair_if_available(self):
        folder=Path(os.environ.get('UNSAFEDISK_SAMPLES','/no-private-samples'))
        retail=folder/'Rayman2(3).exe'
        gog=folder/'rayman2(4).exe'
        if not (retail.is_file() and gog.is_file()):
            self.skipTest('proprietary Rayman 2 test samples not available')
        report=inspect_pair(safe_read(retail),safe_read(gog))
        details=report['stream_reader_variants']
        self.assertEqual(details['changed_initializer_byte_count'],2)
        self.assertEqual(details['shared_instruction_anchors_checked'],15)
        self.assertEqual(details['original_only_instruction_anchors_checked'],3)

    def test_safe_read_rejects_symlink(self):
        if not hasattr(os,'symlink'):self.skipTest('no symlink support')
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'sample'
            path.write_bytes(b'fake')
            link = Path(root) / 'link'
            try:link.symlink_to(path)
            except OSError:self.skipTest('symlink unsupported')
            with self.assertRaisesRegex(ValueError,'symlink'):
                safe_read(link)

    def test_safe_read_regular(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'sample'
            path.write_bytes(b'ordinary synthetic data')
            self.assertEqual(safe_read(path),b'ordinary synthetic data')


if __name__ == '__main__':unittest.main()
