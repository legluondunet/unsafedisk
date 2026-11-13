"""Synthetic PE-data tests; exact commercial samples are never fixtures."""
import os
import hashlib
import random
from pathlib import Path
import struct
import tempfile
import unittest

from rayman2_cd_io_diff import (
    GOG_SHA256, RETAIL_SHA256, SITES, TABLE_VA,
    inspect_pair, inspect_stream_read_variants, read_file_table, safe_read,
    va_bytes, va_cstr, STREAM_BRANCH_BYTES, STREAM_PRESERVED, STREAM_REMOVED,
    stream_xor_step32, stream_xor_transform, inspect_stream_xor_x86,
    STREAM_XOR_SEED, STREAM_XOR_SALT, STREAM_XOR_DIRECT_ANCHORS,
    STREAM_XOR_RETAIL_MASKED_ANCHORS,
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
        xor_report=report['stream_read_xor_exact_x86']
        self.assertEqual(xor_report['naive_modulo_first_state_divergence_offset'],70)
        self.assertEqual(xor_report['naive_modulo_first_key_divergence_offset'],71)
        self.assertEqual(xor_report['direct_reader_opcodes_verified_per_executable'],11)

    @staticmethod
    def reference_x86_step(s):
        """Independent register-level model; mirrors each original operation."""
        mod = 1 << 32
        registers = {'ecx':s ^ 0x075BD924,'eax':0x069C16BD,'edx':0}
        product = registers['eax'] * registers['ecx']
        registers['edx'] = (product // mod) % mod
        registers['eax'] = registers['ecx']
        registers['ecx'] = (registers['ecx'] * 16807) % mod
        registers['eax'] = (registers['eax'] - registers['edx']) % mod
        registers['eax'] //= 2
        registers['eax'] = (registers['eax'] + registers['edx']) % mod
        registers['eax'] //= 65536
        registers['edx'] = (-registers['eax']) % mod
        registers['edx'] = (registers['edx'] * (2**31)) % mod
        registers['edx'] = (registers['edx'] - registers['eax']) % mod
        registers['ecx'] = (registers['ecx'] - registers['edx']) % mod
        return registers['ecx']

    def test_stream_xor_first_16_bytes(self):
        self.assertEqual(stream_xor_transform(bytes(16))[0].hex(),
                         'ccc5dfcceebdf8ceaf15bbae35a91340')

    def test_stream_xor_256_byte_sha256(self):
        output,state=stream_xor_transform(bytes(256))
        self.assertEqual(hashlib.sha256(output).hexdigest(),
                         '8eeed8d4e85f19dd1a78d818003c41056e15755dd1bff524afb49c8cda0bc957')
        self.assertEqual(state,0x2A88DE34)

    def test_stream_xor_512_byte_sha256(self):
        output,state=stream_xor_transform(bytes(512))
        self.assertEqual(hashlib.sha256(output).hexdigest(),
                         '1f91a5cac736fa9301f3a256fda143ede53fb3edf862aa62adc579bbb31691c5')
        self.assertEqual(state,0x68D6D7DE)

    def test_stream_xor_state_matches_independent_x86_interpreter(self):
        random_states=random.Random(8271)
        inputs=[0,1,0xFFFFFFFF,0x7FFFFFFF,STREAM_XOR_SEED,0x61DB5B46]
        inputs.extend(random_states.getrandbits(32) for _ in range(10000))
        for state in inputs:
            self.assertEqual(stream_xor_step32(state),self.reference_x86_step(state))

    def test_park_miller_modulo_diverges_after_70_states(self):
        actual=naive=STREAM_XOR_SEED
        for position in range(70):
            self.assertEqual(actual,naive,msg=f'early divergence at {position}')
            actual=stream_xor_step32(actual)
            naive=((naive^STREAM_XOR_SALT)*16807)%2147483647
        self.assertEqual(actual,0xFEF02481)
        self.assertEqual(naive,0x7EF02480)
        self.assertNotEqual(actual,naive)

    def test_park_miller_modulo_first_differs_in_key_at_71(self):
        actual=naive=STREAM_XOR_SEED
        for position in range(71):
            self.assertEqual((actual>>8)&255,(naive>>8)&255,
                             msg=f'key differs at byte {position}')
            actual=stream_xor_step32(actual)
            naive=((naive^STREAM_XOR_SALT)*16807)%2147483647
        self.assertNotEqual((actual>>8)&255,(naive>>8)&255)

    def test_stream_xor_transform_is_involutive(self):
        plain=bytes(range(256))*2
        cipher,_=stream_xor_transform(plain)
        recovered,_=stream_xor_transform(cipher)
        self.assertEqual(recovered,plain)

    def test_stream_xor_state_resumption_after_split_read(self):
        input_bytes=bytes(range(256))*4
        whole,final=stream_xor_transform(input_bytes)
        for split in (0,1,2,16,69,70,71,72,255,512,1024):
            with self.subTest(split=split):
                start,state=stream_xor_transform(input_bytes[:split])
                end,resumed=stream_xor_transform(input_bytes[split:],state)
                self.assertEqual(start+end,whole)
                self.assertEqual(resumed,final)

    def test_stream_xor_refuses_nonbyte_data(self):
        for bad in (None,False,12,'text',bytearray(b'a')):
            with self.subTest(type=type(bad)),self.assertRaisesRegex(ValueError,'bytes'):
                stream_xor_transform(bad)

    def test_stream_xor_refuses_invalid_states(self):
        for bad in (-1,2**32,True,1.0,None):
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'unsigned 32-bit'):
                stream_xor_step32(bad)
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'unsigned 32-bit'):
                stream_xor_transform(b'',bad)

    def test_stream_xor_empty_input_keeps_state(self):
        self.assertEqual(stream_xor_transform(b'',0xFFFFFFFF),
                         (b'',0xFFFFFFFF))

    def test_stream_xor_original_gog_anchor_inventory(self):
        self.assertEqual(len(STREAM_XOR_DIRECT_ANCHORS),11)
        self.assertEqual(len(STREAM_XOR_RETAIL_MASKED_ANCHORS),9)

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
