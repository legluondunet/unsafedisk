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
    STREAM_WORD_CHECK_ANCHORS, STREAM_WORD_CHECK_COMPARE_ANCHORS,
    stream_word_xor_checksum, inspect_stream_word_checksum,
    SNAPSHOT_CHECKSUM_ANCHORS, SNAPSHOT_TEMPLATES, REFERENCE_SUFFIXES,
    inspect_snapshot_checksum_provenance,
    SNAPSHOT_INDEX_ANCHORS, snapshot_inversion_address,
    inspect_snapshot_index_alias,
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
        self.assertEqual(xor_report['direct_reader_opcodes_verified_per_executable'],16)
        self.assertTrue(xor_report['XOR_enabled_only_with_stream_flag_bit_1'])
        self.assertTrue(xor_report['short_ReadFile_byte_count_skips_XOR_loop'])

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
        self.assertEqual(len(STREAM_XOR_DIRECT_ANCHORS),16)
        self.assertEqual(len(STREAM_XOR_RETAIL_MASKED_ANCHORS),9)

    def test_word_checksum_exact_le_dword(self):
        self.assertEqual(stream_word_xor_checksum(b'\x01\x02\x03\x04'),
                         (0x04030201,b''))

    def test_word_checksum_pending_not_zero_padded(self):
        value,pending=stream_word_xor_checksum(b'\x01\x02\x03')
        self.assertEqual((value,pending),(0,b'\x01\x02\x03'))
        self.assertEqual(stream_word_xor_checksum(b'\x04',value,pending),
                         (0x04030201,b''))

    def test_word_checksum_two_equal_dwords_cancel(self):
        self.assertEqual(stream_word_xor_checksum(b'abcdabcd'),(0,b''))

    def test_word_checksum_chunked_equal_whole(self):
        import random
        rng=random.Random(7127)
        for count in range(0,256):
            payload=bytes(rng.getrandbits(8) for _ in range(count))
            expected=stream_word_xor_checksum(payload)
            got=(0,b'')
            for start in range(0,count,3):
                got=stream_word_xor_checksum(payload[start:start+3],*got)
            self.assertEqual(got,expected)

    def test_word_checksum_skips_unsuccessful_callback(self):
        self.assertEqual(
            stream_word_xor_checksum(b'123',0x10203040,b'xy',
                                      callback_success=False),
            (0x10203040,b'xy'))

    def test_word_checksum_refuses_bad_state(self):
        for value in (-1,2**32,True,'4'):
            with self.assertRaisesRegex(ValueError,'unsigned DWORD'):
                stream_word_xor_checksum(b'',value)
        for tail in (b'1234',bytearray(b'1'),True):
            with self.assertRaisesRegex(ValueError,'pending'):
                stream_word_xor_checksum(b'',pending=tail)
        for data in (None,True,bytearray(b'a'),'hello'):
            with self.assertRaisesRegex(ValueError,'bytes'):
                stream_word_xor_checksum(data)

    def test_word_checksum_refuses_nonbool_callback_status(self):
        for status in (0,1,'true',None):
            with self.assertRaisesRegex(ValueError,'boolean'):
                stream_word_xor_checksum(b'',callback_success=status)

    def word_check_fixture(self):
        retail,gog,h=self.stream_fixture()
        def store(data,va,bytecode):
            ofs=va-0x401000
            data[ofs:ofs+len(bytecode)]=bytecode
        for addr,hexa in (*STREAM_WORD_CHECK_ANCHORS.items(),
                          *STREAM_WORD_CHECK_COMPARE_ANCHORS.items()):
            for data in (retail,gog):
                store(data,addr,bytes.fromhex(hexa))
        store(retail,0x450ADE,bytes.fromhex('56 E8 EC 03 00 00 83 C4 04 84 C0 0F'))
        store(retail,0x450B9E,b'\xff\xd6')
        store(gog,0x450ADE,bytes.fromhex('E9 22 01 00 00'))
        store(gog,0x450AE3,b'\xcc'*290)
        return retail,gog,h

    def test_word_checksum_synthetic_static_audit(self):
        retail,gog,h=self.word_check_fixture()
        result=inspect_stream_word_checksum(bytes(retail),bytes(gog),h,h)
        self.assertEqual(result['common_opcode_anchors_checked'],26)
        self.assertEqual(result['gog_disabled_stream_open_INT3_bytes'],290)
        self.assertEqual(result['checksum_accumulator_offset'],'stream+0x10')

    def test_word_checksum_expected_value_and_inversion_static(self):
        retail,gog,h=self.word_check_fixture()
        report=inspect_stream_word_checksum(bytes(retail),bytes(gog),h,h)
        self.assertEqual(report['checksum_compare_anchors_checked'],9)
        self.assertEqual(report['expected_checksum_global_va'],'0x005117B8')
        self.assertTrue(report['mismatch_gate_returns_true_on_disk'])
        self.assertEqual(report['expected_checksum_stream_read_call_va'],'0x0044DCE6')

    def test_word_checksum_reject_changed_mismatch_branch(self):
        retail,gog,h=self.word_check_fixture()
        gog[0x44D95A-0x401000] ^= 1
        with self.assertRaisesRegex(ValueError,'XOR checksum compare'):
            inspect_stream_word_checksum(bytes(retail),bytes(gog),h,h)

    def test_word_checksum_reject_changed_expected_read_call(self):
        retail,gog,h=self.word_check_fixture()
        gog[0x44DCE6-0x401000] ^= 1
        with self.assertRaisesRegex(ValueError,'XOR checksum compare'):
            inspect_stream_word_checksum(bytes(retail),bytes(gog),h,h)

    def test_word_checksum_reject_changed_open_byte(self):
        retail,gog,h=self.word_check_fixture()
        gog[0x450AE3-0x401000]=0x90
        with self.assertRaisesRegex(ValueError,'masked stream-open'):
            inspect_stream_word_checksum(bytes(retail),bytes(gog),h,h)

    def test_word_checksum_reject_changed_xor_instruction(self):
        retail,gog,h=self.word_check_fixture()
        gog[0x450E70-0x401000]=0x90
        with self.assertRaisesRegex(ValueError,'DWORD checksum anchor'):
            inspect_stream_word_checksum(bytes(retail),bytes(gog),h,h)

    def test_word_checksum_private_pair_if_available(self):
        folder=Path(os.environ.get('UNSAFEDISK_SAMPLES','/no-private-samples'))
        retail=folder/'Rayman2(3).exe'
        gog=folder/'rayman2(4).exe'
        if not(retail.is_file() and gog.is_file()):
            self.skipTest('private commercial samples are not in repository CI')
        result=inspect_pair(safe_read(retail),safe_read(gog))
        self.assertEqual(result['stream_postread_DWORD_checksum']['common_opcode_anchors_checked'],26)
        self.assertEqual(result['stream_postread_DWORD_checksum']['gog_disabled_stream_open_INT3_bytes'],290)
        self.assertEqual(result['stream_postread_DWORD_checksum']['checksum_compare_anchors_checked'],9)

    @staticmethod
    def snapshot_provenance_fixture():
        # Synthetic PE-backed VA layout; no proprietary game code included.
        count=0xA4000
        original=bytearray(b'\x90'*count)
        gog=bytearray(b'\x90'*count)
        headers={'image_base':0x400000,'sections':[
            {'rva':0x1000,'raw_off':0,'raw_size':count}
        ]}
        def put(data,va,raw):
            at=va-0x401000
            data[at:at+len(raw)]=raw
        for va,code in SNAPSHOT_CHECKSUM_ANCHORS.items():
            for buf in (original,gog):
                put(buf,va,bytes.fromhex(code))
        for va,name in SNAPSHOT_TEMPLATES.items():
            for buf in (original,gog):
                put(buf,va,name.encode('ascii')+b'\0')
        for buf in (original,gog):
            put(buf,0x44DBCC,struct.pack('<5I',
                *(branch for branch,_,_ in REFERENCE_SUFFIXES)))
            for branch,filename_va,suffix in REFERENCE_SUFFIXES:
                put(buf,filename_va,suffix.encode('ascii')+b'\0')
                put(buf,branch,bytes.fromhex('8D 95 00 FF FF FF')
                    +b'\xBF'+struct.pack('<I',filename_va))
        return original,gog,headers

    def test_snapshot_checksum_synthetic_reference_separation(self):
        cd,gog,h=self.snapshot_provenance_fixture()
        report=inspect_snapshot_checksum_provenance(bytes(cd),bytes(gog),h,h)
        self.assertEqual(report['verified_common_opcode_anchors'],24)
        self.assertEqual(report['snapshot_stream_mode'],'0x03')
        self.assertEqual(report['reference_stream_normal_mode'],'0x00')
        self.assertEqual(report['snapshot_path_formats'],
                         ['%s\\Fix.sna','%s\\%s\\%s.sna'])
        self.assertEqual([i['suffix'] for i in report['reference_suffix_switch']],
                         ['.rtb','.rtp','.rts','.rtt','.rtl'])

    def test_snapshot_checksum_rejects_changed_snapshot_path(self):
        cd,gog,h=self.snapshot_provenance_fixture()
        gog[0x49F2D8-0x401000]=ord('X')
        with self.assertRaisesRegex(ValueError,'snapshot filename format'):
            inspect_snapshot_checksum_provenance(bytes(cd),bytes(gog),h,h)

    def test_snapshot_checksum_rejects_changed_caller(self):
        cd,gog,h=self.snapshot_provenance_fixture()
        cd[0x402A71-0x401000] ^= 1
        with self.assertRaisesRegex(ValueError,'provenance mismatch'):
            inspect_snapshot_checksum_provenance(bytes(cd),bytes(gog),h,h)

    def test_snapshot_checksum_rejects_modified_suffix_pointer(self):
        cd,gog,h=self.snapshot_provenance_fixture()
        gog[0x44DA70-0x401000+1] ^= 1
        with self.assertRaisesRegex(ValueError,'suffix pointer'):
            inspect_snapshot_checksum_provenance(bytes(cd),bytes(gog),h,h)

    def test_snapshot_checksum_rejects_changed_reference_jump_table(self):
        cd,gog,h=self.snapshot_provenance_fixture()
        gog[0x44DBCC-0x401000] ^= 1
        with self.assertRaisesRegex(ValueError,'suffix switch'):
            inspect_snapshot_checksum_provenance(bytes(cd),bytes(gog),h,h)

    def test_snapshot_checksum_private_pair_optional(self):
        folder=Path(os.environ.get('UNSAFEDISK_SAMPLES','/no-private-samples'))
        retail=folder/'Rayman2(3).exe'
        gog=folder/'rayman2(4).exe'
        if not(retail.is_file() and gog.is_file()):
            self.skipTest('original owner PE binaries unavailable in CI')
        report=inspect_pair(safe_read(retail),safe_read(gog))
        record=report['snapshot_checksum_resource_provenance']
        self.assertEqual(record['verified_common_opcode_anchors'],24)
        self.assertTrue(record['no_index_bound_verified_at_inversion_site'])

    def index_alias_fixture(self):
        # Synthetic PE-backed code; sections model virtual-only .data BSS.
        a,b,h=self.snapshot_provenance_fixture()
        h={'image_base':h['image_base'],'sections':h['sections']+[{
            'name':'.data','rva':0x9f000,
            'raw_off':0,'raw_size':0x7c00,'virtual_size':0x776d0
        }]}
        for va,code in SNAPSHOT_INDEX_ANCHORS.items():
            at=va-0x401000
            raw=bytes.fromhex(code)
            for data in (a,b):
                data[at:at+len(raw)]=raw
        return a,b,h

    def test_index_alias_example_addresses(self):
        self.assertEqual(snapshot_inversion_address(0),0x5116FC)
        self.assertEqual(snapshot_inversion_address(1),0x511700)
        self.assertEqual(snapshot_inversion_address(24),0x51175C)
        self.assertEqual(snapshot_inversion_address(25),0x511760)
        self.assertEqual(snapshot_inversion_address(49),0x5117C0)
        self.assertEqual(snapshot_inversion_address(50),0x5117C4)

    def test_index_alias_points_to_last_appended_read_count(self):
        # Once the sequential path stores slot k and increments count
        # to k+1, a mismatch indexes the same record via base-4.
        for last_written in (0,1,7,23,24,49):
            with self.subTest(last_written=last_written):
                self.assertEqual(
                    snapshot_inversion_address(last_written+1),
                    0x00511700+4*last_written)

    def test_index_alias_x86_address_wrap(self):
        self.assertEqual(snapshot_inversion_address(50+2**30),0x5117C4)

    def test_index_alias_refuses_invalid_dword(self):
        for invalid in (-1,2**32,True,1.0,None):
            with self.subTest(value=invalid),self.assertRaisesRegex(ValueError,'unsigned DWORD'):
                snapshot_inversion_address(invalid)

    def test_index_alias_synthetic_static_audit(self):
        cd,gog,h=self.index_alias_fixture()
        info=inspect_snapshot_index_alias(bytes(cd),bytes(gog),h,h)
        self.assertEqual(info['identical_cd_gog_opcode_anchors'],32)
        self.assertTrue(info['sequential_append_mismatch_inverts_last_written_record'])
        self.assertEqual(info['data_raw_backed_end_exclusive'],'0x004A6C00')
        self.assertTrue(info['inversion_base_is_one_dword_before_first_table'])
        self.assertFalse(info['runtime_index_values_or_bad_memory_access_proven'])

    def test_index_alias_reject_mutated_counter_writer(self):
        cd,gog,h=self.index_alias_fixture()
        gog[0x404317-0x401000]^=1
        with self.assertRaisesRegex(ValueError,'index source/table opcode'):
            inspect_snapshot_index_alias(bytes(cd),bytes(gog),h,h)

    def test_index_alias_reject_missing_bss_region(self):
        cd,gog,h=self.index_alias_fixture()
        h['sections'][1]['virtual_size']=0x7c00
        with self.assertRaisesRegex(ValueError,'PE zero-filled'):
            inspect_snapshot_index_alias(bytes(cd),bytes(gog),h,h)

    def test_index_alias_exact_owner_pair_optional(self):
        root=Path(os.environ.get('UNSAFEDISK_SAMPLES','/missing-private-samples'))
        original=root/'Rayman2(3).exe'
        gog=root/'rayman2(4).exe'
        if not(original.is_file() and gog.is_file()):
            self.skipTest('proprietary owner binaries not available in CI')
        r=inspect_pair(safe_read(original),safe_read(gog))
        index_info=r['snapshot_checksum_index_alias_provenance']
        self.assertEqual(index_info['identical_cd_gog_opcode_anchors'],32)
        self.assertTrue(index_info['sequential_append_mismatch_inverts_last_written_record'])
        self.assertTrue(index_info['index_50_aliases_index_global_itself'])

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
