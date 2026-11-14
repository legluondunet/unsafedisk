"""Synthetic and private opt-in tests for Rayman 2 callback +0x30 audit."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import unittest

import rayman2_callback30_iat_audit as m
from rayman2_callback2c_branch_audit import encoded_export, raw_at, layout


CD = Path(os.environ.get('RAYMAN2_RETAIL_EXE', '/private-owner-inputs-not-in-repository/Rayman2-CD.exe'))
GOG = Path(os.environ.get('RAYMAN2_GOG_EXE', '/private-owner-inputs-not-in-repository/Rayman2-GOG.exe'))


def synthetic_record(name: str, start_sub=0x23, start_xor=0x45,
                     step_sub=0x0c, step_xor=0x02) -> bytes:
    encoded=bytearray([start_sub, start_xor, step_sub, step_xor, len(name)])
    sub,xor=start_sub,start_xor
    for c in name.encode('ascii'):
        encoded.append(((c ^ xor) + sub) & 255)
        sub=(sub+step_sub)&255
        xor=(xor+step_xor)&255
    if len(encoded)>48:
        raise ValueError('too long')
    encoded.extend(bytes(76-len(encoded)))
    return bytes(encoded)


def va_file_offset(data: bytes, va: int) -> int:
    pe=layout(data)
    for _,(rva,vsize,rsize,off,flags) in pe.items():
        d=va-0x400000-rva
        if 0<=d<min(vsize,rsize):return off+d
    raise ValueError(f'Invalid VA {va:#x}')


def synthetic_import_pe() -> tuple[bytes,dict]:
    """A tiny, fully invented PE32 import directory in one mock .rdata."""
    import struct
    b=bytearray(0x1000)
    b[:2]=b'MZ'
    struct.pack_into('<I',b,0x3C,0x80)
    b[0x80:0x84]=b'PE\0\0'
    o=0x98
    struct.pack_into('<H',b,o,0x10b)
    struct.pack_into('<I',b,o+92,16)
    struct.pack_into('<II',b,o+96+8,0x2000,0x3c)
    # IMAGE_IMPORT_DESCRIPTOR begins at file offset 0x200.
    struct.pack_into('<IIIII',b,0x200,0x2080,0,0,0x2040,0x20a0)
    b[0x240:0x240+13]=b'KERNEL32.dll\0'
    struct.pack_into('<I',b,0x280,0x20c0)
    struct.pack_into('<I',b,0x284,0)
    struct.pack_into('<I',b,0x2a0,0x20c0)
    struct.pack_into('<I',b,0x2a4,0)
    b[0x2c0:0x2c0+19]=b'\0\0GetModuleHandleA\0'
    sec={'.rdata':(0x2000,0x600,0x600,0x200,0)}
    return bytes(b),sec


class PureSyntheticTests(unittest.TestCase):
    def test_zero_for_equal_pointers(self):
        for v in (0,1,0x12345678,0xffffffff):
            self.assertEqual(m.pointer_delta(v,v,True),0)

    def test_pointer_difference_unsigned_and_wrapping(self):
        self.assertEqual(m.pointer_delta(0x40001000,0x40000000,True),0x1000)
        self.assertEqual(m.pointer_delta(0x40000000,0x40001000,True),0xfffff000)
        self.assertEqual(m.pointer_delta(0,1,True),0xffffffff)

    def test_no_lookup_not_mistaken_for_positive_pass(self):
        self.assertEqual(m.pointer_delta(0x40001000,0x40000000,False),0)
        self.assertEqual(m.pointer_delta(None,0x40001000,True),0)
        self.assertEqual(m.pointer_delta(0x40001000,None,True),0)

    def test_reject_non_32bit_pointers(self):
        for bad in (-1,0x100000000):
            with self.assertRaises(ValueError):m.pointer_delta(bad,1,True)
            with self.assertRaises(ValueError):m.pointer_delta(1,bad,True)

    def test_descriptor_encoding_roundtrip(self):
        for name in ('GetModuleHandleA','ReadFile','LoadLibraryA','CreateFileA',
                     'EnumProcessModules','SetFilePointer'):
            self.assertEqual(encoded_export(synthetic_record(name)),name)

    def test_descriptor_decode_rejects_truncated_and_corrupt(self):
        for bad in (b'',bytes(76), bytes([0,0,0,0,76])+bytes(71),bytes(75)):
            with self.assertRaises(ValueError):encoded_export(bad)

    def test_synthetic_import_directory_reconstructs_iat_va(self):
        pe,sec=synthetic_import_pe()
        imports=m.pe_imports(pe,sec)
        self.assertEqual(imports,{'GetModuleHandleA':{
            'iat_va':0x4020a0,'module':'KERNEL32.dll'}})

    def test_synthetic_import_directory_requires_terminator(self):
        pe,sec=synthetic_import_pe()
        b=bytearray(pe)
        b[0x214:0x214+20]=b'\xff'*20
        with self.assertRaises(ValueError):m.pe_imports(bytes(b),sec)

    def test_synthetic_import_directory_invalid_module_name(self):
        pe,sec=synthetic_import_pe()
        b=bytearray(pe);b[0x240]=0x00
        with self.assertRaises(ValueError):m.pe_imports(bytes(b),sec)

    def test_synthetic_import_directory_invalid_thunk_rva(self):
        import struct
        pe,sec=synthetic_import_pe()
        b=bytearray(pe)
        struct.pack_into('<I',b,0x280,0x70000000)
        with self.assertRaises(ValueError):m.pe_imports(bytes(b),sec)

    def test_fixture_descriptor_dimensions(self):
        self.assertEqual(m.RECORD_COUNT,36)
        self.assertEqual(m.RECORD_STRIDE,76)
        self.assertEqual(m.RECORD_BASE+36*76,0x4A1E80)
        self.assertEqual(m.CALLBACK_SLOT,0x30)
        self.assertEqual(m.HANDLER_END-m.HANDLER_VA,712)

    def test_opcode_anchors_stable_and_unique(self):
        self.assertEqual(len(m.SOURCE_INSTRUCTIONS),49)
        self.assertEqual(len(m.SOURCE_INSTRUCTIONS),len(set(m.SOURCE_INSTRUCTIONS)))
        self.assertTrue(all(isinstance(a,int) and 0x448ab0<=a<0x448d78
                            for a in m.SOURCE_INSTRUCTIONS))
        self.assertTrue(all(2<=len(bytes.fromhex(s))<=8
                            for s in m.SOURCE_INSTRUCTIONS.values()))

    def test_pure_rel32_call_scanner_with_synthetic_positive(self):
        import struct
        base=0x401000
        target=0x448AB0
        code=bytearray(b'\x90'*32)
        callsite=base+7
        code[7:12]=b'\xe8'+struct.pack('<i',target-callsite-5)
        self.assertEqual(m.raw_rel32_call_sites(code,base,target),[callsite])
        self.assertEqual(m.raw_rel32_call_sites(code,base,target+1),[])
        with self.assertRaises(ValueError):m.raw_rel32_call_sites(code,-1,target)

    def test_binary_snapshot_identities_are_distinct(self):
        self.assertNotEqual(m.CD_HASH,m.GOG_HASH)
        self.assertNotEqual(m.RETAIL_HANDLER_SHA256,m.GOG_HANDLER_SHA256)

    def test_exact_sha_gate_refuses_arbitrary_data(self):
        with self.assertRaisesRegex(ValueError,'Unknown original CD sample'):
            m.audit(b'not a PE',b'not a PE')


@unittest.skipUnless(CD.is_file() and GOG.is_file(),'Private exact samples absent')
class OwnerSampleIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cd=CD.read_bytes();cls.gog=GOG.read_bytes()
        if hashlib.sha256(cls.cd).hexdigest()!=m.CD_HASH or hashlib.sha256(cls.gog).hexdigest()!=m.GOG_HASH:
            raise unittest.SkipTest('Other PE revision is not the verified owner pair')

    def test_integration_on_two_exact_input_files(self):
        r=m.audit(self.cd,self.gog)
        self.assertTrue(r['exact_samples_verified_by_wrapper'])
        self.assertTrue(r['gog_handler_returns_zero'])
        self.assertTrue(r['original_checks_matched_import_against_encoded_masked_descriptor_pointer'])
        self.assertEqual(r['bootstrap_descriptor_zero_name'],'GetModuleHandleA')
        self.assertEqual(r['direct_pointer_and_call_census']['retail']['exact_literal_occurrences_in_active_text'],1)
        self.assertEqual(r['direct_pointer_and_call_census']['gog']['direct_rel32_call_sites'],0)
        self.assertEqual(r['iat_name_intersection']['retail']['named_import_count'],163)
        self.assertEqual(r['iat_name_intersection']['gog']['descriptor_names_also_present_in_IAT'],18)
        self.assertTrue(r['iat_name_intersection']['retail']['candidate_imports_only_kernel32'])
        self.assertTrue(all(row['iat_va'].startswith('0x0049C0') for row in r['iat_name_intersection']['gog']['possible_named_iat_targets']))
        self.assertEqual(r['iat_name_intersection']['retail']['descriptor_indices_with_named_IAT_entries'],
                         [0,3,4,5,6,7,8,9,10,11,12,14,18,26,27,29,30,32])
        self.assertFalse(r['runtime_callback_execution_observed'])
        self.assertFalse(r['safedisc_driver_or_media_verdict_observed'])

    def test_new_audit_agrees_with_existing_callback2c_vector(self):
        import rayman2_callback2c_branch_audit as original
        r=original.audit(self.cd,self.gog)
        self.assertEqual(r['vector_install_site'],'0x4671EB')
        self.assertEqual(m.audit(self.cd,self.gog)['install_va'],'0x4671F4')

    def test_changed_gog_handler_detected(self):
        b=bytearray(self.gog)
        b[va_file_offset(b,0x448AB1)]=0x90
        with self.assertRaises(ValueError):m.inspect_structure(self.cd,bytes(b))

    def test_changed_retail_import_or_compare_detected(self):
        for address in (0x448BF5,0x448C26,0x448C53,0x448C56,
                        0x448C74,0x448CFE,0x448D5E,0x448D64,0x448D66):
            with self.subTest(va=hex(address)):
                a=bytearray(self.cd)
                a[va_file_offset(a,address)] ^= 1
                with self.assertRaises(ValueError):m.inspect_structure(bytes(a),self.gog)

    def test_changed_callback_slot_and_descriptor_detected(self):
        for in_gog,addr in ((False,0x4671F4),(True,0x4671F4),
                            (True,0x4A13D0),(False,0x4A141C)):
            with self.subTest(gog=in_gog,va=hex(addr)):
                a=bytearray(self.gog if in_gog else self.cd)
                a[va_file_offset(a,addr)] ^= 1
                with self.assertRaises(ValueError):
                    m.inspect_structure(self.cd,bytes(a)) if in_gog else m.inspect_structure(bytes(a),self.gog)

    def test_gog_archival_text_cannot_be_mistaken_for_active_handler(self):
        # Check inactive copied bytes remain there in GOG and cannot make the
        # actual GOG active .text verifier appear to be runnable.
        a=layout(self.cd);b=layout(self.gog)
        cd_body=raw_at(self.cd,a,m.HANDLER_VA,712)
        rva=m.HANDLER_VA-0x400000
        extra=b['.extra']
        raw=self.gog[extra[3]+0x1000+rva-0x1000:extra[3]+0x1000+rva-0x1000+712]
        self.assertEqual(raw,cd_body)
        self.assertNotEqual(raw_at(self.gog,b,m.HANDLER_VA,712),cd_body)
        self.assertEqual(m.inspect_structure(self.cd,self.gog)['gog_handler_returns_zero'],True)

    def test_metadata_only_json_output(self):
        dumped=json.dumps(m.audit(self.cd,self.gog))
        self.assertNotIn('4d5a9000',dumped.lower())
        self.assertNotIn('pe_header_bytes',dumped)
        self.assertIn('runtime_target_export_name_known',dumped)


if __name__=='__main__':unittest.main()
