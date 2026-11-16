"""Synthetic unit checks plus optional exact-owned Rayman2 PE32 integration."""
import os
import struct
import unittest
from pathlib import Path
from unittest.mock import patch
import rayman2_guard_boundary_audit as audit


class GuardBoundaryTests(unittest.TestCase):
    def test_pe_reject_non_pe(self):
        for raw in (b'',b'MZ',b'MZ'+bytes(200)):
            with self.assertRaises(ValueError):
                audit.pe_loader_fields(raw)

    def test_synthetic_no_relocation_or_tls(self):
        raw=bytearray(0x400)
        raw[:2]=b'MZ'
        struct.pack_into('<I',raw,0x3c,0x80)
        raw[0x80:0x84]=b'PE\0\0'
        struct.pack_into('<H',raw,0x80+20,224)
        struct.pack_into('<H',raw,0x80+22,1)
        optional=0x80+24
        struct.pack_into('<H',raw,optional,0x10b)
        struct.pack_into('<I',raw,optional+16,0x5fcc0)
        struct.pack_into('<I',raw,optional+28,0x400000)
        struct.pack_into('<I',raw,optional+92,16)
        result=audit.pe_loader_fields(bytes(raw))
        self.assertTrue(result['relocations_stripped'])
        self.assertEqual(result['relocation_directory'],(0,0))
        self.assertEqual(result['tls_directory'],(0,0))

    def test_reject_truncated_optional_header(self):
        raw=bytearray(0x400)
        raw[:2]=b'MZ'
        struct.pack_into('<I',raw,0x3c,0x80)
        raw[0x80:0x84]=b'PE\0\0'
        with self.assertRaisesRegex(ValueError,'optional'):
            audit.pe_loader_fields(raw)

    def test_unaligned_pointer_occurrences(self):
        ptr=0x5113ec
        raw=b'x'+struct.pack('<I',ptr)+b'00'+struct.pack('<I',ptr)
        s={'.text':{'file_offset':0,'raw_size':len(raw),'rva':0x1000}}
        self.assertEqual(audit.pointer_occurrences(raw,s,{ptr})['.text'],
                         [(0x401001,ptr),(0x401007,ptr)])

    def test_scan_section_separately(self):
        ptr=0x510c00
        raw=struct.pack('<I',ptr)+b'x'*8+struct.pack('<I',ptr)
        s={'x':{'file_offset':0,'raw_size':4,'rva':0x1000},
           'y':{'file_offset':12,'raw_size':4,'rva':0x2000}}
        result=audit.pointer_occurrences(raw,s,{ptr})
        self.assertEqual(result['x'],[(0x401000,ptr)])
        self.assertEqual(result['y'],[(0x402000,ptr)])

    def test_registration_pair(self):
        addr=0x405856
        row={'guard_va':addr,'begin_slot_va':0x511400,
             'begin':0x40587f,'end_slot_va':0x511320,
             'end':0x4058e9}
        raw=(b'\xc7\x05'+struct.pack('<II',row['begin_slot_va'],row['begin'])
             +b'\xc7\x05'+struct.pack('<II',row['end_slot_va'],row['end'])
             +b'\0'*52)
        with patch.object(audit,'bytes_at',return_value=raw):
            self.assertEqual(audit.verify_registration_writes(b'',{},[row],{addr}),2)
            self.assertEqual(audit.verify_registration_writes(b'',{},[row],set()),0)

    def test_malformed_registration_rejected(self):
        addr=0x405856
        row={'guard_va':addr,'begin_slot_va':0x511400,
             'begin':0x40587f,'end_slot_va':0x511320,
             'end':0x4058e9}
        raw=b'\xc7\x05'+struct.pack('<II',row['begin_slot_va'],row['begin'])+b'\0'*62
        with patch.object(audit,'bytes_at',return_value=raw):
            with self.assertRaises(ValueError):
                audit.verify_registration_writes(b'',{},[row],{addr})

    def test_strict_sha_input_gate(self):
        with self.assertRaises(ValueError):
            audit.inspect(b'',b'')

    def test_known_historical_sites(self):
        self.assertEqual(audit.HISTORICAL_SITES,(0x405856,0x448e39))

    @unittest.skipUnless(
        os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
        'private original/GOG executables are not shipped to CI')
    def test_owner_executable_integration(self):
        result=audit.inspect(
            Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes(),
            Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes())
        self.assertEqual(result['unique_table_slot_addresses'],56)
        self.assertEqual(result['original_registration_writes'],56)
        self.assertEqual(result['gog_registration_writes'],32)
        self.assertEqual(result['retail_section_pointer_literals']['.text'],85)
        self.assertEqual(result['gog_section_pointer_literals']['.text'],49)
        self.assertEqual(result['gog_section_pointer_literals']['.extra'],85)
        self.assertEqual(result['historical_sample_size_difference_bytes'],45)
        self.assertFalse(result['external_guard_or_table_consumer_identified'])
        self.assertFalse(result['decrypted_retail_executable_created'])


if __name__=='__main__':
    unittest.main()
