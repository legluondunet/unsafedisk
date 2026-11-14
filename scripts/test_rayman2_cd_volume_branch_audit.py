"""Synthetic-only tests for Rayman 2 CD volume branch inspector."""
import struct
import unittest

from rayman2_cd_volume_branch_audit import (
    LABEL_COMPARISON_VAS, audit, check_edge, decode_label_comparisons,
    decode_relative_branch, require, scan_drive_letter_refs, reconstruct_dialog_strings,
)


def make_label_insns(label='RAYMAN2'):
    assert len(label)==7
    # Real order of byte comparisons is intentionally permuted.
    return {va: (b'\x80\xbd'+struct.pack('<i', -0xEC+i)+bytes([ord(c)]),
                 'cmp','synthetic')
            for i,(va,c) in enumerate(zip(LABEL_COMPARISON_VAS,label))}


def make_audit_fixture():
    retail={
        0x44949f: b'\xe8\x8c\xf9\xff\xff',
        0x448e39: b'\xa1\xec\x13\x51\x00',
        0x448e40: b'\x74\x18',
        0x448f02: b'\xff\xd6',
        0x449037: b'\xff\xd6',
        0x449158: b'\xff\xd6',
        0x449096: b'\x83\x7d\x9c\x05',
        0x44909a: b'\x0f\x85\x68\x01\x00\x00',
        0x449203: b'\x83\xf9\x07',
        0x449206: b'\x74\x11',
        0x44921c: b'\xc7\x45\xa0\x01\x00\x00\x00',
        0x449225: b'\xa2\xd8\x6a\x4a\x00',
        0x44922f: b'\x0f\x85\x1c\x01\x00\x00',
        0x449238: b'\x6a\x05',
        0x448f73: b'\xbb\x20\x00\x00\x00',
        0x44934b: b'\x0f\x84\x27\xfc\xff\xff',
        0x449339: b'\xff\x15\x70\xc2\x49\x00',
        0x44933f: b'\x83\xf8\x02',
        0x449342: b'\x75\x05',
        0x449344: b'\xe8\x77\x7e\xfb\xff',
    }
    retail={va:(raw,'cmp' if va in LABEL_COMPARISON_VAS else 'synthetic','')
            for va,raw in retail.items()}
    retail.update(make_label_insns())
    gog={
        0x44949f: b'\xe8\x8c\xf9\xff\xff',
        0x448e39: b'\xa1\xec\x13\x51\x00',
        0x448e40: b'\x74\x18',
        0x448e5a: b'\xb0\x2e',
        0x448e5c: b'\xa2\xd8\x6a\x4a\x00',
        0x448e61: b'\x8b\xe5',
        0x448e64: b'\xc3',
        0x449096: b'\xcc',
        0x449219: b'\xcc',
        0x449339: b'\xcc',
    }
    gog={va:(raw,'synthetic','') for va,raw in gog.items()}
    refs=(0x404af3,0x404b41,0x423680,0x423835,0x42510e,
          0x44cdba,0x44d22a,0x44d53e,0x44db12,0x44dea8,
          0x44eb7a,0x44f14e,0x44f7b3,0x454675,0x45ed00,
          0x467525,0x47b063)
    read=(b'\x0f\xbe\x05\xd8\x6a\x4a\x00', 'movsx',
          'eax,BYTE PTR ds:0x4a6ad8')
    for va in refs:
        retail[va]=read
        gog[va]=read
    retail[0x449225]=(retail[0x449225][0],'mov','ds:0x4a6ad8,al')
    gog[0x448e5c]=(gog[0x448e5c][0],'mov','ds:0x4a6ad8,al')
    index=0
    for start,text in ((-0x5c,'Please, insert Rayman II CD in CDROM Drive'),
                       (-0x28,'Rayman 2 CD not found')):
        for i,c in enumerate(text+'\0'):
            off=start+i
            if c==' ':
                raw=b'\x88\x5d'+bytes([off&255])
            else:
                raw=b'\xc6\x45'+bytes([off&255, ord(c)])
            retail[0x449240+index*2]=(raw,'mov','synthetic')
            index+=1
    rows=[{'site':f'0x{va:08X}','name':name,'retail_call_reg':'esi'} for va,name in (
        (0x448f02,'GetLogicalDrives'), (0x449037,'GetDriveTypeA'),
        (0x449158,'GetVolumeInformationA'))]
    imports={0x49c270:'MessageBoxA'}
    return retail,gog,imports,rows


class VolumeBranchTests(unittest.TestCase):
    def test_label_reconstructed_by_stack_byte_positions(self):
        self.assertEqual(decode_label_comparisons(make_label_insns()),'RAYMAN2')

    def test_wrong_volume_letter_rejected(self):
        with self.assertRaisesRegex(ValueError,'unexpected volume label'):
            decode_label_comparisons(make_label_insns('RAYMAN3'))

    def test_missing_label_comparison_rejected(self):
        ins=make_label_insns()
        del ins[0x4491EA]
        with self.assertRaisesRegex(ValueError,'missing'):
            decode_label_comparisons(ins)

    def test_duplicate_stack_offset_rejected(self):
        ins=make_label_insns()
        ins[0x4491EA]=ins[0x4491B4]
        with self.assertRaisesRegex(ValueError,'duplicate'):
            decode_label_comparisons(ins)

    def test_non_ascii_comparison_rejected(self):
        ins=make_label_insns()
        raw=bytearray(ins[0x4491EA][0]);raw[-1]=0x1F
        ins[0x4491EA]=(bytes(raw),'cmp','synthetic')
        with self.assertRaisesRegex(ValueError,'non-ASCII'):
            decode_label_comparisons(ins)

    def test_branch_decode_signed_rel32_and_short(self):
        self.assertEqual(decode_relative_branch(0x44949F,b'\xe8\x8c\xf9\xff\xff'),0x448e30)
        self.assertEqual(decode_relative_branch(0x44909A,b'\x0f\x85\x68\x01\x00\x00'),0x449208)
        self.assertEqual(decode_relative_branch(0x449206,b'\x74\x11'),0x449219)

    def test_invalid_branch_encoding_rejected(self):
        with self.assertRaisesRegex(ValueError,'unsupported'):
            decode_relative_branch(0x1234,b'\x90')

    def test_correct_independent_synthetic_control_flow(self):
        r,g,imports,rows=make_audit_fixture()
        result=audit(r,g,imports,rows)
        self.assertEqual(result['volume_label_7_bytes'],'RAYMAN2')
        self.assertEqual(result['original_drive_type_required']['value'],5)
        self.assertFalse(result['decryption_performed'])
        self.assertEqual(result['drive_letter_direct_read_count'],17)
        self.assertEqual(result['error_dialog_strings']['title'], 'Rayman 2 CD not found')

    def test_altered_api_classification_rejected(self):
        r,g,imports,rows=make_audit_fixture()
        rows[0]['name']='GetFileSize'
        with self.assertRaisesRegex(ValueError,'GetLogicalDrives'):
            audit(r,g,imports,rows)

    def test_altered_error_import_rejected(self):
        r,g,imports,rows=make_audit_fixture()
        imports[0x49c270]='SetWindowPos'
        with self.assertRaisesRegex(ValueError,'message/error import'):
            audit(r,g,imports,rows)

    def test_dialog_strings_recover_from_mixed_mov_literals_and_bl(self):
        r,_,_,_=make_audit_fixture()
        labels=reconstruct_dialog_strings(r)
        self.assertEqual(labels['prompt'],'Please, insert Rayman II CD in CDROM Drive')
        self.assertEqual(labels['title'],'Rayman 2 CD not found')

    def test_dialog_string_mutation_is_rejected(self):
        r,_,_,_=make_audit_fixture()
        r[0x449240]=(b'\xc6\x45\xa4\x51','mov','synthetic')
        with self.assertRaisesRegex(ValueError,'dialog string differs'):
            reconstruct_dialog_strings(r)

    def test_dialog_source_space_register_must_be_initialized(self):
        r,_,_,_=make_audit_fixture()
        r[0x448f73]=(b'\xbb\x21\x00\x00\x00','mov','wrong')
        with self.assertRaisesRegex(ValueError,'opcode mismatch'):
            reconstruct_dialog_strings(r)

    def test_direct_drive_byte_references_are_preserved(self):
        r,g,_,_=make_audit_fixture()
        rr,rw=scan_drive_letter_refs(r)
        gr,gw=scan_drive_letter_refs(g)
        self.assertEqual(rr,gr)
        self.assertEqual(len(rr),17)
        self.assertEqual((set(rw),set(gw)),({0x449225},{0x448e5c}))

    def test_modified_read_reference_is_rejected(self):
        r,g,imports,rows=make_audit_fixture()
        g[0x404af3]=(b'\x90','nop','')
        with self.assertRaisesRegex(ValueError,'direct drive-letter xref count'):
            audit(r,g,imports,rows)

    def test_extra_direct_write_fails_count(self):
        r,g,imports,rows=make_audit_fixture()
        g[0x440000]=(b'\xa2\xd8\x6a\x4a\x00','mov','ds:0x4a6ad8,al')
        with self.assertRaisesRegex(ValueError,'xref count'):
            audit(r,g,imports,rows)

    def test_gog_stub_must_write_period(self):
        r,g,imports,rows=make_audit_fixture()
        g[0x448e5a]=(b'\xb0\x3a','synthetic','')
        with self.assertRaisesRegex(ValueError,'opcode mismatch'):
            audit(r,g,imports,rows)

    def test_bypass_branch_would_not_pass(self):
        r,g,imports,rows=make_audit_fixture()
        r[0x449206]=(b'\x74\x10','je','wrong')
        with self.assertRaisesRegex(ValueError,'opcode mismatch'):
            audit(r,g,imports,rows)


if __name__ == '__main__':
    unittest.main()
