"""Only synthetic fixture data, with optional integration on user-owned samples."""
import os
from pathlib import Path
import struct
import unittest
from rayman2_sample_provenance import (manifest_entries, pe_sections,
                                       check_opaque_prng, inspect, REFS,
                                       read_bounded, SALT, M, A, changed_runs,
                                       decode_masked_module, audit_cd_gog_data_changes,
                                       FIX_SIDECARS, verify_fix_sidecars)


def manifest_record(name, size):
    text=name.encode('ascii')+b'\0'
    return struct.pack('<II',size,len(text))+text


def sample_stream(seed, n=300, prefix=b''):
    out=bytearray(prefix)
    for _ in range(n):
        out.extend(struct.pack('<I',seed))
        seed=((seed ^ SALT)*A)%M
    return bytes(out)


class SampleProvenanceTests(unittest.TestCase):
    def test_manifest_records_and_sentinel(self):
        blob=(manifest_record('DPLAYERX.DLL',165888)+manifest_record('RAYMAN2.EXE',676352)
              +struct.pack('<II',0xffffffff,0)+b'\0'*11)
        names,used,total=manifest_entries(blob)
        self.assertEqual(names,{'DPLAYERX.DLL':165888,'RAYMAN2.EXE':676352})
        self.assertEqual(used,len(blob)-19)
        self.assertEqual(total,842240)

    def test_manifest_rejects_duplicate_name(self):
        blob=manifest_record('X',1)+manifest_record('X',2)+struct.pack('<II',0xffffffff,0)
        with self.assertRaisesRegex(ValueError,'duplicate'):
            manifest_entries(blob)

    def test_manifest_rejects_missing_sentinel(self):
        with self.assertRaisesRegex(ValueError,'terminator'):
            manifest_entries(manifest_record('A',1))

    def test_manifest_rejects_nul_missing(self):
        with self.assertRaisesRegex(ValueError,'NUL'):
            manifest_entries(struct.pack('<II',2,3)+b'ABC')

    def test_manifest_rejects_fake_length(self):
        with self.assertRaisesRegex(ValueError,'filename record'):
            manifest_entries(struct.pack('<II',2,0xfffffffe)+b'ABC')

    def test_manifest_rejects_trailing_nonzero(self):
        with self.assertRaisesRegex(ValueError,'after manifest'):
            manifest_entries(struct.pack('<II',0xffffffff,0)+b'\x01')

    def test_regenerates_stream_with_prefix(self):
        self.assertTrue(check_opaque_prng(sample_stream(0x6ee4c08a,prefix=b'['),
                                          prefix=b'[',seed=0x6ee4c08a))

    def test_rejects_changed_stream_byte(self):
        data=bytearray(sample_stream(0x0030fbec))
        data[201]^=0x40
        self.assertFalse(check_opaque_prng(bytes(data),prefix=b'',seed=0x0030fbec))

    def test_rejects_wrong_prefix_and_trailing_bytes(self):
        data=sample_stream(0x0030fbec)
        self.assertFalse(check_opaque_prng(data, prefix=b'[',seed=0x0030fbec))
        self.assertFalse(check_opaque_prng(data+b'X',prefix=b'',seed=0x0030fbec))

    def test_rejects_non_pe(self):
        with self.assertRaisesRegex(ValueError,'DOS header'):
            pe_sections(b'notape')

    def test_refuses_unrecognized_samples_before_parsing(self):
        with self.assertRaisesRegex(ValueError,'unknown or changed'):
            inspect({'retail':b'x','gog':b'y','icd':b'z','dplayerx':b'w'})


    def test_diff_runs_grouped(self):
        self.assertEqual(changed_runs(b'abcdefgh',b'aBcdEFgh'),[(1,2),(4,6)])
        self.assertEqual(changed_runs(b'aaa',b'aaa'),[])
        self.assertEqual(changed_runs(b'abcd',b'WXYZ'),[(0,4)])

    def test_diff_runs_reject_other_length(self):
        with self.assertRaisesRegex(ValueError,'raw lengths'):
            changed_runs(b'ab',b'abc')

    def test_masked_module_seed_decoder_synthetic(self):
        name=b'Kernel32.dll'
        subtract,key,sub_incr,key_incr=9,11,3,5
        output=bytearray((subtract,key,sub_incr,key_incr,len(name)))
        for char in name:
            output.append((((char ^ key)+subtract)&255))
            subtract=(subtract+sub_incr)&255
            key=(key+key_incr)&255
        output.extend(b'\0'*(45-len(output)))
        self.assertEqual(decode_masked_module(bytes(output)),'Kernel32.dll')

    def test_masked_module_decoder_rejects_bad_shape(self):
        with self.assertRaisesRegex(ValueError,'45-byte'):
            decode_masked_module(b'a')
        with self.assertRaisesRegex(ValueError,'name length'):
            decode_masked_module(b'\0'*45)

    def test_audit_rejects_unexpected_readonly_difference(self):
        with self.assertRaisesRegex(ValueError,'read-only data'):
            audit_cd_gog_data_changes({'.rdata':b'ab','.data':b'ab'},
                                      {'.rdata':b'aB','.data':b'ab'})

    def test_fix_sidecars_synthetic_ordered_metadata(self):
        records={f'FILLER-{i}':i for i in range(40)}
        rows=list(records.items())
        for index,name,length in FIX_SIDECARS:
            rows[index]=(name,length)
        result=verify_fix_sidecars(dict(rows))
        self.assertEqual(len(result['resources']),5)
        self.assertEqual(result['resources'][-1]['filename'],
                         'DATA\\WORLD\\LEVELS\\FIX.SNA')
        self.assertFalse(result['has_Fix_rtl_manifest_entry'])

    def test_fix_sidecars_wrong_size_rejected(self):
        rows=[(f'FILLER-{i}',i) for i in range(40)]
        for index,name,length in FIX_SIDECARS:
            rows[index]=(name,length)
        index,name,length=FIX_SIDECARS[0]
        rows[index]=(name,length+1)
        with self.assertRaisesRegex(ValueError,'Fix resource record'):
            verify_fix_sidecars(dict(rows))

    def test_fix_sidecars_rtl_unlisted(self):
        rows=[(f'FILLER-{i}',i) for i in range(40)]
        for index,name,length in FIX_SIDECARS:
            rows[index]=(name,length)
        rows.append(('DATA\\WORLD\\LEVELS\\FIX.RTL',512))
        with self.assertRaisesRegex(ValueError,'Fix.rtl'):
            verify_fix_sidecars(dict(rows))

    def test_optional_real_four_file_integration(self):
        folder=Path(os.environ.get('UNSAFEDISK_SAMPLES','/nonexistent'))
        files={'retail':'Rayman2(3).exe','gog':'rayman2(4).exe',
               'icd':'RAYMAN2(1).ICD','dplayerx':'dplayerx(4).dll'}
        if not all((folder/f).is_file() for f in files.values()):
            self.skipTest('owner files not available; only synthetic tests')
        samples={k:read_bounded(folder/f) for k,f in files.items()}
        report=inspect(samples)
        self.assertTrue(report['embedded_retail_text_exact_match'])
        self.assertEqual(len(report['gog_manifest_matches_owner_lengths']),3)
        self.assertEqual(report['gog_manifest_end_offset'],139366)
        self.assertEqual(report['gog_secdrv_sys_declared_bytes'],14368)
        self.assertEqual(len(report['gog_Fix_resource_sidecars']['resources']),5)
        self.assertFalse(report['gog_Fix_resource_sidecars']['has_Fix_rtl_manifest_entry'])
        self.assertTrue(report['contemporary_study_crosscheck']['reported_entry_va_matches_disk'])
        self.assertFalse(report['contemporary_study_crosscheck']['runtime_decrypted_function_bytes_match_disk_at_0x4064d0'])
        self.assertEqual(report['original_to_gog_data_changes']['data_diff_bytes'],127)
        self.assertEqual(report['original_to_gog_data_changes']['module_name_diff_bytes'],107)
        self.assertEqual(report['original_to_gog_data_changes']['path_config_diff_bytes'],20)
        self.assertEqual(report['original_to_gog_data_changes']['masked_api_descriptor_records_identical'],35)

if __name__=='__main__':
    unittest.main()
