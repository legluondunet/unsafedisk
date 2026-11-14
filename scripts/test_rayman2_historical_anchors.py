import struct
import unittest
from rayman2_historical_anchors import HISTORICAL, HISTORICAL_PATTERNS, audit_bytes, pe_code, historical_stage_probe, HISTORICAL_CHECK_CALL_BYTES, HISTORICAL_DECRYPTED_OEP_22


def synthetic_pe(overrides=None):
    a = bytearray(0xA6000)
    a[:2] = b'MZ'
    struct.pack_into('<I', a, 0x3c, 0x80)
    a[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', a, 0x84, 0x14c)
    struct.pack_into('<H', a, 0x86, 1)
    struct.pack_into('<H', a, 0x94, 0xe0)
    struct.pack_into('<H', a, 0x98, 0x10b)
    struct.pack_into('<I', a, 0x98+16, 0x5fcc0)
    struct.pack_into('<I', a, 0x98+28, 0x400000)
    at=0x178
    a[at:at+8]=b'.text\0\0\0'
    struct.pack_into('<IIII', a, at+8, 0x9A1D0, 0x1000, 0x9A200, 0x400)
    for va, payload in (overrides or []):
        pos = 0x400 + va - 0x401000
        a[pos:pos+len(payload)] = payload
    return bytes(a)


class HistoricalAnchorTests(unittest.TestCase):
    def test_matching_historical_anchor_positive(self):
        a = synthetic_pe(list(HISTORICAL.values()))
        got=audit_bytes(a,a)
        self.assertEqual(got['retail_entry_va'], '0x0045FCC0')
        self.assertEqual(got['retail_text_raw_size'], 0x9A200)
        self.assertEqual(sum(x['historical_prefix_matches_retail_disk']
                             for x in got['anchors'].values()), len(HISTORICAL))
        self.assertTrue(all(x['retail_and_gog_32_bytes_identical'] for x in got['anchors'].values()))

    def test_detect_mismatch_even_with_same_entrypoint(self):
        only_entry = synthetic_pe([HISTORICAL['entrypoint_normal_prologue']])
        got=audit_bytes(only_entry,only_entry)
        self.assertTrue(got['anchors']['entrypoint_normal_prologue']['historical_prefix_matches_retail_disk'])
        self.assertEqual(sum(x['historical_prefix_matches_retail_disk'] for x in got['anchors'].values()),1)
        self.assertTrue(got['mismatches_do_not_prove_version_difference'])

    def test_detect_added_signature_in_code_not_arbitrary_file_data(self):
        va=0x403000
        patt=HISTORICAL_PATTERNS['early_local_file_branch']
        a=synthetic_pe([(va,patt)])
        report=audit_bytes(a,a)
        self.assertEqual(report['historical_signature_occurrences']['early_local_file_branch']['retail_count'],1)
        self.assertEqual(sum(x['retail_count'] for x in report['historical_signature_occurrences'].values()),1)

    def test_detect_changed_statically_identical_anchor(self):
        a=synthetic_pe(list(HISTORICAL.values()))
        b=synthetic_pe(list(HISTORICAL.values())+[(0x4124f0,b'\x90')])
        report=audit_bytes(a,b)
        self.assertFalse(report['anchors']['first_cd_check_stack_reserve']['retail_and_gog_32_bytes_identical'])

    def test_reject_invalid_pe(self):
        with self.assertRaises(ValueError):pe_code(b'abcd')
        with self.assertRaises(ValueError):pe_code(synthetic_pe()[:200])
        a=bytearray(synthetic_pe());a[0x80:0x84]=b'NOPE'
        with self.assertRaises(ValueError):pe_code(bytes(a))


    def test_historical_runtime_stage_mismatch_is_explicit(self):
        image = synthetic_pe([
            (0x45FCC0, HISTORICAL_DECRYPTED_OEP_22),
            (0x410A93, bytes.fromhex('B9 01 00 00 00')),
            (0x4052DF, bytes.fromhex('68 00 00 C0 3F')),
        ])
        stage = audit_bytes(image, image)['historical_runtime_stage_discriminator']
        for edition in ('retail', 'gog'):
            p = stage[edition]
            self.assertTrue(p['historical_decrypted_oep_first_22_bytes_on_disk'])
            self.assertTrue(p['0x410A94_in_mov_ecx_1_immediate'])
            self.assertTrue(p['0x4052E0_in_push_float_immediate'])
            self.assertEqual(p['published_call_pattern_occurrences_in_active_text'], 0)
            self.assertFalse(p['published_0x410A94_call_to_0x4270AD_at_same_va'])
            self.assertFalse(p['historic_file_offset_patch_transfer_supported'])

    def test_historical_call_classified_only_if_bytes_actually_match(self):
        image = synthetic_pe([(0x410A94, HISTORICAL_CHECK_CALL_BYTES)])
        base, ep, code = pe_code(image)
        p = historical_stage_probe(code, base)
        self.assertTrue(p['published_0x410A94_call_to_0x4270AD_at_same_va'])
        self.assertEqual(p['published_call_pattern_occurrences_in_active_text'], 1)
        self.assertFalse(p['0x410A94_in_mov_ecx_1_immediate'])
        self.assertFalse(p['historical_decrypted_oep_first_22_bytes_on_disk'])



if __name__=='__main__':unittest.main()
