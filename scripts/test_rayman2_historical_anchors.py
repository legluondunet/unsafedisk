import struct
import unittest
from rayman2_historical_anchors import HISTORICAL, HISTORICAL_PATTERNS, audit_bytes, pe_code


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


if __name__=='__main__':unittest.main()
