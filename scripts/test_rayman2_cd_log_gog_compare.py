#!/usr/bin/env python3
"""Synthetic-only unit tests for the original ISO omission/GOG comparison."""
import struct
import unittest

from rayman2_cd_log_gog_compare import read_catalog, parse_iso_omissions, compare


def fake_pe_catalog(entries):
    data = bytearray(0x400)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x86, 1)
    struct.pack_into('<H', data, 0x94, 0xe0)
    data[0x178:0x180] = b'.extra2\0'
    struct.pack_into('<II', data, 0x178+16, 0x200, 0x200)
    off = 0x200
    for name, size in entries:
        raw = name.encode('ascii') + b'\0'
        struct.pack_into('<II', data, off, size, len(raw))
        data[off+8:off+8+len(raw)] = raw
        off += 8+len(raw)
    struct.pack_into('<II', data, off, 0xffffffff, 0)
    return bytes(data)


SUMMARY = ('DISC: format=ISO9660 / 2048-byte sectors volume=RAYMAN2 '
           'files=4 declared_bytes=300 image_bytes=2048 '
           'cd_excluded_files=2 cd_excluded_bytes=30\n')
OMITTED = ('DISC-OMIT: original path=RAYMAN2.ICD declared_bytes=10 '
           '(not copied; protection status unverified)\n'
           'DISC-OMIT: original path=Drvmgt.dll declared_bytes=20 '
           '(not copied; protection status unverified)\n')


class LogToGogTests(unittest.TestCase):
    def test_pe_catalog_case_and_windows_path(self):
        cat = read_catalog(fake_pe_catalog([
            ('RAYMAN2.ICD', 10), ('DATA\\FILE.DAT', 20)]), verify_hash=False)
        self.assertEqual(cat, {'rayman2.icd': 10, 'data/file.dat': 20})

    def test_log_counts_omission_size(self):
        log = parse_iso_omissions(SUMMARY+OMITTED)
        self.assertEqual(len(log['omissions']), 2)
        self.assertEqual(sum(log['omissions'].values()), 30)
        report = compare(log, {'rayman2.icd': 10, 'drvmgt.dll': 20})
        self.assertEqual(report['same_path_and_declared_size'], 2)
        self.assertEqual(report['iso_omissions_absent_from_gog'], [])
        self.assertEqual(report['iso_omissions_with_different_gog_size'], [])
        self.assertFalse(report['content_hashes_compared'])

    def test_mismatch_and_missing(self):
        log = parse_iso_omissions(SUMMARY+OMITTED)
        report = compare(log, {'rayman2.icd': 11})
        self.assertEqual(report['same_path_and_declared_size'], 0)
        self.assertEqual(len(report['iso_omissions_absent_from_gog']), 1)
        self.assertEqual(len(report['iso_omissions_with_different_gog_size']), 1)

    def test_log_inconsistent_omission_count_or_bytes_rejected(self):
        with self.assertRaises(ValueError):
            parse_iso_omissions(SUMMARY+OMITTED.replace('declared_bytes=20', 'declared_bytes=22'))
        with self.assertRaises(ValueError):
            parse_iso_omissions(SUMMARY+OMITTED+OMITTED.splitlines()[0]+'\n')
        with self.assertRaises(ValueError):
            parse_iso_omissions(SUMMARY.replace('cd_excluded_files=2','cd_excluded_files=3')+OMITTED)

    def test_all_23_unusually_large_dat_records(self):
        from rayman2_cd_log_gog_compare import LEVEL_DAT_PATHS
        self.assertEqual(len(LEVEL_DAT_PATHS), 23)
        synthetic = {name: 200_000_000+i for i, name in
                     enumerate(sorted(LEVEL_DAT_PATHS))}
        log = {'stats': {'files': 24, 'declared_bytes': 4_000_000_000,
                         'image_bytes': 650_000_000},
               'omissions': synthetic}
        result = compare(log, synthetic)
        details = result['historical_23_omitted_dat']
        self.assertTrue(details['all_23_confirmed_in_both'])
        self.assertEqual(details['matching_paths_and_lengths_in_gog'], 23)
        self.assertEqual(details['iso_declared_bytes'], sum(synthetic.values()))
        synthetic.pop('data/world/levels/music0.dat')
        result = compare(log, synthetic)
        self.assertFalse(result['historical_23_omitted_dat']['all_23_confirmed_in_both'])

    def test_23_dat_sizes_alone_explain_nominal_overshoot(self):
        from rayman2_cd_log_gog_compare import LEVEL_DAT_PATHS
        fake_sum = 6_777_257_404
        # Synthetic catalog with the same aggregate properties as the original
        # log and hash-pinned GOG metadata. No commercial data is embedded.
        names = sorted(LEVEL_DAT_PATHS)
        fake = {name: fake_sum // 23 for name in names}
        fake[names[0]] += fake_sum - sum(fake.values())
        catalog = dict(fake)
        catalog['test/ordinary.bin'] = 675_805_210
        log = {'stats': {'files': 3718, 'declared_bytes': 7_450_158_839,
                         'image_bytes': 678_168_576},
               'omissions': fake}
        result = compare(log, catalog)['full_23_dat_declared_size_reconciliation']
        self.assertEqual(result['iso_nominal_bytes_without_23'], 672_901_435)
        self.assertEqual(result['gog_nominal_bytes_without_23'], 675_805_210)
        self.assertEqual(result['iso_image_bytes_minus_remaining_nominal'], 5_267_141)
        del catalog[names[1]]
        self.assertIsNone(compare(log, catalog)['full_23_dat_declared_size_reconciliation'])

    def test_iso_volume_geometry_matches_gog_to_1759_bytes(self):
        from rayman2_cd_log_gog_compare import LEVEL_DAT_PATHS
        nominal_fake = 6_777_257_404
        names = sorted(LEVEL_DAT_PATHS)
        fake = {name: nominal_fake // 23 for name in names}
        fake[names[-1]] += nominal_fake - sum(fake.values())
        catalog = dict(fake)
        catalog['sample'] = 675_805_210
        log = {'stats': {'files': 3718, 'declared_bytes': 7_450_158_839,
                         'image_bytes': 678_168_576,
                         'volume_bytes': 677_853_184},
               'omissions': fake}
        report = compare(log, catalog)['full_23_dat_declared_size_reconciliation']
        self.assertEqual(report['iso_volume_minus_remaining_nominal'], 4_951_749)
        self.assertEqual(report['gog_virtual_volume_minus_remaining_nominal'], 4_949_990)
        self.assertEqual(report['iso_vs_gog_volume_slack_difference'], 1_759)
        self.assertEqual(report['iso_physical_image_bytes'] -
                         report['iso_reported_volume_bytes'], 315_392)

    def test_catalog_malformed_and_wrong_hash_rejected(self):
        good = fake_pe_catalog([('RAYMAN2.ICD', 10)])
        with self.assertRaises(ValueError):
            read_catalog(good)
        with self.assertRaises(ValueError):
            read_catalog(good[:280], verify_hash=False)
        with self.assertRaises(ValueError):
            read_catalog(fake_pe_catalog([('SAME', 1),('same', 2)]),verify_hash=False)


if __name__ == '__main__':
    unittest.main()
