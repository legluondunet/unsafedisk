"""Synthetic tests of Rayman 2 stream open/reader selection."""
import os
import struct
import unittest
from pathlib import Path

import rayman2_stream_mode_audit as m


def toy_pe():
    data = bytearray(1024)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x84, 0x14c)
    struct.pack_into('<H', data, 0x86, 1)
    struct.pack_into('<H', data, 0x94, 224)
    struct.pack_into('<H', data, 0x98, 0x10b)
    struct.pack_into('<I', data, 0x98+28, 0x400000)
    sec = 0x98 + 224
    data[sec:sec+8] = b'.text\0\0\0'
    struct.pack_into('<III', data, sec+12, 0x1000, 16, 0x200)
    data[0x200:0x210] = bytes(range(16))
    return bytes(data)


class ReaderModeTest(unittest.TestCase):
    def test_nonxor_direct_all_flags_low(self):
        for v in (0, 1):
            self.assertEqual(m.reader_for_flags(v, False), 0x4512C0)
            self.assertEqual(m.reader_for_flags(v, True), 0x4512C0)

    def test_xor_direct_when_mask_not_set(self):
        for v in (2, 3):
            self.assertEqual(m.reader_for_flags(v, False), 0x451090)
            self.assertEqual(m.reader_for_flags(v, True), 0x451090)

    def test_masked_readers_only_if_four_flag(self):
        self.assertEqual(m.reader_for_flags(4, False), 0x451300)
        self.assertEqual(m.reader_for_flags(5, False), 0x451300)
        self.assertEqual(m.reader_for_flags(6, False), 0x451110)
        self.assertEqual(m.reader_for_flags(7, False), 0x451110)

    def test_gog_forces_direct_for_masked(self):
        for v in (4, 5):
            self.assertEqual(m.reader_for_flags(v, True), 0x4512C0)
        for v in (6, 7):
            self.assertEqual(m.reader_for_flags(v, True), 0x451090)

    def test_exhaustive_flags(self):
        for v in range(256):
            self.assertEqual(
                m.reader_for_flags(v, True),
                0x451090 if v & 2 else 0x4512C0,
            )
            if not v & 4:
                self.assertEqual(
                    m.reader_for_flags(v, False),
                    m.reader_for_flags(v, True),
                )

    def test_flags_reject_nonbyte(self):
        for v in (-1, 256, 300, None, '2'):
            with self.assertRaises(ValueError):
                m.reader_for_flags(v, True)

    def test_toy_pe_mapping(self):
        at = m.pe_mapper(toy_pe())
        self.assertEqual(at(0x401000, 4), b'\x00\x01\x02\x03')
        self.assertEqual(at(0x40100f, 1), b'\x0f')
        with self.assertRaises(ValueError):
            at(0x401010, 1)
        with self.assertRaises(ValueError):
            at(0x40fff0, 2)

    def test_non_pe_rejected(self):
        for bad in (b'\0'*1024, b'MZ'+b'\0'*1022, toy_pe()[:100]):
            with self.assertRaises((ValueError, struct.error)):
                m.pe_mapper(bad)

    def test_wrong_hash_rejected(self):
        with self.assertRaisesRegex(ValueError, 'unknown SHA256'):
            m.analyze(toy_pe(), toy_pe())

    def test_all_callsite_categories_present(self):
        from collections import Counter
        self.assertEqual(len(m.CALL_SITES), 9)
        self.assertEqual(
            Counter(e[0] for e in m.CALL_SITES.values()),
            {'constant': 6, 'conditional': 3},
        )
        self.assertEqual(
            Counter(
                e[1] for e in m.CALL_SITES.values()
                if e[0] == 'constant'
            ),
            {3: 3, 0: 3},
        )

    @unittest.skipUnless(
        os.environ.get('RAYMAN2_RETAIL_EXE')
        and os.environ.get('RAYMAN2_GOG_EXE'),
        'exact user-owned inputs must be provided outside repository',
    )
    def test_exact_owner_inputs(self):
        retail = Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes()
        gog = Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes()
        result = m.analyze(retail, gog)
        self.assertEqual(result['direct_calls_to_open_wrapper'], 9)
        self.assertEqual(
            result['retail_flag6_reader'], 'masked ReadFile + XOR'
        )
        self.assertEqual(
            result['gog_flag6_reader'], 'direct ReadFile + XOR'
        )
        cd_dat = result['retail_flag6_dat_setup']
        gog_dat = result['gog_flag6_dat_setup']
        self.assertEqual(cd_dat['file_basename'], 'LEVELS0.DAT')
        self.assertEqual(gog_dat['file_basename'], 'LEVELS0.DAT')
        self.assertTrue(cd_dat['retail_selected_via_24_entry_table'])
        self.assertFalse(gog_dat['retail_selected_via_24_entry_table'])
        self.assertIsNone(cd_dat['actual_stream_DAT_basename'])
        self.assertEqual(gog_dat['actual_stream_DAT_basename'], 'LEVELS0.DAT')
        self.assertEqual(cd_dat['file_template_va'], '0x004A2264')
        self.assertEqual(gog_dat['file_template_va'], '0x004A2268')
        self.assertTrue(cd_dat['initial_seed_0x6AB5CC79_overwritten_before_read'])
        self.assertEqual(cd_dat['subsequent_read_element_bytes'], 4)
        self.assertFalse(result['safedisc_135_executable_decrypted'])


if __name__ == '__main__':
    unittest.main()
