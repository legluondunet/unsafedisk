"""SafeDisc-era Rayman 2 startup resolver loop audit, synthetic and private."""
import os
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import rayman2_startup_resolver_loops_audit as m


class StartupResolverLoopsTest(unittest.TestCase):
    def test_total_42_indices_are_conditional(self):
        x = m.expected_indices(0, 7)
        y = m.expected_indices(1, 36)
        self.assertEqual((len(x), x[0], x[-1]), (7, 0, 6))
        self.assertEqual((len(y), y[0], y[-1]), (35, 1, 35))
        self.assertEqual(len(x) + len(y), 42)

    def test_index_boundaries(self):
        self.assertEqual(m.expected_indices(1, 1), [])
        self.assertEqual(m.expected_indices(0, 0), [])
        self.assertEqual(m.expected_indices(255, 255), [])
        with self.assertRaises(ValueError):
            m.expected_indices(-1, 7)
        with self.assertRaises(ValueError):
            m.expected_indices(0, 256)

    def test_five_fixed_direct_calls(self):
        self.assertEqual(len(m.CALLS), 5)
        for source, dest in m.CALLS.items():
            code = b'\xe8' + struct.pack('<i', dest - source - 5)
            self.assertEqual(m.target(code, source), dest)

    def test_reject_wrong_call(self):
        for insn in (b'', b'\x90'*5, b'\xe9\0\0\0\0', b'\xe8\0\0'):
            with self.assertRaises(ValueError):
                m.target(insn, 0x44947C)

    def test_loop_call_offsets_and_control_bytes(self):
        for loop in m.LOOPS.values():
            va, call_va, body = loop['va'], loop['call_va'], loop['code']
            i = call_va - va
            self.assertEqual(m.target(body[i:i+5], call_va), loop['callee_va'])
            self.assertEqual(body[-1], 0xC3)
            self.assertEqual(body[i], 0xE8)

    def test_three_conditional_refresh_calls_not_in_startup_loop_count(self):
        self.assertEqual(m.REFRESH_CALLS, {
            0x44818A: (0x447A90, 2),
            0x448196: (0x447AF0, 24),
            0x4481A2: (0x447AF0, 25),
        })
        for site, (dest, index) in m.REFRESH_CALLS.items():
            self.assertEqual(m.target(b'\xe8' + struct.pack('<i', dest-site-5), site), dest)
            self.assertTrue(index < 36)

    def test_encoded_export_decoder_positive_and_bad_input(self):
        def synth(name):
            k, x, dk, dx = 5, 17, 3, 7
            data = bytearray([k, x, dk, dx, len(name)])
            for c in name.encode('ascii'):
                data.append(((c ^ x) + k) & 255)
                k = (k + dk) & 255
                x = (x + dx) & 255
            data.extend(b'\0' * (76-len(data)))
            return bytes(data)
        for expected in m.REFRESH_EXPORTS.values():
            self.assertEqual(m.decode_export(synth(expected)), expected)
        with self.assertRaises(ValueError):
            m.decode_export(b'ab')
        with self.assertRaises(ValueError):
            m.decode_export(bytes(76))

    def test_descriptor_stride_x86_arithmetic(self):
        for idx in range(36):
            # 9*i -> 19*i -> 76*i mirrors verified LEA/SHL anchors.
            nine = idx + idx*8
            nineteen = idx + nine*2
            self.assertEqual(nineteen*4, idx*76)
        self.assertEqual(0x4A13D0 + 35*76, 0x4A1E34)

    def test_masked_lookup_site_is_not_real_caller_on_gog(self):
        self.assertEqual(m.ANCHORS[0x447ACE], 'ffd1')
        self.assertEqual(m.ANCHORS[0x447B2A], '8b8e04144a00')
        self.assertEqual(m.ANCHORS[0x447B30], '8b9ed0134a00')


@unittest.skipUnless(os.getenv('RAYMAN2_RETAIL_EXE') and os.getenv('RAYMAN2_GOG_EXE'),
                     'Private commercial files are never bundled in public CI')
class PrivateExactSampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cd = Path(os.environ['RAYMAN2_RETAIL_EXE']).read_bytes()
        cls.gog = Path(os.environ['RAYMAN2_GOG_EXE']).read_bytes()

    def test_original_full_sha_and_all_prologue_targets(self):
        report = m.inspect(self.cd, self.gog)
        self.assertEqual(report['original_statically_implied_callback_visits_if_mode_1'], 42)
        self.assertEqual(report['descriptor_count_byte_identical'], 36)
        self.assertEqual(report['loops']['small']['last_index'], 6)
        self.assertEqual(report['loops']['descriptors']['last_index'], 35)
        self.assertTrue(report['descriptor_36_pointer_slots_zero_on_disk'])
        self.assertFalse(report['runtime_call_count_measured'])
        self.assertEqual(len(report['later_conditional_original_refresh_calls']), 3)
        self.assertEqual(report['three_named_refresh_exports'], {
            '2':'GetCurrentProcess', '24':'EnumProcesses',
            '25':'EnumProcessModules'})
        self.assertTrue(all(x['gog_replaced_with_int3'] for x in report['later_conditional_original_refresh_calls']))

    def test_negative_mutations_with_hash_check_disabled_only_in_test(self):
        cpe, gpe = m.pe_sections(self.cd), m.pe_sections(self.gog)
        for edition, site in [('retail', 0x448D80), ('retail', 0x447B24),
                              ('gog', 0x448DB0), ('gog', 0x449485),
                              ('gog', 0x4A1400), ('retail', 0x448194),
                              ('gog', 0x44818A)]:
            with self.subTest(edition=edition, site=hex(site)):
                cd, gog = bytearray(self.cd), bytearray(self.gog)
                b, pe = (cd, cpe) if edition == 'retail' else (gog, gpe)
                for section in pe['sections'].values():
                    d = site - section['va']
                    if 0 <= d < section['raw_size']:
                        b[section['file_offset'] + d] ^= 0x01
                        break
                else:
                    self.fail('mutation site is not file-backed')
                with patch.object(m, 'sha_gate', return_value=None):
                    with self.assertRaises(ValueError):
                        m.inspect(bytes(cd), bytes(gog))


if __name__ == '__main__':
    unittest.main()
