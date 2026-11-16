import unittest
from rayman2_direct_call_audit import audit_code


class DirectCallAuditTests(unittest.TestCase):
    def test_removed_call_and_target(self):
        old = bytearray(b'\x90' * 64)
        new = bytearray(old)
        old[4] = 0x55  # original function entry
        new[4] = 0xCC  # GOG neutralised function
        result = audit_code(old, new, 0x1000, {0x1010: 0x1004}, {})
        self.assertEqual(result['retail_direct_calls_into_gog_int3'], 1)
        self.assertEqual(result['sources_modified_in_gog'], 1)
        self.assertEqual(result['gog_direct_calls_into_int3'], 0)

    def test_still_live_call_is_reported_not_hidden(self):
        old = bytearray(b'\x90' * 64)
        new = bytearray(old)
        old[3], new[3] = 0x55, 0xCC
        result = audit_code(old, new, 0x1000, {0x1010: 0x1003}, {0x1010: 0x1003})
        self.assertEqual(result['sources_still_direct_calls_in_gog'], 1)
        self.assertEqual(result['gog_direct_calls_into_int3'], 1)

    def test_non_executable_or_outside_target_not_counted(self):
        old = bytearray(b'\x90' * 64)
        new = bytearray(old)
        old[3], new[3] = 0xCC, 0xCC
        result = audit_code(old, new, 0x1000, {0x1010: 0x1003, 0x1020: 0x2000}, {})
        self.assertEqual(result['retail_direct_calls_into_gog_int3'], 0)
        self.assertEqual(result['gog_direct_calls_into_int3'], 0)


if __name__ == '__main__':
    unittest.main()
