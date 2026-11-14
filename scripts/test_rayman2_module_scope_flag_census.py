"""Synthetic and optional private exact-SHA tests for module-scope flag census."""
from __future__ import annotations
import os
from pathlib import Path
import struct
import unittest

import rayman2_module_scope_flag_census as mod

CD_PATH=os.environ.get('RAYMAN2_RETAIL_EXE')
GOG_PATH=os.environ.get('RAYMAN2_GOG_EXE')


def sample_pair():
    if not CD_PATH or not GOG_PATH:
        raise unittest.SkipTest('Set both RAYMAN2_RETAIL_EXE and RAYMAN2_GOG_EXE')
    return (Path(CD_PATH).read_bytes(),Path(GOG_PATH).read_bytes())


def mutate(data: bytes, va:int, *, gog=False) -> bytes:
    x=bytearray(data)
    offset=(0x1000 if gog else 0x400)+va-0x401000
    x[offset]^=1
    return bytes(x)


class ModuleScopeFlagTests(unittest.TestCase):
    def test_metadata_and_real_opcode_anchors(self):
        cd,gog=sample_pair()
        result=mod.audit(cd,gog)
        self.assertTrue(result['exact_sample_hashes_verified'])
        self.assertEqual((result['retail_direct_flag_reads'], result['retail_direct_flag_writes']), (3,3))
        self.assertEqual((result['gog_active_direct_flag_reads'], result['gog_active_direct_flag_writes']), (1,0))
        self.assertTrue(result['flag_zero_initialized_in_both_pe_loaders'])
        self.assertTrue(result['retail_psapi_one_module_short_circuit_zero'])
        self.assertEqual(result['gog_callback_replacement_returns_one'],1)
        self.assertFalse(result['safedisc_export_name_identified'])
        self.assertFalse(result['calculated_or_external_flag_writers_excluded'])
        self.assertFalse(result['callback_invocation_observed'])

    def test_two_scopes_and_bounds_match_original(self):
        cd,gog=sample_pair()
        x=mod.inspect_structure(cd,gog)
        self.assertEqual(x['retail_psapi_module_scope'], 'GetCurrentProcess -> EnumProcessModules')
        self.assertEqual(x['retail_psapi_module_list_capacity_bytes'],4096)
        self.assertIn('th32ProcessID=0',x['retail_toolhelp_module_scope'])
        self.assertIn('TH32CS_SNAPMODULE=8',x['retail_toolhelp_module_scope'])
        self.assertEqual(x['gog_archival_text_original_literal_count'],6)

    def test_exact_six_literal_sites_and_cleanup(self):
        cd,gog=sample_pair()
        a=mod.layout(cd); b=mod.layout(gog)
        self.assertEqual(mod.literal_hits(cd,a), [0x447B9A,0x447F51,0x448069,
                                                 0x448079,0x448E05,0x4494C9])
        self.assertEqual(mod.literal_hits(gog,b),[0x4494C9])
        self.assertEqual(sum(role=='read' for role,_ in mod.ORIGINAL_OPERANDS.values()),3)
        self.assertEqual(sum(role.startswith('write') for role,_ in mod.ORIGINAL_OPERANDS.values()),3)

    def test_pure_synthetic_literal_search_and_zero_bss(self):
        pattern=struct.pack('<I',mod.FLAG)
        data=bytearray(80)
        data[0:4]=pattern
        data[16:20]=pattern
        data[60:64]=pattern # must be out of selected .text
        segments={'.text':(0x1000,32,40,0,0x20000000),
                  '.data':(0x9f000,0x776d0,0x7c00,0,0)}
        self.assertEqual(mod.literal_hits(bytes(data),segments), [0x401000,0x401010])
        self.assertTrue(mod.bss_flag(segments))
        no_bss={'.text':segments['.text'], '.data':(0x9f000,0x71000,0x7c00,0,0)}
        self.assertFalse(mod.bss_flag(no_bss))

    def test_invalid_synthetic_text_section_rejected(self):
        with self.assertRaisesRegex(ValueError,'Unrecognized executable section'):
            mod.active_text(b'abcd',{'.text':(0x1000,2,2,0,0)})
        with self.assertRaisesRegex(ValueError,'Unrecognized executable section'):
            mod.active_text(b'abcd',{'.text':(0x2000,2,2,0,0x20000000)})

    def test_real_original_missing_direct_literal_rejected(self):
        cd,gog=sample_pair()
        with self.assertRaises(ValueError):
            mod.inspect_structure(mutate(cd,0x447B9A),gog)

    def test_real_gog_missing_cleanup_literal_rejected(self):
        cd,gog=sample_pair()
        with self.assertRaises(ValueError):
            mod.inspect_structure(cd,mutate(gog,0x4494C9,gog=True))

    def test_extra_literal_false_positive_rejected_in_both_files(self):
        cd,gog=sample_pair()
        a=mod.layout(cd); b=mod.layout(gog)
        # A random additional literal would be caught even without an
        # instruction decoder, as the 6-site source census is exact.
        raw=bytearray(cd); site=0x430000
        off=a['.text'][3]+site-0x401000
        raw[off:off+4]=struct.pack('<I',mod.FLAG)
        with self.assertRaisesRegex(ValueError,'unexpected direct-literal'):
            mod.inspect_structure(bytes(raw),gog)
        raw=bytearray(gog)
        off=b['.text'][3]+site-0x401000
        raw[off:off+4]=struct.pack('<I',mod.FLAG)
        with self.assertRaisesRegex(ValueError,'unexpected direct-literal'):
            mod.inspect_structure(cd,bytes(raw))

    def test_all_eight_module_scope_opcodes_mutated_rejected(self):
        cd,gog=sample_pair()
        for name,(va,seq) in mod.SCOPE_ANCHORS.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    mod.inspect_structure(mutate(cd,va),gog)

    def test_all_six_original_flag_instruction_mutations_rejected(self):
        cd,gog=sample_pair()
        for va,(role,seq) in mod.ORIGINAL_OPERANDS.items():
            with self.subTest(va=hex(va)):
                with self.assertRaises(ValueError):
                    mod.inspect_structure(mutate(cd,va),gog)

    def test_inactive_archive_mutation_rejected_but_not_counted_as_active(self):
        cd,gog=sample_pair()
        pe=mod.layout(gog)
        extra=pe['.extra']
        raw=bytearray(gog)
        raw[extra[3]+0x1000+0x101]^=0x01
        self.assertEqual(mod.literal_hits(bytes(raw),pe),[0x4494C9])
        with self.assertRaisesRegex(ValueError,'archive'):
            mod.inspect_structure(cd,bytes(raw))

    def test_full_file_hash_rejects_mutated_archive(self):
        cd,gog=sample_pair()
        raw=bytearray(gog); raw[-1]^=1
        with self.assertRaisesRegex(ValueError,'Unknown GOG'):
            mod.audit(cd,bytes(raw))

    def test_full_file_hash_rejects_mutated_original(self):
        cd,gog=sample_pair()
        with self.assertRaisesRegex(ValueError,'Unknown retail'):
            mod.audit(mutate(cd,0x401020),gog)


if __name__=='__main__':
    unittest.main()
