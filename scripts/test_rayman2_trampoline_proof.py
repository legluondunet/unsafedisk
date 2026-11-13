"""Synthetic-only tests; no protected game data distributed."""
import unittest
import os
from pathlib import Path
from rayman2_trampoline_proof import (analyze,code_gen,flush_pattern,p32,WRAPPERS,
                                      masked_slot,verify_slot_initializer,SLOT_ANCHORS,
                                      SLOT_INIT_CALLS,BOOTSTRAP_ANCHORS,BOOTSTRAP_RECORD,BOOTSTRAP_SLOT,
                                      RELAY_ENTRY,RELAY_LENGTH,RELAY_STARTUP_CALL,
                                      RELAY_CALLS,GOG_IMMEDIATE_RET_CALLEES,RELAY_TOOLHELP_SLOT_SITES,
                                      RELAY_GENERATOR_ANCHORS,verify_retained_bootstrap_chain)


class TrampolineProofTests(unittest.TestCase):
    def test_reject_unknown_hash(self):
        with self.assertRaisesRegex(ValueError,'protected Rayman 2 SHA-256'):
            analyze(b'synthetic')

    def test_four_wrappers_distinct(self):
        self.assertEqual(len(WRAPPERS),4)
        self.assertEqual(len({w[0] for w in WRAPPERS}),4)
        self.assertEqual({w[1] for w in WRAPPERS},{8,10,11,12})

    def test_push_ret_template_uses_masked_pointer_pair(self):
        b=code_gen(0x4A1714,0x4A1744,'push-ret')
        self.assertEqual(b[:3],b'\xc6\x06\x68')
        self.assertEqual(b[5:9],p32(0x4A1744))
        self.assertIn(p32(0x4A1714),b)
        self.assertTrue(b.endswith(b'\x89\x56\x01'))

    def test_mov_xor_jmp_uses_masked_pointer_pair(self):
        b=code_gen(0x4A1630,0x4A1660,'mov-xor-jmp')
        self.assertIn(p32(0x4A1630),b)
        self.assertIn(p32(0x4A1660),b)
        self.assertTrue(b.endswith(b'\xc6\x46\x0c\xe0'))

    def test_mov_xor_push_ret(self):
        b=code_gen(0x4A16C8,0x4A16F8,'mov-xor-push-ret')
        self.assertTrue(b.endswith(b'\xc6\x46\x0c\xc3'))

    def test_wrong_kind_rejected(self):
        with self.assertRaisesRegex(ValueError,'unknown trampoline'):
            code_gen(0,0,'jmp-nop')

    def test_cache_flush_sequence(self):
        b=flush_pattern()
        self.assertIn(p32(0x4A1498),b)
        self.assertIn(p32(0x4A144C),b)
        self.assertIn(p32(0x464),b)
        self.assertIn(p32(0x510EA0),b)
        self.assertTrue(b.endswith(b'\x50\x33\xca\xff\xd1'))

    def test_first_masked_slot_address(self):
        self.assertEqual(masked_slot(1),(0x004A141C,0x004A144C))

    def test_four_io_slot_addresses(self):
        self.assertEqual(masked_slot(8),(0x004A1630,0x004A1660))
        self.assertEqual(masked_slot(10),(0x004A16C8,0x004A16F8))
        self.assertEqual(masked_slot(11),(0x004A1714,0x004A1744))
        self.assertEqual(masked_slot(12),(0x004A1760,0x004A1790))

    def test_last_masked_slot_address(self):
        self.assertEqual(masked_slot(35),(0x004A1E34,0x004A1E64))

    def test_invalid_descriptor_numbers_refused(self):
        for bad in (-1,0,36,100,True,1.0,'1'):
            with self.subTest(bad=bad),self.assertRaisesRegex(ValueError,'1..35'):
                masked_slot(bad)

    def test_original_initializer_anchor_inventory(self):
        self.assertEqual(len(SLOT_ANCHORS),15)
        self.assertEqual(len(SLOT_INIT_CALLS),5)
        self.assertEqual(sum(target==0x447AF0 for target in SLOT_INIT_CALLS.values()),3)

    def test_special_getmodulehandle_bootstrap_record(self):
        self.assertEqual(BOOTSTRAP_RECORD,0x004A13D0)
        self.assertEqual(BOOTSTRAP_SLOT,BOOTSTRAP_RECORD+0x30)
        self.assertEqual(len(BOOTSTRAP_ANCHORS),10)

    def test_exact_private_samples_optional(self):
        root=Path(os.environ.get('UNSAFEDISK_SAMPLES','/no-samples'))
        original=root/'Rayman2(3).exe'
        gog=root/'rayman2(4).exe'
        if not original.is_file() or not gog.is_file():
            self.skipTest('private retail and GOG game binaries not provided')
        report=analyze(original.read_bytes(),gog.read_bytes())
        init=report['masked_pointer_initialization']
        self.assertEqual(init['api_descriptors_verified'],35)
        self.assertEqual(init['init_instruction_anchors_verified'],15)
        self.assertTrue(init['gog_234_int3_resolver_bytes_verified'])
        self.assertEqual(init['special_bootstrap_api'],'GetModuleHandleA')
        self.assertEqual(init['get_loaded_module_handle_helper_calls_verified'],2)
        self.assertEqual(init['special_bootstrap_anchor_count'],10)
        self.assertFalse(report['runtime_execution_proven'])
        relay=report['retained_retail_GOG_bootstrap_callchain']
        self.assertEqual(relay['initializer_bytes_compared'],331)
        self.assertEqual(relay['total_original_direct_CALLs_verified'],6)
        self.assertTrue(relay['gog_four_callees_replaced_with_RET_INT3_verified'])
        self.assertEqual(relay['original_fourth_callee_process_module_APIs'],
                         ['CreateToolhelp32Snapshot','Process32First','Process32Next',
                          'Module32First','Module32Next'])
        self.assertTrue(relay['gog_fifth_callee_rewritten_to_store_dot_in_global_0x004A6AD8'])

    @staticmethod
    def synthetic_retail_relay():
        # Synthetic PE RVA mapping: no copyrighted game instructions in fixtures.
        block=bytearray(b'\x90'*0x49000)
        h={'image_base':0x00400000,'sections':[{
            'rva':0x1000,'raw_off':0,
            'raw_size':len(block),'virtual_size':len(block)
        }]}
        def put(site,value):
            ofs=site-0x00401000
            block[ofs:ofs+len(value)]=value
        put(RELAY_ENTRY,bytes.fromhex('55 8B EC 83 EC 08 A1'))
        for addr,pattern in RELAY_GENERATOR_ANCHORS.items():
            put(addr,bytes.fromhex(pattern))
        for descriptor_index,site in RELAY_TOOLHELP_SLOT_SITES.items():
            import struct
            _,ptr=masked_slot(descriptor_index)
            put(site,b'\xa1'+struct.pack('<I',ptr))
        for site,target in {RELAY_STARTUP_CALL:RELAY_ENTRY,**RELAY_CALLS}.items():
            import struct
            put(site,b'\xe8'+struct.pack('<i',target-site-5))
        put(0x00449496,bytes.fromhex('85 DB 74 0A'))
        put(0x00401D8E,bytes.fromhex('68 04 01 00 00'))
        put(0x00401D93,bytes.fromhex('50 FF 15 B4 C0 49 00'))
        return block,h

    def test_relay_original_five_call_inventory(self):
        self.assertEqual(RELAY_ENTRY,0x00449360)
        self.assertEqual(RELAY_LENGTH,331)
        self.assertEqual(len(RELAY_CALLS),5)
        self.assertEqual(len(GOG_IMMEDIATE_RET_CALLEES),4)
        self.assertEqual(len(RELAY_GENERATOR_ANCHORS),9)
        self.assertEqual(len(RELAY_TOOLHELP_SLOT_SITES),5)
        self.assertEqual(sorted(RELAY_TOOLHELP_SLOT_SITES),[19,20,21,22,23])
        self.assertEqual(set(RELAY_CALLS.values())-
                         set(GOG_IMMEDIATE_RET_CALLEES),{0x00448E30})

    def test_synthetic_retail_bootstrap_initializer(self):
        b,h=self.synthetic_retail_relay()
        report=verify_retained_bootstrap_chain(bytes(b),h)
        self.assertEqual(report['total_original_direct_CALLs_verified'],6)
        self.assertEqual(report['shared_PRNG_seed_word_count'],281)
        self.assertFalse(report['runtime_execution_proven'])
        self.assertFalse(report['gog_four_callees_replaced_with_RET_INT3_verified'])

    def test_synthetic_relay_rejects_modified_CALL(self):
        b,h=self.synthetic_retail_relay()
        b[0x00449485-0x00401000]^=1
        with self.assertRaisesRegex(ValueError,'opcode pattern'):
            verify_retained_bootstrap_chain(bytes(b),h)

    def test_synthetic_relay_rejects_wrong_seed(self):
        b,h=self.synthetic_retail_relay()
        b[0x0044939E-0x00401000]^=1
        with self.assertRaisesRegex(ValueError,'opcode pattern'):
            verify_retained_bootstrap_chain(bytes(b),h)

    def test_synthetic_relay_rejects_changed_process_enumerator(self):
        b,h=self.synthetic_retail_relay()
        b[0x00447E04-0x00401000]^=1
        with self.assertRaisesRegex(ValueError,'opcode pattern'):
            verify_retained_bootstrap_chain(bytes(b),h)

    def test_synthetic_relay_rejects_missing_original_helper(self):
        b,h=self.synthetic_retail_relay()
        b[0x00447DE0-0x00401000]=0xc3
        with self.assertRaisesRegex(ValueError,'retail callee'):
            verify_retained_bootstrap_chain(bytes(b),h)

    def test_flush_span_covers_all_generated_code(self):
        self.assertGreaterEqual(0x464,0x455-1+13)


if __name__=='__main__':
    unittest.main()
