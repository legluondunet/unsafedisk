"""Synthetic tests plus optional private exact-owner-binary integration tests.

Set RAYMAN2_RETAIL_EXE and RAYMAN2_GOG_EXE to audit the actual owned images.
Never commit proprietary game bytes or a reconstructed executable.
"""
import os
import struct
import unittest
from pathlib import Path
import rayman2_callback2c_branch_audit as m


def synthetic_record(name:str)->bytes:
    sub,xor,dsub,dxor=7,19,5,11
    out=bytearray([sub,xor,dsub,dxor,len(name)])
    for ch in name.encode('ascii'):
        out.append(((ch ^ xor)+sub)&255)
        sub=(sub+dsub)&255
        xor=(xor+dxor)&255
    out.extend(b'\0'*(76-len(out)))
    return bytes(out)


class Callback2CTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        a=os.environ.get('RAYMAN2_RETAIL_EXE')
        b=os.environ.get('RAYMAN2_GOG_EXE')
        cls.real=(Path(a).read_bytes(),Path(b).read_bytes()) if a and b else None

    def owners(self):
        if self.real is None:
            self.skipTest('Private exact-SHA inputs not in CI')
        return self.real

    def mutation(self,kind,va,operand=0):
        cd,gog=self.owners()
        target=bytearray(cd if kind=='cd' else gog)
        raw=0x400 if kind=='cd' else 0x1000
        at=raw + va-0x401000 + operand
        target[at] ^= 0x01
        return (bytes(target),gog) if kind=='cd' else (cd,bytes(target))

    def test_encoded_api_names_and_bad_records(self):
        for name in m.EXPORTS.values():
            self.assertEqual(m.encoded_export(synthetic_record(name)),name)
        with self.assertRaises(ValueError):m.encoded_export(b'bad')
        with self.assertRaises(ValueError):m.encoded_export(bytes(76))

    def test_call_rel32_target_and_bad_opcode(self):
        target=0x4481B0
        site=0x448E11
        delta=target-site-5
        buf=b'\xe8'+struct.pack('<i',delta)
        pe={'.text':(0x4000,5,5,0,0x20000000)}
        m.call_target(buf,{'.text':(site-m.IMGBASE,5,5,0,0x20000000)},site,target)
        self.assertEqual(len(buf),5)
        self.assertEqual(int.from_bytes(buf[1:],'little',signed=True)+site+5,target)
        with self.assertRaises(ValueError):m.call_target(buf,{'.text':(0x48E11,5,5,0,0x20000000)},site,target+1)

    def test_reject_bad_pe_and_nonfilebacked_address(self):
        with self.assertRaises(ValueError):m.layout(b'not pe')
        with self.assertRaises(ValueError):m.raw_at(b'a'*8, {'.text':(0x1000,8,8,0,0)},0x401010,2)

    def test_authenticated_real_samples_and_backends(self):
        cd,gog=self.owners()
        result=m.audit(cd,gog)
        self.assertTrue(result['sample_sha256_pinned'])
        self.assertEqual(result['gog_0x448DE0_returns_constant'],1)
        self.assertEqual(len(result['five_toolhelp_export_presences_tested']),5)
        self.assertEqual(result['other_process_exports']['25'],'EnumProcessModules')
        self.assertFalse(result['safedisc_verdict_identified'])
        self.assertTrue(result['retail_checks_masked_pe_export_names_across_loaded_modules'])
        self.assertTrue(result['gog_replaces_match_count_with_constant_one'])

    def test_sample_hash_mutation_rejected(self):
        cd,gog=self.owners()
        mutable=bytearray(cd);mutable[-1]^=1
        with self.assertRaisesRegex(ValueError,'Unknown retail'):
            m.audit(bytes(mutable),gog)

    def test_vector_dispatch_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x004671eb'):
            m.inspect_structure(*self.mutation('cd',0x4671EB))

    def test_gog_constant_success_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x00448de0'):
            m.inspect_structure(*self.mutation('gog',0x448DE0))

    def test_guard_branch_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x00448de0'):
            m.inspect_structure(*self.mutation('cd',0x448DE0,3))

    def test_backend_call_target_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x00448e11'):
            m.inspect_structure(*self.mutation('cd',0x448E11,1))

    def test_backend_flag_writer_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x00448067'):
            m.inspect_structure(*self.mutation('cd',0x448067,6))

    def test_availability_branch_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x00447e25'):
            m.inspect_structure(*self.mutation('cd',0x447E25,2))

    def test_descriptor_name_mutation_rejected(self):
        cd,gog=self.owners()
        # Export descriptor #19 is in the file-backed original .data.
        target=bytearray(cd)
        at=0x9d600 + (0x4A13D0 + 76*19 - 0x49f000) + 9
        target[at] ^= 0x20
        with self.assertRaises(ValueError):
            m.inspect_structure(bytes(target),gog)

    def test_provider_body_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x00448653'):
            m.inspect_structure(*self.mutation('cd',0x448653,1))

    def test_psapi_pe_export_walker_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x00448351'):
            m.inspect_structure(*self.mutation('cd',0x448351,3))

    def test_toolhelp_match_counter_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x0044881e'):
            m.inspect_structure(*self.mutation('cd',0x44881E,2))

    def test_toolhelp_shared_export_scanner_call_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x0044880e'):
            m.inspect_structure(*self.mutation('cd',0x44880E,1))

    def test_retained_cleanup_mutation_rejected(self):
        with self.assertRaisesRegex(ValueError,'0x004494c7'):
            m.inspect_structure(*self.mutation('gog',0x4494C7,1))

    def test_gog_extra_archive_is_not_live_code(self):
        cd,gog=self.owners()
        target=bytearray(gog)
        # The non-executable archive copy, by design, is not a live callback.
        needle=cd[0x400:0x400+64]
        start=gog.find(needle,0x9c000)
        self.assertGreaterEqual(start,0)
        target[start+10]^=1
        r=m.inspect_structure(cd,bytes(target))
        self.assertEqual(r['gog_0x448DE0_returns_constant'],1)
        with self.assertRaisesRegex(ValueError,'Unknown GOG'):
            m.audit(cd,bytes(target))

if __name__=='__main__':unittest.main()
