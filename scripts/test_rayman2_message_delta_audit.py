"""Synthetic tests; optionally run real-input integration via environment variables."""
import os
import struct
import unittest
from pathlib import Path
from rayman2_message_delta_audit import PE32, audit_images, checked_sample, rel32_target, short_target


def fixture(blob_size=0xA0000):
    blob = bytearray(blob_size)
    blob[:2] = b'MZ'
    struct.pack_into('<I', blob, 0x3C, 0x80)
    blob[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', blob,0x84,0x14c,1,0,0,0,0xe0,0)
    struct.pack_into('<H',blob,0x98,0x10b)
    struct.pack_into('<I',blob,0x98+0x1c,0x400000)
    sh=0x98+0xe0
    blob[sh:sh+8]=b'.text\0\0\0'
    struct.pack_into('<IIII',blob,sh+8,0x9a200,0x1000,0x9a200,0x400)
    return blob


def store(blob, va, raw):
    blob[0x400+(va-0x401000):0x400+(va-0x401000)+len(raw)] = raw


def make_pair():
    from rayman2_message_delta_audit import rel32_target
    # These are declared constants describing precisely checked x86 spans;
    # fixture code deliberately does not carry a real game's full text.
    common = {
        0x401B50: '8B 4C 24 04 53 83 C1 DF',
        0x402039:'C7 44 24 18 D0 22 40 00', 0x4022DD:'8B 7C 24 1C', 0x401B5C:'83 F9 04',
        0x401C30:'6D 1B 40 00 06 1C 40 00 2A 1C 40 00 9A 1B 40 00 20 1C 40 00',
        0x402520:'81 FF 18 02 00 00',0x402528:'81 FF 00 04 00 00',
        0x40252E:'75 1D 55 53',0x402537:'83 C4 08 EB 0F',
        0x40254B:'8B F0 85 F6',0x402580:'8B 4C 24 04 33 C0 8B 51 04',
        0x402589:'83 FA 1C 74 19',0x40258E:'81 FA 00 04 00 00',
        0x402596:'8B 41 0C 8B 49 08 50 51',0x4025A3:'83 C4 08 C3',
        0x4025A7:'8B 41 08 85 C0',0x4025BE:'C3',
    }
    a, b = fixture(), fixture()
    for va, raw in common.items():
        store(a,va,bytes.fromhex(raw));store(b,va,bytes.fromhex(raw))
    retail_call=b'\xE8'+struct.pack('<i',0x401B50-0x402532-5)
    second_call=b'\xE8'+struct.pack('<i',0x401B50-0x40259E-5)
    for blob in (a,b):store(blob,0x40259E,second_call)
    store(a,0x402532,retail_call);store(b,0x402532,b'\x90'*5)
    store(a,0x402594,b'\x75\x28');store(b,0x402594,b'\xEB\x28')
    return PE32(bytes(a)),PE32(bytes(b))


class MessageDeltaTests(unittest.TestCase):
    def test_synthetic_pair(self):
        a,b=make_pair();self.assertEqual(len(audit_images(a,b)['changes']),2)

    def test_wrong_jump(self):
        a,b=make_pair();blob=bytearray(b.blob);store(blob,0x402594,b'\xEB\x27')
        with self.assertRaisesRegex(ValueError,'target mismatch'):audit_images(a,PE32(bytes(blob)))

    def test_wrong_original_call(self):
        a,b=make_pair();blob=bytearray(a.blob);store(blob,0x402532,b'\xE8'+b'\x00'*4)
        with self.assertRaisesRegex(ValueError,'call target mismatch'):audit_images(PE32(bytes(blob)),b)

    def test_wrong_gog_nop(self):
        a,b=make_pair();blob=bytearray(b.blob);store(blob,0x402532,b'\x90'*4+b'\xCC')
        with self.assertRaisesRegex(ValueError,'call disabled'):audit_images(a,PE32(bytes(blob)))

    def test_common_anchor_mutation(self):
        a,b=make_pair();blob=bytearray(b.blob);store(blob,0x402528,b'\x81\xFF\x20\x04\x00\x00')
        with self.assertRaisesRegex(ValueError,'common'):audit_images(a,PE32(bytes(blob)))

    def test_call_signed_displacement(self):
        self.assertEqual(rel32_target(0x402532,b'\xE8'+struct.pack('<i',0x401B50-0x402532-5)),0x401B50)

    def test_short_signed_displacement(self):
        self.assertEqual(short_target(0x100,b'\x75\xFE',0x75),0x100)

    def test_wrong_opcode(self):
        with self.assertRaisesRegex(ValueError,'not CALL'):rel32_target(0x100,b'\xEB\0\0\0\0')
        with self.assertRaisesRegex(ValueError,'not short opcode'):short_target(0x100,b'\xEB\x28',0x75)

    def test_out_of_range(self):
        a,_=make_pair()
        with self.assertRaisesRegex(ValueError,'unmapped'):a.at(0xF0000000,2)

    def test_wrong_pe(self):
        with self.assertRaisesRegex(ValueError,'not an MZ'):PE32(b'bad')

    def test_hash_refusal(self):
        with self.assertRaisesRegex(ValueError,'refusing'):checked_sample(__file__,'retail')

    @unittest.skipUnless(os.environ.get('RAYMAN2_RETAIL') and os.environ.get('RAYMAN2_GOG'), 'owner EXEs not configured')
    def test_exact_owner_samples(self):
        a=PE32(checked_sample(os.environ['RAYMAN2_RETAIL'],'retail'))
        b=PE32(checked_sample(os.environ['RAYMAN2_GOG'],'gog'))
        self.assertEqual(len(audit_images(a,b)['changes']),2)


if __name__=='__main__':unittest.main()