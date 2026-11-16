import struct
import unittest

from rayman2_trampoline_audit import (
    BASE, STRIDE, api_name, bridge_targets, tail_from_builder
)


def descriptor_for(index, name):
    content = bytearray(STRIDE * 35)
    off = (index - 1) * STRIDE
    name = name.encode('ascii')
    content[off:off+5] = bytes([0, 0, 0, 0, len(name)])
    content[off+5:off+5+len(name)] = name
    return {'.data': (BASE, content)}


def make_builder(index, transfer, prefix='edx'):
    ptr = BASE + (index-1)*STRIDE + 0x30
    mask = ptr - 0x30
    specs = {0:0xA1,5:0x33,6:0x05,11:0xFF if transfer=='JMP EAX' else 0x50,
             12:0xE0 if transfer=='JMP EAX' else 0xC3}
    row = {}
    for num, (off, value) in enumerate(specs.items()):
        op = (f'BYTE PTR [edx+{0x510EA0+off:#x}],{value:#x}' if prefix=='edx'
              else f'BYTE PTR [esi{f"+{off:#x}" if off else ""}],{value:#x}')
        row[0x702E + (0,17,24,41,48)[num]] = (b'\x00','mov',op)
    pfx=('edx+0x510ea' if prefix=='edx' else 'esi+0x')
    row[0x7035] = (b'\x00','mov',f'DWORD PTR [{pfx}1],{ptr:#x}')
    row[0x704D] = (b'\x00','mov',f'DWORD PTR [{pfx}7],{mask:#x}')
    return row,ptr,mask


class TrampolineTests(unittest.TestCase):
    def test_export_decoder_and_descriptor_index(self):
        rows = descriptor_for(8,'CreateFileA')
        ptr=BASE+7*STRIDE+0x30
        self.assertEqual(api_name(rows,ptr,ptr-0x30),(8,'CreateFileA'))

    def test_reject_wrong_pair(self):
        with self.assertRaises(ValueError):
            api_name(descriptor_for(8,'CreateFileA'),BASE+7*STRIDE+0x31,BASE+7*STRIDE)

    def test_generated_jump_template(self):
        ins,_,_=make_builder(8,'JMP EAX')
        self.assertEqual(tail_from_builder(ins,0x7035,0x704D,'edx+0x510ea')[0],'JMP EAX')

    def test_generated_push_return_template(self):
        ins,_,_=make_builder(10,'PUSH EAX; RET',prefix='esi')
        self.assertEqual(tail_from_builder(ins,0x7035,0x704D,'esi+0x')[0],'PUSH EAX; RET')

    def test_reject_incomplete_generator(self):
        ins,_,_=make_builder(8,'JMP EAX')
        del ins[0x702E]
        with self.assertRaises(ValueError):
            tail_from_builder(ins,0x7035,0x704D,'edx+0x510ea')

    def test_bridge_matches_export_and_gog_iat(self):
        cd,_,_=make_builder(8,'JMP EAX')
        cd[0x7070] = (b'\xFF\xD6','call','esi')
        gog={0x7070:(b'\xFF\x15'+struct.pack('<I',0x49c058),'call','DWORD PTR ds:0x49c058')}
        rows,bad,counts=bridge_targets(cd,gog,descriptor_for(8,'CreateFileA'),{0x49c058:'CreateFileA'})
        self.assertFalse(bad)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['template_transfer'],'JMP EAX')
        self.assertEqual(counts,{'changed':1})

    def test_bridge_rejects_wrong_import(self):
        cd,_,_=make_builder(8,'JMP EAX')
        cd[0x7070] = (b'\xFF\xD6','call','esi')
        gog={0x7070:(b'\xFF\x15'+struct.pack('<I',0x49c04c),'call','DWORD PTR ds:0x49c04c')}
        rows,bad,_=bridge_targets(cd,gog,descriptor_for(8,'CreateFileA'),{0x49c04c:'ReadFile'})
        self.assertFalse(rows)
        self.assertEqual(len(bad),1)


if __name__=='__main__':
    unittest.main()
