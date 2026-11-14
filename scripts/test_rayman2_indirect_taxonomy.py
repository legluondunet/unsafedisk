import struct
import unittest

from rayman2_indirect_taxonomy import (
    bootstrap_name, classify_non_descriptor_transfer, classify_sites, decode_register_call,
    esi_descriptor_call, summarize,
)
from rayman2_trampoline_audit import BASE, STRIDE


def fake_regions(index=2, name='GetCurrentProcess'):
    b=bytearray(STRIDE*35)
    off=(index-1)*STRIDE
    namebytes=name.encode('ascii')
    b[off:off+5]=bytes((0,0,0,0,len(namebytes)))
    b[off+5:off+5+len(namebytes)]=namebytes
    return {'.data':(BASE,b)}


def bootstrap_regions():
    # Synthetic descriptor index 0 immediately before the ordinary 35 rows.
    name=b'GetModuleHandleA'
    record=bytearray(STRIDE)
    record[4]=len(name)
    record[5:5+len(name)]=name
    return {'.data':(BASE-STRIDE,record)}


def instruction(raw, mnemonic='mov', operands=''):
    return (raw,mnemonic,operands)


class IndirectTaxonomyTests(unittest.TestCase):
    def test_masked_eax_get_current_process(self):
        mask=BASE+STRIDE
        ptr=mask+0x30
        code={0x1000: instruction(b'\x8b\x0d'+struct.pack('<I',ptr)),
              0x1006: instruction(b'\xa1'+struct.pack('<I',mask)),
              0x100b: instruction(b'\x33\xc1','xor','eax,ecx'),
              0x100d: instruction(b'\xff\xd0','call','eax')}
        self.assertEqual(decode_register_call(code,0x100d,'eax',fake_regions())['name'],'GetCurrentProcess')
        self.assertEqual(classify_sites(code,{0x100d: instruction(b'\x90','nop')},fake_regions())[0]['category'],'descriptor-register-call')

    def test_masked_eax_flush_wrapper(self):
        mask=BASE
        ptr=mask+0x30
        code={0x1000: instruction(b'\x8b\x0d'+struct.pack('<I',ptr)),
              0x1006: instruction(b'\xa1'+struct.pack('<I',mask)),
              0x100b: instruction(b'\x33\xc1','xor','eax,ecx')}
        self.assertEqual(decode_register_call(code,0x100d,'eax',fake_regions(1,'FlushInstructionCache'))['name'],'FlushInstructionCache')

    def test_masked_ecx_flush_instruction_cache(self):
        mask=BASE
        ptr=mask+0x30
        code={0x1010:instruction(b'\x8b\x15'+struct.pack('<I',ptr)),
              0x1016:instruction(b'\x8b\x0d'+struct.pack('<I',mask)),
              0x1020:instruction(b'\x33\xca','xor','ecx,edx')}
        self.assertEqual(decode_register_call(code,0x1022,'ecx',fake_regions(1,'FlushInstructionCache'))['name'],'FlushInstructionCache')

    def test_bootstrap_getmodulehandlea_descriptor_zero(self):
        code={0x1000:instruction(b'\x8b\x15'+struct.pack('<I',0x4A1400)),
              0x1006:instruction(b'\x8b\x0d'+struct.pack('<I',0x4A13D0)),
              0x100C:instruction(b'\x33\xca','xor','ecx,edx')}
        regions=bootstrap_regions()
        self.assertEqual(bootstrap_name(regions),'GetModuleHandleA')
        row=decode_register_call(code,0x100e,'ecx',regions)
        self.assertEqual(row['category'],'bootstrap-descriptor-register-call')
        self.assertEqual(row['name'],'GetModuleHandleA')

    def test_wrong_pair_is_rejected(self):
        code={0x1000:instruction(b'\x8b\x0d'+struct.pack('<I',BASE+0x31)),
              0x1006:instruction(b'\xa1'+struct.pack('<I',BASE)),
              0x100b:instruction(b'\x33\xc1','xor','eax,ecx')}
        self.assertIsNone(decode_register_call(code,0x100d,'eax',fake_regions(1,'FlushInstructionCache')))

    def test_complete_generated_descriptor_trampoline(self):
        ptr=BASE+0x30
        mask=BASE
        code={}
        for j,(off,byte) in enumerate([(0,0xa1),(5,0x33),(6,0x05),(11,0xff),(12,0xe0)]):
            args=f'BYTE PTR [esi{f"+{off:#x}" if off else ""}],{byte:#x}'
            code[0x7010+j*9]=instruction(b'\xc6','mov',args)
        code[0x7020]=instruction(b'\xc7','mov',f'DWORD PTR [esi+0x1],{ptr:#x}')
        code[0x7030]=instruction(b'\xc7','mov',f'DWORD PTR [esi+0x7],{mask:#x}')
        got=esi_descriptor_call(code,0x7060,fake_regions(1,'FlushInstructionCache'))
        self.assertIsNotNone(got)
        self.assertEqual(got['name'],'FlushInstructionCache')
        self.assertEqual(got['transfer'],'JMP EAX')

    def test_generated_push_ret(self):
        index=11
        mask=BASE+(index-1)*STRIDE
        ptr=mask+0x30
        pair=(b'\x8b\x15'+struct.pack('<I',ptr),
              b'\x8b\x3d'+struct.pack('<I',mask))
        code={0x1000:instruction(b'\xc6\x06\x68'),
              0x1003:instruction(pair[0]),
              0x1009:instruction(pair[1]),
              0x100f:instruction(b'\xc6\x46\x05\xc3'),
              0x1013:instruction(b'\x33\xd7','xor','edx,edi'),
              0x1015:instruction(b'\x89\x56\x01')}
        regions=fake_regions(index,'CloseHandle')
        result=classify_non_descriptor_transfer(code,0x1020,regions)
        self.assertEqual((result['category'],result['name']),('generated-push-immediate-ret','CloseHandle'))
        code[0x1000]=instruction(b'\xc6\x82\xa0\x0e\x51\x00\x68')
        self.assertEqual(classify_non_descriptor_transfer(code,0x1020,regions)['name'],'CloseHandle')
        # The alternate EBX mask register is used by the original 0x450CF6 site.
        code[0x1009]=instruction(b'\x8b\x1d'+struct.pack('<I',mask))
        code[0x1013]=instruction(b'\x33\xd3','xor','edx,ebx')
        self.assertEqual(classify_non_descriptor_transfer(code,0x1020,regions)['name'],'CloseHandle')
        del code[0x1009]
        self.assertIsNone(classify_non_descriptor_transfer(code,0x1020,regions))

    def test_generated_relative_jump(self):
        index=22
        mask=BASE+(index-1)*STRIDE
        ptr=mask+0x30
        code={0x1000:instruction(b'\xc6\x82\xa0\x0e\x51\x00\xe9'),
              0x1008:instruction(b'\x8b\x0d'+struct.pack('<I',mask)),
              0x100e:instruction(b'\x8b\x15'+struct.pack('<I',ptr)),
              0x1014:instruction(b'\x33\xd1','xor','edx,ecx'),
              0x1016:instruction(b'\x2b\xd6','sub','edx,esi'),
              0x1018:instruction(b'\x83\xea\x05','sub','edx,0x5'),
              0x101b:instruction(b'\x89\x56\x01')}
        r=classify_non_descriptor_transfer(code,0x1020,fake_regions(index,'Module32First'))
        self.assertEqual((r['category'],r['name']),('generated-rel32-jump','Module32First'))
        code[0x1018]=instruction(b'\x90','nop')
        self.assertIsNone(classify_non_descriptor_transfer(code,0x1020,fake_regions(index,'Module32First')))

    def test_dynamic_mask_jump(self):
        opcodes=(b'\xc6\x06\xa1', b'\xc7\x46\x01\x00\x14\x4a\x00',
                 b'\x89\x7e\x07', b'\xc6\x46\x0b\xff', b'\xc6\x46\x0c\xe0')
        code={0x1000+i*8:instruction(op) for i,op in enumerate(opcodes)}
        code[0x0fe0]=instruction(b'\xbf\xd0\x13\x4a\x00')
        result=classify_non_descriptor_transfer(code,0x1040,bootstrap_regions())
        self.assertEqual(result['category'],'generated-bootstrap-trampoline')
        self.assertEqual(result['name'],'GetModuleHandleA')
        del code[0x1008]
        self.assertIsNone(classify_non_descriptor_transfer(code,0x1040,bootstrap_regions()))

    def test_unchanged_and_nonregister_calls_are_excluded(self):
        code={0x1010:instruction(b'\xff\xd0','call','eax'),
              0x1020:instruction(b'\xff\x15\x20\x00\x00\x00','call','DWORD PTR'),
              0x1030:instruction(b'\xff\xd1','call','ecx')}
        gog={0x1010:code[0x1010],0x1030:code[0x1030]}
        self.assertEqual(classify_sites(code,gog,fake_regions()),[])

    def test_summary_records_unknown_explicitly(self):
        data=[{'site':'0x1000','category':'unclassified','name':None,'gog_instruction_at_same_site':'int3'}]
        self.assertEqual(summarize(data)['unclassified_sites'],['0x1000'])


if __name__=='__main__':
    unittest.main()
