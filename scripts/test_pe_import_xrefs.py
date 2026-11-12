"""Offline synthetic PE import fixtures; never includes game bytes."""
import unittest
import pe_import_xrefs as p


def fixture():
    b = bytearray(0x800)
    b[:2] = b'MZ'
    b[0x3c:0x40] = (0x80).to_bytes(4, 'little')
    b[0x80:0x84] = b'PE\0\0'
    b[0x84:0x86] = (0x14c).to_bytes(2, 'little')
    b[0x86:0x88] = (2).to_bytes(2, 'little')
    b[0x94:0x96] = (0xe0).to_bytes(2, 'little')
    b[0x98:0x9a] = (0x10b).to_bytes(2, 'little')
    b[0xb4:0xb8] = (0x400000).to_bytes(4, 'little')
    b[0xf4:0xf8] = (16).to_bytes(4, 'little')
    b[0x100:0x104] = (0x2000).to_bytes(4, 'little')
    b[0x104:0x108] = (0x28).to_bytes(4, 'little')
    text_section = 0x178
    b[text_section:text_section+5] = b'.text'
    for off, val in [(8,0x200),(12,0x1000),(16,0x200),(20,0x200),(36,0x60000020)]:
        b[text_section+off:text_section+off+4] = val.to_bytes(4,'little')
    rdata = 0x1a0
    b[rdata:rdata+6] = b'.rdata'
    for off, val in [(8,0x400),(12,0x2000),(16,0x400),(20,0x400),(36,0x40000040)]:
        b[rdata+off:rdata+off+4] = val.to_bytes(4,'little')
    b[0x400:0x404] = (0x2030).to_bytes(4,'little')
    b[0x40c:0x410] = (0x2070).to_bytes(4,'little')
    b[0x410:0x414] = (0x2040).to_bytes(4,'little')
    b[0x430:0x434] = (0x2090).to_bytes(4,'little')
    b[0x440:0x444] = (0x2090).to_bytes(4,'little')
    b[0x470:0x47d] = b'KERNEL32.dll\0'
    b[0x492:0x49e] = b'CreateFileA\0'
    b[0x210:0x216] = bytes.fromhex('FF 15 40 20 40 00')
    return bytes(b)


class ImportTests(unittest.TestCase):
    def test_invalid_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'MZ'):
            p.profile(b'opaque')
        with self.assertRaisesRegex(ValueError, 'PE'):
            p.profile(b'MZ' + bytes(512))

    def test_header_metadata(self):
        h = p.parse_headers(fixture())
        self.assertEqual(h['image_base'], 0x400000)
        self.assertEqual(h['import_rva'], 0x2000)
        self.assertEqual(len(h['sections']), 2)

    def test_rva_checks(self):
        h = p.parse_headers(fixture())
        self.assertEqual(p.rva_file_offset(h,0x2030,4,0x800),0x430)
        with self.assertRaisesRegex(ValueError,'not backed'):
            p.rva_file_offset(h,0x3000,4,0x800)
        with self.assertRaisesRegex(ValueError,'not backed'):
            p.rva_file_offset(h,0x23ff,10,0x800)

    def test_import_thunk_and_callsite(self):
        result = p.profile(fixture())
        self.assertEqual(result['import_count'],1)
        self.assertEqual(result['import_dlls'],['KERNEL32.dll'])
        self.assertEqual(result['direct_callsite_candidates'],1)
        ref=result['references'][0]
        self.assertEqual(ref['api'],'CreateFileA')
        self.assertEqual(ref['iat_va'],'0x00402040')
        self.assertEqual(ref['candidate_sites'],[{'va':'0x00401010','kind':'call'}])

    def test_no_import_directory(self):
        data=bytearray(fixture())
        data[0x100:0x104]=bytes(4)
        result=p.profile(bytes(data))
        self.assertEqual(result['import_count'],0)
        self.assertEqual(result['references'],[])

    def test_virtual_adjacent_sections_with_disjoint_raw_offsets(self):
        # Metadata may be contiguous in virtual memory but not in the file.
        data = bytearray(0x400)
        data[0x200:0x202] = b"AB"
        data[0x300:0x302] = b"C\0"
        headers = {"sections": [
            {"rva": 0x2000, "raw_off": 0x200, "raw_size": 2},
            {"rva": 0x2002, "raw_off": 0x300, "raw_size": 2},
        ]}
        self.assertEqual(p.cstr(data, headers, 0x2000), "ABC")

    def test_name_unterminated_rejected(self):
        data=bytearray(fixture())
        data[0x470:0x700]=b'K'*0x290
        with self.assertRaisesRegex(ValueError,'unterminated'):
            p.profile(bytes(data))

    def test_bounded_input(self):
        with self.assertRaisesRegex(ValueError,'oversized'):
            p.profile(bytes(p.MAX_INPUT + 1))


if __name__ == '__main__':
    unittest.main()
