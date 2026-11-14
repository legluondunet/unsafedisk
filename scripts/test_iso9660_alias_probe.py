"""Synthetic-only ISO9660 tests: no copyrighted assets or proprietary disc bytes."""
from __future__ import annotations
from io import BytesIO
import os
from pathlib import Path
import struct
import tempfile
import unittest
from iso9660_alias_probe import EXPECTED, SECTOR, _record, scan, scan_iso_file


def rec(name: bytes, lba: int, length: int, directory=False, bad_endian=False):
    n = 33+len(name)
    if n & 1: n+=1
    b=bytearray(n)
    b[0]=n
    struct.pack_into('<I',b,2,lba)
    struct.pack_into('>I',b,6,lba+(1 if bad_endian else 0))
    struct.pack_into('<I',b,10,length)
    struct.pack_into('>I',b,14,length)
    b[25]=2 if directory else 0
    b[28:32]=b'\1\0\0\1'
    b[32]=len(name)
    b[33:33+len(name)]=name
    return bytes(b)


def make_iso(names=None, shared_lba=True, bad_endian=False):
    contents=bytearray(SECTOR*32)
    pvd=bytearray(SECTOR)
    pvd[:7]=b'\x01CD001\x01'
    struct.pack_into('<I',pvd,80,32)
    struct.pack_into('>I',pvd,84,32)
    struct.pack_into('<H',pvd,128,SECTOR)
    struct.pack_into('>H',pvd,130,SECTOR)
    pvd[156:190]=rec(b'\0',20,SECTOR,True)
    contents[16*SECTOR:17*SECTOR]=pvd
    entries=[rec(b'\0',20,SECTOR,True),rec(b'\1',20,SECTOR,True)]
    for i,name in enumerate(names or []):
        entries.append(rec((name+';1').encode(),25 if shared_lba else 25+i,
                           0xC0000000+i*321,False,bad_endian=bad_endian))
    sector=b''.join(entries)
    if len(sector)>SECTOR:raise ValueError('synthetic fixture over sector length')
    contents[20*SECTOR:20*SECTOR+len(sector)] = sector
    return bytes(contents)


class IsoProbeTests(unittest.TestCase):
    def test_empty_iso(self):
        r=scan_iso_file(BytesIO(make_iso()),SECTOR*32)
        self.assertEqual(r['candidate_name_count'],0)
        self.assertEqual(r['directory_count'],1)

    def test_many_fake_names_share_physical_lba(self):
        names=sorted(EXPECTED)
        r=scan_iso_file(BytesIO(make_iso(names)),SECTOR*32)
        self.assertEqual(r['candidate_name_count'],24)
        self.assertEqual(r['expected_candidate_count'],24)
        self.assertEqual(r['file_count'],24)
        self.assertEqual(len(r['same_lba_groups']),1)
        self.assertEqual(r['same_lba_groups'][0]['lba'],25)
        self.assertEqual(len(r['same_lba_groups'][0]['names']),24)
        self.assertTrue(all(not x['inside_physical_image'] for x in r['candidates']))
        self.assertTrue(all(x['start_inside_physical_image'] for x in r['candidates']))

    def test_single_file_no_alias(self):
        r=scan_iso_file(BytesIO(make_iso(['LEVELS0.DAT'])),SECTOR*32)
        self.assertEqual(r['candidate_name_count'],1)
        self.assertEqual(len(r['same_lba_groups']),0)

    def test_nested_data_world_levels(self):
        # The original Rayman 2 DAT names live under DATA/WORLD/LEVELS,
        # not in the image root. Do not rely on flat-only ISO fixtures.
        blob=bytearray(make_iso())
        for sector, name, next_lba in (
                (20, b'DATA', 21), (21, b'WORLD', 22),
                (22, b'LEVELS', 23)):
            entries=(rec(b'\0',sector,SECTOR,True) +
                     rec(b'\1',sector-1,SECTOR,True) +
                     rec(name,next_lba,SECTOR,True))
            blob[sector*SECTOR:sector*SECTOR+len(entries)]=entries
        payload=(rec(b'\0',23,SECTOR,True) +
                 rec(b'\1',22,SECTOR,True) +
                 rec(b'LEVELS0.DAT;1',25,0x7fffffff))
        blob[23*SECTOR:23*SECTOR+len(payload)]=payload
        result=scan_iso_file(BytesIO(blob),len(blob))
        self.assertEqual(result['candidate_name_count'],1)
        self.assertEqual(result['directory_count'],4)
        self.assertEqual(result['candidates'][0]['path'],
                         'DATA/WORLD/LEVELS/LEVELS0.DAT;1')

    def test_endian_anomaly_reported(self):
        r=scan_iso_file(BytesIO(make_iso(['LEVELS0.DAT'],bad_endian=True)),SECTOR*32)
        self.assertFalse(r['candidates'][0]['valid_both_endian'])

    def test_bad_pvd_rejected(self):
        with self.assertRaisesRegex(ValueError,'primary ISO9660'):
            scan_iso_file(BytesIO(b'\0'*(SECTOR*32)),SECTOR*32)

    def test_short_image_rejected(self):
        with self.assertRaisesRegex(ValueError,'physical ISO'):
            scan_iso_file(BytesIO(b'\0'*SECTOR),SECTOR)

    def test_bad_record_rejected(self):
        with self.assertRaisesRegex(ValueError,'malformed'):
            _record(bytes([3])+b'\0'*50,0)

    def test_wrong_sector_size_rejected(self):
        blob=bytearray(make_iso())
        struct.pack_into('<H',blob,16*SECTOR+128,512)
        with self.assertRaisesRegex(ValueError,'logical sector'):
            scan_iso_file(BytesIO(blob),len(blob))

    def test_symlink_refused(self):
        if not hasattr(os,'symlink'):self.skipTest('symlinks unsupported')
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'iso'
            f.write_bytes(make_iso())
            link=Path(d)/'link'
            try:link.symlink_to(f)
            except OSError:self.skipTest('symlink privilege unavailable')
            with self.assertRaisesRegex(ValueError,'symlink'):
                scan(link)

    def test_real_temporary_iso(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'demo.iso'
            f.write_bytes(make_iso(['LEVELS0.DAT']))
            self.assertTrue(scan(f)['read_only'])

if __name__=='__main__':unittest.main()
