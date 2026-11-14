#!/usr/bin/env python3
"""SHA-gated, read-only static audit of the Rayman 2 DAT seek/paired-value chain."""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path
from rayman2_stream_mode_audit import pe_mapper, RETAIL_SHA, GOG_SHA

# x86 source byte anchors; no game payload or memory dump is written.
SHARED = {
  0x44E8D3:'e8 68 02 00 00', 0x44E8DD:'83 fb ff',
  0x44EA18:'8b 75 08 56 6a 06 e8 dd 1f 00 00',
  0x44EA7D:'89 7e 14', 0x44EA86:'8b 15 f0 16 51 00',
  0x44EA8C:'89 14 8d 60 17 51 00',
  0x44EAA0:'e8 eb 22 00 00', 0x44EAAA:'8b 55 f8',
  0x44EAB6:'89 14 85 00 17 51 00',
  0x44EAC4:'a3 c4 17 51 00',
  0x46729F:'a1 c4 17 51 00',
  0x4672AD:'8b 04 b5 60 17 51 00',
  0x4672BD:'c7 45 f4 06 00 00 00',
  0x4672C4:'e8 e7 a4 01 00',
  0x4672CC:'8b 14 b5 00 17 51 00',
  0x4672DC:'c7 45 f4 06 00 00 00',
  0x4672E6:'e8 c5 a4 01 00',
  0x4672F6:'a1 c4 17 51 00',
  0x467300:'81 e6 ff 00 00 00',
  0x467306:'3b f0 72 a3',
  0x46732D:'c7 45 f4 06 00 00 00',
  0x467334:'e8 37 a4 01 00',
}
CD = {
  0x44E8F2:'81 f1 24 d9 5b 07',
  0x44E944:'b9 55 04 00 00',
  0x44E94E:'81 c6 a0 0e 51 00',
  0x44E954:'c6 06 a1',
  0x44E957:'c7 46 01 90 17 4a 00',
  0x44E95E:'c6 46 05 33', 0x44E962:'c6 46 06 05',
  0x44E966:'c7 46 07 60 17 4a 00',
  0x44E96D:'c6 46 0b 50', 0x44E971:'c6 46 0c c3',
  0x44E990:'68 64 04 00 00', 0x44E995:'68 a0 0e 51 00',
  0x44E99F:'6a 00 6a 00 57 53', 0x44E9A5:'ff d6',
  0x44E9A7:'8d 5e 0f 8b fe', 0x44E9AC:'3b f3 73 68',
  0x44E9B0:'8b 0d f0 0b 51 00', 0x44EA13:'88 57 ff 72 98',
}
GOG = {
  0x44E8F2:'e9 a8 00 00 00',
  0x44E99F:'6a 00 6a 00 57 53',
  0x44E9A5:'ff 15 48 c0 49 00',
  0x44E9AB:'eb 6b',
}


def check(at, anchors, label):
    for va, hexdump in anchors.items():
        sample=bytes.fromhex(hexdump)
        if at(va,len(sample)) != sample:
            raise ValueError(f'{label}: unexpected x86 at 0x{va:08X}')


def rel32(at,va):
    opcode=at(va,5)
    if opcode[0] not in (0xe8,0xe9):
        raise ValueError('expected E8/E9 rel32')
    return va+5+struct.unpack('<i',opcode[1:])[0]


def audit(retail:bytes,gog:bytes):
    for name,data,expected in (('retail',retail,RETAIL_SHA),('GOG',gog,GOG_SHA)):
        if hashlib.sha256(data).hexdigest()!=expected:
            raise ValueError(f'{name}: unsupported SHA256')
    a,b=pe_mapper(retail),pe_mapper(gog)
    for at,label in ((a,'retail'),(b,'GOG')):
        check(at,SHARED,label)
    check(a,CD,'retail')
    check(b,GOG,'GOG')
    if rel32(b,0x44E8F2)!=0x44E99F:
        raise ValueError('bad GOG branch to seek wrapper')
    for site,target in (
      (0x44E8D3,0x44EB40), (0x44EAA0,0x450D90),
      (0x4672C4,0x4817B0), (0x4672E6,0x4817B0),
      (0x467334,0x481770),
    ):
        if rel32(a,site)!=target or rel32(b,site)!=target:
            raise ValueError(f'different function target 0x{site:X}')
    # Original 13-byte callable stub is generated from 7 instruction writes.
    stub=bytes.fromhex('a1 90 17 4a 00 33 05 60 17 4a 00 50 c3')
    assert len(stub)==13
    return {
      'original_sha256':RETAIL_SHA, 'gog_sha256':GOG_SHA,
      'retail_seek_site':'0x0044E9A5', 'retail_seek':'generated trampoline CALL ESI',
      'gog_seek':'CALL [0x0049C048] SetFilePointer',
      'original_stub_bytes':len(stub), 'original_scrub_bytes':15,
      'original_staging_va':'0x00510EA0','original_staging_size':1124,
      'source_prng_offset_divisor':1109,
      'saved_seed_snapshot_table':'0x00511760',
      'saved_decoded_dword_table':'0x00511700',
      'saved_pair_count':'0x005117C4',
      'shared_generic_consumer':'0x004672AD -> 0x004817B0 (twice, type 6)',
      'first_four_plaintext_bytes_known':False,
      'safeDisc_decryption_proven':False,
    }


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--retail',required=True,type=Path)
    p.add_argument('--gog',required=True,type=Path)
    args=p.parse_args()
    print(json.dumps(audit(args.retail.read_bytes(),args.gog.read_bytes()),indent=2))


if __name__=='__main__':
    main()
