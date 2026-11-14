#!/usr/bin/env python3
"""Exact-hash-gated, read-only TEA known-plaintext crosscheck for Rayman 2.

Compare the historical 32-round repeated-word TEA encoding of every distinct
8-byte *overlapping* window of the owner's original retail EXE against every
8-byte sliding window of the eight exact owner-provided opaque files.

A zero result falsifies ONLY this direct, constant-key transform from those
particular on-disk source windows; it does not rule out transformed memory
sections, per-sector keys, pre- or post-processing or original CD differences.
No game bytes, decrypted executables, patches or data dumps are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024
RETAIL_SHA256 = "7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3"
RETAIL_BYTES = 676352
KNOWN: dict[str, tuple[int, str]] = {
    "RAYMAN2.ICD": (683565, "4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6"),
    "DPLAYERX.DLL": (165888, "0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee"),
    "CLOKSPL.EXE": (177152, "6efcb3f4ba8052ab8bbd58be703a1de0f9e6eacc8f47c0d6501b0981380edaeb"),
    "CLCD32.DLL": (27648, "432074cae948d0cee2704f66b47f72a4dee2f9bed288e23912fbc531b041f2a5"),
    "DRVMGT.DLL": (32256, "6111ab0664948e05171468835be20b00f6b69d366fab28d7cd1ca9d9b67af35b"),
    "00000001.TMP": (20, "06ba601c966e6770747d84fe1c3fafaab9f48b07db6eae07a9250f7232415396"),
    "0000040C.016": (153718, "5c53568c900404bea863ef5ac6e87e49193d95a06674f3a49d70dcefd3f28608"),
    "0000040C.256": (308278, "5f25849ffa80abb15d3897ba5f4bc44ffa6f06819e370b873e9d172fc00f9933"),
}


def read_bounded(path: Path) -> bytes:
    """Read a regular file via a bounded descriptor; reject symlinks and races."""
    if path.is_symlink():
        raise ValueError("refusing symlink")
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or not 8 <= before.st_size <= MAX_FILE_BYTES:
        raise ValueError("refusing nonregular, too short or oversized input")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (not stat.S_ISREG(opened.st_mode) or
                (opened.st_size, opened.st_mtime_ns) !=
                (before.st_size, before.st_mtime_ns) or
                (os.name != "nt" and
                 (opened.st_dev, opened.st_ino) !=
                 (before.st_dev, before.st_ino))):
            raise ValueError("input was replaced or modified on opening")
        content = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(handle.fileno())
    if (len(content) != opened.st_size or len(content) > MAX_FILE_BYTES or
            (after.st_size, after.st_mtime_ns) !=
            (opened.st_size, opened.st_mtime_ns)):
        raise ValueError("input changed while reading")
    return content


def encrypt_block(block: bytes, key: int) -> bytes:
    """Standard 32-round TEA with four copies of the supplied DWORD key."""
    if len(block) != 8 or not 0 <= key <= 0xffffffff:
        raise ValueError("expected an eight-byte block and DWORD key")
    left, right = struct.unpack("<II", block)
    total = 0
    for _ in range(32):
        total = (total + 0x9E3779B9) & 0xffffffff
        left = (left + (((right << 4) + key) ^ (right + total) ^
                        ((right >> 5) + key))) & 0xffffffff
        right = (right + (((left << 4) + key) ^ (left + total) ^
                          ((left >> 5) + key))) & 0xffffffff
    return struct.pack("<II", left, right)


def historical_vector_valid() -> bool:
    return encrypt_block(bytes(8), 0xC15CF2E5) == bytes.fromhex(
        "3E CD DE 58 A2 75 01 7F")

HISTORICAL_KEY = 0xC15CF2E5
MISPRINTED_KEY = 0xC1552FE5
DEFAULT_KEYS = (HISTORICAL_KEY, MISPRINTED_KEY)


def sliding_words(data: bytes) -> set[int]:
    if len(data) < 8:
        return set()
    return {struct.unpack_from('<Q', data, i)[0]
            for i in range(len(data) - 7)}


def encrypt_word(word: int, key: int) -> int:
    """Use the separately tested historical TEA implementation."""
    return struct.unpack('<Q', encrypt_block(struct.pack('<Q', word), key))[0]


def compare_raw(retail: bytes, samples: dict[str, bytes],
                keys: tuple[int, ...] = DEFAULT_KEYS) -> dict:
    """Pure synthetic-capable comparison; hash gates belong to main()."""
    if len(retail) < 8 or not samples or not keys or len(keys) != len(set(keys)):
        raise ValueError('need a retail input, samples, and unique TEA keys')
    if any(not 0 <= key <= 0xffffffff for key in keys):
        raise ValueError('invalid TEA key')
    if any(len(blob) < 8 for blob in samples.values()):
        raise ValueError('opaque input shorter than one TEA block')
    originals = sliding_words(retail)
    candidates = {name: sliding_words(blob) for name, blob in samples.items()}
    out = {
        'retail_bytes': len(retail),
        'overlapping_plaintext_windows': len(retail) - 7,
        'distinct_plaintext_windows': len(originals),
        'candidate_windows': {name: len(blob)-7 for name,blob in samples.items()},
        'keys': {},
        'input_data_emitted': False,
        'matching_ciphertext_does_not_authenticate_file_provenance': True,
        'no_match_does_not_rule_out_runtime_decryption': True,
    }
    for key in keys:
        # The TEA transform is bijective for 8-byte blocks. Identical
        # original windows cannot create new candidate ciphertexts.
        cipher = {encrypt_word(value, key) for value in originals}
        out['keys'][f'0x{key:08X}'] = {
            'distinct_encrypted_plaintext_blocks': len(cipher),
            'distinct_matches': {
                name: len(target.intersection(cipher))
                for name, target in candidates.items()
            },
        }
    return out


def verify_exact_references(retail: bytes, samples: dict[str, bytes]) -> None:
    if len(retail) != RETAIL_BYTES or hashlib.sha256(retail).hexdigest() != RETAIL_SHA256:
        raise ValueError('retail EXE does not match the exact owner sample')
    for name, blob in samples.items():
        if name not in KNOWN:
            raise ValueError('unknown opaque sample name')
        size, digest = KNOWN[name]
        if len(blob) != size or hashlib.sha256(blob).hexdigest() != digest:
            raise ValueError(f'{name} does not match the exact owner sample')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--retail', type=Path, required=True)
    for name in ('icd', 'dplayerx', 'clokspl', 'clcd32', 'drvmgt', 'tmp', 'file016', 'file256'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args(argv)
    paths = {
        'RAYMAN2.ICD': args.icd,
        'DPLAYERX.DLL': args.dplayerx,
        'CLOKSPL.EXE': args.clokspl,
        'CLCD32.DLL': args.clcd32,
        'DRVMGT.DLL': args.drvmgt,
        '00000001.TMP': args.tmp,
        '0000040C.016': args.file016,
        '0000040C.256': args.file256,
    }
    if not any(paths.values()):
        parser.error('supply at least one owner opaque sample')
    try:
        retail = read_bounded(args.retail)
        targets = {name: read_bounded(path)
                   for name, path in paths.items() if path is not None}
        verify_exact_references(retail, targets)
        if not historical_vector_valid():
            raise ValueError('historical TEA implementation failed its golden vector')
        result = compare_raw(retail, targets)
        result['retail_sha256_verified'] = True
        result['opaque_sha256_verified'] = True
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
