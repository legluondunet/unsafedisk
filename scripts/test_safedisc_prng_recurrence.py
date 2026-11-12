"""Synthetic PRNG/false-positive controls; no copyrighted input samples."""
from __future__ import annotations
import struct
import unittest

from safedisc_prng_recurrence import analyse, MODULUS, MULTIPLIER


def stream(seed: int, salt: int, count: int, endian: str) -> bytes:
    values = [seed]
    for _ in range(count - 1):
        values.append(((values[-1] ^ salt) * MULTIPLIER) % MODULUS)
    fmt = ("<" if endian == "little" else ">") + f"{count}I"
    return struct.pack(fmt, *values)


class RecurrenceTests(unittest.TestCase):
    def test_exact_little_endian_recurrence(self):
        blob = stream(0x30FBEC, 0x075BD924, 512, "little")
        result = analyse(blob, "little")
        self.assertTrue(result["full_recurrence_match"])
        self.assertEqual(result["matching_transitions"], 511)
        self.assertEqual(result["total_transitions"], 511)

    def test_big_endian_recurrence_and_partial_tail(self):
        blob = stream(0x123456, 0x246810, 512, "big") + b"\x29"
        result = analyse(blob, "big")
        self.assertTrue(result["full_recurrence_match"])
        self.assertEqual(result["tail_bytes"], 1)

    def test_bit_flip_breaks_recurrence(self):
        blob = bytearray(stream(0x30FBEC, 0x075BD924, 512, "little"))
        blob[101] ^= 1
        self.assertFalse(analyse(bytes(blob), "little")["full_recurrence_match"])

    def test_wrong_byte_order_is_rejected(self):
        blob = stream(0x30FBEC, 0x075BD924, 512, "little")
        self.assertFalse(analyse(blob, "big")["full_recurrence_match"])

    def test_arbitrary_opaque_data_is_not_misclassified(self):
        blob = (b"\x00\x00\x00\x00\xff\xff\xff\x7f\x11\x22\x33\x44") * 100
        self.assertFalse(analyse(blob, "little")["full_recurrence_match"])

    def test_short_input_and_invalid_endian_fail(self):
        with self.assertRaisesRegex(ValueError, "at least 256"):
            analyse(b"\x00" * 8, "little")
        with self.assertRaisesRegex(ValueError, "at least 256"):
            analyse(stream(0x30FBEC, 0x075BD924, 255, "little"), "little")
        with self.assertRaisesRegex(ValueError, "endian"):
            analyse(b"\x00" * 12, "middle")


if __name__ == "__main__":
    unittest.main()
