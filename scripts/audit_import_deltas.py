#!/usr/bin/env python3
"""Read-only PE32 import descriptor and byte-difference audit.

Not a decryptor: it never writes output or uses historical key assumptions.
"""
import argparse
import collections
import pathlib
import struct


def pe_sections(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("invalid MZ")
    nt = struct.unpack_from("<I", data, 0x3C)[0]
    if nt + 24 > len(data) or data[nt:nt + 4] != b"PE\0\0":
        raise ValueError("invalid PE")
    machine, n, optlen = (
        struct.unpack_from("<H", data, nt + 4)[0],
        struct.unpack_from("<H", data, nt + 6)[0],
        struct.unpack_from("<H", data, nt + 20)[0],
    )
    if machine != 0x14C or n > 96 or not n:
        raise ValueError("expected PE32 x86 with bounded sections")
    optional = nt + 24
    if optional + optlen > len(data) or struct.unpack_from("<H", data, optional)[0] != 0x10B:
        raise ValueError("invalid PE32 optional header")
    start = optional + optlen
    result = {}
    for i in range(n):
        p = start + i * 40
        if p + 40 > len(data):
            raise ValueError("truncated section header")
        name = data[p:p + 8].split(b"\0")[0].decode("ascii", "replace")
        rva, rawlen, rawoff = struct.unpack_from("<III", data, p + 12)
        if rawoff + rawlen > len(data):
            raise ValueError("section outside file")
        result[name] = (rva, rawoff, rawlen)
    return result


def audit_coverage(a, b, descriptors, base_rva):
    """Classify changed .idata bytes by PE import structures in the unwrapped file.

    This identifies metadata locations; it does NOT reverse SafeDisc encryption.
    """
    labels = [None] * len(b)
    changed_words = collections.Counter()

    def mark(start, length, category):
        if start < 0 or length < 0 or start + length > len(b):
            raise ValueError(f"out-of-bounds {category} at 0x{start:X}")
        for i in range(start, start + length):
            if labels[i] not in (None, category):
                raise ValueError(f"overlapping structures: {labels[i]}/{category} at 0x{i:X}")
            labels[i] = category

    def to_offset(rva):
        offset = rva - base_rva
        if not 0 <= offset < len(b):
            raise ValueError(f"import RVA outside .idata: 0x{rva:X}")
        return offset

    def mark_string(start, category, prefix=0):
        if start + prefix >= len(b):
            raise ValueError(f"invalid import string start 0x{start:X}")
        end = b.find(b"\x00", start + prefix)
        if end < 0:
            raise ValueError(f"unterminated import string at 0x{start:X}")
        mark(start, end + 1 - start, category)

    for pos, _old, new in descriptors:
        mark(pos, 20, "descriptors")
        mark_string(to_offset(new[3]), "dll_names")
        dll = b[to_offset(new[3]):].split(b"\x00", 1)[0].decode("ascii", "replace")
        for category, table_rva in (("ILT", new[0]), ("IAT", new[4])):
            start = to_offset(table_rva)
            for entry in range(2048):
                p = start + entry * 4
                if p + 4 > len(b):
                    raise ValueError(f"unterminated {category} array for {dll}")
                old_thunk = struct.unpack_from("<I", a, p)[0]
                new_thunk = struct.unpack_from("<I", b, p)[0]
                mark(p, 4, category)
                if old_thunk != new_thunk:
                    changed_words[(dll, category)] += 1
                if new_thunk == 0:
                    break
                if category == "ILT" and (new_thunk & 0x80000000) == 0:
                    mark_string(to_offset(new_thunk), "import_names", prefix=2)
            else:
                raise ValueError(f"too many {category} entries for {dll}")

    classes = collections.Counter()
    for i, (old_byte, new_byte) in enumerate(zip(a, b)):
        if old_byte != new_byte:
            classes[labels[i] or "unclassified"] += 1
    print("Detailed .idata changed-byte accounting:")
    for category in ("descriptors", "ILT", "IAT", "import_names", "dll_names", "unclassified"):
        print(f"  {category}: {classes[category]} bytes")
    print(f"  total classified/observed: {sum(v for k, v in classes.items() if k != 'unclassified')}/{sum(classes.values())}")
    print("Import thunk entries changed, by DLL:")
    for (dll, table), amount in sorted(changed_words.items()):
        print(f"  {dll} {table}: {amount} DWORDs")
    if classes["unclassified"]:
        print("WARNING: some byte differences are not explained by these import structures")


def audit(icd, unwrapped, coverage=False):
    aa, bb = pe_sections(icd), pe_sections(unwrapped)
    if ".idata" not in aa or ".idata" not in bb:
        raise ValueError("missing .idata")
    ra, off_a, size_a = aa[".idata"]
    rb, off_b, size_b = bb[".idata"]
    if ra != rb or size_a != size_b:
        raise ValueError("incompatible .idata section layout")
    a, b = icd[off_a:off_a + size_a], unwrapped[off_b:off_b + size_b]
    descriptors = []
    for pos in range(0, len(a) - 19, 20):
        old = struct.unpack_from("<5I", a, pos)
        new = struct.unpack_from("<5I", b, pos)
        if not any(old) and not any(new):
            break
        descriptors.append((pos, old, new))
    else:
        raise ValueError("unterminated import descriptors")
    print(f"Import descriptor count: {len(descriptors)}")
    for pos, old, new in descriptors:
        diff = [(j, f"0x{x:08X}", f"0x{y:08X}") for j, (x, y) in enumerate(zip(old, new)) if x != y]
        if diff:
            print(f"  RVA 0x{ra + pos:08X}: changed fields {diff}")
    differences = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    desc_end = (descriptors[-1][0] + 20) if descriptors else 0
    in_desc = sum(i < desc_end for i in differences)
    print(f".idata changed bytes: {len(differences)}; within descriptors: {in_desc}; beyond: {len(differences)-in_desc}")
    by_page = collections.Counter(i // 256 for i in differences if i >= desc_end)
    print("Non-descriptor changed offsets in 256-byte bins:")
    for page, count in sorted(by_page.items()):
        print(f"  RVA 0x{ra + page*256:08X}: {count} bytes")
    if coverage:
        audit_coverage(a, b, descriptors, ra)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--icd", type=pathlib.Path, required=True)
    cli.add_argument("--unwrapped", type=pathlib.Path, required=True)
    cli.add_argument("--coverage", action="store_true", help="classify changed bytes as import metadata, thunks, or import strings")
    args = cli.parse_args()
    audit(args.icd.read_bytes(), args.unwrapped.read_bytes(), coverage=args.coverage)
