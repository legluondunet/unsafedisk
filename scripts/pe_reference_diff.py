#!/usr/bin/env python3
"""Read-only PE32 comparison by virtual section RVA, with optional file-list scan.

Embedded (size, name length, name) records represent claims in a reference
binary, not authenticated on-disc extents. No commercial bytes are emitted.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import struct
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024
MAX_SECTIONS = 96
MAX_RECORDS = 100_000


def u16(data: bytes, at: int) -> int:
    if at < 0 or at + 2 > len(data):
        raise ValueError("truncated PE u16")
    return struct.unpack_from("<H", data, at)[0]


def u32(data: bytes, at: int) -> int:
    if at < 0 or at + 4 > len(data):
        raise ValueError("truncated PE u32")
    return struct.unpack_from("<I", data, at)[0]


def parse_pe32(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError("oversized PE input")
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("expected MZ input")
    nt = u32(data, 0x3C)
    if nt < 0x40 or nt + 24 > len(data) or data[nt:nt+4] != b"PE\0\0":
        raise ValueError("invalid PE header")
    if u16(data, nt+4) != 0x14C:
        raise ValueError("expected x86 PE32")
    count = u16(data, nt+6)
    opt_size = u16(data, nt+20)
    opt = nt+24
    if not 1 <= count <= MAX_SECTIONS or opt_size < 0x70 or opt+opt_size > len(data):
        raise ValueError("invalid section count or optional header")
    if u16(data, opt) != 0x10B:
        raise ValueError("expected PE32 magic")
    sections = {}
    table = opt+opt_size
    if table+count*40 > len(data):
        raise ValueError("truncated section headers")
    for i in range(count):
        at = table+40*i
        name = data[at:at+8].split(b"\0", 1)[0].decode("ascii", "backslashreplace")
        vsize, rva, raw_len, raw_off = struct.unpack_from("<IIII", data, at+8)
        if name in sections:
            raise ValueError("duplicate section name")
        if raw_len and raw_off+raw_len > len(data):
            raise ValueError("section extends beyond EOF")
        sections[name] = {
            "name": name, "rva": rva, "virtual_size": vsize,
            "raw_offset": raw_off, "raw_len": raw_len,
            "characteristics": u32(data, at+36),
            "contents": data[raw_off:raw_off+raw_len] if raw_len else b"",
        }
    directory_count = u32(data, opt+92)
    directories = {}
    for name, index in (("exports", 0), ("imports", 1), ("resources", 2)):
        if directory_count > index:
            if 96+8*(index+1) > opt_size:
                raise ValueError("PE data directory exceeds optional header")
            directories[name] = list(struct.unpack_from("<II", data, opt+96+8*index))
        else:
            directories[name] = [0, 0]
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "entry_rva": u32(data, opt+16), "image_base": u32(data, opt+28),
            "sections": sections, "directories": directories}


def describe(pe: dict) -> dict:
    return {
        "sha256": pe["sha256"], "bytes": pe["bytes"],
        "entry_rva": f"0x{pe['entry_rva']:08X}",
        "image_base": f"0x{pe['image_base']:08X}",
        "sections": [
            {"name": s["name"], "rva": f"0x{s['rva']:08X}",
             "raw_offset": f"0x{s['raw_offset']:X}", "raw_length": s["raw_len"]}
            for s in pe["sections"].values()
        ],
    }


def compare_pe32(protected: dict, reference: dict) -> dict:
    comparisons = []
    for name, a in protected["sections"].items():
        b = reference["sections"].get(name)
        if b is None:
            comparisons.append({"name": name, "status": "protected_only"})
            continue
        if a["rva"] != b["rva"]:
            comparisons.append({
                "name": name, "status": "different_rva",
                "protected_rva": f"0x{a['rva']:X}",
                "reference_rva": f"0x{b['rva']:X}",
            })
            continue
        common = min(a["raw_len"], b["raw_len"])
        diffs, pages = [], {}
        for offset, (x, y) in enumerate(zip(a["contents"][:common], b["contents"][:common])):
            if x != y:
                diffs.append(offset)
                page = (a["rva"]+offset)//4096
                pages[page] = pages.get(page, 0)+1
        comparisons.append({
            "name": name, "status": "compared_by_rva",
            "rva": f"0x{a['rva']:08X}",
            "compared_bytes": common, "equal_bytes": common-len(diffs),
            "different_bytes": len(diffs),
            "changed_to_int3_bytes": sum(
                a["contents"][i] != 0xCC and b["contents"][i] == 0xCC
                for i in diffs
            ),
            "changed_to_nop_bytes": sum(
                a["contents"][i] != 0x90 and b["contents"][i] == 0x90
                for i in diffs
            ),
            "identical_percent": round(100*(common-len(diffs))/common, 4) if common else None,
            "raw_length_protected": a["raw_len"],
            "raw_length_reference": b["raw_len"],
            "changed_4k_pages": len(pages),
            "heaviest_changed_pages": [
                {"rva": f"0x{page*4096:08X}", "changed_bytes": count}
                for page, count in sorted(pages.items(), key=lambda item: (-item[1], item[0]))[:12]
            ],
            "first_difference_rvas": [
                f"0x{a['rva']+offset:08X}" for offset in diffs[:10]
            ],
        })
    for name, b in reference["sections"].items():
        if name not in protected["sections"]:
            comparisons.append({
                "name": name, "status": "reference_only", "raw_length": b["raw_len"]
            })
    return {
        "read_only": True, "no_proprietary_bytes_emitted": True,
        "protected": describe(protected), "reference": describe(reference),
        "same_entry_rva": protected["entry_rva"] == reference["entry_rva"],
        "same_image_base": protected["image_base"] == reference["image_base"],
        "same_import_directory": protected["directories"]["imports"] == reference["directories"]["imports"],
        "same_export_directory": protected["directories"]["exports"] == reference["directories"]["exports"],
        "section_comparison": comparisons,
    }


def find_embedded_section_copies(protected: dict, reference: dict,
                                 min_bytes: int = 4096) -> list[dict]:
    """Find exact FULL section-byte copies inside differently named sections.

    This is a byte-identity test, not evidence of code execution or a
    SafeDisc-only change. Tiny or nearly constant regions are excluded
    to avoid trivial coincidental matches.
    """
    if min_bytes < 1:
        raise ValueError("minimum section size must be positive")
    matches = []
    for source_name, source in protected["sections"].items():
        needle = source["contents"]
        if len(needle) < min_bytes or len(set(needle)) < 8:
            continue
        for target_name, target in reference["sections"].items():
            if source_name == target_name:
                continue
            offset = target["contents"].find(needle)
            if offset < 0:
                continue
            prefix = target["contents"][:offset]
            suffix = target["contents"][offset + len(needle):]
            matches.append({
                "protected_section": source_name,
                "reference_section": target_name,
                "matched_bytes": len(needle),
                "matched_sha256": hashlib.sha256(needle).hexdigest(),
                "reference_section_offset": f"0x{offset:X}",
                "reference_file_offset": f"0x{target['raw_offset'] + offset:X}",
                "reference_rva": f"0x{target['rva'] + offset:08X}",
                "reference_section_characteristics":
                    f"0x{target['characteristics']:08X}",
                "reference_section_header_marks_executable":
                    bool(target["characteristics"] & 0x20000000),
                "prefix_bytes": len(prefix),
                "prefix_all_zero": not any(prefix),
                "suffix_bytes": len(suffix),
                "suffix_all_zero": not any(suffix),
                "interpretation": (
                    "Exact byte copy of a section, not a demonstrated relocation, "
                    "execution path, GOG change reason, or SafeDisc behavior."
                ),
            })
    return matches


def find_added_section_base_literals(protected: dict, reference: dict) -> list[dict]:
    """Find literal 32-bit VA values pointing to GOG/reference-only sections.

    These are raw byte-pattern matches in executable-designated
    sections, not verified disassembled instructions or reachable
    runtime accesses.
    """
    results = []
    for target_name, target in reference["sections"].items():
        if target_name in protected["sections"]:
            continue
        va = reference["image_base"] + target["rva"]
        if va > 0xFFFF_FFFF:
            continue
        pattern = va.to_bytes(4, "little")
        refs = []
        for source_name, source in reference["sections"].items():
            if not source["characteristics"] & 0x2000_0000:
                continue
            start = 0
            while (offset := source["contents"].find(pattern, start)) >= 0:
                refs.append({
                    "source_section": source_name,
                    "immediate_va": f"0x{reference['image_base'] + source['rva'] + offset:08X}",
                })
                start = offset + 1
        if refs:
            results.append({
                "reference_only_section": target_name,
                "section_base_va": f"0x{va:08X}",
                "literal_candidates": refs,
                "interpretation": (
                    "Raw absolute VA byte matches; manual disassembly and "
                    "control-flow analysis required before claiming runtime use."
                ),
            })
    return results


def find_x86_reference_candidates(pe: dict, target_va: int) -> dict:
    """Find E8 rel32 calls and B8..BF MOV-register-immediate references.

    Scans *executable-designated* sections only. Byte-pattern matches
    can fall inside unrelated instructions/data, so results require
    manual decoding and control-flow review. No code is executed.
    """
    if not 0 <= target_va <= 0xFFFF_FFFF:
        raise ValueError("x86 target VA must fit in 32 bits")
    calls, immediates = [], []
    for name, section in pe["sections"].items():
        if not section["characteristics"] & 0x2000_0000:
            continue
        raw = section["contents"]
        va_base = pe["image_base"] + section["rva"]
        for offset in range(max(0, len(raw)-4)):
            opcode = raw[offset]
            site_va = va_base + offset
            if opcode == 0xE8:
                delta = struct.unpack_from("<i", raw, offset+1)[0]
                if (site_va + 5 + delta) & 0xFFFF_FFFF == target_va:
                    calls.append({
                        "site_va": f"0x{site_va:08X}", "section": name,
                        "candidate_opcode": "E8 rel32",
                    })
            elif 0xB8 <= opcode <= 0xBF:
                literal = struct.unpack_from("<I", raw, offset+1)[0]
                if literal == target_va:
                    immediates.append({
                        "site_va": f"0x{site_va:08X}", "section": name,
                        "register_code": opcode-0xB8,
                        "candidate_opcode": "MOV r32, imm32",
                    })
    return {
        "target_va": f"0x{target_va:08X}",
        "direct_call_candidates": calls,
        "mov_immediate_candidates": immediates,
        "caution": "Byte-pattern candidates only; manual instruction-boundary and reachability analysis required",
    }


def read_section_u32_va(pe: dict, va: int) -> dict:
    """Read an exact, file-backed DWORD using PE virtual address mapping.

    On-disk PE data cannot prove runtime pointer values; zero-initialized
    globals can be populated or transformed by other startup code.
    """
    if not 0 <= va <= 0xFFFF_FFFF:
        raise ValueError("virtual address out of 32-bit range")
    rva = va - pe["image_base"]
    for section in pe["sections"].values():
        delta = rva - section["rva"]
        if 0 <= delta and delta + 4 <= section["raw_len"]:
            return {
                "va": f"0x{va:08X}",
                "section": section["name"],
                "file_offset": f"0x{section['raw_offset'] + delta:X}",
                "value_u32": f"0x{struct.unpack_from('<I', section['contents'], delta)[0]:08X}",
            }
    raise ValueError(f"VA 0x{va:08X} is not backed by four file bytes")


def compare_masked_pointer_pairs(protected: dict, reference: dict,
                                 pairs: list[tuple[int, int]]) -> list[dict]:
    """Compare two file-backed operands of an XOR-derived pointer.

    The XOR of on-disk values is NOT asserted to be a runtime callback
    or original SafeDisc key. Never patch source or reference binaries.
    """
    if len(pairs) > 64:
        raise ValueError("at most 64 pairs can be examined")
    results = []
    for first, second in pairs:
        retail_first = read_section_u32_va(protected, first)
        retail_second = read_section_u32_va(protected, second)
        gog_first = read_section_u32_va(reference, first)
        gog_second = read_section_u32_va(reference, second)
        a, b = int(retail_first["value_u32"], 16), int(retail_second["value_u32"], 16)
        c, d = int(gog_first["value_u32"], 16), int(gog_second["value_u32"], 16)
        results.append({
            "first_va": f"0x{first:08X}",
            "second_va": f"0x{second:08X}",
            "retail_file_values": [f"0x{a:08X}", f"0x{b:08X}"],
            "reference_file_values": [f"0x{c:08X}", f"0x{d:08X}"],
            "same_bytes_at_both_vas": a == c and b == d,
            "retail_first_operand_zero_on_disk": a == 0,
            "reference_first_operand_zero_on_disk": c == 0,
            "retail_on_disk_xor": f"0x{a ^ b:08X}",
            "reference_on_disk_xor": f"0x{c ^ d:08X}",
            "runtime_pointer_known": False,
        })
    return results


def read_section_bytes_va(pe: dict, va: int, length: int) -> bytes:
    """Map one contiguous file-backed PE virtual-memory range to raw bytes."""
    if not 0 <= va <= 0xFFFF_FFFF or not 0 <= length <= 1_048_576:
        raise ValueError("invalid VA or byte length")
    rva = va - pe["image_base"]
    for section in pe["sections"].values():
        delta = rva - section["rva"]
        if 0 <= delta and delta + length <= section["raw_len"]:
            return section["contents"][delta:delta + length]
    raise ValueError(f"file bytes unavailable at 0x{va:08X} (length {length})")


def classify_x86_entry_stub(raw: bytes) -> dict:
    """Recognize a few exact tiny x86 function-entry stubs.

    A byte-pattern classifier only. No symbol boundaries, runtime
    reachability, calling conventions or DRM attribution are inferred.
    """
    if raw.startswith(b"\xC3"):
        return {"kind": "ret", "immediate_return": True}
    if len(raw) >= 3 and raw[0] == 0xC2:
        return {
            "kind": "ret_imm16", "immediate_return": True,
            "stack_pop_bytes": struct.unpack_from("<H", raw, 1)[0],
        }
    if raw[:3] in (b"\x31\xC0\xC3", b"\x33\xC0\xC3"):
        return {"kind": "returns_zero", "immediate_return": True}
    if raw[:4] in (b"\x31\xC0\x40\xC3", b"\x33\xC0\x40\xC3"):
        return {"kind": "returns_one", "immediate_return": True}
    if len(raw) >= 6 and raw[0] == 0xB8 and raw[5] == 0xC3:
        return {
            "kind": "returns_constant", "immediate_return": True,
            "value": f"0x{struct.unpack_from('<I', raw, 1)[0]:08X}",
        }
    if raw.startswith(b"\xCC"):
        return {"kind": "int3_at_entry", "immediate_return": False}
    return {"kind": "other_or_longer_function", "immediate_return": False}


def compare_entry_stubs(protected: dict, reference: dict,
                        entries: list[int]) -> list[dict]:
    """Compare selected *on-disk* x86 function entrypoints by VA."""
    if len(entries) > 64:
        raise ValueError("at most 64 entrypoints")
    results = []
    for va in entries:
        source = read_section_bytes_va(protected, va, 12)
        target = read_section_bytes_va(reference, va, 12)
        results.append({
            "va": f"0x{va:08X}",
            "protected": classify_x86_entry_stub(source),
            "reference": classify_x86_entry_stub(target),
            "first_12_bytes_equal": source == target,
            "reference_is_pristine_retail_verified": False,
            "runtime_execution_asserted": False,
            "safe_disc_only_change_asserted": False,
        })
    return results


def describe_virtual_address(pe: dict, va: int, length: int = 4) -> dict:
    """Classify RVA storage in PE image without guessing current runtime data.

    File-backed bytes and zero-initialized virtual tail are different:
    the latter may be populated by the program after loading.
    """
    if not 0 <= va <= 0xFFFF_FFFF or not 1 <= length <= 65536:
        raise ValueError("invalid address or length")
    rva = va - pe["image_base"]
    sections = [
        section for section in pe["sections"].values()
        if section["rva"] <= rva
        and rva + length <= section["rva"] + max(
            section["virtual_size"], section["raw_len"]
        )
    ]
    if not sections:
        return {"va": f"0x{va:08X}", "length": length,
                "storage": "not_in_any_section"}
    if len(sections) > 1:
        return {"va": f"0x{va:08X}", "length": length,
                "storage": "ambiguous_overlapping_sections"}
    section = sections[0]
    offset = rva - section["rva"]
    backed = section["raw_len"]
    virtual = section["virtual_size"]
    if offset + length <= backed:
        storage = "file_backed"
    elif offset >= backed and offset + length <= virtual:
        storage = "virtual_zero_fill_at_load"
    elif offset < backed and offset + length <= virtual:
        storage = "crosses_file_and_zero_fill"
    else:
        storage = "outside_declared_virtual_extent"
    return {
        "va": f"0x{va:08X}", "length": length,
        "section": section["name"],
        "section_rva": f"0x{section['rva']:08X}",
        "section_virtual_size": virtual,
        "section_raw_length": backed,
        "section_delta": f"0x{offset:X}",
        "storage": storage,
        "runtime_value_inferred": False,
        "note": (
            "Virtual zero-fill describes loader mapping, not the "
            "possibly modified in-memory value during execution."
        ),
    }


def compare_code_spans(protected: dict, reference: dict,
                       spans: list[tuple[int, int]]) -> list[dict]:
    """Compare exact file-backed VA spans without assigning patch intent.

    Use this to establish whether a function's on-disk bytes were
    replaced by INT3 or NOP in an independently modified reference.
    Neither an instruction decoder nor a runtime reachability check.
    """
    if len(spans) > 64:
        raise ValueError("at most 64 code spans")
    results = []
    for va, length in spans:
        if not 1 <= length <= 65536:
            raise ValueError("code span length must be between 1 and 65536 bytes")
        old = read_section_bytes_va(protected, va, length)
        new = read_section_bytes_va(reference, va, length)
        differences = sum(a != b for a, b in zip(old, new))
        results.append({
            "start_va": f"0x{va:08X}",
            "length_bytes": length,
            "identical_bytes": length - differences,
            "different_bytes": differences,
            "reference_all_int3_bytes": all(x == 0xCC for x in new),
            "reference_all_nop_bytes": all(x == 0x90 for x in new),
            "bytes_changed_to_int3": sum(
                a != 0xCC and b == 0xCC for a, b in zip(old, new)
            ),
            "bytes_changed_to_nop": sum(
                a != 0x90 and b == 0x90 for a, b in zip(old, new)
            ),
            "protected_sha256": hashlib.sha256(old).hexdigest(),
            "reference_sha256": hashlib.sha256(new).hexdigest(),
            "protection_change_asserted": False,
            "runtime_reachability_asserted": False,
            "interpretation": (
                "Byte-level PE comparison only. GOG/third-party changes "
                "cannot automatically be attributed to SafeDisc."
            ),
        })
    return results


def compare_descriptor_layout(protected: dict, reference: dict,
                              base_va: int, stride: int, count: int,
                              mask_offset: int, slot_offset: int) -> dict:
    """Summarize fixed-stride on-disk descriptors without assigning semantics.

    The mask and pointer-slot labels refer to a hypothesis supplied by
    the researcher; they are not confirmed decoded function pointers.
    """
    if (not 1 <= count <= 256 or not 8 <= stride <= 4096
            or not 0 <= mask_offset <= stride - 4
            or not 0 <= slot_offset <= stride - 4
            or stride * count > 1_048_576):
        raise ValueError("invalid bounded descriptor layout")
    entries = []
    for index in range(count):
        addr = base_va + index * stride
        retail = read_section_bytes_va(protected, addr, stride)
        other = read_section_bytes_va(reference, addr, stride)
        r_mask = struct.unpack_from("<I", retail, mask_offset)[0]
        r_slot = struct.unpack_from("<I", retail, slot_offset)[0]
        g_mask = struct.unpack_from("<I", other, mask_offset)[0]
        g_slot = struct.unpack_from("<I", other, slot_offset)[0]
        entries.append({
            "index": index, "record_va": f"0x{addr:08X}",
            "retail_record_all_zero": not any(retail),
            "reference_record_all_zero": not any(other),
            "retail_mask_candidate": f"0x{r_mask:08X}",
            "retail_pointer_slot_on_disk": f"0x{r_slot:08X}",
            "reference_mask_candidate": f"0x{g_mask:08X}",
            "reference_pointer_slot_on_disk": f"0x{g_slot:08X}",
            "both_full_record_bytes_equal": retail == other,
        })
    return {
        "read_only": True, "base_va": f"0x{base_va:08X}",
        "stride_bytes": stride, "records": count,
        "mask_offset": mask_offset, "pointer_slot_offset": slot_offset,
        "identical_records": sum(row["both_full_record_bytes_equal"] for row in entries),
        "retail_nonzero_records": sum(not row["retail_record_all_zero"] for row in entries),
        "retail_zero_pointer_slots": sum(
            row["retail_pointer_slot_on_disk"] == "0x00000000" for row in entries
        ),
        "source_code_execution_asserted": False,
        "runtime_pointer_values_inferred": False,
        "caution": (
            "Only file-backed record bytes compared. An on-disk zero slot "
            "may change at runtime; layout role and protected function "
            "targets require independent verification."
        ),
        "entries": entries,
    }


def scan_manifest(data: bytes) -> dict:
    """Read <u32 claimed size><u32 name length><NUL-terminated name> records."""
    offset, records = 0, []
    for _ in range(MAX_RECORDS):
        if offset+8 > len(data):
            raise ValueError("manifest has no sentinel")
        size, name_len = struct.unpack_from("<II", data, offset)
        if (size, name_len) == (0xFFFFFFFF, 0):
            return {
                "entries": records, "count": len(records),
                "claimed_total_bytes": sum(x["claimed_size_bytes"] for x in records),
                "manifest_bytes_before_sentinel": offset,
                "bytes_after_sentinel": len(data) - offset - 8,
                "remaining_bytes_all_zero": not any(data[offset+8:]),
                "warning": "Claimed file sizes are not verified physical CD extents",
            }
        if not 1 < name_len <= 512 or offset+8+name_len > len(data):
            raise ValueError("invalid bounded manifest filename length")
        raw = data[offset+8:offset+8+name_len]
        if raw[-1] != 0 or b"\0" in raw[:-1]:
            raise ValueError("manifest filename lacks a single trailing NUL")
        name = raw[:-1].decode("cp1252")
        if any(ord(ch) < 32 for ch in name):
            raise ValueError("control character in manifest filename")
        records.append({"name": name, "claimed_size_bytes": size})
        offset += 8+name_len
    raise ValueError("manifest record limit reached")


def read_bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError(f"non-file, symlink or >16 MiB input: {path}")
    with path.open("rb") as file:
        data = file.read(MAX_BYTES+1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"input grew past limit: {path}")
    return data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protected", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--reference-origin", default="unspecified",
                        help="Provenance label, e.g. GOG (metadata only; not authentication)")
    parser.add_argument("--manifest-section")
    parser.add_argument("--focus-name", action="append", default=[])
    parser.add_argument("--map-va", action="append", default=[],
                        help="PE virtual address to classify as file-backed or zero-fill")
    parser.add_argument("--entry-va", action="append", default=[],
                        help="x86 entrypoint VA to classify, repeatable")
    parser.add_argument("--code-span", action="append", default=[],
                        help="VA:SIZE (file-backed code region), repeatable")
    parser.add_argument("--descriptor-layout",
                        help="BASE:STRIDE:COUNT:MASK_OFFSET:SLOT_OFFSET, integer fields")
    parser.add_argument("--masked-pair", action="append", default=[],
                        help="two PE virtual addresses FIRST:SECOND, repeatable")
    parser.add_argument("--trace-va", action="append", default=[],
                        help="x86 VA in hex (0x...) or decimal; repeatable")
    args = parser.parse_args(argv)
    try:
        if args.protected.samefile(args.reference):
            raise ValueError("protected and reference paths refer to the same file")
        a, b = (parse_pe32(read_bounded(args.protected)),
                parse_pe32(read_bounded(args.reference)))
        result = compare_pe32(a, b)
        result["reference_origin_label"] = args.reference_origin
        result["reference_is_pristine_retail_verified"] = False
        result["difference_attribution"] = (
            "Byte differences are observations only. The reference may "
            "contain GOG, compatibility, third-party, or unrelated "
            "modifications. No difference is attributed to SafeDisc."
        )
        result["exact_embedded_section_copies"] = find_embedded_section_copies(a, b)
        result["reference_added_section_base_literals"] = find_added_section_base_literals(a, b)
        if args.map_va:
            if len(args.map_va) > 64:
                raise ValueError("at most 64 mapped addresses")
            result["virtual_address_storage"] = [
                {
                    "protected": describe_virtual_address(a, int(item, 0)),
                    "reference": describe_virtual_address(b, int(item, 0)),
                }
                for item in args.map_va
            ]
        if args.entry_va:
            if len(args.entry_va) > 64:
                raise ValueError("at most 64 entrypoints")
            result["entrypoint_stub_comparison"] = compare_entry_stubs(
                a, b, [int(item, 0) for item in args.entry_va]
            )
        if args.code_span:
            if len(args.code_span) > 64:
                raise ValueError("at most 64 code spans")
            spans = []
            for item in args.code_span:
                address, separator, length = item.partition(":")
                if not separator or not address or not length:
                    raise ValueError("code span must be VA:SIZE")
                spans.append((int(address, 0), int(length, 0)))
            result["on_disk_code_span_comparison"] = compare_code_spans(a, b, spans)
        if args.descriptor_layout:
            fields = args.descriptor_layout.split(":")
            if len(fields) != 5:
                raise ValueError("descriptor layout must contain five integer fields")
            numbers = [int(piece, 0) for piece in fields]
            result["file_backed_descriptor_observations"] = compare_descriptor_layout(
                a, b, *numbers
            )
        if args.masked_pair:
            if len(args.masked_pair) > 64:
                raise ValueError("at most 64 masked pointer pairs")
            pairs = []
            for item in args.masked_pair:
                left, separator, right = item.partition(":")
                if not separator or not left or not right:
                    raise ValueError("masked pair must be FIRST:SECOND")
                pairs.append((int(left, 0), int(right, 0)))
            result["masked_pointer_pair_observations"] = {
                "pairs": compare_masked_pointer_pairs(a, b, pairs),
                "runtime_inference": (
                    "On-disk pairs are observations, not runtime pointers. "
                    "Changes from initialization, loading or runtime writes are unknown."
                ),
            }
        if args.trace_va:
            # Bound output and prevent accidental exhaustive RVA scanning.
            if len(args.trace_va) > 32:
                raise ValueError("at most 32 traced target VAs")
            targets = [int(arg, 0) for arg in args.trace_va]
            result["x86_reference_candidates"] = [
                {
                    "target": f"0x{target:08X}",
                    "protected": find_x86_reference_candidates(a, target),
                    "reference": find_x86_reference_candidates(b, target),
                }
                for target in targets
            ]
        if args.manifest_section:
            section = b["sections"].get(args.manifest_section)
            if section is None:
                raise ValueError("manifest section not found in reference")
            manifest = scan_manifest(section["contents"])
            focus = {name.casefold() for name in args.focus_name}
            result["embedded_manifest"] = {
                **{k: v for k, v in manifest.items() if k != "entries"},
                "focus_entries": [
                    x for x in manifest["entries"] if x["name"].casefold() in focus
                ],
                "largest_entries": sorted(
                    manifest["entries"], key=lambda x: -x["claimed_size_bytes"]
                )[:10],
                "unique_names_casefold":
                    len({x["name"].casefold() for x in manifest["entries"]}) == manifest["count"],
                "original_cd_manifest_authenticated": False,
                "origin_warning": (
                    "File inventory is embedded in the reference image, "
                    "not independently verified against the original CD"
                ),
            }
    except (OSError, ValueError) as exc:
        parser.exit(1, f"ERROR: {exc}\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
