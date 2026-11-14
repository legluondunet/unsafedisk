#!/usr/bin/env python3
"""Read-only, exact-SHA audit of eight owner-supplied Rayman 2 pseudo-files.

All eight have been independently reproduced as complete masked Park-Miller
streams. The edited GOG EXE can optionally corroborate *declared sizes* via
its own virtual-CD inventory, but it cannot authenticate original CD sectors.

This diagnostic does not run software, decrypt an executable, output game
content, modify a file, or assign any definitive role to these disk bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

from rayman2_sample_provenance import read_bounded, pe_sections, pe_section_flags, manifest_entries

MASKED_SALT = 0x075BD924
MULTIPLIER = 16807
MODULUS = 2147483647
GOG_SHA256 = "9bae484bd84a4afad8d4e7b1bb30a85ce1ce2367f8451463696eabab28a72713"
RETAIL_SHA256 = "7927a106ac4f2244e304e57c196170f6cfb311af87ddf59eb6e6c48b9bb0d5e3"

# name: (exact input bytes, seed, retained prefix, owner-supplied SHA-256).
KNOWN: dict[str, tuple[int, int, bytes, str]] = {
    "RAYMAN2.ICD": (
        683565, 0x6EE4C08A, bytes.fromhex("5b"),
        "4daeae51ded23687fccecd5046dd366b1c083d4931af0a381a0ad0b64bd3d1a6"),
    "DPLAYERX.DLL": (
        165888, 0x0030FBEC, b"",
        "0d5160b1b123636e03a09ae00714f0ff66bbdd759a3f2b639734ecaa487018ee"),
    "CLOKSPL.EXE": (
        177152, 0x67EC2AF6, b"",
        "6efcb3f4ba8052ab8bbd58be703a1de0f9e6eacc8f47c0d6501b0981380edaeb"),
    "CLCD32.DLL": (
        27648, 0x4F2BFCA6, b"",
        "432074cae948d0cee2704f66b47f72a4dee2f9bed288e23912fbc531b041f2a5"),
    "DRVMGT.DLL": (
        32256, 0x2B38CA9A, b"",
        "6111ab0664948e05171468835be20b00f6b69d366fab28d7cd1ca9d9b67af35b"),
    "00000001.TMP": (
        20, 0x2D1B9F61, b"",
        "06ba601c966e6770747d84fe1c3fafaab9f48b07db6eae07a9250f7232415396"),
    "0000040C.016": (
        153718, 0x6B5C5E78, bytes.fromhex("abde"),
        "5c53568c900404bea863ef5ac6e87e49193d95a06674f3a49d70dcefd3f28608"),
    "0000040C.256": (
        308278, 0x777390EF, bytes.fromhex("4dc7"),
        "5f25849ffa80abb15d3897ba5f4bc44ffa6f06819e370b873e9d172fc00f9933"),
}


def verify_stream(data: bytes, *, seed: int, prefix: bytes = b"") -> int:
    """Verify *every* 32-bit state against a fixed recurrence, without output."""
    if not (0 <= seed < 2**31) or len(prefix) > 3:
        raise ValueError("invalid seed/prefix")
    if len(data) < len(prefix) + 8 or data[:len(prefix)] != prefix:
        raise ValueError("missing prefix or too few states")
    if (len(data) - len(prefix)) % 4:
        raise ValueError("unexplained trailing bytes")
    n = (len(data) - len(prefix)) // 4
    state = seed
    for index in range(n):
        word = struct.unpack_from("<I", data, len(prefix) + index * 4)[0]
        if word != state:
            raise ValueError(f"pseudo-random recurrence mismatch at word {index}")
        state = ((state ^ MASKED_SALT) * MULTIPLIER) % MODULUS
    return n


def inspect_pinned(name: str, data: bytes) -> dict:
    if name not in KNOWN:
        raise ValueError("unsupported file name")
    size, seed, prefix, expected_hash = KNOWN[name]
    if len(data) != size or hashlib.sha256(data).hexdigest() != expected_hash:
        raise ValueError(f"{name} size or SHA-256 differs from owner's verified sample")
    n = verify_stream(data, seed=seed, prefix=prefix)
    return {
        "name": name,
        "size": size,
        "sha256": expected_hash,
        "prefix_bytes": len(prefix),
        "initial_state": f"0x{seed:08X}",
        "little_endian_words": n,
        "recurrence_transitions_verified": n-1,
        "complete_file_reconstructible": True,
        "is_valid_on_disk_pe32": False,
        "role_on_original_physical_cd_proven": False,
    }


def literal_name_hits(raw: bytes, names: list[str]) -> dict[str, dict]:
    """Check plain ASCII and UTF-16LE spellings anywhere in on-disk bytes.

    This is deliberately an exact literal scan: it cannot rule out encoded
    names, dynamic construction, indirect references, or runtime loader I/O.
    """
    normalized = raw.lower()
    hits = {}
    for name in names:
        if not name or not name.isascii():
            raise ValueError("expected nonempty ASCII filename")
        ascii_name = name.lower().encode("ascii")
        utf16_name = name.lower().encode("utf-16le")
        hits[name] = {
            "ascii_case_insensitive_occurrences": normalized.count(ascii_name),
            "utf16le_ascii_case_insensitive_occurrences": normalized.count(utf16_name),
        }
    return hits



def count_prng_code_literals(blob: bytes) -> dict[str, int]:
    """Count raw DWORD patterns, NOT reached instructions or runtime calls."""
    return {
        "state_global_pointer_le": blob.count(struct.pack("<I", 0x00510BF0)),
        "masked_prng_xor_salt_le": blob.count(struct.pack("<I", MASKED_SALT)),
    }


def _literal_dword_positions(raw: bytes, dword: int) -> set[int]:
    """All literal byte offsets, including unaligned positions; no x86 claims."""
    needle = struct.pack("<I", dword)
    found: set[int] = set()
    pos = 0
    while True:
        pos = raw.find(needle, pos)
        if pos < 0:
            return found
        found.add(pos)
        pos += 1


def _rva_page_distribution(byte_offsets: set[int], text_rva: int = 0x1000) -> dict[str, int]:
    """Small metadata histogram, never underlying byte sequences."""
    per_page: dict[int, int] = {}
    for offset in byte_offsets:
        page = (offset + text_rva) & ~0xFFF
        per_page[page] = per_page.get(page, 0) + 1
    return {f"0x{page:05X}": per_page[page] for page in sorted(per_page)}


def _compare_literal_code_offsets(original: bytes, active: bytes, value: int) -> dict:
    """Compare matching byte-offset references in two PE sections at same RVA."""
    old_offsets = _literal_dword_positions(original, value)
    new_offsets = _literal_dword_positions(active, value)
    common = old_offsets & new_offsets
    missing = old_offsets - new_offsets
    introduced = new_offsets - old_offsets
    return {
        "original_literal_occurrences": len(old_offsets),
        "active_gog_literal_occurrences": len(new_offsets),
        "retained_at_same_rva": len(common),
        "removed_in_gog": len(missing),
        "introduced_in_gog": len(introduced),
        "removed_rva_pages": _rva_page_distribution(missing),
        "instruction_boundaries_not_proven_by_literal_scan": True,
    }


def compare_masked_mov_ecx_sites(original: bytes, active: bytes) -> dict:
    """Classify replaced x86 MOV ECX,[0x510BF0] instruction beginnings.

    A site is not necessarily a function entry, nor a proven DRM call.
    The existing rayman2_win32_forwarders.py separately verifies the
    actual imported APIs used by the four direct-forwarding replacements.
    """
    op = b"\x8b\x0d" + struct.pack("<I", 0x00510BF0)
    original_sites = _literal_dword_positions(original, 0x00510BF0)
    current_sites = _literal_dword_positions(active, 0x00510BF0)
    orig = {pos-2 for pos in original_sites
            if pos >= 2 and original[pos-2:pos+4] == op}
    gog = {pos-2 for pos in current_sites
           if pos >= 2 and active[pos-2:pos+4] == op}
    removed = sorted(orig - gog)
    kind_counts = {
        "int3_at_old_site": 0,
        "nop_at_old_site": 0,
        "plain_prologue_at_old_site": 0,
        "other_replacement_at_old_site": 0,
    }
    plain_entries = []
    for pos in removed:
        b = active[pos:pos+3]
        if b.startswith(b"\xcc"):
            key = "int3_at_old_site"
        elif b.startswith(b"\x90"):
            key = "nop_at_old_site"
        elif b == b"\x55\x8b\xec":
            key = "plain_prologue_at_old_site"
            plain_entries.append(f"0x{0x401000+pos:08X}")
        else:
            key = "other_replacement_at_old_site"
        kind_counts[key] += 1
    return {
        "original_mov_ecx_global_sites": len(orig),
        "gog_mov_ecx_global_sites": len(gog),
        "retained_at_identical_offsets": len(orig & gog),
        "removed_or_replaced_in_gog": len(removed),
        "introduced_at_new_offsets": len(gog - orig),
        "replacement_starts": kind_counts,
        "plain_prologue_replacement_vas": sorted(plain_entries),
        "instruction_sites_are_not_always_function_entries": True,
        "no_attribution_to_safedisc_alone": True,
    }


def signed_x86_masked_prng_step(value: int) -> int:
    """x86 PRNG step, including signed 32-bit QPC first-word behavior.

    The normal file-stream generator uses only 0..0x7ffffffe states.
    Runtime QueryPerformanceCounter supplies an arbitrary low 32-bit word:
    its high bit alters the *first* 32-bit signed multiplication. Once
    reduced to a nonnegative 31-bit state, subsequent steps coincide.
    """
    if type(value) is not int or not 0 <= value <= 0xffffffff:
        raise ValueError("seed must be an unsigned 32-bit integer")
    masked = value ^ MASKED_SALT
    signed = masked if masked < 0x80000000 else masked - 0x100000000
    return (signed * MULTIPLIER) % MODULUS


def inspect_runtime_rng_initializer(retail: bytes, gog: bytes) -> dict:
    """Only call with *both* SHA-256-verified owner executables.

    A historical, static x86 opcode fingerprint, not a live timer reading
    or a claim about original physical CD payloads.
    """
    rs = pe_sections(retail)
    gs = pe_sections(gog)
    if ".text" not in rs or ".text" not in gs:
        raise ValueError("missing PE code for RNG initializer")
    base = 0x401000
    start = 0x449360
    length = 0x4494AB - start  # 331 bytes, covering initializer and calls
    offset = start - base
    a = rs[".text"][offset:offset+length]
    b = gs[".text"][offset:offset+length]
    expected_sha = "508fb5bc006002d4a7efb27d30747ef453b843219f7fadd1f67b471e7ac30448"
    if len(a) != length or a != b or hashlib.sha256(a).hexdigest() != expected_sha:
        raise ValueError("unexpected retail/GOG RNG initializer bytes")
    anchors = {
        0x401EF8: "6A 01 E8 61 74 04 00",  # push 1; call initializer
        0x449391: "FF 15 60 C0 49 00",     # QueryPerformanceCounter import thunk
        0x449397: "8B 4D F8",              # low DWORD from 64-bit counter
        0x44939E: "B9 78 56 34 12",        # fallback when QPC failed
        0x4493A3: "BE A0 0E 51 00",        # output table base
        0x4493A8: "BF 19 01 00 00",        # 281 words
        0x4493AD: "81 F1 24 D9 5B 07",     # masked XOR
        0x4493BC: "69 C9 A7 41 00 00",     # multiplier 16807
        0x4493DF: "89 0E",                 # write one table word
        0x4493EA: "89 0D F0 0B 51 00",     # final state at 0x510BF0
    }
    for va, hexpattern in anchors.items():
        section_at = va - base
        signature = bytes.fromhex(hexpattern)
        if (rs[".text"][section_at:section_at+len(signature)] != signature or
                gs[".text"][section_at:section_at+len(signature)] != signature):
            raise ValueError(f"RNG bootstrap opcode fingerprint differs at 0x{va:08X}")
    fallback = 0x12345678
    x = fallback
    for _ in range(281):
        x = signed_x86_masked_prng_step(x)
    if (signed_x86_masked_prng_step(fallback) != 0x4F2CEC02 or
            signed_x86_masked_prng_step(0x80000000) != 0x1F0C8C9B or
            x != 0x7A833570):
        raise ValueError("synthetic signed x86 PRNG model differs from known vector")
    return {
        "same_original_gog_331_bytes": True,
        "shared_sha256": expected_sha,
        "bootstrap_entry_va": "0x00449360",
        "startup_call_va": "0x00401EFA",
        "qpc_iat_va": "0x0049C060",
        "initial_seed_source": "low 32 bits of QueryPerformanceCounter; 0x12345678 if call fails",
        "loop_iterations": 281,
        "table_base_va": "0x00510EA0",
        "final_prng_state_va": "0x00510BF0",
        "fallback_seed": "0x12345678",
        "fallback_first_output": "0x4F2CEC02",
        "fallback_281st_output": "0x7A833570",
        "high_bit_seed_example": {
            "input": "0x80000000",
            "x86_signed_first_output": "0x1F0C8C9B",
            "incorrect_unsigned_first_output": "0x1F0D0FE9",
        },
        "static_code_only_no_runtime_timer_observed": True,
        "not_proven_source_of_eight_disc_file_seeds": True,
    }


def original_vs_gog_rng_code(retail: bytes, gog: bytes) -> dict:
    """SHA-gated caller must supply the exact owner CD and GOG executables.

    Distinguish active GOG .text and its archived *non-executable* retail
    copy to avoid mistaking copied original code for live code. Also check
    the eight PRNG seed literals on disk; lack of a literal does not
    refute dynamically derived seeds.
    """
    rs = pe_sections(retail)
    gs = pe_sections(gog)
    original = rs.get(".text", b"")
    active = gs.get(".text", b"")
    archival = gs.get(".extra", b"")
    if len(original) != 631296 or len(active) != 634880:
        raise ValueError("unexpected retail/GOG code section sizes")
    if archival[4096:4096 + len(original)] != original:
        raise ValueError("GOG archived retail .text no longer matches")
    if pe_section_flags(gog, ".extra") & 0x20000000:
        raise ValueError("GOG archived retail code unexpectedly executable")
    counts = {
        "original_retail_text": count_prng_code_literals(original),
        "gog_active_text": count_prng_code_literals(active),
        "gog_archived_retail_text": count_prng_code_literals(
            archival[4096:4096 + len(original)]),
    }
    expected = {
        "original_retail_text": {
            "state_global_pointer_le": 196, "masked_prng_xor_salt_le": 73},
        "gog_active_text": {
            "state_global_pointer_le": 68, "masked_prng_xor_salt_le": 29},
        "gog_archived_retail_text": {
            "state_global_pointer_le": 196, "masked_prng_xor_salt_le": 73},
    }
    if counts != expected:
        raise ValueError("unexpected PRNG code literal fingerprint")
    offset_diff = {
        "state_global_pointer_le": _compare_literal_code_offsets(
            original, active, 0x00510BF0),
        "masked_prng_xor_salt_le": _compare_literal_code_offsets(
            original, active, MASKED_SALT),
    }
    expected_missing = {
        "state_global_pointer_le": {
            "removed_in_gog": 128, "retained_at_same_rva": 68, "introduced_in_gog": 0,
            "removed_rva_pages": {
                "0x47000": 12, "0x48000": 45, "0x49000": 9,
                "0x4D000": 3, "0x4E000": 17, "0x4F000": 12,
                "0x50000": 15, "0x51000": 15,
            },
        },
        "masked_prng_xor_salt_le": {
            "removed_in_gog": 44, "retained_at_same_rva": 29, "introduced_in_gog": 0,
            "removed_rva_pages": {
                "0x47000": 4, "0x48000": 15, "0x49000": 3,
                "0x4D000": 1, "0x4E000": 6, "0x4F000": 4,
                "0x50000": 5, "0x51000": 6,
            },
        },
    }
    for name, measures in expected_missing.items():
        if any(offset_diff[name][key] != value for key, value in measures.items()):
            raise ValueError("unexpected PRNG reference RVA-page fingerprint")
    seeds_in_retail = {}
    seeds_in_gog = {}
    for name, (_, seed, _, _) in KNOWN.items():
        word = struct.pack("<I", seed)
        seeds_in_retail[name] = retail.count(word)
        seeds_in_gog[name] = gog.count(word)
    return {
        "per_section_raw_dword_occurrences": counts,
        "original_vs_active_gog_dword_offset_diff": offset_diff,
        "masked_mov_ecx_original_vs_gog_sites": compare_masked_mov_ecx_sites(original, active),
        "all_eight_seed_literals_absent_from_retail": not any(seeds_in_retail.values()),
        "all_eight_seed_literals_absent_from_gog": not any(seeds_in_gog.values()),
        "per_file_seed_literal_occurrences_retail": seeds_in_retail,
        "per_file_seed_literal_occurrences_gog": seeds_in_gog,
        "gog_extra_is_non_executable": True,
        "archived_original_text_identical": True,
        "raw_literal_counts_are_not_runtime_call_counts": True,
        "seed_absence_does_not_exclude_runtime_derivation": True,
    }


def observed_stream_state_overlap(inspected: dict[str, dict]) -> dict:
    """Pairwise overlap of finite, independently verified PRNG windows only.

    This is a statement about the exact inspected *ranges*, NOT the full
    mathematical periods, disc authenticity, or independent seed sources.
    """
    seen: set[int] = set()
    n = duplicates = 0
    for report in inspected.values():
        state = int(report["initial_state"], 16)
        for _ in range(report["little_endian_words"]):
            if state in seen:
                duplicates += 1
            seen.add(state)
            n += 1
            state = ((state ^ MASKED_SALT) * MULTIPLIER) % MODULUS
    return {
        "observed_words": n,
        "distinct_observed_states": len(seen),
        "observed_state_collisions": duplicates,
        "no_state_overlap_in_observed_intervals": duplicates == 0,
        "global_seed_independence_proven": False,
    }


def compare_gog_manifest(manifest: dict[str, int], inspected: dict[str, dict]) -> dict:
    """Compare selected record sizes without confusing GOG with retail CD."""
    out = {}
    for name, report in inspected.items():
        actual = manifest.get(name)
        out[name] = {"declared_size": actual,
                     "matches_owner_sample_size": actual == report["size"]}
    return {
        "entry_count": len(manifest),
        "checked_names": out,
        "all_checked_sizes_match": all(x["matches_owner_sample_size"]
                                       for x in out.values()),
        "gog_manifest_is_original_disc_authentication": False,
    }


def inspect(samples: dict[str, bytes], gog: bytes | None = None,
            retail: bytes | None = None) -> dict:
    if not samples:
        raise ValueError("at least one sample is required")
    checked = {name: inspect_pinned(name, blob)
               for name, blob in samples.items()}
    result = {"samples": checked,
              "finite_stream_overlap": observed_stream_state_overlap(checked),
              "decrypted_pe_recovered": False,
              "physical_cd_source_authenticated": False}
    if retail is not None:
        if hashlib.sha256(retail).hexdigest() != RETAIL_SHA256 or len(retail) != 676352:
            raise ValueError("original retail EXE differs from owner SHA-256-pinned input")
        result["original_retail_literal_names"] = {
            "checked_sha256": RETAIL_SHA256,
            "file_name_matches": literal_name_hits(retail, list(checked)),
            "absence_does_not_rule_out_dynamic_or_obfuscated_file_open": True,
            "only_on_disk_bytes_searched": True,
        }
    if gog is not None:
        if hashlib.sha256(gog).hexdigest() != GOG_SHA256:
            raise ValueError("GOG reference SHA-256 mismatch")
        pe = pe_sections(gog)
        if ".extra2" not in pe:
            raise ValueError("reference lacks virtual-CD metadata")
        manifest, _, _ = manifest_entries(pe[".extra2"])
        if len(manifest) != 3716:
            raise ValueError("unexpected GOG manifest record count")
        result["gog_virtual_metadata"] = compare_gog_manifest(manifest, result["samples"])
        if not result["gog_virtual_metadata"]["all_checked_sizes_match"]:
            raise ValueError("reference metadata lengths differ from owner samples")
    if retail is not None and gog is not None:
        result["original_vs_gog_rng_code"] = original_vs_gog_rng_code(retail, gog)
        result["runtime_rng_initializer"] = inspect_runtime_rng_initializer(retail, gog)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("icd", "dplayerx", "clokspl", "clcd32", "drvmgt", "tmp", "file016", "file256"):
        parser.add_argument("--" + arg, type=Path, metavar="FILE")
    parser.add_argument("--gog", type=Path,
                        help="Optional exact-hash GOG executable for size-only metadata check")
    parser.add_argument("--retail", type=Path,
                        help="Optional SHA-256-pinned original EXE: literal ASCII/UTF-16LE name scan")
    args = parser.parse_args(argv)
    paths = {
        "RAYMAN2.ICD": args.icd,
        "DPLAYERX.DLL": args.dplayerx,
        "CLOKSPL.EXE": args.clokspl,
        "CLCD32.DLL": args.clcd32,
        "DRVMGT.DLL": args.drvmgt,
        "00000001.TMP": args.tmp,
        "0000040C.016": args.file016,
        "0000040C.256": args.file256,
    }
    if not any(paths.values()):
        parser.error("supply at least one named original sample")
    try:
        samples = {name: read_bounded(path) for name, path in paths.items()
                   if path is not None}
        gog = read_bounded(args.gog) if args.gog else None
        retail = read_bounded(args.retail) if args.retail else None
        result = inspect(samples, gog, retail)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
